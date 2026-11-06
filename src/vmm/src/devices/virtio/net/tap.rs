// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::fmt::{self, Debug};
use std::fs::{self, File, OpenOptions};
use std::io::{Error as IoError, ErrorKind};
use std::os::raw::*;
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

use vmm_sys_util::ioctl::{ioctl_with_mut_ref, ioctl_with_ref, ioctl_with_val};
use vmm_sys_util::ioctl_iow_nr;

use crate::devices::virtio::net::generated;

// As defined in the Linux UAPI:
// https://elixir.bootlin.com/linux/v4.17/source/include/uapi/linux/if.h#L33
const IFACE_NAME_MAX_LEN: usize = 16;

/// List of errors the tap implementation can throw.
#[rustfmt::skip]
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum TapError {
    /// Couldn't open /dev/net/tun: {0}
    OpenTun(IoError),
    /// Couldn't open macvtap device {1}: {0}
    OpenMacvtap(IoError, String),
    /// Invalid interface name
    InvalidIfname,
    /// Error while creating ifreq structure: {0}. Invalid TUN/TAP Backend provided by {1}. Check our documentation on setting up the network devices.
    IfreqExecuteError(IoError, String),
    /// Error while setting the offload flags: {0}
    SetOffloadFlags(IoError),
    /// Error while setting size of the vnet header: {0}
    SetSizeOfVnetHdr(IoError),
}

const TUNTAP: ::std::os::raw::c_uint = 84;
ioctl_iow_nr!(TUNSETIFF, TUNTAP, 202, ::std::os::raw::c_int);
ioctl_iow_nr!(TUNSETOFFLOAD, TUNTAP, 208, ::std::os::raw::c_uint);
ioctl_iow_nr!(TUNSETVNETHDRSZ, TUNTAP, 216, ::std::os::raw::c_int);

/// Handle for a network tap interface.
///
/// For now, this simply wraps the file descriptor for the tap device so methods
/// can run ioctls on the interface. The tap interface fd will be closed when
/// Tap goes out of scope, and the kernel will clean up the interface automatically.
#[derive(Debug)]
pub struct Tap {
    tap_file: File,
    pub(crate) if_name: [u8; IFACE_NAME_MAX_LEN],
}

// Returns a byte vector representing the contents of a null terminated C string which
// contains if_name.
fn build_terminated_if_name(if_name: &str) -> Result<[u8; IFACE_NAME_MAX_LEN], TapError> {
    // Convert the string slice to bytes, and shadow the variable,
    // since we no longer need the &str version.
    let if_name = if_name.as_bytes();

    if if_name.len() >= IFACE_NAME_MAX_LEN {
        return Err(TapError::InvalidIfname);
    }

    let mut terminated_if_name = [b'\0'; IFACE_NAME_MAX_LEN];
    terminated_if_name[..if_name.len()].copy_from_slice(if_name);

    Ok(terminated_if_name)
}

#[derive(Copy, Clone)]
pub struct IfReqBuilder(generated::ifreq);

impl fmt::Debug for IfReqBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IfReqBuilder {{ .. }}")
    }
}

impl IfReqBuilder {
    pub fn new() -> Self {
        Self(Default::default())
    }

    pub fn if_name(mut self, if_name: &[u8; IFACE_NAME_MAX_LEN]) -> Self {
        // SAFETY: Since we don't call as_mut on the same union field more than once, this block is
        // safe.
        let ifrn_name = unsafe { self.0.ifr_ifrn.ifrn_name.as_mut() };
        ifrn_name.copy_from_slice(if_name.as_ref());

        self
    }

    pub(crate) fn flags(mut self, flags: i16) -> Self {
        self.0.ifr_ifru.ifru_flags = flags;
        self
    }

    pub(crate) fn mtu(mut self, mtu: i32) -> Self {
        self.0.ifr_ifru.ifru_mtu = mtu;
        self
    }

    pub(crate) fn execute<F: AsRawFd + Debug>(
        mut self,
        socket: &F,
        ioctl: u64,
    ) -> std::io::Result<generated::ifreq> {
        // SAFETY: ioctl is safe. Called with a valid socket fd, and we check the return.
        if unsafe { ioctl_with_mut_ref(socket, ioctl, &mut self.0) } < 0 {
            return Err(IoError::last_os_error());
        }

        Ok(self.0)
    }
}

fn tap_if_flags() -> i16 {
    i16::try_from(generated::IFF_TAP | generated::IFF_NO_PI | generated::IFF_VNET_HDR).unwrap()
}

/// Linux rejects `/`, whitespace, `:`, empty names, `.` and `..` in interface names.
fn plausible_ifname(if_name: &str) -> bool {
    if if_name.is_empty()
        || if_name.len() >= IFACE_NAME_MAX_LEN
        || if_name == "."
        || if_name == ".."
    {
        return false;
    }
    if_name
        .bytes()
        .all(|byte| !byte.is_ascii_whitespace() && byte != b'/' && byte != b':' && byte != 0)
}

fn is_absent(err: &IoError) -> bool {
    matches!(err.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory)
}

fn read_ifindex(if_name: &str) -> Option<u32> {
    let text = fs::read_to_string(format!("/sys/class/net/{if_name}/ifindex")).ok()?;
    match text.trim().parse::<u32>() {
        Ok(index) if index > 0 => Some(index),
        _ => None,
    }
}

/// `/sys/class/macvtap/tap<ifindex>` exists only for macvtap devices. Plain tuntap and
/// macvlan interfaces do not have it, so a failed lookup falls back to `/dev/net/tun`.
fn macvtap_sysfs_present(ifindex: u32) -> bool {
    File::open(format!("/sys/class/macvtap/tap{ifindex}")).is_ok()
}

/// Open `path` when it is a character device.
///
/// `Ok(None)` means the path is not present, so the caller can try another backend.
/// A path that exists but cannot be used as a macvtap node is returned as an error.
fn try_open_char_device(path: &str) -> Result<Option<File>, TapError> {
    let file = match OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(err) if is_absent(&err) => return Ok(None),
        Err(err) => return Err(TapError::OpenMacvtap(err, path.to_owned())),
    };

    let metadata = file
        .metadata()
        .map_err(|err| TapError::OpenMacvtap(err, path.to_owned()))?;
    if !metadata.file_type().is_char_device() {
        return Err(TapError::OpenMacvtap(
            IoError::new(ErrorKind::InvalidInput, "not a character device"),
            path.to_owned(),
        ));
    }
    Ok(Some(file))
}

/// Open an existing macvtap device.
///
/// QEMU's `tap_open()` tries `/dev/tap<ifindex>` before `/dev/net/tun`. The same probe is
/// used here. `if_nametoindex()` is intentionally not used: musl implements it with
/// `socket(AF_UNIX, SOCK_DGRAM)`, which the VMM seccomp filter does not allow. The ifindex
/// is read from sysfs instead (`open`/`read`/`close` are allowed).
///
/// Inside the jail, sysfs is not mounted. The jailer creates `/dev/tap/<ifname>` with the
/// macvtap major/minor, and that node is tried first.
fn open_macvtap(if_name: &str) -> Result<Option<File>, TapError> {
    if !plausible_ifname(if_name) {
        return Ok(None);
    }

    if let Some(file) = try_open_char_device(&format!("/dev/tap/{if_name}"))? {
        return Ok(Some(file));
    }

    let Some(ifindex) = read_ifindex(if_name) else {
        return Ok(None);
    };
    if !macvtap_sysfs_present(ifindex) {
        return Ok(None);
    }

    let node = format!("/dev/tap{ifindex}");
    match try_open_char_device(&node)? {
        Some(file) => Ok(Some(file)),
        None => Err(TapError::OpenMacvtap(
            IoError::new(ErrorKind::NotFound, "macvtap device node is missing"),
            node,
        )),
    }
}

fn open_tuntap_fd() -> Result<File, TapError> {
    // SAFETY: Open calls are safe because we give a constant null-terminated
    // string and verify the result.
    let fd = unsafe {
        libc::open(
            c"/dev/net/tun".as_ptr(),
            libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(TapError::OpenTun(IoError::last_os_error()));
    }

    // SAFETY: We just checked that the fd is valid.
    Ok(unsafe { File::from_raw_fd(fd) })
}

impl Tap {
    /// Open a host network backend for `if_name`.
    ///
    /// `if_name` is either a persistent tuntap name, or the name of an existing macvtap
    /// device. A macvtap device is not created or destroyed by this handle: dropping `Tap`
    /// only closes the queue. A tuntap name that does not exist yet is created through
    /// `/dev/net/tun`, as before.
    ///
    /// # Arguments
    ///
    /// * `if_name` - the name of the interface.
    pub fn open_named(if_name: &str) -> Result<Tap, TapError> {
        let terminated_if_name = build_terminated_if_name(if_name)?;
        let tap_file = match open_macvtap(if_name)? {
            Some(file) => file,
            None => open_tuntap_fd()?,
        };

        // TUNSETIFF on a macvtap fd does not create an interface. The kernel ignores the
        // name and only applies IFF_TAP | IFF_NO_PI | IFF_VNET_HDR, which `tap_open()` also
        // sets by default. The same ioctl attaches a tuntap fd opened from `/dev/net/tun`.
        let ifreq = IfReqBuilder::new()
            .if_name(&terminated_if_name)
            .flags(tap_if_flags())
            .execute(&tap_file, TUNSETIFF())
            .map_err(|io_error| TapError::IfreqExecuteError(io_error, if_name.to_owned()))?;

        Ok(Tap {
            tap_file,
            // SAFETY: Safe since only the name is accessed, and it's cloned out.
            if_name: unsafe { ifreq.ifr_ifrn.ifrn_name },
        })
    }

    /// Retrieve the interface's name as a str.
    pub fn if_name_as_str(&self) -> &str {
        let len = self
            .if_name
            .iter()
            .position(|x| *x == 0)
            .unwrap_or(IFACE_NAME_MAX_LEN);
        std::str::from_utf8(&self.if_name[..len]).unwrap_or("")
    }

    /// Set the offload flags for the tap interface.
    pub fn set_offload(&self, flags: c_uint) -> Result<(), TapError> {
        // SAFETY: ioctl is safe. Called with a valid tap fd, and we check the return.
        if unsafe { ioctl_with_val(&self.tap_file, TUNSETOFFLOAD(), c_ulong::from(flags)) } < 0 {
            return Err(TapError::SetOffloadFlags(IoError::last_os_error()));
        }

        Ok(())
    }

    /// Set the size of the vnet hdr.
    pub fn set_vnet_hdr_size(&self, size: c_int) -> Result<(), TapError> {
        // SAFETY: ioctl is safe. Called with a valid tap fd, and we check the return.
        if unsafe { ioctl_with_ref(&self.tap_file, TUNSETVNETHDRSZ(), &size) } < 0 {
            return Err(TapError::SetSizeOfVnetHdr(IoError::last_os_error()));
        }

        Ok(())
    }
}

impl AsRawFd for Tap {
    fn as_raw_fd(&self) -> RawFd {
        self.tap_file.as_raw_fd()
    }
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::undocumented_unsafe_blocks)]

    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;
    use std::process::Command;
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;
    use crate::devices::virtio::iovec::IoVecBuffer;
    use crate::devices::virtio::net::generated;
    use crate::devices::virtio::net::test_utils::{TapTrafficSimulator, enable, if_index};
    use crate::devices::virtio::queue::VIRTQ_DESC_F_WRITE;
    use crate::devices::virtio::test_utils::VirtQueue;
    use crate::test_utils::single_region_mem;
    use crate::vstate::memory::{Bytes, GuestAddress};

    // Redefine `IoVecBufferMut` with specific length. Otherwise
    // Rust will not know what to do.
    type IoVecBufferMut = crate::devices::virtio::iovec::IoVecBufferMut<256>;

    // The size of the virtio net header
    const VNET_HDR_SIZE: usize = 10;

    const PAYLOAD_SIZE: usize = 512;

    #[test]
    fn test_tap_name() {
        // Sanity check that the assumed max iface name length is correct.
        assert_eq!(IFACE_NAME_MAX_LEN, unsafe {
            generated::ifreq__bindgen_ty_1::default().ifrn_name.len()
        });

        // Empty name - The tap should be named "tapN" by default, where N is some number
        // assigned by the kernel (e.g. "tap0", "tap1", etc.). We cannot assert a specific
        // number because other tests running in parallel may have already created tap devices.
        let tap = Tap::open_named("").unwrap();
        let name = tap.if_name_as_str();
        assert!(
            name.starts_with("tap")
                && name.len() > 3
                && name[3..].chars().all(|c| c.is_ascii_digit()),
            "Expected tap name matching 'tapN', got '{name}'"
        );

        // Test using '%d' to have the kernel assign an unused name,
        // and that we correctly copy back that generated name
        let tap = Tap::open_named("tap%d").unwrap();
        // '%d' should be replaced with _some_ number, although we don't know what was the next
        // available one. Just assert that '%d' definitely isn't there anymore.
        assert_ne!(b"tap%d", &tap.if_name[..5]);

        // 16 characters - too long.
        let name = "a123456789abcdef";
        match Tap::open_named(name) {
            Err(TapError::InvalidIfname) => (),
            _ => panic!("Expected Error::InvalidIfname"),
        };

        // 15 characters - OK.
        let name = "a123456789abcde";
        let tap = Tap::open_named(name).unwrap();
        assert_eq!(&format!("{}\0", name).as_bytes(), &tap.if_name);
        assert_eq!(name, tap.if_name_as_str());
    }

    #[test]
    fn test_tap_exclusive_open() {
        let _tap1 = Tap::open_named("exclusivetap").unwrap();
        // Opening same tap device a second time should not be permitted.
        Tap::open_named("exclusivetap").unwrap_err();
    }

    #[test]
    fn test_set_options() {
        // This line will fail to provide an initialized FD if the test is not run as root.
        let tap = Tap::open_named("").unwrap();
        tap.set_vnet_hdr_size(16).unwrap();
        tap.set_offload(0).unwrap();
    }

    #[test]
    fn test_raw_fd() {
        let tap = Tap::open_named("").unwrap();
        assert_eq!(tap.as_raw_fd(), tap.tap_file.as_raw_fd());
    }

    #[test]
    fn test_writev_to_tap() {
        let tap = Tap::open_named("").unwrap();
        enable(&tap);
        let tap_traffic_simulator = TapTrafficSimulator::new(if_index(&tap));

        let mut fragment1 = vmm_sys_util::rand::rand_bytes(PAYLOAD_SIZE);
        fragment1.as_mut_slice()[..generated::ETH_HLEN as usize]
            .copy_from_slice(&[0; generated::ETH_HLEN as usize]);
        let fragment2 = vmm_sys_util::rand::rand_bytes(PAYLOAD_SIZE);
        let fragment3 = vmm_sys_util::rand::rand_bytes(PAYLOAD_SIZE);

        let scattered = IoVecBuffer::from(vec![
            fragment1.as_slice(),
            fragment2.as_slice(),
            fragment3.as_slice(),
        ]);

        let num_bytes = scattered.writev_to(&tap).unwrap();
        assert_eq!(num_bytes, scattered.len() as usize);

        let mut read_buf = vec![0u8; scattered.len() as usize];
        assert!(tap_traffic_simulator.pop_rx_packet(&mut read_buf));
        assert_eq!(
            &read_buf[..PAYLOAD_SIZE - VNET_HDR_SIZE],
            &fragment1[VNET_HDR_SIZE..]
        );
        assert_eq!(
            &read_buf[PAYLOAD_SIZE - VNET_HDR_SIZE..2 * PAYLOAD_SIZE - VNET_HDR_SIZE],
            fragment2
        );
        assert_eq!(
            &read_buf[2 * PAYLOAD_SIZE - VNET_HDR_SIZE..3 * PAYLOAD_SIZE - VNET_HDR_SIZE],
            fragment3
        );
    }

    #[test]
    fn test_readv_from_tap() {
        let tap = Tap::open_named("").unwrap();
        enable(&tap);
        let tap_traffic_simulator = TapTrafficSimulator::new(if_index(&tap));

        // Two write-only descriptor chains of one descriptor each, in guest memory, with the
        // first one holding exactly the virtio-net header and the first half of the payload.
        let mem = single_region_mem(0x10000);
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        let mut q = vq.create_queue();
        q.config.ready = true;
        let buff1_len = u32::try_from(PAYLOAD_SIZE + VNET_HDR_SIZE).unwrap();
        let buff2_len = u32::try_from(2 * PAYLOAD_SIZE).unwrap();
        let buff1_addr = vq.end().0;
        let buff2_addr = buff1_addr + u64::from(buff1_len);
        vq.dtable[0].set(buff1_addr, buff1_len, VIRTQ_DESC_F_WRITE, 0);
        vq.dtable[1].set(buff2_addr, buff2_len, VIRTQ_DESC_F_WRITE, 0);
        vq.avail.ring[0].set(0);
        vq.avail.ring[1].set(1);
        vq.avail.idx.set(2);
        let mut rx_buffers = IoVecBufferMut::new().unwrap();
        // SAFETY: the two chains do not overlap.
        unsafe {
            rx_buffers
                .append_descriptor_chain(&mem, q.pop().unwrap().unwrap(), 0)
                .unwrap();
            rx_buffers
                .append_descriptor_chain(&mem, q.pop().unwrap().unwrap(), 0)
                .unwrap();
        }

        let packet = vmm_sys_util::rand::rand_alphanumerics(2 * PAYLOAD_SIZE);
        tap_traffic_simulator.push_tx_packet(packet.as_bytes());
        assert_eq!(
            rx_buffers.readv_from(&mem, &tap, usize::MAX).unwrap(),
            2 * PAYLOAD_SIZE + VNET_HDR_SIZE
        );
        let mut buff1 = vec![0; PAYLOAD_SIZE + VNET_HDR_SIZE];
        mem.read_slice(&mut buff1, GuestAddress(buff1_addr))
            .unwrap();
        let mut buff2 = vec![0; 2 * PAYLOAD_SIZE];
        mem.read_slice(&mut buff2, GuestAddress(buff2_addr))
            .unwrap();
        assert_eq!(&buff1[VNET_HDR_SIZE..], &packet.as_bytes()[..PAYLOAD_SIZE]);
        assert_eq!(&buff2[..PAYLOAD_SIZE], &packet.as_bytes()[PAYLOAD_SIZE..]);
        assert_eq!(&buff2[PAYLOAD_SIZE..], &vec![0; PAYLOAD_SIZE])
    }

    #[test]
    fn test_macvtap_probe_skips_unknown_names() {
        // Missing and unsafe names must fall through to the tuntap backend. The unsafe
        // name must not be interpolated into a sysfs or device path.
        assert!(open_macvtap("fcnosuchmt0").unwrap().is_none());
        assert!(open_macvtap("../etc").unwrap().is_none());
        assert!(open_macvtap("").unwrap().is_none());
        assert!(open_macvtap("tap%d").unwrap().is_none());
    }

    struct MacvtapFixture {
        parent: String,
        tap: String,
    }

    impl MacvtapFixture {
        fn new(tag: &str) -> Self {
            static NEXT: AtomicU32 = AtomicU32::new(0);
            let suffix = NEXT.fetch_add(1, Ordering::Relaxed);
            let fixture = Self {
                parent: format!("fc{tag}p{suffix}"),
                tap: format!("fc{tag}t{suffix}"),
            };
            let _ = Command::new("ip")
                .args(["link", "del", &fixture.tap])
                .output();
            let _ = Command::new("ip")
                .args(["link", "del", &fixture.parent])
                .output();
            fixture
        }
    }

    impl Drop for MacvtapFixture {
        fn drop(&mut self) {
            let _ = Command::new("ip").args(["link", "del", &self.tap]).output();
            let _ = Command::new("ip")
                .args(["link", "del", &self.parent])
                .output();
        }
    }

    fn run_ip(args: &[&str]) -> std::process::Output {
        Command::new("ip")
            .args(args)
            .output()
            .expect("failed to spawn ip")
    }

    fn create_macvtap(fixture: &MacvtapFixture) {
        let created = run_ip(&["link", "add", &fixture.parent, "type", "dummy"]);
        if !created.status.success() {
            // The rest of the tap tests also require CAP_NET_ADMIN. Surface the same failure.
            panic!(
                "failed to create dummy device {}: {}",
                fixture.parent,
                String::from_utf8_lossy(&created.stderr)
            );
        }
        let created = run_ip(&[
            "link",
            "add",
            "link",
            &fixture.parent,
            "name",
            &fixture.tap,
            "type",
            "macvtap",
            "mode",
            "bridge",
        ]);
        assert!(
            created.status.success(),
            "failed to create macvtap {}: {}",
            fixture.tap,
            String::from_utf8_lossy(&created.stderr)
        );
        let up = run_ip(&["link", "set", &fixture.tap, "up"]);
        assert!(
            up.status.success(),
            "failed to set {} up: {}",
            fixture.tap,
            String::from_utf8_lossy(&up.stderr)
        );
    }

    #[test]
    fn test_open_existing_macvtap() {
        let fixture = MacvtapFixture::new("a");
        create_macvtap(&fixture);

        let tap = Tap::open_named(&fixture.tap).unwrap();
        assert_eq!(tap.if_name_as_str(), fixture.tap);
        tap.set_vnet_hdr_size(16).unwrap();
        tap.set_offload(0).unwrap();

        let ifindex = fs::read_to_string(format!("/sys/class/net/{}/ifindex", fixture.tap))
            .unwrap()
            .trim()
            .parse::<u32>()
            .unwrap();
        let host_node = fs::metadata(format!("/dev/tap{ifindex}")).unwrap();
        assert_eq!(tap.tap_file.metadata().unwrap().rdev(), host_node.rdev());

        // Closing the queue must not delete a macvtap created outside Firecracker.
        drop(tap);
        assert!(Path::new(&format!("/sys/class/net/{}", fixture.tap)).exists());
    }

    #[test]
    fn test_jail_node_is_preferred_over_host_node() {
        let fixture = MacvtapFixture::new("b");
        create_macvtap(&fixture);

        // The jailer creates /dev/tap/<ifname>. That node is tried before /dev/tap<ifindex>.
        // Point it at /dev/null so a successful open would be the wrong device.
        struct JailNode {
            path: String,
            remove_dir: bool,
        }
        impl Drop for JailNode {
            fn drop(&mut self) {
                let _ = fs::remove_file(&self.path);
                if self.remove_dir {
                    let _ = fs::remove_dir("/dev/tap");
                }
            }
        }
        let jail_node = JailNode {
            path: format!("/dev/tap/{}", fixture.tap),
            remove_dir: fs::create_dir("/dev/tap").is_ok(),
        };
        let c_node = CString::new(jail_node.path.clone()).unwrap();
        // SAFETY: `c_node` is NUL-terminated. The return value is checked.
        let rc = unsafe {
            libc::mknod(
                c_node.as_ptr(),
                libc::S_IFCHR | 0o666,
                libc::makedev(1, 3),
            )
        };
        assert_eq!(
            rc,
            0,
            "mknod {}: {}",
            jail_node.path,
            std::io::Error::last_os_error()
        );

        let open_err = Tap::open_named(&fixture.tap).unwrap_err();
        assert!(
            matches!(open_err, TapError::IfreqExecuteError(..)),
            "expected the jail node to be opened, got {open_err:?}"
        );

        fs::remove_file(&jail_node.path).unwrap();
        let tap = Tap::open_named(&fixture.tap).unwrap();
        assert_eq!(tap.if_name_as_str(), fixture.tap);
        drop(jail_node);
    }
}
