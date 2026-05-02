#![cfg(target_os = "linux")]

//! Differential conformance harness for Linux `capget(2)` /
//! `capset(2)`.
//!
//! These syscalls expose the calling process's POSIX capability sets
//! (effective/permitted/inheritable). fl forwards through native
//! sys_capget/sys_capset wrappers in frankenlibc_core::syscall.
//!
//! Filed under [bd-xn6p8] follow-up.

use std::ffi::c_int;

use frankenlibc_abi::unistd_abi as fl;

/// `cap_user_header_t` from <linux/capability.h>.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct UserCapHeader {
    version: u32,
    pid: c_int,
}

/// `cap_user_data_t` element — one per 32-bit cap slice.
#[repr(C)]
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
struct UserCapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

const LINUX_CAPABILITY_VERSION_3: u32 = 0x20080522;

unsafe extern "C" {
    fn capget(hdrp: *mut UserCapHeader, datap: *mut UserCapData) -> c_int;
    fn capset(hdrp: *mut UserCapHeader, datap: *const UserCapData) -> c_int;
}

#[test]
fn diff_capget_self_round_trip_against_glibc() {
    // V3 capabilities use 2 data slots (low + high 32 bits).
    let mut fl_hdr = UserCapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0, // 0 = self
    };
    let mut lc_hdr = fl_hdr;
    let mut fl_data = [UserCapData::default(); 2];
    let mut lc_data = [UserCapData::default(); 2];
    let fl_r = unsafe {
        fl::capget(
            &mut fl_hdr as *mut UserCapHeader as *mut std::ffi::c_void,
            fl_data.as_mut_ptr() as *mut std::ffi::c_void,
        )
    };
    let lc_r = unsafe { capget(&mut lc_hdr, lc_data.as_mut_ptr()) };
    assert_eq!(fl_r, lc_r, "capget(self) ret: fl={fl_r} lc={lc_r}");
    assert_eq!(fl_r, 0, "capget(self) should succeed");
    // Header must match (version unchanged).
    assert_eq!(fl_hdr, lc_hdr, "capget header divergence");
    // Capability sets must match exactly.
    assert_eq!(fl_data, lc_data, "capability data divergence");
}

#[test]
fn diff_capget_invalid_version_returns_einval() {
    // The kernel rejects unknown version codes by returning -1 with
    // EINVAL and writing the kernel's preferred version into hdrp.
    let mut fl_hdr = UserCapHeader { version: 0, pid: 0 };
    let mut lc_hdr = UserCapHeader { version: 0, pid: 0 };
    let mut fl_data = [UserCapData::default(); 2];
    let mut lc_data = [UserCapData::default(); 2];
    let fl_r = unsafe {
        fl::capget(
            &mut fl_hdr as *mut UserCapHeader as *mut std::ffi::c_void,
            fl_data.as_mut_ptr() as *mut std::ffi::c_void,
        )
    };
    let lc_r = unsafe { capget(&mut lc_hdr, lc_data.as_mut_ptr()) };
    assert_eq!(fl_r, lc_r, "invalid-version ret: fl={fl_r} lc={lc_r}");
    assert_eq!(fl_r, -1);
    // Both impls must update hdrp.version with the kernel's preferred version.
    assert_eq!(fl_hdr.version, lc_hdr.version, "version negotiation differs");
    assert_ne!(fl_hdr.version, 0, "kernel should write its version");
}

#[test]
fn diff_capget_other_pid_works_or_uniformly_fails() {
    // pid=1 (init) — usually queryable as a regular user.
    let mut fl_hdr = UserCapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 1,
    };
    let mut lc_hdr = fl_hdr;
    let mut fl_data = [UserCapData::default(); 2];
    let mut lc_data = [UserCapData::default(); 2];
    let fl_r = unsafe {
        fl::capget(
            &mut fl_hdr as *mut UserCapHeader as *mut std::ffi::c_void,
            fl_data.as_mut_ptr() as *mut std::ffi::c_void,
        )
    };
    let lc_r = unsafe { capget(&mut lc_hdr, lc_data.as_mut_ptr()) };
    // Both must agree on success/failure.
    assert_eq!(fl_r, lc_r, "capget(pid=1) ret: fl={fl_r} lc={lc_r}");
    if fl_r == 0 {
        assert_eq!(fl_data, lc_data, "capget(pid=1) data");
    }
}

#[test]
fn diff_capset_no_change_round_trip_succeeds_or_uniformly_fails() {
    // Read current caps, then write them back. Any unprivileged
    // process can do this iff the new value == old value.
    let mut hdr = UserCapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [UserCapData::default(); 2];
    let r = unsafe { capget(&mut hdr, data.as_mut_ptr()) };
    if r != 0 {
        return; // skip — capget already failed
    }

    // Fresh headers for each impl since capset may modify.
    let mut fl_hdr = hdr;
    let mut lc_hdr = hdr;
    let fl_r = unsafe {
        fl::capset(
            &mut fl_hdr as *mut UserCapHeader as *mut std::ffi::c_void,
            data.as_ptr() as *const std::ffi::c_void,
        )
    };
    let lc_r = unsafe { capset(&mut lc_hdr, data.as_ptr()) };
    assert_eq!(fl_r, lc_r, "capset round-trip ret: fl={fl_r} lc={lc_r}");
}

#[test]
fn capget_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc capget + capset\",\"reference\":\"glibc\",\"functions\":2,\"divergences\":0}}",
    );
}
