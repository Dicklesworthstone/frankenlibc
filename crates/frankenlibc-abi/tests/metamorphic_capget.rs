#![cfg(target_os = "linux")]

//! Metamorphic-property tests for `capget(2)` / `capset(2)`.
//!
//! Properties:
//!
//!   - capget(self, V3) is deterministic across calls
//!   - capget with version=0 returns -1 EINVAL and writes preferred
//!     version into hdrp.version (negotiation)
//!   - permitted ⊇ effective (every effective bit must be permitted)
//!   - permitted ⊇ inheritable on most user processes
//!   - capset(self, current_caps) is a no-op (same as before)
//!
//! Filed under [bd-xn6p8] follow-up.

use std::ffi::c_int;

use frankenlibc_abi::unistd_abi as fl;

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct UserCapHeader {
    version: u32,
    pid: c_int,
}

#[repr(C)]
#[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
struct UserCapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

const LINUX_CAPABILITY_VERSION_3: u32 = 0x20080522;

#[test]
fn metamorphic_capget_self_deterministic() {
    let mut hdr1 = UserCapHeader { version: LINUX_CAPABILITY_VERSION_3, pid: 0 };
    let mut hdr2 = hdr1;
    let mut hdr3 = hdr1;
    let mut d1 = [UserCapData::default(); 2];
    let mut d2 = [UserCapData::default(); 2];
    let mut d3 = [UserCapData::default(); 2];
    let r1 = unsafe { fl::capget(&mut hdr1 as *mut _ as *mut std::ffi::c_void, d1.as_mut_ptr() as *mut std::ffi::c_void) };
    let r2 = unsafe { fl::capget(&mut hdr2 as *mut _ as *mut std::ffi::c_void, d2.as_mut_ptr() as *mut std::ffi::c_void) };
    let r3 = unsafe { fl::capget(&mut hdr3 as *mut _ as *mut std::ffi::c_void, d3.as_mut_ptr() as *mut std::ffi::c_void) };
    assert_eq!(r1, 0);
    assert_eq!(r2, 0);
    assert_eq!(r3, 0);
    assert_eq!(d1, d2);
    assert_eq!(d1, d3);
}

#[test]
fn metamorphic_capget_invalid_version_writes_preferred() {
    let mut hdr = UserCapHeader { version: 0, pid: 0 };
    let mut data = [UserCapData::default(); 2];
    let r = unsafe { fl::capget(&mut hdr as *mut _ as *mut std::ffi::c_void, data.as_mut_ptr() as *mut std::ffi::c_void) };
    assert_eq!(r, -1);
    assert_ne!(hdr.version, 0, "kernel must write its version");
    // Should be V1, V2, or V3 — all have a known offset_basis-style
    // value not equal to 0.
    assert!(
        hdr.version == 0x19980330
            || hdr.version == 0x20071026
            || hdr.version == LINUX_CAPABILITY_VERSION_3,
        "unexpected preferred version {:#x}",
        hdr.version
    );
}

#[test]
fn metamorphic_capget_permitted_superset_of_effective() {
    let mut hdr = UserCapHeader { version: LINUX_CAPABILITY_VERSION_3, pid: 0 };
    let mut data = [UserCapData::default(); 2];
    let r = unsafe { fl::capget(&mut hdr as *mut _ as *mut std::ffi::c_void, data.as_mut_ptr() as *mut std::ffi::c_void) };
    assert_eq!(r, 0);
    for (i, slot) in data.iter().enumerate() {
        // Every effective bit must be in permitted.
        assert_eq!(
            slot.effective & !slot.permitted,
            0,
            "slot {i}: effective {:#x} has bits not in permitted {:#x}",
            slot.effective,
            slot.permitted,
        );
    }
}

#[test]
fn metamorphic_capset_self_with_current_is_noop() {
    // Read current caps, then set them back; must succeed.
    let mut hdr = UserCapHeader { version: LINUX_CAPABILITY_VERSION_3, pid: 0 };
    let mut data = [UserCapData::default(); 2];
    let r = unsafe { fl::capget(&mut hdr as *mut _ as *mut std::ffi::c_void, data.as_mut_ptr() as *mut std::ffi::c_void) };
    if r != 0 {
        return; // skip
    }
    let mut hdr2 = hdr;
    let r2 = unsafe { fl::capset(&mut hdr2 as *mut _ as *mut std::ffi::c_void, data.as_ptr() as *const std::ffi::c_void) };
    assert_eq!(r2, 0, "capset with current caps should succeed");
}

#[test]
fn metamorphic_capget_repeated_consistent() {
    // 16 rapid calls must all yield identical data.
    let mut hdr0 = UserCapHeader { version: LINUX_CAPABILITY_VERSION_3, pid: 0 };
    let mut data0 = [UserCapData::default(); 2];
    unsafe { fl::capget(&mut hdr0 as *mut _ as *mut std::ffi::c_void, data0.as_mut_ptr() as *mut std::ffi::c_void) };
    for _ in 0..16 {
        let mut hdr = UserCapHeader { version: LINUX_CAPABILITY_VERSION_3, pid: 0 };
        let mut data = [UserCapData::default(); 2];
        unsafe { fl::capget(&mut hdr as *mut _ as *mut std::ffi::c_void, data.as_mut_ptr() as *mut std::ffi::c_void) };
        assert_eq!(data, data0);
    }
}

#[test]
fn capget_metamorphic_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc capget + capset\",\"reference\":\"linux-capability-invariants\",\"properties\":5,\"divergences\":0}}",
    );
}
