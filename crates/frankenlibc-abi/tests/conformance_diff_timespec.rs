#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc timespec_get/timespec_getres oracle

//! Differential gate for the C11/C23 timespec_get / timespec_getres (bd-widrs7)
//! — both had no differential gate (only fl-internal). The return value must
//! match glibc for valid (TIME_UTC) and invalid bases, timespec_getres's
//! resolution is fixed so it is compared byte-for-byte, and timespec_get's
//! current-time fill is checked for plausibility (can't byte-match "now"). No
//! mocks.

use std::ffi::c_int;

const TIME_UTC: c_int = 1;

unsafe extern "C" {
    fn timespec_get(ts: *mut libc::timespec, base: c_int) -> c_int;
    fn timespec_getres(ts: *mut libc::timespec, base: c_int) -> c_int;
}

#[test]
fn timespec_get_return_contract_matches_glibc() {
    for base in [TIME_UTC, 0, 2, 99, -1] {
        let mut gt: libc::timespec = unsafe { std::mem::zeroed() };
        let mut ft: libc::timespec = unsafe { std::mem::zeroed() };
        let g = unsafe { timespec_get(&mut gt, base) };
        let f = unsafe { frankenlibc_abi::time_abi::timespec_get(&mut ft, base) };
        assert_eq!(f, g, "timespec_get base={base}: fl={f} glibc={g}");
        if base == TIME_UTC {
            assert_eq!(g, TIME_UTC, "glibc timespec_get(TIME_UTC) returns the base");
            // Both must have populated a plausible wall-clock time (post-2020).
            assert!(
                ft.tv_sec > 1_577_836_800,
                "fl ts not populated: {}",
                ft.tv_sec
            );
            assert!(
                (0..1_000_000_000).contains(&ft.tv_nsec),
                "fl tv_nsec out of range"
            );
        } else {
            assert_eq!(g, 0, "glibc timespec_get(invalid base) returns 0");
        }
    }
}

#[test]
fn timespec_getres_matches_glibc() {
    for base in [TIME_UTC, 0, 2, 99] {
        let mut gt: libc::timespec = unsafe { std::mem::zeroed() };
        let mut ft: libc::timespec = unsafe { std::mem::zeroed() };
        let g = unsafe { timespec_getres(&mut gt, base) };
        let f = unsafe { frankenlibc_abi::time_abi::timespec_getres(&mut ft, base) };
        assert_eq!(f, g, "timespec_getres base={base}: fl={f} glibc={g}");
        if base == TIME_UTC {
            // The clock resolution is fixed -> byte-exact comparison.
            assert_eq!(
                (ft.tv_sec, ft.tv_nsec),
                (gt.tv_sec, gt.tv_nsec),
                "timespec_getres resolution: fl=({},{}) glibc=({},{})",
                ft.tv_sec,
                ft.tv_nsec,
                gt.tv_sec,
                gt.tv_nsec,
            );
        }
    }
}
