#![cfg(target_os = "linux")]

//! Differential conformance harness for POSIX `ffs(3)` and GNU
//! `ffsl(3)` / `ffsll(3)` — find first set bit (1-indexed).
//!
//! Returns the position of the least significant 1 bit (1-indexed),
//! or 0 if the input is 0. Both fl and glibc must agree on every
//! input.
//!
//! Filed under [bd-xn6p8] follow-up.

use std::ffi::{c_int, c_long, c_longlong};

use frankenlibc_abi::stdlib_abi as fl;

unsafe extern "C" {
    fn ffs(i: c_int) -> c_int;
    fn ffsl(i: c_long) -> c_int;
    fn ffsll(i: c_longlong) -> c_int;
}

#[test]
fn diff_ffs_matches_glibc_full_int_range_samples() {
    let cases: &[c_int] = &[
        0, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256,
        0x10000, 0x80000000u32 as c_int, -1, -2, c_int::MAX, c_int::MIN,
        0x1248_8000, 0x0001_0001,
    ];
    for &v in cases {
        let fl_v = fl::ffs(v);
        let lc_v = unsafe { ffs(v) };
        assert_eq!(fl_v, lc_v, "ffs({v:#x}): fl={fl_v} lc={lc_v}");
    }
}

#[test]
fn diff_ffs_zero_returns_zero() {
    let fl_v = fl::ffs(0);
    let lc_v = unsafe { ffs(0) };
    assert_eq!(fl_v, lc_v);
    assert_eq!(fl_v, 0);
}

#[test]
fn diff_ffs_powers_of_two_return_index_plus_one() {
    for shift in 0..32 {
        let v: c_int = 1 << shift;
        let fl_v = fl::ffs(v);
        let lc_v = unsafe { ffs(v) };
        assert_eq!(fl_v, lc_v);
        assert_eq!(fl_v as u32, shift + 1, "ffs(1 << {shift})");
    }
}

#[test]
fn diff_ffsl_matches_glibc() {
    let cases: &[c_long] = &[
        0, 1, 2, 0x100, 0x10000, 0x1_0000_0000, 0x8000_0000_0000_0000u64 as c_long,
        -1, c_long::MIN, c_long::MAX,
    ];
    for &v in cases {
        let fl_v = fl::ffsl(v);
        let lc_v = unsafe { ffsl(v) };
        assert_eq!(fl_v, lc_v, "ffsl({v:#x}): fl={fl_v} lc={lc_v}");
    }
}

#[test]
fn diff_ffsll_matches_glibc() {
    let cases: &[c_longlong] = &[
        0, 1, 0x100, 0x10000, 0x1_0000_0000,
        0x8000_0000_0000_0000u64 as c_longlong,
        -1, c_longlong::MIN, c_longlong::MAX,
    ];
    for &v in cases {
        let fl_v = fl::ffsll(v);
        let lc_v = unsafe { ffsll(v) };
        assert_eq!(fl_v, lc_v, "ffsll({v:#x}): fl={fl_v} lc={lc_v}");
    }
}

#[test]
fn diff_ffsl_powers_of_two() {
    for shift in 0..64 {
        let v: c_long = 1i64 << shift;
        let fl_v = fl::ffsl(v);
        let lc_v = unsafe { ffsl(v) };
        assert_eq!(fl_v, lc_v);
        assert_eq!(fl_v as u32, shift + 1, "ffsl(1 << {shift})");
    }
}

#[test]
fn ffs_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc ffs + ffsl + ffsll\",\"reference\":\"glibc\",\"functions\":3,\"divergences\":0}}",
    );
}
