#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc fcvt_r oracle
//! fcvt_r (and thus qfcvt, which delegates to it) with NEGATIVE ndigit. fcvt_r
//! used to clamp ndigit to >= 0 before calling core fcvt, dropping the
//! integer-rounding behavior that fcvt itself gained (round to the 10^|ndigit|
//! place). This gates fcvt_r == glibc fcvt_r for negative ndigit (bd-2g7oyh.101).
//! Range capped at |v| < 1e15 — beyond ~17 sig digits glibc's deprecated fcvt is
//! imprecise (fl rounds the exact integer, more correct; same disposition as the
//! ecvt rounding surface).
use std::ffi::{CStr, c_char, c_int};
use frankenlibc_abi::stdlib_abi as fl;
unsafe extern "C" {
    fn fcvt_r(v: f64, n: c_int, dp: *mut c_int, sg: *mut c_int, b: *mut c_char, bl: usize) -> c_int;
}
fn run(host: bool, v: f64, n: c_int) -> (String, c_int, c_int) {
    let mut dp: c_int = -9;
    let mut sg: c_int = -9;
    let mut buf = [0u8; 160];
    let _ = if host {
        unsafe { fcvt_r(v, n, &mut dp, &mut sg, buf.as_mut_ptr() as *mut c_char, 160) }
    } else {
        unsafe { fl::fcvt_r(v, n, &mut dp, &mut sg, buf.as_mut_ptr() as *mut c_char, 160) }
    };
    let s = CStr::from_bytes_until_nul(&buf)
        .map(|c| c.to_string_lossy().into_owned())
        .unwrap_or_default();
    (s, dp, sg)
}
#[test]
fn fcvt_r_negative_ndigit_matches_glibc() {
    let vals: &[f64] = &[
        123456.0, 999.0, 9999.0, 12.0, 5.0, 99.0, 123.0, 150.0, 9500.0, 0.5, 7.0,
        0.0, -999.0, -150.0, 45.0, 55.0, 250.0, 2500.0, 49999.0, 50000.0, 1.0, 999999.0,
    ];
    let mut div = Vec::new();
    for &v in vals {
        if v.abs() >= 1e15 {
            continue;
        }
        for &n in &[-1, -2, -3, -5, -10, -100] {
            let h = run(true, v, n);
            let f = run(false, v, n);
            if h != f {
                div.push(format!("fcvt_r({v:e},{n}): host={h:?} fl={f:?}"));
            }
        }
    }
    assert!(div.is_empty(), "fcvt_r negative-ndigit divergences:\n{}", div.join("\n"));
}
