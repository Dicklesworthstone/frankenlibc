#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc ecvt/fcvt oracle
//! `ecvt`/`fcvt` with ndigit <= 0: glibc returns an empty digit string but still
//! reports decpt = floor(log10(|value|)) + 1 (the unrounded magnitude; zero ->
//! decpt 1). fl previously hardcoded decpt 0 (bd-2g7oyh.101). This gates the
//! clean sub-case fl now matches byte-for-byte vs glibc 2.42. (The separate
//! fcvt-with-NEGATIVE-ndigit integer-rounding quirk — fcvt(123456,-3)=123000,
//! with glibc clamp oddities at large |n| — stays out of scope on the bead.)
use frankenlibc_abi::stdlib_abi as fl;
use std::ffi::{CStr, c_char, c_int};
unsafe extern "C" {
    fn ecvt(v: f64, n: c_int, dp: *mut c_int, sg: *mut c_int) -> *mut c_char;
    fn fcvt(v: f64, n: c_int, dp: *mut c_int, sg: *mut c_int) -> *mut c_char;
}
fn tup(host: bool, v: f64, n: c_int, fc: bool) -> (String, c_int, c_int) {
    let mut dp: c_int = -999;
    let mut sg: c_int = -999;
    let r = match (host, fc) {
        (true, false) => unsafe { ecvt(v, n, &mut dp, &mut sg) },
        (true, true) => unsafe { fcvt(v, n, &mut dp, &mut sg) },
        (false, false) => unsafe { fl::ecvt(v, n, &mut dp, &mut sg) },
        (false, true) => unsafe { fl::fcvt(v, n, &mut dp, &mut sg) },
    };
    let s = if r.is_null() {
        "<null>".into()
    } else {
        unsafe { CStr::from_ptr(r) }.to_string_lossy().into_owned()
    };
    (s, dp, sg)
}
#[test]
#[allow(clippy::approx_constant)]
fn ecvt_fcvt_ndigit_le_zero_matches_glibc() {
    let vals: &[f64] = &[
        1.0, 3.14159, 0.5, 100.0, 0.001, 9.99, 0.0, -0.0, 123456.0, 0.0001234, 99.5, 1e20, 1e-20,
        -5.0, 0.15, 9.9999999, 2.5, 1e308, 5e-324,
    ];
    let mut div = Vec::new();
    for &v in vals {
        // ecvt: ndigit <= 0 (all clean now).
        for &n in &[0, -1, -3, -10, -100] {
            let h = tup(true, v, n, false);
            let f = tup(false, v, n, false);
            if h != f {
                div.push(format!("ecvt({v:e},{n}): host={h:?} fl={f:?}"));
            }
        }
        // fcvt ndigit == 0 (all magnitudes).
        {
            let h = tup(true, v, 0, true);
            let f = tup(false, v, 0, true);
            if h != f {
                div.push(format!("fcvt({v:e},0): host={h:?} fl={f:?}"));
            }
        }
        // fcvt NEGATIVE ndigit rounds the integer to the 10^|n| place (clamped to
        // one significant digit). Only diffed for |v| < 1e15: glibc's deprecated
        // fcvt is IMPRECISE beyond ~17 significant digits (e.g. fcvt(1e308,-1)
        // emits a non-exact expansion), whereas fl rounds the EXACT integer, so
        // huge magnitudes are a documented glibc-imprecision divergence where fl
        // is more correct (same class as the ecvt rounding surface).
        if v.abs() < 1e15 {
            for &n in &[-1, -2, -3, -5, -10, -100] {
                let h = tup(true, v, n, true);
                let f = tup(false, v, n, true);
                if h != f {
                    div.push(format!("fcvt({v:e},{n}): host={h:?} fl={f:?}"));
                }
            }
        }
    }
    assert!(
        div.is_empty(),
        "ecvt/fcvt ndigit<=0 divergences:\n{}",
        div.join("\n")
    );
}
