#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc sscanf oracle

//! `scanf` hex-float parsing parity vs host glibc (bd-2g7oyh.NEW), focused on
//! the subnormal / extreme-exponent range. fl scaled the significand with
//! `2_f64.powi(exp)`, which for a large negative exponent evaluates 1/2^|exp|
//! and overflows 2^1074 to inf — so the smallest subnormal `0x1p-1074`
//! (5e-324) wrongly underflowed to 0. The fix uses `libm::ldexp`. This gate
//! compares the exact bit pattern (and `%n` consumed count) over the whole
//! `0x1.hp±e` grammar, with emphasis on the subnormal boundary.

use frankenlibc_abi::stdio_abi as fl;
use std::ffi::{CString, c_char};

unsafe extern "C" {
    fn sscanf(s: *const c_char, f: *const c_char, ...) -> i32;
}

fn run(eng: u8, inp: &str) -> (i32, u64, i64) {
    let ci = CString::new(inp).unwrap();
    let cf = CString::new("%lf%n").unwrap();
    let mut v = 0f64;
    let mut n: i32 = -1;
    let r = if eng == 0 {
        unsafe { fl::sscanf(ci.as_ptr(), cf.as_ptr(), &mut v, &mut n) }
    } else {
        unsafe { sscanf(ci.as_ptr(), cf.as_ptr(), &mut v, &mut n) }
    };
    (r, v.to_bits(), n as i64)
}

fn check(inp: &str) {
    let a = run(0, inp);
    let b = run(1, inp);
    assert_eq!(a, b, "sscanf({inp:?}, \"%lf\"): fl={a:x?} glibc={b:x?}");
}

#[test]
fn scanf_hexfloat_matches_glibc() {
    let cases = [
        // Subnormal boundary — the regression.
        "0x1p-1074",
        "0x1p-1073",
        "0x1.8p-1074",
        "0x1p-1075",
        "0x3p-1075",
        "0x1p-1076",
        "0x2p-1075",
        "0x1p-2000",
        "-0x1p-1074",
        "0x1.55555p-1070",
        // Around DBL_MIN (smallest normal) and into subnormals.
        "0x1p-1022",
        "0x1.fffffffffffffp-1023",
        "0x0.8p-1021",
        "0x1.0000000000001p-1022",
        "0x1p-1023",
        // Normal range, specials, rounding.
        "0x1.8p3",
        "0x1p-2",
        "0X1.Fp+4",
        "0x.8p1",
        "0x1.p0",
        "-0x1.8p3",
        "0x0p0",
        "0xAp0",
        "0x1.000002p0",
        "0x1.fffffffffffffp1023",
        "0x1p1024",
        "-0x0p0",
        "0x10p-4",
        "0X.1P4",
        // Matching failures / partial tokens.
        "0x1.8p",
        "0x1p",
        "0x",
        "0xg",
        "0x1.8p3xyz",
        "  0x1.8p3",
    ];
    for c in cases {
        check(c);
    }
}
