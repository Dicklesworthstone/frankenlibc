#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc remquo/remquof oracle

//! Differential gate for remquo/remquof (bd-c61ow2) — only a scratch probe
//! existed. remquo(x,y,*quo) returns the round-to-nearest remainder (like
//! remainder()) and stores into *quo at least the low 3 bits of the integer
//! quotient round(x/y), carrying the SIGN of x/y. Both the remainder bits and
//! the *quo value (low bits + sign) are easy to get wrong. fl must match host
//! glibc bit-for-bit on the remainder and exactly on *quo. No mocks.

use std::ffi::c_int;

unsafe extern "C" {
    fn remquo(x: f64, y: f64, quo: *mut c_int) -> f64;
    fn remquof(x: f32, y: f32, quo: *mut c_int) -> f32;
}

// glibc guarantees only the low 3 bits of |quotient| (plus sign); mask before
// comparing so we don't depend on how many extra bits each impl happens to keep.
fn quo_key(q: c_int) -> c_int {
    let mag = (q.unsigned_abs() & 0x7) as c_int;
    if q < 0 { -mag } else { mag }
}

#[test]
fn remquo_matches_glibc() {
    let vals = [
        0.0f64,
        -0.0,
        1.0,
        -1.0,
        2.5,
        -2.5,
        3.0,
        5.0,
        -5.0,
        7.5,
        10.0,
        0.1,
        -0.1,
        100.0,
        1234.5,
        -1234.5,
        1e10,
        1e-10,
        0.3333333333333333,
        2.0,
        4.0,
        8.0,
    ];
    for &x in &vals {
        for &y in &vals {
            if y == 0.0 {
                continue; // domain case: rem is NaN, *quo unspecified
            }
            let mut gq: c_int = 0x5a5a;
            let mut fq: c_int = 0x5a5a;
            let gr = unsafe { remquo(x, y, &mut gq) };
            let fr = unsafe { frankenlibc_abi::math_abi::remquo(x, y, &mut fq) };
            assert_eq!(fr.to_bits(), gr.to_bits(), "remquo({x},{y}) remainder bits");
            assert_eq!(
                quo_key(fq),
                quo_key(gq),
                "remquo({x},{y}) quo (low3+sign) fl={fq} glibc={gq}"
            );
        }
    }
}

#[test]
fn remquof_matches_glibc() {
    let vals = [
        0.0f32, -0.0, 1.0, -1.0, 2.5, -2.5, 3.0, 5.0, -5.0, 7.5, 10.0, 0.25, 100.0, -100.0, 1e6,
        2.0,
    ];
    for &x in &vals {
        for &y in &vals {
            if y == 0.0 {
                continue;
            }
            let mut gq: c_int = 0x5a5a;
            let mut fq: c_int = 0x5a5a;
            let gr = unsafe { remquof(x, y, &mut gq) };
            let fr = unsafe { frankenlibc_abi::math_abi::remquof(x, y, &mut fq) };
            assert_eq!(
                fr.to_bits(),
                gr.to_bits(),
                "remquof({x},{y}) remainder bits"
            );
            assert_eq!(
                quo_key(fq),
                quo_key(gq),
                "remquof({x},{y}) quo fl={fq} glibc={gq}"
            );
        }
    }
}
