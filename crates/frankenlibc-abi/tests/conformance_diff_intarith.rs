#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc div/abs oracle

//! Differential gate for the integer div/abs family (bd-wfx8gn): div / ldiv /
//! lldiv / abs / labs / llabs / imaxabs vs host glibc. Only imaxdiv and the
//! uabs family had gates before. Exercises C99 truncation-toward-zero with
//! mixed operand signs and the INT_MIN/INT64_MIN absolute-value edge (where
//! glibc wraps to the same negative value and fl uses wrapping_abs — pinning
//! this guards against a future refactor to a panicking `.abs()`). No mocks.
//!
//! NOTE: div(INT_MIN, -1) etc. are excluded — that quotient is not
//! representable and raises SIGFPE on x86 in BOTH implementations (UB), so it
//! is not a value to compare.

use std::ffi::{c_int, c_long, c_longlong};

use frankenlibc_abi::stdlib_abi as fl;

// glibc div_t / ldiv_t / lldiv_t are small all-integer structs returned by
// value (in registers per the SysV ABI); the libc crate doesn't bind the
// struct-returning div*/ functions, so declare them with matching repr(C)
// layouts.
#[repr(C)]
struct GDiv {
    quot: c_int,
    rem: c_int,
}
#[repr(C)]
struct GLdiv {
    quot: c_long,
    rem: c_long,
}
#[repr(C)]
struct GLldiv {
    quot: c_longlong,
    rem: c_longlong,
}

unsafe extern "C" {
    fn div(numer: c_int, denom: c_int) -> GDiv;
    fn ldiv(numer: c_long, denom: c_long) -> GLdiv;
    fn lldiv(numer: c_longlong, denom: c_longlong) -> GLldiv;
    fn abs(n: c_int) -> c_int;
    fn labs(n: c_long) -> c_long;
    fn llabs(n: c_longlong) -> c_longlong;
    fn imaxabs(n: i64) -> i64;
}

#[test]
fn div_matches_glibc() {
    let cases: &[(c_int, c_int)] = &[
        (7, 2),
        (-7, 2),
        (7, -2),
        (-7, -2),
        (0, 5),
        (1, 1),
        (10, 3),
        (-10, 3),
        (i32::MAX, 7),
        (i32::MIN, 7),
        (i32::MIN, 2),
        (i32::MAX, -3),
        (i32::MIN, 1),
        (5, 1),
        (123456, 789),
        (-123456, 789),
    ];
    for &(num, den) in cases {
        let g = unsafe { div(num, den) };
        let f = unsafe { fl::div(num, den) };
        assert_eq!(
            (f.quot, f.rem),
            (g.quot, g.rem),
            "div({num},{den}): fl=({},{}) glibc=({},{})",
            f.quot,
            f.rem,
            g.quot,
            g.rem
        );
        // C99: quot truncates toward zero, rem has the sign of the dividend,
        // and quot*den + rem == num.
        assert_eq!(
            f.quot * den + f.rem,
            num,
            "div identity broken for ({num},{den})"
        );
    }
}

#[test]
fn ldiv_lldiv_match_glibc() {
    let lcases: &[(c_long, c_long)] = &[
        (7, 2),
        (-7, 2),
        (7, -2),
        (-7, -2),
        (0, 9),
        (i64::MAX, 11),
        (i64::MIN, 11),
        (i64::MIN, 1),
        (i64::MAX, -13),
    ];
    for &(num, den) in lcases {
        let g = unsafe { ldiv(num, den) };
        let f = unsafe { fl::ldiv(num, den) };
        assert_eq!((f.quot, f.rem), (g.quot, g.rem), "ldiv({num},{den})");
    }
    for &(num, den) in lcases {
        let n = num as c_longlong;
        let d = den as c_longlong;
        let g = unsafe { lldiv(n, d) };
        let f = unsafe { fl::lldiv(n, d) };
        assert_eq!((f.quot, f.rem), (g.quot, g.rem), "lldiv({n},{d})");
    }
}

#[test]
fn abs_family_matches_glibc_including_int_min() {
    for &n in &[0, 1, -1, 5, -5, i32::MAX, i32::MIN, i32::MIN + 1] {
        let g = unsafe { abs(n) };
        let f = unsafe { fl::abs(n) };
        assert_eq!(f, g, "abs({n}): fl={f} glibc={g}");
    }
    // INT_MIN wraps to INT_MIN in both (UB in C; glibc + fl both wrap).
    assert_eq!(
        unsafe { fl::abs(i32::MIN) },
        i32::MIN,
        "abs(INT_MIN) must wrap, not panic"
    );

    for &n in &[0i64, 1, -1, i64::MAX, i64::MIN, i64::MIN + 1, -123456789] {
        let g = unsafe { labs(n) };
        let f = unsafe { fl::labs(n) };
        assert_eq!(f, g, "labs({n})");
        let gll = unsafe { llabs(n) };
        let fll = unsafe { fl::llabs(n) };
        assert_eq!(fll, gll, "llabs({n})");
        let gi = unsafe { imaxabs(n) };
        let fi = unsafe { fl::imaxabs(n) };
        assert_eq!(fi, gi, "imaxabs({n})");
    }
    assert_eq!(
        unsafe { fl::labs(i64::MIN) },
        i64::MIN,
        "labs(LONG_MIN) must wrap"
    );
    assert_eq!(
        unsafe { fl::imaxabs(i64::MIN) },
        i64::MIN,
        "imaxabs(INTMAX_MIN) must wrap"
    );
}
