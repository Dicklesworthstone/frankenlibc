//! Large-positive binary128 `lgamma` must not narrow through f64 before the
//! quad kernel runs.  The oracle is host libm in this process.
#![cfg(target_os = "linux")]
#![feature(f128)]
#![allow(unsafe_code)]

use frankenlibc_abi::math_abi as ma;
use std::ffi::{c_char, c_int, c_void};

unsafe extern "C" {
    fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    fn dlvsym(handle: *mut c_void, symbol: *const c_char, version: *const c_char) -> *mut c_void;
}

type Lgammaf128 = unsafe extern "C" fn(f128) -> f128;
type Lgammaf128R = unsafe extern "C" fn(f128, *mut c_int) -> f128;

const RTLD_NOW: c_int = 2;

fn host_lgammaf128() -> Lgammaf128 {
    unsafe {
        let libm = dlopen(c"libm.so.6".as_ptr(), RTLD_NOW);
        assert!(!libm.is_null(), "dlopen(libm.so.6) failed");
        let symbol = dlsym(libm, c"lgammaf128".as_ptr());
        assert!(!symbol.is_null(), "dlsym(lgammaf128) failed");
        // SAFETY: `lgammaf128` is resolved from libm with its exact C signature.
        std::mem::transmute(symbol)
    }
}

fn host_lgammaf128_r_finite() -> Lgammaf128R {
    unsafe {
        let libm = dlopen(c"libm.so.6".as_ptr(), RTLD_NOW);
        assert!(!libm.is_null(), "dlopen(libm.so.6) failed");
        let symbol = dlvsym(
            libm,
            c"__lgammaf128_r_finite".as_ptr(),
            c"GLIBC_2.26".as_ptr(),
        );
        assert!(
            !symbol.is_null(),
            "dlvsym(__lgammaf128_r_finite, GLIBC_2.26) failed"
        );
        // SAFETY: the requested GLIBC_2.26 symbol has the exact binary128 C signature.
        std::mem::transmute(symbol)
    }
}

fn host_lgammaf128_r() -> Lgammaf128R {
    unsafe {
        let libm = dlopen(c"libm.so.6".as_ptr(), RTLD_NOW);
        assert!(!libm.is_null(), "dlopen(libm.so.6) failed");
        let symbol = dlsym(libm, c"lgammaf128_r".as_ptr());
        assert!(!symbol.is_null(), "dlsym(lgammaf128_r) failed");
        // SAFETY: `lgammaf128_r` is resolved from libm with its exact C signature.
        std::mem::transmute(symbol)
    }
}

#[test]
fn lgammaf128_large_positive_values_match_glibc_bits() {
    let host = host_lgammaf128();
    let inputs = [
        f128::from_bits((16_383u128 + 1_024) << 112),
        f128::from_bits((16_383u128 + 2_048) << 112),
        f128::from_bits((16_383u128 + 4_096) << 112),
    ];

    for x in inputs {
        let expected = unsafe { host(x) };
        let actual = unsafe { ma::lgammaf128(x) };
        assert!(
            expected.is_finite(),
            "host lgammaf128({x:?}) should be finite"
        );
        assert!(
            actual.is_finite(),
            "fl lgammaf128({x:?}) narrowed to infinity"
        );
        assert!(
            actual.to_bits() == expected.to_bits(),
            "lgammaf128({x:?}) bits: fl={:#034x}, glibc={:#034x}",
            actual.to_bits(),
            expected.to_bits(),
        );
    }
}

#[test]
fn lgammaf128_r_preserves_fractional_bits_below_f64_precision() {
    let host = host_lgammaf128_r();
    // This is 1.5 + 2^-80. A f64-backed implementation rounds it to 1.5
    // before evaluating the function, so it cannot produce the host bits.
    let x = f128::from_bits((16_383u128 << 112) | (1u128 << 111) | (1u128 << 32));
    let mut host_sign = 0;
    let expected = unsafe { host(x, &mut host_sign) };
    let mut fl_sign = 0;
    let actual = unsafe { ma::lgammaf128_r(x, &mut fl_sign) };

    assert_eq!(
        actual.to_bits(),
        expected.to_bits(),
        "binary128 result bits"
    );
    assert_eq!(fl_sign, host_sign, "binary128 gamma sign");
}

#[test]
fn lgammaf128_r_accepts_a_null_sign_pointer_without_losing_quad_precision() {
    let host = host_lgammaf128();
    let x = f128::from_bits((16_383u128 << 112) | (1u128 << 111) | (1u128 << 32));
    let expected = unsafe { host(x) };
    let actual = unsafe { ma::lgammaf128_r(x, std::ptr::null_mut()) };

    assert_eq!(
        actual.to_bits(),
        expected.to_bits(),
        "the optional sign pointer must not make the binary128 call unsafe or narrow x"
    );
}

#[test]
fn lgammaf128_r_large_positive_preserves_positive_gamma_sign() {
    let x = f128::from_bits((16_383u128 + 1_024) << 112);
    let mut sign = 0;
    let actual = unsafe { ma::lgammaf128_r(x, &mut sign) };
    assert!(actual.is_finite());
    assert_eq!(sign, 1);
}

#[test]
fn lgammaf128_r_finite_alias_preserves_binary128_argument_and_sign() {
    let host = host_lgammaf128_r_finite();
    let x = f128::from_bits((16_383u128 + 1_024) << 112);
    let mut host_sign = 0;
    let expected = unsafe { host(x, &mut host_sign) };
    let mut fl_sign = 0;
    let actual = unsafe { ma::__lgammaf128_r_finite(x, &mut fl_sign) };

    assert!(
        expected.is_finite(),
        "host finite alias should not narrow x"
    );
    assert!(actual.is_finite(), "fl finite alias should not narrow x");
    assert_eq!(
        actual.to_bits(),
        expected.to_bits(),
        "__lgammaf128_r_finite binary128 result bits"
    );
    assert_eq!(fl_sign, host_sign, "gamma sign through finite alias");
}
