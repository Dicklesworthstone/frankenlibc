//! Large-positive binary128 `lgamma` must not narrow through f64 before the
//! quad kernel runs.  The oracle is host libm in this process.
#![cfg(target_os = "linux")]
#![feature(f128)]
#![allow(unsafe_code)]

use frankenlibc_abi::math_abi as ma;
use std::ffi::{c_char, c_int, c_void};

type Lgammaf128 = unsafe extern "C" fn(f128) -> f128;

const RTLD_NOW: c_int = 2;

unsafe extern "C" {
    fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}

fn host_lgammaf128() -> Lgammaf128 {
    unsafe {
        let libm = dlopen(c"libm.so.6".as_ptr(), RTLD_NOW);
        assert!(!libm.is_null(), "dlopen(libm.so.6) failed");
        let symbol = dlsym(libm, c"lgammaf128".as_ptr());
        assert!(!symbol.is_null(), "dlsym(lgammaf128) failed");
        std::mem::transmute(symbol)
    }
}

#[test]
fn lgammaf128_large_positive_values_remain_finite_and_track_glibc() {
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
        let relative_error = ((actual - expected) / expected).abs();
        assert!(
            relative_error <= 32.0 * f128::EPSILON,
            "lgammaf128({x:?}): fl={actual:?}, glibc={expected:?}, rel={relative_error:?}"
        );
    }
}

#[test]
fn lgammaf128_r_large_positive_preserves_positive_gamma_sign() {
    let x = f128::from_bits((16_383u128 + 1_024) << 112);
    let mut sign = 0;
    let actual = unsafe { ma::lgammaf128_r(x, &mut sign) };
    assert!(actual.is_finite());
    assert_eq!(sign, 1);
}
