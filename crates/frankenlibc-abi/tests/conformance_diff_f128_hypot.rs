//! Differential gate: f128 hypotf128 + cabsf128 match glibc bit-for-bit
//! (bd-9z5ikz). Both were garbage stubs declaring the f64 ABI; the fix ports
//! glibc's ldbl-128 `__ieee754_hypotl` (Borges' MyHypot3, arXiv:1904.09481)
//! verbatim — scale huge/tiny/widely-varying operands, run the f128 sqrt +
//! correctly-rounded correction kernel, unscale — so the value is byte-exact.
//! hypotf128 also sets ERANGE on overflow (glibc's errno wrapper); cabsf128
//! uses the finite alias (no errno). Underflow flag (subnormal results) is not
//! gated — value + errno are the checked contract.
#![cfg(target_os = "linux")]
#![feature(f128)]
#![allow(unsafe_code)]

use frankenlibc_abi::math_abi::{self as ma, CFloat128Complex as C};
use std::ffi::c_int;

unsafe extern "C" {
    fn hypotf128(x: f128, y: f128) -> f128;
    fn cabsf128(z: C) -> f128;
}
fn el() -> *mut c_int {
    unsafe { libc::__errno_location() }
}

fn values() -> Vec<f128> {
    let mut v: Vec<f128> = vec![
        0.0,
        -0.0f128,
        1.0,
        -1.0,
        3.0,
        4.0,
        5.0, // 3-4-5
        2.0,
        0.5,
        1e-30f128,
        1e30f128,
        1e300f128,
        1e-300f128,
        1e4000f128,
        1e-4000f128,
        f128::MIN_POSITIVE,
        f128::MAX,
        f128::from_bits(1),                                     // smallest subnormal
        f128::from_bits(0x7fff_u128 << 112),                    // +inf
        f128::from_bits(0xffff_u128 << 112),                    // -inf
        f128::from_bits((0x7fff_u128 << 112) | (1u128 << 111)), // qNaN
    ];
    let mut st: u64 = 0xdead_beef_0bad_f00d;
    for _ in 0..120 {
        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let hi = st;
        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let lo = st;
        let ef = (hi % 0x7fff) as u128;
        let mant = (((hi as u128) << 64) | lo as u128) & ((1u128 << 112) - 1);
        let sign = ((hi >> 13) & 1) as u128;
        v.push(f128::from_bits((sign << 127) | (ef << 112) | mant));
    }
    v
}

#[test]
fn f128_hypot_matches_glibc() {
    let vals = values();
    let mut mism = Vec::new();
    let mut n = 0u64;
    for &x in &vals {
        for &y in &vals {
            // hypot (value + errno)
            unsafe { *el() = 0 };
            let g = unsafe { hypotf128(x, y) }.to_bits();
            let ge = unsafe { *el() };
            unsafe { *el() = 0 };
            let f = unsafe { ma::hypotf128(x, y) }.to_bits();
            let fe = unsafe { *el() };
            n += 1;
            if g != f || ge != fe {
                mism.push(format!(
                    "hypot({:#034x},{:#034x}): glibc=({g:#034x},e={ge}) fl=({f:#034x},e={fe})",
                    x.to_bits(),
                    y.to_bits()
                ));
            }
            // cabs (value)
            let z = C { re: x, im: y };
            let gc = unsafe { cabsf128(z) }.to_bits();
            let fc = unsafe { ma::cabsf128(z) }.to_bits();
            if gc != fc {
                mism.push(format!(
                    "cabs({:#034x},{:#034x}): glibc={gc:#034x} fl={fc:#034x}",
                    x.to_bits(),
                    y.to_bits()
                ));
            }
        }
    }
    assert!(
        mism.is_empty(),
        "f128 hypot/cabs diverged ({}/{}):\n{}",
        mism.len(),
        n,
        mism.iter().take(30).cloned().collect::<Vec<_>>().join("\n")
    );
}
