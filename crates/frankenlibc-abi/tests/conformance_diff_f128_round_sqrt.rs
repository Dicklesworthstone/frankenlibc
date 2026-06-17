//! Differential gate: f128 rounding family + sqrt + fma match glibc bit-for-bit
//! (bd-9z5ikz batch 2). These had the broken f64 arg-ABI; now they use the
//! IEEE-correct f128 intrinsics (trunc/floor/ceil/round/round_ties_even/sqrt/fma).
#![cfg(target_os = "linux")]
#![feature(f128)]
#![allow(unsafe_code)]

use frankenlibc_abi::math_abi as ma;
use std::ffi::c_int;

unsafe extern "C" {
    fn truncf128(x: f128) -> f128;
    fn floorf128(x: f128) -> f128;
    fn ceilf128(x: f128) -> f128;
    fn roundf128(x: f128) -> f128;
    fn roundevenf128(x: f128) -> f128;
    fn sqrtf128(x: f128) -> f128;
    fn fmaf128(x: f128, y: f128, z: f128) -> f128;
}

fn errno_loc() -> *mut c_int {
    unsafe { libc::__errno_location() }
}

fn values() -> Vec<f128> {
    let mut v: Vec<f128> = vec![
        0.0, -0.0f128, 0.5, -0.5, 1.5, 2.5, -2.5, 3.5, 1.0, -1.0, 2.75, -2.75, 0.4999f128,
        0.50001f128, 1e30f128, -1e30f128, 1e-30f128, 123456.789f128, -987654.321f128, 2.0, 16.0,
        f128::from_bits(0x7fff_u128 << 112),                    // +inf
        f128::from_bits(0xffff_u128 << 112),                    // -inf
        f128::from_bits((0x7fff_u128 << 112) | (1u128 << 111)), // qNaN
        f128::from_bits(1),                                     // smallest subnormal
        f128::from_bits(1u128 << 112),                          // smallest normal
    ];
    let mut st: u64 = 0x0123_4567_89ab_cdef;
    for _ in 0..50 {
        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let hi = st;
        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        // bias exponent toward a moderate range so rounding/fma are exercised
        let ef = 0x3f00u128 + (hi as u128 % 0x180);
        let mant = (((hi as u128) << 64) | st as u128) & ((1u128 << 112) - 1);
        let sign = (st >> 5) as u128 & 1;
        v.push(f128::from_bits((sign << 127) | (ef << 112) | mant));
    }
    v
}

#[test]
fn f128_round_sqrt_fma_match_glibc() {
    let vals = values();
    let mut mism = Vec::new();
    macro_rules! ck1 {
        ($name:literal, $g:path, $f:path) => {
            for &x in &vals {
                let g = unsafe { $g(x) }.to_bits();
                let f = unsafe { $f(x) }.to_bits();
                if g != f {
                    mism.push(format!("{} x={:#034x}: glibc={g:#034x} fl={f:#034x}", $name, x.to_bits()));
                }
            }
        };
    }
    ck1!("trunc", truncf128, ma::truncf128);
    ck1!("floor", floorf128, ma::floorf128);
    ck1!("ceil", ceilf128, ma::ceilf128);
    ck1!("round", roundf128, ma::roundf128);
    ck1!("roundeven", roundevenf128, ma::roundevenf128);

    // sqrt: value + errno (EDOM on negative).
    for &x in &vals {
        unsafe { *errno_loc() = 0 };
        let g = unsafe { sqrtf128(x) }.to_bits();
        let ge = unsafe { *errno_loc() };
        unsafe { *errno_loc() = 0 };
        let f = unsafe { ma::sqrtf128(x) }.to_bits();
        let fe = unsafe { *errno_loc() };
        if g != f || ge != fe {
            mism.push(format!("sqrt x={:#034x}: glibc=({g:#034x},e={ge}) fl=({f:#034x},e={fe})", x.to_bits()));
        }
    }

    // fma over triples (value + errno).
    for (i, &x) in vals.iter().enumerate() {
        let y = vals[(i + 7) % vals.len()];
        let z = vals[(i + 13) % vals.len()];
        unsafe { *errno_loc() = 0 };
        let g = unsafe { fmaf128(x, y, z) }.to_bits();
        let ge = unsafe { *errno_loc() };
        unsafe { *errno_loc() = 0 };
        let f = unsafe { ma::fmaf128(x, y, z) }.to_bits();
        let fe = unsafe { *errno_loc() };
        if g != f || ge != fe {
            mism.push(format!("fma {:#034x},{:#034x},{:#034x}: glibc=({g:#034x},e={ge}) fl=({f:#034x},e={fe})", x.to_bits(), y.to_bits(), z.to_bits()));
        }
    }

    assert!(mism.is_empty(), "f128 round/sqrt/fma diverged ({}):\n{}", mism.len(), mism.iter().take(25).cloned().collect::<Vec<_>>().join("\n"));
}
