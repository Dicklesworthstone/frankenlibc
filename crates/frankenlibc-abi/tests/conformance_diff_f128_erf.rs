//! Differential gate: f128 erff128 + erfcf128 match glibc bit-for-bit
//! (bd-9z5ikz). Both were garbage f64-ABI stubs. The fix ports glibc's ldbl-128
//! __erfl/__erfcl verbatim (interval-dispatched rational approximations on the
//! erf_tables coefficients, neval/deval, + expl). Self-contained → byte-exact.
#![cfg(target_os = "linux")]
#![feature(f128)]
#![allow(unsafe_code)]

use frankenlibc_abi::math_abi as ma;
use std::ffi::c_int;

unsafe extern "C" {
    fn erff128(x: f128) -> f128;
    fn erfcf128(x: f128) -> f128;
}
fn el() -> *mut c_int {
    unsafe { libc::__errno_location() }
}

fn values() -> Vec<f128> {
    let mut v: Vec<f128> = vec![
        0.0,
        -0.0f128,
        0.25,
        0.5,
        0.875,
        1.0,
        1.25,
        2.0,
        5.0,
        9.0,
        16.0,
        100.0,
        107.0,
        108.0,
        -0.5,
        -2.0,
        -9.0,
        -16.0,
        -107.0,
        1e-20f128,
        1e-40f128,
        f128::from_bits(1),
        f128::from_bits(0x7fff_u128 << 112),
        f128::from_bits(0xffff_u128 << 112),
        f128::from_bits((0x7fff_u128 << 112) | (1u128 << 111)),
    ];
    // dense sweep across all the interval boundaries (k/8, 1.25, etc.)
    let mut q: i64 = -11000;
    while q <= 11000 {
        v.push(q as f128 / 1000.0);
        q += 1;
    }
    let mut st: u64 = 0x65_72_66_31_32_38_ff_aa;
    for _ in 0..5000 {
        st = st
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let hi = st;
        st = st
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let lo = st;
        let ef = (0x3f80 + (hi % 0x0090)) as u128;
        let mant = (((hi as u128) << 64) | lo as u128) & ((1u128 << 112) - 1);
        let sign = ((hi >> 23) & 1) as u128;
        v.push(f128::from_bits((sign << 127) | (ef << 112) | mant));
    }
    v
}

#[test]
fn f128_erf_matches_glibc() {
    let mut mism = Vec::new();
    for (name, g, f) in [
        (
            "erf",
            erff128 as unsafe extern "C" fn(f128) -> f128,
            ma::erff128 as unsafe extern "C" fn(f128) -> f128,
        ),
        ("erfc", erfcf128, ma::erfcf128),
    ] {
        for &x in &values() {
            unsafe { *el() = 0 };
            let gv = unsafe { g(x) }.to_bits();
            let ge = unsafe { *el() };
            unsafe { *el() = 0 };
            let fv = unsafe { f(x) }.to_bits();
            let fe = unsafe { *el() };
            if gv != fv || ge != fe {
                mism.push(format!(
                    "{name}({:#034x}): glibc=({gv:#034x},e={ge}) fl=({fv:#034x},e={fe})",
                    x.to_bits()
                ));
            }
        }
    }
    assert!(
        mism.is_empty(),
        "erf/erfc f128 diverged ({}):\n{}",
        mism.len(),
        mism.iter().take(40).cloned().collect::<Vec<_>>().join("\n")
    );
}
