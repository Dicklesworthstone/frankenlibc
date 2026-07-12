//! Differential gate: f128 sinhf128 + coshf128 match glibc bit-for-bit on
//! value + errno (bd-9z5ikz). Both were garbage f64-ABI stubs. The fixes port
//! glibc's ldbl-128 `__ieee754_coshl`/`__ieee754_sinhl` verbatim (range-split
//! via expm1l/expl). Built on the byte-exact expm1l_f128 + expl_f128 →
//! byte-exact. ERANGE on overflow.
#![cfg(target_os = "linux")]
#![feature(f128)]
#![allow(unsafe_code)]

use frankenlibc_abi::math_abi as ma;
use std::ffi::c_int;

unsafe extern "C" {
    fn coshf128(x: f128) -> f128;
    fn sinhf128(x: f128) -> f128;
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
        0.5,
        -0.5,
        0.34,
        0.35, // around 0.5*ln2
        22.0,
        40.0,
        100.0,
        11356.0,
        11357.0, // overflow
        11356.375,
        1e-20f128,
        -1e-20f128,
        1e-40f128,
        f128::from_bits(1),
        f128::from_bits(0x7fff_u128 << 112), // +inf
        f128::from_bits(0xffff_u128 << 112), // -inf
        f128::from_bits((0x7fff_u128 << 112) | (1u128 << 111)), // qNaN
    ];
    let mut q: i64 = -11500;
    while q <= 11500 {
        v.push(q as f128 / 32.0);
        q += 13;
    }
    let mut st: u64 = 0x9988_7766_5544_3322;
    for _ in 0..5000 {
        st = st
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let hi = st;
        st = st
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let lo = st;
        let ef = (0x3fb0 + (hi % 0x0060)) as u128;
        let mant = (((hi as u128) << 64) | lo as u128) & ((1u128 << 112) - 1);
        let sign = ((hi >> 23) & 1) as u128;
        v.push(f128::from_bits((sign << 127) | (ef << 112) | mant));
    }
    v
}

#[test]
fn f128_sinhcosh_matches_glibc() {
    let mut mism = Vec::new();
    for &x in &values() {
        for (name, g, f) in [
            (
                "cosh",
                coshf128 as unsafe extern "C" fn(f128) -> f128,
                ma::coshf128 as unsafe extern "C" fn(f128) -> f128,
            ),
            ("sinh", sinhf128, ma::sinhf128),
        ] {
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
        "f128 sinh/cosh diverged ({}):\n{}",
        mism.len(),
        mism.iter().take(30).cloned().collect::<Vec<_>>().join("\n")
    );
}
