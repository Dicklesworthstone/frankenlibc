//! Differential gate: f128 log1pf128 (and its C23 alias logp1f128) match glibc
//! bit-for-bit on value + errno (bd-9z5ikz). Both were garbage f64-ABI stubs.
//! The fix ports glibc's ldbl-128 `__log1pl` verbatim (frexp + R/S form for
//! |e|>2, else x-.5x²+x³P/Q). Self-contained → byte-exact. ERANGE at -1, EDOM
//! below -1.
#![cfg(target_os = "linux")]
#![feature(f128)]
#![allow(unsafe_code)]

use frankenlibc_abi::math_abi as ma;
use std::ffi::c_int;

unsafe extern "C" {
    fn log1pf128(x: f128) -> f128;
    fn logp1f128(x: f128) -> f128;
}
fn el() -> *mut c_int {
    unsafe { libc::__errno_location() }
}

fn values() -> Vec<f128> {
    let mut v: Vec<f128> = vec![
        0.0,
        -0.0f128,
        1.0,
        -1.0, // pole
        -0.5,
        0.5,
        2.0,
        -2.0,    // < -1 → NaN
        -1.5,
        0.41421356f128, // ~sqrt2-1
        1e-30f128,
        -1e-30f128,
        1e-40f128,
        1e30f128,
        1e300f128,
        1e4000f128,
        f128::from_bits(1),
        f128::from_bits(0x7fff_u128 << 112),                    // +inf
        f128::from_bits(0xffff_u128 << 112),                    // -inf
        f128::from_bits((0x7fff_u128 << 112) | (1u128 << 111)), // qNaN
    ];
    let mut q: i64 = -1100;
    while q <= 4000 {
        v.push(q as f128 / 1024.0);
        q += 1;
    }
    let mut st: u64 = 0xabcd_1234_5678_9f0e;
    for _ in 0..5000 {
        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let hi = st;
        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let lo = st;
        let ef = (hi % 0x7fff) as u128;
        let mant = (((hi as u128) << 64) | lo as u128) & ((1u128 << 112) - 1);
        let sign = ((hi >> 23) & 1) as u128;
        v.push(f128::from_bits((sign << 127) | (ef << 112) | mant));
    }
    v
}

#[test]
fn f128_log1p_matches_glibc() {
    let mut mism = Vec::new();
    for &x in &values() {
        for (name, g, f) in [
            ("log1p", log1pf128 as unsafe extern "C" fn(f128) -> f128, ma::log1pf128 as unsafe extern "C" fn(f128) -> f128),
            ("logp1", logp1f128, ma::logp1f128),
        ] {
            unsafe { *el() = 0 };
            let gv = unsafe { g(x) }.to_bits();
            let ge = unsafe { *el() };
            unsafe { *el() = 0 };
            let fv = unsafe { f(x) }.to_bits();
            let fe = unsafe { *el() };
            if gv != fv || ge != fe {
                mism.push(format!("{name}({:#034x}): glibc=({gv:#034x},e={ge}) fl=({fv:#034x},e={fe})", x.to_bits()));
            }
        }
    }
    assert!(
        mism.is_empty(),
        "f128 log1p diverged ({}):\n{}",
        mism.len(),
        mism.iter().take(30).cloned().collect::<Vec<_>>().join("\n")
    );
}
