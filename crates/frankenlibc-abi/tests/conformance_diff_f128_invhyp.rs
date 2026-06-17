//! Differential gate: f128 inverse hyperbolics (asinh/acosh/atanh) match glibc
//! bit-for-bit on value + errno (bd-9z5ikz). All were garbage f64-ABI stubs.
//! The fixes port glibc's ldbl-128 `__asinhl`/`__ieee754_acoshl`/
//! `__ieee754_atanhl` verbatim (built on the byte-exact logl/log1pl/sqrt) →
//! byte-exact. asinh: no errno; acosh: EDOM x<1; atanh: ERANGE |x|=1, EDOM |x|>1.
#![cfg(target_os = "linux")]
#![feature(f128)]
#![allow(unsafe_code)]

use frankenlibc_abi::math_abi as ma;
use std::ffi::c_int;

unsafe extern "C" {
    fn asinhf128(x: f128) -> f128;
    fn acoshf128(x: f128) -> f128;
    fn atanhf128(x: f128) -> f128;
}
fn el() -> *mut c_int {
    unsafe { libc::__errno_location() }
}

fn values() -> Vec<f128> {
    let mut v: Vec<f128> = vec![
        0.0,
        -0.0f128,
        1.0,
        -1.0, // atanh pole, acosh=0
        2.0,
        -2.0,
        0.5,
        -0.5,
        1.5,
        0.9999f128,
        1.0001f128,
        100.0,
        -100.0,
        1e20f128,
        1e30f128,
        1e-20f128,
        -1e-20f128,
        1e-40f128,
        f128::from_bits(1),
        f128::from_bits(0x7fff_u128 << 112),                    // +inf
        f128::from_bits(0xffff_u128 << 112),                    // -inf
        f128::from_bits((0x7fff_u128 << 112) | (1u128 << 111)), // qNaN
    ];
    let mut q: i64 = -3000;
    while q <= 3000 {
        v.push(q as f128 / 1024.0);
        q += 1;
    }
    let mut st: u64 = 0x7a7a_b3b3_c1c1_d0d0;
    for _ in 0..5000 {
        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let hi = st;
        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let lo = st;
        let ef = (0x3f80 + (hi % 0x0120)) as u128;
        let mant = (((hi as u128) << 64) | lo as u128) & ((1u128 << 112) - 1);
        let sign = ((hi >> 23) & 1) as u128;
        v.push(f128::from_bits((sign << 127) | (ef << 112) | mant));
    }
    v
}

#[test]
fn f128_invhyp_matches_glibc() {
    let mut mism = Vec::new();
    for &x in &values() {
        for (name, g, f) in [
            ("asinh", asinhf128 as unsafe extern "C" fn(f128) -> f128, ma::asinhf128 as unsafe extern "C" fn(f128) -> f128),
            ("acosh", acoshf128, ma::acoshf128),
            ("atanh", atanhf128, ma::atanhf128),
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
        "f128 inverse hyperbolics diverged ({}):\n{}",
        mism.len(),
        mism.iter().take(30).cloned().collect::<Vec<_>>().join("\n")
    );
}
