//! Differential gate: the C23 f128 *pi inverse-trig functions
//! (atanpi/asinpi/acospi/atan2pi) match glibc bit-for-bit on value + errno
//! (bd-9z5ikz). All were garbage f64-ABI stubs. The fix mirrors glibc's generic
//! templates exactly: f(x)/M_PI (f = the byte-exact f128 atan/asin/acos/atan2)
//! with the template's EDOM/ERANGE and the away-from-zero clamps (±0.5 for
//! atan/asin-pi, [.,1]/±1 for acos/atan2-pi). M_PI is the correctly-rounded
//! f128 pi (== glibc's divisor).
#![cfg(target_os = "linux")]
#![feature(f128)]
#![allow(unsafe_code)]

use frankenlibc_abi::math_abi as ma;
use std::ffi::c_int;

unsafe extern "C" {
    fn atanpif128(x: f128) -> f128;
    fn asinpif128(x: f128) -> f128;
    fn acospif128(x: f128) -> f128;
    fn atan2pif128(y: f128, x: f128) -> f128;
}
fn el() -> *mut c_int {
    unsafe { libc::__errno_location() }
}

fn vals() -> Vec<f128> {
    let mut v: Vec<f128> = vec![
        0.0,
        -0.0f128,
        1.0,
        -1.0,
        0.5,
        -0.5,
        0.25,
        2.0,
        -2.0,
        1.5f128,
        100.0,
        1e-30f128,
        1e30f128,
        f128::from_bits(1),
        f128::from_bits(0x7fff_u128 << 112),
        f128::from_bits(0xffff_u128 << 112),
        f128::from_bits((0x7fff_u128 << 112) | (1u128 << 111)),
    ];
    let mut q: i64 = -1100;
    while q <= 1100 {
        v.push((q as f128) / 1024.0);
        q += 40;
    }
    let mut st: u64 = 0x1357_2468_acef_bd09;
    for _ in 0..400 {
        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let hi = st;
        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let lo = st;
        let ef = (0x3e80 + (hi % 0x0200)) as u128;
        let mant = (((hi as u128) << 64) | lo as u128) & ((1u128 << 112) - 1);
        let sign = ((hi >> 23) & 1) as u128;
        v.push(f128::from_bits((sign << 127) | (ef << 112) | mant));
    }
    v
}

fn check1(name: &str, g: unsafe extern "C" fn(f128) -> f128, f: unsafe extern "C" fn(f128) -> f128, mism: &mut Vec<String>) {
    for &x in &vals() {
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

#[test]
fn f128_pi_inverse_trig_matches_glibc() {
    let mut mism = Vec::new();
    check1("atanpi", atanpif128, ma::atanpif128, &mut mism);
    check1("asinpi", asinpif128, ma::asinpif128, &mut mism);
    check1("acospi", acospif128, ma::acospif128, &mut mism);
    // atan2pi over pairs
    let v = vals();
    for &y in &v {
        for &x in &v {
            unsafe { *el() = 0 };
            let gv = unsafe { atan2pif128(y, x) }.to_bits();
            let ge = unsafe { *el() };
            unsafe { *el() = 0 };
            let fv = unsafe { ma::atan2pif128(y, x) }.to_bits();
            let fe = unsafe { *el() };
            if gv != fv || ge != fe {
                mism.push(format!("atan2pi(y={:#034x},x={:#034x}): glibc=({gv:#034x},e={ge}) fl=({fv:#034x},e={fe})", y.to_bits(), x.to_bits()));
            }
        }
    }
    assert!(
        mism.is_empty(),
        "f128 *pi inverse-trig diverged ({}):\n{}",
        mism.len(),
        mism.iter().take(30).cloned().collect::<Vec<_>>().join("\n")
    );
}
