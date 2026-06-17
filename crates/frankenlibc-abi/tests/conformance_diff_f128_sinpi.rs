//! Differential gate: C23 f128 sinpi/cospi/tanpi match glibc bit-for-bit on
//! value + errno (bd-9z5ikz). Were garbage f64-ABI stubs. The fixes mirror
//! glibc's s_sinpi/s_cospi/s_tanpi templates over the byte-exact sinl/cosl/tanl
//! → byte-exact.
#![cfg(target_os = "linux")]
#![feature(f128)]
#![allow(unsafe_code)]

use frankenlibc_abi::math_abi as ma;
use std::ffi::c_int;

unsafe extern "C" {
    fn sinpif128(x: f128) -> f128;
    fn cospif128(x: f128) -> f128;
    fn tanpif128(x: f128) -> f128;
}
fn el() -> *mut c_int {
    unsafe { libc::__errno_location() }
}

fn values() -> Vec<f128> {
    let mut v: Vec<f128> = vec![
        0.0, -0.0f128, 0.25, -0.25, 0.5, -0.5, 0.75, 1.0, -1.0, 1.5, 2.0, 2.5,
        0.125, 0.3333333333333333f128, 10.0, 100.5, 1e10f128, 1e30f128,
        1e-20f128, 1e-40f128,
        f128::from_bits(1),
        f128::from_bits(0x7fff_u128 << 112),
        f128::from_bits(0xffff_u128 << 112),
        f128::from_bits((0x7fff_u128 << 112) | (1u128 << 111)),
    ];
    let mut q: i64 = -4000;
    while q <= 4000 {
        v.push(q as f128 / 256.0);
        q += 1;
    }
    let mut st: u64 = 0x53_69_6e_50_69_31_32_38;
    for _ in 0..3000 {
        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let hi = st;
        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let lo = st;
        let ef = (0x3f00 + (hi % 0x0400)) as u128;
        let mant = (((hi as u128) << 64) | lo as u128) & ((1u128 << 112) - 1);
        let sign = ((hi >> 23) & 1) as u128;
        v.push(f128::from_bits((sign << 127) | (ef << 112) | mant));
    }
    v
}

#[test]
fn f128_pi_trig_matches_glibc() {
    let mut mism = Vec::new();
    for (name, g, f) in [
        ("sinpi", sinpif128 as unsafe extern "C" fn(f128) -> f128, ma::sinpif128 as unsafe extern "C" fn(f128) -> f128),
        ("cospi", cospif128, ma::cospif128),
        ("tanpi", tanpif128, ma::tanpif128),
    ] {
        for &x in &values() {
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
    assert!(mism.is_empty(), "f128 pi-trig diverged ({}):\n{}", mism.len(), mism.iter().take(40).cloned().collect::<Vec<_>>().join("\n"));
}
