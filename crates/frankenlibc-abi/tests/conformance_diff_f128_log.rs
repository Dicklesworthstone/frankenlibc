//! Differential gate: f128 logf128 matches glibc bit-for-bit on value + errno
//! (bd-9z5ikz). logf128 was a garbage f64-ABI stub. The fix ports glibc's
//! ldbl-128 `__ieee754_logl` verbatim (frexp + 92-entry log(t)-(t-1) table +
//! degree-15 Cody&Waite series + e·ln2 split) plus the log errno wrapper
//! (ERANGE pole at 0, EDOM for x<0). Self-contained → byte-exact. The other
//! root of the quad libm (with exp).
#![cfg(target_os = "linux")]
#![feature(f128)]
#![allow(unsafe_code)]

use frankenlibc_abi::math_abi as ma;
use std::ffi::c_int;

unsafe extern "C" {
    fn logf128(x: f128) -> f128;
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
        2.0,
        0.5,
        0.703125,
        1.40625,
        0.9921875,
        1.0078125,
        0.99,
        1.01,
        std::f64::consts::E as f128,
        10.0,
        1e30f128,
        1e-30f128,
        1e300f128,
        1e4000f128,
        1e-4000f128,
        f128::MIN_POSITIVE,
        f128::MAX,
        f128::from_bits(1),                  // smallest subnormal
        f128::from_bits(0x7fff_u128 << 112), // +inf
        f128::from_bits(0xffff_u128 << 112), // -inf
        f128::from_bits((0x7fff_u128 << 112) | (1u128 << 111)), // qNaN
    ];
    // Dense sweep near 1 (table-skip interval + boundaries) and across decades.
    let mut q: i64 = 800;
    while q <= 1300 {
        v.push((q as f128) / 1024.0);
        q += 1;
    }
    // PRNG across the full positive exponent range, both signs of input.
    let mut st: u64 = 0x0123_4567_89ab_cdef;
    for _ in 0..6000 {
        st = st
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let hi = st;
        st = st
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let lo = st;
        let ef = (hi % 0x7fff) as u128;
        let mant = (((hi as u128) << 64) | lo as u128) & ((1u128 << 112) - 1);
        let sign = ((hi >> 23) & 1) as u128;
        v.push(f128::from_bits((sign << 127) | (ef << 112) | mant));
    }
    v
}

#[test]
fn f128_log_matches_glibc() {
    let mut mism = Vec::new();
    let mut n = 0u64;
    for &x in &values() {
        unsafe { *el() = 0 };
        let g = unsafe { logf128(x) }.to_bits();
        let ge = unsafe { *el() };
        unsafe { *el() = 0 };
        let f = unsafe { ma::logf128(x) }.to_bits();
        let fe = unsafe { *el() };
        n += 1;
        if g != f || ge != fe {
            mism.push(format!(
                "log({:#034x}): glibc=({g:#034x},e={ge}) fl=({f:#034x},e={fe})",
                x.to_bits()
            ));
        }
    }
    assert!(
        mism.is_empty(),
        "logf128 diverged ({}/{}):\n{}",
        mism.len(),
        n,
        mism.iter().take(30).cloned().collect::<Vec<_>>().join("\n")
    );
}
