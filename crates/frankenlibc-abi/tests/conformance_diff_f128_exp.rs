//! Differential gate: f128 expf128 matches glibc bit-for-bit on value + errno
//! (bd-9z5ikz). expf128 was a garbage f64-ABI stub. The fix ports glibc's
//! ldbl-128 `__ieee754_expl` verbatim — two-stage table argument reduction
//! (t_expl.h, 930 entries) + degree-7 Chebyshev poly + exponent-field
//! recombination — plus the exp errno wrapper (ERANGE on overflow/underflow).
//! Uses only algebraic f128 ops + the table, so byte-exact in default rounding.
//! This is the foundation of the remaining f128 transcendentals (log/pow/sinh…).
#![cfg(target_os = "linux")]
#![feature(f128)]
#![allow(unsafe_code)]

use frankenlibc_abi::math_abi as ma;
use std::ffi::c_int;

unsafe extern "C" {
    fn expf128(x: f128) -> f128;
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
        -2.0,
        0.5,
        -0.5,
        0.6931471805599453f128, // ~ln2
        10.0,
        -10.0,
        100.0,
        -100.0,
        709.0,
        -709.0,
        11356.0,                 // near himark
        11357.0,                 // over → overflow
        11356.523406294143949f128,
        -11433.0,                // near lomark
        -11434.0,                // under → 0
        1e-30f128,
        -1e-30f128,
        f128::from_bits(1),                                     // smallest subnormal
        f128::MIN_POSITIVE,
        f128::from_bits(0x7fff_u128 << 112),                    // +inf → +inf
        f128::from_bits(0xffff_u128 << 112),                    // -inf → 0
        f128::from_bits((0x7fff_u128 << 112) | (1u128 << 111)), // qNaN
    ];
    // Dense sweep across the whole finite domain incl over/underflow edges.
    let mut q: i64 = -11600;
    while q <= 11500 {
        v.push(q as f128 / 8.0);
        q += 1;
    }
    // PRNG within the in-range band and a bit beyond.
    let mut st: u64 = 0xf0e1_d2c3_b4a5_9687;
    for _ in 0..6000 {
        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let hi = st;
        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let lo = st;
        let ef = (0x3fc0 + (hi % 0x0040)) as u128; // exponents around 1..~16k
        let mant = (((hi as u128) << 64) | lo as u128) & ((1u128 << 112) - 1);
        let sign = ((hi >> 23) & 1) as u128;
        v.push(f128::from_bits((sign << 127) | (ef << 112) | mant));
    }
    v
}

#[test]
fn f128_exp_matches_glibc() {
    let mut mism = Vec::new();
    let mut n = 0u64;
    for &x in &values() {
        unsafe { *el() = 0 };
        let g = unsafe { expf128(x) }.to_bits();
        let ge = unsafe { *el() };
        unsafe { *el() = 0 };
        let f = unsafe { ma::expf128(x) }.to_bits();
        let fe = unsafe { *el() };
        n += 1;
        if g != f || ge != fe {
            mism.push(format!(
                "exp({:#034x}): glibc=({g:#034x},e={ge}) fl=({f:#034x},e={fe})",
                x.to_bits()
            ));
        }
    }
    assert!(
        mism.is_empty(),
        "expf128 diverged ({}/{}):\n{}",
        mism.len(),
        n,
        mism.iter().take(30).cloned().collect::<Vec<_>>().join("\n")
    );
}
