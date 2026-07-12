//! Differential gate: f128 atanf128 matches glibc bit-for-bit (bd-9z5ikz).
//! atanf128 was a garbage f64-ABI stub. The fix is a verbatim port of glibc's
//! ldbl-128 Cephes/Moshier `__atanl` — a 84-entry arctan(k/8) table, the
//! arctan subtraction identity for range reduction, and a rational
//! `t + t³·p(t²)/q(t²)`. Self-contained (no other transcendental) and uses only
//! correctly-rounded f128 `+ - * /`, so it is byte-exact. This is the first
//! function of the f128 transcendental quad libm.
#![cfg(target_os = "linux")]
#![feature(f128)]
#![allow(unsafe_code)]

use frankenlibc_abi::math_abi as ma;

unsafe extern "C" {
    fn atanf128(x: f128) -> f128;
}

fn values() -> Vec<f128> {
    let mut v: Vec<f128> = vec![
        0.0,
        -0.0f128,
        1.0,
        -1.0,
        0.125,
        0.25,
        0.5,
        2.0,
        10.0,
        10.25,
        100.0,
        -100.0,
        0.09375, // polynomial cutoff
        1e-20f128,
        1e-30f128,
        1e30f128,
        1e300f128,
        1e4000f128,
        f128::MIN_POSITIVE,
        f128::MAX,
        f128::from_bits(1),                  // smallest subnormal
        f128::from_bits(0x7fff_u128 << 112), // +inf
        f128::from_bits(0xffff_u128 << 112), // -inf
        f128::from_bits((0x7fff_u128 << 112) | (1u128 << 111)), // qNaN
    ];
    // Dense sweep over the table-reduction range [0, 10.25] (k = 0..82), both
    // signs, plus near each table boundary k/8.
    let mut q: u64 = 1;
    while q < 84 {
        let base = 0.125f128 * (q as f128);
        for d in [-0.06f128, -0.01, 0.0, 0.01, 0.0625] {
            v.push(base + d);
            v.push(-(base + d));
        }
        q += 1;
    }
    // PRNG spread across magnitudes and signs.
    let mut st: u64 = 0xa7a7_1357_9bdf_0246;
    for _ in 0..6000 {
        st = st
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let hi = st;
        st = st
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let lo = st;
        // Bias exponent around 1.0 so most values exercise the reduction.
        let ef = (0x3f00 + (hi % 0x0300)) as u128;
        let mant = (((hi as u128) << 64) | lo as u128) & ((1u128 << 112) - 1);
        let sign = ((hi >> 19) & 1) as u128;
        v.push(f128::from_bits((sign << 127) | (ef << 112) | mant));
    }
    v
}

#[test]
fn f128_atan_matches_glibc() {
    let mut mism = Vec::new();
    let mut n = 0u64;
    for &x in &values() {
        let g = unsafe { atanf128(x) }.to_bits();
        let f = unsafe { ma::atanf128(x) }.to_bits();
        n += 1;
        if g != f {
            mism.push(format!(
                "atan({:#034x}): glibc={g:#034x} fl={f:#034x}",
                x.to_bits()
            ));
        }
    }
    assert!(
        mism.is_empty(),
        "atanf128 diverged ({}/{}):\n{}",
        mism.len(),
        n,
        mism.iter().take(30).cloned().collect::<Vec<_>>().join("\n")
    );
}
