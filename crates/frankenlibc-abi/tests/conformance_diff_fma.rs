#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc fma/fmaf oracle

//! Differential gate for fma/fmaf (bd-h95z6y) — only a scratch bench existed.
//! fma(x,y,z) computes x*y+z with a SINGLE rounding (the product is not rounded
//! before the add), so a naive `x*y+z` implementation diverges whenever the
//! exact product has bits below the rounded result. This gate includes cases
//! engineered to expose double rounding, plus a randomized grid and special
//! values, and requires fl to match host glibc bit-for-bit. No mocks.

unsafe extern "C" {
    fn fma(x: f64, y: f64, z: f64) -> f64;
    fn fmaf(x: f32, y: f32, z: f32) -> f32;
}

fn eq64(a: f64, b: f64) -> bool {
    a.to_bits() == b.to_bits() || (a.is_nan() && b.is_nan())
}
fn eq32(a: f32, b: f32) -> bool {
    a.to_bits() == b.to_bits() || (a.is_nan() && b.is_nan())
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
}

#[test]
fn fma_matches_glibc_double_rounding_cases() {
    // Engineered cases where naive (x*y+z) double-rounds but a correct fma does
    // not. a = 1 + 2^-52, b = 1 + 2^-52, c = -(1 + 2^-51):
    //   exact a*b = 1 + 2^-51 + 2^-104; + c = 2^-104  (correct fma)
    //   naive: round(a*b)=1+2^-51, + c = 0            (wrong)
    let a = 1.0 + f64::from_bits(0x3CB0_0000_0000_0000); // 1 + 2^-52
    let b = a;
    let c = -(1.0 + f64::from_bits(0x3CC0_0000_0000_0000)); // -(1 + 2^-51)
    let g = unsafe { fma(a, b, c) };
    let f = unsafe { frankenlibc_abi::math_abi::fma(a, b, c) };
    assert!(eq64(f, g), "fma double-rounding case: fl={f:e} glibc={g:e}");

    // p = 1 + 2^-26 (mantissa bit 26 set); p*p = 1 + 2^-25 + 2^-52 exactly,
    // which naive rounding of the product would drop the 2^-52 term from.
    let p = 1.0 + f64::from_bits(0x3E50_0000_0000_0000); // 1 + 2^-26
    let pp_hi = 1.0 + f64::from_bits(0x3E60_0000_0000_0000); // 1 + 2^-25
    let cases = [(p, p, -pp_hi), (p, p, -1.0), (1e150, 1e150, -1e300)];
    for (x, y, z) in cases {
        let g = unsafe { fma(x, y, z) };
        let f = unsafe { frankenlibc_abi::math_abi::fma(x, y, z) };
        assert!(eq64(f, g), "fma({x:e},{y:e},{z:e}): fl={f:e} glibc={g:e}");
    }
}

#[test]
fn fma_matches_glibc_special_values() {
    let sv = [0.0f64, -0.0, 1.0, -1.0, f64::INFINITY, f64::NEG_INFINITY, f64::NAN];
    for &x in &sv {
        for &y in &sv {
            for &z in &sv {
                let g = unsafe { fma(x, y, z) };
                let f = unsafe { frankenlibc_abi::math_abi::fma(x, y, z) };
                assert!(eq64(f, g), "fma({x},{y},{z}): fl={f} glibc={g}");
            }
        }
    }
}

#[test]
fn fma_matches_glibc_random_grid() {
    let mut rng = Rng(0x664D_0000_0000_0001);
    for _ in 0..20000 {
        let x = f64::from_bits(rng.next());
        let y = f64::from_bits(rng.next());
        let z = f64::from_bits(rng.next());
        let g = unsafe { fma(x, y, z) };
        let f = unsafe { frankenlibc_abi::math_abi::fma(x, y, z) };
        assert!(eq64(f, g), "fma({x:e},{y:e},{z:e}): fl={f:e} glibc={g:e}");
    }
}

#[test]
fn fmaf_matches_glibc() {
    let mut rng = Rng(0x6D2B_0000_0000_0001);
    for _ in 0..20000 {
        let x = f32::from_bits(rng.next() as u32);
        let y = f32::from_bits((rng.next() >> 7) as u32);
        let z = f32::from_bits((rng.next() >> 13) as u32);
        let g = unsafe { fmaf(x, y, z) };
        let f = unsafe { frankenlibc_abi::math_abi::fmaf(x, y, z) };
        assert!(eq32(f, g), "fmaf({x:e},{y:e},{z:e}): fl={f:e} glibc={g:e}");
    }
}
