#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc round-family oracle

//! Differential gate for the round-to-integer family at special arguments
//! (bd-pna8p1): floor/ceil/trunc/round/roundeven/nearbyint/rint (+ f32). These
//! were value-range tested but not at +/-0, +/-inf, or NaN, where every member
//! must pass the argument through EXACTLY — including the sign of zero
//! (floor(-0.0) == -0.0) and NaN. A few finite midpoints are included as
//! controls. Bit-for-bit NaN-aware vs host glibc. No mocks.

unsafe extern "C" {
    fn floor(x: f64) -> f64; fn ceil(x: f64) -> f64; fn trunc(x: f64) -> f64;
    fn round(x: f64) -> f64; fn roundeven(x: f64) -> f64; fn nearbyint(x: f64) -> f64;
    fn rint(x: f64) -> f64;
    fn floorf(x: f32) -> f32; fn ceilf(x: f32) -> f32; fn truncf(x: f32) -> f32;
    fn roundf(x: f32) -> f32; fn roundevenf(x: f32) -> f32; fn nearbyintf(x: f32) -> f32;
    fn rintf(x: f32) -> f32;
}

fn same64(a: f64, b: f64) -> bool {
    (a.is_nan() && b.is_nan()) || a.to_bits() == b.to_bits()
}
fn same32(a: f32, b: f32) -> bool {
    (a.is_nan() && b.is_nan()) || a.to_bits() == b.to_bits()
}

const CASES: &[f64] = &[
    0.0, -0.0, f64::INFINITY, f64::NEG_INFINITY, f64::NAN,
    2.5, -2.5, 0.5, -0.5, 3.5, -3.5, 2.4, -2.6, 0.0e0,
];

macro_rules! ck64 {
    ($name:literal, $fl:path, $g:ident, $x:expr) => {{
        let g = unsafe { $g($x) };
        let f = unsafe { $fl($x) };
        assert!(same64(f, g), "{}({:?}): fl={f:?} glibc={g:?}", $name, $x);
    }};
}
macro_rules! ck32 {
    ($name:literal, $fl:path, $g:ident, $x:expr) => {{
        let g = unsafe { $g($x) };
        let f = unsafe { $fl($x) };
        assert!(same32(f, g), "{}({:?}): fl={f:?} glibc={g:?}", $name, $x);
    }};
}

#[test]
fn round_family_special_match_glibc() {
    use frankenlibc_abi::math_abi as m;
    for &x in CASES {
        ck64!("floor", m::floor, floor, x);
        ck64!("ceil", m::ceil, ceil, x);
        ck64!("trunc", m::trunc, trunc, x);
        ck64!("round", m::round, round, x);
        ck64!("roundeven", m::roundeven, roundeven, x);
        ck64!("nearbyint", m::nearbyint, nearbyint, x);
        ck64!("rint", m::rint, rint, x);

        let xf = x as f32;
        ck32!("floorf", m::floorf, floorf, xf);
        ck32!("ceilf", m::ceilf, ceilf, xf);
        ck32!("truncf", m::truncf, truncf, xf);
        ck32!("roundf", m::roundf, roundf, xf);
        ck32!("roundevenf", m::roundevenf, roundevenf, xf);
        ck32!("nearbyintf", m::nearbyintf, nearbyintf, xf);
        ck32!("rintf", m::rintf, rintf, xf);
    }
}
