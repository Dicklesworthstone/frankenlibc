#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc round-family oracle

//! Differential gate for the round-to-integer family at special arguments
//! (bd-pna8p1): floor/ceil/trunc/round/roundeven/nearbyint/rint (+ f32). These
//! were value-range tested but not at +/-0, +/-inf, or NaN, where every member
//! must pass the argument through EXACTLY — including the sign of zero
//! (floor(-0.0) == -0.0) and NaN. A few finite midpoints are included as
//! controls. Bit-for-bit NaN-aware vs host glibc. No mocks.

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

/// Host oracles resolved through `dlsym` because `dladdr` proved the link-time
/// arm was NOT glibc.
///
/// bd-v0388t: a census of 101 oracle arms found nine satisfied from the test
/// binary itself rather than from `libm.so.6` — `ceil fabs floor sqrt copysign
/// fdim fmax fmin fmod`, i.e. what `compiler_builtins` supplies and what LLVM
/// lowers to `roundsd` / `andpd` / `sqrtsd`. An arm that never reaches the
/// incumbent cannot fail, and in `conformance_diff_math` one of them did worse
/// than that: it produced a FALSE RED against a correct fl.
///
/// Only the measured-captured symbols are converted here. The rest of this
/// file's arms reach `libm.so.6` and stay link-time declarations, because
/// converting them would be churn against the evidence rather than because
/// of it.
type F64UnaryFn = unsafe extern "C" fn(f64) -> f64;
type F32UnaryFn = unsafe extern "C" fn(f32) -> f32;
type F64BinaryFn = unsafe extern "C" fn(f64, f64) -> f64;
type F32BinaryFn = unsafe extern "C" fn(f32, f32) -> f32;

macro_rules! host_shim {
    ($($rust:ident : $ty:ty = $sym:literal via $flpath:path => ($($arg:ident : $at:ty),*) -> $rt:ty);* $(;)?) => {
        $(
            /// Host oracle via `dlsym`; `unsafe` so existing call sites' blocks
            /// stay meaningful rather than becoming dead syntax.
            unsafe fn $rust($($arg: $at),*) -> $rt {
                // SAFETY: the prototype matches the C declaration, and fl's own
                // definition is handed to the oracle so it refuses to resolve
                // back to fl and compare it against itself.
                let f: $ty = unsafe { dlsym_oracle::host_fn($sym, $flpath as *const ()) };
                unsafe { f($($arg),*) }
            }
        )*
    };
}

host_shim! {
    floor: F64UnaryFn = c"floor" via frankenlibc_abi::math_abi::floor => (x: f64) -> f64;
    ceil: F64UnaryFn = c"ceil" via frankenlibc_abi::math_abi::ceil => (x: f64) -> f64;
    floorf: F32UnaryFn = c"floorf" via frankenlibc_abi::math_abi::floorf => (x: f32) -> f32;
    ceilf: F32UnaryFn = c"ceilf" via frankenlibc_abi::math_abi::ceilf => (x: f32) -> f32;
}

unsafe extern "C" {
    fn trunc(x: f64) -> f64;
    fn round(x: f64) -> f64;
    fn roundeven(x: f64) -> f64;
    fn nearbyint(x: f64) -> f64;
    fn rint(x: f64) -> f64;
    fn truncf(x: f32) -> f32;
    fn roundf(x: f32) -> f32;
    fn roundevenf(x: f32) -> f32;
    fn nearbyintf(x: f32) -> f32;
    fn rintf(x: f32) -> f32;
}

fn same64(a: f64, b: f64) -> bool {
    (a.is_nan() && b.is_nan()) || a.to_bits() == b.to_bits()
}
fn same32(a: f32, b: f32) -> bool {
    (a.is_nan() && b.is_nan()) || a.to_bits() == b.to_bits()
}

const CASES: &[f64] = &[
    0.0,
    -0.0,
    f64::INFINITY,
    f64::NEG_INFINITY,
    f64::NAN,
    2.5,
    -2.5,
    0.5,
    -0.5,
    3.5,
    -3.5,
    2.4,
    -2.6,
    0.0e0,
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
