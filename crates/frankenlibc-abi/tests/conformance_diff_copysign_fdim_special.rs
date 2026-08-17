#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc copysign/fdim oracle

//! Differential gate for copysign/fdim (+f32) sign and special cases
//! (bd-76qkmu) — neither had special-argument differential coverage. copysign
//! takes the SIGN of y, including y == +/-0 and y == +/-NaN (a sign bit, not a
//! value), so copysign(3,-0.0) == -3 and copysign(3,-NaN) == -3. fdim(x,y) is
//! x-y when x>y else +0: fdim(inf,inf)=+0 (inf>inf is false, NOT NaN),
//! fdim(inf,-inf)=+inf, fdim(NaN,_)=NaN. Bit-for-bit NaN-aware vs host glibc.
//! No mocks.

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
    copysign: F64BinaryFn = c"copysign" via frankenlibc_abi::math_abi::copysign => (x: f64, y: f64) -> f64;
    fdim: F64BinaryFn = c"fdim" via frankenlibc_abi::math_abi::fdim => (x: f64, y: f64) -> f64;
    copysignf: F32BinaryFn = c"copysignf" via frankenlibc_abi::math_abi::copysignf => (x: f32, y: f32) -> f32;
    fdimf: F32BinaryFn = c"fdimf" via frankenlibc_abi::math_abi::fdimf => (x: f32, y: f32) -> f32;
}

unsafe extern "C" {
}

fn same64(a: f64, b: f64) -> bool {
    (a.is_nan() && b.is_nan()) || a.to_bits() == b.to_bits()
}
fn same32(a: f32, b: f32) -> bool {
    (a.is_nan() && b.is_nan()) || a.to_bits() == b.to_bits()
}

const N: f64 = f64::NAN;
const I: f64 = f64::INFINITY;

// copysign: result magnitude from x, sign bit from y (incl +/-0 and +/-NaN).
const COPYSIGN_CASES: &[(f64, f64)] = &[
    (3.0, 0.0),
    (3.0, -0.0),
    (3.0, 1.0),
    (3.0, -1.0),
    (3.0, N),
    (3.0, -N),
    (-3.0, 0.0),
    (-3.0, -0.0),
    (I, -1.0),
    (I, 1.0),
    (0.0, -1.0),
    (-0.0, 1.0),
    (N, -1.0),
    (N, 1.0),
];

const FDIM_CASES: &[(f64, f64)] = &[
    (I, I),   // inf>inf false -> +0
    (I, -I),  // -> +inf
    (-I, I),  // -> +0
    (-I, -I), // -> +0
    (N, 3.0), // NaN
    (3.0, N), // NaN
    (N, N),
    (5.0, 3.0), // 2
    (3.0, 5.0), // +0
    (0.0, -0.0),
    (I, 3.0),  // +inf
    (3.0, -I), // +inf
];

#[test]
fn copysign_special_match_glibc() {
    for &(x, y) in COPYSIGN_CASES {
        let g = unsafe { copysign(x, y) };
        let f = unsafe { frankenlibc_abi::math_abi::copysign(x, y) };
        assert!(same64(f, g), "copysign({x:?},{y:?}): fl={f:?} glibc={g:?}");
        let (xf, yf) = (x as f32, y as f32);
        let gf = unsafe { copysignf(xf, yf) };
        let ff = unsafe { frankenlibc_abi::math_abi::copysignf(xf, yf) };
        assert!(
            same32(ff, gf),
            "copysignf({xf:?},{yf:?}): fl={ff:?} glibc={gf:?}"
        );
    }
}

#[test]
fn fdim_special_match_glibc() {
    for &(x, y) in FDIM_CASES {
        let g = unsafe { fdim(x, y) };
        let f = unsafe { frankenlibc_abi::math_abi::fdim(x, y) };
        assert!(same64(f, g), "fdim({x:?},{y:?}): fl={f:?} glibc={g:?}");
        let (xf, yf) = (x as f32, y as f32);
        let gf = unsafe { fdimf(xf, yf) };
        let ff = unsafe { frankenlibc_abi::math_abi::fdimf(xf, yf) };
        assert!(
            same32(ff, gf),
            "fdimf({xf:?},{yf:?}): fl={ff:?} glibc={gf:?}"
        );
    }
}
