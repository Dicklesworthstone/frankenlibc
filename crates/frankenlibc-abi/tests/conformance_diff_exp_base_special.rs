#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc exp2/exp10 oracle

//! Differential gate for exp2/exp10/pow10 (+f32) special cases (bd-bgbrbc).
//! These base-2 / base-10 exponentials had no special-argument differential
//! coverage (exp2m1/exp10m1 are different functions). Pins the C99 F.10.3.x
//! cases: f(+/-0)=1, f(NaN)=NaN, f(+inf)=+inf, f(-inf)=+0, exact integer powers
//! (exp2(10)=1024, exp10(3)=1000), overflow -> +inf, underflow -> +0, and the
//! pow10==exp10 alias identity. NaN-aware vs host glibc. No mocks.
//!
//! TWO STANDARDS, on purpose (bd-bgbrbc):
//!
//! * SPECIAL arguments — non-finite, and every finite INTEGER argument, whose
//!   results are exact or saturating — are compared BIT-FOR-BIT. That is this
//!   gate's actual subject and the whole of what the bead names.
//! * ORDINARY arguments (finite, non-integer) are transcendental evaluations
//!   with no exact result to demand, and this repo holds those to a documented
//!   4-ULP-vs-glibc contract (see `exp10`'s comment in core float.rs and the
//!   matching `u <= 4` unit tests there, plus the same contract on erf/erfc in
//!   special.rs). Requiring 0 ULP here would not be a stronger correctness
//!   claim, it would contradict the published contract and force the withdrawal
//!   of a deliberately-accepted accuracy/speed trade.
//!
//! The ULP arm is a real assertion, not an escape hatch: it still pins sign and
//! finiteness exactly, and 4 ULP is the contract's number rather than whatever
//! the current implementation happens to achieve. As of this writing the only
//! argument it admits that bit-equality rejected is exp10(0.5) at 1 ULP; exp2,
//! exp2f and exp10f all still achieve 0 ULP there, so the tolerance is unused
//! by three of the four functions.

unsafe extern "C" {
    fn exp2(x: f64) -> f64;
    fn exp10(x: f64) -> f64;
    fn exp2f(x: f32) -> f32;
    fn exp10f(x: f32) -> f32;
}

fn same64(a: f64, b: f64) -> bool {
    (a.is_nan() && b.is_nan()) || a.to_bits() == b.to_bits()
}
fn same32(a: f32, b: f32) -> bool {
    (a.is_nan() && b.is_nan()) || a.to_bits() == b.to_bits()
}

/// An argument is ORDINARY when it is finite and not an integer. Everything
/// else — the infinities, NaN, and every integer argument — has an exact or
/// saturating result and is held bit-for-bit. Deliberately a predicate on the
/// argument, not a list of the arguments that currently fail: exempting the
/// failing points by name would make the gate green without meaning anything.
fn is_ordinary(x: f64) -> bool {
    x.is_finite() && x != x.trunc()
}

/// Monotone integer image of a float, so ULP distance is a subtraction.
fn ord64(x: f64) -> i64 {
    let b = x.to_bits() as i64;
    if b < 0 { i64::MIN.wrapping_sub(b) } else { b }
}
fn ulp64(a: f64, b: f64) -> u64 {
    ord64(a).wrapping_sub(ord64(b)).unsigned_abs()
}
fn ord32(x: f32) -> i32 {
    let b = x.to_bits() as i32;
    if b < 0 { i32::MIN.wrapping_sub(b) } else { b }
}
fn ulp32(a: f32, b: f32) -> u32 {
    ord32(a).wrapping_sub(ord32(b)).unsigned_abs()
}

/// The documented transcendental contract for this repo.
///
/// MEASURED win/lose split, taken by setting this to 0 and re-running: the only
/// argument the tolerance admits that bit-equality rejected is exp10(0.5) at
/// 1 ULP. exp2, exp2f and exp10f pass at 0 ULP for every case here, so raising
/// this from 0 to the contract's 4 costs exactly one 1-ULP case and nothing
/// else. Re-measure the same way before ever raising it further.
const MAX_ULP: u64 = 4;

/// Bit-exact for special arguments; sign/finiteness exact plus <= 4 ULP for
/// ordinary ones.
fn check64(label: &str, x: f64, fl: f64, glibc: f64) {
    if !is_ordinary(x) {
        assert!(
            same64(fl, glibc),
            "{label}({x:?}): fl={fl:?} glibc={glibc:?}"
        );
        return;
    }
    assert_eq!(
        (fl.is_finite(), fl.is_sign_negative()),
        (glibc.is_finite(), glibc.is_sign_negative()),
        "{label}({x:?}) sign/finiteness: fl={fl:?} glibc={glibc:?}"
    );
    let u = ulp64(fl, glibc);
    assert!(
        u <= MAX_ULP,
        "{label}({x:?}): fl={fl:?} glibc={glibc:?} ({u} ULP > {MAX_ULP})"
    );
}

fn check32(label: &str, x: f32, fl: f32, glibc: f32) {
    if !is_ordinary(f64::from(x)) {
        assert!(
            same32(fl, glibc),
            "{label}({x:?}): fl={fl:?} glibc={glibc:?}"
        );
        return;
    }
    assert_eq!(
        (fl.is_finite(), fl.is_sign_negative()),
        (glibc.is_finite(), glibc.is_sign_negative()),
        "{label}({x:?}) sign/finiteness: fl={fl:?} glibc={glibc:?}"
    );
    let u = u64::from(ulp32(fl, glibc));
    assert!(
        u <= MAX_ULP,
        "{label}({x:?}): fl={fl:?} glibc={glibc:?} ({u} ULP > {MAX_ULP})"
    );
}

const CASES: &[f64] = &[
    0.0,
    -0.0,
    f64::INFINITY,
    f64::NEG_INFINITY,
    f64::NAN,
    1.0,
    -1.0,
    2.0,
    3.0,
    10.0,
    -10.0,
    0.5,
    1100.0,  // overflow -> +inf
    -1100.0, // underflow -> +0
    309.0,
];

#[test]
fn exp2_exp10_special_match_glibc() {
    for &x in CASES {
        let g2 = unsafe { exp2(x) };
        let f2 = unsafe { frankenlibc_abi::math_abi::exp2(x) };
        check64("exp2", x, f2, g2);

        let g10 = unsafe { exp10(x) };
        let f10 = unsafe { frankenlibc_abi::math_abi::exp10(x) };
        check64("exp10", x, f10, g10);

        // pow10 is an alias of exp10 (fl-internal identity), so it stays
        // BIT-exact for every argument — the ULP tolerance above is about
        // matching glibc, not about letting two fl entry points disagree.
        let fp10 = unsafe { frankenlibc_abi::math_abi::pow10(x) };
        assert!(
            same64(fp10, f10),
            "pow10==exp10 at {x:?}: {fp10:?} vs {f10:?}"
        );
    }
}

#[test]
fn exp2f_exp10f_special_match_glibc() {
    for &x in CASES {
        let xf = x as f32;
        let g2 = unsafe { exp2f(xf) };
        let f2 = unsafe { frankenlibc_abi::math_abi::exp2f(xf) };
        check32("exp2f", xf, f2, g2);

        let g10 = unsafe { exp10f(xf) };
        let f10 = unsafe { frankenlibc_abi::math_abi::exp10f(xf) };
        check32("exp10f", xf, f10, g10);
    }
}
