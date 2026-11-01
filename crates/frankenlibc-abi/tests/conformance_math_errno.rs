//! Conformance gate: fl's math ABI layer sets errno (EDOM / ERANGE) to match
//! host glibc on domain errors, poles, and range errors.
//!
//! Live in-process differential comparison is impossible here: fl exports
//! `__errno_location` as a no_mangle symbol that interposes libc's, so a
//! dlsym'd glibc math function writes errno into fl's slot, not libc's. The
//! expected values below are therefore the GROUND TRUTH captured from a
//! standalone gcc program linked against this host's glibc (`-lm`), recorded in
//! the test body. fl's errno is read in-process (reliable — it is fl's own
//! slot). This pins the hand-written EDOM/ERANGE conditions in math_abi against
//! regression (e.g. the y0/y1/yn x=0 pole, which is ERANGE not EDOM, and fdim
//! overflow).
//!
//! Scope note: a handful of overflow cases route through the value-"healing"
//! membrane (binary_entry/unary_entry), whose per-input decision can convert an
//! infinite result to a finite one and thus suppress the range-errno check.
//! Those cases are deterministic per input but membrane-state-dependent, so
//! this gate only asserts errno that is determined by the INPUT semantics
//! (domain edges + poles) plus range errors on functions with no membrane
//! (f64 fdim, scalbn/ldexp/scalbln scaling). powf-overflow-under-healing is a
//! known separate concern and is intentionally not asserted here.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::errno_abi;
use frankenlibc_abi::math_abi as fa;
use std::ffi::c_int;

const EDOM: c_int = 33;
const ERANGE: c_int = 34;

type Unary64 = unsafe extern "C" fn(f64) -> f64;
type Unary32 = unsafe extern "C" fn(f32) -> f32;

// The deployed provider-bound C fixture independently checks both widths
// against GNU, including NaNs, valid infinities and poles. The last field says
// whether +infinity belongs to the mathematical domain; -infinity does not.
const DOMAIN_FAMILIES: [(&str, Unary64, Unary32, f64, bool); 8] = [
    ("acos", fa::acos, fa::acosf, 0.5, false),
    ("asin", fa::asin, fa::asinf, 0.5, false),
    ("acosh", fa::acosh, fa::acoshf, 2.0, true),
    ("atanh", fa::atanh, fa::atanhf, 0.5, false),
    ("log", fa::log, fa::logf, 2.0, true),
    ("log2", fa::log2, fa::log2f, 2.0, true),
    ("log10", fa::log10, fa::log10f, 2.0, true),
    ("log1p", fa::log1p, fa::log1pf, 0.5, true),
];

fn name(e: c_int) -> &'static str {
    match e {
        0 => "0",
        33 => "EDOM",
        34 => "ERANGE",
        _ => "?",
    }
}
fn clr() {
    unsafe { errno_abi::set_abi_errno(0) };
}
fn rd() -> c_int {
    unsafe { *errno_abi::__errno_location() }
}

#[test]
fn infinite_domain_errors_set_errno_in_both_widths() {
    let mut checked = 0;
    for (label, double, float, _, positive_infinity_valid) in DOMAIN_FAMILIES {
        for x in [f64::NEG_INFINITY, f64::INFINITY] {
            if x.is_sign_positive() && positive_infinity_valid {
                continue;
            }
            for initial in [0, libc::E2BIG] {
                // SAFETY: errno is thread-local, and these scalar math calls
                // have no pointer or allocation preconditions.
                unsafe { errno_abi::set_abi_errno(initial) };
                let result = unsafe { double(x) };
                assert_eq!(rd(), EDOM, "{label}({x}), initial errno={initial}");
                assert!(result.is_nan(), "{label}({x}) must be NaN");

                // SAFETY: same scalar calling contract at f32 width.
                unsafe { errno_abi::set_abi_errno(initial) };
                let result = unsafe { float(x as f32) };
                assert_eq!(rd(), EDOM, "{label}f({x}), initial errno={initial}");
                assert!(result.is_nan(), "{label}f({x}) must be NaN");
                checked += 2;
            }
        }
    }
    assert_eq!(checked, 44);
    println!("infinite domain errors: {checked} errno/result observations");
}

#[test]
fn domain_controls_preserve_existing_errno() {
    for (label, double, float, finite, positive_infinity_valid) in DOMAIN_FAMILIES {
        for initial in [0, libc::E2BIG] {
            for (x64, x32) in [
                (f64::NAN, f32::NAN),
                (-f64::NAN, -f32::NAN),
                (
                    f64::from_bits(0x7ff4_0000_0000_0123),
                    f32::from_bits(0x7fa0_0123),
                ),
                (
                    f64::from_bits(0xfff4_0000_0000_0123),
                    f32::from_bits(0xffa0_0123),
                ),
            ] {
                // SAFETY: scalar inputs, including NaNs, are valid ABI values.
                unsafe { errno_abi::set_abi_errno(initial) };
                assert!(unsafe { double(x64) }.is_nan(), "{label}({x64})");
                assert_eq!(rd(), initial, "{label}(NaN) must preserve errno");
                // SAFETY: same scalar calling contract at f32 width.
                unsafe { errno_abi::set_abi_errno(initial) };
                assert!(unsafe { float(x32) }.is_nan(), "{label}f({x32})");
                assert_eq!(rd(), initial, "{label}f(NaN) must preserve errno");
            }
            // SAFETY: each finite control is in the named function's domain.
            unsafe { errno_abi::set_abi_errno(initial) };
            assert!(unsafe { double(finite) }.is_finite(), "{label}({finite})");
            assert_eq!(rd(), initial, "{label}(valid finite) must preserve errno");
            // SAFETY: the exact f32 narrowing stays in the same valid domain.
            unsafe { errno_abi::set_abi_errno(initial) };
            assert!(unsafe { float(finite as f32) }.is_finite());
            assert_eq!(rd(), initial, "{label}f(valid finite) must preserve errno");
            if positive_infinity_valid {
                // SAFETY: +infinity is explicitly valid for this family.
                unsafe { errno_abi::set_abi_errno(initial) };
                assert_eq!(unsafe { double(f64::INFINITY) }, f64::INFINITY);
                assert_eq!(rd(), initial, "{label}(+inf) must preserve errno");
                // SAFETY: same scalar calling contract at f32 width.
                unsafe { errno_abi::set_abi_errno(initial) };
                assert_eq!(unsafe { float(f32::INFINITY) }, f32::INFINITY);
                assert_eq!(rd(), initial, "{label}f(+inf) must preserve errno");
            }
        }
    }
}

#[test]
fn domain_aliases_share_infinity_errno() {
    for (label, double32x, double64, float32) in [
        (
            "acos",
            fa::acosf32x as Unary64,
            fa::acosf64 as Unary64,
            fa::acosf32 as Unary32,
        ),
        ("asin", fa::asinf32x, fa::asinf64, fa::asinf32),
        ("acosh", fa::acoshf32x, fa::acoshf64, fa::acoshf32),
        ("atanh", fa::atanhf32x, fa::atanhf64, fa::atanhf32),
        ("log", fa::logf32x, fa::logf64, fa::logf32),
        ("log2", fa::log2f32x, fa::log2f64, fa::log2f32),
        ("log10", fa::log10f32x, fa::log10f64, fa::log10f32),
        ("log1p", fa::log1pf32x, fa::log1pf64, fa::log1pf32),
    ] {
        for f in [double32x, double64] {
            clr();
            // SAFETY: these aliases accept a scalar f64 and must report the
            // same negative-infinity domain error as the primary entrypoint.
            assert!(unsafe { f(f64::NEG_INFINITY) }.is_nan(), "{label} alias");
            assert_eq!(rd(), EDOM, "{label} double alias");
        }
        clr();
        // SAFETY: the f32 alias has the same scalar contract.
        assert!(unsafe { float32(f32::NEG_INFINITY) }.is_nan());
        assert_eq!(rd(), EDOM, "{label} float alias");
    }
}

#[test]
fn math_errno_matches_glibc() {
    let mut div: Vec<String> = Vec::new();

    macro_rules! chk {
        ($lbl:literal, $want:expr, $call:expr) => {{
            clr();
            let _ = unsafe { $call };
            let got = rd();
            if got != $want {
                div.push(format!(
                    "{}: fl={} want(glibc)={}",
                    $lbl,
                    name(got),
                    name($want)
                ));
            }
        }};
    }

    // --- Domain errors (EDOM): input-determined ---
    // sqrt of a negative INFINITY is a domain error too -- C requires it for any
    // x < 0, and a real-glibc oracle at f128 width was measured setting EDOM
    // here. fl's predicate had a finiteness guard that excluded exactly this
    // case at all three widths (bd-buvzii).
    chk!("sqrt(-inf)", EDOM, fa::sqrt(f64::NEG_INFINITY));
    chk!("sqrtf(-inf)", EDOM, fa::sqrtf(f32::NEG_INFINITY));
    chk!("acos(2)", EDOM, fa::acos(2.0));
    chk!("asin(2)", EDOM, fa::asin(2.0));
    chk!("acosh(0.5)", EDOM, fa::acosh(0.5));
    chk!("atanh(2)", EDOM, fa::atanh(2.0));
    chk!("log(-1)", EDOM, fa::log(-1.0));
    chk!("log2(-1)", EDOM, fa::log2(-1.0));
    chk!("log10(-1)", EDOM, fa::log10(-1.0));
    chk!("log1p(-2)", EDOM, fa::log1p(-2.0));
    chk!("sqrt(-1)", EDOM, fa::sqrt(-1.0));
    chk!("tgamma(-1)", EDOM, fa::tgamma(-1.0));
    chk!("fmod(1,0)", EDOM, fa::fmod(1.0, 0.0));
    // fmod EDOM edges (same glibc rule as drem): inf%inf is EDOM, NaN operand is not.
    chk!("fmod(inf,5)", EDOM, fa::fmod(f64::INFINITY, 5.0));
    chk!(
        "fmod(inf,inf)",
        EDOM,
        fa::fmod(f64::INFINITY, f64::INFINITY)
    );
    chk!("fmod(nan,0)", 0, fa::fmod(f64::NAN, 0.0));
    chk!("fmod(inf,nan)", 0, fa::fmod(f64::INFINITY, f64::NAN));
    chk!("fmod(5,inf)", 0, fa::fmod(5.0, f64::INFINITY));
    chk!(
        "fmodf(inf,inf)",
        EDOM,
        fa::fmodf(f32::INFINITY, f32::INFINITY)
    );
    chk!("fmodf(nan,0)", 0, fa::fmodf(f32::NAN, 0.0));
    chk!("remainder(1,0)", EDOM, fa::remainder(1.0, 0.0));
    chk!(
        "remainder(inf,inf)",
        EDOM,
        fa::remainder(f64::INFINITY, f64::INFINITY)
    );
    chk!("remainder(nan,0)", 0, fa::remainder(f64::NAN, 0.0));
    chk!(
        "remainderf(inf,inf)",
        EDOM,
        fa::remainderf(f32::INFINITY, f32::INFINITY)
    );
    chk!("remainderf(nan,0)", 0, fa::remainderf(f32::NAN, 0.0));
    // remquo/remquof: C99, NO errno wrapper in glibc -> errno 0 even for domain inputs.
    {
        let mut q: c_int = 0;
        chk!("remquo(5,0)", 0, fa::remquo(5.0, 0.0, &mut q));
        chk!("remquo(inf,5)", 0, fa::remquo(f64::INFINITY, 5.0, &mut q));
        chk!(
            "remquo(inf,inf)",
            0,
            fa::remquo(f64::INFINITY, f64::INFINITY, &mut q)
        );
        chk!("remquof(5,0)", 0, fa::remquof(5.0, 0.0, &mut q));
        chk!("remquof(inf,5)", 0, fa::remquof(f32::INFINITY, 5.0, &mut q));
    }
    chk!("pow(-2,0.5)", EDOM, fa::pow(-2.0, 0.5));
    chk!("y0(-1)", EDOM, fa::y0(-1.0));
    chk!("y1(-1)", EDOM, fa::y1(-1.0));
    chk!("yn(2,-1)", EDOM, fa::yn(2, -1.0));
    // f32 domain
    chk!("acosf(2)", EDOM, fa::acosf(2.0));
    chk!("asinf(2)", EDOM, fa::asinf(2.0));
    chk!("acoshf(0.5)", EDOM, fa::acoshf(0.5));
    chk!("atanhf(2)", EDOM, fa::atanhf(2.0));
    chk!("logf(-1)", EDOM, fa::logf(-1.0));
    chk!("sqrtf(-1)", EDOM, fa::sqrtf(-1.0));
    chk!("tgammaf(-1)", EDOM, fa::tgammaf(-1.0));
    chk!("fmodf(1,0)", EDOM, fa::fmodf(1.0, 0.0));
    chk!("powf(-2,0.5)", EDOM, fa::powf(-2.0, 0.5));

    // --- Poles (ERANGE): input-determined ---
    chk!("atanh(1)", ERANGE, fa::atanh(1.0));
    chk!("log(0)", ERANGE, fa::log(0.0));
    chk!("log2(0)", ERANGE, fa::log2(0.0));
    chk!("log10(0)", ERANGE, fa::log10(0.0));
    chk!("log1p(-1)", ERANGE, fa::log1p(-1.0));
    chk!("tgamma(0)", ERANGE, fa::tgamma(0.0));
    chk!("lgamma(0)", ERANGE, fa::lgamma(0.0));
    chk!("pow(0,-2)", ERANGE, fa::pow(0.0, -2.0));
    chk!("gamma(0)", ERANGE, fa::gamma(0.0));
    chk!("gamma(-1)", ERANGE, fa::gamma(-1.0));
    // Bessel Y poles at x=0 are RANGE errors (the fix): was wrongly EDOM.
    chk!("y0(0)", ERANGE, fa::y0(0.0));
    chk!("y1(0)", ERANGE, fa::y1(0.0));
    chk!("yn(2,0)", ERANGE, fa::yn(2, 0.0));
    chk!("y0f(0)", ERANGE, fa::y0f(0.0));
    chk!("y1f(0)", ERANGE, fa::y1f(0.0));
    chk!("ynf(2,0)", ERANGE, fa::ynf(2, 0.0));
    // f32 poles
    chk!("logf(0)", ERANGE, fa::logf(0.0));
    chk!("log1pf(-1)", ERANGE, fa::log1pf(-1.0));
    chk!("tgammaf(0)", ERANGE, fa::tgammaf(0.0));
    chk!("lgammaf(0)", ERANGE, fa::lgammaf(0.0));

    // --- Range errors on membrane-free / scaling functions (deterministic) ---
    chk!("fdim(big,-big)", ERANGE, fa::fdim(1e308, -1e308)); // f64 fdim: direct, no heal
    chk!("scalbn(1,100000)", ERANGE, fa::scalbn(1.0, 100000));
    chk!("scalbln(1,100000)", ERANGE, fa::scalbln(1.0, 100000));
    chk!("ldexp(1,100000)", ERANGE, fa::ldexp(1.0, 100000));
    chk!("scalbn(1,-100000)", ERANGE, fa::scalbn(1.0, -100000));
    chk!("ldexp(1,-100000)", ERANGE, fa::ldexp(1.0, -100000));

    // --- nextafter / nexttoward range errors (glibc rule) ---
    // overflow: finite -> infinite result
    chk!(
        "nextafter(dmax,inf)",
        ERANGE,
        fa::nextafter(f64::MAX, f64::INFINITY)
    );
    chk!(
        "nextafter(-dmax,-inf)",
        ERANGE,
        fa::nextafter(-f64::MAX, f64::NEG_INFINITY)
    );
    chk!(
        "nextafterf(fmax,inf)",
        ERANGE,
        fa::nextafterf(f32::MAX, f32::INFINITY)
    );
    chk!(
        "nexttoward(dmax,inf)",
        ERANGE,
        fa::nexttoward(f64::MAX, f64::INFINITY)
    );
    chk!(
        "nexttowardf(fmax,inf)",
        ERANGE,
        fa::nexttowardf(f32::MAX, f64::INFINITY)
    );
    // underflow: magnitude decreases into subnormal/zero
    chk!("nextafter(5e-324,0)", ERANGE, fa::nextafter(5e-324, 0.0));
    chk!(
        "nextafter(min_norm,0)",
        ERANGE,
        fa::nextafter(2.2250738585072014e-308, 0.0)
    );
    chk!("nexttoward(5e-324,0)", ERANGE, fa::nexttoward(5e-324, 0.0));
    // NOT a range error: nextafter(0, y) grows from 0 to smallest subnormal
    chk!("nextafter(0,1)", 0, fa::nextafter(0.0, 1.0));
    chk!("nextafter(1,2)", 0, fa::nextafter(1.0, 2.0));

    // --- significand(0): EDOM (no normalized mantissa) ---
    chk!("significand(0)", EDOM, fa::significand(0.0));
    chk!("significandf(0)", EDOM, fa::significandf(0.0));

    // --- logb(0): glibc raises FE flag only, errno stays 0 (NOT ERANGE) ---
    chk!("logb(0)", 0, fa::logb(0.0));
    chk!("logbf(0)", 0, fa::logbf(0.0));
    chk!("logb(inf)", 0, fa::logb(f64::INFINITY));

    // --- drem / dremf domain errors (glibc: x infinite OR y zero, no NaN operand) ---
    chk!("drem(1,0)", EDOM, fa::drem(1.0, 0.0));
    chk!("drem(inf,1)", EDOM, fa::drem(f64::INFINITY, 1.0));
    // Previously MISSED: both operands infinite (old guard required y finite).
    chk!(
        "drem(inf,inf)",
        EDOM,
        fa::drem(f64::INFINITY, f64::INFINITY)
    );
    chk!(
        "drem(-inf,-inf)",
        EDOM,
        fa::drem(f64::NEG_INFINITY, f64::NEG_INFINITY)
    );
    // Previously WRONG: a NaN operand must leave errno 0, even with y==0.
    chk!("drem(nan,0)", 0, fa::drem(f64::NAN, 0.0));
    chk!("drem(5,nan)", 0, fa::drem(5.0, f64::NAN));
    chk!("drem(inf,nan)", 0, fa::drem(f64::INFINITY, f64::NAN));
    chk!("drem(5,inf)", 0, fa::drem(5.0, f64::INFINITY)); // finite remainder, no error
    chk!("drem(5,3)", 0, fa::drem(5.0, 3.0));
    // dremf previously set NO errno at all.
    chk!("dremf(1,0)", EDOM, fa::dremf(1.0, 0.0));
    chk!("dremf(inf,1)", EDOM, fa::dremf(f32::INFINITY, 1.0));
    chk!(
        "dremf(inf,inf)",
        EDOM,
        fa::dremf(f32::INFINITY, f32::INFINITY)
    );
    chk!("dremf(nan,0)", 0, fa::dremf(f32::NAN, 0.0));
    chk!("dremf(5,nan)", 0, fa::dremf(5.0, f32::NAN));
    chk!("dremf(5,3)", 0, fa::dremf(5.0, 3.0));

    // --- Controls: no error ---
    chk!("sin(0.5)", 0, fa::sin(0.5));
    chk!("sqrt(4)", 0, fa::sqrt(4.0));
    chk!("log(2)", 0, fa::log(2.0));
    chk!("acos(0.5)", 0, fa::acos(0.5));
    chk!("j0(0)", 0, fa::j0(0.0));
    chk!("expm1(-1000)", 0, fa::expm1(-1000.0));
    chk!("y0(2)", 0, fa::y0(2.0));

    assert!(
        div.is_empty(),
        "math errno divergences vs glibc ({}):\n  {}",
        div.len(),
        div.join("\n  ")
    );
}
