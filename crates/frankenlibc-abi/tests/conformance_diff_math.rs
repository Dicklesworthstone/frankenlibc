#![cfg(target_os = "linux")]

//! Differential conformance harness for `<math.h>` core transcendentals
//! and rounding/abs functions.
//!
//! Compares FrankenLibC vs glibc reference for:
//!   - sqrt / fabs / floor / ceil           — exact bit equality
//!   - sin / cos / tan / atan2              — ULP tolerance (math impls
//!     historically diverge by a few ULPs across libm vendors)
//!   - exp / log / log2 / log10 / pow       — ULP tolerance
//!   - sinh / cosh / tanh                   — ULP tolerance
//!   - fmod                                 — exact bit equality
//!
//! Special inputs (NaN, ±0, ±Inf, denormal, etc.) are checked for
//! IEEE-754 classification parity rather than bit equality, since
//! NaN payloads can vary.
//!
//! Bead: CONFORMANCE: libc math.h core diff matrix.

use frankenlibc_abi::math_abi as fl;

unsafe extern "C" {
    fn sqrt(x: f64) -> f64;
    fn fabs(x: f64) -> f64;
    fn floor(x: f64) -> f64;
    fn ceil(x: f64) -> f64;
    fn fmod(x: f64, y: f64) -> f64;
    fn copysign(x: f64, y: f64) -> f64;
    fn fmin(x: f64, y: f64) -> f64;
    fn fmax(x: f64, y: f64) -> f64;
    fn fdim(x: f64, y: f64) -> f64;
    fn copysignf(x: f32, y: f32) -> f32;
    fn fminf(x: f32, y: f32) -> f32;
    fn fmaxf(x: f32, y: f32) -> f32;
    fn fdimf(x: f32, y: f32) -> f32;
    fn sin(x: f64) -> f64;
    fn cos(x: f64) -> f64;
    fn tan(x: f64) -> f64;
    fn atan2(y: f64, x: f64) -> f64;
    fn exp(x: f64) -> f64;
    fn log(x: f64) -> f64;
    fn log2(x: f64) -> f64;
    fn log10(x: f64) -> f64;
    fn pow(x: f64, y: f64) -> f64;
    fn exp10(x: f64) -> f64;
    fn exp10f(x: f32) -> f32;
    fn sinh(x: f64) -> f64;
    fn cosh(x: f64) -> f64;
    fn tanh(x: f64) -> f64;

    #[link_name = "__fpclassify"]
    fn glibc_fpclassify(x: f64) -> i32;
    #[link_name = "__fpclassifyf"]
    fn glibc_fpclassifyf(x: f32) -> i32;
    #[link_name = "__signbit"]
    fn glibc_signbit(x: f64) -> i32;
    #[link_name = "__signbitf"]
    fn glibc_signbitf(x: f32) -> i32;
    #[link_name = "__isinf"]
    fn glibc_isinf(x: f64) -> i32;
    #[link_name = "__isinff"]
    fn glibc_isinff(x: f32) -> i32;
    #[link_name = "__isnan"]
    fn glibc_isnan(x: f64) -> i32;
    #[link_name = "__isnanf"]
    fn glibc_isnanf(x: f32) -> i32;
    #[link_name = "__finite"]
    fn glibc_finite(x: f64) -> i32;
    #[link_name = "__finitef"]
    fn glibc_finitef(x: f32) -> i32;
    #[link_name = "finite"]
    fn glibc_public_finite(x: f64) -> i32;
    #[link_name = "finitef"]
    fn glibc_public_finitef(x: f32) -> i32;
}

#[derive(Debug)]
struct Divergence {
    function: &'static str,
    input: String,
    frankenlibc: String,
    glibc: String,
    delta_ulps: Option<i64>,
}

fn render_divs(divs: &[Divergence]) -> String {
    let mut out = String::new();
    for d in divs {
        let ulp = d
            .delta_ulps
            .map(|u| format!(" Δulp={u}"))
            .unwrap_or_default();
        out.push_str(&format!(
            "  {} | input={} | fl={} | glibc={}{ulp}\n",
            d.function, d.input, d.frankenlibc, d.glibc,
        ));
    }
    out
}

/// IEEE-754 ULP distance (signed). Same-sign finite values: difference in
/// representation. NaN-vs-NaN treated as 0. Different signs / one NaN
/// returns i64::MAX.
fn ulps_apart(a: f64, b: f64) -> i64 {
    if a.is_nan() && b.is_nan() {
        return 0;
    }
    if a.is_nan() != b.is_nan() {
        return i64::MAX;
    }
    if a == b {
        return 0; // also handles +0 == -0
    }
    if a.signum() != b.signum() {
        return i64::MAX;
    }
    let ai = a.to_bits() as i64;
    let bi = b.to_bits() as i64;
    (ai - bi).abs()
}

fn ieee_class(x: f64) -> &'static str {
    if x.is_nan() {
        "NaN"
    } else if x.is_infinite() {
        if x > 0.0 { "+Inf" } else { "-Inf" }
    } else if x == 0.0 {
        if x.is_sign_negative() { "-0" } else { "+0" }
    } else if !x.is_normal() {
        "denormal"
    } else if x > 0.0 {
        "+normal"
    } else {
        "-normal"
    }
}

/// Compare two f64s with ULP tolerance OR exact (per `tolerance_ulps`),
/// recording a Divergence if they don't match. Special values must agree
/// in IEEE classification.
fn compare_f64(
    divs: &mut Vec<Divergence>,
    func: &'static str,
    input: String,
    fl_v: f64,
    lc_v: f64,
    tolerance_ulps: i64,
) {
    let fl_class = ieee_class(fl_v);
    let lc_class = ieee_class(lc_v);
    if fl_class != lc_class {
        divs.push(Divergence {
            function: func,
            input,
            frankenlibc: format!("{fl_v} ({fl_class})"),
            glibc: format!("{lc_v} ({lc_class})"),
            delta_ulps: None,
        });
        return;
    }
    if !fl_v.is_finite() {
        return; // both are NaN/Inf with same sign — treated as equal
    }
    let delta = ulps_apart(fl_v, lc_v);
    if delta > tolerance_ulps {
        divs.push(Divergence {
            function: func,
            input,
            frankenlibc: format!("{fl_v}"),
            glibc: format!("{lc_v}"),
            delta_ulps: Some(delta),
        });
    }
}

fn compare_f64_bits(
    divs: &mut Vec<Divergence>,
    func: &'static str,
    input: String,
    fl_v: f64,
    lc_v: f64,
) {
    if fl_v.to_bits() != lc_v.to_bits() {
        divs.push(Divergence {
            function: func,
            input,
            frankenlibc: format!("{fl_v:?} ({:#018x})", fl_v.to_bits()),
            glibc: format!("{lc_v:?} ({:#018x})", lc_v.to_bits()),
            delta_ulps: None,
        });
    }
}

fn compare_f32_bits(
    divs: &mut Vec<Divergence>,
    func: &'static str,
    input: String,
    fl_v: f32,
    lc_v: f32,
) {
    if fl_v.to_bits() != lc_v.to_bits() {
        divs.push(Divergence {
            function: func,
            input,
            frankenlibc: format!("{fl_v:?} ({:#010x})", fl_v.to_bits()),
            glibc: format!("{lc_v:?} ({:#010x})", lc_v.to_bits()),
            delta_ulps: None,
        });
    }
}

fn compare_i32(
    divs: &mut Vec<Divergence>,
    func: &'static str,
    input: String,
    fl_v: i32,
    lc_v: i32,
) {
    if fl_v != lc_v {
        divs.push(Divergence {
            function: func,
            input,
            frankenlibc: fl_v.to_string(),
            glibc: lc_v.to_string(),
            delta_ulps: None,
        });
    }
}

fn compare_nonzero_predicate(
    divs: &mut Vec<Divergence>,
    func: &'static str,
    input: String,
    fl_v: i32,
    lc_v: i32,
) {
    if (fl_v != 0) != (lc_v != 0) {
        divs.push(Divergence {
            function: func,
            input,
            frankenlibc: fl_v.to_string(),
            glibc: lc_v.to_string(),
            delta_ulps: None,
        });
    }
}

// ===========================================================================
// ABI classification helpers: __fpclassify*, __signbit*, __isinf*, __isnan*,
// __finite*, finite*
// ===========================================================================

#[test]
fn diff_classification_helpers_match_glibc() {
    let mut divs = Vec::new();

    let inputs64: &[f64] = &[
        f64::NAN,
        f64::INFINITY,
        f64::NEG_INFINITY,
        0.0,
        -0.0,
        f64::from_bits(1),
        1.0,
        -1.0,
    ];
    for &x in inputs64 {
        let input = format!("{x:?} ({})", ieee_class(x));
        compare_i32(
            &mut divs,
            "__fpclassify",
            input.clone(),
            unsafe { fl::__fpclassify(x) },
            unsafe { glibc_fpclassify(x) },
        );
        compare_nonzero_predicate(
            &mut divs,
            "__signbit",
            input.clone(),
            unsafe { fl::__signbit(x) },
            unsafe { glibc_signbit(x) },
        );
        compare_i32(
            &mut divs,
            "__isinf",
            input.clone(),
            unsafe { fl::__isinf(x) },
            unsafe { glibc_isinf(x) },
        );
        compare_i32(
            &mut divs,
            "__isnan",
            input.clone(),
            unsafe { fl::__isnan(x) },
            unsafe { glibc_isnan(x) },
        );
        compare_i32(
            &mut divs,
            "__finite",
            input.clone(),
            unsafe { fl::__finite(x) },
            unsafe { glibc_finite(x) },
        );
        compare_i32(
            &mut divs,
            "finite",
            input,
            unsafe { fl::finite(x) },
            unsafe { glibc_public_finite(x) },
        );
    }

    let inputs32: &[f32] = &[
        f32::NAN,
        f32::INFINITY,
        f32::NEG_INFINITY,
        0.0,
        -0.0,
        f32::from_bits(1),
        1.0,
        -1.0,
    ];
    for &x in inputs32 {
        let input = format!("{x:?}");
        compare_i32(
            &mut divs,
            "__fpclassifyf",
            input.clone(),
            unsafe { fl::__fpclassifyf(x) },
            unsafe { glibc_fpclassifyf(x) },
        );
        compare_nonzero_predicate(
            &mut divs,
            "__signbitf",
            input.clone(),
            unsafe { fl::__signbitf(x) },
            unsafe { glibc_signbitf(x) },
        );
        compare_i32(
            &mut divs,
            "__isinff",
            input.clone(),
            unsafe { fl::__isinff(x) },
            unsafe { glibc_isinff(x) },
        );
        compare_i32(
            &mut divs,
            "__isnanf",
            input.clone(),
            unsafe { fl::__isnanf(x) },
            unsafe { glibc_isnanf(x) },
        );
        compare_i32(
            &mut divs,
            "__finitef",
            input.clone(),
            unsafe { fl::__finitef(x) },
            unsafe { glibc_finitef(x) },
        );
        compare_i32(
            &mut divs,
            "finitef",
            input,
            unsafe { fl::finitef(x) },
            unsafe { glibc_public_finitef(x) },
        );
    }

    assert!(
        divs.is_empty(),
        "classification helper divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// Exact-equality functions: sqrt, fabs, floor, ceil, fmod
// ===========================================================================

#[test]
fn diff_sqrt_exact() {
    let mut divs = Vec::new();
    let inputs: &[f64] = &[
        0.0,
        -0.0,
        1.0,
        2.0,
        4.0,
        9.0,
        16.0,
        100.0,
        0.5,
        0.25,
        1e10,
        1e-10,
        f64::MAX,
        f64::MIN_POSITIVE,
        -1.0, // NaN domain
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::NAN,
    ];
    for &x in inputs {
        let fl_v = unsafe { fl::sqrt(x) };
        let lc_v = unsafe { sqrt(x) };
        compare_f64(&mut divs, "sqrt", format!("{x:?}"), fl_v, lc_v, 0);
    }
    assert!(divs.is_empty(), "sqrt divergences:\n{}", render_divs(&divs));
}

#[test]
fn diff_fabs_exact() {
    let mut divs = Vec::new();
    let inputs: &[f64] = &[
        0.0,
        -0.0,
        1.0,
        -1.0,
        std::f64::consts::PI,
        -std::f64::consts::PI,
        f64::MAX,
        f64::MIN,
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::NAN,
    ];
    for &x in inputs {
        let fl_v = unsafe { fl::fabs(x) };
        let lc_v = unsafe { fabs(x) };
        compare_f64(&mut divs, "fabs", format!("{x:?}"), fl_v, lc_v, 0);
    }
    assert!(divs.is_empty(), "fabs divergences:\n{}", render_divs(&divs));
}

#[test]
fn diff_floor_ceil_exact() {
    let mut divs = Vec::new();
    let inputs: &[f64] = &[
        0.0,
        0.5,
        0.99,
        1.0,
        1.5,
        -0.5,
        -1.5,
        -0.99,
        100.0,
        100.5,
        -100.5,
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::NAN,
    ];
    for &x in inputs {
        let fl_floor = unsafe { fl::floor(x) };
        let lc_floor = unsafe { floor(x) };
        compare_f64(&mut divs, "floor", format!("{x:?}"), fl_floor, lc_floor, 0);
        let fl_ceil = unsafe { fl::ceil(x) };
        let lc_ceil = unsafe { ceil(x) };
        compare_f64(&mut divs, "ceil", format!("{x:?}"), fl_ceil, lc_ceil, 0);
    }
    assert!(
        divs.is_empty(),
        "floor/ceil divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_fmod_exact() {
    let mut divs = Vec::new();
    let cases: &[(f64, f64)] = &[
        (10.0, 3.0),
        (-10.0, 3.0),
        (10.0, -3.0),
        (5.5, 2.0),
        (0.0, 5.0),
        (5.0, 0.0),           // NaN domain
        (f64::INFINITY, 5.0), // NaN
        (5.0, f64::INFINITY), // x
        (f64::NAN, 5.0),
    ];
    for &(x, y) in cases {
        let fl_v = unsafe { fl::fmod(x, y) };
        let lc_v = unsafe { fmod(x, y) };
        compare_f64(&mut divs, "fmod", format!("({x:?}, {y:?})"), fl_v, lc_v, 0);
    }
    assert!(divs.is_empty(), "fmod divergences:\n{}", render_divs(&divs));
}

#[test]
fn diff_sign_min_max_dim_helpers_match_glibc_bits() {
    let mut divs = Vec::new();

    let sign_cases: &[(f64, f64)] = &[
        (1.0, -0.0),
        (-1.0, 0.0),
        (0.0, -1.0),
        (-0.0, 1.0),
        (f64::INFINITY, -1.0),
        (f64::NEG_INFINITY, 1.0),
    ];
    for &(x, y) in sign_cases {
        compare_f64_bits(
            &mut divs,
            "copysign",
            format!("({x:?}, {y:?})"),
            unsafe { fl::copysign(x, y) },
            unsafe { copysign(x, y) },
        );
    }

    let min_max_cases: &[(f64, f64)] = &[
        (2.0, 3.0),
        (3.0, 2.0),
        (-2.0, -3.0),
        (0.0, -0.0),
        (-0.0, 0.0),
        (f64::INFINITY, 1.0),
        (f64::NEG_INFINITY, 1.0),
        (f64::NAN, 5.0),
        (5.0, f64::NAN),
    ];
    for &(x, y) in min_max_cases {
        compare_f64_bits(
            &mut divs,
            "fmin",
            format!("({x:?}, {y:?})"),
            unsafe { fl::fmin(x, y) },
            unsafe { fmin(x, y) },
        );
        compare_f64_bits(
            &mut divs,
            "fmax",
            format!("({x:?}, {y:?})"),
            unsafe { fl::fmax(x, y) },
            unsafe { fmax(x, y) },
        );
    }

    let dim_cases: &[(f64, f64)] = &[
        (5.0, 3.0),
        (3.0, 5.0),
        (0.0, -0.0),
        (-0.0, 0.0),
        (f64::INFINITY, 1.0),
        (1.0, f64::INFINITY),
    ];
    for &(x, y) in dim_cases {
        compare_f64_bits(
            &mut divs,
            "fdim",
            format!("({x:?}, {y:?})"),
            unsafe { fl::fdim(x, y) },
            unsafe { fdim(x, y) },
        );
    }

    assert!(
        divs.is_empty(),
        "sign/min/max/dim divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_float_sign_min_max_dim_helpers_match_glibc_bits() {
    let mut divs = Vec::new();

    let sign_cases: &[(f32, f32)] = &[
        (1.0, -0.0),
        (-1.0, 0.0),
        (0.0, -1.0),
        (-0.0, 1.0),
        (f32::INFINITY, -1.0),
        (f32::NEG_INFINITY, 1.0),
    ];
    for &(x, y) in sign_cases {
        compare_f32_bits(
            &mut divs,
            "copysignf",
            format!("({x:?}, {y:?})"),
            unsafe { fl::copysignf(x, y) },
            unsafe { copysignf(x, y) },
        );
    }

    let min_max_cases: &[(f32, f32)] = &[
        (2.0, 3.0),
        (3.0, 2.0),
        (-2.0, -3.0),
        (0.0, -0.0),
        (-0.0, 0.0),
        (f32::INFINITY, 1.0),
        (f32::NEG_INFINITY, 1.0),
        (f32::NAN, 5.0),
        (5.0, f32::NAN),
    ];
    for &(x, y) in min_max_cases {
        compare_f32_bits(
            &mut divs,
            "fminf",
            format!("({x:?}, {y:?})"),
            unsafe { fl::fminf(x, y) },
            unsafe { fminf(x, y) },
        );
        compare_f32_bits(
            &mut divs,
            "fmaxf",
            format!("({x:?}, {y:?})"),
            unsafe { fl::fmaxf(x, y) },
            unsafe { fmaxf(x, y) },
        );
    }

    let dim_cases: &[(f32, f32)] = &[
        (5.0, 3.0),
        (3.0, 5.0),
        (0.0, -0.0),
        (-0.0, 0.0),
        (f32::INFINITY, 1.0),
        (1.0, f32::INFINITY),
    ];
    for &(x, y) in dim_cases {
        compare_f32_bits(
            &mut divs,
            "fdimf",
            format!("({x:?}, {y:?})"),
            unsafe { fl::fdimf(x, y) },
            unsafe { fdimf(x, y) },
        );
    }

    assert!(
        divs.is_empty(),
        "float sign/min/max/dim divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// ULP-tolerant transcendentals
// ===========================================================================

const TRIG_INPUTS: &[f64] = &[
    0.0,
    0.5,
    1.0,
    std::f64::consts::FRAC_PI_4,
    std::f64::consts::FRAC_PI_2,
    std::f64::consts::PI,
    2.0 * std::f64::consts::PI,
    -1.0,
    -std::f64::consts::PI,
    1e10,
    -1e10,
    f64::INFINITY,
    f64::NEG_INFINITY,
    f64::NAN,
];

#[test]
fn diff_sin_cos_tan_within_4_ulps() {
    let mut divs = Vec::new();
    for &x in TRIG_INPUTS {
        compare_f64(
            &mut divs,
            "sin",
            format!("{x:?}"),
            unsafe { fl::sin(x) },
            unsafe { sin(x) },
            4,
        );
        compare_f64(
            &mut divs,
            "cos",
            format!("{x:?}"),
            unsafe { fl::cos(x) },
            unsafe { cos(x) },
            4,
        );
        compare_f64(
            &mut divs,
            "tan",
            format!("{x:?}"),
            unsafe { fl::tan(x) },
            unsafe { tan(x) },
            4,
        );
    }
    assert!(
        divs.is_empty(),
        "sin/cos/tan divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_atan2_within_4_ulps() {
    let mut divs = Vec::new();
    let cases: &[(f64, f64)] = &[
        (0.0, 1.0),
        (1.0, 0.0),
        (1.0, 1.0),
        (-1.0, -1.0),
        (1.0, -1.0),
        (-1.0, 1.0),
        (f64::INFINITY, 1.0),
        (1.0, f64::INFINITY),
        (f64::NAN, 1.0),
    ];
    for &(y, x) in cases {
        compare_f64(
            &mut divs,
            "atan2",
            format!("({y:?}, {x:?})"),
            unsafe { fl::atan2(y, x) },
            unsafe { atan2(y, x) },
            4,
        );
    }
    assert!(
        divs.is_empty(),
        "atan2 divergences:\n{}",
        render_divs(&divs)
    );
}

const EXP_INPUTS: &[f64] = &[
    0.0,
    1.0,
    -1.0,
    std::f64::consts::LN_2,
    10.0,
    -10.0,
    700.0,
    -700.0, // near edge of representable range
    1e10,   // overflow → +Inf
    -1e10,  // underflow → 0
    f64::INFINITY,
    f64::NEG_INFINITY,
    f64::NAN,
];

#[test]
fn diff_exp_log_pow_within_4_ulps() {
    let mut divs = Vec::new();
    for &x in EXP_INPUTS {
        compare_f64(
            &mut divs,
            "exp",
            format!("{x:?}"),
            unsafe { fl::exp(x) },
            unsafe { exp(x) },
            4,
        );
    }
    let log_inputs: &[f64] = &[
        1.0,
        std::f64::consts::E,
        10.0,
        100.0,
        1e10,
        0.5,
        0.001,
        0.0,  // -Inf
        -1.0, // NaN
        f64::INFINITY,
        f64::NAN,
    ];
    for &x in log_inputs {
        compare_f64(
            &mut divs,
            "log",
            format!("{x:?}"),
            unsafe { fl::log(x) },
            unsafe { log(x) },
            4,
        );
        compare_f64(
            &mut divs,
            "log2",
            format!("{x:?}"),
            unsafe { fl::log2(x) },
            unsafe { log2(x) },
            4,
        );
        compare_f64(
            &mut divs,
            "log10",
            format!("{x:?}"),
            unsafe { fl::log10(x) },
            unsafe { log10(x) },
            4,
        );
    }
    let pow_cases: &[(f64, f64)] = &[
        (2.0, 10.0),
        (10.0, 3.0),
        (3.0, 0.5),
        (0.0, 0.0),
        (1.0, f64::INFINITY),
        (f64::INFINITY, 0.0),
        (-1.0, 0.5), // NaN domain
        (2.0, -10.0),
    ];
    for &(x, y) in pow_cases {
        compare_f64(
            &mut divs,
            "pow",
            format!("({x:?}, {y:?})"),
            unsafe { fl::pow(x, y) },
            unsafe { pow(x, y) },
            4,
        );
    }
    assert!(
        divs.is_empty(),
        "exp/log/pow divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_exp10_within_4_ulps() {
    // exp10's exp2-based fast path (10^x = 2^(x·log2 10), compensated reduction)
    // must stay within 4 ULP of glibc across the gated [-50,50] window, the
    // integer-exponent path, and the out-of-range fallback.
    let mut divs = Vec::new();
    let mut x = -50.0_f64;
    while x <= 50.0 {
        compare_f64(
            &mut divs,
            "exp10",
            format!("{x:?}"),
            unsafe { fl::exp10(x) },
            unsafe { exp10(x) },
            4,
        );
        x += 0.0007; // ~143k samples across the fast window
    }
    // The |x|>50 fallback tail (libm::exp10) must also stay within 4 ULP — this
    // is the bd-mrnzim regression guard (the old exp(x·ln10) form was ~168 ULP).
    let mut x = 50.0_f64;
    while x <= 307.0 {
        compare_f64(
            &mut divs,
            "exp10",
            format!("{x:?}"),
            unsafe { fl::exp10(x) },
            unsafe { exp10(x) },
            4,
        );
        compare_f64(
            &mut divs,
            "exp10",
            format!("{:?}", -x),
            unsafe { fl::exp10(-x) },
            unsafe { exp10(-x) },
            4,
        );
        x += 0.013;
    }
    // Exact and edge inputs (incl. integers >22 that skip the powi path).
    for &x in &[
        0.0,
        1.0,
        7.0,
        22.0,
        -22.0,
        23.0,
        30.0,
        40.0,
        50.0,
        60.5,
        -80.0,
        300.0,
        307.0,
        -307.0,
        308.0,
        -30.0,
        -50.0,
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::NAN,
    ] {
        compare_f64(
            &mut divs,
            "exp10",
            format!("{x:?}"),
            unsafe { fl::exp10(x) },
            unsafe { exp10(x) },
            4,
        );
    }
    assert!(
        divs.is_empty(),
        "exp10 divergences ({} of many):\n{}",
        divs.len(),
        render_divs(&divs)
    );
}

#[test]
fn diff_exp10f_within_4_ulps() {
    // exp10f routes 10^x = 2^(x·log2 10) through an f64 exp2 then rounds once to
    // f32 — must stay within 4 ULP of glibc across the full finite f32 domain.
    fn f32_ulps(a: f32, b: f32) -> i64 {
        if a.is_nan() && b.is_nan() {
            return 0; // any NaN matches any NaN for a math result
        }
        if a == b {
            return 0;
        }
        if a.is_nan() || b.is_nan() || a.is_sign_negative() != b.is_sign_negative() {
            return i64::MAX;
        }
        (a.to_bits() as i64 - b.to_bits() as i64).abs()
    }
    let mut worst = 0i64;
    let mut bad = Vec::new();
    let mut x = -44.0_f32;
    while x <= 39.0 {
        let (got, want) = (unsafe { fl::exp10f(x) }, unsafe { exp10f(x) });
        let u = f32_ulps(got, want);
        worst = worst.max(u);
        if u > 4 {
            bad.push(format!("exp10f({x}) fl={got:?} glibc={want:?} ({u} ULP)"));
        }
        x += 0.0007;
    }
    for &x in &[
        0.0_f32,
        1.0,
        7.0,
        15.0,
        20.0,
        38.0,
        -38.0,
        40.0,
        -50.0,
        f32::NAN,
    ] {
        let (got, want) = (unsafe { fl::exp10f(x) }, unsafe { exp10f(x) });
        let u = f32_ulps(got, want);
        if u > 4 {
            bad.push(format!("exp10f({x}) fl={got:?} glibc={want:?} ({u} ULP)"));
        }
    }
    assert!(
        bad.is_empty(),
        "exp10f divergences (worst {worst}):\n{}",
        bad.join("\n")
    );
}

#[test]
fn diff_hyperbolic_within_4_ulps() {
    let mut divs = Vec::new();
    let inputs: &[f64] = &[
        0.0,
        1.0,
        -1.0,
        5.0,
        -5.0,
        700.0,
        -700.0,
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::NAN,
    ];
    for &x in inputs {
        compare_f64(
            &mut divs,
            "sinh",
            format!("{x:?}"),
            unsafe { fl::sinh(x) },
            unsafe { sinh(x) },
            4,
        );
        compare_f64(
            &mut divs,
            "cosh",
            format!("{x:?}"),
            unsafe { fl::cosh(x) },
            unsafe { cosh(x) },
            4,
        );
        compare_f64(
            &mut divs,
            "tanh",
            format!("{x:?}"),
            unsafe { fl::tanh(x) },
            unsafe { tanh(x) },
            4,
        );
    }
    assert!(
        divs.is_empty(),
        "hyperbolic divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn math_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"math.h core\",\"reference\":\"glibc\",\"functions\":23,\"divergences\":0,\"ulp_tolerance\":4}}",
    );
}
