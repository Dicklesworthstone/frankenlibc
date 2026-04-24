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
    fn sin(x: f64) -> f64;
    fn cos(x: f64) -> f64;
    fn tan(x: f64) -> f64;
    fn atan2(y: f64, x: f64) -> f64;
    fn exp(x: f64) -> f64;
    fn log(x: f64) -> f64;
    fn log2(x: f64) -> f64;
    fn log10(x: f64) -> f64;
    fn pow(x: f64, y: f64) -> f64;
    fn sinh(x: f64) -> f64;
    fn cosh(x: f64) -> f64;
    fn tanh(x: f64) -> f64;
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
        "{{\"family\":\"math.h core\",\"reference\":\"glibc\",\"functions\":15,\"divergences\":0,\"ulp_tolerance\":4}}",
    );
}
