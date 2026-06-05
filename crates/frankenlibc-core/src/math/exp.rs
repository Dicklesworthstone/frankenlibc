//! Exponential and logarithmic functions.

#[inline]
pub fn exp(x: f64) -> f64 {
    if let Some(result) = exp_medium_exp2_fast_path(x) {
        return result;
    }
    libm::exp(x)
}

#[inline]
pub fn exp2(x: f64) -> f64 {
    libm::exp2(x)
}

#[inline]
pub fn expm1(x: f64) -> f64 {
    libm::expm1(x)
}

#[inline]
pub fn log(x: f64) -> f64 {
    libm::log(x)
}

/// `log2` via the cheaper natural-log kernel: `log2(x) = ln(x) * log2(e)`.
///
/// Profiling (`glibc_baseline_math`, bd-e4jb7k) showed `libm::log2` (~12.2 ns)
/// is markedly slower than `libm::log` (~9.5 ns) — glibc's `log2` (~9.0 ns) is
/// hand-tuned, leaving fl `log2` ~1.35x behind. Routing through `libm::log`
/// scaled by `LOG2_E` reaches glibc parity. A 4M-point sweep (full dynamic
/// range + the near-1 region where `log2 -> 0`) bounds the result within 2 ULP
/// of `libm::log2` (itself correctly rounded), so within the established
/// 4-ULP-vs-glibc math contract shared by the exp/pow fast paths.
///
/// Exact powers of two are gated out (mantissa bits all zero) so glibc's exact
/// integer result (`log2(2^k) == k`) is preserved bit-for-bit; subnormals,
/// non-positive, and non-finite inputs defer to `libm::log2` for its precise
/// special-case handling.
#[inline]
pub fn log2(x: f64) -> f64 {
    if x.is_normal() && x > 0.0 && x.to_bits() & 0x000F_FFFF_FFFF_FFFF != 0 {
        return libm::log(x) * std::f64::consts::LOG2_E;
    }
    libm::log2(x)
}

/// `log10` via the cheaper natural-log kernel: `log10(x) = ln(x) * log10(e)`.
///
/// Profiling (`glibc_baseline_math/log10`, bd-2g7oyh) showed `libm::log10`
/// (~13 ns) is slower than `libm::log` (~9.5 ns); glibc's `log10` is hand-tuned,
/// leaving fl `log10` ~1.07x behind. Routing through `libm::log` scaled by
/// `LOG10_E` is ~1.34x faster on the kernel and beats glibc. A 4M-point sweep
/// bounds it within 2 ULP of glibc (`f64::log10`) across the full dynamic range
/// and near 1 — within the 4-ULP-vs-glibc contract shared by the exp/pow/log2
/// fast paths (mirrors the f64 `log2` reroute).
///
/// At exactly-representable powers of ten the fast form is ~1 ULP off glibc's
/// exact integer — within the 4-ULP contract (an exactness gate was measured to
/// cost more than the reroute saves, since `round`/casts are libm calls or extra
/// branches on baseline x86-64). Subnormal / non-positive / non-finite inputs
/// defer to `libm::log10` for its precise special-case handling.
#[inline]
pub fn log10(x: f64) -> f64 {
    if x.is_normal() && x > 0.0 {
        return libm::log(x) * core::f64::consts::LOG10_E;
    }
    libm::log10(x)
}

#[inline]
pub fn log1p(x: f64) -> f64 {
    libm::log1p(x)
}

const EXP_MEDIUM_MIN: f64 = 0.5;
const EXP_MEDIUM_MAX: f64 = 2.5;
const POW_MEDIUM_EXP_MIN: f64 = -3.0;
const POW_MEDIUM_EXP_MAX: f64 = 3.0;

/// Range over which `exp(x) = exp2(x * log2e)` stays within 4 ULP of glibc.
/// The error is dominated by the rounding of the `x*log2e` product (~0.5*|x|
/// ULP after exp2 amplification), so it stays <=4 ULP up to |x| = 5 and jumps
/// to ~7 ULP by |x| = 6 (measured by a 2M-point sweep). libm::exp2 is markedly
/// cheaper than libm::exp, so this covers the common decay/softmax ranges that
/// previously fell to the slower libm::exp path. Note this is the EXP argument
/// range, distinct from the [`EXP_MEDIUM_MIN`]/[`EXP_MEDIUM_MAX`] pow-base gate.
const EXP_FAST_MIN: f64 = -5.0;
const EXP_FAST_MAX: f64 = 5.0;

/// Fast path for the finite `[-5, 5]` interval via the exp2 kernel. Values
/// outside it retain the previous libm::exp behavior bit-for-bit.
#[inline]
fn exp_medium_exp2_fast_path(x: f64) -> Option<f64> {
    if (EXP_FAST_MIN..=EXP_FAST_MAX).contains(&x) {
        Some(libm::exp2(x * std::f64::consts::LOG2_E))
    } else {
        None
    }
}

/// `base` raised to a small integer power via exponentiation by squaring.
/// `n.unsigned_abs()` must be small (the caller gates on `<= POWI_MAX_EXP`) so
/// the multiply chain stays well inside the 4-ULP glibc parity budget.
#[inline]
fn powi_squaring(base: f64, n: i64) -> f64 {
    let mut result = 1.0_f64;
    let mut b = base;
    let mut e = n.unsigned_abs();
    while e > 0 {
        if e & 1 == 1 {
            result *= b;
        }
        e >>= 1;
        if e > 0 {
            b *= b;
        }
    }
    if n < 0 { 1.0 / result } else { result }
}

/// `base` raised to a small half-integer exponent via `base^n * sqrt(base)`.
/// The caller only reaches this for strictly positive finite bases, so libm's
/// negative/zero/special-case semantics remain on the general path.
#[inline]
fn pow_half_integer_fast_path(base: f64, exponent: f64) -> Option<f64> {
    if !(base > 0.0 && base.is_finite() && exponent.is_finite()) {
        return None;
    }

    let shifted = exponent - 0.5;
    let n = shifted as i64;
    if n as f64 == shifted && n.unsigned_abs() <= POWI_MAX_EXP {
        Some(powi_squaring(base, n) * base.sqrt())
    } else {
        None
    }
}

/// Fast path for positive finite medium bases and bounded non-special
/// exponents. The caller reaches this after the integer and half-integer
/// fast paths, so the remaining profiled workload is the general positive
/// finite path where `pow` would otherwise pay its full IEEE classifier.
#[inline]
fn pow_medium_log2_exp2_fast_path(base: f64, exponent: f64) -> Option<f64> {
    if (EXP_MEDIUM_MIN..EXP_MEDIUM_MAX).contains(&base)
        && (POW_MEDIUM_EXP_MIN..=POW_MEDIUM_EXP_MAX).contains(&exponent)
    {
        Some(libm::exp2(exponent * libm::log2(base)))
    } else {
        None
    }
}

/// Largest |integer exponent| handled by the fast path. Each squaring/multiply
/// adds at most ~0.5 ULP; capping the magnitude here keeps the result within
/// the 4-ULP-vs-glibc contract (verified by `pow_integer_fast_path_within_4_ulps`).
const POWI_MAX_EXP: u64 = 8;

#[inline]
pub fn pow(base: f64, exponent: f64) -> f64 {
    // Fast path: small integer exponents (and y == 0.5) on a finite base.
    // libm::pow always routes through the general log2/exp2 path (~3.3x slower
    // than glibc); exponentiation by squaring is ~10x faster and, bounded to
    // small magnitudes, stays within the 4-ULP glibc parity contract. Non-finite
    // bases, large/non-integer exponents, etc. defer to libm for exact IEEE
    // special-case semantics.
    if base.is_finite() && exponent.is_finite() {
        let n = exponent as i64;
        if n as f64 == exponent && n.unsigned_abs() <= POWI_MAX_EXP {
            return powi_squaring(base, n);
        }
        if exponent == 0.5 && base >= 0.0 {
            return base.sqrt();
        }
        if let Some(result) = pow_half_integer_fast_path(base, exponent) {
            return result;
        }
        if let Some(result) = pow_medium_log2_exp2_fast_path(base, exponent) {
            return result;
        }
    }
    libm::pow(base, exponent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use proptest::test_runner::Config as ProptestConfig;

    fn property_proptest_config(default_cases: u32) -> ProptestConfig {
        let cases = std::env::var("FRANKENLIBC_PROPTEST_CASES")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|&value| value > 0)
            .unwrap_or(default_cases);

        ProptestConfig {
            cases,
            failure_persistence: None,
            ..ProptestConfig::default()
        }
    }

    fn approx_eq(lhs: f64, rhs: f64, abs_tol: f64, rel_tol: f64) -> bool {
        let diff = (lhs - rhs).abs();
        diff <= abs_tol.max(rel_tol * lhs.abs().max(rhs.abs()))
    }

    /// 4-ULP comparison (the math conformance contract). `f64::powf` resolves
    /// to the host glibc `pow`, so this pins the fast path against glibc itself.
    fn within_ulps(a: f64, b: f64, ulps: u64) -> bool {
        if a == b {
            return true;
        }
        if a.is_nan() || b.is_nan() || a.is_sign_negative() != b.is_sign_negative() {
            return false;
        }
        let ab = a.to_bits() as i64;
        let bb = b.to_bits() as i64;
        (ab - bb).unsigned_abs() <= ulps
    }

    #[test]
    fn pow_integer_fast_path_within_4_ulps() {
        // Sweep the gated fast-path domain (|n| <= POWI_MAX_EXP, plus 0.5) over a
        // wide spread of finite bases incl. negatives, zeros, sub/huge, and verify
        // every result is within 4 ULP of the host glibc pow (f64::powf).
        let bases = [
            0.0,
            -0.0,
            1.0,
            -1.0,
            2.0,
            -2.0,
            0.5,
            -0.5,
            std::f64::consts::PI,
            -std::f64::consts::PI,
            1.785,
            1e-3,
            -1e-3,
            1e6,
            -1e6,
            1e150,
            1e-150,
            123.456,
            -123.456,
            0.999_999,
            1.000_001,
        ];
        for &base in &bases {
            for n in -(POWI_MAX_EXP as i64)..=(POWI_MAX_EXP as i64) {
                let exp_f = n as f64;
                let got = pow(base, exp_f);
                let want = base.powf(exp_f);
                assert!(
                    within_ulps(got, want, 4),
                    "pow({base}, {exp_f}) = {got:?} but glibc = {want:?} (>4 ULP)"
                );
            }
            if base >= 0.0 {
                let got = pow(base, 0.5);
                let want = base.powf(0.5);
                assert!(
                    within_ulps(got, want, 4),
                    "pow({base}, 0.5) = {got:?} but glibc = {want:?}"
                );
            }
        }
    }

    #[test]
    fn log2_fast_path_within_4_ulps_of_glibc() {
        // `f64::log2` lowers to the host glibc `log2`, so this pins the
        // `ln(x) * log2(e)` fast path directly against glibc. Sweep the full
        // dynamic range geometrically, the near-1 region (where log2 -> 0 and
        // relative error is most sensitive), and a spread of fixed points.
        let mut x = 1e-300_f64;
        while x < 1e300 {
            assert!(
                within_ulps(log2(x), x.log2(), 4),
                "log2({x:e}) = {:?} but glibc = {:?} (>4 ULP)",
                log2(x),
                x.log2()
            );
            x *= 1.0000071;
        }
        for d in 0..1_000_000i64 {
            let x = 1.0 + (d as f64) * 2e-9;
            assert!(within_ulps(log2(x), x.log2(), 4), "near-1 log2({x}) >4 ULP");
        }
        for &x in &[
            0.5,
            0.323,
            std::f64::consts::E,
            std::f64::consts::PI,
            1e-3,
            1e3,
            123.456,
            f64::MIN_POSITIVE,
            f64::MAX,
        ] {
            assert!(within_ulps(log2(x), x.log2(), 4), "log2({x:e}) >4 ULP");
        }
        // Exact powers of two must match glibc bit-for-bit (gated to libm::log2).
        for k in -1074i32..=1023 {
            let p = (k as f64).exp2();
            if !p.is_normal() {
                continue;
            }
            assert_eq!(
                log2(p).to_bits(),
                p.log2().to_bits(),
                "log2(2^{k}) not bit-exact vs glibc"
            );
        }
        // Special inputs defer to libm::log2 and match glibc exactly.
        assert!(log2(f64::NAN).is_nan());
        assert_eq!(log2(f64::INFINITY), f64::INFINITY);
        assert_eq!(log2(1.0).to_bits(), 0.0_f64.to_bits());
        assert_eq!(log2(0.0), f64::NEG_INFINITY);
        assert!(log2(-1.0).is_nan());
    }

    #[test]
    fn log10_fast_path_within_4_ulps_of_glibc() {
        // `f64::log10` lowers to host glibc, pinning the `ln(x) * log10(e)` fast
        // path directly against it.
        let mut x = 1e-300_f64;
        while x < 1e300 {
            assert!(
                within_ulps(log10(x), x.log10(), 4),
                "log10({x:e}) = {:?} but glibc = {:?} (>4 ULP)",
                log10(x),
                x.log10()
            );
            x *= 1.0000071;
        }
        for d in 0..1_000_000i64 {
            let x = 1.0 + (d as f64) * 2e-9;
            assert!(
                within_ulps(log10(x), x.log10(), 4),
                "near-1 log10({x}) >4 ULP"
            );
        }
        for &x in &[
            0.5,
            0.323,
            std::f64::consts::E,
            std::f64::consts::PI,
            1e-3,
            1e3,
            123.456,
            f64::MIN_POSITIVE,
            f64::MAX,
        ] {
            assert!(within_ulps(log10(x), x.log10(), 4), "log10({x:e}) >4 ULP");
        }
        // Powers of ten stay within 4 ULP of glibc (no exactness gate — the
        // fast form is ~1 ULP off the exact integer at 10^0..10^22).
        for k in -307i32..=308 {
            let p = libm::exp10(k as f64);
            if p.is_normal() {
                assert!(within_ulps(log10(p), p.log10(), 4), "log10(10^{k}) >4 ULP");
            }
        }
        // Special inputs defer to libm::log10 and match glibc exactly.
        assert!(log10(f64::NAN).is_nan());
        assert_eq!(log10(f64::INFINITY), f64::INFINITY);
        assert_eq!(log10(1.0).to_bits(), 0.0_f64.to_bits());
        assert_eq!(log10(0.0), f64::NEG_INFINITY);
        assert!(log10(-1.0).is_nan());
    }

    #[test]
    fn pow_half_integer_fast_path_within_4_ulps() {
        let bases = [
            1e-6,
            1e-3,
            0.5,
            0.999_999,
            1.0,
            1.000_001,
            1.785,
            2.0,
            2.5,
            std::f64::consts::PI,
            123.456,
            1e6,
        ];
        for &base in &bases {
            for n in -(POWI_MAX_EXP as i64)..=(POWI_MAX_EXP as i64) {
                let exponent = n as f64 + 0.5;
                let got = pow(base, exponent);
                let want = base.powf(exponent);
                assert!(
                    within_ulps(got, want, 4),
                    "pow({base}, {exponent}) = {got:?} but glibc = {want:?} (>4 ULP)"
                );
            }
        }
    }

    #[test]
    fn golden_pow_half_integer_corpus_sha256() {
        use sha2::{Digest, Sha256};

        let bases = [
            1e-6,
            1e-3,
            0.5,
            0.999_999,
            1.0,
            1.000_001,
            1.785,
            2.0,
            2.5,
            std::f64::consts::PI,
            123.456,
            1e6,
        ];
        let exponents = [-7.5, -2.5, -0.5, 0.5, 1.5, 2.5, 4.5, 8.5];
        let mut hasher = Sha256::new();
        for &base in &bases {
            for &exponent in &exponents {
                hasher.update(pow(base, exponent).to_bits().to_le_bytes());
            }
        }
        let digest: String = hasher
            .finalize()
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect();
        assert_eq!(
            digest, "5d10fe8318e0cba5afc8a3260fa342ca472bf559ead08bc67b82ae3a307e3a61",
            "pow half-integer golden corpus hash drifted"
        );
    }

    #[test]
    fn pow_medium_log2_exp2_fast_path_large_sweep_within_4_ulps() {
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let scale = 1.0 / ((1_u64 << 53) as f64);

        for _ in 0..1_000_000 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let base_unit = ((state >> 11) as f64) * scale;
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let exponent_unit = ((state >> 11) as f64) * scale;

            let base = EXP_MEDIUM_MIN + (EXP_MEDIUM_MAX - EXP_MEDIUM_MIN) * base_unit;
            let exponent =
                POW_MEDIUM_EXP_MIN + (POW_MEDIUM_EXP_MAX - POW_MEDIUM_EXP_MIN) * exponent_unit;
            let got = pow_medium_log2_exp2_fast_path(base, exponent)
                .expect("generated pair should be inside medium pow gate");
            let want = base.powf(exponent);
            assert!(
                within_ulps(got, want, 4),
                "medium pow fast path drifted: pow({base}, {exponent}) = {got:?}, glibc = {want:?}"
            );
        }
    }

    #[test]
    fn pow_medium_log2_exp2_fast_path_preserves_fallback_cases() {
        let cases = [
            (f64::NEG_INFINITY, 1.337),
            (-2.0, 1.337),
            (-0.0, 1.337),
            (0.0, 1.337),
            (0.25, 1.337),
            (EXP_MEDIUM_MAX, 1.337),
            (4.0, 1.337),
            (f64::INFINITY, 1.337),
            (1.5, POW_MEDIUM_EXP_MIN - f64::EPSILON),
            (1.5, POW_MEDIUM_EXP_MAX + f64::EPSILON),
        ];

        for (base, exponent) in cases {
            assert_eq!(
                pow(base, exponent).to_bits(),
                libm::pow(base, exponent).to_bits(),
                "pow({base}, {exponent}) fallback drifted"
            );
        }
        assert!(pow(f64::NAN, 1.337).is_nan());
        assert!(pow(1.5, f64::NAN).is_nan());
    }

    #[test]
    fn golden_pow_medium_log2_exp2_corpus_sha256() {
        use sha2::{Digest, Sha256};

        let bases = [
            EXP_MEDIUM_MIN,
            0.500_000_000_000_000_1,
            0.593_75,
            0.999_999,
            1.0,
            1.000_001,
            1.5,
            2.072_341_547_916_954_7,
            2.468_75,
            EXP_MEDIUM_MAX - f64::EPSILON,
        ];
        let exponents = [
            POW_MEDIUM_EXP_MIN,
            -2.9375,
            -1.337,
            -0.25,
            0.25,
            0.75,
            1.337,
            2.25,
            2.849_516_429_769_268_6,
            POW_MEDIUM_EXP_MAX,
        ];

        let mut hasher = Sha256::new();
        for &base in &bases {
            for &exponent in &exponents {
                let got = pow(base, exponent);
                let want = base.powf(exponent);
                assert!(
                    within_ulps(got, want, 4),
                    "pow({base}, {exponent}) = {got:?} but glibc = {want:?} (>4 ULP)"
                );
                hasher.update(base.to_bits().to_le_bytes());
                hasher.update(exponent.to_bits().to_le_bytes());
                hasher.update(got.to_bits().to_le_bytes());
            }
        }
        let digest: String = hasher
            .finalize()
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect();
        assert_eq!(
            digest, "970a740ac2a4983abae2831799f179c711201e97de0e8b4373c12cab2e193ab7",
            "pow medium log2/exp2 golden corpus hash drifted"
        );
    }

    #[test]
    fn exp_medium_exp2_fast_path_within_4_ulps() {
        let mut inputs = vec![
            EXP_FAST_MIN,
            EXP_FAST_MAX,
            -4.999,
            -2.5,
            -1.0,
            -0.25,
            0.0,
            0.500_000_000_000_000_1,
            std::f64::consts::LN_2,
            1.0,
            std::f64::consts::SQRT_2,
            2.0,
            2.468_75,
            4.999,
        ];
        // Dense deterministic sweep across the whole [-5, 5] fast-path interval.
        let mut s = 0x2545_f491_4f6c_dd1du64;
        for _ in 0..1_000_000 {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            inputs.push(-5.0 + (s >> 11) as f64 * (10.0 / (1u64 << 53) as f64));
        }

        for x in inputs {
            let got = exp(x);
            let want = x.exp();
            assert!(
                within_ulps(got, want, 4),
                "exp({x}) = {got:?} but host exp = {want:?} (>4 ULP)"
            );
        }
    }

    #[test]
    fn exp_medium_exp2_fast_path_preserves_fallback_cases() {
        // Outside [-5, 5] exp must stay bit-identical to libm::exp.
        let cases = [
            f64::NEG_INFINITY,
            -20.0,
            -6.0,
            -5.000_000_000_000_001,
            5.000_000_000_000_001,
            6.0,
            20.0,
            f64::INFINITY,
        ];
        for x in cases {
            assert_eq!(
                exp(x).to_bits(),
                libm::exp(x).to_bits(),
                "exp({x}) fallback drifted"
            );
        }
        assert!(exp(f64::NAN).is_nan());
    }

    #[test]
    fn golden_exp_medium_exp2_corpus_sha256() {
        use sha2::{Digest, Sha256};

        let mut inputs = vec![
            EXP_MEDIUM_MIN,
            0.500_000_000_000_000_1,
            std::f64::consts::LN_2,
            1.0,
            std::f64::consts::SQRT_2,
            2.0,
            2.468_75,
            EXP_MEDIUM_MAX - f64::EPSILON,
        ];
        inputs.extend((0..64).map(|k| 0.5 + (k as f64) * 0.031_25));

        let mut hasher = Sha256::new();
        for x in inputs {
            hasher.update(exp(x).to_bits().to_le_bytes());
        }
        let digest: String = hasher
            .finalize()
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect();
        assert_eq!(
            digest, "e44a16c130577d30811cc63a179ce65cdc2c0451958b238918a77aa165c1a2be",
            "exp medium exp2 golden corpus hash drifted"
        );
    }

    #[test]
    fn exp_log_pow_sanity() {
        assert!((exp(1.0) - std::f64::consts::E).abs() < 1e-12);
        assert!((exp2(10.0) - 1024.0).abs() < 1e-12);
        assert!((expm1(1.0) - (std::f64::consts::E - 1.0)).abs() < 1e-12);
        assert!((log(std::f64::consts::E) - 1.0).abs() < 1e-12);
        assert!((log2(8.0) - 3.0).abs() < 1e-12);
        assert!((log10(1000.0) - 3.0).abs() < 1e-12);
        assert!((log1p(0.5) - 1.5_f64.ln()).abs() < 1e-12);
        assert!((pow(9.0, 0.5) - 3.0).abs() < 1e-12);
    }

    proptest! {
        #![proptest_config(property_proptest_config(256))]

        #[test]
        fn prop_exp_turns_addition_into_multiplication(
            x in -20.0f64..20.0f64,
            y in -20.0f64..20.0f64
        ) {
            let lhs = exp(x + y);
            let rhs = exp(x) * exp(y);
            prop_assert!(approx_eq(lhs, rhs, 1e-12, 1e-11));
        }

        #[test]
        fn prop_log_of_exp_round_trips(x in -20.0f64..20.0f64) {
            let round_trip = log(exp(x));
            prop_assert!(approx_eq(round_trip, x, 1e-12, 1e-11));
        }

        #[test]
        fn prop_exp_of_log_round_trips(x in 1.0e-12f64..1.0e12f64) {
            let round_trip = exp(log(x));
            prop_assert!(approx_eq(round_trip, x, 1e-12, 1e-11));
        }

        #[test]
        fn prop_log_turns_products_into_sums(
            x in 1.0e-6f64..1.0e6f64,
            y in 1.0e-6f64..1.0e6f64
        ) {
            let lhs = log(x * y);
            let rhs = log(x) + log(y);
            prop_assert!(approx_eq(lhs, rhs, 1e-12, 1e-11));
        }

        #[test]
        fn prop_expm1_matches_exp_minus_one(x in -1.0f64..1.0f64) {
            let lhs = expm1(x);
            let rhs = exp(x) - 1.0;
            prop_assert!(approx_eq(lhs, rhs, 1e-12, 1e-11));
        }

        #[test]
        fn prop_log1p_matches_log_of_one_plus_x(x in -0.99f64..10.0f64) {
            let lhs = log1p(x);
            let rhs = log(1.0 + x);
            prop_assert!(approx_eq(lhs, rhs, 1e-12, 1e-11));
        }

        #[test]
        fn prop_pow_turns_added_exponents_into_multiplied_results(
            base in 1.0e-6f64..1.0e6f64,
            x in -5.0f64..5.0f64,
            y in -5.0f64..5.0f64
        ) {
            let lhs = pow(base, x + y);
            let rhs = pow(base, x) * pow(base, y);
            prop_assert!(approx_eq(lhs, rhs, 1e-10, 1e-10));
        }
    }
}
