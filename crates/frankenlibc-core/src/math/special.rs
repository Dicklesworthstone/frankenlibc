//! Special mathematical functions.

#[inline]
pub fn erf(x: f64) -> f64 {
    // CORE-MATH's correctly rounded erf, which glibc 2.43 ships: bit-identical
    // to glibc. fdlibm's libm::erf differed on 2.2% of inputs in [-6, 6]
    // (bd-otip6a).
    crate::math::coremath::erf(x)
}

#[inline]
pub fn tgamma(x: f64) -> f64 {
    // CORE-MATH's correctly rounded tgamma, which glibc 2.43 ships:
    // bit-identical to glibc. The Cephes rational / libm::tgamma paths differed
    // on 65% of inputs (bd-otip6a).
    crate::math::coremath::tgamma(x)
}

#[cfg(test)]
mod tgamma_lanczos_research {
    //! Research harness for a fast pure-Rust tgamma (bd-pha1c7). The dominant
    //! cost in glibc's tgamma is its general path (~41 ns); our libm::tgamma is
    //! ~125 ns (3.03x slower). This harness evaluates a double-double Lanczos:
    //! the coefficient sum `c_0 + Σ c_k/(z+k)` is accumulated in dd (each term
    //! via dd division), which removes BOTH the per-term f64 rounding and the
    //! catastrophic cancellation of the large alternating g=7 coefficients.
    //!
    //! FINDING: even with exact (dd) arithmetic the result floors at ~16 ULP on
    //! [1,2] (worse for |z| large / reflection). That is the *approximation*
    //! error of the standard g=7, n=9 coefficient set (~1e-14 worst case), NOT
    //! an arithmetic-precision problem — so a 4-ULP tgamma needs HIGHER-ORDER
    //! coefficients (Pugh g=607/128 n=15, or Boost's well-conditioned rational
    //! lanczos13m53), which must be generated offline at high precision
    //! (Godfrey's matrix method evaluated in dd, or copied from a published
    //! table). With 4-ULP coefficients, this dd-Lanczos runtime (~45 ns: dd sum
    //! plus f64 pow and f64 exp) would already be ~2.5x faster than our libm and
    //! near glibc parity; a minimax poly on [1,2] (fit to a dd oracle, not libm
    //! — fitting to libm's ~1-2 ULP noise overfits to 50+ ULP by degree 20)
    //! would be ~4x faster than glibc.

    fn two_sum(a: f64, b: f64) -> (f64, f64) {
        let s = a + b;
        let bb = s - a;
        (s, (a - (s - bb)) + (b - bb))
    }
    fn dd_add(a: (f64, f64), b: (f64, f64)) -> (f64, f64) {
        let (s, e) = two_sum(a.0, b.0);
        let lo = e + a.1 + b.1;
        let (h, l) = two_sum(s, lo);
        (h, l)
    }
    fn dd_div_ff(a: f64, b: f64) -> (f64, f64) {
        let q = a / b;
        let r = (-q).mul_add(b, a);
        (q, r / b)
    }

    const G: f64 = 7.0;
    #[allow(clippy::excessive_precision)]
    const LC: [f64; 9] = [
        0.999_999_999_999_809_93,
        676.520_368_121_885_1,
        -1_259.139_216_722_402_8,
        771.323_428_777_653_13,
        -176.615_029_162_140_59,
        12.507_343_278_686_905,
        -0.138_571_095_265_720_12,
        9.984_369_578_019_571_6e-6,
        1.505_632_735_149_311_6e-7,
    ];

    fn lanczos_dd(z: f64) -> f64 {
        if z < 0.5 {
            let pi = std::f64::consts::PI;
            return pi / ((pi * z).sin() * lanczos_dd(1.0 - z));
        }
        let z = z - 1.0;
        let mut acc = (LC[0], 0.0);
        for (i, &ci) in LC.iter().enumerate().skip(1) {
            acc = dd_add(acc, dd_div_ff(ci, z + i as f64));
        }
        let sum = acc.0 + acc.1;
        let t = z + G + 0.5;
        2.506_628_274_631_000_5 * libm::pow(t, z + 0.5) * libm::exp(-t) * sum
    }

    #[test]
    #[ignore]
    fn sweep_lanczos_dd_ulp() {
        fn ulp(a: f64, b: f64) -> i64 {
            if a == b {
                0
            } else if a.is_nan() || b.is_nan() || a.is_sign_negative() != b.is_sign_negative() {
                i64::MAX
            } else {
                (a.to_bits() as i64 - b.to_bits() as i64).abs()
            }
        }
        for &(lo, hi) in &[(1.0, 2.0), (0.5, 2.5), (0.5, 10.0), (2.0, 50.0)] {
            let mut worst = 0i64;
            let mut x: f64 = lo;
            while x <= hi {
                if !(x <= 0.0 && x == x.trunc()) {
                    worst = worst.max(ulp(lanczos_dd(x), libm::tgamma(x)));
                }
                x += 0.0003;
            }
            println!("lanczos_dd [{lo},{hi}]: worst {worst} ULP (g=7 coeff floor)");
        }
    }
}
// ---------------------------------------------------------------------------
// Negative half-integer lattice (bd-8htzay)
//
// x = 1/2 - n (n >= 1, integral) has the closed form
//     |Gamma(1/2 - n)| = 4^n n! sqrt(pi) / (2n)!
//     lgamma(x)        = n*ln4 + ln(n!) + (1/2)*ln(pi) - ln((2n)!)
//     signgam          = (-1)^n
// (checked: n = 3 gives ln(8*sqrt(pi)/15) = -0.0562437164976740506...).
//
// glibc 2.43's lgamma_r is CORRECTLY ROUNDED on this lattice (mpmath at 60
// digits, n = 1..24), and a correctly rounded value is host-proof, unlike
// algorithm mimicry: the same release's fromfp re-cut (bd-7ilguh) showed how
// fragile matching-a-particular-algorithm is across host upgrades. The branch
// below evaluates the closed form in double-double (~106-bit significand):
// every term is an exact-argument log, the DD sum accumulates <= 2^-90
// relative error at the n cap, and the final f64 rounding is therefore the
// correctly rounded one — CR now, and on whatever glibc ships next. O(n) DD
// log terms, capped at n <= 4096 (larger |x| stays on the libm-crate
// deferral in `lgamma_r`, unchanged).
mod lgamma_half_integer {
    /// Double-double: (hi, lo) with |lo| <= ulp(hi)/2.
    type Dd = (f64, f64);

    /// Split of ln(2) to 106-bit precision.
    #[allow(clippy::approx_constant)] // hi is written exactly, as the split's first half.
    const LN2: Dd = (
        0.693_147_180_559_945_286_226_763_982_995_180_413_126_945_495_605_468_75e0,
        2.319_046_813_846_299_615_494_855_463_875_39e-17,
    );
    /// Split of (1/2) ln(pi) to 106-bit precision.
    const HALF_LN_PI: Dd = (
        0.572_364_942_924_700_087_071_713_675_676_529_355_823_647_406_457_66e0,
        5.132_975_581_353_913_12e-18,
    );
    /// Split of ln(4) to 106-bit precision.
    const LN4: Dd = (1.386_294_361_119_890_571_8, 4.638_093_627_692_599_23e-17);

    #[inline]
    fn quick_two_sum(a: f64, b: f64) -> Dd {
        let s = a + b;
        (s, b - (s - a))
    }

    #[inline]
    fn two_sum(a: f64, b: f64) -> Dd {
        let s = a + b;
        let av = s - b;
        let bv = s - av;
        (s, (a - av) + (b - bv))
    }

    #[inline]
    fn two_prod(a: f64, b: f64) -> Dd {
        let p = a * b;
        (p, a.mul_add(b, -p))
    }

    #[inline]
    fn dd_neg(a: Dd) -> Dd {
        (-a.0, -a.1)
    }

    #[inline]
    fn dd_add(a: Dd, b: Dd) -> Dd {
        let (s, se) = two_sum(a.0, b.0);
        let (t, te) = two_sum(a.1, b.1);
        let (hi, mid) = quick_two_sum(s, se + t);
        quick_two_sum(hi, mid + te)
    }

    #[inline]
    fn dd_mul(a: Dd, b: Dd) -> Dd {
        let (p, pe) = two_prod(a.0, b.0);
        quick_two_sum(p, pe + a.0 * b.1 + a.1 * b.0)
    }

    #[inline]
    fn dd_mul_f64(a: Dd, b: f64) -> Dd {
        let (p, pe) = two_prod(a.0, b);
        quick_two_sum(p, pe + a.1 * b)
    }

    #[inline]
    fn dd_div(a: Dd, b: Dd) -> Dd {
        let q1 = a.0 / b.0;
        // r = a - q1 * b, in DD. (p, pe) carries q1*b.0 to DD precision; only
        // the q1*b.1 tail is subtracted separately. Subtracting q1*b twice
        // collapses r to -a and the quotient to ~0 (caught by the standalone
        // DD probe, bd-8htzay).
        let (p, pe) = two_prod(q1, b.0);
        let r = dd_add(dd_add(a, dd_neg((p, pe))), dd_mul_f64((b.1, 0.0), -q1));
        dd_add((q1, 0.0), dd_mul_f64(r, 1.0 / b.0))
    }

    #[inline]
    fn dd_sqrt(x: Dd) -> Dd {
        let s = x.0.sqrt();
        // One DD Newton step: s' = s + (x - s^2) / (2 s).
        let (p, pe) = two_prod(s, s);
        let corr = dd_mul_f64(dd_add(x, dd_neg((p, pe))), 0.5 / s);
        dd_add((s, 0.0), corr)
    }

    /// ln(x) for finite x > 0, ~2^-105 relative error.
    ///
    /// x = m * 2^k with m in [sqrt(1/2), sqrt(2)); five squarings bring m
    /// into [~0.9975, ~1.0025], where the atanh series converges in a handful
    /// of DD terms: ln m = 32 * ln(m^(1/32)) = 64 * atanh(u) with
    /// u = (m^(1/32) - 1) / (m^(1/32) + 1).
    fn dd_ln(x: f64) -> Dd {
        debug_assert!(x > 0.0 && x.is_finite());
        let bits = x.to_bits();
        let mut k = (((bits >> 52) & 0x7ff) as i64) - 1023;
        let mut m = f64::from_bits((bits & !(0x7ffu64 << 52)) | (1023u64 << 52));
        if m < core::f64::consts::FRAC_1_SQRT_2 {
            m *= 2.0;
            k -= 1;
        }
        let mut s = (m, 0.0);
        for _ in 0..5 {
            s = dd_sqrt(s);
        }
        let u = dd_div(dd_add(s, (-1.0, 0.0)), dd_add(s, (1.0, 0.0)));
        let u2 = dd_mul(u, u);
        let mut term = u;
        let mut acc = (0.0, 0.0);
        let mut i = 1.0;
        loop {
            acc = dd_add(acc, dd_div(term, (i, 0.0)));
            term = dd_mul(term, u2);
            i += 2.0;
            if term.0 == 0.0 || i > 47.0 {
                break;
            }
        }
        // 2 (atanh factor) * 32 (squarings).
        let ln_m = dd_mul_f64(acc, 64.0);
        dd_add(ln_m, dd_mul_f64(LN2, k as f64))
    }

    /// ln|Gamma(1/2 - n)| for integral n in [1, 4096], correctly rounded.
    pub(crate) fn lgamma_neg_half_integer(n: u32) -> (f64, i32) {
        // L = n*ln4 + (1/2)ln(pi) + ln(n!) - ln((2n)!). The ln(n!) terms
        // cancel against the first n terms of ln((2n)!), leaving exactly
        // L = n*ln4 + (1/2)ln(pi) - sum_{k=n+1}^{2n} ln k. (A first version
        // added the k <= n terms instead of dropping them — double-counting
        // ln(n!) — which the mpmath goldens caught immediately.)
        let mut l = dd_add(dd_mul_f64(LN4, n as f64), HALF_LN_PI);
        for k in (n + 1)..=(2 * n) {
            l = dd_add(l, dd_neg(dd_ln(k as f64)));
        }
        let (value, _) = quick_two_sum(l.0, l.1);
        // Gamma(1/2 - n) = (-4)^n n! sqrt(pi) / (2n)!: the sign is (-1)^n.
        let sign = if n % 2 == 0 { 1 } else { -1 };
        (value, sign)
    }
}

#[inline]
pub fn lgamma(x: f64) -> f64 {
    // Derive from lgamma_r so the value matches lgamma_r exactly (the deployed ABI
    // reads the sign from lgamma_r and the value from here — they must agree).
    lgamma_r(x).0
}

/// Complementary error function: 1 - erf(x).
#[inline]
pub fn erfc(x: f64) -> f64 {
    // CORE-MATH's correctly rounded erfc, which glibc 2.43 ships: bit-identical
    // to glibc. fdlibm's libm::erfc differed on 31% of inputs (bd-otip6a).
    let r = crate::math::coremath::erfc(x);
    // erfc(x) for large finite positive x underflows toward 0; glibc raises
    // FE_UNDERFLOW on the subnormal/zero result, which the constant-folded
    // 2^-1074/4 tail does not. erfc(+inf)=0 is an exact limit (no underflow),
    // so exclude non-finite x.
    if x.is_finite() && x > 0.0 && r < f64::MIN_POSITIVE {
        let _ = core::hint::black_box(
            core::hint::black_box(f64::MIN_POSITIVE) * core::hint::black_box(f64::MIN_POSITIVE),
        );
    }
    r
}

/// Reentrant lgamma: returns `(lgamma(x), signgam)` where `signgam` is +1 or -1.
#[inline]
pub fn lgamma_r(x: f64) -> (f64, i32) {
    // [3,13): lgamma(x) = log(tgamma(x)) reusing fl's fast Cephes `tgamma` + fused
    // `log` — ~7% faster than `libm::lgamma` and at glibc parity, ≤2 ULP vs glibc
    // (verified by lgamma_glibc_bench). In this band lgamma ≥ ln 2 ≈ 0.69 > 0 (so
    // signgam = +1), Γ is finite and positive (no overflow/poles), and there is no
    // 1-erf-style cancellation. Every other x defers to `libm::lgamma_r` for the
    // poles (negative integers), the near-zero band around x=1,2, and the large-x
    // tail where Γ overflows. `crate::math::log`/`tgamma` are direct Rust calls (not
    // the interposed symbols), so no membrane round-trip / recursion.
    if x >= 3.0 && x < 13.0 {
        return (crate::math::log(tgamma(x)), 1);
    }
    if (13.0..1.0e15).contains(&x) {
        // Large-x tail: Stirling asymptotic — lgamma(x) = (x-0.5)·ln(x) - x + ½ln(2π) +
        // Σ B_{2k}/(2k(2k-1)·x^{2k-1}). Reuses fl's fused `log` + a 5-term Bernoulli series
        // (converges fast for x ≥ 13); the (x-0.5)·ln(x) leading term is carried with its
        // fma residual to stay ≤2 ULP vs glibc (verified to 1e15 by lgamma_tail_ab_bench).
        // ~1.76x faster than libm::lgamma and beats glibc 0.56x. lgamma > 0 here so
        // signgam = +1; the rare [1e15,∞) tail (near Γ overflow + its FE_OVERFLOW/ERANGE)
        // stays on libm.
        const HALF_LN_2PI: f64 = 0.918_938_533_204_672_74;
        let lnx = crate::math::log(x);
        let a = x - 0.5;
        let hi = a * lnx;
        let lo = a.mul_add(lnx, -hi);
        let inv = 1.0 / x;
        let w = inv * inv;
        let mut s = 1.0_f64 / 1188.0;
        s = s.mul_add(w, -1.0 / 1680.0);
        s = s.mul_add(w, 1.0 / 1260.0);
        s = s.mul_add(w, -1.0 / 360.0);
        s = s.mul_add(w, 1.0 / 12.0);
        s *= inv;
        return (((hi - x) + (HALF_LN_2PI + s)) + lo, 1);
    }
    // Negative half-integer lattice: closed form via the exact reflection
    // |Gamma(1/2-n)| = 4^n n! sqrt(pi)/(2n)! (see lgamma_half_integer above).
    // n = 1/2 - x is exact f64 arithmetic on this range; integers fail the
    // integrality test (1/2 - integer is never integral) and keep the pole
    // handling in the libm-crate deferral below.
    if x < 0.0 {
        let nh = 0.5 - x;
        if nh >= 1.0 && nh <= 4096.0 && nh == nh.trunc() {
            return lgamma_half_integer::lgamma_neg_half_integer(nh as u32);
        }
    }
    libm::lgamma_r(x)
}

// ---------------------------------------------------------------------------
// Bessel functions
// ---------------------------------------------------------------------------

/// Bessel function of the first kind, order 0.
#[inline]
pub fn j0(x: f64) -> f64 {
    libm::j0(x)
}

/// Bessel function of the first kind, order 1.
#[inline]
pub fn j1(x: f64) -> f64 {
    // J1 is odd, so J1(-inf) carries the sign of -J1(+inf) = -0.0; libm::j1(-inf)
    // returns +0.0, but glibc returns -0.0. Match glibc.
    if x == f64::NEG_INFINITY {
        return -0.0;
    }
    libm::j1(x)
}

/// Bessel function of the first kind, order `n`.
#[inline]
pub fn jn(n: i32, x: f64) -> f64 {
    // Route orders 0/±1 through j0/j1 so the corrected signed-zero behaviour at
    // ±inf (J1 is odd: libm returns +0 where glibc returns -0) propagates, and
    // apply the identity J_{-n}(x) = (-1)^n J_n(x) for n = -1. For finite x this
    // is identical to libm::jn (which reduces to ±j1 internally); |n| >= 2 already
    // matches glibc, so it stays on libm::jn.
    match n {
        0 => j0(x),
        1 => j1(x),
        -1 => -j1(x),
        _ => libm::jn(n, x),
    }
}

/// Bessel function of the second kind, order 0.
/// Re-raise the IEEE exception glibc raises for the Y-Bessel family that libm
/// omits: x==0 is a pole (Y(0) = -inf) -> FE_DIVBYZERO; x<0 (incl -inf) is out of
/// domain (Y undefined for negative reals, result NaN) -> FE_INVALID. Cold path.
#[inline]
fn raise_y_special(x: f64) {
    if x == 0.0 {
        let _ =
            core::hint::black_box(core::hint::black_box(-1.0_f64) / core::hint::black_box(0.0_f64));
    } else if x < 0.0 {
        let _ =
            core::hint::black_box(core::hint::black_box(0.0_f64) / core::hint::black_box(0.0_f64));
    }
}

pub fn y0(x: f64) -> f64 {
    raise_y_special(x);
    libm::y0(x)
}

/// Bessel function of the second kind, order 1.
#[inline]
pub fn y1(x: f64) -> f64 {
    raise_y_special(x);
    libm::y1(x)
}

/// Bessel function of the second kind, order `n`.
#[inline]
pub fn yn(n: i32, x: f64) -> f64 {
    // Same as jn: orders 0/±1 via y0/y1 + the identity Y_{-n} = (-1)^n Y_n, so the
    // glibc signed-zero-at-+inf convention (yn(-1, +inf) = -0) is matched. Finite x
    // is identical to libm::yn; |n| >= 2 stays on libm::yn.
    match n {
        0 => y0(x),
        1 => y1(x),
        -1 => -y1(x),
        _ => {
            raise_y_special(x);
            libm::yn(n, x)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn j1_neg_inf_sign_matches_glibc() {
        // J1 is odd → J1(-inf) = -0.0 (glibc); libm returns +0.0.
        assert_eq!(j1(f64::NEG_INFINITY).to_bits(), (-0.0f64).to_bits());
        assert_eq!(j1(f64::INFINITY).to_bits(), 0.0f64.to_bits());
        assert!(j1(f64::NAN).is_nan());
    }

    #[test]
    fn erf_sanity() {
        assert!(erf(0.0).abs() < 1e-12);
        assert!((erf(1.0) - 0.8427).abs() < 5e-4);
    }

    #[test]
    fn gamma_sanity() {
        assert!((tgamma(5.0) - 24.0).abs() < 1e-8);
        assert!((lgamma(5.0) - 24.0_f64.ln()).abs() < 1e-8);
    }

    #[test]
    fn tgamma_exact_factorials() {
        // Γ(n) = (n-1)! exactly representable up to 12!.
        let mut fact = 1.0f64;
        for n in 1..=13u64 {
            // tgamma(n) should equal (n-1)!
            let got = tgamma(n as f64);
            assert!(
                (got - fact).abs() <= fact * 4.0 * f64::EPSILON,
                "tgamma({n}) = {got}, want {fact}"
            );
            fact *= n as f64;
        }
        // Γ(1/2) = sqrt(π) via reflection path.
        let want = core::f64::consts::PI.sqrt();
        assert!((tgamma(0.5) - want).abs() <= want * 4.0 * f64::EPSILON);
    }

    #[test]
    fn tgamma_ulp_vs_closed_form() {
        // The fast path is verified against TRUE references that are independent
        // of any libm: the closed form Γ(n+½) = √π·∏(k+½). (libm itself carries
        // up to ~14 ULP of error in this range, so it is the wrong oracle.)
        fn ulp(a: f64, b: f64) -> i64 {
            if a == b {
                0
            } else if a.is_nan() || b.is_nan() || a.is_sign_negative() != b.is_sign_negative() {
                i64::MAX
            } else {
                (a.to_bits() as i64 - b.to_bits() as i64).abs()
            }
        }
        let sqrt_pi = core::f64::consts::PI.sqrt();
        let mut prod = 1.0f64;
        let mut worst = 0i64;
        for n in 0..=11u64 {
            let z = n as f64 + 0.5;
            let want = sqrt_pi * prod; // Γ(z)
            worst = worst.max(ulp(tgamma(z), want));
            prod *= z;
        }
        assert!(worst <= 4, "worst {worst} ULP vs closed-form half-integers");
    }

    #[test]
    fn erfc_sanity() {
        // erfc(x) = 1 - erf(x)
        assert!((erfc(0.0) - 1.0).abs() < 1e-12);
        assert!((erfc(1.0) - (1.0 - erf(1.0))).abs() < 1e-12);
    }

    #[test]
    fn lgamma_r_sanity() {
        // lgamma_r(5) = ln(24) with positive sign
        let (val, sign) = lgamma_r(5.0);
        assert!((val - 24.0_f64.ln()).abs() < 1e-8);
        assert_eq!(sign, 1);
        // lgamma_r(-0.5) has negative Gamma, so sign = -1
        let (_, sign2) = lgamma_r(-0.5);
        assert_eq!(sign2, -1);
    }

    #[test]
    fn bessel_j_sanity() {
        // J0(0) = 1
        assert!((j0(0.0) - 1.0).abs() < 1e-12);
        // J1(0) = 0
        assert!(j1(0.0).abs() < 1e-12);
        // Jn(0, x) == J0(x)
        assert!((jn(0, 2.5) - j0(2.5)).abs() < 1e-12);
        // Jn(1, x) == J1(x)
        assert!((jn(1, 2.5) - j1(2.5)).abs() < 1e-12);
    }

    #[test]
    fn lgamma_r_neg_half_integer_lattice_matches_cr() {
        // The closed form |Gamma(1/2-n)| = 4^n n! sqrt(pi)/(2n)! evaluated in
        // double-double must reproduce the CORRECTLY ROUNDED lgamma at every
        // lattice point. Goldens: mpmath.loggamma at 60 digits, rounded to
        // f64 (bd-8htzay); glibc 2.43 agrees bit-for-bit on this lattice
        // (verified live by conformance_diff_math_multi_output).
        const GOLDEN: [(u32, f64); 12] = [
            (1, 1.265_512_123_484_645_4),
            (2, 0.860_047_015_376_481),
            (3, -0.056_243_716_497_674_054),
            (4, -1.309_006_684_993_042),
            (5, -2.813_084_081_769_316),
            (6, -4.517_832_174_007_741),
            (7, -6.389_634_350_909_333),
            (8, -8.404_537_371_451_598),
            (9, -10.544_603_534_947_868),
            (10, -12.795_895_333_554_363),
            (11, -15.147_270_590_717_842),
            (12, -17.589_617_626_087_044),
        ];
        for &(n, want) in &GOLDEN {
            let (got, sign) = lgamma_r(0.5 - n as f64);
            assert_eq!(got.to_bits(), want.to_bits(), "lgamma_r(1/2-{n})");
            let want_sign = if n % 2 == 0 { 1 } else { -1 };
            assert_eq!(sign, want_sign, "signgam(1/2-{n})");
        }
        // Non-lattice negative x keeps the deferral contract (value unchanged
        // by the branch): -2.6 is not on the lattice.
        let (v, s) = lgamma_r(-2.6);
        let (lv, ls) = libm::lgamma_r(-2.6);
        assert_eq!((v.to_bits(), s), (lv.to_bits(), ls));
    }

    #[test]
    fn bessel_y_sanity() {
        // Y0 and Y1 at x=1 are well-known values
        // Y0(1) ≈ 0.08825696
        assert!((y0(1.0) - 0.08825696).abs() < 1e-5);
        // Y1(1) ≈ -0.78121282
        assert!((y1(1.0) - (-0.78121282)).abs() < 1e-5);
        // Yn(0, x) == Y0(x)
        assert!((yn(0, 1.0) - y0(1.0)).abs() < 1e-12);
        // Y0(0) = -inf (pole)
        assert!(y0(0.0).is_infinite() && y0(0.0).is_sign_negative());
    }
}
