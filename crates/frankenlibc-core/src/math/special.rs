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
    // CORE-MATH's correctly rounded lgamma, which glibc 2.43 ships: value and
    // sign bit-identical to glibc. The previous log(tgamma) / Stirling / libm
    // paths differed on 43% of inputs (bd-otip6a); the negative half-integer
    // closed form (bd-8htzay) is subsumed, since this is correctly rounded on
    // that lattice too.
    crate::math::coremath::lgamma_r(x)
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
        // Off the lattice too: -2.6 gives glibc 2.43's correctly rounded value.
        let (v, s) = lgamma_r(-2.6);
        assert_eq!((v.to_bits(), s), (0xbfbe_3602_a772_5dbe, -1));
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
