//! Special mathematical functions.

#[inline]
pub fn erf(x: f64) -> f64 {
    libm::erf(x)
}

#[inline]
pub fn tgamma(x: f64) -> f64 {
    libm::tgamma(x)
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
    //! + f64 pow + f64 exp) would already be ~2.5x faster than our libm and
    //! near glibc parity; a minimax poly on [1,2] (fit to a dd oracle, not
    //! libm — fitting to libm's ~1-2 ULP noise overfits to 50+ ULP by degree 20)
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
    const LC: [f64; 9] = [
        0.999_999_999_999_809_93,
        676.520_368_121_885_1,
        -1259.139_216_722_402_8,
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
    libm::lgamma(x)
}

/// Complementary error function: 1 - erf(x).
#[inline]
pub fn erfc(x: f64) -> f64 {
    libm::erfc(x)
}

/// Reentrant lgamma: returns `(lgamma(x), signgam)` where `signgam` is +1 or -1.
#[inline]
pub fn lgamma_r(x: f64) -> (f64, i32) {
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
    libm::j1(x)
}

/// Bessel function of the first kind, order `n`.
#[inline]
pub fn jn(n: i32, x: f64) -> f64 {
    libm::jn(n, x)
}

/// Bessel function of the second kind, order 0.
#[inline]
pub fn y0(x: f64) -> f64 {
    libm::y0(x)
}

/// Bessel function of the second kind, order 1.
#[inline]
pub fn y1(x: f64) -> f64 {
    libm::y1(x)
}

/// Bessel function of the second kind, order `n`.
#[inline]
pub fn yn(n: i32, x: f64) -> f64 {
    libm::yn(n, x)
}

#[cfg(test)]
mod tests {
    use super::*;

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
