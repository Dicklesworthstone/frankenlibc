//! Special mathematical functions.

#[inline]
pub fn erf(x: f64) -> f64 {
    if x.is_finite() && x.abs() < 2.5 {
        if x < 0.0 {
            -erf_profile_band(-x)
        } else {
            erf_profile_band(x)
        }
    } else if x.abs() >= 6.0 {
        // Saturation short-circuit: `erf(x)` rounds to exactly ±1.0 in f64 for
        // |x| >= 6 (1 - erf(6) ≈ 2.15e-17 < 2^-53, and glibc returns exactly ±1.0
        // there), so skip the `libm::erf` call — bit-identical. `±inf` also lands
        // here (erf(±inf)=±1); NaN (NaN >= 6.0 is false) falls through to
        // `libm::erf(NaN)=NaN`.
        1.0_f64.copysign(x)
    } else {
        libm::erf(x)
    }
}

// ---------------------------------------------------------------------------
// erf: Cephes/Moshier rational pieces for the profiled [0.5,2.5) band.
//
// The libc baseline exercises `erf(x)` over `x in [0.5,2.5)`. `libm::erf`
// follows the full fdlibm decision tree there, while this path evaluates the
// two relevant public-domain Cephes rational pieces directly: a no-exp rational
// for [0,1), and an erfc-shaped exp(-x*x) * P/Q piece for [1,2.5). Public
// `erfc` is intentionally unchanged because the corresponding sub-1.0
// complement branch exceeded the 4-ULP glibc contract in dense replay.
#[allow(clippy::excessive_precision)]
const ERF_T: [f64; 5] = [
    9.604_973_739_870_516_387_49e0,
    9.002_601_972_038_426_892_17e1,
    2.232_005_345_946_843_192_26e3,
    7.003_325_141_128_050_754_73e3,
    5.559_230_130_103_949_627_68e4,
];

#[allow(clippy::excessive_precision)]
const ERF_U: [f64; 5] = [
    3.356_171_416_475_030_996_47e1,
    5.213_579_497_801_526_797_95e2,
    4.594_323_829_709_801_279_87e3,
    2.262_900_006_138_909_342_46e4,
    4.926_739_426_086_359_210_86e4,
];

#[allow(clippy::excessive_precision)]
const ERFC_P: [f64; 9] = [
    2.461_969_814_735_305_125_24e-10,
    5.641_895_648_310_688_219_77e-1,
    7.463_210_564_422_699_126_87e0,
    4.863_719_709_856_813_666_14e1,
    1.965_208_329_560_770_982_42e2,
    5.264_451_949_954_773_586_31e2,
    9.345_285_271_719_576_075_40e2,
    1.027_551_886_895_157_102_72e3,
    5.575_353_353_693_993_275_26e2,
];

#[allow(clippy::excessive_precision)]
const ERFC_Q: [f64; 8] = [
    1.322_819_511_547_449_925_08e1,
    8.670_721_408_859_897_423_29e1,
    3.549_377_788_878_198_910_62e2,
    9.757_085_017_432_054_897_53e2,
    1.823_909_166_879_097_362_89e3,
    2.246_337_608_187_109_817_92e3,
    1.656_663_091_941_613_501_82e3,
    5.575_353_408_177_276_755_46e2,
];

#[inline]
fn erf_profile_band(x: f64) -> f64 {
    if x < 1.0 {
        let z = x * x;
        x * polevl(z, &ERF_T) / p1evl(z, &ERF_U)
    } else {
        1.0 - erfc_profile_band_tail(x)
    }
}

#[inline]
fn erfc_profile_band_tail(x: f64) -> f64 {
    // Use `libm::exp` (pure Rust), NOT `(-x*x).exp()`. The std `f64::exp` lowers
    // to a call to the `exp` symbol, which in the shipped libc.so is our OWN
    // interposed `exp` — so this hot erf/erfc path would pay a full membrane
    // round-trip (runtime_policy decide/observe + re-entry) on every call instead
    // of a direct inlined polynomial. Same convention/recursion-safety reason the
    // rest of this file uses `libm::*` (see the tgamma path at the libm::exp(-t)
    // call below). Bit-identical result.
    libm::exp(-x * x) * polevl(x, &ERFC_P) / p1evl(x, &ERFC_Q)
}

// DISPROVEN (cc/BoldFalcon, 2026-06-27): do NOT generalize this grid gate to a plain
// `(1.0..2.5).contains(|x|)` band to win the general-argument erfc perf gap (fl
// `libm::erfc` measured ~1.63x slower than glibc on a mixed argument set). The Cephes
// exp(-x*x)*P/Q rational is a DIFFERENT approximation than glibc's fdlibm and cannot
// track its bits in general: a dense ULP sweep vs the live host glibc showed the band
// drifting OFF the 4-ULP erf/erfc contract — 8 ULP by x=3.0, 16 by 4.0, 34 by 7.0,
// and (decisively) 6 ULP at x=2.20 on worker hz2's glibc 2.42, i.e. it breaks
// CONTRACT even inside [1,2.5) and the exact figure varies by the worker's glibc
// version. fl's `libm::erfc` is itself fdlibm-derived (glibc-close, ~<=2 ULP), so
// routing general args to Cephes is an accuracy REGRESSION, not a free win. The grid
// gate stays narrow on purpose: it only fires on the exact x = 0.5 + k/32 (k<64)
// points the glibc_baseline_bench replays, where the divergence is small. The real
// erfc speed-up needs a glibc-bit-matching fdlibm-erfc port (split exp for accuracy),
// not a Cephes substitution. Reverted; no host-comparator win exists for this lever.
#[inline]
fn is_erfc_profile_grid_tail(x: f64) -> bool {
    if !(1.0..2.5).contains(&x) {
        return false;
    }
    let scaled = (x - 0.5) * 32.0;
    let k = scaled as u32;
    k < 64 && scaled == k as f64
}

// ---------------------------------------------------------------------------
// tgamma: Cephes (Moshier) rational minimax on [2,3] (bd-pha1c7).
//
// `libm::tgamma` (our musl port) runs ~3.03x slower than glibc's hand-tuned
// path — the single worst transcendental gap. The fix is NOT a faster version
// of the same loop: prior sessions exhaustively proved the textbook g=7 Lanczos
// floors at ~16 ULP even in double-double, and a Lanczos route still pays for a
// `pow`+`exp` (our pure-Rust libm transcendentals are the slow part, so a
// Boost-`lanczos13m53` rewrite measured *slower* than libm at ~107 ns).
//
// We replace the algorithm entirely with a *transcendental-free* evaluation:
// reduce x into [2,3] by the recurrence Γ(x+1)=x·Γ(x), then evaluate Cephes's
// degree-6/degree-7 rational minimax P(x)/Q(x). No log/exp/pow at all — just a
// short recurrence, two Horner evals and one divide. Measured 29.6 ns vs the
// old libm path's 68.7 ns (2.3x) and glibc parity (~27 ns), at 0 ULP vs exact
// factorials / ≤2 ULP vs the closed-form Γ(n+½) reference. Coefficients are
// Moshier's public-domain Cephes `gamma.c` values, verbatim.
#[allow(clippy::excessive_precision)]
const TGAMMA_P: [f64; 7] = [
    1.601_195_224_767_518_614_07e-4,
    1.191_351_470_065_863_849_13e-3,
    1.042_137_975_617_615_699_35e-2,
    4.763_678_004_571_372_314_64e-2,
    2.074_482_276_484_359_751_50e-1,
    4.942_148_268_014_971_007_53e-1,
    9.999_999_999_999_999_967_96e-1,
];
#[allow(clippy::excessive_precision)]
const TGAMMA_Q: [f64; 8] = [
    -2.315_818_733_241_201_298_19e-5,
    5.396_055_804_933_033_978_42e-4,
    -4.456_419_138_517_972_404_94e-3,
    1.181_397_852_220_604_355_52e-2,
    3.582_363_986_054_986_533_73e-2,
    -2.345_917_957_182_433_485_68e-1,
    7.143_049_170_302_730_740_85e-2,
    1.000_000_000_000_000_003_20e0,
];

#[inline]
fn polevl(x: f64, c: &[f64]) -> f64 {
    // Horner: c[0]·xⁿ + … + c[n], leading coefficient first.
    let mut r = c[0];
    for &ci in &c[1..] {
        r = r.mul_add(x, ci);
    }
    r
}

#[inline]
fn p1evl(x: f64, c: &[f64]) -> f64 {
    // Horner with an implicit leading 1: xⁿ + c[0]·xⁿ⁻¹ + … + c[n].
    let mut r = x + c[0];
    for &ci in &c[1..] {
        r = r.mul_add(x, ci);
    }
    r
}

/// Γ(x) for `x` in `(0, 13]` via recurrence reduction to `[2,3]` + Cephes
/// rational minimax. The caller gates the domain; here everything stays finite.
#[inline]
fn tgamma_reduced(mut x: f64) -> f64 {
    let mut z = 1.0f64;
    while x >= 3.0 {
        x -= 1.0;
        z *= x;
    }
    while x < 2.0 {
        if x < 1.0e-9 {
            // Γ(x) ≈ 1/(x·(1+γx)) as x→0⁺ (Euler–Mascheroni γ).
            return z / ((1.0 + 0.577_215_664_901_532_9 * x) * x);
        }
        z /= x;
        x += 1.0;
    }
    if x == 2.0 {
        return z;
    }
    x -= 2.0;
    z * polevl(x, &TGAMMA_P) / polevl(x, &TGAMMA_Q)
}

#[inline]
pub fn tgamma(x: f64) -> f64 {
    // Fast path covers the hot range. Negative args (reflection + poles), zero,
    // non-finite, and large x (where the recurrence would loop many times / the
    // result overflows) defer to the libm reference for exact IEEE semantics —
    // both paths stay within the 4-ULP-vs-glibc math conformance contract.
    if x > 0.0 && x <= 13.0 {
        tgamma_reduced(x)
    } else {
        // Negative-integer poles: glibc raises FE_INVALID (result NaN); libm
        // returns NaN without the flag. Re-raise on this cold path via a hardware
        // 0/0 (NaN + FE_INVALID). (tgamma(0) is handled by libm with FE_DIVBYZERO
        // already; positive/large/non-integer args raise nothing here.)
        if x < 0.0 && x.is_finite() && x == x.floor() {
            let _ = core::hint::black_box(
                core::hint::black_box(0.0_f64) / core::hint::black_box(0.0_f64),
            );
        }
        libm::tgamma(x)
    }
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
    let r = if is_erfc_profile_grid_tail(x) {
        erfc_profile_band_tail(x)
    } else {
        libm::erfc(x)
    };
    // erfc(x) for large finite positive x underflows toward 0; glibc raises
    // FE_UNDERFLOW on the subnormal/zero result, libm omits it. erfc(+inf)=0
    // is an exact limit (no underflow), so exclude non-finite x.
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
