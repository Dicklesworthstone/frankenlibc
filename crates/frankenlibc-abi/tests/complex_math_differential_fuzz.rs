#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // host-glibc complex-math oracle (libm)

//! Randomized live differential fuzzer for the C99 `<complex.h>` family vs host
//! glibc. fl's complex functions are hand-rolled formulas (cexp = exp*cis,
//! clog = log(hypot)+i*atan2, csqrt branch formula, cpow = exp(w*clog)); this
//! pins each against the host C library across finite regimes (small, near the
//! unit circle, medium, large) and the C99 Annex G special values (inf / nan /
//! signed zero), where exact results are mandated.
//!
//! `double _Complex` is classified SSE,SSE on System V AMD64 — identical to a
//! `#[repr(C)] { re: f64, im: f64 }` — so we pass `CDoubleComplex` by value to
//! the host functions directly.

use frankenlibc_abi::math_abi::{self as fl, CDoubleComplex as C};

unsafe extern "C" {
    fn cexp(z: C) -> C;
    fn clog(z: C) -> C;
    fn csqrt(z: C) -> C;
    fn cpow(a: C, b: C) -> C;
    fn csin(z: C) -> C;
    fn ccos(z: C) -> C;
    fn ctan(z: C) -> C;
    fn csinh(z: C) -> C;
    fn ccosh(z: C) -> C;
    fn ctanh(z: C) -> C;
    fn casin(z: C) -> C;
    fn cacos(z: C) -> C;
    fn catan(z: C) -> C;
    fn casinh(z: C) -> C;
    fn cacosh(z: C) -> C;
    fn catanh(z: C) -> C;
}

struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    fn f64_in(&mut self, lo: f64, hi: f64) -> f64 {
        let u = (self.next() >> 11) as f64 / (1u64 << 53) as f64; // [0,1)
        lo + u * (hi - lo)
    }
    /// A value drawn from a regime mix: small, unit-ish, medium, large, plus
    /// occasional special values.
    fn comp(&mut self) -> f64 {
        match self.next() % 16 {
            0..=4 => self.f64_in(-1.5, 1.5),
            5..=8 => self.f64_in(-10.0, 10.0),
            9..=11 => self.f64_in(-1e3, 1e3),
            12 => self.f64_in(-1e6, 1e6),
            13 => {
                // near +-1 / +-0 boundaries
                let base = if self.next() & 1 == 0 { 1.0 } else { 0.0 };
                base + self.f64_in(-1e-9, 1e-9)
            }
            14 => match self.next() % 6 {
                0 => f64::INFINITY,
                1 => f64::NEG_INFINITY,
                2 => f64::NAN,
                3 => 0.0,
                4 => -0.0,
                _ => self.f64_in(-3.0, 3.0),
            },
            _ => self.f64_in(-1e300, 1e300),
        }
    }
    fn z(&mut self) -> C {
        C {
            re: self.comp(),
            im: self.comp(),
        }
    }
}

/// ULP distance between two f64 with sign/NaN awareness. Returns `u64::MAX` for
/// a "category" mismatch (one finite, the other inf/nan, or differing inf sign).
fn ulp(a: f64, b: f64) -> u64 {
    if a.to_bits() == b.to_bits() {
        return 0;
    }
    if a.is_nan() && b.is_nan() {
        return 0; // any NaN matches any NaN
    }
    if a.is_nan() != b.is_nan() {
        return u64::MAX;
    }
    if a.is_infinite() || b.is_infinite() {
        // both finite handled below; here at least one is inf
        return if a == b { 0 } else { u64::MAX };
    }
    // Map to a monotonic ordered integer space.
    let ai = a.to_bits() as i64;
    let am = if ai < 0 {
        i64::MIN.wrapping_sub(ai)
    } else {
        ai
    };
    let bi = b.to_bits() as i64;
    let bm = if bi < 0 {
        i64::MIN.wrapping_sub(bi)
    } else {
        bi
    };
    am.abs_diff(bm)
}

struct Stat {
    name: &'static str,
    max_ulp: u64,
    cat_mismatch: u64, // inf/nan category disagreements
    zero_sign: u64,    // signed-zero disagreements on special outputs
    worst: String,
    total: u64,
}

fn main_compare(
    name: &'static str,
    n: usize,
    seed: u64,
    f: impl Fn(C) -> C,
    g: impl Fn(C) -> C,
) -> Stat {
    let mut r = Lcg(seed);
    let mut st = Stat {
        name,
        max_ulp: 0,
        cat_mismatch: 0,
        zero_sign: 0,
        worst: String::new(),
        total: 0,
    };
    for _ in 0..n {
        let z = r.z();
        let a = f(z);
        let b = g(z);
        st.total += 1;
        let ur = ulp(a.re, b.re);
        let ui = ulp(a.im, b.im);
        // Category (inf/nan) mismatch.
        if ur == u64::MAX || ui == u64::MAX {
            st.cat_mismatch += 1;
            if st.worst.is_empty() {
                st.worst = format!(
                    "z=({:e},{:e}) fl=({:e},{:e}) glibc=({:e},{:e}) [category]",
                    z.re, z.im, a.re, a.im, b.re, b.im
                );
            }
            continue;
        }
        // Signed-zero disagreement: glibc returns an exact 0 with a mandated
        // sign but fl differs (wrong sign, or a denormal where 0 is expected).
        // NaN payloads and inf signs are unspecified / already category-checked.
        if (b.re == 0.0 && a.re.to_bits() != b.re.to_bits())
            || (b.im == 0.0 && a.im.to_bits() != b.im.to_bits())
        {
            st.zero_sign += 1;
            if st.worst.is_empty() {
                st.worst = format!(
                    "z=({:e},{:e}) fl=({:e},{:e}) glibc=({:e},{:e}) [signbit]",
                    z.re, z.im, a.re, a.im, b.re, b.im
                );
            }
        }
        let u = ur.max(ui);
        if u > st.max_ulp && a.re.is_finite() && a.im.is_finite() {
            st.max_ulp = u;
            if u > 64 {
                st.worst = format!(
                    "z=({:e},{:e}) fl=({:e},{:e}) glibc=({:e},{:e}) [{}ulp]",
                    z.re, z.im, a.re, a.im, b.re, b.im, u
                );
            }
        }
    }
    st
}

#[test]
fn complex_math_characterize_vs_glibc() {
    let n = 200_000;
    let mut stats = Vec::new();
    macro_rules! cmp {
        ($name:literal, $fl:path, $host:ident, $seed:expr) => {
            stats.push(main_compare(
                $name,
                n,
                $seed,
                |z| unsafe { $fl(z) },
                |z| unsafe { $host(z) },
            ));
        };
    }
    cmp!("cexp", fl::cexp, cexp, 0x1001);
    cmp!("clog", fl::clog, clog, 0x1002);
    cmp!("csqrt", fl::csqrt, csqrt, 0x1003);
    cmp!("csin", fl::csin, csin, 0x1004);
    cmp!("ccos", fl::ccos, ccos, 0x1005);
    cmp!("ctan", fl::ctan, ctan, 0x1006);
    cmp!("csinh", fl::csinh, csinh, 0x1007);
    cmp!("ccosh", fl::ccosh, ccosh, 0x1008);
    cmp!("ctanh", fl::ctanh, ctanh, 0x1009);
    cmp!("casin", fl::casin, casin, 0x100a);
    cmp!("cacos", fl::cacos, cacos, 0x100b);
    cmp!("catan", fl::catan, catan, 0x100c);
    cmp!("casinh", fl::casinh, casinh, 0x100d);
    cmp!("cacosh", fl::cacosh, cacosh, 0x100e);
    cmp!("catanh", fl::catanh, catanh, 0x100f);

    // cpow with random exponents.
    {
        let mut r = Lcg(0x2001);
        let mut st = Stat {
            name: "cpow",
            max_ulp: 0,
            cat_mismatch: 0,
            zero_sign: 0,
            worst: String::new(),
            total: 0,
        };
        for _ in 0..n {
            let a = r.z();
            let b = C {
                re: r.f64_in(-6.0, 6.0),
                im: r.f64_in(-6.0, 6.0),
            };
            let fa = unsafe { fl::cpow(a, b) };
            let ga = unsafe { cpow(a, b) };
            st.total += 1;
            let u = ulp(fa.re, ga.re).max(ulp(fa.im, ga.im));
            if u == u64::MAX {
                st.cat_mismatch += 1;
            } else if u > st.max_ulp && fa.re.is_finite() && fa.im.is_finite() {
                st.max_ulp = u;
            }
        }
        stats.push(st);
    }

    eprintln!("\n=== complex math fl vs glibc ({n} samples each) ===");
    eprintln!(
        "{:<8} {:>12} {:>10} {:>10}  worst",
        "fn", "max_ulp", "cat_mism", "signbit"
    );
    for s in &stats {
        eprintln!(
            "{:<8} {:>12} {:>10} {:>10}  {}",
            s.name,
            s.max_ulp,
            s.cat_mismatch,
            s.zero_sign,
            if s.worst.is_empty() { "-" } else { &s.worst }
        );
    }

    // Regression guard for the clog accuracy fix (bd-2g7oyh.236): the
    // log1p + fma-compensated `re^2 + im^2 - 1` keeps clog within a handful of
    // ULP of glibc across all regimes (it was ~1.5e7 ULP near the unit circle
    // before). clog had no special-value gaps to begin with, so those stay 0.
    // The other complex functions still carry separate, pre-existing branch-cut
    // sign and Annex-G special-value gaps (see bd-2g7oyh.237) and are reported
    // above for tracking but not yet asserted.
    // clog (bd-2g7oyh.236) and csqrt (bd-2g7oyh.239) are fully glibc-exact
    // including signed zero; ctanh/ctan (bd-2g7oyh.240) eliminate the inf/inf ->
    // NaN category failures and stay within a few ULP, but tolerate a single
    // denormal-vs-0 imaginary edge at the exp underflow boundary (fl is in fact
    // the more correctly-rounded there).
    for name in ["clog", "csqrt"] {
        let s = stats.iter().find(|s| s.name == name).unwrap();
        assert!(
            s.max_ulp <= 16,
            "{name} regressed: max_ulp={} (>16): {}",
            s.max_ulp,
            s.worst
        );
        assert_eq!(
            s.cat_mismatch, 0,
            "{name} inf/nan category mismatch: {}",
            s.worst
        );
        assert_eq!(s.zero_sign, 0, "{name} signed-zero mismatch: {}", s.worst);
    }
    for name in ["ctanh", "ctan"] {
        let s = stats.iter().find(|s| s.name == name).unwrap();
        assert!(
            s.max_ulp <= 16,
            "{name} regressed: max_ulp={} (>16): {}",
            s.max_ulp,
            s.worst
        );
        assert_eq!(
            s.cat_mismatch, 0,
            "{name} inf/nan category mismatch: {}",
            s.worst
        );
        assert!(
            s.zero_sign <= 2,
            "{name} signed-zero mismatches={} (>2): {}",
            s.zero_sign,
            s.worst
        );
    }
    // The full elementary complex transcendental family — csinh/ccosh
    // (bd-2g7oyh.241), cexp (bd-2g7oyh.242), and csin/ccos derived from them
    // (bd-2g7oyh.243) — is now glibc-exact: the inf*0 -> NaN special values are
    // gone and the |Re z| ~ 710 overflow band is scaled through e^x = (e^(x/2))^2
    // to a finite value, so there are no category or signed-zero mismatches at
    // all, only a few ULP of rounding.
    for name in ["csinh", "ccosh", "cexp", "csin", "ccos"] {
        let s = stats.iter().find(|s| s.name == name).unwrap();
        assert!(
            s.max_ulp <= 16,
            "{name} regressed: max_ulp={} (>16): {}",
            s.max_ulp,
            s.worst
        );
        assert_eq!(
            s.cat_mismatch, 0,
            "{name} inf/nan category mismatch: {}",
            s.worst
        );
        assert_eq!(s.zero_sign, 0, "{name} signed-zero mismatch: {}", s.worst);
    }
    // catanh (bd-2g7oyh.245) and catan derived from it: the branch-cut sign flips
    // are gone, the cancellation-free closed form keeps a few ULP across the
    // [1,inf)/(-inf,-1] cuts, and the special values match glibc.
    // catanh/catan (bd-2g7oyh.245) and the asin family casin/cacos/casinh/cacosh
    // (bd-2g7oyh.247, via the Hull-Fairgrieve-Tang arcsine/arccosine): the
    // branch-cut sign flips are gone and the closed forms stay within a few ULP.
    for name in ["catanh", "catan", "casin", "cacos", "casinh", "cacosh"] {
        let s = stats.iter().find(|s| s.name == name).unwrap();
        assert!(
            s.max_ulp <= 16,
            "{name} regressed: max_ulp={} (>16): {}",
            s.max_ulp,
            s.worst
        );
        assert_eq!(
            s.cat_mismatch, 0,
            "{name} inf/nan category mismatch: {}",
            s.worst
        );
        assert_eq!(s.zero_sign, 0, "{name} signed-zero mismatch: {}", s.worst);
    }
}

/// Deterministic C99 Annex G special-value contract for csqrt, checked
/// bit-exactly against the host glibc (bd-2g7oyh.239). These mandate exact
/// results, so any divergence is a real conformance bug.
#[test]
fn csqrt_annex_g_special_values_vs_glibc() {
    let vals = [
        0.0f64,
        -0.0,
        1.0,
        -1.0,
        4.0,
        -4.0,
        2.5,
        -2.5,
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::NAN,
    ];
    let mut mism = Vec::new();
    for &re in &vals {
        for &im in &vals {
            let z = C { re, im };
            let a = unsafe { fl::csqrt(z) };
            let b = unsafe { csqrt(z) };
            // Exact bits, except any-NaN matches any-NaN.
            let re_ok = a.re.to_bits() == b.re.to_bits() || (a.re.is_nan() && b.re.is_nan());
            let im_ok = a.im.to_bits() == b.im.to_bits() || (a.im.is_nan() && b.im.is_nan());
            if !(re_ok && im_ok) && mism.len() < 30 {
                mism.push(format!(
                    "csqrt({re:e}{im:+e}i) fl=({:e},{:e}) glibc=({:e},{:e})",
                    a.re, a.im, b.re, b.im
                ));
            }
        }
    }
    assert!(
        mism.is_empty(),
        "csqrt Annex G special-value mismatches:\n{}",
        mism.join("\n")
    );
}

/// Deterministic C99 Annex G special-value contract for catanh (bd-2g7oyh.245),
/// bit-exact vs host glibc. Covers signed zero, the +-1 poles, the branch cuts,
/// and the inf/nan combinations.
#[test]
fn catanh_special_values_vs_glibc() {
    let vals = [
        0.0f64,
        -0.0,
        0.5,
        -0.5,
        1.0,
        -1.0,
        2.0,
        -2.0,
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::NAN,
    ];
    let mut mism = Vec::new();
    for &re in &vals {
        for &im in &vals {
            let z = C { re, im };
            let a = unsafe { fl::catanh(z) };
            let b = unsafe { catanh(z) };
            // Special outputs (0 / inf / nan) must be bit-exact (Annex G); finite
            // transcendental components may differ by a few ULP.
            let cmp = |af: f64, bf: f64| -> bool {
                if bf.is_nan() {
                    af.is_nan()
                } else if bf == 0.0 || bf.is_infinite() {
                    af.to_bits() == bf.to_bits()
                } else {
                    ulp(af, bf) <= 4
                }
            };
            if !(cmp(a.re, b.re) && cmp(a.im, b.im)) && mism.len() < 40 {
                mism.push(format!(
                    "catanh({re:e}{im:+e}i) fl=({:e},{:e}) glibc=({:e},{:e})",
                    a.re, a.im, b.re, b.im
                ));
            }
        }
    }
    assert!(
        mism.is_empty(),
        "catanh Annex G special-value mismatches:\n{}",
        mism.join("\n")
    );
}

/// Deterministic special-value grid for the asin family casinh/cacosh
/// (bd-2g7oyh.247) vs host glibc: special outputs (0/inf/nan) bit-exact (Annex
/// G), finite transcendental components within a few ULP.
#[test]
fn casinh_cacosh_special_values_vs_glibc() {
    let vals = [
        0.0f64,
        -0.0,
        0.5,
        -0.5,
        1.0,
        -1.0,
        2.0,
        -2.0,
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::NAN,
    ];
    type GridCase = (&'static str, fn(C) -> C, unsafe extern "C" fn(C) -> C);
    let cases: &[GridCase] = &[
        ("casinh", |z| unsafe { fl::casinh(z) }, casinh),
        ("cacosh", |z| unsafe { fl::cacosh(z) }, cacosh),
    ];
    let mut mism = Vec::new();
    for (name, flf, host) in cases {
        for &re in &vals {
            for &im in &vals {
                let z = C { re, im };
                let a = flf(z);
                let b = unsafe { host(z) };
                let cmp = |af: f64, bf: f64| -> bool {
                    if bf.is_nan() {
                        af.is_nan()
                    } else if bf == 0.0 || bf.is_infinite() {
                        af.to_bits() == bf.to_bits()
                    } else {
                        ulp(af, bf) <= 4
                    }
                };
                if !(cmp(a.re, b.re) && cmp(a.im, b.im)) && mism.len() < 40 {
                    mism.push(format!(
                        "{name}({re:e}{im:+e}i) fl=({:e},{:e}) glibc=({:e},{:e})",
                        a.re, a.im, b.re, b.im
                    ));
                }
            }
        }
    }
    assert!(
        mism.is_empty(),
        "casinh/cacosh special-value mismatches:\n{}",
        mism.join("\n")
    );
}

/// Deterministic special-value grid for csinh/ccosh (bd-2g7oyh.241) and cexp
/// (bd-2g7oyh.242), bit-exact vs host glibc. Covers signed zero, large finite
/// (overflowing) reals, and the inf/nan combinations where the naive
/// `e^x*cos + i e^x*sin` / `sinh*cos + i cosh*sin` formulas yield `inf*0 = NaN`.
#[test]
fn csinh_ccosh_special_values_vs_glibc() {
    let vals = [
        0.0f64,
        -0.0,
        1.0,
        -1.0,
        1.0e6,
        -1.0e6,
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::NAN,
    ];
    type GridCase = (&'static str, fn(C) -> C, unsafe extern "C" fn(C) -> C);
    // The grid pins the *base* functions exactly. csin/ccos are derived from
    // csinh/ccosh via the i*z identity, which is glibc-exact for all finite and
    // most special inputs (the random sweep below asserts 0 category mismatches),
    // but glibc gives csin/ccos their own sign convention at the both-infinite
    // corners (e.g. csin(inf + i*inf) imag = +inf, not the identity's -inf), so
    // they are not held to bit-exactness on this exhaustive grid.
    let cases: &[GridCase] = &[
        ("csinh", |z| unsafe { fl::csinh(z) }, csinh),
        ("ccosh", |z| unsafe { fl::ccosh(z) }, ccosh),
        ("cexp", |z| unsafe { fl::cexp(z) }, cexp),
    ];
    let mut mism = Vec::new();
    for (name, flf, host) in cases {
        for &re in &vals {
            for &im in &vals {
                let z = C { re, im };
                let a = flf(z);
                let b = unsafe { host(z) };
                let re_ok = a.re.to_bits() == b.re.to_bits() || (a.re.is_nan() && b.re.is_nan());
                let im_ok = a.im.to_bits() == b.im.to_bits() || (a.im.is_nan() && b.im.is_nan());
                if !(re_ok && im_ok) && mism.len() < 40 {
                    mism.push(format!(
                        "{name}({re:e}{im:+e}i) fl=({:e},{:e}) glibc=({:e},{:e})",
                        a.re, a.im, b.re, b.im
                    ));
                }
            }
        }
    }
    assert!(
        mism.is_empty(),
        "csinh/ccosh special-value mismatches:\n{}",
        mism.join("\n")
    );
}
