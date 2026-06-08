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
    let am = if ai < 0 { i64::MIN.wrapping_sub(ai) } else { ai };
    let bi = b.to_bits() as i64;
    let bm = if bi < 0 { i64::MIN.wrapping_sub(bi) } else { bi };
    am.abs_diff(bm)
}

/// True when glibc's result component is a "special" value (inf/nan or signed
/// zero) where Annex G mandates an exact result.
fn is_special(x: f64) -> bool {
    !x.is_normal() && (x == 0.0 || !x.is_finite())
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
        // Signed-zero disagreement where glibc gives an exact special value.
        if (is_special(b.re) && a.re.to_bits() != b.re.to_bits())
            || (is_special(b.im) && a.im.to_bits() != b.im.to_bits())
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
