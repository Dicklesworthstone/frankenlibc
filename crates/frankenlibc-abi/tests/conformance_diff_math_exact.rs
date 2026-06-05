#![cfg(target_os = "linux")]

//! Differential conformance for the EXACT-result `<math.h>` functions —
//! nextafter / scalbn / ilogb / logb / remainder / remquo / modf / frexp /
//! ldexp / trunc / rint / nearbyint / round / significand / l*round / l*rint.
//!
//! Unlike the transcendentals, these produce a uniquely-defined IEEE-754
//! result, so any divergence from host glibc on special values (NaN, ±0, ±Inf,
//! subnormals, halfway cases, exponent extremes) is a real parity bug — not an
//! accuracy/ULP difference. Compared bit-for-bit (NaN-vs-NaN treated equal).

use std::ffi::{c_int, c_long};

use frankenlibc_abi::math_abi as fl;

unsafe extern "C" {
    fn nextafter(x: f64, y: f64) -> f64;
    fn scalbn(x: f64, n: c_int) -> f64;
    fn ilogb(x: f64) -> c_int;
    fn logb(x: f64) -> f64;
    fn remainder(x: f64, y: f64) -> f64;
    fn remquo(x: f64, y: f64, quo: *mut c_int) -> f64;
    fn modf(x: f64, iptr: *mut f64) -> f64;
    fn frexp(x: f64, e: *mut c_int) -> f64;
    fn ldexp(x: f64, n: c_int) -> f64;
    fn trunc(x: f64) -> f64;
    fn rint(x: f64) -> f64;
    fn nearbyint(x: f64) -> f64;
    fn round(x: f64) -> f64;
    fn significand(x: f64) -> f64;
    fn lround(x: f64) -> c_long;
    fn lrint(x: f64) -> c_long;
    fn llround(x: f64) -> i64;
    fn llrint(x: f64) -> i64;
    fn lroundf(x: f32) -> c_long;
    fn lrintf(x: f32) -> c_long;
    // f32 exact-result variants.
    fn truncf(x: f32) -> f32;
    fn rintf(x: f32) -> f32;
    fn nearbyintf(x: f32) -> f32;
    fn roundf(x: f32) -> f32;
    fn logbf(x: f32) -> f32;
    fn ilogbf(x: f32) -> c_int;
    fn significandf(x: f32) -> f32;
    fn nextafterf(x: f32, y: f32) -> f32;
    fn scalbnf(x: f32, n: c_int) -> f32;
    fn remainderf(x: f32, y: f32) -> f32;
    fn modff(x: f32, iptr: *mut f32) -> f32;
    fn frexpf(x: f32, e: *mut c_int) -> f32;
    fn ldexpf(x: f32, n: c_int) -> f32;
}

fn feq32(a: f32, b: f32) -> bool {
    (a.is_nan() && b.is_nan()) || a.to_bits() == b.to_bits()
}

/// Adversarial f32 corpus mirroring the f64 one.
fn corpus_f32() -> Vec<f32> {
    let mut v: Vec<f32> = vec![
        0.0,
        -0.0,
        1.0,
        -1.0,
        2.0,
        -2.0,
        0.5,
        -0.5,
        1.5,
        -1.5,
        2.5,
        -2.5,
        3.5,
        -3.5,
        0.25,
        f32::INFINITY,
        f32::NEG_INFINITY,
        f32::NAN,
        f32::MIN_POSITIVE,
        f32::MIN_POSITIVE / 2.0,
        f32::from_bits(1), // smallest positive subnormal
        f32::MAX,
        f32::MIN,
        8388608.0,  // 2^23
        8388609.0,  // 2^23 + 1
        16777216.0, // 2^24
        -8388608.5,
        0.499_999_97,
        0.500_000_06,
        123_456.79,
        1e30,
        1e-30,
        std::f32::consts::PI,
    ];
    let mut s: u32 = 0x9abc_def1;
    for _ in 0..6000 {
        s ^= s << 13;
        s ^= s >> 17;
        s ^= s << 5;
        v.push(f32::from_bits(s));
    }
    v
}

#[test]
fn diff_math_exact_f32_vs_glibc() {
    let xs = corpus_f32();
    let mut div: Vec<String> = Vec::new();

    macro_rules! chk1 {
        ($name:literal, $fl:path, $g:ident) => {
            for &x in &xs {
                let a = unsafe { $fl(x) };
                let b = unsafe { $g(x) };
                if !feq32(a, b) {
                    div.push(format!(
                        "  {}(0x{:08x} {:e}): fl=0x{:08x} glibc=0x{:08x}",
                        $name,
                        x.to_bits(),
                        x,
                        a.to_bits(),
                        b.to_bits()
                    ));
                }
            }
        };
    }

    chk1!("truncf", fl::truncf, truncf);
    chk1!("rintf", fl::rintf, rintf);
    chk1!("nearbyintf", fl::nearbyintf, nearbyintf);
    chk1!("roundf", fl::roundf, roundf);
    chk1!("logbf", fl::logbf, logbf);
    chk1!("significandf", fl::significandf, significandf);

    for &x in &xs {
        if unsafe { fl::ilogbf(x) } != unsafe { ilogbf(x) } {
            div.push(format!(
                "  ilogbf(0x{:08x} {:e}): fl={} glibc={}",
                x.to_bits(),
                x,
                unsafe { fl::ilogbf(x) },
                unsafe { ilogbf(x) }
            ));
        }
    }

    let ys = &xs[..xs.len().min(64)];
    for &x in &xs {
        for &y in ys {
            let a = unsafe { fl::nextafterf(x, y) };
            let b = unsafe { nextafterf(x, y) };
            if !feq32(a, b) {
                div.push(format!("  nextafterf({x:e},{y:e}): fl={a:e} glibc={b:e}"));
            }
            let a = unsafe { fl::remainderf(x, y) };
            let b = unsafe { remainderf(x, y) };
            if !feq32(a, b) {
                div.push(format!(
                    "  remainderf({x:e},{y:e}): fl=0x{:08x} glibc=0x{:08x}",
                    a.to_bits(),
                    b.to_bits()
                ));
            }
        }
    }

    let ns: [c_int; 9] = [0, 1, -1, 23, -23, 127, -127, 150, -150];
    for &x in &xs {
        for &n in &ns {
            let a = unsafe { fl::scalbnf(x, n) };
            let b = unsafe { scalbnf(x, n) };
            if !feq32(a, b) {
                div.push(format!("  scalbnf({x:e},{n}): fl={a:e} glibc={b:e}"));
            }
            let a = unsafe { fl::ldexpf(x, n) };
            let b = unsafe { ldexpf(x, n) };
            if !feq32(a, b) {
                div.push(format!("  ldexpf({x:e},{n}): fl={a:e} glibc={b:e}"));
            }
        }
    }

    for &x in &xs {
        let (mut ia, mut ib) = (0.0f32, 0.0f32);
        let a = unsafe { fl::modff(x, &mut ia) };
        let b = unsafe { modff(x, &mut ib) };
        if !feq32(a, b) || !feq32(ia, ib) {
            div.push(format!(
                "  modff({x:e}): fl=(f=0x{:08x},i=0x{:08x}) glibc=(f=0x{:08x},i=0x{:08x})",
                a.to_bits(),
                ia.to_bits(),
                b.to_bits(),
                ib.to_bits()
            ));
        }
        let (mut ea, mut eb): (c_int, c_int) = (0, 0);
        let a = unsafe { fl::frexpf(x, &mut ea) };
        let b = unsafe { frexpf(x, &mut eb) };
        if !feq32(a, b) || (a != 0.0 && a.is_finite() && ea != eb) {
            div.push(format!(
                "  frexpf({x:e}): fl=(0x{:08x},e={ea}) glibc=(0x{:08x},e={eb})",
                a.to_bits(),
                b.to_bits()
            ));
        }
    }

    use std::collections::BTreeMap;
    let mut hist: BTreeMap<&str, usize> = BTreeMap::new();
    for d in &div {
        *hist
            .entry(d.trim_start().split('(').next().unwrap_or("?"))
            .or_default() += 1;
    }
    let summary: String = hist.iter().map(|(k, n)| format!("  {k}: {n}\n")).collect();
    let examples: String = div.iter().take(30).cloned().collect::<Vec<_>>().join("\n");
    assert!(
        div.is_empty(),
        "{} f32 exact-math divergences vs glibc.\nHISTOGRAM:\n{}EXAMPLES:\n{}",
        div.len(),
        summary,
        examples
    );
}

/// Bit-equality with NaN-vs-NaN treated as equal (payloads may differ and are
/// not part of the value-level contract).
fn feq(a: f64, b: f64) -> bool {
    (a.is_nan() && b.is_nan()) || a.to_bits() == b.to_bits()
}

/// Adversarial f64 corpus: special values, signed zeros/infs, subnormals,
/// exponent extremes, halfway-to-integer cases, and a deterministic xorshift
/// spray of random bit patterns.
fn corpus() -> Vec<f64> {
    let mut v: Vec<f64> = vec![
        0.0,
        -0.0,
        1.0,
        -1.0,
        2.0,
        -2.0,
        0.5,
        -0.5,
        1.5,
        -1.5,
        2.5,
        -2.5,
        3.5,
        -3.5,
        0.25,
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::NAN,
        f64::MIN_POSITIVE,       // smallest normal
        f64::MIN_POSITIVE / 2.0, // subnormal
        5e-324,                  // smallest positive subnormal
        -5e-324,
        f64::MAX,
        f64::MIN,
        4503599627370496.0, // 2^52
        4503599627370497.0, // 2^52 + 1
        9007199254740992.0, // 2^53
        -4503599627370496.5,
        1.0 - f64::EPSILON / 2.0, // just below 1
        123456.789,
        -0.499_999_999_999_999_9, // just below 0.5 (round/rint boundary)
        0.500_000_000_000_000_1,
        1e300,
        1e-300,
        std::f64::consts::PI,
    ];
    let mut s: u64 = 0x1234_5678_9abc_def1;
    for _ in 0..4000 {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        // Keep random values in a sane magnitude band [2^-40, 2^40) so we probe
        // well-defined results, not the x86 cvttsd2si indefinite that glibc
        // returns for out-of-range lrint/lround (UB territory).
        let r = f64::from_bits(s);
        if r.is_finite() && r != 0.0 && r.abs() >= 9.0e-13 && r.abs() < 1.0e12 {
            v.push(r);
        }
    }
    v
}

#[test]
fn diff_math_exact_unary_and_binary_vs_glibc() {
    let xs = corpus();
    let mut div: Vec<String> = Vec::new();

    macro_rules! chk_unary {
        ($name:literal, $fl:path, $g:ident) => {
            for &x in &xs {
                let a = unsafe { $fl(x) };
                let b = unsafe { $g(x) };
                if !feq(a, b) {
                    div.push(format!(
                        "  {}(x=0x{:016x} {:e}): fl=0x{:016x} glibc=0x{:016x}",
                        $name,
                        x.to_bits(),
                        x,
                        a.to_bits(),
                        b.to_bits()
                    ));
                }
            }
        };
    }

    chk_unary!("logb", fl::logb, logb);
    chk_unary!("trunc", fl::trunc, trunc);
    chk_unary!("rint", fl::rint, rint);
    chk_unary!("nearbyint", fl::nearbyint, nearbyint);
    chk_unary!("round", fl::round, round);
    chk_unary!("significand", fl::significand, significand);

    // ilogb returns an int (with special FP_ILOGB0 / FP_ILOGBNAN / INT_MAX).
    for &x in &xs {
        let a = unsafe { fl::ilogb(x) };
        let b = unsafe { ilogb(x) };
        if a != b {
            div.push(format!(
                "  ilogb(0x{:016x} {:e}): fl={} glibc={}",
                x.to_bits(),
                x,
                a,
                b
            ));
        }
    }

    // lround / lrint return long. Compared over the WHOLE corpus — including
    // out-of-range / NaN / Inf, where glibc returns the x86 cvt(t)sd2si
    // integer-indefinite (i64::MIN). FrankenLibC matches this exactly.
    for &x in &xs {
        let a = unsafe { fl::lround(x) };
        let b = unsafe { lround(x) };
        if a != b {
            div.push(format!("  lround({x:e}): fl={a} glibc={b}"));
        }
        let a = unsafe { fl::lrint(x) };
        let b = unsafe { lrint(x) };
        if a != b {
            div.push(format!("  lrint({x:e}): fl={a} glibc={b}"));
        }
        // ll* variants are identical on LP64 but exercise separate fl wrappers.
        if unsafe { fl::llround(x) } != unsafe { llround(x) } {
            div.push(format!("  llround({x:e}) diverges"));
        }
        if unsafe { fl::llrint(x) } != unsafe { llrint(x) } {
            div.push(format!("  llrint({x:e}) diverges"));
        }
        // f32 path (cvt(t)ss2si): widen the corpus value to f32 and compare.
        let xf = x as f32;
        if unsafe { fl::lroundf(xf) } != unsafe { lroundf(xf) } {
            div.push(format!(
                "  lroundf({xf:e}): fl={} glibc={}",
                unsafe { fl::lroundf(xf) },
                unsafe { lroundf(xf) }
            ));
        }
        if unsafe { fl::lrintf(xf) } != unsafe { lrintf(xf) } {
            div.push(format!(
                "  lrintf({xf:e}): fl={} glibc={}",
                unsafe { fl::lrintf(xf) },
                unsafe { lrintf(xf) }
            ));
        }
    }

    // Binary: nextafter, remainder over the cross product of a focused subset.
    let ys = &xs[..xs.len().min(60)];
    for &x in &xs {
        for &y in ys {
            let a = unsafe { fl::nextafter(x, y) };
            let b = unsafe { nextafter(x, y) };
            if !feq(a, b) {
                div.push(format!(
                    "  nextafter({:e},{:e}): fl=0x{:016x} glibc=0x{:016x}",
                    x,
                    y,
                    a.to_bits(),
                    b.to_bits()
                ));
            }
            let a = unsafe { fl::remainder(x, y) };
            let b = unsafe { remainder(x, y) };
            if !feq(a, b) {
                div.push(format!(
                    "  remainder({:e},{:e}): fl=0x{:016x} glibc=0x{:016x}",
                    x,
                    y,
                    a.to_bits(),
                    b.to_bits()
                ));
            }
        }
    }

    // scalbn / ldexp over integer exponents incl. extremes.
    let ns: [c_int; 11] = [0, 1, -1, 52, -52, 1023, -1023, 1024, -1074, 2048, -2048];
    for &x in &xs {
        for &n in &ns {
            let a = unsafe { fl::scalbn(x, n) };
            let b = unsafe { scalbn(x, n) };
            if !feq(a, b) {
                div.push(format!(
                    "  scalbn({:e},{}): fl=0x{:016x} glibc=0x{:016x}",
                    x,
                    n,
                    a.to_bits(),
                    b.to_bits()
                ));
            }
            let a = unsafe { fl::ldexp(x, n) };
            let b = unsafe { ldexp(x, n) };
            if !feq(a, b) {
                div.push(format!(
                    "  ldexp({:e},{}): fl=0x{:016x} glibc=0x{:016x}",
                    x,
                    n,
                    a.to_bits(),
                    b.to_bits()
                ));
            }
        }
    }

    // remquo: the remainder must match bit-for-bit, and `quo` must satisfy the
    // C99 contract vs glibc — sign of x/y, magnitude congruent mod 2^n (n>=3).
    // We check sign + congruence mod 8 (n=3). FrankenLibC returns the canonical
    // reduced quotient in [-7,7]; glibc agrees for all normal-magnitude
    // quotients and only occasionally returns a congruent non-reduced value
    // (e.g. 8 ≡ 0) for very large |x/y|, which this congruence check accepts.
    for &x in &xs {
        for &y in ys {
            let (mut qa, mut qb): (c_int, c_int) = (0, 0);
            let a = unsafe { fl::remquo(x, y, &mut qa) };
            let b = unsafe { remquo(x, y, &mut qb) };
            let cong = qa.unsigned_abs() % 8 == qb.unsigned_abs() % 8;
            let sign_ok = qa == 0 || qb == 0 || (qa < 0) == (qb < 0);
            if !feq(a, b) || (a.is_finite() && (!cong || !sign_ok)) {
                div.push(format!(
                    "  remquo({:e},{:e}): fl=(0x{:016x},q={}) glibc=(0x{:016x},q={})",
                    x,
                    y,
                    a.to_bits(),
                    qa,
                    b.to_bits(),
                    qb
                ));
            }
        }
    }

    // modf / frexp: both the returned value and the out-param must match.
    for &x in &xs {
        let (mut ia, mut ib) = (0.0_f64, 0.0_f64);
        let a = unsafe { fl::modf(x, &mut ia) };
        let b = unsafe { modf(x, &mut ib) };
        if !feq(a, b) || !feq(ia, ib) {
            div.push(format!(
                "  modf({:e}): fl=(frac=0x{:016x},int=0x{:016x}) glibc=(frac=0x{:016x},int=0x{:016x})",
                x, a.to_bits(), ia.to_bits(), b.to_bits(), ib.to_bits()
            ));
        }
        let (mut ea, mut eb): (c_int, c_int) = (0, 0);
        let a = unsafe { fl::frexp(x, &mut ea) };
        let b = unsafe { frexp(x, &mut eb) };
        if !feq(a, b) || (a != 0.0 && a.is_finite() && ea != eb) {
            div.push(format!(
                "  frexp({:e}): fl=(0x{:016x},e={}) glibc=(0x{:016x},e={})",
                x,
                a.to_bits(),
                ea,
                b.to_bits(),
                eb
            ));
        }
    }

    use std::collections::BTreeMap;
    let mut hist: BTreeMap<&str, usize> = BTreeMap::new();
    for d in &div {
        let name = d.trim_start().split('(').next().unwrap_or("?");
        *hist.entry(name).or_default() += 1;
    }
    let mut summary = String::new();
    for (k, n) in &hist {
        summary.push_str(&format!("  {k}: {n}\n"));
    }
    // Print a few examples per function for diagnosis.
    let mut examples = String::new();
    for k in hist.keys() {
        for d in div
            .iter()
            .filter(|d| d.trim_start().starts_with(*k))
            .take(3)
        {
            examples.push_str(d);
            examples.push('\n');
        }
    }
    assert!(
        div.is_empty(),
        "{} exact-math divergences vs host glibc.\nHISTOGRAM:\n{}EXAMPLES:\n{}",
        div.len(),
        summary,
        examples
    );
}
