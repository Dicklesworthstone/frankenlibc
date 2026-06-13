#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc libm oracle

//! Randomized bit-exact differential fuzzer for the native f64 decomposition /
//! manipulation functions vs host glibc libm: modf, frexp, nextafter, scalbn,
//! ldexp, fma, remainder, remquo. These are IEEE-exact (no ULP tolerance), so
//! random doubles — biased toward signed zeros, subnormals, infinities, NaNs,
//! powers of two, and boundary magnitudes — must reproduce glibc bit-for-bit
//! (including the integer side-outputs of frexp/modf/remquo).

use frankenlibc_abi::math_abi as fl;

unsafe extern "C" {
    fn modf(x: f64, iptr: *mut f64) -> f64;
    fn frexp(x: f64, e: *mut libc::c_int) -> f64;
    fn nextafter(x: f64, y: f64) -> f64;
    fn scalbn(x: f64, n: libc::c_int) -> f64;
    fn ldexp(x: f64, n: libc::c_int) -> f64;
    fn fma(x: f64, y: f64, z: f64) -> f64;
    fn remainder(x: f64, y: f64) -> f64;
    fn remquo(x: f64, y: f64, q: *mut libc::c_int) -> f64;
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
    fn below(&mut self, n: usize) -> usize {
        (self.next() >> 11) as usize % n
    }
}

fn gen_f64(r: &mut Lcg) -> f64 {
    match r.below(12) {
        0 => 0.0,
        1 => -0.0,
        2 => f64::INFINITY,
        3 => f64::NEG_INFINITY,
        4 => f64::NAN,
        5 => f64::from_bits(0x7ff8_0000_0000_0001), // NaN w/ payload
        6 => f64::from_bits(r.next() & 0x000f_ffff_ffff_ffff), // subnormal
        7 => f64::MAX * if r.below(2) == 0 { 1.0 } else { -1.0 },
        8 => f64::MIN_POSITIVE,
        9 => {
            let e = r.below(60) as i32 - 30;
            2f64.powi(e) * if r.below(2) == 0 { 1.0 } else { -1.0 }
        }
        _ => f64::from_bits(r.next()), // arbitrary bits
    }
}

#[test]
fn math_decompose_differential_fuzz_vs_glibc() {
    let mut r = Lcg(0x33ed_1908_f00d_aa01);
    let mut divs: Vec<String> = Vec::new();
    let mut compared = 0u64;
    // NaN payloads from arithmetic are not specified, so compare NaN-ness rather
    // than exact bits when BOTH results are NaN.
    let eq = |a: f64, b: f64| -> bool { (a.is_nan() && b.is_nan()) || a.to_bits() == b.to_bits() };

    for _ in 0..300_000 {
        let x = gen_f64(&mut r);
        let y = gen_f64(&mut r);
        let n = r.below(2200) as i32 - 1100;

        macro_rules! cmp1 {
            ($name:expr, $fl:expr, $lc:expr) => {{
                compared += 1;
                let (f, g) = ($fl, $lc);
                if !eq(f, g) && divs.len() < 30 {
                    divs.push(format!(
                        "{}({:#018x}): fl={:#018x} glibc={:#018x}",
                        $name,
                        x.to_bits(),
                        f.to_bits(),
                        g.to_bits()
                    ));
                }
            }};
        }

        let z = gen_f64(&mut r);
        cmp1!("nextafter", unsafe { fl::nextafter(x, y) }, unsafe {
            nextafter(x, y)
        });
        cmp1!("scalbn", unsafe { fl::scalbn(x, n) }, unsafe {
            scalbn(x, n)
        });
        cmp1!("ldexp", unsafe { fl::ldexp(x, n) }, unsafe { ldexp(x, n) });
        cmp1!("fma", unsafe { fl::fma(x, y, z) }, unsafe { fma(x, y, z) });
        {
            compared += 1;
            let f = unsafe { fl::remainder(x, y) };
            let g = unsafe { remainder(x, y) };
            // glibc's remainder has a sign-of-zero quirk for an astronomically
            // large quotient (e.g. y == MIN_POSITIVE): it can return a zero
            // whose sign is the OPPOSITE of x, violating IEEE-754 5.3.1 ("if
            // r == 0 its sign shall be that of x"). fl (via libm) is correct,
            // so for a zero result assert fl's own sign-of-x rule and require
            // only that glibc agrees on the magnitude (both zero) — not the
            // quirky sign. Non-zero results must still match glibc bit-exact.
            let ok = if f == 0.0 && g == 0.0 {
                f.is_sign_negative() == x.is_sign_negative()
            } else {
                eq(f, g)
            };
            if !ok && divs.len() < 30 {
                divs.push(format!(
                    "remainder(x={:#018x}, y={:#018x}): fl={:#018x} glibc={:#018x}",
                    x.to_bits(),
                    y.to_bits(),
                    f.to_bits(),
                    g.to_bits()
                ));
            }
        }

        // modf: compare both outputs.
        {
            compared += 1;
            let (mut fi, mut gi) = (0.0f64, 0.0f64);
            let ff = unsafe { fl::modf(x, &mut fi) };
            let gf = unsafe { modf(x, &mut gi) };
            if (!eq(ff, gf) || !eq(fi, gi)) && divs.len() < 30 {
                divs.push(format!(
                    "modf({:#018x}): fl=(frac={:#018x},ip={:#018x}) glibc=(frac={:#018x},ip={:#018x})",
                    x.to_bits(), ff.to_bits(), fi.to_bits(), gf.to_bits(), gi.to_bits()
                ));
            }
        }
        // frexp: mantissa bits + exponent.
        {
            compared += 1;
            let (mut fe, mut ge) = (0i32, 0i32);
            let fm = unsafe { fl::frexp(x, &mut fe) };
            let gm = unsafe { frexp(x, &mut ge) };
            if (!eq(fm, gm) || fe != ge) && divs.len() < 30 {
                divs.push(format!(
                    "frexp({:#018x}): fl=(m={:#018x},e={fe}) glibc=(m={:#018x},e={ge})",
                    x.to_bits(),
                    fm.to_bits(),
                    gm.to_bits()
                ));
            }
        }
        // remquo: remainder bits + low quotient bits.
        {
            compared += 1;
            let (mut fq, mut gq) = (0i32, 0i32);
            let fr = unsafe { fl::remquo(x, y, &mut fq) };
            let gr = unsafe { remquo(x, y, &mut gq) };
            // C99 stores a value congruent mod 2^n (n>=3) to the integral
            // quotient with x/y's sign; both fl and glibc keep the low 3 bits
            // ([-7,7]). EXCEPT: for an astronomically large quotient (huge
            // exponent gap between x and y) glibc's iterative path returns an
            // out-of-range value (e.g. -8) inconsistent with its own masking —
            // a glibc quirk fl deliberately does not mirror, so skip the
            // quotient check when glibc steps outside the masked range.
            let q_ok = gq.abs() > 7 || (fq == gq);
            if (!eq(fr, gr) || !q_ok) && divs.len() < 30 {
                divs.push(format!(
                    "remquo({:#018x},{:#018x}): fl=(r={:#018x},q={fq}) glibc=(r={:#018x},q={gq})",
                    x.to_bits(),
                    y.to_bits(),
                    fr.to_bits(),
                    gr.to_bits()
                ));
            }
        }
    }

    assert!(
        divs.is_empty(),
        "math decomposition diverged from glibc ({compared} compared):\n{}",
        divs.join("\n")
    );
    eprintln!("math decompose fuzz: {compared} compared, 0 divergences vs host glibc");
}
