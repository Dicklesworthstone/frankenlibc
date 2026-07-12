//! In-process A/B: %.Ne of an EXACT-INTEGER double via Rust std `{:.Ne}`+reshape (flt2dec,
//! what render_pct_e does today) vs a direct integer-digits build. Guarded to the no-rounding
//! case (digits-1 <= precision). Byte-identity asserted; ratio cancels contention.
use std::fmt::Write;
use std::hint::black_box;
use std::time::Instant;
fn pctl(s: &[f64], q: f64) -> f64 {
    let mut v = s.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((q * (v.len() - 1) as f64).round() as usize).min(v.len() - 1)]
}
// reshape mirror of rust_e_to_glibc_e_no_strip (signed, >=2-digit exponent)
fn reshape(s: &str) -> String {
    let Some(e) = s.find('e') else {
        return s.to_string();
    };
    let m = &s[..e];
    let ep = &s[e + 1..];
    let (sign, digits) = if let Some(r) = ep.strip_prefix('-') {
        ('-', r)
    } else if let Some(r) = ep.strip_prefix('+') {
        ('+', r)
    } else {
        ('+', ep)
    };
    let mut o = String::with_capacity(m.len() + 4 + digits.len());
    o.push_str(m);
    o.push('e');
    o.push(sign);
    if digits.len() < 2 {
        o.push('0');
    }
    o.push_str(digits);
    o
}
fn old(v: f64, nd: usize) -> String {
    let mut s = String::new();
    let _ = write!(s, "{v:.nd$e}");
    reshape(&s)
}
// NEW: exact-integer, no-rounding (L-1 <= nd). glibc-form directly.
fn new(v: f64, nd: usize) -> Option<String> {
    if !(v.fract() == 0.0 && v.abs() < 1.8446744073709552e19) {
        return None;
    }
    let mag = v.abs() as u64;
    let s = mag.to_string();
    let b = s.as_bytes();
    let l = b.len();
    if l - 1 > nd {
        return None;
    } // would need rounding
    let exp = (l as i32) - 1; // mag=0 -> "0", l=1, exp=0
    let mut out = String::with_capacity(l + nd + 6);
    if v.is_sign_negative() {
        out.push('-');
    }
    out.push(b[0] as char);
    if nd > 0 {
        out.push('.');
        for &c in &b[1..] {
            out.push(c as char);
        }
        for _ in 0..(nd - (l - 1)) {
            out.push('0');
        }
    }
    out.push('e');
    out.push(if exp < 0 { '-' } else { '+' });
    let ae = exp.unsigned_abs();
    if ae < 10 {
        out.push('0');
    }
    let _ = write!(out, "{ae}");
    Some(out)
}
fn main() {
    let cases: &[(f64, usize)] = &[
        (42.0, 6),
        (100.0, 6),
        (0.0, 6),
        (7.0, 0),
        (1200.0, 6),
        (255.0, 6),
        (1234567.0, 6),
        (9.0, 1),
        (1000000000000000.0, 15),
        (3.0, 6),
        (-8.0, 6),
        (2.0, 0),
        (50.0, 6),
        (1000000.0, 6),
    ];
    for &(v, nd) in cases {
        if let Some(n) = new(v, nd) {
            assert_eq!(
                old(v, nd),
                n,
                "mismatch {v} .{nd}: old={} new={}",
                old(v, nd),
                n
            );
        }
    }
    let iters = 1_500_000u64;
    let n = cases.len() as u64;
    let (mut ov, mut nv) = (Vec::new(), Vec::new());
    for r in 0..60 {
        let o = || {
            let t = Instant::now();
            for _ in 0..iters {
                for &(v, nd) in cases {
                    black_box(old(black_box(v), nd));
                }
            }
            t.elapsed().as_nanos() as f64 / (iters * n) as f64
        };
        let nw = || {
            let t = Instant::now();
            for _ in 0..iters {
                for &(v, nd) in cases {
                    black_box(new(black_box(v), nd));
                }
            }
            t.elapsed().as_nanos() as f64 / (iters * n) as f64
        };
        if r % 2 == 0 {
            ov.push(o());
            nv.push(nw());
        } else {
            nv.push(nw());
            ov.push(o());
        }
    }
    let (o, nn) = (pctl(&ov, 0.1), pctl(&nv, 0.1));
    println!(
        "inte OLD(std .Ne+reshape)={o:.1}ns NEW(int-build)={nn:.1}ns  new/old={:.3} ({:.2}x faster)",
        nn / o,
        o / nn
    );
}
