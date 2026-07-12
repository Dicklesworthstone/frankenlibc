//! In-process A/B for the %g sci-render fast path: OLD Rust `{:.frac$e}` (flt2dec) vs
//! NEW integer builder (must be byte-identical). Asserts equality, measures ratio.
use std::fmt::Write;
use std::hint::black_box;
use std::time::Instant;
fn pctl(s: &[f64], q: f64) -> f64 {
    let mut v = s.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((q * (v.len() - 1) as f64).round() as usize).min(v.len() - 1)]
}
fn old(v: f64, frac: usize) -> String {
    let mut s = String::new();
    let _ = write!(s, "{v:.frac$e}");
    s
}
fn new(v: f64, frac: usize) -> Option<String> {
    if !(v.fract() == 0.0 && v.abs() < 1.8446744073709552e19) {
        return None;
    }
    let mag = v.abs() as u64;
    let mut tmp = [0u8; 20];
    let mut n = mag;
    let mut i = tmp.len();
    loop {
        i -= 1;
        tmp[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    let digits = &tmp[i..];
    let dc = digits.len();
    if dc - 1 > frac {
        return None;
    }
    let exp = dc as i32 - 1;
    let mut out = String::new();
    if v.is_sign_negative() {
        out.push('-');
    }
    out.push(digits[0] as char);
    if frac > 0 {
        out.push('.');
        for &c in &digits[1..] {
            out.push(c as char);
        }
        for _ in 0..frac - (dc - 1) {
            out.push('0');
        }
    }
    out.push('e');
    let _ = write!(out, "{exp}");
    Some(out)
}
fn main() {
    // (value, frac=ndigit-1) spanning fixed & scientific %g integer ranges
    let cases: &[(f64, usize)] = &[
        (42.0, 5),
        (100.0, 5),
        (0.0, 5),
        (7.0, 0),
        (1000000.0, 5),
        (1200000.0, 5),
        (255.0, 5),
        (9.0, 0),
        (1000000000000000.0, 5),
        (3.0, 5),
        (-8.0, 5),
        (50.0, 5),
        (12345.0, 5),
        (1e18, 5),
        (-1000000.0, 5),
    ];
    for &(v, f) in cases {
        if let Some(n) = new(v, f) {
            assert_eq!(
                old(v, f),
                n,
                "MISMATCH {v} frac{f}: old={} new={}",
                old(v, f),
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
                for &(v, f) in cases {
                    black_box(old(black_box(v), f));
                }
            }
            t.elapsed().as_nanos() as f64 / (iters * n) as f64
        };
        let nw = || {
            let t = Instant::now();
            for _ in 0..iters {
                for &(v, f) in cases {
                    black_box(new(black_box(v), f));
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
        "gsci OLD(std .Fe)={o:.1}ns NEW(int-build)={nn:.1}ns  new/old={:.3} ({:.2}x faster)",
        nn / o,
        o / nn
    );
}
