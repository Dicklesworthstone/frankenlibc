//! In-process A/B: %.Pf of a DYADIC double (value*2^P integral, exact at precision P) via
//! Rust std {:.P} (flt2dec) vs a direct u128 (value*10^P) build. Byte-identity asserted.
use std::fmt::Write;
use std::hint::black_box;
use std::time::Instant;
fn pctl(s: &[f64], q: f64) -> f64 {
    let mut v = s.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((q * (v.len() - 1) as f64).round() as usize).min(v.len() - 1)]
}
fn old(x: f64, p: usize) -> String {
    let mut s = String::new();
    let _ = write!(s, "{x:.p$}");
    s
}
// NEW: x has <= p fractional bits (x*2^p integral) and |x*2^p| < 2^64, p<=19.
fn new(x: f64, p: usize) -> Option<String> {
    if p > 19 {
        return None;
    }
    let scaled = x.abs() * (2f64.powi(p as i32));
    if scaled.fract() != 0.0 || scaled >= 1.8446744073709552e19 {
        return None;
    }
    let m = scaled as u128;
    let pow5: u128 = 5u128.pow(p as u32);
    let digits = m.checked_mul(pow5)?; // value*10^p as an integer
    // format: digits with a decimal point p places from the right (pad left to >= p+1)
    let mut ds = digits.to_string();
    if ds.len() < p + 1 {
        let pad = p + 1 - ds.len();
        ds = "0".repeat(pad) + &ds;
    }
    let point = ds.len() - p;
    let mut out = String::with_capacity(ds.len() + 2);
    if x.is_sign_negative() {
        out.push('-');
    }
    out.push_str(&ds[..point]);
    if p > 0 {
        out.push('.');
        out.push_str(&ds[point..]);
    }
    Some(out)
}
fn main() {
    // dyadic non-integers + integers + <1 values
    let cases: &[(f64, usize)] = &[
        (2.5, 6),
        (0.5, 6),
        (0.25, 6),
        (10.75, 2),
        (3.125, 6),
        (100.5, 2),
        (0.125, 3),
        (-8.5, 2),
        (42.0, 6),
        (0.0, 6),
        (1234.5, 4),
        (0.75, 2),
        (255.25, 2),
        (0.5, 1),
        (63.5, 6),
        (-0.25, 4),
    ];
    for &(x, p) in cases {
        if let Some(n) = new(x, p) {
            assert_eq!(
                old(x, p),
                n,
                "MISMATCH {x} .{p}: old={} new={}",
                old(x, p),
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
                for &(x, p) in cases {
                    black_box(old(black_box(x), p));
                }
            }
            t.elapsed().as_nanos() as f64 / (iters * n) as f64
        };
        let nw = || {
            let t = Instant::now();
            for _ in 0..iters {
                for &(x, p) in cases {
                    black_box(new(black_box(x), p));
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
        "dyadf OLD(std .Pf)={o:.1}ns NEW(u128-build)={nn:.1}ns  new/old={:.3} ({:.2}x faster)",
        nn / o,
        o / nn
    );
}
