//! In-process A/B: OLD %g mantissa trailing-zero strip (to_string+strip+format!) vs
//! NEW (single in-place drain). Ratio cancels contention. Byte-identity asserted.
use std::hint::black_box;
use std::time::Instant;
fn pctl(s: &[f64], q: f64) -> f64 {
    let mut v = s.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((q * (v.len() - 1) as f64).round() as usize).min(v.len() - 1)]
}
fn strip_trailing_zeros(s: &mut String) {
    if s.contains('.') {
        while s.ends_with('0') {
            s.pop();
        }
        if s.ends_with('.') {
            s.pop();
        }
    }
}
// OLD: exactly the code at printf.rs:1862-1867 (alt_form==false branch)
fn old(s0: &str) -> String {
    let mut s = s0.to_string();
    if let Some(e_pos) = s.bytes().position(|b| b == b'e' || b == b'E') {
        let mut mantissa = s[..e_pos].to_string();
        strip_trailing_zeros(&mut mantissa);
        let exp_part = &s[e_pos..];
        s = format!("{mantissa}{exp_part}");
    }
    s
}
// NEW: single in-place drain, no intermediate allocations
fn new(s0: &str) -> String {
    let mut s = s0.to_string();
    if let Some(e_pos) = s.bytes().position(|b| b == b'e' || b == b'E') {
        let b = s.as_bytes();
        if b[..e_pos].contains(&b'.') {
            let mut end = e_pos;
            while end > 0 && b[end - 1] == b'0' {
                end -= 1;
            }
            if end > 0 && b[end - 1] == b'.' {
                end -= 1;
            }
            if end < e_pos {
                s.drain(end..e_pos);
            }
        }
    }
    s
}
fn main() {
    // representative %e outputs feeding the %g strip: trailing zeros, none, dot-only, uppercase E, negative
    let ins = [
        "1.500000e+02",
        "1.234568e+03",
        "1.000000e-04",
        "9.990000e+10",
        "3.141590E+00",
        "-4.200000e+01",
        "1.000000e+100",
        "7.000000e-308",
        "1.230000e+05",
        "5.000000e+00",
    ];
    for s in &ins {
        assert_eq!(
            old(s),
            new(s),
            "mismatch {s}: old={} new={}",
            old(s),
            new(s)
        );
    }
    let iters = 2_000_000u64;
    let n = ins.len() as u64;
    let (mut ov, mut nv) = (Vec::new(), Vec::new());
    for r in 0..60 {
        let o = || {
            let t = Instant::now();
            for _ in 0..iters {
                for s in &ins {
                    black_box(old(black_box(s)));
                }
            }
            t.elapsed().as_nanos() as f64 / (iters * n) as f64
        };
        let nw = || {
            let t = Instant::now();
            for _ in 0..iters {
                for s in &ins {
                    black_box(new(black_box(s)));
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
        "gstrip OLD(to_string+format!)={o:.1}ns NEW(drain)={nn:.1}ns  new/old={:.3} ({:.2}x faster)",
        nn / o,
        o / nn
    );
}
