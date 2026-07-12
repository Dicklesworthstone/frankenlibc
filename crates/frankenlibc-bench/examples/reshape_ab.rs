//! In-process A/B: OLD reshape (parse+format!) vs NEW (direct push). Ratio cancels contention.
use std::hint::black_box;
use std::time::Instant;
fn pctl(s: &[f64], q: f64) -> f64 {
    let mut v = s.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((q * (v.len() - 1) as f64).round() as usize).min(v.len() - 1)]
}
fn old(s: &str) -> String {
    let Some(e_pos) = s.find('e') else {
        return s.to_string();
    };
    let mantissa = &s[..e_pos];
    let exp_part = &s[e_pos + 1..];
    let (sign, digits) = if let Some(r) = exp_part.strip_prefix('-') {
        ('-', r)
    } else if let Some(r) = exp_part.strip_prefix('+') {
        ('+', r)
    } else {
        ('+', exp_part)
    };
    let exp_val: i32 = digits.parse().unwrap_or(0);
    if exp_val.unsigned_abs() < 10 {
        format!("{mantissa}e{sign}0{}", exp_val.unsigned_abs())
    } else {
        format!("{mantissa}e{sign}{}", exp_val.unsigned_abs())
    }
}
fn new(s: &str) -> String {
    let Some(e_pos) = s.find('e') else {
        return s.to_string();
    };
    let mantissa = &s[..e_pos];
    let exp_part = &s[e_pos + 1..];
    let (sign, digits) = if let Some(r) = exp_part.strip_prefix('-') {
        ('-', r)
    } else if let Some(r) = exp_part.strip_prefix('+') {
        ('+', r)
    } else {
        ('+', exp_part)
    };
    let mut out = String::with_capacity(mantissa.len() + 4 + digits.len());
    out.push_str(mantissa);
    out.push('e');
    out.push(sign);
    if digits.len() < 2 {
        out.push('0');
    }
    out.push_str(digits);
    out
}
fn main() {
    let ins = [
        "3.141590e0",
        "2.718280e0",
        "1.234568e3",
        "1.234000e-4",
        "9.990000e10",
        "4.200000e1",
        "1.500000e-100",
        "7.000000e308",
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
        "reshape OLD(parse+format!)={o:.1}ns NEW(direct push)={nn:.1}ns  new/old={:.3} ({:.2}x faster)",
        nn / o,
        o / nn
    );
}
