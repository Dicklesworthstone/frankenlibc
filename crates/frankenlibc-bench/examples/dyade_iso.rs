//! In-process A/B: %.Ne of exact dyadic non-integers via Rust std `{:.Ne}`+reshape
//! vs the deployed render_pct_e dyadic fast path. Byte identity asserted.

use std::fmt::Write;
use std::hint::black_box;
use std::time::Instant;

fn pctl(samples: &[f64], q: f64) -> f64 {
    let mut v = samples.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((q * (v.len() - 1) as f64).round() as usize).min(v.len() - 1)]
}

fn reshape(s: &str) -> String {
    let Some(e) = s.find('e') else {
        return s.to_string();
    };
    let mantissa = &s[..e];
    let exp = &s[e + 1..];
    let (sign, digits) = if let Some(rest) = exp.strip_prefix('-') {
        ('-', rest)
    } else if let Some(rest) = exp.strip_prefix('+') {
        ('+', rest)
    } else {
        ('+', exp)
    };
    let mut out = String::with_capacity(mantissa.len() + digits.len() + 4);
    out.push_str(mantissa);
    out.push('e');
    out.push(sign);
    if digits.len() < 2 {
        out.push('0');
    }
    out.push_str(digits);
    out
}

fn old(value: f64, ndigit: usize) -> String {
    let mut s = String::new();
    let _ = write!(s, "{value:.ndigit$e}");
    reshape(&s)
}

fn new(value: f64, ndigit: usize) -> String {
    frankenlibc_core::stdlib::ecvt::render_pct_e(value, ndigit)
}

fn main() {
    let cases: &[(f64, usize)] = &[
        (0.5, 6),
        (0.25, 6),
        (0.125, 3),
        (0.75, 2),
        (0.03125, 6),
        (1.0625, 4),
        (3.125, 6),
        (10.75, 3),
        (63.5, 3),
        (100.5, 3),
        (255.25, 4),
        (-8.5, 2),
    ];
    for &(value, ndigit) in cases {
        assert_eq!(
            old(value, ndigit),
            new(value, ndigit),
            "mismatch {value} .{ndigit}: old={} new={}",
            old(value, ndigit),
            new(value, ndigit)
        );
    }

    let iters = 120_000u64;
    let n = cases.len() as u64;
    let (mut old_samples, mut new_samples) = (Vec::new(), Vec::new());
    for round in 0..20 {
        let old_run = || {
            let start = Instant::now();
            for _ in 0..iters {
                for &(value, ndigit) in cases {
                    black_box(old(black_box(value), ndigit));
                }
            }
            start.elapsed().as_nanos() as f64 / (iters * n) as f64
        };
        let new_run = || {
            let start = Instant::now();
            for _ in 0..iters {
                for &(value, ndigit) in cases {
                    black_box(new(black_box(value), ndigit));
                }
            }
            start.elapsed().as_nanos() as f64 / (iters * n) as f64
        };
        if round % 2 == 0 {
            old_samples.push(old_run());
            new_samples.push(new_run());
        } else {
            new_samples.push(new_run());
            old_samples.push(old_run());
        }
    }
    let old_p10 = pctl(&old_samples, 0.1);
    let new_p10 = pctl(&new_samples, 0.1);
    println!(
        "dyade OLD(std .Ne+reshape)={old_p10:.1}ns NEW(render_pct_e dyadic)={new_p10:.1}ns  new/old={:.3} ({:.2}x faster)",
        new_p10 / old_p10,
        old_p10 / new_p10
    );
}
