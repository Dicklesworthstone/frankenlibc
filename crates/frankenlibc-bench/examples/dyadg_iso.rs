//! In-process A/B: %.Pg of exact dyadic non-integers through the old Rust
//! scientific probe plus %g reshaping vs the deployed render_pct_g fast path.
//! Cases avoid the existing integer and half-only fixed fast paths.

use std::fmt::Write;
use std::hint::black_box;
use std::time::Instant;

fn pctl(samples: &[f64], q: f64) -> f64 {
    let mut v = samples.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((q * (v.len() - 1) as f64).round() as usize).min(v.len() - 1)]
}

fn strip_trailing_zeros(s: &str) -> &str {
    if !s.contains('.') {
        return s;
    }
    s.trim_end_matches('0').trim_end_matches('.')
}

fn split_scientific(raw: &str) -> (&str, i32) {
    let e_pos = raw.find('e').expect("scientific format has exponent");
    let exp = raw[e_pos + 1..].parse::<i32>().expect("valid exponent");
    (&raw[..e_pos], exp)
}

fn rust_e_to_glibc_e(s: &str) -> String {
    let Some(e_pos) = s.find('e') else {
        return strip_trailing_zeros(s).to_string();
    };
    let mantissa = strip_trailing_zeros(&s[..e_pos]);
    let exp_part = &s[e_pos + 1..];
    let (sign, digits) = if let Some(rest) = exp_part.strip_prefix('-') {
        ('-', rest)
    } else if let Some(rest) = exp_part.strip_prefix('+') {
        ('+', rest)
    } else {
        ('+', exp_part)
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

fn fixed_from_sci(sci: &str, exp: i32) -> String {
    let (neg, rest) = match sci.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, sci),
    };
    let mant = rest.split_once('e').map_or(rest, |(mant, _)| mant);
    let mut digits = String::with_capacity(mant.len());
    for c in mant.chars() {
        if c != '.' {
            digits.push(c);
        }
    }
    let n = digits.len() as i32;
    let mut out = String::with_capacity(digits.len() + 8);
    if neg {
        out.push('-');
    }
    if exp >= 0 {
        let int_len = ((exp + 1).min(n)) as usize;
        out.push_str(&digits[..int_len]);
        if (int_len as i32) < n {
            out.push('.');
            out.push_str(&digits[int_len..]);
        }
    } else {
        out.push_str("0.");
        for _ in 0..(-exp - 1) {
            out.push('0');
        }
        out.push_str(&digits);
    }
    let keep = strip_trailing_zeros(&out).len();
    out.truncate(keep);
    out
}

fn old(value: f64, ndigit: usize) -> String {
    let ndigit = ndigit.max(1);
    let frac = ndigit - 1;
    let mut sci = String::new();
    let _ = write!(sci, "{value:.frac$e}");
    let (_, exp) = split_scientific(&sci);
    if exp < -4 || exp >= ndigit as i32 {
        rust_e_to_glibc_e(&sci)
    } else {
        fixed_from_sci(&sci, exp)
    }
}

fn new(value: f64, ndigit: usize) -> String {
    frankenlibc_core::stdlib::ecvt::render_pct_g(value, ndigit)
}

fn main() {
    let cases: &[(f64, usize)] = &[
        (3.125, 6),
        (10.75, 4),
        (0.03125, 6),
        (0.00003125, 6),
        (-8.25, 4),
        (255.25, 6),
        (1.0625, 6),
        (63.75, 5),
        (0.0078125, 6),
        (100.125, 6),
    ];
    for &(value, ndigit) in cases {
        assert_eq!(
            old(value, ndigit),
            new(value, ndigit),
            "mismatch {value} .{ndigit}g: old={} new={}",
            old(value, ndigit),
            new(value, ndigit)
        );
    }

    let iters = 180_000u64;
    let n = cases.len() as u64;
    let (mut old_samples, mut new_samples) = (Vec::new(), Vec::new());
    for round in 0..24 {
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
        "dyadg OLD(std .Pg+reshape)={old_p10:.1}ns NEW(render_pct_g dyadic)={new_p10:.1}ns  new/old={:.3} ({:.2}x faster)",
        new_p10 / old_p10,
        old_p10 / new_p10
    );
}
