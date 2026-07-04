//! In-process A/B: OLD format_g_exp_from_scientific (to_string+strip+format!) vs
//! NEW (single exact-cap alloc). Byte-identity asserted. Ratio cancels contention.
use std::fmt::Write;
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
fn strip_len(m: &str) -> usize {
    if !m.as_bytes().contains(&b'.') {
        return m.len();
    }
    let b = m.as_bytes();
    let mut e = m.len();
    while e > 0 && b[e - 1] == b'0' {
        e -= 1;
    }
    if e > 0 && b[e - 1] == b'.' {
        e -= 1;
    }
    e
}
fn old(m: &str, exp: i32, uppercase: bool, alt_form: bool) -> String {
    let e_char = if uppercase { 'E' } else { 'e' };
    let mut mantissa = m.to_string();
    if !alt_form {
        strip_trailing_zeros(&mut mantissa);
    } else if !mantissa.contains('.') {
        mantissa.push('.');
    }
    let sign = if exp < 0 { '-' } else { '+' };
    let abs_exp = exp.unsigned_abs();
    format!("{mantissa}{e_char}{sign}{abs_exp:02}")
}
fn new(m: &str, exp: i32, uppercase: bool, alt_form: bool) -> String {
    let e_char = if uppercase { 'E' } else { 'e' };
    let sign = if exp < 0 { '-' } else { '+' };
    let abs_exp = exp.unsigned_abs();
    let (mbytes, extra_dot) = if !alt_form {
        (&m[..strip_len(m)], false)
    } else if !m.as_bytes().contains(&b'.') {
        (m, true)
    } else {
        (m, false)
    };
    let mut s = String::with_capacity(mbytes.len() + 7);
    s.push_str(mbytes);
    if extra_dot {
        s.push('.');
    }
    s.push(e_char);
    s.push(sign);
    let _ = write!(s, "{abs_exp:02}");
    s
}
fn main() {
    let cases: &[(&str, i32, bool, bool)] = &[
        ("1.500000", 2, false, false),
        ("1.234568", 3, false, false),
        ("1.000000", -4, false, false),
        ("9.990000", 10, true, false),
        ("3.141590", 100, false, false),
        ("-4.200000", -1, false, false),
        ("1.230000", 5, false, true),
        ("7", -308, false, true),
        ("2.5", 0, true, false),
        ("1.000000", -123, false, false),
    ];
    for &(m, e, u, a) in cases {
        assert_eq!(
            old(m, e, u, a),
            new(m, e, u, a),
            "mismatch {m} {e} {u} {a}: old={} new={}",
            old(m, e, u, a),
            new(m, e, u, a)
        );
    }
    let iters = 2_000_000u64;
    let n = cases.len() as u64;
    let (mut ov, mut nv) = (Vec::new(), Vec::new());
    for r in 0..60 {
        let o = || {
            let t = Instant::now();
            for _ in 0..iters {
                for &(m, e, u, a) in cases {
                    black_box(old(black_box(m), e, u, a));
                }
            }
            t.elapsed().as_nanos() as f64 / (iters * n) as f64
        };
        let nw = || {
            let t = Instant::now();
            for _ in 0..iters {
                for &(m, e, u, a) in cases {
                    black_box(new(black_box(m), e, u, a));
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
        "gexp OLD(to_string+format!)={o:.1}ns NEW(1-alloc)={nn:.1}ns  new/old={:.3} ({:.2}x faster)",
        nn / o,
        o / nn
    );
}
