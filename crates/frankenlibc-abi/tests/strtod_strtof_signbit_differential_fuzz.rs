#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc strtod/strtof oracle

//! Randomized differential fuzzer for byte `strtod` / `strtof` that is
//! SIGNBIT-AWARE for NaN.
//!
//! The existing `strtod_strtof_live_differential_probe` compares
//! `a.is_nan == b.is_nan` — it deliberately ignores the SIGN of a parsed NaN,
//! so `strtod("-nan")` keeping its sign bit (and, more riskily, `strtof("-nan")`
//! preserving it through the f64->f32 narrowing `wide as f32`, which Rust does
//! NOT guarantee for NaN) was never actually verified. This drives ±inf,
//! ±infinity, ±nan, nan(payload), hex, and decimal forms and compares a
//! fingerprint that captures the value CLASS and the SIGN BIT (NaN mantissa
//! payloads are an impl detail and not compared) plus the consumed length.

use std::ffi::{CString, c_char};

use frankenlibc_core::stdlib::conversion::{strtod_impl, strtof_impl};

unsafe extern "C" {
    fn strtod(nptr: *const c_char, endptr: *mut *mut c_char) -> f64;
    fn strtof(nptr: *const c_char, endptr: *mut *mut c_char) -> f32;
    fn setlocale(category: i32, locale: *const c_char) -> *const c_char;
}
const LC_ALL: i32 = 6;

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

/// Class + signbit fingerprint (NaN payload bits ignored, finite bits exact).
#[derive(PartialEq, Eq, Debug)]
enum Fp {
    Nan { neg: bool },
    Inf { neg: bool },
    Finite(u64),
}
fn fp64(v: f64) -> Fp {
    if v.is_nan() {
        Fp::Nan { neg: v.is_sign_negative() }
    } else if v.is_infinite() {
        Fp::Inf { neg: v.is_sign_negative() }
    } else {
        Fp::Finite(v.to_bits())
    }
}
fn fp32(v: f32) -> Fp {
    if v.is_nan() {
        Fp::Nan { neg: v.is_sign_negative() }
    } else if v.is_infinite() {
        Fp::Inf { neg: v.is_sign_negative() }
    } else {
        Fp::Finite(v.to_bits() as u64)
    }
}

fn recase(r: &mut Lcg, s: &str) -> String {
    s.chars()
        .map(|c| if r.next() & 1 == 0 { c.to_ascii_uppercase() } else { c })
        .collect()
}

fn gen_input(r: &mut Lcg) -> String {
    let mut s = String::new();
    match r.below(4) {
        0 => s.push('-'),
        1 => s.push('+'),
        _ => {}
    }
    match r.below(8) {
        0 => s.push_str(&recase(r, "inf")),
        1 => s.push_str(&recase(r, "infinity")),
        2 => s.push_str(&recase(r, "nan")),
        3 => {
            s.push_str(&recase(r, "nan"));
            s.push('(');
            let n = r.below(6);
            for _ in 0..n {
                let c = match r.below(3) {
                    0 => (b'0' + r.below(10) as u8) as char,
                    1 => (b'a' + r.below(26) as u8) as char,
                    _ => '_',
                };
                s.push(c);
            }
            if r.below(5) != 0 {
                s.push(')');
            }
        }
        4 | 5 => {
            // decimal
            for _ in 0..r.below(6) {
                s.push((b'0' + r.below(10) as u8) as char);
            }
            if r.below(2) == 0 {
                s.push('.');
                for _ in 0..r.below(6) {
                    s.push((b'0' + r.below(10) as u8) as char);
                }
            }
            if r.below(2) == 0 {
                s.push('e');
                if r.below(2) == 0 {
                    s.push(if r.below(2) == 0 { '+' } else { '-' });
                }
                s.push_str(&r.below(40).to_string());
            }
        }
        _ => {
            // hex float
            s.push_str("0x");
            for _ in 0..(1 + r.below(14)) {
                s.push(b"0123456789abcdefABCDEF"[r.below(22)] as char);
            }
            if r.below(2) == 0 {
                s.push('.');
                for _ in 0..r.below(14) {
                    s.push(b"0123456789abcdef"[r.below(16)] as char);
                }
            }
            s.push('p');
            if r.below(2) == 0 {
                s.push('-');
            }
            s.push_str(&r.below(80).to_string());
        }
    }
    s
}

fn host_d(s: &CString) -> (Fp, isize) {
    let mut end: *mut c_char = std::ptr::null_mut();
    let v = unsafe { strtod(s.as_ptr(), &mut end) };
    let off = (end as isize) - (s.as_ptr() as isize);
    (fp64(v), off)
}
fn host_f(s: &CString) -> (Fp, isize) {
    let mut end: *mut c_char = std::ptr::null_mut();
    let v = unsafe { strtof(s.as_ptr(), &mut end) };
    let off = (end as isize) - (s.as_ptr() as isize);
    (fp32(v), off)
}

#[test]
fn strtod_strtof_signbit_differential_fuzz_vs_glibc() {
    let c = CString::new("C").unwrap();
    unsafe { setlocale(LC_ALL, c.as_ptr()) };

    let mut r = Lcg(0xa11c_e5fa_ce71_2003);
    let mut divs: Vec<String> = Vec::new();
    let mut compared = 0u64;

    for _ in 0..200_000 {
        let input = gen_input(&mut r);
        let Ok(cs) = CString::new(input.as_str()) else {
            continue;
        };
        // bytes-with-NUL slice for fl core impls.
        let mut bytes = input.clone().into_bytes();
        bytes.push(0);

        // strtod
        let (fl_v, fl_c, _) = strtod_impl(&bytes);
        let fl_d = (fp64(fl_v), fl_c as isize);
        let host_dd = host_d(&cs);
        compared += 1;
        if fl_d != host_dd && divs.len() < 40 {
            divs.push(format!(
                "strtod input={input:?}\n    fl   ={fl_d:?}\n    glibc={host_dd:?}"
            ));
        }

        // strtof
        let (flf_v, flf_c, _) = strtof_impl(&bytes);
        let fl_f = (fp32(flf_v), flf_c as isize);
        let host_ff = host_f(&cs);
        if fl_f != host_ff && divs.len() < 40 {
            divs.push(format!(
                "strtof input={input:?}\n    fl   ={fl_f:?}\n    glibc={host_ff:?}"
            ));
        }
    }

    assert!(
        divs.is_empty(),
        "strtod/strtof signbit-aware diverged from host glibc on some of {compared} cases (up to 40):\n{}",
        divs.join("\n")
    );
    eprintln!("strtod/strtof signbit fuzz: {compared} comparisons, 0 divergences vs host glibc");
}
