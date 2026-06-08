#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // host-glibc sscanf oracle (libc, linked by std)

//! Randomized live differential fuzzer for `sscanf("%lf")` parsing of the
//! FLOAT SPECIAL tokens `inf` / `infinity` / `nan` / `nan(n-char-sequence)`.
//!
//! The general `sscanf_differential_fuzz` uses a numeric alphabet that never
//! forms the words "inf"/"nan", so the scan engine's dedicated special-token
//! path (independent of `strtod_impl`) was unexercised. This drives it with
//! sign + case + payload variants and compares against live glibc:
//!   - the return value (matched / not),
//!   - the value CLASS (nan vs ±inf vs finite) and SIGN BIT (so `-nan` keeping
//!     its sign is checked — bit-pattern signbit, invisible to `== `),
//!   - the `%n` consumed-character count (so `nan(123)` payload consumption is
//!     checked).
//! NaN mantissa payloads are NOT bit-compared (glibc's payload encoding is an
//! impl detail); class + signbit + consumed length are the parity contract.

use std::ffi::{CString, c_char, c_int};

use frankenlibc_abi::stdio_abi::sscanf as fl_sscanf;

unsafe extern "C" {
    fn sscanf(s: *const c_char, fmt: *const c_char, ...) -> c_int;
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

/// Canonical fingerprint of a parsed double that ignores NaN payload bits but
/// keeps the class and the sign bit.
#[derive(PartialEq, Eq, Debug)]
enum Fp {
    Nan { neg: bool },
    Inf { neg: bool },
    Finite(u64),
}

fn fp(v: f64) -> Fp {
    if v.is_nan() {
        Fp::Nan { neg: v.is_sign_negative() }
    } else if v.is_infinite() {
        Fp::Inf { neg: v.is_sign_negative() }
    } else {
        Fp::Finite(v.to_bits())
    }
}

#[derive(PartialEq, Eq, Debug)]
struct Out {
    ret: c_int,
    val: Option<Fp>,
    n: Option<c_int>,
}

fn run(
    is_fl: bool,
    s: &CString,
    fmt: &CString,
) -> Out {
    let mut v: f64 = 0.0;
    let mut n: c_int = -12345;
    let ret = unsafe {
        if is_fl {
            fl_sscanf(s.as_ptr(), fmt.as_ptr(), &mut v as *mut f64, &mut n as *mut c_int)
        } else {
            sscanf(s.as_ptr(), fmt.as_ptr(), &mut v as *mut f64, &mut n as *mut c_int)
        }
    };
    Out {
        ret,
        val: (ret == 1).then(|| fp(v)),
        n: (ret == 1).then_some(n),
    }
}

fn recase(r: &mut Lcg, s: &str) -> String {
    s.chars()
        .map(|c| {
            if r.next() & 1 == 0 {
                c.to_ascii_uppercase()
            } else {
                c.to_ascii_lowercase()
            }
        })
        .collect()
}

/// Build a special-token input string.
fn gen_input(r: &mut Lcg) -> String {
    let mut s = String::new();
    match r.below(4) {
        0 => s.push('-'),
        1 => s.push('+'),
        _ => {}
    }
    match r.below(4) {
        0 => s.push_str(&recase(r, "inf")),
        1 => s.push_str(&recase(r, "infinity")),
        2 => s.push_str(&recase(r, "nan")),
        _ => {
            // nan with an n-char-sequence payload: [0-9a-zA-Z_]
            s.push_str(&recase(r, "nan"));
            s.push('(');
            let n = r.below(6);
            for _ in 0..n {
                let pick = r.below(4);
                let c = match pick {
                    0 => (b'0' + r.below(10) as u8) as char,
                    1 => (b'a' + r.below(26) as u8) as char,
                    2 => (b'A' + r.below(26) as u8) as char,
                    _ => '_',
                };
                s.push(c);
            }
            // Usually close the paren; sometimes leave it open (malformed).
            if r.below(5) != 0 {
                s.push(')');
            }
        }
    }
    // Occasionally append trailing garbage to probe the consumed-length cutoff.
    if r.below(3) == 0 {
        let tail = [b'x', b'1', b'.', b'z', b' '];
        let n = r.below(3);
        for _ in 0..n {
            s.push(tail[r.below(tail.len())] as char);
        }
    }
    s
}

#[test]
fn scanf_float_special_differential_fuzz_vs_glibc() {
    let fmt = CString::new("%lf%n").unwrap();
    let mut r = Lcg(0x1ee7_f10a_7c0d_5e11);
    let mut divs: Vec<String> = Vec::new();
    let mut compared: u64 = 0;

    for _ in 0..200_000 {
        let input = gen_input(&mut r);
        let Ok(cs) = CString::new(input.as_str()) else {
            continue;
        };
        let fl = run(true, &cs, &fmt);
        let host = run(false, &cs, &fmt);
        compared += 1;
        if fl != host && divs.len() < 40 {
            divs.push(format!(
                "input={input:?}\n    fl   ={fl:?}\n    glibc={host:?}"
            ));
        }
    }

    assert!(
        divs.is_empty(),
        "sscanf %lf special-token parsing diverged from host glibc on {} cases (showing up to 40):\n{}",
        divs.len(),
        divs.join("\n")
    );
    eprintln!("scanf float-special fuzz: {compared} comparisons, 0 divergences vs host glibc");
}
