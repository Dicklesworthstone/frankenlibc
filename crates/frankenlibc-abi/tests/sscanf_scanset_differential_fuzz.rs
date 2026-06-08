#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // host-glibc sscanf oracle (libc)

//! Randomized live differential fuzzer for sscanf `%[...]` scanset parsing vs
//! host glibc. The existing `sscanf_differential_fuzz` exercises a *fixed* set
//! of formats (a handful of scansets) with random inputs; this randomizes the
//! scanset format itself to reach the parser edge cases C11 7.21.6.2 mandates:
//!   - `]` as the first set member (literal, not the terminator),
//!   - a leading or trailing `-` (literal dash, not a range),
//!   - ranges `X-Y` (including reversed `Y-X`), and the `]`-then-`-` ambiguity,
//!   - negation `^`,
//!   - a field width on the scanset (`%30[...]`).
//!
//! Each case runs `<scanset>%n` on a random input and compares the return value,
//! the matched string (only on a match), and the `%n` count against glibc.

use std::ffi::{CStr, CString, c_char, c_int};

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
}

/// Build a random `%[width][^][body]` scanset format with a trailing `%n`.
/// Literal members never include `]` or `%` (which would break the spec); `]`
/// only ever appears as the first set member, and `-` only at the start/end
/// (literal) or as `X-Y` (range) — exactly the positions whose meaning the
/// parser must special-case.
fn gen_scanset(r: &mut Lcg) -> String {
    const LIT: &[u8] = b"abcdeXYZ0129.+_@#:/^ ";
    const ENDP: &[u8] = b"azAZ09 .";
    let mut body = String::new();
    if r.next() & 1 == 0 {
        body.push('^');
    }
    if r.next() & 3 == 0 {
        body.push(']');
    }
    if r.next() & 3 == 0 {
        body.push('-');
    }
    let n = 1 + (r.next() % 5);
    for _ in 0..n {
        match r.next() % 5 {
            2 => {
                let lo = ENDP[(r.next() as usize) % ENDP.len()] as char;
                let hi = ENDP[(r.next() as usize) % ENDP.len()] as char;
                body.push(lo);
                body.push('-');
                body.push(hi);
            }
            _ => body.push(LIT[(r.next() as usize) % LIT.len()] as char),
        }
    }
    if r.next() & 3 == 0 {
        body.push('-');
    }
    let width = if r.next() & 3 == 0 {
        (1 + r.next() % 30).to_string()
    } else {
        String::new()
    };
    format!("%{width}[{body}]%n")
}

/// True if the `%[...]` directive is properly terminated. An unterminated
/// scanset (`%[^]` / `%[]` where the closing `]` is absorbed as the literal
/// first member) is a malformed format — glibc rejects it, fl accepts it; that
/// UB corner is out of scope here, so such cases are skipped.
fn scanset_terminated(fmt: &str) -> bool {
    let b = fmt.as_bytes();
    let Some(mut i) = b.iter().position(|&c| c == b'[') else {
        return true;
    };
    i += 1;
    if i < b.len() && b[i] == b'^' {
        i += 1;
    }
    if i < b.len() && b[i] == b']' {
        i += 1; // literal `]` as first member
    }
    b[i.min(b.len())..].contains(&b']')
}

fn gen_input(r: &mut Lcg) -> String {
    const ALPHA: &[u8] = b"abcXYZ012.+-_@#: /qQ]^";
    let len = (r.next() % 25) as usize;
    (0..len)
        .map(|_| ALPHA[(r.next() as usize) % ALPHA.len()] as char)
        .collect()
}

#[derive(PartialEq, Eq, Debug)]
struct Out {
    ret: c_int,
    val: Option<String>,
    n: Option<c_int>,
}

fn run(is_fl: bool, input: &CStr, fmt: &CStr) -> Out {
    let mut buf = [0xFFu8; 128];
    let mut n: c_int = -98765;
    let bp = buf.as_mut_ptr() as *mut c_char;
    let np = &mut n as *mut c_int;
    let ret = unsafe {
        if is_fl {
            fl_sscanf(input.as_ptr(), fmt.as_ptr(), bp, np)
        } else {
            sscanf(input.as_ptr(), fmt.as_ptr(), bp, np)
        }
    };
    // The string + %n are only defined when the scanset assigned (ret == 1).
    let (val, nn) = if ret == 1 {
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        (
            Some(String::from_utf8_lossy(&buf[..end]).into_owned()),
            Some(n),
        )
    } else {
        (None, None)
    };
    Out { ret, val, n: nn }
}

#[test]
fn sscanf_scanset_differential_fuzz_vs_glibc() {
    let mut r = Lcg(0x5ca5_e700_d1ff_0001);
    let mut divs: Vec<String> = Vec::new();
    let mut compared: u64 = 0;

    for _ in 0..200_000 {
        let fmt = gen_scanset(&mut r);
        if !scanset_terminated(&fmt) {
            continue;
        }
        let input = gen_input(&mut r);
        let (Ok(cfmt), Ok(cinput)) = (CString::new(fmt.as_str()), CString::new(input.as_str()))
        else {
            continue;
        };
        let fl = run(true, &cinput, &cfmt);
        let host = run(false, &cinput, &cfmt);
        compared += 1;
        if fl != host && divs.len() < 40 {
            divs.push(format!(
                "fmt={fmt:?} input={input:?}\n    fl   ={fl:?}\n    glibc={host:?}"
            ));
        }
    }

    assert!(
        divs.is_empty(),
        "sscanf scanset parsing diverged from host glibc on {} cases (showing up to 40):\n{}",
        divs.len(),
        divs.join("\n")
    );
    eprintln!("sscanf scanset fuzz: {compared} comparisons, 0 divergences vs host glibc");
}
