#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // host-glibc sscanf oracle (libc)

//! Randomized live differential fuzzer for sscanf assignment suppression
//! (`%*[width][conv]`) vs host glibc. A suppressed conversion still consumes
//! input but stores nothing and does NOT count toward the return value, so the
//! only output argument is the trailing `%n`. This sweeps random suppressed
//! directives (all conversion classes, with/without a field width) over random
//! inputs and compares the return value and the `%n` consumed count — exercising
//! the suppression flag, the return-counting (0 assigned), and the EOF-vs-0
//! distinction.

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

fn gen_fmt(r: &mut Lcg) -> String {
    let mut s = String::from("%*");
    if r.next() & 1 == 0 {
        s.push_str(&(1 + r.next() % 6).to_string());
    }
    match r.next() % 16 {
        0..=9 => s.push(b"diouxXfeEgGs"[(r.next() % 12) as usize] as char),
        10 => s.push('c'),
        11 => s.push_str("[a-z0-9]"),
        12 => s.push_str("[^ \t]"),
        13 => s.push_str("[A-F0-9.]"),
        _ => s.push(b"dxfsc"[(r.next() % 5) as usize] as char),
    }
    s.push_str("%n");
    s
}

fn gen_input(r: &mut Lcg) -> Vec<u8> {
    const ALPHA: &[u8] = b"ab12XY.+-eE0x \t\n";
    let len = (r.next() % 14) as usize;
    (0..len)
        .map(|_| ALPHA[(r.next() as usize) % ALPHA.len()])
        .collect()
}

#[derive(PartialEq, Eq, Debug)]
struct Out {
    ret: c_int,
    n: c_int, // sentinel when `%n` was not reached (same on both sides)
}

fn run(is_fl: bool, input: &CStr, fmt: &CStr) -> Out {
    let mut n: c_int = -98765;
    let np = &mut n as *mut c_int;
    let ret = unsafe {
        if is_fl {
            fl_sscanf(input.as_ptr(), fmt.as_ptr(), np)
        } else {
            sscanf(input.as_ptr(), fmt.as_ptr(), np)
        }
    };
    Out { ret, n }
}

#[test]
fn sscanf_suppress_differential_fuzz_vs_glibc() {
    let mut r = Lcg(0x0509_90a7_5ee0_0001);
    let mut divs: Vec<String> = Vec::new();
    let mut compared: u64 = 0;

    for _ in 0..200_000 {
        let fmt = gen_fmt(&mut r);
        let input = gen_input(&mut r);
        let (Ok(cfmt), Ok(cinput)) = (CString::new(fmt.as_str()), CString::new(input.clone()))
        else {
            continue;
        };
        let fl = run(true, &cinput, &cfmt);
        let host = run(false, &cinput, &cfmt);
        compared += 1;
        if fl != host && divs.len() < 40 {
            divs.push(format!(
                "fmt={fmt:?} input={:?}\n    fl   ={fl:?}\n    glibc={host:?}",
                String::from_utf8_lossy(&input)
            ));
        }
    }

    assert!(
        divs.is_empty(),
        "sscanf suppression diverged from host glibc on {} cases (showing up to 40):\n{}",
        divs.len(),
        divs.join("\n")
    );
    eprintln!("sscanf suppress fuzz: {compared} comparisons, 0 divergences vs host glibc");
}
