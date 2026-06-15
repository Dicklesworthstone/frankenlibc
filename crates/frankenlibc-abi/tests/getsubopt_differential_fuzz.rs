#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc getsubopt oracle

//! Randomized differential fuzzer for `getsubopt` vs a LIVE host glibc oracle.
//! The existing probe is a single fixed battery; this randomizes the option
//! string AND the token list — including tokens that are prefixes of one another
//! (exact-vs-prefix name matching), empty names, `=`-led segments, repeated and
//! trailing commas — and compares the full per-call sequence of
//! (return index, *valuep, consumed offset) on independent mutable buffers.

use std::ffi::{c_char, c_int};

use frankenlibc_abi::stdlib_abi as fl;

unsafe extern "C" {
    fn getsubopt(
        optionp: *mut *mut c_char,
        tokens: *const *mut c_char,
        valuep: *mut *mut c_char,
    ) -> c_int;
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
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// Token pool: short names, several sharing prefixes ("a"/"ab"/"abc", "b"/"bs")
/// to stress exact-vs-prefix matching, plus an empty name.
const POOL: [&str; 9] = ["a", "ab", "abc", "b", "bs", "ro", "rw", "size", ""];

/// One getsubopt step's observable result.
type Step = (c_int, Option<Vec<u8>>, usize);

fn read_cstr(p: *mut c_char) -> Option<Vec<u8>> {
    if p.is_null() {
        return None;
    }
    let mut v = Vec::new();
    let mut i = 0isize;
    loop {
        let b = unsafe { *p.offset(i) } as u8;
        if b == 0 {
            break;
        }
        v.push(b);
        i += 1;
    }
    Some(v)
}

/// Drive getsubopt (fl or glibc) to exhaustion over a fresh mutable copy of
/// `option`, returning the per-call sequence of (ret, *valuep, consumed offset).
fn run(is_fl: bool, option: &[u8], tokens: &[*mut c_char]) -> Vec<Step> {
    let mut buf: Vec<u8> = option.to_vec();
    buf.push(0);
    let base = buf.as_ptr() as usize;
    let mut sub: *mut c_char = buf.as_mut_ptr() as *mut c_char;
    let mut value: *mut c_char = std::ptr::null_mut();
    let mut steps = Vec::new();
    // Bounded to avoid an infinite loop if the two impls disagree on advancing.
    for _ in 0..64 {
        if unsafe { *sub } == 0 {
            break;
        }
        let r = if is_fl {
            unsafe { fl::getsubopt(&mut sub, tokens.as_ptr(), &mut value) }
        } else {
            unsafe { getsubopt(&mut sub, tokens.as_ptr(), &mut value) }
        };
        let consumed = (sub as usize) - base;
        steps.push((r, read_cstr(value), consumed));
    }
    steps
}

fn gen_option(r: &mut Lcg) -> Vec<u8> {
    let segs = 1 + r.below(6) as usize;
    let mut out: Vec<u8> = Vec::new();
    for s in 0..segs {
        if s > 0 {
            out.push(b',');
        }
        match r.below(8) {
            0 => {} // empty segment
            1 => out.extend_from_slice(b"=noval"),
            2 => {
                // a pool name, no value
                out.extend_from_slice(POOL[r.below(POOL.len() as u64) as usize].as_bytes());
            }
            3 => {
                // a pool name = value
                out.extend_from_slice(POOL[r.below(POOL.len() as u64) as usize].as_bytes());
                out.push(b'=');
                let vlen = r.below(4) as usize;
                out.extend(std::iter::repeat_n(b'x', vlen));
            }
            4 => out.extend_from_slice(b"size="), // empty value
            _ => {
                // random short name maybe with value
                let nlen = r.below(4);
                for _ in 0..nlen {
                    out.push(b'a' + r.below(6) as u8);
                }
                if r.below(2) == 0 {
                    out.push(b'=');
                    for _ in 0..r.below(3) {
                        out.push(b'1' + r.below(3) as u8);
                    }
                }
            }
        }
    }
    out
}

#[test]
fn getsubopt_differential_fuzz_vs_glibc() {
    let mut r = Lcg(0x6e15_a7c3_44d9_0011);
    // Pre-build NUL-terminated token C strings; reuse pointers across iterations.
    let cstrings: Vec<std::ffi::CString> = POOL
        .iter()
        .map(|s| std::ffi::CString::new(*s).unwrap())
        .collect();

    let mut divs: Vec<String> = Vec::new();
    let mut compared = 0u64;

    for _ in 0..150_000 {
        // Random token list (2..=5 distinct pool entries) + NULL sentinel.
        let ntok = 2 + r.below(4) as usize;
        let mut toks: Vec<*mut c_char> = Vec::new();
        for _ in 0..ntok {
            let idx = r.below(cstrings.len() as u64) as usize;
            toks.push(cstrings[idx].as_ptr() as *mut c_char);
        }
        toks.push(std::ptr::null_mut());

        let option = gen_option(&mut r);
        let fl_seq = run(true, &option, &toks);
        let host_seq = run(false, &option, &toks);
        compared += 1;
        if fl_seq != host_seq && divs.len() < 30 {
            divs.push(format!(
                "option={:?}\n    fl   ={:?}\n    glibc={:?}",
                String::from_utf8_lossy(&option),
                fl_seq,
                host_seq
            ));
        }
    }

    assert!(
        divs.is_empty(),
        "getsubopt diverged from host glibc on some of {compared} cases (showing up to 30):\n{}",
        divs.join("\n")
    );
    eprintln!("getsubopt fuzz: {compared} comparisons, 0 divergences vs host glibc");
}
