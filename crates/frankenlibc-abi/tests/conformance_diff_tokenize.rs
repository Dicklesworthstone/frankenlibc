#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc tokenizer oracle + in-place mutation

//! Differential + metamorphic harness for the tokenization family
//! (bd-sk40ln). strtok / strtok_r / strsep had ZERO committed coverage despite
//! famously fiddly semantics: strtok/strtok_r collapse runs of delimiters and
//! skip leading delimiters (no empty tokens), while strsep emits an empty token
//! for every delimiter (no collapsing). All three mutate the input in place.
//!
//! Two layers, no mocks:
//!   1. DIFFERENTIAL — for thousands of randomised (input, delimiter-set) pairs
//!      (leading/trailing/consecutive delimiters, all-delimiter and empty
//!      strings, multi-char delimiter sets), the full token SEQUENCE produced by
//!      fl must equal the host glibc sequence, byte-for-byte, for strtok_r,
//!      strtok (global state), and strsep.
//!   2. METAMORPHIC — strtok_r and strtok agree; strtok never yields an empty
//!      token; strsep's token count == (number of delimiter chars hit) + 1;
//!      concatenating strsep tokens with the original delimiters reconstructs
//!      the input.

use std::ffi::c_char;

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn strtok(s: *mut c_char, d: *const c_char) -> *mut c_char;
        pub fn strtok_r(s: *mut c_char, d: *const c_char, sp: *mut *mut c_char) -> *mut c_char;
        pub fn strsep(sp: *mut *mut c_char, d: *const c_char) -> *mut c_char;
        pub fn strlen(s: *const c_char) -> usize;
    }
}
use frankenlibc_abi::string_abi as fl;

unsafe fn cstr_to_vec(p: *const c_char) -> Vec<u8> {
    if p.is_null() {
        return Vec::new();
    }
    let len = unsafe { g::strlen(p) };
    unsafe { std::slice::from_raw_parts(p.cast::<u8>(), len) }.to_vec()
}

/// A NUL-terminated, freshly-owned mutable copy of `bytes`.
fn cbuf(bytes: &[u8]) -> Vec<c_char> {
    let mut v: Vec<c_char> = bytes.iter().map(|&b| b as c_char).collect();
    v.push(0);
    v
}

// --- token collectors: each runs one tokenizer to exhaustion on a fresh copy.

unsafe fn toks_strtok_r(bytes: &[u8], delim: &[u8], glibc: bool) -> Vec<Vec<u8>> {
    let mut buf = cbuf(bytes);
    let d = cbuf(delim);
    let mut save: *mut c_char = std::ptr::null_mut();
    let mut out = Vec::new();
    let mut first = buf.as_mut_ptr();
    loop {
        let t = unsafe {
            if glibc {
                g::strtok_r(first, d.as_ptr(), &mut save)
            } else {
                fl::strtok_r(first, d.as_ptr(), &mut save)
            }
        };
        first = std::ptr::null_mut();
        if t.is_null() {
            break;
        }
        out.push(unsafe { cstr_to_vec(t) });
    }
    out
}

unsafe fn toks_strtok_global(bytes: &[u8], delim: &[u8], glibc: bool) -> Vec<Vec<u8>> {
    let mut buf = cbuf(bytes);
    let d = cbuf(delim);
    let mut out = Vec::new();
    let mut first = buf.as_mut_ptr();
    loop {
        let t = unsafe {
            if glibc {
                g::strtok(first, d.as_ptr())
            } else {
                fl::strtok(first, d.as_ptr())
            }
        };
        first = std::ptr::null_mut();
        if t.is_null() {
            break;
        }
        out.push(unsafe { cstr_to_vec(t) });
    }
    out
}

unsafe fn toks_strsep(bytes: &[u8], delim: &[u8], glibc: bool) -> Vec<Vec<u8>> {
    let mut buf = cbuf(bytes);
    let d = cbuf(delim);
    let mut sp: *mut c_char = buf.as_mut_ptr();
    let mut out = Vec::new();
    loop {
        let t = unsafe {
            if glibc {
                g::strsep(&mut sp, d.as_ptr())
            } else {
                fl::strsep(&mut sp, d.as_ptr())
            }
        };
        if t.is_null() {
            break;
        }
        out.push(unsafe { cstr_to_vec(t) });
    }
    out
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % (n as u64)) as usize
    }
}

/// Random input over a tiny alphabet where some letters double as delimiters,
/// so leading/trailing/consecutive-delimiter cases arise frequently.
fn rand_input(rng: &mut Rng) -> (Vec<u8>, Vec<u8>) {
    // Delimiter set: 1-3 chars from {b',', b';', b' '}.
    let pool = [b',', b';', b' '];
    let dn = 1 + rng.below(3);
    let mut delim: Vec<u8> = Vec::new();
    for _ in 0..dn {
        let c = pool[rng.below(pool.len())];
        if !delim.contains(&c) {
            delim.push(c);
        }
    }
    // Input alphabet: letters a/b/c plus the delimiter chars (so they appear).
    let alphabet = [b'a', b'b', b'c', b',', b';', b' '];
    let len = rng.below(24);
    let s: Vec<u8> = (0..len)
        .map(|_| alphabet[rng.below(alphabet.len())])
        .collect();
    (s, delim)
}

#[test]
fn strtok_r_matches_glibc() {
    let mut rng = Rng(0xC0FF_EE00_1234_5678);
    for _ in 0..8000 {
        let (s, d) = rand_input(&mut rng);
        let gt = unsafe { toks_strtok_r(&s, &d, true) };
        let ft = unsafe { toks_strtok_r(&s, &d, false) };
        assert_eq!(ft, gt, "strtok_r seq mismatch s={s:?} delim={d:?}");
        // METAMORPHIC: no empty tokens, and strtok_r == strtok (global).
        assert!(
            ft.iter().all(|t| !t.is_empty()),
            "strtok_r emitted empty token"
        );
        let gl = unsafe { toks_strtok_global(&s, &d, false) };
        assert_eq!(
            ft, gl,
            "fl strtok_r vs fl strtok disagree s={s:?} delim={d:?}"
        );
    }
}

#[test]
fn strtok_global_matches_glibc() {
    let mut rng = Rng(0x1357_9BDF_2468_ACE0);
    for _ in 0..6000 {
        let (s, d) = rand_input(&mut rng);
        let gt = unsafe { toks_strtok_global(&s, &d, true) };
        let ft = unsafe { toks_strtok_global(&s, &d, false) };
        assert_eq!(ft, gt, "strtok seq mismatch s={s:?} delim={d:?}");
    }
}

#[test]
fn strsep_matches_glibc_and_reconstructs() {
    let mut rng = Rng(0x2BAD_F00D_5EED_1010);
    for _ in 0..8000 {
        let (s, d) = rand_input(&mut rng);
        let gt = unsafe { toks_strsep(&s, &d, true) };
        let ft = unsafe { toks_strsep(&s, &d, false) };
        assert_eq!(ft, gt, "strsep seq mismatch s={s:?} delim={d:?}");

        // METAMORPHIC: strsep emits exactly (#delimiter chars in s) + 1 tokens,
        // and joining the tokens (each split consumed one delimiter byte)
        // reproduces the original length.
        let ndelim = s.iter().filter(|c| d.contains(c)).count();
        assert_eq!(
            ft.len(),
            ndelim + 1,
            "strsep token count s={s:?} delim={d:?}"
        );
        let total: usize = ft.iter().map(|t| t.len()).sum();
        assert_eq!(
            total + ndelim,
            s.len(),
            "strsep tokens + delimiters must reconstruct input length"
        );
    }
}

#[test]
fn edge_cases_match_glibc() {
    let cases: &[(&[u8], &[u8])] = &[
        (b"", b","),          // empty input
        (b",,,", b","),       // all delimiters
        (b",a,", b","),       // leading + trailing delimiter
        (b"a,,b", b","),      // consecutive delimiters
        (b"abc", b","),       // no delimiter present
        (b"a;b,c d", b",; "), // multi-char delimiter set
        (b"  ", b" "),        // only spaces
    ];
    for (s, d) in cases {
        let gt_r = unsafe { toks_strtok_r(s, d, true) };
        let ft_r = unsafe { toks_strtok_r(s, d, false) };
        assert_eq!(ft_r, gt_r, "strtok_r edge mismatch s={s:?} delim={d:?}");

        let gt_s = unsafe { toks_strsep(s, d, true) };
        let ft_s = unsafe { toks_strsep(s, d, false) };
        assert_eq!(ft_s, gt_s, "strsep edge mismatch s={s:?} delim={d:?}");
    }
}
