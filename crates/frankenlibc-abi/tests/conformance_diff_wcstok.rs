#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc wcstok oracle + in-place mutation

//! Differential + metamorphic harness for wcstok (bd-ta9gjj), the wide
//! tokenizer — POSIX mandates the 3-arg reentrant form (explicit save pointer,
//! no global state). It collapses runs of delimiters and skips leading ones
//! (no empty tokens), like strtok, and mutates the input in place. It had ZERO
//! committed coverage.
//!
//! For thousands of randomised wide inputs (leading/trailing/consecutive
//! delimiters, all-delimiter and empty strings, multi-char delimiter sets,
//! astral-plane wchars as data AND delimiters), the full token SEQUENCE
//! produced by fl must equal host glibc's, byte-for-byte; plus metamorphic
//! invariants (no empty tokens; every token is a maximal delimiter-free run).
//! No mocks.

type Wc = libc::wchar_t; // i32

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn wcstok(s: *mut Wc, delim: *const Wc, save: *mut *mut Wc) -> *mut Wc;
        pub fn wcslen(s: *const Wc) -> usize;
    }
}
use frankenlibc_abi::wchar_abi as fl;

unsafe fn wstr_to_vec(p: *const Wc) -> Vec<Wc> {
    if p.is_null() {
        return Vec::new();
    }
    let len = unsafe { g::wcslen(p) };
    unsafe { std::slice::from_raw_parts(p, len) }.to_vec()
}

fn wbuf(v: &[Wc]) -> Vec<Wc> {
    let mut b = v.to_vec();
    b.push(0);
    b
}

/// Run one wcstok implementation to exhaustion on a fresh copy.
unsafe fn tokens(bytes: &[Wc], delim: &[Wc], glibc: bool) -> Vec<Vec<Wc>> {
    let mut buf = wbuf(bytes);
    let d = wbuf(delim);
    let mut save: *mut Wc = std::ptr::null_mut();
    let mut out = Vec::new();
    let mut first = buf.as_mut_ptr();
    loop {
        let t = unsafe {
            if glibc {
                g::wcstok(first, d.as_ptr(), &mut save)
            } else {
                let mut fsave = save.cast::<u32>();
                let r = fl::wcstok(first.cast::<u32>(), d.as_ptr().cast::<u32>(), &mut fsave);
                save = fsave.cast::<Wc>();
                r.cast::<Wc>()
            }
        };
        first = std::ptr::null_mut();
        if t.is_null() {
            break;
        }
        out.push(unsafe { wstr_to_vec(t) });
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

/// Random wide input where some symbols double as delimiters so leading/
/// trailing/consecutive-delimiter cases arise frequently. Includes an astral
/// codepoint in both the data alphabet and (sometimes) the delimiter set.
fn rand_input(rng: &mut Rng) -> (Vec<Wc>, Vec<Wc>) {
    let delim_pool: [Wc; 3] = [b',' as Wc, b';' as Wc, 0x1_F4A9];
    let dn = 1 + rng.below(3);
    let mut delim: Vec<Wc> = Vec::new();
    for _ in 0..dn {
        let c = delim_pool[rng.below(delim_pool.len())];
        if !delim.contains(&c) {
            delim.push(c);
        }
    }
    let alphabet: [Wc; 6] = [
        b'a' as Wc, b'b' as Wc, 0x4E2D, b',' as Wc, b';' as Wc, 0x1_F4A9,
    ];
    let len = rng.below(24);
    let s: Vec<Wc> = (0..len)
        .map(|_| alphabet[rng.below(alphabet.len())])
        .collect();
    (s, delim)
}

#[test]
fn wcstok_matches_glibc() {
    let mut rng = Rng(0x7763_7374_6F6B_0000);
    for _ in 0..9000 {
        let (s, d) = rand_input(&mut rng);
        let gt = unsafe { tokens(&s, &d, true) };
        let ft = unsafe { tokens(&s, &d, false) };
        assert_eq!(ft, gt, "wcstok seq mismatch s={s:?} delim={d:?}");

        // METAMORPHIC: no empty tokens; each token is delimiter-free.
        for t in &ft {
            assert!(!t.is_empty(), "wcstok emitted empty token");
            assert!(
                t.iter().all(|c| !d.contains(c)),
                "token contains a delimiter: {t:?} delim={d:?}"
            );
        }
        // The concatenation of tokens equals the input with all delimiters
        // removed (since wcstok keeps every non-delimiter char exactly once).
        let joined: Vec<Wc> = ft.iter().flatten().copied().collect();
        let stripped: Vec<Wc> = s.iter().copied().filter(|c| !d.contains(c)).collect();
        assert_eq!(
            joined, stripped,
            "wcstok tokens must cover all non-delims s={s:?}"
        );
    }
}

#[test]
fn edge_cases_match_glibc() {
    let cases: &[(&[Wc], &[Wc])] = &[
        (&[], &[b',' as Wc]),                                   // empty
        (&[b',' as Wc, b',' as Wc], &[b',' as Wc]),             // all delimiters
        (&[b',' as Wc, b'a' as Wc, b',' as Wc], &[b',' as Wc]), // lead+trail
        (
            &[b'a' as Wc, b',' as Wc, b',' as Wc, b'b' as Wc],
            &[b',' as Wc],
        ), // consecutive
        (&[b'a' as Wc, b'b' as Wc, b'c' as Wc], &[b',' as Wc]), // no delimiter
        (&[0x1_F4A9, b'x' as Wc, 0x1_F4A9], &[0x1_F4A9]),       // astral delimiter
        (
            &[b'a' as Wc, 0x4E2D, b';' as Wc, b'b' as Wc],
            &[b';' as Wc, b' ' as Wc],
        ), // multi-set
    ];
    for (s, d) in cases {
        let gt = unsafe { tokens(s, d, true) };
        let ft = unsafe { tokens(s, d, false) };
        assert_eq!(ft, gt, "wcstok edge mismatch s={s:?} delim={d:?}");
    }
}
