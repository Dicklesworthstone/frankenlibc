#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // host-glibc strverscmp oracle (libc, linked by std)

//! Randomized live differential fuzzer for GNU `strverscmp` vs host glibc.
//! The existing `conformance_diff_string::diff_strverscmp_cases` only checks ~19
//! fixed pairs; `strverscmp`'s real complexity is its version-comparison state
//! machine (the interplay of digit runs, leading zeros, all-zero prefixes, and
//! digit/non-digit transitions), which only a randomized sweep over a digit-and-
//! zero-heavy alphabet reaches. This generates pairs — both fully random and
//! single-edit mutations that share long prefixes — and asserts the *sign* of
//! the comparison matches glibc byte-for-byte.

use std::ffi::{CString, c_char};

use frankenlibc_abi::string_abi::strverscmp as fl_strverscmp;

unsafe extern "C" {
    fn strverscmp(s1: *const c_char, s2: *const c_char) -> c_int;
}
use std::ffi::c_int;

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

fn sign(x: c_int) -> i32 {
    x.signum()
}

/// A version-ish string: digits and '0' are over-represented to stress the
/// numeric-run / leading-zero logic, with a few letters and dots mixed in.
fn gen_string(r: &mut Lcg) -> Vec<u8> {
    // Heavy on '0' and digits; some letters, dots, dashes.
    const ALPHABET: &[u8] = b"00001234567899.aZ-: \x01\x7f\x80\xfe\xff";
    let len = r.below(13);
    (0..len)
        .map(|_| ALPHABET[r.below(ALPHABET.len())])
        .collect()
}

/// A single-edit mutation of `base` (substitute / insert / delete one byte) so
/// the pair shares a long common prefix — exactly where the digit-run state
/// machine makes its hardest decisions.
fn mutate(r: &mut Lcg, base: &[u8]) -> Vec<u8> {
    const ALPHABET: &[u8] = b"00001234567899.aZ-: \x01\x7f\x80\xfe\xff";
    let mut v = base.to_vec();
    if v.is_empty() {
        return gen_string(r);
    }
    let pos = r.below(v.len());
    match r.below(3) {
        0 => v[pos] = ALPHABET[r.below(ALPHABET.len())], // substitute
        1 => v.insert(pos, ALPHABET[r.below(ALPHABET.len())]), // insert
        _ => {
            v.remove(pos);
        }        // delete
    }
    v
}

#[test]
fn strverscmp_differential_fuzz_vs_glibc() {
    let mut r = Lcg(0xbada_5515_c0de_1234);
    let mut divs: Vec<String> = Vec::new();
    let mut compared: u64 = 0;

    for _ in 0..120_000 {
        let a = gen_string(&mut r);
        // Half the time compare against a single-edit mutation (shared prefix),
        // half against a fully independent random string.
        let b = if r.next() & 1 == 0 {
            mutate(&mut r, &a)
        } else {
            gen_string(&mut r)
        };
        // strverscmp inputs are C strings, so embedded NULs are not meaningful;
        // CString rejects them — skip those (cannot happen with our alphabet).
        let (Ok(ca), Ok(cb)) = (CString::new(a.clone()), CString::new(b.clone())) else {
            continue;
        };
        let f = unsafe { fl_strverscmp(ca.as_ptr(), cb.as_ptr()) };
        let g = unsafe { strverscmp(ca.as_ptr(), cb.as_ptr()) };
        compared += 1;
        if sign(f) != sign(g) && divs.len() < 40 {
            divs.push(format!(
                "a={:?} b={:?}\n    fl   =sign {}  (raw {f})\n    glibc=sign {}  (raw {g})",
                String::from_utf8_lossy(&a),
                String::from_utf8_lossy(&b),
                sign(f),
                sign(g),
            ));
        }
    }

    assert!(
        divs.is_empty(),
        "strverscmp diverged from host glibc on {} cases (showing up to 40):\n{}",
        divs.len(),
        divs.join("\n")
    );
    eprintln!("strverscmp differential fuzz: {compared} comparisons, 0 divergences vs host glibc");
}
