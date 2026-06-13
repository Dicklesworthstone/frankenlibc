#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc rpmatch oracle

//! Randomized differential fuzzer for `rpmatch` vs a LIVE host glibc oracle.
//!
//! `rpmatch` had ZERO differential coverage. glibc implements it by matching the
//! C-locale `YESEXPR` (`^[yY]`) and `NOEXPR` (`^[nN]`) regexes against the
//! response, returning 1 (yes), 0 (no), or -1 (neither). frankenlibc implements
//! the equivalent by inspecting the leading byte. This fuzzer proves that
//! equivalence holds across the FULL leading-byte range (0..=255, including
//! control bytes, high/non-ASCII bytes, and UTF-8 lead bytes) and over
//! multi-byte responses with arbitrary tails — the surface where a naive
//! first-byte shortcut could silently diverge from the anchored-regex oracle.
//!
//! The process runs under the default C/POSIX locale (no `setlocale` call), so
//! both implementations see the same `YESEXPR`/`NOEXPR`.

use std::ffi::{CString, c_char, c_int};

use frankenlibc_abi::glibc_internal_abi as fl;

unsafe extern "C" {
    fn rpmatch(response: *const c_char) -> c_int;
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

/// Compare fl vs glibc for one NUL-terminated response. `bytes` must not contain
/// an interior NUL (the C string terminates at the first one anyway).
fn check(bytes: &[u8], divs: &mut Vec<String>) {
    let c = CString::new(bytes).expect("no interior NUL");
    let fl_r = unsafe { fl::rpmatch(c.as_ptr()) };
    let host_r = unsafe { rpmatch(c.as_ptr()) };
    if fl_r != host_r && divs.len() < 30 {
        divs.push(format!(
            "response={:?}  fl={fl_r}  glibc={host_r}",
            String::from_utf8_lossy(bytes)
        ));
    }
}

#[test]
fn rpmatch_differential_fuzz_vs_glibc() {
    let mut r = Lcg(0x5142_9ad7_31c0_44f1);
    let mut divs: Vec<String> = Vec::new();
    let mut compared = 0u64;

    // 1) Curated edge cases (the documented C-locale battery + tricky tails).
    let curated: &[&[u8]] = &[
        b"yes", b"Yes", b"YES", b"y", b"Y", b"no", b"No", b"n", b"N", b"maybe",
        b"", b"yep", b"nope", b"1", b"0", b"+", b"ja", b"oui", b" yes", b"\ty",
        b"yarr", b"Narr", b"yY", b"nN", b"Y123", b"NaN", b"\xff", b"\xc3\xa9",
        b"\x01y", b"z", b"yes\xff", b"YEAH", b"NIX",
    ];
    for &c in curated {
        check(c, &mut divs);
        compared += 1;
    }

    // 2) Randomized responses. The leading byte dominates the result, so bias the
    //    generator toward the full 0..=255 range there while appending an
    //    arbitrary (NUL-free) tail of varying length.
    for _ in 0..200_000 {
        let mut bytes: Vec<u8> = Vec::new();
        // Leading byte: sweep the whole non-NUL range, with extra weight on the
        // ASCII letters around y/Y/n/N to stress the case-fold boundary.
        let lead = match r.below(4) {
            0 => (b'a' as u64 + r.below(58)) as u8, // 'a'..='z' plus a few above
            1 => 1 + (r.below(255) as u8),          // any non-NUL byte
            _ => {
                // around the yes/no letters and their neighbours
                let pool = [b'y', b'Y', b'n', b'N', b'x', b'z', b'Z', b'm', b'o'];
                pool[r.below(pool.len() as u64) as usize]
            }
        };
        bytes.push(lead);
        let tail = r.below(6);
        for _ in 0..tail {
            let b = 1 + (r.below(255) as u8); // never an interior NUL
            bytes.push(b);
        }
        check(&bytes, &mut divs);
        compared += 1;
    }

    assert!(
        divs.is_empty(),
        "rpmatch diverged from host glibc on some of {compared} cases (showing up to 30):\n{}",
        divs.join("\n")
    );
    eprintln!("rpmatch fuzz: {compared} comparisons, 0 divergences vs host glibc");
}
