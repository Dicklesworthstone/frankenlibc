#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // host-glibc fnmatch oracle (libc, linked by std)

//! Randomized live differential fuzzer for `fnmatch` vs host glibc. The existing
//! `fnmatch_differential_probe` is a fixed edge-case battery; this generates
//! random glob patterns (metacharacters, bracket expressions, POSIX character
//! classes, backslash escapes, '/' and '.') against random subject strings under
//! random FNM_ flag combinations, and asserts fl's match/no-match verdict equals
//! the live host glibc oracle byte-for-byte.

use std::ffi::{CString, c_char, c_int};

use frankenlibc_abi::string_abi::fnmatch as fl_fnmatch;

unsafe extern "C" {
    fn fnmatch(pattern: *const c_char, string: *const c_char, flags: c_int) -> c_int;
}

// glibc FNM_ bit values.
const PATHNAME: c_int = 1 << 0;
const NOESCAPE: c_int = 1 << 1;
const PERIOD: c_int = 1 << 2;
const LEADING_DIR: c_int = 1 << 3;
const CASEFOLD: c_int = 1 << 4;
const FLAG_BITS: [c_int; 5] = [PATHNAME, NOESCAPE, PERIOD, LEADING_DIR, CASEFOLD];

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

/// POSIX class tokens injected verbatim into patterns so bracket-class parsing
/// (`[[:alpha:]]`, negation, etc.) is exercised.
const CLASSES: &[&str] = &[
    "[:alpha:]", "[:digit:]", "[:alnum:]", "[:space:]", "[:upper:]", "[:lower:]", "[:punct:]",
];

/// Bytes that may appear as a single bracket member / range endpoint. `-` is
/// intentionally excluded from the standalone-member pool: a literal `-`
/// adjacent to a collating symbol (`[.x.]`) forms a range with a collating-
/// symbol endpoint (`X-[.c.]`), a distinct glibc feature fl does not yet support
/// (tracked separately) — explicit ranges below already exercise `X-Y`.
const MEMBER: &[u8] = b"abAB129.^!/";

/// Build a random glob pattern from glob-significant bytes, occasionally
/// emitting a whole bracket expression or POSIX class so those paths are hit
/// far more often than random bytes alone would manage. The bracket generator
/// covers the quirky corners glibc cares about: ranges (`a-z`), collating
/// symbols (`[.a.]`) and equivalence classes (`[=a=]`), a leading literal `]`
/// member (`[]a]`), and backslash escapes inside the class.
fn gen_pattern(r: &mut Lcg) -> Vec<u8> {
    const ATOM: &[u8] = b"ab.*?/-^!\\AB12";
    let len = r.below(11);
    let mut p: Vec<u8> = Vec::new();
    let mut i = 0;
    while i < len {
        match r.below(10) {
            0 | 1 => {
                // A bracket expression: '[', optional '!'/'^', members, ']'.
                p.push(b'[');
                match r.below(3) {
                    0 => p.push(b'!'),
                    1 => p.push(b'^'),
                    _ => {}
                }
                // POSIX: a ']' immediately after '[' or '[!'/'[^' is a literal
                // member, not the terminator.
                if r.below(4) == 0 {
                    p.push(b']');
                }
                let members = 1 + r.below(4);
                for _ in 0..members {
                    match r.below(6) {
                        0 => p.extend_from_slice(CLASSES[r.below(CLASSES.len())].as_bytes()),
                        // Collating symbol [.x.] / equivalence class [=x=].
                        1 => {
                            let k = if r.below(2) == 0 { b'.' } else { b'=' };
                            p.push(b'[');
                            p.push(k);
                            p.push(MEMBER[r.below(MEMBER.len())]);
                            p.push(k);
                            p.push(b']');
                        }
                        // A well-formed range `X-Y`.
                        2 => {
                            p.push(MEMBER[r.below(MEMBER.len())]);
                            p.push(b'-');
                            p.push(MEMBER[r.below(MEMBER.len())]);
                        }
                        // A backslash escape inside the class. The escaped byte
                        // is drawn from a dash-free pool: under NOESCAPE the `\`
                        // is literal, so a following `-` next to a collating
                        // symbol would form a collating-endpoint range (the
                        // separately-tracked feature excluded above).
                        3 => {
                            const ESC: &[u8] = b"*?]ab19.\\";
                            p.push(b'\\');
                            p.push(ESC[r.below(ESC.len())]);
                        }
                        _ => p.push(MEMBER[r.below(MEMBER.len())]),
                    }
                }
                p.push(b']');
            }
            _ => p.push(ATOM[r.below(ATOM.len())]),
        }
        i += 1;
    }
    p
}

/// A random subject string over an alphabet that overlaps the pattern's literal
/// bytes plus path separators and dots (to drive PATHNAME/PERIOD logic).
fn gen_string(r: &mut Lcg) -> Vec<u8> {
    const S: &[u8] = b"ab/.AB12-^!";
    let len = r.below(11);
    (0..len).map(|_| S[r.below(S.len())]).collect()
}

fn gen_flags(r: &mut Lcg) -> c_int {
    let mut f = 0;
    for &bit in &FLAG_BITS {
        if r.below(2) == 0 {
            f |= bit;
        }
    }
    f
}

#[test]
fn fnmatch_differential_fuzz_vs_glibc() {
    let mut r = Lcg(0xf00d_face_1234_5678);
    let mut divs: Vec<String> = Vec::new();
    let mut compared: u64 = 0;

    for _ in 0..200_000 {
        let pat = gen_pattern(&mut r);
        let s = gen_string(&mut r);
        let flags = gen_flags(&mut r);
        let (Ok(cp), Ok(cs)) = (CString::new(pat.clone()), CString::new(s.clone())) else {
            continue;
        };
        let f = unsafe { fl_fnmatch(cp.as_ptr(), cs.as_ptr(), flags) };
        let g = unsafe { fnmatch(cp.as_ptr(), cs.as_ptr(), flags) };
        compared += 1;
        // Normalize to match (0) vs no-match (non-zero).
        if (f == 0) != (g == 0) && divs.len() < 40 {
            divs.push(format!(
                "pat={:?} str={:?} flags={flags:#x}\n    fl   ={} ({f})\n    glibc={} ({g})",
                String::from_utf8_lossy(&pat),
                String::from_utf8_lossy(&s),
                if f == 0 { "match" } else { "nomatch" },
                if g == 0 { "match" } else { "nomatch" },
            ));
        }
    }

    assert!(
        divs.is_empty(),
        "fnmatch diverged from host glibc on {} cases (showing up to 40):\n{}",
        divs.len(),
        divs.join("\n")
    );
    eprintln!("fnmatch differential fuzz: {compared} comparisons, 0 divergences vs host glibc");
}
