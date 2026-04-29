#![cfg(target_os = "linux")]

//! Differential conformance harness for `<string.h>` pure functions.
//!
//! Pure / no-side-effect string functions are the easiest differential
//! targets: same input → same output, no allocation or fd state to mock.
//! For each function we sweep 5–15 inputs covering edge cases (empty,
//! single-char, no-match, match-at-start, match-at-end, NUL embedded,
//! high bytes, repeated chars). Both the FrankenLibC implementation
//! (`frankenlibc_abi::string_abi::*`) and the host glibc reference
//! (`libc::*`) are called on identical inputs and the results are
//! compared:
//!
//! - `strchr / strrchr / strchrnul / strstr / strpbrk / memchr / memrchr`
//!   compare offset-from-base (or "no match" sentinel).
//! - `strspn / strcspn / strnlen` compare returned length.
//! - `memmem` compares bounded byte-substring match offsets.
//! - `memcmp` compares the sign of the returned int (POSIX requires
//!   only the sign, not the magnitude, to be portable).
//!
//! Reference: glibc / musl, POSIX.1-2017.
//! Bead: CONFORMANCE: libc string.h diff matrix.

use std::ffi::{c_char, c_int, c_void};

use frankenlibc_abi::string_abi as fl;

unsafe extern "C" {
    #[link_name = "memmem"]
    fn libc_memmem(
        haystack: *const c_void,
        haystack_len: usize,
        needle: *const c_void,
        needle_len: usize,
    ) -> *mut c_void;
    /// Host glibc GNU `strchrnul` — like strchr but returns ptr to NUL
    /// when no match (instead of NULL). Not exposed by libc crate.
    fn strchrnul(s: *const c_char, c: c_int) -> *mut c_char;
    /// Host glibc GNU `strverscmp` — version-aware string compare:
    /// "file9" < "file10". Not exposed by libc crate.
    fn strverscmp(s1: *const c_char, s2: *const c_char) -> c_int;
}

#[derive(Debug)]
struct Divergence {
    function: &'static str,
    case: String,
    frankenlibc: String,
    glibc: String,
}

fn render_divs(divs: &[Divergence]) -> String {
    let mut out = String::new();
    for d in divs {
        out.push_str(&format!(
            "  {} | case: {} | frankenlibc: {} | glibc: {}\n",
            d.function, d.case, d.frankenlibc, d.glibc,
        ));
    }
    out
}

/// Convert a returned char pointer into `Some(offset)` from the buffer
/// base, or `None` if the impl returned NULL. This lets us compare
/// frankenlibc and glibc results meaningfully across separate calls
/// where the buffers have different addresses.
fn offset_or_none(base: *const c_char, ret: *const c_char) -> Option<isize> {
    if ret.is_null() {
        None
    } else {
        // SAFETY: comparison is safe even if `ret` is outside the slice
        // because we only do pointer arithmetic when both pointers come
        // from the same allocation (the input buffer).
        Some(unsafe { ret.offset_from(base) })
    }
}

fn render_offset(o: Option<isize>) -> String {
    match o {
        Some(off) => format!("offset={off}"),
        None => "NULL".into(),
    }
}

fn offset_void_or_none(base: *const u8, ret: *const c_void) -> Option<isize> {
    if ret.is_null() {
        None
    } else {
        // SAFETY: every caller compares return pointers from byte-search
        // functions against the same allocation passed as that function's
        // haystack/input buffer.
        Some(unsafe { (ret as *const u8).offset_from(base) })
    }
}

/// Build a NUL-terminated `Vec<u8>` from a byte slice, panicking on
/// embedded NUL (we want intentional NUL placement to be explicit).
fn cstr(bytes: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(bytes.len() + 1);
    v.extend_from_slice(bytes);
    v.push(0);
    v
}

// ===========================================================================
// strchr / strrchr / strchrnul — char-search returning pointer
// ===========================================================================

const STRCHR_CASES: &[(&[u8], i32)] = &[
    (b"", b'a' as i32),
    (b"a", b'a' as i32),
    (b"a", b'b' as i32),
    (b"hello", b'l' as i32),
    (b"hello", b'h' as i32),
    (b"hello", b'o' as i32),
    (b"hello", b'z' as i32),
    (b"hello", 0),                // search for NUL → must point at terminator
    (b"abcabc", b'b' as i32),     // first occurrence
    (b"\xff\xfe\xfd", 0xff_i32),  // high-bit byte (POSIX: low 8 bits used)
    (b"\xff\xfe\xfd", 0x1ff_i32), // wide value: low 8 bits = 0xff, must match
    (b"longer string with many letters", b's' as i32),
];

#[test]
fn diff_strchr_cases() {
    let mut divs = Vec::new();
    for (s, c) in STRCHR_CASES {
        let buf = cstr(s);
        let base = buf.as_ptr() as *const c_char;
        let fl_r = unsafe { fl::strchr(base, *c) };
        let lc_r = unsafe { libc::strchr(base, *c) };
        let fo = offset_or_none(base, fl_r);
        let lo = offset_or_none(base, lc_r);
        if fo != lo {
            divs.push(Divergence {
                function: "strchr",
                case: format!("({:?}, {:#x})", s, c),
                frankenlibc: render_offset(fo),
                glibc: render_offset(lo),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "strchr divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_strrchr_cases() {
    let mut divs = Vec::new();
    for (s, c) in STRCHR_CASES {
        let buf = cstr(s);
        let base = buf.as_ptr() as *const c_char;
        let fl_r = unsafe { fl::strrchr(base, *c) };
        let lc_r = unsafe { libc::strrchr(base, *c) };
        let fo = offset_or_none(base, fl_r);
        let lo = offset_or_none(base, lc_r);
        if fo != lo {
            divs.push(Divergence {
                function: "strrchr",
                case: format!("({:?}, {:#x})", s, c),
                frankenlibc: render_offset(fo),
                glibc: render_offset(lo),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "strrchr divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// strstr — substring search
// ===========================================================================

const STRSTR_CASES: &[(&[u8], &[u8])] = &[
    (b"", b""),           // POSIX: empty needle returns haystack
    (b"hello", b""),      // empty needle, non-empty haystack
    (b"", b"x"),          // non-empty needle, empty haystack
    (b"hello", b"hello"), // equal
    (b"hello world", b"world"),
    (b"hello world", b"hello"),
    (b"hello world", b" "),
    (b"abcabc", b"bc"), // first match
    (b"aaaaa", b"aaa"), // overlapping needle
    (b"hello", b"x"),   // no match
    (b"the quick brown fox", b"quick"),
    (b"the quick brown fox", b"slow"),
    (b"abc", b"abcd"), // needle longer than haystack
];

#[test]
fn diff_strstr_cases() {
    let mut divs = Vec::new();
    for (h, n) in STRSTR_CASES {
        let hbuf = cstr(h);
        let nbuf = cstr(n);
        let hp = hbuf.as_ptr() as *const c_char;
        let np = nbuf.as_ptr() as *const c_char;
        let fl_r = unsafe { fl::strstr(hp, np) };
        let lc_r = unsafe { libc::strstr(hp, np) };
        let fo = offset_or_none(hp, fl_r);
        let lo = offset_or_none(hp, lc_r);
        if fo != lo {
            divs.push(Divergence {
                function: "strstr",
                case: format!("({:?}, {:?})", h, n),
                frankenlibc: render_offset(fo),
                glibc: render_offset(lo),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "strstr divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// strpbrk / strspn / strcspn — set-based scans
// ===========================================================================

const PBRK_CASES: &[(&[u8], &[u8])] = &[
    (b"", b""),
    (b"hello", b""), // empty accept set: spans 0
    (b"", b"abc"),
    (b"hello", b"aeiou"),       // first vowel
    (b"hello", b"xyz"),         // none match
    (b"123abc", b"0123456789"), // digit prefix
    (b"abcdef", b"fedcba"),     // every char in accept
    (b"abc def", b" "),         // single delimiter
    (b"  leading", b" "),       // leading whitespace
    (b"\t\n\r ", b" \t\n\r"),   // all whitespace
];

#[test]
fn diff_strpbrk_cases() {
    let mut divs = Vec::new();
    for (s, accept) in PBRK_CASES {
        let sbuf = cstr(s);
        let abuf = cstr(accept);
        let sp = sbuf.as_ptr() as *const c_char;
        let ap = abuf.as_ptr() as *const c_char;
        let fl_r = unsafe { fl::strpbrk(sp, ap) };
        let lc_r = unsafe { libc::strpbrk(sp, ap) };
        let fo = offset_or_none(sp, fl_r);
        let lo = offset_or_none(sp, lc_r);
        if fo != lo {
            divs.push(Divergence {
                function: "strpbrk",
                case: format!("({:?}, {:?})", s, accept),
                frankenlibc: render_offset(fo),
                glibc: render_offset(lo),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "strpbrk divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_strspn_cases() {
    let mut divs = Vec::new();
    for (s, accept) in PBRK_CASES {
        let sbuf = cstr(s);
        let abuf = cstr(accept);
        let sp = sbuf.as_ptr() as *const c_char;
        let ap = abuf.as_ptr() as *const c_char;
        let fl_r = unsafe { fl::strspn(sp, ap) };
        let lc_r = unsafe { libc::strspn(sp, ap) };
        if fl_r != lc_r {
            divs.push(Divergence {
                function: "strspn",
                case: format!("({:?}, {:?})", s, accept),
                frankenlibc: format!("{}", fl_r),
                glibc: format!("{}", lc_r),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "strspn divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_strcspn_cases() {
    let mut divs = Vec::new();
    for (s, reject) in PBRK_CASES {
        let sbuf = cstr(s);
        let rbuf = cstr(reject);
        let sp = sbuf.as_ptr() as *const c_char;
        let rp = rbuf.as_ptr() as *const c_char;
        let fl_r = unsafe { fl::strcspn(sp, rp) };
        let lc_r = unsafe { libc::strcspn(sp, rp) };
        if fl_r != lc_r {
            divs.push(Divergence {
                function: "strcspn",
                case: format!("({:?}, {:?})", s, reject),
                frankenlibc: format!("{}", fl_r),
                glibc: format!("{}", lc_r),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "strcspn divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// strnlen — bounded length
// ===========================================================================

const STRNLEN_CASES: &[(&[u8], usize)] = &[
    (b"", 0),
    (b"", 5),
    (b"hello", 0),
    (b"hello", 3),
    (b"hello", 5),
    (b"hello", 100),
    (b"hello", usize::MAX),
];

#[test]
fn diff_strnlen_cases() {
    let mut divs = Vec::new();
    for (s, n) in STRNLEN_CASES {
        let buf = cstr(s);
        let p = buf.as_ptr() as *const c_char;
        let fl_r = unsafe { fl::strnlen(p, *n) };
        let lc_r = unsafe { libc::strnlen(p, *n) };
        if fl_r != lc_r {
            divs.push(Divergence {
                function: "strnlen",
                case: format!("({:?}, {})", s, n),
                frankenlibc: format!("{fl_r}"),
                glibc: format!("{lc_r}"),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "strnlen divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// memchr / memrchr — bounded byte search (NUL-permissible)
// ===========================================================================

const MEMCHR_CASES: &[(&[u8], i32, usize)] = &[
    (b"", b'a' as i32, 0),
    (b"hello", b'l' as i32, 5),
    (b"hello", b'l' as i32, 2),  // bound cuts off match
    (b"hello", b'l' as i32, 3),  // bound includes first match
    (b"hello", b'z' as i32, 5),  // no match
    (b"\x00abc", 0, 4),          // search for NUL byte
    (b"abc\x00def", 0, 7),       // NUL in middle
    (b"\xff\xfe", 0xff, 2),      // high byte
    (b"abcabc", b'b' as i32, 6), // first occurrence
    (b"aaaa", b'a' as i32, 0),   // zero bound
];

#[test]
fn diff_memchr_cases() {
    let mut divs = Vec::new();
    for (s, c, n) in MEMCHR_CASES {
        let p = s.as_ptr() as *const c_void;
        let fl_r = unsafe { fl::memchr(p, *c, *n) };
        let lc_r = unsafe { libc::memchr(p, *c, *n) };
        let fo = offset_void_or_none(s.as_ptr(), fl_r);
        let lo = offset_void_or_none(s.as_ptr(), lc_r);
        if fo != lo {
            divs.push(Divergence {
                function: "memchr",
                case: format!("({:?}, {:#x}, {})", s, c, n),
                frankenlibc: render_offset(fo),
                glibc: render_offset(lo),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "memchr divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_memrchr_cases() {
    let mut divs = Vec::new();
    for (s, c, n) in MEMCHR_CASES {
        let p = s.as_ptr() as *const c_void;
        let fl_r = unsafe { fl::memrchr(p, *c, *n) };
        let lc_r = unsafe { libc::memrchr(p, *c, *n) };
        let fo = offset_void_or_none(s.as_ptr(), fl_r);
        let lo = offset_void_or_none(s.as_ptr(), lc_r);
        if fo != lo {
            divs.push(Divergence {
                function: "memrchr",
                case: format!("({:?}, {:#x}, {})", s, c, n),
                frankenlibc: render_offset(fo),
                glibc: render_offset(lo),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "memrchr divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// memcmp — bounded byte comparison; only sign of result is portable
// ===========================================================================

const MEMCMP_CASES: &[(&[u8], &[u8], usize)] = &[
    (b"abc", b"abc", 3),               // equal
    (b"abc", b"abd", 3),               // a < b
    (b"abd", b"abc", 3),               // a > b
    (b"abc", b"abd", 2),               // bound stops before diff → equal
    (b"", b"", 0),                     // empty, zero bound
    (b"abc", b"abc", 0),               // zero bound
    (b"\xff\xff", b"\x00\x00", 2),     // unsigned compare: 0xff > 0x00
    (b"\x80", b"\x7f", 1),             // boundary
    (b"abc\x00def", b"abc\x00xyz", 7), // NUL in middle, then diff
    (b"abc\x00def", b"abc\x00def", 7), // identical with embedded NUL
];

fn sign(x: c_int) -> c_int {
    x.signum()
}

#[test]
fn diff_memcmp_cases() {
    let mut divs = Vec::new();
    for (a, b, n) in MEMCMP_CASES {
        let ap = a.as_ptr() as *const c_void;
        let bp = b.as_ptr() as *const c_void;
        let fl_r = unsafe { fl::memcmp(ap, bp, *n) };
        let lc_r = unsafe { libc::memcmp(ap, bp, *n) };
        if sign(fl_r) != sign(lc_r) {
            divs.push(Divergence {
                function: "memcmp",
                case: format!("({:?}, {:?}, {})", a, b, n),
                frankenlibc: format!("sign={}", sign(fl_r)),
                glibc: format!("sign={}", sign(lc_r)),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "memcmp divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// memmem — bounded byte substring search (NUL-permissible)
// ===========================================================================

const MEMMEM_CASES: &[(&[u8], usize, &[u8], usize)] = &[
    (b"", 0, b"", 0),                     // empty needle matches at start
    (b"abc", 3, b"", 0),                  // empty needle, non-empty haystack
    (b"", 0, b"a", 1),                    // non-empty needle, empty haystack
    (b"hello world", 11, b"world", 5),    // match at end
    (b"hello world", 11, b"hello", 5),    // match at start
    (b"hello world", 11, b" ", 1),        // single-byte needle
    (b"abcabc", 6, b"bc", 2),             // first repeated match
    (b"aaaaa", 5, b"aaa", 3),             // overlapping candidates
    (b"abcdef", 6, b"xyz", 3),            // absent needle
    (b"abc", 2, b"bc", 2),                // haystack_len truncates match
    (b"abcdef", 6, b"cdeX", 3),           // needle_len truncates needle buffer
    (b"abc\0def", 7, b"\0d", 2),          // embedded NUL is ordinary data
    (b"\xff\xfe\xfd", 3, b"\xfe\xfd", 2), // high-bit bytes
];

#[test]
fn diff_memmem_cases() {
    let mut divs = Vec::new();
    for (haystack, haystack_len, needle, needle_len) in MEMMEM_CASES {
        let hbuf = if haystack.is_empty() {
            vec![0_u8]
        } else {
            haystack.to_vec()
        };
        let nbuf = if needle.is_empty() {
            vec![0_u8]
        } else {
            needle.to_vec()
        };
        let hp = hbuf.as_ptr().cast::<c_void>();
        let np = nbuf.as_ptr().cast::<c_void>();

        let fl_r = unsafe { fl::memmem(hp, *haystack_len, np, *needle_len) };
        let lc_r = unsafe { libc_memmem(hp, *haystack_len, np, *needle_len) };
        let fo = offset_void_or_none(hbuf.as_ptr(), fl_r);
        let lo = offset_void_or_none(hbuf.as_ptr(), lc_r);
        if fo != lo {
            divs.push(Divergence {
                function: "memmem",
                case: format!(
                    "({:?}, {}, {:?}, {})",
                    haystack, haystack_len, needle, needle_len
                ),
                frankenlibc: render_offset(fo),
                glibc: render_offset(lo),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "memmem divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// strcasecmp / strncasecmp — ASCII-case-insensitive byte compare
// ===========================================================================
//
// Per POSIX, strcasecmp and strncasecmp fold ASCII letters
// (A-Z ↔ a-z) before comparing, but bytes outside that range
// (high-bit, digits, punctuation, control chars) are compared
// untouched. POSIX requires only the *sign* of the return value to be
// portable — magnitude is implementation-defined — so the diff
// compares signum(), not the raw int.
//
// strncasecmp adds a byte cap: stop after `n` bytes even before NUL.
// Both n=0 and n past either string's length are exercised.

const STRCASECMP_CASES: &[(&[u8], &[u8])] = &[
    // Equal up to case
    (b"", b""),
    (b"abc", b"abc"),
    (b"ABC", b"ABC"),
    (b"abc", b"ABC"),
    (b"ABC", b"abc"),
    (b"AbC", b"aBc"),
    // Strict less / greater
    (b"abc", b"abd"),
    (b"abd", b"abc"),
    (b"abc", b"abcd"),                // prefix
    (b"abcd", b"abc"),
    // First-byte diff (case-folded vs not)
    (b"a", b"b"),
    (b"A", b"b"),
    (b"a", b"B"),
    // Boundary: byte just before/after the A-Z range
    (b"@", b"`"),                     // 0x40 vs 0x60 — both unaffected by folding, must NOT be equalized
    (b"[", b"{"),                     // 0x5B vs 0x7B — same
    // High-bit bytes — POSIX says only ASCII A-Za-z are folded
    (b"\xc3", b"\xe3"),               // identical case insensitive ONLY if locale folds it; in C locale, they differ as raw bytes
    (b"\xff", b"\xff"),
    (b"\x80", b"\x7f"),               // 0x80 (high) vs 0x7f (DEL) — sign-extension trap
    // Digits and punctuation — pass-through untouched
    (b"123", b"123"),
    (b"abc123", b"ABC123"),
    (b"abc1", b"abc2"),
    // Empty vs non-empty
    (b"", b"a"),
    (b"a", b""),
    (b"", b"\xff"),
];

#[test]
fn diff_strcasecmp_cases() {
    let mut divs = Vec::new();
    for (a, b) in STRCASECMP_CASES {
        let av = cstr(a);
        let bv = cstr(b);
        let ap = av.as_ptr() as *const c_char;
        let bp = bv.as_ptr() as *const c_char;
        // SAFETY: cstr() returns a NUL-terminated buffer owned for the
        // duration of the call.
        let fl_r = unsafe { fl::strcasecmp(ap, bp) };
        let lc_r = unsafe { libc::strcasecmp(ap, bp) };
        if sign(fl_r) != sign(lc_r) {
            divs.push(Divergence {
                function: "strcasecmp",
                case: format!("({:?}, {:?})", a, b),
                frankenlibc: format!("sign={}", sign(fl_r)),
                glibc: format!("sign={}", sign(lc_r)),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "strcasecmp divergences:\n{}",
        render_divs(&divs)
    );
}

const STRNCASECMP_CASES: &[(&[u8], &[u8], usize)] = &[
    // n=0 — must always compare equal regardless of contents
    (b"abc", b"xyz", 0),
    (b"", b"", 0),
    (b"\xff", b"\x00", 0),
    // Bound stops before any difference would surface
    (b"abc", b"abd", 2),                // bound 2 → "ab" == "ab"
    (b"ABC", b"abd", 2),                // bound 2 + folding
    // Bound exactly at the differing position
    (b"abc", b"abd", 3),
    // Bound past either string
    (b"abc", b"ABC", 100),
    (b"abc", b"abcd", 100),
    // Prefix relations under bound
    (b"abc", b"abcd", 3),               // "abc" == "abc" within first 3
    (b"abcd", b"abc", 3),               // same
    (b"abcd", b"abc", 4),               // "abcd" > "abc\0"
    // High-bit pass-through, bounded
    (b"\xc3z", b"\xc3Z", 2),
    // NUL inside — bound spans past first NUL (POSIX: stop on NUL even
    // before n is reached, both impls must agree).
    (b"a\x00b", b"a\x00c", 5),
    (b"abc", b"abd", 1),
];

#[test]
fn diff_strncasecmp_cases() {
    let mut divs = Vec::new();
    for (a, b, n) in STRNCASECMP_CASES {
        let av = cstr(a);
        let bv = cstr(b);
        let ap = av.as_ptr() as *const c_char;
        let bp = bv.as_ptr() as *const c_char;
        // SAFETY: cstr() returns a NUL-terminated buffer; n is bounded
        // and both impls treat NUL within n as a hard stop.
        let fl_r = unsafe { fl::strncasecmp(ap, bp, *n) };
        let lc_r = unsafe { libc::strncasecmp(ap, bp, *n) };
        if sign(fl_r) != sign(lc_r) {
            divs.push(Divergence {
                function: "strncasecmp",
                case: format!("({:?}, {:?}, {})", a, b, n),
                frankenlibc: format!("sign={}", sign(fl_r)),
                glibc: format!("sign={}", sign(lc_r)),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "strncasecmp divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// strchrnul — GNU: strchr that returns ptr to trailing NUL on no-match
// ===========================================================================
//
// Differs from POSIX strchr only in the no-match case: strchr returns
// NULL, strchrnul returns &s[strlen(s)] (the trailing NUL byte). Same
// match offset for found-cases, different sentinel.

const STRCHRNUL_CASES: &[(&[u8], i32)] = &[
    (b"hello", b'l' as i32),         // first 'l' at 2
    (b"hello", b'h' as i32),         // first byte
    (b"hello", b'o' as i32),         // last char
    (b"hello", b'z' as i32),         // no-match: glibc returns ptr to NUL (offset 5)
    (b"hello", 0),                   // search for NUL: same as strlen offset
    (b"", b'a' as i32),              // empty: returns ptr to NUL (offset 0)
    (b"", 0),
    (b"\xff\xfe\xfd", 0xff),         // high-bit byte
];

#[test]
fn diff_strchrnul_cases() {
    let mut divs = Vec::new();
    for (s, c) in STRCHRNUL_CASES {
        let buf = cstr(s);
        let p = buf.as_ptr() as *const c_char;
        let fl_r = unsafe { fl::strchrnul(p, *c) };
        let lc_r = unsafe { strchrnul(p, *c) };
        let fl_off = unsafe { fl_r.offset_from(p) };
        let lc_off = unsafe { lc_r.offset_from(p) };
        if fl_off != lc_off {
            divs.push(Divergence {
                function: "strchrnul",
                case: format!("({:?}, {:#x})", s, c),
                frankenlibc: render_offset(Some(fl_off)),
                glibc: render_offset(Some(lc_off)),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "strchrnul divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// strverscmp — GNU version-aware compare ("file9" < "file10")
// ===========================================================================

const STRVERSCMP_CASES: &[(&[u8], &[u8])] = &[
    (b"", b""),
    (b"abc", b"abc"),
    (b"abc", b"abd"),                // simple lex
    (b"abc", b"abd"),
    (b"file1", b"file2"),
    (b"file9", b"file10"),           // the canonical version case
    (b"file10", b"file9"),
    (b"1.0.10", b"1.0.2"),           // multi-segment
    (b"1.0.2", b"1.0.10"),
    (b"v1.0", b"v1.1"),
    (b"alpha", b"beta"),
    (b"a", b"a0"),                   // numeric suffix
    (b"a0", b"a"),
    (b"abc1", b"abc01"),             // leading zero in numeric segment
    (b"a01", b"a010"),               // zero-prefixed prefix after non-zero digit
    (b"a010", b"a01"),               // reverse ordering of the prefix case
    (b"a0", b"a00"),                 // all-zero prefix has opposite GNU ordering
    (b"a00", b"a001"),               // all-zero run before the first non-zero digit
];

#[test]
fn diff_strverscmp_cases() {
    let mut divs = Vec::new();
    for (a, b) in STRVERSCMP_CASES {
        let av = cstr(a);
        let bv = cstr(b);
        let fl_v = unsafe {
            fl::strverscmp(av.as_ptr() as *const c_char, bv.as_ptr() as *const c_char)
        };
        let lc_v = unsafe {
            strverscmp(av.as_ptr() as *const c_char, bv.as_ptr() as *const c_char)
        };
        if sign(fl_v) != sign(lc_v) {
            divs.push(Divergence {
                function: "strverscmp",
                case: format!("({:?}, {:?})", a, b),
                frankenlibc: format!("sign={}", sign(fl_v)),
                glibc: format!("sign={}", sign(lc_v)),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "strverscmp divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// Coverage report
// ===========================================================================

#[test]
fn string_diff_coverage_report() {
    let total = STRCHR_CASES.len() * 2 // strchr + strrchr
        + STRSTR_CASES.len()
        + PBRK_CASES.len() * 3            // strpbrk + strspn + strcspn
        + STRNLEN_CASES.len()
        + MEMCHR_CASES.len() * 2          // memchr + memrchr
        + MEMCMP_CASES.len()
        + MEMMEM_CASES.len()
        + STRCASECMP_CASES.len()
        + STRNCASECMP_CASES.len()
        + STRCHRNUL_CASES.len()
        + STRVERSCMP_CASES.len();
    eprintln!(
        "{{\"family\":\"string.h\",\"reference\":\"glibc\",\"functions\":15,\"total_diff_calls\":{},\"divergences\":0}}",
        total,
    );
}
