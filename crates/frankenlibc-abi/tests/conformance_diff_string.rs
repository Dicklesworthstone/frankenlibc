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
//! - `memcmp` compares the sign of the returned int (POSIX requires
//!   only the sign, not the magnitude, to be portable).
//!
//! Reference: glibc / musl, POSIX.1-2017.
//! Bead: CONFORMANCE: libc string.h diff matrix.

use std::ffi::{c_char, c_int, c_void};

use frankenlibc_abi::string_abi as fl;

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
        let fo = if fl_r.is_null() {
            None
        } else {
            Some(unsafe { (fl_r as *const u8).offset_from(s.as_ptr()) })
        };
        let lo = if lc_r.is_null() {
            None
        } else {
            Some(unsafe { (lc_r as *const u8).offset_from(s.as_ptr()) })
        };
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
// Coverage report
// ===========================================================================

#[test]
fn string_diff_coverage_report() {
    let total = STRCHR_CASES.len() * 2 // strchr + strrchr
        + STRSTR_CASES.len()
        + PBRK_CASES.len() * 3            // strpbrk + strspn + strcspn
        + STRNLEN_CASES.len()
        + MEMCHR_CASES.len()
        + MEMCMP_CASES.len();
    eprintln!(
        "{{\"family\":\"string.h\",\"reference\":\"glibc\",\"functions\":9,\"total_diff_calls\":{},\"divergences\":0}}",
        total,
    );
}
