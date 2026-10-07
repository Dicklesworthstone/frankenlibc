#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc regcomp/regexec oracle

//! Bracket-expression equivalence-class `[[=c=]]` and collating-symbol
//! `[[.c.]]` parity vs host glibc (bd-2g7oyh.NEW).
//!
//! fl previously had no support for these and treated the leading `[` as a
//! literal class member, so `[[=a=]]` matched everything (glibc: just `a`) and
//! malformed forms returned rc 0 instead of the right error. In the C locale:
//!   * `[[=c=]]` / `[[.c.]]` with a single character -> that character;
//!   * a collating symbol `[.c.]` may be a range endpoint (`[[.a.]-z]` == `[a-z]`);
//!   * an equivalence class or a POSIX class may NOT (-> REG_ERANGE);
//!   * empty / multi-character (named, e.g. `[[.tab.]]`) bodies -> REG_ECOLLATE;
//!   * a body with no closing `=]` / `.]` -> REG_EBRACK.
//!
//! This gate compiles each pattern with both engines and compares the compile
//! return code and, on success, the match/no-match verdict for a fixed corpus.
//!
//! Then the same under en_US.UTF-8, where LC_COLLATE defines the classes:
//! `[[=a=]]` is every character of a's primary weight (A, à, Å, ā, ⓐ ...;
//! grep's equiv-classes test). Skipped when the host lacks the locale.

use frankenlibc_abi::string_abi as fl;
use std::ffi::CString;

unsafe extern "C" {
    fn regcomp(p: *mut libc::regex_t, re: *const i8, f: i32) -> i32;
    fn regexec(
        p: *const libc::regex_t,
        s: *const i8,
        n: usize,
        m: *mut libc::regmatch_t,
        ef: i32,
    ) -> i32;
    fn regfree(p: *mut libc::regex_t);
    fn setlocale(category: i32, locale: *const i8) -> *mut i8;
}

const CORPUS: &[&str] = &[
    "a", "b", "z", "=", "[", ".", "c", "-", "]", "A", "1", "\t", " ",
];

// (compile_rc, per-corpus regexec rc) — only populated when compile succeeds.
fn run(eng: u8, pat: &str, corpus: &[&str]) -> (i32, Vec<i32>) {
    let cp = CString::new(pat).unwrap();
    let mut re: libc::regex_t = unsafe { std::mem::zeroed() };
    let rc = if eng == 0 {
        unsafe {
            fl::regcomp(
                (&mut re as *mut libc::regex_t).cast(),
                cp.as_ptr(),
                libc::REG_EXTENDED,
            )
        }
    } else {
        unsafe { regcomp(&mut re, cp.as_ptr(), libc::REG_EXTENDED) }
    };
    if rc != 0 {
        return (rc, vec![]);
    }
    let res = corpus
        .iter()
        .map(|s| {
            let cs = CString::new(*s).unwrap();
            if eng == 0 {
                unsafe {
                    fl::regexec(
                        (&re as *const libc::regex_t).cast(),
                        cs.as_ptr(),
                        0,
                        std::ptr::null_mut(),
                        0,
                    )
                }
            } else {
                unsafe { regexec(&re, cs.as_ptr(), 0, std::ptr::null_mut(), 0) }
            }
        })
        .collect();
    if eng == 0 {
        unsafe { fl::regfree((&mut re as *mut libc::regex_t).cast()) };
    } else {
        unsafe { regfree(&mut re) };
    }
    (rc, res)
}

fn check(pat: &str, corpus: &[&str]) {
    let a = run(0, pat, corpus);
    let b = run(1, pat, corpus);
    assert_eq!(a, b, "regex {pat:?} diverged: fl={a:?} glibc={b:?}");
}

#[test]
fn regex_collating_equivalence_matches_glibc() {
    let patterns = [
        // Valid single-character equivalence / collating classes.
        "[[=a=]]",
        "[[.a.]]",
        "[[=a=]b]",
        "[a[=b=]]",
        "[x[.a.]y]",
        "[[=a=][=b=]]",
        "[[:alpha:][=a=]]",
        // Collating symbol as a range endpoint (allowed).
        "[[.a.]-z]",
        "[[.a.]-[.z.]]",
        "[a-[.z.]]",
        // Equivalence / POSIX class as a range start (REG_ERANGE).
        "[[=a=]-z]",
        "[[:alpha:]-z]",
        // POSIX class as a range END (REG_ERANGE via reversed bounds).
        "[a-[:digit:]]",
        // Empty / multi-character (named) bodies -> REG_ECOLLATE.
        "[[..]]",
        "[[==]]",
        "[[.period.]]",
        "[[.tab.]]",
        "[[.NUL.]]",
        "[[=ch=]]",
        "[[=ab=]]",
        // No terminator -> REG_EBRACK.
        "[[=]]",
        "[[.]]",
        // Plain classes / edges still correct.
        "[[:alpha:]]",
        "[a[:digit:]]",
        "[]a]",
        "[^]a]",
        "[-a]",
        "[a-]",
        "[a-z]",
    ];
    for pat in patterns {
        check(pat, CORPUS);
    }

    // The locale is process-global, so the UTF-8 locales run after the
    // C-locale half in this one test.
    for locale in [c"en_US.UTF-8", c"C.UTF-8"] {
        // SAFETY: setlocale with NUL-terminated names; no other thread of this
        // binary uses the locale concurrently (single test).
        if unsafe { setlocale(libc::LC_ALL, locale.as_ptr()) }.is_null() {
            println!("SKIP: host has no {locale:?} locale");
            continue;
        }
        let ours =
            !unsafe { frankenlibc_abi::locale_abi::setlocale(libc::LC_ALL, locale.as_ptr()) }
                .is_null();
        assert!(
            ours,
            "fl setlocale({locale:?}) failed where glibc's succeeded"
        );
        utf8_locale_checks(locale == c"en_US.UTF-8");
    }
    // SAFETY: as above.
    unsafe {
        setlocale(libc::LC_ALL, c"C".as_ptr());
        frankenlibc_abi::locale_abi::setlocale(libc::LC_ALL, c"C".as_ptr());
    }
}

/// Collation-dependent brackets in the current UTF-8 locale. With collation
/// rules (en_US) `[=c=]` is every character of c's primary weight and a range
/// spans collation-sequence values (`[a-z]` holds à, é and ß but not B);
/// without (C.UTF-8) classes are exact and a multibyte range endpoint or
/// equivalence-class name is REG_ECOLLATE. A multibyte collating symbol
/// `[.à.]` is REG_ECOLLATE in both.
fn utf8_locale_checks(collation_rules: bool) {
    let corpus: &[&str] = &[
        "a", "A", "à", "Å", "ā", "ǻ", "ⓐ", "ａ", "b", "e", "é", "Ê", "ß", "ẞ", "ı", "i", "æ", "Æ",
        "ø", "o", "1", "¹", "١", "!", ",", "\u{300}", "€", "中", "xày", "zz", "B", "Z", "z",
    ];
    let patterns = [
        "[[=a=]]",
        "^[[=a=]]$",
        "[^[=a=]]",
        "^[^[=a=]]$",
        "[[=à=]]",
        "[[=A=]x]",
        "[[=e=][=o=]]",
        "^[[=ø=]]+$",
        "[[=ß=]]",
        "[[=æ=]]",
        "[[=1=]]",
        "^[[=!=]]$",
        "x[[=a=]]y",
        "[[=ı=]]",
        "[[=a=]-z]",
        "^[a-z]$",
        "^[A-Z]$",
        "^[^a-z]$",
        "^[a-z]+$",
        "^[0-9]$",
        "^[à-é]$",
        "^[a-ö]$",
        "^[[.a.]-z]$",
        "[[.à.]]",
        "[z-a]",
        "^[a-z[=ø=]]$",
    ];
    for pat in patterns {
        check(pat, corpus);
    }
    // Every character below U+3000, one at a time.
    let all: Vec<String> = (1u32..0x3000)
        .filter_map(char::from_u32)
        .map(String::from)
        .collect();
    let all: Vec<&str> = all.iter().map(String::as_str).collect();
    for pat in [
        "^[[=a=]]$",
        "^[[=o=]]$",
        "^[a-z]$",
        "^[A-Z]$",
        "^[0-9]$",
        "^[^a-z]$",
    ] {
        check(pat, &all);
    }
    if collation_rules {
        // Not vacuous: the class and the range span accented letters.
        let (rc, res) = run(0, "^[[=a=]]$", corpus);
        assert_eq!(rc, 0);
        assert_eq!(
            (res[2], res[8]),
            (0, libc::REG_NOMATCH),
            "à in [[=a=]], b not"
        );
        let (rc, res) = run(0, "^[a-z]$", corpus);
        assert_eq!(rc, 0);
        assert_eq!(
            (res[10], res[30]),
            (0, libc::REG_NOMATCH),
            "é in [a-z], B not"
        );
    }
}
