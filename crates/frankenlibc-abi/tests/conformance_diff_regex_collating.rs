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
//! This gate compiles each pattern with both engines and compares the compile
//! return code and, on success, the match/no-match verdict for a fixed corpus.

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
}

const CORPUS: &[&str] = &[
    "a", "b", "z", "=", "[", ".", "c", "-", "]", "A", "1", "\t", " ",
];

// (compile_rc, per-corpus regexec rc) — only populated when compile succeeds.
fn run(eng: u8, pat: &str) -> (i32, Vec<i32>) {
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
    let res = CORPUS
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

fn check(pat: &str) {
    let a = run(0, pat);
    let b = run(1, pat);
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
        check(pat);
    }
}
