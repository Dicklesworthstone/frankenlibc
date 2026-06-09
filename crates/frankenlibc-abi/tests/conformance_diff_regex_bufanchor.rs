#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc regcomp/regexec oracle

//! GNU buffer anchors `` \` `` (start of buffer) and `\'` (end of buffer) vs
//! host glibc (bd-2g7oyh.NEW). fl previously did not implement them. Unlike
//! `^`/`$`, they always match the buffer edges regardless of REG_NOTBOL /
//! REG_NOTEOL / REG_NEWLINE. This gate compares whole-match bounds across
//! several patterns, execution flags, and inputs — including a back-reference
//! pattern that routes through fl's separate backtracking matcher.

use std::ffi::CString;
use frankenlibc_abi::string_abi as fl;

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

fn run(eng: u8, pat: &str, cflags: i32, s: &str, eflags: i32) -> (i32, i64, i64) {
    let cp = CString::new(pat).unwrap();
    let mut re: libc::regex_t = unsafe { std::mem::zeroed() };
    let rc = if eng == 0 {
        unsafe { fl::regcomp((&mut re as *mut libc::regex_t).cast(), cp.as_ptr(), cflags) }
    } else {
        unsafe { regcomp(&mut re, cp.as_ptr(), cflags) }
    };
    if rc != 0 {
        return (1000 + rc, -1, -1);
    }
    let cs = CString::new(s).unwrap();
    let mut m = [libc::regmatch_t { rm_so: -1, rm_eo: -1 }; 1];
    let r = if eng == 0 {
        unsafe {
            fl::regexec((&re as *const libc::regex_t).cast(), cs.as_ptr(), 1, m.as_mut_ptr().cast(), eflags)
        }
    } else {
        unsafe { regexec(&re, cs.as_ptr(), 1, m.as_mut_ptr(), eflags) }
    };
    if eng == 0 {
        unsafe { fl::regfree((&mut re as *mut libc::regex_t).cast()) };
    } else {
        unsafe { regfree(&mut re) };
    }
    (r, m[0].rm_so as i64, m[0].rm_eo as i64)
}

const ERE: i32 = libc::REG_EXTENDED;
const NEWLINE: i32 = libc::REG_NEWLINE;
const NOTBOL: i32 = libc::REG_NOTBOL;
const NOTEOL: i32 = libc::REG_NOTEOL;

fn check(pat: &str, cflags: i32, s: &str, eflags: i32) {
    let a = run(0, pat, cflags, s, eflags);
    let b = run(1, pat, cflags, s, eflags);
    assert_eq!(
        a, b,
        "regexec({pat:?}, cflags={cflags:#x}, {s:?}, eflags={eflags:#x}): fl={a:?} glibc={b:?}"
    );
}

#[test]
fn regex_buffer_anchors_match_glibc() {
    let inputs = ["foo bar", "foobar", " foo", "a\nb", "", "barbar"];

    for s in inputs {
        for ef in [0, NOTBOL, NOTEOL, NOTBOL | NOTEOL] {
            check(r"\`foo", ERE, s, ef);
            check(r"bar\'", ERE, s, ef);
            check(r"\`foo\'", ERE, s, ef);
            check(r"\`.*\'", ERE, s, ef);
            check(r"\`", ERE, s, ef);
            check(r"\'", ERE, s, ef);
        }
        // Buffer anchors ignore REG_NEWLINE (only the true buffer edges).
        check(r"\`b", ERE | NEWLINE, s, 0);
        check(r"b\'", ERE | NEWLINE, s, 0);
        // BRE form + a back-reference forces the backtracking matcher path.
        check(r"\`\(foo\) \1", 0, s, 0);
        check(r"\`a", 0, s, 0);
        check(r"a\'", 0, s, 0);
    }
}
