#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc wordexp oracle

//! `wordexp` parameter-expansion operator parity vs host glibc (bd-2g7oyh.NEW).
//!
//! glibc's `wordexp` implements the POSIX `${...}` operator set
//! (`${#var}`, `${var:-w}` / `${var:=w}` / `${var:+w}` / `${var:?w}` and their
//! colon-less forms, `${var%w}` / `${var%%w}` / `${var#w}` / `${var##w}`) and
//! rejects bash-only extensions — substring `${var:off[:len]}`, pattern
//! substitution `${var/p/r}`, case `${var^^}` / `${var,,}`, transform
//! `${var@U}`, subscript `${var[i]}` and a dangling `${var:}` — with
//! WRDE_SYNTAX (5). fl previously accepted the extensions silently (rc 0, empty)
//! and mis-handled `${var:?}` (returned empty even when set). This gate sets a
//! fixed environment and compares the return code + word vector for each form.
//!
//! Out of scope (documented divergences, NOT asserted): empty-name / special
//! parameter forms `${@}` `${*}` `${0}` `${!var}` `${#}` (process-state /
//! positional params fl does not model) and arithmetic `$((expr))`.

use frankenlibc_abi::unistd_abi as flu;
use std::ffi::{CStr, CString};

#[repr(C)]
struct WordExp {
    we_wordc: usize,
    we_wordv: *mut *mut i8,
    we_offs: usize,
}

unsafe extern "C" {
    fn wordexp(s: *const i8, p: *mut WordExp, f: i32) -> i32;
    fn wordfree(p: *mut WordExp);
    fn setenv(n: *const i8, v: *const i8, o: i32) -> i32;
}

const WRDE_NOCMD: i32 = 0x4;

fn words(wc: usize, wv: *mut *mut i8) -> Vec<String> {
    (0..wc)
        .map(|i| {
            let p = unsafe { *wv.add(i) };
            if p.is_null() {
                "<null>".into()
            } else {
                unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
            }
        })
        .collect()
}

fn run(eng: u8, inp: &str) -> (i32, Vec<String>) {
    let s = CString::new(inp).unwrap();
    let mut w = WordExp {
        we_wordc: 0,
        we_wordv: std::ptr::null_mut(),
        we_offs: 0,
    };
    let rc = if eng == 0 {
        unsafe { flu::wordexp(s.as_ptr(), (&mut w as *mut WordExp).cast(), WRDE_NOCMD) }
    } else {
        unsafe { wordexp(s.as_ptr(), &mut w, WRDE_NOCMD) }
    };
    let out = if rc == 0 {
        words(w.we_wordc, w.we_wordv)
    } else {
        vec![]
    };
    if rc == 0 {
        if eng == 0 {
            unsafe { flu::wordfree((&mut w as *mut WordExp).cast()) };
        } else {
            unsafe { wordfree(&mut w) };
        }
    }
    (rc, out)
}

fn check(inp: &str) {
    let a = run(0, inp);
    let b = run(1, inp);
    assert_eq!(a, b, "wordexp({inp:?}) diverged: fl={a:?} glibc={b:?}");
}

#[test]
fn wordexp_operators_match_glibc() {
    unsafe {
        setenv(c"FOO".as_ptr(), c"bar".as_ptr(), 1);
        setenv(c"EMPTY".as_ptr(), c"".as_ptr(), 1);
        setenv(c"PATHY".as_ptr(), c"/usr/local/bin".as_ptr(), 1);
        setenv(c"FILE".as_ptr(), c"archive.tar.gz".as_ptr(), 1);
    }

    // Supported POSIX forms (must keep working).
    for inp in [
        "$FOO",
        "${FOO}x",
        "${#FOO}",
        "${UNSET:-d}",
        "${EMPTY:-d}",
        "${EMPTY-d}",
        "${FOO:+y}",
        "${UNSET:+y}",
        "${FOO-x}",
        "${FOO+x}",
        "${FOO=x}",
        "${FOO:=x}",
        "${FILE%.gz}",
        "${FILE%%.*}",
        "${FILE#*.}",
        "${FILE##*.}",
        "${PATHY#/usr}",
        "${FOO%}",
        "${FOO#}",
        "${FOO:-}",
        // `:?` / `?`: value when set, empty when unset (glibc does not abort).
        "${FOO:?}",
        "${FOO?}",
        "${FOO:?msg}",
        "${UNSET:?msg}",
        "${UNSET?msg}",
        "'$FOO'",
        "\"$FOO x\"",
        "a b c",
    ] {
        check(inp);
    }

    // Bash-only operators after a real name -> WRDE_SYNTAX in both engines.
    for inp in [
        "${FOO:1}",
        "${FOO:1:2}",
        "${FOO:2:1}",
        "${FOO:}",
        "${FOO/b/X}",
        "${FOO//b/X}",
        "${FOO^}",
        "${FOO^^}",
        "${FOO,}",
        "${FOO,,}",
        "${FOO@U}",
        "${FOO[0]}",
        "${FILE/tar/zip}",
    ] {
        check(inp);
    }
}
