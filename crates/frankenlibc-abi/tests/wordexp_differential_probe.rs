//! Differential probe: frankenlibc wordexp vs glibc wordexp over a
//! deterministic, fs-independent subset (no glob, no command substitution):
//! $VAR / ${VAR} expansion, tilde, IFS field splitting on unquoted expansions,
//! quoting (single/double), escapes, undefined/empty variables, and
//! concatenation. Env is set in-process so both sides see the same values.
//! glibc reference captured from a C probe (WRDE_NOCMD).

use std::ffi::{CStr, CString, c_char, c_void};
use std::ptr;

use frankenlibc_abi::unistd_abi;

const WRDE_NOCMD: i32 = 1 << 2;

#[repr(C)]
struct WordExpT {
    we_wordc: usize,
    we_wordv: *mut *mut c_char,
    we_offs: usize,
}

fn run(word: &str) -> String {
    let w = CString::new(word).unwrap();
    let mut we = WordExpT {
        we_wordc: 0,
        we_wordv: ptr::null_mut(),
        we_offs: 0,
    };
    let r = unsafe {
        unistd_abi::wordexp(
            w.as_ptr(),
            &mut we as *mut WordExpT as *mut c_void,
            WRDE_NOCMD,
        )
    };
    if r != 0 {
        return format!("err={r}");
    }
    let mut s = format!("wc={}:", we.we_wordc);
    for i in 0..we.we_wordc {
        let p = unsafe { *we.we_wordv.add(i) };
        let ws = if p.is_null() {
            "(null)".to_string()
        } else {
            unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
        };
        s += &format!(" {{{ws}}}");
    }
    s
}

#[test]
fn wordexp_differential_battery() {
    unsafe {
        std::env::set_var("FOO", "bar");
        std::env::set_var("EMPTY", "");
        std::env::set_var("AB", "x y");
        std::env::set_var("HOME", "/home/test");
        std::env::remove_var("UNDEFINED");
    }

    // (word, glibc result). "\"$EMPTY\"" is glibc's quirky err=1 case.
    let cases: &[(&str, &str)] = &[
        ("hello", "wc=1: {hello}"),
        ("$FOO", "wc=1: {bar}"),
        ("${FOO}", "wc=1: {bar}"),
        ("a${FOO}b", "wc=1: {abarb}"),
        ("$AB", "wc=2: {x} {y}"),
        ("\"$AB\"", "wc=1: {x y}"),
        ("$EMPTY", "wc=0:"),
        ("~", "wc=1: {/home/test}"),
        ("pre $FOO post", "wc=3: {pre} {bar} {post}"),
        ("'$FOO'", "wc=1: {$FOO}"),
        ("a\\ b", "wc=1: {a b}"),
        ("$UNDEFINED", "wc=0:"),
        ("$FOO$AB", "wc=2: {barx} {y}"),
        ("x\"$AB\"y", "wc=1: {xx yy}"),
        ("${FOO}${FOO}", "wc=1: {barbar}"),
    ];

    let mut diffs = Vec::new();
    for (word, expected) in cases {
        let got = run(word);
        if got != *expected {
            diffs.push(format!("wordexp({word:?}): frankenlibc={got:?} glibc={expected:?}"));
        }
    }
    assert!(
        diffs.is_empty(),
        "wordexp diverges from glibc in {} case(s):\n{}",
        diffs.len(),
        diffs.join("\n")
    );
}
