#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc wordexp oracle

//! Differential gate for wordexp `$(( ... ))` arithmetic expansion (bd-yb9f9r).
//! Validates the new fl arithmetic evaluator + expander wiring + the
//! WRDE_NOCMD scan fix against glibc: each expression must produce the same
//! single result word AND return code as glibc's wordexp, including operator
//! precedence, bases, short-circuit, ternary, variables, and the WRDE_NOCMD
//! rule (arithmetic allowed, command substitution rejected). No mocks.

use std::ffi::{c_char, c_int, CString};

const WRDE_NOCMD: c_int = 1 << 2;

#[repr(C)]
struct WordexpT {
    we_wordc: usize,
    we_wordv: *mut *mut c_char,
    we_offs: usize,
}

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn wordexp(words: *const c_char, we: *mut WordexpT, flags: c_int) -> c_int;
        pub fn wordfree(we: *mut WordexpT);
        pub fn setenv(n: *const c_char, v: *const c_char, o: c_int) -> c_int;
    }
}
use frankenlibc_abi::unistd_abi as fl;

fn collect(we: &WordexpT) -> Vec<String> {
    let mut words = Vec::new();
    for k in 0..we.we_wordc {
        let p = unsafe { *we.we_wordv.add(k) };
        if !p.is_null() {
            words.push(unsafe { std::ffi::CStr::from_ptr(p) }.to_string_lossy().into_owned());
        }
    }
    words
}

/// (return code, words) for fl.
fn run_fl(s: &str, flags: c_int) -> (c_int, Vec<String>) {
    let c = CString::new(s).unwrap();
    let mut we = WordexpT { we_wordc: 0, we_wordv: std::ptr::null_mut(), we_offs: 0 };
    let rc = unsafe { fl::wordexp(c.as_ptr().cast(), (&mut we as *mut WordexpT).cast(), flags) };
    let words = if rc == 0 { collect(&we) } else { Vec::new() };
    if rc == 0 {
        unsafe { fl::wordfree((&mut we as *mut WordexpT).cast()) };
    }
    (rc, words)
}

fn run_glibc(s: &str, flags: c_int) -> (c_int, Vec<String>) {
    let c = CString::new(s).unwrap();
    let mut we = WordexpT { we_wordc: 0, we_wordv: std::ptr::null_mut(), we_offs: 0 };
    let rc = unsafe { g::wordexp(c.as_ptr(), &mut we, flags) };
    let words = if rc == 0 { collect(&we) } else { Vec::new() };
    if rc == 0 {
        unsafe { g::wordfree(&mut we) };
    }
    (rc, words)
}

#[test]
fn wordexp_arithmetic_matches_glibc() {
    let cases = [
        "$((1+2))", "$((2*3+4))", "$((2+3*4))", "$((10/3))", "$((10%3))",
        "$((1<<4))", "$((256>>2))", "$((5>3))", "$((3>=3))", "$((2==2))",
        "$((2!=3))", "$((1&&0))", "$((0||5))", "$((1&&5))", "$(( (1+2)*3 ))",
        "$((~0))", "$((!0))", "$((!7))", "$((1?5:9))", "$((0?5:9))",
        "$((0x10+1))", "$((010))", "$((-5))", "$((7&3))", "$((1|2))",
        "$((5^3))", "$(( 100 - 4 * 5 ))", "x$((1+1))y", "$((2*(3+4)))",
        "$(())",
    ];
    for s in cases {
        let f = run_fl(s, 0);
        let gg = run_glibc(s, 0);
        assert_eq!(f, gg, "wordexp({s:?}, 0): fl={f:?} glibc={gg:?}");
    }
}

#[test]
fn wordexp_arith_with_variables_matches_glibc() {
    unsafe {
        g::setenv(c"WE_AR_X".as_ptr(), c"5".as_ptr(), 1);
        g::setenv(c"WE_AR_Y".as_ptr(), c"3".as_ptr(), 1);
    }
    for s in ["$((WE_AR_X+1))", "$(($WE_AR_X*2))", "$((WE_AR_X*WE_AR_Y))", "$((WE_AR_UNSET+7))"] {
        let f = run_fl(s, 0);
        let gg = run_glibc(s, 0);
        assert_eq!(f, gg, "wordexp({s:?}) with vars: fl={f:?} glibc={gg:?}");
    }
}

#[test]
fn wordexp_nocmd_allows_arith_rejects_cmdsub() {
    // Arithmetic is permitted under WRDE_NOCMD; command substitution is not.
    let arith = run_fl("$((1+2))", WRDE_NOCMD);
    let arith_g = run_glibc("$((1+2))", WRDE_NOCMD);
    assert_eq!(arith, arith_g, "WRDE_NOCMD $((1+2)): fl={arith:?} glibc={arith_g:?}");

    for cmd in ["$(echo hi)", "`echo hi`"] {
        let f = run_fl(cmd, WRDE_NOCMD);
        let gg = run_glibc(cmd, WRDE_NOCMD);
        assert_eq!(f.0, gg.0, "WRDE_NOCMD {cmd:?} rc: fl={} glibc={}", f.0, gg.0);
    }
}
