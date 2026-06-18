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
        // nested arithmetic (exercises the pre-expansion recursion)
        "$(( $((1+2)) + 3 ))", "$(( $((2*3)) * $((4-1)) ))",
        // unary chains, precedence, signed
        "$((- -5))", "$((!!5))", "$((~~7))", "$((-3*-2))", "$((2+3==5))",
        "$((1<2 && 3<4))", "$((0 || 0 || 7))", "$((5 & 3 | 8))",
        "$((1 ? 2 ? 3 : 4 : 5))", "$((100 % 7 + 1))", "$((1<<2<<2))",
        // hex/octal mixed
        "$((0xff & 0x0f))", "$((010 + 0x10))",
        // assignment / compound-assignment / increment / comma (bd-6a9tuc)
        "$((aa=5))", "$((aa=5, aa*2))", "$((bb=3, ++bb))", "$((cc=10, cc--))",
        "$((dd=10, --dd))", "$((ee=2, ee+=3))", "$((ff=10, ff%=3))",
        "$((gg=1, gg<<=4))", "$((hh=5, hh++, hh))", "$((1,2,3))",
        "$((ii=7, ii-=2, ii*=3))", "$((jj=0, jj||5))", "$((kk=8, kk>>=1))",
        // assignment precedence: rhs is a full expression / ternary; multi-assign
        "$((ll = 2 + 3 * 4))", "$((mm = 1 ? 7 : 9))", "$((nn=1, oo=2, nn+oo))",
        "$((pp = qq = 5))", "$((rr=10, rr>>=1, rr))", "$((ss = 3 < 5))",
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
    for s in [
        "$((WE_AR_X+1))",
        "$(($WE_AR_X*2))",
        "$((WE_AR_X*WE_AR_Y))",
        "$((WE_AR_UNSET+7))",
        // parameter expansion inside arithmetic (bd-4f7oo7): $ / ${} forms are
        // expanded before evaluation; bare names resolved by the evaluator.
        "$(( ${WE_AR_X:-99} + 1 ))",
        "$(( ${WE_AR_UNSET:-5} + 1 ))",
        "$(( ${WE_AR_X} * 2 ))",
        "$(( $WE_AR_X + $WE_AR_Y ))",
    ] {
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

/// fl's $((...)) is POSIX arithmetic, like glibc's wordexp — it must REJECT
/// bash-only extensions, with the same return code as glibc (not silently
/// accept them). Pins the reject-path error-parity (bd-6a9tuc / bd-yb9f9r).
#[test]
fn wordexp_arith_rejects_bash_extensions_like_glibc() {
    let cases = [
        "$((2**3))",     // exponentiation: bash-only, not POSIX arithmetic
        "$((16#ff))",    // base#number: bash-only
        "$((08))",       // invalid octal digit
        "$((1 +))",      // dangling operator
        "$((* 3))",      // leading binary operator
        "$((2+(3))",     // unbalanced parentheses
        "$((1 2))",      // two operands, no operator
        "$((/0))",       // leading slash
    ];
    for s in cases {
        let f = run_fl(s, 0);
        let gg = run_glibc(s, 0);
        // Compare the full (rc, words) outcome — fl must reject exactly when and
        // how glibc does (same rc; no words on failure).
        assert_eq!(f, gg, "wordexp({s:?}) reject-parity: fl={f:?} glibc={gg:?}");
    }
}
