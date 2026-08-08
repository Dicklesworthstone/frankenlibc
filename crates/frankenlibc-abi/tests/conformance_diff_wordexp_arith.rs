#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc wordexp oracle

//! Differential gate for `wordexp` arithmetic expansion `$((...))` and its
//! interaction with `WRDE_NOCMD` (bd-yb9f9r).
//!
//! Two defects motivated this:
//!   1. fl had no arithmetic expansion at all.
//!   2. fl's WRDE_NOCMD scan treated `$((` as command substitution, so
//!      `$((1+2))` returned WRDE_CMDSUB where glibc expands it to "3".
//! A classification-only fix would have been worse than the bug — it would have
//! left `$((1+2))` unexpanded — so both are covered here.
//!
//! Everything asserted is measured against the live host `wordexp`; nothing is
//! hardcoded from the POSIX text. That matters because glibc's arithmetic is
//! NOT POSIX shell arithmetic: it implements only `+ - * /`, parentheses, unary
//! sign and dec/hex/octal literals, and it SILENTLY STOPS at any other operator,
//! returning the value parsed so far (`$((1+2*3<4))` -> "7").

use std::ffi::{CString, c_char, c_int, c_void};

const WRDE_NOCMD: c_int = 1 << 2;
// glibc <wordexp.h>: NOSPACE=1, BADCHAR=2, BADVAL=3, CMDSUB=4, SYNTAX=5.
const WRDE_CMDSUB: c_int = 4;

#[repr(C)]
struct WordExpT {
    we_wordc: usize,
    we_wordv: *mut *mut c_char,
    we_offs: usize,
}

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn wordexp(words: *const c_char, we: *mut WordExpT, flags: c_int) -> c_int;
        pub fn wordfree(we: *mut WordExpT);
    }
}

/// (return code, expanded words) from an implementation.
type Outcome = (c_int, Vec<String>);

fn read_words(we: &WordExpT) -> Vec<String> {
    let mut v = Vec::new();
    for i in 0..we.we_wordc {
        // SAFETY: wordexp reports we_wordc valid NUL-terminated pointers.
        let p = unsafe { *we.we_wordv.add(i) };
        if p.is_null() {
            continue;
        }
        v.push(
            unsafe { std::ffi::CStr::from_ptr(p) }
                .to_string_lossy()
                .into_owned(),
        );
    }
    v
}

fn host(word: &str, flags: c_int) -> Outcome {
    let w = CString::new(word).unwrap();
    let mut we = WordExpT {
        we_wordc: 0,
        we_wordv: std::ptr::null_mut(),
        we_offs: 0,
    };
    // SAFETY: `we` is a valid out-parameter; freed below on success.
    let rc = unsafe { g::wordexp(w.as_ptr(), &mut we, flags) };
    if rc != 0 {
        return (rc, Vec::new());
    }
    let out = read_words(&we);
    unsafe { g::wordfree(&mut we) };
    (0, out)
}

fn fl(word: &str, flags: c_int) -> Outcome {
    let w = CString::new(word).unwrap();
    let mut we = WordExpT {
        we_wordc: 0,
        we_wordv: std::ptr::null_mut(),
        we_offs: 0,
    };
    // SAFETY: as above, against fl's implementation.
    let rc = unsafe {
        frankenlibc_abi::unistd_abi::wordexp(
            w.as_ptr(),
            (&raw mut we).cast::<c_void>(),
            flags,
        )
    };
    if rc != 0 {
        return (rc, Vec::new());
    }
    let out = read_words(&we);
    unsafe { frankenlibc_abi::unistd_abi::wordfree((&raw mut we).cast::<c_void>()) };
    (0, out)
}

/// Every word here is expanded by BOTH implementations and compared. The list
/// deliberately mixes cases glibc evaluates, cases where it stops early, and
/// cases it rejects, because the early-stop behaviour is the surprising part
/// and a reimplementation that "fixed" it would diverge.
const WORDS: &[&str] = &[
    // evaluated
    "$((1+2))",
    "$(( 1 + 2 ))",
    "$((2*3+4))",
    "$((2+3*4))",
    "$(((2+3)*4))",
    "$((2*(3+4)))",
    "$((100-1))",
    "$((10/3))",
    "$((-5))",
    "$((+5))",
    "$((0))",
    "$((0x10))",
    "$((-0x10))",
    "$((010))",
    "a$((1+1))b",
    "$((1+2)) $((3+4))",
    // glibc stops at the first operator it does not implement and keeps the
    // value parsed so far — NOT an error, and not the POSIX answer.
    "$((10%3))",
    "$((5%2+1))",
    "$((1<<4))",
    "$((256>>2))",
    "$((1<2))",
    "$((2<=2))",
    "$((3>4))",
    "$((3!=4))",
    "$((3==3))",
    "$((6&3))",
    "$((6|3))",
    "$((6^3))",
    "$((1&&0))",
    "$((1||0))",
    "$((1?42:7))",
    "$((1+2*3<4))",
    // rejected
    "$((~5))",
    "$((!0))",
    "$((1/0))",
    "$((1+))",
    "$(( ))",
    "$((abc))",
];

#[test]
fn wordexp_arithmetic_matches_glibc() {
    for &w in WORDS {
        let h = host(w, 0);
        let f = fl(w, 0);
        assert_eq!(
            f, h,
            "wordexp({w:?}, 0): fl=(rc={}, {:?}) glibc=(rc={}, {:?})",
            f.0, f.1, h.0, h.1
        );
    }
}

/// The security half: WRDE_NOCMD must reject command substitution and must NOT
/// reject arithmetic. Asserted in both directions against the oracle, so
/// neither "allow everything" nor "reject everything" passes.
#[test]
fn wordexp_nocmd_allows_arithmetic_and_rejects_command_substitution() {
    for &w in WORDS {
        let h = host(w, WRDE_NOCMD);
        let f = fl(w, WRDE_NOCMD);
        assert_eq!(
            f, h,
            "wordexp({w:?}, WRDE_NOCMD): fl=(rc={}, {:?}) glibc=(rc={}, {:?})",
            f.0, f.1, h.0, h.1
        );
        // Positive fact: arithmetic is never rejected as command substitution.
        assert_ne!(
            f.0, WRDE_CMDSUB,
            "WRDE_NOCMD rejected the arithmetic word {w:?} as command substitution"
        );
    }

    // And the flag still does its job. These MUST be refused.
    for &w in &["$(echo hi)", "`echo hi`", "x$(echo hi)y", "\"$(echo hi)\""] {
        let h = host(w, WRDE_NOCMD);
        let f = fl(w, WRDE_NOCMD);
        assert_eq!(
            h.0, WRDE_CMDSUB,
            "oracle: glibc should refuse {w:?} under WRDE_NOCMD (got rc={})",
            h.0
        );
        assert_eq!(
            f.0, WRDE_CMDSUB,
            "fl failed to refuse command substitution {w:?} under WRDE_NOCMD (rc={})",
            f.0
        );
    }
}
