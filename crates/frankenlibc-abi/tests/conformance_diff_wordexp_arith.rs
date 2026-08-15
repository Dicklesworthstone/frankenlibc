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

/// Every test in this file runs under one lock. `wordexp` reads `environ`, and
/// one of the tests has to SET a variable to prove the no-variables rule with a
/// value actually present; letting that overlap a sibling's `wordexp` call is
/// the classic way to fabricate a divergence out of libtest parallelism.
fn serial() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

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
        frankenlibc_abi::unistd_abi::wordexp(w.as_ptr(), (&raw mut we).cast::<c_void>(), flags)
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
    // bd-6a9tuc asked for assignment / increment / comma to be IMPLEMENTED on
    // the premise that glibc supports them. Measured against live glibc 2.42,
    // it does not: every assignment and increment form below is WRDE_SYNTAX,
    // and `,` is just another unimplemented operator that ends the expression
    // (so `$((1,2))` is "1", not "2"). These arms exist so that implementing
    // the bead would fail the gate instead of silently diverging.
    "$((x=5))",
    "$(( x = 5 ))",
    "$((x=5, x*2))",
    "$((x=3, ++x))",
    "$((x=3, x++))",
    "$((1,2))",
    "$((1, 2))",
    "$((++x))",
    "$((x++))",
    "$((--x))",
    "$((x--))",
    "$((x+=2))",
    "$((x-=2))",
    "$((x*=2))",
    "$((x/=2))",
    "$((x%=2))",
    "$((x<<=1))",
    "$((x&=1))",
    "$((x^=1))",
    "$((x|=1))",
    "$((5=3))",
    "$((1+2,3+4))",
];

/// Words whose behaviour depends on an environment variable actually being set.
/// Two rules are pinned here, and they pull in opposite directions, which is why
/// both halves are needed (bd-6a9tuc):
///
///  - the arithmetic PARSER has no variables at all: `$((FLARITH+1))` is
///    WRDE_SYNTAX even with `FLARITH` exported;
///  - the arithmetic BODY is parameter-expanded before it is parsed, so
///    `$(($FLARITH+1))` is "42".
///
/// Every expectation below was measured against live glibc 2.42, including the
/// unobvious ones: an unset name expands to nothing, so `$(($UNSET+1))` is "1"
/// (unary plus) and `$(($UNSET))` is "0", while `$(( $UNSET ))` is a syntax
/// error — the empty body is zero only when it is exactly zero-length.
const ENV_WORDS: &[&str] = &[
    // the parser has no identifiers
    "$((FLARITH))",
    "$((FLARITH+1))",
    "$((FLARITH=7))",
    "$((FLARITH++))",
    // the body is expanded first
    "$(($FLARITH+1))",
    "$((${FLARITH}+1))",
    "$(( $FLARITH ))",
    "$(($FLARITH))",
    "$(($FLARITH))x",
    "$((1+$FLARITH*2))",
    "$(($FLARITH$FLARITH))",
    "$((${FLARITH}${FLARITH}))",
    "$((0x$FLARITH))",
    "$(($FLNEG+1))",
    "$(($FLSP+1))",
    "$((${#FLARITH}))",
    "$((${FLARITH:-9}))",
    // bd-4f7oo7's literal cases: a ${param OP word} form inside arithmetic runs
    // the parameter expansion first, so the operator's RESULT is what gets
    // parsed. Measured: "6", "6", "10", "3".
    "$(( ${x:-5} + 1 ))",
    "$((${x:-5}+1))",
    "$(( ${x-5} + 1 ))",
    "$(( ${FLARITH:+9} + 1 ))",
    "$(( ${#FLARITH} + 1 ))",
    // affix removal inside arithmetic: ${FLARITH%1} on "41" is "4", so this is
    // "5" — a different expansion code path (remove_affix) reached through the
    // same recursion.
    "$(( ${FLARITH%1} + 1 ))",
    "$(( ${FLARITH#4} + 1 ))",
    // unset / empty bodies
    "$(())",
    "$(($NOPEVAR))",
    "$((${NOPEVAR}))",
    "$(($NOPEVAR+1))",
    "$(( $NOPEVAR ))",
    "$(($NOPEVAR $NOPEVAR))",
    "$((1+$NOPEVAR))",
    "$((${NOPEVAR:-7}+1))",
    // expansion happens, but quoting and escaping still keep the name away from
    // the parser, so these stay syntax errors
    "$((\\$FLARITH+1))",
    "$(('$FLARITH'+1))",
    // non-numeric and divide-by-zero survive the substitution
    "$(($FLTXT+1))",
    "$((1/$FLZERO))",
    "$(($FLARITH+))",
    // nested arithmetic
    "$(($((1+2))+1))",
];

#[test]
fn wordexp_arithmetic_matches_glibc() {
    let _serial = serial();
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

/// bd-6a9tuc refutation gate. The bead specified `$((x=5))` -> "5",
/// `$((x=5, x*2))` -> "10" and `$((x=3, ++x))` -> "4" "like glibc". Live glibc
/// 2.42 returns `WRDE_SYNTAX` for all three, and treats `,` the way it treats
/// every other unimplemented operator: it stops there and keeps what it parsed,
/// so `$((1,2))` expands to "1".
///
/// This test asserts those as POSITIVE FACTS about the oracle first, so it
/// cannot pass by both sides being broken the same way, and it is what fails if
/// anyone implements the bead as written.
#[test]
fn wordexp_arithmetic_has_no_assignment_increment_or_comma_operator() {
    let _serial = serial();
    const REJECTED: &[&str] = &[
        "$((x=5))",
        "$(( x = 5 ))",
        "$((x=5, x*2))",
        "$((x=3, ++x))",
        "$((x=3, x++))",
        "$((++x))",
        "$((x++))",
        "$((--x))",
        "$((x--))",
        "$((x+=2))",
        "$((x*=2))",
        "$((x<<=1))",
    ];
    for &w in REJECTED {
        let h = host(w, 0);
        assert_ne!(
            h.0, 0,
            "oracle changed: glibc now ACCEPTS {w:?} -> {:?}. glibc's wordexp arithmetic has \
             gained assignment/increment; re-measure before touching fl.",
            h.1
        );
        let f = fl(w, 0);
        assert_eq!(
            f, h,
            "fl implements an arithmetic operator glibc's wordexp does not: {w:?} \
             fl=(rc={}, {:?}) glibc=(rc={}, {:?})",
            f.0, f.1, h.0, h.1
        );
    }

    // `,` is a stop, not an operator: the LEFT value survives, the right is
    // dropped. An implementation of the comma operator would answer "2"/"7".
    for (w, expected) in [("$((1,2))", "1"), ("$((1+2,3+4))", "3")] {
        let h = host(w, 0);
        assert_eq!(
            (h.0, h.1.as_slice()),
            (0, [expected.to_owned()].as_slice()),
            "oracle changed: glibc {w:?} is no longer {expected:?}"
        );
        let f = fl(w, 0);
        assert_eq!(f, h, "fl diverges on the comma stop for {w:?}");
    }
}

/// The arithmetic PARSER has no variables at all — a bare name is a syntax
/// error even when the variable is set and exported — but the arithmetic BODY is
/// parameter-expanded before the parser sees it, so `$(($VAR+1))` does work.
/// Both halves are pinned with the variables actually set, because an unset name
/// proves much less. This is the test that caught fl returning WRDE_SYNTAX for
/// `$(($FLARITH+1))` where glibc answers "42" (bd-6a9tuc).
///
/// Every word is compared against the live oracle, and the mismatches are
/// collected rather than asserted one at a time: a divergence here is usually a
/// whole class, and stopping at the first one hides its shape.
#[test]
fn wordexp_arithmetic_expands_its_body_but_has_no_parser_variables() {
    let _serial = serial();
    // SAFETY: every test in this file holds `serial()`, so no sibling is calling
    // `wordexp` (which reads `environ`) while these are being set.
    unsafe {
        std::env::set_var("FLARITH", "41");
        std::env::set_var("FLNEG", "-3");
        std::env::set_var("FLSP", " 7 ");
        std::env::set_var("FLTXT", "abc");
        std::env::set_var("FLZERO", "0");
        std::env::remove_var("NOPEVAR");
    }

    let mut mismatches = Vec::new();
    for &w in ENV_WORDS {
        let h = host(w, 0);
        let f = fl(w, 0);
        if f != h {
            mismatches.push(format!(
                "  {w:?}: fl=(rc={}, {:?}) glibc=(rc={}, {:?})",
                f.0, f.1, h.0, h.1
            ));
        }
    }

    // Positive facts about the ORACLE, so the loop above cannot pass by both
    // sides being wrong in the same direction.
    let checks: &[(&str, c_int, &[&str])] = &[
        // the body IS expanded
        ("$(($FLARITH+1))", 0, &["42"]),
        ("$((${#FLARITH}))", 0, &["2"]),
        ("$((0x$FLARITH))", 0, &["65"]),
        // an unset name expands to nothing: unary plus, and zero-length is 0
        ("$(($NOPEVAR+1))", 0, &["1"]),
        ("$(($NOPEVAR))", 0, &["0"]),
        ("$(())", 0, &["0"]),
        // ...but a BLANK body is still a syntax error, so the rule is length
        ("$(( $NOPEVAR ))", 5, &[]),
        // the parser itself still has no identifiers
        ("$((FLARITH+1))", 5, &[]),
    ];
    for &(w, rc, words) in checks {
        let h = host(w, 0);
        let expected: Vec<String> = words.iter().map(|s| (*s).to_owned()).collect();
        assert_eq!(
            (h.0, h.1.clone()),
            (rc, expected.clone()),
            "oracle changed for {w:?}; re-measure glibc before touching fl"
        );
        let f = fl(w, 0);
        if f != h {
            mismatches.push(format!(
                "  {w:?}: fl=(rc={}, {:?}) glibc=(rc={}, {:?})",
                f.0, f.1, h.0, h.1
            ));
        }
    }

    // SAFETY: as above.
    unsafe {
        for name in ["FLARITH", "FLNEG", "FLSP", "FLTXT", "FLZERO"] {
            std::env::remove_var(name);
        }
    }

    assert!(
        mismatches.is_empty(),
        "wordexp arithmetic diverges from live glibc on {} word(s):\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}

/// The security half: WRDE_NOCMD must reject command substitution and must NOT
/// reject arithmetic. Asserted in both directions against the oracle, so
/// neither "allow everything" nor "reject everything" passes.
#[test]
fn wordexp_nocmd_allows_arithmetic_and_rejects_command_substitution() {
    let _serial = serial();
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
