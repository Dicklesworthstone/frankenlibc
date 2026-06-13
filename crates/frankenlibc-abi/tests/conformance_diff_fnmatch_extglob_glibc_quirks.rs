#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc fnmatch oracle (characterization)

//! Characterization of two glibc FNM_EXTMATCH INCONSISTENCIES that frankenlibc
//! deliberately does NOT mirror (bd-2g7oyh.285): in each, glibc accepts every
//! near-identical neighbour but rejects one specific composition, so its verdict
//! is an implementation artifact, not a principled rule. fl returns the sensible
//! (consistent) result. This test PINS fl's behaviour and ASSERTS the glibc
//! inconsistency, so a future glibc that becomes consistent flags this for
//! re-evaluation. (Same policy as ecvt / remquo / regex nested-submatch.)

use std::ffi::{CString, c_char, c_int};

use frankenlibc_abi::string_abi::fnmatch as fl_fnmatch;

unsafe extern "C" {
    fn fnmatch(pattern: *const c_char, string: *const c_char, flags: c_int) -> c_int;
}

const PATHNAME: c_int = 1 << 0;
const PERIOD: c_int = 1 << 2;
const EXTMATCH: c_int = 1 << 5;

fn fl_m(pat: &str, s: &str, flags: c_int) -> bool {
    let cp = CString::new(pat).unwrap();
    let cs = CString::new(s).unwrap();
    unsafe { fl_fnmatch(cp.as_ptr(), cs.as_ptr(), flags) == 0 }
}
fn gl_m(pat: &str, s: &str, flags: c_int) -> bool {
    let cp = CString::new(pat).unwrap();
    let cs = CString::new(s).unwrap();
    unsafe { fnmatch(cp.as_ptr(), cs.as_ptr(), flags) == 0 }
}

#[test]
fn period_star_question_group_inconsistency() {
    let f = EXTMATCH | PERIOD;
    // glibc accepts both neighbours but rejects the `*?`+group composition on a
    // string whose '.' is NOT leading — an inconsistency.
    assert!(
        gl_m("*+(?)", "c.", f),
        "glibc baseline: *+(?) on c. matches"
    );
    assert!(
        gl_m("?+(?)", "c.", f),
        "glibc baseline: ?+(?) on c. matches"
    );
    assert!(
        !gl_m("*?+(?)", "c.", f),
        "glibc inconsistency: rejects *?+(?) on c."
    );
    // fl is consistent: the '.' at index 1 is mid-string, so the wildcard matches.
    assert!(fl_m("*+(?)", "c.", f));
    assert!(fl_m("?+(?)", "c.", f));
    assert!(fl_m("*?+(?)", "c.", f), "fl consistent: *?+(?) matches c.");
}

#[test]
fn pathname_slash_group_inconsistency() {
    let f = EXTMATCH | PATHNAME;
    // glibc lets an extglob group match a literal '/' everywhere…
    assert!(gl_m("@(/)", "/", f), "glibc baseline: @(/) matches /");
    assert!(
        gl_m("a@(/)b", "a/b", f),
        "glibc baseline: a@(/)b matches a/b"
    );
    assert!(gl_m("@(/)c", "/c", f), "glibc baseline: @(/)c matches /c");
    // …except when the group is sandwiched between two `*`s — an inconsistency.
    assert!(
        !gl_m("*@(/)*", "aa/", f),
        "glibc inconsistency: rejects *@(/)* on aa/"
    );
    // fl is consistent: `*`="aa", `@(/)`="/", `*`="" matches.
    assert!(fl_m("@(/)", "/", f));
    assert!(fl_m("a@(/)b", "a/b", f));
    assert!(
        fl_m("*@(/)*", "aa/", f),
        "fl consistent: *@(/)* matches aa/"
    );
}
