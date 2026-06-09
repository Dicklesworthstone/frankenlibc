#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc fnmatch oracle

//! FNM_EXTMATCH + FNM_PERIOD: a wildcard inside an extglob group occurrence that
//! starts MID-component must not re-apply the leading-'.' rule. fl previously
//! matched each group alternative against a fresh sub-slice whose position 0
//! looked "leading", so e.g. `+(a|?)` on "bc.." wrongly rejected the '.' at
//! index 2. Fixed by clearing FNM_PERIOD for non-leading sub-matches; pinned
//! here against the live glibc oracle.

use std::ffi::{CString, c_char, c_int};

use frankenlibc_abi::string_abi::fnmatch as fl_fnmatch;

unsafe extern "C" {
    fn fnmatch(pattern: *const c_char, string: *const c_char, flags: c_int) -> c_int;
}

const PERIOD: c_int = 1 << 2;
const EXTMATCH: c_int = 1 << 5;

fn check(pat: &str, s: &str, flags: c_int) {
    let cp = CString::new(pat).unwrap();
    let cs = CString::new(s).unwrap();
    let fl = unsafe { fl_fnmatch(cp.as_ptr(), cs.as_ptr(), flags) } == 0;
    let gl = unsafe { fnmatch(cp.as_ptr(), cs.as_ptr(), flags) } == 0;
    assert_eq!(fl, gl, "fnmatch({pat:?},{s:?},{flags:#x}): fl={fl} glibc={gl}");
}

#[test]
fn fnmatch_extglob_period_matches_glibc() {
    let f = EXTMATCH | PERIOD;
    // Wildcards inside group occurrences matching a mid-component '.' (the fix).
    check("+(a|?)", "bc..", f);
    check("?+(?)", "c.", f);
    check("?+(?)", "cd", f);
    check("c+(?)", "c.", f);
    check("?+(.|b)", "c.", f);
    check("*(a|?)", "a.b", f);
    check("@(a|?)b", "a.", f); // no match (only 1 group char) — must agree
    check("a+(?)", "a.b.c", f);
    // Leading-'.' rule MUST still hold at a genuine leading position.
    check("+(?)", ".", f);       // '?' can't match leading '.' -> NOMATCH
    check("?(a)", ".", f);
    check("@(?|b)", ".a", f);
    check("@(.a|b)", ".a", f);   // literal '.' matches leading '.' -> match
    check(".+(?)", ".ab", f);    // literal leading '.', then group on "ab"
    check("*(.)", ".a", f);
}
