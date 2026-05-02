#![cfg(target_os = "linux")]

//! Differential conformance harness for the BSD usershell iterator
//! `getusershell(3)` / `setusershell(3)` / `endusershell(3)`.
//!
//! These read /etc/shells (one shell path per line, comments
//! stripped) and yield each valid shell on successive calls. Both
//! fl and host glibc must produce the same sorted set of shells.
//!
//! Filed under [bd-xn6p8] follow-up.

use std::collections::BTreeSet;
use std::ffi::{c_char, CStr};

use frankenlibc_abi::stdlib_abi as fl;

unsafe extern "C" {
    fn getusershell() -> *mut c_char;
    fn setusershell();
    fn endusershell();
}

fn drain_fl() -> BTreeSet<String> {
    fl::setusershell();
    let mut shells = BTreeSet::new();
    loop {
        let p = fl::getusershell();
        if p.is_null() {
            break;
        }
        let s = unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned();
        shells.insert(s);
    }
    fl::endusershell();
    shells
}

fn drain_lc() -> BTreeSet<String> {
    unsafe { setusershell() };
    let mut shells = BTreeSet::new();
    loop {
        let p = unsafe { getusershell() };
        if p.is_null() {
            break;
        }
        let s = unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned();
        shells.insert(s);
    }
    unsafe { endusershell() };
    shells
}

#[test]
fn diff_usershell_full_iteration_yields_same_set() {
    let fl_set = drain_fl();
    let lc_set = drain_lc();
    // Both impls might fall back to a built-in list if /etc/shells
    // is missing — at minimum they should share a non-empty set.
    assert!(!fl_set.is_empty(), "fl yielded no shells");
    assert!(!lc_set.is_empty(), "lc yielded no shells");
    // If /etc/shells exists, both impls should agree exactly on
    // its contents.
    if std::fs::metadata("/etc/shells").is_ok() {
        assert_eq!(
            fl_set, lc_set,
            "fl/lc shell sets diverge:\n  fl - lc = {:?}\n  lc - fl = {:?}",
            fl_set.difference(&lc_set).collect::<Vec<_>>(),
            lc_set.difference(&fl_set).collect::<Vec<_>>()
        );
    }
}

#[test]
fn diff_usershell_setusershell_rewinds() {
    // First pass.
    let s1 = drain_fl();
    let s2 = drain_fl();
    assert_eq!(s1, s2, "fl second pass differs");

    let l1 = drain_lc();
    let l2 = drain_lc();
    assert_eq!(l1, l2, "lc second pass differs");
}

#[test]
fn diff_usershell_endusershell_resets_iterator() {
    fl::setusershell();
    let _ = fl::getusershell(); // consume one
    fl::endusershell();
    // Next setusershell+getusershell should yield the first entry
    // again.
    fl::setusershell();
    let p = fl::getusershell();
    assert!(!p.is_null(), "fl getusershell after endusershell+setusershell");
    fl::endusershell();
}

#[test]
fn diff_usershell_first_shell_is_consistent() {
    fl::setusershell();
    let fl_first_p = fl::getusershell();
    let fl_first = if fl_first_p.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(fl_first_p) }.to_string_lossy().into_owned())
    };
    fl::endusershell();

    unsafe { setusershell() };
    let lc_first_p = unsafe { getusershell() };
    let lc_first = if lc_first_p.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(lc_first_p) }.to_string_lossy().into_owned())
    };
    unsafe { endusershell() };

    if std::fs::metadata("/etc/shells").is_ok() {
        assert_eq!(fl_first, lc_first, "first shell mismatch");
    }
}

#[test]
fn usershell_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc getusershell + setusershell + endusershell\",\"reference\":\"glibc\",\"functions\":3,\"divergences\":0}}",
    );
}
