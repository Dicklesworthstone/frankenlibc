#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc getpwent_r enumeration oracle; reads the system db

//! Differential gate for getpwent_r reentrant enumeration (bd-cngmdy). fl
//! enumerates /etc/passwd (files-only) while glibc enumerates via NSS (files +
//! any configured sources), so an exact set match would be fragile. Instead it
//! asserts the NSS-subset invariant: every (name, uid) fl yields must also be
//! produced by glibc's enumeration — fl(files) ⊆ glibc(NSS). Also checks the
//! ENOENT/NULL terminator at end-of-enumeration. Each impl drives its own
//! setpwent/getpwent_r/endpwent cursor. No mocks.

use std::collections::BTreeSet;
use std::ffi::{CStr, c_char, c_int};

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn setpwent();
        pub fn endpwent();
        pub fn getpwent_r(
            pw: *mut libc::passwd,
            buf: *mut c_char,
            n: usize,
            res: *mut *mut libc::passwd,
        ) -> c_int;
    }
}
use frankenlibc_abi::pwd_abi as flp;

fn cstr(p: *const c_char) -> String {
    if p.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
    }
}

fn glibc_enum() -> (BTreeSet<(String, u32)>, c_int) {
    let mut set = BTreeSet::new();
    let mut term = 0;
    unsafe {
        g::setpwent();
        for _ in 0..10000 {
            let mut pw: libc::passwd = std::mem::zeroed();
            let mut buf = [0u8; 4096];
            let mut res: *mut libc::passwd = std::ptr::null_mut();
            let rc = g::getpwent_r(
                &mut pw,
                buf.as_mut_ptr() as *mut c_char,
                buf.len(),
                &mut res,
            );
            if res.is_null() {
                term = rc;
                break;
            }
            set.insert((cstr(pw.pw_name), pw.pw_uid));
        }
        g::endpwent();
    }
    (set, term)
}
fn fl_enum() -> (BTreeSet<(String, u32)>, c_int) {
    let mut set = BTreeSet::new();
    let mut term = 0;
    unsafe {
        flp::setpwent();
        for _ in 0..10000 {
            let mut pw: libc::passwd = std::mem::zeroed();
            let mut buf = [0u8; 4096];
            let mut res: *mut libc::passwd = std::ptr::null_mut();
            let rc = flp::getpwent_r(
                &mut pw,
                buf.as_mut_ptr() as *mut c_char,
                buf.len(),
                &mut res,
            );
            if res.is_null() {
                term = rc;
                break;
            }
            set.insert((cstr(pw.pw_name), pw.pw_uid));
        }
        flp::endpwent();
    }
    (set, term)
}

#[test]
fn getpwent_r_enumeration_subset_of_glibc() {
    let (gset, gterm) = glibc_enum();
    let (fset, fterm) = fl_enum();

    // fl is files-only; every entry it yields must also be in glibc's view.
    let missing: Vec<_> = fset.difference(&gset).cloned().collect();
    assert!(
        missing.is_empty(),
        "fl getpwent_r yielded entries glibc did not: {missing:?}"
    );

    // Both should terminate with the same code (ENOENT or 0 with NULL result).
    assert_eq!(
        fterm, gterm,
        "enumeration terminator: fl={fterm} glibc={gterm}"
    );

    // Sanity: root must appear in both.
    assert!(
        gset.contains(&("root".to_string(), 0)),
        "glibc enum missing root"
    );
    assert!(
        fset.contains(&("root".to_string(), 0)),
        "fl enum missing root"
    );
}
