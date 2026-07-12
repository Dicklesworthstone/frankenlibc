#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc catopen oracle

//! Differential gate for catopen error paths (bd-rp1e32), validating cod's
//! EINVAL fixes (bd-b7ks5s empty name, bd-jbujfo directory) against the
//! authoritative runtime glibc. For an empty name, an existing directory, and a
//! nonexistent catalog name, fl's catopen must FAIL exactly like glibc — same
//! "is it an error" outcome AND the same errno. NULL is not tested (glibc
//! dereferences it). No mocks.
//!
//! This is a cross-review gate: if cod's catopen returns EINVAL where glibc
//! returns ENOENT/EISDIR, this fails in the batch run and surfaces the bug; if
//! they agree, it confirms the fix.

use std::ffi::{CString, c_char, c_int, c_void};

unsafe extern "C" {
    fn catopen(name: *const c_char, oflag: c_int) -> *mut c_void; // glibc nl_catd
    fn catclose(catd: *mut c_void) -> c_int;
    fn __errno_location() -> *mut c_int;
}

fn errno() -> c_int {
    unsafe { *__errno_location() }
}

/// Returns (failed?, errno) for glibc catopen of `name`.
fn glibc_open(name: &CString) -> (bool, c_int) {
    unsafe { *__errno_location() = 0 };
    let r = unsafe { catopen(name.as_ptr(), 0) };
    let e = errno();
    let failed = r as isize == -1;
    if !failed {
        unsafe { catclose(r) };
    }
    (failed, e)
}

/// Returns (failed?, errno) for fl catopen of `name`.
fn fl_open(name: &CString) -> (bool, c_int) {
    unsafe { *__errno_location() = 0 };
    let r = unsafe { frankenlibc_abi::locale_abi::catopen(name.as_ptr(), 0) };
    let e = errno();
    let failed = r == -1;
    if !failed {
        unsafe { frankenlibc_abi::locale_abi::catclose(r) };
    }
    (failed, e)
}

#[test]
fn catopen_error_paths_match_glibc() {
    // Empty name, an existing directory, and a name that doesn't resolve.
    let cases = [
        CString::new("").unwrap(),
        CString::new("/tmp").unwrap(),
        CString::new("fl_no_such_catalog_zzqq").unwrap(),
    ];
    for name in &cases {
        let (gf, ge) = glibc_open(name);
        let (ff, fe) = fl_open(name);
        assert!(gf, "glibc catopen({name:?}) should fail (error-path test)");
        assert_eq!(
            ff, gf,
            "catopen({name:?}) failure-outcome: fl={ff} glibc={gf}"
        );
        assert_eq!(fe, ge, "catopen({name:?}) errno: fl={fe} glibc={ge}");
    }
}
