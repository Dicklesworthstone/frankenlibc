#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc getenv/putenv oracle; shared process environ

//! Differential gate for getenv / putenv (bd-93orbb) — these fundamental
//! functions had no differential gate. fl and glibc read the SAME process
//! environ, so getenv must agree for every name (existing, PATH, missing,
//! empty). putenv is checked for cross-impl interop: a variable inserted via
//! fl::putenv must be observable through glibc::getenv (and vice-versa), proving
//! fl writes the shared environ in glibc's layout, plus the return code. No mocks.

use std::ffi::{CStr, CString, c_char, c_int};

unsafe extern "C" {
    fn getenv(name: *const c_char) -> *mut c_char;
    fn putenv(string: *mut c_char) -> c_int;
}

fn g_get(name: &str) -> Option<String> {
    let c = CString::new(name).unwrap();
    let p = unsafe { getenv(c.as_ptr()) };
    if p.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
    }
}
fn f_get(name: &str) -> Option<String> {
    let c = CString::new(name).unwrap();
    let p = unsafe { frankenlibc_abi::stdlib_abi::getenv(c.as_ptr()) };
    if p.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
    }
}

#[test]
fn getenv_matches_glibc() {
    // A var we control, set via the platform setenv (writes the shared environ).
    unsafe { std::env::set_var("FL_GETENV_PROBE", "value-42") };
    for name in [
        "FL_GETENV_PROBE",
        "PATH",
        "HOME",
        "PWD",
        "NO_SUCH_VAR_QZX",
        "",
        "FL_GETENV_PROBE=",
    ] {
        assert_eq!(
            f_get(name),
            g_get(name),
            "getenv({name:?}): fl={:?} glibc={:?}",
            f_get(name),
            g_get(name)
        );
    }
}

#[test]
fn putenv_then_getenv_cross_impl() {
    // Insert via fl::putenv; both impls' getenv must see it (shared environ).
    // putenv keeps the passed string in environ, so it must outlive the lookups.
    let s1 = CString::new("FL_PUTENV_A=alpha").unwrap();
    let s1 = Box::leak(s1.into_boxed_c_str());
    let rc_fl = unsafe { frankenlibc_abi::stdlib_abi::putenv(s1.as_ptr() as *mut c_char) };
    assert_eq!(rc_fl, 0, "fl::putenv should succeed");
    assert_eq!(
        g_get("FL_PUTENV_A"),
        Some("alpha".to_string()),
        "glibc getenv must see fl::putenv"
    );
    assert_eq!(
        f_get("FL_PUTENV_A"),
        Some("alpha".to_string()),
        "fl getenv must see fl::putenv"
    );

    // Insert via glibc putenv; fl::getenv must see it.
    let s2 = CString::new("FL_PUTENV_B=beta").unwrap();
    let s2 = Box::leak(s2.into_boxed_c_str());
    let rc_g = unsafe { putenv(s2.as_ptr() as *mut c_char) };
    assert_eq!(rc_g, 0, "glibc putenv should succeed");
    assert_eq!(
        f_get("FL_PUTENV_B"),
        g_get("FL_PUTENV_B"),
        "fl/glibc getenv agree after glibc putenv"
    );
    assert_eq!(f_get("FL_PUTENV_B"), Some("beta".to_string()));
}
