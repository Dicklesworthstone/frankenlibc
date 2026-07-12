#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc getlogin oracle

//! Differential gate for getlogin / getlogin_r (bd-746q8r) — no differential
//! gate existed. Both derive the login name from the same source (the
//! controlling terminal's utmp entry, falling back as glibc does), so fl and
//! glibc must agree regardless of environment: same name when a tty/utmp entry
//! exists, same (rc, errno) failure when it does not (e.g. no controlling tty in
//! CI). This also integration-tests fl's utmp read path. The small-buffer
//! ERANGE case is checked too. No mocks.

use std::ffi::{CStr, c_char, c_int};

unsafe extern "C" {
    fn getlogin_r(buf: *mut c_char, bufsize: usize) -> c_int;
    fn getlogin() -> *mut c_char;
    fn __errno_location() -> *mut c_int;
}

fn errno() -> c_int {
    unsafe { *__errno_location() }
}

/// (rc, name-on-success-or-empty)
fn call_r(f: unsafe extern "C" fn(*mut c_char, usize) -> c_int) -> (c_int, c_int, String) {
    let mut buf = [0u8; 256];
    unsafe {
        *__errno_location() = 0;
        let rc = f(buf.as_mut_ptr() as *mut c_char, buf.len());
        let er = errno();
        let name = if rc == 0 {
            CStr::from_ptr(buf.as_ptr() as *const c_char)
                .to_string_lossy()
                .into_owned()
        } else {
            String::new()
        };
        (rc, er, name)
    }
}

#[test]
fn getlogin_r_matches_glibc() {
    let g = call_r(getlogin_r);
    let f = call_r(frankenlibc_abi::unistd_abi::getlogin_r);
    // On failure the errno value may legitimately differ run-to-run only if the
    // sources differ; both read the same tty/utmp, so rc + name must match, and
    // on success errno is irrelevant. Compare rc + name always; errno on failure.
    assert_eq!(
        (f.0, &f.2),
        (g.0, &g.2),
        "getlogin_r: fl=(rc{},name{:?}) glibc=(rc{},name{:?})",
        f.0,
        f.2,
        g.0,
        g.2
    );
    if g.0 != 0 {
        assert_eq!(
            f.1, g.1,
            "getlogin_r failure errno: fl={} glibc={}",
            f.1, g.1
        );
    }
}

#[test]
fn getlogin_matches_glibc() {
    let g = unsafe {
        let p = getlogin();
        if p.is_null() {
            None
        } else {
            Some(CStr::from_ptr(p).to_string_lossy().into_owned())
        }
    };
    let f = unsafe {
        let p = frankenlibc_abi::unistd_abi::getlogin();
        if p.is_null() {
            None
        } else {
            Some(CStr::from_ptr(p).to_string_lossy().into_owned())
        }
    };
    assert_eq!(f, g, "getlogin: fl={f:?} glibc={g:?}");
}

#[test]
fn getlogin_r_small_buffer_matches_glibc() {
    // Only meaningful when a login name exists; if both fail with no name, the
    // tiny-buffer path is exercised identically and still must agree.
    let mut gb = [0u8; 1];
    let mut fb = [0u8; 1];
    let g = unsafe { (getlogin_r(gb.as_mut_ptr() as *mut c_char, 1), errno()) };
    let f = unsafe {
        (
            frankenlibc_abi::unistd_abi::getlogin_r(fb.as_mut_ptr() as *mut c_char, 1),
            errno(),
        )
    };
    assert_eq!(f.0, g.0, "getlogin_r(len=1) rc: fl={} glibc={}", f.0, g.0);
    if g.0 != 0 {
        assert_eq!(
            f.1, g.1,
            "getlogin_r(len=1) errno: fl={} glibc={}",
            f.1, g.1
        );
    }
}
