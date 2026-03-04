#![cfg(target_os = "linux")]

//! Integration tests for `<pwd.h>` and shadow password ABI entrypoints.
//!
//! Uses `FRANKENLIBC_PASSWD_PATH` env var to point at test fixture files
//! instead of the real /etc/passwd.

use std::ffi::{CStr, CString, c_char};
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};

use frankenlibc_abi::pwd_abi::{
    endpwent, getpwent, getpwnam, getpwnam_r, getpwuid, getpwuid_r, setpwent,
};

static SEQ: AtomicU64 = AtomicU64::new(0);

fn temp_passwd_path() -> std::path::PathBuf {
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "frankenlibc-pwd-test-{}-{seq}.txt",
        std::process::id()
    ))
}

fn with_passwd_file(content: &[u8], f: impl FnOnce()) {
    let path = temp_passwd_path();
    std::fs::write(&path, content).expect("write temp passwd");
    // SAFETY: Tests run single-threaded (--test-threads=1 or serialized).
    unsafe { std::env::set_var("FRANKENLIBC_PASSWD_PATH", &path) };
    f();
    // SAFETY: Same as above.
    unsafe { std::env::remove_var("FRANKENLIBC_PASSWD_PATH") };
    let _ = std::fs::remove_file(&path);
}

const FIXTURE: &[u8] =
    b"root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000:Alice:/home/alice:/bin/sh\nbob:x:1001:1001:Bob:/home/bob:/bin/zsh\n";

// ---------------------------------------------------------------------------
// getpwnam
// ---------------------------------------------------------------------------

#[test]
fn getpwnam_finds_root() {
    with_passwd_file(FIXTURE, || {
        let name = CString::new("root").unwrap();
        let pw = unsafe { getpwnam(name.as_ptr()) };
        assert!(!pw.is_null(), "getpwnam(root) should find root");
        let pw_ref = unsafe { &*pw };
        assert_eq!(pw_ref.pw_uid, 0);
        assert_eq!(pw_ref.pw_gid, 0);
        let pw_name = unsafe { CStr::from_ptr(pw_ref.pw_name) };
        assert_eq!(pw_name.to_bytes(), b"root");
    });
}

#[test]
fn getpwnam_finds_alice() {
    with_passwd_file(FIXTURE, || {
        let name = CString::new("alice").unwrap();
        let pw = unsafe { getpwnam(name.as_ptr()) };
        assert!(!pw.is_null());
        let pw_ref = unsafe { &*pw };
        assert_eq!(pw_ref.pw_uid, 1000);
        let gecos = unsafe { CStr::from_ptr(pw_ref.pw_gecos) };
        assert_eq!(gecos.to_bytes(), b"Alice");
    });
}

#[test]
fn getpwnam_not_found() {
    with_passwd_file(FIXTURE, || {
        let name = CString::new("nonexistent").unwrap();
        let pw = unsafe { getpwnam(name.as_ptr()) };
        assert!(pw.is_null(), "getpwnam for nonexistent user should return null");
    });
}

#[test]
fn getpwnam_null_returns_null() {
    let pw = unsafe { getpwnam(ptr::null()) };
    assert!(pw.is_null());
}

// ---------------------------------------------------------------------------
// getpwuid
// ---------------------------------------------------------------------------

#[test]
fn getpwuid_finds_by_uid() {
    with_passwd_file(FIXTURE, || {
        let pw = unsafe { getpwuid(1001) };
        assert!(!pw.is_null(), "getpwuid(1001) should find bob");
        let pw_ref = unsafe { &*pw };
        let pw_name = unsafe { CStr::from_ptr(pw_ref.pw_name) };
        assert_eq!(pw_name.to_bytes(), b"bob");
        let shell = unsafe { CStr::from_ptr(pw_ref.pw_shell) };
        assert_eq!(shell.to_bytes(), b"/bin/zsh");
    });
}

#[test]
fn getpwuid_not_found() {
    with_passwd_file(FIXTURE, || {
        let pw = unsafe { getpwuid(9999) };
        assert!(pw.is_null());
    });
}

// ---------------------------------------------------------------------------
// getpwnam_r (reentrant)
// ---------------------------------------------------------------------------

#[test]
fn getpwnam_r_succeeds() {
    with_passwd_file(FIXTURE, || {
        let name = CString::new("alice").unwrap();
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut buf = vec![0u8; 1024];
        let mut result: *mut libc::passwd = ptr::null_mut();

        let rc = unsafe {
            getpwnam_r(
                name.as_ptr(),
                &mut pwd,
                buf.as_mut_ptr() as *mut c_char,
                buf.len(),
                &mut result,
            )
        };
        assert_eq!(rc, 0);
        assert!(!result.is_null());
        assert_eq!(pwd.pw_uid, 1000);
    });
}

#[test]
fn getpwnam_r_not_found() {
    with_passwd_file(FIXTURE, || {
        let name = CString::new("nobody_here").unwrap();
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut buf = vec![0u8; 1024];
        let mut result: *mut libc::passwd = ptr::null_mut();

        let rc = unsafe {
            getpwnam_r(
                name.as_ptr(),
                &mut pwd,
                buf.as_mut_ptr() as *mut c_char,
                buf.len(),
                &mut result,
            )
        };
        assert_eq!(rc, 0);
        assert!(result.is_null(), "result should be null when not found");
    });
}

#[test]
fn getpwnam_r_buffer_too_small() {
    with_passwd_file(FIXTURE, || {
        let name = CString::new("root").unwrap();
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut buf = [0u8; 2]; // Too small
        let mut result: *mut libc::passwd = ptr::null_mut();

        let rc = unsafe {
            getpwnam_r(
                name.as_ptr(),
                &mut pwd,
                buf.as_mut_ptr() as *mut c_char,
                buf.len(),
                &mut result,
            )
        };
        assert_eq!(rc, libc::ERANGE, "should return ERANGE for small buffer");
        assert!(result.is_null());
    });
}

#[test]
fn getpwnam_r_null_args_returns_einval() {
    let rc = unsafe { getpwnam_r(ptr::null(), ptr::null_mut(), ptr::null_mut(), 0, ptr::null_mut()) };
    assert_eq!(rc, libc::EINVAL);
}

// ---------------------------------------------------------------------------
// getpwuid_r (reentrant)
// ---------------------------------------------------------------------------

#[test]
fn getpwuid_r_succeeds() {
    with_passwd_file(FIXTURE, || {
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut buf = vec![0u8; 1024];
        let mut result: *mut libc::passwd = ptr::null_mut();

        let rc = unsafe {
            getpwuid_r(
                0,
                &mut pwd,
                buf.as_mut_ptr() as *mut c_char,
                buf.len(),
                &mut result,
            )
        };
        assert_eq!(rc, 0);
        assert!(!result.is_null());
        let pw_name = unsafe { CStr::from_ptr(pwd.pw_name) };
        assert_eq!(pw_name.to_bytes(), b"root");
    });
}

// ---------------------------------------------------------------------------
// setpwent / getpwent / endpwent (iteration)
// ---------------------------------------------------------------------------

#[test]
fn pwent_iteration() {
    with_passwd_file(FIXTURE, || {
        unsafe { setpwent() };

        let mut names = Vec::new();
        loop {
            let pw = unsafe { getpwent() };
            if pw.is_null() {
                break;
            }
            let pw_ref = unsafe { &*pw };
            let name = unsafe { CStr::from_ptr(pw_ref.pw_name) };
            names.push(name.to_bytes().to_vec());
        }

        unsafe { endpwent() };

        assert_eq!(names.len(), 3);
        assert_eq!(&names[0], b"root");
        assert_eq!(&names[1], b"alice");
        assert_eq!(&names[2], b"bob");
    });
}

#[test]
fn setpwent_rewinds_cursor() {
    with_passwd_file(FIXTURE, || {
        unsafe { setpwent() };
        let _ = unsafe { getpwent() }; // skip first

        unsafe { setpwent() };
        let pw = unsafe { getpwent() };
        assert!(!pw.is_null());
        let name = unsafe { CStr::from_ptr((*pw).pw_name) };
        assert_eq!(name.to_bytes(), b"root", "setpwent should rewind to first entry");

        unsafe { endpwent() };
    });
}

// ---------------------------------------------------------------------------
// gshadow stubs
// ---------------------------------------------------------------------------

#[test]
fn gshadow_stubs_return_null_or_enoent() {
    use frankenlibc_abi::pwd_abi::{endsgent, getsgent, getsgnam, setsgent};

    unsafe { setsgent() };
    let ptr = unsafe { getsgent() };
    assert!(ptr.is_null(), "getsgent should return null (stub)");

    let name = CString::new("root").unwrap();
    let ptr = unsafe { getsgnam(name.as_ptr()) };
    assert!(ptr.is_null(), "getsgnam should return null (stub)");

    unsafe { endsgent() };
}

// ---------------------------------------------------------------------------
// lckpwdf / ulckpwdf
// ---------------------------------------------------------------------------

#[test]
fn lckpwdf_ulckpwdf_succeed() {
    use frankenlibc_abi::pwd_abi::{lckpwdf, ulckpwdf};
    let rc = unsafe { lckpwdf() };
    assert_eq!(rc, 0, "lckpwdf should succeed (no-op)");
    let rc = unsafe { ulckpwdf() };
    assert_eq!(rc, 0, "ulckpwdf should succeed (no-op)");
}
