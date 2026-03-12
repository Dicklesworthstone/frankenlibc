#![cfg(target_os = "linux")]

//! Integration tests for `<pwd.h>` and shadow password ABI entrypoints.
//!
//! Uses `FRANKENLIBC_PASSWD_PATH` env var to point at test fixture files
//! instead of the real /etc/passwd.

use std::ffi::{CStr, CString, c_char, c_void};
use std::ptr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use frankenlibc_abi::pwd_abi::{
    endpwent, getpwent, getpwnam, getpwnam_r, getpwuid, getpwuid_r, setpwent,
};

static SEQ: AtomicU64 = AtomicU64::new(0);

/// Mutex to serialize tests that manipulate the FRANKENLIBC_PASSWD_PATH env var,
/// since env var manipulation is process-global and not thread-safe.
static PASSWD_ENV_LOCK: Mutex<()> = Mutex::new(());

fn temp_passwd_path() -> std::path::PathBuf {
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "frankenlibc-pwd-test-{}-{seq}.txt",
        std::process::id()
    ))
}

fn with_passwd_file(content: &[u8], f: impl FnOnce()) {
    let _guard = PASSWD_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let path = temp_passwd_path();
    std::fs::write(&path, content).expect("write temp passwd");
    // SAFETY: Serialized by PASSWD_ENV_LOCK — only one test thread at a time.
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
        assert!(
            pw.is_null(),
            "getpwnam for nonexistent user should return null"
        );
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
    let rc = unsafe {
        getpwnam_r(
            ptr::null(),
            ptr::null_mut(),
            ptr::null_mut(),
            0,
            ptr::null_mut(),
        )
    };
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
        assert_eq!(
            name.to_bytes(),
            b"root",
            "setpwent should rewind to first entry"
        );

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

// ---------------------------------------------------------------------------
// getpwent_r (reentrant iteration)
// ---------------------------------------------------------------------------

#[test]
fn getpwent_r_iterates_all_entries() {
    use frankenlibc_abi::pwd_abi::getpwent_r;

    with_passwd_file(FIXTURE, || {
        unsafe { setpwent() };

        let mut count = 0;
        loop {
            let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
            let mut buf = vec![0u8; 1024];
            let mut result: *mut libc::passwd = ptr::null_mut();

            let rc = unsafe {
                getpwent_r(
                    &mut pwd,
                    buf.as_mut_ptr() as *mut c_char,
                    buf.len(),
                    &mut result,
                )
            };
            if result.is_null() {
                break;
            }
            assert_eq!(rc, 0);
            count += 1;
        }

        unsafe { endpwent() };
        assert_eq!(count, 3, "should iterate all 3 entries");
    });
}

#[test]
fn getpwent_r_null_args() {
    use frankenlibc_abi::pwd_abi::getpwent_r;

    let rc = unsafe {
        getpwent_r(
            ptr::null_mut(),
            ptr::null_mut(),
            0,
            ptr::null_mut(),
        )
    };
    assert_eq!(rc, libc::EINVAL, "null args should return EINVAL");
}

// ---------------------------------------------------------------------------
// getpwuid_r — additional edge cases
// ---------------------------------------------------------------------------

#[test]
fn getpwuid_r_not_found() {
    with_passwd_file(FIXTURE, || {
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut buf = vec![0u8; 1024];
        let mut result: *mut libc::passwd = ptr::null_mut();

        let rc = unsafe {
            getpwuid_r(
                99999,
                &mut pwd,
                buf.as_mut_ptr() as *mut c_char,
                buf.len(),
                &mut result,
            )
        };
        assert_eq!(rc, 0);
        assert!(result.is_null(), "nonexistent uid should yield null result");
    });
}

#[test]
fn getpwuid_r_buffer_too_small() {
    with_passwd_file(FIXTURE, || {
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut buf = [0u8; 2];
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
        assert_eq!(rc, libc::ERANGE, "small buffer should return ERANGE");
        assert!(result.is_null());
    });
}

// ---------------------------------------------------------------------------
// getpwnam / getpwuid — additional edge cases
// ---------------------------------------------------------------------------

#[test]
fn getpwnam_checks_all_fields() {
    with_passwd_file(FIXTURE, || {
        let name = CString::new("bob").unwrap();
        let pw = unsafe { getpwnam(name.as_ptr()) };
        assert!(!pw.is_null());
        let pw_ref = unsafe { &*pw };
        assert_eq!(pw_ref.pw_uid, 1001);
        assert_eq!(pw_ref.pw_gid, 1001);
        let pw_dir = unsafe { CStr::from_ptr(pw_ref.pw_dir) };
        assert_eq!(pw_dir.to_bytes(), b"/home/bob");
        let pw_shell = unsafe { CStr::from_ptr(pw_ref.pw_shell) };
        assert_eq!(pw_shell.to_bytes(), b"/bin/zsh");
        let pw_gecos = unsafe { CStr::from_ptr(pw_ref.pw_gecos) };
        assert_eq!(pw_gecos.to_bytes(), b"Bob");
    });
}

#[test]
fn getpwuid_checks_home_dir() {
    with_passwd_file(FIXTURE, || {
        let pw = unsafe { getpwuid(1000) };
        assert!(!pw.is_null());
        let pw_ref = unsafe { &*pw };
        let dir = unsafe { CStr::from_ptr(pw_ref.pw_dir) };
        assert_eq!(dir.to_bytes(), b"/home/alice");
    });
}

// ---------------------------------------------------------------------------
// shadow password stubs (getspnam, getspnam_r, getspent, getspent_r)
// ---------------------------------------------------------------------------

#[test]
fn getspnam_returns_null_stub() {
    use frankenlibc_abi::pwd_abi::getspnam;
    let name = CString::new("root").unwrap();
    let sp = unsafe { getspnam(name.as_ptr()) };
    assert!(sp.is_null(), "getspnam should return null (stub)");
}

#[test]
fn getspnam_r_returns_enoent_stub() {
    use frankenlibc_abi::pwd_abi::getspnam_r;
    let name = CString::new("root").unwrap();
    let mut spwd_storage = [0u8; 256];
    let mut buf = vec![0u8; 1024];
    let mut result: *mut c_void = ptr::null_mut();

    let rc = unsafe {
        getspnam_r(
            name.as_ptr(),
            spwd_storage.as_mut_ptr() as *mut c_void,
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            &mut result,
        )
    };
    assert!(result.is_null(), "getspnam_r result should be null (stub)");
    // rc may be 0 (not found), ENOENT, or EACCES (no /etc/shadow access)
    assert!(
        rc == 0 || rc == libc::ENOENT || rc == libc::EACCES,
        "unexpected rc: {rc}"
    );
}

#[test]
fn getspent_returns_null_stub() {
    use frankenlibc_abi::pwd_abi::getspent;
    let sp = unsafe { getspent() };
    assert!(sp.is_null(), "getspent should return null (stub)");
}

#[test]
fn getspent_r_returns_enoent_stub() {
    use frankenlibc_abi::pwd_abi::getspent_r;
    let mut spwd_storage = [0u8; 256];
    let mut buf = vec![0u8; 1024];
    let mut result: *mut c_void = ptr::null_mut();

    let rc = unsafe {
        getspent_r(
            spwd_storage.as_mut_ptr() as *mut c_void,
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            &mut result,
        )
    };
    assert!(result.is_null(), "getspent_r result should be null (stub)");
    assert!(rc == 0 || rc == libc::ENOENT, "unexpected rc: {rc}");
}

// ---------------------------------------------------------------------------
// gshadow stubs — additional (getsgent_r, getsgnam_r, fgetsgent, etc.)
// ---------------------------------------------------------------------------

#[test]
fn getsgent_r_returns_enoent_stub() {
    use frankenlibc_abi::pwd_abi::getsgent_r;
    // sgrp is not in libc crate; use raw bytes
    let mut buf = vec![0u8; 512];
    // getsgent_r takes (struct sgrp*, char*, size_t, struct sgrp**) → int
    // We pass zeroed memory as the struct pointer since it's a stub
    let mut sgrp_storage = [0u8; 128];
    let mut result_ptr: *mut u8 = ptr::null_mut();

    let rc = unsafe {
        getsgent_r(
            sgrp_storage.as_mut_ptr() as *mut _,
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            &mut result_ptr as *mut *mut u8 as *mut *mut _,
        )
    };
    assert!(result_ptr.is_null(), "getsgent_r result should be null (stub)");
    assert!(rc == 0 || rc == libc::ENOENT, "unexpected rc: {rc}");
}

#[test]
fn getsgnam_r_returns_enoent_stub() {
    use frankenlibc_abi::pwd_abi::getsgnam_r;
    let name = CString::new("root").unwrap();
    let mut sgrp_storage = [0u8; 128];
    let mut buf = vec![0u8; 512];
    let mut result_ptr: *mut u8 = ptr::null_mut();

    let rc = unsafe {
        getsgnam_r(
            name.as_ptr(),
            sgrp_storage.as_mut_ptr() as *mut _,
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            &mut result_ptr as *mut *mut u8 as *mut *mut _,
        )
    };
    assert!(result_ptr.is_null(), "getsgnam_r result should be null (stub)");
    assert!(rc == 0 || rc == libc::ENOENT, "unexpected rc: {rc}");
}

#[test]
fn fgetsgent_null_stream_returns_null() {
    use frankenlibc_abi::pwd_abi::fgetsgent;
    let result = unsafe { fgetsgent(ptr::null_mut()) };
    assert!(result.is_null(), "fgetsgent(null) should return null");
}

#[test]
fn fgetsgent_r_null_stream_returns_error() {
    use frankenlibc_abi::pwd_abi::fgetsgent_r;
    let mut sgrp_storage = [0u8; 128];
    let mut buf = vec![0u8; 512];
    let mut result_ptr: *mut u8 = ptr::null_mut();

    let rc = unsafe {
        fgetsgent_r(
            ptr::null_mut(),
            sgrp_storage.as_mut_ptr() as *mut _,
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            &mut result_ptr as *mut *mut u8 as *mut *mut _,
        )
    };
    assert!(result_ptr.is_null());
    assert_ne!(rc, 0, "fgetsgent_r with null stream should fail");
}

#[test]
fn sgetsgent_null_returns_null() {
    use frankenlibc_abi::pwd_abi::sgetsgent;
    let result = unsafe { sgetsgent(ptr::null()) };
    assert!(result.is_null(), "sgetsgent(null) should return null");
}

#[test]
fn sgetsgent_r_null_returns_error() {
    use frankenlibc_abi::pwd_abi::sgetsgent_r;
    let mut sgrp_storage = [0u8; 128];
    let mut buf = vec![0u8; 512];
    let mut result_ptr: *mut u8 = ptr::null_mut();

    let rc = unsafe {
        sgetsgent_r(
            ptr::null(),
            sgrp_storage.as_mut_ptr() as *mut _,
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            &mut result_ptr as *mut *mut u8 as *mut *mut _,
        )
    };
    assert!(result_ptr.is_null());
    assert_ne!(rc, 0, "sgetsgent_r with null string should fail");
}

#[test]
fn putsgent_null_returns_error() {
    use frankenlibc_abi::pwd_abi::putsgent;
    let rc = unsafe { putsgent(ptr::null(), ptr::null_mut()) };
    assert_eq!(rc, -1, "putsgent with null args should fail");
}
