#![cfg(target_os = "linux")]

//! Integration tests for `<pwd.h>` and shadow password ABI entrypoints.
//!
//! Uses `FRANKENLIBC_PASSWD_PATH` env var to point at test fixture files
//! instead of the real /etc/passwd.

use std::ffi::{CStr, CString, c_char, c_void};
use std::ptr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use frankenlibc_abi::errno_abi::__errno_location;
use frankenlibc_abi::malloc_abi::{free, malloc, malloc_known_remaining_for_tests};
use frankenlibc_abi::pwd_abi::{
    endpwent, getpwent, getpwnam, getpwnam_r, getpwuid, getpwuid_r, setpwent,
};
use frankenlibc_core::errno;

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

fn with_passwd_path(path: &std::path::Path, f: impl FnOnce()) {
    let _guard = PASSWD_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // SAFETY: Serialized by PASSWD_ENV_LOCK.
    unsafe { std::env::set_var("FRANKENLIBC_PASSWD_PATH", path) };
    f();
    // SAFETY: Serialized by PASSWD_ENV_LOCK.
    unsafe { std::env::remove_var("FRANKENLIBC_PASSWD_PATH") };
}

const FIXTURE: &[u8] =
    b"root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000:Alice:/home/alice:/bin/sh\nbob:x:1001:1001:Bob:/home/bob:/bin/zsh\n";

unsafe fn tracked_zeroed_bytes(len: usize) -> *mut c_void {
    assert!(len > 0);
    let raw = unsafe { malloc(len) };
    assert!(!raw.is_null());
    unsafe { std::ptr::write_bytes(raw.cast::<u8>(), 0, len) };
    raw
}

fn assert_known_short(raw: *const c_void, required: usize) {
    let remaining = malloc_known_remaining_for_tests(raw).unwrap_or(usize::MAX);
    assert_ne!(
        remaining,
        usize::MAX,
        "test allocation should be tracked by malloc metadata"
    );
    assert!(
        remaining < required,
        "test allocation should expose {remaining} tracked bytes, less than required {required}"
    );
}

unsafe fn free_tracked(raw: *mut c_void) {
    unsafe { free(raw) };
}

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

#[test]
fn getpwnam_rejects_unterminated_name() {
    with_passwd_file(FIXTURE, || unsafe {
        let name = malloc(4).cast::<u8>();
        assert!(!name.is_null());
        std::ptr::copy_nonoverlapping(b"root".as_ptr(), name, 4);
        let pw = getpwnam(name.cast());
        free(name.cast());
        assert!(pw.is_null(), "unterminated getpwnam name should fail");
    });
}

#[test]
fn getpwnam_missing_backend_sets_errno() {
    let missing = temp_passwd_path();
    with_passwd_path(&missing, || {
        let name = CString::new("root").unwrap();
        unsafe { *__errno_location() = 0 };
        let pw = unsafe { getpwnam(name.as_ptr()) };
        assert!(pw.is_null());
        assert_eq!(unsafe { *__errno_location() }, errno::ENOENT);
    });
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

#[test]
fn getpwnam_r_rejects_unterminated_name() {
    with_passwd_file(FIXTURE, || unsafe {
        let name = malloc(5).cast::<u8>();
        assert!(!name.is_null());
        std::ptr::copy_nonoverlapping(b"alice".as_ptr(), name, 5);
        let mut pwd: libc::passwd = std::mem::zeroed();
        let mut buf = vec![0u8; 1024];
        let mut result: *mut libc::passwd = ptr::null_mut();

        let rc = getpwnam_r(
            name.cast(),
            &mut pwd,
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            &mut result,
        );
        free(name.cast());
        assert_eq!(rc, libc::EINVAL);
        assert!(result.is_null());
    });
}

#[test]
fn getpwnam_r_rejects_tracked_buffer_shorter_than_claimed() {
    with_passwd_file(FIXTURE, || unsafe {
        let name = CString::new("root").unwrap();
        let mut pwd: libc::passwd = std::mem::zeroed();
        let raw = tracked_zeroed_bytes(2);
        assert_known_short(raw, 3);
        let mut result: *mut libc::passwd = ptr::null_mut();

        let rc = getpwnam_r(
            name.as_ptr(),
            &mut pwd,
            raw.cast::<c_char>(),
            1024,
            &mut result,
        );

        assert_eq!(rc, libc::ERANGE);
        assert!(result.is_null());
        free_tracked(raw);
    });
}

#[test]
fn getpwuid_r_rejects_tracked_short_result_slot_before_write() {
    with_passwd_file(FIXTURE, || unsafe {
        let mut pwd: libc::passwd = std::mem::zeroed();
        let mut buf = vec![0u8; 1024];
        let raw = tracked_zeroed_bytes(std::mem::size_of::<*mut libc::passwd>() - 1);
        assert_known_short(raw, std::mem::size_of::<*mut libc::passwd>());

        let rc = getpwuid_r(
            0,
            &mut pwd,
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            raw.cast::<*mut libc::passwd>(),
        );

        assert_eq!(rc, libc::EINVAL);
        free_tracked(raw);
    });
}

#[test]
fn getpwuid_r_rejects_tracked_misaligned_result_slot_before_write() {
    with_passwd_file(FIXTURE, || unsafe {
        let mut pwd: libc::passwd = std::mem::zeroed();
        let mut buf = vec![0u8; 1024];
        let raw = tracked_zeroed_bytes(std::mem::size_of::<*mut libc::passwd>() + 1);
        let result = raw.cast::<u8>().add(1).cast::<*mut libc::passwd>();
        assert_ne!(
            (result as usize) % std::mem::align_of::<*mut libc::passwd>(),
            0
        );

        let rc = getpwuid_r(
            0,
            &mut pwd,
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            result,
        );

        assert_eq!(rc, libc::EINVAL);
        free_tracked(raw);
    });
}

#[test]
fn getpwuid_r_clears_result_before_rejecting_tracked_short_passwd_slot() {
    with_passwd_file(FIXTURE, || unsafe {
        let raw = tracked_zeroed_bytes(std::mem::size_of::<libc::passwd>() - 1);
        assert_known_short(raw, std::mem::size_of::<libc::passwd>());
        let mut buf = vec![0u8; 1024];
        let mut result = std::ptr::NonNull::<libc::passwd>::dangling().as_ptr();

        let rc = getpwuid_r(
            0,
            raw.cast::<libc::passwd>(),
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            &mut result,
        );

        assert_eq!(rc, libc::EINVAL);
        assert!(result.is_null());
        free_tracked(raw);
    });
}

#[test]
fn getpwuid_r_clears_result_before_rejecting_tracked_misaligned_passwd_slot() {
    with_passwd_file(FIXTURE, || unsafe {
        let raw = tracked_zeroed_bytes(std::mem::size_of::<libc::passwd>() + 1);
        let pwd = raw.cast::<u8>().add(1).cast::<libc::passwd>();
        assert_ne!((pwd as usize) % std::mem::align_of::<libc::passwd>(), 0);
        let mut buf = vec![0u8; 1024];
        let mut result = std::ptr::NonNull::<libc::passwd>::dangling().as_ptr();

        let rc = getpwuid_r(
            0,
            pwd,
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            &mut result,
        );

        assert_eq!(rc, libc::EINVAL);
        assert!(result.is_null());
        free_tracked(raw);
    });
}

#[test]
fn getpwnam_r_missing_backend_returns_errno() {
    let missing = temp_passwd_path();
    with_passwd_path(&missing, || {
        let name = CString::new("root").unwrap();
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
        assert_eq!(rc, libc::ENOENT);
        assert!(result.is_null());
    });
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

    let rc = unsafe { getpwent_r(ptr::null_mut(), ptr::null_mut(), 0, ptr::null_mut()) };
    assert_eq!(rc, libc::EINVAL, "null args should return EINVAL");
}

#[test]
fn getpwent_r_erange_does_not_advance_cursor() {
    use frankenlibc_abi::pwd_abi::getpwent_r;

    with_passwd_file(FIXTURE, || {
        unsafe { setpwent() };

        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut tiny = [0u8; 1];
        let mut result: *mut libc::passwd = ptr::null_mut();
        let rc = unsafe {
            getpwent_r(
                &mut pwd,
                tiny.as_mut_ptr() as *mut c_char,
                tiny.len(),
                &mut result,
            )
        };
        assert_eq!(rc, libc::ERANGE);
        assert!(result.is_null());

        let mut retry_buf = vec![0u8; 1024];
        let rc = unsafe {
            getpwent_r(
                &mut pwd,
                retry_buf.as_mut_ptr() as *mut c_char,
                retry_buf.len(),
                &mut result,
            )
        };
        assert_eq!(rc, 0);
        assert!(!result.is_null());
        let name = unsafe { CStr::from_ptr(pwd.pw_name) };
        assert_eq!(name.to_bytes(), b"root");

        unsafe { endpwent() };
    });
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
fn getspnam_r_rejects_unterminated_name() {
    use frankenlibc_abi::pwd_abi::getspnam_r;
    unsafe {
        let name = malloc(4).cast::<u8>();
        assert!(!name.is_null());
        std::ptr::copy_nonoverlapping(b"root".as_ptr(), name, 4);
        let mut spwd_storage = [0u8; 256];
        let mut buf = vec![0u8; 1024];
        let mut result: *mut c_void = ptr::null_mut();

        let rc = getspnam_r(
            name.cast(),
            spwd_storage.as_mut_ptr() as *mut c_void,
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            &mut result,
        );
        free(name.cast());
        assert_eq!(rc, libc::EINVAL);
        assert!(result.is_null());
    }
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
    assert!(
        result_ptr.is_null(),
        "getsgent_r result should be null (stub)"
    );
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
    assert!(
        result_ptr.is_null(),
        "getsgnam_r result should be null (stub)"
    );
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
fn sgetsgent_r_rejects_unterminated_string() {
    use frankenlibc_abi::pwd_abi::sgetsgent_r;
    unsafe {
        let line = b"wheel:!:root";
        let unterminated = malloc(line.len()).cast::<u8>();
        assert!(!unterminated.is_null());
        std::ptr::copy_nonoverlapping(line.as_ptr(), unterminated, line.len());
        let mut sgrp_storage = [0u8; 128];
        let mut buf = vec![0u8; 512];
        let mut result_ptr: *mut u8 = ptr::null_mut();

        let rc = sgetsgent_r(
            unterminated.cast(),
            sgrp_storage.as_mut_ptr() as *mut _,
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            &mut result_ptr as *mut *mut u8 as *mut *mut _,
        );
        free(unterminated.cast());
        assert_eq!(rc, libc::EINVAL);
        assert!(result_ptr.is_null());
    }
}

#[test]
fn putsgent_null_returns_error() {
    use frankenlibc_abi::pwd_abi::putsgent;
    let rc = unsafe { putsgent(ptr::null(), ptr::null_mut()) };
    assert_eq!(rc, -1, "putsgent with null args should fail");
}

// ---------------------------------------------------------------------------
// Strict/Hardened Mode Tests (bd-x2sq)
// ---------------------------------------------------------------------------

/// Static mutex for mode env var manipulation (process-global).
static MODE_ENV_LOCK: Mutex<()> = Mutex::new(());

fn with_mode(mode: &str, f: impl FnOnce()) {
    let _guard = MODE_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // SAFETY: Serialized by MODE_ENV_LOCK.
    unsafe { std::env::set_var("FRANKENLIBC_MODE", mode) };
    f();
    // SAFETY: Same as above.
    unsafe { std::env::remove_var("FRANKENLIBC_MODE") };
}

fn with_mode_and_passwd(mode: &str, passwd_content: &[u8], f: impl FnOnce()) {
    let _mode_guard = MODE_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _passwd_guard = PASSWD_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let path = temp_passwd_path();
    std::fs::write(&path, passwd_content).expect("write temp passwd");

    // SAFETY: Serialized by both locks.
    unsafe {
        std::env::set_var("FRANKENLIBC_MODE", mode);
        std::env::set_var("FRANKENLIBC_PASSWD_PATH", &path);
    }
    f();
    // SAFETY: Same as above.
    unsafe {
        std::env::remove_var("FRANKENLIBC_MODE");
        std::env::remove_var("FRANKENLIBC_PASSWD_PATH");
    }
    let _ = std::fs::remove_file(&path);
}

#[test]
fn strict_mode_getpwnam_returns_null_for_invalid() {
    with_mode_and_passwd("strict", FIXTURE, || {
        let name = CString::new("nonexistent_user_strict_test").unwrap();
        let pw = unsafe { getpwnam(name.as_ptr()) };
        assert!(
            pw.is_null(),
            "strict mode: getpwnam for nonexistent user should return null"
        );
    });
}

#[test]
fn strict_mode_getpwuid_returns_null_for_invalid_uid() {
    with_mode_and_passwd("strict", FIXTURE, || {
        let pw = unsafe { getpwuid(99999) };
        assert!(
            pw.is_null(),
            "strict mode: getpwuid for nonexistent uid should return null"
        );
    });
}

#[test]
fn hardened_mode_getpwnam_returns_null_for_invalid() {
    with_mode_and_passwd("hardened", FIXTURE, || {
        let name = CString::new("nonexistent_user_hardened_test").unwrap();
        let pw = unsafe { getpwnam(name.as_ptr()) };
        // In hardened mode, invalid lookups still return null (no healing for missing entries).
        assert!(
            pw.is_null(),
            "hardened mode: getpwnam for nonexistent user should return null"
        );
    });
}

#[test]
fn hardened_mode_getpwuid_returns_null_for_invalid_uid() {
    with_mode_and_passwd("hardened", FIXTURE, || {
        let pw = unsafe { getpwuid(99999) };
        // In hardened mode, invalid lookups still return null.
        assert!(
            pw.is_null(),
            "hardened mode: getpwuid for nonexistent uid should return null"
        );
    });
}

#[test]
fn strict_mode_getpwnam_null_input_returns_null() {
    with_mode("strict", || {
        let pw = unsafe { getpwnam(ptr::null()) };
        assert!(
            pw.is_null(),
            "strict mode: getpwnam(null) should return null"
        );
    });
}

#[test]
fn hardened_mode_getpwnam_null_input_returns_null() {
    with_mode("hardened", || {
        let pw = unsafe { getpwnam(ptr::null()) };
        assert!(
            pw.is_null(),
            "hardened mode: getpwnam(null) should return null"
        );
    });
}

#[test]
fn strict_mode_pwent_iteration_works() {
    with_mode_and_passwd("strict", FIXTURE, || {
        unsafe { setpwent() };
        let mut count = 0;
        loop {
            let pw = unsafe { getpwent() };
            if pw.is_null() {
                break;
            }
            count += 1;
            assert!(
                count <= 10,
                "strict mode: pwent iteration should not infinite loop"
            );
        }
        unsafe { endpwent() };
        assert_eq!(count, 3, "strict mode: fixture has 3 entries");
    });
}

#[test]
fn hardened_mode_pwent_iteration_works() {
    with_mode_and_passwd("hardened", FIXTURE, || {
        unsafe { setpwent() };
        let mut count = 0;
        loop {
            let pw = unsafe { getpwent() };
            if pw.is_null() {
                break;
            }
            count += 1;
            assert!(
                count <= 10,
                "hardened mode: pwent iteration should not infinite loop"
            );
        }
        unsafe { endpwent() };
        assert_eq!(count, 3, "hardened mode: fixture has 3 entries");
    });
}

// ---------------------------------------------------------------------------
// uid_from_user / user_from_uid (BSD libutil pwcache)
// ---------------------------------------------------------------------------

#[test]
fn uid_from_user_resolves_known_name() {
    use frankenlibc_abi::pwd_abi::uid_from_user;
    with_passwd_file(FIXTURE, || {
        let name = CString::new("alice").unwrap();
        let mut uid: libc::uid_t = u32::MAX;
        let rc = unsafe { uid_from_user(name.as_ptr(), &mut uid) };
        assert_eq!(rc, 0);
        assert_eq!(uid, 1000);
    });
}

#[test]
fn uid_from_user_returns_minus_one_for_unknown() {
    use frankenlibc_abi::pwd_abi::uid_from_user;
    with_passwd_file(FIXTURE, || {
        let name = CString::new("nosuchuser").unwrap();
        let mut uid: libc::uid_t = 999;
        let rc = unsafe { uid_from_user(name.as_ptr(), &mut uid) };
        assert_eq!(rc, -1);
        assert_eq!(uid, 999, "uid output must be untouched on failure");
    });
}

#[test]
fn uid_from_user_null_name_is_error() {
    use frankenlibc_abi::pwd_abi::uid_from_user;
    let mut uid: libc::uid_t = 0;
    let rc = unsafe { uid_from_user(ptr::null(), &mut uid) };
    assert_eq!(rc, -1);
}

#[test]
fn uid_from_user_null_uid_pointer_skips_write() {
    use frankenlibc_abi::pwd_abi::uid_from_user;
    with_passwd_file(FIXTURE, || {
        let name = CString::new("bob").unwrap();
        let rc = unsafe { uid_from_user(name.as_ptr(), ptr::null_mut()) };
        assert_eq!(rc, 0, "lookup must still succeed with NULL uid pointer");
    });
}

#[test]
fn user_from_uid_resolves_known_uid() {
    use frankenlibc_abi::pwd_abi::user_from_uid;
    with_passwd_file(FIXTURE, || {
        let p = unsafe { user_from_uid(1000, 0) };
        assert!(!p.is_null());
        let bytes = unsafe { CStr::from_ptr(p).to_bytes() };
        assert_eq!(bytes, b"alice");
    });
}

#[test]
fn user_from_uid_unknown_returns_null_when_nouser_zero() {
    use frankenlibc_abi::pwd_abi::user_from_uid;
    with_passwd_file(FIXTURE, || {
        let p = unsafe { user_from_uid(99999, 0) };
        assert!(p.is_null(), "missing uid + nouser=0 must return NULL");
    });
}

#[test]
fn user_from_uid_unknown_with_nouser_returns_decimal_string() {
    use frankenlibc_abi::pwd_abi::user_from_uid;
    with_passwd_file(FIXTURE, || {
        let p = unsafe { user_from_uid(424242, 1) };
        assert!(
            !p.is_null(),
            "nouser=1 must always return a non-NULL pointer"
        );
        let bytes = unsafe { CStr::from_ptr(p).to_bytes() };
        assert_eq!(bytes, b"424242");
    });
}

#[test]
fn user_from_uid_zero_with_nouser_renders_zero() {
    use frankenlibc_abi::pwd_abi::user_from_uid;
    // Use a fixture that does NOT have uid=0 so the fallback path triggers.
    let no_root: &[u8] =
        b"alice:x:1000:1000:Alice:/home/alice:/bin/sh\nbob:x:1001:1001:Bob:/home/bob:/bin/zsh\n";
    with_passwd_file(no_root, || {
        let p = unsafe { user_from_uid(0, 1) };
        assert!(!p.is_null());
        let bytes = unsafe { CStr::from_ptr(p).to_bytes() };
        assert_eq!(bytes, b"0");
    });
}
