#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc pthread_sigmask oracle; mutates this thread's mask

//! Differential gate for pthread_sigmask return convention (bd-ucdbr0).
//! pthread_sigmask uses the pthread convention: 0 on success, a POSITIVE error
//! number on failure (e.g. EINVAL for an invalid `how`), with the global errno
//! left UNCHANGED — NOT sigprocmask's -1/errno. fl previously returned -1 and
//! set errno. Asserts fl matches glibc on the return value AND on leaving errno
//! untouched, for an invalid `how` and a valid round-trip. No mocks.

use std::ffi::c_int;

const SIG_SETMASK: c_int = 2;

unsafe extern "C" {
    fn pthread_sigmask(how: c_int, set: *const libc::sigset_t, old: *mut libc::sigset_t) -> c_int;
    fn sigemptyset(set: *mut libc::sigset_t) -> c_int;
    fn __errno_location() -> *mut c_int;
}

#[test]
fn pthread_sigmask_invalid_how_returns_positive_errno() {
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe { sigemptyset(&mut set) };
    let bad_how = 99;

    // glibc
    unsafe { *__errno_location() = 0 };
    let g = unsafe { pthread_sigmask(bad_how, &set, std::ptr::null_mut()) };
    let g_errno = unsafe { *__errno_location() };

    // fl
    unsafe { *__errno_location() = 0 };
    let f = unsafe {
        frankenlibc_abi::signal_abi::pthread_sigmask(bad_how, &set, std::ptr::null_mut())
    };
    let f_errno = unsafe { *__errno_location() };

    assert_eq!(f, g, "pthread_sigmask(bad how) return: fl={f} glibc={g}");
    assert!(g > 0, "glibc returns a positive error number, got {g}");
    assert_eq!(
        f_errno, g_errno,
        "errno must be left unchanged like glibc: fl={f_errno} glibc={g_errno}"
    );
    assert_eq!(g_errno, 0, "glibc leaves errno at its pre-call value (0)");
}

#[test]
fn pthread_sigmask_valid_returns_zero() {
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe { sigemptyset(&mut set) };
    let mut old: libc::sigset_t = unsafe { std::mem::zeroed() };

    let f = unsafe { frankenlibc_abi::signal_abi::pthread_sigmask(SIG_SETMASK, &set, &mut old) };
    assert_eq!(f, 0, "valid pthread_sigmask should return 0");
    // restore (set the empty mask back via glibc to be safe)
    unsafe { pthread_sigmask(SIG_SETMASK, &old, std::ptr::null_mut()) };
}
