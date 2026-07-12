#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc seteuid/setegid oracle

//! Gate for the seteuid/setegid (uid_t)-1 rejection (bd-40ymct, pinning the
//! EINVAL part of bd-nb3egy). glibc's seteuid/setegid reject (uid_t)-1 /
//! (gid_t)-1 with EINVAL; fl previously routed through setreuid/setregid, which
//! treated -1 as "no change" and returned 0. These cases change NO credentials
//! (the -1 is rejected, and the no-op set-to-current succeeds), so the test is
//! safe to run in-process. fl must match host glibc on rc + errno. No mocks.

use std::ffi::c_int;

unsafe extern "C" {
    fn seteuid(euid: libc::uid_t) -> c_int;
    fn setegid(egid: libc::gid_t) -> c_int;
    fn __errno_location() -> *mut c_int;
}

fn errno() -> c_int {
    unsafe { *__errno_location() }
}

#[test]
fn seteuid_minus_one_is_einval_like_glibc() {
    let bad = libc::uid_t::MAX; // (uid_t)-1
    unsafe { *__errno_location() = 0 };
    let g = unsafe { seteuid(bad) };
    let g_err = errno();
    unsafe { *__errno_location() = 0 };
    let f = unsafe { frankenlibc_abi::unistd_abi::seteuid(bad) };
    let f_err = errno();
    assert_eq!(f, g, "seteuid(-1) rc: fl={f} glibc={g}");
    assert_eq!(g, -1, "glibc seteuid(-1) must fail");
    assert_eq!(f_err, g_err, "seteuid(-1) errno: fl={f_err} glibc={g_err}");
    assert_eq!(
        g_err,
        libc::EINVAL,
        "glibc seteuid(-1) errno must be EINVAL"
    );
}

#[test]
fn setegid_minus_one_is_einval_like_glibc() {
    let bad = libc::gid_t::MAX; // (gid_t)-1
    unsafe { *__errno_location() = 0 };
    let g = unsafe { setegid(bad) };
    let g_err = errno();
    unsafe { *__errno_location() = 0 };
    let f = unsafe { frankenlibc_abi::unistd_abi::setegid(bad) };
    let f_err = errno();
    assert_eq!(f, g, "setegid(-1) rc: fl={f} glibc={g}");
    assert_eq!(g, -1, "glibc setegid(-1) must fail");
    assert_eq!(f_err, g_err, "setegid(-1) errno: fl={f_err} glibc={g_err}");
    assert_eq!(
        g_err,
        libc::EINVAL,
        "glibc setegid(-1) errno must be EINVAL"
    );
}

#[test]
fn seteuid_to_current_euid_succeeds() {
    // Setting the effective uid to its current value is a no-op that must
    // succeed (no privilege needed), in both impls.
    let cur = unsafe { libc::geteuid() };
    let f = unsafe { frankenlibc_abi::unistd_abi::seteuid(cur) };
    assert_eq!(f, 0, "fl seteuid(current euid) should succeed");
    let g = unsafe { seteuid(cur) };
    assert_eq!(g, 0, "glibc seteuid(current euid) should succeed");
}
