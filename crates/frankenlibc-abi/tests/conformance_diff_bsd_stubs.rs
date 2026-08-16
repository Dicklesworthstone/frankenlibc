#![cfg(target_os = "linux")]
#![allow(unsafe_code)]
//! Live host-glibc differential coverage for BSD compatibility stubs.

use frankenlibc_abi::{errno_abi, glibc_internal_abi as fl};
use std::ffi::{CString, c_char, c_int, c_long, c_ulong, c_void};

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

type Chflags = unsafe extern "C" fn(*const c_char, c_ulong) -> c_int;
type Revoke = unsafe extern "C" fn(*const c_char) -> c_int;
type Setlogin = unsafe extern "C" fn(*const c_char) -> c_int;

// chflags / revoke / setlogin resolved by dlsym rather than declared at link
// time (bd-v0388t).
//
// This file already used dlvsym for bdflush/sstk, which are versioned compat
// symbols, so it LOOKED like a gate with a real oracle. These three were plain
// link-time externs sitting alongside that machinery -- the same shape that hid
// a link-time scalb/scalbf behind dlvsym'd __scalb_finite.
//
// It matters more here than in most gates because the ENTIRE observable is
// (return code, errno). These are stub syscalls: there is no output buffer to
// disagree about, so if the "host" arm were fl, every comparison would be fl's
// ENOSYS against fl's ENOSYS and the gate would be green by construction. That
// is the catopen shape exactly, and catopen's version hid a real EINVAL vs
// ENOENT divergence.
fn glibc_chflags() -> Chflags {
    // SAFETY: matches BSD's documented chflags signature.
    unsafe {
        dlsym_oracle::host_fn(c"chflags", fl::chflags as *const ())
    }
}

fn glibc_revoke() -> Revoke {
    // SAFETY: matches BSD's documented revoke signature.
    unsafe { dlsym_oracle::host_fn(c"revoke", fl::revoke as *const ()) }
}

fn glibc_setlogin() -> Setlogin {
    // SAFETY: matches BSD's documented setlogin signature.
    unsafe {
        dlsym_oracle::host_fn(c"setlogin", fl::setlogin as *const ())
    }
}

const GLIBC_2_2_5: &std::ffi::CStr = c"GLIBC_2.2.5";
type BdflushFn = unsafe extern "C" fn(c_int, c_long) -> c_int;
type SstkFn = unsafe extern "C" fn(c_int) -> c_int;

union BdflushSymbol {
    raw: *mut c_void,
    function: BdflushFn,
}

union SstkSymbol {
    raw: *mut c_void,
    function: SstkFn,
}

unsafe fn host_versioned_symbol(name: &std::ffi::CStr) -> (*mut c_void, *mut c_void) {
    // SAFETY: libc.so.6 is the process host libc; the constant flags request a local handle.
    let handle = unsafe { libc::dlopen(c"libc.so.6".as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!handle.is_null(), "dlopen libc.so.6");
    // SAFETY: `handle` came from dlopen and both C strings are NUL-terminated constants.
    let symbol = unsafe { libc::dlvsym(handle, name.as_ptr(), GLIBC_2_2_5.as_ptr()) };
    assert!(
        !symbol.is_null(),
        "dlvsym {}@GLIBC_2.2.5",
        name.to_string_lossy()
    );
    (handle, symbol)
}

fn clear_errnos() {
    unsafe {
        *errno_abi::__errno_location() = 0;
        *libc::__errno_location() = 0;
    }
}

fn fl_errno() -> c_int {
    unsafe { *errno_abi::__errno_location() }
}

fn host_errno() -> c_int {
    unsafe { *libc::__errno_location() }
}

#[test]
fn bsd_stubs_match_host_enosys_contract() {
    let path = CString::new("/nonexistent/frankenlibc-chflags").unwrap();
    clear_errnos();
    let host_chflags = unsafe { glibc_chflags()(path.as_ptr(), 0) };
    let host_chflags_errno = host_errno();
    clear_errnos();
    let fl_chflags = unsafe { fl::chflags(path.as_ptr(), 0) };
    assert_eq!(
        (fl_chflags, fl_errno()),
        (host_chflags, host_chflags_errno),
        "chflags ENOSYS contract"
    );

    let login = CString::new("frankenlibc").unwrap();
    clear_errnos();
    let host_setlogin = unsafe { glibc_setlogin()(login.as_ptr()) };
    let host_setlogin_errno = host_errno();
    clear_errnos();
    let fl_setlogin = unsafe { fl::setlogin(login.as_ptr()) };
    assert_eq!(
        (fl_setlogin, fl_errno()),
        (host_setlogin, host_setlogin_errno),
        "setlogin ENOSYS contract"
    );
}

#[test]
fn revoke_matches_host_enosys_contract() {
    let path = CString::new("/nonexistent/frankenlibc-revoke").unwrap();
    clear_errnos();
    let host_result = unsafe { glibc_revoke()(path.as_ptr()) };
    let host_result_errno = host_errno();
    clear_errnos();
    let fl_result = unsafe { fl::revoke(path.as_ptr()) };
    assert_eq!(
        (fl_result, fl_errno()),
        (host_result, host_result_errno),
        "revoke ENOSYS contract"
    );
}

#[test]
fn obsolete_linux_stubs_match_host_enosys_contract() {
    let (bdflush_handle, bdflush_symbol) = unsafe { host_versioned_symbol(c"bdflush") };
    // SAFETY: dlvsym resolved the documented bdflush@GLIBC_2.2.5 signature;
    // Linux uses identical pointer representation for this function pointer and dlsym result.
    let host_bdflush = unsafe {
        BdflushSymbol {
            raw: bdflush_symbol,
        }
        .function
    };
    clear_errnos();
    // SAFETY: host_bdflush was resolved as the exact C ABI signature.
    let host_bdflush = unsafe { host_bdflush(0, 0) };
    let host_bdflush_errno = host_errno();
    // SAFETY: the resolved function is no longer used after this call.
    assert_eq!(
        unsafe { libc::dlclose(bdflush_handle) },
        0,
        "dlclose bdflush"
    );
    clear_errnos();
    let fl_bdflush = unsafe { fl::bdflush(0, 0) };
    assert_eq!(
        (fl_bdflush, fl_errno()),
        (host_bdflush, host_bdflush_errno),
        "bdflush ENOSYS contract"
    );

    let (sstk_handle, sstk_symbol) = unsafe { host_versioned_symbol(c"sstk") };
    // SAFETY: dlvsym resolved the documented sstk@GLIBC_2.2.5 signature;
    // Linux uses identical pointer representation for this function pointer and dlsym result.
    let host_sstk = unsafe { SstkSymbol { raw: sstk_symbol }.function };
    clear_errnos();
    // SAFETY: host_sstk was resolved as the exact C ABI signature.
    let host_sstk = unsafe { host_sstk(0) };
    let host_sstk_errno = host_errno();
    // SAFETY: the resolved function is no longer used after this call.
    assert_eq!(unsafe { libc::dlclose(sstk_handle) }, 0, "dlclose sstk");
    clear_errnos();
    let fl_sstk = unsafe { fl::sstk(0) };
    assert_eq!(
        (fl_sstk, fl_errno()),
        (host_sstk, host_sstk_errno),
        "sstk ENOSYS contract"
    );
}
