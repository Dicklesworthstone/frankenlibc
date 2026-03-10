#![cfg(target_os = "linux")]

//! Integration tests for err.h ABI entrypoints (warn/warnx only;
//! err/errx call _exit and cannot be tested in-process).

use frankenlibc_abi::err_abi::{vwarn, vwarnx, warn, warnx};
use std::ffi::c_char;

// ---------------------------------------------------------------------------
// warn / warnx — these write to stderr but don't exit
// ---------------------------------------------------------------------------

#[test]
fn test_warn_null_fmt() {
    // warn(NULL) should print "progname: strerror(errno)\n" without crashing.
    unsafe { warn(std::ptr::null()) };
}

#[test]
fn test_warn_simple_message() {
    let msg = b"test message %d\0";
    // This will print "progname: test message <garbage>: strerror(errno)\n"
    // We just verify it doesn't crash.
    unsafe { warn(msg.as_ptr() as *const c_char) };
}

#[test]
fn test_warn_empty_fmt() {
    let msg = b"\0";
    unsafe { warn(msg.as_ptr() as *const c_char) };
}

#[test]
fn test_warn_long_message() {
    // Test with a longer format string
    let msg = b"this is a longer warning message with no format specifiers\0";
    unsafe { warn(msg.as_ptr() as *const c_char) };
}

#[test]
fn test_warn_percent_literal() {
    // Test %% (literal percent) in format string
    let msg = b"100%% complete\0";
    unsafe { warn(msg.as_ptr() as *const c_char) };
}

#[test]
fn test_warnx_null_fmt() {
    // warnx(NULL) should print "progname: \n" without crashing.
    unsafe { warnx(std::ptr::null()) };
}

#[test]
fn test_warnx_simple_message() {
    let msg = b"simple warning\0";
    unsafe { warnx(msg.as_ptr() as *const c_char) };
}

#[test]
fn test_warnx_empty_fmt() {
    let msg = b"\0";
    unsafe { warnx(msg.as_ptr() as *const c_char) };
}

#[test]
fn test_warnx_long_message() {
    let msg = b"this is a warnx message without errno appended\0";
    unsafe { warnx(msg.as_ptr() as *const c_char) };
}

#[test]
fn test_warnx_percent_literal() {
    let msg = b"50%% done\0";
    unsafe { warnx(msg.as_ptr() as *const c_char) };
}

#[test]
fn test_vwarn_null_fmt() {
    unsafe { vwarn(std::ptr::null(), std::ptr::null_mut()) };
}

#[test]
fn test_vwarnx_null_fmt() {
    unsafe { vwarnx(std::ptr::null(), std::ptr::null_mut()) };
}

// ---------------------------------------------------------------------------
// warn/warnx with errno set — verify errno context doesn't crash
// ---------------------------------------------------------------------------

#[test]
fn test_warn_with_enoent_errno() {
    // Set errno to ENOENT, then call warn — should include "No such file..."
    unsafe { *frankenlibc_abi::errno_abi::__errno_location() = libc::ENOENT };
    let msg = b"open failed\0";
    unsafe { warn(msg.as_ptr() as *const c_char) };
}

#[test]
fn test_warn_with_eperm_errno() {
    unsafe { *frankenlibc_abi::errno_abi::__errno_location() = libc::EPERM };
    let msg = b"permission check\0";
    unsafe { warn(msg.as_ptr() as *const c_char) };
}

#[test]
fn test_warn_with_zero_errno() {
    // errno=0 → "Success"
    unsafe { *frankenlibc_abi::errno_abi::__errno_location() = 0 };
    let msg = b"no error\0";
    unsafe { warn(msg.as_ptr() as *const c_char) };
}

// ---------------------------------------------------------------------------
// Multiple sequential calls — exercise progname caching
// ---------------------------------------------------------------------------

#[test]
fn test_warn_warnx_interleaved() {
    let w1 = b"first warn\0";
    let w2 = b"then warnx\0";
    let w3 = b"back to warn\0";
    unsafe {
        warn(w1.as_ptr() as *const c_char);
        warnx(w2.as_ptr() as *const c_char);
        warn(w3.as_ptr() as *const c_char);
    }
}

// ---------------------------------------------------------------------------
// Thread safety — concurrent warn/warnx calls
// ---------------------------------------------------------------------------

#[test]
fn test_warn_concurrent() {
    let handles: Vec<_> = (0..4)
        .map(|i| {
            std::thread::spawn(move || {
                let msg = format!("thread {} warning\0", i);
                unsafe { warn(msg.as_ptr() as *const c_char) };
                unsafe { warnx(msg.as_ptr() as *const c_char) };
            })
        })
        .collect();

    for h in handles {
        h.join().unwrap();
    }
}
