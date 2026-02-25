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
fn test_vwarn_null_fmt() {
    unsafe { vwarn(std::ptr::null(), std::ptr::null_mut()) };
}

#[test]
fn test_vwarnx_null_fmt() {
    unsafe { vwarnx(std::ptr::null(), std::ptr::null_mut()) };
}
