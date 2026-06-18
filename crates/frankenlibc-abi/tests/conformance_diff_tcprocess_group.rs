#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc tcgetpgrp/tcsetpgrp oracle

//! Differential coverage for terminal process-group queries.
//!
//! `tcgetsid` already has a live differential gate; this covers `tcgetpgrp`
//! and `tcsetpgrp` on contracts that do not mutate a real terminal: invalid
//! descriptors and `/dev/null` as a stable non-tty descriptor.

use frankenlibc_abi::errno_abi::__errno_location as fl_errno_location;
use frankenlibc_abi::unistd_abi as fl;
use std::ffi::{c_char, c_int, c_void};

type TcgetpgrpFn = unsafe extern "C" fn(c_int) -> libc::pid_t;
type TcsetpgrpFn = unsafe extern "C" fn(c_int, libc::pid_t) -> c_int;

const RTLD_NOW: c_int = 2;

unsafe extern "C" {
    fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}

fn libc_handle() -> *mut c_void {
    unsafe {
        let lib = dlopen(c"libc.so.6".as_ptr(), RTLD_NOW);
        assert!(!lib.is_null(), "dlopen(libc.so.6) failed");
        lib
    }
}

fn host_tcgetpgrp(lib: *mut c_void) -> TcgetpgrpFn {
    unsafe {
        let symbol = dlsym(lib, c"tcgetpgrp".as_ptr());
        assert!(!symbol.is_null(), "dlsym(tcgetpgrp) failed");
        std::mem::transmute(symbol)
    }
}

fn host_tcsetpgrp(lib: *mut c_void) -> TcsetpgrpFn {
    unsafe {
        let symbol = dlsym(lib, c"tcsetpgrp".as_ptr());
        assert!(!symbol.is_null(), "dlsym(tcsetpgrp) failed");
        std::mem::transmute(symbol)
    }
}

fn host_errno() -> c_int {
    unsafe { *libc::__errno_location() }
}

fn set_host_errno(value: c_int) {
    unsafe { *libc::__errno_location() = value };
}

fn fl_errno() -> c_int {
    unsafe { *fl_errno_location() }
}

fn set_fl_errno(value: c_int) {
    unsafe { *fl_errno_location() = value };
}

fn open_dev_null() -> c_int {
    let fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
    assert!(fd >= 0, "open(/dev/null) failed with errno {}", host_errno());
    fd
}

#[test]
fn tcgetpgrp_invalid_and_non_tty_match_host() {
    let lib = libc_handle();
    let host = host_tcgetpgrp(lib);

    for (label, fd, expected_errno) in [
        ("invalid fd", -1, libc::EBADF),
        ("/dev/null", open_dev_null(), libc::ENOTTY),
    ] {
        set_host_errno(0);
        let host_rc = unsafe { host(fd) };
        let host_err = host_errno();

        set_fl_errno(0);
        let fl_rc = unsafe { fl::tcgetpgrp(fd) };
        let fl_err = fl_errno();

        if fd >= 0 {
            unsafe { libc::close(fd) };
        }

        assert_eq!(
            (fl_rc, fl_err),
            (host_rc, host_err),
            "tcgetpgrp({label}): fl=({fl_rc}, {fl_err}) \
             glibc=({host_rc}, {host_err})"
        );
        assert_eq!((fl_rc, fl_err), (-1, expected_errno), "tcgetpgrp({label})");
    }
}

#[test]
fn tcsetpgrp_invalid_and_non_tty_match_host() {
    let lib = libc_handle();
    let host = host_tcsetpgrp(lib);
    let pgrp = unsafe { libc::getpgrp() };
    assert!(pgrp > 0, "getpgrp returned {pgrp}");

    for (label, fd, expected_errno) in [
        ("invalid fd", -1, libc::EBADF),
        ("/dev/null", open_dev_null(), libc::ENOTTY),
    ] {
        set_host_errno(0);
        let host_rc = unsafe { host(fd, pgrp) };
        let host_err = host_errno();

        set_fl_errno(0);
        let fl_rc = unsafe { fl::tcsetpgrp(fd, pgrp) };
        let fl_err = fl_errno();

        if fd >= 0 {
            unsafe { libc::close(fd) };
        }

        assert_eq!(
            (fl_rc, fl_err),
            (host_rc, host_err),
            "tcsetpgrp({label}): fl=({fl_rc}, {fl_err}) \
             glibc=({host_rc}, {host_err})"
        );
        assert_eq!((fl_rc, fl_err), (-1, expected_errno), "tcsetpgrp({label})");
    }
}
