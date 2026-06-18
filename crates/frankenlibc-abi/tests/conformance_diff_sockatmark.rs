#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc sockatmark oracle + socketpair fds

//! Differential coverage for `sockatmark(3)`.
//!
//! `sockatmark` is a thin SIOCATMARK query. This gate checks the stable error
//! contract for an invalid descriptor and the ordinary not-at-mark result on a
//! live stream socket, comparing FrankenLibC with host glibc in one process.

use frankenlibc_abi::errno_abi::__errno_location as fl_errno_location;
use frankenlibc_abi::unistd_abi as fl;
use std::ffi::{c_char, c_int, c_void};

type SockatmarkFn = unsafe extern "C" fn(c_int) -> c_int;

const RTLD_NOW: c_int = 2;

unsafe extern "C" {
    fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}

fn host_sockatmark() -> SockatmarkFn {
    unsafe {
        let lib = dlopen(c"libc.so.6".as_ptr(), RTLD_NOW);
        assert!(!lib.is_null(), "dlopen(libc.so.6) failed");
        let symbol = dlsym(lib, c"sockatmark".as_ptr());
        assert!(!symbol.is_null(), "dlsym(sockatmark) failed");
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

#[test]
fn sockatmark_invalid_fd_matches_host_errno() {
    let host = host_sockatmark();

    set_host_errno(0);
    let host_rc = unsafe { host(-1) };
    let host_err = host_errno();

    set_fl_errno(0);
    let fl_rc = unsafe { fl::sockatmark(-1) };
    let fl_err = fl_errno();

    assert_eq!(
        (fl_rc, fl_err),
        (host_rc, host_err),
        "sockatmark(-1): fl=({fl_rc}, {fl_err}) glibc=({host_rc}, {host_err})"
    );
    assert_eq!((fl_rc, fl_err), (-1, libc::EBADF));
}

#[test]
fn sockatmark_stream_socket_not_at_mark_matches_host() {
    let host = host_sockatmark();
    let mut fds = [-1 as c_int; 2];
    let pair_rc =
        unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
    assert_eq!(pair_rc, 0, "socketpair failed with errno {}", host_errno());

    set_host_errno(0);
    let host_rc = unsafe { host(fds[0]) };
    let host_err = host_errno();

    set_fl_errno(0);
    let fl_rc = unsafe { fl::sockatmark(fds[0]) };
    let fl_err = fl_errno();

    unsafe {
        libc::close(fds[0]);
        libc::close(fds[1]);
    }

    assert_eq!(
        (fl_rc, fl_err),
        (host_rc, host_err),
        "sockatmark(stream socket): fl=({fl_rc}, {fl_err}) \
         glibc=({host_rc}, {host_err})"
    );
    assert_eq!((fl_rc, fl_err), (0, 0));
}
