//! Differential gate: dup2(fd, fd) returns fd for a valid fd and EBADF for a
//! closed one, matching glibc — never EINVAL.
//!
//! POSIX dup2(fd, fd) is a no-op returning fd when fd is valid. On arches with
//! no native dup2 syscall (aarch64), routing through dup3(fd, fd, 0) would
//! return EINVAL, so glibc special-cases equal fds (validate via fcntl, return
//! fd). This gate validates the contract and fl's equal-fd code path on x86_64
//! (where fl now takes the same fcntl path) against the host's dup2.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::io_abi as fl;
use std::ffi::c_int;

fn errno_now() -> c_int {
    unsafe { *libc::__errno_location() }
}

/// A valid, open fd (the read end of a pipe; the write end is leaked but the
/// test process is short-lived).
fn open_fd() -> c_int {
    let mut fds = [0 as c_int; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
    fds[0]
}

/// An in-range but closed fd: open then close /dev/null.
fn closed_fd() -> c_int {
    let fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
    assert!(fd >= 0, "open /dev/null");
    unsafe { libc::close(fd) };
    fd
}

#[test]
fn dup2_same_valid_fd_returns_fd_like_glibc() {
    let valid = open_fd();

    unsafe { *libc::__errno_location() = 0 };
    let g = unsafe { libc::dup2(valid, valid) };
    let ge = errno_now();

    unsafe { *libc::__errno_location() = 0 };
    let f = unsafe { fl::dup2(valid, valid) };
    let fe = errno_now();

    assert_eq!(g, valid, "glibc dup2(fd,fd) should return fd");
    assert_eq!(f, g, "dup2(fd,fd) rc: glibc={g} fl={f}");
    if g >= 0 {
        // On success errno is unspecified; only require fl also succeeded.
        let _ = (ge, fe);
    }
}

#[test]
fn dup2_same_closed_fd_is_ebadf_like_glibc() {
    let bad = closed_fd();

    unsafe { *libc::__errno_location() = 0 };
    let g = unsafe { libc::dup2(bad, bad) };
    let ge = errno_now();

    unsafe { *libc::__errno_location() = 0 };
    let f = unsafe { fl::dup2(bad, bad) };
    let fe = errno_now();

    assert_eq!(g, -1, "glibc dup2(closed,closed) should fail");
    assert_eq!(ge, libc::EBADF, "glibc errno should be EBADF (not EINVAL)");
    assert_eq!(f, g, "dup2(closed,closed) rc: glibc={g} fl={f}");
    assert_eq!(fe, ge, "dup2(closed,closed) errno: glibc={ge} fl={fe}");
}
