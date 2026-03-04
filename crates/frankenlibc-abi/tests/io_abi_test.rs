#![cfg(target_os = "linux")]

//! Integration tests for POSIX I/O ABI entrypoints (dup, dup2, dup3, pipe, fcntl).

use std::ffi::c_int;

use frankenlibc_abi::io_abi::{dup, dup2};
use frankenlibc_abi::unistd_abi::close;

// ---------------------------------------------------------------------------
// Helper: create a disposable fd
// ---------------------------------------------------------------------------

fn temp_fd() -> c_int {
    // Create a pipe and return the read end (close write end)
    let mut fds = [0 as c_int; 2];
    let rc = unsafe { frankenlibc_abi::io_abi::pipe(&mut fds as *mut c_int) };
    assert_eq!(rc, 0, "pipe() should succeed");
    unsafe { close(fds[1]) };
    fds[0]
}

// ---------------------------------------------------------------------------
// dup
// ---------------------------------------------------------------------------

#[test]
fn dup_returns_new_fd() {
    let fd = temp_fd();
    let new_fd = unsafe { dup(fd) };
    assert!(new_fd >= 0, "dup should return a valid fd, got {new_fd}");
    assert_ne!(fd, new_fd, "dup should return a different fd");
    unsafe { close(new_fd) };
    unsafe { close(fd) };
}

#[test]
fn dup_negative_fd_fails() {
    let new_fd = unsafe { dup(-1) };
    assert_eq!(new_fd, -1, "dup(-1) should fail");
}

// ---------------------------------------------------------------------------
// dup2
// ---------------------------------------------------------------------------

#[test]
fn dup2_to_specific_fd() {
    let fd = temp_fd();
    // Use a high fd number unlikely to be in use
    let target = 200;
    let rc = unsafe { dup2(fd, target) };
    assert_eq!(rc, target, "dup2 should return the target fd");
    unsafe { close(target) };
    unsafe { close(fd) };
}

#[test]
fn dup2_same_fd_is_noop() {
    let fd = temp_fd();
    let rc = unsafe { dup2(fd, fd) };
    assert_eq!(rc, fd, "dup2(fd, fd) should return fd unchanged");
    unsafe { close(fd) };
}

// ---------------------------------------------------------------------------
// dup3
// ---------------------------------------------------------------------------

#[test]
fn dup3_with_cloexec() {
    use frankenlibc_abi::io_abi::dup3;
    let fd = temp_fd();
    let target = 201;
    let rc = unsafe { dup3(fd, target, libc::O_CLOEXEC) };
    assert_eq!(rc, target, "dup3 should return the target fd");
    unsafe { close(target) };
    unsafe { close(fd) };
}

// ---------------------------------------------------------------------------
// pipe / pipe2
// ---------------------------------------------------------------------------

#[test]
fn pipe_creates_pair() {
    use frankenlibc_abi::io_abi::pipe;
    let mut fds = [0 as c_int; 2];
    let rc = unsafe { pipe(&mut fds as *mut c_int) };
    assert_eq!(rc, 0, "pipe() should succeed");
    assert!(fds[0] >= 0);
    assert!(fds[1] >= 0);
    assert_ne!(fds[0], fds[1]);

    // Write to write end, read from read end
    let msg = b"hello";
    let written = unsafe { libc::write(fds[1], msg.as_ptr() as *const _, msg.len()) };
    assert_eq!(written, msg.len() as isize);

    let mut buf = [0u8; 16];
    let read_n = unsafe { libc::read(fds[0], buf.as_mut_ptr() as *mut _, buf.len()) };
    assert_eq!(read_n, msg.len() as isize);
    assert_eq!(&buf[..msg.len()], msg);

    unsafe { close(fds[0]) };
    unsafe { close(fds[1]) };
}

#[test]
fn pipe2_cloexec() {
    use frankenlibc_abi::io_abi::pipe2;
    let mut fds = [0 as c_int; 2];
    let rc = unsafe { pipe2(&mut fds as *mut c_int, libc::O_CLOEXEC) };
    assert_eq!(rc, 0, "pipe2 with O_CLOEXEC should succeed");
    assert!(fds[0] >= 0);
    assert!(fds[1] >= 0);
    unsafe { close(fds[0]) };
    unsafe { close(fds[1]) };
}

#[test]
fn pipe_null_fails() {
    use frankenlibc_abi::io_abi::pipe;
    let rc = unsafe { pipe(std::ptr::null_mut()) };
    assert_eq!(rc, -1, "pipe(NULL) should fail");
}

// ---------------------------------------------------------------------------
// close
// ---------------------------------------------------------------------------

#[test]
fn close_valid_fd() {
    let fd = temp_fd();
    let rc = unsafe { close(fd) };
    assert_eq!(rc, 0, "close should succeed");
}

#[test]
fn close_invalid_fd() {
    let rc = unsafe { close(-1) };
    assert_eq!(rc, -1, "close(-1) should fail");
}

// ---------------------------------------------------------------------------
// fcntl
// ---------------------------------------------------------------------------

#[test]
fn fcntl_getfd() {
    use frankenlibc_abi::io_abi::fcntl;
    let fd = temp_fd();
    let flags = unsafe { fcntl(fd, libc::F_GETFD, 0) };
    assert!(flags >= 0, "fcntl F_GETFD should succeed");
    unsafe { close(fd) };
}

#[test]
fn fcntl_setfd_cloexec() {
    use frankenlibc_abi::io_abi::fcntl;
    let fd = temp_fd();
    let rc = unsafe { fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC as libc::c_long) };
    assert_eq!(rc, 0, "fcntl F_SETFD should succeed");

    let flags = unsafe { fcntl(fd, libc::F_GETFD, 0) };
    assert_ne!(flags & libc::FD_CLOEXEC, 0, "FD_CLOEXEC should be set");
    unsafe { close(fd) };
}

#[test]
fn fcntl_getfl() {
    use frankenlibc_abi::io_abi::fcntl;
    let fd = temp_fd();
    let flags = unsafe { fcntl(fd, libc::F_GETFL, 0) };
    assert!(flags >= 0, "fcntl F_GETFL should succeed");
    unsafe { close(fd) };
}
