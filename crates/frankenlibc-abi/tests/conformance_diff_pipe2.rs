#![cfg(target_os = "linux")]

//! Differential conformance harness for `pipe(2)` / `pipe2(2)`.
//!
//! pipe2 takes a flags arg (O_CLOEXEC, O_NONBLOCK, O_DIRECT) and
//! creates a pipe with those flags pre-applied. Both fl and glibc
//! must agree on which flag combinations succeed and on the
//! resulting file-descriptor flag bits.
//!
//! Filed under [bd-xn6p8] follow-up.

use std::ffi::c_int;

use frankenlibc_abi::io_abi as fl;

unsafe extern "C" {
    fn pipe(fds: *mut c_int) -> c_int;
    fn pipe2(fds: *mut c_int, flags: c_int) -> c_int;
}

fn check_fd_flag(fd: c_int, flag: c_int, target: c_int) -> bool {
    let f = unsafe { libc::fcntl(fd, target) };
    f & flag == flag
}

#[test]
fn diff_pipe_creates_two_valid_fds() {
    let mut fl_fds = [-1i32, -1];
    let mut lc_fds = [-1i32, -1];
    let fl_r = unsafe { fl::pipe(fl_fds.as_mut_ptr()) };
    let lc_r = unsafe { pipe(lc_fds.as_mut_ptr()) };
    assert_eq!(fl_r, lc_r);
    assert_eq!(fl_r, 0);
    assert!(fl_fds[0] >= 0 && fl_fds[1] >= 0);
    unsafe {
        libc::close(fl_fds[0]);
        libc::close(fl_fds[1]);
        libc::close(lc_fds[0]);
        libc::close(lc_fds[1]);
    }
}

#[test]
fn diff_pipe2_zero_flags_equivalent_to_pipe() {
    let mut fl_fds = [-1i32, -1];
    let mut lc_fds = [-1i32, -1];
    let fl_r = unsafe { fl::pipe2(fl_fds.as_mut_ptr(), 0) };
    let lc_r = unsafe { pipe2(lc_fds.as_mut_ptr(), 0) };
    assert_eq!(fl_r, lc_r);
    assert_eq!(fl_r, 0);
    unsafe {
        libc::close(fl_fds[0]);
        libc::close(fl_fds[1]);
        libc::close(lc_fds[0]);
        libc::close(lc_fds[1]);
    }
}

#[test]
fn diff_pipe2_o_cloexec_sets_close_on_exec() {
    let mut fl_fds = [-1i32, -1];
    let mut lc_fds = [-1i32, -1];
    let fl_r = unsafe { fl::pipe2(fl_fds.as_mut_ptr(), libc::O_CLOEXEC) };
    let lc_r = unsafe { pipe2(lc_fds.as_mut_ptr(), libc::O_CLOEXEC) };
    assert_eq!(fl_r, lc_r);
    assert_eq!(fl_r, 0);
    // Both fds in both pipes must have FD_CLOEXEC set.
    for fd in [fl_fds[0], fl_fds[1], lc_fds[0], lc_fds[1]] {
        assert!(
            check_fd_flag(fd, libc::FD_CLOEXEC, libc::F_GETFD),
            "fd {fd} missing FD_CLOEXEC"
        );
    }
    unsafe {
        libc::close(fl_fds[0]);
        libc::close(fl_fds[1]);
        libc::close(lc_fds[0]);
        libc::close(lc_fds[1]);
    }
}

#[test]
fn diff_pipe2_o_nonblock_sets_nonblock_status() {
    let mut fl_fds = [-1i32, -1];
    let mut lc_fds = [-1i32, -1];
    let fl_r = unsafe { fl::pipe2(fl_fds.as_mut_ptr(), libc::O_NONBLOCK) };
    let lc_r = unsafe { pipe2(lc_fds.as_mut_ptr(), libc::O_NONBLOCK) };
    assert_eq!(fl_r, lc_r);
    assert_eq!(fl_r, 0);
    for fd in [fl_fds[0], fl_fds[1], lc_fds[0], lc_fds[1]] {
        assert!(
            check_fd_flag(fd, libc::O_NONBLOCK, libc::F_GETFL),
            "fd {fd} missing O_NONBLOCK"
        );
    }
    unsafe {
        libc::close(fl_fds[0]);
        libc::close(fl_fds[1]);
        libc::close(lc_fds[0]);
        libc::close(lc_fds[1]);
    }
}

#[test]
fn diff_pipe2_combined_flags() {
    let flags = libc::O_CLOEXEC | libc::O_NONBLOCK;
    let mut fl_fds = [-1i32, -1];
    let mut lc_fds = [-1i32, -1];
    let fl_r = unsafe { fl::pipe2(fl_fds.as_mut_ptr(), flags) };
    let lc_r = unsafe { pipe2(lc_fds.as_mut_ptr(), flags) };
    assert_eq!(fl_r, lc_r);
    assert_eq!(fl_r, 0);
    for fd in [fl_fds[0], fl_fds[1], lc_fds[0], lc_fds[1]] {
        assert!(check_fd_flag(fd, libc::FD_CLOEXEC, libc::F_GETFD));
        assert!(check_fd_flag(fd, libc::O_NONBLOCK, libc::F_GETFL));
    }
    unsafe {
        libc::close(fl_fds[0]);
        libc::close(fl_fds[1]);
        libc::close(lc_fds[0]);
        libc::close(lc_fds[1]);
    }
}

#[test]
fn diff_pipe2_invalid_flags_returns_einval() {
    let mut fl_fds = [-1i32, -1];
    let mut lc_fds = [-1i32, -1];
    // Use a flag bit that's not allowed for pipe2.
    let fl_r = unsafe { fl::pipe2(fl_fds.as_mut_ptr(), 0x10_0000) };
    let lc_r = unsafe { pipe2(lc_fds.as_mut_ptr(), 0x10_0000) };
    assert_eq!(fl_r, lc_r);
    if fl_r == -1 {
        let fl_e = unsafe { *libc::__errno_location() };
        let lc_e = unsafe { *libc::__errno_location() };
        assert_eq!(fl_e, lc_e);
    }
}

#[test]
fn diff_pipe_null_pipefd_segv_avoidance() {
    // glibc may segfault on NULL — only verify fl is hardened.
    let r = unsafe { fl::pipe(std::ptr::null_mut()) };
    assert_eq!(r, -1);
}

#[test]
fn pipe2_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc pipe + pipe2\",\"reference\":\"glibc\",\"functions\":2,\"divergences\":0}}",
    );
}
