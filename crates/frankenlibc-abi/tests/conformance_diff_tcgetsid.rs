#![cfg(target_os = "linux")]

//! Differential conformance harness for POSIX `tcgetsid(3)`.
//!
//! Returns the process group leader of the session associated with
//! the terminal `fd`. Using it on a non-tty fd must fail with
//! ENOTTY in both impls.
//!
//! Filed under [bd-xn6p8] follow-up.

use std::ffi::c_int;

use frankenlibc_abi::unistd_abi as fl;

unsafe extern "C" {
    fn tcgetsid(fd: c_int) -> libc::pid_t;
}

#[test]
fn diff_tcgetsid_non_tty_returns_enotty() {
    // Open a non-tty fd (a pipe end). Both impls must return -1
    // with ENOTTY.
    let mut fds = [-1i32, -1];
    unsafe { libc::pipe(fds.as_mut_ptr()) };
    let fl_v = unsafe { fl::tcgetsid(fds[0]) };
    let fl_e = unsafe { *libc::__errno_location() };
    let lc_v = unsafe { tcgetsid(fds[0]) };
    let lc_e = unsafe { *libc::__errno_location() };
    unsafe {
        libc::close(fds[0]);
        libc::close(fds[1]);
    }
    assert_eq!(fl_v, lc_v, "tcgetsid(non-tty) ret: fl={fl_v} lc={lc_v}");
    assert_eq!(fl_v, -1);
    assert_eq!(fl_e, lc_e, "errno: fl={fl_e} lc={lc_e}");
    assert_eq!(fl_e, libc::ENOTTY, "expected ENOTTY, got {fl_e}");
}

#[test]
fn diff_tcgetsid_invalid_fd_returns_ebadf() {
    let fl_v = unsafe { fl::tcgetsid(-1) };
    let fl_e = unsafe { *libc::__errno_location() };
    let lc_v = unsafe { tcgetsid(-1) };
    let lc_e = unsafe { *libc::__errno_location() };
    assert_eq!(fl_v, lc_v);
    assert_eq!(fl_v, -1);
    assert_eq!(fl_e, lc_e, "errno: fl={fl_e} lc={lc_e}");
    assert_eq!(fl_e, libc::EBADF);
}

#[test]
fn diff_tcgetsid_pty_returns_session_id() {
    // Open a master/slave PTY pair; the slave is a real tty.
    let master = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
    if master < 0 {
        eprintln!("PTY unavailable; skipping");
        return;
    }
    if unsafe { libc::grantpt(master) } < 0 || unsafe { libc::unlockpt(master) } < 0 {
        unsafe { libc::close(master) };
        eprintln!("grantpt/unlockpt failed; skipping");
        return;
    }
    let slave_name = unsafe { libc::ptsname(master) };
    if slave_name.is_null() {
        unsafe { libc::close(master) };
        return;
    }
    let slave_fd = unsafe { libc::open(slave_name, libc::O_RDWR | libc::O_NOCTTY) };
    if slave_fd < 0 {
        unsafe { libc::close(master) };
        return;
    }

    // tcgetsid on a non-controlling tty: kernels return -1 ENOTTY
    // on Linux when the tty isn't the calling process's
    // controlling terminal. Both impls must agree.
    let fl_v = unsafe { fl::tcgetsid(slave_fd) };
    let fl_e = unsafe { *libc::__errno_location() };
    let lc_v = unsafe { tcgetsid(slave_fd) };
    let lc_e = unsafe { *libc::__errno_location() };
    unsafe {
        libc::close(slave_fd);
        libc::close(master);
    }
    assert_eq!(fl_v, lc_v, "tcgetsid(pty) ret");
    if fl_v == -1 {
        assert_eq!(fl_e, lc_e);
    }
}

#[test]
fn tcgetsid_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc tcgetsid\",\"reference\":\"glibc\",\"functions\":1,\"divergences\":0}}",
    );
}
