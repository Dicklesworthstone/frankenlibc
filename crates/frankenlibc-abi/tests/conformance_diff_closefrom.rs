#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // forks a child to exercise closefrom on real fds

//! Behavioral gate for closefrom (bd-6br349). closefrom(lowfd) must close every
//! descriptor >= lowfd and leave lower ones open. Because that would also close
//! the test harness's own fds, the check runs entirely inside a forked child
//! that _exit()s immediately — the parent only inspects the exit code. On this
//! host (kernel 6.17) closefrom takes the close_range fast path; the older-
//! kernel brute-force fallback the fix added shares the same observable
//! contract. No mocks.

use std::ffi::c_int;

#[test]
fn closefrom_closes_fds_at_or_above_lowfd() {
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");
    if pid == 0 {
        // ---- child ----
        // dup three fresh descriptors; dup hands out the lowest free fd each
        // time, so a < b < c.
        let a = unsafe { libc::dup(2) };
        let b = unsafe { libc::dup(2) };
        let c = unsafe { libc::dup(2) };
        let ok_setup = a >= 0 && b > a && c > b;

        unsafe { frankenlibc_abi::unistd_abi::closefrom(b) };

        // a (< b) must remain open; b and c (>= b) must be closed.
        let a_open = unsafe { libc::fcntl(a, libc::F_GETFD) } >= 0;
        let b_closed = unsafe { libc::fcntl(b, libc::F_GETFD) } < 0;
        let c_closed = unsafe { libc::fcntl(c, libc::F_GETFD) } < 0;

        let code: c_int = if ok_setup && a_open && b_closed && c_closed { 0 } else { 1 };
        unsafe { libc::_exit(code) };
    }

    // ---- parent ----
    let mut status: c_int = 0;
    let w = unsafe { libc::waitpid(pid, &mut status, 0) };
    assert_eq!(w, pid, "waitpid failed");
    assert!(libc::WIFEXITED(status), "child did not exit normally");
    assert_eq!(
        libc::WEXITSTATUS(status),
        0,
        "closefrom must close fds >= lowfd and keep lower ones"
    );
}
