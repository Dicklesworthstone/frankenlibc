#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // forks a child to exercise closefrom on real fds

//! Behavioral gate for closefrom (bd-6br349). closefrom(lowfd) must close every
//! descriptor >= lowfd and leave lower ones open. Because that would also close
//! the test harness's own fds, the check runs entirely inside a forked child
//! that _exit()s immediately — the parent only inspects the exit code. No mocks.
//!
//! On this host (kernel 6.17) closefrom takes the close_range fast path, so the
//! fallbacks that carry the contract on kernels < 5.9 — or wherever seccomp
//! denies close_range — would never execute under test. They are therefore
//! driven DIRECTLY as well, rather than asserted to "share the same contract":
//! that assumption is exactly what let closefrom ship as a silent no-op, since
//! discarding the close_range result is invisible on any host that has it.

use std::ffi::c_int;

/// Exit-code channel for the forked children: the fds under test may include
/// the ones stdio would need, so a child reports by bit rather than by writing.
fn child_verdict(child: impl FnOnce() -> bool) -> bool {
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");
    if pid == 0 {
        let ok = child();
        unsafe { libc::_exit(if ok { 0 } else { 1 }) };
    }
    let mut status: c_int = 0;
    let w = unsafe { libc::waitpid(pid, &mut status, 0) };
    assert_eq!(w, pid, "waitpid failed");
    assert!(libc::WIFEXITED(status), "child did not exit normally");
    libc::WEXITSTATUS(status) == 0
}

fn is_open(fd: c_int) -> bool {
    unsafe { libc::fcntl(fd, libc::F_GETFD) >= 0 }
}

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

        let code: c_int = if ok_setup && a_open && b_closed && c_closed {
            0
        } else {
            1
        };
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

#[test]
fn closefrom_proc_fallback_closes_the_same_fds_as_close_range() {
    // Drives the /proc/self/fd walk directly. Without this the fallback is
    // dead code on every machine that can run the suite.
    assert!(
        child_verdict(|| {
            let a = unsafe { libc::dup(2) };
            let b = unsafe { libc::dup(2) };
            let c = unsafe { libc::dup(2) };
            if !(a >= 0 && b > a && c > b) {
                return false;
            }
            if !frankenlibc_abi::unistd_abi::closefrom_proc_fallback(b as u32) {
                return false; // /proc unavailable: reported, not silently passed
            }
            is_open(a) && !is_open(b) && !is_open(c)
        }),
        "the /proc fallback must close fds >= lowfd and keep lower ones"
    );
}

#[test]
fn closefrom_rlimit_fallback_closes_the_same_fds_as_close_range() {
    // The last resort, used when /proc is not mounted. Same observable
    // contract, reached without reading any directory.
    assert!(
        child_verdict(|| {
            let a = unsafe { libc::dup(2) };
            let b = unsafe { libc::dup(2) };
            let c = unsafe { libc::dup(2) };
            if !(a >= 0 && b > a && c > b) {
                return false;
            }
            frankenlibc_abi::unistd_abi::closefrom_rlimit_fallback(b as u32);
            is_open(a) && !is_open(b) && !is_open(c)
        }),
        "the rlimit fallback must close fds >= lowfd and keep lower ones"
    );
}

#[test]
fn closefrom_negative_lowfd_closes_everything_like_glibc() {
    // Measured against live glibc 2.42: closefrom(-1) clamps to 0 and closes
    // every descriptor. Casting lowfd straight to u32 instead asks close_range
    // to start near 2^32, which closes NOTHING — the opposite of the contract,
    // and silent.
    assert!(
        child_verdict(|| {
            let hi = unsafe { libc::dup2(2, 100) };
            if hi != 100 {
                return false;
            }
            unsafe { frankenlibc_abi::unistd_abi::closefrom(-1) };
            !is_open(100) && !is_open(0) && !is_open(1) && !is_open(2)
        }),
        "closefrom(-1) must clamp to 0 and close every descriptor, as glibc does"
    );
}

#[test]
fn closefrom_above_every_open_fd_is_a_noop() {
    // Negative control for the arms above: a lowfd past everything open must
    // leave the process untouched, so "closes fds >= lowfd" is being measured
    // rather than "closes fds".
    assert!(
        child_verdict(|| {
            let hi = unsafe { libc::dup2(2, 100) };
            if hi != 100 {
                return false;
            }
            unsafe { frankenlibc_abi::unistd_abi::closefrom(200) };
            is_open(100) && is_open(2)
        }),
        "closefrom(200) must leave lower descriptors open"
    );
}
