#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc wait oracle; forks short-lived children

//! Differential gate for wait3 / wait4 / waitid (bd-cttqvh) — waitpid is gated
//! but these were not. Each test forks a child that immediately _exit()s with a
//! known code; the parent reaps it through the function under test and the
//! decoded result (reaped pid, WIFEXITED, WEXITSTATUS, or waitid's si_code) is
//! compared vs glibc. Each impl reaps its own child. No mocks.

use std::ffi::c_int;
use std::mem::MaybeUninit;

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn wait4(
            pid: libc::pid_t,
            st: *mut c_int,
            opt: c_int,
            ru: *mut libc::rusage,
        ) -> libc::pid_t;
        pub fn wait3(st: *mut c_int, opt: c_int, ru: *mut libc::rusage) -> libc::pid_t;
        pub fn waitid(idtype: c_int, id: libc::id_t, si: *mut libc::siginfo_t, opt: c_int)
        -> c_int;
    }
}
use frankenlibc_abi::process_abi as fl;

const P_PID: c_int = 1;
const WEXITED: c_int = 4;
const CLD_EXITED: c_int = 1;

/// Fork a child that _exit(code)s; returns its pid (parent only).
fn spawn_child(code: c_int) -> libc::pid_t {
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe { libc::_exit(code) };
    }
    assert!(pid > 0, "fork failed");
    pid
}

fn decode(pid: libc::pid_t, st: c_int) -> (bool, bool, c_int) {
    (pid > 0, libc::WIFEXITED(st), libc::WEXITSTATUS(st))
}

#[test]
fn wait4_matches_glibc() {
    let gr = unsafe {
        let pid = spawn_child(42);
        let mut st = 0;
        let mut ru = MaybeUninit::<libc::rusage>::zeroed();
        let r = g::wait4(pid, &mut st, 0, ru.as_mut_ptr());
        decode(r, st)
    };
    let fr = unsafe {
        let pid = spawn_child(42);
        let mut st = 0;
        let mut ru = MaybeUninit::<libc::rusage>::zeroed();
        let r = fl::wait4(pid, &mut st, 0, ru.as_mut_ptr());
        decode(r, st)
    };
    assert_eq!(fr, gr, "wait4: fl={fr:?} glibc={gr:?}");
    assert_eq!(gr, (true, true, 42), "glibc: reaped, WIFEXITED, status 42");
}

#[test]
fn wait3_matches_glibc() {
    let gr = unsafe {
        let _pid = spawn_child(17);
        let mut st = 0;
        let mut ru = MaybeUninit::<libc::rusage>::zeroed();
        let r = g::wait3(&mut st, 0, ru.as_mut_ptr());
        decode(r, st)
    };
    let fr = unsafe {
        let _pid = spawn_child(17);
        let mut st = 0;
        let mut ru = MaybeUninit::<libc::rusage>::zeroed();
        let r = fl::wait3(&mut st, 0, ru.as_mut_ptr());
        decode(r, st)
    };
    assert_eq!(fr, gr, "wait3: fl={fr:?} glibc={gr:?}");
    assert_eq!(gr, (true, true, 17), "glibc: reaped, WIFEXITED, status 17");
}

#[test]
fn waitid_matches_glibc() {
    let gr = unsafe {
        let pid = spawn_child(99);
        let mut si = MaybeUninit::<libc::siginfo_t>::zeroed();
        let rc = g::waitid(P_PID, pid as libc::id_t, si.as_mut_ptr(), WEXITED);
        (rc, si.assume_init().si_code)
    };
    let fr = unsafe {
        let pid = spawn_child(99);
        let mut si = MaybeUninit::<libc::siginfo_t>::zeroed();
        let rc = fl::waitid(P_PID, pid as libc::id_t, si.as_mut_ptr(), WEXITED);
        (rc, si.assume_init().si_code)
    };
    assert_eq!(fr, gr, "waitid: fl={fr:?} glibc={gr:?}");
    assert_eq!(gr, (0, CLD_EXITED), "glibc: rc 0, si_code CLD_EXITED");
}
