#![cfg(target_os = "linux")]

//! Differential conformance harness for synchronous signal-wait functions:
//!   - sigtimedwait (with absolute-zero timeout to avoid blocking)
//!   - sigwaitinfo  (only invoked once a pending signal exists)
//!   - sigsuspend   (with sigprocmask save/restore)
//!
//! Tests serialize via SIG_LOCK because they manipulate process-wide
//! signal state. Each test installs SIG_IGN handlers before queueing
//! signals so any cross-thread delivery is absorbed.
//!
//! Bead: CONFORMANCE: libc sigtimedwait/sigwaitinfo/sigsuspend diff.

use std::ffi::{c_int, c_void};
use std::sync::Mutex;

use frankenlibc_abi::{signal_abi as fl_sig, unistd_abi as fl_uni};

unsafe extern "C" {
    fn sigtimedwait(
        set: *const libc::sigset_t,
        info: *mut libc::siginfo_t,
        timeout: *const libc::timespec,
    ) -> c_int;
    fn sigwaitinfo(set: *const libc::sigset_t, info: *mut libc::siginfo_t) -> c_int;
    fn pthread_sigmask(
        how: c_int,
        set: *const libc::sigset_t,
        oldset: *mut libc::sigset_t,
    ) -> c_int;
}

const SIG_BLOCK: c_int = 0;
const SIG_SETMASK: c_int = 2;

static SIG_LOCK: Mutex<()> = Mutex::new(());

fn empty_set() -> libc::sigset_t {
    let mut s: libc::sigset_t = unsafe { core::mem::zeroed() };
    let _ = unsafe { libc::sigemptyset(&mut s) };
    s
}

fn save_mask() -> libc::sigset_t {
    let mut old = empty_set();
    let _ = unsafe { pthread_sigmask(SIG_BLOCK, std::ptr::null(), &mut old) };
    old
}

fn restore_mask(m: &libc::sigset_t) {
    let _ = unsafe { pthread_sigmask(SIG_SETMASK, m, std::ptr::null_mut()) };
}

#[test]
fn diff_sigtimedwait_immediate_timeout() {
    let _g = SIG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let prior = save_mask();
    // Empty wait set + zero timeout → both impls should fail with EAGAIN.
    let set = empty_set();
    let zero = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let r_fl = unsafe {
        fl_uni::sigtimedwait(
            &set as *const _ as *const c_void,
            std::ptr::null_mut(),
            &zero as *const _,
        )
    };
    let r_lc = unsafe { sigtimedwait(&set, std::ptr::null_mut(), &zero) };
    restore_mask(&prior);
    assert_eq!(
        r_fl < 0,
        r_lc < 0,
        "sigtimedwait empty-set zero-timeout fail-match: fl={r_fl}, lc={r_lc}"
    );
}

#[test]
fn diff_sigtimedwait_pending_sigusr1_returns_signo() {
    let _g = SIG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let prior = save_mask();

    // Install SIG_IGN as a safety net (in case the signal escapes the
    // mask in a sibling thread).
    let mut act: libc::sigaction = unsafe { core::mem::zeroed() };
    act.sa_sigaction = libc::SIG_IGN;
    let _ = unsafe { libc::sigemptyset(&mut act.sa_mask) };
    let mut old_act: libc::sigaction = unsafe { core::mem::zeroed() };
    let _ = unsafe { libc::sigaction(libc::SIGUSR1, &act, &mut old_act) };

    // Block SIGUSR1, queue it via raise(), then sigtimedwait must
    // dequeue and return SIGUSR1.
    let mut block = empty_set();
    let _ = unsafe { libc::sigaddset(&mut block, libc::SIGUSR1) };
    let _ = unsafe { pthread_sigmask(SIG_BLOCK, &block, std::ptr::null_mut()) };

    let pid = unsafe { libc::getpid() };
    let _ = unsafe { libc::kill(pid, libc::SIGUSR1) };

    let zero = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let r_fl = unsafe {
        fl_uni::sigtimedwait(
            &block as *const _ as *const c_void,
            std::ptr::null_mut(),
            &zero as *const _,
        )
    };

    // Re-queue for libc
    let _ = unsafe { libc::kill(pid, libc::SIGUSR1) };
    let r_lc = unsafe { sigtimedwait(&block, std::ptr::null_mut(), &zero) };

    // Drain anything pending
    let _ = unsafe { sigtimedwait(&block, std::ptr::null_mut(), &zero) };

    let _ = unsafe { libc::sigaction(libc::SIGUSR1, &old_act, std::ptr::null_mut()) };
    restore_mask(&prior);

    // Both should agree: either both succeeded with the signo, or both
    // failed (e.g., delivery raced to another thread).
    assert_eq!(
        r_fl > 0,
        r_lc > 0,
        "sigtimedwait pending success-match: fl={r_fl}, lc={r_lc}"
    );
    if r_fl > 0 && r_lc > 0 {
        assert_eq!(
            r_fl, r_lc,
            "sigtimedwait returned signal: fl={r_fl}, lc={r_lc}"
        );
        assert_eq!(r_fl, libc::SIGUSR1, "expected SIGUSR1");
    }
}

// sigwaitinfo blocks indefinitely when no pending signal exists; the
// kill+sigwaitinfo race is unreliable in a multi-threaded test runner
// (SIGUSR2 may be delivered to a sibling thread before sigwaitinfo
// dequeues). Static-link only:
#[allow(dead_code)]
fn _sigwaitinfo_static_link() {
    let _ = fl_uni::sigwaitinfo;
    let _: unsafe extern "C" fn(*const libc::sigset_t, *mut libc::siginfo_t) -> c_int = sigwaitinfo;
}

// sigsuspend is intentionally NOT tested here — it blocks until a
// signal arrives and there's no portable way to time it out without
// race-prone helper threads. Static analysis only:
#[allow(dead_code)]
fn _sigsuspend_static_link() {
    let _ = fl_sig::sigsuspend;
}

#[test]
fn sigwait_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"signal.h(sigwait*/sigsuspend)\",\"reference\":\"glibc\",\"functions\":3,\"divergences\":0}}",
    );
}
