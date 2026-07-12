//! Differential gate: sigwait() restarts on EINTR rather than reporting it,
//! matching POSIX/glibc.
//!
//! POSIX sigwait's only defined error is EINVAL; it never returns EINTR. If the
//! wait is interrupted by a signal NOT in the wait set (a handler runs), the
//! kernel's rt_sigtimedwait returns EINTR, but glibc restarts the wait. fl
//! previously surfaced EINTR to the caller.
//!
//! We block SIGUSR1 (the awaited signal) and install a no-op SIGUSR2 handler.
//! A helper thread first sends SIGUSR2 (interrupts the wait -> kernel EINTR) and
//! then SIGUSR1. A conforming sigwait must ignore the interruption and return
//! SIGUSR1 with rc 0. We require identical (rc, sig) from fl and glibc
//! (libc::sigwait is the host's).
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::signal_abi as fl;
use std::ffi::c_int;
use std::time::Duration;

extern "C" fn noop_handler(_: c_int) {}

type WaitFn = unsafe extern "C" fn(*const libc::sigset_t, *mut c_int) -> c_int;

/// Block SIGUSR1 in this thread and install a no-op SIGUSR2 handler so SIGUSR2
/// interrupts (rather than terminates) a blocking wait.
fn arm() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = noop_handler as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = 0;
        libc::sigaction(libc::SIGUSR2, &sa, std::ptr::null_mut());

        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGUSR1);
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
    }
}

/// Run `waiter` on SIGUSR1 while a helper thread interrupts with SIGUSR2 then
/// delivers SIGUSR1. Returns (rc, captured-signal).
fn run(waiter: WaitFn) -> (c_int, c_int) {
    let main_tid = unsafe { libc::pthread_self() };
    let helper = std::thread::spawn(move || unsafe {
        std::thread::sleep(Duration::from_millis(150));
        libc::pthread_kill(main_tid, libc::SIGUSR2); // interrupt the wait -> EINTR
        std::thread::sleep(Duration::from_millis(150));
        libc::pthread_kill(main_tid, libc::SIGUSR1); // the awaited signal
    });

    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGUSR1);
    }
    let mut sig: c_int = -1;
    let rc = unsafe { waiter(&set, &mut sig) };
    helper.join().unwrap();
    (rc, sig)
}

#[test]
fn sigwait_restarts_on_eintr_like_glibc() {
    arm();

    // glibc reference (libc::sigwait is the host's sigwait).
    let g = run(libc::sigwait);
    assert_eq!(
        g,
        (0, libc::SIGUSR1),
        "glibc sigwait should restart on EINTR and return SIGUSR1"
    );

    // fl must match: rc 0, sig SIGUSR1, NOT EINTR.
    let f = run(fl::sigwait);
    assert_eq!(
        f,
        g,
        "fl sigwait diverged: got (rc={}, sig={}), glibc=(rc={}, sig={}) (EINTR={})",
        f.0,
        f.1,
        g.0,
        g.1,
        libc::EINTR
    );
}
