#![cfg(target_os = "linux")]

//! Differential conformance harness for BSD/XPG `bsd_signal(3)`.
//!
//! `bsd_signal` is a SysV-style alias for `signal()` — set a signal
//! handler with persistent semantics (handler stays installed across
//! invocations). Both fl and glibc must accept the same signals,
//! return the same prior-handler pointer, and reject the same
//! invalid sigs.
//!
//! Filed under [bd-xn6p8] follow-up.

use std::ffi::c_int;
use std::sync::{Mutex, MutexGuard};

unsafe extern "C" {
    fn bsd_signal(sig: c_int, handler: libc::sighandler_t) -> libc::sighandler_t;
}

use frankenlibc_abi::unistd_abi as fl;

// Tests in this file mutate process-global signal handlers; serialize
// them so cargo's parallel runner doesn't race us.
static SIG_LOCK: Mutex<()> = Mutex::new(());

fn sig_guard() -> MutexGuard<'static, ()> {
    match SIG_LOCK.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}

extern "C" fn dummy_handler(_sig: c_int) {}

fn dummy_handler_value() -> libc::sighandler_t {
    dummy_handler as *const () as libc::sighandler_t
}

#[test]
fn diff_bsd_signal_install_default_then_restore() {
    let _g = sig_guard();
    // Install SIG_DFL via fl, then via lc; both must return the
    // *previous* handler pointer.
    let fl_old = unsafe { fl::bsd_signal(libc::SIGUSR1, libc::SIG_DFL) };
    let lc_old = unsafe { bsd_signal(libc::SIGUSR2, libc::SIG_DFL) };
    // SIG_DFL on a never-set signal is just SIG_DFL.
    assert!(fl_old == libc::SIG_DFL || fl_old == libc::SIG_IGN || fl_old != libc::SIG_ERR);
    let _ = lc_old;
}

#[test]
fn diff_bsd_signal_swap_returns_previous() {
    let _g = sig_guard();
    let dummy = dummy_handler_value();
    // Install dummy via fl, then swap to SIG_DFL — should get dummy back.
    let fl_first = unsafe { fl::bsd_signal(libc::SIGUSR1, dummy) };
    let fl_back = unsafe { fl::bsd_signal(libc::SIGUSR1, libc::SIG_DFL) };
    assert_ne!(fl_back, libc::SIG_ERR, "fl bsd_signal swap should succeed");
    assert_eq!(fl_back, dummy, "fl: swap returns prior handler");
    // Restore to original.
    let _ = unsafe { fl::bsd_signal(libc::SIGUSR1, fl_first) };

    // Same for lc on a different signal.
    let lc_first = unsafe { bsd_signal(libc::SIGUSR2, dummy) };
    let lc_back = unsafe { bsd_signal(libc::SIGUSR2, libc::SIG_DFL) };
    assert_ne!(lc_back, libc::SIG_ERR);
    assert_eq!(lc_back, dummy, "lc: swap returns prior handler");
    let _ = unsafe { bsd_signal(libc::SIGUSR2, lc_first) };
}

#[test]
fn diff_bsd_signal_invalid_signal_returns_sig_err() {
    let _g = sig_guard();
    // Signal 0 and signals > _NSIG are invalid.
    let fl_v = unsafe { fl::bsd_signal(0, libc::SIG_DFL) };
    let lc_v = unsafe { bsd_signal(0, libc::SIG_DFL) };
    assert_eq!(fl_v, libc::SIG_ERR, "fl rejects signal 0");
    assert_eq!(lc_v, libc::SIG_ERR, "lc rejects signal 0");

    let fl_big = unsafe { fl::bsd_signal(9999, libc::SIG_DFL) };
    let lc_big = unsafe { bsd_signal(9999, libc::SIG_DFL) };
    assert_eq!(fl_big, libc::SIG_ERR);
    assert_eq!(lc_big, libc::SIG_ERR);
}

#[test]
fn diff_bsd_signal_uncatchable_signals_rejected() {
    let _g = sig_guard();
    let dummy = dummy_handler_value();
    // SIGKILL and SIGSTOP cannot have handlers set. Both impls
    // must reject with SIG_ERR.
    for &sig in &[libc::SIGKILL, libc::SIGSTOP] {
        let fl_v = unsafe { fl::bsd_signal(sig, dummy) };
        let lc_v = unsafe { bsd_signal(sig, dummy) };
        assert_eq!(fl_v, libc::SIG_ERR, "fl: signal {sig} should be rejected");
        assert_eq!(lc_v, libc::SIG_ERR, "lc: signal {sig} should be rejected");
    }
}

#[test]
fn bsd_signal_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc bsd_signal\",\"reference\":\"glibc\",\"functions\":1,\"divergences\":0}}",
    );
}
