//! ABI layer for `<signal.h>` functions.
//!
//! Validates via `frankenlibc_core::signal` helpers, then calls `libc` for
//! actual signal delivery.

use std::ffi::c_int;

use frankenlibc_core::errno;
use frankenlibc_core::signal as signal_core;
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::runtime_policy;

#[inline]
unsafe fn set_abi_errno(val: c_int) {
    let p = unsafe { super::errno_abi::__errno_location() };
    unsafe { *p = val };
}

/// Type alias for C signal handler: `void (*)(int)`.
type SigHandler = unsafe extern "C" fn(c_int);

// ---------------------------------------------------------------------------
// signal
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn signal(signum: c_int, handler: SigHandler) -> SigHandler {
    // SIG_ERR = transmuted -1isize
    let sig_err: SigHandler = unsafe { std::mem::transmute(-1isize) };

    let (_mode, decision) =
        runtime_policy::decide(ApiFamily::Signal, signum as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Signal, decision.profile, 5, true);
        return sig_err;
    }

    if !signal_core::catchable_signal(signum) {
        unsafe { set_abi_errno(errno::EINVAL) };
        runtime_policy::observe(ApiFamily::Signal, decision.profile, 5, true);
        return sig_err;
    }

    let prev = unsafe { libc::signal(signum, handler as libc::sighandler_t) };
    let adverse = prev == libc::SIG_ERR;
    if adverse {
        unsafe { set_abi_errno(errno::EINVAL) };
    }
    runtime_policy::observe(ApiFamily::Signal, decision.profile, 10, adverse);
    if adverse {
        sig_err
    } else {
        unsafe { std::mem::transmute::<usize, SigHandler>(prev) }
    }
}

// ---------------------------------------------------------------------------
// raise
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn raise(signum: c_int) -> c_int {
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Signal, signum as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Signal, decision.profile, 5, true);
        return -1;
    }

    if !signal_core::valid_signal(signum) {
        unsafe { set_abi_errno(errno::EINVAL) };
        runtime_policy::observe(ApiFamily::Signal, decision.profile, 5, true);
        return -1;
    }

    let rc = unsafe { libc::raise(signum) };
    let adverse = rc != 0;
    runtime_policy::observe(ApiFamily::Signal, decision.profile, 10, adverse);
    rc
}

// ---------------------------------------------------------------------------
// kill
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn kill(pid: libc::pid_t, signum: c_int) -> c_int {
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Signal, signum as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Signal, decision.profile, 5, true);
        return -1;
    }

    if !signal_core::valid_signal(signum) && signum != 0 {
        unsafe { set_abi_errno(errno::EINVAL) };
        runtime_policy::observe(ApiFamily::Signal, decision.profile, 5, true);
        return -1;
    }

    let rc = unsafe { libc::kill(pid, signum) };
    let adverse = rc != 0;
    if adverse {
        unsafe { set_abi_errno(errno::EINVAL) };
    }
    runtime_policy::observe(ApiFamily::Signal, decision.profile, 10, adverse);
    rc
}

// ---------------------------------------------------------------------------
// sigaction
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sigaction(
    signum: c_int,
    act: *const libc::sigaction,
    oldact: *mut libc::sigaction,
) -> c_int {
    let (_mode, decision) =
        runtime_policy::decide(ApiFamily::Signal, signum as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Signal, decision.profile, 5, true);
        return -1;
    }

    if !signal_core::catchable_signal(signum) {
        unsafe { set_abi_errno(errno::EINVAL) };
        runtime_policy::observe(ApiFamily::Signal, decision.profile, 5, true);
        return -1;
    }

    let rc = unsafe { libc::sigaction(signum, act, oldact) };
    let adverse = rc != 0;
    if adverse {
        unsafe { set_abi_errno(errno::EINVAL) };
    }
    runtime_policy::observe(ApiFamily::Signal, decision.profile, 10, adverse);
    rc
}
