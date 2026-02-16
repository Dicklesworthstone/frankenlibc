//! ABI layer for `<signal.h>` functions.
//!
//! Validates via `frankenlibc_core::signal` helpers, then calls `libc` for
//! actual signal delivery.

use std::ffi::c_int;

use frankenlibc_core::errno;
use frankenlibc_core::signal as signal_core;
use frankenlibc_core::syscall;
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::runtime_policy;

#[inline]
unsafe fn set_abi_errno(val: c_int) {
    let p = unsafe { super::errno_abi::__errno_location() };
    unsafe { *p = val };
}

#[inline]
fn last_host_errno(default_errno: c_int) -> c_int {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(default_errno)
}

// ---------------------------------------------------------------------------
// signal
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn signal(signum: c_int, handler: libc::sighandler_t) -> libc::sighandler_t {
    let sig_err = libc::SIG_ERR;

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

    let mut act = unsafe { std::mem::zeroed::<libc::sigaction>() };
    act.sa_sigaction = handler as libc::sighandler_t;
    let mut oldact = unsafe { std::mem::zeroed::<libc::sigaction>() };
    let rc = unsafe { sigaction(signum, &act as *const libc::sigaction, &mut oldact) };
    let adverse = rc != 0;
    runtime_policy::observe(ApiFamily::Signal, decision.profile, 10, adverse);
    if adverse {
        sig_err
    } else {
        oldact.sa_sigaction
    }
}

// ---------------------------------------------------------------------------
// raise
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
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

    let pid = syscall::sys_getpid();
    let rc = unsafe { libc::syscall(libc::SYS_kill, pid, signum) as c_int };
    let adverse = rc != 0;
    runtime_policy::observe(ApiFamily::Signal, decision.profile, 10, adverse);
    rc
}

// ---------------------------------------------------------------------------
// kill
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
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

    let rc = unsafe { libc::syscall(libc::SYS_kill, pid, signum) as c_int };
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

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
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

    // Linux `rt_sigaction` expects the kernel sigset size (`sizeof(unsigned long)`),
    // not libc's userspace `sigset_t` size.
    let kernel_sigset_size = std::mem::size_of::<libc::c_ulong>();
    let rc = unsafe {
        libc::syscall(
            libc::SYS_rt_sigaction,
            signum,
            act,
            oldact,
            kernel_sigset_size,
        ) as c_int
    };
    let adverse = rc != 0;
    if adverse {
        unsafe { set_abi_errno(last_host_errno(errno::EINVAL)) };
    }
    runtime_policy::observe(ApiFamily::Signal, decision.profile, 10, adverse);
    rc
}
