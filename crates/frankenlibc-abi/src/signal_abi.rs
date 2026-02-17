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
// killpg
// ---------------------------------------------------------------------------

/// Send a signal to a process group.
///
/// Equivalent to `kill(-pgrp, sig)`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn killpg(pgrp: libc::pid_t, signum: c_int) -> c_int {
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Signal, signum as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Signal, decision.profile, 5, true);
        return -1;
    }

    if pgrp < 0 {
        unsafe { set_abi_errno(errno::EINVAL) };
        runtime_policy::observe(ApiFamily::Signal, decision.profile, 5, true);
        return -1;
    }

    if !signal_core::valid_signal(signum) && signum != 0 {
        unsafe { set_abi_errno(errno::EINVAL) };
        runtime_policy::observe(ApiFamily::Signal, decision.profile, 5, true);
        return -1;
    }

    // killpg(pgrp, sig) == kill(-pgrp, sig); for pgrp==0 means own process group.
    let target = if pgrp == 0 { 0 } else { -pgrp };
    let rc = unsafe { libc::syscall(libc::SYS_kill, target, signum) as c_int };
    let adverse = rc != 0;
    if adverse {
        unsafe { set_abi_errno(last_host_errno(errno::ESRCH)) };
    }
    runtime_policy::observe(ApiFamily::Signal, decision.profile, 10, adverse);
    rc
}

// ---------------------------------------------------------------------------
// sigprocmask
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sigprocmask(
    how: c_int,
    set: *const libc::sigset_t,
    oldset: *mut libc::sigset_t,
) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::Signal, how as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Signal, decision.profile, 5, true);
        return -1;
    }

    let kernel_sigset_size = std::mem::size_of::<libc::c_ulong>();
    let rc = unsafe {
        libc::syscall(
            libc::SYS_rt_sigprocmask,
            how,
            set,
            oldset,
            kernel_sigset_size,
        ) as c_int
    };
    let adverse = rc != 0;
    if adverse {
        unsafe { set_abi_errno(last_host_errno(errno::EINVAL)) };
    }
    runtime_policy::observe(ApiFamily::Signal, decision.profile, 8, adverse);
    rc
}

// ---------------------------------------------------------------------------
// pthread_sigmask (identical to sigprocmask on Linux)
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_sigmask(
    how: c_int,
    set: *const libc::sigset_t,
    oldset: *mut libc::sigset_t,
) -> c_int {
    // On Linux, pthread_sigmask is identical to sigprocmask — both operate on
    // the calling thread's signal mask via rt_sigprocmask.
    unsafe { sigprocmask(how, set, oldset) }
}

// ---------------------------------------------------------------------------
// sigemptyset
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sigemptyset(set: *mut libc::sigset_t) -> c_int {
    if set.is_null() {
        return -1;
    }
    // Zero the entire sigset_t structure.
    unsafe {
        std::ptr::write_bytes(set as *mut u8, 0, std::mem::size_of::<libc::sigset_t>());
    }
    0
}

// ---------------------------------------------------------------------------
// sigfillset
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sigfillset(set: *mut libc::sigset_t) -> c_int {
    if set.is_null() {
        return -1;
    }
    // Set all bits in the sigset_t structure.
    unsafe {
        std::ptr::write_bytes(set as *mut u8, 0xFF, std::mem::size_of::<libc::sigset_t>());
    }
    0
}

// ---------------------------------------------------------------------------
// sigaddset
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sigaddset(set: *mut libc::sigset_t, signum: c_int) -> c_int {
    if set.is_null() || !signal_core::valid_signal(signum) {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }
    // sigset_t is an array of unsigned longs. Signal N maps to:
    //   word = (N-1) / bits_per_word, bit = (N-1) % bits_per_word
    let idx = (signum - 1) as usize;
    let bits_per_word = std::mem::size_of::<libc::c_ulong>() * 8;
    let word = idx / bits_per_word;
    let bit = idx % bits_per_word;
    let words = set as *mut libc::c_ulong;
    unsafe { *words.add(word) |= 1usize.wrapping_shl(bit as u32) as libc::c_ulong };
    0
}

// ---------------------------------------------------------------------------
// sigdelset
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sigdelset(set: *mut libc::sigset_t, signum: c_int) -> c_int {
    if set.is_null() || !signal_core::valid_signal(signum) {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }
    let idx = (signum - 1) as usize;
    let bits_per_word = std::mem::size_of::<libc::c_ulong>() * 8;
    let word = idx / bits_per_word;
    let bit = idx % bits_per_word;
    let words = set as *mut libc::c_ulong;
    unsafe { *words.add(word) &= !(1usize.wrapping_shl(bit as u32) as libc::c_ulong) };
    0
}

// ---------------------------------------------------------------------------
// sigismember
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sigismember(set: *const libc::sigset_t, signum: c_int) -> c_int {
    if set.is_null() || !signal_core::valid_signal(signum) {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }
    let idx = (signum - 1) as usize;
    let bits_per_word = std::mem::size_of::<libc::c_ulong>() * 8;
    let word = idx / bits_per_word;
    let bit = idx % bits_per_word;
    let words = set as *const libc::c_ulong;
    let val = unsafe { *words.add(word) };
    if (val & (1usize.wrapping_shl(bit as u32) as libc::c_ulong)) != 0 {
        1
    } else {
        0
    }
}

// ---------------------------------------------------------------------------
// pause
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pause() -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::Signal, 0, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Signal, decision.profile, 5, true);
        return -1;
    }

    let rc = unsafe { libc::syscall(libc::SYS_pause) as c_int };
    // pause always returns -1 with EINTR when interrupted.
    unsafe { set_abi_errno(last_host_errno(errno::EINTR)) };
    runtime_policy::observe(ApiFamily::Signal, decision.profile, 10, true);
    rc
}

// ---------------------------------------------------------------------------
// sigsuspend
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sigsuspend(mask: *const libc::sigset_t) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::Signal, mask as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Signal, decision.profile, 5, true);
        return -1;
    }

    if mask.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::Signal, decision.profile, 5, true);
        return -1;
    }

    let kernel_sigset_size = std::mem::size_of::<libc::c_ulong>();
    let rc = unsafe { libc::syscall(libc::SYS_rt_sigsuspend, mask, kernel_sigset_size) as c_int };
    // sigsuspend always returns -1 with EINTR.
    unsafe { set_abi_errno(last_host_errno(errno::EINTR)) };
    runtime_policy::observe(ApiFamily::Signal, decision.profile, 10, true);
    rc
}

// ---------------------------------------------------------------------------
// sigaltstack
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sigaltstack(
    ss: *const libc::stack_t,
    old_ss: *mut libc::stack_t,
) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::Signal, ss as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Signal, decision.profile, 5, true);
        return -1;
    }

    let rc = unsafe { libc::syscall(libc::SYS_sigaltstack, ss, old_ss) as c_int };
    let adverse = rc != 0;
    if adverse {
        unsafe { set_abi_errno(last_host_errno(errno::EINVAL)) };
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
