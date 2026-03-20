//! ABI layer for `<signal.h>` functions.
//!
//! Validates via `frankenlibc_core::signal` helpers, then calls `libc` for
//! actual signal delivery.

use std::ffi::c_int;

use frankenlibc_core::errno;
use frankenlibc_core::signal as signal_core;
use frankenlibc_core::syscall;
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::errno_abi::set_abi_errno;
use crate::runtime_policy;

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
        unsafe { set_abi_errno(errno::EINVAL) };
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
        unsafe { set_abi_errno(errno::EINVAL) };
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
        unsafe { set_abi_errno(errno::EPERM) };
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
        unsafe { set_abi_errno(last_host_errno(errno::ESRCH)) };
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
        unsafe { set_abi_errno(errno::EPERM) };
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
        unsafe { set_abi_errno(errno::EINVAL) };
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
        unsafe { set_abi_errno(errno::EPERM) };
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
        unsafe { set_abi_errno(errno::EPERM) };
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
        unsafe { set_abi_errno(errno::EPERM) };
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
        unsafe { set_abi_errno(errno::EINVAL) };
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

// ---------------------------------------------------------------------------
// Additional signal functions — native raw-syscall implementation
// ---------------------------------------------------------------------------

/// `sigpending` — get pending signals via `rt_sigpending` syscall.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sigpending(set: *mut libc::sigset_t) -> c_int {
    if set.is_null() {
        unsafe { set_abi_errno(libc::EFAULT as c_int) };
        return -1;
    }
    let kernel_sigset_size = std::mem::size_of::<libc::c_ulong>();
    // SAFETY: rt_sigpending writes to the provided set pointer.
    let rc = unsafe { libc::syscall(libc::SYS_rt_sigpending, set, kernel_sigset_size) as c_int };
    if rc != 0 {
        unsafe { set_abi_errno(last_host_errno(errno::EFAULT)) };
    }
    rc
}

/// `sigwait` — wait for a signal from `set` via `rt_sigtimedwait` syscall.
/// Returns 0 on success with the signal number stored in `*sig`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sigwait(set: *const libc::sigset_t, sig: *mut c_int) -> c_int {
    if set.is_null() || sig.is_null() {
        return libc::EINVAL;
    }
    let kernel_sigset_size = std::mem::size_of::<libc::c_ulong>();
    // SAFETY: rt_sigtimedwait blocks until a signal from `set` is pending.
    // With null timeout, it blocks indefinitely. Returns the signal number.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_rt_sigtimedwait,
            set,
            std::ptr::null::<libc::siginfo_t>(),
            std::ptr::null::<libc::timespec>(),
            kernel_sigset_size,
        ) as c_int
    };
    if rc > 0 {
        // SAFETY: sig is non-null; we checked above.
        unsafe { *sig = rc };
        0
    } else {
        // On error, return the errno value per POSIX sigwait semantics.
        last_host_errno(libc::EINTR)
    }
}

// ---------------------------------------------------------------------------
// Legacy/obsolete signal functions — implemented natively
// ---------------------------------------------------------------------------

/// `siginterrupt` — allow signals to interrupt system calls (obsolete).
/// Implemented natively via sigaction.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn siginterrupt(sig: c_int, flag: c_int) -> c_int {
    let mut sa: libc::sigaction = unsafe { std::mem::zeroed() };
    // SAFETY: get current action for the signal.
    if unsafe {
        libc::syscall(
            libc::SYS_rt_sigaction,
            sig,
            std::ptr::null::<libc::sigaction>(),
            &mut sa as *mut libc::sigaction,
            std::mem::size_of::<libc::c_ulong>(),
        )
    } != 0
    {
        return -1;
    }
    if flag != 0 {
        sa.sa_flags &= !libc::SA_RESTART;
    } else {
        sa.sa_flags |= libc::SA_RESTART;
    }
    // SAFETY: set the modified action.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_rt_sigaction,
            sig,
            &sa as *const libc::sigaction,
            std::ptr::null::<libc::sigaction>(),
            std::mem::size_of::<libc::c_ulong>(),
        ) as c_int
    };
    if rc != 0 { -1 } else { 0 }
}

/// `sighold` — add signal to process signal mask (XSI obsolete).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sighold(sig: c_int) -> c_int {
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe { libc::sigemptyset(&mut set) };
    unsafe { libc::sigaddset(&mut set, sig) };
    let kernel_sigset_size = std::mem::size_of::<libc::c_ulong>();
    let rc = unsafe {
        libc::syscall(
            libc::SYS_rt_sigprocmask,
            libc::SIG_BLOCK,
            &set as *const libc::sigset_t,
            std::ptr::null::<libc::sigset_t>(),
            kernel_sigset_size,
        ) as c_int
    };
    if rc != 0 { -1 } else { 0 }
}

/// `sigrelse` — remove signal from process signal mask (XSI obsolete).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sigrelse(sig: c_int) -> c_int {
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe { libc::sigemptyset(&mut set) };
    unsafe { libc::sigaddset(&mut set, sig) };
    let kernel_sigset_size = std::mem::size_of::<libc::c_ulong>();
    let rc = unsafe {
        libc::syscall(
            libc::SYS_rt_sigprocmask,
            libc::SIG_UNBLOCK,
            &set as *const libc::sigset_t,
            std::ptr::null::<libc::sigset_t>(),
            kernel_sigset_size,
        ) as c_int
    };
    if rc != 0 { -1 } else { 0 }
}

/// `sigignore` — set signal disposition to SIG_IGN (XSI obsolete).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sigignore(sig: c_int) -> c_int {
    let mut sa: libc::sigaction = unsafe { std::mem::zeroed() };
    sa.sa_sigaction = libc::SIG_IGN;
    sa.sa_flags = 0;
    unsafe { libc::sigemptyset(&mut sa.sa_mask) };
    let rc = unsafe {
        libc::syscall(
            libc::SYS_rt_sigaction,
            sig,
            &sa as *const libc::sigaction,
            std::ptr::null::<libc::sigaction>(),
            std::mem::size_of::<libc::c_ulong>(),
        ) as c_int
    };
    if rc != 0 { -1 } else { 0 }
}

/// `psiginfo` — print signal info to stderr.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn psiginfo(info: *const libc::siginfo_t, msg: *const std::ffi::c_char) {
    if info.is_null() {
        return;
    }
    let sig = unsafe { (*info).si_signo };
    let abbrev = unsafe { sigabbrev_np(sig) };
    let desc = if abbrev.is_null() {
        "Unknown signal"
    } else {
        unsafe { std::ffi::CStr::from_ptr(abbrev) }
            .to_str()
            .unwrap_or("Unknown signal")
    };
    if !msg.is_null() {
        let c_msg = unsafe { std::ffi::CStr::from_ptr(msg) };
        if let Ok(s) = c_msg.to_str() {
            let out = format!("{s}: SIG{desc}\n");
            unsafe {
                crate::unistd_abi::sys_write_fd(libc::STDERR_FILENO, out.as_ptr().cast(), out.len())
            };
            return;
        }
    }
    let out = format!("SIG{desc}\n");
    unsafe { crate::unistd_abi::sys_write_fd(libc::STDERR_FILENO, out.as_ptr().cast(), out.len()) };
}

/// `sigabbrev_np` — return abbreviated signal name (GNU extension).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sigabbrev_np(sig: c_int) -> *const std::ffi::c_char {
    // Return signal abbreviation without "SIG" prefix
    static NAMES: &[&[u8]] = &[
        b"0\0",      // 0
        b"HUP\0",    // 1
        b"INT\0",    // 2
        b"QUIT\0",   // 3
        b"ILL\0",    // 4
        b"TRAP\0",   // 5
        b"ABRT\0",   // 6
        b"BUS\0",    // 7
        b"FPE\0",    // 8
        b"KILL\0",   // 9
        b"USR1\0",   // 10
        b"SEGV\0",   // 11
        b"USR2\0",   // 12
        b"PIPE\0",   // 13
        b"ALRM\0",   // 14
        b"TERM\0",   // 15
        b"STKFLT\0", // 16
        b"CHLD\0",   // 17
        b"CONT\0",   // 18
        b"STOP\0",   // 19
        b"TSTP\0",   // 20
        b"TTIN\0",   // 21
        b"TTOU\0",   // 22
        b"URG\0",    // 23
        b"XCPU\0",   // 24
        b"XFSZ\0",   // 25
        b"VTALRM\0", // 26
        b"PROF\0",   // 27
        b"WINCH\0",  // 28
        b"IO\0",     // 29
        b"PWR\0",    // 30
        b"SYS\0",    // 31
    ];
    if sig < 0 || sig as usize >= NAMES.len() {
        return std::ptr::null();
    }
    NAMES[sig as usize].as_ptr().cast()
}

/// `sigdescr_np` — return signal description string (GNU extension).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sigdescr_np(sig: c_int) -> *const std::ffi::c_char {
    static DESCS: &[&[u8]] = &[
        b"Unknown signal 0\0",         // 0
        b"Hangup\0",                   // 1
        b"Interrupt\0",                // 2
        b"Quit\0",                     // 3
        b"Illegal instruction\0",      // 4
        b"Trace/breakpoint trap\0",    // 5
        b"Aborted\0",                  // 6
        b"Bus error\0",                // 7
        b"Floating point exception\0", // 8
        b"Killed\0",                   // 9
        b"User defined signal 1\0",    // 10
        b"Segmentation fault\0",       // 11
        b"User defined signal 2\0",    // 12
        b"Broken pipe\0",              // 13
        b"Alarm clock\0",              // 14
        b"Terminated\0",               // 15
        b"Stack fault\0",              // 16
        b"Child exited\0",             // 17
        b"Continued\0",                // 18
        b"Stopped (signal)\0",         // 19
        b"Stopped\0",                  // 20
        b"Stopped (tty input)\0",      // 21
        b"Stopped (tty output)\0",     // 22
        b"Urgent I/O condition\0",     // 23
        b"CPU time limit exceeded\0",  // 24
        b"File size limit exceeded\0", // 25
        b"Virtual timer expired\0",    // 26
        b"Profiling timer expired\0",  // 27
        b"Window changed\0",           // 28
        b"I/O possible\0",             // 29
        b"Power failure\0",            // 30
        b"Bad system call\0",          // 31
    ];
    if sig < 0 || sig as usize >= DESCS.len() {
        return std::ptr::null();
    }
    DESCS[sig as usize].as_ptr().cast()
}

/// `sigandset` — compute intersection of two signal sets (GNU).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sigandset(
    dest: *mut libc::sigset_t,
    left: *const libc::sigset_t,
    right: *const libc::sigset_t,
) -> c_int {
    if dest.is_null() || left.is_null() || right.is_null() {
        return -1;
    }
    // SAFETY: sigset_t on Linux is an array of unsigned longs.
    unsafe {
        let d = dest as *mut u64;
        let l = left as *const u64;
        let r = right as *const u64;
        let n = std::mem::size_of::<libc::sigset_t>() / 8;
        for i in 0..n {
            *d.add(i) = *l.add(i) & *r.add(i);
        }
    }
    0
}

/// `sigorset` — compute union of two signal sets (GNU).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sigorset(
    dest: *mut libc::sigset_t,
    left: *const libc::sigset_t,
    right: *const libc::sigset_t,
) -> c_int {
    if dest.is_null() || left.is_null() || right.is_null() {
        return -1;
    }
    // SAFETY: sigset_t on Linux is an array of unsigned longs.
    unsafe {
        let d = dest as *mut u64;
        let l = left as *const u64;
        let r = right as *const u64;
        let n = std::mem::size_of::<libc::sigset_t>() / 8;
        for i in 0..n {
            *d.add(i) = *l.add(i) | *r.add(i);
        }
    }
    0
}

/// `sigisemptyset` — test if signal set is empty (GNU).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sigisemptyset(set: *const libc::sigset_t) -> c_int {
    if set.is_null() {
        return -1;
    }
    // SAFETY: sigset_t on Linux is an array of unsigned longs.
    unsafe {
        let s = set as *const u64;
        let n = std::mem::size_of::<libc::sigset_t>() / 8;
        for i in 0..n {
            if *s.add(i) != 0 {
                return 0; // Not empty
            }
        }
    }
    1 // Empty
}

/// `__libc_current_sigrtmin` — return minimum real-time signal number.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_current_sigrtmin() -> c_int {
    // Linux reserves SIGRTMIN+0..+2 for NPTL; usable range starts at SIGRTMIN+3 = 35.
    35
}

/// `__libc_current_sigrtmax` — return maximum real-time signal number.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_current_sigrtmax() -> c_int {
    // SIGRTMAX on Linux x86_64 = 64.
    64
}
