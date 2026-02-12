//! ABI layer for process control functions.
//!
//! Provides the POSIX process-control surface: fork, _exit, execve, execvp,
//! waitpid, wait. All functions route through the membrane RuntimeMathKernel
//! under `ApiFamily::Process`.

use std::ffi::{c_char, c_int, c_void};
use std::os::raw::c_long;

use frankenlibc_core::process;
use frankenlibc_membrane::heal::{HealingAction, global_healing_policy};
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::runtime_policy;

#[inline]
unsafe fn set_abi_errno(val: c_int) {
    let p = unsafe { super::errno_abi::__errno_location() };
    unsafe { *p = val };
}

// ---------------------------------------------------------------------------
// fork
// ---------------------------------------------------------------------------

/// POSIX `fork` — create a child process.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fork() -> libc::pid_t {
    let (_, decision) = runtime_policy::decide(ApiFamily::Process, 0, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Process, decision.profile, 50, true);
        unsafe { set_abi_errno(libc::EAGAIN) };
        return -1;
    }

    let rc = unsafe { libc::syscall(libc::SYS_clone as c_long, libc::SIGCHLD, 0, 0, 0, 0) };
    let pid = rc as libc::pid_t;
    let adverse = pid < 0;
    if adverse {
        unsafe { set_abi_errno(libc::EAGAIN) };
    }
    runtime_policy::observe(ApiFamily::Process, decision.profile, 50, adverse);
    pid
}

// ---------------------------------------------------------------------------
// _exit
// ---------------------------------------------------------------------------

/// POSIX `_exit` — terminate the calling process immediately.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _exit(status: c_int) -> ! {
    let (mode, decision) = runtime_policy::decide(ApiFamily::Process, 0, 0, false, false, 0);

    let clamped = if mode.heals_enabled() {
        let c = process::clamp_exit_status(status);
        if c != status {
            global_healing_policy().record(&HealingAction::ClampSize {
                requested: status as usize,
                clamped: c as usize,
            });
        }
        c
    } else {
        status
    };

    runtime_policy::observe(ApiFamily::Process, decision.profile, 5, false);
    unsafe { libc::syscall(libc::SYS_exit_group as c_long, clamped) };
    // SAFETY: `SYS_exit_group` does not return on Linux; `_exit` is a diverging API.
    unsafe { core::hint::unreachable_unchecked() }
}

// ---------------------------------------------------------------------------
// execve
// ---------------------------------------------------------------------------

/// POSIX `execve` — execute a program.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn execve(
    pathname: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    if pathname.is_null() || argv.is_null() {
        unsafe { set_abi_errno(libc::EFAULT) };
        return -1;
    }

    let (_, decision) =
        runtime_policy::decide(ApiFamily::Process, pathname as usize, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Process, decision.profile, 40, true);
        unsafe { set_abi_errno(libc::EPERM) };
        return -1;
    }

    let rc = unsafe { libc::syscall(libc::SYS_execve as c_long, pathname, argv, envp) as c_int };

    // execve only returns on failure.
    runtime_policy::observe(ApiFamily::Process, decision.profile, 40, true);
    rc
}

// ---------------------------------------------------------------------------
// execvp
// ---------------------------------------------------------------------------

/// POSIX `execvp` — execute a file, searching PATH.
///
/// Delegates to libc execvp which handles PATH resolution.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn execvp(file: *const c_char, argv: *const *const c_char) -> c_int {
    if file.is_null() || argv.is_null() {
        unsafe { set_abi_errno(libc::EFAULT) };
        return -1;
    }

    let (_, decision) =
        runtime_policy::decide(ApiFamily::Process, file as usize, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Process, decision.profile, 40, true);
        unsafe { set_abi_errno(libc::EPERM) };
        return -1;
    }

    // Use libc's execvp for PATH search logic.
    let rc = unsafe { libc::execvp(file, argv) };

    // execvp only returns on failure.
    runtime_policy::observe(ApiFamily::Process, decision.profile, 40, true);
    rc
}

// ---------------------------------------------------------------------------
// waitpid
// ---------------------------------------------------------------------------

/// POSIX `waitpid` — wait for a child process to change state.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn waitpid(
    pid: libc::pid_t,
    wstatus: *mut c_int,
    options: c_int,
) -> libc::pid_t {
    let (mode, decision) =
        runtime_policy::decide(ApiFamily::Process, wstatus as usize, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Process, decision.profile, 30, true);
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }

    // Sanitize options in hardened mode.
    let opts = if mode.heals_enabled() && !process::valid_wait_options(options) {
        let sanitized = process::sanitize_wait_options(options);
        global_healing_policy().record(&HealingAction::ClampSize {
            requested: options as usize,
            clamped: sanitized as usize,
        });
        sanitized
    } else {
        options
    };

    let rc = unsafe {
        libc::syscall(
            libc::SYS_wait4 as c_long,
            pid,
            wstatus,
            opts,
            std::ptr::null::<c_void>(),
        ) as libc::pid_t
    };

    let adverse = rc < 0;
    if adverse {
        unsafe { set_abi_errno(libc::ECHILD) };
    }
    runtime_policy::observe(ApiFamily::Process, decision.profile, 30, adverse);
    rc
}

// ---------------------------------------------------------------------------
// wait
// ---------------------------------------------------------------------------

/// POSIX `wait` — equivalent to `waitpid(-1, wstatus, 0)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wait(wstatus: *mut c_int) -> libc::pid_t {
    unsafe { waitpid(-1, wstatus, 0) }
}
