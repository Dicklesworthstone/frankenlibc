//! ABI layer for process control functions.
//!
//! Provides the POSIX process-control surface: fork, _exit, execve, execvp,
//! waitpid, wait. All functions route through the membrane RuntimeMathKernel
//! under `ApiFamily::Process`.

use std::ffi::{c_char, c_int, c_void};
use std::os::raw::c_long;
use std::os::unix::ffi::OsStrExt;

use frankenlibc_core::process;
use frankenlibc_membrane::heal::{HealingAction, global_healing_policy};
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::runtime_policy;

unsafe extern "C" {
    static mut environ: *mut *mut c_char;
}

#[inline]
unsafe fn set_abi_errno(val: c_int) {
    let p = unsafe { super::errno_abi::__errno_location() };
    unsafe { *p = val };
}

unsafe fn execvp_via_execve(file: *const c_char, argv: *const *const c_char) -> c_int {
    if file.is_null() || argv.is_null() {
        unsafe { set_abi_errno(libc::EFAULT) };
        return -1;
    }

    let file_bytes = unsafe { std::ffi::CStr::from_ptr(file) }.to_bytes();
    if file_bytes.is_empty() {
        unsafe { set_abi_errno(libc::ENOENT) };
        return -1;
    }

    if file_bytes.contains(&b'/') {
        return unsafe { libc::syscall(libc::SYS_execve as c_long, file, argv, environ) } as c_int;
    }

    let path =
        std::env::var_os("PATH").unwrap_or_else(|| std::ffi::OsString::from("/bin:/usr/bin"));
    let path_bytes = path.as_os_str().as_bytes();

    for dir in path_bytes.split(|b| *b == b':') {
        let dir = if dir.is_empty() { b"." as &[u8] } else { dir };
        let mut candidate = Vec::with_capacity(dir.len() + 1 + file_bytes.len() + 1);
        candidate.extend_from_slice(dir);
        candidate.push(b'/');
        candidate.extend_from_slice(file_bytes);
        candidate.push(0);

        let rc = unsafe {
            libc::syscall(
                libc::SYS_execve as c_long,
                candidate.as_ptr().cast::<c_char>(),
                argv,
                environ,
            ) as c_int
        };
        if rc == 0 {
            return rc;
        }

        let err = unsafe { *super::errno_abi::__errno_location() };
        if err != libc::ENOENT && err != libc::ENOTDIR {
            return -1;
        }
    }

    unsafe { set_abi_errno(libc::ENOENT) };
    -1
}

// ---------------------------------------------------------------------------
// fork
// ---------------------------------------------------------------------------

/// POSIX `fork` — create a child process.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
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
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
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
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
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
/// Performs PATH search and dispatches via raw `execve` syscalls.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
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

    let rc = unsafe { execvp_via_execve(file, argv) };

    // execvp only returns on failure.
    runtime_policy::observe(ApiFamily::Process, decision.profile, 40, true);
    rc
}

// ---------------------------------------------------------------------------
// waitpid
// ---------------------------------------------------------------------------

/// POSIX `waitpid` — wait for a child process to change state.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
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
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wait(wstatus: *mut c_int) -> libc::pid_t {
    unsafe { waitpid(-1, wstatus, 0) }
}

// ---------------------------------------------------------------------------
// wait3
// ---------------------------------------------------------------------------

/// BSD `wait3` — wait for any child with resource usage.
///
/// Equivalent to `wait4(-1, wstatus, options, rusage)`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wait3(
    wstatus: *mut c_int,
    options: c_int,
    rusage: *mut libc::rusage,
) -> libc::pid_t {
    unsafe { wait4(-1, wstatus, options, rusage) }
}

// ---------------------------------------------------------------------------
// wait4
// ---------------------------------------------------------------------------

/// BSD `wait4` — wait for a specific child with resource usage.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wait4(
    pid: libc::pid_t,
    wstatus: *mut c_int,
    options: c_int,
    rusage: *mut libc::rusage,
) -> libc::pid_t {
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Process, wstatus as usize, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Process, decision.profile, 30, true);
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }

    let rc = unsafe {
        libc::syscall(libc::SYS_wait4 as c_long, pid, wstatus, options, rusage) as libc::pid_t
    };
    let adverse = rc < 0;
    if adverse {
        unsafe { set_abi_errno(libc::ECHILD) };
    }
    runtime_policy::observe(ApiFamily::Process, decision.profile, 30, adverse);
    rc
}

// ---------------------------------------------------------------------------
// waitid
// ---------------------------------------------------------------------------

/// POSIX `waitid` — wait for a child process to change state (extended).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn waitid(
    idtype: c_int,
    id: libc::id_t,
    infop: *mut libc::siginfo_t,
    options: c_int,
) -> c_int {
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Process, infop as usize, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Process, decision.profile, 30, true);
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }

    let rc =
        unsafe { libc::syscall(libc::SYS_waitid as c_long, idtype, id, infop, options) as c_int };
    let adverse = rc < 0;
    if adverse {
        unsafe { set_abi_errno(libc::ECHILD) };
    }
    runtime_policy::observe(ApiFamily::Process, decision.profile, 30, adverse);
    rc
}

// ---------------------------------------------------------------------------
// vfork
// ---------------------------------------------------------------------------

/// BSD/POSIX `vfork` — on modern Linux, identical to `fork`.
///
/// POSIX.1-2008 removed vfork; glibc maps it to fork. We do the same.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn vfork() -> libc::pid_t {
    unsafe { fork() }
}

// ---------------------------------------------------------------------------
// exec family — GlibcCallThrough (variadic exec functions)
// ---------------------------------------------------------------------------

unsafe extern "C" {
    #[link_name = "execvpe"]
    fn libc_execvpe(file: *const c_char, argv: *const *const c_char, envp: *const *const c_char) -> c_int;
}

/// POSIX `execvpe` — exec with path search and custom environment.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn execvpe(
    file: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    unsafe { libc_execvpe(file, argv, envp) }
}
