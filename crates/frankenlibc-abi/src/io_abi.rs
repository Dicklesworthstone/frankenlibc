//! ABI layer for POSIX I/O functions (`dup`, `dup2`, `pipe`, `fcntl`).
//!
//! Validates via `frankenlibc_core::io` helpers, then calls `libc`.

use std::ffi::c_int;

use frankenlibc_core::errno;
use frankenlibc_core::io as io_core;
use frankenlibc_core::syscall;
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::runtime_policy;

#[inline]
unsafe fn set_abi_errno(val: c_int) {
    let p = unsafe { super::errno_abi::__errno_location() };
    unsafe { *p = val };
}

// ---------------------------------------------------------------------------
// dup
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dup(oldfd: c_int) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::IoFd, oldfd as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }

    if !io_core::valid_fd(oldfd) {
        unsafe { set_abi_errno(errno::EBADF) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }

    match syscall::sys_dup(oldfd) {
        Ok(new_fd) => {
            runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, false);
            new_fd
        }
        Err(e) => {
            unsafe { set_abi_errno(e) };
            runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, true);
            -1
        }
    }
}

// ---------------------------------------------------------------------------
// dup2
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dup2(oldfd: c_int, newfd: c_int) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::IoFd, oldfd as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }

    if !io_core::valid_fd(oldfd) || !io_core::valid_fd(newfd) {
        unsafe { set_abi_errno(errno::EBADF) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }

    match syscall::sys_dup2(oldfd, newfd) {
        Ok(fd) => {
            runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, false);
            fd
        }
        Err(e) => {
            unsafe { set_abi_errno(e) };
            runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, true);
            -1
        }
    }
}

// ---------------------------------------------------------------------------
// pipe
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pipe(pipefd: *mut c_int) -> c_int {
    let (mode, decision) = runtime_policy::decide(ApiFamily::IoFd, 0, 0, true, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }

    if pipefd.is_null() {
        if mode.heals_enabled() {
            runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
            return -1;
        }
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }

    let rc = match unsafe { syscall::sys_pipe2(pipefd, 0) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    };
    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, rc != 0);
    rc
}

// ---------------------------------------------------------------------------
// fcntl
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fcntl(fd: c_int, cmd: c_int, arg: libc::c_long) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::IoFd, fd as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }

    if !io_core::valid_fd(fd) {
        unsafe { set_abi_errno(errno::EBADF) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }

    match unsafe { syscall::sys_fcntl(fd, cmd, arg as usize) } {
        Ok(val) => {
            runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, false);
            val
        }
        Err(e) => {
            unsafe { set_abi_errno(e) };
            runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, true);
            -1
        }
    }
}
