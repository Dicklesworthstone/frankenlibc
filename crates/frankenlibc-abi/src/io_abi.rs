//! ABI layer for POSIX I/O functions (`dup`, `dup2`, `pipe`, `fcntl`).
//!
//! Validates via `frankenlibc_core::io` helpers, then calls `libc`.

use std::ffi::{c_int, c_void};

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

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
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

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
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

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
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

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
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

// ---------------------------------------------------------------------------
// pipe2
// ---------------------------------------------------------------------------

/// Linux `pipe2` — create a pipe with flags.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pipe2(pipefd: *mut c_int, flags: c_int) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::IoFd, 0, 0, true, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    if pipefd.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    let rc = match unsafe { syscall::sys_pipe2(pipefd, flags) } {
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
// dup3
// ---------------------------------------------------------------------------

/// Linux `dup3` — duplicate a file descriptor with flags.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn dup3(oldfd: c_int, newfd: c_int, flags: c_int) -> c_int {
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
    let rc = unsafe { libc::syscall(libc::SYS_dup3, oldfd, newfd, flags) as c_int };
    if rc < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(errno::EBADF);
        unsafe { set_abi_errno(e) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, true);
        -1
    } else {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, false);
        rc
    }
}

// ---------------------------------------------------------------------------
// ioctl
// ---------------------------------------------------------------------------

/// POSIX `ioctl` — device control.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ioctl(fd: c_int, request: libc::c_ulong, arg: libc::c_ulong) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::IoFd, fd as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    match unsafe { syscall::sys_ioctl(fd, request as usize, arg as usize) } {
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

// ---------------------------------------------------------------------------
// pread / pwrite
// ---------------------------------------------------------------------------

/// POSIX `pread` — read from a file descriptor at a given offset.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pread(
    fd: c_int,
    buf: *mut c_void,
    count: usize,
    offset: i64,
) -> libc::ssize_t {
    let (_, decision) = runtime_policy::decide(ApiFamily::IoFd, buf as usize, count, true, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 8, true);
        return -1;
    }
    if buf.is_null() && count > 0 {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 8, true);
        return -1;
    }
    match unsafe { syscall::sys_pread64(fd, buf as *mut u8, count, offset) } {
        Ok(n) => {
            runtime_policy::observe(ApiFamily::IoFd, decision.profile, 8, false);
            n as libc::ssize_t
        }
        Err(e) => {
            unsafe { set_abi_errno(e) };
            runtime_policy::observe(ApiFamily::IoFd, decision.profile, 8, true);
            -1
        }
    }
}

/// POSIX `pwrite` — write to a file descriptor at a given offset.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pwrite(
    fd: c_int,
    buf: *const c_void,
    count: usize,
    offset: i64,
) -> libc::ssize_t {
    let (_, decision) =
        runtime_policy::decide(ApiFamily::IoFd, buf as usize, count, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 8, true);
        return -1;
    }
    if buf.is_null() && count > 0 {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 8, true);
        return -1;
    }
    match unsafe { syscall::sys_pwrite64(fd, buf as *const u8, count, offset) } {
        Ok(n) => {
            runtime_policy::observe(ApiFamily::IoFd, decision.profile, 8, false);
            n as libc::ssize_t
        }
        Err(e) => {
            unsafe { set_abi_errno(e) };
            runtime_policy::observe(ApiFamily::IoFd, decision.profile, 8, true);
            -1
        }
    }
}

// ---------------------------------------------------------------------------
// readv / writev
// ---------------------------------------------------------------------------

/// POSIX `readv` — scatter read from a file descriptor.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn readv(fd: c_int, iov: *const libc::iovec, iovcnt: c_int) -> libc::ssize_t {
    let (_, decision) = runtime_policy::decide(ApiFamily::IoFd, fd as usize, 0, true, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 8, true);
        return -1;
    }
    if iov.is_null() || iovcnt <= 0 {
        unsafe { set_abi_errno(errno::EINVAL) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 8, true);
        return -1;
    }
    let rc = unsafe { libc::syscall(libc::SYS_readv, fd, iov, iovcnt) };
    if rc < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(errno::EIO);
        unsafe { set_abi_errno(e) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 8, true);
        -1
    } else {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 8, false);
        rc as libc::ssize_t
    }
}

/// POSIX `writev` — gather write to a file descriptor.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn writev(
    fd: c_int,
    iov: *const libc::iovec,
    iovcnt: c_int,
) -> libc::ssize_t {
    let (_, decision) = runtime_policy::decide(ApiFamily::IoFd, fd as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 8, true);
        return -1;
    }
    if iov.is_null() || iovcnt <= 0 {
        unsafe { set_abi_errno(errno::EINVAL) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 8, true);
        return -1;
    }
    let rc = unsafe { libc::syscall(libc::SYS_writev, fd, iov, iovcnt) };
    if rc < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(errno::EIO);
        unsafe { set_abi_errno(e) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 8, true);
        -1
    } else {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 8, false);
        rc as libc::ssize_t
    }
}

// ---------------------------------------------------------------------------
// sendfile
// ---------------------------------------------------------------------------

/// Linux `sendfile` — transfer data between file descriptors.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sendfile(
    out_fd: c_int,
    in_fd: c_int,
    offset: *mut i64,
    count: usize,
) -> libc::ssize_t {
    let (_, decision) =
        runtime_policy::decide(ApiFamily::IoFd, out_fd as usize, count, true, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 8, true);
        return -1;
    }
    let rc = unsafe { libc::syscall(libc::SYS_sendfile, out_fd, in_fd, offset, count) };
    if rc < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(errno::EIO);
        unsafe { set_abi_errno(e) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 8, true);
        -1
    } else {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 8, false);
        rc as libc::ssize_t
    }
}
