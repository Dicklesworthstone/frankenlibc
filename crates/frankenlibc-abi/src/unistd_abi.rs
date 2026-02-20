//! ABI layer for `<unistd.h>` functions.
//!
//! Covers POSIX I/O (read/write/close/lseek), file metadata (stat/fstat/lstat/access),
//! directory navigation (getcwd/chdir), process identity (getpid/getppid/getuid/...),
//! link operations (link/symlink/readlink/unlink/rmdir), and sync (fsync/fdatasync).

use std::ffi::{c_char, c_int, c_uint, c_void};

use frankenlibc_core::errno;
use frankenlibc_core::syscall;
use frankenlibc_core::unistd as unistd_core;
use frankenlibc_membrane::heal::{HealingAction, global_healing_policy};
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::malloc_abi::known_remaining;
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

#[inline]
unsafe fn syscall_ret_int(ret: libc::c_long, default_errno: c_int) -> c_int {
    if ret < 0 {
        unsafe { set_abi_errno(last_host_errno(default_errno)) };
        -1
    } else {
        ret as c_int
    }
}

#[inline]
unsafe fn syscall_ret_isize(ret: libc::c_long, default_errno: c_int) -> isize {
    if ret < 0 {
        unsafe { set_abi_errno(last_host_errno(default_errno)) };
        -1
    } else {
        ret as isize
    }
}

fn maybe_clamp_io_len(requested: usize, addr: usize, enable_repair: bool) -> (usize, bool) {
    if !enable_repair || requested == 0 || addr == 0 {
        return (requested, false);
    }
    let Some(remaining) = known_remaining(addr) else {
        return (requested, false);
    };
    if remaining >= requested {
        return (requested, false);
    }
    let action = HealingAction::ClampSize {
        requested,
        clamped: remaining,
    };
    global_healing_policy().record(&action);
    (remaining, true)
}

pub(crate) unsafe fn sys_read_fd(fd: c_int, buf: *mut c_void, count: usize) -> libc::ssize_t {
    // SAFETY: caller enforces syscall argument validity.
    match unsafe { syscall::sys_read(fd, buf as *mut u8, count) } {
        Ok(n) => n as libc::ssize_t,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

pub(crate) unsafe fn sys_write_fd(fd: c_int, buf: *const c_void, count: usize) -> libc::ssize_t {
    // SAFETY: caller enforces syscall argument validity.
    match unsafe { syscall::sys_write(fd, buf as *const u8, count) } {
        Ok(n) => n as libc::ssize_t,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// POSIX `read`.
///
/// # Safety
///
/// `buf` must be valid for writes of up to `count` bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn read(fd: c_int, buf: *mut c_void, count: usize) -> libc::ssize_t {
    if buf.is_null() && count > 0 {
        return -1;
    }

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::Stdio,
        buf as usize,
        count,
        true,
        known_remaining(buf as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(
            ApiFamily::Stdio,
            decision.profile,
            runtime_policy::scaled_cost(8, count),
            true,
        );
        return -1;
    }

    let (effective_count, clamped) = maybe_clamp_io_len(
        count,
        buf as usize,
        mode.heals_enabled() || matches!(decision.action, MembraneAction::Repair(_)),
    );
    // SAFETY: syscall wrapper expects raw fd/buffer/count.
    let rc = unsafe { sys_read_fd(fd, buf, effective_count) };
    runtime_policy::observe(
        ApiFamily::Stdio,
        decision.profile,
        runtime_policy::scaled_cost(8, effective_count),
        rc < 0 || clamped,
    );
    rc
}

/// POSIX `write`.
///
/// # Safety
///
/// `buf` must be valid for reads of up to `count` bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn write(fd: c_int, buf: *const c_void, count: usize) -> libc::ssize_t {
    if buf.is_null() && count > 0 {
        return -1;
    }

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::Stdio,
        buf as usize,
        count,
        false,
        known_remaining(buf as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(
            ApiFamily::Stdio,
            decision.profile,
            runtime_policy::scaled_cost(8, count),
            true,
        );
        return -1;
    }

    let (effective_count, clamped) = maybe_clamp_io_len(
        count,
        buf as usize,
        mode.heals_enabled() || matches!(decision.action, MembraneAction::Repair(_)),
    );
    // SAFETY: syscall wrapper expects raw fd/buffer/count.
    let rc = unsafe { sys_write_fd(fd, buf, effective_count) };
    runtime_policy::observe(
        ApiFamily::Stdio,
        decision.profile,
        runtime_policy::scaled_cost(8, effective_count),
        rc < 0 || clamped,
    );
    rc
}

/// POSIX `close`.
///
/// # Safety
///
/// `fd` should be a live file descriptor owned by the caller process.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn close(fd: c_int) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, fd as usize, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 6, true);
        return -1;
    }
    let rc = match syscall::sys_close(fd) {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    };
    runtime_policy::observe(ApiFamily::Stdio, decision.profile, 6, rc != 0);
    rc
}

/// POSIX `getpid`.
///
/// # Safety
///
/// C ABI entrypoint; no additional safety preconditions.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getpid() -> libc::pid_t {
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, 0, 0, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 4, true);
        return -1;
    }
    let pid = syscall::sys_getpid();
    runtime_policy::observe(ApiFamily::Stdio, decision.profile, 4, pid < 0);
    pid
}

/// POSIX `isatty`.
///
/// # Safety
///
/// `fd` should be a file descriptor that may refer to a terminal device.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn isatty(fd: c_int) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, fd as usize, 0, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 6, true);
        return 0;
    }

    let mut ws = std::mem::MaybeUninit::<libc::winsize>::zeroed();
    // SAFETY: ioctl(TIOCGWINSZ) writes into `ws` on success.
    let rc = unsafe { syscall::sys_ioctl(fd, libc::TIOCGWINSZ as usize, ws.as_mut_ptr() as usize) };
    let success = rc.is_ok();
    runtime_policy::observe(ApiFamily::Stdio, decision.profile, 6, !success);
    if success { 1 } else { 0 }
}

// ---------------------------------------------------------------------------
// lseek
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lseek(fd: c_int, offset: i64, whence: c_int) -> i64 {
    let (mode, decision) = runtime_policy::decide(ApiFamily::IoFd, fd as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }

    if !unistd_core::valid_whence(whence) {
        if mode.heals_enabled() {
            // default to SEEK_SET in hardened mode
            match syscall::sys_lseek(fd, offset, unistd_core::SEEK_SET) {
                Ok(pos) => {
                    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 8, false);
                    return pos;
                }
                Err(e) => {
                    unsafe { set_abi_errno(e) };
                    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 8, true);
                    return -1;
                }
            }
        }
        unsafe { set_abi_errno(errno::EINVAL) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }

    match syscall::sys_lseek(fd, offset, whence) {
        Ok(pos) => {
            runtime_policy::observe(ApiFamily::IoFd, decision.profile, 8, false);
            pos
        }
        Err(e) => {
            unsafe { set_abi_errno(e) };
            runtime_policy::observe(ApiFamily::IoFd, decision.profile, 8, true);
            -1
        }
    }
}

// ---------------------------------------------------------------------------
// stat / fstat / lstat
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn stat(path: *const c_char, buf: *mut libc::stat) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::IoFd, path as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }

    if path.is_null() || buf.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }

    let rc = unsafe {
        syscall_ret_int(
            libc::syscall(libc::SYS_newfstatat, libc::AT_FDCWD, path, buf, 0),
            errno::ENOENT,
        )
    };
    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 15, rc != 0);
    rc
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fstat(fd: c_int, buf: *mut libc::stat) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::IoFd, fd as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }

    if buf.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }

    let rc = unsafe { syscall_ret_int(libc::syscall(libc::SYS_fstat, fd, buf), errno::EBADF) };
    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, rc != 0);
    rc
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lstat(path: *const c_char, buf: *mut libc::stat) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::IoFd, path as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }

    if path.is_null() || buf.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }

    let rc = unsafe {
        syscall_ret_int(
            libc::syscall(
                libc::SYS_newfstatat,
                libc::AT_FDCWD,
                path,
                buf,
                libc::AT_SYMLINK_NOFOLLOW,
            ),
            errno::ENOENT,
        )
    };
    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 15, rc != 0);
    rc
}

// ---------------------------------------------------------------------------
// access
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn access(path: *const c_char, amode: c_int) -> c_int {
    let (mode, decision) =
        runtime_policy::decide(ApiFamily::IoFd, path as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }

    if path.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }

    if !unistd_core::valid_access_mode(amode) {
        if mode.heals_enabled() {
            // default to F_OK (existence check) in hardened mode
            let rc = unsafe {
                syscall_ret_int(
                    libc::syscall(
                        libc::SYS_faccessat,
                        libc::AT_FDCWD,
                        path,
                        unistd_core::F_OK,
                        0,
                    ),
                    errno::EACCES,
                )
            };
            runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, rc != 0);
            return rc;
        }
        unsafe { set_abi_errno(errno::EINVAL) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }

    let rc = unsafe {
        syscall_ret_int(
            libc::syscall(libc::SYS_faccessat, libc::AT_FDCWD, path, amode, 0),
            errno::EACCES,
        )
    };
    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, rc != 0);
    rc
}

// ---------------------------------------------------------------------------
// getcwd
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getcwd(buf: *mut c_char, size: usize) -> *mut c_char {
    let (_, decision) = runtime_policy::decide(ApiFamily::IoFd, buf as usize, size, true, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return std::ptr::null_mut();
    }

    if buf.is_null() || size == 0 {
        unsafe { set_abi_errno(errno::EINVAL) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return std::ptr::null_mut();
    }

    let rc = unsafe { libc::syscall(libc::SYS_getcwd, buf, size) };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(errno::EINVAL)) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 15, true);
        return std::ptr::null_mut();
    }
    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 15, false);
    buf
}

// ---------------------------------------------------------------------------
// chdir / fchdir
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn chdir(path: *const c_char) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::IoFd, path as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }

    if path.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }

    let rc = unsafe { syscall_ret_int(libc::syscall(libc::SYS_chdir, path), errno::ENOENT) };
    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, rc != 0);
    rc
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fchdir(fd: c_int) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::IoFd, fd as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    let rc = unsafe { syscall_ret_int(libc::syscall(libc::SYS_fchdir, fd), errno::EBADF) };
    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, rc != 0);
    rc
}

// ---------------------------------------------------------------------------
// Process identity: getppid, getuid, geteuid, getgid, getegid
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getppid() -> libc::pid_t {
    let rc = unsafe { libc::syscall(libc::SYS_getppid) };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(errno::EINVAL)) };
        -1
    } else {
        rc as libc::pid_t
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getuid() -> libc::uid_t {
    let rc = unsafe { libc::syscall(libc::SYS_getuid) };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(errno::EINVAL)) };
        libc::uid_t::MAX
    } else {
        rc as libc::uid_t
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn geteuid() -> libc::uid_t {
    let rc = unsafe { libc::syscall(libc::SYS_geteuid) };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(errno::EINVAL)) };
        libc::uid_t::MAX
    } else {
        rc as libc::uid_t
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getgid() -> libc::gid_t {
    let rc = unsafe { libc::syscall(libc::SYS_getgid) };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(errno::EINVAL)) };
        libc::gid_t::MAX
    } else {
        rc as libc::gid_t
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getegid() -> libc::gid_t {
    let rc = unsafe { libc::syscall(libc::SYS_getegid) };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(errno::EINVAL)) };
        libc::gid_t::MAX
    } else {
        rc as libc::gid_t
    }
}

// ---------------------------------------------------------------------------
// Process group / session: getpgid, setpgid, getsid, setsid
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getpgid(pid: libc::pid_t) -> libc::pid_t {
    let rc = unsafe { libc::syscall(libc::SYS_getpgid, pid) };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(errno::ESRCH)) };
        -1
    } else {
        rc as libc::pid_t
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setpgid(pid: libc::pid_t, pgid: libc::pid_t) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_setpgid, pid, pgid) as c_int };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(errno::EINVAL)) };
    }
    rc
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getsid(pid: libc::pid_t) -> libc::pid_t {
    let rc = unsafe { libc::syscall(libc::SYS_getsid, pid) };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(errno::ESRCH)) };
        -1
    } else {
        rc as libc::pid_t
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setsid() -> libc::pid_t {
    let rc = unsafe { libc::syscall(libc::SYS_setsid) };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(errno::EPERM)) };
        -1
    } else {
        rc as libc::pid_t
    }
}

// ---------------------------------------------------------------------------
// Credential operations: setuid, seteuid, setreuid, setgid, setegid, setregid
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setuid(uid: libc::uid_t) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_setuid, uid) as c_int };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(errno::EPERM)) };
    }
    rc
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn seteuid(euid: libc::uid_t) -> c_int {
    // seteuid(euid) == setreuid(-1, euid)
    let rc = unsafe { libc::syscall(libc::SYS_setreuid, libc::uid_t::MAX, euid) as c_int };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(errno::EPERM)) };
    }
    rc
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setreuid(ruid: libc::uid_t, euid: libc::uid_t) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_setreuid, ruid, euid) as c_int };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(errno::EPERM)) };
    }
    rc
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setgid(gid: libc::gid_t) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_setgid, gid) as c_int };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(errno::EPERM)) };
    }
    rc
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setegid(egid: libc::gid_t) -> c_int {
    // setegid(egid) == setregid(-1, egid)
    let rc = unsafe { libc::syscall(libc::SYS_setregid, libc::gid_t::MAX, egid) as c_int };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(errno::EPERM)) };
    }
    rc
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setregid(rgid: libc::gid_t, egid: libc::gid_t) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_setregid, rgid, egid) as c_int };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(errno::EPERM)) };
    }
    rc
}

// ---------------------------------------------------------------------------
// Supplementary groups: getgroups, setgroups
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getgroups(size: c_int, list: *mut libc::gid_t) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_getgroups, size, list) as c_int };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(errno::EINVAL)) };
    }
    rc
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setgroups(size: usize, list: *const libc::gid_t) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_setgroups, size, list) as c_int };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(errno::EPERM)) };
    }
    rc
}

// ---------------------------------------------------------------------------
// Link operations: unlink, rmdir, link, symlink, readlink
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn unlink(path: *const c_char) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::IoFd, path as usize, 0, true, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    if path.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    let rc = unsafe {
        syscall_ret_int(
            libc::syscall(libc::SYS_unlinkat, libc::AT_FDCWD, path, 0),
            errno::ENOENT,
        )
    };
    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, rc != 0);
    rc
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rmdir(path: *const c_char) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::IoFd, path as usize, 0, true, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    if path.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    let rc = unsafe {
        syscall_ret_int(
            libc::syscall(libc::SYS_unlinkat, libc::AT_FDCWD, path, libc::AT_REMOVEDIR),
            errno::ENOENT,
        )
    };
    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, rc != 0);
    rc
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn link(oldpath: *const c_char, newpath: *const c_char) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::IoFd, oldpath as usize, 0, true, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    if oldpath.is_null() || newpath.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    let rc = unsafe {
        syscall_ret_int(
            libc::syscall(
                libc::SYS_linkat,
                libc::AT_FDCWD,
                oldpath,
                libc::AT_FDCWD,
                newpath,
                0,
            ),
            errno::ENOENT,
        )
    };
    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 12, rc != 0);
    rc
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn symlink(target: *const c_char, linkpath: *const c_char) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::IoFd, target as usize, 0, true, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    if target.is_null() || linkpath.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    let rc = unsafe {
        syscall_ret_int(
            libc::syscall(libc::SYS_symlinkat, target, libc::AT_FDCWD, linkpath),
            errno::ENOENT,
        )
    };
    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 12, rc != 0);
    rc
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn readlink(path: *const c_char, buf: *mut c_char, bufsiz: usize) -> isize {
    let (_, decision) =
        runtime_policy::decide(ApiFamily::IoFd, path as usize, bufsiz, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    if path.is_null() || buf.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    let rc = unsafe {
        syscall_ret_isize(
            libc::syscall(libc::SYS_readlinkat, libc::AT_FDCWD, path, buf, bufsiz),
            errno::ENOENT,
        )
    };
    let adverse = rc < 0;
    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 12, adverse);
    rc
}

// ---------------------------------------------------------------------------
// Sync: fsync, fdatasync
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fsync(fd: c_int) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::IoFd, fd as usize, 0, true, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    let rc = match syscall::sys_fsync(fd) {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    };
    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 15, rc != 0);
    rc
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fdatasync(fd: c_int) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::IoFd, fd as usize, 0, true, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    let rc = match syscall::sys_fdatasync(fd) {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    };
    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 15, rc != 0);
    rc
}

// ---------------------------------------------------------------------------
// open / creat
// ---------------------------------------------------------------------------

/// POSIX `open` — open a file descriptor.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn open(path: *const c_char, flags: c_int, mode: libc::mode_t) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::IoFd, path as usize, 0, true, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    if path.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    let rc = unsafe {
        syscall_ret_int(
            libc::syscall(libc::SYS_openat, libc::AT_FDCWD, path, flags, mode),
            errno::ENOENT,
        )
    };
    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 12, rc < 0);
    rc
}

/// POSIX `creat` — equivalent to `open(path, O_CREAT|O_WRONLY|O_TRUNC, mode)`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn creat(path: *const c_char, mode: libc::mode_t) -> c_int {
    unsafe { open(path, libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC, mode) }
}

// ---------------------------------------------------------------------------
// rename / mkdir
// ---------------------------------------------------------------------------

/// POSIX `rename` — rename a file.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rename(oldpath: *const c_char, newpath: *const c_char) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::IoFd, oldpath as usize, 0, true, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    if oldpath.is_null() || newpath.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    let rc = unsafe {
        syscall_ret_int(
            libc::syscall(
                libc::SYS_renameat2,
                libc::AT_FDCWD,
                oldpath,
                libc::AT_FDCWD,
                newpath,
                0,
            ),
            errno::ENOENT,
        )
    };
    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 12, rc != 0);
    rc
}

/// POSIX `mkdir` — create a directory.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mkdir(path: *const c_char, mode: libc::mode_t) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::IoFd, path as usize, 0, true, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    if path.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    let rc = unsafe {
        syscall_ret_int(
            libc::syscall(libc::SYS_mkdirat, libc::AT_FDCWD, path, mode),
            errno::ENOENT,
        )
    };
    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, rc != 0);
    rc
}

// ---------------------------------------------------------------------------
// chmod / fchmod
// ---------------------------------------------------------------------------

/// POSIX `chmod` — change file mode bits.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn chmod(path: *const c_char, mode: libc::mode_t) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::IoFd, path as usize, 0, true, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    if path.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    let rc = unsafe {
        syscall_ret_int(
            libc::syscall(libc::SYS_fchmodat, libc::AT_FDCWD, path, mode, 0),
            errno::ENOENT,
        )
    };
    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, rc != 0);
    rc
}

/// POSIX `fchmod` — change file mode bits by file descriptor.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fchmod(fd: c_int, mode: libc::mode_t) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::IoFd, fd as usize, 0, true, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    let rc = unsafe { syscall_ret_int(libc::syscall(libc::SYS_fchmod, fd, mode), errno::EBADF) };
    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, rc != 0);
    rc
}

// ---------------------------------------------------------------------------
// chown / fchown / lchown
// ---------------------------------------------------------------------------

/// POSIX `chown` — change ownership of a file.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn chown(
    path: *const c_char,
    owner: libc::uid_t,
    group: libc::gid_t,
) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::IoFd, path as usize, 0, true, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    if path.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    let rc = unsafe {
        syscall_ret_int(
            libc::syscall(libc::SYS_fchownat, libc::AT_FDCWD, path, owner, group, 0),
            errno::ENOENT,
        )
    };
    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, rc != 0);
    rc
}

/// POSIX `fchown` — change ownership of a file by file descriptor.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fchown(fd: c_int, owner: libc::uid_t, group: libc::gid_t) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::IoFd, fd as usize, 0, true, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    let rc = unsafe {
        syscall_ret_int(
            libc::syscall(libc::SYS_fchown, fd, owner, group),
            errno::EBADF,
        )
    };
    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, rc != 0);
    rc
}

/// POSIX `lchown` — change ownership of a symbolic link.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lchown(
    path: *const c_char,
    owner: libc::uid_t,
    group: libc::gid_t,
) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::IoFd, path as usize, 0, true, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    if path.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    let rc = unsafe {
        syscall_ret_int(
            libc::syscall(
                libc::SYS_fchownat,
                libc::AT_FDCWD,
                path,
                owner,
                group,
                libc::AT_SYMLINK_NOFOLLOW,
            ),
            errno::ENOENT,
        )
    };
    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, rc != 0);
    rc
}

// ---------------------------------------------------------------------------
// umask
// ---------------------------------------------------------------------------

/// POSIX `umask` — set the file mode creation mask.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn umask(mask: libc::mode_t) -> libc::mode_t {
    unsafe { libc::syscall(libc::SYS_umask, mask) as libc::mode_t }
}

// ---------------------------------------------------------------------------
// truncate / ftruncate
// ---------------------------------------------------------------------------

/// POSIX `truncate` — truncate a file to a specified length.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn truncate(path: *const c_char, length: i64) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::IoFd, path as usize, 0, true, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    if path.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    let rc = unsafe {
        syscall_ret_int(
            libc::syscall(libc::SYS_truncate, path, length),
            errno::ENOENT,
        )
    };
    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, rc != 0);
    rc
}

/// POSIX `ftruncate` — truncate a file to a specified length by file descriptor.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ftruncate(fd: c_int, length: i64) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::IoFd, fd as usize, 0, true, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    let rc =
        unsafe { syscall_ret_int(libc::syscall(libc::SYS_ftruncate, fd, length), errno::EBADF) };
    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, rc != 0);
    rc
}

// ---------------------------------------------------------------------------
// flock
// ---------------------------------------------------------------------------

/// BSD `flock` — apply or remove an advisory lock on an open file.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn flock(fd: c_int, operation: c_int) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::IoFd, fd as usize, 0, true, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    let rc =
        unsafe { syscall_ret_int(libc::syscall(libc::SYS_flock, fd, operation), errno::EBADF) };
    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, rc != 0);
    rc
}

// ---------------------------------------------------------------------------
// *at() family: openat, fstatat, unlinkat, renameat, mkdirat
// ---------------------------------------------------------------------------

/// POSIX `openat` — open a file relative to a directory file descriptor.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn openat(
    dirfd: c_int,
    path: *const c_char,
    flags: c_int,
    mode: libc::mode_t,
) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::IoFd, path as usize, 0, true, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    if path.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    let rc = unsafe {
        syscall_ret_int(
            libc::syscall(libc::SYS_openat, dirfd, path, flags, mode),
            errno::ENOENT,
        )
    };
    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 12, rc < 0);
    rc
}

/// POSIX `fstatat` — get file status relative to a directory file descriptor.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fstatat(
    dirfd: c_int,
    path: *const c_char,
    buf: *mut libc::stat,
    flags: c_int,
) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::IoFd, path as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    if path.is_null() || buf.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    let rc = unsafe {
        syscall_ret_int(
            libc::syscall(libc::SYS_newfstatat, dirfd, path, buf, flags),
            errno::ENOENT,
        )
    };
    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 15, rc != 0);
    rc
}

/// POSIX `unlinkat` — remove a directory entry relative to a directory fd.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn unlinkat(dirfd: c_int, path: *const c_char, flags: c_int) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::IoFd, path as usize, 0, true, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    if path.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    let rc = unsafe {
        syscall_ret_int(
            libc::syscall(libc::SYS_unlinkat, dirfd, path, flags),
            errno::ENOENT,
        )
    };
    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, rc != 0);
    rc
}

/// POSIX `renameat` — rename a file relative to directory fds.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn renameat(
    olddirfd: c_int,
    oldpath: *const c_char,
    newdirfd: c_int,
    newpath: *const c_char,
) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::IoFd, oldpath as usize, 0, true, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    if oldpath.is_null() || newpath.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    let rc = unsafe {
        syscall_ret_int(
            libc::syscall(libc::SYS_renameat2, olddirfd, oldpath, newdirfd, newpath, 0),
            errno::ENOENT,
        )
    };
    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 12, rc != 0);
    rc
}

/// POSIX `mkdirat` — create a directory relative to a directory fd.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mkdirat(dirfd: c_int, path: *const c_char, mode: libc::mode_t) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::IoFd, path as usize, 0, true, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    if path.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    let rc = unsafe {
        syscall_ret_int(
            libc::syscall(libc::SYS_mkdirat, dirfd, path, mode),
            errno::ENOENT,
        )
    };
    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, rc != 0);
    rc
}

// ---------------------------------------------------------------------------
// *at() family: readlinkat, symlinkat, faccessat, fchownat, fchmodat, linkat
// ---------------------------------------------------------------------------

/// POSIX `readlinkat` — read value of a symbolic link relative to a directory fd.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn readlinkat(
    dirfd: c_int,
    path: *const c_char,
    buf: *mut c_char,
    bufsiz: usize,
) -> isize {
    let (_, decision) =
        runtime_policy::decide(ApiFamily::IoFd, path as usize, bufsiz, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    if path.is_null() || buf.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    let rc = unsafe {
        syscall_ret_isize(
            libc::syscall(libc::SYS_readlinkat, dirfd, path, buf, bufsiz),
            errno::ENOENT,
        )
    };
    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 12, rc < 0);
    rc
}

/// POSIX `symlinkat` — create a symbolic link relative to a directory fd.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn symlinkat(
    target: *const c_char,
    newdirfd: c_int,
    linkpath: *const c_char,
) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::IoFd, target as usize, 0, true, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    if target.is_null() || linkpath.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    let rc = unsafe {
        syscall_ret_int(
            libc::syscall(libc::SYS_symlinkat, target, newdirfd, linkpath),
            errno::ENOENT,
        )
    };
    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 12, rc != 0);
    rc
}

/// POSIX `faccessat` — check file accessibility relative to a directory fd.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn faccessat(
    dirfd: c_int,
    path: *const c_char,
    amode: c_int,
    flags: c_int,
) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::IoFd, path as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    if path.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    let rc = unsafe {
        syscall_ret_int(
            libc::syscall(libc::SYS_faccessat, dirfd, path, amode, flags),
            errno::EACCES,
        )
    };
    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, rc != 0);
    rc
}

/// POSIX `fchownat` — change ownership of a file relative to a directory fd.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fchownat(
    dirfd: c_int,
    path: *const c_char,
    owner: libc::uid_t,
    group: libc::gid_t,
    flags: c_int,
) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::IoFd, path as usize, 0, true, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    if path.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    let rc = unsafe {
        syscall_ret_int(
            libc::syscall(libc::SYS_fchownat, dirfd, path, owner, group, flags),
            errno::ENOENT,
        )
    };
    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, rc != 0);
    rc
}

/// POSIX `fchmodat` — change file mode bits relative to a directory fd.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fchmodat(
    dirfd: c_int,
    path: *const c_char,
    mode: libc::mode_t,
    flags: c_int,
) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::IoFd, path as usize, 0, true, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    if path.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    let rc = unsafe {
        syscall_ret_int(
            libc::syscall(libc::SYS_fchmodat, dirfd, path, mode, flags),
            errno::ENOENT,
        )
    };
    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, rc != 0);
    rc
}

/// POSIX `linkat` — create a hard link relative to directory fds.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn linkat(
    olddirfd: c_int,
    oldpath: *const c_char,
    newdirfd: c_int,
    newpath: *const c_char,
    flags: c_int,
) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::IoFd, oldpath as usize, 0, true, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    if oldpath.is_null() || newpath.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    let rc = unsafe {
        syscall_ret_int(
            libc::syscall(
                libc::SYS_linkat,
                olddirfd,
                oldpath,
                newdirfd,
                newpath,
                flags,
            ),
            errno::ENOENT,
        )
    };
    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 12, rc != 0);
    rc
}

// ---------------------------------------------------------------------------
// uname / gethostname
// ---------------------------------------------------------------------------

#[inline]
fn read_utsname() -> Result<libc::utsname, c_int> {
    let mut uts = std::mem::MaybeUninit::<libc::utsname>::zeroed();
    let rc = unsafe { libc::syscall(libc::SYS_uname, uts.as_mut_ptr()) };
    if rc < 0 {
        Err(last_host_errno(errno::EFAULT))
    } else {
        Ok(unsafe { uts.assume_init() })
    }
}

#[inline]
fn uts_field_len(field: &[c_char]) -> usize {
    field.iter().position(|&c| c == 0).unwrap_or(field.len())
}

/// POSIX `uname` — get system identification.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn uname(buf: *mut libc::utsname) -> c_int {
    if buf.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        return -1;
    }
    unsafe { syscall_ret_int(libc::syscall(libc::SYS_uname, buf), errno::EFAULT) }
}

/// POSIX `gethostname` — get the hostname.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn gethostname(name: *mut c_char, len: usize) -> c_int {
    if name.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        return -1;
    }
    let uts = match read_utsname() {
        Ok(uts) => uts,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            return -1;
        }
    };
    let nodename = &uts.nodename;
    let hostname_len = uts_field_len(nodename);
    if hostname_len >= len {
        unsafe { set_abi_errno(errno::ENAMETOOLONG) };
        return -1;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(nodename.as_ptr(), name.cast(), hostname_len);
        *name.add(hostname_len) = 0;
    }
    0
}

// ---------------------------------------------------------------------------
// getrusage
// ---------------------------------------------------------------------------

/// POSIX `getrusage` — get resource usage.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getrusage(who: c_int, usage: *mut libc::rusage) -> c_int {
    if usage.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        return -1;
    }
    unsafe {
        syscall_ret_int(
            libc::syscall(libc::SYS_getrusage, who, usage),
            errno::EINVAL,
        )
    }
}

// ---------------------------------------------------------------------------
// alarm / sysconf
// ---------------------------------------------------------------------------

/// POSIX `alarm` — schedule a SIGALRM signal.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn alarm(seconds: u32) -> u32 {
    unsafe { libc::syscall(libc::SYS_alarm, seconds) as u32 }
}

// ---------------------------------------------------------------------------
// sleep / usleep
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sleep(seconds: u32) -> u32 {
    let req = libc::timespec {
        tv_sec: seconds as libc::time_t,
        tv_nsec: 0,
    };
    let mut rem = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let rc = unsafe { libc::syscall(libc::SYS_nanosleep, &req, &mut rem) };
    if rc < 0 {
        let e = last_host_errno(errno::EINTR);
        unsafe { set_abi_errno(e) };
        if e == errno::EINTR {
            let mut remaining = rem.tv_sec.max(0) as u32;
            if rem.tv_nsec > 0 {
                remaining = remaining.saturating_add(1);
            }
            remaining
        } else {
            seconds
        }
    } else {
        0
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn usleep(usec: u32) -> c_int {
    let req = libc::timespec {
        tv_sec: (usec / 1_000_000) as libc::time_t,
        tv_nsec: ((usec % 1_000_000) * 1_000) as libc::c_long,
    };
    unsafe {
        syscall_ret_int(
            libc::syscall(
                libc::SYS_nanosleep,
                &req,
                std::ptr::null_mut::<libc::timespec>(),
            ),
            errno::EINVAL,
        )
    }
}

// ---------------------------------------------------------------------------
// inotify
// ---------------------------------------------------------------------------

/// Linux `inotify_init` — initialize an inotify instance.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn inotify_init() -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_inotify_init1, 0) as c_int };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(errno::ENOMEM)) };
    }
    rc
}

/// Linux `inotify_init1` — initialize an inotify instance with flags.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn inotify_init1(flags: c_int) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_inotify_init1, flags) as c_int };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(errno::EINVAL)) };
    }
    rc
}

/// Linux `inotify_add_watch` — add a watch to an inotify instance.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn inotify_add_watch(fd: c_int, pathname: *const c_char, mask: u32) -> c_int {
    if pathname.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        return -1;
    }
    let rc = unsafe { libc::syscall(libc::SYS_inotify_add_watch, fd, pathname, mask) as c_int };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(errno::EBADF)) };
    }
    rc
}

/// Linux `inotify_rm_watch` — remove a watch from an inotify instance.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn inotify_rm_watch(fd: c_int, wd: c_int) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_inotify_rm_watch, fd, wd) as c_int };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(errno::EBADF)) };
    }
    rc
}

// ---------------------------------------------------------------------------
// setitimer / getitimer
// ---------------------------------------------------------------------------

/// POSIX `setitimer` — set value of an interval timer.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setitimer(
    which: c_int,
    new_value: *const libc::itimerval,
    old_value: *mut libc::itimerval,
) -> c_int {
    if new_value.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        return -1;
    }
    let rc = unsafe { libc::syscall(libc::SYS_setitimer, which, new_value, old_value) as c_int };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(errno::EINVAL)) };
    }
    rc
}

/// POSIX `getitimer` — get value of an interval timer.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getitimer(which: c_int, curr_value: *mut libc::itimerval) -> c_int {
    if curr_value.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        return -1;
    }
    let rc = unsafe { libc::syscall(libc::SYS_getitimer, which, curr_value) as c_int };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(errno::EINVAL)) };
    }
    rc
}

// ---------------------------------------------------------------------------
// mknod / mkfifo
// ---------------------------------------------------------------------------

/// POSIX `mknod` — create a special or ordinary file.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mknod(path: *const c_char, mode: libc::mode_t, dev: libc::dev_t) -> c_int {
    if path.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        return -1;
    }
    unsafe {
        syscall_ret_int(
            libc::syscall(libc::SYS_mknodat, libc::AT_FDCWD, path, mode, dev),
            errno::ENOENT,
        )
    }
}

/// POSIX `mkfifo` — create a FIFO (named pipe).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mkfifo(path: *const c_char, mode: libc::mode_t) -> c_int {
    // mkfifo is mknod with S_IFIFO
    unsafe { mknod(path, mode | libc::S_IFIFO, 0) }
}

// ---------------------------------------------------------------------------
// sysconf
// ---------------------------------------------------------------------------

/// POSIX `sysconf` — get configurable system variables.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sysconf(name: c_int) -> libc::c_long {
    match name {
        libc::_SC_PAGESIZE => 4096,
        libc::_SC_CLK_TCK => 100,
        libc::_SC_NPROCESSORS_ONLN | libc::_SC_NPROCESSORS_CONF => {
            // Read from /sys/devices/system/cpu/online or fallback.
            // Simple approach: use SYS_sched_getaffinity to count CPUs.
            let mut mask = [0u8; 128]; // 1024 CPUs max
            let rc = unsafe {
                libc::syscall(
                    libc::SYS_sched_getaffinity,
                    0,
                    mask.len(),
                    mask.as_mut_ptr(),
                )
            };
            if rc > 0 {
                let n = mask[..rc as usize]
                    .iter()
                    .map(|b| b.count_ones() as libc::c_long)
                    .sum();
                if n > 0 {
                    return n;
                }
            }
            1
        }
        libc::_SC_OPEN_MAX => {
            // Try to get from getrlimit.
            let mut rlim = std::mem::MaybeUninit::<libc::rlimit>::zeroed();
            let rc = unsafe {
                libc::syscall(libc::SYS_getrlimit, libc::RLIMIT_NOFILE, rlim.as_mut_ptr())
            };
            if rc == 0 {
                let rlim = unsafe { rlim.assume_init() };
                return rlim.rlim_cur as libc::c_long;
            }
            1024
        }
        libc::_SC_HOST_NAME_MAX => 64,
        libc::_SC_LINE_MAX => 2048,
        libc::_SC_ARG_MAX => 2097152, // 2 MiB
        libc::_SC_CHILD_MAX => 32768,
        libc::_SC_IOV_MAX => 1024,
        _ => {
            unsafe { set_abi_errno(errno::EINVAL) };
            -1
        }
    }
}

// ---------------------------------------------------------------------------
// getopt — GlibcCallThrough (uses glibc global state: optarg, optind, etc.)
// ---------------------------------------------------------------------------

unsafe extern "C" {
    #[link_name = "getopt"]
    fn libc_getopt(argc: c_int, argv: *const *mut c_char, optstring: *const c_char) -> c_int;
    #[link_name = "getopt_long"]
    fn libc_getopt_long(
        argc: c_int,
        argv: *const *mut c_char,
        optstring: *const c_char,
        longopts: *const libc::option,
        longindex: *mut c_int,
    ) -> c_int;
}

/// POSIX `getopt` — parse command-line options.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getopt(
    argc: c_int,
    argv: *const *mut c_char,
    optstring: *const c_char,
) -> c_int {
    unsafe { libc_getopt(argc, argv, optstring) }
}

/// GNU `getopt_long` — parse long command-line options.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getopt_long(
    argc: c_int,
    argv: *const *mut c_char,
    optstring: *const c_char,
    longopts: *const libc::option,
    longindex: *mut c_int,
) -> c_int {
    unsafe { libc_getopt_long(argc, argv, optstring, longopts, longindex) }
}

// Note: getopt global variables (optarg, optind, opterr, optopt) are provided
// by glibc and will be available to programs through the glibc linkage since
// we delegate to libc_getopt. Programs using LD_PRELOAD will see glibc's globals.

// ---------------------------------------------------------------------------
// syslog — GlibcCallThrough
// ---------------------------------------------------------------------------

unsafe extern "C" {
    #[link_name = "openlog"]
    fn libc_openlog(ident: *const c_char, option: c_int, facility: c_int);
    #[link_name = "closelog"]
    fn libc_closelog();
    #[link_name = "vsyslog"]
    fn libc_vsyslog(priority: c_int, format: *const c_char, ap: *mut c_void);
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn openlog(ident: *const c_char, option: c_int, facility: c_int) {
    unsafe { libc_openlog(ident, option, facility) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn syslog(priority: c_int, format: *const c_char, mut args: ...) {
    unsafe { libc_vsyslog(priority, format, (&mut args) as *mut _ as *mut c_void) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn closelog() {
    unsafe { libc_closelog() }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn vsyslog(priority: c_int, format: *const c_char, ap: *mut c_void) {
    unsafe { libc_vsyslog(priority, format, ap) }
}

// ---------------------------------------------------------------------------
// misc POSIX — mixed (implemented + call-through)
// ---------------------------------------------------------------------------

unsafe extern "C" {
    #[link_name = "nice"]
    fn libc_nice(inc: c_int) -> c_int;
    #[link_name = "daemon"]
    fn libc_daemon(nochdir: c_int, noclose: c_int) -> c_int;
}

const MKDTEMP_SUFFIX_LEN: usize = 6;
const MKDTEMP_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
static MKDTEMP_NONCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
const CONFSTR_PATH: &[u8] = b"/bin:/usr/bin\0";
const CTERMID_PATH: &[u8] = b"/dev/tty\0";
static mut CTERMID_FALLBACK: [c_char; CTERMID_PATH.len()] = [0; CTERMID_PATH.len()];

#[inline]
fn confstr_value(name: c_int) -> Option<&'static [u8]> {
    match name {
        libc::_CS_PATH => Some(CONFSTR_PATH),
        _ => None,
    }
}

#[inline]
fn pathconf_value(name: c_int) -> Option<libc::c_long> {
    match name {
        libc::_PC_LINK_MAX => Some(127),
        libc::_PC_MAX_CANON => Some(255),
        libc::_PC_MAX_INPUT => Some(255),
        libc::_PC_NAME_MAX => Some(255),
        libc::_PC_PATH_MAX => Some(4096),
        libc::_PC_PIPE_BUF => Some(4096),
        libc::_PC_CHOWN_RESTRICTED => Some(1),
        libc::_PC_NO_TRUNC => Some(1),
        libc::_PC_VDISABLE => Some(0),
        _ => None,
    }
}

#[inline]
fn mix64(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

unsafe fn mkdtemp_inner(template: *mut c_char) -> (*mut c_char, bool) {
    if template.is_null() {
        unsafe { set_abi_errno(errno::EINVAL) };
        return (std::ptr::null_mut(), true);
    }

    // SAFETY: `template` must be writable and NUL-terminated by ABI contract.
    let template_bytes = unsafe { std::ffi::CStr::from_ptr(template) }.to_bytes();
    if template_bytes.len() < MKDTEMP_SUFFIX_LEN
        || !template_bytes[template_bytes.len() - MKDTEMP_SUFFIX_LEN..]
            .iter()
            .all(|&b| b == b'X')
    {
        unsafe { set_abi_errno(errno::EINVAL) };
        return (std::ptr::null_mut(), true);
    }

    // SAFETY: `template` points to writable bytes with at least len+1 capacity.
    let buf = unsafe { std::slice::from_raw_parts_mut(template as *mut u8, template_bytes.len()) };
    let start = buf.len() - MKDTEMP_SUFFIX_LEN;
    let seed = mix64(
        (std::process::id() as u64).wrapping_shl(32)
            ^ (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0))
            ^ MKDTEMP_NONCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
    );

    for attempt in 0_u64..256 {
        let mut state = mix64(seed ^ attempt.wrapping_mul(0x9e37_79b9_7f4a_7c15));
        for i in 0..MKDTEMP_SUFFIX_LEN {
            state = mix64(state.wrapping_add(i as u64));
            buf[start + i] = MKDTEMP_CHARS[(state as usize) % MKDTEMP_CHARS.len()];
        }

        // SAFETY: `template` points to a valid candidate pathname.
        let rc = unsafe { libc::mkdir(template as *const c_char, 0o700) };
        if rc == 0 {
            return (template, false);
        }
        let err = last_host_errno(errno::EIO);
        if err != libc::EEXIST {
            unsafe { set_abi_errno(err) };
            return (std::ptr::null_mut(), true);
        }
    }

    unsafe { set_abi_errno(libc::EEXIST) };
    (std::ptr::null_mut(), true)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn confstr(name: c_int, buf: *mut c_char, len: usize) -> usize {
    let (_, decision) = runtime_policy::decide(
        ApiFamily::IoFd,
        buf as usize,
        len,
        true,
        buf.is_null() && len > 0,
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(libc::EPERM) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 8, true);
        return 0;
    }

    let value = match confstr_value(name) {
        Some(v) => v,
        None => {
            unsafe { set_abi_errno(libc::EINVAL) };
            runtime_policy::observe(ApiFamily::IoFd, decision.profile, 8, true);
            return 0;
        }
    };

    if !buf.is_null() && len > 0 {
        let copy_len = std::cmp::min(len, value.len());
        unsafe { std::ptr::copy_nonoverlapping(value.as_ptr(), buf.cast::<u8>(), copy_len) };
        if copy_len == len {
            unsafe { *buf.add(len - 1) = 0 };
        }
    }

    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 8, false);
    value.len()
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pathconf(path: *const c_char, name: c_int) -> libc::c_long {
    let (_, decision) =
        runtime_policy::decide(ApiFamily::IoFd, path as usize, 0, true, path.is_null(), 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(libc::EPERM) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 8, true);
        return -1;
    }

    if path.is_null() {
        unsafe { set_abi_errno(libc::EINVAL) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 8, true);
        return -1;
    }

    let mut st = std::mem::MaybeUninit::<libc::stat>::zeroed();
    let stat_rc = unsafe {
        libc::syscall(
            libc::SYS_newfstatat,
            libc::AT_FDCWD,
            path,
            st.as_mut_ptr(),
            0,
        )
    };
    if stat_rc < 0 {
        unsafe { set_abi_errno(last_host_errno(libc::ENOENT)) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 8, true);
        return -1;
    }

    let out = match pathconf_value(name) {
        Some(v) => v,
        None => {
            unsafe { set_abi_errno(libc::EINVAL) };
            runtime_policy::observe(ApiFamily::IoFd, decision.profile, 8, true);
            return -1;
        }
    };
    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 8, false);
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fpathconf(fd: c_int, name: c_int) -> libc::c_long {
    let (_, decision) = runtime_policy::decide(ApiFamily::IoFd, fd as usize, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(libc::EPERM) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 8, true);
        return -1;
    }

    if let Err(e) = unsafe { syscall::sys_fcntl(fd, libc::F_GETFD, 0) } {
        unsafe { set_abi_errno(e) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 8, true);
        return -1;
    }

    let out = match pathconf_value(name) {
        Some(v) => v,
        None => {
            unsafe { set_abi_errno(libc::EINVAL) };
            runtime_policy::observe(ApiFamily::IoFd, decision.profile, 8, true);
            return -1;
        }
    };
    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 8, false);
    out
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nice(inc: c_int) -> c_int {
    unsafe { libc_nice(inc) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn daemon(nochdir: c_int, noclose: c_int) -> c_int {
    unsafe { libc_daemon(nochdir, noclose) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getpagesize() -> c_int {
    let page_size = unsafe { sysconf(libc::_SC_PAGESIZE) };
    if page_size <= 0 || page_size > c_int::MAX as libc::c_long {
        4096
    } else {
        page_size as c_int
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn gethostid() -> libc::c_long {
    let uts = match read_utsname() {
        Ok(uts) => uts,
        Err(_) => return 0,
    };
    let nodename = &uts.nodename;
    let nodename_len = uts_field_len(nodename);
    if nodename_len == 0 {
        return 0;
    }
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for &byte in &nodename[..nodename_len] {
        hash ^= byte as u8 as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    let hostid32 = mix64(hash) as u32 as i32;
    hostid32 as libc::c_long
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getdomainname(name: *mut c_char, len: usize) -> c_int {
    if name.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        return -1;
    }
    let uts = match read_utsname() {
        Ok(uts) => uts,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            return -1;
        }
    };
    let domainname = &uts.domainname;
    let domain_len = uts_field_len(domainname);
    if len == 0 {
        return 0;
    }

    let copy_len = domain_len.min(len);
    unsafe {
        std::ptr::copy_nonoverlapping(domainname.as_ptr(), name.cast(), copy_len);
        if copy_len < len {
            *name.add(copy_len) = 0;
        }
    }
    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mkdtemp(template: *mut c_char) -> *mut c_char {
    let (_, decision) = runtime_policy::decide(
        ApiFamily::IoFd,
        template as usize,
        0,
        true,
        template.is_null() || known_remaining(template as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(libc::EPERM) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, true);
        return std::ptr::null_mut();
    }

    let (out, failed) = unsafe { mkdtemp_inner(template) };
    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 16, failed);
    out
}

// ---------------------------------------------------------------------------
// getrandom — RawSyscall
// ---------------------------------------------------------------------------

/// Linux `getrandom` — fill buffer with random bytes from the kernel CSPRNG.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getrandom(buf: *mut c_void, buflen: usize, flags: c_uint) -> isize {
    let (_, decision) =
        runtime_policy::decide(ApiFamily::IoFd, buf as usize, buflen, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }

    let rc = unsafe { libc::syscall(libc::SYS_getrandom, buf, buflen, flags) };
    if rc < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(errno::EIO);
        unsafe { set_abi_errno(e) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 8, true);
        -1
    } else {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 8, false);
        rc as isize
    }
}

// ---------------------------------------------------------------------------
// statx — RawSyscall
// ---------------------------------------------------------------------------

/// Linux `statx` — extended file status.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn statx(
    dirfd: c_int,
    pathname: *const c_char,
    flags: c_int,
    mask: c_uint,
    statxbuf: *mut c_void,
) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::IoFd, dirfd as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }

    let rc =
        unsafe { libc::syscall(libc::SYS_statx, dirfd, pathname, flags, mask, statxbuf) } as c_int;
    if rc < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(errno::ENOSYS);
        unsafe { set_abi_errno(e) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 8, true);
    } else {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 8, false);
    }
    rc
}

// ---------------------------------------------------------------------------
// fallocate — RawSyscall
// ---------------------------------------------------------------------------

/// Linux `fallocate` — allocate/deallocate file space.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fallocate(fd: c_int, mode: c_int, offset: i64, len: i64) -> c_int {
    let (_, decision) =
        runtime_policy::decide(ApiFamily::IoFd, fd as usize, len as usize, true, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }

    let rc = unsafe { libc::syscall(libc::SYS_fallocate, fd, mode, offset, len) } as c_int;
    if rc < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(errno::ENOSPC);
        unsafe { set_abi_errno(e) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, true);
    } else {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, false);
    }
    rc
}

// ---------------------------------------------------------------------------
// ftw / nftw — GlibcCallThrough
// ---------------------------------------------------------------------------

unsafe extern "C" {
    #[link_name = "ftw"]
    fn libc_ftw(
        dirpath: *const c_char,
        func: Option<unsafe extern "C" fn(*const c_char, *const libc::stat, c_int) -> c_int>,
        nopenfd: c_int,
    ) -> c_int;
    #[link_name = "nftw"]
    fn libc_nftw(
        dirpath: *const c_char,
        func: Option<
            unsafe extern "C" fn(*const c_char, *const libc::stat, c_int, *mut c_void) -> c_int,
        >,
        nopenfd: c_int,
        flags: c_int,
    ) -> c_int;
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ftw(
    dirpath: *const c_char,
    func: Option<unsafe extern "C" fn(*const c_char, *const libc::stat, c_int) -> c_int>,
    nopenfd: c_int,
) -> c_int {
    unsafe { libc_ftw(dirpath, func, nopenfd) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nftw(
    dirpath: *const c_char,
    func: Option<
        unsafe extern "C" fn(*const c_char, *const libc::stat, c_int, *mut c_void) -> c_int,
    >,
    nopenfd: c_int,
    flags: c_int,
) -> c_int {
    unsafe { libc_nftw(dirpath, func, nopenfd, flags) }
}

// ---------------------------------------------------------------------------
// sched_getaffinity / sched_setaffinity — RawSyscall
// ---------------------------------------------------------------------------

/// Linux `sched_getaffinity` — get CPU affinity mask.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sched_getaffinity(
    pid: libc::pid_t,
    cpusetsize: usize,
    mask: *mut c_void,
) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_sched_getaffinity, pid, cpusetsize, mask) } as c_int;
    if rc < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(errno::EINVAL);
        unsafe { set_abi_errno(e) };
    }
    rc
}

/// Linux `sched_setaffinity` — set CPU affinity mask.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sched_setaffinity(
    pid: libc::pid_t,
    cpusetsize: usize,
    mask: *const c_void,
) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_sched_setaffinity, pid, cpusetsize, mask) } as c_int;
    if rc < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(errno::EINVAL);
        unsafe { set_abi_errno(e) };
    }
    rc
}

// ---------------------------------------------------------------------------
// getentropy — implemented via SYS_getrandom
// ---------------------------------------------------------------------------

/// POSIX `getentropy` — fill buffer with random data (up to 256 bytes).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getentropy(buffer: *mut c_void, length: usize) -> c_int {
    if length > 256 {
        unsafe { set_abi_errno(libc::EIO) };
        return -1;
    }
    let rc = unsafe { libc::syscall(libc::SYS_getrandom, buffer, length, 0) };
    if rc < 0 || (rc as usize) < length {
        unsafe { set_abi_errno(libc::EIO) };
        -1
    } else {
        0
    }
}

// ---------------------------------------------------------------------------
// arc4random family — implemented via SYS_getrandom
// ---------------------------------------------------------------------------

/// BSD `arc4random` — return a random 32-bit value.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn arc4random() -> u32 {
    let mut val: u32 = 0;
    unsafe {
        libc::syscall(
            libc::SYS_getrandom,
            &mut val as *mut u32 as *mut c_void,
            4usize,
            0,
        );
    }
    val
}

/// BSD `arc4random_buf` — fill buffer with random bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn arc4random_buf(buf: *mut c_void, nbytes: usize) {
    unsafe {
        libc::syscall(libc::SYS_getrandom, buf, nbytes, 0);
    }
}

/// BSD `arc4random_uniform` — return a uniform random value less than `upper_bound`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn arc4random_uniform(upper_bound: u32) -> u32 {
    if upper_bound < 2 {
        return 0;
    }
    // Rejection sampling to avoid modulo bias.
    let min = upper_bound.wrapping_neg() % upper_bound;
    loop {
        let r = unsafe { arc4random() };
        if r >= min {
            return r % upper_bound;
        }
    }
}

// ---------------------------------------------------------------------------
// 64-bit file aliases
// ---------------------------------------------------------------------------
// On LP64 (x86_64), these are ABI aliases of the non-64 variants. Route to
// our own entrypoints to avoid recursive self-resolution through interposition.

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn open64(
    pathname: *const c_char,
    flags: c_int,
    mode: libc::mode_t,
) -> c_int {
    unsafe { open(pathname, flags, mode) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn creat64(pathname: *const c_char, mode: libc::mode_t) -> c_int {
    unsafe { creat(pathname, mode) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn stat64(path: *const c_char, buf: *mut c_void) -> c_int {
    unsafe { stat(path, buf.cast::<libc::stat>()) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fstat64(fd: c_int, buf: *mut c_void) -> c_int {
    unsafe { fstat(fd, buf.cast::<libc::stat>()) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lstat64(path: *const c_char, buf: *mut c_void) -> c_int {
    unsafe { lstat(path, buf.cast::<libc::stat>()) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fstatat64(
    dirfd: c_int,
    pathname: *const c_char,
    buf: *mut c_void,
    flags: c_int,
) -> c_int {
    unsafe { fstatat(dirfd, pathname, buf.cast::<libc::stat>(), flags) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lseek64(fd: c_int, offset: i64, whence: c_int) -> i64 {
    unsafe { lseek(fd, offset, whence) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn truncate64(path: *const c_char, length: i64) -> c_int {
    unsafe { truncate(path, length) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ftruncate64(fd: c_int, length: i64) -> c_int {
    unsafe { ftruncate(fd, length) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pread64(fd: c_int, buf: *mut c_void, count: usize, offset: i64) -> isize {
    unsafe { crate::io_abi::pread(fd, buf, count, offset) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pwrite64(
    fd: c_int,
    buf: *const c_void,
    count: usize,
    offset: i64,
) -> isize {
    unsafe { crate::io_abi::pwrite(fd, buf, count, offset) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mmap64(
    addr: *mut c_void,
    len: usize,
    prot: c_int,
    flags: c_int,
    fd: c_int,
    offset: i64,
) -> *mut c_void {
    unsafe { crate::mmap_abi::mmap(addr, len, prot, flags, fd, offset) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sendfile64(
    out_fd: c_int,
    in_fd: c_int,
    offset: *mut i64,
    count: usize,
) -> isize {
    unsafe { crate::io_abi::sendfile(out_fd, in_fd, offset, count) }
}

// ---------------------------------------------------------------------------
// POSIX shared memory — GlibcCallThrough
// ---------------------------------------------------------------------------

unsafe extern "C" {
    #[link_name = "shm_open"]
    fn libc_shm_open(name: *const c_char, oflag: c_int, mode: libc::mode_t) -> c_int;
    #[link_name = "shm_unlink"]
    fn libc_shm_unlink(name: *const c_char) -> c_int;
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn shm_open(name: *const c_char, oflag: c_int, mode: libc::mode_t) -> c_int {
    unsafe { libc_shm_open(name, oflag, mode) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn shm_unlink(name: *const c_char) -> c_int {
    unsafe { libc_shm_unlink(name) }
}

// ---------------------------------------------------------------------------
// POSIX semaphores — GlibcCallThrough
// ---------------------------------------------------------------------------

unsafe extern "C" {
    #[link_name = "sem_open"]
    fn libc_sem_open(name: *const c_char, oflag: c_int, ...) -> *mut c_void;
    #[link_name = "sem_close"]
    fn libc_sem_close(sem: *mut c_void) -> c_int;
    #[link_name = "sem_unlink"]
    fn libc_sem_unlink(name: *const c_char) -> c_int;
    #[link_name = "sem_wait"]
    fn libc_sem_wait(sem: *mut c_void) -> c_int;
    #[link_name = "sem_trywait"]
    fn libc_sem_trywait(sem: *mut c_void) -> c_int;
    #[link_name = "sem_timedwait"]
    fn libc_sem_timedwait(sem: *mut c_void, abs_timeout: *const libc::timespec) -> c_int;
    #[link_name = "sem_post"]
    fn libc_sem_post(sem: *mut c_void) -> c_int;
    #[link_name = "sem_getvalue"]
    fn libc_sem_getvalue(sem: *mut c_void, sval: *mut c_int) -> c_int;
    #[link_name = "sem_init"]
    fn libc_sem_init(sem: *mut c_void, pshared: c_int, value: c_uint) -> c_int;
    #[link_name = "sem_destroy"]
    fn libc_sem_destroy(sem: *mut c_void) -> c_int;
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sem_open(name: *const c_char, oflag: c_int, args: ...) -> *mut c_void {
    unsafe { libc_sem_open(name, oflag, args) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sem_close(sem: *mut c_void) -> c_int {
    unsafe { libc_sem_close(sem) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sem_unlink(name: *const c_char) -> c_int {
    unsafe { libc_sem_unlink(name) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sem_wait(sem: *mut c_void) -> c_int {
    unsafe { libc_sem_wait(sem) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sem_trywait(sem: *mut c_void) -> c_int {
    unsafe { libc_sem_trywait(sem) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sem_timedwait(
    sem: *mut c_void,
    abs_timeout: *const libc::timespec,
) -> c_int {
    unsafe { libc_sem_timedwait(sem, abs_timeout) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sem_post(sem: *mut c_void) -> c_int {
    unsafe { libc_sem_post(sem) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sem_getvalue(sem: *mut c_void, sval: *mut c_int) -> c_int {
    unsafe { libc_sem_getvalue(sem, sval) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sem_init(sem: *mut c_void, pshared: c_int, value: c_uint) -> c_int {
    unsafe { libc_sem_init(sem, pshared, value) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sem_destroy(sem: *mut c_void) -> c_int {
    unsafe { libc_sem_destroy(sem) }
}

// ---------------------------------------------------------------------------
// POSIX message queues — GlibcCallThrough
// ---------------------------------------------------------------------------

unsafe extern "C" {
    #[link_name = "mq_open"]
    fn libc_mq_open(name: *const c_char, oflag: c_int, ...) -> c_int;
    #[link_name = "mq_close"]
    fn libc_mq_close(mqdes: c_int) -> c_int;
    #[link_name = "mq_unlink"]
    fn libc_mq_unlink(name: *const c_char) -> c_int;
    #[link_name = "mq_send"]
    fn libc_mq_send(
        mqdes: c_int,
        msg_ptr: *const c_char,
        msg_len: usize,
        msg_prio: c_uint,
    ) -> c_int;
    #[link_name = "mq_receive"]
    fn libc_mq_receive(
        mqdes: c_int,
        msg_ptr: *mut c_char,
        msg_len: usize,
        msg_prio: *mut c_uint,
    ) -> isize;
    #[link_name = "mq_getattr"]
    fn libc_mq_getattr(mqdes: c_int, attr: *mut c_void) -> c_int;
    #[link_name = "mq_setattr"]
    fn libc_mq_setattr(mqdes: c_int, newattr: *const c_void, oldattr: *mut c_void) -> c_int;
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mq_open(name: *const c_char, oflag: c_int, args: ...) -> c_int {
    unsafe { libc_mq_open(name, oflag, args) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mq_close(mqdes: c_int) -> c_int {
    unsafe { libc_mq_close(mqdes) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mq_unlink(name: *const c_char) -> c_int {
    unsafe { libc_mq_unlink(name) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mq_send(
    mqdes: c_int,
    msg_ptr: *const c_char,
    msg_len: usize,
    msg_prio: c_uint,
) -> c_int {
    unsafe { libc_mq_send(mqdes, msg_ptr, msg_len, msg_prio) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mq_receive(
    mqdes: c_int,
    msg_ptr: *mut c_char,
    msg_len: usize,
    msg_prio: *mut c_uint,
) -> isize {
    unsafe { libc_mq_receive(mqdes, msg_ptr, msg_len, msg_prio) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mq_getattr(mqdes: c_int, attr: *mut c_void) -> c_int {
    unsafe { libc_mq_getattr(mqdes, attr) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mq_setattr(
    mqdes: c_int,
    newattr: *const c_void,
    oldattr: *mut c_void,
) -> c_int {
    unsafe { libc_mq_setattr(mqdes, newattr, oldattr) }
}

// ---------------------------------------------------------------------------
// Scheduler — GlibcCallThrough
// ---------------------------------------------------------------------------

unsafe extern "C" {
    #[link_name = "sched_getscheduler"]
    fn libc_sched_getscheduler(pid: libc::pid_t) -> c_int;
    #[link_name = "sched_setscheduler"]
    fn libc_sched_setscheduler(pid: libc::pid_t, policy: c_int, param: *const c_void) -> c_int;
    #[link_name = "sched_getparam"]
    fn libc_sched_getparam(pid: libc::pid_t, param: *mut c_void) -> c_int;
    #[link_name = "sched_setparam"]
    fn libc_sched_setparam(pid: libc::pid_t, param: *const c_void) -> c_int;
    #[link_name = "sched_get_priority_min"]
    fn libc_sched_get_priority_min(policy: c_int) -> c_int;
    #[link_name = "sched_get_priority_max"]
    fn libc_sched_get_priority_max(policy: c_int) -> c_int;
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sched_getscheduler(pid: libc::pid_t) -> c_int {
    unsafe { libc_sched_getscheduler(pid) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sched_setscheduler(
    pid: libc::pid_t,
    policy: c_int,
    param: *const c_void,
) -> c_int {
    unsafe { libc_sched_setscheduler(pid, policy, param) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sched_getparam(pid: libc::pid_t, param: *mut c_void) -> c_int {
    unsafe { libc_sched_getparam(pid, param) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sched_setparam(pid: libc::pid_t, param: *const c_void) -> c_int {
    unsafe { libc_sched_setparam(pid, param) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sched_get_priority_min(policy: c_int) -> c_int {
    unsafe { libc_sched_get_priority_min(policy) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sched_get_priority_max(policy: c_int) -> c_int {
    unsafe { libc_sched_get_priority_max(policy) }
}

// ---------------------------------------------------------------------------
// wordexp — GlibcCallThrough
// ---------------------------------------------------------------------------

unsafe extern "C" {
    #[link_name = "wordexp"]
    fn libc_wordexp(words: *const c_char, pwordexp: *mut c_void, flags: c_int) -> c_int;
    #[link_name = "wordfree"]
    fn libc_wordfree(pwordexp: *mut c_void);
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wordexp(
    words: *const c_char,
    pwordexp: *mut c_void,
    flags: c_int,
) -> c_int {
    unsafe { libc_wordexp(words, pwordexp, flags) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wordfree(pwordexp: *mut c_void) {
    unsafe { libc_wordfree(pwordexp) }
}

// ---------------------------------------------------------------------------
// Linux-specific syscalls — RawSyscall
// ---------------------------------------------------------------------------

/// Linux `signalfd4` — create a file descriptor for signals.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn signalfd(fd: c_int, mask: *const c_void, flags: c_int) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_signalfd4, fd, mask, 8usize, flags) } as c_int;
    if rc < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(errno::EINVAL);
        unsafe { set_abi_errno(e) };
    }
    rc
}

/// Linux `close_range` — close a range of file descriptors.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn close_range(first: c_uint, last: c_uint, flags: c_uint) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_close_range, first, last, flags) } as c_int;
    if rc < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(errno::EINVAL);
        unsafe { set_abi_errno(e) };
    }
    rc
}

/// Linux `pidfd_open` — obtain a file descriptor that refers to a process.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pidfd_open(pid: libc::pid_t, flags: c_uint) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, flags) } as c_int;
    if rc < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(errno::EINVAL);
        unsafe { set_abi_errno(e) };
    }
    rc
}

/// Linux `pidfd_send_signal` — send a signal via a process file descriptor.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pidfd_send_signal(
    pidfd: c_int,
    sig: c_int,
    info: *const c_void,
    flags: c_uint,
) -> c_int {
    let rc =
        unsafe { libc::syscall(libc::SYS_pidfd_send_signal, pidfd, sig, info, flags) } as c_int;
    if rc < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(errno::EINVAL);
        unsafe { set_abi_errno(e) };
    }
    rc
}

// ---------------------------------------------------------------------------
// Extended attributes — RawSyscall
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getxattr(
    path: *const c_char,
    name: *const c_char,
    value: *mut c_void,
    size: usize,
) -> isize {
    let rc = unsafe { libc::syscall(libc::SYS_getxattr, path, name, value, size) };
    if rc < 0 {
        unsafe {
            set_abi_errno(
                std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::ENOTSUP),
            )
        };
    }
    rc as isize
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setxattr(
    path: *const c_char,
    name: *const c_char,
    value: *const c_void,
    size: usize,
    flags: c_int,
) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_setxattr, path, name, value, size, flags) } as c_int;
    if rc < 0 {
        unsafe {
            set_abi_errno(
                std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::ENOTSUP),
            )
        };
    }
    rc
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn listxattr(path: *const c_char, list: *mut c_char, size: usize) -> isize {
    let rc = unsafe { libc::syscall(libc::SYS_listxattr, path, list, size) };
    if rc < 0 {
        unsafe {
            set_abi_errno(
                std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::ENOTSUP),
            )
        };
    }
    rc as isize
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn removexattr(path: *const c_char, name: *const c_char) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_removexattr, path, name) } as c_int;
    if rc < 0 {
        unsafe {
            set_abi_errno(
                std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::ENOTSUP),
            )
        };
    }
    rc
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fgetxattr(
    fd: c_int,
    name: *const c_char,
    value: *mut c_void,
    size: usize,
) -> isize {
    let rc = unsafe { libc::syscall(libc::SYS_fgetxattr, fd, name, value, size) };
    if rc < 0 {
        unsafe {
            set_abi_errno(
                std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::ENOTSUP),
            )
        };
    }
    rc as isize
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fsetxattr(
    fd: c_int,
    name: *const c_char,
    value: *const c_void,
    size: usize,
    flags: c_int,
) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_fsetxattr, fd, name, value, size, flags) } as c_int;
    if rc < 0 {
        unsafe {
            set_abi_errno(
                std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::ENOTSUP),
            )
        };
    }
    rc
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn flistxattr(fd: c_int, list: *mut c_char, size: usize) -> isize {
    let rc = unsafe { libc::syscall(libc::SYS_flistxattr, fd, list, size) };
    if rc < 0 {
        unsafe {
            set_abi_errno(
                std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::ENOTSUP),
            )
        };
    }
    rc as isize
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fremovexattr(fd: c_int, name: *const c_char) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_fremovexattr, fd, name) } as c_int;
    if rc < 0 {
        unsafe {
            set_abi_errno(
                std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::ENOTSUP),
            )
        };
    }
    rc
}

// ---------------------------------------------------------------------------
// Misc Linux syscalls — RawSyscall
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mincore(addr: *mut c_void, length: usize, vec: *mut u8) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_mincore, addr, length, vec) } as c_int;
    if rc < 0 {
        unsafe {
            set_abi_errno(
                std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(errno::ENOMEM),
            )
        };
    }
    rc
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn posix_fadvise(fd: c_int, offset: i64, len: i64, advice: c_int) -> c_int {
    unsafe { libc::syscall(libc::SYS_fadvise64, fd, offset, len, advice) as c_int }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn readahead(fd: c_int, offset: i64, count: usize) -> isize {
    let rc = unsafe { libc::syscall(libc::SYS_readahead, fd, offset, count) };
    if rc < 0 {
        unsafe {
            set_abi_errno(
                std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(errno::EBADF),
            )
        };
    }
    rc as isize
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn syncfs(fd: c_int) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_syncfs, fd) } as c_int;
    if rc < 0 {
        unsafe {
            set_abi_errno(
                std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(errno::EBADF),
            )
        };
    }
    rc
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sync() {
    unsafe { libc::syscall(libc::SYS_sync) };
}

// ---------------------------------------------------------------------------
// PTY / crypt / utmp — GlibcCallThrough
// ---------------------------------------------------------------------------

unsafe extern "C" {
    #[link_name = "openpty"]
    fn libc_openpty(
        amaster: *mut c_int,
        aslave: *mut c_int,
        name: *mut c_char,
        termp: *const c_void,
        winp: *const c_void,
    ) -> c_int;
    #[link_name = "login_tty"]
    fn libc_login_tty(fd: c_int) -> c_int;
    #[link_name = "forkpty"]
    fn libc_forkpty(
        amaster: *mut c_int,
        name: *mut c_char,
        termp: *const c_void,
        winp: *const c_void,
    ) -> libc::pid_t;
    #[link_name = "grantpt"]
    fn libc_grantpt(fd: c_int) -> c_int;
    #[link_name = "unlockpt"]
    fn libc_unlockpt(fd: c_int) -> c_int;
    #[link_name = "ptsname"]
    fn libc_ptsname(fd: c_int) -> *mut c_char;
    #[link_name = "posix_openpt"]
    fn libc_posix_openpt(flags: c_int) -> c_int;
    #[link_name = "crypt"]
    fn libc_crypt(key: *const c_char, salt: *const c_char) -> *mut c_char;
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn openpty(
    amaster: *mut c_int,
    aslave: *mut c_int,
    name: *mut c_char,
    termp: *const c_void,
    winp: *const c_void,
) -> c_int {
    unsafe { libc_openpty(amaster, aslave, name, termp, winp) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn login_tty(fd: c_int) -> c_int {
    unsafe { libc_login_tty(fd) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn forkpty(
    amaster: *mut c_int,
    name: *mut c_char,
    termp: *const c_void,
    winp: *const c_void,
) -> libc::pid_t {
    unsafe { libc_forkpty(amaster, name, termp, winp) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn grantpt(fd: c_int) -> c_int {
    unsafe { libc_grantpt(fd) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn unlockpt(fd: c_int) -> c_int {
    unsafe { libc_unlockpt(fd) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ptsname(fd: c_int) -> *mut c_char {
    unsafe { libc_ptsname(fd) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn posix_openpt(flags: c_int) -> c_int {
    unsafe { libc_posix_openpt(flags) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn crypt(key: *const c_char, salt: *const c_char) -> *mut c_char {
    unsafe { libc_crypt(key, salt) }
}

// ---------------------------------------------------------------------------
// Symlink-aware extended attributes — RawSyscall
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lgetxattr(
    path: *const c_char,
    name: *const c_char,
    value: *mut c_void,
    size: usize,
) -> isize {
    let rc = unsafe { libc::syscall(libc::SYS_lgetxattr, path, name, value, size) };
    if rc < 0 {
        unsafe {
            set_abi_errno(
                std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::ENOTSUP),
            )
        };
    }
    rc as isize
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lsetxattr(
    path: *const c_char,
    name: *const c_char,
    value: *const c_void,
    size: usize,
    flags: c_int,
) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_lsetxattr, path, name, value, size, flags) } as c_int;
    if rc < 0 {
        unsafe {
            set_abi_errno(
                std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::ENOTSUP),
            )
        };
    }
    rc
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn llistxattr(path: *const c_char, list: *mut c_char, size: usize) -> isize {
    let rc = unsafe { libc::syscall(libc::SYS_llistxattr, path, list, size) };
    if rc < 0 {
        unsafe {
            set_abi_errno(
                std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::ENOTSUP),
            )
        };
    }
    rc as isize
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lremovexattr(path: *const c_char, name: *const c_char) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_lremovexattr, path, name) } as c_int;
    if rc < 0 {
        unsafe {
            set_abi_errno(
                std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::ENOTSUP),
            )
        };
    }
    rc
}

// ---------------------------------------------------------------------------
// prlimit — RawSyscall
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn prlimit(
    pid: libc::pid_t,
    resource: c_int,
    new_limit: *const libc::rlimit,
    old_limit: *mut libc::rlimit,
) -> c_int {
    let rc =
        unsafe { libc::syscall(libc::SYS_prlimit64, pid, resource, new_limit, old_limit) } as c_int;
    if rc < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(errno::EINVAL);
        unsafe { set_abi_errno(e) };
    }
    rc
}

/// `prlimit64` alias — on LP64, identical to prlimit.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn prlimit64(
    pid: libc::pid_t,
    resource: c_int,
    new_limit: *const libc::rlimit,
    old_limit: *mut libc::rlimit,
) -> c_int {
    unsafe { prlimit(pid, resource, new_limit, old_limit) }
}

// ---------------------------------------------------------------------------
// GNU system info — GlibcCallThrough
// ---------------------------------------------------------------------------

unsafe extern "C" {
    #[link_name = "getutent"]
    fn libc_getutent() -> *mut c_void;
    #[link_name = "setutent"]
    fn libc_setutent();
    #[link_name = "endutent"]
    fn libc_endutent();
    #[link_name = "utmpname"]
    fn libc_utmpname(file: *const c_char) -> c_int;
}

#[inline]
fn normalized_nprocs(name: c_int) -> c_int {
    let value = unsafe { sysconf(name) };
    if value <= 0 || value > c_int::MAX as libc::c_long {
        1
    } else {
        value as c_int
    }
}

#[inline]
fn sysinfo_pages(free: bool) -> libc::c_long {
    let mut info = std::mem::MaybeUninit::<libc::sysinfo>::zeroed();
    let rc = unsafe { libc::syscall(libc::SYS_sysinfo, info.as_mut_ptr()) };
    if rc < 0 {
        return -1;
    }
    let info = unsafe { info.assume_init() };

    let page_size = unsafe { sysconf(libc::_SC_PAGESIZE) };
    if page_size <= 0 {
        return -1;
    }

    let mem_unit = if info.mem_unit == 0 {
        1_u128
    } else {
        info.mem_unit as u128
    };
    let ram = if free {
        info.freeram as u128
    } else {
        info.totalram as u128
    };
    let pages = ram.saturating_mul(mem_unit) / page_size as u128;
    pages.min(libc::c_long::MAX as u128) as libc::c_long
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn get_nprocs() -> c_int {
    normalized_nprocs(libc::_SC_NPROCESSORS_ONLN)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn get_nprocs_conf() -> c_int {
    normalized_nprocs(libc::_SC_NPROCESSORS_CONF)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn get_phys_pages() -> std::ffi::c_long {
    sysinfo_pages(false)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn get_avphys_pages() -> std::ffi::c_long {
    sysinfo_pages(true)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getutent() -> *mut c_void {
    unsafe { libc_getutent() }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setutent() {
    unsafe { libc_setutent() }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn endutent() {
    unsafe { libc_endutent() }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn utmpname(file: *const c_char) -> c_int {
    unsafe { libc_utmpname(file) }
}

// ---------------------------------------------------------------------------
// eventfd_read / eventfd_write — Implemented
// ---------------------------------------------------------------------------

/// `eventfd_read` — read an eventfd counter.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn eventfd_read(fd: c_int, value: *mut u64) -> c_int {
    let rc = unsafe { syscall::sys_read(fd, value as *mut u8, 8) };
    match rc {
        Ok(8) => 0,
        _ => {
            unsafe { set_abi_errno(errno::EIO) };
            -1
        }
    }
}

/// `eventfd_write` — write to an eventfd counter.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn eventfd_write(fd: c_int, value: u64) -> c_int {
    let buf = value.to_ne_bytes();
    let rc = unsafe { syscall::sys_write(fd, buf.as_ptr(), 8) };
    match rc {
        Ok(8) => 0,
        _ => {
            unsafe { set_abi_errno(errno::EIO) };
            -1
        }
    }
}

// ---------------------------------------------------------------------------
// lockf / posix_fallocate / posix_madvise — RawSyscall
// ---------------------------------------------------------------------------

const LOCKF_ULOCK: c_int = 0;
const LOCKF_LOCK: c_int = 1;
const LOCKF_TLOCK: c_int = 2;
const LOCKF_TEST: c_int = 3;

/// `lockf` — apply, test or remove a POSIX lock on a file section.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lockf(fd: c_int, cmd: c_int, len: libc::off_t) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::IoFd, fd as usize, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(libc::EPERM) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, true);
        return -1;
    }

    let start = match syscall::sys_lseek(fd, 0, unistd_core::SEEK_CUR) {
        Ok(pos) => pos,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, true);
            return -1;
        }
    };

    let mut lock: libc::flock = unsafe { std::mem::zeroed() };
    lock.l_whence = libc::SEEK_SET as libc::c_short;
    lock.l_start = start as libc::off_t;
    lock.l_len = len;

    let rc = match cmd {
        LOCKF_ULOCK => {
            lock.l_type = libc::F_UNLCK as libc::c_short;
            unsafe { syscall::sys_fcntl(fd, libc::F_SETLK, (&lock as *const libc::flock) as usize) }
        }
        LOCKF_LOCK => {
            lock.l_type = libc::F_WRLCK as libc::c_short;
            unsafe {
                syscall::sys_fcntl(fd, libc::F_SETLKW, (&lock as *const libc::flock) as usize)
            }
        }
        LOCKF_TLOCK => {
            lock.l_type = libc::F_WRLCK as libc::c_short;
            unsafe { syscall::sys_fcntl(fd, libc::F_SETLK, (&lock as *const libc::flock) as usize) }
        }
        LOCKF_TEST => {
            lock.l_type = libc::F_WRLCK as libc::c_short;
            match unsafe {
                syscall::sys_fcntl(fd, libc::F_GETLK, (&mut lock as *mut libc::flock) as usize)
            } {
                Ok(_) => {
                    if lock.l_type == libc::F_UNLCK as libc::c_short
                        || lock.l_pid == syscall::sys_getpid()
                    {
                        Ok(0)
                    } else {
                        Err(libc::EACCES)
                    }
                }
                Err(e) => Err(e),
            }
        }
        _ => Err(libc::EINVAL),
    };

    let failed = rc.is_err();
    let out = match rc {
        Ok(_) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    };
    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 12, failed);
    out
}

/// `posix_fallocate` — allocate file space.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn posix_fallocate(
    fd: c_int,
    offset: libc::off_t,
    len: libc::off_t,
) -> c_int {
    if offset < 0 || len < 0 {
        return libc::EINVAL;
    }

    let (_, decision) =
        runtime_policy::decide(ApiFamily::IoFd, fd as usize, len as usize, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 12, true);
        return libc::EPERM;
    }

    let rc = match syscall::sys_fallocate(fd, 0, offset, len) {
        Ok(()) => 0,
        Err(e) => e,
    };
    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 12, rc != 0);
    rc
}

/// `posix_madvise` — POSIX advisory information on memory usage.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn posix_madvise(addr: *mut c_void, len: usize, advice: c_int) -> c_int {
    let (_, decision) = runtime_policy::decide(
        ApiFamily::IoFd,
        addr as usize,
        len,
        false,
        addr.is_null() && len > 0,
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 8, true);
        return libc::EPERM;
    }

    let rc = match unsafe { syscall::sys_madvise(addr.cast(), len, advice) } {
        Ok(()) => 0,
        Err(e) => e,
    };
    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 8, rc != 0);
    rc
}

// ---------------------------------------------------------------------------
// SysV IPC — GlibcCallThrough (shmget, shmctl, shmat, shmdt,
//                                semget, semctl, semop,
//                                msgget, msgctl, msgsnd, msgrcv)
// ---------------------------------------------------------------------------

unsafe extern "C" {
    #[link_name = "shmget"]
    fn libc_shmget(key: c_int, size: usize, shmflg: c_int) -> c_int;
    #[link_name = "shmctl"]
    fn libc_shmctl(shmid: c_int, cmd: c_int, buf: *mut c_void) -> c_int;
    #[link_name = "shmat"]
    fn libc_shmat(shmid: c_int, shmaddr: *const c_void, shmflg: c_int) -> *mut c_void;
    #[link_name = "shmdt"]
    fn libc_shmdt(shmaddr: *const c_void) -> c_int;
    #[link_name = "semget"]
    fn libc_semget(key: c_int, nsems: c_int, semflg: c_int) -> c_int;
    #[link_name = "semctl"]
    fn libc_semctl(semid: c_int, semnum: c_int, cmd: c_int, ...) -> c_int;
    #[link_name = "semop"]
    fn libc_semop(semid: c_int, sops: *mut c_void, nsops: usize) -> c_int;
    #[link_name = "msgget"]
    fn libc_msgget(key: c_int, msgflg: c_int) -> c_int;
    #[link_name = "msgctl"]
    fn libc_msgctl(msqid: c_int, cmd: c_int, buf: *mut c_void) -> c_int;
    #[link_name = "msgsnd"]
    fn libc_msgsnd(msqid: c_int, msgp: *const c_void, msgsz: usize, msgflg: c_int) -> c_int;
    #[link_name = "msgrcv"]
    fn libc_msgrcv(
        msqid: c_int,
        msgp: *mut c_void,
        msgsz: usize,
        msgtyp: std::ffi::c_long,
        msgflg: c_int,
    ) -> libc::ssize_t;
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn shmget(key: c_int, size: usize, shmflg: c_int) -> c_int {
    unsafe { libc_shmget(key, size, shmflg) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn shmctl(shmid: c_int, cmd: c_int, buf: *mut c_void) -> c_int {
    unsafe { libc_shmctl(shmid, cmd, buf) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn shmat(shmid: c_int, shmaddr: *const c_void, shmflg: c_int) -> *mut c_void {
    unsafe { libc_shmat(shmid, shmaddr, shmflg) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn shmdt(shmaddr: *const c_void) -> c_int {
    unsafe { libc_shmdt(shmaddr) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn semget(key: c_int, nsems: c_int, semflg: c_int) -> c_int {
    unsafe { libc_semget(key, nsems, semflg) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn semctl(semid: c_int, semnum: c_int, cmd: c_int, args: ...) -> c_int {
    unsafe { libc_semctl(semid, semnum, cmd, args) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn semop(semid: c_int, sops: *mut c_void, nsops: usize) -> c_int {
    unsafe { libc_semop(semid, sops, nsops) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn msgget(key: c_int, msgflg: c_int) -> c_int {
    unsafe { libc_msgget(key, msgflg) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn msgctl(msqid: c_int, cmd: c_int, buf: *mut c_void) -> c_int {
    unsafe { libc_msgctl(msqid, cmd, buf) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn msgsnd(
    msqid: c_int,
    msgp: *const c_void,
    msgsz: usize,
    msgflg: c_int,
) -> c_int {
    unsafe { libc_msgsnd(msqid, msgp, msgsz, msgflg) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn msgrcv(
    msqid: c_int,
    msgp: *mut c_void,
    msgsz: usize,
    msgtyp: std::ffi::c_long,
    msgflg: c_int,
) -> libc::ssize_t {
    unsafe { libc_msgrcv(msqid, msgp, msgsz, msgtyp, msgflg) }
}

// ---------------------------------------------------------------------------
// Signal extras — RawSyscall / GlibcCallThrough
// ---------------------------------------------------------------------------

unsafe extern "C" {
    #[link_name = "sigqueue"]
    fn libc_sigqueue(pid: libc::pid_t, sig: c_int, value: *const c_void) -> c_int;
    #[link_name = "sigtimedwait"]
    fn libc_sigtimedwait(
        set: *const c_void,
        info: *mut c_void,
        timeout: *const libc::timespec,
    ) -> c_int;
    #[link_name = "sigwaitinfo"]
    fn libc_sigwaitinfo(set: *const c_void, info: *mut c_void) -> c_int;
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sigqueue(pid: libc::pid_t, sig: c_int, value: *const c_void) -> c_int {
    unsafe { libc_sigqueue(pid, sig, value) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sigtimedwait(
    set: *const c_void,
    info: *mut c_void,
    timeout: *const libc::timespec,
) -> c_int {
    unsafe { libc_sigtimedwait(set, info, timeout) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sigwaitinfo(set: *const c_void, info: *mut c_void) -> c_int {
    unsafe { libc_sigwaitinfo(set, info) }
}

// ---------------------------------------------------------------------------
// getifaddrs / freeifaddrs — GlibcCallThrough
// ---------------------------------------------------------------------------

unsafe extern "C" {
    #[link_name = "getifaddrs"]
    fn libc_getifaddrs(ifap: *mut *mut c_void) -> c_int;
    #[link_name = "freeifaddrs"]
    fn libc_freeifaddrs(ifa: *mut c_void);
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getifaddrs(ifap: *mut *mut c_void) -> c_int {
    unsafe { libc_getifaddrs(ifap) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn freeifaddrs(ifa: *mut c_void) {
    unsafe { libc_freeifaddrs(ifa) }
}

// ---------------------------------------------------------------------------
// ether_aton / ether_ntoa — GlibcCallThrough
// ---------------------------------------------------------------------------

unsafe extern "C" {
    #[link_name = "ether_aton"]
    fn libc_ether_aton(asc: *const c_char) -> *mut c_void;
    #[link_name = "ether_ntoa"]
    fn libc_ether_ntoa(addr: *const c_void) -> *mut c_char;
    #[link_name = "ether_aton_r"]
    fn libc_ether_aton_r(asc: *const c_char, addr: *mut c_void) -> *mut c_void;
    #[link_name = "ether_ntoa_r"]
    fn libc_ether_ntoa_r(addr: *const c_void, buf: *mut c_char) -> *mut c_char;
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ether_aton(asc: *const c_char) -> *mut c_void {
    unsafe { libc_ether_aton(asc) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ether_ntoa(addr: *const c_void) -> *mut c_char {
    unsafe { libc_ether_ntoa(addr) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ether_aton_r(asc: *const c_char, addr: *mut c_void) -> *mut c_void {
    unsafe { libc_ether_aton_r(asc, addr) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ether_ntoa_r(addr: *const c_void, buf: *mut c_char) -> *mut c_char {
    unsafe { libc_ether_ntoa_r(addr, buf) }
}

// ---------------------------------------------------------------------------
// herror / hstrerror — GlibcCallThrough
// ---------------------------------------------------------------------------

unsafe extern "C" {
    #[link_name = "herror"]
    fn libc_herror(s: *const c_char);
    #[link_name = "hstrerror"]
    fn libc_hstrerror(err: c_int) -> *const c_char;
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn herror(s: *const c_char) {
    unsafe { libc_herror(s) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn hstrerror(err: c_int) -> *const c_char {
    unsafe { libc_hstrerror(err) }
}

// ---------------------------------------------------------------------------
// execl / execlp / execle — GlibcCallThrough (variadic)
// ---------------------------------------------------------------------------

unsafe extern "C" {
    #[link_name = "execl"]
    fn libc_execl(path: *const c_char, arg: *const c_char, ...) -> c_int;
    #[link_name = "execlp"]
    fn libc_execlp(file: *const c_char, arg: *const c_char, ...) -> c_int;
    #[link_name = "execle"]
    fn libc_execle(path: *const c_char, arg: *const c_char, ...) -> c_int;
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn execl(path: *const c_char, arg: *const c_char, args: ...) -> c_int {
    unsafe { libc_execl(path, arg, args) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn execlp(file: *const c_char, arg: *const c_char, args: ...) -> c_int {
    unsafe { libc_execlp(file, arg, args) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn execle(path: *const c_char, arg: *const c_char, args: ...) -> c_int {
    unsafe { libc_execle(path, arg, args) }
}

// ---------------------------------------------------------------------------
// timer_* — GlibcCallThrough (POSIX per-process timers)
// ---------------------------------------------------------------------------

unsafe extern "C" {
    #[link_name = "timer_create"]
    fn libc_timer_create(
        clockid: libc::clockid_t,
        sevp: *mut c_void,
        timerid: *mut c_void,
    ) -> c_int;
    #[link_name = "timer_settime"]
    fn libc_timer_settime(
        timerid: *mut c_void,
        flags: c_int,
        new_value: *const c_void,
        old_value: *mut c_void,
    ) -> c_int;
    #[link_name = "timer_gettime"]
    fn libc_timer_gettime(timerid: *mut c_void, curr_value: *mut c_void) -> c_int;
    #[link_name = "timer_delete"]
    fn libc_timer_delete(timerid: *mut c_void) -> c_int;
    #[link_name = "timer_getoverrun"]
    fn libc_timer_getoverrun(timerid: *mut c_void) -> c_int;
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn timer_create(
    clockid: libc::clockid_t,
    sevp: *mut c_void,
    timerid: *mut c_void,
) -> c_int {
    unsafe { libc_timer_create(clockid, sevp, timerid) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn timer_settime(
    timerid: *mut c_void,
    flags: c_int,
    new_value: *const c_void,
    old_value: *mut c_void,
) -> c_int {
    unsafe { libc_timer_settime(timerid, flags, new_value, old_value) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn timer_gettime(timerid: *mut c_void, curr_value: *mut c_void) -> c_int {
    unsafe { libc_timer_gettime(timerid, curr_value) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn timer_delete(timerid: *mut c_void) -> c_int {
    unsafe { libc_timer_delete(timerid) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn timer_getoverrun(timerid: *mut c_void) -> c_int {
    unsafe { libc_timer_getoverrun(timerid) }
}

// ---------------------------------------------------------------------------
// aio_* — GlibcCallThrough (POSIX async I/O)
// ---------------------------------------------------------------------------

unsafe extern "C" {
    #[link_name = "aio_read"]
    fn libc_aio_read(aiocbp: *mut c_void) -> c_int;
    #[link_name = "aio_write"]
    fn libc_aio_write(aiocbp: *mut c_void) -> c_int;
    #[link_name = "aio_error"]
    fn libc_aio_error(aiocbp: *const c_void) -> c_int;
    #[link_name = "aio_return"]
    fn libc_aio_return(aiocbp: *mut c_void) -> libc::ssize_t;
    #[link_name = "aio_cancel"]
    fn libc_aio_cancel(fd: c_int, aiocbp: *mut c_void) -> c_int;
    #[link_name = "aio_suspend"]
    fn libc_aio_suspend(
        list: *const *const c_void,
        nent: c_int,
        timeout: *const libc::timespec,
    ) -> c_int;
    #[link_name = "aio_fsync"]
    fn libc_aio_fsync(op: c_int, aiocbp: *mut c_void) -> c_int;
    #[link_name = "lio_listio"]
    fn libc_lio_listio(
        mode: c_int,
        list: *const *mut c_void,
        nent: c_int,
        sevp: *mut c_void,
    ) -> c_int;
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn aio_read(aiocbp: *mut c_void) -> c_int {
    unsafe { libc_aio_read(aiocbp) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn aio_write(aiocbp: *mut c_void) -> c_int {
    unsafe { libc_aio_write(aiocbp) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn aio_error(aiocbp: *const c_void) -> c_int {
    unsafe { libc_aio_error(aiocbp) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn aio_return(aiocbp: *mut c_void) -> libc::ssize_t {
    unsafe { libc_aio_return(aiocbp) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn aio_cancel(fd: c_int, aiocbp: *mut c_void) -> c_int {
    unsafe { libc_aio_cancel(fd, aiocbp) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn aio_suspend(
    list: *const *const c_void,
    nent: c_int,
    timeout: *const libc::timespec,
) -> c_int {
    unsafe { libc_aio_suspend(list, nent, timeout) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn aio_fsync(op: c_int, aiocbp: *mut c_void) -> c_int {
    unsafe { libc_aio_fsync(op, aiocbp) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lio_listio(
    mode: c_int,
    list: *const *mut c_void,
    nent: c_int,
    sevp: *mut c_void,
) -> c_int {
    unsafe { libc_lio_listio(mode, list, nent, sevp) }
}

// ---------------------------------------------------------------------------
// mount table — GlibcCallThrough
// ---------------------------------------------------------------------------

unsafe extern "C" {
    #[link_name = "setmntent"]
    fn libc_setmntent(filename: *const c_char, type_: *const c_char) -> *mut c_void;
    #[link_name = "getmntent"]
    fn libc_getmntent(stream: *mut c_void) -> *mut c_void;
    #[link_name = "endmntent"]
    fn libc_endmntent(stream: *mut c_void) -> c_int;
    #[link_name = "hasmntopt"]
    fn libc_hasmntopt(mnt: *const c_void, opt: *const c_char) -> *mut c_char;
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setmntent(filename: *const c_char, type_: *const c_char) -> *mut c_void {
    unsafe { libc_setmntent(filename, type_) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getmntent(stream: *mut c_void) -> *mut c_void {
    unsafe { libc_getmntent(stream) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn endmntent(stream: *mut c_void) -> c_int {
    unsafe { libc_endmntent(stream) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn hasmntopt(mnt: *const c_void, opt: *const c_char) -> *mut c_char {
    unsafe { libc_hasmntopt(mnt, opt) }
}

// ---------------------------------------------------------------------------
// sendmmsg / recvmmsg — RawSyscall
// ---------------------------------------------------------------------------

/// `sendmmsg` — send multiple messages on a socket.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sendmmsg(
    sockfd: c_int,
    msgvec: *mut c_void,
    vlen: c_uint,
    flags: c_int,
) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_sendmmsg, sockfd, msgvec, vlen, flags) } as c_int;
    if rc < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::ENOTSUP);
        unsafe { set_abi_errno(e) };
    }
    rc
}

/// `recvmmsg` — receive multiple messages on a socket.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn recvmmsg(
    sockfd: c_int,
    msgvec: *mut c_void,
    vlen: c_uint,
    flags: c_int,
    timeout: *mut libc::timespec,
) -> c_int {
    let rc =
        unsafe { libc::syscall(libc::SYS_recvmmsg, sockfd, msgvec, vlen, flags, timeout) } as c_int;
    if rc < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::ENOTSUP);
        unsafe { set_abi_errno(e) };
    }
    rc
}

// ---------------------------------------------------------------------------
// sched_rr_get_interval / sched_getaffinity CPU_COUNT helper
// ---------------------------------------------------------------------------

unsafe extern "C" {
    #[link_name = "sched_rr_get_interval"]
    fn libc_sched_rr_get_interval(pid: libc::pid_t, tp: *mut libc::timespec) -> c_int;
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sched_rr_get_interval(pid: libc::pid_t, tp: *mut libc::timespec) -> c_int {
    unsafe { libc_sched_rr_get_interval(pid, tp) }
}

// ---------------------------------------------------------------------------
// res_init / res_query / res_search — GlibcCallThrough (resolver)
// ---------------------------------------------------------------------------

unsafe extern "C" {
    #[link_name = "__res_init"]
    fn libc_res_init() -> c_int;
    #[link_name = "res_query"]
    fn libc_res_query(
        dname: *const c_char,
        class: c_int,
        type_: c_int,
        answer: *mut u8,
        anslen: c_int,
    ) -> c_int;
    #[link_name = "res_search"]
    fn libc_res_search(
        dname: *const c_char,
        class: c_int,
        type_: c_int,
        answer: *mut u8,
        anslen: c_int,
    ) -> c_int;
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn res_init() -> c_int {
    unsafe { libc_res_init() }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn res_query(
    dname: *const c_char,
    class: c_int,
    type_: c_int,
    answer: *mut u8,
    anslen: c_int,
) -> c_int {
    unsafe { libc_res_query(dname, class, type_, answer, anslen) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn res_search(
    dname: *const c_char,
    class: c_int,
    type_: c_int,
    answer: *mut u8,
    anslen: c_int,
) -> c_int {
    unsafe { libc_res_search(dname, class, type_, answer, anslen) }
}

// ---------------------------------------------------------------------------
// _r variants for passwd/group — GlibcCallThrough
// ---------------------------------------------------------------------------

unsafe extern "C" {
    #[link_name = "getpwent_r"]
    fn libc_getpwent_r(
        pwd: *mut c_void,
        buf: *mut c_char,
        buflen: usize,
        result: *mut *mut c_void,
    ) -> c_int;
    #[link_name = "getgrent_r"]
    fn libc_getgrent_r(
        grp: *mut c_void,
        buf: *mut c_char,
        buflen: usize,
        result: *mut *mut c_void,
    ) -> c_int;
    #[link_name = "fgetpwent"]
    fn libc_fgetpwent(stream: *mut c_void) -> *mut c_void;
    #[link_name = "fgetgrent"]
    fn libc_fgetgrent(stream: *mut c_void) -> *mut c_void;
    #[link_name = "getgrouplist"]
    fn libc_getgrouplist(
        user: *const c_char,
        group: libc::gid_t,
        groups: *mut libc::gid_t,
        ngroups: *mut c_int,
    ) -> c_int;
    #[link_name = "initgroups"]
    fn libc_initgroups(user: *const c_char, group: libc::gid_t) -> c_int;
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getpwent_r(
    pwd: *mut c_void,
    buf: *mut c_char,
    buflen: usize,
    result: *mut *mut c_void,
) -> c_int {
    unsafe { libc_getpwent_r(pwd, buf, buflen, result) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getgrent_r(
    grp: *mut c_void,
    buf: *mut c_char,
    buflen: usize,
    result: *mut *mut c_void,
) -> c_int {
    unsafe { libc_getgrent_r(grp, buf, buflen, result) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fgetpwent(stream: *mut c_void) -> *mut c_void {
    unsafe { libc_fgetpwent(stream) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fgetgrent(stream: *mut c_void) -> *mut c_void {
    unsafe { libc_fgetgrent(stream) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getgrouplist(
    user: *const c_char,
    group: libc::gid_t,
    groups: *mut libc::gid_t,
    ngroups: *mut c_int,
) -> c_int {
    unsafe { libc_getgrouplist(user, group, groups, ngroups) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn initgroups(user: *const c_char, group: libc::gid_t) -> c_int {
    unsafe { libc_initgroups(user, group) }
}

// ---------------------------------------------------------------------------
// Misc POSIX extras — GlibcCallThrough / RawSyscall
// ---------------------------------------------------------------------------

unsafe extern "C" {
    #[link_name = "getlogin"]
    fn libc_getlogin() -> *mut c_char;
    #[link_name = "getlogin_r"]
    fn libc_getlogin_r(buf: *mut c_char, bufsize: usize) -> c_int;
    #[link_name = "ttyname"]
    fn libc_ttyname(fd: c_int) -> *mut c_char;
    #[link_name = "ttyname_r"]
    fn libc_ttyname_r(fd: c_int, buf: *mut c_char, buflen: usize) -> c_int;
    #[link_name = "getpass"]
    fn libc_getpass(prompt: *const c_char) -> *mut c_char;
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getlogin() -> *mut c_char {
    unsafe { libc_getlogin() }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getlogin_r(buf: *mut c_char, bufsize: usize) -> c_int {
    unsafe { libc_getlogin_r(buf, bufsize) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ttyname(fd: c_int) -> *mut c_char {
    unsafe { libc_ttyname(fd) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ttyname_r(fd: c_int, buf: *mut c_char, buflen: usize) -> c_int {
    unsafe { libc_ttyname_r(fd, buf, buflen) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ctermid(s: *mut c_char) -> *mut c_char {
    let dst = if s.is_null() {
        std::ptr::addr_of_mut!(CTERMID_FALLBACK).cast::<c_char>()
    } else {
        s
    };
    unsafe {
        std::ptr::copy_nonoverlapping(
            CTERMID_PATH.as_ptr().cast::<c_char>(),
            dst,
            CTERMID_PATH.len(),
        );
    }
    dst
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getpass(prompt: *const c_char) -> *mut c_char {
    unsafe { libc_getpass(prompt) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sethostname(name: *const c_char, len: usize) -> c_int {
    let (_, decision) = runtime_policy::decide(
        ApiFamily::Process,
        name as usize,
        len,
        false,
        name.is_null() && len > 0,
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EPERM) };
        runtime_policy::observe(
            ApiFamily::Process,
            decision.profile,
            runtime_policy::scaled_cost(8, len),
            true,
        );
        return -1;
    }
    if name.is_null() && len > 0 {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(
            ApiFamily::Process,
            decision.profile,
            runtime_policy::scaled_cost(8, len),
            true,
        );
        return -1;
    }
    let rc = unsafe {
        syscall_ret_int(
            libc::syscall(libc::SYS_sethostname, name, len),
            errno::EPERM,
        )
    };
    runtime_policy::observe(
        ApiFamily::Process,
        decision.profile,
        runtime_policy::scaled_cost(8, len),
        rc != 0,
    );
    rc
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setdomainname(name: *const c_char, len: usize) -> c_int {
    let (_, decision) = runtime_policy::decide(
        ApiFamily::Process,
        name as usize,
        len,
        false,
        name.is_null() && len > 0,
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EPERM) };
        runtime_policy::observe(
            ApiFamily::Process,
            decision.profile,
            runtime_policy::scaled_cost(8, len),
            true,
        );
        return -1;
    }
    if name.is_null() && len > 0 {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(
            ApiFamily::Process,
            decision.profile,
            runtime_policy::scaled_cost(8, len),
            true,
        );
        return -1;
    }
    let rc = unsafe {
        syscall_ret_int(
            libc::syscall(libc::SYS_setdomainname, name, len),
            errno::EPERM,
        )
    };
    runtime_policy::observe(
        ApiFamily::Process,
        decision.profile,
        runtime_policy::scaled_cost(8, len),
        rc != 0,
    );
    rc
}

// ---------------------------------------------------------------------------
// Linux namespace / mount / security — RawSyscall
// ---------------------------------------------------------------------------

/// `setns` — reassociate thread with a namespace.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setns(fd: c_int, nstype: c_int) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_setns, fd, nstype) } as c_int;
    if rc < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::ENOTSUP);
        unsafe { set_abi_errno(e) };
    }
    rc
}

/// `unshare` — disassociate parts of process execution context.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn unshare(flags: c_int) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_unshare, flags) } as c_int;
    if rc < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::ENOTSUP);
        unsafe { set_abi_errno(e) };
    }
    rc
}

/// `mount` — mount a filesystem.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mount(
    source: *const c_char,
    target: *const c_char,
    filesystemtype: *const c_char,
    mountflags: std::ffi::c_ulong,
    data: *const c_void,
) -> c_int {
    let rc = unsafe {
        libc::syscall(
            libc::SYS_mount,
            source,
            target,
            filesystemtype,
            mountflags,
            data,
        )
    } as c_int;
    if rc < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::ENOTSUP);
        unsafe { set_abi_errno(e) };
    }
    rc
}

/// `umount2` — unmount a filesystem with flags.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn umount2(target: *const c_char, flags: c_int) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_umount2, target, flags) } as c_int;
    if rc < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::ENOTSUP);
        unsafe { set_abi_errno(e) };
    }
    rc
}

/// `chroot` — change root directory.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn chroot(path: *const c_char) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_chroot, path) } as c_int;
    if rc < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::ENOTSUP);
        unsafe { set_abi_errno(e) };
    }
    rc
}

/// `pivot_root` — change the root filesystem.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pivot_root(new_root: *const c_char, put_old: *const c_char) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_pivot_root, new_root, put_old) } as c_int;
    if rc < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::ENOTSUP);
        unsafe { set_abi_errno(e) };
    }
    rc
}

/// `acct` — process accounting.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn acct(filename: *const c_char) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_acct, filename) } as c_int;
    if rc < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::ENOTSUP);
        unsafe { set_abi_errno(e) };
    }
    rc
}

/// `reboot` — reboot or enable/disable Ctrl-Alt-Del.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn reboot(cmd: c_int) -> c_int {
    let rc =
        unsafe { libc::syscall(libc::SYS_reboot, 0xfee1dead_u64, 672274793_u64, cmd) } as c_int;
    if rc < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::ENOTSUP);
        unsafe { set_abi_errno(e) };
    }
    rc
}

/// `swapon` — start swapping.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn swapon(path: *const c_char, swapflags: c_int) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_swapon, path, swapflags) } as c_int;
    if rc < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::ENOTSUP);
        unsafe { set_abi_errno(e) };
    }
    rc
}

/// `swapoff` — stop swapping.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn swapoff(path: *const c_char) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_swapoff, path) } as c_int;
    if rc < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::ENOTSUP);
        unsafe { set_abi_errno(e) };
    }
    rc
}

// ---------------------------------------------------------------------------
// UID/GID extras — RawSyscall
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getresuid(
    ruid: *mut libc::uid_t,
    euid: *mut libc::uid_t,
    suid: *mut libc::uid_t,
) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_getresuid, ruid, euid, suid) } as c_int;
    if rc < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::ENOTSUP);
        unsafe { set_abi_errno(e) };
    }
    rc
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getresgid(
    rgid: *mut libc::gid_t,
    egid: *mut libc::gid_t,
    sgid: *mut libc::gid_t,
) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_getresgid, rgid, egid, sgid) } as c_int;
    if rc < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::ENOTSUP);
        unsafe { set_abi_errno(e) };
    }
    rc
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setresuid(
    ruid: libc::uid_t,
    euid: libc::uid_t,
    suid: libc::uid_t,
) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_setresuid, ruid, euid, suid) } as c_int;
    if rc < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::ENOTSUP);
        unsafe { set_abi_errno(e) };
    }
    rc
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setresgid(
    rgid: libc::gid_t,
    egid: libc::gid_t,
    sgid: libc::gid_t,
) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_setresgid, rgid, egid, sgid) } as c_int;
    if rc < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::ENOTSUP);
        unsafe { set_abi_errno(e) };
    }
    rc
}

// ---------------------------------------------------------------------------
// fanotify — RawSyscall
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fanotify_init(flags: c_uint, event_f_flags: c_uint) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_fanotify_init, flags, event_f_flags) } as c_int;
    if rc < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::ENOTSUP);
        unsafe { set_abi_errno(e) };
    }
    rc
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fanotify_mark(
    fanotify_fd: c_int,
    flags: c_uint,
    mask: u64,
    dirfd: c_int,
    pathname: *const c_char,
) -> c_int {
    let rc = unsafe {
        libc::syscall(
            libc::SYS_fanotify_mark,
            fanotify_fd,
            flags,
            mask,
            dirfd,
            pathname,
        )
    } as c_int;
    if rc < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::ENOTSUP);
        unsafe { set_abi_errno(e) };
    }
    rc
}

// ---------------------------------------------------------------------------
// process_vm — RawSyscall
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn process_vm_readv(
    pid: libc::pid_t,
    local_iov: *const libc::iovec,
    liovcnt: std::ffi::c_ulong,
    remote_iov: *const libc::iovec,
    riovcnt: std::ffi::c_ulong,
    flags: std::ffi::c_ulong,
) -> isize {
    let rc = unsafe {
        libc::syscall(
            libc::SYS_process_vm_readv,
            pid,
            local_iov,
            liovcnt,
            remote_iov,
            riovcnt,
            flags,
        )
    };
    if rc < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::ENOTSUP);
        unsafe { set_abi_errno(e) };
    }
    rc as isize
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn process_vm_writev(
    pid: libc::pid_t,
    local_iov: *const libc::iovec,
    liovcnt: std::ffi::c_ulong,
    remote_iov: *const libc::iovec,
    riovcnt: std::ffi::c_ulong,
    flags: std::ffi::c_ulong,
) -> isize {
    let rc = unsafe {
        libc::syscall(
            libc::SYS_process_vm_writev,
            pid,
            local_iov,
            liovcnt,
            remote_iov,
            riovcnt,
            flags,
        )
    };
    if rc < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::ENOTSUP);
        unsafe { set_abi_errno(e) };
    }
    rc as isize
}

// ---------------------------------------------------------------------------
// mlock2, name_to_handle_at, open_by_handle_at — RawSyscall
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mlock2(addr: *const c_void, len: usize, flags: c_uint) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_mlock2, addr, len, flags) } as c_int;
    if rc < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::ENOTSUP);
        unsafe { set_abi_errno(e) };
    }
    rc
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn name_to_handle_at(
    dirfd: c_int,
    pathname: *const c_char,
    handle: *mut c_void,
    mount_id: *mut c_int,
    flags: c_int,
) -> c_int {
    let rc = unsafe {
        libc::syscall(
            libc::SYS_name_to_handle_at,
            dirfd,
            pathname,
            handle,
            mount_id,
            flags,
        )
    } as c_int;
    if rc < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::ENOTSUP);
        unsafe { set_abi_errno(e) };
    }
    rc
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn open_by_handle_at(
    mount_fd: c_int,
    handle: *mut c_void,
    flags: c_int,
) -> c_int {
    let rc =
        unsafe { libc::syscall(libc::SYS_open_by_handle_at, mount_fd, handle, flags) } as c_int;
    if rc < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::ENOTSUP);
        unsafe { set_abi_errno(e) };
    }
    rc
}

// ---------------------------------------------------------------------------
// 64-bit LFS extras / umount — GlibcCallThrough
// ---------------------------------------------------------------------------

unsafe extern "C" {
    #[link_name = "umount"]
    fn libc_umount(target: *const c_char) -> c_int;
    #[link_name = "glob64"]
    fn libc_glob64(
        pattern: *const c_char,
        flags: c_int,
        errfunc: Option<unsafe extern "C" fn(*const c_char, c_int) -> c_int>,
        pglob: *mut c_void,
    ) -> c_int;
    #[link_name = "globfree64"]
    fn libc_globfree64(pglob: *mut c_void);
    #[link_name = "nftw64"]
    fn libc_nftw64(
        dirpath: *const c_char,
        fn_: *const c_void,
        nopenfd: c_int,
        flags: c_int,
    ) -> c_int;
    #[link_name = "alphasort64"]
    fn libc_alphasort64(a: *mut *const c_void, b: *mut *const c_void) -> c_int;
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn umount(target: *const c_char) -> c_int {
    unsafe { libc_umount(target) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn glob64(
    pattern: *const c_char,
    flags: c_int,
    errfunc: Option<unsafe extern "C" fn(*const c_char, c_int) -> c_int>,
    pglob: *mut c_void,
) -> c_int {
    unsafe { libc_glob64(pattern, flags, errfunc, pglob) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn globfree64(pglob: *mut c_void) {
    unsafe { libc_globfree64(pglob) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nftw64(
    dirpath: *const c_char,
    fn_: *const c_void,
    nopenfd: c_int,
    flags: c_int,
) -> c_int {
    unsafe { libc_nftw64(dirpath, fn_, nopenfd, flags) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn alphasort64(a: *mut *const c_void, b: *mut *const c_void) -> c_int {
    unsafe { libc_alphasort64(a, b) }
}
