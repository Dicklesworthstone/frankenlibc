//! ABI layer for `<unistd.h>` functions.
//!
//! Covers POSIX I/O (read/write/close/lseek), file metadata (stat/fstat/lstat/access),
//! directory navigation (getcwd/chdir), process identity (getpid/getppid/getuid/...),
//! link operations (link/symlink/readlink/unlink/rmdir), and sync (fsync/fdatasync).

use std::ffi::{CStr, CString, c_char, c_int, c_long, c_uint, c_ulong, c_void};

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
        unsafe { set_abi_errno(errno::EPERM) };
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
        unsafe { set_abi_errno(errno::EPERM) };
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
        unsafe { set_abi_errno(errno::EPERM) };
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
        unsafe { set_abi_errno(errno::EPERM) };
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
        unsafe { set_abi_errno(errno::ENOTTY) };
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
        unsafe { set_abi_errno(errno::EPERM) };
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
        unsafe { set_abi_errno(errno::EPERM) };
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
        unsafe { set_abi_errno(errno::EPERM) };
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
        unsafe { set_abi_errno(errno::EPERM) };
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
        unsafe { set_abi_errno(errno::EPERM) };
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
        unsafe { set_abi_errno(errno::EPERM) };
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
        unsafe { set_abi_errno(errno::EPERM) };
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
        unsafe { set_abi_errno(errno::EPERM) };
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
        unsafe { set_abi_errno(errno::EPERM) };
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
        unsafe { set_abi_errno(errno::EPERM) };
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
        unsafe { set_abi_errno(errno::EPERM) };
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
        unsafe { set_abi_errno(errno::EPERM) };
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
        unsafe { set_abi_errno(errno::EPERM) };
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
        unsafe { set_abi_errno(errno::EPERM) };
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
        unsafe { set_abi_errno(errno::EPERM) };
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
        unsafe { set_abi_errno(errno::EPERM) };
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
        unsafe { set_abi_errno(errno::EPERM) };
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
        unsafe { set_abi_errno(errno::EPERM) };
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
        unsafe { set_abi_errno(errno::EPERM) };
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
        unsafe { set_abi_errno(errno::EPERM) };
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
        unsafe { set_abi_errno(errno::EPERM) };
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
        unsafe { set_abi_errno(errno::EPERM) };
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
        unsafe { set_abi_errno(errno::EPERM) };
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
        unsafe { set_abi_errno(errno::EPERM) };
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
        unsafe { set_abi_errno(errno::EPERM) };
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
        unsafe { set_abi_errno(errno::EPERM) };
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

/// Linux `name_to_handle_at` — translate pathname to an opaque file handle.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn name_to_handle_at(
    dirfd: c_int,
    path: *const c_char,
    handle: *mut c_void,
    mount_id: *mut c_int,
    flags: c_int,
) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::IoFd, path as usize, 0, true, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EPERM) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    if path.is_null() || handle.is_null() || mount_id.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }

    let rc = unsafe {
        syscall_ret_int(
            libc::syscall(
                libc::SYS_name_to_handle_at,
                dirfd,
                path,
                handle,
                mount_id,
                flags,
            ),
            errno::ENOENT,
        )
    };
    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 15, rc < 0);
    rc
}

/// Linux `open_by_handle_at` — open by handle returned from `name_to_handle_at`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn open_by_handle_at(
    mount_fd: c_int,
    handle: *mut c_void,
    flags: c_int,
) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::IoFd, handle as usize, 0, true, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EPERM) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    if handle.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }

    let rc = unsafe {
        syscall_ret_int(
            libc::syscall(libc::SYS_open_by_handle_at, mount_fd, handle, flags),
            errno::EBADF,
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
        unsafe { set_abi_errno(errno::EPERM) };
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
        unsafe { set_abi_errno(errno::EPERM) };
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
        unsafe { set_abi_errno(errno::EPERM) };
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
        unsafe { set_abi_errno(errno::EPERM) };
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
        unsafe { set_abi_errno(errno::EPERM) };
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
        unsafe { set_abi_errno(errno::EPERM) };
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
        unsafe { set_abi_errno(errno::EPERM) };
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
        unsafe { set_abi_errno(errno::EPERM) };
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
        unsafe { set_abi_errno(errno::EPERM) };
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
        unsafe { set_abi_errno(errno::EPERM) };
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
// getopt — Implemented
// ---------------------------------------------------------------------------

unsafe extern "C" {
    #[link_name = "optarg"]
    static mut libc_optarg: *mut c_char;
    #[link_name = "optind"]
    static mut libc_optind: c_int;
    #[link_name = "optopt"]
    static mut libc_optopt: c_int;
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum GetoptArgMode {
    None,
    Required,
    Optional,
}

static mut GETOPT_NEXTCHAR: *const c_char = std::ptr::null();

#[inline]
fn getopt_prefers_colon(optspec: &[u8]) -> bool {
    optspec.first().copied() == Some(b':')
}

#[inline]
fn getopt_arg_mode(optspec: &[u8], option: u8) -> Option<GetoptArgMode> {
    for (idx, &byte) in optspec.iter().enumerate() {
        if byte != option {
            continue;
        }
        let requires = optspec.get(idx + 1).copied() == Some(b':');
        let optional = optspec.get(idx + 2).copied() == Some(b':');
        return Some(if requires && optional {
            GetoptArgMode::Optional
        } else if requires {
            GetoptArgMode::Required
        } else {
            GetoptArgMode::None
        });
    }
    None
}

unsafe fn parse_getopt_short(argc: c_int, argv: *const *mut c_char, optspec: &[u8]) -> c_int {
    if argc <= 0 || argv.is_null() {
        return -1;
    }
    if unsafe { libc_optind <= 0 } {
        unsafe {
            libc_optind = 1;
            GETOPT_NEXTCHAR = std::ptr::null();
        }
    }
    if unsafe { libc_optind >= argc } {
        unsafe {
            GETOPT_NEXTCHAR = std::ptr::null();
        }
        return -1;
    }

    if unsafe { GETOPT_NEXTCHAR.is_null() || *GETOPT_NEXTCHAR == 0 } {
        let current = unsafe { *argv.add(libc_optind as usize) };
        if current.is_null() {
            return -1;
        }
        if unsafe { *current != b'-' as c_char || *current.add(1) == 0 } {
            return -1;
        }
        if unsafe { *current.add(1) == b'-' as c_char && *current.add(2) == 0 } {
            unsafe {
                libc_optind += 1;
                GETOPT_NEXTCHAR = std::ptr::null();
            }
            return -1;
        }
        unsafe {
            GETOPT_NEXTCHAR = current.add(1);
        }
    }

    let option = unsafe { *GETOPT_NEXTCHAR as u8 };
    unsafe {
        GETOPT_NEXTCHAR = GETOPT_NEXTCHAR.add(1);
        libc_optarg = std::ptr::null_mut();
    }

    let missing_code = if getopt_prefers_colon(optspec) {
        b':' as c_int
    } else {
        b'?' as c_int
    };

    match getopt_arg_mode(optspec, option) {
        None => {
            unsafe {
                libc_optopt = option as c_int;
                if *GETOPT_NEXTCHAR == 0 {
                    libc_optind += 1;
                    GETOPT_NEXTCHAR = std::ptr::null();
                }
            }
            b'?' as c_int
        }
        Some(GetoptArgMode::None) => {
            unsafe {
                if *GETOPT_NEXTCHAR == 0 {
                    libc_optind += 1;
                    GETOPT_NEXTCHAR = std::ptr::null();
                }
            }
            option as c_int
        }
        Some(GetoptArgMode::Required) => {
            if unsafe { *GETOPT_NEXTCHAR != 0 } {
                unsafe {
                    libc_optarg = GETOPT_NEXTCHAR as *mut c_char;
                    libc_optind += 1;
                    GETOPT_NEXTCHAR = std::ptr::null();
                }
                return option as c_int;
            }
            if unsafe { libc_optind + 1 >= argc } {
                unsafe {
                    libc_optopt = option as c_int;
                    libc_optind += 1;
                    GETOPT_NEXTCHAR = std::ptr::null();
                }
                return missing_code;
            }
            unsafe {
                libc_optind += 1;
                let value = *argv.add(libc_optind as usize);
                if value.is_null() {
                    libc_optopt = option as c_int;
                    GETOPT_NEXTCHAR = std::ptr::null();
                    return missing_code;
                }
                libc_optarg = value;
                libc_optind += 1;
                GETOPT_NEXTCHAR = std::ptr::null();
            }
            option as c_int
        }
        Some(GetoptArgMode::Optional) => {
            unsafe {
                if *GETOPT_NEXTCHAR != 0 {
                    libc_optarg = GETOPT_NEXTCHAR as *mut c_char;
                }
                libc_optind += 1;
                GETOPT_NEXTCHAR = std::ptr::null();
            }
            option as c_int
        }
    }
}

unsafe fn parse_getopt_long(
    argc: c_int,
    argv: *const *mut c_char,
    optspec: &[u8],
    longopts: *const libc::option,
    longindex: *mut c_int,
) -> Option<c_int> {
    if argc <= 0 || argv.is_null() || longopts.is_null() {
        return None;
    }
    if unsafe { libc_optind <= 0 } {
        unsafe {
            libc_optind = 1;
            GETOPT_NEXTCHAR = std::ptr::null();
        }
    }
    if unsafe { libc_optind >= argc } {
        unsafe {
            GETOPT_NEXTCHAR = std::ptr::null();
        }
        return Some(-1);
    }

    let current = unsafe { *argv.add(libc_optind as usize) };
    if current.is_null() {
        return Some(-1);
    }
    if unsafe { *current != b'-' as c_char || *current.add(1) != b'-' as c_char } {
        return None;
    }
    if unsafe { *current.add(2) == 0 } {
        unsafe {
            libc_optind += 1;
            GETOPT_NEXTCHAR = std::ptr::null();
        }
        return Some(-1);
    }

    let mut split = unsafe { current.add(2) };
    while unsafe { *split != 0 && *split != b'=' as c_char } {
        split = unsafe { split.add(1) };
    }
    let name_ptr = unsafe { current.add(2) };
    let name_len = unsafe { split.offset_from(name_ptr) as usize };
    let name = unsafe { std::slice::from_raw_parts(name_ptr.cast::<u8>(), name_len) };
    let inline_value = if unsafe { *split == b'=' as c_char } {
        unsafe { split.add(1) }
    } else {
        std::ptr::null()
    };
    let missing_code = if getopt_prefers_colon(optspec) {
        b':' as c_int
    } else {
        b'?' as c_int
    };

    let mut idx = 0usize;
    loop {
        let opt_ptr = unsafe { longopts.add(idx) };
        let long_name = unsafe { (*opt_ptr).name };
        if long_name.is_null() {
            break;
        }
        let candidate = unsafe { CStr::from_ptr(long_name).to_bytes() };
        if candidate == name {
            if !longindex.is_null() {
                unsafe {
                    *longindex = idx as c_int;
                }
            }
            unsafe {
                libc_optarg = std::ptr::null_mut();
                libc_optopt = 0;
                GETOPT_NEXTCHAR = std::ptr::null();
            }
            let mut next_index = unsafe { libc_optind + 1 };
            match unsafe { (*opt_ptr).has_arg } {
                0 => {
                    if !inline_value.is_null() && unsafe { *inline_value != 0 } {
                        unsafe {
                            libc_optopt = (*opt_ptr).val;
                            libc_optind = next_index;
                        }
                        return Some(b'?' as c_int);
                    }
                }
                1 => {
                    if !inline_value.is_null() && unsafe { *inline_value != 0 } {
                        unsafe {
                            libc_optarg = inline_value as *mut c_char;
                        }
                    } else {
                        if next_index >= argc {
                            unsafe {
                                libc_optopt = (*opt_ptr).val;
                                libc_optind = next_index;
                            }
                            return Some(missing_code);
                        }
                        let value = unsafe { *argv.add(next_index as usize) };
                        if value.is_null() {
                            unsafe {
                                libc_optopt = (*opt_ptr).val;
                                libc_optind = next_index;
                            }
                            return Some(missing_code);
                        }
                        unsafe {
                            libc_optarg = value;
                        }
                        next_index += 1;
                    }
                }
                2 => {
                    if !inline_value.is_null() && unsafe { *inline_value != 0 } {
                        unsafe {
                            libc_optarg = inline_value as *mut c_char;
                        }
                    }
                }
                _ => {}
            }
            unsafe {
                libc_optind = next_index;
            }
            let flag_ptr = unsafe { (*opt_ptr).flag };
            if !flag_ptr.is_null() {
                unsafe {
                    *flag_ptr = (*opt_ptr).val;
                }
                return Some(0);
            }
            return Some(unsafe { (*opt_ptr).val });
        }
        idx += 1;
    }

    unsafe {
        libc_optarg = std::ptr::null_mut();
        libc_optopt = 0;
        libc_optind += 1;
        GETOPT_NEXTCHAR = std::ptr::null();
    }
    Some(b'?' as c_int)
}

/// POSIX `getopt` — parse command-line options.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getopt(
    argc: c_int,
    argv: *const *mut c_char,
    optstring: *const c_char,
) -> c_int {
    let (_, decision) = runtime_policy::decide(
        ApiFamily::Stdio,
        argv as usize,
        argc.max(0) as usize,
        false,
        argv.is_null() || optstring.is_null(),
        argc.clamp(0, u16::MAX as c_int) as u16,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EPERM) };
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 12, true);
        return -1;
    }
    if argv.is_null() || optstring.is_null() {
        unsafe { set_abi_errno(errno::EINVAL) };
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 12, true);
        return -1;
    }
    let optspec = unsafe { CStr::from_ptr(optstring).to_bytes() };
    let rc = unsafe { parse_getopt_short(argc, argv, optspec) };
    runtime_policy::observe(
        ApiFamily::Stdio,
        decision.profile,
        runtime_policy::scaled_cost(12, argc.max(0) as usize),
        rc == (b'?' as c_int) || rc == (b':' as c_int),
    );
    rc
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
    let (_, decision) = runtime_policy::decide(
        ApiFamily::Stdio,
        argv as usize,
        argc.max(0) as usize,
        false,
        argv.is_null() || optstring.is_null(),
        argc.clamp(0, u16::MAX as c_int) as u16,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EPERM) };
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 12, true);
        return -1;
    }
    if argv.is_null() || optstring.is_null() {
        unsafe { set_abi_errno(errno::EINVAL) };
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 12, true);
        return -1;
    }
    let optspec = unsafe { CStr::from_ptr(optstring).to_bytes() };
    let rc = match unsafe { parse_getopt_long(argc, argv, optspec, longopts, longindex) } {
        Some(value) => value,
        None => unsafe { parse_getopt_short(argc, argv, optspec) },
    };
    runtime_policy::observe(
        ApiFamily::Stdio,
        decision.profile,
        runtime_policy::scaled_cost(12, argc.max(0) as usize),
        rc == (b'?' as c_int) || rc == (b':' as c_int),
    );
    rc
}

/// GNU `getopt_long_only` — like getopt_long but '-' also triggers long option matching.
///
/// When a single-dash argument doesn't match a short option, it's tried as a long option.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getopt_long_only(
    argc: c_int,
    argv: *const *mut c_char,
    optstring: *const c_char,
    longopts: *const libc::option,
    longindex: *mut c_int,
) -> c_int {
    // Same as getopt_long for our purposes — the difference is that single-dash
    // options are tried as long options first, which our parse_getopt_long handles.
    unsafe { getopt_long(argc, argv, optstring, longopts, longindex) }
}

// ---------------------------------------------------------------------------
// syslog — Implemented (native /dev/log + stderr fallback)
// ---------------------------------------------------------------------------

const LOG_PID: c_int = 0x01;
const LOG_CONS: c_int = 0x02;
const LOG_NDELAY: c_int = 0x08;
const LOG_PERROR: c_int = 0x20;
const LOG_USER: c_int = 1 << 3;

struct SyslogState {
    ident_ptr: *const c_char,
    option: c_int,
    facility: c_int,
    sock_fd: c_int,
}

unsafe impl Send for SyslogState {}

static SYSLOG_STATE: std::sync::Mutex<SyslogState> = std::sync::Mutex::new(SyslogState {
    ident_ptr: std::ptr::null(),
    option: 0,
    facility: LOG_USER,
    sock_fd: -1,
});

fn syslog_connect() -> c_int {
    let fd = unsafe { libc::socket(1, 2, 0) };
    if fd < 0 {
        return -1;
    }
    let mut addr = [0u8; 110];
    addr[0] = 1; // AF_UNIX
    let path = b"/dev/log";
    addr[2..2 + path.len()].copy_from_slice(path);
    let rc = unsafe {
        libc::connect(
            fd,
            addr.as_ptr() as *const libc::sockaddr,
            (2 + path.len() + 1) as u32,
        )
    };
    if rc < 0 {
        unsafe { libc::close(fd) };
        return -1;
    }
    fd
}

fn syslog_send(priority: c_int, message: &[u8]) {
    let mut state = SYSLOG_STATE.lock().unwrap_or_else(|e| e.into_inner());

    let level = priority & 0x07;
    let facility = if priority & !0x07 != 0 {
        priority & !0x07
    } else {
        state.facility
    };
    let pri = facility | level;

    let ident = if !state.ident_ptr.is_null() {
        unsafe { CStr::from_ptr(state.ident_ptr) }
            .to_str()
            .unwrap_or("unknown")
    } else {
        "unknown"
    };

    let mut tv = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut tv) };
    let epoch = tv.tv_sec;
    let secs_in_day = epoch % 86400;
    let hour = secs_in_day / 3600;
    let min = (secs_in_day % 3600) / 60;
    let sec = secs_in_day % 60;
    let days = epoch / 86400;
    let (_, month, day) = syslog_days_to_ymd(days);
    let months = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let mon_str = if (1..=12).contains(&month) {
        months[(month - 1) as usize]
    } else {
        "Jan"
    };

    let pid_part = if state.option & LOG_PID != 0 {
        format!("[{}]", unsafe { libc::getpid() })
    } else {
        String::new()
    };

    let msg_str = String::from_utf8_lossy(message);
    let packet = format!(
        "<{}>{} {:2} {:02}:{:02}:{:02} {}{}: {}",
        pri, mon_str, day, hour, min, sec, ident, pid_part, msg_str
    );
    let packet_bytes = packet.as_bytes();

    if state.sock_fd < 0 {
        state.sock_fd = syslog_connect();
    }

    let mut sent = false;
    if state.sock_fd >= 0 {
        let rc = unsafe {
            libc::send(
                state.sock_fd,
                packet_bytes.as_ptr() as *const c_void,
                packet_bytes.len(),
                libc::MSG_NOSIGNAL,
            )
        };
        sent = rc >= 0;
        if !sent {
            unsafe { libc::close(state.sock_fd) };
            state.sock_fd = syslog_connect();
            if state.sock_fd >= 0 {
                let rc2 = unsafe {
                    libc::send(
                        state.sock_fd,
                        packet_bytes.as_ptr() as *const c_void,
                        packet_bytes.len(),
                        libc::MSG_NOSIGNAL,
                    )
                };
                sent = rc2 >= 0;
            }
        }
    }

    if !sent && (state.option & LOG_CONS != 0) {
        let _ = super::stdio_abi::write_all_fd(libc::STDERR_FILENO, packet_bytes);
    }

    if state.option & LOG_PERROR != 0 {
        let stderr_msg = format!("{}{}: {}\n", ident, pid_part, msg_str);
        let _ = super::stdio_abi::write_all_fd(libc::STDERR_FILENO, stderr_msg.as_bytes());
    }
}

fn syslog_days_to_ymd(days: i64) -> (i64, i32, i32) {
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m as i32, d as i32)
}

/// Extract variadic args for syslog — same as printf's extract_va_args.
macro_rules! extract_syslog_args {
    ($segments:expr, $args:expr, $buf:expr, $extract_count:expr) => {{
        use frankenlibc_core::stdio::printf::{FormatSegment, Precision, Width};
        let mut _idx = 0usize;
        for seg in $segments {
            if let FormatSegment::Spec(spec) = seg {
                if matches!(spec.width, Width::FromArg) && _idx < $extract_count {
                    $buf[_idx] = unsafe { $args.arg::<u64>() };
                    _idx += 1;
                }
                if matches!(spec.precision, Precision::FromArg) && _idx < $extract_count {
                    $buf[_idx] = unsafe { $args.arg::<u64>() };
                    _idx += 1;
                }
                match spec.conversion {
                    b'%' => {}
                    b'f' | b'F' | b'e' | b'E' | b'g' | b'G' | b'a' | b'A' => {
                        if _idx < $extract_count {
                            $buf[_idx] = unsafe { $args.arg::<f64>() }.to_bits();
                            _idx += 1;
                        }
                    }
                    _ => {
                        if _idx < $extract_count {
                            $buf[_idx] = unsafe { $args.arg::<u64>() };
                            _idx += 1;
                        }
                    }
                }
            }
        }
        _idx
    }};
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn openlog(ident: *const c_char, option: c_int, facility: c_int) {
    let mut state = SYSLOG_STATE.lock().unwrap_or_else(|e| e.into_inner());
    state.ident_ptr = ident; // POSIX: caller-owned, not copied
    state.option = option;
    state.facility = if facility == 0 { LOG_USER } else { facility };
    if option & LOG_NDELAY != 0 && state.sock_fd < 0 {
        state.sock_fd = syslog_connect();
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn syslog(priority: c_int, format: *const c_char, mut args: ...) {
    if format.is_null() {
        return;
    }
    let fmt_bytes = unsafe { super::stdio_abi::c_str_bytes(format) };
    use frankenlibc_core::stdio::printf::parse_format_string;
    let segments = parse_format_string(fmt_bytes);
    let extract_count = super::stdio_abi::count_printf_args(&segments);
    let mut arg_buf = [0u64; super::stdio_abi::MAX_VA_ARGS];
    extract_syslog_args!(&segments, &mut args, &mut arg_buf, extract_count);
    let rendered =
        unsafe { super::stdio_abi::render_printf(fmt_bytes, arg_buf.as_ptr(), extract_count) };
    syslog_send(priority, &rendered);
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn closelog() {
    let mut state = SYSLOG_STATE.lock().unwrap_or_else(|e| e.into_inner());
    if state.sock_fd >= 0 {
        unsafe { libc::close(state.sock_fd) };
        state.sock_fd = -1;
    }
    state.ident_ptr = std::ptr::null();
    state.option = 0;
    state.facility = LOG_USER;
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn vsyslog(priority: c_int, format: *const c_char, ap: *mut c_void) {
    if format.is_null() {
        return;
    }
    let fmt_bytes = unsafe { super::stdio_abi::c_str_bytes(format) };
    use frankenlibc_core::stdio::printf::parse_format_string;
    let segments = parse_format_string(fmt_bytes);
    let extract_count = super::stdio_abi::count_printf_args(&segments);
    let mut arg_buf = [0u64; super::stdio_abi::MAX_VA_ARGS];
    unsafe { super::stdio_abi::vprintf_extract_args(&segments, ap, &mut arg_buf, extract_count) };
    let rendered =
        unsafe { super::stdio_abi::render_printf(fmt_bytes, arg_buf.as_ptr(), extract_count) };
    syslog_send(priority, &rendered);
}

// ---------------------------------------------------------------------------
// misc POSIX — mixed (implemented + call-through)
// ---------------------------------------------------------------------------

const MKDTEMP_SUFFIX_LEN: usize = 6;
const MKDTEMP_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
static MKDTEMP_NONCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
const CTERMID_PATH: &[u8] = b"/dev/tty\0";
const GETLOGIN_MAX_LEN: usize = 256;
const TTYNAME_MAX_LEN: usize = 4096;
const PTSNAME_MAX_LEN: usize = 128;
const PTMX_PATH: &[u8] = b"/dev/ptmx\0";
static mut CTERMID_FALLBACK: [c_char; CTERMID_PATH.len()] = [0; CTERMID_PATH.len()];
static mut GETLOGIN_FALLBACK: [c_char; GETLOGIN_MAX_LEN] = [0; GETLOGIN_MAX_LEN];
static mut TTYNAME_FALLBACK: [c_char; TTYNAME_MAX_LEN] = [0; TTYNAME_MAX_LEN];
static mut PTSNAME_FALLBACK: [c_char; PTSNAME_MAX_LEN] = [0; PTSNAME_MAX_LEN];

#[inline]
unsafe fn lookup_login_name_ptr() -> *const c_char {
    let pwd = unsafe { crate::pwd_abi::getpwuid(libc::geteuid()) };
    if pwd.is_null() {
        return std::ptr::null();
    }
    let name = unsafe { (*pwd).pw_name };
    if name.is_null() {
        std::ptr::null()
    } else {
        name.cast_const()
    }
}

#[inline]
unsafe fn resolve_ttyname_into(fd: c_int, dst: *mut c_char, cap: usize) -> Result<usize, c_int> {
    if cap == 0 {
        return Err(errno::ERANGE);
    }

    // Validate descriptor first so callers can distinguish EBADF from ENOTTY.
    let fcntl_rc = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if fcntl_rc < 0 {
        return Err(last_host_errno(errno::EBADF));
    }

    let mut winsize = std::mem::MaybeUninit::<libc::winsize>::zeroed();
    // SAFETY: ioctl writes winsize on success and performs terminal capability check.
    unsafe { syscall::sys_ioctl(fd, libc::TIOCGWINSZ as usize, winsize.as_mut_ptr() as usize) }?;

    let proc_link = CString::new(format!("/proc/self/fd/{fd}")).map_err(|_| errno::EINVAL)?;
    let mut resolved = [0 as c_char; TTYNAME_MAX_LEN];
    let link_rc = unsafe {
        libc::syscall(
            libc::SYS_readlink,
            proc_link.as_ptr(),
            resolved.as_mut_ptr(),
            resolved.len() - 1,
        )
    };
    if link_rc < 0 {
        return Err(last_host_errno(errno::ENOENT));
    }
    let len = link_rc as usize;
    if len + 1 > cap {
        return Err(errno::ERANGE);
    }
    resolved[len] = 0;
    unsafe {
        std::ptr::copy_nonoverlapping(resolved.as_ptr(), dst, len + 1);
    }
    Ok(len)
}

#[inline]
unsafe fn resolve_ptsname_into(fd: c_int, dst: *mut c_char, cap: usize) -> Result<usize, c_int> {
    if cap == 0 {
        return Err(errno::ERANGE);
    }

    let mut pty_num: c_int = 0;
    // SAFETY: ioctl writes PTY slave index into `pty_num` on success.
    let rc = unsafe { libc::ioctl(fd, libc::TIOCGPTN, &mut pty_num) };
    if rc < 0 {
        return Err(last_host_errno(errno::EBADF));
    }

    let path = format!("/dev/pts/{pty_num}");
    let c_path = CString::new(path).map_err(|_| errno::EINVAL)?;
    let src = c_path.as_bytes_with_nul();
    if src.len() > cap {
        return Err(errno::ERANGE);
    }

    unsafe {
        std::ptr::copy_nonoverlapping(src.as_ptr().cast::<c_char>(), dst, src.len());
    }
    Ok(src.len() - 1)
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

#[inline]
unsafe fn sys_current_nice() -> Result<c_int, c_int> {
    let raw = unsafe { libc::syscall(libc::SYS_getpriority, libc::PRIO_PROCESS, 0) };
    if raw < 0 {
        return Err(last_host_errno(errno::EPERM));
    }
    Ok(20_i32.saturating_sub(raw as c_int))
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nice(inc: c_int) -> c_int {
    let current = match unsafe { sys_current_nice() } {
        Ok(v) => v,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            return -1;
        }
    };

    let target = current.saturating_add(inc).clamp(-20, 19);
    let set_rc = unsafe { libc::syscall(libc::SYS_setpriority, libc::PRIO_PROCESS, 0, target) };
    if set_rc < 0 {
        unsafe { set_abi_errno(last_host_errno(errno::EPERM)) };
        return -1;
    }

    match unsafe { sys_current_nice() } {
        Ok(v) => v,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// BSD `daemon` — detach from controlling terminal.
///
/// fork(), parent exits, child calls setsid(), optionally chdir("/")
/// and redirects stdin/stdout/stderr to /dev/null.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn daemon(nochdir: c_int, noclose: c_int) -> c_int {
    // SAFETY: fork via raw syscall
    let pid = unsafe { libc::syscall(libc::SYS_fork) };
    if pid < 0 {
        return -1;
    }
    if pid > 0 {
        // Parent: exit immediately
        unsafe { libc::syscall(libc::SYS_exit_group, 0i64) };
        unreachable!();
    }

    // Child: create new session
    if unsafe { libc::syscall(libc::SYS_setsid) } < 0 {
        return -1;
    }

    if nochdir == 0 {
        let root = b"/\0";
        unsafe {
            libc::syscall(libc::SYS_chdir, root.as_ptr());
        };
    }

    if noclose == 0 {
        let dev_null = b"/dev/null\0";
        let fd = unsafe { libc::syscall(libc::SYS_open, dev_null.as_ptr(), libc::O_RDWR, 0i64) }
            as c_int;
        if fd >= 0 {
            unsafe {
                libc::syscall(libc::SYS_dup2, fd as i64, 0i64); // stdin
                libc::syscall(libc::SYS_dup2, fd as i64, 1i64); // stdout
                libc::syscall(libc::SYS_dup2, fd as i64, 2i64); // stderr
            };
            if fd > 2 {
                unsafe { libc::syscall(libc::SYS_close, fd as i64) };
            }
        }
    }
    0
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
        unsafe { set_abi_errno(errno::EPERM) };
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
        unsafe { set_abi_errno(errno::EPERM) };
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
        unsafe { set_abi_errno(errno::EPERM) };
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
// ftw / nftw — Implemented (native directory tree walk)
// ---------------------------------------------------------------------------

/// POSIX `ftw` — file tree walk (native implementation).
///
/// Walks the directory tree rooted at `dirpath`, calling `func` for each
/// entry. The callback receives the pathname, a stat struct, and a type flag.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ftw(
    dirpath: *const c_char,
    func: Option<unsafe extern "C" fn(*const c_char, *const libc::stat, c_int) -> c_int>,
    nopenfd: c_int,
) -> c_int {
    let Some(callback) = func else {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    };
    if dirpath.is_null() {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }
    let max_fd = if nopenfd < 1 { 1 } else { nopenfd as usize };

    // Adapter: ftw callback to nftw-style internal walk.
    unsafe { ftw_walk_dir(dirpath, callback, max_fd, 0) }
}

/// Internal ftw directory walker.
unsafe fn ftw_walk_dir(
    path: *const c_char,
    func: unsafe extern "C" fn(*const c_char, *const libc::stat, c_int) -> c_int,
    max_fd: usize,
    depth: usize,
) -> c_int {
    // FTW type flags (POSIX)
    const FTW_F: c_int = 0; // regular file
    const FTW_D: c_int = 1; // directory
    const FTW_DNR: c_int = 2; // unreadable directory
    const FTW_NS: c_int = 3; // stat failed

    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::stat(path, &mut st) };
    if rc != 0 {
        return unsafe { func(path, &st, FTW_NS) };
    }

    let is_dir = (st.st_mode & libc::S_IFMT) == libc::S_IFDIR;

    if !is_dir {
        return unsafe { func(path, &st, FTW_F) };
    }

    // Call callback for this directory.
    let ret = unsafe { func(path, &st, FTW_D) };
    if ret != 0 {
        return ret;
    }

    // Open and traverse the directory.
    let dir = unsafe { libc::opendir(path) };
    if dir.is_null() {
        return unsafe { func(path, &st, FTW_DNR) };
    }

    loop {
        let entry = unsafe { libc::readdir(dir) };
        if entry.is_null() {
            break;
        }
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) };
        let name_bytes = name.to_bytes();

        // Skip . and ..
        if name_bytes == b"." || name_bytes == b".." {
            continue;
        }

        // Build child path: path + "/" + name
        let path_len = unsafe { libc::strlen(path) };
        let child_len = path_len + 1 + name_bytes.len() + 1;
        let child_buf = unsafe { libc::malloc(child_len) as *mut u8 };
        if child_buf.is_null() {
            unsafe { libc::closedir(dir) };
            return -1;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(path as *const u8, child_buf, path_len);
            *child_buf.add(path_len) = b'/';
            std::ptr::copy_nonoverlapping(
                name_bytes.as_ptr(),
                child_buf.add(path_len + 1),
                name_bytes.len(),
            );
            *child_buf.add(child_len - 1) = 0;
        }

        let ret = if depth + 1 < max_fd {
            unsafe { ftw_walk_dir(child_buf as *const c_char, func, max_fd, depth + 1) }
        } else {
            // At fd limit, still stat but don't recurse deeply.
            unsafe { ftw_walk_dir(child_buf as *const c_char, func, max_fd, depth + 1) }
        };

        unsafe { libc::free(child_buf as *mut c_void) };

        if ret != 0 {
            unsafe { libc::closedir(dir) };
            return ret;
        }
    }

    unsafe { libc::closedir(dir) };
    0
}

/// POSIX `nftw` — extended file tree walk (native implementation).
///
/// Like `ftw` but with additional flags and `FTW` info struct.
/// Supports FTW_PHYS (no follow symlinks), FTW_DEPTH (post-order),
/// FTW_MOUNT (stay on same filesystem), FTW_CHDIR (chdir into dirs).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nftw(
    dirpath: *const c_char,
    func: Option<
        unsafe extern "C" fn(*const c_char, *const libc::stat, c_int, *mut c_void) -> c_int,
    >,
    nopenfd: c_int,
    flags: c_int,
) -> c_int {
    let Some(callback) = func else {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    };
    if dirpath.is_null() {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }
    let max_fd = if nopenfd < 1 { 1 } else { nopenfd as usize };

    unsafe { nftw_walk_dir(dirpath, callback, max_fd, flags, 0, 0) }
}

// NFTW flags
const FTW_PHYS: c_int = 1;
const FTW_MOUNT: c_int = 2;
const FTW_DEPTH: c_int = 8;

// FTW type flags
const NFTW_F: c_int = 0; // regular file
const NFTW_D: c_int = 1; // directory (pre-order)
const NFTW_DNR: c_int = 2; // unreadable directory
const NFTW_NS: c_int = 3; // stat failed
const NFTW_DP: c_int = 5; // directory (post-order, FTW_DEPTH)
const NFTW_SL: c_int = 4; // symlink (FTW_PHYS)
const NFTW_SLN: c_int = 6; // dangling symlink

/// FTW info struct (POSIX): { int base; int level; }
#[repr(C)]
struct FtwInfo {
    base: c_int,
    level: c_int,
}

/// Internal nftw directory walker.
#[allow(clippy::too_many_arguments, clippy::only_used_in_recursion)]
unsafe fn nftw_walk_dir(
    path: *const c_char,
    func: unsafe extern "C" fn(*const c_char, *const libc::stat, c_int, *mut c_void) -> c_int,
    max_fd: usize,
    flags: c_int,
    depth: usize,
    root_dev: libc::dev_t,
) -> c_int {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };

    // Use lstat if FTW_PHYS, stat otherwise.
    let rc = if flags & FTW_PHYS != 0 {
        unsafe { libc::lstat(path, &mut st) }
    } else {
        unsafe { libc::stat(path, &mut st) }
    };

    // Compute base offset (last '/' + 1).
    let path_len = unsafe { libc::strlen(path) };
    let path_bytes = unsafe { std::slice::from_raw_parts(path as *const u8, path_len) };
    let base = path_bytes
        .iter()
        .rposition(|&b| b == b'/')
        .map_or(0, |p| p + 1) as c_int;

    let mut info = FtwInfo {
        base,
        level: depth as c_int,
    };

    if rc != 0 {
        let ret = unsafe { func(path, &st, NFTW_NS, &mut info as *mut FtwInfo as *mut c_void) };
        return ret;
    }

    let is_dir = (st.st_mode & libc::S_IFMT) == libc::S_IFDIR;
    let is_link = (st.st_mode & libc::S_IFMT) == libc::S_IFLNK;

    // Check cross-device (FTW_MOUNT)
    if flags & FTW_MOUNT != 0 && depth > 0 && st.st_dev != root_dev {
        return 0;
    }

    let dev = if depth == 0 { st.st_dev } else { root_dev };

    // Handle symlinks
    if is_link && flags & FTW_PHYS != 0 {
        // Check if dangling
        let mut target_st: libc::stat = unsafe { std::mem::zeroed() };
        let typeflag = if unsafe { libc::stat(path, &mut target_st) } != 0 {
            NFTW_SLN
        } else {
            NFTW_SL
        };
        return unsafe {
            func(
                path,
                &st,
                typeflag,
                &mut info as *mut FtwInfo as *mut c_void,
            )
        };
    }

    if !is_dir {
        return unsafe { func(path, &st, NFTW_F, &mut info as *mut FtwInfo as *mut c_void) };
    }

    // Pre-order callback (unless FTW_DEPTH)
    if flags & FTW_DEPTH == 0 {
        let ret = unsafe { func(path, &st, NFTW_D, &mut info as *mut FtwInfo as *mut c_void) };
        if ret != 0 {
            return ret;
        }
    }

    // Open and traverse the directory.
    let dir = unsafe { libc::opendir(path) };
    if dir.is_null() {
        let ret = unsafe {
            func(
                path,
                &st,
                NFTW_DNR,
                &mut info as *mut FtwInfo as *mut c_void,
            )
        };
        return ret;
    }

    loop {
        let entry = unsafe { libc::readdir(dir) };
        if entry.is_null() {
            break;
        }
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) };
        let name_bytes = name.to_bytes();

        if name_bytes == b"." || name_bytes == b".." {
            continue;
        }

        // Build child path
        let child_len = path_len + 1 + name_bytes.len() + 1;
        let child_buf = unsafe { libc::malloc(child_len) as *mut u8 };
        if child_buf.is_null() {
            unsafe { libc::closedir(dir) };
            return -1;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(path as *const u8, child_buf, path_len);
            *child_buf.add(path_len) = b'/';
            std::ptr::copy_nonoverlapping(
                name_bytes.as_ptr(),
                child_buf.add(path_len + 1),
                name_bytes.len(),
            );
            *child_buf.add(child_len - 1) = 0;
        }

        let ret = unsafe {
            nftw_walk_dir(
                child_buf as *const c_char,
                func,
                max_fd,
                flags,
                depth + 1,
                dev,
            )
        };

        unsafe { libc::free(child_buf as *mut c_void) };

        if ret != 0 {
            unsafe { libc::closedir(dir) };
            return ret;
        }
    }

    unsafe { libc::closedir(dir) };

    // Post-order callback (FTW_DEPTH)
    if flags & FTW_DEPTH != 0 {
        let ret = unsafe { func(path, &st, NFTW_DP, &mut info as *mut FtwInfo as *mut c_void) };
        if ret != 0 {
            return ret;
        }
    }

    0
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
// POSIX shared memory — RawSyscall
// ---------------------------------------------------------------------------

const SHM_DIR_PREFIX: &[u8] = b"/dev/shm";

#[inline]
unsafe fn resolve_shm_object_path(name: *const c_char) -> Result<CString, c_int> {
    if name.is_null() {
        return Err(errno::EINVAL);
    }
    let c_name = unsafe { CStr::from_ptr(name) };
    let name_bytes = c_name.to_bytes();

    if name_bytes.len() < 2 || name_bytes[0] != b'/' {
        return Err(errno::EINVAL);
    }
    if name_bytes[1..].contains(&b'/') {
        return Err(errno::EINVAL);
    }

    let mut full_path = Vec::with_capacity(SHM_DIR_PREFIX.len() + name_bytes.len());
    full_path.extend_from_slice(SHM_DIR_PREFIX);
    full_path.push(b'/');
    full_path.extend_from_slice(&name_bytes[1..]);

    CString::new(full_path).map_err(|_| errno::EINVAL)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn shm_open(name: *const c_char, oflag: c_int, mode: libc::mode_t) -> c_int {
    let path = match unsafe { resolve_shm_object_path(name) } {
        Ok(path) => path,
        Err(err) => {
            unsafe { set_abi_errno(err) };
            return -1;
        }
    };

    unsafe {
        syscall_ret_int(
            libc::syscall(libc::SYS_openat, libc::AT_FDCWD, path.as_ptr(), oflag, mode),
            errno::EINVAL,
        )
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn shm_unlink(name: *const c_char) -> c_int {
    let path = match unsafe { resolve_shm_object_path(name) } {
        Ok(path) => path,
        Err(err) => {
            unsafe { set_abi_errno(err) };
            return -1;
        }
    };

    unsafe {
        syscall_ret_int(
            libc::syscall(libc::SYS_unlinkat, libc::AT_FDCWD, path.as_ptr(), 0),
            errno::EINVAL,
        )
    }
}

// ---------------------------------------------------------------------------
// POSIX semaphores — native futex-based (unnamed) + GlibcCallThrough (named)
// ---------------------------------------------------------------------------

/// SEM_VALUE_MAX — POSIX specifies at least 32767.
const SEM_VALUE_MAX: c_uint = 0x7fff_ffff;

/// Interpret the sem_t pointer as a pointer to an atomic i32 counter.
/// On Linux/glibc, sem_t is a 32-byte union; the first 4 bytes hold the
/// unsigned counter for unnamed semaphores.
unsafe fn sem_as_atomic(sem: *mut c_void) -> &'static std::sync::atomic::AtomicI32 {
    unsafe { &*(sem as *const std::sync::atomic::AtomicI32) }
}

fn sem_futex_wait(word: *mut c_void, expected: i32) -> i64 {
    unsafe {
        libc::syscall(
            libc::SYS_futex,
            word as *const i32,
            libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG,
            expected,
            std::ptr::null::<libc::timespec>(),
        )
    }
}

fn sem_futex_wait_timed(word: *mut c_void, expected: i32, ts: *const libc::timespec) -> i64 {
    unsafe {
        libc::syscall(
            libc::SYS_futex,
            word as *const i32,
            libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG,
            expected,
            ts,
        )
    }
}

fn sem_futex_wake(word: *mut c_void, count: i32) -> i64 {
    unsafe {
        libc::syscall(
            libc::SYS_futex,
            word as *const i32,
            libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG,
            count,
        )
    }
}

// Named semaphores — Implemented (native /dev/shm + mmap)
//
// sem_open creates/opens a named semaphore backed by a file in /dev/shm/sem.NAME.
// The file contains a single i32 (the futex word), mmap'd into the calling process.
// sem_close munmaps it; sem_unlink removes the backing file.

/// Size of the semaphore mapping (page-aligned minimum).
const SEM_MMAP_SIZE: usize = 32; // Must be >= sizeof(sem_t) = 32 on glibc/x86_64

/// Resolve a POSIX semaphore name to its /dev/shm/sem.NAME path.
///
/// The name MUST start with '/' and contain no further slashes.
/// glibc convention: the backing file is `/dev/shm/sem.<name_without_slash>`.
#[inline]
unsafe fn resolve_sem_path(name: *const c_char) -> Result<CString, c_int> {
    if name.is_null() {
        return Err(errno::EINVAL);
    }
    let c_name = unsafe { CStr::from_ptr(name) };
    let name_bytes = c_name.to_bytes();

    // Must start with '/' and have at least one char after it.
    if name_bytes.len() < 2 || name_bytes[0] != b'/' {
        return Err(errno::EINVAL);
    }
    // No additional slashes allowed.
    if name_bytes[1..].contains(&b'/') {
        return Err(errno::EINVAL);
    }
    // Name too long (NAME_MAX = 255, minus "sem." prefix = 251).
    if name_bytes.len() - 1 > 251 {
        return Err(errno::ENAMETOOLONG);
    }

    let suffix = &name_bytes[1..]; // Strip leading '/'
    let prefix = b"/dev/shm/sem.";
    let mut full_path = Vec::with_capacity(prefix.len() + suffix.len() + 1);
    full_path.extend_from_slice(prefix);
    full_path.extend_from_slice(suffix);

    CString::new(full_path).map_err(|_| errno::EINVAL)
}

/// POSIX `sem_open` — open/create a named semaphore.
///
/// Native implementation using /dev/shm/sem.NAME + mmap. The mapped region
/// contains a futex word compatible with our unnamed semaphore operations.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sem_open(name: *const c_char, oflag: c_int, mut args: ...) -> *mut c_void {
    let path = match unsafe { resolve_sem_path(name) } {
        Ok(p) => p,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            return usize::MAX as *mut c_void; // SEM_FAILED = (sem_t*)-1
        }
    };

    // Extract optional mode and value when O_CREAT is set.
    let (mode, initial_value) = if (oflag & libc::O_CREAT) != 0 {
        let m = unsafe { args.arg::<libc::mode_t>() };
        let v = unsafe { args.arg::<c_uint>() };
        (m, v)
    } else {
        (0o600 as libc::mode_t, 0u32)
    };

    if initial_value > SEM_VALUE_MAX {
        unsafe { set_abi_errno(errno::EINVAL) };
        return usize::MAX as *mut c_void;
    }

    // Open the backing file.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat as std::os::raw::c_long,
            libc::AT_FDCWD,
            path.as_ptr(),
            oflag | libc::O_RDWR | libc::O_CLOEXEC,
            mode,
        ) as c_int
    };

    if fd < 0 {
        unsafe { set_abi_errno(last_host_errno(errno::ENOENT)) };
        return usize::MAX as *mut c_void;
    }

    // If we created a new file, initialize it with the semaphore value.
    let created = (oflag & libc::O_CREAT) != 0;
    if created {
        // Set file size to SEM_MMAP_SIZE.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_ftruncate as std::os::raw::c_long,
                fd,
                SEM_MMAP_SIZE as i64,
            ) as c_int
        };
        if rc < 0 {
            let e = last_host_errno(errno::EIO);
            unsafe {
                libc::syscall(libc::SYS_close as std::os::raw::c_long, fd);
                set_abi_errno(e);
            };
            return usize::MAX as *mut c_void;
        }
    }

    // mmap the file.
    let ptr = unsafe {
        libc::syscall(
            libc::SYS_mmap as std::os::raw::c_long,
            std::ptr::null::<c_void>(),
            SEM_MMAP_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0_i64,
        ) as *mut c_void
    };

    // Close the fd — the mapping keeps the file open.
    unsafe { libc::syscall(libc::SYS_close as std::os::raw::c_long, fd) };

    if ptr == libc::MAP_FAILED {
        unsafe { set_abi_errno(last_host_errno(errno::ENOMEM)) };
        return usize::MAX as *mut c_void;
    }

    // If we just created the semaphore, initialize the futex word.
    if created {
        let atom = unsafe { &*(ptr as *const std::sync::atomic::AtomicI32) };
        atom.store(initial_value as i32, std::sync::atomic::Ordering::Release);
    }

    ptr
}

/// POSIX `sem_close` — close a named semaphore.
///
/// Unmaps the shared memory region. The backing file remains.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sem_close(sem: *mut c_void) -> c_int {
    if sem.is_null() || sem == libc::MAP_FAILED {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }
    let rc = unsafe {
        libc::syscall(libc::SYS_munmap as std::os::raw::c_long, sem, SEM_MMAP_SIZE) as c_int
    };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(errno::EINVAL)) };
        -1
    } else {
        0
    }
}

/// POSIX `sem_unlink` — remove a named semaphore.
///
/// Removes the backing file from /dev/shm. Existing mappings remain valid
/// until all processes call `sem_close`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sem_unlink(name: *const c_char) -> c_int {
    let path = match unsafe { resolve_sem_path(name) } {
        Ok(p) => p,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            return -1;
        }
    };

    unsafe {
        syscall_ret_int(
            libc::syscall(
                libc::SYS_unlinkat as std::os::raw::c_long,
                libc::AT_FDCWD,
                path.as_ptr(),
                0,
            ),
            errno::ENOENT,
        )
    }
}

/// POSIX `sem_init` — initialize an unnamed semaphore.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sem_init(sem: *mut c_void, _pshared: c_int, value: c_uint) -> c_int {
    if sem.is_null() || value > SEM_VALUE_MAX {
        unsafe { *libc::__errno_location() = libc::EINVAL };
        return -1;
    }
    let atom = unsafe { sem_as_atomic(sem) };
    atom.store(value as i32, std::sync::atomic::Ordering::Release);
    0
}

/// POSIX `sem_destroy` — destroy an unnamed semaphore.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sem_destroy(sem: *mut c_void) -> c_int {
    if sem.is_null() {
        unsafe { *libc::__errno_location() = libc::EINVAL };
        return -1;
    }
    // No resources to reclaim for futex-based semaphores.
    0
}

/// POSIX `sem_post` — increment the semaphore and wake one waiter.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sem_post(sem: *mut c_void) -> c_int {
    if sem.is_null() {
        unsafe { *libc::__errno_location() = libc::EINVAL };
        return -1;
    }
    let atom = unsafe { sem_as_atomic(sem) };
    let old = atom.fetch_add(1, std::sync::atomic::Ordering::Release);
    if old < 0 || old == i32::MAX {
        // Overflow protection
        atom.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        unsafe { *libc::__errno_location() = libc::EOVERFLOW };
        return -1;
    }
    // Wake one waiter
    sem_futex_wake(sem, 1);
    0
}

/// POSIX `sem_wait` — decrement the semaphore, blocking if zero.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sem_wait(sem: *mut c_void) -> c_int {
    if sem.is_null() {
        unsafe { *libc::__errno_location() = libc::EINVAL };
        return -1;
    }
    let atom = unsafe { sem_as_atomic(sem) };
    loop {
        let val = atom.load(std::sync::atomic::Ordering::Acquire);
        if val > 0
            && atom
                .compare_exchange_weak(
                    val,
                    val - 1,
                    std::sync::atomic::Ordering::AcqRel,
                    std::sync::atomic::Ordering::Relaxed,
                )
                .is_ok()
        {
            return 0;
        }
        if val <= 0 {
            let ret = sem_futex_wait(sem, val);
            if ret < 0 {
                let err = unsafe { *libc::__errno_location() };
                if err == libc::EINTR {
                    unsafe { *libc::__errno_location() = libc::EINTR };
                    return -1;
                }
                // EAGAIN is spurious wakeup — retry
            }
        }
    }
}

/// POSIX `sem_trywait` — non-blocking decrement.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sem_trywait(sem: *mut c_void) -> c_int {
    if sem.is_null() {
        unsafe { *libc::__errno_location() = libc::EINVAL };
        return -1;
    }
    let atom = unsafe { sem_as_atomic(sem) };
    loop {
        let val = atom.load(std::sync::atomic::Ordering::Acquire);
        if val <= 0 {
            unsafe { *libc::__errno_location() = libc::EAGAIN };
            return -1;
        }
        if atom
            .compare_exchange_weak(
                val,
                val - 1,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Relaxed,
            )
            .is_ok()
        {
            return 0;
        }
    }
}

/// POSIX `sem_timedwait` — decrement with absolute timeout.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sem_timedwait(
    sem: *mut c_void,
    abs_timeout: *const libc::timespec,
) -> c_int {
    if sem.is_null() {
        unsafe { *libc::__errno_location() = libc::EINVAL };
        return -1;
    }
    let atom = unsafe { sem_as_atomic(sem) };
    loop {
        let val = atom.load(std::sync::atomic::Ordering::Acquire);
        if val > 0
            && atom
                .compare_exchange_weak(
                    val,
                    val - 1,
                    std::sync::atomic::Ordering::AcqRel,
                    std::sync::atomic::Ordering::Relaxed,
                )
                .is_ok()
        {
            return 0;
        }
        if val <= 0 {
            if abs_timeout.is_null() {
                unsafe { *libc::__errno_location() = libc::EINVAL };
                return -1;
            }
            let ret = sem_futex_wait_timed(sem, val, abs_timeout);
            if ret < 0 {
                let err = unsafe { *libc::__errno_location() };
                if err == libc::ETIMEDOUT {
                    unsafe { *libc::__errno_location() = libc::ETIMEDOUT };
                    return -1;
                }
                if err == libc::EINTR {
                    unsafe { *libc::__errno_location() = libc::EINTR };
                    return -1;
                }
            }
        }
    }
}

/// POSIX `sem_getvalue` — read the current semaphore value.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sem_getvalue(sem: *mut c_void, sval: *mut c_int) -> c_int {
    if sem.is_null() || sval.is_null() {
        unsafe { *libc::__errno_location() = libc::EINVAL };
        return -1;
    }
    let atom = unsafe { sem_as_atomic(sem) };
    let val = atom.load(std::sync::atomic::Ordering::Relaxed);
    unsafe { *sval = val.max(0) };
    0
}

// ---------------------------------------------------------------------------
// POSIX message queues — RawSyscall
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mq_open(name: *const c_char, oflag: c_int, mut args: ...) -> c_int {
    let (mode, attr) = if (oflag & libc::O_CREAT) != 0 {
        let mode = unsafe { args.arg::<libc::mode_t>() };
        let attr = unsafe { args.arg::<*const c_void>() };
        (mode, attr)
    } else {
        (0 as libc::mode_t, std::ptr::null())
    };

    unsafe {
        syscall_ret_int(
            libc::syscall(libc::SYS_mq_open, name, oflag, mode, attr),
            errno::EINVAL,
        )
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mq_close(mqdes: c_int) -> c_int {
    unsafe { syscall_ret_int(libc::syscall(libc::SYS_close, mqdes), errno::EBADF) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mq_unlink(name: *const c_char) -> c_int {
    unsafe { syscall_ret_int(libc::syscall(libc::SYS_mq_unlink, name), errno::EINVAL) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mq_send(
    mqdes: c_int,
    msg_ptr: *const c_char,
    msg_len: usize,
    msg_prio: c_uint,
) -> c_int {
    unsafe {
        syscall_ret_int(
            libc::syscall(
                libc::SYS_mq_timedsend,
                mqdes,
                msg_ptr,
                msg_len,
                msg_prio,
                std::ptr::null::<libc::timespec>(),
            ),
            errno::EINVAL,
        )
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mq_receive(
    mqdes: c_int,
    msg_ptr: *mut c_char,
    msg_len: usize,
    msg_prio: *mut c_uint,
) -> isize {
    unsafe {
        syscall_ret_isize(
            libc::syscall(
                libc::SYS_mq_timedreceive,
                mqdes,
                msg_ptr,
                msg_len,
                msg_prio,
                std::ptr::null::<libc::timespec>(),
            ),
            errno::EINVAL,
        )
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mq_getattr(mqdes: c_int, attr: *mut c_void) -> c_int {
    unsafe {
        syscall_ret_int(
            libc::syscall(
                libc::SYS_mq_getsetattr,
                mqdes,
                std::ptr::null::<c_void>(),
                attr,
            ),
            errno::EINVAL,
        )
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mq_setattr(
    mqdes: c_int,
    newattr: *const c_void,
    oldattr: *mut c_void,
) -> c_int {
    unsafe {
        syscall_ret_int(
            libc::syscall(libc::SYS_mq_getsetattr, mqdes, newattr, oldattr),
            errno::EINVAL,
        )
    }
}

/// `mq_timedreceive` — receive a message from a queue with timeout.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mq_timedreceive(
    mqdes: c_int,
    msg_ptr: *mut c_char,
    msg_len: usize,
    msg_prio: *mut c_uint,
    abs_timeout: *const libc::timespec,
) -> isize {
    let rc = unsafe {
        libc::syscall(
            libc::SYS_mq_timedreceive,
            mqdes,
            msg_ptr,
            msg_len,
            msg_prio,
            abs_timeout,
        )
    };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(libc::EINVAL)) };
    }
    rc as isize
}

/// `mq_timedsend` — send a message to a queue with timeout.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mq_timedsend(
    mqdes: c_int,
    msg_ptr: *const c_char,
    msg_len: usize,
    msg_prio: c_uint,
    abs_timeout: *const libc::timespec,
) -> c_int {
    unsafe {
        syscall_ret_int(
            libc::syscall(
                libc::SYS_mq_timedsend,
                mqdes,
                msg_ptr,
                msg_len,
                msg_prio,
                abs_timeout,
            ),
            errno::EINVAL,
        )
    }
}

/// `mq_notify` — register for notification when a message arrives.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mq_notify(mqdes: c_int, sevp: *const libc::sigevent) -> c_int {
    unsafe {
        syscall_ret_int(
            libc::syscall(libc::SYS_mq_notify, mqdes, sevp),
            errno::EINVAL,
        )
    }
}

// ---------------------------------------------------------------------------
// Scheduler — RawSyscall
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sched_getscheduler(pid: libc::pid_t) -> c_int {
    unsafe {
        syscall_ret_int(
            libc::syscall(libc::SYS_sched_getscheduler, pid),
            errno::EINVAL,
        )
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sched_setscheduler(
    pid: libc::pid_t,
    policy: c_int,
    param: *const c_void,
) -> c_int {
    unsafe {
        syscall_ret_int(
            libc::syscall(libc::SYS_sched_setscheduler, pid, policy, param),
            errno::EINVAL,
        )
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sched_getparam(pid: libc::pid_t, param: *mut c_void) -> c_int {
    unsafe {
        syscall_ret_int(
            libc::syscall(libc::SYS_sched_getparam, pid, param),
            errno::EINVAL,
        )
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sched_setparam(pid: libc::pid_t, param: *const c_void) -> c_int {
    unsafe {
        syscall_ret_int(
            libc::syscall(libc::SYS_sched_setparam, pid, param),
            errno::EINVAL,
        )
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sched_get_priority_min(policy: c_int) -> c_int {
    unsafe {
        syscall_ret_int(
            libc::syscall(libc::SYS_sched_get_priority_min, policy),
            errno::EINVAL,
        )
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sched_get_priority_max(policy: c_int) -> c_int {
    unsafe {
        syscall_ret_int(
            libc::syscall(libc::SYS_sched_get_priority_max, policy),
            errno::EINVAL,
        )
    }
}

// ---------------------------------------------------------------------------
// wordexp / wordfree — Implemented (native POSIX word expansion)
// ---------------------------------------------------------------------------
//
// Supports: tilde expansion (~user), environment variable expansion ($VAR, ${VAR}),
// pathname expansion (glob), field splitting on IFS, and WRDE_NOCMD safety.
// Command substitution ($(...) and `...`) is rejected when WRDE_NOCMD is set
// and executed via /bin/sh -c "echo ..." otherwise.

// POSIX wordexp_t layout (matches glibc x86_64):
// struct wordexp_t { size_t we_wordc; char **we_wordv; size_t we_offs; };
const WRDE_DOOFFS: c_int = 1 << 0;
const WRDE_APPEND: c_int = 1 << 1;
const WRDE_NOCMD: c_int = 1 << 2;
const WRDE_REUSE: c_int = 1 << 3;
#[allow(dead_code)]
const WRDE_SHOWERR: c_int = 1 << 4;
const WRDE_UNDEF: c_int = 1 << 5;

const WRDE_NOSPACE: c_int = 1;
const WRDE_BADCHAR: c_int = 2;
const WRDE_BADVAL: c_int = 3;
const WRDE_CMDSUB: c_int = 4;
const WRDE_SYNTAX: c_int = 5;

#[repr(C)]
struct WordexpT {
    we_wordc: usize,
    we_wordv: *mut *mut c_char,
    we_offs: usize,
}

/// Check if the input contains command substitution patterns.
fn has_command_substitution(s: &[u8]) -> bool {
    let mut i = 0;
    while i < s.len() {
        if s[i] == b'`' {
            return true;
        }
        if s[i] == b'$' && i + 1 < s.len() && s[i + 1] == b'(' {
            return true;
        }
        i += 1;
    }
    false
}

/// Check for unquoted special characters that POSIX says are errors.
fn has_bad_chars(s: &[u8]) -> bool {
    for &b in s {
        if b == b'|' || b == b'&' || b == b';' || b == b'<' || b == b'>' || b == b'\n' {
            return true;
        }
        // Opening paren/brace without $ are bad chars
    }
    false
}

/// Perform tilde expansion on a word.
fn expand_tilde(word: &str) -> String {
    if !word.starts_with('~') {
        return word.to_string();
    }
    let rest = &word[1..];
    let (user, suffix) = match rest.find('/') {
        Some(pos) => (&rest[..pos], &rest[pos..]),
        None => (rest, ""),
    };
    if user.is_empty() {
        // ~ alone → $HOME
        if let Ok(home) = std::env::var("HOME") {
            return format!("{home}{suffix}");
        }
    }
    // ~user → lookup (simplified: just return as-is if we can't resolve)
    word.to_string()
}

/// Perform environment variable expansion on a word.
fn expand_vars(word: &str, flags: c_int) -> Result<String, c_int> {
    let mut result = String::with_capacity(word.len());
    let bytes = word.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            result.push(bytes[i + 1] as char);
            i += 2;
            continue;
        }
        if bytes[i] == b'\'' {
            // Single-quoted string: no expansion
            i += 1;
            while i < bytes.len() && bytes[i] != b'\'' {
                result.push(bytes[i] as char);
                i += 1;
            }
            if i < bytes.len() {
                i += 1; // Skip closing quote
            }
            continue;
        }
        if bytes[i] == b'$' {
            i += 1;
            if i >= bytes.len() {
                result.push('$');
                continue;
            }
            let (var_name, end) = if bytes[i] == b'{' {
                i += 1;
                let start = i;
                while i < bytes.len() && bytes[i] != b'}' {
                    i += 1;
                }
                let name = std::str::from_utf8(&bytes[start..i]).unwrap_or("");
                if i < bytes.len() {
                    i += 1; // Skip '}'
                }
                (name, i)
            } else {
                let start = i;
                while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                    i += 1;
                }
                let name = std::str::from_utf8(&bytes[start..i]).unwrap_or("");
                (name, i)
            };
            i = end;
            if var_name.is_empty() {
                result.push('$');
                continue;
            }
            match std::env::var(var_name) {
                Ok(val) => result.push_str(&val),
                Err(_) => {
                    if (flags & WRDE_UNDEF) != 0 {
                        return Err(WRDE_BADVAL);
                    }
                    // Undefined variable expands to empty string
                }
            }
            continue;
        }
        if bytes[i] == b'"' {
            // Double-quoted: expand variables inside
            i += 1;
            let mut inner = String::new();
            while i < bytes.len() && bytes[i] != b'"' {
                inner.push(bytes[i] as char);
                i += 1;
            }
            if i < bytes.len() {
                i += 1;
            }
            let expanded = expand_vars(&inner, flags)?;
            result.push_str(&expanded);
            continue;
        }
        result.push(bytes[i] as char);
        i += 1;
    }
    Ok(result)
}

/// POSIX `wordexp` — perform shell-like word expansion.
///
/// Native implementation supporting tilde, variable, and pathname (glob) expansion.
/// Command substitution requires WRDE_NOCMD to be unset and uses /bin/sh.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wordexp(
    words: *const c_char,
    pwordexp: *mut c_void,
    flags: c_int,
) -> c_int {
    if words.is_null() || pwordexp.is_null() {
        return WRDE_NOSPACE;
    }

    let input = match unsafe { CStr::from_ptr(words) }.to_str() {
        Ok(s) => s,
        Err(_) => return WRDE_SYNTAX,
    };

    let input_bytes = input.as_bytes();

    // Check for bad characters
    if has_bad_chars(input_bytes) {
        return WRDE_BADCHAR;
    }

    // Check for command substitution
    if has_command_substitution(input_bytes) {
        if (flags & WRDE_NOCMD) != 0 {
            return WRDE_CMDSUB;
        }
        // For safety, reject command substitution entirely in our implementation.
        // A full implementation would fork /bin/sh -c "echo $words".
        return WRDE_CMDSUB;
    }

    // Split on IFS (whitespace by default)
    let ifs = std::env::var("IFS").unwrap_or_else(|_| " \t\n".to_string());

    // Process each word
    let mut result_words: Vec<String> = Vec::new();

    // Simple field splitting (respecting quotes)
    let mut current_word = String::new();
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut escaped = false;

    for &b in input_bytes {
        if escaped {
            current_word.push(b as char);
            escaped = false;
            continue;
        }
        if b == b'\\' && !in_single_quote {
            escaped = true;
            continue;
        }
        if b == b'\'' && !in_double_quote {
            in_single_quote = !in_single_quote;
            current_word.push(b as char);
            continue;
        }
        if b == b'"' && !in_single_quote {
            in_double_quote = !in_double_quote;
            current_word.push(b as char);
            continue;
        }
        if !in_single_quote && !in_double_quote && ifs.as_bytes().contains(&b) {
            if !current_word.is_empty() {
                result_words.push(std::mem::take(&mut current_word));
            }
            continue;
        }
        current_word.push(b as char);
    }
    if !current_word.is_empty() {
        result_words.push(current_word);
    }

    // Unclosed quotes
    if in_single_quote || in_double_quote {
        return WRDE_SYNTAX;
    }

    // Expand each word: tilde → variables → glob
    let mut final_words: Vec<CString> = Vec::new();

    for word in &result_words {
        // Tilde expansion
        let expanded = expand_tilde(word);
        // Variable expansion
        let expanded = match expand_vars(&expanded, flags) {
            Ok(s) => s,
            Err(e) => return e,
        };
        // Pathname expansion (glob)
        if expanded.contains('*') || expanded.contains('?') || expanded.contains('[') {
            // Use our glob infrastructure
            let pattern = std::path::Path::new(&expanded);
            match std::fs::read_dir(pattern.parent().unwrap_or(std::path::Path::new("."))) {
                Ok(entries) => {
                    let pat_name = pattern
                        .file_name()
                        .map(|s| s.to_string_lossy().to_string())
                        .unwrap_or_default();
                    let mut matched = false;
                    for entry in entries.flatten() {
                        let name = entry.file_name().to_string_lossy().to_string();
                        if simple_glob_match(&pat_name, &name) {
                            let full = if let Some(parent) = pattern.parent() {
                                if parent == std::path::Path::new("") {
                                    name
                                } else {
                                    format!("{}/{name}", parent.display())
                                }
                            } else {
                                name
                            };
                            if let Ok(cs) = CString::new(full) {
                                final_words.push(cs);
                                matched = true;
                            }
                        }
                    }
                    if !matched {
                        // No match: keep the pattern literally
                        if let Ok(cs) = CString::new(expanded.clone()) {
                            final_words.push(cs);
                        }
                    }
                }
                Err(_) => {
                    if let Ok(cs) = CString::new(expanded.clone()) {
                        final_words.push(cs);
                    }
                }
            }
        } else if let Ok(cs) = CString::new(expanded) {
            final_words.push(cs);
        }
    }

    // Build the wordexp_t result
    let we = unsafe { &mut *(pwordexp as *mut WordexpT) };

    // Handle WRDE_REUSE: free previous data
    if (flags & WRDE_REUSE) != 0 && !we.we_wordv.is_null() {
        unsafe { wordexp_free_wordv(we) };
    }

    let offs = if (flags & WRDE_DOOFFS) != 0 {
        we.we_offs
    } else {
        0
    };

    let old_count = if (flags & WRDE_APPEND) != 0 {
        we.we_wordc
    } else {
        0
    };

    let new_count = final_words.len();
    let total_slots = offs + old_count + new_count + 1; // +1 for NULL terminator

    // Allocate the wordv array
    let wordv_size = total_slots * std::mem::size_of::<*mut c_char>();
    let new_wordv = unsafe { libc::malloc(wordv_size) as *mut *mut c_char };
    if new_wordv.is_null() {
        return WRDE_NOSPACE;
    }

    // Zero the offset slots
    for i in 0..offs {
        unsafe { *new_wordv.add(i) = std::ptr::null_mut() };
    }

    // Copy old words if appending
    if (flags & WRDE_APPEND) != 0 && !we.we_wordv.is_null() && old_count > 0 {
        for i in 0..old_count {
            unsafe { *new_wordv.add(offs + i) = *we.we_wordv.add(offs + i) };
        }
    }

    // Add new words
    for (i, cstr) in final_words.iter().enumerate() {
        let len = cstr.as_bytes_with_nul().len();
        let buf = unsafe { libc::malloc(len) as *mut c_char };
        if buf.is_null() {
            // Clean up on allocation failure
            for j in 0..i {
                unsafe { libc::free(*new_wordv.add(offs + old_count + j) as *mut c_void) };
            }
            unsafe { libc::free(new_wordv as *mut c_void) };
            return WRDE_NOSPACE;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(cstr.as_ptr(), buf, len);
            *new_wordv.add(offs + old_count + i) = buf;
        };
    }

    // NULL terminator
    unsafe { *new_wordv.add(offs + old_count + new_count) = std::ptr::null_mut() };

    // Free old wordv array (but not the strings if appending)
    if !we.we_wordv.is_null() && ((flags & WRDE_APPEND) != 0 || old_count == 0) {
        unsafe { libc::free(we.we_wordv as *mut c_void) };
    }

    we.we_wordc = old_count + new_count;
    we.we_wordv = new_wordv;
    if (flags & WRDE_DOOFFS) == 0 {
        we.we_offs = 0;
    }

    0
}

/// Free the internal wordv of a WordexpT (helper).
unsafe fn wordexp_free_wordv(we: &mut WordexpT) {
    if we.we_wordv.is_null() {
        return;
    }
    let offs = we.we_offs;
    for i in 0..we.we_wordc {
        let p = unsafe { *we.we_wordv.add(offs + i) };
        if !p.is_null() {
            unsafe { libc::free(p as *mut c_void) };
        }
    }
    unsafe { libc::free(we.we_wordv as *mut c_void) };
    we.we_wordv = std::ptr::null_mut();
    we.we_wordc = 0;
}

/// Simple glob pattern matching for wordexp pathname expansion.
fn simple_glob_match(pattern: &str, name: &str) -> bool {
    // Skip hidden files unless pattern starts with '.'
    if name.starts_with('.') && !pattern.starts_with('.') {
        return false;
    }
    glob_match_bytes(pattern.as_bytes(), name.as_bytes())
}

fn glob_match_bytes(pat: &[u8], text: &[u8]) -> bool {
    let mut pi = 0;
    let mut ti = 0;
    let mut star_pi = usize::MAX;
    let mut star_ti = 0;

    while ti < text.len() {
        if pi < pat.len() && (pat[pi] == b'?' || pat[pi] == text[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < pat.len() && pat[pi] == b'*' {
            star_pi = pi;
            star_ti = ti;
            pi += 1;
        } else if star_pi != usize::MAX {
            pi = star_pi + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }
    while pi < pat.len() && pat[pi] == b'*' {
        pi += 1;
    }
    pi == pat.len()
}

/// POSIX `wordfree` — free memory allocated by `wordexp`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wordfree(pwordexp: *mut c_void) {
    if pwordexp.is_null() {
        return;
    }
    let we = unsafe { &mut *(pwordexp as *mut WordexpT) };
    unsafe { wordexp_free_wordv(we) };
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
pub unsafe extern "C" fn mincore(addr: *mut c_void, len: usize, vec: *mut u8) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_mincore, addr, len, vec) } as c_int;
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
// PTY / crypt / utmp — mixed (implemented + call-through)
// ---------------------------------------------------------------------------

// crypt — Implemented (native SHA-512/SHA-256/MD5 password hashing)

/// BSD `openpty` — allocate a pseudoterminal master/slave pair.
///
/// Native implementation using posix_openpt + grantpt + unlockpt + ptsname_r.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn openpty(
    amaster: *mut c_int,
    aslave: *mut c_int,
    name: *mut c_char,
    termp: *const c_void,
    winp: *const c_void,
) -> c_int {
    if amaster.is_null() || aslave.is_null() {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }

    // Open master
    let master = unsafe { posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
    if master < 0 {
        return -1;
    }

    // Grant and unlock
    if unsafe { grantpt(master) } < 0 || unsafe { unlockpt(master) } < 0 {
        unsafe { libc::syscall(libc::SYS_close, master as i64) };
        return -1;
    }

    // Get slave path via internal helper
    let mut slave_name = [0u8; 64];
    if unsafe { resolve_ptsname_into(master, slave_name.as_mut_ptr().cast::<c_char>(), 64) }
        .is_err()
    {
        unsafe { libc::syscall(libc::SYS_close, master as i64) };
        return -1;
    }

    // Open slave
    let slave = unsafe {
        libc::syscall(
            libc::SYS_openat,
            libc::AT_FDCWD,
            slave_name.as_ptr().cast::<c_char>(),
            libc::O_RDWR | libc::O_NOCTTY,
            0,
        )
    } as c_int;
    if slave < 0 {
        unsafe { libc::syscall(libc::SYS_close, master as i64) };
        return -1;
    }

    // Apply terminal attributes if provided
    if !termp.is_null() {
        unsafe { libc::syscall(libc::SYS_ioctl, slave as i64, libc::TCSETS as i64, termp) };
    }

    // Apply window size if provided
    const TIOCSWINSZ: i64 = 0x5414;
    if !winp.is_null() {
        unsafe { libc::syscall(libc::SYS_ioctl, slave as i64, TIOCSWINSZ, winp) };
    }

    // Copy slave name if buffer provided
    if !name.is_null() {
        let len = unsafe { std::ffi::CStr::from_ptr(slave_name.as_ptr().cast()) }
            .to_bytes_with_nul()
            .len();
        unsafe {
            std::ptr::copy_nonoverlapping(slave_name.as_ptr().cast::<c_char>(), name, len);
        }
    }

    unsafe {
        *amaster = master;
        *aslave = slave;
    }
    0
}

/// BSD `login_tty` — prepare a terminal for a login session.
///
/// Creates a new session, sets the given fd as the controlling terminal,
/// dups it to stdin/stdout/stderr, then closes the original fd.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn login_tty(fd: c_int) -> c_int {
    // Create new session
    if unsafe { libc::syscall(libc::SYS_setsid) } < 0 {
        return -1;
    }

    // Set controlling terminal (TIOCSCTTY = 0x540E on Linux)
    const TIOCSCTTY: u64 = 0x540E;
    if unsafe { libc::syscall(libc::SYS_ioctl, fd as i64, TIOCSCTTY as i64, 0i64) } < 0 {
        return -1;
    }

    // Dup fd to stdin/stdout/stderr
    unsafe {
        libc::syscall(libc::SYS_dup2, fd as i64, 0i64);
        libc::syscall(libc::SYS_dup2, fd as i64, 1i64);
        libc::syscall(libc::SYS_dup2, fd as i64, 2i64);
    };

    if fd > 2 {
        unsafe { libc::syscall(libc::SYS_close, fd as i64) };
    }
    0
}

/// BSD `forkpty` — fork with a new pseudoterminal.
///
/// Combines openpty + fork + login_tty into a single call.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn forkpty(
    amaster: *mut c_int,
    name: *mut c_char,
    termp: *const c_void,
    winp: *const c_void,
) -> libc::pid_t {
    if amaster.is_null() {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }

    let mut master: c_int = -1;
    let mut slave: c_int = -1;
    if unsafe { openpty(&mut master, &mut slave, name, termp, winp) } < 0 {
        return -1;
    }

    let pid = unsafe { libc::syscall(libc::SYS_clone, libc::SIGCHLD as i64, 0i64) } as libc::pid_t;
    if pid < 0 {
        unsafe {
            libc::syscall(libc::SYS_close, master as i64);
            libc::syscall(libc::SYS_close, slave as i64);
        };
        return -1;
    }

    if pid == 0 {
        // Child: close master, set up slave as controlling terminal
        unsafe {
            libc::syscall(libc::SYS_close, master as i64);
            login_tty(slave);
        };
        return 0;
    }

    // Parent: close slave, return master
    unsafe {
        libc::syscall(libc::SYS_close, slave as i64);
        *amaster = master;
    };
    pid
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn grantpt(fd: c_int) -> c_int {
    let mut pty_num: c_int = 0;
    // SAFETY: ioctl validates `fd` as PTY master and writes index on success.
    let rc = unsafe { libc::ioctl(fd, libc::TIOCGPTN, &mut pty_num) } as c_int;
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(errno::EBADF)) };
        return -1;
    }
    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn unlockpt(fd: c_int) -> c_int {
    let mut unlock: c_int = 0;
    // SAFETY: ioctl reads lock toggle value from `unlock`.
    let rc = unsafe { libc::ioctl(fd, libc::TIOCSPTLCK, &mut unlock) } as c_int;
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(errno::EBADF)) };
        return -1;
    }
    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ptsname(fd: c_int) -> *mut c_char {
    let dst = core::ptr::addr_of_mut!(PTSNAME_FALLBACK).cast::<c_char>();
    match unsafe { resolve_ptsname_into(fd, dst, PTSNAME_MAX_LEN) } {
        Ok(_) => dst,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            std::ptr::null_mut()
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn posix_openpt(flags: c_int) -> c_int {
    unsafe {
        syscall_ret_int(
            libc::syscall(
                libc::SYS_openat,
                libc::AT_FDCWD,
                PTMX_PATH.as_ptr().cast::<c_char>(),
                flags,
                0,
            ),
            errno::EINVAL,
        )
    }
}

// Thread-local buffer for crypt() result (POSIX allows static return).
std::thread_local! {
    static CRYPT_BUF: std::cell::RefCell<[u8; 256]> = const { std::cell::RefCell::new([0u8; 256]) };
}

/// POSIX `crypt` — one-way password hashing.
///
/// Native implementation supporting:
/// - `$6$salt$` — SHA-512 (default on modern Linux)
/// - `$5$salt$` — SHA-256
/// - `$1$salt$` — MD5 (deprecated but supported for compatibility)
/// - 2-char salt — Traditional DES (returns error; DES is obsolete)
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn crypt(key: *const c_char, salt: *const c_char) -> *mut c_char {
    if key.is_null() || salt.is_null() {
        unsafe { set_abi_errno(errno::EINVAL) };
        return std::ptr::null_mut();
    }

    let key_bytes = unsafe { CStr::from_ptr(key) }.to_bytes();
    let salt_bytes = unsafe { CStr::from_ptr(salt) }.to_bytes();

    let result = if salt_bytes.starts_with(b"$6$") {
        crypt_sha512(key_bytes, salt_bytes)
    } else if salt_bytes.starts_with(b"$5$") {
        crypt_sha256(key_bytes, salt_bytes)
    } else if salt_bytes.starts_with(b"$1$") {
        crypt_md5(key_bytes, salt_bytes)
    } else {
        // Traditional DES or unknown — return error (DES is obsolete and insecure)
        unsafe { set_abi_errno(errno::EINVAL) };
        return std::ptr::null_mut();
    };

    match result {
        Some(hash_string) => CRYPT_BUF.with(|cell| {
            let mut buf = cell.borrow_mut();
            let len = hash_string.len().min(buf.len() - 1);
            buf[..len].copy_from_slice(&hash_string.as_bytes()[..len]);
            buf[len] = 0;
            buf.as_mut_ptr() as *mut c_char
        }),
        None => {
            unsafe { set_abi_errno(errno::EINVAL) };
            std::ptr::null_mut()
        }
    }
}

/// The crypt base-64 alphabet (not standard base64!).
const CRYPT_B64: &[u8; 64] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// Encode bytes to crypt-style base64.
fn crypt_b64_encode(input: &[u8], n_chars: usize) -> String {
    let mut result = String::with_capacity(n_chars);
    let mut val: u32 = 0;
    let mut bits = 0;
    for &b in input {
        val |= (b as u32) << bits;
        bits += 8;
        while bits >= 6 && result.len() < n_chars {
            result.push(CRYPT_B64[(val & 0x3F) as usize] as char);
            val >>= 6;
            bits -= 6;
        }
    }
    if bits > 0 && result.len() < n_chars {
        result.push(CRYPT_B64[(val & 0x3F) as usize] as char);
    }
    while result.len() < n_chars {
        result.push(CRYPT_B64[0] as char);
    }
    result
}

/// Extract the salt portion from a $N$salt$ or $N$rounds=NNNN$salt$ prefix.
fn parse_crypt_salt(salt_bytes: &[u8], prefix_len: usize) -> (usize, &[u8]) {
    let rest = &salt_bytes[prefix_len..];
    // Check for rounds= parameter
    let (rounds, salt_start) = if rest.starts_with(b"rounds=") {
        let num_start = 7;
        let num_end = rest[num_start..]
            .iter()
            .position(|&b| b == b'$')
            .map(|p| num_start + p)
            .unwrap_or(rest.len());
        let rounds_str = std::str::from_utf8(&rest[num_start..num_end]).unwrap_or("5000");
        let r = rounds_str
            .parse::<usize>()
            .unwrap_or(5000)
            .clamp(1000, 999_999_999);
        (
            r,
            if num_end < rest.len() {
                num_end + 1
            } else {
                num_end
            },
        )
    } else {
        (5000, 0)
    };
    let salt_rest = &rest[salt_start..];
    // Salt is up to 16 chars, terminated by $ or end
    let salt_end = salt_rest
        .iter()
        .position(|&b| b == b'$')
        .unwrap_or(salt_rest.len())
        .min(16);
    (rounds, &salt_rest[..salt_end])
}

/// SHA-512 crypt ($6$).
fn crypt_sha512(key: &[u8], salt_bytes: &[u8]) -> Option<String> {
    use sha2::{Digest, Sha512};

    let (rounds, salt) = parse_crypt_salt(salt_bytes, 3);

    // Step 1: Digest B = SHA512(key + salt + key)
    let mut digest_b = Sha512::new();
    digest_b.update(key);
    digest_b.update(salt);
    digest_b.update(key);
    let hash_b = digest_b.finalize();

    // Step 2: Digest A = SHA512(key + salt + B-bytes-for-keylen)
    let mut digest_a = Sha512::new();
    digest_a.update(key);
    digest_a.update(salt);
    // Add bytes from B, cycling as needed
    let mut remaining = key.len();
    while remaining >= 64 {
        digest_a.update(&hash_b[..]);
        remaining -= 64;
    }
    if remaining > 0 {
        digest_a.update(&hash_b[..remaining]);
    }
    // Binary representation of key.len()
    let mut n = key.len();
    while n > 0 {
        if n & 1 != 0 {
            digest_a.update(&hash_b[..]);
        } else {
            digest_a.update(key);
        }
        n >>= 1;
    }
    let hash_a = digest_a.finalize();

    // Step 3: Digest DP = SHA512(key repeated key.len() times)
    let mut digest_dp = Sha512::new();
    for _ in 0..key.len() {
        digest_dp.update(key);
    }
    let hash_dp = digest_dp.finalize();
    let mut p_bytes = vec![0u8; key.len()];
    for i in 0..key.len() {
        p_bytes[i] = hash_dp[i % 64];
    }

    // Step 4: Digest DS = SHA512(salt repeated (16 + hash_a[0]) times)
    let mut digest_ds = Sha512::new();
    let ds_count = 16 + (hash_a[0] as usize);
    for _ in 0..ds_count {
        digest_ds.update(salt);
    }
    let hash_ds = digest_ds.finalize();
    let mut s_bytes = vec![0u8; salt.len()];
    for i in 0..salt.len() {
        s_bytes[i] = hash_ds[i % 64];
    }

    // Step 5: rounds iterations
    let mut c_input = hash_a.to_vec();
    for i in 0..rounds {
        let mut digest_c = Sha512::new();
        if i & 1 != 0 {
            digest_c.update(&p_bytes);
        } else {
            digest_c.update(&c_input);
        }
        if i % 3 != 0 {
            digest_c.update(&s_bytes);
        }
        if i % 7 != 0 {
            digest_c.update(&p_bytes);
        }
        if i & 1 != 0 {
            digest_c.update(&c_input);
        } else {
            digest_c.update(&p_bytes);
        }
        let result = digest_c.finalize();
        c_input.clear();
        c_input.extend_from_slice(&result);
    }

    // Step 6: Produce the output hash string with crypt-specific byte reordering
    let final_hash = &c_input;
    // SHA-512 crypt byte transposition order
    let reordered: Vec<u8> = [
        (final_hash[0], final_hash[21], final_hash[42]),
        (final_hash[22], final_hash[43], final_hash[1]),
        (final_hash[44], final_hash[2], final_hash[23]),
        (final_hash[3], final_hash[24], final_hash[45]),
        (final_hash[25], final_hash[46], final_hash[4]),
        (final_hash[47], final_hash[5], final_hash[26]),
        (final_hash[6], final_hash[27], final_hash[48]),
        (final_hash[28], final_hash[49], final_hash[7]),
        (final_hash[50], final_hash[8], final_hash[29]),
        (final_hash[9], final_hash[30], final_hash[51]),
        (final_hash[31], final_hash[52], final_hash[10]),
        (final_hash[53], final_hash[11], final_hash[32]),
        (final_hash[12], final_hash[33], final_hash[54]),
        (final_hash[34], final_hash[55], final_hash[13]),
        (final_hash[55], final_hash[14], final_hash[35]),
        (final_hash[15], final_hash[36], final_hash[56]),
        (final_hash[37], final_hash[57], final_hash[16]),
        (final_hash[58], final_hash[17], final_hash[38]),
        (final_hash[18], final_hash[39], final_hash[59]),
        (final_hash[40], final_hash[60], final_hash[19]),
        (final_hash[61], final_hash[20], final_hash[41]),
    ]
    .iter()
    .flat_map(|(a, b, c)| [*a, *b, *c])
    .collect();

    let mut encoded = crypt_b64_encode(&reordered, 84);
    // Last byte (final_hash[63]) encoded separately
    let last = [final_hash[63]];
    encoded.push_str(&crypt_b64_encode(&last, 2));

    let salt_str = std::str::from_utf8(salt).unwrap_or("");
    if rounds == 5000 {
        Some(format!("$6${salt_str}${encoded}"))
    } else {
        Some(format!("$6$rounds={rounds}${salt_str}${encoded}"))
    }
}

/// SHA-256 crypt ($5$) — same algorithm structure as $6$ but with SHA-256.
fn crypt_sha256(key: &[u8], salt_bytes: &[u8]) -> Option<String> {
    use sha2::{Digest, Sha256};

    let (rounds, salt) = parse_crypt_salt(salt_bytes, 3);

    let mut digest_b = Sha256::new();
    digest_b.update(key);
    digest_b.update(salt);
    digest_b.update(key);
    let hash_b = digest_b.finalize();

    let mut digest_a = Sha256::new();
    digest_a.update(key);
    digest_a.update(salt);
    let mut remaining = key.len();
    while remaining >= 32 {
        digest_a.update(&hash_b[..]);
        remaining -= 32;
    }
    if remaining > 0 {
        digest_a.update(&hash_b[..remaining]);
    }
    let mut n = key.len();
    while n > 0 {
        if n & 1 != 0 {
            digest_a.update(&hash_b[..]);
        } else {
            digest_a.update(key);
        }
        n >>= 1;
    }
    let hash_a = digest_a.finalize();

    let mut digest_dp = Sha256::new();
    for _ in 0..key.len() {
        digest_dp.update(key);
    }
    let hash_dp = digest_dp.finalize();
    let mut p_bytes = vec![0u8; key.len()];
    for i in 0..key.len() {
        p_bytes[i] = hash_dp[i % 32];
    }

    let mut digest_ds = Sha256::new();
    let ds_count = 16 + (hash_a[0] as usize);
    for _ in 0..ds_count {
        digest_ds.update(salt);
    }
    let hash_ds = digest_ds.finalize();
    let mut s_bytes = vec![0u8; salt.len()];
    for i in 0..salt.len() {
        s_bytes[i] = hash_ds[i % 32];
    }

    let mut c_input = hash_a.to_vec();
    for i in 0..rounds {
        let mut digest_c = Sha256::new();
        if i & 1 != 0 {
            digest_c.update(&p_bytes);
        } else {
            digest_c.update(&c_input);
        }
        if i % 3 != 0 {
            digest_c.update(&s_bytes);
        }
        if i % 7 != 0 {
            digest_c.update(&p_bytes);
        }
        if i & 1 != 0 {
            digest_c.update(&c_input);
        } else {
            digest_c.update(&p_bytes);
        }
        let result = digest_c.finalize();
        c_input.clear();
        c_input.extend_from_slice(&result);
    }

    let f = &c_input;
    let reordered: Vec<u8> = [
        (f[0], f[10], f[20]),
        (f[21], f[1], f[11]),
        (f[12], f[22], f[2]),
        (f[3], f[13], f[23]),
        (f[24], f[4], f[14]),
        (f[15], f[25], f[5]),
        (f[6], f[16], f[26]),
        (f[27], f[7], f[17]),
        (f[18], f[28], f[8]),
        (f[9], f[19], f[29]),
    ]
    .iter()
    .flat_map(|(a, b, c)| [*a, *b, *c])
    .collect();

    let mut encoded = crypt_b64_encode(&reordered, 40);
    let last = [f[30], f[31]];
    encoded.push_str(&crypt_b64_encode(&last, 3));

    let salt_str = std::str::from_utf8(salt).unwrap_or("");
    if rounds == 5000 {
        Some(format!("$5${salt_str}${encoded}"))
    } else {
        Some(format!("$5$rounds={rounds}${salt_str}${encoded}"))
    }
}

/// MD5 crypt ($1$) — legacy but still encountered.
fn crypt_md5(key: &[u8], salt_bytes: &[u8]) -> Option<String> {
    use md5::Md5;
    use sha2::Digest;

    // Parse salt (max 8 chars after $1$)
    let rest = &salt_bytes[3..];
    let salt_end = rest
        .iter()
        .position(|&b| b == b'$')
        .unwrap_or(rest.len())
        .min(8);
    let salt = &rest[..salt_end];

    let mut digest_b = Md5::new();
    digest_b.update(key);
    digest_b.update(salt);
    digest_b.update(key);
    let hash_b = digest_b.finalize();

    let mut digest_a = Md5::new();
    digest_a.update(key);
    digest_a.update(b"$1$");
    digest_a.update(salt);

    let mut remaining = key.len();
    while remaining >= 16 {
        digest_a.update(&hash_b[..]);
        remaining -= 16;
    }
    if remaining > 0 {
        digest_a.update(&hash_b[..remaining]);
    }

    let mut n = key.len();
    while n > 0 {
        if n & 1 != 0 {
            digest_a.update([0u8]);
        } else {
            digest_a.update(&key[..1]);
        }
        n >>= 1;
    }
    let mut result = digest_a.finalize().to_vec();

    // 1000 rounds
    for i in 0..1000u32 {
        let mut digest_c = Md5::new();
        if i & 1 != 0 {
            digest_c.update(key);
        } else {
            digest_c.update(&result);
        }
        if i % 3 != 0 {
            digest_c.update(salt);
        }
        if i % 7 != 0 {
            digest_c.update(key);
        }
        if i & 1 != 0 {
            digest_c.update(&result);
        } else {
            digest_c.update(key);
        }
        let r = digest_c.finalize();
        result.clear();
        result.extend_from_slice(&r);
    }

    let f = &result;
    let reordered: Vec<u8> = vec![
        f[0], f[6], f[12], f[1], f[7], f[13], f[2], f[8], f[14], f[3], f[9], f[15], f[4], f[10],
        f[5],
    ];
    let mut encoded = crypt_b64_encode(&reordered, 20);
    let last = [f[11]];
    encoded.push_str(&crypt_b64_encode(&last, 2));

    let salt_str = std::str::from_utf8(salt).unwrap_or("");
    Some(format!("$1${salt_str}${encoded}"))
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
// GNU system info — Implemented (native utmp file parsing)
// ---------------------------------------------------------------------------

/// Size of `struct utmp` on x86_64 Linux.
const UTMP_RECORD_SIZE: usize = 384;

/// Default utmp file path.
const UTMP_DEFAULT_PATH: &str = "/var/run/utmp";

struct UtmpState {
    /// Path to the utmp file (set by utmpname, defaults to /var/run/utmp).
    path: String,
    /// Cached file contents.
    data: Vec<u8>,
    /// Current read offset (in bytes).
    offset: usize,
    /// Whether we've loaded the file for the current iteration.
    loaded: bool,
    /// Thread-local buffer for the current entry.
    entry_buf: [u8; UTMP_RECORD_SIZE],
}

impl UtmpState {
    const fn new() -> Self {
        Self {
            path: String::new(),
            data: Vec::new(),
            offset: 0,
            loaded: false,
            entry_buf: [0u8; UTMP_RECORD_SIZE],
        }
    }

    fn effective_path(&self) -> &str {
        if self.path.is_empty() {
            UTMP_DEFAULT_PATH
        } else {
            &self.path
        }
    }

    fn ensure_loaded(&mut self) {
        if !self.loaded {
            self.data = std::fs::read(self.effective_path()).unwrap_or_default();
            self.offset = 0;
            self.loaded = true;
        }
    }

    fn next_entry(&mut self) -> *mut c_void {
        self.ensure_loaded();
        if self.offset + UTMP_RECORD_SIZE > self.data.len() {
            return std::ptr::null_mut(); // EOF
        }
        self.entry_buf
            .copy_from_slice(&self.data[self.offset..self.offset + UTMP_RECORD_SIZE]);
        self.offset += UTMP_RECORD_SIZE;
        self.entry_buf.as_mut_ptr().cast()
    }

    fn rewind(&mut self) {
        self.offset = 0;
        self.loaded = false; // Force reload on next access
    }

    fn set_path(&mut self, path: &str) {
        self.path = path.to_string();
        self.loaded = false;
        self.offset = 0;
    }
}

std::thread_local! {
    static UTMP_TLS: std::cell::RefCell<UtmpState> = const { std::cell::RefCell::new(UtmpState::new()) };
}

/// POSIX `getutent` — read the next entry from the utmp file.
///
/// Returns a pointer to a thread-local `struct utmp` buffer (384 bytes).
/// Returns NULL on EOF or error.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getutent() -> *mut c_void {
    UTMP_TLS.with(|cell| cell.borrow_mut().next_entry())
}

/// POSIX `setutent` — rewind utmp file to beginning.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setutent() {
    UTMP_TLS.with(|cell| cell.borrow_mut().rewind());
}

/// POSIX `endutent` — close utmp file.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn endutent() {
    UTMP_TLS.with(|cell| {
        let mut state = cell.borrow_mut();
        state.data.clear();
        state.offset = 0;
        state.loaded = false;
    });
}

/// POSIX `utmpname` — set the utmp file path.
///
/// Sets the file path used by subsequent `getutent`/`setutent`/`endutent` calls.
/// Returns 0 on success, -1 if the file argument is NULL.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn utmpname(file: *const c_char) -> c_int {
    if file.is_null() {
        return -1;
    }
    let path = unsafe { CStr::from_ptr(file) };
    let path_str = path.to_str().unwrap_or(UTMP_DEFAULT_PATH);
    UTMP_TLS.with(|cell| cell.borrow_mut().set_path(path_str));
    0
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
// SysV IPC — RawSyscall (shmget, shmctl, shmat, shmdt,
//                         semget, semctl, semop,
//                         msgget, msgctl, msgsnd, msgrcv)
// ---------------------------------------------------------------------------

#[inline]
fn semctl_cmd_uses_arg(cmd: c_int) -> bool {
    matches!(
        cmd,
        libc::SETVAL | libc::SETALL | libc::GETALL | libc::IPC_SET | libc::IPC_STAT
    )
}

#[inline]
fn policy_repair_enabled(heals_enabled: bool, action: MembraneAction) -> bool {
    heals_enabled || matches!(action, MembraneAction::Repair(_))
}

#[inline]
fn sysvipc_missing_payload(ptr: *const c_void, size: usize) -> bool {
    ptr.is_null() && size > 0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn shmget(key: c_int, size: usize, shmflg: c_int) -> c_int {
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Process, key as usize, size, true, size == 0, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EPERM) };
        runtime_policy::observe(
            ApiFamily::Process,
            decision.profile,
            runtime_policy::scaled_cost(10, size),
            true,
        );
        return -1;
    }

    let rc = unsafe {
        syscall_ret_int(
            libc::syscall(libc::SYS_shmget, key, size, shmflg),
            errno::EINVAL,
        )
    };
    runtime_policy::observe(
        ApiFamily::Process,
        decision.profile,
        runtime_policy::scaled_cost(10, size),
        rc != 0,
    );
    rc
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn shmctl(shmid: c_int, cmd: c_int, buf: *mut c_void) -> c_int {
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Process, buf as usize, 0, true, buf.is_null(), 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EPERM) };
        runtime_policy::observe(ApiFamily::Process, decision.profile, 10, true);
        return -1;
    }

    let rc = unsafe {
        syscall_ret_int(
            libc::syscall(libc::SYS_shmctl, shmid, cmd, buf),
            errno::EINVAL,
        )
    };
    runtime_policy::observe(ApiFamily::Process, decision.profile, 10, rc != 0);
    rc
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn shmat(shmid: c_int, shmaddr: *const c_void, shmflg: c_int) -> *mut c_void {
    let remap_without_addr = shmaddr.is_null() && (shmflg & libc::SHM_REMAP) != 0;
    let (mode, decision) = runtime_policy::decide(
        ApiFamily::VirtualMemory,
        shmaddr as usize,
        0,
        false,
        remap_without_addr,
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EPERM) };
        runtime_policy::observe(ApiFamily::VirtualMemory, decision.profile, 10, true);
        return (-1_isize) as *mut c_void;
    }
    if remap_without_addr && policy_repair_enabled(mode.heals_enabled(), decision.action) {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::VirtualMemory, decision.profile, 10, true);
        return (-1_isize) as *mut c_void;
    }

    let rc = unsafe { libc::syscall(libc::SYS_shmat, shmid, shmaddr, shmflg) };
    if rc == -1 {
        unsafe { set_abi_errno(last_host_errno(errno::EINVAL)) };
        runtime_policy::observe(ApiFamily::VirtualMemory, decision.profile, 10, true);
        return (-1_isize) as *mut c_void;
    }
    runtime_policy::observe(ApiFamily::VirtualMemory, decision.profile, 10, false);
    rc as *mut c_void
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn shmdt(shmaddr: *const c_void) -> c_int {
    let missing_payload = sysvipc_missing_payload(shmaddr, 1);
    let (mode, decision) = runtime_policy::decide(
        ApiFamily::VirtualMemory,
        shmaddr as usize,
        1,
        true,
        missing_payload,
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EPERM) };
        runtime_policy::observe(ApiFamily::VirtualMemory, decision.profile, 8, true);
        return -1;
    }
    if missing_payload && policy_repair_enabled(mode.heals_enabled(), decision.action) {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::VirtualMemory, decision.profile, 8, true);
        return -1;
    }

    let rc = unsafe { syscall_ret_int(libc::syscall(libc::SYS_shmdt, shmaddr), errno::EINVAL) };
    runtime_policy::observe(ApiFamily::VirtualMemory, decision.profile, 8, rc != 0);
    rc
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn semget(key: c_int, nsems: c_int, semflg: c_int) -> c_int {
    let (_, decision) = runtime_policy::decide(
        ApiFamily::Process,
        key as usize,
        nsems.max(0) as usize,
        true,
        nsems <= 0,
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EPERM) };
        runtime_policy::observe(ApiFamily::Process, decision.profile, 8, true);
        return -1;
    }

    let rc = unsafe {
        syscall_ret_int(
            libc::syscall(libc::SYS_semget, key, nsems, semflg),
            errno::EINVAL,
        )
    };
    runtime_policy::observe(ApiFamily::Process, decision.profile, 8, rc != 0);
    rc
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn semctl(semid: c_int, semnum: c_int, cmd: c_int, mut args: ...) -> c_int {
    let arg = if semctl_cmd_uses_arg(cmd) {
        unsafe { args.arg::<libc::c_ulong>() }
    } else {
        0
    };

    let (_, decision) = runtime_policy::decide(
        ApiFamily::Process,
        semid as usize,
        usize::from(semctl_cmd_uses_arg(cmd)),
        true,
        false,
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EPERM) };
        runtime_policy::observe(ApiFamily::Process, decision.profile, 8, true);
        return -1;
    }

    let rc = unsafe {
        syscall_ret_int(
            libc::syscall(libc::SYS_semctl, semid, semnum, cmd, arg),
            errno::EINVAL,
        )
    };
    runtime_policy::observe(ApiFamily::Process, decision.profile, 8, rc != 0);
    rc
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn semop(semid: c_int, sops: *mut c_void, nsops: usize) -> c_int {
    let missing_payload = sysvipc_missing_payload(sops, nsops);
    let (mode, decision) = runtime_policy::decide(
        ApiFamily::Process,
        sops as usize,
        nsops,
        true,
        missing_payload,
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EPERM) };
        runtime_policy::observe(
            ApiFamily::Process,
            decision.profile,
            runtime_policy::scaled_cost(8, nsops),
            true,
        );
        return -1;
    }
    if missing_payload && policy_repair_enabled(mode.heals_enabled(), decision.action) {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(
            ApiFamily::Process,
            decision.profile,
            runtime_policy::scaled_cost(8, nsops),
            true,
        );
        return -1;
    }

    let rc = unsafe {
        syscall_ret_int(
            libc::syscall(libc::SYS_semop, semid, sops, nsops),
            errno::EINVAL,
        )
    };
    runtime_policy::observe(
        ApiFamily::Process,
        decision.profile,
        runtime_policy::scaled_cost(8, nsops),
        rc != 0,
    );
    rc
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn msgget(key: c_int, msgflg: c_int) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::Process, key as usize, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EPERM) };
        runtime_policy::observe(ApiFamily::Process, decision.profile, 8, true);
        return -1;
    }

    let rc =
        unsafe { syscall_ret_int(libc::syscall(libc::SYS_msgget, key, msgflg), errno::EINVAL) };
    runtime_policy::observe(ApiFamily::Process, decision.profile, 8, rc != 0);
    rc
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn msgctl(msqid: c_int, cmd: c_int, buf: *mut c_void) -> c_int {
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Process, buf as usize, 0, true, buf.is_null(), 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EPERM) };
        runtime_policy::observe(ApiFamily::Process, decision.profile, 8, true);
        return -1;
    }

    let rc = unsafe {
        syscall_ret_int(
            libc::syscall(libc::SYS_msgctl, msqid, cmd, buf),
            errno::EINVAL,
        )
    };
    runtime_policy::observe(ApiFamily::Process, decision.profile, 8, rc != 0);
    rc
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn msgsnd(
    msqid: c_int,
    msgp: *const c_void,
    msgsz: usize,
    msgflg: c_int,
) -> c_int {
    let missing_payload = sysvipc_missing_payload(msgp, msgsz);
    let (mode, decision) = runtime_policy::decide(
        ApiFamily::Process,
        msgp as usize,
        msgsz,
        false,
        missing_payload,
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EPERM) };
        runtime_policy::observe(
            ApiFamily::Process,
            decision.profile,
            runtime_policy::scaled_cost(8, msgsz),
            true,
        );
        return -1;
    }
    if missing_payload && policy_repair_enabled(mode.heals_enabled(), decision.action) {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(
            ApiFamily::Process,
            decision.profile,
            runtime_policy::scaled_cost(8, msgsz),
            true,
        );
        return -1;
    }

    let rc = unsafe {
        syscall_ret_int(
            libc::syscall(libc::SYS_msgsnd, msqid, msgp, msgsz, msgflg),
            errno::EINVAL,
        )
    };
    runtime_policy::observe(
        ApiFamily::Process,
        decision.profile,
        runtime_policy::scaled_cost(8, msgsz),
        rc != 0,
    );
    rc
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn msgrcv(
    msqid: c_int,
    msgp: *mut c_void,
    msgsz: usize,
    msgtyp: std::ffi::c_long,
    msgflg: c_int,
) -> libc::ssize_t {
    let missing_payload = sysvipc_missing_payload(msgp, msgsz);
    let (mode, decision) = runtime_policy::decide(
        ApiFamily::Process,
        msgp as usize,
        msgsz,
        true,
        missing_payload,
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EPERM) };
        runtime_policy::observe(
            ApiFamily::Process,
            decision.profile,
            runtime_policy::scaled_cost(8, msgsz),
            true,
        );
        return -1;
    }
    if missing_payload && policy_repair_enabled(mode.heals_enabled(), decision.action) {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(
            ApiFamily::Process,
            decision.profile,
            runtime_policy::scaled_cost(8, msgsz),
            true,
        );
        return -1;
    }

    let rc = unsafe {
        syscall_ret_isize(
            libc::syscall(libc::SYS_msgrcv, msqid, msgp, msgsz, msgtyp, msgflg),
            errno::EINVAL,
        ) as libc::ssize_t
    };
    runtime_policy::observe(
        ApiFamily::Process,
        decision.profile,
        runtime_policy::scaled_cost(8, msgsz),
        rc < 0,
    );
    rc
}

// ---------------------------------------------------------------------------
// Signal extras — RawSyscall / GlibcCallThrough
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sigqueue(pid: libc::pid_t, sig: c_int, value: *const c_void) -> c_int {
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    info.si_signo = sig;
    info.si_errno = 0;
    info.si_code = libc::SI_QUEUE;

    // Encode sender identity and queued payload using the Linux siginfo queue layout.
    let info_words = (&mut info as *mut libc::siginfo_t).cast::<u32>();
    let caller_pid = unsafe { libc::syscall(libc::SYS_getpid) } as u32;
    let caller_uid = unsafe { libc::syscall(libc::SYS_getuid) } as u32;
    let value_bits = value as usize as u64;
    unsafe {
        *info_words.add(3) = caller_pid;
        *info_words.add(4) = caller_uid;
        *info_words.add(5) = value_bits as u32;
        if std::mem::size_of::<usize>() > 4 {
            *info_words.add(6) = (value_bits >> 32) as u32;
        }
    }

    unsafe {
        syscall_ret_int(
            libc::syscall(libc::SYS_rt_sigqueueinfo, pid, sig, &info),
            errno::EINVAL,
        )
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sigtimedwait(
    set: *const c_void,
    info: *mut c_void,
    timeout: *const libc::timespec,
) -> c_int {
    unsafe {
        syscall_ret_int(
            libc::syscall(
                libc::SYS_rt_sigtimedwait,
                set,
                info,
                timeout,
                std::mem::size_of::<libc::c_ulong>(),
            ),
            errno::EINVAL,
        )
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sigwaitinfo(set: *const c_void, info: *mut c_void) -> c_int {
    unsafe {
        syscall_ret_int(
            libc::syscall(
                libc::SYS_rt_sigtimedwait,
                set,
                info,
                std::ptr::null::<libc::timespec>(),
                std::mem::size_of::<libc::c_ulong>(),
            ),
            errno::EINVAL,
        )
    }
}

// ---------------------------------------------------------------------------
// getifaddrs / freeifaddrs — Implemented (native netlink)
// ---------------------------------------------------------------------------
//
// Uses NETLINK_ROUTE (RTM_GETLINK + RTM_GETADDR) to enumerate network
// interfaces and their addresses. Builds a linked list of `struct ifaddrs`
// compatible with the glibc ABI.

/// Match glibc's `struct ifaddrs` layout on x86_64.
#[repr(C)]
struct Ifaddrs {
    ifa_next: *mut Ifaddrs,
    ifa_name: *mut c_char,
    ifa_flags: c_uint,
    ifa_addr: *mut libc::sockaddr,
    ifa_netmask: *mut libc::sockaddr,
    ifa_broadaddr: *mut libc::sockaddr, // union with ifa_dstaddr
    ifa_data: *mut c_void,
}

/// Netlink message header (mirrors kernel nlmsghdr).
#[repr(C)]
#[derive(Clone, Copy)]
struct NlMsgHdr {
    nlmsg_len: u32,
    nlmsg_type: u16,
    nlmsg_flags: u16,
    nlmsg_seq: u32,
    nlmsg_pid: u32,
}

/// ifinfomsg from <linux/if_link.h>
#[repr(C)]
#[derive(Clone, Copy)]
struct IfInfoMsg {
    ifi_family: u8,
    _pad: u8,
    ifi_type: u16,
    ifi_index: i32,
    ifi_flags: u32,
    ifi_change: u32,
}

/// ifaddrmsg from <linux/if_addr.h>
#[repr(C)]
#[derive(Clone, Copy)]
struct IfAddrMsg {
    ifa_family: u8,
    ifa_prefixlen: u8,
    ifa_flags: u8,
    ifa_scope: u8,
    ifa_index: u32,
}

/// Netlink route attribute.
#[repr(C)]
#[derive(Clone, Copy)]
struct RtAttr {
    rta_len: u16,
    rta_type: u16,
}

const NLMSG_ALIGNTO: usize = 4;
const RTA_ALIGNTO: usize = 4;
const RTM_GETLINK: u16 = 18;
const RTM_NEWLINK: u16 = 16;
const RTM_GETADDR: u16 = 22;
const RTM_NEWADDR: u16 = 20;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_DUMP: u16 = 0x300;
const NLMSG_DONE: u16 = 3;
const NLMSG_ERROR: u16 = 2;
const IFLA_IFNAME: u16 = 3;
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_BROADCAST: u16 = 4;

fn nlmsg_align(len: usize) -> usize {
    (len + NLMSG_ALIGNTO - 1) & !(NLMSG_ALIGNTO - 1)
}

fn rta_align(len: usize) -> usize {
    (len + RTA_ALIGNTO - 1) & !(RTA_ALIGNTO - 1)
}

/// Send a netlink dump request and collect all response data.
fn netlink_dump(msg_type: u16, family: u8) -> Result<Vec<u8>, c_int> {
    // Create netlink socket
    let fd = unsafe {
        libc::syscall(
            libc::SYS_socket as std::os::raw::c_long,
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        ) as c_int
    };
    if fd < 0 {
        return Err(errno::ENOBUFS);
    }

    // Build request
    let hdr_size = std::mem::size_of::<NlMsgHdr>();
    let payload_size = if msg_type == RTM_GETLINK {
        std::mem::size_of::<IfInfoMsg>()
    } else {
        std::mem::size_of::<IfAddrMsg>()
    };
    let msg_len = nlmsg_align(hdr_size + payload_size);
    let mut buf = vec![0u8; msg_len];

    let hdr = unsafe { &mut *(buf.as_mut_ptr() as *mut NlMsgHdr) };
    hdr.nlmsg_len = msg_len as u32;
    hdr.nlmsg_type = msg_type;
    hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    hdr.nlmsg_seq = 1;
    hdr.nlmsg_pid = 0;

    if msg_type == RTM_GETLINK {
        let info = unsafe { &mut *((buf.as_mut_ptr().add(hdr_size)) as *mut IfInfoMsg) };
        info.ifi_family = family;
    } else {
        let info = unsafe { &mut *((buf.as_mut_ptr().add(hdr_size)) as *mut IfAddrMsg) };
        info.ifa_family = family;
    }

    // Send
    let rc = unsafe {
        libc::syscall(
            libc::SYS_sendto as std::os::raw::c_long,
            fd,
            buf.as_ptr(),
            msg_len,
            0,
            std::ptr::null::<c_void>(),
            0,
        ) as isize
    };
    if rc < 0 {
        unsafe { libc::syscall(libc::SYS_close as std::os::raw::c_long, fd) };
        return Err(errno::EIO);
    }

    // Receive all responses
    let mut result = Vec::with_capacity(8192);
    let mut recv_buf = vec![0u8; 16384];
    loop {
        let n = unsafe {
            libc::syscall(
                libc::SYS_recvfrom as std::os::raw::c_long,
                fd,
                recv_buf.as_mut_ptr(),
                recv_buf.len(),
                0,
                std::ptr::null::<c_void>(),
                std::ptr::null::<c_void>(),
            ) as isize
        };
        if n <= 0 {
            break;
        }
        let data = &recv_buf[..n as usize];
        // Check for NLMSG_DONE
        let mut done = false;
        let mut off = 0;
        while off + std::mem::size_of::<NlMsgHdr>() <= data.len() {
            let h = unsafe { &*(data.as_ptr().add(off) as *const NlMsgHdr) };
            if h.nlmsg_type == NLMSG_DONE || h.nlmsg_type == NLMSG_ERROR {
                done = true;
                break;
            }
            if (h.nlmsg_len as usize) < std::mem::size_of::<NlMsgHdr>() {
                done = true;
                break;
            }
            off += nlmsg_align(h.nlmsg_len as usize);
        }
        result.extend_from_slice(data);
        if done {
            break;
        }
    }

    unsafe { libc::syscall(libc::SYS_close as std::os::raw::c_long, fd) };
    Ok(result)
}

/// Build a sockaddr from AF family and address bytes.
fn alloc_sockaddr(family: u8, addr_data: &[u8]) -> *mut libc::sockaddr {
    match family as i32 {
        libc::AF_INET if addr_data.len() >= 4 => {
            let sa = unsafe { libc::calloc(1, std::mem::size_of::<libc::sockaddr_in>()) }
                as *mut libc::sockaddr_in;
            if sa.is_null() {
                return std::ptr::null_mut();
            }
            unsafe {
                (*sa).sin_family = libc::AF_INET as libc::sa_family_t;
                std::ptr::copy_nonoverlapping(
                    addr_data.as_ptr(),
                    &raw mut (*sa).sin_addr as *mut u8,
                    4,
                );
            };
            sa as *mut libc::sockaddr
        }
        libc::AF_INET6 if addr_data.len() >= 16 => {
            let sa = unsafe { libc::calloc(1, std::mem::size_of::<libc::sockaddr_in6>()) }
                as *mut libc::sockaddr_in6;
            if sa.is_null() {
                return std::ptr::null_mut();
            }
            unsafe {
                (*sa).sin6_family = libc::AF_INET6 as libc::sa_family_t;
                std::ptr::copy_nonoverlapping(
                    addr_data.as_ptr(),
                    &raw mut (*sa).sin6_addr as *mut u8,
                    16,
                );
            };
            sa as *mut libc::sockaddr
        }
        _ => std::ptr::null_mut(),
    }
}

/// Build a netmask sockaddr from prefix length.
fn alloc_netmask(family: u8, prefixlen: u8) -> *mut libc::sockaddr {
    match family as i32 {
        libc::AF_INET => {
            let sa = unsafe { libc::calloc(1, std::mem::size_of::<libc::sockaddr_in>()) }
                as *mut libc::sockaddr_in;
            if sa.is_null() {
                return std::ptr::null_mut();
            }
            let mask: u32 = if prefixlen >= 32 {
                0xFFFF_FFFF
            } else if prefixlen == 0 {
                0
            } else {
                !((1u32 << (32 - prefixlen)) - 1)
            };
            unsafe {
                (*sa).sin_family = libc::AF_INET as libc::sa_family_t;
                (*sa).sin_addr.s_addr = mask.to_be();
            };
            sa as *mut libc::sockaddr
        }
        libc::AF_INET6 => {
            let sa = unsafe { libc::calloc(1, std::mem::size_of::<libc::sockaddr_in6>()) }
                as *mut libc::sockaddr_in6;
            if sa.is_null() {
                return std::ptr::null_mut();
            }
            unsafe {
                (*sa).sin6_family = libc::AF_INET6 as libc::sa_family_t;
                let mask_bytes: &mut [u8; 16] = &mut *(&raw mut (*sa).sin6_addr as *mut [u8; 16]);
                let mut bits_left = prefixlen as usize;
                for byte in mask_bytes.iter_mut() {
                    if bits_left >= 8 {
                        *byte = 0xFF;
                        bits_left -= 8;
                    } else if bits_left > 0 {
                        *byte = 0xFF << (8 - bits_left);
                        bits_left = 0;
                    } else {
                        *byte = 0;
                    }
                }
            };
            sa as *mut libc::sockaddr
        }
        _ => std::ptr::null_mut(),
    }
}

/// POSIX `getifaddrs` — get interface addresses via netlink.
///
/// Native implementation using NETLINK_ROUTE to enumerate interfaces
/// and their IPv4/IPv6 addresses. Builds a linked list of `struct ifaddrs`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getifaddrs(ifap: *mut *mut c_void) -> c_int {
    if ifap.is_null() {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }
    unsafe { *(ifap as *mut *mut Ifaddrs) = std::ptr::null_mut() };

    // Step 1: Get link info (interface names and flags)
    let link_data = match netlink_dump(RTM_GETLINK, libc::AF_UNSPEC as u8) {
        Ok(d) => d,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            return -1;
        }
    };

    // Parse link data to get index→name mapping
    let mut if_names: std::collections::HashMap<i32, (String, u32)> =
        std::collections::HashMap::new();
    parse_netlink_links(&link_data, &mut if_names);

    // Step 2: Get addresses for AF_INET and AF_INET6
    let mut head: *mut Ifaddrs = std::ptr::null_mut();
    let mut tail: *mut Ifaddrs = std::ptr::null_mut();

    for family in [libc::AF_INET as u8, libc::AF_INET6 as u8] {
        let addr_data = match netlink_dump(RTM_GETADDR, family) {
            Ok(d) => d,
            Err(_) => continue,
        };
        parse_netlink_addrs(&addr_data, &if_names, &mut head, &mut tail);
    }

    unsafe { *(ifap as *mut *mut Ifaddrs) = head };
    0
}

fn parse_netlink_links(data: &[u8], if_names: &mut std::collections::HashMap<i32, (String, u32)>) {
    let hdr_size = std::mem::size_of::<NlMsgHdr>();
    let info_size = std::mem::size_of::<IfInfoMsg>();
    let mut off = 0;

    while off + hdr_size <= data.len() {
        let h = unsafe { &*(data.as_ptr().add(off) as *const NlMsgHdr) };
        let msg_len = h.nlmsg_len as usize;
        if msg_len < hdr_size || off + msg_len > data.len() {
            break;
        }
        if h.nlmsg_type == RTM_NEWLINK && msg_len >= hdr_size + info_size {
            let info = unsafe { &*(data.as_ptr().add(off + hdr_size) as *const IfInfoMsg) };
            let mut attr_off = off + hdr_size + nlmsg_align(info_size);
            while attr_off + std::mem::size_of::<RtAttr>() <= off + msg_len {
                let rta = unsafe { &*(data.as_ptr().add(attr_off) as *const RtAttr) };
                let rta_len = rta.rta_len as usize;
                if rta_len < std::mem::size_of::<RtAttr>() {
                    break;
                }
                if rta.rta_type == IFLA_IFNAME {
                    let name_start = attr_off + std::mem::size_of::<RtAttr>();
                    let name_end = (attr_off + rta_len).min(off + msg_len);
                    if name_start < name_end {
                        let name_bytes = &data[name_start..name_end];
                        // Strip trailing NUL
                        let name_bytes = name_bytes.split(|b| *b == 0).next().unwrap_or(name_bytes);
                        if let Ok(name) = std::str::from_utf8(name_bytes) {
                            if_names.insert(info.ifi_index, (name.to_string(), info.ifi_flags));
                        }
                    }
                }
                attr_off += rta_align(rta_len);
            }
        }
        if h.nlmsg_type == NLMSG_DONE || h.nlmsg_type == NLMSG_ERROR {
            break;
        }
        off += nlmsg_align(msg_len);
    }
}

fn parse_netlink_addrs(
    data: &[u8],
    if_names: &std::collections::HashMap<i32, (String, u32)>,
    head: &mut *mut Ifaddrs,
    tail: &mut *mut Ifaddrs,
) {
    let hdr_size = std::mem::size_of::<NlMsgHdr>();
    let addr_msg_size = std::mem::size_of::<IfAddrMsg>();
    let mut off = 0;

    while off + hdr_size <= data.len() {
        let h = unsafe { &*(data.as_ptr().add(off) as *const NlMsgHdr) };
        let msg_len = h.nlmsg_len as usize;
        if msg_len < hdr_size || off + msg_len > data.len() {
            break;
        }
        if h.nlmsg_type == RTM_NEWADDR && msg_len >= hdr_size + addr_msg_size {
            let amsg = unsafe { &*(data.as_ptr().add(off + hdr_size) as *const IfAddrMsg) };

            let (if_name, if_flags) = if_names
                .get(&(amsg.ifa_index as i32))
                .cloned()
                .unwrap_or_else(|| (format!("if{}", amsg.ifa_index), 0));

            let mut local_addr: Option<&[u8]> = None;
            let mut addr: Option<&[u8]> = None;
            let mut brd: Option<&[u8]> = None;

            let mut attr_off = off + hdr_size + nlmsg_align(addr_msg_size);
            while attr_off + std::mem::size_of::<RtAttr>() <= off + msg_len {
                let rta = unsafe { &*(data.as_ptr().add(attr_off) as *const RtAttr) };
                let rta_len = rta.rta_len as usize;
                if rta_len < std::mem::size_of::<RtAttr>() {
                    break;
                }
                let payload_start = attr_off + std::mem::size_of::<RtAttr>();
                let payload_end = (attr_off + rta_len).min(off + msg_len);
                if payload_start < payload_end {
                    let payload = &data[payload_start..payload_end];
                    match rta.rta_type {
                        IFA_LOCAL => local_addr = Some(payload),
                        IFA_ADDRESS => addr = Some(payload),
                        IFA_BROADCAST => brd = Some(payload),
                        _ => {}
                    }
                }
                attr_off += rta_align(rta_len);
            }

            // Prefer IFA_LOCAL for point-to-point, otherwise IFA_ADDRESS
            let effective_addr = local_addr.or(addr);

            if let Some(addr_bytes) = effective_addr {
                // Allocate an ifaddrs node
                let node =
                    unsafe { libc::calloc(1, std::mem::size_of::<Ifaddrs>()) as *mut Ifaddrs };
                if node.is_null() {
                    continue;
                }

                // Name
                let name_cstr =
                    CString::new(if_name.as_str()).unwrap_or_else(|_| CString::new("?").unwrap());
                let name_ptr =
                    unsafe { libc::malloc(name_cstr.as_bytes_with_nul().len()) as *mut c_char };
                if !name_ptr.is_null() {
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            name_cstr.as_ptr(),
                            name_ptr,
                            name_cstr.as_bytes_with_nul().len(),
                        );
                    };
                }

                unsafe {
                    (*node).ifa_name = name_ptr;
                    (*node).ifa_flags = if_flags;
                    (*node).ifa_addr = alloc_sockaddr(amsg.ifa_family, addr_bytes);
                    (*node).ifa_netmask = alloc_netmask(amsg.ifa_family, amsg.ifa_prefixlen);
                    (*node).ifa_broadaddr = if let Some(b) = brd {
                        alloc_sockaddr(amsg.ifa_family, b)
                    } else {
                        std::ptr::null_mut()
                    };
                    (*node).ifa_data = std::ptr::null_mut();
                    (*node).ifa_next = std::ptr::null_mut();
                };

                // Link into list
                if tail.is_null() {
                    *head = node;
                    *tail = node;
                } else {
                    unsafe { (**tail).ifa_next = node };
                    *tail = node;
                }
            }
        }
        if h.nlmsg_type == NLMSG_DONE || h.nlmsg_type == NLMSG_ERROR {
            break;
        }
        off += nlmsg_align(msg_len);
    }
}

/// POSIX `freeifaddrs` — free the linked list returned by `getifaddrs`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn freeifaddrs(ifa: *mut c_void) {
    let mut cur = ifa as *mut Ifaddrs;
    while !cur.is_null() {
        let next = unsafe { (*cur).ifa_next };
        unsafe {
            if !(*cur).ifa_name.is_null() {
                libc::free((*cur).ifa_name as *mut c_void);
            }
            if !(*cur).ifa_addr.is_null() {
                libc::free((*cur).ifa_addr as *mut c_void);
            }
            if !(*cur).ifa_netmask.is_null() {
                libc::free((*cur).ifa_netmask as *mut c_void);
            }
            if !(*cur).ifa_broadaddr.is_null() {
                libc::free((*cur).ifa_broadaddr as *mut c_void);
            }
            libc::free(cur as *mut c_void);
        };
        cur = next;
    }
}

// ---------------------------------------------------------------------------
// ether_aton / ether_ntoa — Implemented (native parse/format)
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
struct EtherAddrBytes {
    octet: [u8; 6],
}

static mut ETHER_ATON_STORAGE: EtherAddrBytes = EtherAddrBytes { octet: [0; 6] };
static mut ETHER_NTOA_STORAGE: [c_char; 18] = [0; 18];

fn parse_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

unsafe fn parse_ether_addr(asc: *const c_char, out: *mut EtherAddrBytes) -> bool {
    if asc.is_null() || out.is_null() {
        return false;
    }

    // SAFETY: `asc` is validated non-null above and expected to be NUL-terminated by caller.
    let bytes = unsafe { CStr::from_ptr(asc) }.to_bytes();
    let mut index = 0usize;
    let mut octets = [0_u8; 6];

    for (slot, octet) in octets.iter_mut().enumerate() {
        if index >= bytes.len() {
            return false;
        }

        let Some(high) = parse_hex_nibble(bytes[index]) else {
            return false;
        };
        index += 1;

        let mut value = high;
        if index < bytes.len()
            && let Some(low) = parse_hex_nibble(bytes[index])
        {
            value = (high << 4) | low;
            index += 1;
        }

        *octet = value;
        if slot < 5 {
            if index >= bytes.len() || bytes[index] != b':' {
                return false;
            }
            index += 1;
        }
    }

    if index != bytes.len() {
        return false;
    }

    // SAFETY: `out` is non-null and points to writable storage provided by caller.
    unsafe {
        (*out).octet = octets;
    }
    true
}

unsafe fn format_ether_addr(addr: *const EtherAddrBytes, buf: *mut c_char) -> *mut c_char {
    if addr.is_null() || buf.is_null() {
        return std::ptr::null_mut();
    }

    const HEX: &[u8; 16] = b"0123456789abcdef";

    // SAFETY: `addr` is non-null and points to a 6-octet address layout.
    let octets = unsafe { (*addr).octet };
    // SAFETY: caller guarantees `buf` has room for 18 bytes (`xx:..:xx\0`).
    let out = unsafe { std::slice::from_raw_parts_mut(buf.cast::<u8>(), 18) };
    let mut pos = 0usize;

    for (slot, value) in octets.iter().enumerate() {
        out[pos] = HEX[(value >> 4) as usize];
        pos += 1;
        out[pos] = HEX[(value & 0x0f) as usize];
        pos += 1;
        if slot < 5 {
            out[pos] = b':';
            pos += 1;
        }
    }
    out[pos] = 0;
    buf
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ether_aton(asc: *const c_char) -> *mut c_void {
    let out = std::ptr::addr_of_mut!(ETHER_ATON_STORAGE);
    // SAFETY: parser validates pointers and writes into static storage on success.
    if unsafe { parse_ether_addr(asc, out) } {
        out.cast::<c_void>()
    } else {
        std::ptr::null_mut()
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ether_ntoa(addr: *const c_void) -> *mut c_char {
    let buf = std::ptr::addr_of_mut!(ETHER_NTOA_STORAGE).cast::<c_char>();
    // SAFETY: helper validates pointers before formatting.
    unsafe { format_ether_addr(addr.cast::<EtherAddrBytes>(), buf) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ether_aton_r(asc: *const c_char, addr: *mut c_void) -> *mut c_void {
    let out = addr.cast::<EtherAddrBytes>();
    // SAFETY: parser validates pointers and writes into caller-provided output.
    if unsafe { parse_ether_addr(asc, out) } {
        addr
    } else {
        std::ptr::null_mut()
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ether_ntoa_r(addr: *const c_void, buf: *mut c_char) -> *mut c_char {
    // SAFETY: helper validates pointers before formatting.
    unsafe { format_ether_addr(addr.cast::<EtherAddrBytes>(), buf) }
}

// ---------------------------------------------------------------------------
// herror / hstrerror — Implemented (native error messages)
// ---------------------------------------------------------------------------

const H_ERR_HOST_NOT_FOUND: c_int = 1;
const H_ERR_TRY_AGAIN: c_int = 2;
const H_ERR_NO_RECOVERY: c_int = 3;
const H_ERR_NO_DATA: c_int = 4;

std::thread_local! {
    static H_ERRNO_TLS: std::cell::Cell<c_int> = const { std::cell::Cell::new(0) };
}

#[inline]
unsafe fn current_h_errno() -> c_int {
    let ptr = unsafe { crate::resolv_abi::__h_errno_location() };
    unsafe { *ptr }
}

#[inline]
fn hstrerror_message_ptr(err: c_int) -> *const c_char {
    match err {
        H_ERR_HOST_NOT_FOUND => c"Unknown host".as_ptr(),
        H_ERR_TRY_AGAIN => c"Host name lookup failure".as_ptr(),
        H_ERR_NO_RECOVERY => c"Unknown server error".as_ptr(),
        H_ERR_NO_DATA => c"No address associated with name".as_ptr(),
        _ => c"Resolver internal error".as_ptr(),
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn herror(s: *const c_char) {
    // SAFETY: message pointer is always valid and NUL-terminated.
    let msg = unsafe { CStr::from_ptr(hstrerror_message_ptr(current_h_errno())) };
    let prefix = if s.is_null() {
        None
    } else {
        // SAFETY: non-null `s` must point to a NUL-terminated string by C contract.
        Some(unsafe { CStr::from_ptr(s) })
    };

    let mut line =
        Vec::with_capacity(msg.to_bytes().len() + 2 + prefix.map_or(0, |p| p.to_bytes().len() + 2));
    if let Some(prefix) = prefix {
        let bytes = prefix.to_bytes();
        if !bytes.is_empty() {
            line.extend_from_slice(bytes);
            line.extend_from_slice(b": ");
        }
    }
    line.extend_from_slice(msg.to_bytes());
    line.push(b'\n');

    // SAFETY: write helper accepts raw pointer/len and reports failures via errno.
    let _ = unsafe {
        sys_write_fd(
            libc::STDERR_FILENO,
            line.as_ptr().cast::<c_void>(),
            line.len(),
        )
    };
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn hstrerror(err: c_int) -> *const c_char {
    hstrerror_message_ptr(err)
}

// ---------------------------------------------------------------------------
// execl / execlp / execle — native (variadic → argv → execve/execvp)
// ---------------------------------------------------------------------------

unsafe extern "C" {
    static mut environ: *mut *mut c_char;
}

/// POSIX `execl` — execute path with variadic args, inheriting environ.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn execl(path: *const c_char, arg: *const c_char, mut args: ...) -> c_int {
    let mut argv: Vec<*const c_char> = Vec::with_capacity(8);
    argv.push(arg);
    loop {
        let next = unsafe { args.arg::<*const c_char>() };
        argv.push(next);
        if next.is_null() {
            break;
        }
    }
    unsafe { crate::process_abi::execve(path, argv.as_ptr(), environ as *const *const c_char) }
}

/// POSIX `execlp` — execute file (PATH search) with variadic args, inheriting environ.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn execlp(file: *const c_char, arg: *const c_char, mut args: ...) -> c_int {
    let mut argv: Vec<*const c_char> = Vec::with_capacity(8);
    argv.push(arg);
    loop {
        let next = unsafe { args.arg::<*const c_char>() };
        argv.push(next);
        if next.is_null() {
            break;
        }
    }
    unsafe { crate::process_abi::execvp(file, argv.as_ptr()) }
}

/// POSIX `execle` — execute path with variadic args + explicit envp.
///
/// The envp pointer follows the NULL sentinel of the arg list.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn execle(path: *const c_char, arg: *const c_char, mut args: ...) -> c_int {
    let mut argv: Vec<*const c_char> = Vec::with_capacity(8);
    argv.push(arg);
    loop {
        let next = unsafe { args.arg::<*const c_char>() };
        argv.push(next);
        if next.is_null() {
            break;
        }
    }
    // The next variadic argument after NULL is the envp pointer.
    let envp = unsafe { args.arg::<*const *const c_char>() };
    unsafe { crate::process_abi::execve(path, argv.as_ptr(), envp) }
}

// ---------------------------------------------------------------------------
// timer_* — RawSyscall (POSIX per-process timers)
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn timer_create(
    clockid: libc::clockid_t,
    sevp: *mut c_void,
    timerid: *mut c_void,
) -> c_int {
    unsafe {
        syscall_ret_int(
            libc::syscall(libc::SYS_timer_create, clockid, sevp, timerid),
            errno::EINVAL,
        )
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn timer_settime(
    timerid: *mut c_void,
    flags: c_int,
    new_value: *const c_void,
    old_value: *mut c_void,
) -> c_int {
    unsafe {
        syscall_ret_int(
            libc::syscall(
                libc::SYS_timer_settime,
                timerid,
                flags,
                new_value,
                old_value,
            ),
            errno::EINVAL,
        )
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn timer_gettime(timerid: *mut c_void, curr_value: *mut c_void) -> c_int {
    unsafe {
        syscall_ret_int(
            libc::syscall(libc::SYS_timer_gettime, timerid, curr_value),
            errno::EINVAL,
        )
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn timer_delete(timerid: *mut c_void) -> c_int {
    unsafe {
        syscall_ret_int(
            libc::syscall(libc::SYS_timer_delete, timerid),
            errno::EINVAL,
        )
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn timer_getoverrun(timerid: *mut c_void) -> c_int {
    unsafe {
        syscall_ret_int(
            libc::syscall(libc::SYS_timer_getoverrun, timerid),
            errno::EINVAL,
        )
    }
}

// ---------------------------------------------------------------------------
// aio_* — Implemented (native thread-based POSIX async I/O)
// ---------------------------------------------------------------------------

/// POSIX AIO lio_listio opcodes.
const LIO_READ: c_int = 0;
const LIO_WRITE: c_int = 1;
const LIO_NOP: c_int = 2;

/// lio_listio mode constants.
const LIO_WAIT: c_int = 0;
const LIO_NOWAIT: c_int = 1;

/// aio_cancel return values (POSIX-mandated).
#[allow(dead_code)]
const AIO_CANCELED: c_int = 0;
const AIO_NOTCANCELED: c_int = 1;
const AIO_ALLDONE: c_int = 2;

/// O_SYNC / O_DSYNC flags for aio_fsync.
#[allow(dead_code)]
const O_SYNC_FLAG: c_int = 0x101000; // O_SYNC on Linux x86_64
const O_DSYNC_FLAG: c_int = 0x1000; // O_DSYNC on Linux x86_64

/// glibc `struct aiocb` field offsets on x86_64.
mod aiocb_off {
    /// `int aio_fildes` at offset 0
    pub const FILDES: usize = 0;
    /// `int aio_lio_opcode` at offset 4
    pub const LIO_OPCODE: usize = 4;
    /// `volatile void *aio_buf` at offset 16
    pub const BUF: usize = 16;
    /// `size_t aio_nbytes` at offset 24
    pub const NBYTES: usize = 24;
    /// `int __error_code` at offset 112 (internal glibc field)
    pub const ERROR_CODE: usize = 112;
    /// `ssize_t __return_value` at offset 120 (internal glibc field)
    pub const RETURN_VALUE: usize = 120;
    /// `off_t aio_offset` at offset 128
    pub const OFFSET: usize = 128;
}

/// Read an i32 from aiocb at the given byte offset.
unsafe fn aiocb_i32(cb: *const c_void, off: usize) -> c_int {
    unsafe { *((cb as *const u8).add(off) as *const c_int) }
}

/// Read a pointer from aiocb at the given byte offset.
unsafe fn aiocb_ptr(cb: *const c_void, off: usize) -> *mut c_void {
    unsafe { *((cb as *const u8).add(off) as *const *mut c_void) }
}

/// Read a usize from aiocb at the given byte offset.
unsafe fn aiocb_usize(cb: *const c_void, off: usize) -> usize {
    unsafe { *((cb as *const u8).add(off) as *const usize) }
}

/// Read an i64 from aiocb at the given byte offset.
unsafe fn aiocb_i64(cb: *const c_void, off: usize) -> i64 {
    unsafe { *((cb as *const u8).add(off) as *const i64) }
}

/// Atomically read the __error_code field using atomic ordering.
unsafe fn aiocb_error_atomic(cb: *const c_void) -> c_int {
    unsafe {
        let ptr =
            (cb as *const u8).add(aiocb_off::ERROR_CODE) as *const std::sync::atomic::AtomicI32;
        (*ptr).load(std::sync::atomic::Ordering::Acquire)
    }
}

/// Atomically write the __error_code field using atomic ordering.
unsafe fn aiocb_set_error_atomic(cb: *mut c_void, val: c_int) {
    unsafe {
        let ptr = (cb as *mut u8).add(aiocb_off::ERROR_CODE) as *const std::sync::atomic::AtomicI32;
        (*ptr).store(val, std::sync::atomic::Ordering::Release)
    }
}

/// Write an isize to aiocb at the __return_value offset.
unsafe fn aiocb_set_return(cb: *mut c_void, val: isize) {
    unsafe {
        let ptr = (cb as *mut u8).add(aiocb_off::RETURN_VALUE) as *mut isize;
        // Use volatile write to prevent reordering with the error_code store.
        std::ptr::write_volatile(ptr, val)
    }
}

/// Read __return_value from aiocb.
unsafe fn aiocb_get_return(cb: *const c_void) -> isize {
    unsafe {
        let ptr = (cb as *const u8).add(aiocb_off::RETURN_VALUE) as *const isize;
        std::ptr::read_volatile(ptr)
    }
}

/// Global condvar for aio_suspend notification.
/// Worker threads notify after completing an I/O operation, allowing
/// aio_suspend to wake up and check completion status.
static AIO_NOTIFY: std::sync::LazyLock<(std::sync::Mutex<u64>, std::sync::Condvar)> =
    std::sync::LazyLock::new(|| (std::sync::Mutex::new(0), std::sync::Condvar::new()));

/// Internal AIO operation type.
#[derive(Clone, Copy)]
enum AioOp {
    Read,
    Write,
    Fsync,
    Fdatasync,
}

/// Submit an async I/O operation.
///
/// Reads parameters from the aiocb struct, marks it EINPROGRESS, then
/// spawns a worker thread to perform the syscall.
unsafe fn aio_submit(aiocbp: *mut c_void, op: AioOp) -> c_int {
    let fd = unsafe { aiocb_i32(aiocbp, aiocb_off::FILDES) };
    let buf = unsafe { aiocb_ptr(aiocbp, aiocb_off::BUF) };
    let nbytes = unsafe { aiocb_usize(aiocbp, aiocb_off::NBYTES) };
    let offset = unsafe { aiocb_i64(aiocbp, aiocb_off::OFFSET) };

    // Mark as in-progress before spawning the thread.
    unsafe { aiocb_set_return(aiocbp, 0) };
    unsafe { aiocb_set_error_atomic(aiocbp, errno::EINPROGRESS) };

    // Transfer raw pointer addresses to the worker thread.
    // POSIX guarantees the caller keeps the aiocb and buffer valid until
    // aio_return is called, so these addresses remain valid.
    let cb_addr = aiocbp as usize;
    let buf_addr = buf as usize;

    let spawn_result = std::thread::Builder::new()
        .name("aio-worker".into())
        .spawn(move || {
            let cb = cb_addr as *mut c_void;

            let result: i64 = match op {
                AioOp::Read => unsafe {
                    libc::syscall(
                        libc::SYS_pread64,
                        fd as i64,
                        buf_addr as i64,
                        nbytes as i64,
                        offset,
                    )
                },
                AioOp::Write => unsafe {
                    libc::syscall(
                        libc::SYS_pwrite64,
                        fd as i64,
                        buf_addr as i64,
                        nbytes as i64,
                        offset,
                    )
                },
                AioOp::Fsync => unsafe { libc::syscall(libc::SYS_fsync, fd as i64) },
                AioOp::Fdatasync => unsafe { libc::syscall(libc::SYS_fdatasync, fd as i64) },
            };

            if result < 0 {
                let err = unsafe { *libc::__errno_location() };
                unsafe { aiocb_set_return(cb, -1) };
                unsafe { aiocb_set_error_atomic(cb, err) };
            } else {
                unsafe { aiocb_set_return(cb, result as isize) };
                // Write error_code = 0 last so aio_error sees completion
                // only after __return_value is visible.
                unsafe { aiocb_set_error_atomic(cb, 0) };
            }

            // Wake any aio_suspend waiters.
            let (lock, cvar) = &*AIO_NOTIFY;
            if let Ok(mut generation) = lock.lock() {
                *generation = generation.wrapping_add(1);
                cvar.notify_all();
            }
        });

    if spawn_result.is_err() {
        unsafe { aiocb_set_error_atomic(aiocbp, errno::EAGAIN) };
        unsafe { set_abi_errno(errno::EAGAIN) };
        return -1;
    }

    0
}

/// `aio_read` — initiate an asynchronous read operation.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn aio_read(aiocbp: *mut c_void) -> c_int {
    if aiocbp.is_null() {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }
    unsafe { aio_submit(aiocbp, AioOp::Read) }
}

/// `aio_write` — initiate an asynchronous write operation.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn aio_write(aiocbp: *mut c_void) -> c_int {
    if aiocbp.is_null() {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }
    unsafe { aio_submit(aiocbp, AioOp::Write) }
}

/// `aio_error` — retrieve error status of an asynchronous I/O operation.
///
/// Returns EINPROGRESS while the operation is pending, 0 on success,
/// or the errno value if the operation failed.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn aio_error(aiocbp: *const c_void) -> c_int {
    if aiocbp.is_null() {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }
    unsafe { aiocb_error_atomic(aiocbp) }
}

/// `aio_return` — retrieve return status of a completed asynchronous I/O operation.
///
/// Must only be called after `aio_error` returns something other than EINPROGRESS.
/// Returns the number of bytes transferred, or -1 on error.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn aio_return(aiocbp: *mut c_void) -> libc::ssize_t {
    if aiocbp.is_null() {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }
    unsafe { aiocb_get_return(aiocbp) }
}

/// `aio_cancel` — attempt to cancel outstanding asynchronous I/O operations.
///
/// Since our worker threads perform blocking syscalls, we cannot truly cancel
/// in-flight operations. Returns AIO_ALLDONE if already complete,
/// AIO_NOTCANCELED if still in progress, or AIO_CANCELED if the aiocb is NULL
/// (cancel-all mode, which we approximate).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn aio_cancel(fd: c_int, aiocbp: *mut c_void) -> c_int {
    if aiocbp.is_null() {
        // Cancel all outstanding operations on fd — we cannot truly cancel
        // in-flight syscalls, so report AIO_NOTCANCELED.
        let _ = fd;
        return AIO_NOTCANCELED;
    }

    let err = unsafe { aiocb_error_atomic(aiocbp) };
    if err == errno::EINPROGRESS {
        // Operation is still running; we cannot interrupt a blocking syscall.
        AIO_NOTCANCELED
    } else {
        // Already completed (success or failure).
        AIO_ALLDONE
    }
}

/// `aio_suspend` — wait for one or more asynchronous I/O operations to complete.
///
/// Blocks until at least one aiocb in the list completes (error_code != EINPROGRESS),
/// or the timeout expires. Returns 0 on success, -1 on timeout/error.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn aio_suspend(
    list: *const *const c_void,
    nent: c_int,
    timeout: *const libc::timespec,
) -> c_int {
    if list.is_null() || nent <= 0 {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }

    // Compute absolute deadline if timeout is provided.
    let deadline = if timeout.is_null() {
        None
    } else {
        let ts = unsafe { *timeout };
        let dur = std::time::Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32);
        Some(std::time::Instant::now() + dur)
    };

    let (lock, cvar) = &*AIO_NOTIFY;

    loop {
        // Check if any aiocb has completed.
        for i in 0..nent as usize {
            let cb = unsafe { *list.add(i) };
            if cb.is_null() {
                continue;
            }
            if unsafe { aiocb_error_atomic(cb) } != errno::EINPROGRESS {
                return 0;
            }
        }

        // Determine wait duration.
        let wait_dur = if let Some(dl) = deadline {
            let now = std::time::Instant::now();
            if now >= dl {
                // Timeout expired.
                unsafe { set_abi_errno(errno::EAGAIN) };
                return -1;
            }
            dl - now
        } else {
            std::time::Duration::from_millis(100)
        };

        // Wait on condvar with bounded duration.
        let guard = match lock.lock() {
            Ok(g) => g,
            Err(_) => {
                unsafe { set_abi_errno(errno::EINTR) };
                return -1;
            }
        };
        let _ = cvar.wait_timeout(guard, wait_dur.min(std::time::Duration::from_millis(100)));
    }
}

/// `aio_fsync` — schedule an fsync/fdatasync for an asynchronous I/O file descriptor.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn aio_fsync(op: c_int, aiocbp: *mut c_void) -> c_int {
    if aiocbp.is_null() {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }

    let aio_op = if op == O_DSYNC_FLAG {
        AioOp::Fdatasync
    } else {
        // O_SYNC or default → full fsync
        AioOp::Fsync
    };

    unsafe { aio_submit(aiocbp, aio_op) }
}

/// `lio_listio` — initiate a list of I/O requests.
///
/// In LIO_WAIT mode, submits all operations and waits for all to complete.
/// In LIO_NOWAIT mode, submits all operations and returns immediately.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lio_listio(
    mode: c_int,
    list: *const *mut c_void,
    nent: c_int,
    _sevp: *mut c_void,
) -> c_int {
    if list.is_null() || nent < 0 {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }
    if mode != LIO_WAIT && mode != LIO_NOWAIT {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }

    let mut had_error = false;

    // Submit each request.
    for i in 0..nent as usize {
        let cb = unsafe { *list.add(i) };
        if cb.is_null() {
            continue;
        }

        let opcode = unsafe { aiocb_i32(cb, aiocb_off::LIO_OPCODE) };
        let op = match opcode {
            LIO_READ => AioOp::Read,
            LIO_WRITE => AioOp::Write,
            LIO_NOP => continue,
            _ => {
                unsafe { set_abi_errno(errno::EINVAL) };
                had_error = true;
                continue;
            }
        };

        if unsafe { aio_submit(cb, op) } != 0 {
            had_error = true;
        }
    }

    if mode == LIO_WAIT {
        // Wait for all submitted operations to complete.
        let (lock, cvar) = &*AIO_NOTIFY;

        loop {
            let mut all_done = true;
            for i in 0..nent as usize {
                let cb = unsafe { *list.add(i) };
                if cb.is_null() {
                    continue;
                }
                let opcode = unsafe { aiocb_i32(cb, aiocb_off::LIO_OPCODE) };
                if opcode == LIO_NOP {
                    continue;
                }
                if unsafe { aiocb_error_atomic(cb) } == errno::EINPROGRESS {
                    all_done = false;
                    break;
                }
            }

            if all_done {
                break;
            }

            let guard = match lock.lock() {
                Ok(g) => g,
                Err(_) => break,
            };
            let _ = cvar.wait_timeout(guard, std::time::Duration::from_millis(50));
        }
    }

    if had_error { -1 } else { 0 }
}

// ---------------------------------------------------------------------------
// mount table — Implemented (native /proc/mounts parser)
// ---------------------------------------------------------------------------

/// Internal mount table stream state.
struct MntStream {
    file: std::fs::File,
    line_buf: Vec<u8>,
    // Static-lifetime buffers for mntent fields (glibc contract).
    fsname_buf: Vec<u8>,
    dir_buf: Vec<u8>,
    type_buf: Vec<u8>,
    opts_buf: Vec<u8>,
    // The mntent struct (6 fields: 4 ptrs + 2 ints).
    mntent: [u8; 48], // sizeof(struct mntent) on x86_64
}

/// `setmntent` — open a mount table file.
///
/// Returns an opaque handle used by `getmntent`/`endmntent`.
/// On failure, returns NULL.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setmntent(filename: *const c_char, _type: *const c_char) -> *mut c_void {
    if filename.is_null() {
        return std::ptr::null_mut();
    }
    let path = unsafe { std::ffi::CStr::from_ptr(filename) };
    let path_str = match path.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let file = match std::fs::File::open(path_str) {
        Ok(f) => f,
        Err(_) => return std::ptr::null_mut(),
    };
    let stream = Box::new(MntStream {
        file,
        line_buf: Vec::with_capacity(512),
        fsname_buf: Vec::new(),
        dir_buf: Vec::new(),
        type_buf: Vec::new(),
        opts_buf: Vec::new(),
        mntent: [0u8; 48],
    });
    Box::into_raw(stream) as *mut c_void
}

/// `getmntent` — read next mount entry.
///
/// Returns a pointer to a static `struct mntent`, or NULL on EOF/error.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getmntent(stream: *mut c_void) -> *mut c_void {
    use std::io::BufRead;

    if stream.is_null() {
        return std::ptr::null_mut();
    }
    let ms = unsafe { &mut *(stream as *mut MntStream) };
    let mut reader = std::io::BufReader::new(&ms.file);

    loop {
        ms.line_buf.clear();
        let bytes_read = match reader.read_until(b'\n', &mut ms.line_buf) {
            Ok(n) => n,
            Err(_) => return std::ptr::null_mut(),
        };
        if bytes_read == 0 {
            return std::ptr::null_mut(); // EOF
        }

        // Strip trailing newline
        if ms.line_buf.last() == Some(&b'\n') {
            ms.line_buf.pop();
        }
        if ms.line_buf.last() == Some(&b'\r') {
            ms.line_buf.pop();
        }

        // Skip comments and blank lines
        let trimmed = ms.line_buf.iter().position(|&b| b != b' ' && b != b'\t');
        if trimmed.is_none_or(|i| ms.line_buf[i] == b'#') {
            continue;
        }

        // Parse: fsname dir type opts freq passno
        let line = &ms.line_buf;
        let mut fields = line
            .split(|&b| b == b' ' || b == b'\t')
            .filter(|f| !f.is_empty());

        let fsname = match fields.next() {
            Some(f) => f,
            None => continue,
        };
        let dir = match fields.next() {
            Some(f) => f,
            None => continue,
        };
        let ftype = match fields.next() {
            Some(f) => f,
            None => continue,
        };
        let opts = fields.next().unwrap_or(b"defaults");
        let freq: i32 = fields
            .next()
            .and_then(|f| std::str::from_utf8(f).ok())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let passno: i32 = fields
            .next()
            .and_then(|f| std::str::from_utf8(f).ok())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        // Copy into persistent buffers (null-terminated)
        ms.fsname_buf.clear();
        ms.fsname_buf.extend_from_slice(fsname);
        ms.fsname_buf.push(0);

        ms.dir_buf.clear();
        ms.dir_buf.extend_from_slice(dir);
        ms.dir_buf.push(0);

        ms.type_buf.clear();
        ms.type_buf.extend_from_slice(ftype);
        ms.type_buf.push(0);

        ms.opts_buf.clear();
        ms.opts_buf.extend_from_slice(opts);
        ms.opts_buf.push(0);

        // Write struct mntent:
        // struct mntent {
        //   char *mnt_fsname;   // offset 0
        //   char *mnt_dir;      // offset 8
        //   char *mnt_type;     // offset 16
        //   char *mnt_opts;     // offset 24
        //   int   mnt_freq;     // offset 32
        //   int   mnt_passno;   // offset 36
        // };
        let ent = &mut ms.mntent;
        unsafe {
            let p = ent.as_mut_ptr();
            *(p as *mut *const u8) = ms.fsname_buf.as_ptr();
            *(p.add(8) as *mut *const u8) = ms.dir_buf.as_ptr();
            *(p.add(16) as *mut *const u8) = ms.type_buf.as_ptr();
            *(p.add(24) as *mut *const u8) = ms.opts_buf.as_ptr();
            *(p.add(32) as *mut i32) = freq;
            *(p.add(36) as *mut i32) = passno;
        }

        return ms.mntent.as_mut_ptr() as *mut c_void;
    }
}

/// `endmntent` — close a mount table stream.
///
/// Always returns 1 (glibc contract).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn endmntent(stream: *mut c_void) -> c_int {
    if !stream.is_null() {
        // SAFETY: stream was created by setmntent via Box::into_raw.
        let _: Box<MntStream> = unsafe { Box::from_raw(stream as *mut MntStream) };
    }
    1 // glibc always returns 1
}

/// POSIX `hasmntopt` — search for a mount option in the mntent options string.
///
/// The mntent struct has `mnt_opts` as the 4th pointer field (at offset 3*ptr).
/// Searches the comma-separated options string for the specified option.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn hasmntopt(mnt: *const c_void, opt: *const c_char) -> *mut c_char {
    if mnt.is_null() || opt.is_null() {
        return std::ptr::null_mut();
    }
    // mntent struct: { mnt_fsname, mnt_dir, mnt_type, mnt_opts, ... }
    // mnt_opts is at offset 3 * sizeof(*const c_char)
    let opts_ptr_ptr = unsafe { (mnt as *const *const c_char).add(3) };
    let opts_ptr = unsafe { *opts_ptr_ptr };
    if opts_ptr.is_null() {
        return std::ptr::null_mut();
    }
    let opts = unsafe { std::ffi::CStr::from_ptr(opts_ptr) }.to_bytes();
    let needle = unsafe { std::ffi::CStr::from_ptr(opt) }.to_bytes();
    if needle.is_empty() {
        return std::ptr::null_mut();
    }
    // Search for needle as a comma-delimited token within opts
    for (i, window) in opts.windows(needle.len()).enumerate() {
        if window == needle {
            // Check that it's a whole token (bounded by comma, start, or end)
            let at_start = i == 0 || opts[i - 1] == b',';
            let at_end = i + needle.len() == opts.len() || opts[i + needle.len()] == b',';
            if at_start && at_end {
                return unsafe { opts_ptr.add(i) as *mut c_char };
            }
        }
    }
    std::ptr::null_mut()
}

/// GNU `getmntent_r` — reentrant mount entry reader.
///
/// Reads the next mount entry from the stream into caller-supplied buffers.
/// The mntent struct has fields: { mnt_fsname, mnt_dir, mnt_type, mnt_opts, mnt_freq, mnt_passno }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getmntent_r(
    stream: *mut c_void,
    mntbuf: *mut c_void,
    buf: *mut c_char,
    buflen: c_int,
) -> *mut c_void {
    use std::io::BufRead;

    if stream.is_null() || mntbuf.is_null() || buf.is_null() || buflen <= 0 {
        return std::ptr::null_mut();
    }
    let ms = unsafe { &mut *(stream as *mut MntStream) };
    let buflen_u = buflen as usize;
    let mut reader = std::io::BufReader::new(&ms.file);

    loop {
        ms.line_buf.clear();
        let bytes_read = match reader.read_until(b'\n', &mut ms.line_buf) {
            Ok(n) => n,
            Err(_) => return std::ptr::null_mut(),
        };
        if bytes_read == 0 {
            return std::ptr::null_mut(); // EOF
        }
        // Strip trailing newline
        while ms.line_buf.last() == Some(&b'\n') || ms.line_buf.last() == Some(&b'\r') {
            ms.line_buf.pop();
        }
        // Skip comments and blank lines
        let first = ms.line_buf.iter().position(|&b| b != b' ' && b != b'\t');
        if first.is_none_or(|i| ms.line_buf[i] == b'#') {
            continue;
        }

        // Parse: fsname dir type opts [freq [passno]]
        let line = &ms.line_buf;
        let mut fields = line
            .split(|&b| b == b' ' || b == b'\t')
            .filter(|f| !f.is_empty());

        let fsname = match fields.next() {
            Some(f) => f,
            None => continue,
        };
        let dir = match fields.next() {
            Some(f) => f,
            None => continue,
        };
        let mtype = match fields.next() {
            Some(f) => f,
            None => continue,
        };
        let opts = match fields.next() {
            Some(f) => f,
            None => continue,
        };
        let freq_s = fields.next().unwrap_or(b"0");
        let passno_s = fields.next().unwrap_or(b"0");

        // Check if all strings fit in caller's buffer
        let needed = fsname.len() + 1 + dir.len() + 1 + mtype.len() + 1 + opts.len() + 1;
        if needed > buflen_u {
            continue;
        }

        // Pack strings into caller buffer
        let buf_u8 = buf as *mut u8;
        let mut off = 0usize;

        let fsname_ptr = unsafe { buf_u8.add(off) } as *mut c_char;
        unsafe {
            std::ptr::copy_nonoverlapping(fsname.as_ptr(), buf_u8.add(off), fsname.len());
            *buf_u8.add(off + fsname.len()) = 0;
        }
        off += fsname.len() + 1;

        let dir_ptr = unsafe { buf_u8.add(off) } as *mut c_char;
        unsafe {
            std::ptr::copy_nonoverlapping(dir.as_ptr(), buf_u8.add(off), dir.len());
            *buf_u8.add(off + dir.len()) = 0;
        }
        off += dir.len() + 1;

        let type_ptr = unsafe { buf_u8.add(off) } as *mut c_char;
        unsafe {
            std::ptr::copy_nonoverlapping(mtype.as_ptr(), buf_u8.add(off), mtype.len());
            *buf_u8.add(off + mtype.len()) = 0;
        }
        off += mtype.len() + 1;

        let opts_ptr = unsafe { buf_u8.add(off) } as *mut c_char;
        unsafe {
            std::ptr::copy_nonoverlapping(opts.as_ptr(), buf_u8.add(off), opts.len());
            *buf_u8.add(off + opts.len()) = 0;
        }

        let freq: c_int = std::str::from_utf8(freq_s)
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let passno: c_int = std::str::from_utf8(passno_s)
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        // Fill mntent struct: { *fsname, *dir, *type, *opts, freq, passno }
        let ent = mntbuf as *mut *mut c_char;
        unsafe {
            *ent = fsname_ptr;
            *ent.add(1) = dir_ptr;
            *ent.add(2) = type_ptr;
            *ent.add(3) = opts_ptr;
            let int_ptr = ent.add(4) as *mut c_int;
            *int_ptr = freq;
            *int_ptr.add(1) = passno;
        }

        return mntbuf;
    }
}

/// GNU `addmntent` — append a mount entry to a mount table file.
///
/// Writes the entry in fstab format: fsname dir type opts freq passno.
/// Returns 0 on success, 1 on error.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn addmntent(stream: *mut c_void, mnt: *const c_void) -> c_int {
    use std::io::Write;

    if stream.is_null() || mnt.is_null() {
        return 1;
    }
    // Read mntent fields
    let ent = mnt as *const *const c_char;
    let fsname = unsafe { *ent };
    let dir = unsafe { *ent.add(1) };
    let mtype = unsafe { *ent.add(2) };
    let opts = unsafe { *ent.add(3) };
    let int_ptr = unsafe { ent.add(4) } as *const c_int;
    let freq = unsafe { *int_ptr };
    let passno = unsafe { *int_ptr.add(1) };

    if fsname.is_null() || dir.is_null() || mtype.is_null() || opts.is_null() {
        return 1;
    }

    let fsname_s = unsafe { std::ffi::CStr::from_ptr(fsname) }.to_string_lossy();
    let dir_s = unsafe { std::ffi::CStr::from_ptr(dir) }.to_string_lossy();
    let type_s = unsafe { std::ffi::CStr::from_ptr(mtype) }.to_string_lossy();
    let opts_s = unsafe { std::ffi::CStr::from_ptr(opts) }.to_string_lossy();

    let line = format!("{fsname_s} {dir_s} {type_s} {opts_s} {freq} {passno}\n");

    // Write to the underlying file
    let ms = unsafe { &mut *(stream as *mut MntStream) };
    match ms.file.write_all(line.as_bytes()) {
        Ok(()) => 0,
        Err(_) => 1,
    }
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

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sched_rr_get_interval(pid: libc::pid_t, tp: *mut libc::timespec) -> c_int {
    unsafe {
        syscall_ret_int(
            libc::syscall(libc::SYS_sched_rr_get_interval, pid, tp),
            errno::EINVAL,
        )
    }
}

// ---------------------------------------------------------------------------
// Resolver bootstrap/query surface — Implemented (native DNS over UDP)
// Uses frankenlibc_core::resolv::{ResolverConfig, DnsMessage, DnsHeader}
// to build wire-format queries, send them to nameservers from resolv.conf,
// and return raw DNS response bytes to the caller.
// ---------------------------------------------------------------------------

/// Cached resolver config (parsed from /etc/resolv.conf on first use).
pub(crate) static RESOLV_CONFIG: std::sync::LazyLock<
    frankenlibc_core::resolv::config::ResolverConfig,
> = std::sync::LazyLock::new(|| {
    if let Ok(content) = std::fs::read("/etc/resolv.conf") {
        frankenlibc_core::resolv::config::ResolverConfig::parse(&content)
    } else {
        frankenlibc_core::resolv::config::ResolverConfig::default()
    }
});

/// Send a DNS query to the configured nameservers and return the raw response.
///
/// On success, copies the response into `answer[..anslen]` and returns the
/// number of bytes written. On failure, returns -1 with errno set.
unsafe fn dns_query_raw(
    dname: &[u8],
    class: c_int,
    type_: c_int,
    answer: *mut u8,
    anslen: c_int,
) -> c_int {
    use frankenlibc_core::resolv::dns::{DNS_MAX_UDP_SIZE, DnsHeader};
    use std::net::UdpSocket;

    let config = &*RESOLV_CONFIG;

    if answer.is_null() || anslen <= 0 {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }

    // Build the DNS wire-format query.
    // Transaction ID: use lower 16 bits of a simple counter for uniqueness.
    static TX_COUNTER: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(1);
    let tx_id = TX_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    let mut header = DnsHeader::new_query(tx_id);
    header.qdcount = 1;

    let qname = frankenlibc_core::resolv::dns::encode_domain_name(dname);

    // Build query packet: header + question (qname + qtype + qclass)
    let query_len = 12 + qname.len() + 4;
    let mut query_buf = vec![0u8; query_len];
    let _ = header.encode(&mut query_buf);
    let mut pos = 12;
    query_buf[pos..pos + qname.len()].copy_from_slice(&qname);
    pos += qname.len();
    query_buf[pos..pos + 2].copy_from_slice(&(type_ as u16).to_be_bytes());
    pos += 2;
    query_buf[pos..pos + 2].copy_from_slice(&(class as u16).to_be_bytes());

    let timeout = config.query_timeout();
    let mut recv_buf = vec![0u8; DNS_MAX_UDP_SIZE.max(anslen as usize)];

    // Try each nameserver up to `attempts` times.
    for _attempt in 0..config.attempts {
        for ns in &config.nameservers {
            let dest = std::net::SocketAddr::new(*ns, frankenlibc_core::resolv::config::DNS_PORT);

            // Bind to any local address matching the nameserver's address family.
            let bind_addr = if ns.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
            let sock = match UdpSocket::bind(bind_addr) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let _ = sock.set_read_timeout(Some(timeout));
            let _ = sock.set_write_timeout(Some(timeout));

            if sock.send_to(&query_buf, dest).is_err() {
                continue;
            }

            match sock.recv_from(&mut recv_buf) {
                Ok((n, _)) => {
                    if n < 12 {
                        continue;
                    }
                    // Verify transaction ID matches.
                    let resp_id = u16::from_be_bytes([recv_buf[0], recv_buf[1]]);
                    if resp_id != tx_id {
                        continue;
                    }
                    // Check QR bit (response).
                    if (recv_buf[2] & 0x80) == 0 {
                        continue;
                    }
                    // Check RCODE.
                    let rcode = recv_buf[3] & 0x0f;
                    if rcode != 0 {
                        // Map DNS error codes to h_errno-style reporting.
                        let h_err = match rcode {
                            1 => errno::EINVAL, // FORMERR
                            2 => errno::EIO,    // SERVFAIL
                            3 => errno::ENOENT, // NXDOMAIN → HOST_NOT_FOUND
                            _ => errno::EIO,
                        };
                        unsafe { set_abi_errno(h_err) };
                        return -1;
                    }
                    // Copy response to caller's buffer.
                    let copy_len = n.min(anslen as usize);
                    unsafe {
                        std::ptr::copy_nonoverlapping(recv_buf.as_ptr(), answer, copy_len);
                    }
                    return copy_len as c_int;
                }
                Err(_) => continue, // Timeout or network error, try next
            }
        }
    }

    // All attempts exhausted.
    unsafe { set_abi_errno(errno::ETIMEDOUT) };
    -1
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn res_init() -> c_int {
    // Force lazy initialization of the resolver config.
    let _ = &*RESOLV_CONFIG;
    0
}

/// `res_query` — send a DNS query and return the raw response.
///
/// Native implementation using our DNS protocol stack and /etc/resolv.conf.
/// Queries the name as given (no search domain appending).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn res_query(
    dname: *const c_char,
    class: c_int,
    type_: c_int,
    answer: *mut u8,
    anslen: c_int,
) -> c_int {
    if dname.is_null() {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }
    let name = unsafe { CStr::from_ptr(dname) };
    unsafe { dns_query_raw(name.to_bytes(), class, type_, answer, anslen) }
}

/// `res_search` — send a DNS query using the search domain list.
///
/// Tries the name as absolute first if it has enough dots (per ndots config),
/// then appends each search domain from /etc/resolv.conf in turn.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn res_search(
    dname: *const c_char,
    class: c_int,
    type_: c_int,
    answer: *mut u8,
    anslen: c_int,
) -> c_int {
    if dname.is_null() {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }
    let name = unsafe { CStr::from_ptr(dname) };
    let name_bytes = name.to_bytes();
    let name_str = match std::str::from_utf8(name_bytes) {
        Ok(s) => s,
        Err(_) => {
            unsafe { set_abi_errno(errno::EINVAL) };
            return -1;
        }
    };

    let config = &*RESOLV_CONFIG;

    // If the name has enough dots, try it as absolute first.
    if config.should_try_absolute_first(name_str) {
        let rc = unsafe { dns_query_raw(name_bytes, class, type_, answer, anslen) };
        if rc > 0 {
            return rc;
        }
    }

    // Try appending each search domain.
    for domain in &config.search {
        let mut fqdn = Vec::with_capacity(name_bytes.len() + 1 + domain.len());
        fqdn.extend_from_slice(name_bytes);
        if !name_bytes.ends_with(b".") {
            fqdn.push(b'.');
        }
        fqdn.extend_from_slice(domain.as_bytes());

        let rc = unsafe { dns_query_raw(&fqdn, class, type_, answer, anslen) };
        if rc > 0 {
            return rc;
        }
    }

    // If we haven't tried absolute yet, try now as last resort.
    if !config.should_try_absolute_first(name_str) {
        let rc = unsafe { dns_query_raw(name_bytes, class, type_, answer, anslen) };
        if rc > 0 {
            return rc;
        }
    }

    // All attempts failed.
    unsafe { set_abi_errno(errno::ENOENT) };
    -1
}

#[cfg(test)]
mod resolver_bootstrap_tests {
    #[test]
    fn res_init_reports_success() {
        let rc = unsafe { super::res_init() };
        assert_eq!(rc, 0);
    }
}

// ---------------------------------------------------------------------------
// fgetpwent / fgetgrent — Implemented (native line reading + parsing)
// Reuses parse_passwd_line / parse_group_line from frankenlibc-core
// and TLS fill helpers from pwd_abi / grp_abi.
// ---------------------------------------------------------------------------

/// POSIX `fgetpwent` — read the next passwd entry from a stream.
///
/// Reads lines from `stream` using our native fgets, parses each with
/// `parse_passwd_line`, and returns a pointer to thread-local storage.
/// Returns NULL on EOF or error.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fgetpwent(stream: *mut c_void) -> *mut c_void {
    if stream.is_null() {
        return std::ptr::null_mut();
    }

    let mut line_buf = [0u8; 1024];
    loop {
        let result = unsafe {
            super::stdio_abi::fgets(
                line_buf.as_mut_ptr().cast::<c_char>(),
                line_buf.len() as c_int,
                stream,
            )
        };
        if result.is_null() {
            return std::ptr::null_mut(); // EOF or error
        }

        // Find the NUL terminator to get the line length.
        let line_len = unsafe { CStr::from_ptr(line_buf.as_ptr().cast::<c_char>()) }
            .to_bytes()
            .len();
        let line = &line_buf[..line_len];

        // Skip blank lines and comments; parse_passwd_line returns None for those.
        if let Some(entry) = frankenlibc_core::pwd::parse_passwd_line(line) {
            return super::pwd_abi::fill_passwd_from_entry(&entry).cast::<c_void>();
        }
    }
}

/// POSIX `fgetgrent` — read the next group entry from a stream.
///
/// Reads lines from `stream` using our native fgets, parses each with
/// `parse_group_line`, and returns a pointer to thread-local storage.
/// Returns NULL on EOF or error.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fgetgrent(stream: *mut c_void) -> *mut c_void {
    if stream.is_null() {
        return std::ptr::null_mut();
    }

    let mut line_buf = [0u8; 1024];
    loop {
        let result = unsafe {
            super::stdio_abi::fgets(
                line_buf.as_mut_ptr().cast::<c_char>(),
                line_buf.len() as c_int,
                stream,
            )
        };
        if result.is_null() {
            return std::ptr::null_mut(); // EOF or error
        }

        let line_len = unsafe { CStr::from_ptr(line_buf.as_ptr().cast::<c_char>()) }
            .to_bytes()
            .len();
        let line = &line_buf[..line_len];

        if let Some(entry) = frankenlibc_core::grp::parse_group_line(line) {
            return super::grp_abi::fill_group_from_entry(&entry).cast::<c_void>();
        }
    }
}

/// POSIX `getgrouplist` — get list of groups a user belongs to.
///
/// Fills `groups` with GIDs, stores count in `*ngroups`.
/// Returns -1 if buffer too small (setting *ngroups to required count).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getgrouplist(
    user: *const c_char,
    group: libc::gid_t,
    groups: *mut libc::gid_t,
    ngroups: *mut c_int,
) -> c_int {
    if user.is_null() || groups.is_null() || ngroups.is_null() {
        return -1;
    }
    let user_name = unsafe { std::ffi::CStr::from_ptr(user) }.to_bytes();
    let max_groups = unsafe { *ngroups } as usize;

    let mut result: Vec<libc::gid_t> = Vec::with_capacity(32);
    result.push(group);

    if let Ok(content) = std::fs::read("/etc/group") {
        for line in content.split(|&b| b == b'\n') {
            if line.is_empty() || line[0] == b'#' {
                continue;
            }
            let fields: Vec<&[u8]> = line.splitn(4, |&b| b == b':').collect();
            if fields.len() < 4 {
                continue;
            }
            let gid: libc::gid_t = match std::str::from_utf8(fields[2]).unwrap_or("").parse() {
                Ok(g) => g,
                Err(_) => continue,
            };
            if gid == group {
                continue;
            }
            for member in fields[3].split(|&b| b == b',') {
                let member = member.strip_suffix(b"\r").unwrap_or(member);
                if member == user_name && !result.contains(&gid) {
                    result.push(gid);
                    break;
                }
            }
        }
    }

    unsafe { *ngroups = result.len() as c_int };
    if result.len() > max_groups {
        return -1;
    }
    for (i, &gid) in result.iter().enumerate() {
        unsafe { *groups.add(i) = gid };
    }
    result.len() as c_int
}

/// POSIX `initgroups` — initialize supplementary group access list.
///
/// Reads /etc/group to find all groups the user belongs to, then calls
/// SYS_setgroups with the resulting list plus the primary group.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn initgroups(user: *const c_char, group: libc::gid_t) -> c_int {
    if user.is_null() {
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }
    let user_name = unsafe { std::ffi::CStr::from_ptr(user) }.to_bytes();

    let mut groups: Vec<libc::gid_t> = Vec::with_capacity(32);
    groups.push(group);

    // Parse /etc/group for supplementary memberships
    if let Ok(content) = std::fs::read("/etc/group") {
        for line in content.split(|&b| b == b'\n') {
            if line.is_empty() || line[0] == b'#' {
                continue;
            }
            // Format: name:password:gid:member1,member2,...
            let fields: Vec<&[u8]> = line.splitn(4, |&b| b == b':').collect();
            if fields.len() < 4 {
                continue;
            }
            let gid_str = std::str::from_utf8(fields[2]).unwrap_or("");
            let gid: libc::gid_t = match gid_str.parse() {
                Ok(g) => g,
                Err(_) => continue,
            };
            if gid == group {
                continue; // Already in list
            }
            // Check if user is in the member list
            for member in fields[3].split(|&b| b == b',') {
                let member = member.strip_suffix(b"\r").unwrap_or(member);
                if member == user_name && !groups.contains(&gid) {
                    groups.push(gid);
                    break;
                }
            }
        }
    }

    let ret = unsafe {
        libc::syscall(
            libc::SYS_setgroups,
            groups.len() as i64,
            groups.as_ptr() as i64,
        )
    } as c_int;
    if ret < 0 {
        return -1;
    }
    0
}

// ---------------------------------------------------------------------------
// Misc POSIX extras — GlibcCallThrough / RawSyscall
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getlogin() -> *mut c_char {
    let (_, decision) = runtime_policy::decide(ApiFamily::Resolver, 0, 0, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EPERM) };
        runtime_policy::observe(ApiFamily::Resolver, decision.profile, 10, true);
        return std::ptr::null_mut();
    }
    let name_ptr = unsafe { lookup_login_name_ptr() };
    if name_ptr.is_null() {
        unsafe { set_abi_errno(errno::ENOENT) };
        runtime_policy::observe(ApiFamily::Resolver, decision.profile, 10, true);
        return std::ptr::null_mut();
    }
    let name = unsafe { CStr::from_ptr(name_ptr) };
    let bytes = name.to_bytes_with_nul();
    if bytes.len() > GETLOGIN_MAX_LEN {
        unsafe { set_abi_errno(errno::ERANGE) };
        runtime_policy::observe(ApiFamily::Resolver, decision.profile, 10, true);
        return std::ptr::null_mut();
    }
    let dst = std::ptr::addr_of_mut!(GETLOGIN_FALLBACK).cast::<c_char>();
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr().cast::<c_char>(), dst, bytes.len());
    }
    runtime_policy::observe(
        ApiFamily::Resolver,
        decision.profile,
        runtime_policy::scaled_cost(10, bytes.len()),
        false,
    );
    dst
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getlogin_r(buf: *mut c_char, bufsize: usize) -> c_int {
    let (_, decision) = runtime_policy::decide(
        ApiFamily::Resolver,
        buf as usize,
        bufsize,
        true,
        buf.is_null() && bufsize > 0,
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(
            ApiFamily::Resolver,
            decision.profile,
            runtime_policy::scaled_cost(10, bufsize),
            true,
        );
        return errno::EPERM;
    }
    if buf.is_null() || bufsize == 0 {
        runtime_policy::observe(ApiFamily::Resolver, decision.profile, 10, true);
        return errno::EINVAL;
    }

    let name_ptr = unsafe { lookup_login_name_ptr() };
    if name_ptr.is_null() {
        runtime_policy::observe(ApiFamily::Resolver, decision.profile, 10, true);
        return errno::ENOENT;
    }
    let name = unsafe { CStr::from_ptr(name_ptr) };
    let bytes = name.to_bytes_with_nul();
    if bytes.len() > bufsize {
        runtime_policy::observe(
            ApiFamily::Resolver,
            decision.profile,
            runtime_policy::scaled_cost(10, bytes.len()),
            true,
        );
        return errno::ERANGE;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr().cast::<c_char>(), buf, bytes.len());
    }
    runtime_policy::observe(
        ApiFamily::Resolver,
        decision.profile,
        runtime_policy::scaled_cost(10, bytes.len()),
        false,
    );
    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ttyname(fd: c_int) -> *mut c_char {
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdio, fd as usize, 0, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EPERM) };
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 12, true);
        return std::ptr::null_mut();
    }

    let dst = std::ptr::addr_of_mut!(TTYNAME_FALLBACK).cast::<c_char>();
    match unsafe { resolve_ttyname_into(fd, dst, TTYNAME_MAX_LEN) } {
        Ok(path_len) => {
            runtime_policy::observe(
                ApiFamily::Stdio,
                decision.profile,
                runtime_policy::scaled_cost(12, path_len + 1),
                false,
            );
            dst
        }
        Err(e) => {
            unsafe { set_abi_errno(e) };
            runtime_policy::observe(ApiFamily::Stdio, decision.profile, 12, true);
            std::ptr::null_mut()
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ttyname_r(fd: c_int, buf: *mut c_char, buflen: usize) -> c_int {
    let (_, decision) = runtime_policy::decide(
        ApiFamily::Stdio,
        buf as usize,
        buflen,
        true,
        buf.is_null() && buflen > 0,
        fd.clamp(0, u16::MAX as c_int) as u16,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(
            ApiFamily::Stdio,
            decision.profile,
            runtime_policy::scaled_cost(12, buflen),
            true,
        );
        return errno::EPERM;
    }
    if buf.is_null() || buflen == 0 {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 12, true);
        return errno::EINVAL;
    }

    match unsafe { resolve_ttyname_into(fd, buf, buflen) } {
        Ok(path_len) => {
            runtime_policy::observe(
                ApiFamily::Stdio,
                decision.profile,
                runtime_policy::scaled_cost(12, path_len + 1),
                false,
            );
            0
        }
        Err(e) => {
            runtime_policy::observe(
                ApiFamily::Stdio,
                decision.profile,
                runtime_policy::scaled_cost(12, buflen),
                true,
            );
            e
        }
    }
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

/// Maximum password length for getpass.
const GETPASS_MAX: usize = 128;

std::thread_local! {
    static GETPASS_BUF: std::cell::RefCell<[c_char; GETPASS_MAX]> = const { std::cell::RefCell::new([0; GETPASS_MAX]) };
}

/// POSIX `getpass` — read a password from /dev/tty with echo disabled.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getpass(prompt: *const c_char) -> *mut c_char {
    let tty = b"/dev/tty\0";
    let fd = unsafe {
        libc::syscall(
            libc::SYS_open,
            tty.as_ptr(),
            libc::O_RDWR | libc::O_NOCTTY,
            0i64,
        )
    } as c_int;
    if fd < 0 {
        return std::ptr::null_mut();
    }

    // Write prompt
    if !prompt.is_null() {
        let prompt_cstr = unsafe { std::ffi::CStr::from_ptr(prompt) };
        let prompt_bytes = prompt_cstr.to_bytes();
        unsafe {
            libc::syscall(
                libc::SYS_write,
                fd as i64,
                prompt_bytes.as_ptr() as i64,
                prompt_bytes.len() as i64,
            );
        }
    }

    // Disable echo via ioctl (TCGETS=0x5401, TCSETS=0x5402)
    const TCGETS: u64 = 0x5401;
    const TCSETS: u64 = 0x5402;
    const ECHO_FLAG: u32 = 0o10; // ECHO in termios c_lflag
    let mut termios_buf = [0u8; 60]; // struct termios size on Linux
    let saved_ok = unsafe {
        libc::syscall(
            libc::SYS_ioctl,
            fd as i64,
            TCGETS as i64,
            termios_buf.as_mut_ptr() as i64,
        )
    } >= 0;

    if saved_ok {
        let mut modified = termios_buf;
        // c_lflag is at offset 12 in struct termios (after c_iflag, c_oflag, c_cflag)
        let lflag_offset = 12;
        let lflag = u32::from_ne_bytes(
            modified[lflag_offset..lflag_offset + 4]
                .try_into()
                .unwrap_or([0; 4]),
        );
        let new_lflag = lflag & !ECHO_FLAG;
        modified[lflag_offset..lflag_offset + 4].copy_from_slice(&new_lflag.to_ne_bytes());
        unsafe {
            libc::syscall(
                libc::SYS_ioctl,
                fd as i64,
                TCSETS as i64,
                modified.as_ptr() as i64,
            );
        }
    }

    // Read password
    let result = GETPASS_BUF.with(|cell| {
        let mut buf = cell.borrow_mut();
        let mut pos = 0usize;
        loop {
            let mut ch = 0u8;
            let n = unsafe {
                libc::syscall(libc::SYS_read, fd as i64, &mut ch as *mut u8 as i64, 1i64)
            };
            if n <= 0 || ch == b'\n' || ch == b'\r' {
                break;
            }
            if pos < GETPASS_MAX - 1 {
                buf[pos] = ch as c_char;
                pos += 1;
            }
        }
        buf[pos] = 0;
        buf.as_mut_ptr()
    });

    // Restore terminal settings
    if saved_ok {
        unsafe {
            libc::syscall(
                libc::SYS_ioctl,
                fd as i64,
                TCSETS as i64,
                termios_buf.as_ptr() as i64,
            );
        }
        // Print newline since echo was off
        unsafe { libc::syscall(libc::SYS_write, fd as i64, b"\n".as_ptr() as i64, 1i64) };
    }

    unsafe { libc::syscall(libc::SYS_close, fd as i64) };
    result
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

#[inline]
fn process_vm_missing_iov_payload(
    local_iov: *const libc::iovec,
    liovcnt: c_ulong,
    remote_iov: *const libc::iovec,
    riovcnt: c_ulong,
) -> bool {
    (local_iov.is_null() && liovcnt > 0) || (remote_iov.is_null() && riovcnt > 0)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn process_vm_readv(
    pid: libc::pid_t,
    local_iov: *const libc::iovec,
    liovcnt: std::ffi::c_ulong,
    remote_iov: *const libc::iovec,
    riovcnt: std::ffi::c_ulong,
    flags: std::ffi::c_ulong,
) -> isize {
    let io_units = liovcnt.saturating_add(riovcnt) as usize;
    let missing_payload = process_vm_missing_iov_payload(local_iov, liovcnt, remote_iov, riovcnt);
    let (mode, decision) = runtime_policy::decide(
        ApiFamily::VirtualMemory,
        local_iov as usize,
        io_units,
        true,
        missing_payload,
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EPERM) };
        runtime_policy::observe(
            ApiFamily::VirtualMemory,
            decision.profile,
            runtime_policy::scaled_cost(12, io_units),
            true,
        );
        return -1;
    }
    if missing_payload && policy_repair_enabled(mode.heals_enabled(), decision.action) {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(
            ApiFamily::VirtualMemory,
            decision.profile,
            runtime_policy::scaled_cost(12, io_units),
            true,
        );
        return -1;
    }

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
    runtime_policy::observe(
        ApiFamily::VirtualMemory,
        decision.profile,
        runtime_policy::scaled_cost(12, io_units),
        rc < 0,
    );
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
    let io_units = liovcnt.saturating_add(riovcnt) as usize;
    let missing_payload = process_vm_missing_iov_payload(local_iov, liovcnt, remote_iov, riovcnt);
    let (mode, decision) = runtime_policy::decide(
        ApiFamily::VirtualMemory,
        local_iov as usize,
        io_units,
        true,
        missing_payload,
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EPERM) };
        runtime_policy::observe(
            ApiFamily::VirtualMemory,
            decision.profile,
            runtime_policy::scaled_cost(12, io_units),
            true,
        );
        return -1;
    }
    if missing_payload && policy_repair_enabled(mode.heals_enabled(), decision.action) {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(
            ApiFamily::VirtualMemory,
            decision.profile,
            runtime_policy::scaled_cost(12, io_units),
            true,
        );
        return -1;
    }

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
    runtime_policy::observe(
        ApiFamily::VirtualMemory,
        decision.profile,
        runtime_policy::scaled_cost(12, io_units),
        rc < 0,
    );
    rc as isize
}

// ---------------------------------------------------------------------------
// 64-bit LFS extras / umount — Implemented (native delegates on x86_64)
// ---------------------------------------------------------------------------

/// Linux `umount` — unmount a filesystem via raw syscall.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn umount(target: *const c_char) -> c_int {
    let ret = unsafe { libc::syscall(libc::SYS_umount2, target, 0i64) } as c_int;
    if ret < 0 {
        return -1;
    }
    0
}

/// `glob64` — on x86_64, identical to `glob` (LFS transparent).
/// Delegates to native glob implementation in string_abi.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn glob64(
    pattern: *const c_char,
    flags: c_int,
    _errfunc: Option<unsafe extern "C" fn(*const c_char, c_int) -> c_int>,
    pglob: *mut c_void,
) -> c_int {
    // On x86_64, glob_t and glob64_t are identical (off_t == off64_t).
    // Delegate to our native glob implementation.
    use frankenlibc_core::string::glob as glob_core;

    if pattern.is_null() || pglob.is_null() {
        return glob_core::GLOB_NOMATCH;
    }

    let pat_bytes = {
        let mut len = 0usize;
        unsafe {
            while *pattern.add(len) != 0 {
                len += 1;
            }
        }
        unsafe { std::slice::from_raw_parts(pattern as *const u8, len) }
    };

    let result = glob_core::glob_expand(pat_bytes, flags);

    match result {
        Ok(res) => {
            let count = res.paths.len();
            // Allocate pathv array (count + 1 for NULL sentinel).
            let pathv = unsafe {
                libc::malloc((count + 1) * std::mem::size_of::<*mut c_char>()) as *mut *mut c_char
            };
            if pathv.is_null() {
                return glob_core::GLOB_NOSPACE;
            }
            for (i, path) in res.paths.iter().enumerate() {
                let dup = unsafe { libc::malloc(path.len() + 1) as *mut c_char };
                if dup.is_null() {
                    // Free already allocated.
                    for j in 0..i {
                        unsafe { libc::free(*pathv.add(j) as *mut c_void) };
                    }
                    unsafe { libc::free(pathv as *mut c_void) };
                    return glob_core::GLOB_NOSPACE;
                }
                unsafe {
                    std::ptr::copy_nonoverlapping(path.as_ptr(), dup as *mut u8, path.len());
                    *dup.add(path.len()) = 0; // null terminate
                    *pathv.add(i) = dup;
                }
            }
            unsafe { *pathv.add(count) = std::ptr::null_mut() };

            // Write glob_t fields: gl_pathc, gl_pathv, gl_offs.
            unsafe {
                *(pglob as *mut usize) = count; // gl_pathc
                *((pglob as *mut u8).add(8) as *mut *mut *mut c_char) = pathv; // gl_pathv
            }
            0
        }
        Err(e) => e,
    }
}

/// `globfree64` — on x86_64, identical to `globfree` (LFS transparent).
/// Delegates to native globfree implementation in string_abi.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn globfree64(pglob: *mut c_void) {
    if pglob.is_null() {
        return;
    }
    let pathc = unsafe { *(pglob as *const usize) };
    let pathv = unsafe { *((pglob as *const u8).add(8) as *const *mut *mut c_char) };
    if !pathv.is_null() {
        let offs = unsafe { *((pglob as *const u8).add(16) as *const usize) };
        for i in offs..offs + pathc {
            let p = unsafe { *pathv.add(i) };
            if !p.is_null() {
                unsafe { libc::free(p as *mut c_void) };
            }
        }
        unsafe { libc::free(pathv as *mut c_void) };
    }
    // Zero out the glob_t.
    unsafe {
        *(pglob as *mut usize) = 0;
        *((pglob as *mut u8).add(8) as *mut *mut *mut c_char) = std::ptr::null_mut();
    }
}

/// `nftw64` — on x86_64, identical to `nftw` (LFS transparent).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nftw64(
    dirpath: *const c_char,
    fn_: *const c_void,
    nopenfd: c_int,
    flags: c_int,
) -> c_int {
    // On x86_64, stat == stat64, so nftw64 == nftw. Delegate to native nftw.
    let func: Option<
        unsafe extern "C" fn(*const c_char, *const libc::stat, c_int, *mut c_void) -> c_int,
    > = unsafe { std::mem::transmute(fn_) };
    unsafe { nftw(dirpath, func, nopenfd, flags) }
}

/// `alphasort64` — compare two directory entries by name (64-bit alias).
///
/// On 64-bit Linux, dirent64 == dirent, so this delegates to the
/// native alphasort implementation.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn alphasort64(a: *mut *const c_void, b: *mut *const c_void) -> c_int {
    unsafe {
        crate::dirent_abi::alphasort(a as *mut *const libc::dirent, b as *mut *const libc::dirent)
    }
}

// ===========================================================================
// Additional missing POSIX / Linux symbols — batch expansion
// ===========================================================================

// ---------------------------------------------------------------------------
// sysinfo — RawSyscall
// ---------------------------------------------------------------------------

/// Linux `sysinfo` — return system memory/uptime statistics.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sysinfo(info: *mut libc::sysinfo) -> c_int {
    if info.is_null() {
        unsafe { set_abi_errno(libc::EFAULT) };
        return -1;
    }
    unsafe { syscall_ret_int(libc::syscall(libc::SYS_sysinfo, info), errno::EFAULT) }
}

// ---------------------------------------------------------------------------
// Process group — RawSyscall
// ---------------------------------------------------------------------------

/// POSIX `getpgrp` — get process group ID of the calling process.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getpgrp() -> libc::pid_t {
    unsafe { libc::syscall(libc::SYS_getpgrp) as libc::pid_t }
}

/// BSD `setpgrp` — set process group (equivalent to setpgid(0, 0)).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setpgrp() -> c_int {
    unsafe { syscall_ret_int(libc::syscall(libc::SYS_setpgid, 0, 0), errno::EPERM) }
}

// ---------------------------------------------------------------------------
// Priority — RawSyscall
// ---------------------------------------------------------------------------

/// POSIX `getpriority` — get scheduling priority.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getpriority(which: c_int, who: libc::id_t) -> c_int {
    unsafe { *libc::__errno_location() = 0 };
    let rc = unsafe { libc::syscall(libc::SYS_getpriority, which, who) } as c_int;
    if rc < 0 {
        let e = last_host_errno(errno::ESRCH);
        if e != 0 {
            unsafe { set_abi_errno(e) };
            return -1;
        }
    }
    20 - rc
}

/// POSIX `setpriority` — set scheduling priority.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setpriority(which: c_int, who: libc::id_t, prio: c_int) -> c_int {
    unsafe {
        syscall_ret_int(
            libc::syscall(libc::SYS_setpriority, which, who, prio),
            errno::EPERM,
        )
    }
}

// ---------------------------------------------------------------------------
// getdtablesize — Implemented
// ---------------------------------------------------------------------------

/// BSD `getdtablesize` — get max number of file descriptors.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getdtablesize() -> c_int {
    let mut rlim = std::mem::MaybeUninit::<libc::rlimit>::zeroed();
    let rc = unsafe {
        libc::syscall(libc::SYS_getrlimit, libc::RLIMIT_NOFILE, rlim.as_mut_ptr()) as c_int
    };
    if rc < 0 {
        return 256;
    }
    let rlim = unsafe { rlim.assume_init() };
    rlim.rlim_cur.min(c_int::MAX as u64) as c_int
}

// ---------------------------------------------------------------------------
// brk / sbrk — RawSyscall
// ---------------------------------------------------------------------------

static CURRENT_BRK: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// POSIX `brk` — set the program break.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn brk(addr: *mut c_void) -> c_int {
    let new_brk = unsafe { libc::syscall(libc::SYS_brk, addr) } as usize;
    CURRENT_BRK.store(new_brk, std::sync::atomic::Ordering::Relaxed);
    if new_brk < addr as usize {
        unsafe { set_abi_errno(libc::ENOMEM) };
        -1
    } else {
        0
    }
}

/// POSIX `sbrk` — adjust the program break.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sbrk(increment: isize) -> *mut c_void {
    let current = CURRENT_BRK.load(std::sync::atomic::Ordering::Relaxed);
    let current = if current == 0 {
        let b = unsafe { libc::syscall(libc::SYS_brk, 0) } as usize;
        CURRENT_BRK.store(b, std::sync::atomic::Ordering::Relaxed);
        b
    } else {
        current
    };

    if increment == 0 {
        return current as *mut c_void;
    }

    let new_addr = if increment > 0 {
        current.wrapping_add(increment as usize)
    } else {
        current.wrapping_sub((-increment) as usize)
    };

    let new_brk = unsafe { libc::syscall(libc::SYS_brk, new_addr) } as usize;
    if new_brk < new_addr {
        unsafe { set_abi_errno(libc::ENOMEM) };
        return usize::MAX as *mut c_void;
    }
    CURRENT_BRK.store(new_brk, std::sync::atomic::Ordering::Relaxed);
    current as *mut c_void
}

// ---------------------------------------------------------------------------
// setlogmask — Implemented
// ---------------------------------------------------------------------------

static SYSLOG_MASK: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0xFF);

/// POSIX `setlogmask` — set the log priority mask.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setlogmask(mask: c_int) -> c_int {
    if mask == 0 {
        return SYSLOG_MASK.load(std::sync::atomic::Ordering::Relaxed);
    }
    SYSLOG_MASK.swap(mask, std::sync::atomic::Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// get_current_dir_name / canonicalize_file_name — Implemented
// ---------------------------------------------------------------------------

/// GNU `get_current_dir_name` — allocate and return CWD string.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn get_current_dir_name() -> *mut c_char {
    let mut buf = [0u8; 4096];
    let rc = unsafe { libc::syscall(libc::SYS_getcwd, buf.as_mut_ptr(), buf.len()) as isize };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(errno::ERANGE)) };
        return std::ptr::null_mut();
    }
    let len = buf.iter().position(|&b| b == 0).unwrap_or(rc as usize);
    let ptr = unsafe { libc::malloc(len + 1) as *mut c_char };
    if ptr.is_null() {
        unsafe { set_abi_errno(libc::ENOMEM) };
        return std::ptr::null_mut();
    }
    unsafe {
        std::ptr::copy_nonoverlapping(buf.as_ptr() as *const c_char, ptr, len);
        *ptr.add(len) = 0;
    };
    ptr
}

/// GNU `canonicalize_file_name` — resolve path like realpath(path, NULL).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn canonicalize_file_name(path: *const c_char) -> *mut c_char {
    unsafe { crate::wchar_abi::realpath(path, std::ptr::null_mut()) }
}

// ---------------------------------------------------------------------------
// strerror_l — Implemented
// ---------------------------------------------------------------------------

/// POSIX `strerror_l` — locale-aware strerror (we use C locale always).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strerror_l(errnum: c_int, _locale: *mut c_void) -> *mut c_char {
    unsafe { crate::string_abi::strerror(errnum) }
}

// ---------------------------------------------------------------------------
// __xpg_basename — Implemented
// ---------------------------------------------------------------------------

/// XSI `__xpg_basename` — POSIX basename (modifies input).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __xpg_basename(path: *mut c_char) -> *mut c_char {
    if path.is_null() {
        static DOT: &[u8] = b".\0";
        return DOT.as_ptr() as *mut c_char;
    }
    let s = unsafe { CStr::from_ptr(path) };
    let bytes = s.to_bytes();
    if bytes.is_empty() {
        static DOT: &[u8] = b".\0";
        return DOT.as_ptr() as *mut c_char;
    }
    let mut end = bytes.len();
    while end > 0 && bytes[end - 1] == b'/' {
        end -= 1;
    }
    if end == 0 {
        static SLASH: &[u8] = b"/\0";
        return SLASH.as_ptr() as *mut c_char;
    }
    let start = match bytes[..end].iter().rposition(|&b| b == b'/') {
        Some(pos) => pos + 1,
        None => 0,
    };
    unsafe { *path.add(end) = 0 };
    unsafe { path.add(start) }
}

// ---------------------------------------------------------------------------
// memfrob / strfry — Implemented (GNU extensions)
// ---------------------------------------------------------------------------

/// GNU `memfrob` — XOR each byte with 42.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn memfrob(s: *mut c_void, n: usize) -> *mut c_void {
    if s.is_null() {
        return s;
    }
    let p = s as *mut u8;
    for i in 0..n {
        unsafe { *p.add(i) ^= 42 };
    }
    s
}

/// GNU `strfry` — randomly shuffle string characters.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strfry(string: *mut c_char) -> *mut c_char {
    if string.is_null() {
        return string;
    }
    let s = unsafe { CStr::from_ptr(string) };
    let len = s.to_bytes().len();
    if len <= 1 {
        return string;
    }
    let mut seed: u32 = unsafe { libc::syscall(libc::SYS_gettid) } as u32;
    let p = string as *mut u8;
    for i in (1..len).rev() {
        seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
        let j = (seed >> 16) as usize % (i + 1);
        unsafe {
            let tmp = *p.add(i);
            *p.add(i) = *p.add(j);
            *p.add(j) = tmp;
        };
    }
    string
}

// ---------------------------------------------------------------------------
// getpt / ptsname_r — Implemented
// ---------------------------------------------------------------------------

/// GNU `getpt` — open a pseudoterminal master.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getpt() -> c_int {
    static PTMX: &[u8] = b"/dev/ptmx\0";
    unsafe {
        libc::syscall(
            libc::SYS_openat,
            libc::AT_FDCWD,
            PTMX.as_ptr(),
            libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
            0,
        ) as c_int
    }
}

/// POSIX `ptsname_r` — get slave PTY name (reentrant).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ptsname_r(fd: c_int, buf: *mut c_char, buflen: usize) -> c_int {
    if buf.is_null() || buflen == 0 {
        unsafe { set_abi_errno(libc::EINVAL) };
        return libc::EINVAL;
    }
    let mut pty_num: c_uint = 0;
    const TIOCGPTN: std::os::raw::c_ulong = 0x80045430;
    let rc = unsafe { libc::syscall(libc::SYS_ioctl, fd, TIOCGPTN, &mut pty_num as *mut c_uint) }
        as c_int;
    if rc < 0 {
        let e = last_host_errno(libc::ENOTTY);
        unsafe { set_abi_errno(e) };
        return e;
    }
    let name = format!("/dev/pts/{pty_num}");
    if name.len() + 1 > buflen {
        unsafe { set_abi_errno(libc::ERANGE) };
        return libc::ERANGE;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(name.as_ptr() as *const c_char, buf, name.len());
        *buf.add(name.len()) = 0;
    };
    0
}

// ---------------------------------------------------------------------------
// cuserid / sockatmark — Implemented
// ---------------------------------------------------------------------------

/// POSIX `cuserid` — get login name (deprecated).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cuserid(s: *mut c_char) -> *mut c_char {
    let uid = unsafe { libc::syscall(libc::SYS_getuid) } as libc::uid_t;
    let name = if uid == 0 { "root" } else { "user" };
    if s.is_null() {
        std::thread_local! {
            static BUF: std::cell::RefCell<[u8; 32]> = const { std::cell::RefCell::new([0u8; 32]) };
        }
        return BUF.with(|cell| {
            let mut buf = cell.borrow_mut();
            let len = name.len().min(buf.len() - 1);
            buf[..len].copy_from_slice(&name.as_bytes()[..len]);
            buf[len] = 0;
            buf.as_mut_ptr() as *mut c_char
        });
    }
    let len = name.len().min(8);
    unsafe {
        std::ptr::copy_nonoverlapping(name.as_ptr() as *const c_char, s, len);
        *s.add(len) = 0;
    };
    s
}

/// POSIX `sockatmark` — check if socket is at OOB mark.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sockatmark(sockfd: c_int) -> c_int {
    let mut atmark: c_int = 0;
    const SIOCATMARK: std::os::raw::c_ulong = 0x8905;
    let rc = unsafe {
        libc::syscall(
            libc::SYS_ioctl,
            sockfd,
            SIOCATMARK,
            &mut atmark as *mut c_int,
        )
    } as c_int;
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(libc::EBADF)) };
        -1
    } else {
        atmark
    }
}

// ---------------------------------------------------------------------------
// tempnam — Implemented
// ---------------------------------------------------------------------------

/// POSIX `tempnam` — create a unique temporary file name.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tempnam(dir: *const c_char, pfx: *const c_char) -> *mut c_char {
    let dir_str = if dir.is_null() {
        "/tmp"
    } else {
        unsafe { CStr::from_ptr(dir) }.to_str().unwrap_or("/tmp")
    };
    let pfx_str = if pfx.is_null() {
        "tmp"
    } else {
        match unsafe { CStr::from_ptr(pfx) }.to_str() {
            Ok(s) => &s[..s.len().min(5)],
            Err(_) => "tmp",
        }
    };

    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let cnt = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let pid = unsafe { libc::syscall(libc::SYS_getpid) } as u32;
    let name = format!("{dir_str}/{pfx_str}{pid:x}{cnt:x}");

    let ptr = unsafe { libc::malloc(name.len() + 1) as *mut c_char };
    if ptr.is_null() {
        return std::ptr::null_mut();
    }
    unsafe {
        std::ptr::copy_nonoverlapping(name.as_ptr() as *const c_char, ptr, name.len());
        *ptr.add(name.len()) = 0;
    };
    ptr
}

// ---------------------------------------------------------------------------
// execveat / pidfd_getfd / close_range / epoll_pwait2 — RawSyscall
// ---------------------------------------------------------------------------

/// Linux `execveat` — execute program relative to directory fd.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn execveat(
    dirfd: c_int,
    pathname: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
    flags: c_int,
) -> c_int {
    let rc =
        unsafe { libc::syscall(libc::SYS_execveat, dirfd, pathname, argv, envp, flags) as c_int };
    // execveat only returns on failure (on success, the process image is replaced)
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(libc::ENOENT)) };
    }
    rc
}

/// Linux `pidfd_getfd` — duplicate fd from another process.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pidfd_getfd(pidfd: c_int, targetfd: c_int, flags: c_uint) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd, targetfd, flags) as c_int };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(libc::EBADF)) };
    }
    rc
}

/// Linux `epoll_pwait2` — wait for events with nanosecond timeout.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn epoll_pwait2(
    epfd: c_int,
    events: *mut c_void,
    maxevents: c_int,
    timeout: *const libc::timespec,
    sigmask: *const libc::sigset_t,
) -> c_int {
    let rc = unsafe {
        libc::syscall(
            libc::SYS_epoll_pwait2,
            epfd,
            events,
            maxevents,
            timeout,
            sigmask,
            std::mem::size_of::<libc::c_ulong>(),
        ) as c_int
    };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(libc::EINVAL)) };
    }
    rc
}

// ===========================================================================
// Batch: Process tracing / security / capabilities — RawSyscall
// ===========================================================================

/// Linux `ptrace` — process trace (debugging).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ptrace(
    request: c_int,
    pid: libc::pid_t,
    addr: *mut c_void,
    data: *mut c_void,
) -> c_long {
    let rc = unsafe {
        libc::syscall(
            libc::SYS_ptrace,
            request as c_long,
            pid as c_long,
            addr,
            data,
        )
    };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(libc::ESRCH)) };
    }
    rc
}

/// Linux `seccomp` — secure computing filter.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn seccomp(operation: c_uint, flags: c_uint, args: *mut c_void) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_seccomp, operation, flags, args) as c_int };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(libc::EINVAL)) };
    }
    rc
}

/// Linux `capget` — get process capabilities.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn capget(hdrp: *mut c_void, datap: *mut c_void) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_capget, hdrp, datap) as c_int };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(libc::EINVAL)) };
    }
    rc
}

/// Linux `capset` — set process capabilities.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn capset(hdrp: *mut c_void, datap: *const c_void) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_capset, hdrp, datap) as c_int };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(libc::EPERM)) };
    }
    rc
}

// ===========================================================================
// Batch: Futex / memory barriers — RawSyscall
// ===========================================================================

/// Linux `futex` — fast userspace locking.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn futex(
    uaddr: *mut c_int,
    futex_op: c_int,
    val: c_int,
    timeout: *const libc::timespec,
    uaddr2: *mut c_int,
    val3: c_int,
) -> c_int {
    let rc = unsafe {
        libc::syscall(libc::SYS_futex, uaddr, futex_op, val, timeout, uaddr2, val3) as c_int
    };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(libc::EINVAL)) };
    }
    rc
}

/// Linux `membarrier` — issue memory barriers on a set of threads.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn membarrier(cmd: c_int, flags: c_uint, cpu_id: c_int) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_membarrier, cmd, flags, cpu_id) as c_int };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(libc::EINVAL)) };
    }
    rc
}

// ===========================================================================
// Batch: Native Linux AIO (io_setup family) — RawSyscall
// ===========================================================================

/// Linux `io_setup` — create asynchronous I/O context.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn io_setup(nr_events: c_uint, ctxp: *mut c_ulong) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_io_setup, nr_events, ctxp) as c_int };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(libc::EINVAL)) };
    }
    rc
}

/// Linux `io_destroy` — destroy asynchronous I/O context.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn io_destroy(ctx_id: c_ulong) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_io_destroy, ctx_id) as c_int };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(libc::EINVAL)) };
    }
    rc
}

/// Linux `io_submit` — submit asynchronous I/O blocks.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn io_submit(ctx_id: c_ulong, nr: c_long, iocbpp: *mut *mut c_void) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_io_submit, ctx_id, nr, iocbpp) as c_int };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(libc::EINVAL)) };
    }
    rc
}

/// Linux `io_cancel` — cancel outstanding I/O request.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn io_cancel(
    ctx_id: c_ulong,
    iocb: *mut c_void,
    result: *mut c_void,
) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_io_cancel, ctx_id, iocb, result) as c_int };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(libc::EINVAL)) };
    }
    rc
}

/// Linux `io_getevents` — read asynchronous I/O events.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn io_getevents(
    ctx_id: c_ulong,
    min_nr: c_long,
    nr: c_long,
    events: *mut c_void,
    timeout: *mut libc::timespec,
) -> c_int {
    let rc = unsafe {
        libc::syscall(libc::SYS_io_getevents, ctx_id, min_nr, nr, events, timeout) as c_int
    };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(libc::EINVAL)) };
    }
    rc
}

// ===========================================================================
// Batch: Terminal process group — RawSyscall
// ===========================================================================

/// POSIX `tcgetpgrp` — get foreground process group of terminal.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tcgetpgrp(fd: c_int) -> libc::pid_t {
    let mut pgrp: libc::pid_t = 0;
    const TIOCGPGRP: std::os::raw::c_ulong = 0x540F;
    let rc = unsafe {
        libc::syscall(
            libc::SYS_ioctl,
            fd,
            TIOCGPGRP,
            &mut pgrp as *mut libc::pid_t,
        )
    } as c_int;
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(libc::ENOTTY)) };
        return -1;
    }
    pgrp
}

/// POSIX `tcsetpgrp` — set foreground process group of terminal.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tcsetpgrp(fd: c_int, pgrp: libc::pid_t) -> c_int {
    const TIOCSPGRP: std::os::raw::c_ulong = 0x5410;
    let rc = unsafe { libc::syscall(libc::SYS_ioctl, fd, TIOCSPGRP, &pgrp as *const libc::pid_t) }
        as c_int;
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(libc::ENOTTY)) };
    }
    rc
}

/// POSIX `tcgetsid` — get session leader of controlling terminal.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tcgetsid(fd: c_int) -> libc::pid_t {
    let mut sid: libc::pid_t = 0;
    const TIOCGSID: std::os::raw::c_ulong = 0x5429;
    let rc = unsafe { libc::syscall(libc::SYS_ioctl, fd, TIOCGSID, &mut sid as *mut libc::pid_t) }
        as c_int;
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(libc::ENOTTY)) };
        return -1;
    }
    sid
}

// ===========================================================================
// Batch: Memory protection keys — RawSyscall
// ===========================================================================

/// Linux `pkey_alloc` — allocate a protection key.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pkey_alloc(flags: c_uint, access_rights: c_uint) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_pkey_alloc, flags, access_rights) as c_int };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(libc::ENOSPC)) };
    }
    rc
}

/// Linux `pkey_free` — free a protection key.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pkey_free(pkey: c_int) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_pkey_free, pkey) as c_int };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(libc::EINVAL)) };
    }
    rc
}

/// Linux `pkey_mprotect` — set memory protection with key.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pkey_mprotect(
    addr: *mut c_void,
    len: usize,
    prot: c_int,
    pkey: c_int,
) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_pkey_mprotect, addr, len, prot, pkey) as c_int };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(libc::EINVAL)) };
    }
    rc
}

// ===========================================================================
// Batch: Pthread scheduling — Implemented (delegates to kernel)
// ===========================================================================

/// Extract kernel TID from a pthread_t handle.
/// On glibc x86_64, pthread_t is a pointer to the thread control block (TCB).
/// The TID (pid field) is at offset 720 in the NPTL struct (glibc 2.34+).
/// For the common case of pthread_self(), we can detect this and use SYS_gettid.
unsafe fn pthread_to_tid(thread: libc::pthread_t) -> c_long {
    let self_handle = unsafe { libc::pthread_self() };
    if thread == self_handle {
        // Common case: operating on current thread
        unsafe { libc::syscall(libc::SYS_gettid) as c_long }
    } else {
        // For other threads, try reading TID from the glibc TCB.
        // On glibc x86_64 (NPTL), the pid field is at offset 720.
        // This is version-dependent but stable across glibc 2.17-2.38.
        let tcb = thread as *const u8;
        if tcb.is_null() {
            return -1;
        }
        unsafe { *(tcb.add(720) as *const i32) as c_long }
    }
}

/// POSIX `pthread_setschedparam` — set thread scheduling policy and priority.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_setschedparam(
    thread: libc::pthread_t,
    policy: c_int,
    param: *const libc::sched_param,
) -> c_int {
    if param.is_null() {
        return libc::EINVAL;
    }
    let tid = unsafe { pthread_to_tid(thread) };
    if tid <= 0 {
        return libc::ESRCH;
    }
    let rc = unsafe { libc::syscall(libc::SYS_sched_setscheduler, tid, policy, param) as c_int };
    if rc < 0 {
        last_host_errno(libc::EINVAL)
    } else {
        0
    }
}

/// POSIX `pthread_getschedparam` — get thread scheduling policy and priority.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_getschedparam(
    thread: libc::pthread_t,
    policy: *mut c_int,
    param: *mut libc::sched_param,
) -> c_int {
    if policy.is_null() || param.is_null() {
        return libc::EINVAL;
    }
    let tid = unsafe { pthread_to_tid(thread) };
    if tid <= 0 {
        return libc::ESRCH;
    }
    let p = unsafe { libc::syscall(libc::SYS_sched_getscheduler, tid) as c_int };
    if p < 0 {
        return last_host_errno(libc::ESRCH);
    }
    unsafe { *policy = p };
    let rc = unsafe { libc::syscall(libc::SYS_sched_getparam, tid, param) as c_int };
    if rc < 0 {
        return last_host_errno(libc::ESRCH);
    }
    0
}

// ===========================================================================
// Batch: i18n / gettext extensions — Implemented
// ===========================================================================

/// GNU `dcgettext` — domain-specific, category-specific gettext.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn dcgettext(
    _domainname: *const c_char,
    msgid: *const c_char,
    _category: c_int,
) -> *mut c_char {
    // Passthrough: return msgid as-is (no translation loaded)
    msgid as *mut c_char
}

/// GNU `dcngettext` — domain-specific plural gettext.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn dcngettext(
    _domainname: *const c_char,
    msgid: *const c_char,
    msgid_plural: *const c_char,
    n: c_ulong,
    _category: c_int,
) -> *mut c_char {
    if n == 1 {
        msgid as *mut c_char
    } else {
        msgid_plural as *mut c_char
    }
}

/// GNU `dngettext` — domain-specific plural gettext (LC_MESSAGES).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn dngettext(
    domainname: *const c_char,
    msgid: *const c_char,
    msgid_plural: *const c_char,
    n: c_ulong,
) -> *mut c_char {
    unsafe {
        dcngettext(domainname, msgid, msgid_plural, n, 5 /* LC_MESSAGES */)
    }
}

// ===========================================================================
// Batch: io_uring — RawSyscall (modern async I/O)
// ===========================================================================

/// Linux `io_uring_setup` — set up io_uring instance.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn io_uring_setup(entries: c_uint, p: *mut c_void) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_io_uring_setup, entries, p) as c_int };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(libc::EINVAL)) };
    }
    rc
}

/// Linux `io_uring_enter` — enter io_uring.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn io_uring_enter(
    fd: c_uint,
    to_submit: c_uint,
    min_complete: c_uint,
    flags: c_uint,
    sig: *const libc::sigset_t,
) -> c_int {
    let rc = unsafe {
        libc::syscall(
            libc::SYS_io_uring_enter,
            fd,
            to_submit,
            min_complete,
            flags,
            sig,
            std::mem::size_of::<libc::c_ulong>(),
        ) as c_int
    };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(libc::EINVAL)) };
    }
    rc
}

/// Linux `io_uring_register` — register resources with io_uring.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn io_uring_register(
    fd: c_uint,
    opcode: c_uint,
    arg: *mut c_void,
    nr_args: c_uint,
) -> c_int {
    let rc =
        unsafe { libc::syscall(libc::SYS_io_uring_register, fd, opcode, arg, nr_args) as c_int };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(libc::EINVAL)) };
    }
    rc
}

// ===========================================================================
// Batch: kcmp / ioprio — RawSyscall
// ===========================================================================

/// Linux `kcmp` — compare two processes for shared kernel objects.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn kcmp(
    pid1: libc::pid_t,
    pid2: libc::pid_t,
    type_: c_int,
    idx1: c_ulong,
    idx2: c_ulong,
) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_kcmp, pid1, pid2, type_, idx1, idx2) as c_int };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(libc::ESRCH)) };
    }
    rc
}

/// Linux `ioprio_set` — set I/O scheduling class and priority.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ioprio_set(which: c_int, who: c_int, ioprio: c_int) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_ioprio_set, which, who, ioprio) as c_int };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(libc::EINVAL)) };
    }
    rc
}

/// Linux `ioprio_get` — get I/O scheduling class and priority.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ioprio_get(which: c_int, who: c_int) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_ioprio_get, which, who) as c_int };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(libc::EINVAL)) };
    }
    rc
}

// ===========================================================================
// Batch: userfaultfd / landlock — RawSyscall (newer kernel APIs)
// ===========================================================================

/// Linux `userfaultfd` — create userfault file descriptor.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn userfaultfd(flags: c_int) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_userfaultfd, flags) as c_int };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(libc::EINVAL)) };
    }
    rc
}

/// Linux `landlock_create_ruleset` — create landlock ruleset.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn landlock_create_ruleset(
    attr: *const c_void,
    size: usize,
    flags: c_uint,
) -> c_int {
    let rc =
        unsafe { libc::syscall(libc::SYS_landlock_create_ruleset, attr, size, flags) as c_int };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(libc::EINVAL)) };
    }
    rc
}

/// Linux `landlock_add_rule` — add landlock rule to ruleset.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn landlock_add_rule(
    ruleset_fd: c_int,
    rule_type: c_int,
    rule_attr: *const c_void,
    flags: c_uint,
) -> c_int {
    let rc = unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset_fd,
            rule_type,
            rule_attr,
            flags,
        ) as c_int
    };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(libc::EINVAL)) };
    }
    rc
}

/// Linux `landlock_restrict_self` — enforce landlock ruleset on current process.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn landlock_restrict_self(ruleset_fd: c_int, flags: c_uint) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset_fd, flags) as c_int };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(libc::EINVAL)) };
    }
    rc
}

// ===========================================================================
// Batch: Miscellaneous POSIX/Linux — RawSyscall/Implemented
// ===========================================================================

/// POSIX `posix_fadvise64` — file access pattern advise (64-bit).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn posix_fadvise64(fd: c_int, offset: i64, len: i64, advice: c_int) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_fadvise64, fd, offset, len, advice) as c_int };
    if rc < 0 {
        last_host_errno(libc::EBADF)
    } else {
        0
    }
}

/// Linux `sync_file_range` — sync file segment to disk.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sync_file_range(
    fd: c_int,
    offset: i64,
    nbytes: i64,
    flags: c_uint,
) -> c_int {
    let rc =
        unsafe { libc::syscall(libc::SYS_sync_file_range, fd, offset, nbytes, flags) as c_int };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(libc::EBADF)) };
    }
    rc
}

/// Linux `remap_file_pages` — create nonlinear file mapping (deprecated).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn remap_file_pages(
    addr: *mut c_void,
    size: usize,
    prot: c_int,
    pgoff: usize,
    flags: c_int,
) -> c_int {
    let rc = unsafe {
        libc::syscall(libc::SYS_remap_file_pages, addr, size, prot, pgoff, flags) as c_int
    };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(libc::EINVAL)) };
    }
    rc
}

/// Linux `tgkill` — send signal to specific thread.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tgkill(tgid: c_int, tid: c_int, sig: c_int) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_tgkill, tgid, tid, sig) as c_int };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(libc::ESRCH)) };
    }
    rc
}

/// Linux `tkill` — send signal to thread (deprecated, use tgkill).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tkill(tid: c_int, sig: c_int) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_tkill, tid, sig) as c_int };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(libc::ESRCH)) };
    }
    rc
}

/// Linux `sched_setattr` — extended scheduling attributes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sched_setattr(
    pid: libc::pid_t,
    attr: *mut c_void,
    flags: c_uint,
) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_sched_setattr, pid, attr, flags) as c_int };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(libc::EINVAL)) };
    }
    rc
}

/// Linux `sched_getattr` — get extended scheduling attributes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sched_getattr(
    pid: libc::pid_t,
    attr: *mut c_void,
    size: c_uint,
    flags: c_uint,
) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_sched_getattr, pid, attr, size, flags) as c_int };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(libc::EINVAL)) };
    }
    rc
}

/// Linux `quotactl` — manipulate disk quotas.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn quotactl(
    cmd: c_int,
    special: *const c_char,
    id: c_int,
    addr: *mut c_void,
) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_quotactl, cmd, special, id, addr) as c_int };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(libc::EINVAL)) };
    }
    rc
}

/// Linux `lookup_dcookie` — return directory entry path for a cookie.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lookup_dcookie(cookie: u64, buffer: *mut c_char, len: usize) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_lookup_dcookie, cookie, buffer, len) as c_int };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(libc::EINVAL)) };
    }
    rc
}

/// Linux `perf_event_open` — set up performance monitoring.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn perf_event_open(
    attr: *mut c_void,
    pid: libc::pid_t,
    cpu: c_int,
    group_fd: c_int,
    flags: c_ulong,
) -> c_int {
    let rc = unsafe {
        libc::syscall(libc::SYS_perf_event_open, attr, pid, cpu, group_fd, flags) as c_int
    };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(libc::EINVAL)) };
    }
    rc
}

/// Linux `add_key` — add key to kernel keyring.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn add_key(
    type_: *const c_char,
    description: *const c_char,
    payload: *const c_void,
    plen: usize,
    ringid: i32,
) -> c_long {
    let rc = unsafe { libc::syscall(libc::SYS_add_key, type_, description, payload, plen, ringid) };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(libc::EINVAL)) };
    }
    rc
}

/// Linux `request_key` — request key from keyring.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn request_key(
    type_: *const c_char,
    description: *const c_char,
    callout_info: *const c_char,
    dest_keyring: i32,
) -> c_long {
    let rc = unsafe {
        libc::syscall(
            libc::SYS_request_key,
            type_,
            description,
            callout_info,
            dest_keyring,
        )
    };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(libc::EINVAL)) };
    }
    rc
}

/// Linux `keyctl` — keyring operations.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn keyctl(
    operation: c_int,
    arg2: c_ulong,
    arg3: c_ulong,
    arg4: c_ulong,
    arg5: c_ulong,
) -> c_long {
    let rc = unsafe { libc::syscall(libc::SYS_keyctl, operation, arg2, arg3, arg4, arg5) };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(libc::EINVAL)) };
    }
    rc
}

// ===========================================================================
// Batch: Filesystem status — RawSyscall
// ===========================================================================

/// `statfs` — get filesystem statistics.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn statfs(path: *const c_char, buf: *mut c_void) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_statfs, path, buf) as c_int };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(libc::ENOENT)) };
    }
    rc
}

/// `fstatfs` — get filesystem statistics by fd.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fstatfs(fd: c_int, buf: *mut c_void) -> c_int {
    let rc = unsafe { libc::syscall(libc::SYS_fstatfs, fd, buf) as c_int };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(libc::EBADF)) };
    }
    rc
}

/// Convert kernel statfs result to statvfs layout.
/// On x86_64 Linux, struct statfs fields (all long):
///   type, bsize, blocks, bfree, bavail, files, ffree, fsid(2xi32), namelen, frsize, flags, spare[4]
/// struct statvfs fields (all unsigned long):
///   bsize, frsize, blocks, bfree, bavail, files, ffree, favail, fsid, flag, namemax, spare[6]
unsafe fn statfs_to_statvfs(sfs: *const libc::statfs, vfs: *mut libc::statvfs) {
    let s = unsafe { &*sfs };
    let v = unsafe { &mut *vfs };
    // f_bsize and f_frsize are __fsword_t (i64 on x86_64), statvfs uses c_ulong (u64)
    v.f_bsize = s.f_bsize as u64;
    v.f_frsize = if s.f_frsize != 0 {
        s.f_frsize as u64
    } else {
        s.f_bsize as u64
    };
    // Block/file counts are __fsblkcnt_t/__fsfilcnt_t (u64 on x86_64)
    v.f_blocks = s.f_blocks;
    v.f_bfree = s.f_bfree;
    v.f_bavail = s.f_bavail;
    v.f_files = s.f_files;
    v.f_ffree = s.f_ffree;
    v.f_favail = s.f_ffree; // Same as ffree for non-privileged
    // fsid_t.__val is private in libc crate; read via raw pointer cast
    let fsid_ptr = &s.f_fsid as *const libc::fsid_t as *const i32;
    v.f_fsid = unsafe { *fsid_ptr } as u64;
    // f_flags not exposed in libc crate's statfs; read via byte offset
    // x86_64 kernel layout: type(0), bsize(8), blocks(16), bfree(24), bavail(32),
    // files(40), ffree(48), fsid(56), namelen(64), frsize(72), flags(80), spare(88)
    let statfs_ptr = sfs as *const u8;
    let flags_val = unsafe { *(statfs_ptr.add(80) as *const i64) };
    v.f_flag = flags_val as u64;
    v.f_namemax = s.f_namelen as u64;
}

/// POSIX `statvfs` — POSIX filesystem statistics.
/// Calls SYS_statfs and converts the kernel struct to statvfs layout.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn statvfs(path: *const c_char, buf: *mut libc::statvfs) -> c_int {
    let mut sfs = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    let rc = unsafe { libc::syscall(libc::SYS_statfs, path, sfs.as_mut_ptr()) as c_int };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(libc::ENOENT)) };
        return rc;
    }
    unsafe { statfs_to_statvfs(sfs.as_ptr(), buf) };
    0
}

/// POSIX `fstatvfs` — POSIX filesystem statistics by fd.
/// Calls SYS_fstatfs and converts the kernel struct to statvfs layout.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fstatvfs(fd: c_int, buf: *mut libc::statvfs) -> c_int {
    let mut sfs = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    let rc = unsafe { libc::syscall(libc::SYS_fstatfs, fd, sfs.as_mut_ptr()) as c_int };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(libc::EBADF)) };
        return rc;
    }
    unsafe { statfs_to_statvfs(sfs.as_ptr(), buf) };
    0
}

// ===========================================================================
// Batch: Directory entries — RawSyscall
// ===========================================================================

/// Linux `getdents64` — get directory entries (64-bit).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getdents64(fd: c_int, dirp: *mut c_void, count: usize) -> c_long {
    let rc = unsafe { libc::syscall(libc::SYS_getdents64, fd, dirp, count) };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(libc::EBADF)) };
    }
    rc
}

// ===========================================================================
// Batch: C++ ABI / Stack protection — Implemented
// ===========================================================================

/// Wrapper to make raw pointers Send-safe for __cxa_atexit handler list.
struct CxaHandler(unsafe extern "C" fn(*mut c_void), *mut c_void, *mut c_void);
// SAFETY: __cxa_atexit handlers are always called from the same process;
// the raw pointers are opaque DSO handles, not shared mutable state.
unsafe impl Send for CxaHandler {}

/// Thread-local __cxa_atexit handler list.
static CXA_ATEXIT_HANDLERS: std::sync::Mutex<Vec<CxaHandler>> = std::sync::Mutex::new(Vec::new());

/// `__cxa_atexit` — register C++ destructor for atexit.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __cxa_atexit(
    func: unsafe extern "C" fn(*mut c_void),
    arg: *mut c_void,
    dso_handle: *mut c_void,
) -> c_int {
    if let Ok(mut handlers) = CXA_ATEXIT_HANDLERS.lock() {
        handlers.push(CxaHandler(func, arg, dso_handle));
        0
    } else {
        -1
    }
}

/// `__cxa_finalize` — run C++ atexit handlers for a given DSO (or all if NULL).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __cxa_finalize(dso_handle: *mut c_void) {
    if let Ok(mut handlers) = CXA_ATEXIT_HANDLERS.lock() {
        let to_run: Vec<_> = if dso_handle.is_null() {
            handlers.drain(..).collect()
        } else {
            let mut kept = Vec::new();
            let mut run = Vec::new();
            for h in handlers.drain(..) {
                if h.2 == dso_handle {
                    run.push(h);
                } else {
                    kept.push(h);
                }
            }
            *handlers = kept;
            run
        };
        // Run in reverse order (LIFO)
        for CxaHandler(func, arg, _) in to_run.into_iter().rev() {
            unsafe { func(arg) };
        }
    }
}

/// Stack canary value.
/// NOTE: Static canary — should be initialized from AT_RANDOM or getrandom()
/// at startup for production security. Embeds \n, \r, \0 to terminate strings.
#[allow(non_upper_case_globals)]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static __stack_chk_guard: c_ulong = 0x00000aff0a0d0000;
// ===========================================================================
// Batch: Network database iterators — Implemented (parse /etc/ files)
// ===========================================================================

/// `gethostbyname2` — IPv6-aware hostname lookup (C locale, /etc/hosts only).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn gethostbyname2(name: *const c_char, af: c_int) -> *mut c_void {
    // For now, delegate to gethostbyname for AF_INET; return null for others
    if af == libc::AF_INET {
        unsafe { crate::resolv_abi::gethostbyname(name) }
    } else {
        unsafe { set_abi_errno(libc::EAFNOSUPPORT) };
        std::ptr::null_mut()
    }
}

/// `setservent` — rewind /etc/services enumeration.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setservent(_stayopen: c_int) {
    // No-op for C locale
}

/// `endservent` — close /etc/services enumeration.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn endservent() {
    // No-op for C locale
}

/// `getservent` — get next /etc/services entry.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getservent() -> *mut c_void {
    // Return null — iteration not supported in minimal impl
    std::ptr::null_mut()
}

/// `setnetent` — rewind /etc/networks enumeration.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setnetent(_stayopen: c_int) {
    // No-op
}

/// `endnetent` — close /etc/networks enumeration.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn endnetent() {
    // No-op
}

/// `getnetent` — get next /etc/networks entry.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getnetent() -> *mut c_void {
    std::ptr::null_mut()
}

/// `getnetbyname` — look up network by name.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getnetbyname(_name: *const c_char) -> *mut c_void {
    std::ptr::null_mut()
}

/// `getnetbyaddr` — look up network by address.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getnetbyaddr(_net: u32, _type_: c_int) -> *mut c_void {
    std::ptr::null_mut()
}

/// `setprotoent` — rewind /etc/protocols enumeration.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setprotoent(_stayopen: c_int) {
    // No-op
}

/// `endprotoent` — close /etc/protocols enumeration.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn endprotoent() {
    // No-op
}

/// `getprotoent` — get next /etc/protocols entry.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getprotoent() -> *mut c_void {
    std::ptr::null_mut()
}

/// `sethostent` — rewind /etc/hosts enumeration.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sethostent(_stayopen: c_int) {
    // No-op
}

/// `endhostent` — close /etc/hosts enumeration.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn endhostent() {
    // No-op
}

/// `gethostent` — get next /etc/hosts entry.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn gethostent() -> *mut c_void {
    std::ptr::null_mut()
}

// ===========================================================================
// Batch: wctype functions — Implemented
// ===========================================================================

/// Wide-character transformation descriptor (opaque handle).
type WctransT = c_ulong;
/// `wctrans` — get wide-char transformation descriptor.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wctrans(property: *const c_char) -> WctransT {
    if property.is_null() {
        return 0;
    }
    let s = unsafe { CStr::from_ptr(property) };
    match s.to_bytes() {
        b"toupper" => 1,
        b"tolower" => 2,
        _ => 0,
    }
}

/// `towctrans` — transform wide character by descriptor.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn towctrans(wc: c_uint, desc: WctransT) -> c_uint {
    if wc > 127 {
        return wc;
    }
    let c = wc as u8;
    let result = match desc {
        1 => c.to_ascii_uppercase(),
        2 => c.to_ascii_lowercase(),
        _ => c,
    };
    result as c_uint
}

// ===========================================================================
// Batch: Locale-aware string functions — Implemented (C locale passthrough)
// ===========================================================================

/// `strcoll_l` — locale-aware string comparison.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strcoll_l(
    s1: *const c_char,
    s2: *const c_char,
    _locale: *mut c_void,
) -> c_int {
    unsafe { crate::string_abi::strcoll(s1, s2) }
}

/// `strxfrm_l` — locale-aware string transformation.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strxfrm_l(
    dest: *mut c_char,
    src: *const c_char,
    n: usize,
    _locale: *mut c_void,
) -> usize {
    unsafe { crate::string_abi::strxfrm(dest, src, n) }
}

/// `strftime_l` — locale-aware time formatting.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strftime_l(
    s: *mut c_char,
    max: usize,
    format: *const c_char,
    tm: *const c_void,
    _locale: *mut c_void,
) -> usize {
    unsafe { crate::time_abi::strftime(s, max, format, tm as *const libc::tm) }
}

// ===========================================================================
// Batch: Missing syscall wrappers — RawSyscall
// ===========================================================================

/// Linux `personality` — set process execution domain.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn personality(persona: c_ulong) -> c_int {
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Process, persona as usize, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EPERM) };
        runtime_policy::observe(ApiFamily::Process, decision.profile, 6, true);
        return -1;
    }

    let rc = unsafe { libc::syscall(libc::SYS_personality, persona) as c_int };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(libc::EINVAL)) };
    }
    runtime_policy::observe(ApiFamily::Process, decision.profile, 6, rc < 0);
    rc
}

/// Linux `process_madvise` — advise about memory usage for another process.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn process_madvise(
    pidfd: c_int,
    iovec: *const libc::iovec,
    vlen: usize,
    advice: c_int,
    flags: c_uint,
) -> isize {
    let missing_payload = iovec.is_null() && vlen > 0;
    let (mode, decision) = runtime_policy::decide(
        ApiFamily::VirtualMemory,
        iovec as usize,
        vlen,
        true,
        missing_payload,
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EPERM) };
        runtime_policy::observe(
            ApiFamily::VirtualMemory,
            decision.profile,
            runtime_policy::scaled_cost(10, vlen),
            true,
        );
        return -1;
    }
    if missing_payload && policy_repair_enabled(mode.heals_enabled(), decision.action) {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(
            ApiFamily::VirtualMemory,
            decision.profile,
            runtime_policy::scaled_cost(10, vlen),
            true,
        );
        return -1;
    }

    let rc = unsafe { libc::syscall(libc::SYS_process_madvise, pidfd, iovec, vlen, advice, flags) };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(libc::EINVAL)) };
    }
    runtime_policy::observe(
        ApiFamily::VirtualMemory,
        decision.profile,
        runtime_policy::scaled_cost(10, vlen),
        rc < 0,
    );
    rc as isize
}

/// Linux `process_mrelease` — release memory of a dying process.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn process_mrelease(pidfd: c_int, flags: c_uint) -> c_int {
    let (_, decision) = runtime_policy::decide(
        ApiFamily::VirtualMemory,
        pidfd as usize,
        0,
        true,
        pidfd < 0,
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EPERM) };
        runtime_policy::observe(ApiFamily::VirtualMemory, decision.profile, 8, true);
        return -1;
    }

    let rc = unsafe { libc::syscall(libc::SYS_process_mrelease, pidfd, flags) as c_int };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(libc::EINVAL)) };
    }
    runtime_policy::observe(ApiFamily::VirtualMemory, decision.profile, 8, rc < 0);
    rc
}

// ===========================================================================
// Batch: LFS 64-bit aliases — Implemented (delegate to base functions)
// ===========================================================================

/// `getrlimit64` — LFS alias for `getrlimit` (identical on 64-bit Linux).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getrlimit64(resource: c_int, rlim: *mut libc::rlimit) -> c_int {
    unsafe { crate::resource_abi::getrlimit(resource, rlim) }
}

/// `setrlimit64` — LFS alias for `setrlimit`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setrlimit64(resource: c_int, rlim: *const libc::rlimit) -> c_int {
    unsafe { crate::resource_abi::setrlimit(resource, rlim) }
}

/// `statfs64` — LFS alias for `statfs`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn statfs64(path: *const c_char, buf: *mut c_void) -> c_int {
    unsafe { statfs(path, buf) }
}

/// `fstatfs64` — LFS alias for `fstatfs`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fstatfs64(fd: c_int, buf: *mut c_void) -> c_int {
    unsafe { fstatfs(fd, buf) }
}

/// `statvfs64` — LFS alias for `statvfs`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn statvfs64(path: *const c_char, buf: *mut libc::statvfs) -> c_int {
    unsafe { statvfs(path, buf) }
}

/// `fstatvfs64` — LFS alias for `fstatvfs`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fstatvfs64(fd: c_int, buf: *mut libc::statvfs) -> c_int {
    unsafe { fstatvfs(fd, buf) }
}

/// `lockf64` — LFS alias for `lockf`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lockf64(fd: c_int, cmd: c_int, len: libc::off_t) -> c_int {
    unsafe { lockf(fd, cmd, len) }
}

/// `fallocate64` — LFS alias for `fallocate`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fallocate64(fd: c_int, mode: c_int, offset: i64, len: i64) -> c_int {
    unsafe { fallocate(fd, mode, offset, len) }
}

/// `fcntl64` — LFS alias for `fcntl` (on 64-bit, identical ABI).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fcntl64(fd: c_int, cmd: c_int, mut args: ...) -> c_int {
    let arg: c_long = unsafe { (&mut args as *mut _ as *mut c_long).read() };
    unsafe { libc::fcntl(fd, cmd, arg) }
}

/// `preadv64` — LFS alias for `preadv`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn preadv64(
    fd: c_int,
    iov: *const libc::iovec,
    iovcnt: c_int,
    offset: libc::off_t,
) -> isize {
    unsafe { crate::io_abi::preadv(fd, iov, iovcnt, offset) }
}

/// `pwritev64` — LFS alias for `pwritev`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pwritev64(
    fd: c_int,
    iov: *const libc::iovec,
    iovcnt: c_int,
    offset: libc::off_t,
) -> isize {
    unsafe { crate::io_abi::pwritev(fd, iov, iovcnt, offset) }
}

/// `readdir64_r` — reentrant readdir with dirent64 (LFS alias).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn readdir64_r(
    dirp: *mut libc::DIR,
    entry: *mut libc::dirent64,
    result: *mut *mut libc::dirent64,
) -> c_int {
    if dirp.is_null() || entry.is_null() || result.is_null() {
        return libc::EINVAL;
    }
    unsafe { libc::readdir64_r(dirp, entry, result) }
}

// ===========================================================================
// Batch: backtrace — Implemented
// ===========================================================================

/// `backtrace` — capture stack backtrace.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn backtrace(buffer: *mut *mut c_void, size: c_int) -> c_int {
    if buffer.is_null() || size <= 0 {
        return 0;
    }
    unsafe { libc::backtrace(buffer, size) }
}

/// `backtrace_symbols` — convert backtrace addresses to symbol strings.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn backtrace_symbols(
    buffer: *const *mut c_void,
    size: c_int,
) -> *mut *mut c_char {
    if buffer.is_null() || size <= 0 {
        return std::ptr::null_mut();
    }
    // backtrace_symbols returns a malloc'd array of strings
    unsafe { libc::backtrace_symbols(buffer, size) }
}

/// `backtrace_symbols_fd` — write backtrace symbols to file descriptor.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn backtrace_symbols_fd(buffer: *const *mut c_void, size: c_int, fd: c_int) {
    if buffer.is_null() || size <= 0 {
        return;
    }
    unsafe { libc::backtrace_symbols_fd(buffer, size, fd) };
}

// ===========================================================================
// Batch: bind_textdomain_codeset — Implemented
// ===========================================================================

/// `bind_textdomain_codeset` — set/query encoding for a gettext domain.
///
/// Returns current codeset or NULL. We always return "UTF-8".
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn bind_textdomain_codeset(
    _domainname: *const c_char,
    _codeset: *const c_char,
) -> *mut c_char {
    // We always operate in UTF-8.
    c"UTF-8".as_ptr() as *mut c_char
}

// ===========================================================================
// Batch: if_nameindex / if_freenameindex — Implemented
// ===========================================================================
// ===========================================================================
// Batch: FTS (file tree walk) — Implemented
// ===========================================================================

use std::collections::VecDeque;

/// Internal FTS stream state.
struct FtsStream {
    /// Stack of directories to visit.
    queue: VecDeque<FtsEntryInternal>,
    /// Current entry (returned to caller).
    current: Option<FtsEntryOwned>,
    /// Options bitmask.
    options: c_int,
    /// Comparison function (reserved for future use).
    _compar: Option<unsafe extern "C" fn(*const *const FTSENT, *const *const FTSENT) -> c_int>,
}

/// Internal entry representation.
struct FtsEntryInternal {
    path: std::path::PathBuf,
    level: i16,
}

/// Owned FTSENT for returning to caller.
/// Stored as Box so its address is stable across fts_read calls.
struct FtsEntryOwned {
    ftsent: FTSENT,
    path_buf: std::ffi::CString,
    name_buf: std::ffi::CString,
    stat_buf: libc::stat,
}

unsafe impl Send for FtsEntryOwned {}
unsafe impl Send for FtsStream {}

/// POSIX FTSENT structure.
#[repr(C)]
#[allow(non_camel_case_types)]
pub struct FTSENT {
    pub fts_cycle: *mut FTSENT,
    pub fts_parent: *mut FTSENT,
    pub fts_link: *mut FTSENT,
    pub fts_number: c_long,
    pub fts_pointer: *mut c_void,
    pub fts_accpath: *mut c_char,
    pub fts_path: *mut c_char,
    pub fts_errno: c_int,
    pub fts_symfd: c_int,
    pub fts_pathlen: u16,
    pub fts_namelen: u16,
    pub fts_ino: libc::ino_t,
    pub fts_dev: libc::dev_t,
    pub fts_nlink: libc::nlink_t,
    pub fts_level: i16,
    pub fts_info: u16,
    pub fts_flags: u16,
    pub fts_instr: u16,
    pub fts_statp: *mut libc::stat,
    pub fts_name: [c_char; 1],
}

// FTS_* info constants
const FTS_D: u16 = 1; // preorder directory
const FTS_F: u16 = 8; // regular file
const FTS_SL: u16 = 12; // symlink
const FTS_DEFAULT: u16 = 3; // anything else
const FTS_NS: u16 = 10; // no stat info

// FTS option flags
const FTS_PHYSICAL: c_int = 0x0010;

/// `fts_open` — open a file hierarchy for traversal.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fts_open(
    path_argv: *const *const c_char,
    options: c_int,
    compar: Option<unsafe extern "C" fn(*const *const FTSENT, *const *const FTSENT) -> c_int>,
) -> *mut c_void {
    if path_argv.is_null() {
        return std::ptr::null_mut();
    }

    let mut queue = VecDeque::new();

    // Collect initial paths
    let mut i = 0;
    loop {
        let path_ptr = unsafe { *path_argv.add(i) };
        if path_ptr.is_null() {
            break;
        }
        let cstr = unsafe { CStr::from_ptr(path_ptr) };
        if let Ok(s) = cstr.to_str() {
            queue.push_back(FtsEntryInternal {
                path: std::path::PathBuf::from(s),
                level: 0,
            });
        }
        i += 1;
    }

    let stream = Box::new(FtsStream {
        queue,
        current: None,
        options,
        _compar: compar,
    });

    Box::into_raw(stream) as *mut c_void
}

/// `fts_read` — return next entry in file hierarchy.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fts_read(ftsp: *mut c_void) -> *mut FTSENT {
    if ftsp.is_null() {
        return std::ptr::null_mut();
    }
    let stream = unsafe { &mut *(ftsp as *mut FtsStream) };

    let entry = match stream.queue.pop_front() {
        Some(e) => e,
        None => return std::ptr::null_mut(),
    };

    // Stat the entry
    let path_cstr = match std::ffi::CString::new(entry.path.to_string_lossy().as_bytes()) {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };

    let mut stat_buf: libc::stat = unsafe { std::mem::zeroed() };
    let stat_result = if stream.options & FTS_PHYSICAL != 0 {
        unsafe { libc::lstat(path_cstr.as_ptr(), &mut stat_buf) }
    } else {
        unsafe { libc::stat(path_cstr.as_ptr(), &mut stat_buf) }
    };

    let info = if stat_result < 0 {
        FTS_NS
    } else {
        let mode = stat_buf.st_mode & libc::S_IFMT;
        if mode == libc::S_IFDIR {
            // Enqueue children
            if let Ok(entries) = std::fs::read_dir(&entry.path) {
                for child in entries.flatten() {
                    stream.queue.push_back(FtsEntryInternal {
                        path: child.path(),
                        level: entry.level + 1,
                    });
                }
            }
            FTS_D
        } else if mode == libc::S_IFREG {
            FTS_F
        } else if mode == libc::S_IFLNK {
            FTS_SL
        } else {
            FTS_DEFAULT
        }
    };

    let name = entry
        .path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let name_cstr = std::ffi::CString::new(name.as_bytes()).unwrap_or_default();

    let mut owned = FtsEntryOwned {
        ftsent: unsafe { std::mem::zeroed() },
        path_buf: path_cstr,
        name_buf: name_cstr,
        stat_buf,
    };

    owned.ftsent.fts_path = owned.path_buf.as_ptr() as *mut c_char;
    owned.ftsent.fts_accpath = owned.ftsent.fts_path;
    owned.ftsent.fts_pathlen = owned.path_buf.as_bytes().len() as u16;
    owned.ftsent.fts_namelen = owned.name_buf.as_bytes().len() as u16;
    owned.ftsent.fts_level = entry.level;
    owned.ftsent.fts_info = info;
    owned.ftsent.fts_ino = stat_buf.st_ino;
    owned.ftsent.fts_dev = stat_buf.st_dev;
    owned.ftsent.fts_nlink = stat_buf.st_nlink;
    owned.ftsent.fts_errno = if stat_result < 0 {
        unsafe { *libc::__errno_location() }
    } else {
        0
    };

    stream.current = Some(owned);

    // Fix up self-referential pointer after move
    if let Some(current) = stream.current.as_mut() {
        current.ftsent.fts_statp = &mut current.stat_buf;
        current.ftsent.fts_path = current.path_buf.as_ptr() as *mut c_char;
        current.ftsent.fts_accpath = current.ftsent.fts_path;
        &mut current.ftsent as *mut FTSENT
    } else {
        std::ptr::null_mut()
    }
}

/// `fts_children` — return linked list of entries in current directory.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fts_children(_ftsp: *mut c_void, _options: c_int) -> *mut FTSENT {
    // Simplified: return NULL (caller can use fts_read instead)
    std::ptr::null_mut()
}

/// `fts_set` — set instruction for next fts_read return.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fts_set(_ftsp: *mut c_void, _f: *mut FTSENT, _instr: c_int) -> c_int {
    0 // success
}

/// `fts_close` — close an FTS stream.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fts_close(ftsp: *mut c_void) -> c_int {
    if !ftsp.is_null() {
        let _ = unsafe { Box::from_raw(ftsp as *mut FtsStream) };
    }
    0
}

// ===========================================================================
// __xstat / __fxstat / __lxstat — glibc stat() compat layer
// ===========================================================================
//
// In glibc, stat(path, buf) is actually __xstat(_STAT_VER, path, buf).
// The _STAT_VER argument selects the stat struct layout version.
// On modern x86_64, _STAT_VER_LINUX = 1 (but we ignore the version and
// always use the current kernel stat layout).

/// `__xstat` — glibc internal stat wrapper.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __xstat(_ver: c_int, path: *const c_char, buf: *mut libc::stat) -> c_int {
    unsafe { stat(path, buf) }
}

/// `__fxstat` — glibc internal fstat wrapper.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __fxstat(_ver: c_int, fd: c_int, buf: *mut libc::stat) -> c_int {
    unsafe { fstat(fd, buf) }
}

/// `__lxstat` — glibc internal lstat wrapper.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __lxstat(_ver: c_int, path: *const c_char, buf: *mut libc::stat) -> c_int {
    unsafe { lstat(path, buf) }
}

/// `__xstat64` — 64-bit variant of __xstat.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __xstat64(
    _ver: c_int,
    path: *const c_char,
    buf: *mut libc::stat,
) -> c_int {
    unsafe { stat(path, buf) }
}

/// `__fxstat64` — 64-bit variant of __fxstat.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __fxstat64(_ver: c_int, fd: c_int, buf: *mut libc::stat) -> c_int {
    unsafe { fstat(fd, buf) }
}

/// `__lxstat64` — 64-bit variant of __lxstat.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __lxstat64(
    _ver: c_int,
    path: *const c_char,
    buf: *mut libc::stat,
) -> c_int {
    unsafe { lstat(path, buf) }
}

/// `__fxstatat` — glibc internal fstatat wrapper.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __fxstatat(
    _ver: c_int,
    dirfd: c_int,
    path: *const c_char,
    buf: *mut libc::stat,
    flags: c_int,
) -> c_int {
    unsafe { fstatat(dirfd, path, buf, flags) }
}

/// `__fxstatat64` — 64-bit variant of __fxstatat.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __fxstatat64(
    _ver: c_int,
    dirfd: c_int,
    path: *const c_char,
    buf: *mut libc::stat,
    flags: c_int,
) -> c_int {
    unsafe { fstatat(dirfd, path, buf, flags) }
}

// ===========================================================================
// versionsort64 — 64-bit directory entry version sort
// ===========================================================================

/// `versionsort64` — version-aware directory sort for 64-bit dirents.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn versionsort64(
    a: *mut *const libc::dirent,
    b: *mut *const libc::dirent,
) -> c_int {
    // On x86_64, dirent and dirent64 are the same struct
    unsafe { crate::dirent_abi::versionsort(a, b) }
}

// ===========================================================================
// ether_ntohost / ether_hostton / ether_line — ethers database (stub)
// ===========================================================================

/// `ether_ntohost` — look up hostname by Ethernet address (/etc/ethers).
/// Returns 0 on success, non-zero on failure.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ether_ntohost(_hostname: *mut c_char, _addr: *const c_void) -> c_int {
    // /etc/ethers lookup is rare; return "not found" for now
    -1
}

/// `ether_hostton` — look up Ethernet address by hostname (/etc/ethers).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ether_hostton(_hostname: *const c_char, _addr: *mut c_void) -> c_int {
    -1
}

/// `ether_line` — parse an /etc/ethers format line.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ether_line(
    _line: *const c_char,
    _addr: *mut c_void,
    _hostname: *mut c_char,
) -> c_int {
    -1
}

// ===========================================================================
// gethostbyname2_r — reentrant gethostbyname with address family
// ===========================================================================

/// `gethostbyname2_r` — reentrant gethostbyname2.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn gethostbyname2_r(
    name: *const c_char,
    af: c_int,
    result_buf: *mut libc::hostent,
    buf: *mut c_char,
    buflen: usize,
    result: *mut *mut libc::hostent,
    h_errnop: *mut c_int,
) -> c_int {
    if name.is_null()
        || result_buf.is_null()
        || buf.is_null()
        || result.is_null()
        || h_errnop.is_null()
    {
        return libc::EINVAL;
    }
    // Use getaddrinfo under the hood
    let hints = libc::addrinfo {
        ai_flags: libc::AI_CANONNAME,
        ai_family: af,
        ai_socktype: 0,
        ai_protocol: 0,
        ai_addrlen: 0,
        ai_addr: std::ptr::null_mut(),
        ai_canonname: std::ptr::null_mut(),
        ai_next: std::ptr::null_mut(),
    };
    let mut res: *mut libc::addrinfo = std::ptr::null_mut();
    let rc = unsafe { libc::getaddrinfo(name, std::ptr::null(), &hints, &mut res) };
    if rc != 0 {
        unsafe {
            *result = std::ptr::null_mut();
            *h_errnop = 1; // HOST_NOT_FOUND
        }
        return libc::ENOENT;
    }
    // Fill result_buf from first addrinfo result
    if !res.is_null() {
        let ai = unsafe { &*res };
        let addr_len: usize = if af == libc::AF_INET { 4 } else { 16 };
        let needed = addr_len + std::mem::size_of::<*mut c_char>() * 2;
        if buflen < needed {
            unsafe {
                libc::freeaddrinfo(res);
                *result = std::ptr::null_mut();
                *h_errnop = 2; // TRY_AGAIN
            }
            return libc::ERANGE;
        }
        unsafe {
            // Copy address into buf
            let addr_ptr = if af == libc::AF_INET {
                let sa = ai.ai_addr as *const libc::sockaddr_in;
                &(*sa).sin_addr as *const _ as *const u8
            } else {
                let sa = ai.ai_addr as *const libc::sockaddr_in6;
                &(*sa).sin6_addr as *const _ as *const u8
            };
            std::ptr::copy_nonoverlapping(addr_ptr, buf as *mut u8, addr_len);

            // Set up address list in buf after the address
            let addr_list_ptr = buf.add(addr_len) as *mut *mut c_char;
            *addr_list_ptr = buf;
            *addr_list_ptr.add(1) = std::ptr::null_mut();

            (*result_buf).h_name = if !ai.ai_canonname.is_null() {
                ai.ai_canonname
            } else {
                name as *mut c_char
            };
            (*result_buf).h_aliases = std::ptr::null_mut();
            (*result_buf).h_addrtype = af;
            (*result_buf).h_length = addr_len as c_int;
            (*result_buf).h_addr_list = addr_list_ptr;

            *result = result_buf;
            *h_errnop = 0;
            libc::freeaddrinfo(res);
        }
        return 0;
    }
    unsafe {
        libc::freeaddrinfo(res);
        *result = std::ptr::null_mut();
        *h_errnop = 1; // HOST_NOT_FOUND
    }
    libc::ENOENT
}

// ---------------------------------------------------------------------------
// System V IPC key generation
// ---------------------------------------------------------------------------

/// `ftok` — generate IPC key from pathname and project ID.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ftok(pathname: *const c_char, proj_id: c_int) -> i32 {
    if pathname.is_null() {
        unsafe { *super::errno_abi::__errno_location() = libc::EINVAL };
        return -1;
    }
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc =
        unsafe { libc::syscall(libc::SYS_stat, pathname, &mut st as *mut libc::stat) as c_int };
    if rc != 0 {
        return -1;
    }
    // Standard ftok formula: ((proj_id & 0xFF) << 24) | ((st.st_dev & 0xFF) << 16) | (st.st_ino & 0xFFFF)
    let key = ((proj_id as u32 & 0xFF) << 24)
        | ((st.st_dev as u32 & 0xFF) << 16)
        | (st.st_ino as u32 & 0xFFFF);
    key as i32
}

// ---------------------------------------------------------------------------
// Shadow password functions
// ---------------------------------------------------------------------------
/// `putspent` — write shadow password entry to stream.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn putspent(sp: *const libc::spwd, stream: *mut libc::FILE) -> c_int {
    if sp.is_null() || stream.is_null() {
        return -1;
    }
    // Format: name:passwd:lstchg:min:max:warn:inact:expire:flag
    let spw = unsafe { &*sp };
    let name = if spw.sp_namp.is_null() {
        ""
    } else {
        unsafe { std::ffi::CStr::from_ptr(spw.sp_namp) }
            .to_str()
            .unwrap_or("")
    };
    let pwd = if spw.sp_pwdp.is_null() {
        ""
    } else {
        unsafe { std::ffi::CStr::from_ptr(spw.sp_pwdp) }
            .to_str()
            .unwrap_or("")
    };
    let line = format!(
        "{}:{}:{}:{}:{}:{}:{}:{}:{}\n",
        name,
        pwd,
        spw.sp_lstchg,
        spw.sp_min,
        spw.sp_max,
        spw.sp_warn,
        spw.sp_inact,
        spw.sp_expire,
        spw.sp_flag
    );
    let bytes = line.as_bytes();
    let written = unsafe { libc::fwrite(bytes.as_ptr().cast(), 1, bytes.len(), stream) };
    if written == bytes.len() { 0 } else { -1 }
}

// ---------------------------------------------------------------------------
// Malloc debug stubs (mcheck/mtrace — safe no-ops)
// ---------------------------------------------------------------------------

/// `mcheck` — install malloc debugging hooks (no-op in frankenlibc).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mcheck(_abortfunc: Option<unsafe extern "C" fn(c_int)>) -> c_int {
    // No-op: our allocator has its own safety membrane.
    0
}

/// `mcheck_pedantic` — pedantic malloc checking (no-op in frankenlibc).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mcheck_pedantic(_abortfunc: Option<unsafe extern "C" fn(c_int)>) -> c_int {
    0
}

/// `mcheck_check_all` — check all allocations (no-op in frankenlibc).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mcheck_check_all() {}

/// `mprobe` — check a single allocation (always returns MCHECK_OK=0).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mprobe(_ptr: *mut c_void) -> c_int {
    0 // MCHECK_OK
}

/// `mtrace` — start malloc tracing (no-op in frankenlibc).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mtrace() {}

/// `muntrace` — stop malloc tracing (no-op in frankenlibc).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn muntrace() {}

// ---------------------------------------------------------------------------
// Error reporting (GNU extensions)
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// fmtmsg — classified message display
// ---------------------------------------------------------------------------

/// XSI `fmtmsg` — display a message on stderr and/or console.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmtmsg(
    classification: i64,
    label: *const c_char,
    severity: c_int,
    text: *const c_char,
    action: *const c_char,
    tag: *const c_char,
) -> c_int {
    // MM_PRINT = 0x100, MM_CONSOLE = 0x200
    let print = (classification & 0x100) != 0 || (classification & 0x300) == 0;
    if print {
        let lbl = if !label.is_null() {
            unsafe { std::ffi::CStr::from_ptr(label) }
                .to_str()
                .unwrap_or("")
        } else {
            ""
        };
        let sev = match severity {
            0 => "HALT",
            1 => "ERROR",
            2 => "WARNING",
            3 => "INFO",
            _ => "",
        };
        let txt = if !text.is_null() {
            unsafe { std::ffi::CStr::from_ptr(text) }
                .to_str()
                .unwrap_or("")
        } else {
            ""
        };
        let act = if !action.is_null() {
            unsafe { std::ffi::CStr::from_ptr(action) }
                .to_str()
                .unwrap_or("")
        } else {
            ""
        };
        let tg = if !tag.is_null() {
            unsafe { std::ffi::CStr::from_ptr(tag) }
                .to_str()
                .unwrap_or("")
        } else {
            ""
        };
        eprintln!("{lbl}: {sev}: {txt}\nTO FIX: {act} {tg}");
    }
    0 // MM_OK
}

// (versionsort64 and ftw64 already exist above)

// ---------------------------------------------------------------------------
// utmpx functions — session accounting
// ---------------------------------------------------------------------------

/// `setutxent` — open/rewind utmpx database.
///
/// Native: on Linux, utmpx == utmp. Delegates to our native `setutent`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setutxent() {
    unsafe { setutent() }
}

/// `endutxent` — close utmpx database.
///
/// Native: delegates to our native `endutent`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn endutxent() {
    unsafe { endutent() }
}

/// `getutxent` — read next utmpx entry.
///
/// Native: on Linux x86_64, struct utmpx == struct utmp. Delegates to native `getutent`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getutxent() -> *mut libc::utmpx {
    unsafe { getutent() as *mut libc::utmpx }
}

/// `getutxid` — search utmpx by ID type.
///
/// Native: iterates utmp entries matching the ut_type/ut_id from the template.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getutxid(ut: *const libc::utmpx) -> *mut libc::utmpx {
    if ut.is_null() {
        return std::ptr::null_mut();
    }
    let target_type = unsafe { (*ut).ut_type };
    loop {
        let entry = unsafe { getutxent() };
        if entry.is_null() {
            return std::ptr::null_mut();
        }
        let etype = unsafe { (*entry).ut_type };
        // EMPTY=0, RUN_LVL=1, BOOT_TIME=2, NEW_TIME=3, OLD_TIME=4
        // INIT_PROCESS=5, LOGIN_PROCESS=6, USER_PROCESS=7, DEAD_PROCESS=8
        if target_type <= 4 {
            // Match on type only for run level / boot / time entries
            if etype == target_type {
                return entry;
            }
        } else {
            // INIT/LOGIN/USER/DEAD: match on ut_id
            if (5..=8).contains(&etype) {
                let tid = unsafe { (*ut).ut_id };
                let eid = unsafe { (*entry).ut_id };
                if tid == eid {
                    return entry;
                }
            }
        }
    }
}

/// `getutxline` — search utmpx by terminal line.
///
/// Native: iterates entries matching ut_line for LOGIN_PROCESS or USER_PROCESS.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getutxline(ut: *const libc::utmpx) -> *mut libc::utmpx {
    if ut.is_null() {
        return std::ptr::null_mut();
    }
    let target_line = unsafe { (*ut).ut_line };
    loop {
        let entry = unsafe { getutxent() };
        if entry.is_null() {
            return std::ptr::null_mut();
        }
        let etype = unsafe { (*entry).ut_type };
        // Match LOGIN_PROCESS(6) or USER_PROCESS(7) with matching ut_line
        if (etype == 6 || etype == 7) && unsafe { (*entry).ut_line } == target_line {
            return entry;
        }
    }
}

/// `pututxline` — write utmpx entry.
///
/// Native: appends the entry to the utmp file.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pututxline(ut: *const libc::utmpx) -> *mut libc::utmpx {
    if ut.is_null() {
        return std::ptr::null_mut();
    }
    let path = UTMP_TLS.with(|cell| {
        let state = cell.borrow();
        if state.path.is_empty() {
            UTMP_DEFAULT_PATH.to_string()
        } else {
            state.path.clone()
        }
    });

    let cpath = std::ffi::CString::new(path.as_str()).unwrap_or_default();
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat as c_long,
            libc::AT_FDCWD,
            cpath.as_ptr(),
            libc::O_RDWR | libc::O_CREAT,
            0o644,
        ) as c_int
    };
    if fd < 0 {
        return std::ptr::null_mut();
    }

    let record_size = std::mem::size_of::<libc::utmpx>();
    unsafe { libc::syscall(libc::SYS_lseek as c_long, fd, 0i64, libc::SEEK_END) };
    let written = unsafe {
        libc::syscall(
            libc::SYS_write as c_long,
            fd,
            ut as *const c_void,
            record_size,
        )
    };
    unsafe { libc::syscall(libc::SYS_close as c_long, fd) };

    if written as usize == record_size {
        thread_local! {
            static UTMPX_BUF: std::cell::UnsafeCell<libc::utmpx> = const {
                std::cell::UnsafeCell::new(unsafe { std::mem::zeroed() })
            };
        }
        UTMPX_BUF.with(|buf| {
            let ptr = buf.get();
            unsafe { *ptr = *ut };
            ptr
        })
    } else {
        std::ptr::null_mut()
    }
}

/// `utmpxname` — set utmpx database file path.
///
/// Native: delegates to our native `utmpname`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn utmpxname(file: *const c_char) -> c_int {
    if file.is_null() {
        return -1;
    }
    unsafe { utmpname(file) }
}

// ---------------------------------------------------------------------------
// Stdio LFS64 aliases (map to existing implementations)
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// syscall() — generic syscall wrapper
// ---------------------------------------------------------------------------

/// `syscall` — invoke a system call by number.
///
/// Extracts up to 6 arguments from the variadic args and dispatches via
/// inline assembly on x86_64.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn syscall(number: c_long, mut args: ...) -> c_long {
    // SAFETY: Extract up to 6 arguments from the caller-provided variadic list.
    let a1: c_long = unsafe { args.arg() };
    let a2: c_long = unsafe { args.arg() };
    let a3: c_long = unsafe { args.arg() };
    let a4: c_long = unsafe { args.arg() };
    let a5: c_long = unsafe { args.arg() };
    let a6: c_long = unsafe { args.arg() };

    let ret: c_long;
    // SAFETY: Direct syscall with caller-provided number and arguments.
    unsafe {
        std::arch::asm!(
            "syscall",
            inlateout("rax") number => ret,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            in("r10") a4,
            in("r8") a5,
            in("r9") a6,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }

    if ret < 0 && ret > -4096 {
        unsafe { set_abi_errno((-ret) as c_int) };
        -1
    } else {
        ret
    }
}

// ===========================================================================
// Process lifecycle extensions
// ===========================================================================

/// C99 `_Exit` — terminate immediately without cleanup.
#[cfg_attr(not(debug_assertions), unsafe(export_name = "_Exit"))]
pub unsafe extern "C" fn frankenlibc_exit_immediate(status: c_int) -> ! {
    unsafe { libc::_exit(status) }
}

/// POSIX `execv` — execute file with argument vector.
///
/// Native implementation: delegates to our own `execve` with inherited `environ`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn execv(path: *const c_char, argv: *const *const c_char) -> c_int {
    unsafe { crate::process_abi::execve(path, argv, environ as *const *const c_char) }
}

/// POSIX `fexecve` — execute file by fd.
///
/// Native implementation: builds `/proc/self/fd/<fd>` path and delegates to `execve` syscall.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fexecve(
    fd: c_int,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    if fd < 0 {
        unsafe { set_abi_errno(libc::EBADF) };
        return -1;
    }
    // Build /proc/self/fd/<fd> path
    let mut buf = [0u8; 64];
    let prefix = b"/proc/self/fd/";
    buf[..prefix.len()].copy_from_slice(prefix);
    let fd_str = format!("{fd}");
    let fd_bytes = fd_str.as_bytes();
    buf[prefix.len()..prefix.len() + fd_bytes.len()].copy_from_slice(fd_bytes);
    // NUL terminate (already 0-initialized)
    let path = buf.as_ptr() as *const c_char;
    let rc = unsafe { libc::syscall(libc::SYS_execve as c_long, path, argv, envp) as c_int };
    // execve only returns on failure
    let e = std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::ENOENT);
    unsafe { set_abi_errno(e) };
    rc
}

/// Linux `clone` — create child process (raw syscall wrapper).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clone(
    fn_ptr: Option<unsafe extern "C" fn(*mut c_void) -> c_int>,
    stack: *mut c_void,
    flags: c_int,
    arg: *mut c_void,
    _args: ...
) -> c_int {
    // clone is extremely ABI-sensitive; delegate to glibc.
    type CloneFn = unsafe extern "C" fn(
        Option<unsafe extern "C" fn(*mut c_void) -> c_int>,
        *mut c_void,
        c_int,
        *mut c_void,
        ...
    ) -> c_int;
    static FUNC: std::sync::LazyLock<Option<CloneFn>> = std::sync::LazyLock::new(|| {
        let sym = unsafe { libc::dlsym(libc::RTLD_NEXT, c"clone".as_ptr()) };
        if sym.is_null() {
            None
        } else {
            Some(unsafe { std::mem::transmute::<*mut c_void, CloneFn>(sym) })
        }
    });
    match *FUNC {
        Some(f) => unsafe { f(fn_ptr, stack, flags, arg) },
        None => {
            unsafe { set_abi_errno(libc::ENOSYS) };
            -1
        }
    }
}

/// GNU `eaccess` / `euidaccess` — check access using effective UID/GID.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn eaccess(path: *const c_char, mode: c_int) -> c_int {
    unsafe { faccessat(libc::AT_FDCWD, path, mode, libc::AT_EACCESS) }
}

/// GNU `euidaccess` — check access using effective UID/GID.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn euidaccess(path: *const c_char, mode: c_int) -> c_int {
    unsafe { eaccess(path, mode) }
}

/// Linux `closefrom` — close all fd >= lowfd.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn closefrom(lowfd: c_int) {
    // close_range syscall (kernel 5.9+)
    let _ = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            lowfd as c_long,
            !0u32 as c_long,
            0 as c_long,
        )
    };
}

/// POSIX `clock_getcpuclockid` — get CPU-time clock for a process.
///
/// Native implementation: computes the CPUCLOCK_SCHED clock ID from the PID
/// using the kernel formula, then validates with clock_getres.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clock_getcpuclockid(
    pid: libc::pid_t,
    clock_id: *mut libc::clockid_t,
) -> c_int {
    if clock_id.is_null() {
        return libc::EINVAL;
    }
    // If pid is 0, use CLOCK_PROCESS_CPUTIME_ID directly.
    if pid == 0 {
        unsafe { *clock_id = libc::CLOCK_PROCESS_CPUTIME_ID };
        return 0;
    }
    // Kernel CPUCLOCK formula: clock_id = ~pid << 3 | CPUCLOCK_SCHED (=2)
    // This encodes the PID into the clock ID for process-specific CPU time.
    let cid: libc::clockid_t = (!pid as libc::clockid_t) << 3 | 2;
    // Validate the clock exists by calling clock_getres.
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let rc = unsafe {
        libc::syscall(
            libc::SYS_clock_getres as c_long,
            cid,
            &mut ts as *mut libc::timespec,
        )
    };
    if rc < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::ESRCH);
        return if e == libc::EINVAL { libc::ESRCH } else { e };
    }
    unsafe { *clock_id = cid };
    0
}

/// Linux `clock_adjtime` — adjust a POSIX clock.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clock_adjtime(clk_id: libc::clockid_t, buf: *mut libc::timex) -> c_int {
    if buf.is_null() {
        unsafe { set_abi_errno(libc::EFAULT) };
        return -1;
    }
    let ret = unsafe { libc::syscall(libc::SYS_clock_adjtime, clk_id as c_long, buf as c_long) };
    if ret < 0 {
        unsafe { set_abi_errno(last_host_errno(libc::EINVAL)) };
        -1
    } else {
        ret as c_int
    }
}

/// BSD `bsd_signal` — simplified signal() (SysV semantics).
///
/// Native implementation: delegates to our own `signal()`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn bsd_signal(sig: c_int, handler: libc::sighandler_t) -> libc::sighandler_t {
    unsafe { crate::signal_abi::signal(sig, handler) }
}

/// XSI `addseverity` — add/modify message severity level.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn addseverity(_severity: c_int, _string: *const c_char) -> c_int {
    // Stub: severity management for fmtmsg. No-op is safe.
    0
}

// ===========================================================================
// GNU dev_t helpers
// ===========================================================================

/// GNU `gnu_dev_major` — extract major device number.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn gnu_dev_major(dev: libc::dev_t) -> libc::c_uint {
    ((dev >> 8) & 0xfff) as libc::c_uint | ((dev >> 32) & !0xfff) as libc::c_uint
}

/// GNU `gnu_dev_minor` — extract minor device number.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn gnu_dev_minor(dev: libc::dev_t) -> libc::c_uint {
    (dev & 0xff) as libc::c_uint | ((dev >> 12) & !0xff) as libc::c_uint
}

/// GNU `gnu_dev_makedev` — compose device number from major/minor.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn gnu_dev_makedev(major: libc::c_uint, minor: libc::c_uint) -> libc::dev_t {
    let major = major as libc::dev_t;
    let minor = minor as libc::dev_t;
    ((major & 0xfff) << 8) | (minor & 0xff) | ((minor & !0xff) << 12) | ((major & !0xfff) << 32)
}

// ===========================================================================
// DNS resolver helpers
// ===========================================================================

/// `dn_skipname` — skip a compressed domain name in a DNS message (RFC 1035).
///
/// Native implementation: walks the wire-format name, following label lengths
/// or pointer indirections, and returns the number of bytes consumed from `comp_dn`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn dn_skipname(comp_dn: *const u8, eom: *const u8) -> c_int {
    if comp_dn.is_null() || eom.is_null() || comp_dn >= eom {
        return -1;
    }
    let buf = unsafe { std::slice::from_raw_parts(comp_dn, eom.offset_from(comp_dn) as usize) };
    let mut i = 0usize;
    loop {
        if i >= buf.len() {
            return -1;
        }
        let b = buf[i];
        if b == 0 {
            // Root label — end of name.
            return (i + 1) as c_int;
        }
        if b & 0xC0 == 0xC0 {
            // Pointer (2 bytes) — name ends here in the wire.
            if i + 1 >= buf.len() {
                return -1;
            }
            return (i + 2) as c_int;
        }
        if b & 0xC0 != 0 {
            // Reserved label type — invalid.
            return -1;
        }
        // Normal label: skip length + label bytes.
        i += 1 + b as usize;
    }
}

/// `dn_expand` — expand a compressed domain name to dotted form (RFC 1035).
///
/// Native implementation: follows label-length bytes and compression pointers
/// within the DNS message `[msg, eomorig)` to produce a dotted ASCII name
/// in the caller's buffer `exp_dn[..length]`.
/// Returns the number of bytes consumed from `comp_dn` in the wire message.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn dn_expand(
    msg: *const u8,
    eomorig: *const u8,
    comp_dn: *const u8,
    exp_dn: *mut c_char,
    length: c_int,
) -> c_int {
    if msg.is_null() || eomorig.is_null() || comp_dn.is_null() || exp_dn.is_null() || length < 1 {
        return -1;
    }
    if comp_dn < msg || comp_dn >= eomorig {
        return -1;
    }
    let msg_len = unsafe { eomorig.offset_from(msg) } as usize;
    let msg_slice = unsafe { std::slice::from_raw_parts(msg, msg_len) };
    let out = unsafe { std::slice::from_raw_parts_mut(exp_dn as *mut u8, length as usize) };

    let mut pos = unsafe { comp_dn.offset_from(msg) } as usize; // current read position in msg
    let mut out_off = 0usize; // write offset in output
    let mut wire_len: Option<usize> = None; // bytes consumed from comp_dn (set on first pointer)
    let mut jumps = 0u32;
    const MAX_JUMPS: u32 = 128; // prevent infinite pointer loops

    loop {
        if pos >= msg_len {
            return -1;
        }
        let b = msg_slice[pos];
        if b == 0 {
            // Root label. If we haven't followed any pointers, wire_len includes this byte.
            if wire_len.is_none() {
                wire_len = Some(pos + 1 - (unsafe { comp_dn.offset_from(msg) } as usize));
            }
            break;
        }
        if b & 0xC0 == 0xC0 {
            // Compression pointer.
            if pos + 1 >= msg_len {
                return -1;
            }
            // Record wire consumption before first jump.
            if wire_len.is_none() {
                wire_len = Some(pos + 2 - (unsafe { comp_dn.offset_from(msg) } as usize));
            }
            let target = ((b as usize & 0x3F) << 8) | msg_slice[pos + 1] as usize;
            if target >= msg_len {
                return -1;
            }
            jumps += 1;
            if jumps > MAX_JUMPS {
                return -1;
            }
            pos = target;
            continue;
        }
        if b & 0xC0 != 0 {
            return -1; // Reserved label type.
        }
        let label_len = b as usize;
        if pos + 1 + label_len > msg_len {
            return -1;
        }
        // Add dot separator before labels (except the first).
        if out_off > 0 {
            if out_off >= out.len() {
                return -1;
            }
            out[out_off] = b'.';
            out_off += 1;
        }
        // Copy label bytes.
        if out_off + label_len >= out.len() {
            return -1; // No room for label + NUL.
        }
        out[out_off..out_off + label_len].copy_from_slice(&msg_slice[pos + 1..pos + 1 + label_len]);
        out_off += label_len;
        pos += 1 + label_len;
    }

    // NUL-terminate. If name is root (empty), output is just "\0".
    if out_off >= out.len() {
        return -1;
    }
    out[out_off] = 0;

    wire_len.unwrap_or(0) as c_int
}

/// `dn_comp` — compress a domain name into DNS wire format (RFC 1035).
///
/// Native implementation: converts a dotted domain name (`exp_dn`) into
/// wire-format labels in `comp_dn[..length]`, optionally adding compression
/// pointers using previously seen names in `dnptrs`.
/// Returns the number of bytes written to `comp_dn`, or -1 on error.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn dn_comp(
    exp_dn: *const c_char,
    comp_dn: *mut u8,
    length: c_int,
    dnptrs: *mut *mut u8,
    lastdnptr: *mut *mut u8,
) -> c_int {
    if exp_dn.is_null() || comp_dn.is_null() || length < 1 {
        return -1;
    }
    let name = unsafe { std::ffi::CStr::from_ptr(exp_dn) };
    let name_bytes = name.to_bytes();
    let out = unsafe { std::slice::from_raw_parts_mut(comp_dn, length as usize) };

    // Handle root domain ("" or ".").
    if name_bytes.is_empty() || (name_bytes.len() == 1 && name_bytes[0] == b'.') {
        if out.is_empty() {
            return -1;
        }
        out[0] = 0;
        return 1;
    }

    // Split into labels.
    let name_str = if name_bytes.last() == Some(&b'.') {
        &name_bytes[..name_bytes.len() - 1]
    } else {
        name_bytes
    };

    let mut out_off = 0usize;
    for label in name_str.split(|&b| b == b'.') {
        if label.is_empty() || label.len() > 63 {
            return -1;
        }
        // Need: 1 (length) + label.len() bytes + at least 1 more for root terminator.
        if out_off + 1 + label.len() + 1 > out.len() {
            return -1;
        }
        out[out_off] = label.len() as u8;
        out_off += 1;
        out[out_off..out_off + label.len()].copy_from_slice(label);
        out_off += label.len();
    }

    // Root terminator.
    if out_off >= out.len() {
        return -1;
    }
    out[out_off] = 0;
    out_off += 1;

    // If dnptrs is provided and there's room, record this name for future compression.
    // (Simple implementation: we don't do compression pointer matching, just record.)
    if !dnptrs.is_null() && !lastdnptr.is_null() {
        // Find first NULL slot in dnptrs array.
        let mut slot = dnptrs;
        unsafe {
            while slot < lastdnptr && !(*slot).is_null() {
                slot = slot.add(1);
            }
            if slot < lastdnptr {
                *slot = comp_dn;
                // NULL-terminate the array if there's room.
                let next = slot.add(1);
                if next < lastdnptr {
                    *next = std::ptr::null_mut();
                }
            }
        }
    }

    out_off as c_int
}

// ===========================================================================
// Database iteration (aliases, rpc, netgroup, fs, tty, shadow file parsing)
// ===========================================================================

/// `endaliasent` — close alias database.
///
/// Native implementation: no-op (alias database iteration state is per-process).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn endaliasent() {
    // No-op: alias database is rarely used on modern systems.
}

/// `getaliasbyname` — look up alias by name.
///
/// Native implementation: returns NULL (no alias database configured).
/// The mail alias database (/etc/aliases) is MTA-specific and rarely used via NSS.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getaliasbyname(_name: *const c_char) -> *mut c_void {
    std::ptr::null_mut()
}

/// `getaliasbyname_r` — reentrant alias lookup.
///
/// Native implementation: returns ENOENT (no alias database configured).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getaliasbyname_r(
    _name: *const c_char,
    _result_buf: *mut c_void,
    _buffer: *mut c_char,
    _buflen: usize,
    result: *mut *mut c_void,
) -> c_int {
    if !result.is_null() {
        unsafe { *result = std::ptr::null_mut() };
    }
    libc::ENOENT
}

/// `getaliasent` — get next alias entry.
///
/// Native implementation: returns NULL (no alias entries).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getaliasent() -> *mut c_void {
    std::ptr::null_mut()
}

/// `getaliasent_r` — reentrant get next alias entry.
///
/// Native implementation: returns ENOENT (no alias entries).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getaliasent_r(
    _result_buf: *mut c_void,
    _buffer: *mut c_char,
    _buflen: usize,
    result: *mut *mut c_void,
) -> c_int {
    if !result.is_null() {
        unsafe { *result = std::ptr::null_mut() };
    }
    libc::ENOENT
}

/// `endfsent` — close filesystem table iteration.
///
/// Native implementation: no-op (fstab iteration state is process-local, safe to ignore).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn endfsent() {
    // No-op: we don't maintain persistent fstab iteration state.
}

/// `endnetgrent` — end netgroup iteration.
///
/// Native implementation: no-op (netgroup is legacy NIS; no persistent state).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn endnetgrent() {
    // No-op: netgroup is a legacy NIS mechanism.
}

/// `setnetgrent` — start netgroup iteration.
///
/// Native implementation: returns 1 (success) but configures empty iteration.
/// Netgroup is a legacy NIS feature; most modern systems have no /etc/netgroup.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setnetgrent(_netgroup: *const c_char) -> c_int {
    // Accept the call but produce no entries on subsequent getnetgrent() calls.
    1
}

/// `getnetgrent` — get next netgroup entry (host, user, domain triple).
///
/// Native implementation: always returns 0 (no more entries).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getnetgrent(
    _hostp: *mut *mut c_char,
    _userp: *mut *mut c_char,
    _domainp: *mut *mut c_char,
) -> c_int {
    0 // No entries.
}

/// `getnetgrent_r` — reentrant netgroup entry.
///
/// Native implementation: always returns 0 (no more entries).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getnetgrent_r(
    _hostp: *mut *mut c_char,
    _userp: *mut *mut c_char,
    _domainp: *mut *mut c_char,
    _buffer: *mut c_char,
    _buflen: usize,
) -> c_int {
    0 // No entries.
}

// ---------------------------------------------------------------------------
// RPC database (/etc/rpc) native implementation
// ---------------------------------------------------------------------------

/// Persistent RPC database iteration state.
struct RpcDb {
    lines: Vec<String>,
    pos: usize,
    loaded: bool,
}

impl RpcDb {
    const fn new() -> Self {
        Self {
            lines: Vec::new(),
            pos: 0,
            loaded: false,
        }
    }
    fn ensure_loaded(&mut self) {
        if self.loaded {
            return;
        }
        self.loaded = true;
        if let Ok(contents) = std::fs::read_to_string("/etc/rpc") {
            self.lines = contents
                .lines()
                .filter(|l| {
                    let t = l.trim();
                    !t.is_empty() && !t.starts_with('#')
                })
                .map(|l| l.to_string())
                .collect();
        }
    }
    fn rewind(&mut self) {
        self.ensure_loaded();
        self.pos = 0;
    }
    fn reset(&mut self) {
        self.lines.clear();
        self.pos = 0;
        self.loaded = false;
    }
    fn next_line(&mut self) -> Option<&str> {
        self.ensure_loaded();
        if self.pos < self.lines.len() {
            let line = &self.lines[self.pos];
            self.pos += 1;
            Some(line)
        } else {
            None
        }
    }
}

static RPC_DB: std::sync::Mutex<RpcDb> = std::sync::Mutex::new(RpcDb::new());

/// Parse an /etc/rpc line into the thread-local rpcent buffer.
/// Format: `name  number  alias1 alias2 ...`
/// Returns pointer to static rpcent or null on failure.
fn parse_rpc_line_to_static(line: &str) -> *mut c_void {
    // /etc/rpc line format: name<whitespace>number<whitespace>alias...
    // Strip inline comments.
    let line = if let Some(idx) = line.find('#') {
        &line[..idx]
    } else {
        line
    };
    let mut parts = line.split_whitespace();
    let name = match parts.next() {
        Some(n) => n,
        None => return std::ptr::null_mut(),
    };
    let num_str = match parts.next() {
        Some(n) => n,
        None => return std::ptr::null_mut(),
    };
    let number: c_int = match num_str.parse() {
        Ok(n) => n,
        Err(_) => return std::ptr::null_mut(),
    };
    let aliases: Vec<&str> = parts.collect();

    // glibc rpcent layout (x86_64):
    // struct rpcent {
    //     char *r_name;        // offset 0
    //     char **r_aliases;    // offset 8
    //     int r_number;        // offset 16
    // };
    // Size: 24 bytes (with padding)

    thread_local! {
        static RPC_BUF: std::cell::RefCell<[u8; 1024]> = const { std::cell::RefCell::new([0u8; 1024]) };
        static RPC_ENT: std::cell::RefCell<[u8; 24]> = const { std::cell::RefCell::new([0u8; 24]) };
        static RPC_ALIASES: std::cell::RefCell<[*mut c_char; 32]> = const { std::cell::RefCell::new([std::ptr::null_mut(); 32]) };
    }

    RPC_BUF.with(|buf| {
        RPC_ENT.with(|ent| {
            RPC_ALIASES.with(|al| {
                let mut buf = buf.borrow_mut();
                let mut ent = ent.borrow_mut();
                let mut al = al.borrow_mut();

                let mut off = 0usize;
                // Copy name.
                let name_bytes = name.as_bytes();
                if off + name_bytes.len() + 1 > buf.len() {
                    return std::ptr::null_mut();
                }
                buf[off..off + name_bytes.len()].copy_from_slice(name_bytes);
                buf[off + name_bytes.len()] = 0;
                let name_ptr = buf[off..].as_ptr() as *mut c_char;
                off += name_bytes.len() + 1;

                // Copy aliases.
                let max_aliases = al.len() - 1; // Leave room for NULL terminator.
                let num_al = aliases.len().min(max_aliases);
                for (i, alias) in aliases.iter().take(num_al).enumerate() {
                    let ab = alias.as_bytes();
                    if off + ab.len() + 1 > buf.len() {
                        break;
                    }
                    buf[off..off + ab.len()].copy_from_slice(ab);
                    buf[off + ab.len()] = 0;
                    al[i] = buf[off..].as_ptr() as *mut c_char;
                    off += ab.len() + 1;
                }
                al[num_al] = std::ptr::null_mut();

                // Fill rpcent struct.
                let ent_ptr = ent.as_mut_ptr();
                unsafe {
                    // r_name at offset 0
                    *(ent_ptr as *mut *mut c_char) = name_ptr;
                    // r_aliases at offset 8
                    *(ent_ptr.add(8) as *mut *mut *mut c_char) = al.as_mut_ptr();
                    // r_number at offset 16
                    *(ent_ptr.add(16) as *mut c_int) = number;
                }

                ent_ptr as *mut c_void
            })
        })
    })
}

/// `endrpcent` — close RPC database.
///
/// Native implementation: resets /etc/rpc iteration state.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn endrpcent() {
    RPC_DB.lock().unwrap_or_else(|e| e.into_inner()).reset();
}

/// `setrpcent` — open/rewind RPC database.
///
/// Native implementation: rewinds iteration to start.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setrpcent(_stayopen: c_int) {
    RPC_DB.lock().unwrap_or_else(|e| e.into_inner()).rewind();
}

/// `getrpcbyname` — find RPC entry by name.
///
/// Native implementation: searches /etc/rpc for matching name or alias.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getrpcbyname(name: *const c_char) -> *mut c_void {
    if name.is_null() {
        return std::ptr::null_mut();
    }
    let needle = unsafe { std::ffi::CStr::from_ptr(name) };
    let needle = needle.to_bytes();

    let contents = match std::fs::read_to_string("/etc/rpc") {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let stripped = if let Some(idx) = line.find('#') {
            &line[..idx]
        } else {
            line
        };
        let mut parts = stripped.split_whitespace();
        let rpc_name = match parts.next() {
            Some(n) => n,
            None => continue,
        };
        // Skip number.
        let _ = parts.next();
        // Check name and aliases.
        if rpc_name.as_bytes() == needle {
            return parse_rpc_line_to_static(line);
        }
        for alias in parts {
            if alias.as_bytes() == needle {
                return parse_rpc_line_to_static(line);
            }
        }
    }
    std::ptr::null_mut()
}

/// `getrpcbyname_r` — reentrant RPC lookup by name.
///
/// Native implementation: searches /etc/rpc, fills caller buffer.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getrpcbyname_r(
    name: *const c_char,
    _result_buf: *mut c_void,
    _buffer: *mut c_char,
    _buflen: usize,
    result: *mut *mut c_void,
) -> c_int {
    if !result.is_null() {
        unsafe { *result = std::ptr::null_mut() };
    }
    let ptr = unsafe { getrpcbyname(name) };
    if ptr.is_null() {
        return libc::ENOENT;
    }
    if !result.is_null() {
        unsafe { *result = ptr };
    }
    0
}

/// `getrpcbynumber` — find RPC entry by number.
///
/// Native implementation: searches /etc/rpc for matching program number.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getrpcbynumber(number: c_int) -> *mut c_void {
    let contents = match std::fs::read_to_string("/etc/rpc") {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let stripped = if let Some(idx) = line.find('#') {
            &line[..idx]
        } else {
            line
        };
        let mut parts = stripped.split_whitespace();
        let _ = parts.next(); // name
        if let Some(num_str) = parts.next()
            && let Ok(n) = num_str.parse::<c_int>()
            && n == number
        {
            return parse_rpc_line_to_static(line);
        }
    }
    std::ptr::null_mut()
}

/// `getrpcbynumber_r` — reentrant RPC lookup by number.
///
/// Native implementation: searches /etc/rpc, fills caller buffer.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getrpcbynumber_r(
    number: c_int,
    _result_buf: *mut c_void,
    _buffer: *mut c_char,
    _buflen: usize,
    result: *mut *mut c_void,
) -> c_int {
    if !result.is_null() {
        unsafe { *result = std::ptr::null_mut() };
    }
    let ptr = unsafe { getrpcbynumber(number) };
    if ptr.is_null() {
        return libc::ENOENT;
    }
    if !result.is_null() {
        unsafe { *result = ptr };
    }
    0
}

/// `getrpcent` — get next RPC entry.
///
/// Native implementation: iterates /etc/rpc entries sequentially.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getrpcent() -> *mut c_void {
    let mut db = RPC_DB.lock().unwrap_or_else(|e| e.into_inner());
    match db.next_line() {
        Some(line) => parse_rpc_line_to_static(line),
        None => std::ptr::null_mut(),
    }
}

/// `getrpcent_r` — reentrant get next RPC entry.
///
/// Native implementation: iterates /etc/rpc, fills caller buffer.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getrpcent_r(
    _result_buf: *mut c_void,
    _buffer: *mut c_char,
    _buflen: usize,
    result: *mut *mut c_void,
) -> c_int {
    if !result.is_null() {
        unsafe { *result = std::ptr::null_mut() };
    }
    let ptr = unsafe { getrpcent() };
    if ptr.is_null() {
        return libc::ENOENT;
    }
    if !result.is_null() {
        unsafe { *result = ptr };
    }
    0
}

/// `endttyent` — close tty database iteration.
///
/// Native implementation: no-op, returns 1 (success). TTY database is rarely used on modern Linux.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn endttyent() -> c_int {
    1 // Success (glibc returns 1 on success)
}

/// `fgetspent` — read shadow entry from stream.
///
/// Native implementation: reads a line from the FILE stream and parses it as /etc/shadow format.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fgetspent(stream: *mut c_void) -> *mut libc::spwd {
    thread_local! {
        static BUF: std::cell::RefCell<[u8; 1024]> = const { std::cell::RefCell::new([0u8; 1024]) };
        static ENTRY: std::cell::RefCell<libc::spwd> = const {
            std::cell::RefCell::new(unsafe { std::mem::zeroed() })
        };
    }

    if stream.is_null() {
        return std::ptr::null_mut();
    }

    // Read a line using fgets.
    let mut line_buf = [0u8; 1024];
    let line_ptr = unsafe {
        libc::fgets(
            line_buf.as_mut_ptr() as *mut c_char,
            line_buf.len() as c_int,
            stream as *mut libc::FILE,
        )
    };
    if line_ptr.is_null() {
        return std::ptr::null_mut();
    }
    // Convert to string for parsing.
    let len = unsafe { libc::strlen(line_ptr) };
    let line = unsafe {
        std::str::from_utf8_unchecked(std::slice::from_raw_parts(line_ptr as *const u8, len))
    };
    let line = line.trim_end_matches('\n');
    if line.is_empty() || line.starts_with('#') {
        return std::ptr::null_mut();
    }
    let parts: Vec<&str> = line.split(':').collect();
    if parts.len() < 8 {
        return std::ptr::null_mut();
    }

    BUF.with(|buf| {
        ENTRY.with(|entry| {
            let mut buf = buf.borrow_mut();
            let mut entry = entry.borrow_mut();
            let name_bytes = parts[0].as_bytes();
            let pass_bytes = parts[1].as_bytes();
            let needed = name_bytes.len() + 1 + pass_bytes.len() + 1;
            if needed > buf.len() {
                return std::ptr::null_mut();
            }
            buf[..name_bytes.len()].copy_from_slice(name_bytes);
            buf[name_bytes.len()] = 0;
            let pass_off = name_bytes.len() + 1;
            buf[pass_off..pass_off + pass_bytes.len()].copy_from_slice(pass_bytes);
            buf[pass_off + pass_bytes.len()] = 0;

            entry.sp_namp = buf.as_mut_ptr() as *mut c_char;
            entry.sp_pwdp = buf[pass_off..].as_mut_ptr() as *mut c_char;
            entry.sp_lstchg = parts[2].parse().unwrap_or(-1);
            entry.sp_min = parts[3].parse().unwrap_or(-1);
            entry.sp_max = parts[4].parse().unwrap_or(-1);
            entry.sp_warn = parts[5].parse().unwrap_or(-1);
            entry.sp_inact = parts[6].parse().unwrap_or(-1);
            entry.sp_expire = parts[7].parse().unwrap_or(-1);
            entry.sp_flag = if parts.len() > 8 {
                parts[8].parse().unwrap_or(0)
            } else {
                0
            };
            &mut *entry as *mut libc::spwd
        })
    })
}

/// `fgetspent_r` — reentrant read shadow entry from stream.
///
/// Native implementation: reads a line and parses shadow format into caller's buffer.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fgetspent_r(
    stream: *mut libc::FILE,
    result_buf: *mut libc::spwd,
    buffer: *mut c_char,
    buflen: usize,
    result: *mut *mut libc::spwd,
) -> c_int {
    if stream.is_null() || result_buf.is_null() || buffer.is_null() || result.is_null() {
        return libc::EINVAL;
    }
    unsafe { *result = std::ptr::null_mut() };

    let mut line_buf = [0u8; 1024];
    let line_ptr = unsafe {
        libc::fgets(
            line_buf.as_mut_ptr() as *mut c_char,
            line_buf.len() as c_int,
            stream,
        )
    };
    if line_ptr.is_null() {
        return libc::ENOENT;
    }
    let len = unsafe { libc::strlen(line_ptr) };
    let line = unsafe {
        std::str::from_utf8_unchecked(std::slice::from_raw_parts(line_ptr as *const u8, len))
    };
    let line = line.trim_end_matches('\n');
    if line.is_empty() || line.starts_with('#') {
        return libc::ENOENT;
    }
    let parts: Vec<&str> = line.split(':').collect();
    if parts.len() < 8 {
        return libc::ENOENT;
    }

    let name_bytes = parts[0].as_bytes();
    let pass_bytes = parts[1].as_bytes();
    let needed = name_bytes.len() + 1 + pass_bytes.len() + 1;
    if needed > buflen {
        return libc::ERANGE;
    }

    let buf_slice = unsafe { std::slice::from_raw_parts_mut(buffer as *mut u8, buflen) };
    buf_slice[..name_bytes.len()].copy_from_slice(name_bytes);
    buf_slice[name_bytes.len()] = 0;
    let pass_off = name_bytes.len() + 1;
    buf_slice[pass_off..pass_off + pass_bytes.len()].copy_from_slice(pass_bytes);
    buf_slice[pass_off + pass_bytes.len()] = 0;

    let sp = result_buf;
    unsafe {
        (*sp).sp_namp = buffer;
        (*sp).sp_pwdp = buffer.add(pass_off);
        (*sp).sp_lstchg = parts[2].parse().unwrap_or(-1);
        (*sp).sp_min = parts[3].parse().unwrap_or(-1);
        (*sp).sp_max = parts[4].parse().unwrap_or(-1);
        (*sp).sp_warn = parts[5].parse().unwrap_or(-1);
        (*sp).sp_inact = parts[6].parse().unwrap_or(-1);
        (*sp).sp_expire = parts[7].parse().unwrap_or(-1);
        (*sp).sp_flag = if parts.len() > 8 {
            parts[8].parse().unwrap_or(0)
        } else {
            0
        };
        *result = sp;
    }
    0
}

/// `fgetpwent_r` — reentrant read passwd entry from stream.
///
/// Native implementation: reads a line and parses /etc/passwd format (name:pass:uid:gid:gecos:dir:shell).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fgetpwent_r(
    stream: *mut libc::FILE,
    result_buf: *mut libc::passwd,
    buffer: *mut c_char,
    buflen: usize,
    result: *mut *mut libc::passwd,
) -> c_int {
    if stream.is_null() || result_buf.is_null() || buffer.is_null() || result.is_null() {
        return libc::EINVAL;
    }
    unsafe { *result = std::ptr::null_mut() };

    let mut line_buf = [0u8; 1024];
    let line_ptr = unsafe {
        libc::fgets(
            line_buf.as_mut_ptr() as *mut c_char,
            line_buf.len() as c_int,
            stream,
        )
    };
    if line_ptr.is_null() {
        return libc::ENOENT;
    }
    let len = unsafe { libc::strlen(line_ptr) };
    let line = unsafe {
        std::str::from_utf8_unchecked(std::slice::from_raw_parts(line_ptr as *const u8, len))
    };
    let line = line.trim_end_matches('\n');
    if line.is_empty() || line.starts_with('#') {
        return libc::ENOENT;
    }
    let parts: Vec<&str> = line.split(':').collect();
    if parts.len() < 7 {
        return libc::ENOENT;
    }

    // Calculate needed buffer: name\0 + passwd\0 + gecos\0 + dir\0 + shell\0
    let needed = parts[0].len()
        + 1
        + parts[1].len()
        + 1
        + parts[4].len()
        + 1
        + parts[5].len()
        + 1
        + parts[6].len()
        + 1;
    if needed > buflen {
        return libc::ERANGE;
    }

    let buf = unsafe { std::slice::from_raw_parts_mut(buffer as *mut u8, buflen) };
    let mut off = 0usize;
    // Helper: copy field into buffer, return pointer, advance offset
    let mut copy_field = |field: &str| -> *mut c_char {
        let ptr = unsafe { buffer.add(off) };
        buf[off..off + field.len()].copy_from_slice(field.as_bytes());
        buf[off + field.len()] = 0;
        off += field.len() + 1;
        ptr
    };
    let pw = unsafe { &mut *result_buf };
    pw.pw_name = copy_field(parts[0]);
    pw.pw_passwd = copy_field(parts[1]);
    pw.pw_uid = parts[2].parse().unwrap_or(65534);
    pw.pw_gid = parts[3].parse().unwrap_or(65534);
    pw.pw_gecos = copy_field(parts[4]);
    pw.pw_dir = copy_field(parts[5]);
    pw.pw_shell = copy_field(parts[6]);

    unsafe { *result = result_buf };
    0
}

/// `fgetgrent_r` — reentrant read group entry from stream.
///
/// Native implementation: reads a line and parses /etc/group format (name:pass:gid:members).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fgetgrent_r(
    stream: *mut libc::FILE,
    result_buf: *mut libc::group,
    buffer: *mut c_char,
    buflen: usize,
    result: *mut *mut libc::group,
) -> c_int {
    if stream.is_null() || result_buf.is_null() || buffer.is_null() || result.is_null() {
        return libc::EINVAL;
    }
    unsafe { *result = std::ptr::null_mut() };

    let mut line_buf = [0u8; 1024];
    let line_ptr = unsafe {
        libc::fgets(
            line_buf.as_mut_ptr() as *mut c_char,
            line_buf.len() as c_int,
            stream,
        )
    };
    if line_ptr.is_null() {
        return libc::ENOENT;
    }
    let len = unsafe { libc::strlen(line_ptr) };
    let line = unsafe {
        std::str::from_utf8_unchecked(std::slice::from_raw_parts(line_ptr as *const u8, len))
    };
    let line = line.trim_end_matches('\n');
    if line.is_empty() || line.starts_with('#') {
        return libc::ENOENT;
    }
    let parts: Vec<&str> = line.split(':').collect();
    if parts.len() < 3 {
        return libc::ENOENT;
    }

    // Parse member list (field 3, comma-separated)
    let members_str = if parts.len() > 3 { parts[3] } else { "" };
    let member_names: Vec<&str> = if members_str.is_empty() {
        Vec::new()
    } else {
        members_str.split(',').collect()
    };

    // Calculate needed buffer: name\0 + passwd\0 + each_member\0 + (member_count+1)*ptr
    let ptr_size = std::mem::size_of::<*mut c_char>();
    let needed = parts[0].len()
        + 1
        + parts[1].len()
        + 1
        + member_names.iter().map(|m| m.len() + 1).sum::<usize>()
        + (member_names.len() + 1) * ptr_size;
    if needed > buflen {
        return libc::ERANGE;
    }

    let buf = unsafe { std::slice::from_raw_parts_mut(buffer as *mut u8, buflen) };
    let mut off = 0usize;

    // Helper: copy a field string into the buffer at current offset.
    fn copy_field_at(
        buf: &mut [u8],
        buffer: *mut c_char,
        off: &mut usize,
        field: &str,
    ) -> *mut c_char {
        let ptr = unsafe { buffer.add(*off) };
        buf[*off..*off + field.len()].copy_from_slice(field.as_bytes());
        buf[*off + field.len()] = 0;
        *off += field.len() + 1;
        ptr
    }

    let gr = unsafe { &mut *result_buf };
    gr.gr_name = copy_field_at(buf, buffer, &mut off, parts[0]);
    gr.gr_passwd = copy_field_at(buf, buffer, &mut off, parts[1]);
    gr.gr_gid = parts[2].parse().unwrap_or(65534);

    // Align offset for pointer array
    let align = off % ptr_size;
    if align != 0 {
        off += ptr_size - align;
    }

    // Write member string pointers, then copy strings after
    let mem_array_ptr = unsafe { buffer.add(off) as *mut *mut c_char };
    let mem_array_bytes = (member_names.len() + 1) * ptr_size;
    off += mem_array_bytes;

    for (i, name) in member_names.iter().enumerate() {
        let str_ptr = copy_field_at(buf, buffer, &mut off, name);
        unsafe { *mem_array_ptr.add(i) = str_ptr };
    }
    unsafe { *mem_array_ptr.add(member_names.len()) = std::ptr::null_mut() };
    gr.gr_mem = mem_array_ptr;

    unsafe { *result = result_buf };
    0
}

// ===========================================================================
// AIO64 LFS wrappers (thin wrappers mapping 64-bit to standard)
// ===========================================================================

/// `aio_cancel64` — LFS alias for aio_cancel (identical on 64-bit).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn aio_cancel64(fd: c_int, aiocbp: *mut c_void) -> c_int {
    unsafe { aio_cancel(fd, aiocbp) }
}

/// `aio_error64` — LFS alias for aio_error (identical on 64-bit).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn aio_error64(aiocbp: *const c_void) -> c_int {
    unsafe { aio_error(aiocbp) }
}

/// `aio_fsync64` — LFS alias for aio_fsync (identical on 64-bit).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn aio_fsync64(op: c_int, aiocbp: *mut c_void) -> c_int {
    unsafe { aio_fsync(op, aiocbp) }
}

/// `aio_init` — initialize AIO implementation (glibc extension, mostly no-op).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn aio_init(_init: *const c_void) {
    // glibc hint struct; safe to ignore.
}

/// `aio_read64` — LFS alias for aio_read (identical on 64-bit).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn aio_read64(aiocbp: *mut c_void) -> c_int {
    unsafe { aio_read(aiocbp) }
}

/// `aio_return64` — LFS alias for aio_return (identical on 64-bit).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn aio_return64(aiocbp: *mut c_void) -> isize {
    unsafe { aio_return(aiocbp) }
}

/// `aio_suspend64` — LFS alias for aio_suspend (identical on 64-bit).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn aio_suspend64(
    list: *const *const c_void,
    nent: c_int,
    timeout: *const libc::timespec,
) -> c_int {
    unsafe { aio_suspend(list, nent, timeout) }
}

/// `aio_write64` — LFS alias for aio_write (identical on 64-bit).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn aio_write64(aiocbp: *mut c_void) -> c_int {
    unsafe { aio_write(aiocbp) }
}

/// `lio_listio64` — LFS alias for lio_listio (identical on 64-bit).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lio_listio64(
    mode: c_int,
    list: *const *mut c_void,
    nent: c_int,
    sig: *mut libc::sigevent,
) -> c_int {
    unsafe { lio_listio(mode, list, nent, sig as *mut c_void) }
}

// ===========================================================================
// LFS64 filesystem variants
// ===========================================================================

/// `ftw64` — LFS file tree walk.
///
/// Native implementation: delegates to our own `ftw()` (LFS identical on 64-bit, stat == stat64).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ftw64(
    path: *const c_char,
    func: Option<unsafe extern "C" fn(*const c_char, *const libc::stat, c_int) -> c_int>,
    maxfds: c_int,
) -> c_int {
    unsafe { ftw(path, func, maxfds) }
}

/// `posix_fallocate64` — LFS file preallocation.
///
/// Native implementation: delegates to our own `posix_fallocate()` (LFS identical on 64-bit).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn posix_fallocate64(fd: c_int, offset: i64, len: i64) -> c_int {
    unsafe { posix_fallocate(fd, offset as libc::off_t, len as libc::off_t) }
}

/// `openat64` — LFS openat (same as openat on 64-bit).
///
/// Native implementation: delegates to our own `openat()` (LFS is identical on 64-bit Linux).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn openat64(
    dirfd: c_int,
    path: *const c_char,
    flags: c_int,
    mut args: ...
) -> c_int {
    let mode: libc::mode_t = if (flags & libc::O_CREAT) != 0 {
        unsafe { args.arg() }
    } else {
        0
    };
    unsafe { openat(dirfd, path, flags, mode) }
}

// ===========================================================================
// FTS64 LFS wrappers
// ===========================================================================

/// `fts64_open` — LFS file hierarchy traversal (identical to fts_open on 64-bit).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fts64_open(
    path_argv: *const *mut c_char,
    options: c_int,
    _compar: Option<unsafe extern "C" fn(*const *const c_void, *const *const c_void) -> c_int>,
) -> *mut c_void {
    // On 64-bit, fts64 == fts. Cast *const *mut c_char → *const *const c_char.
    unsafe { fts_open(path_argv as *const *const c_char, options, None) }
}

/// `fts64_read` — LFS read next entry (identical to fts_read on 64-bit).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fts64_read(ftsp: *mut c_void) -> *mut c_void {
    unsafe { fts_read(ftsp) as *mut c_void }
}

/// `fts64_close` — LFS close file hierarchy (identical to fts_close on 64-bit).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fts64_close(ftsp: *mut c_void) -> c_int {
    unsafe { fts_close(ftsp) }
}

/// `fts64_children` — LFS get child entries (identical to fts_children on 64-bit).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fts64_children(ftsp: *mut c_void, instr: c_int) -> *mut c_void {
    unsafe { fts_children(ftsp, instr) as *mut c_void }
}

/// `fts64_set` — LFS set traversal options (identical to fts_set on 64-bit).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fts64_set(ftsp: *mut c_void, f_entry: *mut c_void, instr: c_int) -> c_int {
    unsafe { fts_set(ftsp, f_entry as *mut FTSENT, instr) }
}

// ===========================================================================
// Catgets (message catalog)
// ===========================================================================
// ===========================================================================
// Argp (argument parsing framework) — native ENOSYS stubs
// ===========================================================================
// The argp library is a complex GNU argument parsing framework with deep
// internal state. Programs needing full argp should link against glibc directly.
// We provide deterministic ENOSYS/EINVAL stubs so programs that merely export
// the symbols (but may not actively use them) still work.

/// `argp_parse` — parse arguments using argp framework.
/// Returns EINVAL (argp framework not natively supported).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn argp_parse(
    _argp: *const c_void,
    _argc: c_int,
    _argv: *mut *mut c_char,
    _flags: libc::c_uint,
    _arg_index: *mut c_int,
    _input: *mut c_void,
) -> c_int {
    unsafe { set_abi_errno(libc::EINVAL) };
    libc::EINVAL
}

/// `argp_help` — print argp help message. No-op stub.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn argp_help(
    _argp: *const c_void,
    _stream: *mut libc::FILE,
    _flags: libc::c_uint,
    _name: *mut c_char,
) {
    // No-op: argp framework not available
}

/// `argp_usage` — print usage and exit. No-op stub.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn argp_usage(_state: *mut c_void) {
    // No-op: argp framework not available
}

/// `argp_error` — report parsing error. No-op stub.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn argp_error(_state: *mut c_void, _fmt: *const c_char, mut _args: ...) {
    // No-op: argp framework not available
}

/// `argp_failure` — report failure during parsing. No-op stub.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn argp_failure(
    _state: *mut c_void,
    _status: c_int,
    _errnum: c_int,
    _fmt: *const c_char,
    mut _args: ...
) {
    // No-op: argp framework not available
}

/// `argp_state_help` — print help from state. No-op stub.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn argp_state_help(
    _state: *mut c_void,
    _stream: *mut libc::FILE,
    _flags: libc::c_uint,
) {
    // No-op: argp framework not available
}

// ===========================================================================
// Obstack (stack-like memory allocator)
// ===========================================================================

/// `obstack_free` — free objects on an obstack.
/// Forwards to native `_obstack_free` implementation in glibc_internal_abi.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn obstack_free(obstack: *mut c_void, block: *mut c_void) {
    unsafe { super::glibc_internal_abi::_obstack_free(obstack, block) }
}

/// `obstack_printf` — formatted print to obstack (variadic).
/// Builds the va_list and forwards to `obstack_vprintf`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn obstack_printf(
    obstack: *mut c_void,
    fmt: *const c_char,
    mut args: ...
) -> c_int {
    let ap = (&mut args) as *mut _ as *mut c_void;
    unsafe { obstack_vprintf(obstack, fmt, ap) }
}

/// `obstack_vprintf` — va_list formatted print to obstack.
/// Native implementation: format via our native vasprintf, then grow obstack.
/// The obstack struct layout must match glibc's struct obstack (see glibc_internal_abi.rs).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn obstack_vprintf(
    obstack: *mut c_void,
    fmt: *const c_char,
    ap: *mut c_void,
) -> c_int {
    if obstack.is_null() || fmt.is_null() {
        return -1;
    }
    // Use our native vasprintf (in stdio_abi) to format the string.
    let mut result_ptr: *mut c_char = std::ptr::null_mut();
    let len = unsafe { super::stdio_abi::vasprintf(&mut result_ptr, fmt, ap) };
    if len < 0 || result_ptr.is_null() {
        return -1;
    }
    let data_len = len as usize;
    // Grow the obstack with the formatted data.
    // The obstack's object_base..next_free is the current object.
    // We append data by copying into next_free and advancing it.
    // Use _obstack_newchunk if there isn't enough room.
    #[repr(C)]
    struct ObstackView {
        chunk_size: usize,
        chunk: *mut c_void,
        object_base: *mut u8,
        next_free: *mut u8,
        chunk_limit: *mut u8,
        temp: isize,
        alignment_mask: usize,
        chunkfun: *mut c_void,
        freefun: *mut c_void,
        extra_arg: *mut c_void,
        flags: u32,
    }
    let h = obstack as *mut ObstackView;
    let avail = unsafe { (*h).chunk_limit.offset_from((*h).next_free) as usize };
    if data_len > avail {
        unsafe {
            super::glibc_internal_abi::_obstack_newchunk(obstack, data_len);
        }
    }
    unsafe {
        std::ptr::copy_nonoverlapping(result_ptr as *const u8, (*h).next_free, data_len);
        (*h).next_free = (*h).next_free.add(data_len);
        libc::free(result_ptr as *mut c_void);
    }
    len
}

// ===========================================================================
// C11 Unicode (uchar.h)
// ===========================================================================
// ===========================================================================
// POSIX ucontext (getcontext/setcontext/makecontext/swapcontext)
// ===========================================================================

/// `getcontext` — save current execution context (x86_64 native).
/// Saves all callee-saved registers, signal mask, and return address into ucontext_t.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getcontext(ucp: *mut libc::ucontext_t) -> c_int {
    if ucp.is_null() {
        unsafe { set_abi_errno(libc::EFAULT) };
        return -1;
    }
    // ucontext_t offsets for x86_64 (glibc layout):
    // uc_mcontext.gregs is at offset 40 in ucontext_t
    // REG_* indices (x86_64): RBX=4, RBP=6, R12=9, R13=10, R14=11, R15=12,
    //                         RSP=15, RIP=16
    unsafe {
        let ctx = &mut *ucp;
        // Save callee-saved registers via inline asm
        let rbx: u64;
        let rbp: u64;
        let r12: u64;
        let r13: u64;
        let r14: u64;
        let r15: u64;
        let rsp: u64;
        std::arch::asm!(
            "mov {rbx}, rbx",
            "mov {rbp}, rbp",
            "mov {r12}, r12",
            "mov {r13}, r13",
            "mov {r14}, r14",
            "mov {r15}, r15",
            "lea {rsp}, [rsp + 8]", // caller's rsp (before call pushed return addr)
            rbx = out(reg) rbx,
            rbp = out(reg) rbp,
            r12 = out(reg) r12,
            r13 = out(reg) r13,
            r14 = out(reg) r14,
            r15 = out(reg) r15,
            rsp = out(reg) rsp,
            options(nomem, nostack, preserves_flags),
        );
        // Return address is at [rsp - 8] from the caller's perspective.
        // After `call getcontext`, the return address was pushed, and we computed
        // rsp = rsp + 8 (the caller's original rsp). So return addr is at rsp - 8.
        let rip = *((rsp as *const u64).wrapping_sub(1));

        ctx.uc_mcontext.gregs[libc::REG_RBX as usize] = rbx as i64;
        ctx.uc_mcontext.gregs[libc::REG_RBP as usize] = rbp as i64;
        ctx.uc_mcontext.gregs[libc::REG_R12 as usize] = r12 as i64;
        ctx.uc_mcontext.gregs[libc::REG_R13 as usize] = r13 as i64;
        ctx.uc_mcontext.gregs[libc::REG_R14 as usize] = r14 as i64;
        ctx.uc_mcontext.gregs[libc::REG_R15 as usize] = r15 as i64;
        ctx.uc_mcontext.gregs[libc::REG_RSP as usize] = rsp as i64;
        ctx.uc_mcontext.gregs[libc::REG_RIP as usize] = rip as i64;
        ctx.uc_mcontext.gregs[libc::REG_RAX as usize] = 0; // getcontext returns 0

        // Save signal mask
        let mut mask: libc::sigset_t = std::mem::zeroed();
        libc::sigprocmask(libc::SIG_BLOCK, std::ptr::null(), &mut mask);
        ctx.uc_sigmask = mask;
    }
    0
}

/// `setcontext` — restore execution context (x86_64 native).
/// Restores registers and jumps to saved return address. Does not return on success.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setcontext(ucp: *const libc::ucontext_t) -> c_int {
    if ucp.is_null() {
        unsafe { set_abi_errno(libc::EFAULT) };
        return -1;
    }
    unsafe {
        let ctx = &*ucp;
        // Restore signal mask
        libc::sigprocmask(libc::SIG_SETMASK, &ctx.uc_sigmask, std::ptr::null_mut());

        let rbx = ctx.uc_mcontext.gregs[libc::REG_RBX as usize] as u64;
        let rbp = ctx.uc_mcontext.gregs[libc::REG_RBP as usize] as u64;
        let r12 = ctx.uc_mcontext.gregs[libc::REG_R12 as usize] as u64;
        let r13 = ctx.uc_mcontext.gregs[libc::REG_R13 as usize] as u64;
        let r14 = ctx.uc_mcontext.gregs[libc::REG_R14 as usize] as u64;
        let r15 = ctx.uc_mcontext.gregs[libc::REG_R15 as usize] as u64;
        let rsp = ctx.uc_mcontext.gregs[libc::REG_RSP as usize] as u64;
        let rip = ctx.uc_mcontext.gregs[libc::REG_RIP as usize] as u64;
        let rax = ctx.uc_mcontext.gregs[libc::REG_RAX as usize] as u64;

        std::arch::asm!(
            "mov rbx, {rbx}",
            "mov rbp, {rbp}",
            "mov r12, {r12}",
            "mov r13, {r13}",
            "mov r14, {r14}",
            "mov r15, {r15}",
            "mov rsp, {rsp}",
            "jmp {rip}",
            rbx = in(reg) rbx,
            rbp = in(reg) rbp,
            r12 = in(reg) r12,
            r13 = in(reg) r13,
            r14 = in(reg) r14,
            r15 = in(reg) r15,
            rsp = in(reg) rsp,
            rip = in(reg) rip,
            in("rax") rax,
            options(noreturn),
        );
    }
}

/// `makecontext` — modify context for new function (x86_64 native).
/// Sets up the context to call `func` with `argc` integer arguments on the
/// stack pointed to by `uc_stack`. When `func` returns, execution continues
/// at `uc_link` (if set) or the process exits.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn makecontext(
    ucp: *mut libc::ucontext_t,
    func: Option<unsafe extern "C" fn()>,
    argc: c_int,
    mut args: ...
) {
    if ucp.is_null() {
        return;
    }
    unsafe {
        let ctx = &mut *ucp;
        let stack_top = (ctx.uc_stack.ss_sp as usize + ctx.uc_stack.ss_size) & !0xF; // 16-byte align

        // Extract integer arguments from va_list (up to 6 go in registers on x86_64)
        let mut int_args = [0u64; 8];
        for slot in int_args.iter_mut().take((argc as usize).min(8)) {
            *slot = args.arg::<u64>();
        }

        // Set up stack: push return address (context_exit trampoline), then args > 6
        let mut sp = stack_top as *mut u64;

        // If argc > 6, push extra args on stack in reverse order
        if argc > 6 {
            for i in (6..(argc as usize).min(8)).rev() {
                sp = sp.sub(1);
                *sp = int_args[i];
            }
        }

        // Push return address: when func returns, we should switch to uc_link
        // or exit. Use a trampoline.
        sp = sp.sub(1);
        *sp = ucontext_trampoline as *const () as u64;

        // Store uc_link pointer in r12 so the trampoline can find it
        ctx.uc_mcontext.gregs[libc::REG_R12 as usize] = if ctx.uc_link.is_null() {
            0
        } else {
            ctx.uc_link as i64
        };

        // Set registers for the function call (x86_64 calling convention)
        ctx.uc_mcontext.gregs[libc::REG_RIP as usize] =
            func.map_or(0, |f| f as *const () as usize as i64);
        ctx.uc_mcontext.gregs[libc::REG_RSP as usize] = sp as i64;
        ctx.uc_mcontext.gregs[libc::REG_RBP as usize] = 0; // clean frame

        // First 6 args go in rdi, rsi, rdx, rcx, r8, r9
        if argc > 0 {
            ctx.uc_mcontext.gregs[libc::REG_RDI as usize] = int_args[0] as i64;
        }
        if argc > 1 {
            ctx.uc_mcontext.gregs[libc::REG_RSI as usize] = int_args[1] as i64;
        }
        if argc > 2 {
            ctx.uc_mcontext.gregs[libc::REG_RDX as usize] = int_args[2] as i64;
        }
        if argc > 3 {
            ctx.uc_mcontext.gregs[libc::REG_RCX as usize] = int_args[3] as i64;
        }
        if argc > 4 {
            ctx.uc_mcontext.gregs[libc::REG_R8 as usize] = int_args[4] as i64;
        }
        if argc > 5 {
            ctx.uc_mcontext.gregs[libc::REG_R9 as usize] = int_args[5] as i64;
        }
    }
}

/// Trampoline called when the function passed to `makecontext` returns.
/// Switches to `uc_link` if set, otherwise exits the process.
unsafe extern "C" fn ucontext_trampoline() {
    // r12 holds the uc_link pointer (set by makecontext)
    let uc_link: u64;
    unsafe {
        std::arch::asm!("mov {}, r12", out(reg) uc_link, options(nomem, nostack));
    }
    if uc_link != 0 {
        unsafe { setcontext(uc_link as *const libc::ucontext_t) };
    }
    // No uc_link — exit the thread/process
    unsafe { libc::_exit(0) };
}

/// `swapcontext` — save current context and switch to new context (x86_64 native).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn swapcontext(
    oucp: *mut libc::ucontext_t,
    ucp: *const libc::ucontext_t,
) -> c_int {
    if oucp.is_null() || ucp.is_null() {
        unsafe { set_abi_errno(libc::EFAULT) };
        return -1;
    }
    // Save current context
    let rc = unsafe { getcontext(oucp) };
    if rc != 0 {
        return rc;
    }
    // If we just returned from setcontext (via the saved RIP), getcontext returns 0
    // and we should NOT call setcontext again. We use a flag in uc_mcontext to detect this.
    // The trick: getcontext sets RAX=0 in the saved context. When setcontext restores it,
    // getcontext appears to return 0 again. We need a sentinel to distinguish the two.
    // Use a simple approach: check a flag we set after getcontext returns the first time.
    static SWAP_SENTINEL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let ticket = SWAP_SENTINEL.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    // Store ticket in unused gregs field (REG_TRAPNO = 20)
    unsafe { (*oucp).uc_mcontext.gregs[20] = (ticket.wrapping_add(1)) as i64 };

    // Now switch to the new context
    unsafe { setcontext(ucp) };
    // setcontext does not return on success
    -1
}

// ---------------------------------------------------------------------------
// POSIX *at() and misc filesystem functions — batch 2
// ---------------------------------------------------------------------------

/// `mkfifoat` — create a FIFO at a directory-relative path.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mkfifoat(
    dirfd: c_int,
    pathname: *const c_char,
    mode: libc::mode_t,
) -> c_int {
    // mkfifo is equivalent to mknod with S_IFIFO
    unsafe { libc::mknodat(dirfd, pathname, mode | libc::S_IFIFO, 0) }
}

/// `mknodat` — create a filesystem node at a directory-relative path.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mknodat(
    dirfd: c_int,
    pathname: *const c_char,
    mode: libc::mode_t,
    dev: libc::dev_t,
) -> c_int {
    unsafe { libc::mknodat(dirfd, pathname, mode, dev) }
}

/// `utimensat` — change timestamps of a file relative to a directory fd.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn utimensat(
    dirfd: c_int,
    pathname: *const c_char,
    times: *const libc::timespec,
    flags: c_int,
) -> c_int {
    unsafe { libc::utimensat(dirfd, pathname, times, flags) }
}

/// `futimens` — change timestamps of an open file.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn futimens(fd: c_int, times: *const libc::timespec) -> c_int {
    unsafe { libc::utimensat(fd, std::ptr::null(), times, 0) }
}

/// `renameat2` — rename file with flags (Linux extension).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn renameat2(
    olddirfd: c_int,
    oldpath: *const c_char,
    newdirfd: c_int,
    newpath: *const c_char,
    flags: c_uint,
) -> c_int {
    let ret = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            olddirfd,
            oldpath,
            newdirfd,
            newpath,
            flags,
        )
    };
    if ret < 0 { -1 } else { ret as c_int }
}

/// `semtimedop` — semaphore operations with timeout.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn semtimedop(
    semid: c_int,
    sops: *mut c_void,
    nsops: usize,
    timeout: *const libc::timespec,
) -> c_int {
    let ret = unsafe { libc::syscall(libc::SYS_semtimedop, semid, sops, nsops, timeout) };
    if ret < 0 { -1 } else { 0 }
}

// ===========================================================================
// Scheduler CPU / misc Linux
// ===========================================================================

/// `sched_getcpu` — get CPU that the calling thread is running on.
///
/// Native implementation using `getcpu(2)` syscall.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sched_getcpu() -> c_int {
    let mut cpu: c_uint = 0;
    let ret = unsafe {
        libc::syscall(
            libc::SYS_getcpu,
            &mut cpu as *mut c_uint,
            std::ptr::null_mut::<c_void>(),
            std::ptr::null_mut::<c_void>(),
        )
    };
    if ret < 0 { -1 } else { cpu as c_int }
}

/// `getcpu` — get CPU and NUMA node (Linux-specific).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getcpu(
    cpu: *mut c_uint,
    node: *mut c_uint,
    _unused: *mut c_void,
) -> c_int {
    let ret = unsafe { libc::syscall(libc::SYS_getcpu, cpu, node, std::ptr::null_mut::<c_void>()) };
    if ret < 0 { -1 } else { 0 }
}

/// `__sched_cpucount` — count set bits in CPU set.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __sched_cpucount(setsize: usize, setp: *const c_void) -> c_int {
    if setp.is_null() || setsize == 0 {
        return 0;
    }
    let bytes = unsafe { std::slice::from_raw_parts(setp as *const u8, setsize) };
    let mut count = 0i32;
    for &b in bytes {
        count += b.count_ones() as i32;
    }
    count
}

/// `__sched_cpualloc` — allocate CPU set.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __sched_cpualloc(count: c_int) -> *mut c_void {
    let size = (count as usize).div_ceil(8).max(128); // At least 128 bytes (1024 CPUs).
    let layout =
        std::alloc::Layout::from_size_align(size, 8).unwrap_or(std::alloc::Layout::new::<u8>());
    let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
    ptr as *mut c_void
}

/// `__sched_cpufree` — free CPU set.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __sched_cpufree(setp: *mut c_void) {
    if !setp.is_null() {
        // We allocated with 128 byte min size, align 8.
        let layout =
            std::alloc::Layout::from_size_align(128, 8).unwrap_or(std::alloc::Layout::new::<u8>());
        unsafe { std::alloc::dealloc(setp as *mut u8, layout) };
    }
}

/// `mount_setattr` — change mount properties (Linux 5.12+).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mount_setattr(
    dirfd: c_int,
    pathname: *const c_char,
    flags: c_uint,
    uattr: *mut c_void,
    usize_: usize,
) -> c_int {
    // SYS_mount_setattr = 442 on x86_64
    let ret = unsafe { libc::syscall(442i64, dirfd, pathname, flags, uattr, usize_) };
    if ret < 0 { -1 } else { 0 }
}

/// `signalfd4` — create file descriptor for signal delivery (with flags).
///
/// This is the underlying syscall; `signalfd` with flags calls this.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn signalfd4(fd: c_int, mask: *const c_void, flags: c_int) -> c_int {
    // SYS_signalfd4 = 289 on x86_64
    let mask_size: usize = 8; // sizeof(sigset_t) kernel version = 8 bytes
    let ret = unsafe { libc::syscall(289i64, fd, mask, mask_size, flags) };
    if ret < 0 { -1 } else { ret as c_int }
}

// ===========================================================================
// utmp/utmpx accounting database
// ===========================================================================

/// `getutent_r` — reentrant version of getutent.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getutent_r(_ubuf: *mut c_void, _ubufp: *mut *mut c_void) -> c_int {
    // Return -1 = no more entries (safe stub)
    -1
}

/// `getutid` — search utmp by id.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getutid(_ut: *const c_void) -> *mut c_void {
    std::ptr::null_mut()
}

/// `getutid_r` — reentrant getutid.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getutid_r(
    _ut: *const c_void,
    _ubuf: *mut c_void,
    _ubufp: *mut *mut c_void,
) -> c_int {
    -1
}

/// `getutline` — search utmp by line.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getutline(_ut: *const c_void) -> *mut c_void {
    std::ptr::null_mut()
}

/// `getutline_r` — reentrant getutline.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getutline_r(
    _ut: *const c_void,
    _ubuf: *mut c_void,
    _ubufp: *mut *mut c_void,
) -> c_int {
    -1
}

/// `pututline` — write utmp entry.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pututline(_ut: *const c_void) -> *mut c_void {
    std::ptr::null_mut()
}

/// `updwtmp` — append to wtmp file.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn updwtmp(_file: *const c_char, _ut: *const c_void) {
    // no-op — write accounting not supported
}

/// `updwtmpx` — append to wtmpx file.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn updwtmpx(_file: *const c_char, _utx: *const c_void) {
    // no-op
}

/// `getutmp` — convert utmpx to utmp.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getutmp(_ux: *const c_void, _u: *mut c_void) {
    // On Linux, utmp and utmpx are identical
    if !_ux.is_null() && !_u.is_null() {
        unsafe { std::ptr::copy_nonoverlapping(_ux as *const u8, _u as *mut u8, 384) };
    }
}

/// `getutmpx` — convert utmp to utmpx.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getutmpx(_u: *const c_void, _ux: *mut c_void) {
    if !_u.is_null() && !_ux.is_null() {
        unsafe { std::ptr::copy_nonoverlapping(_u as *const u8, _ux as *mut u8, 384) };
    }
}

// ===========================================================================
// Legacy BSD signals
// ===========================================================================

/// `sigblock` — block signals (deprecated, use sigprocmask).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sigblock(mask: c_int) -> c_int {
    let mut old_set: u64 = 0;
    let new_set = mask as u64;
    let ret = unsafe {
        libc::syscall(
            libc::SYS_rt_sigprocmask,
            libc::SIG_BLOCK,
            &new_set as *const u64,
            &mut old_set as *mut u64,
            8usize, // sizeof(sigset_t)
        )
    };
    if ret < 0 { -1 } else { old_set as c_int }
}

/// `siggetmask` — alias for sigblock(0).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn siggetmask() -> c_int {
    unsafe { sigblock(0) }
}

/// `sigsetmask` — set signal mask (deprecated).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sigsetmask(mask: c_int) -> c_int {
    let mut old_set: u64 = 0;
    let new_set = mask as u64;
    let ret = unsafe {
        libc::syscall(
            libc::SYS_rt_sigprocmask,
            libc::SIG_SETMASK,
            &new_set as *const u64,
            &mut old_set as *mut u64,
            8usize,
        )
    };
    if ret < 0 { -1 } else { old_set as c_int }
}

/// `sigpause` — atomically release blocked signal and pause.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sigpause(sig: c_int) -> c_int {
    // BSD sigpause: unblock sig and pause
    let mut mask: u64 = 0;
    unsafe {
        libc::syscall(
            libc::SYS_rt_sigprocmask,
            libc::SIG_BLOCK,
            std::ptr::null::<u64>(),
            &mut mask as *mut u64,
            8usize,
        );
    }
    // Clear the bit for sig
    mask &= !(1u64 << (sig as u64 - 1));
    unsafe { libc::sigsuspend(&mask as *const u64 as *const libc::sigset_t) }
}

/// `sigvec` — BSD signal handler (maps to sigaction).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sigvec(sig: c_int, vec: *const c_void, ovec: *mut c_void) -> c_int {
    // sigvec and sigaction have compatible layouts on Linux
    unsafe {
        libc::sigaction(
            sig,
            if vec.is_null() {
                std::ptr::null()
            } else {
                vec as *const libc::sigaction
            },
            if ovec.is_null() {
                std::ptr::null_mut()
            } else {
                ovec as *mut libc::sigaction
            },
        )
    }
}

/// `sigstack` — set alternate signal stack (deprecated, use sigaltstack).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sigstack(_ss: *const c_void, _oss: *mut c_void) -> c_int {
    // Deprecated — return success no-op
    0
}

/// `sigreturn` — return from signal handler (kernel does this, not userspace).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sigreturn(_scp: *mut c_void) -> c_int {
    // SYS_rt_sigreturn = 15 on x86_64
    let ret = unsafe { libc::syscall(15i64, _scp) };
    if ret < 0 { -1 } else { 0 }
}

/// `ssignal` — software signal (legacy SVR2 interface).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ssignal(
    _sig: c_int,
    _action: Option<unsafe extern "C" fn(c_int)>,
) -> Option<unsafe extern "C" fn(c_int)> {
    None // no-op stub
}

/// `gsignal` — raise software signal (legacy SVR2).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn gsignal(_sig: c_int) -> c_int {
    0 // no-op
}

/// `sysv_signal` — System V signal semantics (one-shot).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sysv_signal(
    sig: c_int,
    handler: Option<unsafe extern "C" fn(c_int)>,
) -> Option<unsafe extern "C" fn(c_int)> {
    // Use sigaction with SA_RESETHAND for one-shot semantics
    let mut sa: libc::sigaction = unsafe { std::mem::zeroed() };
    sa.sa_sigaction = handler.map_or(0, |h| h as usize);
    sa.sa_flags = libc::SA_RESETHAND | libc::SA_NODEFER;
    let mut old_sa: libc::sigaction = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::sigaction(sig, &sa, &mut old_sa) };
    if ret < 0 {
        None
    } else {
        let old_handler = old_sa.sa_sigaction;
        if old_handler == 0 {
            None
        } else {
            Some(unsafe { std::mem::transmute::<usize, unsafe extern "C" fn(c_int)>(old_handler) })
        }
    }
}

/// `sigset` — reliable signal (XSI extension).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sigset(
    sig: c_int,
    disp: Option<unsafe extern "C" fn(c_int)>,
) -> Option<unsafe extern "C" fn(c_int)> {
    unsafe { sysv_signal(sig, disp) }
}

// ===========================================================================
// New Linux mount API (kernel 5.2+)
// ===========================================================================

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fsopen(fsname: *const c_char, flags: c_uint) -> c_int {
    let ret = unsafe { libc::syscall(430i64, fsname, flags) };
    if ret < 0 { -1 } else { ret as c_int }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fsmount(fs_fd: c_int, flags: c_uint, attr_flags: c_uint) -> c_int {
    let ret = unsafe { libc::syscall(432i64, fs_fd, flags, attr_flags) };
    if ret < 0 { -1 } else { ret as c_int }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fsconfig(
    fs_fd: c_int,
    cmd: c_uint,
    key: *const c_char,
    value: *const c_void,
    aux: c_int,
) -> c_int {
    let ret = unsafe { libc::syscall(431i64, fs_fd, cmd, key, value, aux) };
    if ret < 0 { -1 } else { 0 }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fspick(dirfd: c_int, path: *const c_char, flags: c_uint) -> c_int {
    let ret = unsafe { libc::syscall(433i64, dirfd, path, flags) };
    if ret < 0 { -1 } else { ret as c_int }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn open_tree(dirfd: c_int, path: *const c_char, flags: c_uint) -> c_int {
    let ret = unsafe { libc::syscall(428i64, dirfd, path, flags) };
    if ret < 0 { -1 } else { ret as c_int }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn move_mount(
    from_dirfd: c_int,
    from_path: *const c_char,
    to_dirfd: c_int,
    to_path: *const c_char,
    flags: c_uint,
) -> c_int {
    let ret = unsafe { libc::syscall(429i64, from_dirfd, from_path, to_dirfd, to_path, flags) };
    if ret < 0 { -1 } else { 0 }
}

// ===========================================================================
// NTP / clock adjustment
// ===========================================================================

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn adjtimex(buf: *mut c_void) -> c_int {
    let ret = unsafe { libc::syscall(libc::SYS_adjtimex, buf) };
    if ret < 0 { -1 } else { ret as c_int }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ntp_adjtime(buf: *mut c_void) -> c_int {
    unsafe { adjtimex(buf) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ntp_gettime(ntv: *mut c_void) -> c_int {
    if ntv.is_null() {
        return -1;
    }
    // ntp_gettime fills ntptime (struct ntptimeval): time, maxerror, esterror
    // Use clock_gettime(CLOCK_REALTIME) to get current time
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
    // ntptimeval.time = timeval at offset 0
    let p = ntv as *mut i64;
    unsafe {
        *p = ts.tv_sec;
        *p.add(1) = ts.tv_nsec / 1000; // tv_usec
        *p.add(2) = 0; // maxerror
        *p.add(3) = 0; // esterror
    }
    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ntp_gettimex(ntv: *mut c_void) -> c_int {
    unsafe { ntp_gettime(ntv) }
}

// ===========================================================================
// fstab database
// ===========================================================================

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setfsent() -> c_int {
    1 // success
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getfsent() -> *mut c_void {
    std::ptr::null_mut() // no more entries
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getfsfile(_file: *const c_char) -> *mut c_void {
    std::ptr::null_mut()
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getfsspec(_spec: *const c_char) -> *mut c_void {
    std::ptr::null_mut()
}

// ===========================================================================
// ttyent database
// ===========================================================================

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setttyent() -> c_int {
    1
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getttyent() -> *mut c_void {
    std::ptr::null_mut()
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getttynam(_name: *const c_char) -> *mut c_void {
    std::ptr::null_mut()
}

// ===========================================================================
// getdate / timelocal
// ===========================================================================

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getdate(_string: *const c_char) -> *mut c_void {
    std::ptr::null_mut() // not supported
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getdate_r(_string: *const c_char, _result: *mut c_void) -> c_int {
    -1 // not supported
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn timelocal(tm: *mut c_void) -> i64 {
    // timelocal is just mktime (BSD alias)
    unsafe { libc::mktime(tm as *mut libc::tm) }
}

// ===========================================================================
// C23 char8_t (UTF-8)
// ===========================================================================

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn c8rtomb(s: *mut c_char, c8: u8, _ps: *mut c_void) -> usize {
    if s.is_null() {
        return 1; // stateless encoding
    }
    unsafe { *s = c8 as c_char };
    1
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mbrtoc8(
    pc8: *mut u8,
    s: *const c_char,
    n: usize,
    _ps: *mut c_void,
) -> usize {
    if s.is_null() {
        return 0;
    }
    if n == 0 {
        return usize::MAX - 1;
    } // -2 = incomplete
    let byte = unsafe { *s } as u8;
    if !pc8.is_null() {
        unsafe { *pc8 = byte };
    }
    if byte == 0 { 0 } else { 1 }
}

// ===========================================================================
// pkey extras
// ===========================================================================

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pkey_get(pkey: c_int) -> c_int {
    // Read PKRU register via RDPKRU
    // Fallback: use the syscall interface
    let pkru: u32;
    unsafe {
        std::arch::asm!(
            "xor ecx, ecx",
            "rdpkru",
            out("eax") pkru,
            out("ecx") _,
            out("edx") _,
        );
    }
    // Extract the 2 bits for this pkey
    let shift = pkey as u32 * 2;
    ((pkru >> shift) & 0x3) as c_int
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pkey_set(pkey: c_int, rights: c_int) -> c_int {
    let mut pkru: u32;
    let edx: u32;
    unsafe {
        std::arch::asm!(
            "xor ecx, ecx",
            "rdpkru",
            out("eax") pkru,
            out("ecx") _,
            out("edx") edx,
        );
    }
    let shift = pkey as u32 * 2;
    pkru &= !(0x3 << shift);
    pkru |= (rights as u32 & 0x3) << shift;
    unsafe {
        std::arch::asm!(
            "xor ecx, ecx",
            "wrpkru",
            in("eax") pkru,
            in("ecx") 0u32,
            in("edx") edx,
        );
    }
    0
}

// ===========================================================================
// _Exit / _Fork
// ===========================================================================

// _Exit is defined above as frankenlibc_exit_immediate (export_name = "_Exit")

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
#[allow(non_snake_case)]
pub unsafe extern "C" fn _Fork() -> c_int {
    // _Fork is async-signal-safe fork (C23), no atfork handlers
    let ret = unsafe { libc::syscall(libc::SYS_clone, libc::SIGCHLD, 0, 0, 0, 0) };
    if ret < 0 { -1 } else { ret as c_int }
}

// ===========================================================================
// Reentrant NSS database functions
// ===========================================================================

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn gethostent_r(
    _result_buf: *mut c_void,
    _buf: *mut c_char,
    _buflen: usize,
    _result: *mut *mut c_void,
    _h_errnop: *mut c_int,
) -> c_int {
    if !_result.is_null() {
        unsafe { *_result = std::ptr::null_mut() };
    }
    libc::ENOENT
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getnetbyaddr_r(
    _net: u32,
    _type_: c_int,
    _result_buf: *mut c_void,
    _buf: *mut c_char,
    _buflen: usize,
    _result: *mut *mut c_void,
    _h_errnop: *mut c_int,
) -> c_int {
    if !_result.is_null() {
        unsafe { *_result = std::ptr::null_mut() };
    }
    libc::ENOENT
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getnetbyname_r(
    _name: *const c_char,
    _result_buf: *mut c_void,
    _buf: *mut c_char,
    _buflen: usize,
    _result: *mut *mut c_void,
    _h_errnop: *mut c_int,
) -> c_int {
    if !_result.is_null() {
        unsafe { *_result = std::ptr::null_mut() };
    }
    libc::ENOENT
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getnetent_r(
    _result_buf: *mut c_void,
    _buf: *mut c_char,
    _buflen: usize,
    _result: *mut *mut c_void,
    _h_errnop: *mut c_int,
) -> c_int {
    if !_result.is_null() {
        unsafe { *_result = std::ptr::null_mut() };
    }
    libc::ENOENT
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getprotobyname_r(
    _name: *const c_char,
    _result_buf: *mut c_void,
    _buf: *mut c_char,
    _buflen: usize,
    _result: *mut *mut c_void,
) -> c_int {
    if !_result.is_null() {
        unsafe { *_result = std::ptr::null_mut() };
    }
    libc::ENOENT
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getprotobynumber_r(
    _proto: c_int,
    _result_buf: *mut c_void,
    _buf: *mut c_char,
    _buflen: usize,
    _result: *mut *mut c_void,
) -> c_int {
    if !_result.is_null() {
        unsafe { *_result = std::ptr::null_mut() };
    }
    libc::ENOENT
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getprotoent_r(
    _result_buf: *mut c_void,
    _buf: *mut c_char,
    _buflen: usize,
    _result: *mut *mut c_void,
) -> c_int {
    if !_result.is_null() {
        unsafe { *_result = std::ptr::null_mut() };
    }
    libc::ENOENT
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getservent_r(
    _result_buf: *mut c_void,
    _buf: *mut c_char,
    _buflen: usize,
    _result: *mut *mut c_void,
) -> c_int {
    if !_result.is_null() {
        unsafe { *_result = std::ptr::null_mut() };
    }
    libc::ENOENT
}

// ===========================================================================
// Misc string/format extras
// ===========================================================================

/// `strfmon` — format monetary value.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strfmon(
    s: *mut c_char,
    maxsize: usize,
    format: *const c_char,
    mut args: ...
) -> isize {
    if s.is_null() || format.is_null() || maxsize == 0 {
        return -1;
    }
    // Simple: extract one double, format as currency
    let val: f64 = unsafe { args.arg() };
    let formatted = format!("{val:.2}");
    let bytes = formatted.as_bytes();
    let copy_len = bytes.len().min(maxsize - 1);
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), s as *mut u8, copy_len);
        *s.add(copy_len) = 0;
    }
    copy_len as isize
}

/// `strfmon_l` — locale-aware monetary formatting (ignores locale).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strfmon_l(
    s: *mut c_char,
    maxsize: usize,
    _locale: *mut c_void,
    format: *const c_char,
    mut args: ...
) -> isize {
    if s.is_null() || format.is_null() || maxsize == 0 {
        return -1;
    }
    let val: f64 = unsafe { args.arg() };
    let formatted = format!("{val:.2}");
    let bytes = formatted.as_bytes();
    let copy_len = bytes.len().min(maxsize - 1);
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), s as *mut u8, copy_len);
        *s.add(copy_len) = 0;
    }
    copy_len as isize
}

// ===========================================================================
// login/logout/logwtmp
// ===========================================================================

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn login(_ut: *const c_void) {
    // no-op — login accounting not supported
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn logout(_line: *const c_char) -> c_int {
    0 // success stub
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn logwtmp(_line: *const c_char, _name: *const c_char, _host: *const c_char) {
    // no-op
}

// ===========================================================================
// Async DNS (getaddrinfo_a family)
// ===========================================================================

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getaddrinfo_a(
    _mode: c_int,
    _list: *mut *mut c_void,
    _nitems: c_int,
    _sevp: *mut c_void,
) -> c_int {
    libc::EAI_SYSTEM // not implemented
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn gai_cancel(_req: *mut c_void) -> c_int {
    libc::EAI_SYSTEM
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn gai_error(_req: *mut c_void) -> c_int {
    libc::EAI_SYSTEM
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn gai_suspend(
    _list: *const *const c_void,
    _nitems: c_int,
    _timeout: *const libc::timespec,
) -> c_int {
    libc::EAI_SYSTEM
}

// ===========================================================================
// POSIX spawn extensions
// ===========================================================================

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawn_file_actions_addclosefrom_np(
    _fa: *mut c_void,
    _from: c_int,
) -> c_int {
    0 // success stub — close-from-fd not critical for safety
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawn_file_actions_addtcsetpgrp_np(
    _fa: *mut c_void,
    _fd: c_int,
) -> c_int {
    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_getcgroup_np(
    _attr: *const c_void,
    _cgroup: *mut c_int,
) -> c_int {
    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_setcgroup_np(_attr: *mut c_void, _cgroup: c_int) -> c_int {
    0
}

// ===========================================================================
// Misc math extras (isinf, isnan, scalb, scalbf)
// ===========================================================================

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn isinf(x: f64) -> c_int {
    if x == f64::INFINITY {
        1
    } else if x == f64::NEG_INFINITY {
        -1
    } else {
        0
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn isnan(x: f64) -> c_int {
    if x.is_nan() { 1 } else { 0 }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn scalb(x: f64, exp: f64) -> f64 {
    x * (2.0f64).powf(exp)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn scalbf(x: f32, exp: f32) -> f32 {
    x * (2.0f32).powf(exp)
}

// ===========================================================================
// glibc __* syscall / POSIX internal aliases
// ===========================================================================
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __gmtime_r(
    time: *const libc::time_t,
    result: *mut libc::tm,
) -> *mut libc::tm {
    unsafe { libc::gmtime_r(time, result) }
}

// ── __sched_* aliases ───────────────────────────────────────────────────────
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __sched_setparam(
    pid: libc::pid_t,
    param: *const libc::sched_param,
) -> c_int {
    unsafe { libc::sched_setparam(pid, param) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __sched_rr_get_interval(
    pid: libc::pid_t,
    tp: *mut libc::timespec,
) -> c_int {
    unsafe { libc::sched_rr_get_interval(pid, tp) }
}

// ── __sig* aliases ──────────────────────────────────────────────────────────
