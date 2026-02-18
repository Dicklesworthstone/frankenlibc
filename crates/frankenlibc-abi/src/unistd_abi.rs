//! ABI layer for `<unistd.h>` functions.
//!
//! Covers POSIX I/O (read/write/close/lseek), file metadata (stat/fstat/lstat/access),
//! directory navigation (getcwd/chdir), process identity (getpid/getppid/getuid/...),
//! link operations (link/symlink/readlink/unlink/rmdir), and sync (fsync/fdatasync).

use std::ffi::{c_char, c_int, c_void};

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
    let mut uts = std::mem::MaybeUninit::<libc::utsname>::zeroed();
    let rc = unsafe { libc::syscall(libc::SYS_uname, uts.as_mut_ptr()) };
    if rc < 0 {
        unsafe { set_abi_errno(last_host_errno(errno::EFAULT)) };
        return -1;
    }
    let uts = unsafe { uts.assume_init() };
    let nodename = &uts.nodename;
    let hostname_len = nodename
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(nodename.len());
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
// misc POSIX — GlibcCallThrough
// ---------------------------------------------------------------------------

unsafe extern "C" {
    #[link_name = "confstr"]
    fn libc_confstr(name: c_int, buf: *mut c_char, len: usize) -> usize;
    #[link_name = "pathconf"]
    fn libc_pathconf(path: *const c_char, name: c_int) -> libc::c_long;
    #[link_name = "fpathconf"]
    fn libc_fpathconf(fd: c_int, name: c_int) -> libc::c_long;
    #[link_name = "nice"]
    fn libc_nice(inc: c_int) -> c_int;
    #[link_name = "daemon"]
    fn libc_daemon(nochdir: c_int, noclose: c_int) -> c_int;
    #[link_name = "getpagesize"]
    fn libc_getpagesize() -> c_int;
    #[link_name = "gethostid"]
    fn libc_gethostid() -> libc::c_long;
    #[link_name = "getdomainname"]
    fn libc_getdomainname(name: *mut c_char, len: usize) -> c_int;
    #[link_name = "mkdtemp"]
    fn libc_mkdtemp(template: *mut c_char) -> *mut c_char;
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn confstr(name: c_int, buf: *mut c_char, len: usize) -> usize {
    unsafe { libc_confstr(name, buf, len) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pathconf(path: *const c_char, name: c_int) -> libc::c_long {
    unsafe { libc_pathconf(path, name) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fpathconf(fd: c_int, name: c_int) -> libc::c_long {
    unsafe { libc_fpathconf(fd, name) }
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
    unsafe { libc_getpagesize() }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn gethostid() -> libc::c_long {
    unsafe { libc_gethostid() }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getdomainname(name: *mut c_char, len: usize) -> c_int {
    unsafe { libc_getdomainname(name, len) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mkdtemp(template: *mut c_char) -> *mut c_char {
    unsafe { libc_mkdtemp(template) }
}
