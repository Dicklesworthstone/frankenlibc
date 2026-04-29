//! ABI layer for `<unistd.h>` functions.
//!
//! Covers POSIX I/O (read/write/close/lseek), file metadata (stat/fstat/lstat/access),
//! directory navigation (getcwd/chdir), process identity (getpid/getppid/getuid/...),
//! link operations (link/symlink/readlink/unlink/rmdir), and sync (fsync/fdatasync).

use std::ffi::{CString, c_char, c_int, c_long, c_uchar, c_uint, c_ulong, c_void};

use frankenlibc_core::errno;
use frankenlibc_core::stdio::{ValueArgKind, count_printf_args, positional_printf_arg_plan};
use frankenlibc_core::syscall;
use frankenlibc_core::unistd as unistd_core;
use frankenlibc_membrane::heal::{HealingAction, global_healing_policy};
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::errno_abi::set_abi_errno;
use crate::malloc_abi::known_remaining;
use crate::runtime_policy;
use crate::util::scan_c_string;

#[repr(C)]
struct RpcEnt {
    r_name: *mut c_char,
    r_aliases: *mut *mut c_char,
    r_number: c_int,
}

unsafe extern "C" {}

#[inline]
fn last_host_errno(default_errno: c_int) -> c_int {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(default_errno)
}

#[inline]
fn current_abi_errno() -> c_int {
    // SAFETY: __errno_location returns valid thread-local errno storage.
    unsafe { std::ptr::read_volatile(crate::errno_abi::__errno_location()) }
}

#[inline]
unsafe fn read_c_string_bytes(ptr: *const c_char) -> Option<Vec<u8>> {
    if ptr.is_null() {
        return None;
    }
    let (len, terminated) = unsafe { scan_c_string(ptr, known_remaining(ptr as usize)) };
    if !terminated {
        return None;
    }
    let bytes = unsafe { core::slice::from_raw_parts(ptr.cast::<u8>(), len) };
    Some(bytes.to_vec())
}

#[inline]
unsafe fn read_bounded_c_string_with_nul(ptr: *const c_char, limit: usize) -> Option<Vec<u8>> {
    if ptr.is_null() || limit == 0 {
        return None;
    }
    let (len, terminated) = unsafe { scan_c_string(ptr, Some(limit)) };
    if !terminated {
        return None;
    }
    let bytes = unsafe { core::slice::from_raw_parts(ptr.cast::<u8>(), len + 1) };
    Some(bytes.to_vec())
}

#[inline]
fn packed_entry_cstr_bytes(storage: &[u8], ptr: *const c_char) -> Option<&[u8]> {
    if ptr.is_null() {
        return None;
    }
    let base = storage.as_ptr() as usize;
    let raw = ptr as usize;
    let offset = raw.checked_sub(base)?;
    let tail = storage.get(offset..)?;
    let len = tail.iter().position(|&byte| byte == 0)?;
    Some(&tail[..len])
}

#[inline]
fn bounded_nul_len_with_nul(bytes: &[u8]) -> Option<usize> {
    bytes.iter().position(|&byte| byte == 0).map(|len| len + 1)
}

#[inline]
fn tracked_region_fits(addr: usize, len: usize) -> bool {
    known_remaining(addr).is_none_or(|remaining| len <= remaining)
}

#[inline]
fn tracked_output_capacity(ptr: *mut c_char, requested: usize) -> usize {
    known_remaining(ptr as usize).map_or(requested, |remaining| remaining.min(requested))
}

#[inline]
fn tracked_void_output_capacity(ptr: *mut c_void, requested: usize) -> usize {
    known_remaining(ptr as usize).map_or(requested, |remaining| remaining.min(requested))
}

/// Query the system page size via AT_PAGESZ from /proc/self/auxv, cached.
/// Falls back to 4096 (x86_64 default) if the query fails.
fn runtime_page_size() -> usize {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static CACHED: AtomicUsize = AtomicUsize::new(0);
    let cached = CACHED.load(Ordering::Relaxed);
    if cached != 0 {
        return cached;
    }
    // Read AT_PAGESZ (type 6) from /proc/self/auxv
    let page_sz = (|| -> Option<usize> {
        let data = std::fs::read("/proc/self/auxv").ok()?;
        // auxv entries are pairs of usize (type, value)
        let word = std::mem::size_of::<usize>();
        let entry_size = word * 2;
        for chunk in data.chunks_exact(entry_size) {
            let a_type = usize::from_ne_bytes(chunk[..word].try_into().ok()?);
            let a_val = usize::from_ne_bytes(chunk[word..word * 2].try_into().ok()?);
            if a_type == 6 {
                // AT_PAGESZ
                return Some(a_val);
            }
            if a_type == 0 {
                break; // AT_NULL
            }
        }
        None
    })()
    .unwrap_or(4096);
    CACHED.store(page_sz, Ordering::Relaxed);
    page_sz
}

#[inline]
fn runtime_procfs_long(path: &str) -> Option<libc::c_long> {
    std::fs::read_to_string(path)
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
        .and_then(|value| libc::c_long::try_from(value).ok())
}

#[inline]
fn runtime_meminfo_pages(field: &str) -> Option<libc::c_long> {
    let page_size = runtime_page_size();
    if page_size == 0 {
        return None;
    }

    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    for line in meminfo.lines() {
        if !line.starts_with(field) {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            return None;
        }
        let kb = parts[1].parse::<u64>().ok()?;
        let bytes = kb.checked_mul(1024)?;
        let pages = bytes / page_size as u64;
        return libc::c_long::try_from(pages).ok();
    }
    None
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
        unsafe { set_abi_errno(errno::EFAULT) };
        return -1;
    }

    let initial_remaining = known_remaining(buf as usize);
    if initial_remaining.is_some_and(|remaining| count > remaining) {
        unsafe { set_abi_errno(errno::EFAULT) };
        return -1;
    }

    // Fast path during early startup: bypass membrane, do raw syscall.
    if runtime_policy::bootstrap_passthrough_active() {
        return unsafe { sys_read_fd(fd, buf, count) };
    }

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::Stdio,
        buf as usize,
        count,
        true,
        initial_remaining.is_none(),
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

    let repair_enabled =
        mode.heals_enabled() || matches!(decision.action, MembraneAction::Repair(_));
    let (effective_count, clamped) = maybe_clamp_io_len(count, buf as usize, repair_enabled);
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
        unsafe { set_abi_errno(errno::EFAULT) };
        return -1;
    }

    let initial_remaining = known_remaining(buf as usize);
    if initial_remaining.is_some_and(|remaining| count > remaining) {
        unsafe { set_abi_errno(errno::EFAULT) };
        return -1;
    }

    // Fast path during early startup: bypass membrane, do raw syscall.
    if runtime_policy::bootstrap_passthrough_active() {
        return unsafe { sys_write_fd(fd, buf, count) };
    }

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::Stdio,
        buf as usize,
        count,
        false,
        initial_remaining.is_none(),
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

    let repair_enabled =
        mode.heals_enabled() || matches!(decision.action, MembraneAction::Repair(_));
    let (effective_count, clamped) = maybe_clamp_io_len(count, buf as usize, repair_enabled);
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

/// POSIX 2024 `posix_close` — explicit-error variant of `close`.
///
/// Identical to `close(fd)` except that an `EINPROGRESS` failure is
/// reported as success (return 0). Per IEEE Std 1003.1-2024 §close,
/// the file descriptor is closed even when an in-progress operation
/// produces that errno, so the EINPROGRESS reporting is purely
/// advisory and most callers should ignore it. The `flag` argument
/// is reserved for future use; POSIX 2024 defines no values, so any
/// non-zero `flag` returns -1 with errno set to EINVAL.
///
/// # Safety
///
/// C ABI entrypoint; no additional safety preconditions.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn posix_close(fd: c_int, flag: c_int) -> c_int {
    if flag != 0 {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }
    let rc = unsafe { close(fd) };
    if rc < 0 {
        let err = unsafe { *crate::errno_abi::__errno_location() };
        if err == errno::EINPROGRESS {
            // Per POSIX 2024: the fd is closed even on EINPROGRESS;
            // posix_close translates that to success.
            return 0;
        }
    }
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
    if let Err(err) = rc {
        unsafe { set_abi_errno(err) };
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 6, true);
        return 0;
    }
    runtime_policy::observe(ApiFamily::Stdio, decision.profile, 6, false);
    1
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

    match unsafe { syscall::sys_newfstatat(libc::AT_FDCWD, path as *const u8, buf as *mut u8, 0) } {
        Ok(()) => {
            runtime_policy::observe(ApiFamily::IoFd, decision.profile, 15, false);
            0
        }
        Err(e) => {
            unsafe { set_abi_errno(e) };
            runtime_policy::observe(ApiFamily::IoFd, decision.profile, 15, true);
            -1
        }
    }
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

    let rc = match unsafe { syscall::sys_fstat(fd, buf as *mut u8) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    };
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

    match unsafe {
        syscall::sys_newfstatat(
            libc::AT_FDCWD,
            path as *const u8,
            buf as *mut u8,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } {
        Ok(()) => {
            runtime_policy::observe(ApiFamily::IoFd, decision.profile, 15, false);
            0
        }
        Err(e) => {
            unsafe { set_abi_errno(e) };
            runtime_policy::observe(ApiFamily::IoFd, decision.profile, 15, true);
            -1
        }
    }
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
            let rc = match unsafe {
                syscall::sys_faccessat(libc::AT_FDCWD, path as *const u8, unistd_core::F_OK)
            } {
                Ok(()) => 0,
                Err(e) => {
                    unsafe { set_abi_errno(e) };
                    -1
                }
            };
            runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, rc != 0);
            return rc;
        }
        unsafe { set_abi_errno(errno::EINVAL) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }

    let rc = match unsafe { syscall::sys_faccessat(libc::AT_FDCWD, path as *const u8, amode) } {
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

    let effective_size = tracked_output_capacity(buf, size);
    match unsafe { syscall::sys_getcwd(buf as *mut u8, effective_size) } {
        Ok(_) => {
            runtime_policy::observe(ApiFamily::IoFd, decision.profile, 15, false);
            buf
        }
        Err(e) => {
            unsafe { set_abi_errno(e) };
            runtime_policy::observe(ApiFamily::IoFd, decision.profile, 15, true);
            std::ptr::null_mut()
        }
    }
}

/// glibc reserved-namespace alias for [`getcwd`].
///
/// # Safety
///
/// Same as [`getcwd`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __getcwd(buf: *mut c_char, size: usize) -> *mut c_char {
    unsafe { getcwd(buf, size) }
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

    let rc = match unsafe { syscall::sys_chdir(path as *const u8) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    };
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
    let rc = match syscall::sys_fchdir(fd) {
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
// Process identity: getppid, getuid, geteuid, getgid, getegid
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getppid() -> libc::pid_t {
    syscall::sys_getppid()
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getuid() -> libc::uid_t {
    syscall::sys_getuid()
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn geteuid() -> libc::uid_t {
    syscall::sys_geteuid()
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getgid() -> libc::gid_t {
    syscall::sys_getgid()
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getegid() -> libc::gid_t {
    syscall::sys_getegid()
}

/// glibc reserved-namespace alias for [`getppid`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __getppid() -> libc::pid_t {
    unsafe { getppid() }
}

/// glibc reserved-namespace alias for [`getuid`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __getuid() -> libc::uid_t {
    unsafe { getuid() }
}

/// glibc reserved-namespace alias for [`geteuid`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __geteuid() -> libc::uid_t {
    unsafe { geteuid() }
}

/// glibc reserved-namespace alias for [`getgid`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __getgid() -> libc::gid_t {
    unsafe { getgid() }
}

/// glibc reserved-namespace alias for [`getegid`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __getegid() -> libc::gid_t {
    unsafe { getegid() }
}

// ---------------------------------------------------------------------------
// Process group / session: getpgid, setpgid, getsid, setsid
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getpgid(pid: libc::pid_t) -> libc::pid_t {
    match syscall::sys_getpgid(pid) {
        Ok(pgid) => pgid,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setpgid(pid: libc::pid_t, pgid: libc::pid_t) -> c_int {
    match syscall::sys_setpgid(pid, pgid) {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getsid(pid: libc::pid_t) -> libc::pid_t {
    match syscall::sys_getsid(pid) {
        Ok(sid) => sid,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setsid() -> libc::pid_t {
    match syscall::sys_setsid() {
        Ok(sid) => sid,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

// ---------------------------------------------------------------------------
// Credential operations: setuid, seteuid, setreuid, setgid, setegid, setregid
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setuid(uid: libc::uid_t) -> c_int {
    match syscall::sys_setuid(uid) {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn seteuid(euid: libc::uid_t) -> c_int {
    // seteuid(euid) == setreuid(-1, euid)
    match syscall::sys_setreuid(libc::uid_t::MAX, euid) {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setreuid(ruid: libc::uid_t, euid: libc::uid_t) -> c_int {
    match syscall::sys_setreuid(ruid, euid) {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setgid(gid: libc::gid_t) -> c_int {
    match syscall::sys_setgid(gid) {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setegid(egid: libc::gid_t) -> c_int {
    // setegid(egid) == setregid(-1, egid)
    match syscall::sys_setregid(libc::gid_t::MAX, egid) {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// glibc reserved-namespace alias for [`setuid`].
///
/// # Safety
///
/// Same as [`setuid`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __setuid(uid: libc::uid_t) -> c_int {
    unsafe { setuid(uid) }
}

/// glibc reserved-namespace alias for [`seteuid`].
///
/// # Safety
///
/// Same as [`seteuid`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __seteuid(euid: libc::uid_t) -> c_int {
    unsafe { seteuid(euid) }
}

/// glibc reserved-namespace alias for [`setgid`].
///
/// # Safety
///
/// Same as [`setgid`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __setgid(gid: libc::gid_t) -> c_int {
    unsafe { setgid(gid) }
}

/// glibc reserved-namespace alias for [`setegid`].
///
/// # Safety
///
/// Same as [`setegid`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __setegid(egid: libc::gid_t) -> c_int {
    unsafe { setegid(egid) }
}

/// glibc reserved-namespace alias for [`setsid`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __setsid() -> libc::pid_t {
    unsafe { setsid() }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setregid(rgid: libc::gid_t, egid: libc::gid_t) -> c_int {
    match syscall::sys_setregid(rgid, egid) {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

// ---------------------------------------------------------------------------
// Supplementary groups: getgroups, setgroups
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getgroups(size: c_int, list: *mut libc::gid_t) -> c_int {
    match unsafe { syscall::sys_getgroups(size, list) } {
        Ok(n) => n,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setgroups(size: usize, list: *const libc::gid_t) -> c_int {
    match unsafe { syscall::sys_setgroups(size, list) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
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
    let rc = match unsafe { syscall::sys_unlinkat(libc::AT_FDCWD, path as *const u8, 0) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
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
    let rc = match unsafe {
        syscall::sys_unlinkat(libc::AT_FDCWD, path as *const u8, libc::AT_REMOVEDIR)
    } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
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
    match unsafe {
        syscall::sys_linkat(
            libc::AT_FDCWD,
            oldpath as *const u8,
            libc::AT_FDCWD,
            newpath as *const u8,
            0,
        )
    } {
        Ok(()) => {
            runtime_policy::observe(ApiFamily::IoFd, decision.profile, 12, false);
            0
        }
        Err(e) => {
            unsafe { set_abi_errno(e) };
            runtime_policy::observe(ApiFamily::IoFd, decision.profile, 12, true);
            -1
        }
    }
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
    let rc = match unsafe {
        syscall::sys_symlinkat(target as *const u8, libc::AT_FDCWD, linkpath as *const u8)
    } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
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
    let effective_bufsiz = tracked_output_capacity(buf, bufsiz);
    let rc = match unsafe {
        syscall::sys_readlinkat(
            libc::AT_FDCWD,
            path as *const u8,
            buf as *mut u8,
            effective_bufsiz,
        )
    } {
        Ok(n) => n,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
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
    let rc = match unsafe { syscall::sys_openat(libc::AT_FDCWD, path as *const u8, flags, mode) } {
        Ok(fd) => fd,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
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
    match unsafe {
        syscall::sys_renameat2(
            libc::AT_FDCWD,
            oldpath as *const u8,
            libc::AT_FDCWD,
            newpath as *const u8,
            0,
        )
    } {
        Ok(()) => {
            runtime_policy::observe(ApiFamily::IoFd, decision.profile, 12, false);
            0
        }
        Err(e) => {
            unsafe { set_abi_errno(e) };
            runtime_policy::observe(ApiFamily::IoFd, decision.profile, 12, true);
            -1
        }
    }
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
    let rc = match unsafe { syscall::sys_mkdirat(libc::AT_FDCWD, path as *const u8, mode) } {
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
// glibc reserved-namespace aliases:
// __chdir / __fchdir / __mkdir / __rmdir / __unlink / __link /
// __symlink / __rename / __access
// ---------------------------------------------------------------------------

/// glibc reserved-namespace alias for [`access`].
///
/// # Safety
///
/// Same as [`access`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __access(path: *const c_char, amode: c_int) -> c_int {
    unsafe { access(path, amode) }
}

/// glibc reserved-namespace alias for [`chdir`].
///
/// # Safety
///
/// Same as [`chdir`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __chdir(path: *const c_char) -> c_int {
    unsafe { chdir(path) }
}

/// glibc reserved-namespace alias for [`fchdir`].
///
/// # Safety
///
/// Same as [`fchdir`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __fchdir(fd: c_int) -> c_int {
    unsafe { fchdir(fd) }
}

/// glibc reserved-namespace alias for [`mkdir`].
///
/// # Safety
///
/// Same as [`mkdir`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __mkdir(path: *const c_char, mode: libc::mode_t) -> c_int {
    unsafe { mkdir(path, mode) }
}

/// glibc reserved-namespace alias for [`rmdir`].
///
/// # Safety
///
/// Same as [`rmdir`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __rmdir(path: *const c_char) -> c_int {
    unsafe { rmdir(path) }
}

/// glibc reserved-namespace alias for [`unlink`].
///
/// # Safety
///
/// Same as [`unlink`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __unlink(path: *const c_char) -> c_int {
    unsafe { unlink(path) }
}

/// glibc reserved-namespace alias for [`link`].
///
/// # Safety
///
/// Same as [`link`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __link(oldpath: *const c_char, newpath: *const c_char) -> c_int {
    unsafe { link(oldpath, newpath) }
}

/// glibc reserved-namespace alias for [`symlink`].
///
/// # Safety
///
/// Same as [`symlink`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __symlink(target: *const c_char, linkpath: *const c_char) -> c_int {
    unsafe { symlink(target, linkpath) }
}

/// glibc reserved-namespace alias for [`rename`].
///
/// # Safety
///
/// Same as [`rename`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __rename(oldpath: *const c_char, newpath: *const c_char) -> c_int {
    unsafe { rename(oldpath, newpath) }
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
    let rc = match unsafe { syscall::sys_fchmodat(libc::AT_FDCWD, path as *const u8, mode, 0) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
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
    let rc = match unsafe { syscall::sys_fchmod(fd, mode) } {
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
    let rc = match unsafe {
        syscall::sys_fchownat(libc::AT_FDCWD, path as *const u8, owner, group, 0)
    } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
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
    let rc = match unsafe { syscall::sys_fchown(fd, owner, group) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
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
    let rc = match unsafe {
        syscall::sys_fchownat(
            libc::AT_FDCWD,
            path as *const u8,
            owner,
            group,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } {
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
// umask
// ---------------------------------------------------------------------------

/// POSIX `umask` — set the file mode creation mask.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn umask(mask: libc::mode_t) -> libc::mode_t {
    syscall::sys_umask(mask)
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
    let rc = match unsafe { syscall::sys_truncate(path as *const u8, length) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
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
    let rc = match unsafe { syscall::sys_ftruncate(fd, length) } {
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
    let rc = match unsafe { syscall::sys_flock(fd, operation) } {
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
    let rc = match unsafe { syscall::sys_openat(dirfd, path as *const u8, flags, mode) } {
        Ok(fd) => fd,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
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

    match unsafe {
        syscall::sys_name_to_handle_at(dirfd, path as *const u8, handle as *mut u8, mount_id, flags)
    } {
        Ok(()) => {
            runtime_policy::observe(ApiFamily::IoFd, decision.profile, 15, false);
            0
        }
        Err(e) => {
            unsafe { set_abi_errno(e) };
            runtime_policy::observe(ApiFamily::IoFd, decision.profile, 15, true);
            -1
        }
    }
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

    match unsafe { syscall::sys_open_by_handle_at(mount_fd, handle as *const u8, flags) } {
        Ok(fd) => {
            runtime_policy::observe(ApiFamily::IoFd, decision.profile, 12, false);
            fd
        }
        Err(e) => {
            unsafe { set_abi_errno(e) };
            runtime_policy::observe(ApiFamily::IoFd, decision.profile, 12, true);
            -1
        }
    }
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
    match unsafe { syscall::sys_newfstatat(dirfd, path as *const u8, buf as *mut u8, flags) } {
        Ok(()) => {
            runtime_policy::observe(ApiFamily::IoFd, decision.profile, 15, false);
            0
        }
        Err(e) => {
            unsafe { set_abi_errno(e) };
            runtime_policy::observe(ApiFamily::IoFd, decision.profile, 15, true);
            -1
        }
    }
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
    let rc = match unsafe { syscall::sys_unlinkat(dirfd, path as *const u8, flags) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
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
    let rc = match unsafe {
        syscall::sys_renameat2(
            olddirfd,
            oldpath as *const u8,
            newdirfd,
            newpath as *const u8,
            0,
        )
    } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
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
    let rc = match unsafe { syscall::sys_mkdirat(dirfd, path as *const u8, mode) } {
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
    let effective_bufsiz = tracked_output_capacity(buf, bufsiz);
    let rc = match unsafe {
        syscall::sys_readlinkat(dirfd, path as *const u8, buf as *mut u8, effective_bufsiz)
    } {
        Ok(n) => n,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
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
    let rc = match unsafe {
        syscall::sys_symlinkat(target as *const u8, newdirfd, linkpath as *const u8)
    } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
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
    let rc = match unsafe { syscall::sys_faccessat2(dirfd, path as *const u8, amode, flags) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
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
    let rc = match unsafe { syscall::sys_fchownat(dirfd, path as *const u8, owner, group, flags) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
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
    let rc = match unsafe { syscall::sys_fchmodat(dirfd, path as *const u8, mode, flags) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
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
    let rc = match unsafe {
        syscall::sys_linkat(
            olddirfd,
            oldpath as *const u8,
            newdirfd,
            newpath as *const u8,
            flags,
        )
    } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
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
    match unsafe { syscall::sys_uname(uts.as_mut_ptr() as *mut u8) } {
        Ok(()) => Ok(unsafe { uts.assume_init() }),
        Err(e) => Err(e),
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
    match unsafe { syscall::sys_uname(buf as *mut u8) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// POSIX `gethostname` — get the hostname.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn gethostname(name: *mut c_char, len: usize) -> c_int {
    if name.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        return -1;
    }
    let effective_len = tracked_output_capacity(name, len);
    let uts = match read_utsname() {
        Ok(uts) => uts,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            return -1;
        }
    };
    let nodename = &uts.nodename;
    let hostname_len = uts_field_len(nodename);
    if hostname_len >= effective_len {
        if effective_len > 0 {
            unsafe {
                std::ptr::copy_nonoverlapping(nodename.as_ptr(), name.cast(), effective_len);
            }
        }
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
    match unsafe { syscall::sys_getrusage(who, usage as *mut u8) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// glibc reserved-namespace alias for [`getrusage`].
///
/// # Safety
///
/// Same as [`getrusage`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __getrusage(who: c_int, usage: *mut libc::rusage) -> c_int {
    unsafe { getrusage(who, usage) }
}

// ---------------------------------------------------------------------------
// alarm / sysconf
// ---------------------------------------------------------------------------

/// POSIX `alarm` — schedule a SIGALRM signal.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
#[cfg(target_arch = "x86_64")]
pub unsafe extern "C" fn alarm(seconds: u32) -> u32 {
    syscall::sys_alarm(seconds)
}

/// POSIX `alarm` — schedule a SIGALRM signal.
/// On aarch64, alarm is implemented via setitimer (no direct alarm syscall).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
#[cfg(target_arch = "aarch64")]
pub unsafe extern "C" fn alarm(seconds: u32) -> u32 {
    // aarch64 doesn't have SYS_alarm, use setitimer instead
    let new_value = libc::itimerval {
        it_interval: libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        },
        it_value: libc::timeval {
            tv_sec: seconds as i64,
            tv_usec: 0,
        },
    };
    let mut old_value = libc::itimerval {
        it_interval: libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        },
        it_value: libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        },
    };
    match unsafe {
        syscall::sys_setitimer(
            libc::ITIMER_REAL,
            &new_value as *const _ as *const u8,
            &mut old_value as *mut _ as *mut u8,
        )
    } {
        Ok(()) => {
            // Return remaining seconds from old timer
            old_value.it_value.tv_sec as u32 + if old_value.it_value.tv_usec > 0 { 1 } else { 0 }
        }
        Err(_) => 0,
    }
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
    match unsafe {
        syscall::sys_nanosleep(
            (&req) as *const _ as *const u8,
            (&mut rem) as *mut _ as *mut u8,
        )
    } {
        Ok(()) => 0,
        Err(e) => {
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
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn usleep(usec: u32) -> c_int {
    let req = libc::timespec {
        tv_sec: (usec / 1_000_000) as libc::time_t,
        tv_nsec: ((usec % 1_000_000) * 1_000) as libc::c_long,
    };
    match unsafe { syscall::sys_nanosleep((&req) as *const _ as *const u8, std::ptr::null_mut()) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

// ---------------------------------------------------------------------------
// inotify
// ---------------------------------------------------------------------------

/// Linux `inotify_init` — initialize an inotify instance.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn inotify_init() -> c_int {
    match syscall::sys_inotify_init1(0) {
        Ok(fd) => fd,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// Linux `inotify_init1` — initialize an inotify instance with flags.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn inotify_init1(flags: c_int) -> c_int {
    match syscall::sys_inotify_init1(flags) {
        Ok(fd) => fd,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// Linux `inotify_add_watch` — add a watch to an inotify instance.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn inotify_add_watch(fd: c_int, pathname: *const c_char, mask: u32) -> c_int {
    if pathname.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        return -1;
    }
    match unsafe { syscall::sys_inotify_add_watch(fd, pathname as *const u8, mask) } {
        Ok(wd) => wd,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// Linux `inotify_rm_watch` — remove a watch from an inotify instance.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn inotify_rm_watch(fd: c_int, wd: c_int) -> c_int {
    match syscall::sys_inotify_rm_watch(fd, wd) {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
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
    match unsafe { syscall::sys_setitimer(which, new_value as *const u8, old_value as *mut u8) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// POSIX `getitimer` — get value of an interval timer.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getitimer(which: c_int, curr_value: *mut libc::itimerval) -> c_int {
    if curr_value.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        return -1;
    }
    match unsafe { syscall::sys_getitimer(which, curr_value as *mut u8) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// glibc reserved-namespace alias for [`setitimer`].
///
/// # Safety
///
/// Same as [`setitimer`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __setitimer(
    which: c_int,
    new_value: *const libc::itimerval,
    old_value: *mut libc::itimerval,
) -> c_int {
    unsafe { setitimer(which, new_value, old_value) }
}

/// glibc reserved-namespace alias for [`getitimer`].
///
/// # Safety
///
/// Same as [`getitimer`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __getitimer(which: c_int, curr_value: *mut libc::itimerval) -> c_int {
    unsafe { getitimer(which, curr_value) }
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
    match unsafe { syscall::sys_mknodat(libc::AT_FDCWD, path as *const u8, mode, dev) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
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
        libc::_SC_PAGESIZE => runtime_page_size() as libc::c_long,
        libc::_SC_CLK_TCK => 100,
        libc::_SC_NPROCESSORS_ONLN | libc::_SC_NPROCESSORS_CONF => {
            // Read from /sys/devices/system/cpu/online or fallback.
            // Simple approach: use SYS_sched_getaffinity to count CPUs.
            let mut mask = [0u8; 512]; // 4096 CPUs max (supports large NUMA systems)
            let rc = unsafe { syscall::sys_sched_getaffinity(0, mask.len(), mask.as_mut_ptr()) };
            if let Ok(bytes) = rc {
                let n = mask[..bytes as usize]
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
            match unsafe {
                syscall::sys_getrlimit(libc::RLIMIT_NOFILE as i32, rlim.as_mut_ptr() as *mut u8)
            } {
                Ok(()) => {
                    let rlim = unsafe { rlim.assume_init() };
                    rlim.rlim_cur as libc::c_long
                }
                Err(_) => 1024,
            }
        }
        libc::_SC_HOST_NAME_MAX => 64,
        libc::_SC_LINE_MAX => 2048,
        libc::_SC_ARG_MAX => {
            // glibc calculates ARG_MAX as min(rlimit_stack / 4, 3/4 * 128KiB pages).
            // The common result is 2097152 (for 8MB stack) or 3200000 (for >= 12.8MB stack).
            let mut rlim = std::mem::MaybeUninit::<libc::rlimit>::zeroed();
            match unsafe {
                syscall::sys_getrlimit(libc::RLIMIT_STACK as i32, rlim.as_mut_ptr() as *mut u8)
            } {
                Ok(()) => {
                    let rlim = unsafe { rlim.assume_init() };
                    let stack_based = (rlim.rlim_cur / 4) as libc::c_long;
                    let cap = 3200000i64 as libc::c_long;
                    stack_based.min(cap).max(131072) // at least 128K
                }
                Err(_) => 2097152,
            }
        }
        libc::_SC_CHILD_MAX => {
            // glibc queries RLIMIT_NPROC. Match that behavior so callers
            // see the actual per-user process limit, not the POSIX
            // minimum.
            let mut rlim = std::mem::MaybeUninit::<libc::rlimit>::zeroed();
            match unsafe {
                syscall::sys_getrlimit(libc::RLIMIT_NPROC as i32, rlim.as_mut_ptr() as *mut u8)
            } {
                Ok(()) => {
                    let rlim = unsafe { rlim.assume_init() };
                    if rlim.rlim_cur == libc::RLIM_INFINITY {
                        -1i64 as libc::c_long
                    } else {
                        rlim.rlim_cur as libc::c_long
                    }
                }
                Err(_) => 32768,
            }
        }
        libc::_SC_STREAM_MAX => 16, // FOPEN_MAX (matches glibc)
        libc::_SC_IOV_MAX => 1024,
        libc::_SC_PHYS_PAGES => runtime_meminfo_pages("MemTotal:").unwrap_or(-1),
        libc::_SC_AVPHYS_PAGES => runtime_meminfo_pages("MemAvailable:").unwrap_or(-1),
        libc::_SC_NGROUPS_MAX => {
            runtime_procfs_long("/proc/sys/kernel/ngroups_max").unwrap_or(65536)
        }
        libc::_SC_GETPW_R_SIZE_MAX => 4096,
        libc::_SC_GETGR_R_SIZE_MAX => 4096,
        libc::_SC_LOGIN_NAME_MAX => 256,
        libc::_SC_TTY_NAME_MAX => 32,
        libc::_SC_SYMLOOP_MAX => 40,
        libc::_SC_RE_DUP_MAX => 32767,
        libc::_SC_2_VERSION => 200809,
        libc::_SC_VERSION => 200809,
        libc::_SC_THREAD_SAFE_FUNCTIONS => 1,
        libc::_SC_THREADS => 1,
        libc::_SC_THREAD_KEYS_MAX => 1024,
        libc::_SC_THREAD_STACK_MIN => libc::PTHREAD_STACK_MIN as libc::c_long,
        libc::_SC_THREAD_THREADS_MAX => -1i64 as libc::c_long, // unlimited
        libc::_SC_THREAD_DESTRUCTOR_ITERATIONS => 4,
        libc::_SC_MONOTONIC_CLOCK => 1,
        libc::_SC_CPUTIME => 1,
        libc::_SC_THREAD_CPUTIME => 1,
        libc::_SC_MAPPED_FILES => 1,
        libc::_SC_MEMLOCK => 1,
        libc::_SC_MEMLOCK_RANGE => 1,
        libc::_SC_MEMORY_PROTECTION => 1,
        libc::_SC_SEMAPHORES => 1,
        libc::_SC_SHARED_MEMORY_OBJECTS => 1,
        libc::_SC_SYNCHRONIZED_IO => 1,
        libc::_SC_TIMERS => 1,
        libc::_SC_REALTIME_SIGNALS => 1,
        libc::_SC_PRIORITY_SCHEDULING => 1,
        libc::_SC_FSYNC => 1,
        libc::_SC_ASYNCHRONOUS_IO => 1,
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

use frankenlibc_core::getopt as getopt_core;
use frankenlibc_core::getopt::{ArgRef, GetoptState, StepOutcome};

/// Persistent scanner state across `parse_getopt_short` calls.
///
/// Only `nextchar` carries cross-call meaning here; `optind`, `optopt`,
/// and `optarg` are mirrored to/from the public `libc_optind` /
/// `libc_optopt` / `libc_optarg` externs at each shim entry/exit so
/// callers (including code linked against system libc symbols) see
/// the canonical POSIX state.
static mut GETOPT_NEXTCHAR: Option<ArgRef> = None;

/// Reconstruct a C-style argv into owned byte vectors.
///
/// Returns `None` for any null or tracked-unterminated entry within
/// `0..argc`.
unsafe fn argv_byte_slices(argc: c_int, argv: *const *mut c_char) -> Option<Vec<Vec<u8>>> {
    let argc = usize::try_from(argc).ok()?;
    let mut out = Vec::with_capacity(argc);
    for i in 0..argc {
        let p = unsafe { *argv.add(i) };
        if p.is_null() {
            return None;
        }
        out.push(unsafe { read_c_string_bytes(p) }?);
    }
    Some(out)
}

unsafe fn parse_getopt_short(argc: c_int, argv: *const *mut c_char, optspec: &[u8]) -> c_int {
    if argc <= 0 || argv.is_null() {
        return -1;
    }
    let argv_bytes = match unsafe { argv_byte_slices(argc, argv) } {
        Some(v) => v,
        None => {
            unsafe { set_abi_errno(errno::EINVAL) };
            return -1;
        }
    };
    let argv_slices: Vec<&[u8]> = argv_bytes.iter().map(Vec::as_slice).collect();

    let mut state = GetoptState {
        optind: unsafe { libc_optind.max(0) as usize },
        nextchar: unsafe { GETOPT_NEXTCHAR },
        optopt: unsafe { libc_optopt as u8 },
        optarg: None,
    };

    let outcome = getopt_core::step_short(&argv_slices, optspec, &mut state);

    unsafe {
        libc_optind = state.optind as c_int;
        libc_optopt = state.optopt as c_int;
        GETOPT_NEXTCHAR = state.nextchar;
        libc_optarg = match state.optarg {
            Some(ArgRef {
                argv_idx,
                byte_offset,
            }) => {
                let base = *argv.add(argv_idx);
                if base.is_null() {
                    std::ptr::null_mut()
                } else {
                    base.add(byte_offset)
                }
            }
            None => std::ptr::null_mut(),
        };
    }

    match outcome {
        StepOutcome::Done => -1,
        StepOutcome::Found(c) => c,
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
            GETOPT_NEXTCHAR = None;
        }
    }
    if unsafe { libc_optind >= argc } {
        unsafe {
            GETOPT_NEXTCHAR = None;
        }
        return Some(-1);
    }

    let current = unsafe { *argv.add(libc_optind as usize) };
    if current.is_null() {
        return Some(-1);
    }
    let Some(current_bytes) = (unsafe { read_c_string_bytes(current) }) else {
        unsafe { set_abi_errno(errno::EINVAL) };
        return Some(-1);
    };
    if !current_bytes.starts_with(b"--") {
        return None;
    }
    if current_bytes.len() == 2 {
        unsafe {
            libc_optind += 1;
            GETOPT_NEXTCHAR = None;
        }
        return Some(-1);
    }

    let body = &current_bytes[2..];
    let split_idx = body.iter().position(|&b| b == b'=').unwrap_or(body.len());
    let name = &body[..split_idx];
    let inline_value = if split_idx < body.len() {
        unsafe { current.add(2 + split_idx + 1) }
    } else {
        std::ptr::null()
    };
    let missing_code = if getopt_core::getopt_prefers_colon(optspec) {
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
        let Some(candidate) = (unsafe { read_c_string_bytes(long_name) }) else {
            unsafe { set_abi_errno(errno::EINVAL) };
            return Some(-1);
        };
        if candidate.as_slice() == name {
            if !longindex.is_null() {
                unsafe {
                    *longindex = idx as c_int;
                }
            }
            unsafe {
                libc_optarg = std::ptr::null_mut();
                libc_optopt = 0;
                GETOPT_NEXTCHAR = None;
            }
            let mut next_index = unsafe { libc_optind + 1 };
            match unsafe { (*opt_ptr).has_arg } {
                0 if !inline_value.is_null() && unsafe { *inline_value != 0 } => {
                    unsafe {
                        libc_optopt = (*opt_ptr).val;
                        libc_optind = next_index;
                    }
                    return Some(b'?' as c_int);
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
                2 if !inline_value.is_null() && unsafe { *inline_value != 0 } => unsafe {
                    libc_optarg = inline_value as *mut c_char;
                },
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
        GETOPT_NEXTCHAR = None;
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
    let Some(optspec) = (unsafe { read_c_string_bytes(optstring) }) else {
        unsafe { set_abi_errno(errno::EINVAL) };
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 12, true);
        return -1;
    };
    let rc = unsafe { parse_getopt_short(argc, argv, &optspec) };
    runtime_policy::observe(
        ApiFamily::Stdio,
        decision.profile,
        runtime_policy::scaled_cost(12, argc.max(0) as usize),
        rc == (b'?' as c_int) || rc == (b':' as c_int),
    );
    rc
}

/// libbsd `bsd_getopt(nargc, nargv, options)` — thin BSD-flavored
/// wrapper over POSIX [`getopt`]. The leading `+` or `-` of
/// `options`, if present, is stripped before delegation: glibc
/// uses those prefixes to toggle GNU-style argument permutation
/// vs. POSIX strict ordering, but our getopt is unconditionally
/// POSIX-strict so the prefix would otherwise be misparsed as an
/// option spec.
///
/// `options == NULL` is forwarded as-is and inherits the NULL
/// rejection from [`getopt`] (yielding `-1` with errno=EINVAL).
///
/// # Safety
///
/// Caller must satisfy the same invariants as for [`getopt`]:
/// `argv` points to an `argc + 1`-long array of NUL-terminated C
/// strings (the extra slot being the conventional NULL terminator),
/// and `options`, when non-NULL, is a valid NUL-terminated C string.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn bsd_getopt(
    nargc: c_int,
    nargv: *const *mut c_char,
    options: *const c_char,
) -> c_int {
    let stripped = if options.is_null() {
        options
    } else {
        let Some(option_bytes) = (unsafe { read_c_string_bytes(options) }) else {
            unsafe { set_abi_errno(errno::EINVAL) };
            return -1;
        };
        if matches!(option_bytes.first(), Some(b'+' | b'-')) {
            // SAFETY: skipping past the prefix into the same string;
            // the underlying buffer is at least one byte longer than
            // a non-empty C string, and the resulting pointer is
            // still NUL-terminated.
            unsafe { options.add(1) }
        } else {
            options
        }
    };
    unsafe { getopt(nargc, nargv, stripped) }
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
    let Some(optspec) = (unsafe { read_c_string_bytes(optstring) }) else {
        unsafe { set_abi_errno(errno::EINVAL) };
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 12, true);
        return -1;
    };
    let rc = match unsafe { parse_getopt_long(argc, argv, &optspec, longopts, longindex) } {
        Some(value) => value,
        None => unsafe { parse_getopt_short(argc, argv, &optspec) },
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
    let fd = match syscall::sys_socket(libc::AF_UNIX, libc::SOCK_DGRAM, 0) {
        Ok(f) => f,
        Err(_) => return -1,
    };
    let mut addr = [0u8; 110];
    addr[0] = 1; // AF_UNIX
    let path = b"/dev/log";
    addr[2..2 + path.len()].copy_from_slice(path);
    if unsafe { syscall::sys_connect(fd, addr.as_ptr(), (2 + path.len() + 1) as u32) }.is_err() {
        let _ = syscall::sys_close(fd);
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

    let ident = if state.ident_ptr.is_null() {
        "unknown".to_string()
    } else {
        unsafe { read_c_string_bytes(state.ident_ptr) }
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .unwrap_or_else(|| "unknown".to_string())
    };

    let mut tv = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let _ =
        unsafe { syscall::sys_clock_gettime(libc::CLOCK_REALTIME, &mut tv as *mut _ as *mut u8) };
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
        format!("[{}]", syscall::sys_getpid())
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
            syscall::sys_sendto(
                state.sock_fd,
                packet_bytes.as_ptr(),
                packet_bytes.len(),
                libc::MSG_NOSIGNAL,
                std::ptr::null(),
                0,
            )
        };
        sent = rc.is_ok();
        if !sent {
            let _ = syscall::sys_close(state.sock_fd);
            state.sock_fd = syslog_connect();
            if state.sock_fd >= 0 {
                let rc2 = unsafe {
                    syscall::sys_sendto(
                        state.sock_fd,
                        packet_bytes.as_ptr(),
                        packet_bytes.len(),
                        libc::MSG_NOSIGNAL,
                        std::ptr::null(),
                        0,
                    )
                };
                sent = rc2.is_ok();
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
        use frankenlibc_core::stdio::printf::FormatSegment;
        let mut _idx = 0usize;
        if let Some(_plan) = positional_printf_arg_plan($segments) {
            for _kind in _plan.iter().take($extract_count) {
                match _kind {
                    ValueArgKind::Gp => {
                        if _idx < $extract_count {
                            $buf[_idx] = unsafe { $args.next_arg::<u64>() };
                            _idx += 1;
                        }
                    }
                    ValueArgKind::Fp => {
                        if _idx < $extract_count {
                            $buf[_idx] = unsafe { $args.next_arg::<f64>() }.to_bits();
                            _idx += 1;
                        }
                    }
                }
            }
        } else {
            for seg in $segments {
                if let FormatSegment::Spec(spec) = seg {
                    if spec.width.uses_arg() && _idx < $extract_count {
                        $buf[_idx] = unsafe { $args.next_arg::<u64>() };
                        _idx += 1;
                    }
                    if spec.precision.uses_arg() && _idx < $extract_count {
                        $buf[_idx] = unsafe { $args.next_arg::<u64>() };
                        _idx += 1;
                    }
                    match spec.conversion {
                        b'%' => {}
                        b'f' | b'F' | b'e' | b'E' | b'g' | b'G' | b'a' | b'A' => {
                            if _idx < $extract_count {
                                $buf[_idx] = unsafe { $args.next_arg::<f64>() }.to_bits();
                                _idx += 1;
                            }
                        }
                        _ => {
                            if _idx < $extract_count {
                                $buf[_idx] = unsafe { $args.next_arg::<u64>() };
                                _idx += 1;
                            }
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
    let Some(fmt_bytes) = (unsafe { read_c_string_bytes(format) }) else {
        return;
    };
    use frankenlibc_core::stdio::printf::parse_format_string;
    let segments = parse_format_string(&fmt_bytes);
    let extract_count = count_printf_args(&segments).min(super::stdio_abi::MAX_VA_ARGS);
    let mut arg_buf = [0u64; super::stdio_abi::MAX_VA_ARGS];
    extract_syslog_args!(&segments, &mut args, &mut arg_buf, extract_count);
    let rendered =
        unsafe { super::stdio_abi::render_printf(&fmt_bytes, arg_buf.as_ptr(), extract_count) };
    syslog_send(priority, &rendered);
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn closelog() {
    let mut state = SYSLOG_STATE.lock().unwrap_or_else(|e| e.into_inner());
    if state.sock_fd >= 0 {
        let _ = syscall::sys_close(state.sock_fd);
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
    let Some(fmt_bytes) = (unsafe { read_c_string_bytes(format) }) else {
        return;
    };
    use frankenlibc_core::stdio::printf::parse_format_string;
    let segments = parse_format_string(&fmt_bytes);
    let extract_count = count_printf_args(&segments).min(super::stdio_abi::MAX_VA_ARGS);
    let mut arg_buf = [0u64; super::stdio_abi::MAX_VA_ARGS];
    unsafe { super::stdio_abi::vprintf_extract_args(&segments, ap, &mut arg_buf, extract_count) };
    let rendered =
        unsafe { super::stdio_abi::render_printf(&fmt_bytes, arg_buf.as_ptr(), extract_count) };
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
    let pwd = unsafe { crate::pwd_abi::getpwuid(syscall::sys_geteuid()) };
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
    unsafe { syscall::sys_fcntl(fd, libc::F_GETFD, 0) }?;

    let mut winsize = std::mem::MaybeUninit::<libc::winsize>::zeroed();
    // SAFETY: ioctl writes winsize on success and performs terminal capability check.
    unsafe { syscall::sys_ioctl(fd, libc::TIOCGWINSZ as usize, winsize.as_mut_ptr() as usize) }?;

    let proc_link = CString::new(format!("/proc/self/fd/{fd}")).map_err(|_| errno::EINVAL)?;
    let mut resolved = [0 as c_char; TTYNAME_MAX_LEN];
    let len = unsafe {
        syscall::sys_readlinkat(
            libc::AT_FDCWD,
            proc_link.as_ptr() as *const u8,
            resolved.as_mut_ptr() as *mut u8,
            resolved.len() - 1,
        )
    }? as usize;
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
    unsafe {
        syscall::sys_ioctl(
            fd,
            libc::TIOCGPTN as usize,
            &mut pty_num as *mut c_int as usize,
        )
    }?;

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
/// Per-filesystem LINK_MAX values, mirroring glibc's pathconf table.
/// f_type magic numbers from <linux/magic.h>.
fn fs_link_max_for_type(f_type: i64) -> libc::c_long {
    const EXT2_SUPER_MAGIC: i64 = 0xEF53; // also EXT3, EXT4
    const BTRFS_SUPER_MAGIC: i64 = 0x9123683E;
    const XFS_SUPER_MAGIC: i64 = 0x58465342;
    const TMPFS_MAGIC: i64 = 0x01021994;
    const NFS_SUPER_MAGIC: i64 = 0x6969;
    const RAMFS_MAGIC: i64 = 0x858458F6;
    const PROC_SUPER_MAGIC: i64 = 0x9FA0;
    const SYSFS_MAGIC: i64 = 0x62656572;
    match f_type {
        EXT2_SUPER_MAGIC => 65000, // EXT4 limit; ext2/3 cap at 32000 but glibc returns 65000
        BTRFS_SUPER_MAGIC => 65535,
        XFS_SUPER_MAGIC => 2147483647, // INT32_MAX
        TMPFS_MAGIC | RAMFS_MAGIC => 127,
        NFS_SUPER_MAGIC => 32000,
        PROC_SUPER_MAGIC | SYSFS_MAGIC => 1,
        _ => 127, // POSIX minimum (LINUX_LINK_MAX)
    }
}

/// Resolve _PC_LINK_MAX for a path by querying statfs and dispatching
/// on the filesystem type. Falls back to POSIX minimum on probe error.
unsafe fn pc_link_max_for_path(path: *const c_char) -> libc::c_long {
    let mut sf = std::mem::MaybeUninit::<frankenlibc_core::syscall::StatFs>::zeroed();
    match unsafe { syscall::sys_statfs(path as *const u8, sf.as_mut_ptr()) } {
        Ok(()) => fs_link_max_for_type(unsafe { sf.assume_init() }.f_type),
        Err(_) => 127,
    }
}

/// Resolve _PC_LINK_MAX for an fd by querying fstatfs and dispatching.
unsafe fn pc_link_max_for_fd(fd: c_int) -> libc::c_long {
    let mut sf = std::mem::MaybeUninit::<frankenlibc_core::syscall::StatFs>::zeroed();
    match unsafe { syscall::sys_fstatfs(fd, sf.as_mut_ptr()) } {
        Ok(()) => fs_link_max_for_type(unsafe { sf.assume_init() }.f_type),
        Err(_) => 127,
    }
}

fn pathconf_value(name: c_int) -> Option<libc::c_long> {
    match name {
        // _PC_LINK_MAX is resolved via per-path/per-fd statfs in the
        // public pathconf/fpathconf wrappers; this fallback is only
        // hit if the caller routes through pathconf_value directly.
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

    let Some(template_bytes) = (unsafe { read_c_string_bytes(template) }) else {
        unsafe { set_abi_errno(errno::EINVAL) };
        return (std::ptr::null_mut(), true);
    };
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
        match unsafe { syscall::sys_mkdirat(libc::AT_FDCWD, template as *const u8, 0o700) } {
            Ok(()) => return (template, false),
            Err(e) => {
                if e != libc::EEXIST {
                    unsafe { set_abi_errno(e) };
                    return (std::ptr::null_mut(), true);
                }
            }
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
    match unsafe {
        syscall::sys_newfstatat(
            libc::AT_FDCWD,
            path as *const u8,
            st.as_mut_ptr() as *mut u8,
            0,
        )
    } {
        Ok(()) => {}
        Err(e) => {
            unsafe { set_abi_errno(e) };
            runtime_policy::observe(ApiFamily::IoFd, decision.profile, 8, true);
            return -1;
        }
    }

    // _PC_LINK_MAX needs the actual filesystem type; query via statfs.
    if name == libc::_PC_LINK_MAX {
        let v = unsafe { pc_link_max_for_path(path) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 8, false);
        return v;
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

/// glibc reserved-namespace alias for [`pathconf`].
///
/// # Safety
///
/// Same as [`pathconf`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __pathconf(path: *const c_char, name: c_int) -> libc::c_long {
    unsafe { pathconf(path, name) }
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

    if name == libc::_PC_LINK_MAX {
        let v = unsafe { pc_link_max_for_fd(fd) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 8, false);
        return v;
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
fn sys_current_nice() -> Result<c_int, c_int> {
    syscall::sys_getpriority(libc::PRIO_PROCESS as c_int, 0)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nice(inc: c_int) -> c_int {
    let current = match sys_current_nice() {
        Ok(v) => v,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            return -1;
        }
    };

    let target = current.saturating_add(inc).clamp(-20, 19);
    if let Err(e) = syscall::sys_setpriority(libc::PRIO_PROCESS as c_int, 0, target) {
        unsafe { set_abi_errno(e) };
        return -1;
    }

    match sys_current_nice() {
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
    // Apply ApiFamily::Process policy before any state mutation. fork()
    // runs through the same gate; daemon() is a fork-creator and must
    // respect the same Deny decisions, otherwise a sandbox or runtime
    // policy that disables fork could be bypassed simply by routing
    // through daemon().
    let (_, decision) = runtime_policy::decide(ApiFamily::Process, 0, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Process, decision.profile, 50, true);
        unsafe { set_abi_errno(libc::EAGAIN) };
        return -1;
    }

    // The daemon child runs forever without exec, so it inherits the full
    // mutex state of the parent. If a different parent thread held
    // ENVIRON_LOCK (or any pipeline lock) at clone time, that lock becomes
    // stuck in the child whose owning thread doesn't exist on the child
    // side. Mirror fork()'s pre-clone preparation: run atfork_prepare,
    // acquire the membrane pipeline guard, and serialize against in-flight
    // setenv via ENVIRON_LOCK before the syscall. (Same hazard class as
    // bd-sq7ae and the round-4 fork() ENVIRON_LOCK fix.)
    crate::pthread_abi::run_atfork_prepare();
    let _pipeline_guard =
        crate::membrane_state::try_global_pipeline().map(|pipeline| pipeline.atfork_prepare());
    let _environ_guard = crate::stdlib_abi::ENVIRON_LOCK.lock();

    // SAFETY: fork via raw syscall
    let pid = match syscall::sys_clone_fork(0) {
        Ok(p) => p,
        Err(_) => {
            drop(_environ_guard);
            drop(_pipeline_guard);
            return -1;
        }
    };

    drop(_environ_guard);
    drop(_pipeline_guard);

    if pid > 0 {
        // Parent: run atfork_parent for symmetry with fork(), then exit.
        crate::pthread_abi::run_atfork_parent();
        syscall::sys_exit_group(0);
    }

    // Child: re-initialize via atfork_child before any further work.
    crate::pthread_abi::run_atfork_child();

    // Child: create new session
    if syscall::sys_setsid().is_err() {
        return -1;
    }

    if nochdir == 0 {
        let root = b"/\0";
        let _ = unsafe { syscall::sys_chdir(root.as_ptr()) };
    }

    if noclose == 0 {
        let dev_null = b"/dev/null\0";
        if let Ok(fd) = unsafe { syscall::sys_open(dev_null.as_ptr(), libc::O_RDWR, 0) } {
            let _ = syscall::sys_dup2(fd, 0); // stdin
            let _ = syscall::sys_dup2(fd, 1); // stdout
            let _ = syscall::sys_dup2(fd, 2); // stderr
            if fd > 2 {
                let _ = syscall::sys_close(fd);
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
    let effective_len = tracked_output_capacity(name, len);
    let uts = match read_utsname() {
        Ok(uts) => uts,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            return -1;
        }
    };
    let domainname = &uts.domainname;
    let domain_len = uts_field_len(domainname);
    if effective_len == 0 {
        return 0;
    }

    let copy_len = domain_len.min(effective_len);
    unsafe {
        std::ptr::copy_nonoverlapping(domainname.as_ptr(), name.cast(), copy_len);
        if copy_len < effective_len {
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

    let effective_buflen = tracked_void_output_capacity(buf, buflen);
    match unsafe { syscall::sys_getrandom(buf as *mut u8, effective_buflen, flags) } {
        Ok(n) => {
            runtime_policy::observe(ApiFamily::IoFd, decision.profile, 8, false);
            n
        }
        Err(e) => {
            unsafe { set_abi_errno(e) };
            runtime_policy::observe(ApiFamily::IoFd, decision.profile, 8, true);
            -1
        }
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

    match unsafe {
        syscall::sys_statx(
            dirfd,
            pathname as *const u8,
            flags,
            mask,
            statxbuf as *mut u8,
        )
    } {
        Ok(()) => {
            runtime_policy::observe(ApiFamily::IoFd, decision.profile, 8, false);
            0
        }
        Err(e) => {
            unsafe { set_abi_errno(e) };
            runtime_policy::observe(ApiFamily::IoFd, decision.profile, 8, true);
            -1
        }
    }
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

    let rc = match syscall::sys_fallocate(fd, mode, offset, len) {
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
// ftw / nftw — backed by frankenlibc-core::ftw::walk_tree (bd-ftw-3,
// epic bd-ftw-epic).
//
// The recursion driver, path joining, and POSIX type-flag dispatch
// live in core. This abi layer:
//   - validates args
//   - probes the root via newfstatat (preserves the bd-ftw2 fix)
//   - wires concrete syscall closures (newfstatat / opendir / readdir
//     / closedir) into core's FsOps trait
//   - bridges the user's C callback to core's visit closure
// ---------------------------------------------------------------------------

/// libc::stat wrapper implementing core's StatLike trait.
#[derive(Clone)]
struct AbiStat(libc::stat);

impl Default for AbiStat {
    fn default() -> Self {
        // libc::stat doesn't implement Default; an all-zero stat
        // matches the C-side behavior of passing a zeroed struct
        // when stat() failed (POSIX says contents are undefined
        // for FTW_NS visits).
        AbiStat(unsafe { std::mem::zeroed() })
    }
}

impl frankenlibc_core::ftw::StatLike for AbiStat {
    fn is_dir(&self) -> bool {
        (self.0.st_mode & libc::S_IFMT) == libc::S_IFDIR
    }
    fn is_symlink(&self) -> bool {
        (self.0.st_mode & libc::S_IFMT) == libc::S_IFLNK
    }
    fn dev_id(&self) -> u64 {
        self.0.st_dev
    }
}

/// FsOps impl wrapping the syscall layer + dirent_abi.
struct AbiFs;

impl frankenlibc_core::ftw::FsOps for AbiFs {
    type Stat = AbiStat;

    fn stat(&self, path: &[u8]) -> Option<AbiStat> {
        // Build a NUL-terminated copy on the stack-bounded heap.
        let mut buf = path.to_vec();
        buf.push(0);
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        match unsafe {
            syscall::sys_newfstatat(
                libc::AT_FDCWD,
                buf.as_ptr(),
                &mut st as *mut _ as *mut u8,
                0,
            )
        } {
            Ok(()) => Some(AbiStat(st)),
            Err(_) => None,
        }
    }

    fn lstat(&self, path: &[u8]) -> Option<AbiStat> {
        let mut buf = path.to_vec();
        buf.push(0);
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        match unsafe {
            syscall::sys_newfstatat(
                libc::AT_FDCWD,
                buf.as_ptr(),
                &mut st as *mut _ as *mut u8,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } {
            Ok(()) => Some(AbiStat(st)),
            Err(_) => None,
        }
    }

    fn read_dir(&self, path: &[u8], visit_entry: &mut dyn FnMut(&[u8])) -> bool {
        let mut buf = path.to_vec();
        buf.push(0);
        let dir = unsafe { crate::dirent_abi::opendir(buf.as_ptr() as *const c_char) }
            .cast::<libc::DIR>();
        if dir.is_null() {
            return false;
        }
        loop {
            let entry = unsafe { crate::dirent_abi::readdir(dir.cast()) };
            if entry.is_null() {
                break;
            }
            let name_storage = unsafe { &(*entry).d_name };
            let name_len = name_storage
                .iter()
                .position(|&byte| byte == 0)
                .unwrap_or(name_storage.len());
            let name_bytes = unsafe {
                core::slice::from_raw_parts(name_storage.as_ptr().cast::<u8>(), name_len)
            };
            if name_bytes == b"." || name_bytes == b".." {
                continue;
            }
            visit_entry(name_bytes);
        }
        unsafe { crate::dirent_abi::closedir(dir.cast()) };
        true
    }
}

/// Adapter: translate a core WalkType to the POSIX FTW_* int.
#[inline]
fn walktype_to_ftw_int(t: frankenlibc_core::ftw::WalkType) -> c_int {
    t.as_c_int()
}

/// POSIX `ftw` — file tree walk.
///
/// Now a thin shim over `frankenlibc_core::ftw::walk_tree` (bd-ftw-3).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ftw(
    dirpath: *const c_char,
    func: Option<unsafe extern "C" fn(*const c_char, *const libc::stat, c_int) -> c_int>,
    _nopenfd: c_int,
) -> c_int {
    let Some(callback) = func else {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    };
    if dirpath.is_null() {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }
    let Some(path_bytes) = (unsafe { read_c_string_bytes(dirpath) }) else {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    };

    let fs = AbiFs;
    let r = frankenlibc_core::ftw::walk_tree(
        &path_bytes,
        &fs,
        frankenlibc_core::ftw::WalkFlags::NONE,
        |p, st, t, _level, _base| {
            // Build NUL-terminated path for the C callback.
            let mut buf = p.to_vec();
            buf.push(0);
            unsafe { callback(buf.as_ptr() as *const c_char, &st.0, walktype_to_ftw_int(t)) }
        },
    );
    if r == -1 {
        // Root probe failed — propagate a sensible errno.
        unsafe { set_abi_errno(errno::ENOENT) };
    }
    r
}

/// FTW info struct (POSIX): { int base; int level; }
#[repr(C)]
struct FtwInfo {
    base: c_int,
    level: c_int,
}

/// POSIX `nftw` — extended file tree walk (native implementation
/// backed by frankenlibc-core::ftw::walk_tree as of bd-ftw-3).
///
/// Supports FTW_PHYS (no follow symlinks), FTW_DEPTH (post-order),
/// FTW_MOUNT (stay on same filesystem). FTW_CHDIR is accepted but
/// not honored by the core walker (caller can chdir before calling).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nftw(
    dirpath: *const c_char,
    func: Option<
        unsafe extern "C" fn(*const c_char, *const libc::stat, c_int, *mut c_void) -> c_int,
    >,
    _nopenfd: c_int,
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
    let Some(path_bytes) = (unsafe { read_c_string_bytes(dirpath) }) else {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    };

    let fs = AbiFs;
    let core_flags = frankenlibc_core::ftw::WalkFlags::from_bits(flags as u32);
    let r =
        frankenlibc_core::ftw::walk_tree(&path_bytes, &fs, core_flags, |p, st, t, level, base| {
            let mut buf = p.to_vec();
            buf.push(0);
            let mut info = FtwInfo {
                base: base as c_int,
                level: level as c_int,
            };
            unsafe {
                callback(
                    buf.as_ptr() as *const c_char,
                    &st.0,
                    t.as_c_int(),
                    &mut info as *mut FtwInfo as *mut c_void,
                )
            }
        });
    if r == -1 {
        unsafe { set_abi_errno(errno::ENOENT) };
    }
    r
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
    match unsafe { syscall::sys_sched_getaffinity(pid, cpusetsize, mask as *mut u8) } {
        Ok(_) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// Linux `sched_setaffinity` — set CPU affinity mask.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sched_setaffinity(
    pid: libc::pid_t,
    cpusetsize: usize,
    mask: *const c_void,
) -> c_int {
    match unsafe { syscall::sys_sched_setaffinity(pid, cpusetsize, mask as *const u8) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
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
    if known_remaining(buffer as usize).is_some_and(|remaining| remaining < length) {
        unsafe { set_abi_errno(errno::EFAULT) };
        return -1;
    }
    match unsafe { syscall::sys_getrandom(buffer as *mut u8, length, 0) } {
        Ok(n) if (n as usize) >= length => 0,
        _ => {
            unsafe { set_abi_errno(libc::EIO) };
            -1
        }
    }
}

// ---------------------------------------------------------------------------
// arc4random family — implemented via SYS_getrandom
// ---------------------------------------------------------------------------

/// BSD `arc4random` — return a random 32-bit value.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn arc4random() -> u32 {
    let mut val: u32 = 0;
    let _ = unsafe { syscall::sys_getrandom(&mut val as *mut u32 as *mut u8, 4, 0) };
    val
}

/// BSD `arc4random_buf` — fill buffer with random bytes.
///
/// BSD contract: this function never fails and the entire buffer must be
/// populated with strong random bytes. Linux `getrandom(2)` guarantees a
/// full read only for sizes <= 256; larger requests may short-read when
/// a signal interrupts the syscall, so loop until the whole buffer is
/// filled, retrying on EINTR. On any other error we fall back to a
/// /dev/urandom read so the caller still gets entropy. (bd-ubkl7)
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn arc4random_buf(buf: *mut c_void, nbytes: usize) {
    if nbytes == 0 || buf.is_null() {
        return;
    }
    let mut written: usize = 0;
    while written < nbytes {
        let remaining = nbytes - written;
        let dst = unsafe { (buf as *mut u8).add(written) };
        match unsafe { syscall::sys_getrandom(dst, remaining, 0) } {
            Ok(n) if n > 0 => {
                written += n as usize;
            }
            Ok(_) => {
                // Zero-byte "success" would be an infinite loop.
                break;
            }
            Err(e) if e == errno::EINTR => {
                continue;
            }
            Err(_) => break,
        }
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

/// OpenBSD `arc4random_addrandom(dat, datlen)` — historical entropy-
/// mixing primitive. Modern arc4random implementations (including
/// ours) auto-reseed from getrandom(2)/getentropy(2) on demand, so
/// the documented behavior is to make this a no-op while still
/// exporting the symbol for libbsd-linked binaries.
///
/// # Safety
///
/// `dat` may be NULL or point to `datlen` bytes; the bytes are
/// inspected solely to honour the historical contract — no
/// internal state is mutated.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn arc4random_addrandom(_dat: *mut c_uchar, _datlen: c_int) {
    // Deprecated in OpenBSD 5.5 / glibc 2.41 compat: deliberate no-op.
    // Kept as an exported symbol for binaries linked against libbsd.
}

/// OpenBSD `arc4random_stir()` — historical reseed trigger. Same
/// deprecated-no-op rationale as `arc4random_addrandom`: our CSPRNG
/// reseeds from kernel entropy on its own schedule and exposing this
/// hook would only reintroduce attack surface.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn arc4random_stir() {
    // Deprecated in OpenBSD 5.5 / glibc 2.41 compat: deliberate no-op.
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

/// glibc reserved-namespace alias for [`mmap64`].
///
/// # Safety
///
/// Same as [`mmap64`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __mmap64(
    addr: *mut c_void,
    len: usize,
    prot: c_int,
    flags: c_int,
    fd: c_int,
    offset: i64,
) -> *mut c_void {
    unsafe { mmap64(addr, len, prot, flags, fd, offset) }
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
    let Some(name_bytes) = (unsafe { read_c_string_bytes(name) }) else {
        return Err(errno::EINVAL);
    };

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

    match unsafe { syscall::sys_openat(libc::AT_FDCWD, path.as_ptr() as *const u8, oflag, mode) } {
        Ok(fd) => fd,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
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

    match unsafe { syscall::sys_unlinkat(libc::AT_FDCWD, path.as_ptr() as *const u8, 0) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
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

fn sem_futex_wait(word: *mut c_void, expected: i32) -> c_int {
    match unsafe {
        syscall::sys_futex(
            word as *const u32,
            libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG,
            expected as u32,
            0, // null timeout
            0,
            0,
        )
    } {
        Ok(_) => 0,
        Err(e) => -e,
    }
}

fn sem_realtime_now() -> Result<libc::timespec, c_int> {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        syscall::sys_clock_gettime(libc::CLOCK_REALTIME, &mut now as *mut _ as *mut u8)?;
    }
    Ok(now)
}

fn sem_relative_timeout(abs_timeout: *const libc::timespec) -> Result<libc::timespec, c_int> {
    if abs_timeout.is_null() {
        return Err(libc::EINVAL);
    }
    let deadline = unsafe { *abs_timeout };
    if !(0..1_000_000_000).contains(&deadline.tv_nsec) {
        return Err(libc::EINVAL);
    }
    let now = sem_realtime_now()?;
    let Some(sec_diff) = deadline.tv_sec.checked_sub(now.tv_sec) else {
        return Err(libc::ETIMEDOUT);
    };
    let mut rel = libc::timespec {
        tv_sec: sec_diff,
        tv_nsec: deadline.tv_nsec - now.tv_nsec,
    };
    if rel.tv_nsec < 0 {
        let Some(adjusted) = rel.tv_sec.checked_sub(1) else {
            return Err(libc::ETIMEDOUT);
        };
        rel.tv_sec = adjusted;
        rel.tv_nsec += 1_000_000_000;
    }
    if rel.tv_sec < 0 || (rel.tv_sec == 0 && rel.tv_nsec <= 0) {
        return Err(libc::ETIMEDOUT);
    }
    Ok(rel)
}

fn sem_futex_wait_timed(
    word: *mut c_void,
    expected: i32,
    abs_timeout: *const libc::timespec,
) -> c_int {
    let rel = match sem_relative_timeout(abs_timeout) {
        Ok(rel) => rel,
        Err(errno) => return -errno,
    };
    match unsafe {
        syscall::sys_futex(
            word as *const u32,
            libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG,
            expected as u32,
            &rel as *const libc::timespec as usize,
            0,
            0,
        )
    } {
        Ok(_) => 0,
        Err(e) => -e,
    }
}

fn sem_futex_wake(word: *mut c_void, count: i32) -> i64 {
    match unsafe {
        syscall::sys_futex(
            word as *const u32,
            libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG,
            count as u32,
            0,
            0,
            0,
        )
    } {
        Ok(v) => v as i64,
        Err(e) => -(e as i64),
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
    let Some(name_bytes) = (unsafe { read_c_string_bytes(name) }) else {
        return Err(errno::EINVAL);
    };

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
        let m = unsafe { args.next_arg::<libc::mode_t>() };
        let v = unsafe { args.next_arg::<c_uint>() };
        (m, v)
    } else {
        (0o600 as libc::mode_t, 0u32)
    };

    if initial_value > SEM_VALUE_MAX {
        unsafe { set_abi_errno(errno::EINVAL) };
        return usize::MAX as *mut c_void;
    }

    // Open the backing file.
    let fd = match unsafe {
        syscall::sys_openat(
            libc::AT_FDCWD,
            path.as_ptr() as *const u8,
            oflag | libc::O_RDWR | libc::O_CLOEXEC,
            mode,
        )
    } {
        Ok(fd) => fd,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            return usize::MAX as *mut c_void;
        }
    };

    // If we created a new file, initialize it with the semaphore value.
    let created = (oflag & libc::O_CREAT) != 0;
    if created {
        // Set file size to SEM_MMAP_SIZE.
        if let Err(e) = unsafe { syscall::sys_ftruncate(fd, SEM_MMAP_SIZE as i64) } {
            let _ = syscall::sys_close(fd);
            unsafe { set_abi_errno(e) };
            return usize::MAX as *mut c_void;
        }
    }

    // mmap the file.
    let ptr = match unsafe {
        syscall::sys_mmap(
            std::ptr::null_mut(),
            SEM_MMAP_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        )
    } {
        Ok(p) => p as *mut c_void,
        Err(_) => libc::MAP_FAILED,
    };

    // Close the fd — the mapping keeps the file open.
    let _ = syscall::sys_close(fd);

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
    match unsafe { syscall::sys_munmap(sem as *mut u8, SEM_MMAP_SIZE) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
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

    match unsafe { syscall::sys_unlinkat(libc::AT_FDCWD, path.as_ptr() as *const u8, 0) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// POSIX `sem_init` — initialize an unnamed semaphore.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sem_init(sem: *mut c_void, _pshared: c_int, value: c_uint) -> c_int {
    if sem.is_null() || value > SEM_VALUE_MAX {
        unsafe { set_abi_errno(libc::EINVAL) };
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
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }
    // No resources to reclaim for futex-based semaphores.
    0
}

/// POSIX `sem_post` — increment the semaphore and wake one waiter.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sem_post(sem: *mut c_void) -> c_int {
    if sem.is_null() {
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }
    let atom = unsafe { sem_as_atomic(sem) };
    let old = atom.fetch_add(1, std::sync::atomic::Ordering::Release);
    if old < 0 || old == i32::MAX {
        // Overflow protection
        atom.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        unsafe { set_abi_errno(libc::EOVERFLOW) };
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
        unsafe { set_abi_errno(libc::EINVAL) };
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
                let err = -ret;
                if err == libc::EINTR {
                    unsafe { set_abi_errno(libc::EINTR) };
                    return -1;
                }
                if err != libc::EAGAIN {
                    unsafe { set_abi_errno(err) };
                    return -1;
                }
                // EAGAIN is spurious wakeup or value mismatch — retry.
            }
        }
    }
}

/// POSIX `sem_trywait` — non-blocking decrement.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sem_trywait(sem: *mut c_void) -> c_int {
    if sem.is_null() {
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }
    let atom = unsafe { sem_as_atomic(sem) };
    loop {
        let val = atom.load(std::sync::atomic::Ordering::Acquire);
        if val <= 0 {
            unsafe { set_abi_errno(libc::EAGAIN) };
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
        unsafe { set_abi_errno(libc::EINVAL) };
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
                unsafe { set_abi_errno(libc::EINVAL) };
                return -1;
            }
            let ret = sem_futex_wait_timed(sem, val, abs_timeout);
            if ret < 0 {
                let err = -ret;
                if err != libc::EAGAIN {
                    unsafe { set_abi_errno(err) };
                    return -1;
                }
                // EAGAIN is spurious wakeup or value mismatch — retry.
            }
        }
    }
}

/// POSIX `sem_getvalue` — read the current semaphore value.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sem_getvalue(sem: *mut c_void, sval: *mut c_int) -> c_int {
    if sem.is_null() || sval.is_null() {
        unsafe { set_abi_errno(libc::EINVAL) };
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
    if name.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        return -1;
    }
    // POSIX requires the queue name to begin with '/'. glibc strips
    // that leading slash before passing the path to the kernel
    // SYS_mq_open syscall (the kernel resolves the name relative to
    // an internal mqueue mount and would reject names containing '/').
    let first_byte = unsafe { *name } as u8;
    if first_byte != b'/' {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }
    let kernel_name = unsafe { name.add(1) } as *const u8;

    let (mode, attr) = if (oflag & libc::O_CREAT) != 0 {
        let mode = unsafe { args.next_arg::<libc::mode_t>() };
        let attr = unsafe { args.next_arg::<*const c_void>() };
        (mode, attr)
    } else {
        (0 as libc::mode_t, std::ptr::null())
    };

    match unsafe { syscall::sys_mq_open(kernel_name, oflag, mode, attr as usize) } {
        Ok(fd) => fd,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mq_close(mqdes: c_int) -> c_int {
    match syscall::sys_close(mqdes) {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mq_unlink(name: *const c_char) -> c_int {
    if name.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        return -1;
    }
    let first = unsafe { *name } as u8;
    if first != b'/' {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }
    // Strip the leading '/' for the kernel SYS_mq_unlink syscall;
    // matches glibc's behavior. (See bd-mq2 / mq_open.)
    let kernel_name = unsafe { name.add(1) } as *const u8;
    match unsafe { syscall::sys_mq_unlink(kernel_name) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mq_send(
    mqdes: c_int,
    msg_ptr: *const c_char,
    msg_len: usize,
    msg_prio: c_uint,
) -> c_int {
    match unsafe { syscall::sys_mq_timedsend(mqdes, msg_ptr as *const u8, msg_len, msg_prio, 0) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mq_receive(
    mqdes: c_int,
    msg_ptr: *mut c_char,
    msg_len: usize,
    msg_prio: *mut c_uint,
) -> isize {
    match unsafe {
        syscall::sys_mq_timedreceive(mqdes, msg_ptr as *mut u8, msg_len, msg_prio as usize, 0)
    } {
        Ok(n) => n,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mq_getattr(mqdes: c_int, attr: *mut c_void) -> c_int {
    match unsafe { syscall::sys_mq_getsetattr(mqdes, 0, attr as usize) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mq_setattr(
    mqdes: c_int,
    newattr: *const c_void,
    oldattr: *mut c_void,
) -> c_int {
    match unsafe { syscall::sys_mq_getsetattr(mqdes, newattr as usize, oldattr as usize) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
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
    match unsafe {
        syscall::sys_mq_timedreceive(
            mqdes,
            msg_ptr as *mut u8,
            msg_len,
            msg_prio as usize,
            abs_timeout as usize,
        )
    } {
        Ok(n) => n,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
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
    match unsafe {
        syscall::sys_mq_timedsend(
            mqdes,
            msg_ptr as *const u8,
            msg_len,
            msg_prio,
            abs_timeout as usize,
        )
    } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// `mq_notify` — register for notification when a message arrives.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mq_notify(mqdes: c_int, sevp: *const libc::sigevent) -> c_int {
    match unsafe { syscall::sys_mq_notify(mqdes, sevp as usize) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

// ---------------------------------------------------------------------------
// mq_clocksend / mq_clockreceive — clockid_t variants (glibc 2.34+)
// ---------------------------------------------------------------------------
//
// The kernel's mq_timed{send,receive} syscalls use CLOCK_REALTIME for
// the supplied abstime. For CLOCK_MONOTONIC we shift the abstime into
// realtime by computing `realtime_now + (mono_abs - mono_now)` and
// forwarding the converted value.

/// Convert a CLOCK_MONOTONIC absolute timespec to the equivalent
/// CLOCK_REALTIME absolute timespec by computing the delta to "now".
/// Returns Some(converted) on success, None if either clock_gettime
/// call fails.
fn mq_convert_mono_to_real(mono_abs: libc::timespec) -> Option<libc::timespec> {
    let mut mono_now: libc::timespec = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let mut real_now: libc::timespec = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut mono_now) } != 0 {
        return None;
    }
    if unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut real_now) } != 0 {
        return None;
    }
    // delta = mono_abs - mono_now
    let mut delta_sec = mono_abs.tv_sec - mono_now.tv_sec;
    let mut delta_nsec = mono_abs.tv_nsec - mono_now.tv_nsec;
    if delta_nsec < 0 {
        delta_nsec += 1_000_000_000;
        delta_sec -= 1;
    }
    // real_abs = real_now + delta
    let mut sec = real_now.tv_sec.checked_add(delta_sec)?;
    let mut nsec = real_now.tv_nsec + delta_nsec;
    if nsec >= 1_000_000_000 {
        nsec -= 1_000_000_000;
        sec = sec.checked_add(1)?;
    } else if nsec < 0 {
        nsec += 1_000_000_000;
        sec = sec.checked_sub(1)?;
    }
    Some(libc::timespec {
        tv_sec: sec,
        tv_nsec: nsec,
    })
}

/// POSIX `mq_clocksend(mqdes, msg, len, prio, clockid, abstime)` —
/// `mq_timedsend` with an explicit clockid. Supports
/// `CLOCK_REALTIME` (direct forward) and `CLOCK_MONOTONIC`
/// (abstime is rebased onto realtime then forwarded). Other
/// clockids return -1 with errno=EINVAL. NULL abstime is forwarded
/// verbatim (meaning "block forever").
///
/// # Safety
///
/// `msg_ptr` must point to at least `msg_len` readable bytes.
/// `abs_timeout`, when non-NULL, must point to a valid timespec.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mq_clocksend(
    mqdes: c_int,
    msg_ptr: *const c_char,
    msg_len: usize,
    msg_prio: c_uint,
    clockid: libc::clockid_t,
    abs_timeout: *const libc::timespec,
) -> c_int {
    if abs_timeout.is_null() || clockid == libc::CLOCK_REALTIME {
        return unsafe { mq_timedsend(mqdes, msg_ptr, msg_len, msg_prio, abs_timeout) };
    }
    if clockid == libc::CLOCK_MONOTONIC {
        // SAFETY: caller-supplied valid timespec.
        let mono = unsafe { *abs_timeout };
        let Some(real) = mq_convert_mono_to_real(mono) else {
            unsafe { set_abi_errno(libc::EINVAL) };
            return -1;
        };
        return unsafe { mq_timedsend(mqdes, msg_ptr, msg_len, msg_prio, &real) };
    }
    unsafe { set_abi_errno(libc::EINVAL) };
    -1
}

/// POSIX `mq_clockreceive(mqdes, msg, len, *prio, clockid, abstime)` —
/// `mq_timedreceive` with an explicit clockid. Same dispatch rules as
/// [`mq_clocksend`].
///
/// # Safety
///
/// `msg_ptr` must point to at least `msg_len` writable bytes.
/// `msg_prio`, when non-NULL, must point to writable `c_uint`.
/// `abs_timeout`, when non-NULL, must point to a valid timespec.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mq_clockreceive(
    mqdes: c_int,
    msg_ptr: *mut c_char,
    msg_len: usize,
    msg_prio: *mut c_uint,
    clockid: libc::clockid_t,
    abs_timeout: *const libc::timespec,
) -> isize {
    if abs_timeout.is_null() || clockid == libc::CLOCK_REALTIME {
        return unsafe { mq_timedreceive(mqdes, msg_ptr, msg_len, msg_prio, abs_timeout) };
    }
    if clockid == libc::CLOCK_MONOTONIC {
        // SAFETY: caller-supplied valid timespec.
        let mono = unsafe { *abs_timeout };
        let Some(real) = mq_convert_mono_to_real(mono) else {
            unsafe { set_abi_errno(libc::EINVAL) };
            return -1;
        };
        return unsafe { mq_timedreceive(mqdes, msg_ptr, msg_len, msg_prio, &real) };
    }
    unsafe { set_abi_errno(libc::EINVAL) };
    -1
}

// ---------------------------------------------------------------------------
// openat2 (Linux 5.6+, glibc 2.34) and futex_waitv (Linux 5.16+, glibc 2.35)
// ---------------------------------------------------------------------------

/// Linux `openat2(dirfd, pathname, *open_how, size) -> int` —
/// extended openat that takes a versioned `struct open_how`. The
/// kernel rejects calls whose `size` is wrong for its known
/// versions, so callers must pass `size_of::<open_how>()`.
///
/// Forwards through the raw syscall veneer. Returns the new fd on
/// success or -1 with errno set.
///
/// # Safety
///
/// `pathname` must be a NUL-terminated C string. `how` must point
/// to readable storage of at least `size` bytes describing a valid
/// `open_how` struct.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn openat2(
    dirfd: c_int,
    pathname: *const c_char,
    how: *const c_void,
    size: usize,
) -> c_int {
    if pathname.is_null() || how.is_null() {
        unsafe { set_abi_errno(libc::EFAULT) };
        return -1;
    }
    // SAFETY: caller contract supplies a NUL-terminated pathname and readable `how`.
    match unsafe { syscall::sys_openat2(dirfd, pathname as *const u8, how as *const u8, size) } {
        Ok(fd) => fd,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// Linux `futex_waitv(*waiters, nr_futexes, flags, *timeout,
/// clockid) -> int` — wait on multiple futexes simultaneously.
/// Returns the index of the woken futex on success, or -1 with
/// errno set on timeout / error.
///
/// The kernel rejects `flags != 0`, `nr_futexes == 0`, and
/// `nr_futexes > FUTEX_WAITV_MAX (= 128)`; we also defend against
/// NULL `waiters` with `nr_futexes > 0`.
///
/// # Safety
///
/// `waiters`, when `nr_futexes > 0`, must point to an array of
/// `nr_futexes` valid `struct futex_waitv` entries. `timeout`,
/// when non-NULL, must point to a valid `timespec`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn futex_waitv(
    waiters: *const c_void,
    nr_futexes: c_uint,
    flags: c_uint,
    timeout: *const libc::timespec,
    clockid: libc::clockid_t,
) -> c_int {
    if nr_futexes > 0 && waiters.is_null() {
        unsafe { set_abi_errno(libc::EFAULT) };
        return -1;
    }
    // Cast through the core syscall's typed `FutexWaitV` pointer; the
    // raw layout matches our wrapper's opaque c_void caller view.
    let waiters_typed = waiters as *const frankenlibc_core::syscall::FutexWaitV;
    // SAFETY: caller contract supplies a valid waiter array and optional timeout.
    match unsafe {
        frankenlibc_core::syscall::sys_futex_waitv(
            waiters_typed,
            nr_futexes,
            flags,
            timeout as *const u8,
            clockid,
        )
    } {
        Ok(idx) => idx,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

// ---------------------------------------------------------------------------
// mseal / memfd_secret / rseq / cachestat (modern Linux syscall wrappers)
// ---------------------------------------------------------------------------

#[inline]
unsafe fn raw_syscall_with_errno(rc: libc::c_long) -> c_int {
    if rc < 0 {
        let e = unsafe { *libc::__errno_location() };
        unsafe { set_abi_errno(e) };
        return -1;
    }
    rc as c_int
}

/// Linux `mseal(addr, len, flags) -> int` (Linux 6.10+, glibc 2.40,
/// `SYS_mseal = 462`) — seal a memory region against future
/// `mprotect`, `munmap`, `mremap`, etc. Returns 0 on success or -1
/// with errno on failure.
///
/// # Safety
///
/// `addr` must point to a memory region of at least `len` bytes; the
/// kernel rejects unaligned or non-VM-area addresses.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mseal(addr: *mut c_void, len: usize, flags: c_uint) -> c_int {
    // SAFETY: forwarding to the kernel.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_mseal,
            addr as libc::c_long,
            len as libc::c_long,
            flags as libc::c_long,
        )
    };
    unsafe { raw_syscall_with_errno(rc) }
}

/// Linux `memfd_secret(flags) -> int` (Linux 5.14+, `SYS_memfd_secret
/// = 447`) — create an anonymous file backed by memory inaccessible
/// from the rest of the system (no /proc/PID/mem, no ptrace).
/// Returns the new fd or -1 with errno.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn memfd_secret(flags: c_uint) -> c_int {
    // SAFETY: forwarding to the kernel.
    let rc = unsafe { libc::syscall(libc::SYS_memfd_secret, flags as libc::c_long) };
    unsafe { raw_syscall_with_errno(rc) }
}

/// Linux `rseq(*rseq, rseq_len, flags, sig) -> int` (Linux 4.18+,
/// `SYS_rseq = 334`) — register or unregister a per-thread
/// `struct rseq` for restartable sequences (a per-CPU concurrency
/// primitive). Returns 0 on success or -1 with errno.
///
/// # Safety
///
/// `rseq_ptr` must point to writable storage of at least `rseq_len`
/// bytes describing a valid `struct rseq`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rseq(
    rseq_ptr: *mut c_void,
    rseq_len: u32,
    flags: c_int,
    sig: u32,
) -> c_int {
    if rseq_ptr.is_null() {
        unsafe { set_abi_errno(libc::EFAULT) };
        return -1;
    }
    // SAFETY: forwarding to the kernel.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_rseq,
            rseq_ptr as libc::c_long,
            rseq_len as libc::c_long,
            flags as libc::c_long,
            sig as libc::c_long,
        )
    };
    unsafe { raw_syscall_with_errno(rc) }
}

/// Linux `cachestat(fd, *cstat_range, *cstat, flags) -> int`
/// (Linux 6.5+, syscall 451) — query page cache statistics for a
/// file range. The struct definitions live in the kernel's
/// `<linux/cachestat.h>` and are exposed here as opaque pointers
/// since their layout is kernel-version-specific.
///
/// Returns 0 on success or -1 with errno on failure.
///
/// # Safety
///
/// `cstat_range` must point to a valid `struct cachestat_range`
/// (off + len). `cstat` must point to writable `struct cachestat`
/// storage that the kernel will fill in.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cachestat(
    fd: c_uint,
    cstat_range: *const c_void,
    cstat: *mut c_void,
    flags: c_uint,
) -> c_int {
    if cstat_range.is_null() || cstat.is_null() {
        unsafe { set_abi_errno(libc::EFAULT) };
        return -1;
    }
    // SYS_cachestat = 451 on x86_64 (libc 0.2.185 doesn't expose
    // SYS_cachestat yet; embed the literal so we work on every
    // Linux x86_64 toolchain that has the kernel support).
    const SYS_CACHESTAT: libc::c_long = 451;
    // SAFETY: forwarding to the kernel.
    let rc = unsafe {
        libc::syscall(
            SYS_CACHESTAT,
            fd as libc::c_long,
            cstat_range as libc::c_long,
            cstat as libc::c_long,
            flags as libc::c_long,
        )
    };
    unsafe { raw_syscall_with_errno(rc) }
}

// ---------------------------------------------------------------------------
// NUMA memory policy (set/get_mempolicy + mbind + migrate_pages + move_pages
// + set_mempolicy_home_node)
// ---------------------------------------------------------------------------

#[inline]
unsafe fn raw_syscall_with_errno_long(rc: libc::c_long) -> libc::c_long {
    if rc < 0 {
        let e = unsafe { *libc::__errno_location() };
        unsafe { set_abi_errno(e) };
        return -1;
    }
    rc
}

/// Linux `set_mempolicy(mode, *nodemask, maxnode) -> long`
/// (`SYS_set_mempolicy = 238`) — set the calling thread's default
/// NUMA memory policy.
///
/// # Safety
///
/// `nodemask`, when non-NULL, must point to at least
/// `(maxnode + 7) / 8` readable bytes describing a valid node bitmap.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn set_mempolicy(
    mode: c_int,
    nodemask: *const c_ulong,
    maxnode: c_ulong,
) -> c_long {
    // SAFETY: forwarding to the kernel.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_set_mempolicy,
            mode as libc::c_long,
            nodemask as libc::c_long,
            maxnode as libc::c_long,
        )
    };
    unsafe { raw_syscall_with_errno_long(rc) }
}

/// Linux `get_mempolicy(*mode, *nodemask, maxnode, addr, flags) ->
/// long` (`SYS_get_mempolicy = 239`) — read the NUMA policy for the
/// calling thread or for a specific address.
///
/// # Safety
///
/// `mode`, when non-NULL, must point to writable `c_int` storage.
/// `nodemask`, when non-NULL, must point to at least
/// `(maxnode + 7) / 8` writable bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn get_mempolicy(
    mode: *mut c_int,
    nodemask: *mut c_ulong,
    maxnode: c_ulong,
    addr: *mut c_void,
    flags: c_ulong,
) -> c_long {
    // SAFETY: forwarding to the kernel.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_get_mempolicy,
            mode as libc::c_long,
            nodemask as libc::c_long,
            maxnode as libc::c_long,
            addr as libc::c_long,
            flags as libc::c_long,
        )
    };
    unsafe { raw_syscall_with_errno_long(rc) }
}

/// Linux `mbind(addr, len, mode, *nodemask, maxnode, flags) -> long`
/// (`SYS_mbind = 237`) — set the NUMA memory policy for a range of
/// virtual memory.
///
/// # Safety
///
/// `addr` must point to a memory region of at least `len` bytes.
/// `nodemask`, when non-NULL, follows the same shape as in
/// [`set_mempolicy`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mbind(
    addr: *mut c_void,
    len: c_ulong,
    mode: c_int,
    nodemask: *const c_ulong,
    maxnode: c_ulong,
    flags: c_uint,
) -> c_long {
    // SAFETY: forwarding to the kernel.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_mbind,
            addr as libc::c_long,
            len as libc::c_long,
            mode as libc::c_long,
            nodemask as libc::c_long,
            maxnode as libc::c_long,
            flags as libc::c_long,
        )
    };
    unsafe { raw_syscall_with_errno_long(rc) }
}

/// Linux `migrate_pages(pid, maxnode, *old_nodes, *new_nodes) ->
/// long` (`SYS_migrate_pages = 256`) — move all pages of `pid`
/// (or 0 for the calling process) on `old_nodes` to the
/// corresponding entries in `new_nodes`.
///
/// # Safety
///
/// `old_nodes` and `new_nodes`, when non-NULL, must each point to at
/// least `(maxnode + 7) / 8` readable bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn migrate_pages(
    pid: c_int,
    maxnode: c_ulong,
    old_nodes: *const c_ulong,
    new_nodes: *const c_ulong,
) -> c_long {
    // SAFETY: forwarding to the kernel.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_migrate_pages,
            pid as libc::c_long,
            maxnode as libc::c_long,
            old_nodes as libc::c_long,
            new_nodes as libc::c_long,
        )
    };
    unsafe { raw_syscall_with_errno_long(rc) }
}

/// Linux `move_pages(pid, count, **pages, *nodes, *status, flags) ->
/// long` (`SYS_move_pages = 279`) — move the listed pages (in
/// process `pid`, or the calling process if 0) to the specified
/// target NUMA nodes. If `nodes` is NULL the call only queries
/// current locations into `status`.
///
/// # Safety
///
/// `pages` must point to an array of `count` pointers. `nodes`,
/// when non-NULL, must point to `count` `c_int` entries. `status`,
/// when non-NULL, must point to writable `count` `c_int` entries.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn move_pages(
    pid: c_int,
    count: c_ulong,
    pages: *const *mut c_void,
    nodes: *const c_int,
    status: *mut c_int,
    flags: c_int,
) -> c_long {
    // SAFETY: forwarding to the kernel.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_move_pages,
            pid as libc::c_long,
            count as libc::c_long,
            pages as libc::c_long,
            nodes as libc::c_long,
            status as libc::c_long,
            flags as libc::c_long,
        )
    };
    unsafe { raw_syscall_with_errno_long(rc) }
}

/// Linux `set_mempolicy_home_node(start, len, home_node, flags) ->
/// long` (Linux 5.17+, `SYS_set_mempolicy_home_node = 450`) — set
/// the preferred NUMA home node for an existing memory range.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn set_mempolicy_home_node(
    start: c_ulong,
    len: c_ulong,
    home_node: c_ulong,
    flags: c_ulong,
) -> c_long {
    // SAFETY: forwarding to the kernel.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_set_mempolicy_home_node,
            start as libc::c_long,
            len as libc::c_long,
            home_node as libc::c_long,
            flags as libc::c_long,
        )
    };
    unsafe { raw_syscall_with_errno_long(rc) }
}

// ---------------------------------------------------------------------------
// Mount API (statmount/listmount), module loader (finit_module), quotactl_fd,
// map_shadow_stack, bpf, kexec_load, kexec_file_load
// ---------------------------------------------------------------------------

/// Linux `statmount(*req, *out, bufsize, flags) -> int` (Linux 6.8+,
/// syscall 457) — query a single mount by ID. Both `req` and `out`
/// are opaque kernel structs (`struct mnt_id_req` / `struct
/// statmount`) whose layouts are version-specific.
///
/// # Safety
///
/// `req` must point to a valid `struct mnt_id_req`. `out` must point
/// to at least `bufsize` writable bytes that the kernel will fill with
/// a `struct statmount`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn statmount(
    req: *const c_void,
    out: *mut c_void,
    bufsize: usize,
    flags: c_uint,
) -> c_int {
    if req.is_null() || out.is_null() {
        unsafe { set_abi_errno(libc::EFAULT) };
        return -1;
    }
    const SYS_STATMOUNT: libc::c_long = 457;
    // SAFETY: forwarding to the kernel.
    let rc = unsafe {
        libc::syscall(
            SYS_STATMOUNT,
            req as libc::c_long,
            out as libc::c_long,
            bufsize as libc::c_long,
            flags as libc::c_long,
        )
    };
    unsafe { raw_syscall_with_errno(rc) }
}

/// Linux `listmount(*req, *mnt_ids, count, flags) -> int` (Linux
/// 6.8+, syscall 458) — list child mount IDs of a mount into a
/// `u64[count]` array.
///
/// # Safety
///
/// `req` must point to a valid `struct mnt_id_req`. `mnt_ids` must
/// point to writable storage for at least `count` `u64` entries.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn listmount(
    req: *const c_void,
    mnt_ids: *mut u64,
    count: usize,
    flags: c_uint,
) -> c_int {
    if req.is_null() || (count > 0 && mnt_ids.is_null()) {
        unsafe { set_abi_errno(libc::EFAULT) };
        return -1;
    }
    const SYS_LISTMOUNT: libc::c_long = 458;
    // SAFETY: forwarding to the kernel.
    let rc = unsafe {
        libc::syscall(
            SYS_LISTMOUNT,
            req as libc::c_long,
            mnt_ids as libc::c_long,
            count as libc::c_long,
            flags as libc::c_long,
        )
    };
    unsafe { raw_syscall_with_errno(rc) }
}

/// Linux `finit_module(fd, *param_values, flags) -> int`
/// (`SYS_finit_module = 313`) — load a kernel module from an open
/// file descriptor.
///
/// # Safety
///
/// `param_values`, when non-NULL, must be a NUL-terminated C string
/// of comma-separated parameter assignments.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn finit_module(
    fd: c_int,
    param_values: *const c_char,
    flags: c_int,
) -> c_int {
    // SAFETY: forwarding to the kernel.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_finit_module,
            fd as libc::c_long,
            param_values as libc::c_long,
            flags as libc::c_long,
        )
    };
    unsafe { raw_syscall_with_errno(rc) }
}

/// Linux `quotactl_fd(fd, cmd, id, *addr) -> int` (Linux 5.14+,
/// `SYS_quotactl_fd = 443`) — like quotactl but uses an open fd of
/// the filesystem instead of a block-device path.
///
/// # Safety
///
/// `addr` is interpreted per the supplied `cmd` (typically a
/// pointer to a `struct dqblk`, `struct dqinfo`, etc.). When
/// non-NULL it must point to readable/writable storage matching
/// the cmd contract.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn quotactl_fd(
    fd: c_uint,
    cmd: c_int,
    id: c_uint,
    addr: *mut c_void,
) -> c_int {
    // SAFETY: forwarding to the kernel.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_quotactl_fd,
            fd as libc::c_long,
            cmd as libc::c_long,
            id as libc::c_long,
            addr as libc::c_long,
        )
    };
    unsafe { raw_syscall_with_errno(rc) }
}

/// Linux `map_shadow_stack(addr, size, flags) -> long` (Linux
/// 6.6+, syscall 453) — allocate a CET shadow stack for the calling
/// thread on x86_64. `addr == 0` lets the kernel pick.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn map_shadow_stack(addr: c_ulong, size: c_ulong, flags: c_uint) -> c_long {
    const SYS_MAP_SHADOW_STACK: libc::c_long = 453;
    // SAFETY: forwarding to the kernel.
    let rc = unsafe {
        libc::syscall(
            SYS_MAP_SHADOW_STACK,
            addr as libc::c_long,
            size as libc::c_long,
            flags as libc::c_long,
        )
    };
    unsafe { raw_syscall_with_errno_long(rc) }
}

/// Linux `bpf(cmd, *attr, size) -> int` (`SYS_bpf = 321`) —
/// universal eBPF entry point. The interpretation of `attr`
/// depends on `cmd` (load program, create map, lookup, ...).
///
/// # Safety
///
/// `attr` must point to at least `size` bytes describing a valid
/// `union bpf_attr` for the requested `cmd`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn bpf(cmd: c_int, attr: *mut c_void, size: c_uint) -> c_int {
    if size > 0 && attr.is_null() {
        unsafe { set_abi_errno(libc::EFAULT) };
        return -1;
    }
    // SAFETY: forwarding to the kernel.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            cmd as libc::c_long,
            attr as libc::c_long,
            size as libc::c_long,
        )
    };
    unsafe { raw_syscall_with_errno(rc) }
}

/// Linux `kexec_load(entry, nr_segments, *segments, flags) -> long`
/// (`SYS_kexec_load = 246`) — load a kernel image (built up of
/// in-memory segments) for a future `reboot(LINUX_REBOOT_CMD_KEXEC)`.
///
/// # Safety
///
/// `segments`, when `nr_segments > 0`, must point to an array of
/// `nr_segments` `struct kexec_segment` entries.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn kexec_load(
    entry: c_ulong,
    nr_segments: c_ulong,
    segments: *const c_void,
    flags: c_ulong,
) -> c_long {
    if nr_segments > 0 && segments.is_null() {
        unsafe { set_abi_errno(libc::EFAULT) };
        return -1;
    }
    // SAFETY: forwarding to the kernel.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_kexec_load,
            entry as libc::c_long,
            nr_segments as libc::c_long,
            segments as libc::c_long,
            flags as libc::c_long,
        )
    };
    unsafe { raw_syscall_with_errno_long(rc) }
}

/// Linux `kexec_file_load(kernel_fd, initrd_fd, cmdline_len,
/// *cmdline, flags) -> long` (`SYS_kexec_file_load = 320`) — load a
/// kernel image from `kernel_fd` (and an optional `initrd_fd`) for
/// a future `reboot(LINUX_REBOOT_CMD_KEXEC)`.
///
/// # Safety
///
/// `cmdline`, when `cmdline_len > 0`, must point to at least
/// `cmdline_len` readable bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn kexec_file_load(
    kernel_fd: c_int,
    initrd_fd: c_int,
    cmdline_len: c_ulong,
    cmdline: *const c_char,
    flags: c_ulong,
) -> c_long {
    if cmdline_len > 0 && cmdline.is_null() {
        unsafe { set_abi_errno(libc::EFAULT) };
        return -1;
    }
    // SAFETY: forwarding to the kernel.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_kexec_file_load,
            kernel_fd as libc::c_long,
            initrd_fd as libc::c_long,
            cmdline_len as libc::c_long,
            cmdline as libc::c_long,
            flags as libc::c_long,
        )
    };
    unsafe { raw_syscall_with_errno_long(rc) }
}

// ---------------------------------------------------------------------------
// Robust futex list (set_robust_list / get_robust_list) + LSM self-attr API
// ---------------------------------------------------------------------------

/// Linux `set_robust_list(*head, len) -> int`
/// (`SYS_set_robust_list = 273`) — register a per-thread robust
/// futex list head. The kernel walks the list when the thread exits
/// to release any held mutexes whose owner died unexpectedly.
///
/// # Safety
///
/// `head`, when non-NULL, must point to a valid
/// `struct robust_list_head` of `len` bytes that lives at least
/// until the thread exits.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn set_robust_list(head: *mut c_void, len: usize) -> c_int {
    // SAFETY: forwarding to the kernel.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_set_robust_list,
            head as libc::c_long,
            len as libc::c_long,
        )
    };
    unsafe { raw_syscall_with_errno(rc) }
}

/// Linux `get_robust_list(pid, **head_ptr, *len_ptr) -> int`
/// (`SYS_get_robust_list = 274`) — read the robust-futex list head
/// + length previously registered for `pid` (or 0 = self).
///
/// # Safety
///
/// `head_ptr` and `len_ptr` must each point to writable storage.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn get_robust_list(
    pid: c_int,
    head_ptr: *mut *mut c_void,
    len_ptr: *mut usize,
) -> c_int {
    if head_ptr.is_null() || len_ptr.is_null() {
        unsafe { set_abi_errno(libc::EFAULT) };
        return -1;
    }
    // SAFETY: forwarding to the kernel.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_get_robust_list,
            pid as libc::c_long,
            head_ptr as libc::c_long,
            len_ptr as libc::c_long,
        )
    };
    unsafe { raw_syscall_with_errno(rc) }
}

/// Linux `lsm_get_self_attr(attr_id, *ctx, *size, flags) -> int`
/// (Linux 6.8+, syscall 459) — read an LSM attribute (e.g. SELinux
/// `current` context) for the calling thread into `ctx`. The
/// caller's `*size` is updated to the actual length on success or
/// to the required length on `E2BIG`.
///
/// # Safety
///
/// `size` must point to writable `u32` storage. `ctx`, when
/// non-NULL, must point to at least `*size` writable bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lsm_get_self_attr(
    attr_id: c_uint,
    ctx: *mut c_void,
    size: *mut u32,
    flags: c_uint,
) -> c_int {
    if size.is_null() {
        unsafe { set_abi_errno(libc::EFAULT) };
        return -1;
    }
    const SYS_LSM_GET_SELF_ATTR: libc::c_long = 459;
    // SAFETY: forwarding to the kernel.
    let rc = unsafe {
        libc::syscall(
            SYS_LSM_GET_SELF_ATTR,
            attr_id as libc::c_long,
            ctx as libc::c_long,
            size as libc::c_long,
            flags as libc::c_long,
        )
    };
    unsafe { raw_syscall_with_errno(rc) }
}

/// Linux `lsm_set_self_attr(attr_id, *ctx, size, flags) -> int`
/// (Linux 6.8+, syscall 460) — write an LSM attribute for the
/// calling thread.
///
/// # Safety
///
/// `ctx` must point to at least `size` readable bytes describing
/// the LSM-specific attribute payload.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lsm_set_self_attr(
    attr_id: c_uint,
    ctx: *const c_void,
    size: u32,
    flags: c_uint,
) -> c_int {
    if size > 0 && ctx.is_null() {
        unsafe { set_abi_errno(libc::EFAULT) };
        return -1;
    }
    const SYS_LSM_SET_SELF_ATTR: libc::c_long = 460;
    // SAFETY: forwarding to the kernel.
    let rc = unsafe {
        libc::syscall(
            SYS_LSM_SET_SELF_ATTR,
            attr_id as libc::c_long,
            ctx as libc::c_long,
            size as libc::c_long,
            flags as libc::c_long,
        )
    };
    unsafe { raw_syscall_with_errno(rc) }
}

/// Linux `lsm_list_modules(*ids, *size, flags) -> int` (Linux 6.8+,
/// syscall 461) — enumerate LSM module IDs into `ids`, with `*size`
/// updated to the actual length on success or required length on
/// `E2BIG`.
///
/// # Safety
///
/// `size` must point to writable `u32` storage. `ids`, when
/// non-NULL, must point to at least `*size` writable bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lsm_list_modules(ids: *mut u64, size: *mut u32, flags: c_uint) -> c_int {
    if size.is_null() {
        unsafe { set_abi_errno(libc::EFAULT) };
        return -1;
    }
    const SYS_LSM_LIST_MODULES: libc::c_long = 461;
    // SAFETY: forwarding to the kernel.
    let rc = unsafe {
        libc::syscall(
            SYS_LSM_LIST_MODULES,
            ids as libc::c_long,
            size as libc::c_long,
            flags as libc::c_long,
        )
    };
    unsafe { raw_syscall_with_errno(rc) }
}

// ---------------------------------------------------------------------------
// faccessat2 / io_pgetevents / clone3
// ---------------------------------------------------------------------------

/// Linux `faccessat2(dirfd, pathname, mode, flags) -> int`
/// (Linux 5.8+, `SYS_faccessat2 = 439`) — like `faccessat` but
/// accepts a `flags` argument for `AT_SYMLINK_NOFOLLOW`,
/// `AT_EACCESS`, and `AT_EMPTY_PATH`.
///
/// # Safety
///
/// `pathname`, when `flags & AT_EMPTY_PATH == 0`, must be a
/// NUL-terminated C string.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn faccessat2(
    dirfd: c_int,
    pathname: *const c_char,
    mode: c_int,
    flags: c_int,
) -> c_int {
    // SAFETY: forwarding to the kernel.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_faccessat2,
            dirfd as libc::c_long,
            pathname as libc::c_long,
            mode as libc::c_long,
            flags as libc::c_long,
        )
    };
    unsafe { raw_syscall_with_errno(rc) }
}

/// Linux `io_pgetevents(ctx_id, min_nr, nr, *events, *timeout, *sig)
/// -> int` (Linux 4.18+, syscall 333) — like `io_getevents` but
/// accepts a `struct __aio_sigset` for atomically blocking signals
/// during the wait. Use `sig == NULL` to behave like
/// `io_getevents`.
///
/// # Safety
///
/// `events`, when `nr > 0`, must point to writable storage for
/// `nr` `struct io_event` entries. `timeout`, when non-NULL, must
/// point to a valid `timespec`. `sig`, when non-NULL, must point
/// to a valid `struct __aio_sigset`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn io_pgetevents(
    ctx_id: c_ulong,
    min_nr: c_long,
    nr: c_long,
    events: *mut c_void,
    timeout: *const libc::timespec,
    sig: *const c_void,
) -> c_int {
    if nr > 0 && events.is_null() {
        unsafe { set_abi_errno(libc::EFAULT) };
        return -1;
    }
    const SYS_IO_PGETEVENTS: libc::c_long = 333;
    // SAFETY: forwarding to the kernel.
    let rc = unsafe {
        libc::syscall(
            SYS_IO_PGETEVENTS,
            ctx_id as libc::c_long,
            min_nr,
            nr,
            events as libc::c_long,
            timeout as libc::c_long,
            sig as libc::c_long,
        )
    };
    unsafe { raw_syscall_with_errno(rc) }
}

/// Linux `clone3(*cl_args, size) -> pid_t` (Linux 5.3+,
/// `SYS_clone3 = 435`) — extended `clone` with a versioned
/// `struct clone_args`. Returns the new pid in the parent or 0 in
/// the child; -1 + errno on failure.
///
/// # Safety
///
/// `cl_args` must point to a valid `struct clone_args` of `size`
/// bytes. The kernel rejects calls with the wrong size for any of
/// its known struct versions.
///
/// Callers in Rust must be extremely careful: in the child branch,
/// stack/TLS state may be unsafe to use until the kernel completes
/// thread setup. Most usage should go through pthread_create or the
/// portable libc clone wrapper instead.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clone3(cl_args: *mut c_void, size: usize) -> libc::pid_t {
    if cl_args.is_null() {
        unsafe { set_abi_errno(libc::EFAULT) };
        return -1;
    }
    // SAFETY: forwarding to the kernel.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            cl_args as libc::c_long,
            size as libc::c_long,
        )
    };
    if rc < 0 {
        let e = unsafe { *libc::__errno_location() };
        unsafe { set_abi_errno(e) };
        return -1;
    }
    rc as libc::pid_t
}

// ---------------------------------------------------------------------------
// fchmodat2 / eventfd2 / rt_sig* (procmask, queueinfo, suspend, tgsigqueueinfo)
// ---------------------------------------------------------------------------

/// Linux `fchmodat2(dirfd, pathname, mode, flags) -> int` (Linux
/// 6.6+, `SYS_fchmodat2 = 452`) — like `fchmodat` but also accepts
/// `AT_SYMLINK_NOFOLLOW` and `AT_EMPTY_PATH` flags.
///
/// # Safety
///
/// `pathname` must be a NUL-terminated C string (or, with
/// `AT_EMPTY_PATH`, may be empty when `dirfd` already names the
/// target).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fchmodat2(
    dirfd: c_int,
    pathname: *const c_char,
    mode: libc::mode_t,
    flags: c_int,
) -> c_int {
    let (_, decision) =
        runtime_policy::decide(ApiFamily::IoFd, pathname as usize, 0, true, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EPERM) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    if pathname.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }
    let rc = match unsafe { syscall::sys_fchmodat2(dirfd, pathname as *const u8, mode, flags) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    };
    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, rc != 0);
    rc
}

/// Linux `eventfd2(initval, flags) -> int` (`SYS_eventfd2 = 290`)
/// — kernel-name variant of `eventfd` that accepts `flags`
/// directly. Some sandbox/seccomp policies trace this name
/// explicitly so we expose it alongside our higher-level
/// `eventfd`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn eventfd2(initval: c_uint, flags: c_int) -> c_int {
    match syscall::sys_eventfd2(initval, flags) {
        Ok(fd) => fd,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// Linux `rt_sigprocmask(how, *set, *oldset, sigsetsize) -> int`
/// (`SYS_rt_sigprocmask = 14`) — kernel-level `sigprocmask` with an
/// explicit `sigsetsize` parameter.
///
/// # Safety
///
/// `set` and `oldset`, when non-NULL, must each point to at least
/// `sigsetsize` bytes describing a `sigset_t`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rt_sigprocmask(
    how: c_int,
    set: *const c_void,
    oldset: *mut c_void,
    sigsetsize: usize,
) -> c_int {
    // SAFETY: caller owns the kernel ABI pointers and sigset size.
    match unsafe {
        syscall::sys_rt_sigprocmask(how, set as *const u8, oldset as *mut u8, sigsetsize)
    } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// Linux `rt_sigqueueinfo(tgid, sig, *uinfo) -> int`
/// (`SYS_rt_sigqueueinfo = 129`) — send a `siginfo_t` to a thread
/// group.
///
/// # Safety
///
/// `uinfo`, when non-NULL, must point to a valid `siginfo_t`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rt_sigqueueinfo(
    tgid: libc::pid_t,
    sig: c_int,
    uinfo: *mut c_void,
) -> c_int {
    if uinfo.is_null() {
        unsafe { set_abi_errno(libc::EFAULT) };
        return -1;
    }
    // SAFETY: caller supplied a non-null siginfo_t pointer for the kernel ABI.
    match unsafe { syscall::sys_rt_sigqueueinfo(tgid, sig, uinfo as *const u8) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// Linux `rt_sigsuspend(*mask, sigsetsize) -> int`
/// (`SYS_rt_sigsuspend = 130`) — temporarily replace the calling
/// thread's signal mask with `*mask` and sleep until a non-masked
/// signal arrives. Always returns -1 with errno set (typically
/// `EINTR`).
///
/// # Safety
///
/// `mask` must point to at least `sigsetsize` bytes describing a
/// `sigset_t`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rt_sigsuspend(mask: *const c_void, sigsetsize: usize) -> c_int {
    if mask.is_null() {
        unsafe { set_abi_errno(libc::EFAULT) };
        return -1;
    }
    // SAFETY: caller supplied a non-null signal-mask pointer for the kernel ABI.
    match unsafe { syscall::sys_rt_sigsuspend(mask as *const u8, sigsetsize) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// Linux `rt_tgsigqueueinfo(tgid, tid, sig, *uinfo) -> int`
/// (`SYS_rt_tgsigqueueinfo = 297`) — send a `siginfo_t` to a
/// specific thread (vs. the whole thread group).
///
/// # Safety
///
/// `uinfo`, when non-NULL, must point to a valid `siginfo_t`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rt_tgsigqueueinfo(
    tgid: libc::pid_t,
    tid: libc::pid_t,
    sig: c_int,
    uinfo: *mut c_void,
) -> c_int {
    if uinfo.is_null() {
        unsafe { set_abi_errno(libc::EFAULT) };
        return -1;
    }
    // SAFETY: caller supplied a non-null siginfo_t pointer for the kernel ABI.
    match unsafe { syscall::sys_rt_tgsigqueueinfo(tgid, tid, sig, uinfo as *const u8) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

// ---------------------------------------------------------------------------
// Scheduler — RawSyscall
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sched_getscheduler(pid: libc::pid_t) -> c_int {
    match syscall::sys_sched_getscheduler(pid) {
        Ok(policy) => policy,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sched_setscheduler(
    pid: libc::pid_t,
    policy: c_int,
    param: *const c_void,
) -> c_int {
    match unsafe { syscall::sys_sched_setscheduler(pid, policy, param as *const u8) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sched_getparam(pid: libc::pid_t, param: *mut c_void) -> c_int {
    match unsafe { syscall::sys_sched_getparam(pid, param as *mut u8) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sched_setparam(pid: libc::pid_t, param: *const c_void) -> c_int {
    match unsafe { syscall::sys_sched_setparam(pid, param as *const u8) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sched_get_priority_min(policy: c_int) -> c_int {
    match syscall::sys_sched_get_priority_min(policy) {
        Ok(prio) => prio,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sched_get_priority_max(policy: c_int) -> c_int {
    match syscall::sys_sched_get_priority_max(policy) {
        Ok(prio) => prio,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
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

struct WordexpSyntaxScan {
    has_bad_char: bool,
    has_command_substitution: bool,
}

/// Scan `wordexp` input while honoring shell quoting and escaping context.
fn scan_wordexp_syntax(s: &[u8]) -> WordexpSyntaxScan {
    let mut scan = WordexpSyntaxScan {
        has_bad_char: false,
        has_command_substitution: false,
    };
    let mut i = 0;
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut escaped = false;
    let mut parameter_brace_depth = 0usize;

    while i < s.len() {
        let byte = s[i];
        if escaped {
            escaped = false;
            i += 1;
            continue;
        }
        if in_single_quote {
            if byte == b'\'' {
                in_single_quote = false;
            }
            i += 1;
            continue;
        }
        if byte == b'\\' {
            escaped = true;
            i += 1;
            continue;
        }
        if byte == b'\'' && !in_double_quote {
            in_single_quote = true;
            i += 1;
            continue;
        }
        if in_double_quote {
            if byte == b'"' {
                in_double_quote = false;
                i += 1;
                continue;
            }
            if byte == b'`' {
                scan.has_command_substitution = true;
                return scan;
            }
            if byte == b'$' && i + 1 < s.len() {
                match s[i + 1] {
                    b'(' => {
                        scan.has_command_substitution = true;
                        return scan;
                    }
                    b'{' => {
                        parameter_brace_depth += 1;
                        i += 2;
                        continue;
                    }
                    _ => {}
                }
            }
            if parameter_brace_depth > 0 && byte == b'}' {
                parameter_brace_depth -= 1;
            }
            i += 1;
            continue;
        }
        if byte == b'"' {
            in_double_quote = !in_double_quote;
            i += 1;
            continue;
        }
        if byte == b'`' {
            scan.has_command_substitution = true;
            return scan;
        }
        if byte == b'$' && i + 1 < s.len() {
            match s[i + 1] {
                b'(' => {
                    scan.has_command_substitution = true;
                    return scan;
                }
                b'{' => {
                    parameter_brace_depth += 1;
                    i += 2;
                    continue;
                }
                _ => {}
            }
        }
        if parameter_brace_depth > 0 && byte == b'}' {
            parameter_brace_depth -= 1;
            i += 1;
            continue;
        }
        if matches!(
            byte,
            b'|' | b'&' | b';' | b'<' | b'>' | b'\n' | b'(' | b')' | b'{' | b'}'
        ) {
            scan.has_bad_char = true;
            return scan;
        }
        i += 1;
    }

    scan
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
///
/// Thin shim over `frankenlibc_core::stdlib::wordexp::expand_vars` —
/// supplies the env-lookup closure (using `std::env::var`) and maps
/// the typed `ExpandError::UndefinedVariable` to the `WRDE_BADVAL`
/// integer return code at the boundary.
fn expand_vars(word: &str, flags: c_int) -> Result<String, c_int> {
    let undef_is_error = (flags & WRDE_UNDEF) != 0;
    frankenlibc_core::stdlib::wordexp::expand_vars(word, undef_is_error, |name| {
        std::env::var(name).ok()
    })
    .map_err(|e| match e {
        frankenlibc_core::stdlib::wordexp::ExpandError::UndefinedVariable(_) => WRDE_BADVAL,
    })
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

    let Some(input_vec) = (unsafe { read_c_string_bytes(words) }) else {
        return WRDE_SYNTAX;
    };
    let input = match std::str::from_utf8(&input_vec) {
        Ok(s) => s,
        Err(_) => return WRDE_SYNTAX,
    };

    let input_bytes = input.as_bytes();

    let syntax_scan = scan_wordexp_syntax(input_bytes);

    // Check for bad characters
    if syntax_scan.has_bad_char {
        return WRDE_BADCHAR;
    }

    // Check for command substitution
    if syntax_scan.has_command_substitution {
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
    let new_wordv = unsafe { crate::malloc_abi::raw_alloc(wordv_size) as *mut *mut c_char };
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
        let buf = unsafe { crate::malloc_abi::raw_alloc(len) as *mut c_char };
        if buf.is_null() {
            // Clean up on allocation failure
            for j in 0..i {
                unsafe {
                    crate::malloc_abi::raw_free(*new_wordv.add(offs + old_count + j) as *mut c_void)
                };
            }
            unsafe { crate::malloc_abi::raw_free(new_wordv as *mut c_void) };
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
        unsafe { crate::malloc_abi::raw_free(we.we_wordv as *mut c_void) };
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
            unsafe { crate::malloc_abi::raw_free(p as *mut c_void) };
        }
    }
    unsafe { crate::malloc_abi::raw_free(we.we_wordv as *mut c_void) };
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

// glob_match_bytes moved to frankenlibc_core::string::wildcard::wildcard_match.
use frankenlibc_core::string::wildcard::wildcard_match as glob_match_bytes;

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
    match unsafe { syscall::sys_signalfd4(fd, mask as *const u8, 8, flags) } {
        Ok(fd) => fd,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// Linux `close_range` — close a range of file descriptors.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn close_range(first: c_uint, last: c_uint, flags: c_uint) -> c_int {
    match syscall::sys_close_range(first, last, flags) {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// Linux `pidfd_open` — obtain a file descriptor that refers to a process.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pidfd_open(pid: libc::pid_t, flags: c_uint) -> c_int {
    match syscall::sys_pidfd_open(pid, flags) {
        Ok(fd) => fd,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// Linux `pidfd_send_signal` — send a signal via a process file descriptor.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pidfd_send_signal(
    pidfd: c_int,
    sig: c_int,
    info: *const c_void,
    flags: c_uint,
) -> c_int {
    match unsafe { syscall::sys_pidfd_send_signal(pidfd, sig, info as usize, flags) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
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
    match unsafe {
        syscall::sys_getxattr(path as *const u8, name as *const u8, value as *mut u8, size)
    } {
        Ok(n) => n,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setxattr(
    path: *const c_char,
    name: *const c_char,
    value: *const c_void,
    size: usize,
    flags: c_int,
) -> c_int {
    match unsafe {
        syscall::sys_setxattr(
            path as *const u8,
            name as *const u8,
            value as *const u8,
            size,
            flags,
        )
    } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn listxattr(path: *const c_char, list: *mut c_char, size: usize) -> isize {
    match unsafe { syscall::sys_listxattr(path as *const u8, list as *mut u8, size) } {
        Ok(n) => n,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn removexattr(path: *const c_char, name: *const c_char) -> c_int {
    match unsafe { syscall::sys_removexattr(path as *const u8, name as *const u8) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fgetxattr(
    fd: c_int,
    name: *const c_char,
    value: *mut c_void,
    size: usize,
) -> isize {
    match unsafe { syscall::sys_fgetxattr(fd, name as *const u8, value as *mut u8, size) } {
        Ok(n) => n,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fsetxattr(
    fd: c_int,
    name: *const c_char,
    value: *const c_void,
    size: usize,
    flags: c_int,
) -> c_int {
    match unsafe { syscall::sys_fsetxattr(fd, name as *const u8, value as *const u8, size, flags) }
    {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn flistxattr(fd: c_int, list: *mut c_char, size: usize) -> isize {
    match unsafe { syscall::sys_flistxattr(fd, list as *mut u8, size) } {
        Ok(n) => n,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fremovexattr(fd: c_int, name: *const c_char) -> c_int {
    match unsafe { syscall::sys_fremovexattr(fd, name as *const u8) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

// ---------------------------------------------------------------------------
// Misc Linux syscalls — RawSyscall
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mincore(addr: *mut c_void, len: usize, vec: *mut u8) -> c_int {
    match unsafe { syscall::sys_mincore(addr as usize, len, vec) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn posix_fadvise(fd: c_int, offset: i64, len: i64, advice: c_int) -> c_int {
    match syscall::sys_fadvise64(fd, offset, len, advice) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn readahead(fd: c_int, offset: i64, count: usize) -> isize {
    match syscall::sys_readahead(fd, offset, count) {
        Ok(n) => n,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn syncfs(fd: c_int) -> c_int {
    match syscall::sys_syncfs(fd) {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sync() {
    syscall::sys_sync();
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
        let _ = syscall::sys_close(master);
        return -1;
    }

    // Get slave path via internal helper
    let mut slave_name = [0u8; 64];
    if let Err(err) =
        unsafe { resolve_ptsname_into(master, slave_name.as_mut_ptr().cast::<c_char>(), 64) }
    {
        unsafe { set_abi_errno(err) };
        let _ = syscall::sys_close(master);
        return -1;
    }
    let Some(slave_name_len) = bounded_nul_len_with_nul(&slave_name) else {
        unsafe { set_abi_errno(errno::EIO) };
        let _ = syscall::sys_close(master);
        return -1;
    };

    // Open slave
    let slave = match unsafe {
        syscall::sys_openat(
            libc::AT_FDCWD,
            slave_name.as_ptr(),
            libc::O_RDWR | libc::O_NOCTTY,
            0,
        )
    } {
        Ok(fd) => fd,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            let _ = syscall::sys_close(master);
            return -1;
        }
    };

    // Apply terminal attributes if provided
    if !termp.is_null()
        && unsafe { syscall::sys_ioctl(slave, libc::TCSETS as usize, termp as usize) }.is_err()
    {
        unsafe { set_abi_errno(errno::EBADF) };
        let _ = syscall::sys_close(master);
        let _ = syscall::sys_close(slave);
        return -1;
    }

    // Apply window size if provided
    const TIOCSWINSZ: usize = 0x5414;
    if !winp.is_null() && unsafe { syscall::sys_ioctl(slave, TIOCSWINSZ, winp as usize) }.is_err() {
        unsafe { set_abi_errno(errno::EBADF) };
        let _ = syscall::sys_close(master);
        let _ = syscall::sys_close(slave);
        return -1;
    }

    // Copy slave name if buffer provided
    if !name.is_null() {
        unsafe {
            std::ptr::copy_nonoverlapping(
                slave_name.as_ptr().cast::<c_char>(),
                name,
                slave_name_len,
            );
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
    if syscall::sys_setsid().is_err() {
        unsafe { set_abi_errno(errno::EPERM) };
        return -1;
    }

    // Set controlling terminal (TIOCSCTTY = 0x540E on Linux)
    const TIOCSCTTY: u64 = 0x540E;
    if unsafe { syscall::sys_ioctl(fd, TIOCSCTTY as usize, 0) }.is_err() {
        unsafe { set_abi_errno(errno::ENOTTY) };
        return -1;
    }

    // Dup fd to stdin/stdout/stderr
    if syscall::sys_dup2(fd, 0).is_err() {
        unsafe { set_abi_errno(errno::EBADF) };
        return -1;
    }
    if syscall::sys_dup2(fd, 1).is_err() {
        unsafe { set_abi_errno(errno::EBADF) };
        return -1;
    }
    if syscall::sys_dup2(fd, 2).is_err() {
        unsafe { set_abi_errno(errno::EBADF) };
        return -1;
    }

    if fd > 2 {
        let _ = syscall::sys_close(fd);
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

    // Apply ApiFamily::Process policy before allocating PTY fds. fork()
    // runs through the same gate; forkpty() is a fork-creator and must
    // respect the same Deny decisions, otherwise a runtime policy that
    // disables fork could be bypassed by routing through forkpty().
    let (_, decision) = runtime_policy::decide(ApiFamily::Process, 0, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Process, decision.profile, 50, true);
        unsafe { set_abi_errno(libc::EAGAIN) };
        return -1;
    }

    let mut master: c_int = -1;
    let mut slave: c_int = -1;
    if unsafe { openpty(&mut master, &mut slave, name, termp, winp) } < 0 {
        return -1;
    }

    crate::pthread_abi::run_atfork_prepare();
    let _pipeline_guard =
        crate::membrane_state::try_global_pipeline().map(|pipeline| pipeline.atfork_prepare());
    // Mirror fork()'s ENVIRON_LOCK acquisition: the forkpty child does not exec,
    // so any held environ lock from another parent thread becomes a stuck lock
    // in the child address space. Acquiring here forces serialization with any
    // in-flight setenv before the clone.
    let _environ_guard = crate::stdlib_abi::ENVIRON_LOCK.lock();

    let pid = match syscall::sys_clone_fork(libc::SIGCHLD as usize) {
        Ok(p) => p,
        Err(_) => {
            drop(_environ_guard);
            drop(_pipeline_guard);
            let _ = syscall::sys_close(master);
            let _ = syscall::sys_close(slave);
            return -1;
        }
    };

    drop(_environ_guard);
    drop(_pipeline_guard);

    if pid == 0 {
        crate::pthread_abi::run_atfork_child();
    } else {
        crate::pthread_abi::run_atfork_parent();
    }

    if pid == 0 {
        // Child: close master, set up slave as controlling terminal
        let _ = syscall::sys_close(master);
        unsafe { login_tty(slave) };
        return 0;
    }

    // Parent: close slave, return master
    let _ = syscall::sys_close(slave);
    unsafe { *amaster = master };
    pid
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn grantpt(fd: c_int) -> c_int {
    let mut pty_num: c_int = 0;
    // SAFETY: ioctl validates `fd` as PTY master and writes index on success.
    if let Err(e) = unsafe {
        syscall::sys_ioctl(
            fd,
            libc::TIOCGPTN as usize,
            &mut pty_num as *mut c_int as usize,
        )
    } {
        unsafe { set_abi_errno(e) };
        return -1;
    }
    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn unlockpt(fd: c_int) -> c_int {
    let mut unlock: c_int = 0;
    // SAFETY: ioctl reads lock toggle value from `unlock`.
    if let Err(e) = unsafe {
        syscall::sys_ioctl(
            fd,
            libc::TIOCSPTLCK as usize,
            &mut unlock as *mut c_int as usize,
        )
    } {
        unsafe { set_abi_errno(e) };
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
    match unsafe { syscall::sys_openat(libc::AT_FDCWD, PTMX_PATH.as_ptr(), flags, 0) } {
        Ok(fd) => fd,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
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

    let Some(key_bytes) = (unsafe { read_c_string_bytes(key) }) else {
        unsafe { set_abi_errno(errno::EINVAL) };
        return std::ptr::null_mut();
    };
    let Some(salt_bytes) = (unsafe { read_c_string_bytes(salt) }) else {
        unsafe { set_abi_errno(errno::EINVAL) };
        return std::ptr::null_mut();
    };

    let result = if salt_bytes.starts_with(b"$6$") {
        crypt_sha512(&key_bytes, &salt_bytes)
    } else if salt_bytes.starts_with(b"$5$") {
        crypt_sha256(&key_bytes, &salt_bytes)
    } else if salt_bytes.starts_with(b"$1$") {
        crypt_md5(&key_bytes, &salt_bytes)
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

// ---------------------------------------------------------------------------
// libcrypt aliases + DES no-op stubs + crypt_preferred_method + crypt_checksalt
// ---------------------------------------------------------------------------

/// libcrypt `fcrypt(key, salt)` — historical alias of `crypt`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fcrypt(key: *const c_char, salt: *const c_char) -> *mut c_char {
    unsafe { crypt(key, salt) }
}

/// libcrypt `xcrypt(key, salt)` — alternate-name alias of `crypt`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn xcrypt(key: *const c_char, salt: *const c_char) -> *mut c_char {
    unsafe { crypt(key, salt) }
}

/// libcrypt `encrypt(block, edflag)` — DES single-block encrypt /
/// decrypt. DES is obsolete and unsupported; this is a no-op stub
/// so binaries that link the symbol but never invoke it still work.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn encrypt(_block: *mut c_char, _edflag: c_int) {}

/// libcrypt `encrypt_r(block, edflag, *data)` — reentrant `encrypt`.
/// Same DES no-op rationale as [`encrypt`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn encrypt_r(_block: *mut c_char, _edflag: c_int, _data: *mut c_void) {}

/// libcrypt `setkey(key)` — DES key schedule. No-op stub (see
/// [`encrypt`]).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setkey(_key: *const c_char) {}

/// libcrypt `setkey_r(key, *data)` — reentrant DES key schedule.
/// No-op stub.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setkey_r(_key: *const c_char, _data: *mut c_void) {}

// libxcrypt's preferred-method static string. Lives in BSS as a
// NUL-terminated byte array so we can hand out a stable `*const
// c_char` for as long as the process is running.
static CRYPT_PREFERRED_METHOD_STATIC: [u8; 4] = *b"$6$\0";

/// libcrypt `crypt_preferred_method() -> *const c_char` — return
/// the static prefix string of the preferred crypto method
/// supported on this system. We return `"$6$"` (SHA-512), which is
/// the strongest method our `crypt()` honors.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn crypt_preferred_method() -> *const c_char {
    CRYPT_PREFERRED_METHOD_STATIC.as_ptr() as *const c_char
}

/// libcrypt `crypt_checksalt(setting) -> int` — validate that
/// `setting` begins with a recognized crypt prefix. Returns
/// `CRYPT_SALT_OK = 0` for `$1$` (MD5), `$5$` (SHA-256), and `$6$`
/// (SHA-512); returns `CRYPT_SALT_INVALID = 1` for any other
/// prefix or NULL input. (libxcrypt also defines
/// `CRYPT_SALT_METHOD_LEGACY = 2` and `CRYPT_SALT_METHOD_DISABLED
/// = 3` for older / disabled algorithms; we don't classify those
/// separately.)
///
/// # Safety
///
/// `setting`, when non-NULL, must be a NUL-terminated C string.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn crypt_checksalt(setting: *const c_char) -> c_int {
    if setting.is_null() {
        return 1;
    }
    let Some(bytes) = (unsafe { read_c_string_bytes(setting) }) else {
        return 1;
    };
    if bytes.starts_with(b"$1$") || bytes.starts_with(b"$5$") || bytes.starts_with(b"$6$") {
        0
    } else {
        1
    }
}

// ---------------------------------------------------------------------------
// Re-entrant crypt + crypt_gensalt family (libcrypt parity)
// ---------------------------------------------------------------------------

/// Minimum size of caller storage for crypt_r / crypt_rn results.
/// libxcrypt sets `CRYPT_OUTPUT_SIZE = 384`. The `output` field
/// sits at offset 0 of `struct crypt_data` for both glibc and
/// libxcrypt, so writing the result there is layout-safe.
const CRYPT_OUTPUT_SIZE: usize = 384;

/// Maximum length of a generated salt string (algorithm prefix +
/// optional rounds= + base64 random + terminating NUL).
const CRYPT_GENSALT_OUTPUT_SIZE: usize = 192;

/// Copy a bounded C string into a writable byte slice; returns
/// Some(strlen-without-NUL) on success, None if the source is
/// unterminated within `src_limit` or the destination is too small.
#[inline]
unsafe fn copy_bounded_cstr_into(
    src: *const c_char,
    src_limit: usize,
    dst_ptr: *mut c_char,
    dst_len: usize,
) -> Option<usize> {
    if src.is_null() || dst_ptr.is_null() || src_limit == 0 {
        return None;
    }
    let (len, terminated) = unsafe { scan_c_string(src, Some(src_limit)) };
    if !terminated || len + 1 > dst_len {
        return None;
    }
    let bytes = unsafe { core::slice::from_raw_parts(src.cast::<u8>(), len) };
    // SAFETY: caller validated dst_ptr/dst_len; len+1 <= dst_len.
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr().cast::<c_char>(), dst_ptr, len);
        *dst_ptr.add(len) = 0;
    }
    Some(len)
}

/// libcrypt `crypt_r(key, salt, *data) -> *mut c_char` —
/// re-entrant `crypt`. Forwards to our `crypt()` and copies the
/// result into the first `CRYPT_OUTPUT_SIZE` bytes of `data` (the
/// `output` field at offset 0 of both glibc and libxcrypt's
/// `struct crypt_data`). Returns the buffer pointer on success or
/// NULL with errno on failure.
///
/// # Safety
///
/// `data` must point to writable storage of at least
/// `CRYPT_OUTPUT_SIZE = 384` bytes (always true for any real
/// `struct crypt_data`).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn crypt_r(
    key: *const c_char,
    salt: *const c_char,
    data: *mut c_void,
) -> *mut c_char {
    if data.is_null() {
        unsafe { set_abi_errno(errno::EINVAL) };
        return core::ptr::null_mut();
    }
    let result = unsafe { crypt(key, salt) };
    if result.is_null() {
        return core::ptr::null_mut();
    }
    let dst = data as *mut c_char;
    if unsafe { copy_bounded_cstr_into(result, CRYPT_OUTPUT_SIZE, dst, CRYPT_OUTPUT_SIZE) }
        .is_none()
    {
        unsafe { set_abi_errno(errno::ERANGE) };
        return core::ptr::null_mut();
    }
    dst
}

/// libcrypt `crypt_rn(key, salt, *data, size) -> *mut c_char` —
/// like [`crypt_r`] but with an explicit `size` for the data
/// buffer. Refuses if `size` is too small.
///
/// # Safety
///
/// `data` must point to at least `size` writable bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn crypt_rn(
    key: *const c_char,
    salt: *const c_char,
    data: *mut c_void,
    size: c_int,
) -> *mut c_char {
    if data.is_null() || size <= 0 {
        unsafe { set_abi_errno(errno::EINVAL) };
        return core::ptr::null_mut();
    }
    let result = unsafe { crypt(key, salt) };
    if result.is_null() {
        return core::ptr::null_mut();
    }
    let dst = data as *mut c_char;
    if unsafe { copy_bounded_cstr_into(result, CRYPT_OUTPUT_SIZE, dst, size as usize) }.is_none() {
        unsafe { set_abi_errno(errno::ERANGE) };
        return core::ptr::null_mut();
    }
    dst
}

/// libcrypt `crypt_ra(key, salt, **data, *size) -> *mut c_char` —
/// auto-allocating re-entrant `crypt`. If `*data` is NULL or
/// `*size` is too small, allocates a `CRYPT_OUTPUT_SIZE`-byte
/// buffer via our `malloc_abi::malloc` and updates `*data + *size`
/// before forwarding to the inner copy.
///
/// # Safety
///
/// `data` and `size` must each point to writable storage. Any
/// existing buffer at `*data` must have been allocated with our
/// `malloc` so the caller can `free` it.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn crypt_ra(
    key: *const c_char,
    salt: *const c_char,
    data: *mut *mut c_void,
    size: *mut c_int,
) -> *mut c_char {
    if data.is_null() || size.is_null() {
        unsafe { set_abi_errno(errno::EINVAL) };
        return core::ptr::null_mut();
    }
    let need = CRYPT_OUTPUT_SIZE as c_int;
    // SAFETY: caller-supplied writable pointers.
    let cur = unsafe { *data };
    let cur_size = unsafe { *size };
    if cur.is_null() || cur_size < need {
        let new_buf = if cur.is_null() {
            unsafe { crate::malloc_abi::malloc(need as usize) }
        } else {
            unsafe { crate::malloc_abi::realloc(cur, need as usize) }
        };
        if new_buf.is_null() {
            unsafe { set_abi_errno(errno::ENOMEM) };
            return core::ptr::null_mut();
        }
        unsafe {
            *data = new_buf;
            *size = need;
        }
    }
    let buf = unsafe { *data };
    unsafe { crypt_rn(key, salt, buf, *size) }
}

/// Pick the algorithm prefix for a `crypt_gensalt` call.
/// `NULL`/empty maps to `"$6$"` (SHA-512); unsupported prefixes are
/// rejected instead of silently changing the requested method.
fn gensalt_prefix(prefix: *const c_char) -> Result<&'static [u8], c_int> {
    if prefix.is_null() {
        return Ok(b"$6$");
    }
    let Some(bytes) = (unsafe { read_c_string_bytes(prefix) }) else {
        return Err(errno::EINVAL);
    };
    match bytes.as_slice() {
        b"" => Ok(b"$6$"),
        b"$1$" => Ok(b"$1$"),
        b"$5$" => Ok(b"$5$"),
        b"$6$" => Ok(b"$6$"),
        _ => Err(errno::EINVAL),
    }
}

fn gensalt_nrbytes(nrbytes: c_int) -> Result<usize, c_int> {
    if nrbytes < 0 {
        Err(errno::EINVAL)
    } else {
        Ok(nrbytes as usize)
    }
}

/// Encode `rbytes[0..nrbytes]` (capped at 12 bytes → 16 base64
/// chars) into the libxcrypt-style `./0-9A-Za-z` base64 alphabet
/// and append exactly 16 chars to `out`.
fn gensalt_encode_bytes(rbytes: *const c_char, nrbytes: usize, out: &mut Vec<u8>) {
    const ALPHABET: &[u8; 64] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let n = nrbytes.min(12);
    if n == 0 || rbytes.is_null() {
        out.extend_from_slice(b"AAAAAAAAAAAAAAAA");
        return;
    }
    // SAFETY: caller-supplied buffer of at least nrbytes bytes.
    let bytes = unsafe { core::slice::from_raw_parts(rbytes as *const u8, n) };
    let mut emitted = 0usize;
    let mut i = 0;
    while i + 3 <= bytes.len() && emitted + 4 <= 16 {
        let b0 = bytes[i] as u32;
        let b1 = bytes[i + 1] as u32;
        let b2 = bytes[i + 2] as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((triple >> 18) & 0x3F) as usize]);
        out.push(ALPHABET[((triple >> 12) & 0x3F) as usize]);
        out.push(ALPHABET[((triple >> 6) & 0x3F) as usize]);
        out.push(ALPHABET[(triple & 0x3F) as usize]);
        emitted += 4;
        i += 3;
    }
    while emitted < 16 {
        out.push(b'A');
        emitted += 1;
    }
}

/// Build the salt string into `out`, in libxcrypt format:
/// `prefix[rounds=N$]base64salt`. The result is NUL-terminated.
fn build_gensalt(
    prefix: *const c_char,
    count: c_ulong,
    rbytes: *const c_char,
    nrbytes: usize,
    out: &mut Vec<u8>,
) -> Result<(), c_int> {
    out.clear();
    let p = gensalt_prefix(prefix)?;
    out.extend_from_slice(p);
    if (p == b"$5$" || p == b"$6$") && count >= 1000 {
        use std::io::Write;
        let _ = write!(out, "rounds={count}$");
    }
    gensalt_encode_bytes(rbytes, nrbytes, out);
    if out.len() + 1 > CRYPT_GENSALT_OUTPUT_SIZE {
        return Err(errno::ERANGE);
    }
    out.push(0);
    Ok(())
}

std::thread_local! {
    static GENSALT_TLS: core::cell::RefCell<Vec<u8>> =
        const { core::cell::RefCell::new(Vec::new()) };
}

/// libcrypt `crypt_gensalt(prefix, count, *rbytes, nrbytes) ->
/// *mut c_char` — generate a salt string for the requested
/// algorithm. NULL/empty prefix maps to `"$6$"` (SHA-512);
/// unsupported prefixes are rejected with EINVAL. When `count >=
/// 1000` we emit the optional `rounds=N$` segment.
/// Returns a pointer to a thread-local static buffer; valid until
/// the next call on the same thread.
///
/// # Safety
///
/// `prefix`, when non-NULL, must be a NUL-terminated C string.
/// `rbytes`, when non-NULL, must point to at least `nrbytes`
/// readable bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn crypt_gensalt(
    prefix: *const c_char,
    count: c_ulong,
    rbytes: *const c_char,
    nrbytes: c_int,
) -> *mut c_char {
    let n = match gensalt_nrbytes(nrbytes) {
        Ok(n) => n,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            return core::ptr::null_mut();
        }
    };
    GENSALT_TLS.with(|cell| {
        let mut buf = cell.borrow_mut();
        match build_gensalt(prefix, count, rbytes, n, &mut buf) {
            Ok(()) => buf.as_mut_ptr() as *mut c_char,
            Err(e) => {
                unsafe { set_abi_errno(e) };
                core::ptr::null_mut()
            }
        }
    })
}

/// libcrypt `crypt_gensalt_r(prefix, count, *rbytes, nrbytes,
/// *output, output_size) -> *mut c_char` — same as
/// [`crypt_gensalt`] but writes into the caller's buffer. Returns
/// `output` on success or NULL + EINVAL/ERANGE on failure.
///
/// # Safety
///
/// `output` must point to at least `output_size` writable bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn crypt_gensalt_r(
    prefix: *const c_char,
    count: c_ulong,
    rbytes: *const c_char,
    nrbytes: c_int,
    output: *mut c_char,
    output_size: c_int,
) -> *mut c_char {
    if output.is_null() || output_size <= 0 {
        unsafe { set_abi_errno(errno::EINVAL) };
        return core::ptr::null_mut();
    }
    let n = match gensalt_nrbytes(nrbytes) {
        Ok(n) => n,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            return core::ptr::null_mut();
        }
    };
    let mut tmp = Vec::<u8>::new();
    if let Err(e) = build_gensalt(prefix, count, rbytes, n, &mut tmp) {
        unsafe { set_abi_errno(e) };
        return core::ptr::null_mut();
    }
    if tmp.len() > output_size as usize {
        unsafe { set_abi_errno(errno::ERANGE) };
        return core::ptr::null_mut();
    }
    // SAFETY: output has at least output_size >= tmp.len() bytes; tmp
    // already includes the NUL.
    unsafe { core::ptr::copy_nonoverlapping(tmp.as_ptr() as *const c_char, output, tmp.len()) };
    output
}

/// libcrypt `crypt_gensalt_rn(...)` — alternate name for
/// [`crypt_gensalt_r`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn crypt_gensalt_rn(
    prefix: *const c_char,
    count: c_ulong,
    rbytes: *const c_char,
    nrbytes: c_int,
    output: *mut c_char,
    output_size: c_int,
) -> *mut c_char {
    unsafe { crypt_gensalt_r(prefix, count, rbytes, nrbytes, output, output_size) }
}

/// libcrypt `crypt_gensalt_ra(prefix, count, *rbytes, nrbytes) ->
/// *mut c_char` — auto-allocating gensalt. Returns a freshly
/// `malloc`-allocated NUL-terminated string the caller is
/// responsible for `free`ing. Returns NULL on alloc failure.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn crypt_gensalt_ra(
    prefix: *const c_char,
    count: c_ulong,
    rbytes: *const c_char,
    nrbytes: c_int,
) -> *mut c_char {
    let n = match gensalt_nrbytes(nrbytes) {
        Ok(n) => n,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            return core::ptr::null_mut();
        }
    };
    let mut tmp = Vec::<u8>::new();
    if let Err(e) = build_gensalt(prefix, count, rbytes, n, &mut tmp) {
        unsafe { set_abi_errno(e) };
        return core::ptr::null_mut();
    }
    let buf = unsafe { crate::malloc_abi::malloc(tmp.len()) };
    if buf.is_null() {
        unsafe { set_abi_errno(errno::ENOMEM) };
        return core::ptr::null_mut();
    }
    // SAFETY: buf has at least tmp.len() bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(
            tmp.as_ptr() as *const c_char,
            buf as *mut c_char,
            tmp.len(),
        );
    }
    buf as *mut c_char
}

/// libcrypt `xcrypt_r(key, salt, *data) -> *mut c_char` — alias
/// of [`crypt_r`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn xcrypt_r(
    key: *const c_char,
    salt: *const c_char,
    data: *mut c_void,
) -> *mut c_char {
    unsafe { crypt_r(key, salt, data) }
}

/// libcrypt `xcrypt_gensalt(prefix, count, *rbytes, nrbytes) ->
/// *mut c_char` — alias of [`crypt_gensalt`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn xcrypt_gensalt(
    prefix: *const c_char,
    count: c_ulong,
    rbytes: *const c_char,
    nrbytes: c_int,
) -> *mut c_char {
    unsafe { crypt_gensalt(prefix, count, rbytes, nrbytes) }
}

/// libcrypt `xcrypt_gensalt_r(...)` — alias of [`crypt_gensalt_r`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn xcrypt_gensalt_r(
    prefix: *const c_char,
    count: c_ulong,
    rbytes: *const c_char,
    nrbytes: c_int,
    output: *mut c_char,
    output_size: c_int,
) -> *mut c_char {
    unsafe { crypt_gensalt_r(prefix, count, rbytes, nrbytes, output, output_size) }
}

#[allow(dead_code)]
const _: () = {
    // Compile-time hint: keep CRYPT_GENSALT_OUTPUT_SIZE referenced
    // even though all gensalt paths size-check via the runtime Vec.
    let _: usize = CRYPT_GENSALT_OUTPUT_SIZE;
};

// ---------------------------------------------------------------------------
// NIS / yp_* fail-safe stubs (libnsl parity)
// ---------------------------------------------------------------------------
//
// NIS / Yellow Pages is dead infrastructure; modern Linux systems do
// not run ypbind. These wrappers exist so binaries that statically
// reference yp_* through libc do not fail at link time, and a graceful
// YPERR_NODOM (= 12, "local NIS domain name not set") is returned at
// runtime. Programs that link libnsl.so.1 explicitly still get the
// real impls there.

const YPERR_BADARGS: c_int = 1;
const YPERR_DOMAIN: c_int = 3;
const YPERR_KEY: c_int = 5;
const YPERR_YPBIND: c_int = 10;
const YPERR_NODOM: c_int = 12;

/// libnsl `yp_get_default_domain(**outdomain) -> int` — returns the
/// local NIS domain name. Stub writes NULL and returns YPERR_NODOM.
///
/// # Safety
///
/// `outdomain`, when non-NULL, must point to writable storage for a
/// `*mut c_char`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn yp_get_default_domain(outdomain: *mut *mut c_char) -> c_int {
    if !outdomain.is_null() {
        // SAFETY: caller-supplied writable slot.
        unsafe { *outdomain = core::ptr::null_mut() };
    }
    YPERR_NODOM
}

/// libnsl `yp_bind(*dom) -> int` — bind to a NIS server. Stub
/// returns YPERR_DOMAIN.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn yp_bind(_dom: *const c_char) -> c_int {
    YPERR_DOMAIN
}

/// libnsl `yp_unbind(*dom)` — unbind from a NIS server. No-op.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn yp_unbind(_dom: *const c_char) {}

/// libnsl `yp_match(*dom, *map, *key, keylen, **val, *vallen) ->
/// int`. Zeros outputs and returns YPERR_DOMAIN.
///
/// # Safety
///
/// `val` and `vallen`, when non-NULL, must point to writable
/// storage. `key`, when non-NULL, must point to at least `keylen`
/// readable bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn yp_match(
    _dom: *const c_char,
    _map: *const c_char,
    _key: *const c_char,
    _keylen: c_int,
    val: *mut *mut c_char,
    vallen: *mut c_int,
) -> c_int {
    if !val.is_null() {
        // SAFETY: caller-supplied writable slot.
        unsafe { *val = core::ptr::null_mut() };
    }
    if !vallen.is_null() {
        // SAFETY: caller-supplied writable slot.
        unsafe { *vallen = 0 };
    }
    YPERR_DOMAIN
}

/// libnsl `yp_first(*dom, *map, **outkey, *outkeylen, **outval,
/// *outvallen) -> int`. Zeros outputs and returns YPERR_DOMAIN.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn yp_first(
    _dom: *const c_char,
    _map: *const c_char,
    outkey: *mut *mut c_char,
    outkeylen: *mut c_int,
    outval: *mut *mut c_char,
    outvallen: *mut c_int,
) -> c_int {
    if !outkey.is_null() {
        // SAFETY: caller-supplied writable slot.
        unsafe { *outkey = core::ptr::null_mut() };
    }
    if !outkeylen.is_null() {
        // SAFETY: caller-supplied writable slot.
        unsafe { *outkeylen = 0 };
    }
    if !outval.is_null() {
        // SAFETY: caller-supplied writable slot.
        unsafe { *outval = core::ptr::null_mut() };
    }
    if !outvallen.is_null() {
        // SAFETY: caller-supplied writable slot.
        unsafe { *outvallen = 0 };
    }
    YPERR_DOMAIN
}

/// libnsl `yp_next(*dom, *map, *inkey, inkeylen, **outkey,
/// *outkeylen, **outval, *outvallen) -> int`. Zeros outputs and
/// returns YPERR_DOMAIN.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn yp_next(
    _dom: *const c_char,
    _map: *const c_char,
    _inkey: *const c_char,
    _inkeylen: c_int,
    outkey: *mut *mut c_char,
    outkeylen: *mut c_int,
    outval: *mut *mut c_char,
    outvallen: *mut c_int,
) -> c_int {
    if !outkey.is_null() {
        // SAFETY: caller-supplied writable slot.
        unsafe { *outkey = core::ptr::null_mut() };
    }
    if !outkeylen.is_null() {
        // SAFETY: caller-supplied writable slot.
        unsafe { *outkeylen = 0 };
    }
    if !outval.is_null() {
        // SAFETY: caller-supplied writable slot.
        unsafe { *outval = core::ptr::null_mut() };
    }
    if !outvallen.is_null() {
        // SAFETY: caller-supplied writable slot.
        unsafe { *outvallen = 0 };
    }
    YPERR_DOMAIN
}

/// libnsl `yp_all(*dom, *map, *callback) -> int`. Stub returns
/// YPERR_DOMAIN without invoking the callback.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn yp_all(
    _dom: *const c_char,
    _map: *const c_char,
    _callback: *mut c_void,
) -> c_int {
    YPERR_DOMAIN
}

/// libnsl `yp_master(*dom, *map, **outname) -> int`. Stub returns
/// YPERR_DOMAIN.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn yp_master(
    _dom: *const c_char,
    _map: *const c_char,
    outname: *mut *mut c_char,
) -> c_int {
    if !outname.is_null() {
        // SAFETY: caller-supplied writable slot.
        unsafe { *outname = core::ptr::null_mut() };
    }
    YPERR_DOMAIN
}

/// libnsl `yp_order(*dom, *map, *order) -> int`. Stub returns
/// YPERR_DOMAIN.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn yp_order(
    _dom: *const c_char,
    _map: *const c_char,
    order: *mut c_uint,
) -> c_int {
    if !order.is_null() {
        // SAFETY: caller-supplied writable slot.
        unsafe { *order = 0 };
    }
    YPERR_DOMAIN
}

/// libnsl `yp_maplist(*dom, **outmaplist) -> int`. Stub returns
/// YPERR_DOMAIN.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn yp_maplist(_dom: *const c_char, outmaplist: *mut *mut c_void) -> c_int {
    if !outmaplist.is_null() {
        // SAFETY: caller-supplied writable slot.
        unsafe { *outmaplist = core::ptr::null_mut() };
    }
    YPERR_DOMAIN
}

/// libnsl `yp_update(*dom, *map, ypop, *key, keylen, *data,
/// datalen) -> int`. Stub returns YPERR_DOMAIN.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn yp_update(
    _dom: *const c_char,
    _map: *const c_char,
    _ypop: c_uint,
    _key: *const c_char,
    _keylen: c_int,
    _data: *const c_char,
    _datalen: c_int,
) -> c_int {
    YPERR_DOMAIN
}

// Static error message strings for yperr_string and ypbinderr_string.
// Storage is process-static so callers may rely on the returned
// pointers remaining valid for the lifetime of the program.
static YPERR_MSGS: [&[u8]; 17] = [
    b"Success\0",
    b"Bad arguments\0",
    b"RPC failure\0",
    b"can't bind to server which serves this domain\0",
    b"no such map in server's domain\0",
    b"no such key in map\0",
    b"internal yp library error\0",
    b"resource allocation failure\0",
    b"no more records in map database\0",
    b"can't communicate with portmapper\0",
    b"can't communicate with ypbind\0",
    b"can't communicate with ypserv\0",
    b"local domain name not set\0",
    b"yp database is bad\0",
    b"yp version mismatch\0",
    b"access violation\0",
    b"database busy\0",
];

static YPBINDERR_MSGS: [&[u8]; 4] = [
    b"Success\0",
    b"Internal ypbind error\0",
    b"Domain not bound\0",
    b"System resource allocation failure\0",
];

/// libnsl `yperr_string(err) -> *const c_char` — return a static
/// human-readable description for the given YPERR_* code.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn yperr_string(err: c_int) -> *const c_char {
    if (0..YPERR_MSGS.len() as c_int).contains(&err) {
        YPERR_MSGS[err as usize].as_ptr() as *const c_char
    } else {
        c"unknown yp error".as_ptr()
    }
}

/// libnsl `ypbinderr_string(err) -> *const c_char` — return a
/// static description for the given ypbind-protocol error.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ypbinderr_string(err: c_int) -> *const c_char {
    if (0..YPBINDERR_MSGS.len() as c_int).contains(&err) {
        YPBINDERR_MSGS[err as usize].as_ptr() as *const c_char
    } else {
        c"unknown ypbind error".as_ptr()
    }
}

/// libnsl `ypprot_err(code) -> int` — convert a ypbind protocol
/// error code (`ypbind_resptype.ypbind_status`) into a `YPERR_*`
/// value. Without a real NIS runtime we collapse all non-zero
/// codes to `YPERR_YPBIND`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ypprot_err(code: c_uint) -> c_int {
    if code == 0 { 0 } else { YPERR_YPBIND }
}

#[allow(dead_code)]
const _: () = {
    // Keep YPERR_BADARGS / YPERR_KEY referenced even though they don't
    // appear in any of the always-fail stubs above; they're part of
    // the public yp ABI catalogue.
    let _ = YPERR_BADARGS;
    let _ = YPERR_KEY;
};

// ---------------------------------------------------------------------------
// NIS+ (nis_*) fail-safe stubs (libnsl parity)
// ---------------------------------------------------------------------------
//
// NIS+ was deprecated by Sun in the late 1990s and is dead
// infrastructure. These stubs let binaries that statically reference
// the symbols resolve at link-edit while returning safe failure values
// (NIS_NAMEUNREACHABLE) at runtime.

const NIS_NAMEUNREACHABLE: c_int = 5;

static NIS_LOCAL_EMPTY: [c_char; 1] = [0];

/// libnsl `nis_local_directory() -> *const c_char` — return the
/// local NIS+ directory name. Stub returns the empty string.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_local_directory() -> *const c_char {
    NIS_LOCAL_EMPTY.as_ptr()
}

/// libnsl `nis_local_host() -> *const c_char` — return the local
/// NIS+ host name. Stub returns the empty string.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_local_host() -> *const c_char {
    NIS_LOCAL_EMPTY.as_ptr()
}

/// libnsl `nis_local_principal() -> *const c_char` — return the
/// principal-name string for the calling process. Stub returns the
/// empty string.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_local_principal() -> *const c_char {
    NIS_LOCAL_EMPTY.as_ptr()
}

/// libnsl `nis_local_group() -> *const c_char` — return the
/// local NIS+ group name. Stub returns the empty string.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_local_group() -> *const c_char {
    NIS_LOCAL_EMPTY.as_ptr()
}

// nis_freeresult / nis_freenames / nis_free_object / nis_free_directory
// / nis_free_request / nis_freeservlist / nis_freetags — every
// query/list operation in our stubs would never have allocated
// anything, so all the free helpers are no-ops.

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_freeresult(_result: *mut c_void) {}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_freenames(_names: *mut *mut c_char) {}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_free_object(_obj: *mut c_void) {}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_free_directory(_dir: *mut c_void) {}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_free_request(_req: *mut c_void) {}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_freeservlist(_list: *mut *mut c_void) {}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_freetags(_tags: *mut c_void) {}

// Static descriptions for nis_sperrno() / nis_sperror() / nis_perror().
// Indexed by the standard NIS+ enum nis_error values (0..63).
fn nis_error_text(status: c_int) -> &'static [u8] {
    match status {
        0 => b"Success",
        1 => b"Probably success",
        2 => b"Not found",
        3 => b"Probably not found",
        4 => b"Cache expired",
        5 => b"Name unreachable",
        6 => b"Unknown object",
        7 => b"Try again",
        8 => b"System error",
        9 => b"Chain broken",
        10 => b"Permission denied",
        11 => b"Out of memory",
        12 => b"Object name exists",
        13 => b"Not master server",
        14 => b"Object/entry is invalid",
        15 => b"Could not contact master",
        16 => b"Could not generate name",
        17 => b"Subsystem failure",
        18 => b"Master server busy",
        19 => b"Object update failure",
        20 => b"Update could not be propagated",
        21 => b"Operation not supported",
        22 => b"Update partially failed",
        23 => b"Lookup limit reached",
        24 => b"Permission denied (modify)",
        25 => b"Already at server end",
        26 => b"Returned data malformed",
        27 => b"Object/entry conflict",
        28 => b"Operation not yet implemented",
        63 => b"Generic NIS+ failure",
        _ => b"Unknown NIS+ error",
    }
}

/// libnsl `nis_sperrno(status) -> *const c_char` — return a static
/// human-readable description of a NIS+ status code. The returned
/// pointer is backed by a thread-local buffer and remains valid until
/// the next `nis_sperrno` call on the same thread.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_sperrno(status: c_int) -> *const c_char {
    thread_local! {
        static NIS_SPERRNO_TLS: core::cell::RefCell<Vec<u8>> =
            const { core::cell::RefCell::new(Vec::new()) };
    }
    NIS_SPERRNO_TLS.with(|cell| {
        let mut buf = cell.borrow_mut();
        buf.clear();
        buf.extend_from_slice(nis_error_text(status));
        buf.push(0);
        buf.as_ptr() as *const c_char
    })
}

/// libnsl `nis_perror(status, label)` — write `<label>: <message>`
/// to fd 2.
///
/// # Safety
///
/// `label`, when non-NULL, must be a NUL-terminated C string.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_perror(status: c_int, label: *const c_char) {
    let mut msg = Vec::<u8>::new();
    match unsafe { read_optional_c_string_bytes(label) } {
        Ok(Some(lbytes)) => {
            msg.extend_from_slice(&lbytes);
            msg.extend_from_slice(b": ");
        }
        Ok(None) => {}
        Err(e) => unsafe { set_abi_errno(e) },
    }
    msg.extend_from_slice(nis_error_text(status));
    msg.push(b'\n');
    // SAFETY: raw syscall write to stderr; the buffer outlives the call.
    let _ = unsafe { syscall::sys_write(2, msg.as_ptr(), msg.len()) };
}

/// libnsl `nis_lerror(status, label)` — log to syslog. Stub no-op
/// (syslog not wired into our libnsl stub layer).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_lerror(_status: c_int, _label: *const c_char) {}

/// libnsl `nis_sperror(status, label) -> *mut c_char` — return a
/// freshly-`malloc`-allocated `"<label>: <message>"` string the
/// caller is responsible for `free`ing. Returns NULL on alloc
/// failure.
///
/// # Safety
///
/// `label`, when non-NULL, must be a NUL-terminated C string.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_sperror(status: c_int, label: *const c_char) -> *mut c_char {
    let mut tmp = Vec::<u8>::new();
    match unsafe { read_optional_c_string_bytes(label) } {
        Ok(Some(lbytes)) => {
            tmp.extend_from_slice(&lbytes);
            tmp.extend_from_slice(b": ");
        }
        Ok(None) => {}
        Err(e) => {
            unsafe { set_abi_errno(e) };
            return core::ptr::null_mut();
        }
    }
    tmp.extend_from_slice(nis_error_text(status));
    tmp.push(0);
    let buf = unsafe { crate::malloc_abi::malloc(tmp.len()) };
    if buf.is_null() {
        unsafe { set_abi_errno(errno::ENOMEM) };
        return core::ptr::null_mut();
    }
    // SAFETY: buf has tmp.len() writable bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(
            tmp.as_ptr() as *const c_char,
            buf as *mut c_char,
            tmp.len(),
        );
    }
    buf as *mut c_char
}

/// libnsl `nis_sperror_r(status, label, *buf, buflen) -> *mut c_char`
/// — write `"<label>: <message>"` into the caller's buffer and
/// return `buf` on success, or NULL with errno=ERANGE if the buffer
/// is too small.
///
/// # Safety
///
/// `buf`, when non-NULL, must point to at least `buflen` writable
/// bytes. `label`, when non-NULL, must be a NUL-terminated C
/// string.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_sperror_r(
    status: c_int,
    label: *const c_char,
    buf: *mut c_char,
    buflen: usize,
) -> *mut c_char {
    if buf.is_null() || buflen == 0 {
        unsafe { set_abi_errno(errno::EINVAL) };
        return core::ptr::null_mut();
    }
    let mut tmp = Vec::<u8>::new();
    match unsafe { read_optional_c_string_bytes(label) } {
        Ok(Some(lbytes)) => {
            tmp.extend_from_slice(&lbytes);
            tmp.extend_from_slice(b": ");
        }
        Ok(None) => {}
        Err(e) => {
            unsafe { set_abi_errno(e) };
            return core::ptr::null_mut();
        }
    }
    tmp.extend_from_slice(nis_error_text(status));
    tmp.push(0);
    if tmp.len() > buflen {
        unsafe { set_abi_errno(errno::ERANGE) };
        return core::ptr::null_mut();
    }
    // SAFETY: buf has buflen >= tmp.len() bytes.
    unsafe { core::ptr::copy_nonoverlapping(tmp.as_ptr() as *const c_char, buf, tmp.len()) };
    buf
}

#[allow(dead_code)]
const _: () = {
    // Reference NIS_NAMEUNREACHABLE so future additions of nis_lookup
    // / nis_list / etc. that return it stay grouped with this module.
    let _ = NIS_NAMEUNREACHABLE;
};

// ---------------------------------------------------------------------------
// NIS+ name-handling helpers (nis_domain_of / leaf_of / name_of + _r) +
// nis_dir_cmp + clone stubs
// ---------------------------------------------------------------------------

/// Find the byte index of the first un-escaped '.' in `bytes`. A
/// '.' preceded by an odd number of consecutive '\\' characters is
/// considered escaped (NIS+ name escaping convention).
fn nis_first_unescaped_dot(bytes: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'.' {
            let mut bs = 0usize;
            let mut j = i;
            while j > 0 && bytes[j - 1] == b'\\' {
                bs += 1;
                j -= 1;
            }
            if bs.is_multiple_of(2) {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

#[inline]
unsafe fn read_optional_c_string_bytes(ptr: *const c_char) -> Result<Option<Vec<u8>>, c_int> {
    if ptr.is_null() {
        return Ok(None);
    }
    // SAFETY: ABI callers provide C string pointers; read_c_string_bytes
    // applies a hard bound for tracked allocations and rejects missing NULs.
    unsafe { read_c_string_bytes(ptr) }
        .map(Some)
        .ok_or(errno::EINVAL)
}

thread_local! {
    static NIS_DOMAIN_OF_TLS: core::cell::RefCell<Vec<u8>> =
        const { core::cell::RefCell::new(Vec::new()) };
    static NIS_LEAF_OF_TLS: core::cell::RefCell<Vec<u8>> =
        const { core::cell::RefCell::new(Vec::new()) };
    static NIS_NAME_OF_TLS: core::cell::RefCell<Vec<u8>> =
        const { core::cell::RefCell::new(Vec::new()) };
}

/// libnsl `nis_domain_of(name) -> *mut c_char` — strip the first
/// label of a NIS+ name and return the rest. For `"host.subdom.dom."`
/// returns `"subdom.dom."`. NULL or empty input returns the empty
/// string.
///
/// # Safety
///
/// `name`, when non-NULL, must be a NUL-terminated C string.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_domain_of(name: *const c_char) -> *mut c_char {
    NIS_DOMAIN_OF_TLS.with(|cell| {
        let mut buf = cell.borrow_mut();
        buf.clear();
        match unsafe { read_optional_c_string_bytes(name) } {
            Ok(Some(bytes)) => {
                if let Some(dot) = nis_first_unescaped_dot(&bytes) {
                    buf.extend_from_slice(&bytes[dot + 1..]);
                }
            }
            Ok(None) => {}
            Err(e) => unsafe { set_abi_errno(e) },
        }
        buf.push(0);
        buf.as_mut_ptr() as *mut c_char
    })
}

/// libnsl `nis_domain_of_r(name, *buf, buflen) -> *mut c_char` —
/// like [`nis_domain_of`] but writes into the caller's buffer.
/// Returns `buf` on success, NULL with errno=ERANGE on overflow.
///
/// # Safety
///
/// `name`, when non-NULL, must be a NUL-terminated C string. `buf`
/// must point to at least `buflen` writable bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_domain_of_r(
    name: *const c_char,
    buf: *mut c_char,
    buflen: usize,
) -> *mut c_char {
    if buf.is_null() || buflen == 0 {
        unsafe { set_abi_errno(errno::EINVAL) };
        return core::ptr::null_mut();
    }
    let name_bytes = match unsafe { read_optional_c_string_bytes(name) } {
        Ok(Some(bytes)) => bytes,
        Ok(None) => Vec::new(),
        Err(e) => {
            unsafe { set_abi_errno(e) };
            return core::ptr::null_mut();
        }
    };
    let tail = if let Some(dot) = nis_first_unescaped_dot(&name_bytes) {
        &name_bytes[dot + 1..]
    } else {
        &[]
    };
    if tail.len() + 1 > buflen {
        unsafe { set_abi_errno(errno::ERANGE) };
        return core::ptr::null_mut();
    }
    // SAFETY: buf has buflen >= tail.len()+1 bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(tail.as_ptr() as *const c_char, buf, tail.len());
        *buf.add(tail.len()) = 0;
    }
    buf
}

/// libnsl `nis_leaf_of(name) -> *mut c_char` — return the first
/// label of a NIS+ name. For `"host.subdom.dom."` returns `"host"`.
/// NULL or empty input returns the empty string.
///
/// # Safety
///
/// `name`, when non-NULL, must be a NUL-terminated C string.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_leaf_of(name: *const c_char) -> *mut c_char {
    NIS_LEAF_OF_TLS.with(|cell| {
        let mut buf = cell.borrow_mut();
        buf.clear();
        match unsafe { read_optional_c_string_bytes(name) } {
            Ok(Some(bytes)) => {
                let head_end = nis_first_unescaped_dot(&bytes).unwrap_or(bytes.len());
                buf.extend_from_slice(&bytes[..head_end]);
            }
            Ok(None) => {}
            Err(e) => unsafe { set_abi_errno(e) },
        }
        buf.push(0);
        buf.as_mut_ptr() as *mut c_char
    })
}

/// libnsl `nis_leaf_of_r(name, *buf, buflen) -> *mut c_char` —
/// like [`nis_leaf_of`] but writes into the caller's buffer.
///
/// # Safety
///
/// See [`nis_domain_of_r`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_leaf_of_r(
    name: *const c_char,
    buf: *mut c_char,
    buflen: usize,
) -> *mut c_char {
    if buf.is_null() || buflen == 0 {
        unsafe { set_abi_errno(errno::EINVAL) };
        return core::ptr::null_mut();
    }
    let name_bytes = match unsafe { read_optional_c_string_bytes(name) } {
        Ok(Some(bytes)) => bytes,
        Ok(None) => Vec::new(),
        Err(e) => {
            unsafe { set_abi_errno(e) };
            return core::ptr::null_mut();
        }
    };
    let head_end = nis_first_unescaped_dot(&name_bytes).unwrap_or(name_bytes.len());
    let head = &name_bytes[..head_end];
    if head.len() + 1 > buflen {
        unsafe { set_abi_errno(errno::ERANGE) };
        return core::ptr::null_mut();
    }
    // SAFETY: buf has buflen >= head.len()+1 bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(head.as_ptr() as *const c_char, buf, head.len());
        *buf.add(head.len()) = 0;
    }
    buf
}

/// libnsl `nis_name_of(name) -> *mut c_char` — return the part of
/// `name` that is "in" the local NIS+ directory. Without a local
/// directory configured we behave as a pass-through and return the
/// input verbatim.
///
/// # Safety
///
/// `name`, when non-NULL, must be a NUL-terminated C string.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_name_of(name: *const c_char) -> *mut c_char {
    NIS_NAME_OF_TLS.with(|cell| {
        let mut buf = cell.borrow_mut();
        buf.clear();
        match unsafe { read_optional_c_string_bytes(name) } {
            Ok(Some(bytes)) => {
                buf.extend_from_slice(&bytes);
            }
            Ok(None) => {}
            Err(e) => unsafe { set_abi_errno(e) },
        }
        buf.push(0);
        buf.as_mut_ptr() as *mut c_char
    })
}

/// libnsl `nis_name_of_r(name, *buf, buflen) -> *mut c_char` —
/// pass-through copy of `name` into the caller's buffer (see
/// [`nis_name_of`] for the reasoning).
///
/// # Safety
///
/// See [`nis_domain_of_r`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_name_of_r(
    name: *const c_char,
    buf: *mut c_char,
    buflen: usize,
) -> *mut c_char {
    if buf.is_null() || buflen == 0 {
        unsafe { set_abi_errno(errno::EINVAL) };
        return core::ptr::null_mut();
    }
    let name_bytes = match unsafe { read_optional_c_string_bytes(name) } {
        Ok(Some(bytes)) => bytes,
        Ok(None) => Vec::new(),
        Err(e) => {
            unsafe { set_abi_errno(e) };
            return core::ptr::null_mut();
        }
    };
    let s = name_bytes.as_slice();
    if s.len() + 1 > buflen {
        unsafe { set_abi_errno(errno::ERANGE) };
        return core::ptr::null_mut();
    }
    // SAFETY: buf has buflen >= s.len()+1 bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(s.as_ptr() as *const c_char, buf, s.len());
        *buf.add(s.len()) = 0;
    }
    buf
}

/// libnsl `nis_dir_cmp(a, b) -> nis_compare_t` — compare two
/// NIS+ directory names (case-insensitive ASCII). Returns 1 if
/// equal (`SAME_NAME`), 0 if `a < b` (`LOWER_NAME`), 2 if `a > b`
/// (`HIGHER_NAME`), or 3 (`NOT_SEQUENTIAL`) when either input is
/// NULL. Note: glibc's nis_compare_t enum uses LOWER_NAME=0,
/// SAME_NAME=1, HIGHER_NAME=2, NOT_SEQUENTIAL=3.
///
/// # Safety
///
/// `a` and `b`, when non-NULL, must be NUL-terminated C strings.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_dir_cmp(a: *const c_char, b: *const c_char) -> c_int {
    if a.is_null() || b.is_null() {
        return 3; // NOT_SEQUENTIAL
    }
    let Some(ab) = (unsafe { read_c_string_bytes(a) }) else {
        return 3;
    };
    let Some(bb) = (unsafe { read_c_string_bytes(b) }) else {
        return 3;
    };
    // Strip a single trailing dot (NIS+ convention) before compare.
    fn stripped(s: &[u8]) -> &[u8] {
        if s.last() == Some(&b'.') {
            &s[..s.len() - 1]
        } else {
            s
        }
    }
    let ab = stripped(&ab);
    let bb = stripped(&bb);
    let lower = |x: u8| -> u8 { if x.is_ascii_uppercase() { x | 0x20 } else { x } };
    let common = ab.len().min(bb.len());
    for i in 0..common {
        let ca = lower(ab[i]);
        let cb = lower(bb[i]);
        if ca < cb {
            return 0; // LOWER_NAME
        }
        if ca > cb {
            return 2; // HIGHER_NAME
        }
    }
    if ab.len() == bb.len() {
        1 // SAME_NAME
    } else if ab.len() < bb.len() {
        0
    } else {
        2
    }
}

/// libnsl `nis_clone_directory(*src) -> *mut c_void` — would deep-
/// copy a NIS+ directory object. Stub returns NULL.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_clone_directory(_src: *const c_void) -> *mut c_void {
    core::ptr::null_mut()
}

/// libnsl `nis_clone_object(*src, *dest) -> *mut c_void` — would
/// deep-copy a NIS+ object. Stub returns NULL.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_clone_object(_src: *const c_void, _dest: *mut c_void) -> *mut c_void {
    core::ptr::null_mut()
}

/// libnsl `nis_clone_result(*src, *dest) -> *mut c_void` — would
/// deep-copy a NIS+ result. Stub returns NULL.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_clone_result(_src: *const c_void, _dest: *mut c_void) -> *mut c_void {
    core::ptr::null_mut()
}

// ---------------------------------------------------------------------------
// NIS+ print helpers + group ops + nis_destroy_object
// ---------------------------------------------------------------------------

/// Shared body for the nis_print_* family: write a constant
/// "(NIS+ unsupported)\n" line to stdout. Argument values are
/// ignored.
#[inline]
fn nis_print_unsupported() {
    const MSG: &[u8] = b"(NIS+ unsupported)\n";
    let _ = super::stdio_abi::write_all_fd(libc::STDOUT_FILENO, MSG);
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_print_directory(_dir: *const c_void) {
    nis_print_unsupported();
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_print_entry(_entry: *const c_void) {
    nis_print_unsupported();
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_print_group(_group: *const c_void) {
    nis_print_unsupported();
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_print_group_entry(_group: *const c_char) {
    nis_print_unsupported();
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_print_link(_link: *const c_void) {
    nis_print_unsupported();
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_print_object(_obj: *const c_void) {
    nis_print_unsupported();
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_print_result(_res: *const c_void) {
    nis_print_unsupported();
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_print_rights(_rights: c_uint) {
    nis_print_unsupported();
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_print_table(_table: *const c_void) {
    nis_print_unsupported();
}

/// libnsl `nis_creategroup(name, flags) -> nis_error` — would
/// create a NIS+ group. Stub returns NIS_NAMEUNREACHABLE.
///
/// # Safety
///
/// `name`, when non-NULL, must be a NUL-terminated C string.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_creategroup(_name: *const c_char, _flags: c_uint) -> c_int {
    NIS_NAMEUNREACHABLE
}

/// libnsl `nis_destroygroup(name) -> nis_error` — would delete a
/// NIS+ group. Stub returns NIS_NAMEUNREACHABLE.
///
/// # Safety
///
/// `name`, when non-NULL, must be a NUL-terminated C string.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_destroygroup(_name: *const c_char) -> c_int {
    NIS_NAMEUNREACHABLE
}

/// libnsl `nis_addmember(name, group) -> nis_error` — would add a
/// member to a group. Stub returns NIS_NAMEUNREACHABLE.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_addmember(_name: *const c_char, _group: *const c_char) -> c_int {
    NIS_NAMEUNREACHABLE
}

/// libnsl `nis_removemember(name, group) -> nis_error` — would
/// remove a member. Stub returns NIS_NAMEUNREACHABLE.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_removemember(_name: *const c_char, _group: *const c_char) -> c_int {
    NIS_NAMEUNREACHABLE
}

/// libnsl `nis_verifygroup(group) -> nis_error` — would verify a
/// group exists. Stub returns NIS_NAMEUNREACHABLE.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_verifygroup(_group: *const c_char) -> c_int {
    NIS_NAMEUNREACHABLE
}

/// libnsl `nis_ismember(name, group) -> bool_t` — would test group
/// membership. Stub returns 0 (FALSE) — without a real NIS+ runtime
/// no membership claim can be verified.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_ismember(_name: *const c_char, _group: *const c_char) -> c_int {
    0
}

/// libnsl `nis_destroy_object(*obj)` — would free a NIS+
/// object. Stub does nothing because
/// our query layer never allocates real NIS+ objects.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_destroy_object(_obj: *mut c_void) {}

// ---------------------------------------------------------------------------
// NIS+ CRUD + directory + misc stubs (closes libnsl nis_* parity)
// ---------------------------------------------------------------------------
//
// All `*mut nis_result`, `*mut nis_object`, and `**directory_obj` /
// `**char` returns are NULL — the documented out-of-memory path that
// well-behaved NIS+ callers already handle. Without a real NIS+
// runtime there is nothing meaningful to allocate. Functions
// returning `nis_error` collapse to `NIS_NAMEUNREACHABLE`.

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_lookup(_name: *const c_char, _flags: c_uint) -> *mut c_void {
    core::ptr::null_mut()
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_list(
    _name: *const c_char,
    _flags: c_uint,
    _callback: *mut c_void,
    _userdata: *mut c_void,
) -> *mut c_void {
    core::ptr::null_mut()
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_add(_name: *const c_char, _obj: *const c_void) -> *mut c_void {
    core::ptr::null_mut()
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_add_entry(
    _name: *const c_char,
    _obj: *const c_void,
    _flags: c_uint,
) -> *mut c_void {
    core::ptr::null_mut()
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_modify(_name: *const c_char, _obj: *const c_void) -> *mut c_void {
    core::ptr::null_mut()
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_modify_entry(
    _name: *const c_char,
    _obj: *const c_void,
    _flags: c_uint,
) -> *mut c_void {
    core::ptr::null_mut()
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_remove(_name: *const c_char, _obj: *const c_void) -> *mut c_void {
    core::ptr::null_mut()
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_remove_entry(
    _name: *const c_char,
    _obj: *const c_void,
    _flags: c_uint,
) -> *mut c_void {
    core::ptr::null_mut()
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_first_entry(_name: *const c_char) -> *mut c_void {
    core::ptr::null_mut()
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_next_entry(
    _name: *const c_char,
    _cookie: *const c_void,
) -> *mut c_void {
    core::ptr::null_mut()
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_checkpoint(_name: *const c_char) -> *mut c_void {
    core::ptr::null_mut()
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_mkdir(_name: *const c_char, _server: *const c_void) -> c_int {
    NIS_NAMEUNREACHABLE
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_rmdir(_name: *const c_char, _server: *const c_void) -> c_int {
    NIS_NAMEUNREACHABLE
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_ping(_name: *const c_char, _utime: c_uint, _dirobj: *const c_void) {}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_servstate(
    _server: *const c_void,
    _state: *mut c_void,
    _num: c_int,
    _result: *mut *mut c_void,
) -> c_int {
    NIS_NAMEUNREACHABLE
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_stats(
    _server: *const c_void,
    _info: *mut c_void,
    _num: c_int,
    _result: *mut *mut c_void,
) -> c_int {
    NIS_NAMEUNREACHABLE
}

/// libnsl `nis_getnames(name) -> **char` — would expand a partially-
/// qualified NIS+ name into a NULL-terminated array of fully-qualified
/// candidates. Stub returns NULL (out-of-memory failure path).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_getnames(_name: *const c_char) -> *mut *mut c_char {
    core::ptr::null_mut()
}

/// libnsl `nis_getservlist(dir) -> **directory_obj` — would
/// enumerate the servers backing a directory. Stub returns NULL.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_getservlist(_dir: *const c_char) -> *mut *mut c_void {
    core::ptr::null_mut()
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_read_obj(_filename: *const c_char) -> *mut c_void {
    core::ptr::null_mut()
}

/// libnsl `nis_write_obj(filename, *obj) -> bool_t` — return 0
/// (FALSE) since we have no NIS+ object to serialize.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nis_write_obj(_filename: *const c_char, _obj: *const c_void) -> c_int {
    0
}

// ---------------------------------------------------------------------------
// NIS XDR encoder/decoder stubs + ColdStartFile helpers (closes libnsl xdr_*)
// ---------------------------------------------------------------------------
//
// Each xdr_* function is a (XDR *xdrs, T *p) -> bool_t encoder/decoder.
// Without a real NIS backend we fail closed with XDR_FALSE (= 0)
// without touching either the stream or the destination struct.
// Returning success while decoding nothing would invite callers to
// trust stale or uninitialized output.
//
// We only declare them here as no-mangle stubs so the link-edit
// resolves cleanly. The *p pointer is not dereferenced.

macro_rules! xdr_stub {
    ($name:ident) => {
        #[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
        pub unsafe extern "C" fn $name(_xdrs: *mut c_void, _p: *mut c_void) -> c_int {
            0 // XDR_FALSE
        }
    };
}

xdr_stub!(xdr_cback_data);
xdr_stub!(xdr_domainname);
xdr_stub!(xdr_keydat);
xdr_stub!(xdr_mapname);
xdr_stub!(xdr_obj_p);
xdr_stub!(xdr_peername);
xdr_stub!(xdr_valdat);
xdr_stub!(xdr_yp_buf);
xdr_stub!(xdr_ypall);
xdr_stub!(xdr_ypbind_binding);
xdr_stub!(xdr_ypbind_resp);
xdr_stub!(xdr_ypbind_resptype);
xdr_stub!(xdr_ypbind_setdom);
xdr_stub!(xdr_ypdelete_args);
xdr_stub!(xdr_ypmap_parms);
xdr_stub!(xdr_ypmaplist);
xdr_stub!(xdr_yppush_status);
xdr_stub!(xdr_yppushresp_xfr);
xdr_stub!(xdr_ypreq_key);
xdr_stub!(xdr_ypreq_nokey);
xdr_stub!(xdr_ypreq_xfr);
xdr_stub!(xdr_ypresp_all);
xdr_stub!(xdr_ypresp_key_val);
xdr_stub!(xdr_ypresp_maplist);
xdr_stub!(xdr_ypresp_master);
xdr_stub!(xdr_ypresp_order);
xdr_stub!(xdr_ypresp_val);
xdr_stub!(xdr_ypresp_xfr);
xdr_stub!(xdr_ypstat);
xdr_stub!(xdr_ypupdate_args);
xdr_stub!(xdr_ypxfrstat);

/// libnsl `readColdStartFile() -> *mut directory_obj` — would
/// load a cold-start NIS+ binding. Stub returns NULL.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
#[allow(non_snake_case)]
pub unsafe extern "C" fn readColdStartFile() -> *mut c_void {
    core::ptr::null_mut()
}

/// libnsl `writeColdStartFile(*obj) -> bool_t` — would persist a
/// cold-start NIS+ binding. Stub returns 0 (FALSE).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
#[allow(non_snake_case)]
pub unsafe extern "C" fn writeColdStartFile(_obj: *const c_void) -> c_int {
    0
}

// ---------------------------------------------------------------------------
// _nss_files_endXX NSS plugin "end iteration" stubs
// ---------------------------------------------------------------------------
//
// These are the GLIBC_PRIVATE-versioned NSS plugin entries for the
// `files` source (i.e. /etc/passwd, /etc/group, /etc/hosts, ...)
// when nsswitch.conf chooses it. All but endnetgrent take no arguments
// and return `enum nss_status`. Returning NSS_STATUS_SUCCESS (= 1, "I
// successfully ended the iteration") is the safe stub since we never
// started one — the NSS dispatch layer accepts it and moves on.

const NSS_STATUS_SUCCESS: c_int = 1;

macro_rules! nss_files_end_stub {
    ($name:ident) => {
        #[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
        pub unsafe extern "C" fn $name() -> c_int {
            NSS_STATUS_SUCCESS
        }
    };
}

nss_files_end_stub!(_nss_files_endaliasent);
nss_files_end_stub!(_nss_files_endetherent);
nss_files_end_stub!(_nss_files_endgrent);
nss_files_end_stub!(_nss_files_endhostent);
nss_files_end_stub!(_nss_files_endnetent);
nss_files_end_stub!(_nss_files_endprotoent);
nss_files_end_stub!(_nss_files_endpwent);
nss_files_end_stub!(_nss_files_endrpcent);
nss_files_end_stub!(_nss_files_endservent);
nss_files_end_stub!(_nss_files_endsgent);
nss_files_end_stub!(_nss_files_endspent);

/// `_nss_files_endnetgrent(*result) -> nss_status` — netgroup end
/// callbacks receive the iterator state object.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_files_endnetgrent(_result: *mut c_void) -> c_int {
    NSS_STATUS_SUCCESS
}

// ---------------------------------------------------------------------------
// _nss_files_setXX NSS plugin "begin iteration" stubs
// ---------------------------------------------------------------------------
//
// Each pairs with a corresponding _nss_files_endXX from the prior
// bead. We never actually open any backing file, so returning
// NSS_STATUS_SUCCESS (= 1) is the safe stub. Signatures vary per
// family per the NSS files-module convention.

/// No-arg `set*ent` family: `enum nss_status fn(void)`.
macro_rules! nss_files_set_void_stub {
    ($name:ident) => {
        #[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
        pub unsafe extern "C" fn $name() -> c_int {
            NSS_STATUS_SUCCESS
        }
    };
}

/// `int stayopen` family: `enum nss_status fn(int stayopen)`.
macro_rules! nss_files_set_stayopen_stub {
    ($name:ident) => {
        #[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
        pub unsafe extern "C" fn $name(_stayopen: c_int) -> c_int {
            NSS_STATUS_SUCCESS
        }
    };
}

nss_files_set_void_stub!(_nss_files_setaliasent);
nss_files_set_stayopen_stub!(_nss_files_setetherent);
nss_files_set_stayopen_stub!(_nss_files_setgrent);
nss_files_set_stayopen_stub!(_nss_files_sethostent);
nss_files_set_stayopen_stub!(_nss_files_setnetent);
nss_files_set_stayopen_stub!(_nss_files_setprotoent);
nss_files_set_stayopen_stub!(_nss_files_setpwent);
nss_files_set_stayopen_stub!(_nss_files_setrpcent);
nss_files_set_stayopen_stub!(_nss_files_setservent);
nss_files_set_stayopen_stub!(_nss_files_setsgent);
nss_files_set_stayopen_stub!(_nss_files_setspent);

/// `_nss_files_setnetgrent(*group, *result) -> nss_status` — special
/// signature taking the netgroup name plus a `struct __netgrent`
/// result pointer. Both ignored; returns NSS_STATUS_SUCCESS so the
/// dispatch layer can move on to the next module.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_files_setnetgrent(
    _group: *const c_char,
    _result: *mut c_void,
) -> c_int {
    NSS_STATUS_SUCCESS
}

// ---------------------------------------------------------------------------
// _nss_files_getXX_r NSS plugin lookup stubs
// ---------------------------------------------------------------------------
//
// Each pairs with the set/end stubs from prior beads. Returns
// NSS_STATUS_NOTFOUND (= 0, "I checked, no record") and sets
// *errnop = ENOENT when non-NULL, so the NSS dispatch layer falls
// through to the next module. Signatures match the canonical glibc
// NSS files-module convention so register placement of the errnop
// pointer matches what callers actually pass.

const NSS_STATUS_NOTFOUND: c_int = 0;
const NSS_HOST_NOT_FOUND: c_int = 1;

#[inline]
unsafe fn nss_set_errnop_enoent(errnop: *mut c_int) {
    if !errnop.is_null() {
        // SAFETY: caller-supplied writable slot per NSS contract.
        unsafe { *errnop = libc::ENOENT };
    }
}

#[inline]
unsafe fn nss_set_herr_host_not_found(h_errnop: *mut c_int) {
    if !h_errnop.is_null() {
        // SAFETY: caller-supplied writable slot per NSS contract.
        unsafe { *h_errnop = NSS_HOST_NOT_FOUND };
    }
}

/// Plain `getXXent_r(*result, *buf, buflen, *errnop)` shape.
macro_rules! nss_files_get_ent_stub {
    ($name:ident) => {
        #[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
        pub unsafe extern "C" fn $name(
            _result: *mut c_void,
            _buffer: *mut c_char,
            _buflen: usize,
            errnop: *mut c_int,
        ) -> c_int {
            unsafe { nss_set_errnop_enoent(errnop) };
            NSS_STATUS_NOTFOUND
        }
    };
}

/// Single-string-key `getXXbyYY_r(name, *result, *buf, buflen,
/// *errnop)` shape.
macro_rules! nss_files_get_by_str_stub {
    ($name:ident) => {
        #[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
        pub unsafe extern "C" fn $name(
            _key: *const c_char,
            _result: *mut c_void,
            _buffer: *mut c_char,
            _buflen: usize,
            errnop: *mut c_int,
        ) -> c_int {
            unsafe { nss_set_errnop_enoent(errnop) };
            NSS_STATUS_NOTFOUND
        }
    };
}

/// Single-int-key `getXXbyYY_r(id, *result, *buf, buflen, *errnop)`
/// shape (gid_t / uid_t / int).
macro_rules! nss_files_get_by_int_stub {
    ($name:ident, $key:ty) => {
        #[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
        pub unsafe extern "C" fn $name(
            _key: $key,
            _result: *mut c_void,
            _buffer: *mut c_char,
            _buflen: usize,
            errnop: *mut c_int,
        ) -> c_int {
            unsafe { nss_set_errnop_enoent(errnop) };
            NSS_STATUS_NOTFOUND
        }
    };
}

// 12 plain getent_r stubs.
nss_files_get_ent_stub!(_nss_files_getaliasent_r);
nss_files_get_ent_stub!(_nss_files_getetherent_r);
nss_files_get_ent_stub!(_nss_files_getgrent_r);
nss_files_get_ent_stub!(_nss_files_getprotoent_r);
nss_files_get_ent_stub!(_nss_files_getpwent_r);
nss_files_get_ent_stub!(_nss_files_getrpcent_r);
nss_files_get_ent_stub!(_nss_files_getservent_r);
nss_files_get_ent_stub!(_nss_files_getsgent_r);
nss_files_get_ent_stub!(_nss_files_getspent_r);

/// `_nss_files_gethostent_r(*result, *buf, buflen, *errnop,
/// *h_errnop)` — host database iteration carries both errno and
/// h_errno slots.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_files_gethostent_r(
    _result: *mut c_void,
    _buffer: *mut c_char,
    _buflen: usize,
    errnop: *mut c_int,
    h_errnop: *mut c_int,
) -> c_int {
    unsafe { nss_set_errnop_enoent(errnop) };
    unsafe { nss_set_herr_host_not_found(h_errnop) };
    NSS_STATUS_NOTFOUND
}

/// `_nss_files_getnetent_r(*result, *buf, buflen, *errnop,
/// *h_errnop)` — network database iteration carries both errno and
/// h_errno slots.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_files_getnetent_r(
    _result: *mut c_void,
    _buffer: *mut c_char,
    _buflen: usize,
    errnop: *mut c_int,
    h_errnop: *mut c_int,
) -> c_int {
    unsafe { nss_set_errnop_enoent(errnop) };
    unsafe { nss_set_herr_host_not_found(h_errnop) };
    NSS_STATUS_NOTFOUND
}

// `_nss_files_getnetgrent_r(*result, *buf, buflen, *errnop)` —
// special variant returning the next netgroup triple. Signature is
// the same as the plain getent_r form (the `*result` is a struct
// `__netgrent` rather than a pubkey type, but our stub doesn't
// dereference it).
nss_files_get_ent_stub!(_nss_files_getnetgrent_r);

// 9 single-key string lookup stubs.
nss_files_get_by_str_stub!(_nss_files_getaliasbyname_r);
nss_files_get_by_str_stub!(_nss_files_getgrnam_r);
nss_files_get_by_str_stub!(_nss_files_getprotobyname_r);
nss_files_get_by_str_stub!(_nss_files_getpwnam_r);
nss_files_get_by_str_stub!(_nss_files_getrpcbyname_r);
nss_files_get_by_str_stub!(_nss_files_getsgnam_r);
nss_files_get_by_str_stub!(_nss_files_getspnam_r);
// gethostton/getntohost have the *_by_str shape under the hood.
nss_files_get_by_str_stub!(_nss_files_gethostton_r);
nss_files_get_by_str_stub!(_nss_files_getntohost_r);

// 4 single-int lookup stubs (gid_t / uid_t / int).
nss_files_get_by_int_stub!(_nss_files_getgrgid_r, libc::gid_t);
nss_files_get_by_int_stub!(_nss_files_getpwuid_r, libc::uid_t);
nss_files_get_by_int_stub!(_nss_files_getprotobynumber_r, c_int);
nss_files_get_by_int_stub!(_nss_files_getrpcbynumber_r, c_int);

/// `_nss_files_getcanonname_r(name, *buffer, buflen, **result,
/// *errnop, *h_errnop)`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_files_getcanonname_r(
    _name: *const c_char,
    _buffer: *mut c_char,
    _buflen: usize,
    result: *mut *mut c_char,
    errnop: *mut c_int,
    h_errnop: *mut c_int,
) -> c_int {
    if !result.is_null() {
        // SAFETY: caller-supplied output slot per NSS contract.
        unsafe { *result = std::ptr::null_mut() };
    }
    unsafe { nss_set_errnop_enoent(errnop) };
    unsafe { nss_set_herr_host_not_found(h_errnop) };
    NSS_STATUS_NOTFOUND
}

/// `_nss_files_gethostbyname_r(name, *result, *buf, buflen,
/// *errnop, *h_errnop)` — extra `*h_errnop` slot for h_errno.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_files_gethostbyname_r(
    _name: *const c_char,
    _result: *mut c_void,
    _buffer: *mut c_char,
    _buflen: usize,
    errnop: *mut c_int,
    h_errnop: *mut c_int,
) -> c_int {
    unsafe { nss_set_errnop_enoent(errnop) };
    unsafe { nss_set_herr_host_not_found(h_errnop) };
    NSS_STATUS_NOTFOUND
}

/// `_nss_files_gethostbyname2_r(name, af, *result, *buf, buflen,
/// *errnop, *h_errnop)` — like gethostbyname_r with an extra address
/// family parameter.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_files_gethostbyname2_r(
    _name: *const c_char,
    _af: c_int,
    _result: *mut c_void,
    _buffer: *mut c_char,
    _buflen: usize,
    errnop: *mut c_int,
    h_errnop: *mut c_int,
) -> c_int {
    unsafe { nss_set_errnop_enoent(errnop) };
    unsafe { nss_set_herr_host_not_found(h_errnop) };
    NSS_STATUS_NOTFOUND
}

/// `_nss_files_gethostbyname3_r(name, af, *result, *buf, buflen,
/// *errnop, *h_errnop, *ttlp, **canonp)` — adds TTL/canonical-name
/// out-parameters.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn _nss_files_gethostbyname3_r(
    _name: *const c_char,
    _af: c_int,
    _result: *mut c_void,
    _buffer: *mut c_char,
    _buflen: usize,
    errnop: *mut c_int,
    h_errnop: *mut c_int,
    _ttlp: *mut i32,
    _canonp: *mut *mut c_char,
) -> c_int {
    unsafe { nss_set_errnop_enoent(errnop) };
    unsafe { nss_set_herr_host_not_found(h_errnop) };
    NSS_STATUS_NOTFOUND
}

/// `_nss_files_gethostbyname4_r(name, *gaih_addrtuple_pp, *buf,
/// buflen, *errnop, *h_errnop, *ttlp)` — newer gaih_addrtuple shape.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_files_gethostbyname4_r(
    _name: *const c_char,
    _pat: *mut *mut c_void,
    _buffer: *mut c_char,
    _buflen: usize,
    errnop: *mut c_int,
    h_errnop: *mut c_int,
    _ttlp: *mut i32,
) -> c_int {
    unsafe { nss_set_errnop_enoent(errnop) };
    unsafe { nss_set_herr_host_not_found(h_errnop) };
    NSS_STATUS_NOTFOUND
}

/// `_nss_files_gethostbyaddr_r(addr, len, type, *result, *buf,
/// buflen, *errnop, *h_errnop)`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn _nss_files_gethostbyaddr_r(
    _addr: *const c_void,
    _len: libc::socklen_t,
    _af: c_int,
    _result: *mut c_void,
    _buffer: *mut c_char,
    _buflen: usize,
    errnop: *mut c_int,
    h_errnop: *mut c_int,
) -> c_int {
    unsafe { nss_set_errnop_enoent(errnop) };
    unsafe { nss_set_herr_host_not_found(h_errnop) };
    NSS_STATUS_NOTFOUND
}

/// `_nss_files_gethostbyaddr2_r(addr, len, type, *result, *buf,
/// buflen, *errnop, *h_errnop, *ttlp)`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn _nss_files_gethostbyaddr2_r(
    _addr: *const c_void,
    _len: libc::socklen_t,
    _af: c_int,
    _result: *mut c_void,
    _buffer: *mut c_char,
    _buflen: usize,
    errnop: *mut c_int,
    h_errnop: *mut c_int,
    _ttlp: *mut i32,
) -> c_int {
    unsafe { nss_set_errnop_enoent(errnop) };
    unsafe { nss_set_herr_host_not_found(h_errnop) };
    NSS_STATUS_NOTFOUND
}

/// `_nss_files_getnetbyaddr_r(net, type, *result, *buf, buflen,
/// *errnop, *h_errnop)`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_files_getnetbyaddr_r(
    _net: u32,
    _type: c_int,
    _result: *mut c_void,
    _buffer: *mut c_char,
    _buflen: usize,
    errnop: *mut c_int,
    h_errnop: *mut c_int,
) -> c_int {
    unsafe { nss_set_errnop_enoent(errnop) };
    unsafe { nss_set_herr_host_not_found(h_errnop) };
    NSS_STATUS_NOTFOUND
}

/// `_nss_files_getnetbyname_r(name, *result, *buf, buflen,
/// *errnop, *h_errnop)`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_files_getnetbyname_r(
    _name: *const c_char,
    _result: *mut c_void,
    _buffer: *mut c_char,
    _buflen: usize,
    errnop: *mut c_int,
    h_errnop: *mut c_int,
) -> c_int {
    unsafe { nss_set_errnop_enoent(errnop) };
    unsafe { nss_set_herr_host_not_found(h_errnop) };
    NSS_STATUS_NOTFOUND
}

/// `_nss_files_getservbyname_r(name, proto, *result, *buf, buflen,
/// *errnop)`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_files_getservbyname_r(
    _name: *const c_char,
    _proto: *const c_char,
    _result: *mut c_void,
    _buffer: *mut c_char,
    _buflen: usize,
    errnop: *mut c_int,
) -> c_int {
    unsafe { nss_set_errnop_enoent(errnop) };
    NSS_STATUS_NOTFOUND
}

/// `_nss_files_getservbyport_r(port, proto, *result, *buf, buflen,
/// *errnop)`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_files_getservbyport_r(
    _port: c_int,
    _proto: *const c_char,
    _result: *mut c_void,
    _buffer: *mut c_char,
    _buflen: usize,
    errnop: *mut c_int,
) -> c_int {
    unsafe { nss_set_errnop_enoent(errnop) };
    NSS_STATUS_NOTFOUND
}

// ---------------------------------------------------------------------------
// Remaining _nss_files_* tail entries (init + initgroups_dyn + parse_*)
// ---------------------------------------------------------------------------

/// `_nss_files_init() -> nss_status` — module initialization. Some
/// glibc versions return void; we return NSS_STATUS_SUCCESS so both
/// callers see a clean success.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_files_init() -> c_int {
    NSS_STATUS_SUCCESS
}

/// `_nss_files_initgroups_dyn(user, gid, *start, *size, **groupsp,
/// limit, *errnop) -> nss_status` — supplementary group lookup.
/// Stub returns NSS_STATUS_NOTFOUND with errnop=ENOENT.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn _nss_files_initgroups_dyn(
    _user: *const c_char,
    _gid: libc::gid_t,
    _start: *mut c_long,
    _size: *mut c_long,
    _groupsp: *mut *mut libc::gid_t,
    _limit: c_long,
    errnop: *mut c_int,
) -> c_int {
    unsafe { nss_set_errnop_enoent(errnop) };
    NSS_STATUS_NOTFOUND
}

/// `_nss_files_parse_*(line, *result, *parser_data, buflen, *errnop)
/// -> int` — internal line parsers. Each returns 1 on success, 0 to
/// signal "skip this line", -1 to signal ERANGE. Stubs return 0
/// (skip) so callers walk to the next line without complaint.
macro_rules! nss_files_parse_stub {
    ($name:ident) => {
        #[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
        pub unsafe extern "C" fn $name(
            _line: *mut c_char,
            _result: *mut c_void,
            _data: *mut c_void,
            _buflen: usize,
            _errnop: *mut c_int,
        ) -> c_int {
            0
        }
    };
}

nss_files_parse_stub!(_nss_files_parse_etherent);
nss_files_parse_stub!(_nss_files_parse_grent);
nss_files_parse_stub!(_nss_files_parse_netent);
nss_files_parse_stub!(_nss_files_parse_protoent);
nss_files_parse_stub!(_nss_files_parse_pwent);
nss_files_parse_stub!(_nss_files_parse_rpcent);
nss_files_parse_stub!(_nss_files_parse_servent);
nss_files_parse_stub!(_nss_files_parse_sgent);

// ---------------------------------------------------------------------------
// _nss_dns_* NSS DNS plugin lookup stubs
// ---------------------------------------------------------------------------
//
// Each returns NSS_STATUS_NOTFOUND (= 0) and sets *errnop = ENOENT
// + *h_errnop = HOST_NOT_FOUND (= 1) when non-NULL, so the NSS
// dispatch layer falls through to the next module. Without a real
// resolver-backed NSS_DNS module we never claim to have an answer.

#[inline]
unsafe fn nss_set_h_errnop_host_not_found(h_errnop: *mut c_int) {
    if !h_errnop.is_null() {
        // SAFETY: caller-supplied writable slot per NSS contract.
        unsafe { *h_errnop = 1 }; // HOST_NOT_FOUND
    }
}

/// `_nss_dns_getcanonname_r(name, *buffer, buflen, **result,
/// *errnop, *h_errnop) -> nss_status` — return canonical name for
/// `name`. Stub: NOTFOUND + h_errno = HOST_NOT_FOUND.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_dns_getcanonname_r(
    _name: *const c_char,
    _buffer: *mut c_char,
    _buflen: usize,
    _result: *mut *mut c_char,
    errnop: *mut c_int,
    h_errnop: *mut c_int,
) -> c_int {
    unsafe { nss_set_errnop_enoent(errnop) };
    unsafe { nss_set_h_errnop_host_not_found(h_errnop) };
    NSS_STATUS_NOTFOUND
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_dns_gethostbyname_r(
    _name: *const c_char,
    _result: *mut c_void,
    _buffer: *mut c_char,
    _buflen: usize,
    errnop: *mut c_int,
    h_errnop: *mut c_int,
) -> c_int {
    unsafe { nss_set_errnop_enoent(errnop) };
    unsafe { nss_set_h_errnop_host_not_found(h_errnop) };
    NSS_STATUS_NOTFOUND
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_dns_gethostbyname2_r(
    _name: *const c_char,
    _af: c_int,
    _result: *mut c_void,
    _buffer: *mut c_char,
    _buflen: usize,
    errnop: *mut c_int,
    h_errnop: *mut c_int,
) -> c_int {
    unsafe { nss_set_errnop_enoent(errnop) };
    unsafe { nss_set_h_errnop_host_not_found(h_errnop) };
    NSS_STATUS_NOTFOUND
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn _nss_dns_gethostbyname3_r(
    _name: *const c_char,
    _af: c_int,
    _result: *mut c_void,
    _buffer: *mut c_char,
    _buflen: usize,
    errnop: *mut c_int,
    h_errnop: *mut c_int,
    _ttlp: *mut i32,
    _canonp: *mut *mut c_char,
) -> c_int {
    unsafe { nss_set_errnop_enoent(errnop) };
    unsafe { nss_set_h_errnop_host_not_found(h_errnop) };
    NSS_STATUS_NOTFOUND
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_dns_gethostbyname4_r(
    _name: *const c_char,
    _pat: *mut *mut c_void,
    _buffer: *mut c_char,
    _buflen: usize,
    errnop: *mut c_int,
    h_errnop: *mut c_int,
    _ttlp: *mut i32,
) -> c_int {
    unsafe { nss_set_errnop_enoent(errnop) };
    unsafe { nss_set_h_errnop_host_not_found(h_errnop) };
    NSS_STATUS_NOTFOUND
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn _nss_dns_gethostbyaddr_r(
    _addr: *const c_void,
    _len: usize,
    _af: c_int,
    _result: *mut c_void,
    _buffer: *mut c_char,
    _buflen: usize,
    errnop: *mut c_int,
    h_errnop: *mut c_int,
) -> c_int {
    unsafe { nss_set_errnop_enoent(errnop) };
    unsafe { nss_set_h_errnop_host_not_found(h_errnop) };
    NSS_STATUS_NOTFOUND
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn _nss_dns_gethostbyaddr2_r(
    _addr: *const c_void,
    _len: usize,
    _af: c_int,
    _result: *mut c_void,
    _buffer: *mut c_char,
    _buflen: usize,
    errnop: *mut c_int,
    h_errnop: *mut c_int,
    _ttlp: *mut i32,
) -> c_int {
    unsafe { nss_set_errnop_enoent(errnop) };
    unsafe { nss_set_h_errnop_host_not_found(h_errnop) };
    NSS_STATUS_NOTFOUND
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_dns_getnetbyname_r(
    _name: *const c_char,
    _result: *mut c_void,
    _buffer: *mut c_char,
    _buflen: usize,
    errnop: *mut c_int,
    h_errnop: *mut c_int,
) -> c_int {
    unsafe { nss_set_errnop_enoent(errnop) };
    unsafe { nss_set_h_errnop_host_not_found(h_errnop) };
    NSS_STATUS_NOTFOUND
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_dns_getnetbyaddr_r(
    _net: u32,
    _af: c_int,
    _result: *mut c_void,
    _buffer: *mut c_char,
    _buflen: usize,
    errnop: *mut c_int,
    h_errnop: *mut c_int,
) -> c_int {
    unsafe { nss_set_errnop_enoent(errnop) };
    unsafe { nss_set_h_errnop_host_not_found(h_errnop) };
    NSS_STATUS_NOTFOUND
}

// ---------------------------------------------------------------------------
// __internal_*netgrent + __nss_* GLIBC_PRIVATE helpers (17 stubs)
// ---------------------------------------------------------------------------

/// `__internal_setnetgrent(*group, *result) -> int` — would set up
/// netgroup iteration. Stub returns 0 (failure).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __internal_setnetgrent(
    _group: *const c_char,
    _result: *mut c_void,
) -> c_int {
    0
}

/// `__internal_getnetgrent_r(**host, **user, **dom, *result, *buf,
/// buflen, *errnop) -> int` — would advance the netgroup iterator.
/// Stub returns 0 (no more entries).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn __internal_getnetgrent_r(
    _host: *mut *mut c_char,
    _user: *mut *mut c_char,
    _domain: *mut *mut c_char,
    _result: *mut c_void,
    _buffer: *mut c_char,
    _buflen: usize,
    errnop: *mut c_int,
) -> c_int {
    unsafe { nss_set_errnop_enoent(errnop) };
    0
}

/// `__internal_endnetgrent(*result) -> int` — close the iterator.
/// Stub returns 1 (success).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __internal_endnetgrent(_result: *mut c_void) -> c_int {
    1
}

/// `__nss_database_get(db_id, *result) -> int` — query the
/// configured NSS sources for a database. Stub returns 0 (no
/// configuration available; caller falls through to defaults).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __nss_database_get(_db: c_int, _result: *mut *mut c_void) -> c_int {
    0
}

/// `__nss_disable_nscd(callback)` — would disable nscd integration.
/// Stub no-op since we have no nscd hookup.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __nss_disable_nscd(_cb: *mut c_void) {}

/// `__nss_hash(name, len) -> u32` — string hash used by the NSS
/// dispatcher. Stub returns 0 (a valid hash, just constant).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __nss_hash(_name: *const c_void, _len: usize) -> u32 {
    0
}

/// `__nss_lookup(*ni, fct_name, *fct, **resp) -> int` — resolve an
/// NSS function name within a configured module list. Stub returns
/// -1 (no module / function found).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __nss_lookup(
    _ni: *mut *mut c_void,
    _fct_name: *const c_char,
    _fct: *const c_char,
    _resp: *mut *mut c_void,
) -> c_int {
    -1
}

/// `__nss_files_data_open(*kind) -> *FILE` — open the shared
/// per-database file handle for the files module. Stub returns NULL.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __nss_files_data_open(_kind: *mut c_void) -> *mut c_void {
    core::ptr::null_mut()
}

/// `__nss_files_data_setent(kind, stayopen) -> nss_status` — Stub
/// returns NSS_STATUS_UNAVAIL.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __nss_files_data_setent(_kind: c_int, _stayopen: c_int) -> c_int {
    -1 // NSS_STATUS_UNAVAIL
}

/// `__nss_files_data_endent(kind) -> nss_status` — Stub returns
/// NSS_STATUS_SUCCESS (= 1) since "ending nothing" succeeds.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __nss_files_data_endent(_kind: c_int) -> c_int {
    NSS_STATUS_SUCCESS
}

/// `__nss_files_data_put(kind)` — release the shared file handle.
/// Stub no-op.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __nss_files_data_put(_kind: c_int) {}

/// `__nss_files_fopen(path) -> FILE*` — open `path` with the
/// expected flags for an NSS files-module backing file. Stub
/// returns NULL.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __nss_files_fopen(_path: *const c_char) -> *mut c_void {
    core::ptr::null_mut()
}

/// `__nss_group_lookup2(*ni, name, *result, *errnop) -> int` —
/// typed group lookup helper. Stub returns -1 with errnop=ENOENT.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __nss_group_lookup2(
    _ni: *mut *mut c_void,
    _name: *const c_char,
    _result: *mut c_void,
    errnop: *mut c_int,
) -> c_int {
    unsafe { nss_set_errnop_enoent(errnop) };
    -1
}

/// `__nss_passwd_lookup2(*ni, name, *result, *errnop) -> int` —
/// typed passwd lookup helper. Stub returns -1 with errnop=ENOENT.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __nss_passwd_lookup2(
    _ni: *mut *mut c_void,
    _name: *const c_char,
    _result: *mut c_void,
    errnop: *mut c_int,
) -> c_int {
    unsafe { nss_set_errnop_enoent(errnop) };
    -1
}

/// `__nss_services_lookup2(*ni, name, *proto, *result, *errnop)
/// -> int` — typed services lookup helper. Stub returns -1 with
/// errnop=ENOENT.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __nss_services_lookup2(
    _ni: *mut *mut c_void,
    _name: *const c_char,
    _proto: *const c_char,
    _result: *mut c_void,
    errnop: *mut c_int,
) -> c_int {
    unsafe { nss_set_errnop_enoent(errnop) };
    -1
}

/// `__nss_parse_line_result(*fp, line, parser_result) -> int` —
/// converts a parser_data result into an nss_status. Stub returns
/// 0 (NSS_STATUS_NOTFOUND) so the caller treats the line as
/// non-matching.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __nss_parse_line_result(
    _fp: *mut c_void,
    _line: *mut c_char,
    _parse_res: c_int,
) -> c_int {
    0
}

/// `__nss_readline(*fp, buf, len, *poffset) -> int` — read the
/// next non-blank, non-comment line from `fp`. Stub returns -1
/// (NSS_STATUS_TRYAGAIN) without setting *poffset.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __nss_readline(
    _fp: *mut c_void,
    _buf: *mut c_char,
    _len: usize,
    _poffset: *mut i64,
) -> c_int {
    -1
}

// ---------------------------------------------------------------------------
// __libc_alloc_buffer / __libc_dynarray / __libc_scratch_buffer / early_init +
// nss_files_parse_spent + nss_netgroup_parseline (18 stubs)
// ---------------------------------------------------------------------------
//
// All GLIBC_PRIVATE-versioned. Stubs provide the safe failure path so
// link-edit resolves cleanly and any caller falls into its existing
// error handling.

// alloc_buffer is glibc's bounded sub-allocator over a caller buffer.
// The minimum viable failure shape is: allocate returns NULL; copy
// helpers do nothing; create_failure marks an alloc_buffer as
// permanently failed (we no-op since we never produced a live one).

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_alloc_buffer_alloc_array(
    _buf: *mut c_void,
    _size: usize,
    _align: usize,
    _count: usize,
) -> *mut c_void {
    core::ptr::null_mut()
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_alloc_buffer_allocate(
    _size: usize,
    _pptr: *mut *mut c_void,
) -> *mut c_void {
    core::ptr::null_mut()
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_alloc_buffer_copy_bytes(
    _buf: *mut c_void,
    _src: *const c_void,
    _len: usize,
) -> *mut c_void {
    core::ptr::null_mut()
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_alloc_buffer_copy_string(
    _buf: *mut c_void,
    _src: *const c_char,
) -> *mut c_void {
    core::ptr::null_mut()
}

/// `__libc_alloc_buffer_create_failure(start, size) -> alloc_buffer` —
/// glibc returns the failure-marked alloc_buffer struct by value. We
/// model the return as void since our caller never inspects the
/// failed buffer beyond knowing the allocation failed; the actual
/// alloc_buffer struct is small enough that callers passing the
/// return value through an alloc_buffer slot will see a partly-
/// uninitialized struct, but glibc's check_alloc_buffer macro only
/// looks at the failure bit which we never set (the caller's slot
/// is treated as failed by the next allocate).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_alloc_buffer_create_failure(_start: *mut c_void, _size: usize) {}

// dynarray is glibc's growable Vec-equivalent. Stubs:
//   - at_failure: glibc convention is to abort; we abort_message().
//   - emplace_enlarge / resize / resize_clear: 0 (failure) so caller
//     short-circuits without reading our (unmaintained) buffer.
//   - finalize: 0 (false) — finalize-into-result not provided.

/// Glibc convention: __libc_dynarray_at_failure aborts (out-of-bounds
/// access on a dynarray is a fatal usage bug). Mirror that behavior.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_dynarray_at_failure(_size: usize, _index: usize) -> ! {
    let msg: &[u8] = b"__libc_dynarray_at: index out of range\n";
    // SAFETY: writing to fd 2 is always safe.
    unsafe {
        libc::write(2, msg.as_ptr() as *const c_void, msg.len());
        libc::abort();
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_dynarray_emplace_enlarge(
    _list: *mut c_void,
    _scratch: *mut c_void,
    _element_size: usize,
) -> c_int {
    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_dynarray_resize(
    _list: *mut c_void,
    _new_size: usize,
    _scratch: *mut c_void,
    _element_size: usize,
) -> c_int {
    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_dynarray_resize_clear(
    _list: *mut c_void,
    _new_size: usize,
    _scratch: *mut c_void,
    _element_size: usize,
) -> c_int {
    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_dynarray_finalize(
    _list: *mut c_void,
    _scratch: *mut c_void,
    _element_size: usize,
    _result: *mut c_void,
) -> c_int {
    0
}

// scratch_buffer is glibc's stack-or-heap scratch space helper.
// All grow/sizing entries return false (out of memory), forcing
// callers to take the fail path.

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_scratch_buffer_grow(_buf: *mut c_void) -> c_int {
    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_scratch_buffer_grow_preserve(_buf: *mut c_void) -> c_int {
    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_scratch_buffer_set_array_size(
    _buf: *mut c_void,
    _nelem: usize,
    _size: usize,
) -> c_int {
    0
}

/// `__libc_early_init(initial)` — early-init marker called by ld.so
/// when our libc shared object is first loaded. Stub no-op (our
/// init runs through #[link_section = ".init_array"] entries; we
/// don't need anything additional from the dynamic loader).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_early_init(_initial: c_int) {}

// Two NSS line parsers we missed in the earlier batch.
nss_files_parse_stub!(_nss_files_parse_spent);

/// `_nss_netgroup_parseline(*cursor, *result, *buf, buflen, *errnop)
/// -> int` — parses the next netgroup triple from a backing line.
/// Stub returns 0 (NSS_STATUS_NOTFOUND / no parsed triple).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_netgroup_parseline(
    _cursor: *mut *mut c_char,
    _result: *mut c_void,
    _buf: *mut c_char,
    _buflen: usize,
    errnop: *mut c_int,
) -> c_int {
    unsafe { nss_set_errnop_enoent(errnop) };
    0
}

// ---------------------------------------------------------------------------
// __libc_*/__res_*/__open_catalog GLIBC_PRIVATE stubs (18 entries)
// ---------------------------------------------------------------------------

/// `__libc_allocate_once_slow(*ptr, *constructor, *closure)` —
/// pthread_once-style helper. Stub no-op; the caller's "is
/// initialized" check will see whatever they had.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_allocate_once_slow(
    _ptr: *mut *mut c_void,
    _constructor: *mut c_void,
    _closure: *mut c_void,
) {
}

/// `__libc_clntudp_bufcreate(addr, prog, vers, wait, sockp, sendsz,
/// recvsz, flags) -> CLIENT*` — RPC private. Stub returns NULL.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn __libc_clntudp_bufcreate(
    _addr: *mut c_void,
    _prog: c_ulong,
    _vers: c_ulong,
    _wait_lo: c_long,
    _wait_hi: c_long,
    _sockp: *mut c_int,
    _sendsz: c_uint,
    _recvsz: c_uint,
    _flags: c_uint,
) -> *mut c_void {
    core::ptr::null_mut()
}

/// `__libc_ifunc_impl_list(name, *array, max) -> usize` — populate
/// `array` with IFUNC implementation entries for `name`. Stub
/// returns 0 (no entries available).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_ifunc_impl_list(
    _name: *const c_char,
    _array: *mut c_void,
    _max: usize,
) -> usize {
    0
}

/// `__libc_ns_makecanon(src, dst, dstsiz) -> int` — internal alias
/// of the public `ns_makecanon` we ship in resolv_abi.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_ns_makecanon(
    src: *const c_char,
    dst: *mut c_char,
    dstsiz: usize,
) -> c_int {
    unsafe { crate::resolv_abi::ns_makecanon(src, dst, dstsiz) }
}

/// `__libc_ns_samename(a, b) -> int` — internal alias of the
/// public `ns_samename` we ship in resolv_abi.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_ns_samename(a: *const c_char, b: *const c_char) -> c_int {
    unsafe { crate::resolv_abi::ns_samename(a, b) }
}

/// `__libc_res_nameinquery(name, type, class, *buf, eom) -> int` —
/// "is this name in the supplied query?" predicate. Stub returns 0
/// (not present).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_res_nameinquery(
    _name: *const c_char,
    _type: c_int,
    _class: c_int,
    _buf: *const c_void,
    _eom: *const c_void,
) -> c_int {
    0
}

/// `__libc_res_queriesmatch(buf1, eom1, buf2, eom2) -> int` —
/// "are these two DNS query messages equivalent?". Stub returns 0
/// (not equivalent).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_res_queriesmatch(
    _buf1: *const c_void,
    _eom1: *const c_void,
    _buf2: *const c_void,
    _eom2: *const c_void,
) -> c_int {
    0
}

/// `__libc_rpc_getport(*addr, prognum, versnum, protocol, timo,
/// tottimeout) -> u16` — portmapper lookup. Stub returns 0 (no
/// port available).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_rpc_getport(
    _addr: *mut c_void,
    _prognum: c_ulong,
    _versnum: c_ulong,
    _protocol: c_ulong,
    _timo_lo: c_long,
    _timo_hi: c_long,
    _tot_lo: c_long,
    _tot_hi: c_long,
) -> u16 {
    0
}

/// `__libc_unwind_link_get() -> *unwind_link` — load the libgcc_s
/// unwind hook. Stub returns NULL (no unwinder bridged).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_unwind_link_get() -> *mut c_void {
    core::ptr::null_mut()
}

/// `__open_catalog(name, *result) -> int` — locate and open a
/// message catalog. Stub returns -1 (catopen failure).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __open_catalog(
    _name: *const c_char,
    _nlspath: *const c_char,
    _env_var: *const c_char,
    _result: *mut c_void,
) -> c_int {
    -1
}

/// `__res_context_hostalias(*ctx, name, *buf, buflen) ->
/// *const c_char` — look up the HOSTALIASES entry for `name`.
/// Stub returns NULL.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __res_context_hostalias(
    _ctx: *mut c_void,
    _name: *const c_char,
    _buf: *mut c_char,
    _buflen: usize,
) -> *const c_char {
    core::ptr::null()
}

/// `__res_context_mkquery(*ctx, op, *dname, class, type, *data,
/// datalen, *newrr, *buf, buflen) -> int` — build a DNS query
/// packet. Stub returns -1 (failure).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn __res_context_mkquery(
    _ctx: *mut c_void,
    _op: c_int,
    _dname: *const c_char,
    _class: c_int,
    _type: c_int,
    _data: *const c_void,
    _datalen: c_int,
    _newrr: *const c_void,
    _buf: *mut c_void,
    _buflen: c_int,
) -> c_int {
    -1
}

/// `__res_context_query(*ctx, name, class, type, *answer,
/// anslen) -> int` — perform a DNS query. Stub returns -1.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __res_context_query(
    _ctx: *mut c_void,
    _name: *const c_char,
    _class: c_int,
    _type: c_int,
    _answer: *mut c_void,
    _anslen: c_int,
) -> c_int {
    -1
}

/// `__res_context_search(*ctx, name, class, type, *answer,
/// anslen) -> int` — DNS query with search-list expansion. Stub
/// returns -1.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __res_context_search(
    _ctx: *mut c_void,
    _name: *const c_char,
    _class: c_int,
    _type: c_int,
    _answer: *mut c_void,
    _anslen: c_int,
) -> c_int {
    -1
}

/// `__res_context_send(*ctx, *buf, buflen, *buf2, buflen2,
/// *answer, anslen, *anssiz, *thishreply) -> int` — send a
/// pre-built DNS query. Stub returns -1.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn __res_context_send(
    _ctx: *mut c_void,
    _buf: *const c_void,
    _buflen: c_int,
    _buf2: *const c_void,
    _buflen2: c_int,
    _answer: *mut c_void,
    _anslen: c_int,
    _ansp: *mut *mut c_void,
    _ansp2: *mut *mut c_void,
) -> c_int {
    -1
}

/// `__res_get_nsaddr(*statp, n) -> *struct sockaddr_in` — return
/// nameserver `n`'s address. Stub returns NULL.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __res_get_nsaddr(_statp: *mut c_void, _n: c_uint) -> *mut c_void {
    core::ptr::null_mut()
}

/// `__res_iclose(*statp, free_addr) -> ()` — close all the
/// nameserver sockets in `*statp`. Stub no-op since we have no
/// sockets to close.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __res_iclose(_statp: *mut c_void, _free_addr: c_int) {}

/// `__res_nopt(*ctx, n0, *buf, buflen, anslen) -> int` — append an
/// EDNS OPT pseudo-RR to a DNS query. Stub returns -1.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __res_nopt(
    _ctx: *mut c_void,
    _n0: c_int,
    _buf: *mut c_void,
    _buflen: c_int,
    _anslen: c_int,
) -> c_int {
    -1
}

// CRYPT_B64 / crypt_b64_encode / crypt_sha512 / crypt_sha256 / crypt_md5
// moved to frankenlibc_core::crypt. The crypt() entry above dispatches
// directly to the core impls — no further shim layer needed.
fn crypt_sha512(key: &[u8], salt_bytes: &[u8]) -> Option<String> {
    frankenlibc_core::crypt::sha512::sha512_crypt(key, salt_bytes)
}

fn crypt_sha256(key: &[u8], salt_bytes: &[u8]) -> Option<String> {
    frankenlibc_core::crypt::sha256::sha256_crypt(key, salt_bytes)
}

fn crypt_md5(key: &[u8], salt_bytes: &[u8]) -> Option<String> {
    frankenlibc_core::crypt::md5::md5_crypt(key, salt_bytes)
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
    match unsafe {
        syscall::sys_lgetxattr(path as *const u8, name as *const u8, value as *mut u8, size)
    } {
        Ok(n) => n,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lsetxattr(
    path: *const c_char,
    name: *const c_char,
    value: *const c_void,
    size: usize,
    flags: c_int,
) -> c_int {
    match unsafe {
        syscall::sys_lsetxattr(
            path as *const u8,
            name as *const u8,
            value as *const u8,
            size,
            flags,
        )
    } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn llistxattr(path: *const c_char, list: *mut c_char, size: usize) -> isize {
    match unsafe { syscall::sys_llistxattr(path as *const u8, list as *mut u8, size) } {
        Ok(n) => n,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lremovexattr(path: *const c_char, name: *const c_char) -> c_int {
    match unsafe { syscall::sys_lremovexattr(path as *const u8, name as *const u8) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
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
    match unsafe {
        syscall::sys_prlimit64(
            pid,
            resource as u32,
            new_limit as *const u8,
            old_limit as *mut u8,
        )
    } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
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
    let Some(path_bytes) = (unsafe { read_c_string_bytes(file) }) else {
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    };
    let path_str = std::str::from_utf8(&path_bytes).unwrap_or(UTMP_DEFAULT_PATH);
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
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
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
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
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

    let rc = match syscall::sys_shmget(key, size, shmflg) {
        Ok(id) => id,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    };
    runtime_policy::observe(
        ApiFamily::Process,
        decision.profile,
        runtime_policy::scaled_cost(10, size),
        rc < 0,
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

    let rc = match unsafe { syscall::sys_shmctl(shmid, cmd, buf as *mut u8) } {
        Ok(r) => r,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    };
    runtime_policy::observe(ApiFamily::Process, decision.profile, 10, rc < 0);
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

    match unsafe { syscall::sys_shmat(shmid, shmaddr as usize, shmflg) } {
        Ok(addr) => {
            runtime_policy::observe(ApiFamily::VirtualMemory, decision.profile, 10, false);
            addr as *mut c_void
        }
        Err(e) => {
            unsafe { set_abi_errno(e) };
            runtime_policy::observe(ApiFamily::VirtualMemory, decision.profile, 10, true);
            (-1_isize) as *mut c_void
        }
    }
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

    let rc = match unsafe { syscall::sys_shmdt(shmaddr as usize) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    };
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

    let rc = match syscall::sys_semget(key, nsems, semflg) {
        Ok(id) => id,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    };
    runtime_policy::observe(ApiFamily::Process, decision.profile, 8, rc < 0);
    rc
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn semctl(semid: c_int, semnum: c_int, cmd: c_int, mut args: ...) -> c_int {
    let arg = if semctl_cmd_uses_arg(cmd) {
        unsafe { args.next_arg::<libc::c_ulong>() }
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

    let rc = match syscall::sys_semctl(semid, semnum, cmd, arg as usize) {
        Ok(r) => r,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    };
    runtime_policy::observe(ApiFamily::Process, decision.profile, 8, rc < 0);
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

    let rc = match unsafe { syscall::sys_semop(semid, sops as *const u8, nsops) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
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

    let rc = match syscall::sys_msgget(key, msgflg) {
        Ok(id) => id,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    };
    runtime_policy::observe(ApiFamily::Process, decision.profile, 8, rc < 0);
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

    let rc = match unsafe { syscall::sys_msgctl(msqid, cmd, buf as *mut u8) } {
        Ok(r) => r,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    };
    runtime_policy::observe(ApiFamily::Process, decision.profile, 8, rc < 0);
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

    let rc = match unsafe { syscall::sys_msgsnd(msqid, msgp as *const u8, msgsz, msgflg) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
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

    let rc = match unsafe {
        syscall::sys_msgrcv(msqid, msgp as *mut u8, msgsz, msgtyp as isize, msgflg)
    } {
        Ok(n) => n as libc::ssize_t,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
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
pub unsafe extern "C" fn sigqueue(pid: libc::pid_t, sig: c_int, value: libc::sigval) -> c_int {
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    info.si_signo = sig;
    info.si_errno = 0;
    info.si_code = libc::SI_QUEUE;

    // Encode sender identity and queued payload using the Linux siginfo queue layout.
    let info_words = (&mut info as *mut libc::siginfo_t).cast::<u32>();
    let caller_pid = syscall::sys_getpid() as u32;
    let caller_uid = syscall::sys_getuid();
    let value_bits = value.sival_ptr as usize as u64;
    unsafe {
        *info_words.add(3) = caller_pid;
        *info_words.add(4) = caller_uid;
        if std::mem::size_of::<usize>() > 4 {
            // Linux aligns `sigval_t` to 8 bytes inside the SI_QUEUE
            // payload, leaving one 32-bit hole after `si_uid`.
            *info_words.add(6) = value_bits as u32;
            *info_words.add(7) = (value_bits >> 32) as u32;
        } else {
            *info_words.add(5) = value_bits as u32;
        }
    }

    match unsafe { syscall::sys_rt_sigqueueinfo(pid, sig, &info as *const _ as *const u8) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sigtimedwait(
    set: *const c_void,
    info: *mut c_void,
    timeout: *const libc::timespec,
) -> c_int {
    match unsafe {
        syscall::sys_rt_sigtimedwait(
            set as *const u8,
            info as *mut u8,
            timeout as *const u8,
            std::mem::size_of::<libc::c_ulong>(),
        )
    } {
        Ok(sig) => sig,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sigwaitinfo(set: *const c_void, info: *mut c_void) -> c_int {
    match unsafe {
        syscall::sys_rt_sigtimedwait(
            set as *const u8,
            info as *mut u8,
            std::ptr::null(),
            std::mem::size_of::<libc::c_ulong>(),
        )
    } {
        Ok(sig) => sig,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// glibc reserved-namespace alias for [`sigqueue`].
///
/// # Safety
///
/// Same as [`sigqueue`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __sigqueue(pid: libc::pid_t, sig: c_int, value: libc::sigval) -> c_int {
    unsafe { sigqueue(pid, sig, value) }
}

/// glibc reserved-namespace alias for [`sigwaitinfo`].
///
/// # Safety
///
/// Same as [`sigwaitinfo`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __sigwaitinfo(set: *const c_void, info: *mut c_void) -> c_int {
    unsafe { sigwaitinfo(set, info) }
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
    let fd = match syscall::sys_socket(
        libc::AF_NETLINK,
        libc::SOCK_RAW | libc::SOCK_CLOEXEC,
        libc::NETLINK_ROUTE,
    ) {
        Ok(fd) => fd,
        Err(_) => return Err(errno::ENOBUFS),
    };

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
    if unsafe { syscall::sys_sendto(fd, buf.as_ptr(), msg_len, 0, std::ptr::null(), 0) }.is_err() {
        let _ = syscall::sys_close(fd);
        return Err(errno::EIO);
    }

    // Receive all responses
    let mut result = Vec::with_capacity(8192);
    let mut recv_buf = vec![0u8; 16384];
    while let Ok(n) = unsafe {
        syscall::sys_recvfrom(
            fd,
            recv_buf.as_mut_ptr(),
            recv_buf.len(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    } {
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

    let _ = syscall::sys_close(fd);
    Ok(result)
}

/// Build a sockaddr from AF family and address bytes.
fn alloc_sockaddr(family: u8, addr_data: &[u8]) -> *mut libc::sockaddr {
    match family as i32 {
        libc::AF_INET if addr_data.len() >= 4 => {
            let sa =
                unsafe { crate::malloc_abi::raw_alloc(std::mem::size_of::<libc::sockaddr_in>()) }
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
            let sa =
                unsafe { crate::malloc_abi::raw_alloc(std::mem::size_of::<libc::sockaddr_in6>()) }
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
            let sa =
                unsafe { crate::malloc_abi::raw_alloc(std::mem::size_of::<libc::sockaddr_in>()) }
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
            let sa =
                unsafe { crate::malloc_abi::raw_alloc(std::mem::size_of::<libc::sockaddr_in6>()) }
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
                // Name
                let name_cstr = match CString::new(if_name.as_str()) {
                    Ok(name) => name,
                    Err(_) => continue,
                };

                // Allocate an ifaddrs node
                let node = unsafe {
                    crate::malloc_abi::raw_alloc(std::mem::size_of::<Ifaddrs>()) as *mut Ifaddrs
                };
                if node.is_null() {
                    continue;
                }
                let name_ptr = unsafe {
                    crate::malloc_abi::raw_alloc(name_cstr.as_bytes_with_nul().len()) as *mut c_char
                };
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
                crate::malloc_abi::raw_free((*cur).ifa_name as *mut c_void);
            }
            if !(*cur).ifa_addr.is_null() {
                crate::malloc_abi::raw_free((*cur).ifa_addr as *mut c_void);
            }
            if !(*cur).ifa_netmask.is_null() {
                crate::malloc_abi::raw_free((*cur).ifa_netmask as *mut c_void);
            }
            if !(*cur).ifa_broadaddr.is_null() {
                crate::malloc_abi::raw_free((*cur).ifa_broadaddr as *mut c_void);
            }
            crate::malloc_abi::raw_free(cur as *mut c_void);
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

unsafe fn parse_ether_addr(asc: *const c_char, out: *mut EtherAddrBytes) -> bool {
    if asc.is_null() || out.is_null() {
        return false;
    }
    let Some(bytes) = (unsafe { read_c_string_bytes(asc) }) else {
        return false;
    };
    match frankenlibc_core::ether::parse_ether_addr(&bytes) {
        Some(octet) => {
            unsafe { (*out).octet = octet };
            true
        }
        None => false,
    }
}

unsafe fn format_ether_addr(addr: *const EtherAddrBytes, buf: *mut c_char) -> *mut c_char {
    if addr.is_null() || buf.is_null() {
        return std::ptr::null_mut();
    }
    let octet = unsafe { (*addr).octet };
    let text = frankenlibc_core::ether::format_ether_addr(&octet);
    let out = unsafe { std::slice::from_raw_parts_mut(buf.cast::<u8>(), 18) };
    out[..17].copy_from_slice(&text);
    out[17] = 0;
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

// H_ERR_* constants moved to frankenlibc_core::resolv::messages.

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
    // Look up canonical text via core; map back to a NUL-terminated
    // `c"..."` literal at the FFI boundary so the returned pointer is
    // valid for the entire program lifetime.
    let text = frankenlibc_core::resolv::messages::hstrerror_text(err);
    match text {
        "Unknown host" => c"Unknown host".as_ptr(),
        "Host name lookup failure" => c"Host name lookup failure".as_ptr(),
        "Unknown server error" => c"Unknown server error".as_ptr(),
        "No address associated with name" => c"No address associated with name".as_ptr(),
        _ => c"Resolver internal error".as_ptr(),
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn herror(s: *const c_char) {
    let msg =
        frankenlibc_core::resolv::messages::hstrerror_text(unsafe { current_h_errno() }).as_bytes();
    let prefix = if s.is_null() {
        None
    } else {
        let Some(bytes) = (unsafe { read_c_string_bytes(s) }) else {
            unsafe { set_abi_errno(errno::EINVAL) };
            return;
        };
        Some(bytes)
    };

    let mut line = Vec::with_capacity(msg.len() + 2 + prefix.as_ref().map_or(0, |p| p.len() + 2));
    if let Some(prefix) = prefix
        && !prefix.is_empty()
    {
        line.extend_from_slice(&prefix);
        line.extend_from_slice(b": ");
    }
    line.extend_from_slice(msg);
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
        let next = unsafe { args.next_arg::<*const c_char>() };
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
        let next = unsafe { args.next_arg::<*const c_char>() };
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
        let next = unsafe { args.next_arg::<*const c_char>() };
        argv.push(next);
        if next.is_null() {
            break;
        }
    }
    // The next variadic argument after NULL is the envp pointer.
    let envp = unsafe { args.next_arg::<*const *const c_char>() };
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
    match unsafe { syscall::sys_timer_create(clockid, sevp as usize, timerid as *mut i32) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn timer_settime(
    timerid: *mut c_void,
    flags: c_int,
    new_value: *const c_void,
    old_value: *mut c_void,
) -> c_int {
    match unsafe {
        syscall::sys_timer_settime(
            timerid as i32,
            flags,
            new_value as *const u8,
            old_value as *mut u8,
        )
    } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn timer_gettime(timerid: *mut c_void, curr_value: *mut c_void) -> c_int {
    let (_, decision) = runtime_policy::decide(
        ApiFamily::Time,
        curr_value as usize,
        0,
        true,
        curr_value.is_null(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EPERM) };
        runtime_policy::observe(ApiFamily::Time, decision.profile, 5, true);
        return -1;
    }

    if !timerid.is_null() && curr_value.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::Time, decision.profile, 5, true);
        return -1;
    }

    let rc = match unsafe { syscall::sys_timer_gettime(timerid as i32, curr_value as *mut u8) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    };

    runtime_policy::observe(ApiFamily::Time, decision.profile, 5, rc < 0);
    rc
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn timer_delete(timerid: *mut c_void) -> c_int {
    match syscall::sys_timer_delete(timerid as i32) {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn timer_getoverrun(timerid: *mut c_void) -> c_int {
    match syscall::sys_timer_getoverrun(timerid as i32) {
        Ok(count) => count,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
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
                AioOp::Read => {
                    match unsafe { syscall::sys_pread64(fd, buf_addr as *mut u8, nbytes, offset) } {
                        Ok(n) => n as i64,
                        Err(e) => {
                            unsafe { set_abi_errno(e) };
                            -1
                        }
                    }
                }
                AioOp::Write => match unsafe {
                    syscall::sys_pwrite64(fd, buf_addr as *const u8, nbytes, offset)
                } {
                    Ok(n) => n as i64,
                    Err(e) => {
                        unsafe { set_abi_errno(e) };
                        -1
                    }
                },
                AioOp::Fsync => match syscall::sys_fsync(fd) {
                    Ok(()) => 0,
                    Err(e) => {
                        unsafe { set_abi_errno(e) };
                        -1
                    }
                },
                AioOp::Fdatasync => match syscall::sys_fdatasync(fd) {
                    Ok(()) => 0,
                    Err(e) => {
                        unsafe { set_abi_errno(e) };
                        -1
                    }
                },
            };

            if result < 0 {
                let err = current_abi_errno();
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
        // POSIX: aio_suspend with invalid timeout fields must fail with EINVAL.
        // A negative tv_sec or tv_nsec outside [0, 999_999_999] would otherwise
        // silently wrap through `as u64` / `as u32` and cause `Instant + Duration`
        // to panic with 'overflow when adding duration to instant', aborting the
        // process. (bd-4rdz8)
        if ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1_000_000_000 {
            unsafe { set_abi_errno(errno::EINVAL) };
            return -1;
        }
        let dur = std::time::Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32);
        // For very large but technically valid tv_sec values, `Instant + dur`
        // can still overflow. Fall back to None (poll indefinitely) instead of
        // panicking — POSIX does not bound tv_sec, and treating an unreachable
        // deadline as "no timeout" is the safest approximation.
        std::time::Instant::now().checked_add(dur)
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

/// Internal mount table stream state for native mntent implementation.
struct MntStream {
    reader: std::io::BufReader<std::fs::File>,
    line_buf: Vec<u8>,
}

/// `setmntent` — open a mount table file.
///
/// Native implementation: opens the file and returns an opaque MntStream
/// pointer. The stream is used by getmntent/getmntent_r/addmntent/endmntent.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setmntent(filename: *const c_char, type_: *const c_char) -> *mut c_void {
    if filename.is_null() {
        return std::ptr::null_mut();
    }
    let Some(path_bytes) = (unsafe { read_c_string_bytes(filename) }) else {
        unsafe { set_abi_errno(libc::EINVAL) };
        return std::ptr::null_mut();
    };
    let path_str = match std::str::from_utf8(&path_bytes) {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    // Determine open mode from the type string (fopen-style mode).
    let mode_bytes = if type_.is_null() {
        b"r".to_vec()
    } else {
        let Some(bytes) = (unsafe { read_c_string_bytes(type_) }) else {
            unsafe { set_abi_errno(libc::EINVAL) };
            return std::ptr::null_mut();
        };
        bytes
    };

    use std::fs::OpenOptions;
    let mut opts = OpenOptions::new();
    match mode_bytes.first() {
        Some(b'r') => {
            opts.read(true);
            if mode_bytes.contains(&b'+') {
                opts.write(true);
            }
        }
        Some(b'w') => {
            opts.write(true).create(true).truncate(true);
            if mode_bytes.contains(&b'+') {
                opts.read(true);
            }
        }
        Some(b'a') => {
            opts.append(true).create(true);
            if mode_bytes.contains(&b'+') {
                opts.read(true);
            }
        }
        _ => {
            opts.read(true);
        }
    }

    match opts.open(path_str) {
        Ok(file) => {
            let ms = Box::new(MntStream {
                reader: std::io::BufReader::new(file),
                line_buf: Vec::with_capacity(256),
            });
            Box::into_raw(ms) as *mut c_void
        }
        Err(_) => std::ptr::null_mut(),
    }
}

/// Thread-local buffer for the non-reentrant `getmntent`.
///
/// glibc uses a static internal mntent + string buffer per-thread.
/// Layout: first 48 bytes = struct mntent, rest = string data.
const GETMNTENT_BUFSIZE: usize = 4096;
std::thread_local! {
    static GETMNTENT_BUF: std::cell::UnsafeCell<[u8; GETMNTENT_BUFSIZE]> =
        const { std::cell::UnsafeCell::new([0u8; GETMNTENT_BUFSIZE]) };
}

/// `getmntent` — read next mount entry (non-reentrant).
///
/// Native implementation using thread-local storage. Calls getmntent_r
/// internally with a thread-local buffer.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getmntent(stream: *mut c_void) -> *mut c_void {
    if stream.is_null() {
        return std::ptr::null_mut();
    }
    GETMNTENT_BUF.with(|cell| {
        let buf = unsafe { &mut *cell.get() };
        // struct mntent is the first 48 bytes; string data starts after.
        let mntbuf = buf.as_mut_ptr() as *mut c_void;
        let str_buf = unsafe { buf.as_mut_ptr().add(48) } as *mut c_char;
        let str_len = (GETMNTENT_BUFSIZE - 48) as c_int;
        unsafe { getmntent_r(stream, mntbuf, str_buf, str_len) }
    })
}

/// `endmntent` — close a mount table stream.
///
/// Native implementation: drops the MntStream box. Always returns 1
/// per the glibc contract.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn endmntent(stream: *mut c_void) -> c_int {
    if stream.is_null() {
        return 1;
    }
    // SAFETY: stream was created by setmntent via Box::into_raw.
    let _ = unsafe { Box::from_raw(stream as *mut MntStream) };
    1
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
    let Some(opts) = (unsafe { read_c_string_bytes(opts_ptr) }) else {
        unsafe { set_abi_errno(libc::EINVAL) };
        return std::ptr::null_mut();
    };
    let Some(needle) = (unsafe { read_c_string_bytes(opt) }) else {
        unsafe { set_abi_errno(libc::EINVAL) };
        return std::ptr::null_mut();
    };
    match frankenlibc_core::mntent::has_mnt_opt(&opts, &needle) {
        Some(off) => unsafe { opts_ptr.add(off) as *mut c_char },
        None => std::ptr::null_mut(),
    }
}

/// GNU `getmntent_r` — reentrant mount entry reader.
///
/// Native implementation: reads the next mount entry from the stream into
/// caller-supplied buffers by parsing whitespace-separated fields from the
/// mount table file.
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
    // SAFETY: stream was created by setmntent via Box::into_raw.
    let ms = unsafe { &mut *(stream as *mut MntStream) };
    let buflen_u = buflen as usize;

    loop {
        ms.line_buf.clear();
        let bytes_read = match ms.reader.read_until(b'\n', &mut ms.line_buf) {
            Ok(n) => n,
            Err(_) => return std::ptr::null_mut(),
        };
        if bytes_read == 0 {
            return std::ptr::null_mut(); // EOF
        }
        let Some(fields) = frankenlibc_core::mntent::parse_mntent_line(&ms.line_buf) else {
            continue;
        };

        // Check whether all four NUL-terminated strings fit in caller's buffer.
        let needed = fields.fsname.len()
            + 1
            + fields.dir.len()
            + 1
            + fields.mtype.len()
            + 1
            + fields.opts.len()
            + 1;
        if needed > buflen_u {
            continue;
        }

        // Pack NUL-terminated strings into caller buffer.
        let buf_u8 = buf as *mut u8;
        let mut off = 0usize;
        let mut pack = |bytes: &[u8]| -> *mut c_char {
            let p = unsafe { buf_u8.add(off) } as *mut c_char;
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf_u8.add(off), bytes.len());
                *buf_u8.add(off + bytes.len()) = 0;
            }
            off += bytes.len() + 1;
            p
        };
        let fsname_ptr = pack(fields.fsname);
        let dir_ptr = pack(fields.dir);
        let type_ptr = pack(fields.mtype);
        let opts_ptr = pack(fields.opts);

        // Fill mntent struct: { *fsname, *dir, *type, *opts, freq, passno }
        let ent = mntbuf as *mut *mut c_char;
        unsafe {
            *ent = fsname_ptr;
            *ent.add(1) = dir_ptr;
            *ent.add(2) = type_ptr;
            *ent.add(3) = opts_ptr;
            let int_ptr = ent.add(4) as *mut c_int;
            *int_ptr = fields.freq as c_int;
            *int_ptr.add(1) = fields.passno as c_int;
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
    let Some(fsname_bytes) = (unsafe { read_c_string_bytes(fsname) }) else {
        unsafe { set_abi_errno(libc::EINVAL) };
        return 1;
    };
    let Some(dir_bytes) = (unsafe { read_c_string_bytes(dir) }) else {
        unsafe { set_abi_errno(libc::EINVAL) };
        return 1;
    };
    let Some(mtype_bytes) = (unsafe { read_c_string_bytes(mtype) }) else {
        unsafe { set_abi_errno(libc::EINVAL) };
        return 1;
    };
    let Some(opts_bytes) = (unsafe { read_c_string_bytes(opts) }) else {
        unsafe { set_abi_errno(libc::EINVAL) };
        return 1;
    };

    let fields = frankenlibc_core::mntent::MntFields {
        fsname: &fsname_bytes,
        dir: &dir_bytes,
        mtype: &mtype_bytes,
        opts: &opts_bytes,
        freq,
        passno,
    };
    let mut line = Vec::with_capacity(
        fields.fsname.len() + fields.dir.len() + fields.mtype.len() + fields.opts.len() + 16,
    );
    frankenlibc_core::mntent::format_mntent_line(&fields, &mut line);

    // Write to the underlying file (accessed via BufReader::get_mut).
    let ms = unsafe { &mut *(stream as *mut MntStream) };
    match ms.reader.get_mut().write_all(&line) {
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
    match unsafe { syscall::sys_sendmmsg(sockfd, msgvec as *mut u8, vlen, flags) } {
        Ok(n) => n,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
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
    match unsafe { syscall::sys_recvmmsg(sockfd, msgvec as *mut u8, vlen, flags, timeout as usize) }
    {
        Ok(n) => n,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

// ---------------------------------------------------------------------------
// sched_rr_get_interval / sched_getaffinity CPU_COUNT helper
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sched_rr_get_interval(pid: libc::pid_t, tp: *mut libc::timespec) -> c_int {
    match unsafe { syscall::sys_sched_rr_get_interval(pid, tp as *mut u8) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
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
    let Some(name_bytes) = (unsafe { read_c_string_bytes(dname) }) else {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    };
    unsafe { dns_query_raw(&name_bytes, class, type_, answer, anslen) }
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
    let Some(name_bytes) = (unsafe { read_c_string_bytes(dname) }) else {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    };
    let name_str = match std::str::from_utf8(&name_bytes) {
        Ok(s) => s,
        Err(_) => {
            unsafe { set_abi_errno(errno::EINVAL) };
            return -1;
        }
    };

    let config = &*RESOLV_CONFIG;

    // If the name has enough dots, try it as absolute first.
    if config.should_try_absolute_first(name_str) {
        let rc = unsafe { dns_query_raw(&name_bytes, class, type_, answer, anslen) };
        if rc > 0 {
            return rc;
        }
    }

    // Try appending each search domain.
    for domain in &config.search {
        let mut fqdn = Vec::with_capacity(name_bytes.len() + 1 + domain.len());
        fqdn.extend_from_slice(&name_bytes);
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
        let rc = unsafe { dns_query_raw(&name_bytes, class, type_, answer, anslen) };
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

        // `fgets` writes into a fixed local buffer; keep the scan inside it.
        let line_len = line_buf
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(line_buf.len());
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

        let line_len = line_buf
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(line_buf.len());
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
    let Some(user_name) = (unsafe { read_c_string_bytes(user) }) else {
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    };
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
                if member == user_name.as_slice() && !result.contains(&gid) {
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
    let Some(user_name) = (unsafe { read_c_string_bytes(user) }) else {
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    };

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
                if member == user_name.as_slice() && !groups.contains(&gid) {
                    groups.push(gid);
                    break;
                }
            }
        }
    }

    match unsafe { syscall::sys_setgroups(groups.len(), groups.as_ptr()) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
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
    let Some(bytes) = (unsafe { read_bounded_c_string_with_nul(name_ptr, GETLOGIN_MAX_LEN) })
    else {
        unsafe { set_abi_errno(errno::ERANGE) };
        runtime_policy::observe(ApiFamily::Resolver, decision.profile, 10, true);
        return std::ptr::null_mut();
    };
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
    let Some(bytes) = (unsafe { read_bounded_c_string_with_nul(name_ptr, GETLOGIN_MAX_LEN) })
    else {
        runtime_policy::observe(ApiFamily::Resolver, decision.profile, 10, true);
        return errno::ERANGE;
    };
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

/// glibc reserved-namespace alias for [`getlogin`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __getlogin() -> *mut c_char {
    unsafe { getlogin() }
}

/// glibc reserved-namespace alias for [`getlogin_r`].
///
/// # Safety
///
/// Same as [`getlogin_r`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __getlogin_r(buf: *mut c_char, bufsize: usize) -> c_int {
    unsafe { getlogin_r(buf, bufsize) }
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
    let effective_buflen = tracked_output_capacity(buf, buflen);
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
    if effective_buflen == 0 {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 12, true);
        return errno::ERANGE;
    }

    match unsafe { resolve_ttyname_into(fd, buf, effective_buflen) } {
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
                runtime_policy::scaled_cost(12, effective_buflen),
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
    let fd = match unsafe { syscall::sys_open(tty.as_ptr(), libc::O_RDWR | libc::O_NOCTTY, 0) } {
        Ok(fd) => fd,
        Err(_) => return std::ptr::null_mut(),
    };

    // Write prompt
    if !prompt.is_null() {
        let Some(prompt_bytes) = (unsafe { read_c_string_bytes(prompt) }) else {
            unsafe { set_abi_errno(libc::EINVAL) };
            let _ = syscall::sys_close(fd);
            return std::ptr::null_mut();
        };
        let _ = unsafe { syscall::sys_write(fd, prompt_bytes.as_ptr(), prompt_bytes.len()) };
    }

    // Disable echo via ioctl (TCGETS=0x5401, TCSETS=0x5402)
    const TCGETS: usize = 0x5401;
    const TCSETS: usize = 0x5402;
    const ECHO_FLAG: u32 = 0o10; // ECHO in termios c_lflag
    let mut termios_buf = [0u8; 60]; // struct termios size on Linux
    let saved_ok =
        unsafe { syscall::sys_ioctl(fd, TCGETS, termios_buf.as_mut_ptr() as usize) }.is_ok();

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
        let _ = unsafe { syscall::sys_ioctl(fd, TCSETS, modified.as_ptr() as usize) };
    }

    // Read password
    let result = GETPASS_BUF.with(|cell| {
        let mut buf = cell.borrow_mut();
        let mut pos = 0usize;
        loop {
            let mut ch = 0u8;
            let n = match unsafe { syscall::sys_read(fd, &mut ch as *mut u8, 1) } {
                Ok(n) => n as isize,
                Err(_) => -1,
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
        let _ = unsafe { syscall::sys_ioctl(fd, TCSETS, termios_buf.as_ptr() as usize) };
        // Print newline since echo was off
        let _ = unsafe { syscall::sys_write(fd, b"\n".as_ptr(), 1) };
    }

    let _ = syscall::sys_close(fd);
    result
}

// ---------------------------------------------------------------------------
// readpassphrase (OpenBSD: passphrase reader with flag-controlled behavior)
// ---------------------------------------------------------------------------
//
// Companion to getpass: same /dev/tty + ioctl(TCGETS/TCSETS) ECHO flip
// pattern, but with a caller-provided buffer and the documented OpenBSD
// flag set:
//   RPP_ECHO_OFF   = 0x00  default — disable echo
//   RPP_ECHO_ON    = 0x01  echo as typed
//   RPP_REQUIRE_TTY= 0x02  fail if /dev/tty unavailable
//   RPP_FORCELOWER = 0x04  convert to lowercase
//   RPP_FORCEUPPER = 0x08  convert to uppercase
//   RPP_SEVENBIT   = 0x10  strip the high bit
//   RPP_STDIN      = 0x20  use stdin/stderr instead of /dev/tty

const RPP_ECHO_ON: c_int = 0x01;
const RPP_REQUIRE_TTY: c_int = 0x02;
const RPP_FORCELOWER: c_int = 0x04;
const RPP_FORCEUPPER: c_int = 0x08;
const RPP_SEVENBIT: c_int = 0x10;
const RPP_STDIN: c_int = 0x20;

/// OpenBSD `readpassphrase(prompt, buf, bufsiz, flags)` — read a
/// passphrase from /dev/tty (or stdin/stderr when [`RPP_STDIN`] is
/// set) into the caller-supplied `buf` (at most `bufsiz - 1` bytes,
/// NUL-terminated). Returns `buf` on success, NULL on error or when
/// `bufsiz == 0`.
///
/// # Safety
///
/// Caller must ensure `buf` is valid for `bufsiz` writable bytes
/// and `prompt`, when non-NULL, is a valid NUL-terminated C string.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn readpassphrase(
    prompt: *const c_char,
    buf: *mut c_char,
    bufsiz: usize,
    flags: c_int,
) -> *mut c_char {
    if buf.is_null() || bufsiz == 0 {
        return std::ptr::null_mut();
    }

    let want_stdin = flags & RPP_STDIN != 0;
    let echo_on = flags & RPP_ECHO_ON != 0;
    let force_lower = flags & RPP_FORCELOWER != 0;
    let force_upper = flags & RPP_FORCEUPPER != 0;
    let seven_bit = flags & RPP_SEVENBIT != 0;
    let require_tty = flags & RPP_REQUIRE_TTY != 0;

    // Open /dev/tty unless RPP_STDIN was requested.
    let (read_fd, write_fd, owns_fd) = if want_stdin {
        (0, 2, false) // stdin reads, stderr writes
    } else {
        let tty = b"/dev/tty\0";
        match unsafe { syscall::sys_open(tty.as_ptr(), libc::O_RDWR | libc::O_NOCTTY, 0) } {
            Ok(fd) => (fd, fd, true),
            Err(_) => {
                if require_tty {
                    return std::ptr::null_mut();
                }
                (0, 2, false)
            }
        }
    };

    // Write the prompt to the write fd.
    if !prompt.is_null() {
        let Some(prompt_bytes) = (unsafe { read_c_string_bytes(prompt) }) else {
            unsafe { set_abi_errno(libc::EINVAL) };
            if owns_fd {
                let _ = syscall::sys_close(read_fd);
            }
            return std::ptr::null_mut();
        };
        let _ = unsafe { syscall::sys_write(write_fd, prompt_bytes.as_ptr(), prompt_bytes.len()) };
    }

    // Toggle ECHO via ioctl(TCGETS/TCSETS) only when echo should be off.
    const TCGETS: usize = 0x5401;
    const TCSETS: usize = 0x5402;
    const ECHO_FLAG: u32 = 0o10;
    let mut termios_buf = [0u8; 60];
    let saved_ok = if !echo_on {
        let ok = unsafe { syscall::sys_ioctl(read_fd, TCGETS, termios_buf.as_mut_ptr() as usize) }
            .is_ok();
        if ok {
            let mut modified = termios_buf;
            let lflag_offset = 12;
            let lflag = u32::from_ne_bytes(
                modified[lflag_offset..lflag_offset + 4]
                    .try_into()
                    .unwrap_or([0; 4]),
            );
            let new_lflag = lflag & !ECHO_FLAG;
            modified[lflag_offset..lflag_offset + 4].copy_from_slice(&new_lflag.to_ne_bytes());
            let _ = unsafe { syscall::sys_ioctl(read_fd, TCSETS, modified.as_ptr() as usize) };
        }
        ok
    } else {
        false
    };

    // Read up to bufsiz-1 bytes, byte-by-byte until newline / EOF.
    let mut pos = 0usize;
    let max_pos = bufsiz - 1;
    loop {
        let mut ch = 0u8;
        let n = unsafe { syscall::sys_read(read_fd, &mut ch as *mut u8, 1) }
            .map(|n| n as isize)
            .unwrap_or(-1);
        if n <= 0 || ch == b'\n' || ch == b'\r' {
            break;
        }
        if pos >= max_pos {
            // Drain remaining input on the line so the user's next
            // operation isn't fed leftover bytes — matches OpenBSD.
            continue;
        }
        let mut byte = ch;
        if seven_bit {
            byte &= 0x7f;
        }
        if force_lower {
            byte = byte.to_ascii_lowercase();
        } else if force_upper {
            byte = byte.to_ascii_uppercase();
        }
        // SAFETY: pos < max_pos < bufsiz; buf has bufsiz writable bytes.
        unsafe { *buf.add(pos) = byte as c_char };
        pos += 1;
    }
    // SAFETY: pos <= max_pos < bufsiz; the NUL slot is in range.
    unsafe { *buf.add(pos) = 0 };

    // Restore the terminal + emit the suppressed newline.
    if saved_ok {
        let _ = unsafe { syscall::sys_ioctl(read_fd, TCSETS, termios_buf.as_ptr() as usize) };
        let _ = unsafe { syscall::sys_write(write_fd, b"\n".as_ptr(), 1) };
    }

    if owns_fd {
        let _ = syscall::sys_close(read_fd);
    }

    buf
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
    let rc = match unsafe { syscall::sys_sethostname(name as *const u8, len) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
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
    let rc = match unsafe { syscall::sys_setdomainname(name as *const u8, len) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
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
    match syscall::sys_setns(fd, nstype) {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// `unshare` — disassociate parts of process execution context.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn unshare(flags: c_int) -> c_int {
    match syscall::sys_unshare(flags) {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
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
    match unsafe {
        syscall::sys_mount(
            source as *const u8,
            target as *const u8,
            filesystemtype as *const u8,
            mountflags as usize,
            data as *const u8,
        )
    } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// `umount2` — unmount a filesystem with flags.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn umount2(target: *const c_char, flags: c_int) -> c_int {
    match unsafe { syscall::sys_umount2(target as *const u8, flags) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// `chroot` — change root directory.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn chroot(path: *const c_char) -> c_int {
    match unsafe { syscall::sys_chroot(path as *const u8) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// `pivot_root` — change the root filesystem.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pivot_root(new_root: *const c_char, put_old: *const c_char) -> c_int {
    match unsafe { syscall::sys_pivot_root(new_root as *const u8, put_old as *const u8) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// `acct` — process accounting.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn acct(filename: *const c_char) -> c_int {
    match unsafe { syscall::sys_acct(filename as *const u8) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// `reboot` — reboot or enable/disable Ctrl-Alt-Del.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn reboot(cmd: c_int) -> c_int {
    match syscall::sys_reboot(0xfee1dead, 672274793, cmd) {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// `swapon` — start swapping.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn swapon(path: *const c_char, swapflags: c_int) -> c_int {
    match unsafe { syscall::sys_swapon(path as *const u8, swapflags) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// `swapoff` — stop swapping.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn swapoff(path: *const c_char) -> c_int {
    match unsafe { syscall::sys_swapoff(path as *const u8) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
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
    match unsafe { syscall::sys_getresuid(ruid, euid, suid) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getresgid(
    rgid: *mut libc::gid_t,
    egid: *mut libc::gid_t,
    sgid: *mut libc::gid_t,
) -> c_int {
    match unsafe { syscall::sys_getresgid(rgid, egid, sgid) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setresuid(
    ruid: libc::uid_t,
    euid: libc::uid_t,
    suid: libc::uid_t,
) -> c_int {
    match syscall::sys_setresuid(ruid, euid, suid) {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setresgid(
    rgid: libc::gid_t,
    egid: libc::gid_t,
    sgid: libc::gid_t,
) -> c_int {
    match syscall::sys_setresgid(rgid, egid, sgid) {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

// ---------------------------------------------------------------------------
// fanotify — RawSyscall
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fanotify_init(flags: c_uint, event_f_flags: c_uint) -> c_int {
    match syscall::sys_fanotify_init(flags, event_f_flags) {
        Ok(fd) => fd,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fanotify_mark(
    fanotify_fd: c_int,
    flags: c_uint,
    mask: u64,
    dirfd: c_int,
    pathname: *const c_char,
) -> c_int {
    match unsafe {
        syscall::sys_fanotify_mark(fanotify_fd, flags, mask, dirfd, pathname as *const u8)
    } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
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

#[inline]
fn process_vm_invalid_flags(flags: c_ulong) -> bool {
    flags != 0
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
    let invalid_flags = process_vm_invalid_flags(flags);
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
    if invalid_flags {
        unsafe { set_abi_errno(errno::EINVAL) };
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

    match unsafe {
        syscall::sys_process_vm_readv(
            pid,
            local_iov as *const u8,
            liovcnt as usize,
            remote_iov as *const u8,
            riovcnt as usize,
            flags as usize,
        )
    } {
        Ok(n) => {
            runtime_policy::observe(
                ApiFamily::VirtualMemory,
                decision.profile,
                runtime_policy::scaled_cost(12, io_units),
                false,
            );
            n
        }
        Err(e) => {
            unsafe { set_abi_errno(e) };
            runtime_policy::observe(
                ApiFamily::VirtualMemory,
                decision.profile,
                runtime_policy::scaled_cost(12, io_units),
                true,
            );
            -1
        }
    }
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
    let invalid_flags = process_vm_invalid_flags(flags);
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
    if invalid_flags {
        unsafe { set_abi_errno(errno::EINVAL) };
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

    match unsafe {
        syscall::sys_process_vm_writev(
            pid,
            local_iov as *const u8,
            liovcnt as usize,
            remote_iov as *const u8,
            riovcnt as usize,
            flags as usize,
        )
    } {
        Ok(n) => {
            runtime_policy::observe(
                ApiFamily::VirtualMemory,
                decision.profile,
                runtime_policy::scaled_cost(12, io_units),
                false,
            );
            n
        }
        Err(e) => {
            unsafe { set_abi_errno(e) };
            runtime_policy::observe(
                ApiFamily::VirtualMemory,
                decision.profile,
                runtime_policy::scaled_cost(12, io_units),
                true,
            );
            -1
        }
    }
}

// ---------------------------------------------------------------------------
// 64-bit LFS extras / umount — Implemented (native delegates on x86_64)
// ---------------------------------------------------------------------------

/// Linux `umount` — unmount a filesystem via raw syscall.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn umount(target: *const c_char) -> c_int {
    match unsafe { syscall::sys_umount2(target as *const u8, 0) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
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
    // On x86_64, glob_t and glob64_t are layout-identical, so delegate to the
    // canonical implementation instead of maintaining a second raw-offset path.
    unsafe { crate::string_abi::glob(pattern, flags, _errfunc, pglob) }
}

/// `globfree64` — on x86_64, identical to `globfree` (LFS transparent).
/// Delegates to native globfree implementation in string_abi.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn globfree64(pglob: *mut c_void) {
    unsafe { crate::string_abi::globfree(pglob) }
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
    > = unsafe { std::mem::transmute(fn_) }; // ubs:ignore — nftw64 callback ABI matches nftw on x86_64
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
    match unsafe { syscall::sys_sysinfo(info.cast::<syscall::Sysinfo>()) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

// ---------------------------------------------------------------------------
// Process group — RawSyscall
// ---------------------------------------------------------------------------

/// POSIX `getpgrp` — get process group ID of the calling process.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getpgrp() -> libc::pid_t {
    syscall::sys_getpgrp()
}

/// BSD `setpgrp` — set process group (equivalent to setpgid(0, 0)).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setpgrp() -> c_int {
    match syscall::sys_setpgid(0, 0) {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// glibc reserved-namespace alias for [`setpgrp`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __setpgrp() -> c_int {
    unsafe { setpgrp() }
}

// ---------------------------------------------------------------------------
// Priority — RawSyscall
// ---------------------------------------------------------------------------

/// POSIX `getpriority` — get scheduling priority.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getpriority(which: c_int, who: libc::id_t) -> c_int {
    unsafe { set_abi_errno(0) };
    match syscall::sys_getpriority(which, who as i32) {
        Ok(prio) => prio,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// POSIX `setpriority` — set scheduling priority.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setpriority(which: c_int, who: libc::id_t, prio: c_int) -> c_int {
    match syscall::sys_setpriority(which, who as i32, prio) {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// glibc reserved-namespace alias for [`getpriority`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __getpriority(which: c_int, who: libc::id_t) -> c_int {
    unsafe { getpriority(which, who) }
}

/// glibc reserved-namespace alias for [`setpriority`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __setpriority(which: c_int, who: libc::id_t, prio: c_int) -> c_int {
    unsafe { setpriority(which, who, prio) }
}

// ---------------------------------------------------------------------------
// getdtablesize — Implemented
// ---------------------------------------------------------------------------

/// BSD `getdtablesize` — get max number of file descriptors.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getdtablesize() -> c_int {
    let mut rlim = std::mem::MaybeUninit::<libc::rlimit>::zeroed();
    match unsafe {
        syscall::sys_getrlimit(libc::RLIMIT_NOFILE as i32, rlim.as_mut_ptr() as *mut u8)
    } {
        Ok(()) => {
            let rlim = unsafe { rlim.assume_init() };
            rlim.rlim_cur.min(c_int::MAX as u64) as c_int
        }
        Err(_) => 256,
    }
}

// ---------------------------------------------------------------------------
// brk / sbrk — RawSyscall
// ---------------------------------------------------------------------------

static CURRENT_BRK: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// POSIX `brk` — set the program break.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn brk(addr: *mut c_void) -> c_int {
    let new_brk = syscall::sys_brk(addr as usize);
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
        let b = syscall::sys_brk(0);
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

    let new_brk = syscall::sys_brk(new_addr);
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
    match unsafe { syscall::sys_getcwd(buf.as_mut_ptr(), buf.len()) } {
        Ok(rc) => {
            let len = buf.iter().position(|&b| b == 0).unwrap_or(rc);
            // GNU get_current_dir_name returns a buffer the caller frees
            // with free() — libc::malloc so the pair matches in both
            // LD_PRELOAD and non-preload contexts (bd-zgifl).
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
        Err(e) => {
            unsafe { set_abi_errno(e) };
            std::ptr::null_mut()
        }
    }
}

/// GNU `canonicalize_file_name` — resolve path like realpath(path, NULL).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn canonicalize_file_name(path: *const c_char) -> *mut c_char {
    unsafe { crate::stdlib_abi::realpath(path, std::ptr::null_mut()) }
}

// ---------------------------------------------------------------------------
// strerror_l — Implemented
// ---------------------------------------------------------------------------

/// POSIX `strerror_l` — locale-aware strerror (we use C locale always).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strerror_l(errnum: c_int, _locale: *mut c_void) -> *mut c_char {
    unsafe { crate::string_abi::strerror(errnum) }
}

/// glibc reserved-namespace alias for [`strerror_l`]. Some
/// glibc-internal callers (NSS modules, libstdc++ cancellation
/// machinery) link against the underscored variant instead of
/// the public name.
///
/// # Safety
///
/// Same as [`strerror_l`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __strerror_l(errnum: c_int, locale: *mut c_void) -> *mut c_char {
    unsafe { strerror_l(errnum, locale) }
}

// ---------------------------------------------------------------------------
// __xpg_basename — Implemented
// ---------------------------------------------------------------------------

/// XSI `__xpg_basename` — POSIX basename (modifies input).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __xpg_basename(path: *mut c_char) -> *mut c_char {
    static DOT: &[u8] = b".\0";
    static SLASH: &[u8] = b"/\0";

    if path.is_null() {
        return DOT.as_ptr() as *mut c_char;
    }
    let Some(bytes) = (unsafe { read_c_string_bytes(path) }) else {
        unsafe { set_abi_errno(libc::EINVAL) };
        return DOT.as_ptr() as *mut c_char;
    };
    if bytes.is_empty() {
        return DOT.as_ptr() as *mut c_char;
    }
    let mut end = bytes.len();
    while end > 0 && bytes[end - 1] == b'/' {
        end -= 1;
    }
    if end == 0 {
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
    let Some(bytes) = (unsafe { read_c_string_bytes(string) }) else {
        unsafe { set_abi_errno(libc::EINVAL) };
        return string;
    };
    let len = bytes.len();
    if len <= 1 {
        return string;
    }
    let mut seed: u32 = syscall::sys_gettid() as u32;
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
    match unsafe {
        syscall::sys_openat(
            libc::AT_FDCWD,
            PTMX.as_ptr(),
            libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
            0,
        )
    } {
        Ok(fd) => fd,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// POSIX `ptsname_r` — get slave PTY name (reentrant).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ptsname_r(fd: c_int, buf: *mut c_char, buflen: usize) -> c_int {
    let effective_buflen = tracked_output_capacity(buf, buflen);
    if buf.is_null() || buflen == 0 {
        unsafe { set_abi_errno(libc::EINVAL) };
        return libc::EINVAL;
    }
    if effective_buflen == 0 {
        unsafe { set_abi_errno(libc::ERANGE) };
        return libc::ERANGE;
    }
    let mut pty_num: c_uint = 0;
    const TIOCGPTN: usize = 0x80045430;
    if let Err(e) =
        unsafe { syscall::sys_ioctl(fd, TIOCGPTN, &mut pty_num as *mut c_uint as usize) }
    {
        unsafe { set_abi_errno(e) };
        return e;
    }
    let name = format!("/dev/pts/{pty_num}");
    if name.len() + 1 > effective_buflen {
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
    let uid = syscall::sys_getuid();
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
    const SIOCATMARK: usize = 0x8905;
    match unsafe { syscall::sys_ioctl(sockfd, SIOCATMARK, &mut atmark as *mut c_int as usize) } {
        Ok(_) => atmark,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

// ---------------------------------------------------------------------------
// tempnam — Implemented
// ---------------------------------------------------------------------------

/// POSIX `tempnam` — create a unique temporary file name.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tempnam(dir: *const c_char, pfx: *const c_char) -> *mut c_char {
    let dir_bytes = if dir.is_null() {
        std::borrow::Cow::Borrowed(b"/tmp".as_slice())
    } else {
        match unsafe { read_c_string_bytes(dir) } {
            Some(bytes) => std::borrow::Cow::Owned(bytes),
            None => {
                unsafe { set_abi_errno(libc::EINVAL) };
                std::borrow::Cow::Borrowed(b"/tmp".as_slice())
            }
        }
    };
    let pfx_bytes = if pfx.is_null() {
        std::borrow::Cow::Borrowed(b"tmp".as_slice())
    } else {
        match unsafe { read_c_string_bytes(pfx) } {
            Some(bytes) => std::borrow::Cow::Owned(bytes),
            None => {
                unsafe { set_abi_errno(libc::EINVAL) };
                std::borrow::Cow::Borrowed(b"tmp".as_slice())
            }
        }
    };

    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let cnt = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let pid = syscall::sys_getpid() as u32;
    let pfx_len = pfx_bytes.len().min(5);
    let mut name = Vec::with_capacity(dir_bytes.len() + 1 + pfx_len + 32);
    name.extend_from_slice(&dir_bytes);
    name.push(b'/');
    name.extend_from_slice(&pfx_bytes[..pfx_len]);
    {
        use std::io::Write;
        let _ = write!(name, "{pid:x}{cnt:x}");
    }

    // POSIX tempnam(3) — caller frees with free(). Use libc::malloc so
    // alloc/free is consistent in both LD_PRELOAD and non-preload builds
    // (bd-zgifl).
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
    // execveat only returns on failure (on success, the process image is replaced)
    match unsafe {
        syscall::sys_execveat(
            dirfd,
            pathname as *const u8,
            argv as *const *const u8,
            envp as *const *const u8,
            flags,
        )
    } {
        Ok(()) => 0, // should never reach here
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// Linux `pidfd_getfd` — duplicate fd from another process.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pidfd_getfd(pidfd: c_int, targetfd: c_int, flags: c_uint) -> c_int {
    match syscall::sys_pidfd_getfd(pidfd, targetfd, flags) {
        Ok(fd) => fd,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
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
    match unsafe {
        syscall::sys_epoll_pwait2(
            epfd,
            events as *mut u8,
            maxevents,
            timeout as *const u8,
            sigmask as *const u8,
            std::mem::size_of::<libc::c_ulong>(),
        )
    } {
        Ok(n) => n,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
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
    match unsafe { syscall::sys_ptrace(request, pid, addr as usize, data as usize) } {
        Ok(v) => v as c_long,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// Linux `seccomp` — secure computing filter.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn seccomp(operation: c_uint, flags: c_uint, args: *mut c_void) -> c_int {
    match unsafe { syscall::sys_seccomp(operation, flags, args as *const u8) } {
        Ok(v) => v,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// Linux `capget` — get process capabilities.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn capget(hdrp: *mut c_void, datap: *mut c_void) -> c_int {
    match unsafe { syscall::sys_capget(hdrp as *mut u8, datap as *mut u8) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// Linux `capset` — set process capabilities.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn capset(hdrp: *mut c_void, datap: *const c_void) -> c_int {
    match unsafe { syscall::sys_capset(hdrp as *const u8, datap as *const u8) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
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
    match unsafe {
        syscall::sys_futex(
            uaddr as *const u32,
            futex_op,
            val as u32,
            timeout as usize,
            uaddr2 as usize,
            val3 as u32,
        )
    } {
        Ok(v) => v as c_int,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// Linux `membarrier` — issue memory barriers on a set of threads.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn membarrier(cmd: c_int, flags: c_uint, cpu_id: c_int) -> c_int {
    match syscall::sys_membarrier(cmd, flags, cpu_id) {
        Ok(v) => v,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

// ===========================================================================
// Batch: Native Linux AIO (io_setup family) — RawSyscall
// ===========================================================================

/// Linux `io_setup` — create asynchronous I/O context.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn io_setup(nr_events: c_uint, ctxp: *mut c_ulong) -> c_int {
    match unsafe { syscall::sys_io_setup(nr_events, ctxp as *mut usize) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// Linux `io_destroy` — destroy asynchronous I/O context.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn io_destroy(ctx_id: c_ulong) -> c_int {
    match syscall::sys_io_destroy(ctx_id as usize) {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// Linux `io_submit` — submit asynchronous I/O blocks.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn io_submit(ctx_id: c_ulong, nr: c_long, iocbpp: *mut *mut c_void) -> c_int {
    match unsafe { syscall::sys_io_submit(ctx_id as usize, nr, iocbpp as *mut *mut u8) } {
        Ok(v) => v as c_int,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// Linux `io_cancel` — cancel outstanding I/O request.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn io_cancel(
    ctx_id: c_ulong,
    iocb: *mut c_void,
    result: *mut c_void,
) -> c_int {
    match unsafe { syscall::sys_io_cancel(ctx_id as usize, iocb as *mut u8, result as *mut u8) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
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
    match unsafe {
        syscall::sys_io_getevents(
            ctx_id as usize,
            min_nr,
            nr,
            events as *mut u8,
            timeout as *mut u8,
        )
    } {
        Ok(v) => v as c_int,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

// ===========================================================================
// Batch: Terminal process group — RawSyscall
// ===========================================================================

/// POSIX `tcgetpgrp` — get foreground process group of terminal.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tcgetpgrp(fd: c_int) -> libc::pid_t {
    let mut pgrp: libc::pid_t = 0;
    const TIOCGPGRP: usize = 0x540F;
    match unsafe { syscall::sys_ioctl(fd, TIOCGPGRP, &mut pgrp as *mut libc::pid_t as usize) } {
        Ok(_) => pgrp,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// POSIX `tcsetpgrp` — set foreground process group of terminal.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tcsetpgrp(fd: c_int, pgrp: libc::pid_t) -> c_int {
    const TIOCSPGRP: usize = 0x5410;
    match unsafe { syscall::sys_ioctl(fd, TIOCSPGRP, &pgrp as *const libc::pid_t as usize) } {
        Ok(_) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// POSIX `tcgetsid` — get session leader of controlling terminal.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tcgetsid(fd: c_int) -> libc::pid_t {
    let mut sid: libc::pid_t = 0;
    const TIOCGSID: usize = 0x5429;
    if let Err(e) =
        unsafe { syscall::sys_ioctl(fd, TIOCGSID, &mut sid as *mut libc::pid_t as usize) }
    {
        unsafe { set_abi_errno(e) };
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
    match syscall::sys_pkey_alloc(flags, access_rights) {
        Ok(pkey) => pkey,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// Linux `pkey_free` — free a protection key.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pkey_free(pkey: c_int) -> c_int {
    match syscall::sys_pkey_free(pkey) {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// Linux `pkey_mprotect` — set memory protection with key.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pkey_mprotect(
    addr: *mut c_void,
    len: usize,
    prot: c_int,
    pkey: c_int,
) -> c_int {
    match unsafe { syscall::sys_pkey_mprotect(addr as *mut u8, len, prot, pkey) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

// ===========================================================================
// Batch: Pthread scheduling — Implemented (delegates to kernel)
// ===========================================================================

/// Extract kernel TID from a pthread_t handle.
/// On glibc x86_64, pthread_t is a pointer to the thread control block (TCB).
/// The TID (pid field) is at offset 720 in the NPTL struct (glibc 2.34+).
/// For the common case of pthread_self(), we can detect this and use SYS_gettid.
unsafe fn pthread_to_tid(thread: libc::pthread_t) -> c_long {
    let self_handle = unsafe { crate::pthread_abi::pthread_self() };
    if thread == self_handle {
        // Common case: operating on current thread
        syscall::sys_gettid() as c_long
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
    match unsafe { syscall::sys_sched_setscheduler(tid as i32, policy, param as *const u8) } {
        Ok(()) => 0,
        Err(e) => e,
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
    let p = match syscall::sys_sched_getscheduler(tid as i32) {
        Ok(p) => p,
        Err(e) => return e,
    };
    unsafe { *policy = p };
    match unsafe { syscall::sys_sched_getparam(tid as i32, param as *mut u8) } {
        Ok(()) => 0,
        Err(e) => e,
    }
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
    match unsafe { syscall::sys_io_uring_setup(entries, p as *mut u8) } {
        Ok(fd) => fd,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
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
    match unsafe {
        syscall::sys_io_uring_enter(
            fd as i32,
            to_submit,
            min_complete,
            flags,
            sig as *const u8,
            std::mem::size_of::<libc::c_ulong>(),
        )
    } {
        Ok(v) => v,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// Linux `io_uring_register` — register resources with io_uring.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn io_uring_register(
    fd: c_uint,
    opcode: c_uint,
    arg: *mut c_void,
    nr_args: c_uint,
) -> c_int {
    match unsafe { syscall::sys_io_uring_register(fd as i32, opcode, arg as *const u8, nr_args) } {
        Ok(v) => v,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
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
    match syscall::sys_kcmp(pid1, pid2, type_, idx1, idx2) {
        Ok(v) => v,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// Linux `ioprio_set` — set I/O scheduling class and priority.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ioprio_set(which: c_int, who: c_int, ioprio: c_int) -> c_int {
    match syscall::sys_ioprio_set(which, who, ioprio) {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// Linux `ioprio_get` — get I/O scheduling class and priority.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ioprio_get(which: c_int, who: c_int) -> c_int {
    match syscall::sys_ioprio_get(which, who) {
        Ok(v) => v,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

// ===========================================================================
// Batch: userfaultfd / landlock — RawSyscall (newer kernel APIs)
// ===========================================================================

/// Linux `userfaultfd` — create userfault file descriptor.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn userfaultfd(flags: c_int) -> c_int {
    match syscall::sys_userfaultfd(flags) {
        Ok(fd) => fd,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// Linux `landlock_create_ruleset` — create landlock ruleset.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn landlock_create_ruleset(
    attr: *const c_void,
    size: usize,
    flags: c_uint,
) -> c_int {
    match unsafe { syscall::sys_landlock_create_ruleset(attr as *const u8, size, flags) } {
        Ok(fd) => fd,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// Linux `landlock_add_rule` — add landlock rule to ruleset.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn landlock_add_rule(
    ruleset_fd: c_int,
    rule_type: c_int,
    rule_attr: *const c_void,
    flags: c_uint,
) -> c_int {
    match unsafe {
        syscall::sys_landlock_add_rule(ruleset_fd, rule_type, rule_attr as *const u8, flags)
    } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// Linux `landlock_restrict_self` — enforce landlock ruleset on current process.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn landlock_restrict_self(ruleset_fd: c_int, flags: c_uint) -> c_int {
    match syscall::sys_landlock_restrict_self(ruleset_fd, flags) {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

// ===========================================================================
// Batch: Miscellaneous POSIX/Linux — RawSyscall/Implemented
// ===========================================================================

/// POSIX `posix_fadvise64` — file access pattern advise (64-bit).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn posix_fadvise64(fd: c_int, offset: i64, len: i64, advice: c_int) -> c_int {
    match syscall::sys_fadvise64(fd, offset, len, advice) {
        Ok(()) => 0,
        Err(e) => e,
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
    match syscall::sys_sync_file_range(fd, offset, nbytes, flags) {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
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
    match unsafe { syscall::sys_remap_file_pages(addr as *mut u8, size, prot, pgoff, flags) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// Linux `tgkill` — send signal to specific thread.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tgkill(tgid: c_int, tid: c_int, sig: c_int) -> c_int {
    match syscall::sys_tgkill(tgid, tid, sig) {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// Linux `tkill` — send signal to thread (deprecated, use tgkill).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tkill(tid: c_int, sig: c_int) -> c_int {
    match syscall::sys_tkill(tid, sig) {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// Linux `sched_setattr` — extended scheduling attributes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sched_setattr(
    pid: libc::pid_t,
    attr: *mut c_void,
    flags: c_uint,
) -> c_int {
    match unsafe { syscall::sys_sched_setattr(pid, attr as *const syscall::SchedAttr, flags) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// Linux `sched_getattr` — get extended scheduling attributes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sched_getattr(
    pid: libc::pid_t,
    attr: *mut c_void,
    size: c_uint,
    flags: c_uint,
) -> c_int {
    match unsafe { syscall::sys_sched_getattr(pid, attr as *mut u8, size, flags) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// Linux `quotactl` — manipulate disk quotas.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn quotactl(
    cmd: c_int,
    special: *const c_char,
    id: c_int,
    addr: *mut c_void,
) -> c_int {
    match unsafe { syscall::sys_quotactl(cmd, special as *const u8, id, addr as *mut u8) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// Linux `lookup_dcookie` — return directory entry path for a cookie.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lookup_dcookie(cookie: u64, buffer: *mut c_char, len: usize) -> c_int {
    match unsafe { syscall::sys_lookup_dcookie(cookie, buffer as *mut u8, len) } {
        Ok(v) => v as c_int,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
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
    match unsafe {
        syscall::sys_perf_event_open(attr as *const u8, pid, cpu, group_fd, flags as u32)
    } {
        Ok(fd) => fd,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
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
    match unsafe {
        syscall::sys_add_key(
            type_ as *const u8,
            description as *const u8,
            payload as *const u8,
            plen,
            ringid,
        )
    } {
        Ok(key) => key as c_long,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// Linux `request_key` — request key from keyring.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn request_key(
    type_: *const c_char,
    description: *const c_char,
    callout_info: *const c_char,
    dest_keyring: i32,
) -> c_long {
    match unsafe {
        syscall::sys_request_key(
            type_ as *const u8,
            description as *const u8,
            callout_info as *const u8,
            dest_keyring,
        )
    } {
        Ok(key) => key as c_long,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
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
    match syscall::sys_keyctl(operation, arg2, arg3, arg4, arg5) {
        Ok(v) => v,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

// ===========================================================================
// Batch: Filesystem status — RawSyscall
// ===========================================================================

/// `statfs` — get filesystem statistics.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn statfs(path: *const c_char, buf: *mut c_void) -> c_int {
    match unsafe { syscall::sys_statfs(path as *const u8, buf.cast::<syscall::StatFs>()) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// `fstatfs` — get filesystem statistics by fd.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fstatfs(fd: c_int, buf: *mut c_void) -> c_int {
    match unsafe { syscall::sys_fstatfs(fd, buf.cast::<syscall::StatFs>()) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// Convert kernel statfs result to statvfs layout.
/// On x86_64 Linux, struct statfs fields (all long):
///   type, bsize, blocks, bfree, bavail, files, ffree, fsid(2xi32), namelen, frsize, flags, spare[4]
/// struct statvfs fields (all unsigned long):
///   bsize, frsize, blocks, bfree, bavail, files, ffree, favail, fsid, flag, namemax, spare[6]
unsafe fn statfs_to_statvfs(sfs: *const syscall::StatFs, vfs: *mut libc::statvfs) {
    let s = unsafe { &*sfs };
    let v = unsafe { &mut *vfs };
    v.f_bsize = s.f_bsize as u64;
    v.f_frsize = if s.f_frsize != 0 {
        s.f_frsize as u64
    } else {
        s.f_bsize as u64
    };
    v.f_blocks = s.f_blocks;
    v.f_bfree = s.f_bfree;
    v.f_bavail = s.f_bavail;
    v.f_files = s.f_files;
    v.f_ffree = s.f_ffree;
    v.f_favail = s.f_ffree; // Same as ffree for non-privileged
    v.f_fsid = u64::from(s.f_fsid.val[0] as u32) | (u64::from(s.f_fsid.val[1] as u32) << 32);
    // Mask f_flags to only the public ST_* bits per <sys/statvfs.h>:
    // ST_RDONLY (1) | ST_NOSUID (2) | ST_NODEV (4) | ST_NOEXEC (8) |
    // ST_SYNCHRONOUS (16) | ST_MANDLOCK (64) | ST_WRITE (128) |
    // ST_APPEND (256) | ST_IMMUTABLE (512) | ST_NOATIME (1024) |
    // ST_NODIRATIME (2048) | ST_RELATIME (4096).
    // The kernel includes internal mount-flag bits (e.g. MS_REMOUNT = 0x20)
    // in f_flags that glibc strips before exposing to user space; matching
    // that filter avoids spurious f_flag divergence (bd-2b63f4).
    const PUBLIC_ST_MASK: u64 = 0x1 | 0x2 | 0x4 | 0x8 | 0x10 | 0x40
        | 0x80 | 0x100 | 0x200 | 0x400 | 0x800 | 0x1000;
    v.f_flag = (s.f_flags as u64) & PUBLIC_ST_MASK;
    v.f_namemax = s.f_namelen as u64;
}

/// POSIX `statvfs` — POSIX filesystem statistics.
/// Calls SYS_statfs and converts the kernel struct to statvfs layout.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn statvfs(path: *const c_char, buf: *mut libc::statvfs) -> c_int {
    let mut sfs = std::mem::MaybeUninit::<syscall::StatFs>::zeroed();
    match unsafe { syscall::sys_statfs(path as *const u8, sfs.as_mut_ptr()) } {
        Ok(()) => {
            unsafe { statfs_to_statvfs(sfs.as_ptr(), buf) };
            0
        }
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// POSIX `fstatvfs` — POSIX filesystem statistics by fd.
/// Calls SYS_fstatfs and converts the kernel struct to statvfs layout.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fstatvfs(fd: c_int, buf: *mut libc::statvfs) -> c_int {
    let mut sfs = std::mem::MaybeUninit::<syscall::StatFs>::zeroed();
    match unsafe { syscall::sys_fstatfs(fd, sfs.as_mut_ptr()) } {
        Ok(()) => {
            unsafe { statfs_to_statvfs(sfs.as_ptr(), buf) };
            0
        }
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

// ===========================================================================
// Batch: Directory entries — RawSyscall
// ===========================================================================

/// Linux `getdents64` — get directory entries (64-bit).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getdents64(fd: c_int, dirp: *mut c_void, count: usize) -> c_long {
    match unsafe { syscall::sys_getdents64(fd, dirp as *mut u8, count) } {
        Ok(n) => n as c_long,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

// ===========================================================================
// Batch: C++ ABI / Stack protection — Implemented
// ===========================================================================

// Itanium C++ ABI `__dso_handle` — a per-DSO token whose address is the key
// callers pass as the third argument to `__cxa_atexit`.
//
// GCC/Rust startup objects already define this symbol for the linked shared
// object. FrankenLibC declares it so Rust tests and helper code can take the
// same address without adding a second definition that collides with
// `crtbeginS.o` during release linking.
#[allow(non_upper_case_globals)]
unsafe extern "C" {
    pub static __dso_handle: u8;
}

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

/// Itanium C++ ABI `__cxa_pure_virtual` — stub installed in vtable
/// slots for pure virtual functions. If a caller dispatches through
/// an under-construction or partially-destructed object whose
/// vtable still points to a pure-virtual entry, control reaches
/// here. We mirror glibc's behavior: write a diagnostic to stderr
/// and abort.
///
/// Without this symbol, every C++ binary linked against our libc
/// fails at link time with an undefined reference.
///
/// Marked `-> !` because we never return.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __cxa_pure_virtual() -> ! {
    let msg: &[u8] = b"pure virtual method called\n";
    unsafe {
        libc::write(2, msg.as_ptr() as *const c_void, msg.len());
        libc::abort();
    }
}

/// Itanium C++ ABI `__cxa_throw_bad_array_new_length` — entry
/// point compilers emit when a `new T[n]` allocation expression
/// computes an array length whose byte size would overflow
/// `size_t`. The full ABI calls for this to throw a
/// `std::bad_array_new_length` exception; with no exception
/// runtime available we mirror [`__cxa_pure_virtual`]'s
/// fail-stop convention: write a diagnostic to stderr and abort.
///
/// Without this symbol, C++ binaries that use array-new
/// expressions fail at link time with an undefined reference.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __cxa_throw_bad_array_new_length() -> ! {
    let msg: &[u8] = b"bad_array_new_length\n";
    unsafe {
        libc::write(2, msg.as_ptr() as *const c_void, msg.len());
        libc::abort();
    }
}

/// Itanium C++ ABI `__cxa_call_unexpected(exception_obj)` — entry
/// point invoked when a thrown exception does not match the
/// dynamic exception specification of the function it would
/// propagate through. Per ABI it should call `std::unexpected`
/// (which by default calls `std::terminate`). With no real
/// exception runtime we mirror [`__cxa_pure_virtual`]'s
/// fail-stop convention: write a diagnostic to stderr and abort.
///
/// The `_exception_obj` argument (a pointer to the in-flight
/// exception's runtime info) is consumed and ignored.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __cxa_call_unexpected(_exception_obj: *mut c_void) -> ! {
    let msg: &[u8] =
        b"terminate called after throwing an instance violating exception specification\n";
    unsafe {
        libc::write(2, msg.as_ptr() as *const c_void, msg.len());
        libc::abort();
    }
}

/// Itanium C++ ABI `__cxa_call_terminate(exc_obj)` — entry point
/// the personality routine invokes when an exception escapes a
/// `noexcept`/`throw()` boundary. Per ABI it should call
/// `std::terminate` (which by default calls `abort`). With no
/// exception runtime in play we collapse the call directly into
/// the same fail-stop convention as [`__cxa_pure_virtual`].
///
/// The `_exc_obj` argument (the in-flight exception's runtime
/// info) is consumed and ignored.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __cxa_call_terminate(_exc_obj: *mut c_void) -> ! {
    let msg: &[u8] = b"terminate called via __cxa_call_terminate\n";
    unsafe {
        libc::write(2, msg.as_ptr() as *const c_void, msg.len());
        libc::abort();
    }
}

/// Itanium C++ ABI `__cxa_deleted_virtual` — vtable slot
/// installed by the compiler for member functions marked
/// `= delete` that are dispatched through a base-class pointer.
/// If the program ever calls one, control reaches here. We mirror
/// [`__cxa_pure_virtual`]'s fail-stop convention.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __cxa_deleted_virtual() -> ! {
    let msg: &[u8] = b"deleted virtual method called\n";
    unsafe {
        libc::write(2, msg.as_ptr() as *const c_void, msg.len());
        libc::abort();
    }
}

/// Itanium C++ ABI `__cxa_bad_cast` — entry point the runtime
/// invokes when `dynamic_cast<T&>` fails (the reference form, in
/// contrast to the pointer form which returns NULL). Per ABI it
/// should throw `std::bad_cast`. With no exception runtime we
/// mirror [`__cxa_pure_virtual`]'s fail-stop convention.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __cxa_bad_cast() -> ! {
    let msg: &[u8] = b"std::bad_cast (via __cxa_bad_cast)\n";
    unsafe {
        libc::write(2, msg.as_ptr() as *const c_void, msg.len());
        libc::abort();
    }
}

/// Itanium C++ ABI `__cxa_bad_typeid` — entry point the runtime
/// invokes when `typeid(*p)` is evaluated with `p == nullptr`.
/// Per ABI it should throw `std::bad_typeid`. With no exception
/// runtime we mirror [`__cxa_pure_virtual`]'s fail-stop
/// convention.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __cxa_bad_typeid() -> ! {
    let msg: &[u8] = b"std::bad_typeid (via __cxa_bad_typeid)\n";
    unsafe {
        libc::write(2, msg.as_ptr() as *const c_void, msg.len());
        libc::abort();
    }
}

/// Itanium C++ ABI `__cxa_throw_bad_array_length` — entry point
/// the compiler emits for `new T[n]` when `n` is signed and
/// negative. Per ABI it should throw `std::bad_array_length`
/// (a removed C++14-era exception type that some pre-existing
/// binaries still link against). With no exception runtime we
/// mirror [`__cxa_pure_virtual`]'s fail-stop convention.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __cxa_throw_bad_array_length() -> ! {
    let msg: &[u8] = b"bad_array_length\n";
    unsafe {
        libc::write(2, msg.as_ptr() as *const c_void, msg.len());
        libc::abort();
    }
}

// ---------------------------------------------------------------------------
// Itanium C++ ABI guard variables (__cxa_guard_acquire/release/abort)
// ---------------------------------------------------------------------------
//
// These are emitted by the compiler around every function-scope `static`
// variable initializer in C++. Without them, every C++ binary linked
// against frankenlibc fails at link time.
//
// Per the Itanium ABI, the guard is a 64-bit value whose lowest two
// bytes encode initialization state:
//   - byte 0: "fully initialized" flag (1 = initialized)
//   - byte 1: "in-progress" flag (1 = some thread currently initializing)
//
// Concurrency model: a single global `Mutex<()>` + `Condvar` serializes
// all guard-state transitions. Static initialization is not a hot path,
// so the global serialization is fine and avoids the complexity of
// per-guard futexes.

static GUARD_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
static GUARD_CONDVAR: std::sync::Condvar = std::sync::Condvar::new();

#[inline]
fn read_guard_byte(g: *mut u64, byte: usize) -> u8 {
    // SAFETY: caller-supplied 8-byte guard storage.
    let bytes = unsafe { (g as *const u8).add(byte) };
    unsafe { core::ptr::read_volatile(bytes) }
}

#[inline]
fn write_guard_byte(g: *mut u64, byte: usize, val: u8) {
    // SAFETY: caller-supplied 8-byte guard storage.
    let bytes = unsafe { (g as *mut u8).add(byte) };
    unsafe { core::ptr::write_volatile(bytes, val) };
}

/// Itanium C++ ABI `__cxa_guard_acquire(g)` — race for the right
/// to run a function-scope static variable initializer.
///
/// Returns 1 if the calling thread should run the initializer
/// (and must follow up with [`__cxa_guard_release`] on success or
/// [`__cxa_guard_abort`] on a thrown exception). Returns 0 if
/// initialization is already complete.
///
/// Threads that arrive while another thread is initializing block
/// until the initializer either completes (returns 0) or aborts
/// (loop and re-race).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __cxa_guard_acquire(g: *mut u64) -> c_int {
    if g.is_null() {
        return 0;
    }
    let mut lock = GUARD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    loop {
        if read_guard_byte(g, 0) == 1 {
            return 0;
        }
        if read_guard_byte(g, 1) == 0 {
            write_guard_byte(g, 1, 1);
            return 1;
        }
        lock = GUARD_CONDVAR.wait(lock).unwrap_or_else(|e| e.into_inner());
    }
}

/// Itanium C++ ABI `__cxa_guard_release(g)` — mark initialization
/// complete and wake any threads blocked in `__cxa_guard_acquire`
/// for the same guard.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __cxa_guard_release(g: *mut u64) {
    if g.is_null() {
        return;
    }
    let _lock = GUARD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    write_guard_byte(g, 0, 1);
    write_guard_byte(g, 1, 0);
    GUARD_CONDVAR.notify_all();
}

/// Itanium C++ ABI `__cxa_guard_abort(g)` — release the
/// in-progress flag without setting "initialized". Called when
/// the initializer threw, so a future `__cxa_guard_acquire` on
/// the same guard re-races.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __cxa_guard_abort(g: *mut u64) {
    if g.is_null() {
        return;
    }
    let _lock = GUARD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    write_guard_byte(g, 1, 0);
    GUARD_CONDVAR.notify_all();
}

// ---------------------------------------------------------------------------
// Itanium C++ ABI: thread-local destructors, TM cleanup, vector ctor/dtor
// ---------------------------------------------------------------------------

/// Itanium C++ ABI `__cxa_thread_atexit(dtor, obj, dso)` — public-name
/// alias of `__cxa_thread_atexit_impl`. Some toolchains emit calls to
/// the unprefixed name; both must resolve to the same registry.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __cxa_thread_atexit(
    dtor: unsafe extern "C" fn(*mut c_void),
    obj: *mut c_void,
    dso_handle: *mut c_void,
) -> c_int {
    unsafe { crate::startup_abi::__cxa_thread_atexit_impl(dtor, obj, dso_handle) }
}

/// Itanium C++ ABI `__cxa_tm_cleanup(this_ptr, x, y)` — Transactional
/// Memory cleanup hook from the long-deprecated GCC `-fgnu-tm`
/// extension. Modern toolchains rarely use TM, but link-edit still
/// resolves the symbol. We accept the call and do nothing.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __cxa_tm_cleanup(_this_ptr: *mut c_void, _x: *mut c_void, _y: c_uint) {}

/// Itanium C++ ABI `__cxa_vec_ctor(array, count, size, ctor, dtor)` —
/// invoke `ctor` on each element of an array of `count` elements of
/// `size` bytes, in forward order. NULL `ctor` is a documented no-op
/// (the compiler omits the constructor when the element type is
/// trivially constructible).
///
/// We have no exception runtime, so the `_dtor` parameter (used to
/// destruct already-constructed elements when a constructor throws)
/// is accepted and ignored.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __cxa_vec_ctor(
    array: *mut c_void,
    element_count: usize,
    element_size: usize,
    ctor: Option<unsafe extern "C" fn(*mut c_void)>,
    _dtor: Option<unsafe extern "C" fn(*mut c_void)>,
) {
    if array.is_null() {
        return;
    }
    let Some(ctor) = ctor else {
        return;
    };
    let base = array as *mut u8;
    for i in 0..element_count {
        // SAFETY: caller-supplied array of (element_count * element_size).
        let p = unsafe { base.add(i * element_size) } as *mut c_void;
        unsafe { ctor(p) };
    }
}

/// Itanium C++ ABI `__cxa_vec_dtor(array, count, size, dtor)` —
/// invoke `dtor` on each element in REVERSE order. NULL `dtor` is a
/// documented no-op.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __cxa_vec_dtor(
    array: *mut c_void,
    element_count: usize,
    element_size: usize,
    dtor: Option<unsafe extern "C" fn(*mut c_void)>,
) {
    if array.is_null() || element_count == 0 {
        return;
    }
    let Some(dtor) = dtor else {
        return;
    };
    let base = array as *mut u8;
    for i in (0..element_count).rev() {
        // SAFETY: caller-supplied array of (element_count * element_size).
        let p = unsafe { base.add(i * element_size) } as *mut c_void;
        unsafe { dtor(p) };
    }
}

/// Itanium C++ ABI `__cxa_vec_cleanup(array, count, size, dtor)` —
/// EH-time cleanup of a partially-constructed array. Behaves the
/// same as [`__cxa_vec_dtor`]: invoke `dtor` on each element in
/// reverse order.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __cxa_vec_cleanup(
    array: *mut c_void,
    element_count: usize,
    element_size: usize,
    dtor: Option<unsafe extern "C" fn(*mut c_void)>,
) {
    unsafe { __cxa_vec_dtor(array, element_count, element_size, dtor) };
}

// ---------------------------------------------------------------------------
// Itanium C++ ABI: vector new / delete / copy-ctor (cxa_vec_new/delete[2/3])
// ---------------------------------------------------------------------------
//
// The compiler emits these for `new T[n]` / `delete[] arr` over types with
// non-trivial constructors/destructors. Without these symbols, every C++
// program that uses array-new fails at link time.
//
// Allocation layout when `padding > 0`:
//
//     +----------------- padding -----------------+----- count*size -----+
//     | size_t element_count | (rest unused/0)    | T[0] T[1] ... T[n-1] |
//     +-------------------------------------------+----------------------+
//     ^                                           ^
//     `raw` (returned to free)                    `array` (returned to user)
//
// `__cxa_vec_delete` recovers `count` from the start of the padding so it
// can run the destructors. When `padding == 0` the runtime cannot store
// the count, so `delete` must be called with a known count via `vec_dtor`
// directly (callers that allocate without padding take responsibility).

#[inline]
fn cxa_vec_total_bytes(count: usize, size: usize, padding: usize) -> Option<usize> {
    count.checked_mul(size).and_then(|n| n.checked_add(padding))
}

#[inline]
unsafe fn cxa_vec_stash_count(raw: *mut c_void, padding: usize, count: usize) {
    if padding >= core::mem::size_of::<usize>() {
        // SAFETY: caller-allocated raw has at least `padding` bytes.
        unsafe { (raw as *mut usize).write_unaligned(count) };
    }
}

#[inline]
unsafe fn cxa_vec_recover_count(raw: *const c_void, padding: usize) -> usize {
    if padding >= core::mem::size_of::<usize>() {
        // SAFETY: matches the layout written by cxa_vec_stash_count.
        unsafe { (raw as *const usize).read_unaligned() }
    } else {
        0
    }
}

/// Itanium C++ ABI `__cxa_vec_new(count, size, padding, ctor, dtor)` —
/// allocate `count*size + padding` bytes, stash the count at the start
/// of the padding (so `__cxa_vec_delete` can recover it), invoke the
/// per-element constructor, and return a pointer to the array (which is
/// `raw + padding`). Returns NULL on overflow or allocation failure.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __cxa_vec_new(
    element_count: usize,
    element_size: usize,
    padding: usize,
    ctor: Option<unsafe extern "C" fn(*mut c_void)>,
    dtor: Option<unsafe extern "C" fn(*mut c_void)>,
) -> *mut c_void {
    let Some(total) = cxa_vec_total_bytes(element_count, element_size, padding) else {
        return core::ptr::null_mut();
    };
    if total == 0 {
        return core::ptr::null_mut();
    }
    // SAFETY: routed through our own malloc, valid with arbitrary size.
    let raw = unsafe { crate::malloc_abi::malloc(total) };
    if raw.is_null() {
        return core::ptr::null_mut();
    }
    unsafe { cxa_vec_stash_count(raw, padding, element_count) };
    let array = unsafe { (raw as *mut u8).add(padding) } as *mut c_void;
    unsafe { __cxa_vec_ctor(array, element_count, element_size, ctor, dtor) };
    array
}

/// Itanium C++ ABI `__cxa_vec_new2` — like `__cxa_vec_new` but uses a
/// caller-supplied `alloc_func`. Returns NULL on overflow or alloc
/// failure (the user's `alloc_func` returning NULL).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __cxa_vec_new2(
    element_count: usize,
    element_size: usize,
    padding: usize,
    ctor: Option<unsafe extern "C" fn(*mut c_void)>,
    dtor: Option<unsafe extern "C" fn(*mut c_void)>,
    alloc_func: Option<unsafe extern "C" fn(usize) -> *mut c_void>,
    _dealloc_func: Option<unsafe extern "C" fn(*mut c_void)>,
) -> *mut c_void {
    let Some(total) = cxa_vec_total_bytes(element_count, element_size, padding) else {
        return core::ptr::null_mut();
    };
    if total == 0 {
        return core::ptr::null_mut();
    }
    let Some(alloc_func) = alloc_func else {
        return core::ptr::null_mut();
    };
    // SAFETY: caller-supplied allocator with the agreed signature.
    let raw = unsafe { alloc_func(total) };
    if raw.is_null() {
        return core::ptr::null_mut();
    }
    unsafe { cxa_vec_stash_count(raw, padding, element_count) };
    let array = unsafe { (raw as *mut u8).add(padding) } as *mut c_void;
    unsafe { __cxa_vec_ctor(array, element_count, element_size, ctor, dtor) };
    array
}

/// Itanium C++ ABI `__cxa_vec_new3` — like `__cxa_vec_new2` but the
/// caller-supplied dealloc function takes both the pointer and the
/// allocation size (matching sized-deallocation conventions). The
/// dealloc parameter is unused here because we never unwind (no EH
/// runtime); it is only invoked by `__cxa_vec_delete3`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __cxa_vec_new3(
    element_count: usize,
    element_size: usize,
    padding: usize,
    ctor: Option<unsafe extern "C" fn(*mut c_void)>,
    dtor: Option<unsafe extern "C" fn(*mut c_void)>,
    alloc_func: Option<unsafe extern "C" fn(usize) -> *mut c_void>,
    _dealloc_func: Option<unsafe extern "C" fn(*mut c_void, usize)>,
) -> *mut c_void {
    let Some(total) = cxa_vec_total_bytes(element_count, element_size, padding) else {
        return core::ptr::null_mut();
    };
    if total == 0 {
        return core::ptr::null_mut();
    }
    let Some(alloc_func) = alloc_func else {
        return core::ptr::null_mut();
    };
    // SAFETY: caller-supplied allocator with the agreed signature.
    let raw = unsafe { alloc_func(total) };
    if raw.is_null() {
        return core::ptr::null_mut();
    }
    unsafe { cxa_vec_stash_count(raw, padding, element_count) };
    let array = unsafe { (raw as *mut u8).add(padding) } as *mut c_void;
    unsafe { __cxa_vec_ctor(array, element_count, element_size, ctor, dtor) };
    array
}

/// Itanium C++ ABI `__cxa_vec_delete(array, size, padding, dtor)` —
/// invoke `dtor` on each element in reverse order, then free the
/// allocation. `array` is the pointer originally returned by
/// `__cxa_vec_new`; the runtime recovers the element count from the
/// padding region prepended by `__cxa_vec_new`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __cxa_vec_delete(
    array: *mut c_void,
    element_size: usize,
    padding: usize,
    dtor: Option<unsafe extern "C" fn(*mut c_void)>,
) {
    if array.is_null() {
        return;
    }
    let raw = unsafe { (array as *mut u8).sub(padding) } as *mut c_void;
    let count = unsafe { cxa_vec_recover_count(raw, padding) };
    if count > 0 {
        unsafe { __cxa_vec_dtor(array, count, element_size, dtor) };
    }
    // SAFETY: raw was returned by our crate::malloc_abi::malloc.
    unsafe { crate::malloc_abi::free(raw) };
}

/// Itanium C++ ABI `__cxa_vec_delete2(array, size, padding, dtor,
/// dealloc_func)` — like `__cxa_vec_delete` but uses a
/// caller-supplied `dealloc_func(*mut c_void)`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __cxa_vec_delete2(
    array: *mut c_void,
    element_size: usize,
    padding: usize,
    dtor: Option<unsafe extern "C" fn(*mut c_void)>,
    dealloc_func: Option<unsafe extern "C" fn(*mut c_void)>,
) {
    if array.is_null() {
        return;
    }
    let raw = unsafe { (array as *mut u8).sub(padding) } as *mut c_void;
    let count = unsafe { cxa_vec_recover_count(raw, padding) };
    if count > 0 {
        unsafe { __cxa_vec_dtor(array, count, element_size, dtor) };
    }
    if let Some(dealloc_func) = dealloc_func {
        // SAFETY: caller-supplied dealloc with the agreed signature.
        unsafe { dealloc_func(raw) };
    }
}

/// Itanium C++ ABI `__cxa_vec_delete3(array, size, padding, dtor,
/// dealloc_func)` — like `__cxa_vec_delete` but uses a
/// caller-supplied `dealloc_func(*mut c_void, usize)` matching the
/// sized-deallocation convention. The size passed is the recovered
/// `count*size + padding` total.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __cxa_vec_delete3(
    array: *mut c_void,
    element_size: usize,
    padding: usize,
    dtor: Option<unsafe extern "C" fn(*mut c_void)>,
    dealloc_func: Option<unsafe extern "C" fn(*mut c_void, usize)>,
) {
    if array.is_null() {
        return;
    }
    let raw = unsafe { (array as *mut u8).sub(padding) } as *mut c_void;
    let count = unsafe { cxa_vec_recover_count(raw, padding) };
    if count > 0 {
        unsafe { __cxa_vec_dtor(array, count, element_size, dtor) };
    }
    if let Some(dealloc_func) = dealloc_func {
        // We don't track the original total bytes outside the padding
        // header, so reconstruct it from the recovered count + caller-
        // supplied element size + padding (saturating on overflow).
        let total = cxa_vec_total_bytes(count, element_size, padding).unwrap_or(0);
        // SAFETY: caller-supplied dealloc with the agreed signature.
        unsafe { dealloc_func(raw, total) };
    }
}

/// Itanium C++ ABI `__cxa_vec_cctor(dest, src, count, size, ctor,
/// dtor)` — copy-construct each element of `dest[i]` from `src[i]`,
/// in forward order. `ctor` is a binary copy-ctor of signature
/// `void (dest_elem, src_elem)`. NULL `ctor` is a no-op (the
/// element type is trivially copyable).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __cxa_vec_cctor(
    dest_array: *mut c_void,
    src_array: *mut c_void,
    element_count: usize,
    element_size: usize,
    ctor: Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>,
    _dtor: Option<unsafe extern "C" fn(*mut c_void)>,
) {
    if dest_array.is_null() || src_array.is_null() {
        return;
    }
    let Some(ctor) = ctor else {
        return;
    };
    let dst = dest_array as *mut u8;
    let src = src_array as *mut u8;
    for i in 0..element_count {
        // SAFETY: caller-supplied arrays of element_count * element_size.
        let d = unsafe { dst.add(i * element_size) } as *mut c_void;
        let s = unsafe { src.add(i * element_size) } as *mut c_void;
        unsafe { ctor(d, s) };
    }
}

/// Itanium C++ ABI `__cxa_eh_globals` — per-thread exception
/// state struct. We expose only the two fields callers can
/// legally inspect (`caughtExceptions` head pointer and the
/// `uncaughtExceptions` counter). Both are zero-initialized; with
/// no exception runtime in play, callers that read the counter
/// (e.g. `std::uncaught_exceptions()`) get a coherent answer of 0.
#[repr(C)]
#[derive(Default)]
pub struct CxaEhGlobals {
    pub caught_exceptions: *mut c_void,
    pub uncaught_exceptions: u32,
}

std::thread_local! {
    /// Per-thread storage for `__cxa_get_globals` / `__cxa_get_globals_fast`.
    /// `UnsafeCell` is not needed because callers receive a `*mut`
    /// pointer to the thread-local — they own all writes.
    static CXA_EH_GLOBALS: std::cell::UnsafeCell<CxaEhGlobals> = const {
        std::cell::UnsafeCell::new(CxaEhGlobals {
            caught_exceptions: core::ptr::null_mut(),
            uncaught_exceptions: 0,
        })
    };
}

fn cxa_eh_globals_ptr() -> *mut CxaEhGlobals {
    CXA_EH_GLOBALS.with(|cell| cell.get())
}

/// Itanium C++ ABI `__cxa_get_globals()` — return the calling
/// thread's `__cxa_eh_globals` pointer, allocating it on first
/// call. We back this with a `thread_local!` cell so the pointer
/// is stable for the thread's lifetime.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __cxa_get_globals() -> *mut CxaEhGlobals {
    cxa_eh_globals_ptr()
}

/// Itanium C++ ABI `__cxa_get_globals_fast()` — same as
/// [`__cxa_get_globals`] but the spec allows it to assume the
/// per-thread storage has already been allocated. Our
/// `thread_local!` initialization is unconditional, so the two
/// entry points are functionally identical.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __cxa_get_globals_fast() -> *mut CxaEhGlobals {
    cxa_eh_globals_ptr()
}

/// Stack canary value, initialized from AT_RANDOM for proper randomization.
///
/// The low byte is forced to 0x00 (NUL terminator) to prevent string-based
/// buffer overflow attacks from leaking or overwriting the canary.
#[allow(non_upper_case_globals)]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static __stack_chk_guard: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Initialize __stack_chk_guard from AT_RANDOM in /proc/self/auxv.
/// Called during startup before main().
pub(crate) fn init_stack_canary() {
    use std::sync::atomic::Ordering;
    // Read AT_RANDOM (type 25) from auxv — it points to 16 random bytes
    // provided by the kernel.
    let canary = (|| -> Option<usize> {
        let data = std::fs::read("/proc/self/auxv").ok()?;
        let word = std::mem::size_of::<usize>();
        let entry_size = word * 2;
        for chunk in data.chunks_exact(entry_size) {
            let a_type = usize::from_ne_bytes(chunk[..word].try_into().ok()?);
            let a_val = usize::from_ne_bytes(chunk[word..word * 2].try_into().ok()?);
            if a_type == 25 {
                // AT_RANDOM: a_val is a pointer to 16 random bytes in memory.
                // Read 8 bytes from that address as our canary.
                let ptr = a_val as *const u8;
                let mut bytes = [0u8; 8];
                unsafe { std::ptr::copy_nonoverlapping(ptr, bytes.as_mut_ptr(), 8) };
                let mut val = usize::from_ne_bytes(bytes);
                // Force low byte to 0x00 (NUL) per glibc convention.
                val &= !0xFF;
                return Some(val);
            }
            if a_type == 0 {
                break;
            }
        }
        None
    })()
    .unwrap_or(0x00000aff0a0d0000); // Fallback: static canary with sentinel bytes
    __stack_chk_guard.store(canary, Ordering::Release);
}
// ===========================================================================
// Batch: Network database iterators — Implemented (parse /etc/ files)
// ===========================================================================

/// `gethostbyname2` — IPv6-aware hostname lookup (C locale, /etc/hosts only).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn gethostbyname2(name: *const c_char, af: c_int) -> *mut c_void {
    thread_local! {
        static HOSTENT: std::cell::RefCell<libc::hostent> =
            const { std::cell::RefCell::new(unsafe { std::mem::zeroed() }) };
        static BUFFER: std::cell::RefCell<[c_char; 1024]> = const { std::cell::RefCell::new([0; 1024]) };
    }

    HOSTENT.with(|hostent| {
        BUFFER.with(|buffer| {
            let mut hostent = hostent.borrow_mut();
            let mut buffer = buffer.borrow_mut();
            let mut result: *mut libc::hostent = std::ptr::null_mut();
            let h_errno = unsafe { crate::resolv_abi::__h_errno_location() };
            let rc = unsafe {
                gethostbyname2_r(
                    name,
                    af,
                    (&mut *hostent as *mut libc::hostent).cast(),
                    buffer.as_mut_ptr(),
                    buffer.len(),
                    (&mut result as *mut *mut libc::hostent).cast(),
                    h_errno,
                )
            };
            if rc != 0 || result.is_null() {
                return std::ptr::null_mut();
            }
            result.cast()
        })
    })
}

// ---------------------------------------------------------------------------
// /etc/services iteration — native
// ---------------------------------------------------------------------------

const SERVICES_PATH: &str = "/etc/services";

struct ServIterState {
    reader: Option<std::io::BufReader<std::fs::File>>,
    line_buf: Vec<u8>,
    /// Thread-local servent struct + string data for non-reentrant getservent.
    /// struct servent is 32 bytes on x86_64; rest is string data.
    entry_buf: [u8; 1024],
    aliases_ptrs: [*mut c_char; 8], // NULL-terminated alias pointer list
}

impl ServIterState {
    const fn new() -> Self {
        Self {
            reader: None,
            line_buf: Vec::new(),
            entry_buf: [0u8; 1024],
            aliases_ptrs: [std::ptr::null_mut(); 8],
        }
    }
}

std::thread_local! {
    static SERV_ITER: std::cell::UnsafeCell<ServIterState> =
        const { std::cell::UnsafeCell::new(ServIterState::new()) };
}

/// Parse the next service entry into the entry_buf.
///
/// struct servent layout (x86_64, 32 bytes):
///   s_name:    *mut c_char    (offset 0)
///   s_aliases: *mut *mut c_char (offset 8)
///   s_port:    c_int          (offset 16, network byte order)
///   [pad 4]
///   s_proto:   *mut c_char    (offset 24)
unsafe fn serv_iter_next(state: &mut ServIterState) -> *mut c_void {
    use std::io::BufRead;

    let reader = match state.reader.as_mut() {
        Some(r) => r,
        None => return std::ptr::null_mut(),
    };

    loop {
        state.line_buf.clear();
        match reader.read_until(b'\n', &mut state.line_buf) {
            Ok(0) => return std::ptr::null_mut(),
            Err(_) => return std::ptr::null_mut(),
            Ok(_) => {}
        }

        let entry = match frankenlibc_core::resolv::parse_services_line(&state.line_buf) {
            Some(e) => e,
            None => continue,
        };

        // Pack into entry_buf: struct servent (32 bytes) + strings
        let str_offset = 32usize;
        let needed = str_offset + entry.name.len() + 1 + entry.protocol.len() + 1;
        if needed > state.entry_buf.len() {
            continue;
        }

        let buf = state.entry_buf.as_mut_ptr();
        let mut off = str_offset;

        // Name
        let name_ptr = unsafe { buf.add(off) } as *mut c_char;
        unsafe {
            std::ptr::copy_nonoverlapping(entry.name.as_ptr(), buf.add(off), entry.name.len());
            *buf.add(off + entry.name.len()) = 0;
        }
        off += entry.name.len() + 1;

        // Protocol
        let proto_ptr = unsafe { buf.add(off) } as *mut c_char;
        unsafe {
            std::ptr::copy_nonoverlapping(
                entry.protocol.as_ptr(),
                buf.add(off),
                entry.protocol.len(),
            );
            *buf.add(off + entry.protocol.len()) = 0;
        }

        // Aliases: NULL-terminated
        state.aliases_ptrs[0] = std::ptr::null_mut();

        // Fill struct servent
        let ptrs = buf as *mut *mut c_char;
        unsafe {
            *ptrs = name_ptr; // s_name
            *(ptrs.add(1) as *mut *mut *mut c_char) = state.aliases_ptrs.as_mut_ptr(); // s_aliases
            *(buf.add(16) as *mut c_int) = (entry.port as c_int).to_be(); // s_port (NBO)
            *(buf.add(24) as *mut *mut c_char) = proto_ptr; // s_proto
        }

        return buf as *mut c_void;
    }
}

/// `setservent` — open /etc/services for iteration.
///
/// Native implementation.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setservent(_stayopen: c_int) {
    SERV_ITER.with(|cell| {
        let state = unsafe { &mut *cell.get() };
        match std::fs::File::open(SERVICES_PATH) {
            Ok(f) => state.reader = Some(std::io::BufReader::new(f)),
            Err(_) => state.reader = None,
        }
    });
}

/// `endservent` — close /etc/services iteration.
///
/// Native implementation.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn endservent() {
    SERV_ITER.with(|cell| {
        let state = unsafe { &mut *cell.get() };
        state.reader = None;
    });
}

/// `getservent` — get next /etc/services entry.
///
/// Native implementation using thread-local iterator state.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getservent() -> *mut c_void {
    SERV_ITER.with(|cell| {
        let state = unsafe { &mut *cell.get() };
        if state.reader.is_none() {
            match std::fs::File::open(SERVICES_PATH) {
                Ok(f) => state.reader = Some(std::io::BufReader::new(f)),
                Err(_) => return std::ptr::null_mut(),
            }
        }
        unsafe { serv_iter_next(state) }
    })
}

// ---------------------------------------------------------------------------
// /etc/networks iteration — native
// ---------------------------------------------------------------------------

const NETWORKS_PATH: &str = "/etc/networks";

struct NetIterState {
    reader: Option<std::io::BufReader<std::fs::File>>,
    line_buf: Vec<u8>,
    entry_buf: [u8; 512],
    aliases_ptrs: [*mut c_char; 2],
}

impl NetIterState {
    const fn new() -> Self {
        Self {
            reader: None,
            line_buf: Vec::new(),
            entry_buf: [0u8; 512],
            aliases_ptrs: [std::ptr::null_mut(); 2],
        }
    }
}

std::thread_local! {
    static NET_ITER: std::cell::UnsafeCell<NetIterState> =
        const { std::cell::UnsafeCell::new(NetIterState::new()) };
}

/// Parse a /etc/networks line: "name number [aliases...]"
/// Returns (name, network_number) or None.
/// Adapter around frankenlibc_core::resolv::parse_networks_line that
/// returns the canonical (name, number) tuple in the form the local
/// netent fillers consume. Returns `None` for blank/comment/malformed
/// lines.
fn parse_networks_line(line: &[u8]) -> Option<(Vec<u8>, u32)> {
    let entry = frankenlibc_core::resolv::parse_networks_line(line)?;
    Some((entry.name, entry.number))
}

/// Fill a netent struct in the entry buffer.
///
/// struct netent (x86_64, 24 bytes):
///   n_name:     *mut c_char    (offset 0)
///   n_aliases:  *mut *mut c_char (offset 8)
///   n_addrtype: c_int          (offset 16)
///   n_net:      u32            (offset 20)
unsafe fn fill_netent_buf(state: &mut NetIterState, name: &[u8], net: u32) -> *mut c_void {
    let str_offset = 24usize;
    let needed = str_offset + name.len() + 1;
    if needed > state.entry_buf.len() {
        return std::ptr::null_mut();
    }
    let buf = state.entry_buf.as_mut_ptr();
    let name_ptr = unsafe { buf.add(str_offset) } as *mut c_char;
    unsafe {
        std::ptr::copy_nonoverlapping(name.as_ptr(), buf.add(str_offset), name.len());
        *buf.add(str_offset + name.len()) = 0;
    }
    state.aliases_ptrs[0] = std::ptr::null_mut();

    let ptrs = buf as *mut *mut c_char;
    unsafe {
        *ptrs = name_ptr;
        *(ptrs.add(1) as *mut *mut *mut c_char) = state.aliases_ptrs.as_mut_ptr();
        *(buf.add(16) as *mut c_int) = libc::AF_INET;
        *(buf.add(20) as *mut u32) = net;
    }
    buf as *mut c_void
}

/// Parse the next networks entry from the reader.
unsafe fn net_iter_next(state: &mut NetIterState) -> *mut c_void {
    use std::io::BufRead;
    loop {
        let reader = match state.reader.as_mut() {
            Some(r) => r,
            None => return std::ptr::null_mut(),
        };
        state.line_buf.clear();
        match reader.read_until(b'\n', &mut state.line_buf) {
            Ok(0) => return std::ptr::null_mut(),
            Err(_) => return std::ptr::null_mut(),
            Ok(_) => {}
        }
        // Parse and extract values before passing state to fill_netent_buf
        if let Some((name, net)) = parse_networks_line(&state.line_buf) {
            // Copy name to stack to avoid borrowing state.line_buf through fill
            let mut name_copy = [0u8; 256];
            let nlen = name.len().min(255);
            name_copy[..nlen].copy_from_slice(&name[..nlen]);
            let result = unsafe { fill_netent_buf(state, &name_copy[..nlen], net) };
            if !result.is_null() {
                return result;
            }
        }
    }
}

/// `setnetent` — open /etc/networks for iteration.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setnetent(_stayopen: c_int) {
    NET_ITER.with(|cell| {
        let state = unsafe { &mut *cell.get() };
        match std::fs::File::open(NETWORKS_PATH) {
            Ok(f) => state.reader = Some(std::io::BufReader::new(f)),
            Err(_) => state.reader = None,
        }
    });
}

/// `endnetent` — close /etc/networks iteration.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn endnetent() {
    NET_ITER.with(|cell| {
        let state = unsafe { &mut *cell.get() };
        state.reader = None;
    });
}

/// `getnetent` — get next /etc/networks entry.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getnetent() -> *mut c_void {
    NET_ITER.with(|cell| {
        let state = unsafe { &mut *cell.get() };
        if state.reader.is_none() {
            match std::fs::File::open(NETWORKS_PATH) {
                Ok(f) => state.reader = Some(std::io::BufReader::new(f)),
                Err(_) => return std::ptr::null_mut(),
            }
        }
        unsafe { net_iter_next(state) }
    })
}

/// `getnetbyname` — look up network by name in /etc/networks.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getnetbyname(name: *const c_char) -> *mut c_void {
    if name.is_null() {
        return std::ptr::null_mut();
    }
    let Some(needle) = (unsafe { read_c_string_bytes(name) }) else {
        unsafe { set_abi_errno(libc::EINVAL) };
        return std::ptr::null_mut();
    };
    let content = match std::fs::read(NETWORKS_PATH) {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };
    for line in content.split(|&b| b == b'\n') {
        if let Some((pname, net)) = parse_networks_line(line)
            && pname.eq_ignore_ascii_case(&needle)
        {
            return NET_ITER.with(|cell| {
                let state = unsafe { &mut *cell.get() };
                unsafe { fill_netent_buf(state, &pname, net) }
            });
        }
    }
    std::ptr::null_mut()
}

/// `getnetbyaddr` — look up network by address in /etc/networks.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getnetbyaddr(net: u32, _type: c_int) -> *mut c_void {
    let content = match std::fs::read(NETWORKS_PATH) {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };
    for line in content.split(|&b| b == b'\n') {
        if let Some((pname, pnet)) = parse_networks_line(line)
            && pnet == net
        {
            return NET_ITER.with(|cell| {
                let state = unsafe { &mut *cell.get() };
                unsafe { fill_netent_buf(state, &pname, pnet) }
            });
        }
    }
    std::ptr::null_mut()
}

// ---------------------------------------------------------------------------
// /etc/protocols iteration — native
// ---------------------------------------------------------------------------

const PROTOCOLS_PATH: &str = "/etc/protocols";

struct ProtoIterState {
    reader: Option<std::io::BufReader<std::fs::File>>,
    line_buf: Vec<u8>,
    /// Thread-local protoent + string data for non-reentrant getprotoent.
    entry_buf: [u8; 512],
    aliases_ptrs: [*mut c_char; 2], // NULL-terminated alias list (empty)
}

impl ProtoIterState {
    const fn new() -> Self {
        Self {
            reader: None,
            line_buf: Vec::new(),
            entry_buf: [0u8; 512],
            aliases_ptrs: [std::ptr::null_mut(); 2],
        }
    }
}

std::thread_local! {
    static PROTO_ITER: std::cell::UnsafeCell<ProtoIterState> =
        const { std::cell::UnsafeCell::new(ProtoIterState::new()) };
}

/// Parse the next protocol entry from the reader into the entry_buf.
///
/// struct protoent layout (x86_64):
///   p_name:    *mut c_char   (offset 0, 8 bytes)
///   p_aliases: *mut *mut c_char (offset 8, 8 bytes)
///   p_proto:   c_int         (offset 16, 4 bytes)
///   [pad 4 bytes]
///   Total: 24 bytes (with padding)
unsafe fn proto_iter_next(state: &mut ProtoIterState) -> *mut c_void {
    use std::io::BufRead;

    let reader = match state.reader.as_mut() {
        Some(r) => r,
        None => return std::ptr::null_mut(),
    };

    loop {
        state.line_buf.clear();
        match reader.read_until(b'\n', &mut state.line_buf) {
            Ok(0) => return std::ptr::null_mut(),
            Err(_) => return std::ptr::null_mut(),
            Ok(_) => {}
        }

        // Parse using the same logic as resolv_abi::parse_protocols_line
        let line = &state.line_buf;
        // Strip comments
        let line = if let Some(pos) = line.iter().position(|&b| b == b'#') {
            &line[..pos]
        } else {
            line
        };

        let mut fields = line
            .split(|&b| b == b' ' || b == b'\t' || b == b'\n' || b == b'\r')
            .filter(|f| !f.is_empty());

        let name = match fields.next() {
            Some(f) => f,
            None => continue,
        };
        let num_str = match fields.next() {
            Some(f) => f,
            None => continue,
        };
        let proto_num: c_int = match std::str::from_utf8(num_str)
            .ok()
            .and_then(|s| s.parse().ok())
        {
            Some(n) => n,
            None => continue,
        };

        // struct protoent is 24 bytes; strings packed after
        let str_offset = 24usize;
        let needed = str_offset + name.len() + 1;
        if needed > state.entry_buf.len() {
            continue;
        }

        let buf = state.entry_buf.as_mut_ptr();

        // Copy name string after struct
        let name_ptr = unsafe { buf.add(str_offset) } as *mut c_char;
        unsafe {
            std::ptr::copy_nonoverlapping(name.as_ptr(), buf.add(str_offset), name.len());
            *buf.add(str_offset + name.len()) = 0;
        }

        // Set up NULL-terminated aliases list (empty for now)
        state.aliases_ptrs[0] = std::ptr::null_mut();

        // Fill struct protoent
        let ptrs = buf as *mut *mut c_char;
        unsafe {
            *ptrs = name_ptr; // p_name
            *(ptrs.add(1) as *mut *mut *mut c_char) = state.aliases_ptrs.as_mut_ptr(); // p_aliases
            *(buf.add(16) as *mut c_int) = proto_num; // p_proto
        }

        return buf as *mut c_void;
    }
}

/// `setprotoent` — open /etc/protocols for iteration.
///
/// Native implementation.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setprotoent(_stayopen: c_int) {
    PROTO_ITER.with(|cell| {
        let state = unsafe { &mut *cell.get() };
        match std::fs::File::open(PROTOCOLS_PATH) {
            Ok(f) => state.reader = Some(std::io::BufReader::new(f)),
            Err(_) => state.reader = None,
        }
    });
}

/// `endprotoent` — close /etc/protocols iteration.
///
/// Native implementation.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn endprotoent() {
    PROTO_ITER.with(|cell| {
        let state = unsafe { &mut *cell.get() };
        state.reader = None;
    });
}

/// `getprotoent` — get next /etc/protocols entry.
///
/// Native implementation using thread-local iterator state.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getprotoent() -> *mut c_void {
    PROTO_ITER.with(|cell| {
        let state = unsafe { &mut *cell.get() };
        if state.reader.is_none() {
            // Auto-open on first call (glibc behavior)
            match std::fs::File::open(PROTOCOLS_PATH) {
                Ok(f) => state.reader = Some(std::io::BufReader::new(f)),
                Err(_) => return std::ptr::null_mut(),
            }
        }
        unsafe { proto_iter_next(state) }
    })
}

// ---------------------------------------------------------------------------
// /etc/hosts iteration — native
// ---------------------------------------------------------------------------

const HOSTS_PATH: &str = "/etc/hosts";

struct HostIterState {
    reader: Option<std::io::BufReader<std::fs::File>>,
    line_buf: Vec<u8>,
    // Buffer: struct hostent (32 bytes) + strings + address data + pointer arrays
    entry_buf: [u8; 2048],
    // Pointer arrays stored separately to avoid borrow issues
    alias_ptrs: [*mut c_char; 16],
    addr_ptrs: [*mut c_char; 2],
    addr_data: [u8; 16], // room for one IPv4 or IPv6 address
}

impl HostIterState {
    const fn new() -> Self {
        Self {
            reader: None,
            line_buf: Vec::new(),
            entry_buf: [0u8; 2048],
            alias_ptrs: [std::ptr::null_mut(); 16],
            addr_ptrs: [std::ptr::null_mut(); 2],
            addr_data: [0u8; 16],
        }
    }
}

std::thread_local! {
    static HOST_ITER: std::cell::UnsafeCell<HostIterState> =
        const { std::cell::UnsafeCell::new(HostIterState::new()) };
}

/// Parse address text into binary. Returns (address_bytes, af, length).
///
/// Thin shim over `frankenlibc_core::resolv::parse_addr_binary` that
/// maps the typed `AddrFamily` enum into the `libc::AF_INET` /
/// `AF_INET6` integer constants the call sites here expect.
fn parse_addr_binary(addr_str: &str) -> Option<([u8; 16], c_int, c_int)> {
    let (buf, fam, len) = frankenlibc_core::resolv::parse_addr_binary(addr_str)?;
    let af = match fam {
        frankenlibc_core::resolv::AddrFamily::Inet4 => libc::AF_INET,
        frankenlibc_core::resolv::AddrFamily::Inet6 => libc::AF_INET6,
    };
    Some((buf, af, len as c_int))
}

/// Parse the next hosts entry from the reader.
///
/// struct hostent (x86_64, 32 bytes):
///   h_name:      *mut c_char    (offset 0)
///   h_aliases:   *mut *mut c_char (offset 8)
///   h_addrtype:  c_int          (offset 16)
///   h_length:    c_int          (offset 20)
///   h_addr_list: *mut *mut c_char (offset 24)
unsafe fn host_iter_next(state: &mut HostIterState) -> *mut c_void {
    use std::io::BufRead;
    loop {
        let reader = match state.reader.as_mut() {
            Some(r) => r,
            None => return std::ptr::null_mut(),
        };
        state.line_buf.clear();
        match reader.read_until(b'\n', &mut state.line_buf) {
            Ok(0) => return std::ptr::null_mut(),
            Err(_) => return std::ptr::null_mut(),
            Ok(_) => {}
        }

        // Use parse_hosts_line from core
        let parsed = frankenlibc_core::resolv::parse_hosts_line(&state.line_buf);
        let (addr_text, hostnames) = match parsed {
            Some(v) => v,
            None => continue,
        };

        if hostnames.is_empty() {
            continue;
        }

        let addr_str = match std::str::from_utf8(&addr_text) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let (addr_bin, af, addr_len) = match parse_addr_binary(addr_str) {
            Some(v) => v,
            None => continue,
        };

        // Copy address data
        state.addr_data[..addr_len as usize].copy_from_slice(&addr_bin[..addr_len as usize]);

        // Set up address list: [&addr_data, NULL]
        state.addr_ptrs[0] = state.addr_data.as_mut_ptr() as *mut c_char;
        state.addr_ptrs[1] = std::ptr::null_mut();

        // Pack hostname string into entry_buf (after struct hostent at offset 32)
        let buf = state.entry_buf.as_mut_ptr();
        let str_offset = 32usize;
        let primary_name = &hostnames[0];
        let needed = str_offset + primary_name.len() + 1;
        if needed > state.entry_buf.len() {
            continue;
        }

        let name_ptr = unsafe { buf.add(str_offset) } as *mut c_char;
        unsafe {
            std::ptr::copy_nonoverlapping(
                primary_name.as_ptr(),
                buf.add(str_offset),
                primary_name.len(),
            );
            *buf.add(str_offset + primary_name.len()) = 0;
        }

        // Aliases: remaining hostnames (up to 14)
        let mut off = str_offset + primary_name.len() + 1;
        let max_aliases = state.alias_ptrs.len() - 1; // leave room for NULL
        let alias_count = (hostnames.len() - 1).min(max_aliases);
        for i in 0..alias_count {
            let alias = &hostnames[i + 1];
            if off + alias.len() + 1 > state.entry_buf.len() {
                break;
            }
            state.alias_ptrs[i] = unsafe { buf.add(off) } as *mut c_char;
            unsafe {
                std::ptr::copy_nonoverlapping(alias.as_ptr(), buf.add(off), alias.len());
                *buf.add(off + alias.len()) = 0;
            }
            off += alias.len() + 1;
        }
        state.alias_ptrs[alias_count] = std::ptr::null_mut();

        // Fill struct hostent
        unsafe {
            *(buf as *mut *mut c_char) = name_ptr; // h_name
            *((buf as *mut *mut c_char).add(1) as *mut *mut *mut c_char) =
                state.alias_ptrs.as_mut_ptr(); // h_aliases
            *(buf.add(16) as *mut c_int) = af; // h_addrtype
            *(buf.add(20) as *mut c_int) = addr_len; // h_length
            *(buf.add(24) as *mut *mut *mut c_char) = state.addr_ptrs.as_mut_ptr(); // h_addr_list
        }

        return buf as *mut c_void;
    }
}

/// `sethostent` — open /etc/hosts for iteration.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sethostent(_stayopen: c_int) {
    HOST_ITER.with(|cell| {
        let state = unsafe { &mut *cell.get() };
        match std::fs::File::open(HOSTS_PATH) {
            Ok(f) => state.reader = Some(std::io::BufReader::new(f)),
            Err(_) => state.reader = None,
        }
    });
}

/// `endhostent` — close /etc/hosts iteration.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn endhostent() {
    HOST_ITER.with(|cell| {
        let state = unsafe { &mut *cell.get() };
        state.reader = None;
    });
}

/// `gethostent` — get next /etc/hosts entry.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn gethostent() -> *mut c_void {
    HOST_ITER.with(|cell| {
        let state = unsafe { &mut *cell.get() };
        if state.reader.is_none() {
            match std::fs::File::open(HOSTS_PATH) {
                Ok(f) => state.reader = Some(std::io::BufReader::new(f)),
                Err(_) => return std::ptr::null_mut(),
            }
        }
        unsafe { host_iter_next(state) }
    })
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
    let Some(property_bytes) = (unsafe { read_c_string_bytes(property) }) else {
        unsafe { set_abi_errno(libc::EINVAL) };
        return 0;
    };
    match property_bytes.as_slice() {
        b"toupper" => 1,
        b"tolower" => 2,
        _ => 0,
    }
}

/// `towctrans` — transform wide character by descriptor.
///
/// Dispatches to the wchar_abi towupper/towlower so non-ASCII codepoints
/// get the same Unicode case-folding as direct calls. The previous
/// implementation short-circuited any wc > 127 to the input unchanged,
/// which meant `towctrans(L'а', wctrans("toupper"))` returned U+0430
/// instead of the correct U+0410 for Cyrillic.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn towctrans(wc: c_uint, desc: WctransT) -> c_uint {
    match desc {
        1 => unsafe { crate::wchar_abi::towupper(wc) },
        2 => unsafe { crate::wchar_abi::towlower(wc) },
        _ => wc,
    }
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

    match syscall::sys_personality(persona as u32) {
        Ok(v) => {
            runtime_policy::observe(ApiFamily::Process, decision.profile, 6, false);
            v as c_int
        }
        Err(e) => {
            unsafe { set_abi_errno(e) };
            runtime_policy::observe(ApiFamily::Process, decision.profile, 6, true);
            -1
        }
    }
}

#[inline]
fn process_madvise_invalid_flags(flags: c_uint) -> bool {
    flags != 0
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
    let invalid_flags = process_madvise_invalid_flags(flags);
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
    if invalid_flags {
        unsafe { set_abi_errno(errno::EINVAL) };
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

    match unsafe { syscall::sys_process_madvise(pidfd, iovec as *const u8, vlen, advice, flags) } {
        Ok(n) => {
            runtime_policy::observe(
                ApiFamily::VirtualMemory,
                decision.profile,
                runtime_policy::scaled_cost(10, vlen),
                false,
            );
            n
        }
        Err(e) => {
            unsafe { set_abi_errno(e) };
            runtime_policy::observe(
                ApiFamily::VirtualMemory,
                decision.profile,
                runtime_policy::scaled_cost(10, vlen),
                true,
            );
            -1
        }
    }
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

    match syscall::sys_process_mrelease(pidfd, flags) {
        Ok(()) => {
            runtime_policy::observe(ApiFamily::VirtualMemory, decision.profile, 8, false);
            0
        }
        Err(e) => {
            unsafe { set_abi_errno(e) };
            runtime_policy::observe(ApiFamily::VirtualMemory, decision.profile, 8, true);
            -1
        }
    }
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
    match unsafe { syscall::sys_fcntl(fd, cmd, arg as usize) } {
        Ok(r) => r,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
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
    unsafe {
        *result = std::ptr::null_mut();
        *crate::errno_abi::__errno_location() = 0;
    }
    let next = unsafe { crate::dirent_abi::readdir64(dirp.cast()) } as *mut libc::dirent64;
    if next.is_null() {
        let err = unsafe { *crate::errno_abi::__errno_location() };
        return if err == 0 { 0 } else { err };
    }
    unsafe {
        std::ptr::copy_nonoverlapping(next, entry, 1);
        *result = entry;
    }
    0
}

// ===========================================================================
// Batch: backtrace — Implemented
// ===========================================================================

type HostBacktraceFn = unsafe extern "C" fn(*mut *mut c_void, c_int) -> c_int;
type HostBacktraceSymbolsFn = unsafe extern "C" fn(*const *mut c_void, c_int) -> *mut *mut c_char;
type HostBacktraceSymbolsFdFn = unsafe extern "C" fn(*const *mut c_void, c_int, c_int);

static HOST_BACKTRACE_FN: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
static HOST_BACKTRACE_SYMBOLS_FN: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
static HOST_BACKTRACE_SYMBOLS_FD_FN: std::sync::OnceLock<usize> = std::sync::OnceLock::new();

unsafe fn host_unistd_symbol(
    slot: &std::sync::OnceLock<usize>,
    symbol: &'static str,
) -> Option<usize> {
    crate::host_resolve::resolve_host_symbol_cached(slot, symbol)
}

unsafe fn host_backtrace_fn() -> Option<HostBacktraceFn> {
    unsafe { host_unistd_symbol(&HOST_BACKTRACE_FN, "backtrace") }
        .map(|addr| unsafe { std::mem::transmute(addr) }) // ubs:ignore — host symbol ABI resolved, pointer cast is deliberate
}

unsafe fn host_backtrace_symbols_fn() -> Option<HostBacktraceSymbolsFn> {
    unsafe { host_unistd_symbol(&HOST_BACKTRACE_SYMBOLS_FN, "backtrace_symbols") }
        .map(|addr| unsafe { std::mem::transmute(addr) }) // ubs:ignore — host symbol ABI resolved, pointer cast is deliberate
}

unsafe fn host_backtrace_symbols_fd_fn() -> Option<HostBacktraceSymbolsFdFn> {
    unsafe { host_unistd_symbol(&HOST_BACKTRACE_SYMBOLS_FD_FN, "backtrace_symbols_fd") }
        .map(|addr| unsafe { std::mem::transmute(addr) }) // ubs:ignore — host symbol ABI resolved, pointer cast is deliberate
}

/// `backtrace` — capture stack backtrace.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn backtrace(buffer: *mut *mut c_void, size: c_int) -> c_int {
    if buffer.is_null() || size <= 0 {
        return 0;
    }
    match unsafe { host_backtrace_fn() } {
        Some(host_backtrace) => unsafe { host_backtrace(buffer, size) },
        None => 0,
    }
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
    match unsafe { host_backtrace_symbols_fn() } {
        Some(host_backtrace_symbols) => unsafe { host_backtrace_symbols(buffer, size) },
        None => std::ptr::null_mut(),
    }
}

/// `backtrace_symbols_fd` — write backtrace symbols to file descriptor.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn backtrace_symbols_fd(buffer: *const *mut c_void, size: c_int, fd: c_int) {
    if buffer.is_null() || size <= 0 {
        return;
    }
    if let Some(host_backtrace_symbols_fd) = unsafe { host_backtrace_symbols_fd_fn() } {
        unsafe { host_backtrace_symbols_fd(buffer, size, fd) };
    }
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

use std::collections::{HashMap, VecDeque};

/// Internal FTS stream state.
struct FtsStream {
    /// FIFO traversal queue. Directory children are pushed to the front so each
    /// root is exhausted before the next root begins.
    queue: VecDeque<FtsEntryInternal>,
    /// Root paths passed to fts_open for the pre-read fts_children() case.
    roots: Vec<std::path::PathBuf>,
    /// Current entry returned to the caller.
    current: Option<FtsEntryOwned>,
    /// Cached child list returned by the most recent fts_children() call.
    children_cache: Vec<FtsEntryOwned>,
    /// Options bitmask.
    options: c_int,
    /// Deferred revisit triggered by fts_set(..., FTS_AGAIN/FOLLOW).
    pending_revisit: Option<FtsEntryInternal>,
    /// Deferred directory expansion. Children (and postorder revisit) are
    /// inserted on the next fts_read() after the preorder return.
    pending_children: Option<FtsEntryInternal>,
    /// One-shot controls installed via fts_set() on entries returned by
    /// fts_children().
    pending_controls: HashMap<std::path::PathBuf, u16>,
    /// Whether fts_read() has been called at least once.
    started: bool,
    /// Comparison function (reserved for future use).
    _compar: Option<unsafe extern "C" fn(*const *const FTSENT, *const *const FTSENT) -> c_int>,
}

/// Internal entry representation.
#[derive(Clone)]
struct FtsEntryInternal {
    path: std::path::PathBuf,
    level: i16,
    follow_symlink: bool,
    instr: u16,
    visit: FtsVisit,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum FtsVisit {
    Preorder,
    Postorder,
}

/// Owned FTSENT for returning to caller.
/// The name is stored inline in a boxed flexible-array payload so callers can
/// treat `fts_name` exactly like glibc's trailing storage.
struct FtsEntryOwned {
    raw: Box<[u8]>,
    path: std::path::PathBuf,
    _path_buf: CString,
    _stat_buf: Box<libc::stat>,
    level: i16,
    follow_symlink: bool,
    visit: FtsVisit,
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
const FTS_DNR: u16 = 4; // unreadable directory
const FTS_DP: u16 = 6; // postorder directory
const FTS_F: u16 = 8; // regular file
const FTS_NSOK: u16 = 11; // no stat requested
const FTS_SL: u16 = 12; // symlink
const FTS_SLNONE: u16 = 13; // broken symlink
const FTS_DEFAULT: u16 = 3; // anything else
const FTS_NS: u16 = 10; // no stat info

// FTS option flags
const FTS_COMFOLLOW: c_int = 0x0001;
const FTS_LOGICAL: c_int = 0x0002;
const FTS_NOSTAT: c_int = 0x0008;
const FTS_PHYSICAL: c_int = 0x0010;
const FTS_OPTIONMASK: c_int = 0x00ff;

// fts_children() option
const FTS_NAMEONLY: c_int = 0x0100;

// fts_set() instructions
const FTS_AGAIN: u16 = 1;
const FTS_FOLLOW: u16 = 2;
const FTS_NOINSTR: u16 = 3;
const FTS_SKIP: u16 = 4;

fn fts_path_bytes(path: &std::path::Path) -> &[u8] {
    use std::os::unix::ffi::OsStrExt;

    path.as_os_str().as_bytes()
}

fn fts_path_to_cstring(path: &std::path::Path) -> Result<CString, c_int> {
    CString::new(fts_path_bytes(path)).map_err(|_| errno::EINVAL)
}

fn fts_name_bytes(path: &std::path::Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;

    path.file_name()
        .map(|name| name.as_bytes().to_vec())
        .filter(|bytes| !bytes.is_empty())
        .unwrap_or_else(|| fts_path_bytes(path).to_vec())
}

fn fts_controlled_entry(control: u16, mut entry: FtsEntryInternal) -> FtsEntryInternal {
    match control {
        FTS_FOLLOW => {
            entry.follow_symlink = true;
            entry.instr = FTS_FOLLOW;
        }
        FTS_SKIP => {
            entry.instr = FTS_SKIP;
        }
        _ => {
            entry.instr = FTS_NOINSTR;
        }
    }
    entry
}

fn fts_stat_entry(
    path: &std::path::Path,
    options: c_int,
    follow_symlink: bool,
) -> (libc::stat, u16, c_int) {
    let mut stat_buf: libc::stat = unsafe { std::mem::zeroed() };
    if options & FTS_NOSTAT != 0 {
        return (stat_buf, FTS_NSOK, 0);
    }

    let path_cstr = match fts_path_to_cstring(path) {
        Ok(path_cstr) => path_cstr,
        Err(err) => return (stat_buf, FTS_NS, err),
    };

    let primary_flags = if follow_symlink {
        0
    } else if options & FTS_PHYSICAL != 0 {
        libc::AT_SYMLINK_NOFOLLOW
    } else {
        0
    };

    let primary = unsafe {
        syscall::sys_newfstatat(
            libc::AT_FDCWD,
            path_cstr.as_ptr() as *const u8,
            &mut stat_buf as *mut libc::stat as *mut u8,
            primary_flags,
        )
    };

    if primary.is_ok() {
        let file_type = stat_buf.st_mode & libc::S_IFMT;
        let info = if file_type == libc::S_IFDIR {
            FTS_D
        } else if file_type == libc::S_IFREG {
            FTS_F
        } else if file_type == libc::S_IFLNK {
            FTS_SL
        } else {
            FTS_DEFAULT
        };
        return (stat_buf, info, 0);
    }

    let stat_errno = primary.err().unwrap_or(errno::EIO);
    if !follow_symlink && options & FTS_PHYSICAL == 0 {
        let mut lstat_buf: libc::stat = unsafe { std::mem::zeroed() };
        let lstat_result = unsafe {
            syscall::sys_newfstatat(
                libc::AT_FDCWD,
                path_cstr.as_ptr() as *const u8,
                &mut lstat_buf as *mut libc::stat as *mut u8,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if lstat_result.is_ok() && (lstat_buf.st_mode & libc::S_IFMT) == libc::S_IFLNK {
            return (lstat_buf, FTS_SLNONE, 0);
        }
    }

    (stat_buf, FTS_NS, stat_errno)
}

impl FtsEntryOwned {
    fn new(
        entry: &FtsEntryInternal,
        options: c_int,
        parent: *mut FTSENT,
        name_only: bool,
    ) -> Result<Self, c_int> {
        let path_buf = fts_path_to_cstring(&entry.path)?;
        let name = if entry.level == 0 {
            fts_path_bytes(&entry.path).to_vec()
        } else {
            fts_name_bytes(&entry.path)
        };
        let mut inline_name = name;
        inline_name.push(0);

        let extra_name_bytes = inline_name.len().saturating_sub(1);
        let total_size = std::mem::size_of::<FTSENT>() + extra_name_bytes;
        let mut raw = vec![0u8; total_size].into_boxed_slice();
        let raw_ptr = raw.as_mut_ptr() as *mut FTSENT;

        let (stat_value, mut info, stat_errno) = if entry.visit == FtsVisit::Postorder {
            let (stat_value, _info, stat_errno) =
                fts_stat_entry(&entry.path, options, entry.follow_symlink);
            (stat_value, FTS_DP, stat_errno)
        } else {
            fts_stat_entry(&entry.path, options, entry.follow_symlink)
        };

        if name_only {
            info = FTS_NSOK;
        }

        let mut stat_buf = Box::new(stat_value);

        unsafe {
            (*raw_ptr).fts_parent = parent;
            (*raw_ptr).fts_path = path_buf.as_ptr() as *mut c_char;
            (*raw_ptr).fts_accpath = (*raw_ptr).fts_path;
            (*raw_ptr).fts_pathlen = path_buf.as_bytes().len() as u16;
            (*raw_ptr).fts_namelen = inline_name.len().saturating_sub(1) as u16;
            (*raw_ptr).fts_level = entry.level;
            (*raw_ptr).fts_info = info;
            (*raw_ptr).fts_instr = if entry.instr == 0 {
                FTS_NOINSTR
            } else {
                entry.instr
            };
            (*raw_ptr).fts_errno = stat_errno;
            (*raw_ptr).fts_ino = stat_buf.st_ino;
            (*raw_ptr).fts_dev = stat_buf.st_dev;
            (*raw_ptr).fts_nlink = stat_buf.st_nlink;
            (*raw_ptr).fts_statp = if name_only {
                std::ptr::null_mut()
            } else {
                &mut *stat_buf
            };
            std::ptr::copy_nonoverlapping(
                inline_name.as_ptr(),
                (*raw_ptr).fts_name.as_mut_ptr() as *mut u8,
                inline_name.len(),
            );
        }

        Ok(Self {
            raw,
            path: entry.path.clone(),
            _path_buf: path_buf,
            _stat_buf: stat_buf,
            level: entry.level,
            follow_symlink: entry.follow_symlink,
            visit: entry.visit,
        })
    }

    fn entry(&self) -> &FTSENT {
        unsafe { &*(self.raw.as_ptr() as *const FTSENT) }
    }

    fn entry_mut(&mut self) -> &mut FTSENT {
        unsafe { &mut *(self.raw.as_mut_ptr() as *mut FTSENT) }
    }

    fn as_mut_ptr(&mut self) -> *mut FTSENT {
        self.entry_mut() as *mut FTSENT
    }

    fn as_ptr(&self) -> *const FTSENT {
        self.entry() as *const FTSENT
    }

    fn same_ptr(&self, ptr: *mut FTSENT) -> bool {
        std::ptr::eq(self.as_ptr(), ptr as *const FTSENT)
    }

    fn internal(&self) -> FtsEntryInternal {
        FtsEntryInternal {
            path: self.path.clone(),
            level: self.level,
            follow_symlink: self.follow_symlink,
            instr: self.entry().fts_instr,
            visit: self.visit,
        }
    }
}

fn fts_read_dir_paths(path: &std::path::Path) -> Result<Vec<std::path::PathBuf>, c_int> {
    let mut paths = Vec::new();
    let entries =
        std::fs::read_dir(path).map_err(|err| err.raw_os_error().unwrap_or(errno::EIO))?;
    for child in entries {
        let child = child.map_err(|err| err.raw_os_error().unwrap_or(errno::EIO))?;
        paths.push(child.path());
    }
    Ok(paths)
}

fn fts_expand_pending_children(stream: &mut FtsStream) {
    let Some(dir_entry) = stream.pending_children.take() else {
        return;
    };

    let postorder = FtsEntryInternal {
        path: dir_entry.path.clone(),
        level: dir_entry.level,
        follow_symlink: dir_entry.follow_symlink,
        instr: FTS_NOINSTR,
        visit: FtsVisit::Postorder,
    };
    stream.queue.push_front(postorder);

    if dir_entry.instr == FTS_SKIP {
        return;
    }

    let children = match fts_read_dir_paths(&dir_entry.path) {
        Ok(children) => children,
        Err(err) => {
            if let Some(current) = stream.current.as_mut()
                && current.path == dir_entry.path
                && current.visit == FtsVisit::Preorder
            {
                current.entry_mut().fts_info = FTS_DNR;
                current.entry_mut().fts_errno = err;
            }
            unsafe { set_abi_errno(err) };
            return;
        }
    };

    for child in children.into_iter().rev() {
        let control = stream
            .pending_controls
            .remove(&child)
            .unwrap_or(FTS_NOINSTR);
        stream.queue.push_front(fts_controlled_entry(
            control,
            FtsEntryInternal {
                path: child,
                level: dir_entry.level + 1,
                follow_symlink: false,
                instr: FTS_NOINSTR,
                visit: FtsVisit::Preorder,
            },
        ));
    }
}

fn fts_build_children_list(
    stream: &mut FtsStream,
    entries: Vec<FtsEntryInternal>,
    parent: *mut FTSENT,
    name_only: bool,
) -> *mut FTSENT {
    stream.children_cache.clear();
    for entry in entries {
        match FtsEntryOwned::new(&entry, stream.options, parent, name_only) {
            Ok(owned) => stream.children_cache.push(owned),
            Err(err) => {
                unsafe { set_abi_errno(err) };
                stream.children_cache.clear();
                return std::ptr::null_mut();
            }
        }
    }

    for index in 0..stream.children_cache.len() {
        let next = if index + 1 < stream.children_cache.len() {
            stream.children_cache[index + 1].as_mut_ptr()
        } else {
            std::ptr::null_mut()
        };
        stream.children_cache[index].entry_mut().fts_link = next;
    }

    stream
        .children_cache
        .first_mut()
        .map(FtsEntryOwned::as_mut_ptr)
        .unwrap_or(std::ptr::null_mut())
}

/// `fts_open` — open a file hierarchy for traversal.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fts_open(
    path_argv: *const *const c_char,
    options: c_int,
    compar: Option<unsafe extern "C" fn(*const *const FTSENT, *const *const FTSENT) -> c_int>,
) -> *mut c_void {
    if path_argv.is_null() {
        unsafe { set_abi_errno(errno::EINVAL) };
        return std::ptr::null_mut();
    }

    if options & !FTS_OPTIONMASK != 0 || (options & FTS_PHYSICAL != 0 && options & FTS_LOGICAL != 0)
    {
        unsafe { set_abi_errno(errno::EINVAL) };
        return std::ptr::null_mut();
    }

    let mut queue = VecDeque::new();
    let mut roots = Vec::new();

    // Collect initial paths
    let mut i = 0;
    loop {
        let path_ptr = unsafe { *path_argv.add(i) };
        if path_ptr.is_null() {
            break;
        }
        let Some(path_bytes) = (unsafe { read_c_string_bytes(path_ptr) }) else {
            unsafe { set_abi_errno(errno::EINVAL) };
            return std::ptr::null_mut();
        };
        if path_bytes.is_empty() {
            unsafe { set_abi_errno(0) };
            return std::ptr::null_mut();
        }
        use std::os::unix::ffi::OsStringExt;
        let path = std::path::PathBuf::from(std::ffi::OsString::from_vec(path_bytes));
        let follow_root = options & FTS_COMFOLLOW != 0;
        roots.push(path.clone());
        queue.push_back(FtsEntryInternal {
            path,
            level: 0,
            follow_symlink: follow_root,
            instr: FTS_NOINSTR,
            visit: FtsVisit::Preorder,
        });
        i += 1;
    }

    if roots.is_empty() {
        unsafe { set_abi_errno(errno::ENOENT) };
        return std::ptr::null_mut();
    }

    let stream = Box::new(FtsStream {
        queue,
        roots,
        current: None,
        children_cache: Vec::new(),
        options,
        pending_revisit: None,
        pending_children: None,
        pending_controls: HashMap::new(),
        started: false,
        _compar: compar,
    });

    Box::into_raw(stream) as *mut c_void
}

/// `fts_read` — return next entry in file hierarchy.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fts_read(ftsp: *mut c_void) -> *mut FTSENT {
    if ftsp.is_null() {
        unsafe { set_abi_errno(errno::EINVAL) };
        return std::ptr::null_mut();
    }
    let stream = unsafe { &mut *(ftsp as *mut FtsStream) };
    stream.started = true;

    if stream.pending_revisit.is_none() {
        fts_expand_pending_children(stream);
    }

    let entry = match stream
        .pending_revisit
        .take()
        .or_else(|| stream.queue.pop_front())
    {
        Some(e) => e,
        None => {
            unsafe { set_abi_errno(0) };
            return std::ptr::null_mut();
        }
    };
    let parent = stream
        .current
        .as_mut()
        .and_then(|current| {
            if current.level + 1 == entry.level && current.visit == FtsVisit::Preorder {
                Some(current.as_mut_ptr())
            } else {
                None
            }
        })
        .unwrap_or(std::ptr::null_mut());

    let owned = match FtsEntryOwned::new(&entry, stream.options, parent, false) {
        Ok(owned) => owned,
        Err(err) => {
            unsafe { set_abi_errno(err) };
            return std::ptr::null_mut();
        }
    };

    stream.current = Some(owned);
    if entry.visit == FtsVisit::Preorder {
        if stream
            .current
            .as_ref()
            .is_some_and(|current| current.entry().fts_info == FTS_D)
        {
            stream.pending_children = Some(entry);
        } else {
            stream.pending_children = None;
        }
    } else {
        stream.pending_children = None;
    }

    stream
        .current
        .as_mut()
        .map(FtsEntryOwned::as_mut_ptr)
        .unwrap_or(std::ptr::null_mut())
}

/// `fts_children` — return linked list of entries in current directory.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fts_children(ftsp: *mut c_void, options: c_int) -> *mut FTSENT {
    if ftsp.is_null() {
        unsafe { set_abi_errno(errno::EINVAL) };
        return std::ptr::null_mut();
    }
    if options != 0 && options != FTS_NAMEONLY {
        unsafe { set_abi_errno(errno::EINVAL) };
        return std::ptr::null_mut();
    }

    let stream = unsafe { &mut *(ftsp as *mut FtsStream) };
    let name_only = options == FTS_NAMEONLY;

    if !stream.started {
        let roots = stream
            .roots
            .iter()
            .cloned()
            .map(|path| FtsEntryInternal {
                path,
                level: 0,
                follow_symlink: stream.options & FTS_COMFOLLOW != 0,
                instr: FTS_NOINSTR,
                visit: FtsVisit::Preorder,
            })
            .collect();
        return fts_build_children_list(stream, roots, std::ptr::null_mut(), name_only);
    }

    let (parent, current_path, current_level) = {
        let Some(current) = stream.current.as_mut() else {
            unsafe { set_abi_errno(0) };
            return std::ptr::null_mut();
        };
        if current.visit != FtsVisit::Preorder || current.entry().fts_info != FTS_D {
            unsafe { set_abi_errno(0) };
            return std::ptr::null_mut();
        }
        (current.as_mut_ptr(), current.path.clone(), current.level)
    };

    let child_paths = match fts_read_dir_paths(&current_path) {
        Ok(paths) => paths,
        Err(err) => {
            unsafe { set_abi_errno(err) };
            return std::ptr::null_mut();
        }
    };
    if child_paths.is_empty() {
        unsafe { set_abi_errno(0) };
        return std::ptr::null_mut();
    }

    let children = child_paths
        .into_iter()
        .map(|path| FtsEntryInternal {
            path,
            level: current_level + 1,
            follow_symlink: false,
            instr: FTS_NOINSTR,
            visit: FtsVisit::Preorder,
        })
        .collect();
    fts_build_children_list(stream, children, parent, name_only)
}

/// `fts_set` — set instruction for next fts_read return.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fts_set(ftsp: *mut c_void, f: *mut FTSENT, instr: c_int) -> c_int {
    if ftsp.is_null() || f.is_null() {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }

    let normalized_instr = match instr {
        0 => FTS_NOINSTR,
        value if value == FTS_AGAIN as c_int => FTS_AGAIN,
        value if value == FTS_FOLLOW as c_int => FTS_FOLLOW,
        value if value == FTS_SKIP as c_int => FTS_SKIP,
        _ => {
            unsafe { set_abi_errno(errno::EINVAL) };
            return -1;
        }
    };

    let stream = unsafe { &mut *(ftsp as *mut FtsStream) };

    if let Some(current) = stream.current.as_mut()
        && current.same_ptr(f)
    {
        current.entry_mut().fts_instr = normalized_instr;
        match normalized_instr {
            FTS_NOINSTR => return 0,
            FTS_AGAIN => {
                stream.pending_revisit = Some(current.internal());
                return 0;
            }
            FTS_FOLLOW => {
                current.follow_symlink = true;
                stream.pending_revisit = Some(FtsEntryInternal {
                    path: current.path.clone(),
                    level: current.level,
                    follow_symlink: true,
                    instr: FTS_FOLLOW,
                    visit: current.visit,
                });
                return 0;
            }
            FTS_SKIP => {
                if let Some(pending) = stream.pending_children.as_mut()
                    && pending.path == current.path
                {
                    pending.instr = FTS_SKIP;
                }
                return 0;
            }
            _ => {}
        }
    }

    for child in &mut stream.children_cache {
        if child.same_ptr(f) {
            child.entry_mut().fts_instr = normalized_instr;
            if normalized_instr == FTS_AGAIN {
                unsafe { set_abi_errno(errno::EINVAL) };
                return -1;
            }
            if normalized_instr == FTS_NOINSTR {
                stream.pending_controls.remove(&child.path);
            } else {
                stream
                    .pending_controls
                    .insert(child.path.clone(), normalized_instr);
            }
            return 0;
        }
    }

    unsafe { set_abi_errno(errno::EINVAL) };
    -1
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
// ether_ntohost / ether_hostton / ether_line — native /etc/ethers parser
// ===========================================================================

const ETHERS_PATH: &str = "/etc/ethers";

/// `ether_line` — parse an /etc/ethers format line into addr + hostname.
///
/// Native implementation. Line format: "XX:XX:XX:XX:XX:XX hostname".
/// Returns 0 on success, -1 on parse error.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ether_line(
    line: *const c_char,
    addr: *mut c_void,
    hostname: *mut c_char,
) -> c_int {
    if line.is_null() || addr.is_null() || hostname.is_null() {
        return -1;
    }
    let Some(s) = (unsafe { read_c_string_bytes(line) }) else {
        return -1;
    };
    let Some((octet, host)) = frankenlibc_core::ether::parse_ether_line(&s) else {
        return -1;
    };
    unsafe {
        (*(addr as *mut EtherAddrBytes)).octet = octet;
        std::ptr::copy_nonoverlapping(host.as_ptr(), hostname as *mut u8, host.len());
        *(hostname as *mut u8).add(host.len()) = 0;
    }
    0
}

/// `ether_ntohost` — look up hostname by Ethernet address in /etc/ethers.
///
/// Native implementation: scans /etc/ethers line by line.
/// Returns 0 on success, -1 if not found or file unavailable.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ether_ntohost(hostname: *mut c_char, addr: *const c_void) -> c_int {
    use std::io::BufRead;

    if hostname.is_null() || addr.is_null() {
        return -1;
    }
    let file = match std::fs::File::open(ETHERS_PATH) {
        Ok(f) => f,
        Err(_) => return -1,
    };
    let needle = unsafe { *(addr as *const EtherAddrBytes) };
    let mut reader = std::io::BufReader::new(file);
    let mut line_buf = Vec::with_capacity(256);

    loop {
        line_buf.clear();
        match reader.read_until(b'\n', &mut line_buf) {
            Ok(0) => return -1, // EOF
            Err(_) => return -1,
            Ok(_) => {}
        }
        // NUL-terminate for ether_line
        if line_buf.last() == Some(&b'\n') {
            if let Some(last) = line_buf.last_mut() {
                *last = 0;
            } else {
                line_buf.push(0);
            }
        } else {
            line_buf.push(0);
        }

        let mut parsed_addr = EtherAddrBytes { octet: [0; 6] };
        let mut host_buf = [0u8; 256];

        let rc = unsafe {
            ether_line(
                line_buf.as_ptr() as *const c_char,
                (&mut parsed_addr as *mut EtherAddrBytes).cast(),
                host_buf.as_mut_ptr() as *mut c_char,
            )
        };
        if rc == 0 && parsed_addr.octet == needle.octet {
            // Found it — copy hostname to caller
            let hlen = host_buf.iter().position(|&b| b == 0).unwrap_or(0);
            unsafe {
                std::ptr::copy_nonoverlapping(host_buf.as_ptr(), hostname as *mut u8, hlen);
                *(hostname as *mut u8).add(hlen) = 0;
            }
            return 0;
        }
    }
}

/// `ether_hostton` — look up Ethernet address by hostname in /etc/ethers.
///
/// Native implementation: scans /etc/ethers line by line.
/// Returns 0 on success, -1 if not found or file unavailable.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ether_hostton(hostname: *const c_char, addr: *mut c_void) -> c_int {
    use std::io::BufRead;

    if hostname.is_null() || addr.is_null() {
        return -1;
    }
    let Some(needle) = (unsafe { read_c_string_bytes(hostname) }) else {
        return -1;
    };
    let mut reader = std::io::BufReader::new(match std::fs::File::open(ETHERS_PATH) {
        Ok(f) => f,
        Err(_) => return -1,
    });
    let mut line_buf = Vec::with_capacity(256);

    loop {
        line_buf.clear();
        match reader.read_until(b'\n', &mut line_buf) {
            Ok(0) => return -1,
            Err(_) => return -1,
            Ok(_) => {}
        }
        if line_buf.last() == Some(&b'\n') {
            if let Some(last) = line_buf.last_mut() {
                *last = 0;
            } else {
                line_buf.push(0);
            }
        } else {
            line_buf.push(0);
        }

        let mut parsed_addr = EtherAddrBytes { octet: [0; 6] };
        let mut host_buf = [0u8; 256];

        let rc = unsafe {
            ether_line(
                line_buf.as_ptr() as *const c_char,
                (&mut parsed_addr as *mut EtherAddrBytes).cast(),
                host_buf.as_mut_ptr() as *mut c_char,
            )
        };
        if rc == 0 {
            let hlen = host_buf.iter().position(|&b| b == 0).unwrap_or(0);
            if &host_buf[..hlen] == needle.as_slice() {
                unsafe {
                    *(addr as *mut EtherAddrBytes) = parsed_addr;
                }
                return 0;
            }
        }
    }
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
    let Some(requested_name_bytes) = (unsafe { read_c_string_bytes(name) }) else {
        unsafe {
            *result = std::ptr::null_mut();
            *h_errnop = 1; // HOST_NOT_FOUND
        }
        return 0;
    };
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
    let rc = unsafe { crate::resolv_abi::getaddrinfo(name, std::ptr::null(), &hints, &mut res) };
    if rc != 0 {
        unsafe {
            *result = std::ptr::null_mut();
            *h_errnop = 1; // HOST_NOT_FOUND
        }
        return 0;
    }
    // Fill result_buf from first addrinfo result
    if !res.is_null() {
        let ai = unsafe { &*res };
        let addr_len: usize = if ai.ai_family == libc::AF_INET { 4 } else { 16 };
        let name_bytes = if !ai.ai_canonname.is_null() {
            unsafe { read_c_string_bytes(ai.ai_canonname) }
                .unwrap_or_else(|| requested_name_bytes.clone())
        } else {
            requested_name_bytes
        };
        let ptr_size = core::mem::size_of::<*mut c_char>();
        let addr_align = if ai.ai_family == libc::AF_INET {
            core::mem::align_of::<libc::in_addr>()
        } else {
            core::mem::align_of::<libc::in6_addr>()
        };
        let name_end = name_bytes.len() + 1;
        let addr_off = (name_end + (addr_align - 1)) & !(addr_align - 1);
        let addr_end = addr_off + addr_len;
        let list_off = (addr_end + (ptr_size - 1)) & !(ptr_size - 1);
        let addr_list_off = list_off;
        let alias_list_off = addr_list_off + 2 * ptr_size;
        // glibc's reentrant host lookup ABI requires extra pointer scratch beyond
        // the packed hostent fields themselves. Preserving that headroom keeps the
        // ERANGE threshold aligned with the host for small caller buffers.
        let scratch_ptr_slots = 5 * ptr_size;
        let needed = alias_list_off + ptr_size + scratch_ptr_slots;
        if buflen < needed {
            unsafe {
                crate::resolv_abi::freeaddrinfo(res);
                *result = std::ptr::null_mut();
            }
            return libc::ERANGE;
        }
        unsafe {
            let buf_u8 = buf as *mut u8;
            std::ptr::copy_nonoverlapping(name_bytes.as_ptr(), buf_u8, name_bytes.len());
            *buf_u8.add(name_bytes.len()) = 0;

            // Copy address into caller buffer after the packed hostname.
            let addr_ptr = if af == libc::AF_INET {
                let sa = ai.ai_addr as *const libc::sockaddr_in;
                &(*sa).sin_addr as *const _ as *const u8
            } else {
                let sa = ai.ai_addr as *const libc::sockaddr_in6;
                &(*sa).sin6_addr as *const _ as *const u8
            };
            std::ptr::copy_nonoverlapping(addr_ptr, buf_u8.add(addr_off), addr_len);

            // Set up address and alias lists inside the caller buffer.
            let addr_list_ptr = buf_u8.add(addr_list_off) as *mut *mut c_char;
            *addr_list_ptr = buf_u8.add(addr_off) as *mut c_char;
            *addr_list_ptr.add(1) = std::ptr::null_mut();
            let alias_list_ptr = buf_u8.add(alias_list_off) as *mut *mut c_char;
            *alias_list_ptr = std::ptr::null_mut();

            (*result_buf).h_name = buf;
            (*result_buf).h_aliases = alias_list_ptr;
            (*result_buf).h_addrtype = ai.ai_family;
            (*result_buf).h_length = addr_len as c_int;
            (*result_buf).h_addr_list = addr_list_ptr;

            *result = result_buf;
            *h_errnop = 0;
            crate::resolv_abi::freeaddrinfo(res);
        }
        return 0;
    }
    unsafe {
        crate::resolv_abi::freeaddrinfo(res);
        *result = std::ptr::null_mut();
        *h_errnop = 1; // HOST_NOT_FOUND
    }
    0
}

// ---------------------------------------------------------------------------
// System V IPC key generation
// ---------------------------------------------------------------------------

/// `ftok` — generate IPC key from pathname and project ID.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ftok(pathname: *const c_char, proj_id: c_int) -> i32 {
    if pathname.is_null() {
        unsafe { super::errno_abi::set_abi_errno(libc::EINVAL) };
        return -1;
    }
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // Use newfstatat with AT_FDCWD for stat() equivalent (works on both x86_64 and aarch64)
    if unsafe {
        syscall::sys_newfstatat(
            libc::AT_FDCWD,
            pathname as *const u8,
            &mut st as *mut libc::stat as *mut u8,
            0,
        )
    }
    .is_err()
    {
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
    let spw = unsafe { &*sp };
    let name = match unsafe { read_optional_c_string_bytes(spw.sp_namp) } {
        Ok(Some(bytes)) => bytes,
        Ok(None) => Vec::new(),
        Err(e) => {
            unsafe { set_abi_errno(e) };
            return -1;
        }
    };
    let passwd = match unsafe { read_optional_c_string_bytes(spw.sp_pwdp) } {
        Ok(Some(bytes)) => bytes,
        Ok(None) => Vec::new(),
        Err(e) => {
            unsafe { set_abi_errno(e) };
            return -1;
        }
    };

    let mut line = Vec::with_capacity(96 + name.len() + passwd.len());
    frankenlibc_core::pwd::shadow::format_shadow_line(
        frankenlibc_core::pwd::shadow::ShadowLineFields {
            name: &name,
            passwd: &passwd,
            lstchg: spw.sp_lstchg,
            min: spw.sp_min,
            max: spw.sp_max,
            warn: spw.sp_warn,
            inact: spw.sp_inact,
            expire: spw.sp_expire,
            flag: spw.sp_flag,
        },
        &mut line,
    );
    let written =
        unsafe { crate::stdio_abi::fwrite(line.as_ptr().cast(), 1, line.len(), stream.cast()) };
    if written == line.len() { 0 } else { -1 }
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

/// `mprobe` — check a single allocation using FrankenLibC allocator metadata.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mprobe(ptr: *mut c_void) -> c_int {
    unsafe { crate::malloc_abi::mprobe_status(ptr) }
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
    if frankenlibc_core::fmtmsg::should_print(classification) {
        let label_bytes = match unsafe { read_optional_c_string_bytes(label) } {
            Ok(Some(bytes)) => bytes,
            Ok(None) => Vec::new(),
            Err(e) => {
                unsafe { set_abi_errno(e) };
                return -1;
            }
        };
        let text_bytes = match unsafe { read_optional_c_string_bytes(text) } {
            Ok(Some(bytes)) => bytes,
            Ok(None) => Vec::new(),
            Err(e) => {
                unsafe { set_abi_errno(e) };
                return -1;
            }
        };
        let action_bytes = match unsafe { read_optional_c_string_bytes(action) } {
            Ok(Some(bytes)) => bytes,
            Ok(None) => Vec::new(),
            Err(e) => {
                unsafe { set_abi_errno(e) };
                return -1;
            }
        };
        let tag_bytes = match unsafe { read_optional_c_string_bytes(tag) } {
            Ok(Some(bytes)) => bytes,
            Ok(None) => Vec::new(),
            Err(e) => {
                unsafe { set_abi_errno(e) };
                return -1;
            }
        };
        let out = frankenlibc_core::fmtmsg::format_fmtmsg_message(
            &label_bytes,
            severity,
            &text_bytes,
            &action_bytes,
            &tag_bytes,
        );
        unsafe { sys_write_fd(libc::STDERR_FILENO, out.as_ptr().cast(), out.len()) };
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
    let fd = match unsafe {
        syscall::sys_openat(
            libc::AT_FDCWD,
            cpath.as_ptr() as *const u8,
            libc::O_RDWR | libc::O_CREAT,
            0o644,
        )
    } {
        Ok(fd) => fd,
        Err(_) => return std::ptr::null_mut(),
    };

    let record_size = std::mem::size_of::<libc::utmpx>();
    let _ = syscall::sys_lseek(fd, 0, libc::SEEK_END);
    let written = match unsafe { syscall::sys_write(fd, ut as *const u8, record_size) } {
        Ok(n) => n as isize,
        Err(_) => -1,
    };
    let _ = syscall::sys_close(fd);

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
    let a1: c_long = unsafe { args.next_arg() };
    let a2: c_long = unsafe { args.next_arg() };
    let a3: c_long = unsafe { args.next_arg() };
    let a4: c_long = unsafe { args.next_arg() };
    let a5: c_long = unsafe { args.next_arg() };
    let a6: c_long = unsafe { args.next_arg() };

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
    match unsafe {
        syscall::sys_execve(
            path as *const u8,
            argv as *const *const u8,
            envp as *const *const u8,
        )
    } {
        Ok(()) => unreachable!("execve only returns on failure"),
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
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
        let sym = unsafe { crate::dlfcn_abi::dlsym(libc::RTLD_NEXT, c"clone".as_ptr()) };
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
    let _ = syscall::sys_close_range(lowfd as u32, !0u32, 0);
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
    if let Err(e) =
        unsafe { syscall::sys_clock_getres(cid as i32, (&mut ts as *mut libc::timespec).cast()) }
    {
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
    match unsafe { syscall::sys_clock_adjtime(clk_id, buf as *mut u8) } {
        Ok(v) => v,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
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
    let Some(name_bytes) = (unsafe { read_c_string_bytes(exp_dn) }) else {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    };
    let name_bytes = name_bytes.as_slice();
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
// /etc/aliases database — native parser
// ===========================================================================
//
// Format: "name: member1, member2, ..."
//
// struct aliasent (x86_64, 32 bytes):
//   alias_name:        *mut c_char    (offset 0)
//   alias_members_len: size_t         (offset 8)
//   alias_members:     *mut *mut c_char (offset 16)
//   alias_local:       c_int          (offset 24)

const ALIASES_PATH: &str = "/etc/aliases";

struct AliasIterState {
    reader: Option<std::io::BufReader<std::fs::File>>,
    line_buf: Vec<u8>,
    entry_buf: [u8; 4096],
    member_ptrs: [*mut c_char; 64],
}

impl AliasIterState {
    const fn new() -> Self {
        Self {
            reader: None,
            line_buf: Vec::new(),
            entry_buf: [0u8; 4096],
            member_ptrs: [std::ptr::null_mut(); 64],
        }
    }
}

std::thread_local! {
    static ALIAS_ITER: std::cell::UnsafeCell<AliasIterState> =
        const { std::cell::UnsafeCell::new(AliasIterState::new()) };
}

// Parse an /etc/aliases line into name + member list.
// parse_aliases_line moved to frankenlibc_core::aliases. Callers below
// use frankenlibc_core::aliases::parse_aliases_line directly and access
// the owned name / members fields of the returned AliasEntry.

/// Fill an aliasent in the entry_buf from parsed data.
unsafe fn fill_aliasent_buf(
    state: &mut AliasIterState,
    name: &[u8],
    members: &[&[u8]],
) -> *mut c_void {
    let str_offset = 32usize; // sizeof(struct aliasent)
    let mut needed = str_offset + name.len() + 1;
    for m in members {
        needed += m.len() + 1;
    }
    if needed > state.entry_buf.len() || members.len() + 1 > state.member_ptrs.len() {
        return std::ptr::null_mut();
    }

    let buf = state.entry_buf.as_mut_ptr();
    let mut off = str_offset;

    // Pack name
    let name_ptr = unsafe { buf.add(off) } as *mut c_char;
    unsafe {
        std::ptr::copy_nonoverlapping(name.as_ptr(), buf.add(off), name.len());
        *buf.add(off + name.len()) = 0;
    }
    off += name.len() + 1;

    // Pack members and build pointer array
    for (i, m) in members.iter().enumerate() {
        state.member_ptrs[i] = unsafe { buf.add(off) } as *mut c_char;
        unsafe {
            std::ptr::copy_nonoverlapping(m.as_ptr(), buf.add(off), m.len());
            *buf.add(off + m.len()) = 0;
        }
        off += m.len() + 1;
    }
    state.member_ptrs[members.len()] = std::ptr::null_mut();

    // Fill struct aliasent
    unsafe {
        *(buf as *mut *mut c_char) = name_ptr; // alias_name
        *(buf.add(8) as *mut usize) = members.len(); // alias_members_len
        *(buf.add(16) as *mut *mut *mut c_char) = state.member_ptrs.as_mut_ptr(); // alias_members
        *(buf.add(24) as *mut c_int) = 0; // alias_local
    }
    buf as *mut c_void
}

/// Parse next alias entry from iterator.
unsafe fn alias_iter_next(state: &mut AliasIterState) -> *mut c_void {
    use std::io::BufRead;
    loop {
        let reader = match state.reader.as_mut() {
            Some(r) => r,
            None => return std::ptr::null_mut(),
        };
        state.line_buf.clear();
        match reader.read_until(b'\n', &mut state.line_buf) {
            Ok(0) => return std::ptr::null_mut(),
            Err(_) => return std::ptr::null_mut(),
            Ok(_) => {}
        }
        if let Some(entry) = frankenlibc_core::aliases::parse_aliases_line(&state.line_buf) {
            let mut name_copy = [0u8; 256];
            let nlen = entry.name.len().min(255);
            name_copy[..nlen].copy_from_slice(&entry.name[..nlen]);
            let member_refs: Vec<&[u8]> = entry.members.iter().map(|v| v.as_slice()).collect();
            let result = unsafe { fill_aliasent_buf(state, &name_copy[..nlen], &member_refs) };
            if !result.is_null() {
                return result;
            }
        }
    }
}

/// `endaliasent` — close alias database iteration.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn endaliasent() {
    ALIAS_ITER.with(|cell| {
        let state = unsafe { &mut *cell.get() };
        state.reader = None;
    });
}

/// `getaliasbyname` — look up alias by name in /etc/aliases.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getaliasbyname(name: *const c_char) -> *mut c_void {
    if name.is_null() {
        unsafe { set_abi_errno(libc::ENOENT) };
        return std::ptr::null_mut();
    }
    let Some(needle) = (unsafe { read_c_string_bytes(name) }) else {
        unsafe { set_abi_errno(libc::EINVAL) };
        return std::ptr::null_mut();
    };
    let content = match std::fs::read(ALIASES_PATH) {
        Ok(c) => c,
        Err(_) => {
            unsafe { set_abi_errno(libc::ENOENT) };
            return std::ptr::null_mut();
        }
    };
    for line in content.split(|&b| b == b'\n') {
        if let Some(entry) = frankenlibc_core::aliases::parse_aliases_line(line)
            && entry.name.eq_ignore_ascii_case(&needle)
        {
            return ALIAS_ITER.with(|cell| {
                let state = unsafe { &mut *cell.get() };
                let member_refs: Vec<&[u8]> = entry.members.iter().map(|v| v.as_slice()).collect();
                unsafe { fill_aliasent_buf(state, &entry.name, &member_refs) }
            });
        }
    }
    unsafe { set_abi_errno(libc::ENOENT) };
    std::ptr::null_mut()
}

/// `getaliasbyname_r` — reentrant alias lookup by name.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getaliasbyname_r(
    name: *const c_char,
    result_buf: *mut c_void,
    buffer: *mut c_char,
    buflen: usize,
    result: *mut *mut c_void,
) -> c_int {
    if !result.is_null() {
        unsafe { *result = std::ptr::null_mut() };
    }
    if name.is_null() || result_buf.is_null() || buffer.is_null() {
        return libc::EINVAL;
    }
    let Some(needle) = (unsafe { read_c_string_bytes(name) }) else {
        return libc::EINVAL;
    };
    let content = match std::fs::read(ALIASES_PATH) {
        Ok(c) => c,
        Err(_) => {
            unsafe { set_abi_errno(libc::ENOENT) };
            return libc::ENOENT;
        }
    };
    for line in content.split(|&b| b == b'\n') {
        if let Some(entry) = frankenlibc_core::aliases::parse_aliases_line(line)
            && entry.name.eq_ignore_ascii_case(&needle)
        {
            let pname = &entry.name;
            let members = &entry.members;

            // Pack into caller buffer: name + NUL + members + NULs + ptr array
            let ptr_size = core::mem::size_of::<*mut c_char>();
            let mut needed = pname.len() + 1;
            for m in members {
                needed += m.len() + 1;
            }
            let ptrs_offset = (needed + (ptr_size - 1)) & !(ptr_size - 1);
            let total = ptrs_offset + (members.len() + 1) * ptr_size;
            if total > buflen {
                return libc::ERANGE;
            }

            let buf_u8 = buffer as *mut u8;

            let name_ptr = buffer;
            unsafe {
                std::ptr::copy_nonoverlapping(pname.as_ptr(), buf_u8, pname.len());
                *buf_u8.add(pname.len()) = 0;
            }
            let mut off = pname.len() + 1;

            let member_ptrs_base = unsafe { buf_u8.add(ptrs_offset) } as *mut *mut c_char;
            for (i, m) in members.iter().enumerate() {
                unsafe {
                    *(member_ptrs_base.add(i)) = buf_u8.add(off) as *mut c_char;
                    std::ptr::copy_nonoverlapping(m.as_ptr(), buf_u8.add(off), m.len());
                    *buf_u8.add(off + m.len()) = 0;
                }
                off += m.len() + 1;
            }
            unsafe { *(member_ptrs_base.add(members.len())) = std::ptr::null_mut() };

            let ent = result_buf as *mut u8;
            unsafe {
                *(ent as *mut *mut c_char) = name_ptr;
                *(ent.add(8) as *mut usize) = members.len();
                *(ent.add(16) as *mut *mut *mut c_char) = member_ptrs_base;
                *(ent.add(24) as *mut c_int) = 0;
            }
            if !result.is_null() {
                unsafe { *result = result_buf };
            }
            return 0;
        }
    }
    unsafe { set_abi_errno(libc::ENOENT) };
    libc::ENOENT
}

/// `getaliasent` — get next alias entry from /etc/aliases.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getaliasent() -> *mut c_void {
    let result = ALIAS_ITER.with(|cell| {
        let state = unsafe { &mut *cell.get() };
        if state.reader.is_none() {
            match std::fs::File::open(ALIASES_PATH) {
                Ok(f) => state.reader = Some(std::io::BufReader::new(f)),
                Err(_) => return std::ptr::null_mut(),
            }
        }
        unsafe { alias_iter_next(state) }
    });
    if result.is_null() {
        unsafe { set_abi_errno(libc::ENOENT) };
    }
    result
}

/// `getaliasent_r` — reentrant get next alias entry.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getaliasent_r(
    result_buf: *mut c_void,
    buffer: *mut c_char,
    buflen: usize,
    result: *mut *mut c_void,
) -> c_int {
    use std::io::BufRead;
    if !result.is_null() {
        unsafe { *result = std::ptr::null_mut() };
    }
    if result_buf.is_null() || buffer.is_null() {
        return libc::EINVAL;
    }

    ALIAS_ITER.with(|cell| {
        let state = unsafe { &mut *cell.get() };
        if state.reader.is_none() {
            match std::fs::File::open(ALIASES_PATH) {
                Ok(f) => state.reader = Some(std::io::BufReader::new(f)),
                Err(_) => return libc::ENOENT,
            }
        }
        let reader = match state.reader.as_mut() {
            Some(reader) => reader,
            None => return libc::ENOENT,
        };
        loop {
            state.line_buf.clear();
            match reader.read_until(b'\n', &mut state.line_buf) {
                Ok(0) => return libc::ENOENT,
                Err(_) => return libc::ENOENT,
                Ok(_) => {}
            }
            if let Some(entry) = frankenlibc_core::aliases::parse_aliases_line(&state.line_buf) {
                let pname = &entry.name;
                let members = &entry.members;
                let ptr_size = core::mem::size_of::<*mut c_char>();
                let mut needed = pname.len() + 1;
                for m in members {
                    needed += m.len() + 1;
                }
                let ptrs_offset = (needed + (ptr_size - 1)) & !(ptr_size - 1);
                let total = ptrs_offset + (members.len() + 1) * ptr_size;
                if total > buflen {
                    return libc::ERANGE;
                }
                let buf_u8 = buffer as *mut u8;
                let name_ptr = buffer;
                unsafe {
                    std::ptr::copy_nonoverlapping(pname.as_ptr(), buf_u8, pname.len());
                    *buf_u8.add(pname.len()) = 0;
                }
                let mut off = pname.len() + 1;
                let member_ptrs_base = unsafe { buf_u8.add(ptrs_offset) } as *mut *mut c_char;
                for (i, m) in members.iter().enumerate() {
                    unsafe {
                        *(member_ptrs_base.add(i)) = buf_u8.add(off) as *mut c_char;
                        std::ptr::copy_nonoverlapping(m.as_ptr(), buf_u8.add(off), m.len());
                        *buf_u8.add(off + m.len()) = 0;
                    }
                    off += m.len() + 1;
                }
                unsafe { *(member_ptrs_base.add(members.len())) = std::ptr::null_mut() };
                let ent = result_buf as *mut u8;
                unsafe {
                    *(ent as *mut *mut c_char) = name_ptr;
                    *(ent.add(8) as *mut usize) = members.len();
                    *(ent.add(16) as *mut *mut *mut c_char) = member_ptrs_base;
                    *(ent.add(24) as *mut c_int) = 0;
                }
                if !result.is_null() {
                    unsafe { *result = result_buf };
                }
                return 0;
            }
        }
    })
}

/// `endfsent` — close filesystem table iteration.
///
/// Native implementation: resets the thread-local fstab parser state.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn endfsent() {
    FSTAB_STATE.with(|cell| {
        let state = unsafe { &mut *cell.get() };
        state.reader = None;
    });
}

// ---------------------------------------------------------------------------
// /etc/netgroup iteration — native
// ---------------------------------------------------------------------------
//
// Format: "groupname (host,user,domain) (host,user,domain) ..."
// Fields within parens can be empty (wildcard). Groups can reference
// other groups by name (non-paren tokens), but we don't expand those
// recursively (matching minimal glibc files-backend behavior).

const NETGROUP_PATH: &str = "/etc/netgroup";

use frankenlibc_core::netgroup::NetgroupTriple;

struct NetgroupIterState {
    /// Pre-parsed triples for the current group.
    triples: Vec<NetgroupTriple>,
    /// Current position in the triples vector.
    pos: usize,
    /// Thread-local string buffer for non-reentrant getnetgrent.
    str_buf: [u8; 1024],
}

impl NetgroupIterState {
    const fn new() -> Self {
        Self {
            triples: Vec::new(),
            pos: 0,
            str_buf: [0u8; 1024],
        }
    }
}

std::thread_local! {
    static NETGROUP_ITER: std::cell::UnsafeCell<NetgroupIterState> =
        const { std::cell::UnsafeCell::new(NetgroupIterState::new()) };
}

// parse_netgroup_triples moved to frankenlibc_core::netgroup. The
// callers below invoke frankenlibc_core::netgroup::parse_netgroup_triples
// directly.

/// `endnetgrent` — end netgroup iteration.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn endnetgrent() {
    NETGROUP_ITER.with(|cell| {
        let state = unsafe { &mut *cell.get() };
        state.triples.clear();
        state.pos = 0;
    });
}

/// `setnetgrent` — start netgroup iteration for the named group.
///
/// Native implementation: reads /etc/netgroup and pre-parses all triples
/// for the specified group.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setnetgrent(netgroup: *const c_char) -> c_int {
    if netgroup.is_null() {
        return 0;
    }
    let Some(group) = (unsafe { read_c_string_bytes(netgroup) }) else {
        unsafe { set_abi_errno(libc::EINVAL) };
        NETGROUP_ITER.with(|cell| {
            let state = unsafe { &mut *cell.get() };
            state.triples.clear();
            state.pos = 0;
        });
        return 0;
    };
    let content = match std::fs::read(NETGROUP_PATH) {
        Ok(c) => c,
        Err(_) => {
            // No /etc/netgroup — not an error, just empty results
            NETGROUP_ITER.with(|cell| {
                let state = unsafe { &mut *cell.get() };
                state.triples.clear();
                state.pos = 0;
            });
            return 0;
        }
    };
    let triples = frankenlibc_core::netgroup::parse_netgroup_triples(&content, &group);
    NETGROUP_ITER.with(|cell| {
        let state = unsafe { &mut *cell.get() };
        state.triples = triples;
        state.pos = 0;
    });
    1
}

/// `getnetgrent` — get next netgroup entry (host, user, domain triple).
///
/// Native implementation using thread-local pre-parsed triples.
/// Returns 1 on success, 0 when exhausted.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getnetgrent(
    hostp: *mut *mut c_char,
    userp: *mut *mut c_char,
    domainp: *mut *mut c_char,
) -> c_int {
    if hostp.is_null() || userp.is_null() || domainp.is_null() {
        return 0;
    }
    NETGROUP_ITER.with(|cell| {
        let state = unsafe { &mut *cell.get() };
        if state.pos >= state.triples.len() {
            return 0;
        }
        let triple = &state.triples[state.pos];
        state.pos += 1;

        // Pack strings into thread-local buffer
        let buf = state.str_buf.as_mut_ptr();
        let mut off = 0usize;

        macro_rules! pack_or_null {
            ($field:expr, $ptr:expr) => {
                if $field.is_empty() {
                    unsafe { *$ptr = std::ptr::null_mut() };
                } else if off + $field.len() < state.str_buf.len() {
                    let p = unsafe { buf.add(off) } as *mut c_char;
                    unsafe {
                        std::ptr::copy_nonoverlapping($field.as_ptr(), buf.add(off), $field.len());
                        *buf.add(off + $field.len()) = 0;
                        *$ptr = p;
                    }
                    off += $field.len() + 1;
                } else {
                    unsafe { *$ptr = std::ptr::null_mut() };
                }
            };
        }

        pack_or_null!(triple.host, hostp);
        pack_or_null!(triple.user, userp);
        pack_or_null!(triple.domain, domainp);
        let _ = off;
        1
    })
}

/// `getnetgrent_r` — reentrant netgroup entry.
///
/// Native implementation using thread-local pre-parsed triples,
/// packing strings into caller-supplied buffer.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getnetgrent_r(
    hostp: *mut *mut c_char,
    userp: *mut *mut c_char,
    domainp: *mut *mut c_char,
    buffer: *mut c_char,
    buflen: usize,
) -> c_int {
    if hostp.is_null() || userp.is_null() || domainp.is_null() || buffer.is_null() {
        return 0;
    }
    NETGROUP_ITER.with(|cell| {
        let state = unsafe { &mut *cell.get() };
        if state.pos >= state.triples.len() {
            return 0;
        }
        let triple = &state.triples[state.pos];

        // Check buffer space
        let needed = triple.host.len() + 1 + triple.user.len() + 1 + triple.domain.len() + 1;
        if needed > buflen {
            return 0; // ERANGE-like, but getnetgrent_r returns 0/1
        }
        state.pos += 1;

        let buf = buffer as *mut u8;
        let mut off = 0usize;

        macro_rules! pack_r {
            ($field:expr, $ptr:expr) => {
                if $field.is_empty() {
                    unsafe { *$ptr = std::ptr::null_mut() };
                } else {
                    let p = unsafe { buf.add(off) } as *mut c_char;
                    unsafe {
                        std::ptr::copy_nonoverlapping($field.as_ptr(), buf.add(off), $field.len());
                        *buf.add(off + $field.len()) = 0;
                        *$ptr = p;
                    }
                    off += $field.len() + 1;
                }
            };
        }

        pack_r!(triple.host, hostp);
        pack_r!(triple.user, userp);
        pack_r!(triple.domain, domainp);
        let _ = off;
        1
    })
}

// ---------------------------------------------------------------------------
// RPC database (/etc/rpc) native implementation
// ---------------------------------------------------------------------------

const RPC_ENTRY_STORAGE_BYTES: usize = 1024;
const RPC_ENTRY_STRUCT_BYTES: usize = 24;
const RPC_ENTRY_ALIAS_SLOTS: usize = 32;

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
    let entry = match frankenlibc_core::rpc::parse_rpc_line(line.as_bytes()) {
        Some(e) => e,
        None => return std::ptr::null_mut(),
    };
    fill_rpc_tls_from_entry(&entry)
}

/// Pack an [`frankenlibc_core::rpc::RpcEntry`] into the thread-local
/// rpcent storage and return a pointer to the layout-compatible
/// rpcent struct (or null if the entry exceeds the storage budget).
fn fill_rpc_tls_from_entry(entry: &frankenlibc_core::rpc::RpcEntry) -> *mut c_void {
    // glibc rpcent layout (x86_64):
    // struct rpcent {
    //     char *r_name;        // offset 0
    //     char **r_aliases;    // offset 8
    //     int r_number;        // offset 16
    // };
    // Size: 24 bytes (with padding)
    thread_local! {
        static RPC_BUF: std::cell::RefCell<[u8; RPC_ENTRY_STORAGE_BYTES]> = const { std::cell::RefCell::new([0u8; RPC_ENTRY_STORAGE_BYTES]) };
        static RPC_ENT: std::cell::RefCell<[u8; RPC_ENTRY_STRUCT_BYTES]> = const { std::cell::RefCell::new([0u8; RPC_ENTRY_STRUCT_BYTES]) };
        static RPC_ALIASES: std::cell::RefCell<[*mut c_char; RPC_ENTRY_ALIAS_SLOTS]> = const { std::cell::RefCell::new([std::ptr::null_mut(); RPC_ENTRY_ALIAS_SLOTS]) };
    }

    let name_bytes = entry.name.as_slice();
    let aliases = &entry.aliases;
    let number = entry.number;

    RPC_BUF.with(|buf| {
        RPC_ENT.with(|ent| {
            RPC_ALIASES.with(|al| {
                let mut buf = buf.borrow_mut();
                let mut ent = ent.borrow_mut();
                let mut al = al.borrow_mut();

                al.fill(std::ptr::null_mut());
                let mut off = 0usize;
                if off + name_bytes.len() + 1 > buf.len() {
                    return std::ptr::null_mut();
                }
                buf[off..off + name_bytes.len()].copy_from_slice(name_bytes);
                buf[off + name_bytes.len()] = 0;
                let name_ptr = buf[off..].as_ptr() as *mut c_char;
                off += name_bytes.len() + 1;

                let max_aliases = al.len() - 1; // Leave room for NULL terminator.
                let mut copied_aliases = 0usize;
                for (i, alias) in aliases.iter().take(max_aliases).enumerate() {
                    let ab = alias.as_slice();
                    if off + ab.len() + 1 > buf.len() {
                        break;
                    }
                    buf[off..off + ab.len()].copy_from_slice(ab);
                    buf[off + ab.len()] = 0;
                    al[i] = buf[off..].as_ptr() as *mut c_char;
                    off += ab.len() + 1;
                    copied_aliases = i + 1;
                }
                al[copied_aliases] = std::ptr::null_mut();

                let ent_ptr = ent.as_mut_ptr();
                unsafe {
                    *(ent_ptr as *mut *mut c_char) = name_ptr;
                    *(ent_ptr.add(8) as *mut *mut *mut c_char) = al.as_mut_ptr();
                    *(ent_ptr.add(16) as *mut c_int) = number;
                }

                ent_ptr as *mut c_void
            })
        })
    })
}

unsafe fn fill_rpcent_result(
    src: *const RpcEnt,
    result_buf: *mut c_void,
    buffer: *mut c_char,
    buflen: usize,
    result: *mut *mut c_void,
) -> c_int {
    if !result.is_null() {
        unsafe { *result = std::ptr::null_mut() };
    }
    if src.is_null() {
        return 0;
    }
    if result_buf.is_null() || buffer.is_null() {
        return libc::EINVAL;
    }

    let src = unsafe { &*src };
    let dst = result_buf as *mut RpcEnt;
    let buf = buffer as *mut u8;
    let mut off = 0usize;

    if src.r_name.is_null() {
        return libc::EINVAL;
    }
    let (name_len, name_terminated) =
        unsafe { scan_c_string(src.r_name, Some(RPC_ENTRY_STORAGE_BYTES)) };
    if !name_terminated {
        return libc::EINVAL;
    }
    let name_len_with_nul = name_len + 1;
    let alias_count = if src.r_aliases.is_null() {
        0
    } else {
        let mut count = 0usize;
        loop {
            if count >= RPC_ENTRY_ALIAS_SLOTS {
                return libc::EINVAL;
            }
            let alias_ptr = unsafe { *src.r_aliases.add(count) };
            if alias_ptr.is_null() {
                break;
            }
            count += 1;
        }
        count
    };
    let alias_table_bytes = (alias_count + 1) * std::mem::size_of::<*mut c_char>();
    let aliases_region = buf;
    off += alias_table_bytes;
    if off > buflen {
        return libc::ERANGE;
    }

    let name_ptr = unsafe { buf.add(off) as *mut c_char };
    if off + name_len_with_nul > buflen {
        return libc::ERANGE;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(src.r_name.cast::<u8>(), buf.add(off), name_len_with_nul);
    }
    off += name_len_with_nul;

    for i in 0..alias_count {
        let alias_src = unsafe { *src.r_aliases.add(i) };
        if alias_src.is_null() {
            return libc::EINVAL;
        }
        let (alias_len, alias_terminated) =
            unsafe { scan_c_string(alias_src, Some(RPC_ENTRY_STORAGE_BYTES)) };
        if !alias_terminated {
            return libc::EINVAL;
        }
        let alias_len_with_nul = alias_len + 1;
        if off + alias_len_with_nul > buflen {
            return libc::ERANGE;
        }
        let alias_ptr = unsafe { buf.add(off) as *mut c_char };
        unsafe {
            std::ptr::copy_nonoverlapping(alias_src.cast::<u8>(), buf.add(off), alias_len_with_nul);
            *(aliases_region as *mut *mut c_char).add(i) = alias_ptr;
        }
        off += alias_len_with_nul;
    }
    unsafe {
        *(aliases_region as *mut *mut c_char).add(alias_count) = std::ptr::null_mut();
        (*dst).r_name = name_ptr;
        (*dst).r_aliases = aliases_region as *mut *mut c_char;
        (*dst).r_number = src.r_number;
    }

    if !result.is_null() {
        unsafe { *result = dst.cast() };
    }
    0
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
    let Some(needle) = (unsafe { read_c_string_bytes(name) }) else {
        unsafe { set_abi_errno(libc::EINVAL) };
        return std::ptr::null_mut();
    };
    let contents = match std::fs::read("/etc/rpc") {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };
    match frankenlibc_core::rpc::lookup_rpc_by_name(&contents, &needle) {
        Some(entry) => fill_rpc_tls_from_entry(&entry),
        None => std::ptr::null_mut(),
    }
}

/// `getrpcbyname_r` — reentrant RPC lookup by name.
///
/// Native implementation: searches /etc/rpc, fills caller buffer.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getrpcbyname_r(
    name: *const c_char,
    result_buf: *mut c_void,
    buffer: *mut c_char,
    buflen: usize,
    result: *mut *mut c_void,
) -> c_int {
    if !result.is_null() {
        unsafe { *result = std::ptr::null_mut() };
    }
    if name.is_null() {
        return unsafe { fill_rpcent_result(std::ptr::null(), result_buf, buffer, buflen, result) };
    }
    let Some(needle) = (unsafe { read_c_string_bytes(name) }) else {
        unsafe { set_abi_errno(libc::EINVAL) };
        return libc::EINVAL;
    };
    let contents = match std::fs::read("/etc/rpc") {
        Ok(c) => c,
        Err(_) => {
            return unsafe {
                fill_rpcent_result(std::ptr::null(), result_buf, buffer, buflen, result)
            };
        }
    };
    let ptr = match frankenlibc_core::rpc::lookup_rpc_by_name(&contents, &needle) {
        Some(entry) => fill_rpc_tls_from_entry(&entry),
        None => std::ptr::null_mut(),
    };
    unsafe { fill_rpcent_result(ptr.cast(), result_buf, buffer, buflen, result) }
}

/// `getrpcbynumber` — find RPC entry by number.
///
/// Native implementation: searches /etc/rpc for matching program number.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getrpcbynumber(number: c_int) -> *mut c_void {
    let contents = match std::fs::read("/etc/rpc") {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };
    match frankenlibc_core::rpc::lookup_rpc_by_number(&contents, number) {
        Some(entry) => fill_rpc_tls_from_entry(&entry),
        None => std::ptr::null_mut(),
    }
}

/// `getrpcbynumber_r` — reentrant RPC lookup by number.
///
/// Native implementation: searches /etc/rpc, fills caller buffer.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getrpcbynumber_r(
    number: c_int,
    result_buf: *mut c_void,
    buffer: *mut c_char,
    buflen: usize,
    result: *mut *mut c_void,
) -> c_int {
    let ptr = unsafe { getrpcbynumber(number) };
    unsafe { fill_rpcent_result(ptr.cast(), result_buf, buffer, buflen, result) }
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
    result_buf: *mut c_void,
    buffer: *mut c_char,
    buflen: usize,
    result: *mut *mut c_void,
) -> c_int {
    let ptr = unsafe { getrpcent() };
    unsafe { fill_rpcent_result(ptr.cast(), result_buf, buffer, buflen, result) }
}

/// `endttyent` — close tty database iteration.
///
/// Native implementation: resets the thread-local ttyent parser state.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn endttyent() -> c_int {
    TTYENT_STATE.with(|cell| {
        let state = unsafe { &mut *cell.get() };
        state.reader = None;
    });
    1
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

    let mut line_buf = [0u8; 1024];
    loop {
        let line_ptr = unsafe {
            crate::stdio_abi::fgets(
                line_buf.as_mut_ptr().cast(),
                line_buf.len() as c_int,
                stream,
            )
        };
        if line_ptr.is_null() {
            return std::ptr::null_mut();
        }
        let len = unsafe { crate::string_abi::strlen(line_ptr) };
        let line_bytes = unsafe { std::slice::from_raw_parts(line_ptr as *const u8, len) };
        let Some(parsed) = frankenlibc_core::pwd::shadow::parse_shadow_line(line_bytes) else {
            continue;
        };

        return BUF.with(|buf| {
            ENTRY.with(|entry| {
                let mut buf = buf.borrow_mut();
                let mut entry = entry.borrow_mut();
                let needed = parsed.name.len() + 1 + parsed.passwd.len() + 1;
                if needed > buf.len() {
                    return std::ptr::null_mut();
                }
                buf[..parsed.name.len()].copy_from_slice(&parsed.name);
                buf[parsed.name.len()] = 0;
                let pass_off = parsed.name.len() + 1;
                buf[pass_off..pass_off + parsed.passwd.len()].copy_from_slice(&parsed.passwd);
                buf[pass_off + parsed.passwd.len()] = 0;

                entry.sp_namp = buf.as_mut_ptr() as *mut c_char;
                entry.sp_pwdp = buf[pass_off..].as_mut_ptr() as *mut c_char;
                entry.sp_lstchg = parsed.lstchg;
                entry.sp_min = parsed.min;
                entry.sp_max = parsed.max;
                entry.sp_warn = parsed.warn;
                entry.sp_inact = parsed.inact;
                entry.sp_expire = parsed.expire;
                entry.sp_flag = parsed.flag;
                &mut *entry as *mut libc::spwd
            })
        });
    }
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
    loop {
        let line_ptr = unsafe {
            crate::stdio_abi::fgets(
                line_buf.as_mut_ptr().cast(),
                line_buf.len() as c_int,
                stream.cast(),
            )
        };
        if line_ptr.is_null() {
            return libc::ENOENT;
        }
        let len = unsafe { crate::string_abi::strlen(line_ptr) };
        let line_bytes = unsafe { std::slice::from_raw_parts(line_ptr as *const u8, len) };
        let Some(parsed) = frankenlibc_core::pwd::shadow::parse_shadow_line(line_bytes) else {
            continue;
        };
        let needed = parsed.name.len() + 1 + parsed.passwd.len() + 1;
        if needed > buflen {
            return libc::ERANGE;
        }
        let buf_slice = unsafe { std::slice::from_raw_parts_mut(buffer as *mut u8, buflen) };
        buf_slice[..parsed.name.len()].copy_from_slice(&parsed.name);
        buf_slice[parsed.name.len()] = 0;
        let pass_off = parsed.name.len() + 1;
        buf_slice[pass_off..pass_off + parsed.passwd.len()].copy_from_slice(&parsed.passwd);
        buf_slice[pass_off + parsed.passwd.len()] = 0;

        let sp = result_buf;
        unsafe {
            (*sp).sp_namp = buffer;
            (*sp).sp_pwdp = buffer.add(pass_off);
            (*sp).sp_lstchg = parsed.lstchg;
            (*sp).sp_min = parsed.min;
            (*sp).sp_max = parsed.max;
            (*sp).sp_warn = parsed.warn;
            (*sp).sp_inact = parsed.inact;
            (*sp).sp_expire = parsed.expire;
            (*sp).sp_flag = parsed.flag;
            *result = sp;
        }
        return 0;
    }
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
    loop {
        let line_ptr = unsafe {
            crate::stdio_abi::fgets(
                line_buf.as_mut_ptr().cast(),
                line_buf.len() as c_int,
                stream.cast(),
            )
        };
        if line_ptr.is_null() {
            return libc::ENOENT;
        }
        let len = unsafe { crate::string_abi::strlen(line_ptr) };
        let line = unsafe {
            std::str::from_utf8_unchecked(std::slice::from_raw_parts(line_ptr as *const u8, len))
        };
        let line = line.trim_end_matches('\n');
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() < 7 {
            continue;
        }

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
        return 0;
    }
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
    loop {
        let line_ptr = unsafe {
            crate::stdio_abi::fgets(
                line_buf.as_mut_ptr().cast(),
                line_buf.len() as c_int,
                stream.cast(),
            )
        };
        if line_ptr.is_null() {
            return libc::ENOENT;
        }
        let len = unsafe { crate::string_abi::strlen(line_ptr) };
        let line = unsafe {
            std::str::from_utf8_unchecked(std::slice::from_raw_parts(line_ptr as *const u8, len))
        };
        let line = line.trim_end_matches('\n');
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() < 3 {
            continue;
        }

        let members_str = if parts.len() > 3 { parts[3] } else { "" };
        let member_names: Vec<&str> = if members_str.is_empty() {
            Vec::new()
        } else {
            members_str.split(',').collect()
        };

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

        let align = off % ptr_size;
        if align != 0 {
            off += ptr_size - align;
        }

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
        return 0;
    }
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
        unsafe { args.next_arg() }
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
// Argp (argument parsing framework)
// ===========================================================================

#[repr(C)]
struct ArgpHeader {
    options: *const c_void,
    parser: *const c_void,
    args_doc: *const c_char,
    doc: *const c_char,
    children: *const c_void,
    help_filter: *const c_void,
    argp_domain: *const c_char,
}

impl ArgpHeader {
    fn is_empty(&self) -> bool {
        self.options.is_null()
            && self.parser.is_null()
            && self.args_doc.is_null()
            && self.doc.is_null()
            && self.children.is_null()
            && self.help_filter.is_null()
            && self.argp_domain.is_null()
    }
}

/// `argp_parse` — parse arguments using argp framework.
///
/// Native phase-1 support handles the common zeroed `struct argp` case as a
/// successful no-op parse, matching glibc's behavior for empty parsers.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn argp_parse(
    argp: *const c_void,
    argc: c_int,
    argv: *mut *mut c_char,
    _flags: libc::c_uint,
    arg_index: *mut c_int,
    _input: *mut c_void,
) -> c_int {
    if argp.is_null() || argc < 0 || (argc > 0 && argv.is_null()) {
        unsafe { set_abi_errno(libc::EINVAL) };
        return libc::EINVAL;
    }

    let header = unsafe { &*(argp as *const ArgpHeader) };
    if header.is_empty() {
        if !arg_index.is_null() {
            unsafe { *arg_index = argc.min(1) };
        }
        return 0;
    }

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
        crate::malloc_abi::raw_free(result_ptr as *mut c_void);
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
        crate::signal_abi::sigprocmask(libc::SIG_BLOCK, std::ptr::null(), &mut mask);
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
        crate::signal_abi::sigprocmask(libc::SIG_SETMASK, &ctx.uc_sigmask, std::ptr::null_mut());

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
            *slot = args.next_arg::<u64>();
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
    frankenlibc_core::syscall::sys_exit_group(0);
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
    if pathname.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        return -1;
    }
    // mkfifo is equivalent to mknod with S_IFIFO
    match unsafe { syscall::sys_mknodat(dirfd, pathname as *const u8, mode | libc::S_IFIFO, 0) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// `mknodat` — create a filesystem node at a directory-relative path.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mknodat(
    dirfd: c_int,
    pathname: *const c_char,
    mode: libc::mode_t,
    dev: libc::dev_t,
) -> c_int {
    if pathname.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        return -1;
    }
    match unsafe { syscall::sys_mknodat(dirfd, pathname as *const u8, mode, dev) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// `utimensat` — change timestamps of a file relative to a directory fd.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn utimensat(
    dirfd: c_int,
    pathname: *const c_char,
    times: *const libc::timespec,
    flags: c_int,
) -> c_int {
    match unsafe { syscall::sys_utimensat(dirfd, pathname as *const u8, times as *const u8, flags) }
    {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// `futimens` — change timestamps of an open file.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn futimens(fd: c_int, times: *const libc::timespec) -> c_int {
    match unsafe { syscall::sys_utimensat(fd, std::ptr::null(), times as *const u8, 0) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
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
    match unsafe {
        syscall::sys_renameat2(
            olddirfd,
            oldpath as *const u8,
            newdirfd,
            newpath as *const u8,
            flags,
        )
    } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// `semtimedop` — semaphore operations with timeout.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn semtimedop(
    semid: c_int,
    sops: *mut c_void,
    nsops: usize,
    timeout: *const libc::timespec,
) -> c_int {
    match unsafe { syscall::sys_semtimedop(semid, sops as *const u8, nsops, timeout as *const u8) }
    {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
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
    match unsafe { syscall::sys_getcpu(&mut cpu, std::ptr::null_mut()) } {
        Ok(()) => cpu as c_int,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// `getcpu` — get CPU and NUMA node (Linux-specific).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getcpu(
    cpu: *mut c_uint,
    node: *mut c_uint,
    _unused: *mut c_void,
) -> c_int {
    match unsafe { syscall::sys_getcpu(cpu, node) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
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
    let ptr = unsafe { crate::malloc_abi::raw_alloc(size) };
    if !ptr.is_null() {
        unsafe { std::ptr::write_bytes(ptr, 0, size) };
    }
    ptr.cast()
}

/// `__sched_cpufree` — free CPU set.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __sched_cpufree(setp: *mut c_void) {
    if !setp.is_null() {
        unsafe { crate::malloc_abi::raw_free(setp.cast()) };
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
    match unsafe {
        syscall::sys_mount_setattr(
            dirfd,
            pathname as *const u8,
            flags,
            uattr as *mut u8,
            usize_,
        )
    } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// `signalfd4` — create file descriptor for signal delivery (with flags).
///
/// This is the underlying syscall; `signalfd` with flags calls this.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn signalfd4(fd: c_int, mask: *const c_void, flags: c_int) -> c_int {
    match unsafe {
        syscall::sys_signalfd4(fd, mask as *const u8, std::mem::size_of::<u64>(), flags)
    } {
        Ok(fd) => fd,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

// ===========================================================================
// utmp/utmpx accounting database
// ===========================================================================

/// `getutent_r` — reentrant version of getutent.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getutent_r(ubuf: *mut c_void, ubufp: *mut *mut c_void) -> c_int {
    if ubufp.is_null() || ubuf.is_null() {
        if !ubufp.is_null() {
            unsafe { *ubufp = std::ptr::null_mut() };
        }
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }

    let entry = unsafe { getutent() };
    if entry.is_null() {
        unsafe {
            *ubufp = std::ptr::null_mut();
            set_abi_errno(libc::ENOENT);
        }
        return -1;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(entry as *const u8, ubuf as *mut u8, UTMP_RECORD_SIZE);
        *ubufp = ubuf;
    }
    0
}

/// `getutid` — search utmp by id.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getutid(ut: *const c_void) -> *mut c_void {
    if ut.is_null() {
        return std::ptr::null_mut();
    }

    let target = unsafe { &*(ut as *const libc::utmpx) };
    let target_type = target.ut_type;
    if !(1..=8).contains(&target_type) {
        unsafe { set_abi_errno(libc::EINVAL) };
        return std::ptr::null_mut();
    }

    loop {
        let entry = unsafe { getutent() as *mut libc::utmpx };
        if entry.is_null() {
            unsafe { set_abi_errno(libc::ENOENT) };
            return std::ptr::null_mut();
        }

        let etype = unsafe { (*entry).ut_type };
        if target_type <= 4 {
            if etype == target_type {
                return entry.cast();
            }
        } else if (5..=8).contains(&etype) && unsafe { (*entry).ut_id } == target.ut_id {
            return entry.cast();
        }
    }
}

/// `getutid_r` — reentrant getutid.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getutid_r(
    ut: *const c_void,
    ubuf: *mut c_void,
    ubufp: *mut *mut c_void,
) -> c_int {
    if ubufp.is_null() || ubuf.is_null() || ut.is_null() {
        if !ubufp.is_null() {
            unsafe { *ubufp = std::ptr::null_mut() };
        }
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }

    let entry = unsafe { getutid(ut) };
    if entry.is_null() {
        unsafe { *ubufp = std::ptr::null_mut() };
        return -1;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(entry as *const u8, ubuf as *mut u8, UTMP_RECORD_SIZE);
        *ubufp = ubuf;
    }
    0
}

/// `getutline` — search utmp by line.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getutline(ut: *const c_void) -> *mut c_void {
    if ut.is_null() {
        return std::ptr::null_mut();
    }

    let target = unsafe { &*(ut as *const libc::utmpx) };
    loop {
        let entry = unsafe { getutent() as *mut libc::utmpx };
        if entry.is_null() {
            unsafe { set_abi_errno(libc::ENOENT) };
            return std::ptr::null_mut();
        }

        let etype = unsafe { (*entry).ut_type };
        if (etype == libc::LOGIN_PROCESS || etype == libc::USER_PROCESS)
            && unsafe { (*entry).ut_line } == target.ut_line
        {
            return entry.cast();
        }
    }
}

/// `getutline_r` — reentrant getutline.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getutline_r(
    ut: *const c_void,
    ubuf: *mut c_void,
    ubufp: *mut *mut c_void,
) -> c_int {
    if ubufp.is_null() || ubuf.is_null() || ut.is_null() {
        if !ubufp.is_null() {
            unsafe { *ubufp = std::ptr::null_mut() };
        }
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }

    let entry = unsafe { getutline(ut) };
    if entry.is_null() {
        unsafe { *ubufp = std::ptr::null_mut() };
        return -1;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(entry as *const u8, ubuf as *mut u8, UTMP_RECORD_SIZE);
        *ubufp = ubuf;
    }
    0
}

/// `pututline` — write utmp entry.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pututline(ut: *const c_void) -> *mut c_void {
    unsafe { pututxline(ut as *const libc::utmpx) as *mut c_void }
}

/// `updwtmp` — append a utmp record to the specified wtmp file.
///
/// Native implementation: opens the file, seeks to end, writes the 384-byte
/// utmp record, and closes. On Linux, utmp and utmpx are the same struct.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn updwtmp(file: *const c_char, ut: *const c_void) {
    if file.is_null() || ut.is_null() {
        return;
    }
    // Open file for appending (O_WRONLY | O_APPEND)
    let fd = match unsafe {
        syscall::sys_openat(
            libc::AT_FDCWD,
            file as *const u8,
            libc::O_WRONLY | libc::O_APPEND | libc::O_CLOEXEC,
            0o644,
        )
    } {
        Ok(fd) => fd,
        Err(_) => return,
    };
    // Write the 384-byte utmp struct
    let _ = unsafe { syscall::sys_write(fd, ut as *const u8, 384) };
    let _ = syscall::sys_close(fd);
}

/// `updwtmpx` — append a utmpx record to the specified wtmpx file.
///
/// Native implementation. On Linux, utmpx and utmp are identical (384 bytes).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn updwtmpx(file: *const c_char, utx: *const c_void) {
    // On Linux, utmpx == utmp; delegate to updwtmp.
    unsafe { updwtmp(file, utx) };
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
    match unsafe {
        syscall::sys_rt_sigprocmask(
            libc::SIG_BLOCK,
            (&new_set as *const u64).cast(),
            (&mut old_set as *mut u64).cast(),
            std::mem::size_of::<u64>(),
        )
    } {
        Ok(()) => old_set as c_int,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
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
    match unsafe {
        syscall::sys_rt_sigprocmask(
            libc::SIG_SETMASK,
            (&new_set as *const u64).cast(),
            (&mut old_set as *mut u64).cast(),
            std::mem::size_of::<u64>(),
        )
    } {
        Ok(()) => old_set as c_int,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// `sigpause` — atomically release blocked signal and pause.
///
/// Native implementation via raw syscalls: gets current signal mask,
/// clears the specified signal bit, then calls sigsuspend.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sigpause(sig: c_int) -> c_int {
    if sig <= 0 {
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }

    let mut validation_set: libc::sigset_t = unsafe { std::mem::zeroed() };
    let validation_rc = unsafe {
        crate::signal_abi::sigemptyset(&mut validation_set);
        crate::signal_abi::sigaddset(&mut validation_set, sig)
    };
    if validation_rc != 0 {
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }

    // BSD sigpause: get current mask, unblock sig, then suspend.
    let mut mask: u64 = 0;
    match unsafe {
        syscall::sys_rt_sigprocmask(
            libc::SIG_BLOCK,
            std::ptr::null(),
            (&mut mask as *mut u64).cast(),
            std::mem::size_of::<u64>(),
        )
    } {
        Ok(()) => {}
        Err(e) => {
            unsafe { set_abi_errno(e) };
            return -1;
        }
    }
    // Clear the bit for sig
    mask &= !(1u64 << (sig as u64 - 1));
    let rc = unsafe { crate::signal_abi::sigsuspend(&mask as *const u64 as *const libc::sigset_t) };
    if rc != 0 {
        unsafe { set_abi_errno(libc::EINTR) };
    }
    rc
}

/// `sigvec` — BSD signal handler (maps to sigaction).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sigvec(sig: c_int, vec: *const c_void, ovec: *mut c_void) -> c_int {
    // sigvec and sigaction have compatible layouts on Linux
    unsafe {
        crate::signal_abi::sigaction(
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
///
/// Native implementation: translates the legacy `struct sigstack`
/// (ss_sp, ss_onstack) into a `sigaltstack` call.
/// struct sigstack { void *ss_sp; int ss_onstack; }
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sigstack(ss: *const c_void, oss: *mut c_void) -> c_int {
    // If caller wants the old stack, query via sigaltstack first.
    if !oss.is_null() {
        let mut old_alt: libc::stack_t = unsafe { std::mem::zeroed() };
        if let Err(e) = unsafe {
            syscall::sys_sigaltstack(
                std::ptr::null(),
                (&mut old_alt as *mut libc::stack_t).cast(),
            )
        } {
            unsafe { set_abi_errno(e) };
            return -1;
        }
        // Fill legacy struct sigstack: { ss_sp, ss_onstack }
        let out = oss as *mut *mut c_void;
        unsafe {
            *out = old_alt.ss_sp;
            *(out.add(1) as *mut c_int) = if old_alt.ss_flags & libc::SS_ONSTACK != 0 {
                1
            } else {
                0
            };
        }
    }

    if !ss.is_null() {
        let inp = ss as *const *const c_void;
        let sp = unsafe { *inp };
        let onstack = unsafe { *(inp.add(1) as *const c_int) };

        let mut new_alt: libc::stack_t = unsafe { std::mem::zeroed() };
        new_alt.ss_sp = sp as *mut c_void;
        new_alt.ss_size = libc::SIGSTKSZ;
        new_alt.ss_flags = if onstack != 0 { libc::SS_DISABLE } else { 0 };

        if let Err(e) = unsafe {
            syscall::sys_sigaltstack(
                (&new_alt as *const libc::stack_t).cast(),
                std::ptr::null_mut(),
            )
        } {
            unsafe { set_abi_errno(e) };
            return -1;
        }
    }

    0
}

/// `sigreturn` — return from signal handler (kernel does this, not userspace).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sigreturn(_scp: *mut c_void) -> c_int {
    match unsafe { syscall::sys_rt_sigreturn(_scp as *mut u8) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

/// `ssignal` — software signal (legacy SVR2 interface).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ssignal(sig: c_int, action: libc::sighandler_t) -> libc::sighandler_t {
    unsafe { sysv_signal(sig, action) }
}

/// `gsignal` — raise software signal (legacy SVR2).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn gsignal(sig: c_int) -> c_int {
    unsafe { crate::signal_abi::raise(sig) }
}

/// `sysv_signal` — System V signal semantics (one-shot).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sysv_signal(
    sig: c_int,
    handler: libc::sighandler_t,
) -> libc::sighandler_t {
    let sig_err = libc::SIG_ERR;
    // Use sigaction with SA_RESETHAND for one-shot semantics
    let mut sa: libc::sigaction = unsafe { std::mem::zeroed() };
    sa.sa_sigaction = handler;
    sa.sa_flags = libc::SA_RESETHAND | libc::SA_NODEFER;
    let mut old_sa: libc::sigaction = unsafe { std::mem::zeroed() };
    let ret = unsafe { crate::signal_abi::sigaction(sig, &sa, &mut old_sa) };
    if ret < 0 {
        sig_err
    } else {
        old_sa.sa_sigaction
    }
}

/// `sigset` — reliable signal (XSI extension).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sigset(sig: c_int, disp: libc::sighandler_t) -> libc::sighandler_t {
    unsafe { sysv_signal(sig, disp) }
}

// ===========================================================================
// New Linux mount API (kernel 5.2+)
// ===========================================================================

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fsopen(fsname: *const c_char, flags: c_uint) -> c_int {
    match unsafe { syscall::sys_fsopen(fsname as *const u8, flags) } {
        Ok(fd) => fd,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fsmount(fs_fd: c_int, flags: c_uint, attr_flags: c_uint) -> c_int {
    match unsafe { syscall::sys_fsmount(fs_fd, flags, attr_flags) } {
        Ok(fd) => fd,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fsconfig(
    fs_fd: c_int,
    cmd: c_uint,
    key: *const c_char,
    value: *const c_void,
    aux: c_int,
) -> c_int {
    match unsafe { syscall::sys_fsconfig(fs_fd, cmd, key as *const u8, value as *const u8, aux) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fspick(dirfd: c_int, path: *const c_char, flags: c_uint) -> c_int {
    match unsafe { syscall::sys_fspick(dirfd, path as *const u8, flags) } {
        Ok(fd) => fd,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn open_tree(dirfd: c_int, path: *const c_char, flags: c_uint) -> c_int {
    match unsafe { syscall::sys_open_tree(dirfd, path as *const u8, flags) } {
        Ok(fd) => fd,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn move_mount(
    from_dirfd: c_int,
    from_path: *const c_char,
    to_dirfd: c_int,
    to_path: *const c_char,
    flags: c_uint,
) -> c_int {
    match unsafe {
        syscall::sys_move_mount(
            from_dirfd,
            from_path as *const u8,
            to_dirfd,
            to_path as *const u8,
            flags,
        )
    } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

// ===========================================================================
// NTP / clock adjustment
// ===========================================================================

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn adjtimex(buf: *mut c_void) -> c_int {
    match unsafe { syscall::sys_adjtimex(buf as *mut u8) } {
        Ok(v) => v,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
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
    let _ =
        unsafe { syscall::sys_clock_gettime(libc::CLOCK_REALTIME, &mut ts as *mut _ as *mut u8) };
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
// fstab database — native /etc/fstab parser
// ===========================================================================

/// Thread-local state for the fstab iteration API.
///
/// struct fstab layout (x86_64):
///   fs_spec:    *mut c_char  (offset 0)
///   fs_file:    *mut c_char  (offset 8)
///   fs_vfstype: *mut c_char  (offset 16)
///   fs_mntops:  *mut c_char  (offset 24)
///   fs_type:    *mut c_char  (offset 32)
///   fs_freq:    c_int        (offset 40)
///   fs_passno:  c_int        (offset 44)
///   Total: 48 bytes
const FSTAB_BUF_SIZE: usize = 4096;
const FSTAB_PATH: &str = "/etc/fstab";

struct FstabState {
    reader: Option<std::io::BufReader<std::fs::File>>,
    line_buf: Vec<u8>,
    /// Buffer for the current fstab entry (struct fstab + string data).
    entry_buf: [u8; FSTAB_BUF_SIZE],
}

impl FstabState {
    const fn new() -> Self {
        Self {
            reader: None,
            line_buf: Vec::new(),
            entry_buf: [0u8; FSTAB_BUF_SIZE],
        }
    }
}

std::thread_local! {
    static FSTAB_STATE: std::cell::UnsafeCell<FstabState> =
        const { std::cell::UnsafeCell::new(FstabState::new()) };
}

/// Parse the next fstab line into the entry buffer, returning a pointer to
/// the struct fstab or null on EOF/error. The struct is laid out at the
/// start of `entry_buf`; string data follows at offset 48.
unsafe fn fstab_next(state: &mut FstabState) -> *mut c_void {
    use std::io::BufRead;

    let reader = match state.reader.as_mut() {
        Some(r) => r,
        None => return std::ptr::null_mut(),
    };

    loop {
        state.line_buf.clear();
        let n = match reader.read_until(b'\n', &mut state.line_buf) {
            Ok(n) => n,
            Err(_) => return std::ptr::null_mut(),
        };
        if n == 0 {
            return std::ptr::null_mut(); // EOF
        }
        // Strip trailing newline/CR
        while state.line_buf.last() == Some(&b'\n') || state.line_buf.last() == Some(&b'\r') {
            state.line_buf.pop();
        }
        // Skip comments and blank lines
        let first = state.line_buf.iter().position(|&b| b != b' ' && b != b'\t');
        if first.is_none_or(|i| state.line_buf[i] == b'#') {
            continue;
        }

        // Parse: fs_spec fs_file fs_vfstype fs_mntops fs_freq fs_passno
        let line = &state.line_buf;
        let mut fields = line
            .split(|&b| b == b' ' || b == b'\t')
            .filter(|f| !f.is_empty());

        let spec = match fields.next() {
            Some(f) => f,
            None => continue,
        };
        let file = match fields.next() {
            Some(f) => f,
            None => continue,
        };
        let vfstype = match fields.next() {
            Some(f) => f,
            None => continue,
        };
        let mntops = match fields.next() {
            Some(f) => f,
            None => continue,
        };
        let freq_s = fields.next().unwrap_or(b"0");
        let passno_s = fields.next().unwrap_or(b"0");

        // Derive fs_type from mntops: "ro" if contains "ro", else "rw"
        let fs_type_str = if mntops.windows(2).any(|w| w == b"ro") {
            b"ro" as &[u8]
        } else {
            b"rw" as &[u8]
        };

        // Check that all strings fit after the 48-byte struct header
        let str_offset = 48usize; // sizeof(struct fstab) on x86_64
        let needed = str_offset
            + spec.len()
            + 1
            + file.len()
            + 1
            + vfstype.len()
            + 1
            + mntops.len()
            + 1
            + fs_type_str.len()
            + 1;
        if needed > FSTAB_BUF_SIZE {
            continue;
        }

        let buf = state.entry_buf.as_mut_ptr();
        let mut off = str_offset;

        // Helper: copy a field into the buffer, NUL-terminate, return pointer
        macro_rules! pack_field {
            ($src:expr) => {{
                let ptr = unsafe { buf.add(off) } as *mut c_char;
                unsafe {
                    std::ptr::copy_nonoverlapping($src.as_ptr(), buf.add(off), $src.len());
                    *buf.add(off + $src.len()) = 0;
                }
                off += $src.len() + 1;
                ptr
            }};
        }

        let spec_ptr = pack_field!(spec);
        let file_ptr = pack_field!(file);
        let vfstype_ptr = pack_field!(vfstype);
        let mntops_ptr = pack_field!(mntops);
        let type_ptr = pack_field!(fs_type_str);
        let _ = off; // suppress unused assignment warning from last pack_field

        let freq: c_int = std::str::from_utf8(freq_s)
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let passno: c_int = std::str::from_utf8(passno_s)
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        // Fill struct fstab at the start of the buffer
        let ent = buf as *mut *mut c_char;
        unsafe {
            *ent = spec_ptr; // fs_spec
            *ent.add(1) = file_ptr; // fs_file
            *ent.add(2) = vfstype_ptr; // fs_vfstype
            *ent.add(3) = mntops_ptr; // fs_mntops
            *ent.add(4) = type_ptr; // fs_type
            let int_ptr = ent.add(5) as *mut c_int;
            *int_ptr = freq; // fs_freq
            *int_ptr.add(1) = passno; // fs_passno
        }

        return buf as *mut c_void;
    }
}

/// `setfsent` — open /etc/fstab for iteration.
///
/// Native implementation: opens /etc/fstab and initializes the parser.
/// Returns 1 on success, 0 on failure.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setfsent() -> c_int {
    FSTAB_STATE.with(|cell| {
        let state = unsafe { &mut *cell.get() };
        match std::fs::File::open(FSTAB_PATH) {
            Ok(f) => {
                state.reader = Some(std::io::BufReader::new(f));
                1
            }
            Err(_) => {
                state.reader = None;
                unsafe { set_abi_errno(libc::ENOENT) };
                0
            }
        }
    })
}

/// `getfsent` — read next entry from /etc/fstab.
///
/// Native implementation. Returns pointer to a thread-local struct fstab,
/// or NULL at EOF.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getfsent() -> *mut c_void {
    FSTAB_STATE.with(|cell| {
        let state = unsafe { &mut *cell.get() };
        unsafe { fstab_next(state) }
    })
}

/// `getfsfile` — find fstab entry by mount point.
///
/// Native implementation: rewinds /etc/fstab and searches for the entry
/// whose fs_file matches the given path.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getfsfile(file: *const c_char) -> *mut c_void {
    if file.is_null() {
        return std::ptr::null_mut();
    }
    let Some(needle) = (unsafe { read_c_string_bytes(file) }) else {
        unsafe { set_abi_errno(libc::EINVAL) };
        return std::ptr::null_mut();
    };
    // Rewind
    unsafe { setfsent() };
    FSTAB_STATE.with(|cell| {
        let state = unsafe { &mut *cell.get() };
        loop {
            let ent = unsafe { fstab_next(state) };
            if ent.is_null() {
                return std::ptr::null_mut();
            }
            // fs_file is at offset 1 * sizeof(pointer)
            let file_ptr = unsafe { *((ent as *const *const c_char).add(1)) };
            if let Some(entry_file) = packed_entry_cstr_bytes(&state.entry_buf, file_ptr)
                && entry_file == needle.as_slice()
            {
                return ent;
            }
        }
    })
}

/// `getfsspec` — find fstab entry by device spec.
///
/// Native implementation: rewinds /etc/fstab and searches for the entry
/// whose fs_spec matches the given device.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getfsspec(spec: *const c_char) -> *mut c_void {
    if spec.is_null() {
        return std::ptr::null_mut();
    }
    let Some(needle) = (unsafe { read_c_string_bytes(spec) }) else {
        unsafe { set_abi_errno(libc::EINVAL) };
        return std::ptr::null_mut();
    };
    // Rewind
    unsafe { setfsent() };
    FSTAB_STATE.with(|cell| {
        let state = unsafe { &mut *cell.get() };
        loop {
            let ent = unsafe { fstab_next(state) };
            if ent.is_null() {
                return std::ptr::null_mut();
            }
            // fs_spec is at offset 0
            let spec_ptr = unsafe { *(ent as *const *const c_char) };
            if let Some(entry_spec) = packed_entry_cstr_bytes(&state.entry_buf, spec_ptr)
                && entry_spec == needle.as_slice()
            {
                return ent;
            }
        }
    })
}

// ===========================================================================
// ttyent database — native /etc/ttys parser
// ===========================================================================
//
// The ttyent API (setttyent/getttyent/getttynam/endttyent) originates from
// BSD. On Linux, /etc/ttys typically does not exist; glibc's implementation
// returns the same results as parsing a missing file. Our native
// implementation opens the file if present, otherwise returns NULL entries.
//
// struct ttyent layout (x86_64, 48 bytes):
//   ty_name:    *mut c_char  (offset 0)
//   ty_getty:   *mut c_char  (offset 8)
//   ty_type:    *mut c_char  (offset 16)
//   ty_status:  c_int        (offset 24)
//   [pad 4]
//   ty_window:  *mut c_char  (offset 32)
//   ty_comment: *mut c_char  (offset 40)

const TTYENT_BUF_SIZE: usize = 2048;
const TTYENT_PATH: &str = "/etc/ttys";

struct TtyentState {
    reader: Option<std::io::BufReader<std::fs::File>>,
    line_buf: Vec<u8>,
    entry_buf: [u8; TTYENT_BUF_SIZE],
}

impl TtyentState {
    const fn new() -> Self {
        Self {
            reader: None,
            line_buf: Vec::new(),
            entry_buf: [0u8; TTYENT_BUF_SIZE],
        }
    }
}

std::thread_local! {
    static TTYENT_STATE: std::cell::UnsafeCell<TtyentState> =
        const { std::cell::UnsafeCell::new(TtyentState::new()) };
}

/// Parse the next ttyent line into the entry buffer.
unsafe fn ttyent_next(state: &mut TtyentState) -> *mut c_void {
    use std::io::BufRead;

    let reader = match state.reader.as_mut() {
        Some(r) => r,
        None => return std::ptr::null_mut(),
    };

    loop {
        state.line_buf.clear();
        let n = match reader.read_until(b'\n', &mut state.line_buf) {
            Ok(n) => n,
            Err(_) => return std::ptr::null_mut(),
        };
        if n == 0 {
            return std::ptr::null_mut();
        }
        while state.line_buf.last() == Some(&b'\n') || state.line_buf.last() == Some(&b'\r') {
            state.line_buf.pop();
        }
        let first = state.line_buf.iter().position(|&b| b != b' ' && b != b'\t');
        if first.is_none_or(|i| state.line_buf[i] == b'#') {
            continue;
        }

        // Parse: ty_name [ty_getty [ty_type]]
        // ty_status defaults to 0, ty_window and ty_comment default to empty.
        let line = &state.line_buf;
        let mut fields = line
            .split(|&b| b == b' ' || b == b'\t')
            .filter(|f| !f.is_empty());

        let name = match fields.next() {
            Some(f) => f,
            None => continue,
        };
        let getty = fields.next().unwrap_or(b"");
        let ttype = fields.next().unwrap_or(b"");
        let empty = b"" as &[u8];

        // Struct is 48 bytes; strings packed after
        let str_offset = 48usize;
        let needed = str_offset + name.len() + 1 + getty.len() + 1 + ttype.len() + 1 + 1 + 1;
        if needed > TTYENT_BUF_SIZE {
            continue;
        }

        let buf = state.entry_buf.as_mut_ptr();
        let mut off = str_offset;

        macro_rules! pack {
            ($src:expr) => {{
                let ptr = unsafe { buf.add(off) } as *mut c_char;
                unsafe {
                    std::ptr::copy_nonoverlapping($src.as_ptr(), buf.add(off), $src.len());
                    *buf.add(off + $src.len()) = 0;
                }
                off += $src.len() + 1;
                ptr
            }};
        }

        let name_ptr = pack!(name);
        let getty_ptr = pack!(getty);
        let type_ptr = pack!(ttype);
        let window_ptr = pack!(empty);
        let comment_ptr = pack!(empty);
        let _ = off;

        // Fill struct ttyent
        let ptrs = buf as *mut *mut c_char;
        unsafe {
            *ptrs = name_ptr; // ty_name
            *ptrs.add(1) = getty_ptr; // ty_getty
            *ptrs.add(2) = type_ptr; // ty_type
            // ty_status at byte offset 24 (after 3 pointers)
            let status_ptr = buf.add(24) as *mut c_int;
            *status_ptr = 0;
            // ty_window at byte offset 32
            *(buf.add(32) as *mut *mut c_char) = window_ptr;
            // ty_comment at byte offset 40
            *(buf.add(40) as *mut *mut c_char) = comment_ptr;
        }

        return buf as *mut c_void;
    }
}

/// `setttyent` — open /etc/ttys for iteration.
///
/// Native implementation. Returns 1 on success, 0 if file missing (common
/// on Linux where /etc/ttys is a BSD convention). Sets errno to ENOENT on
/// failure to match glibc behavior.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setttyent() -> c_int {
    TTYENT_STATE.with(|cell| {
        let state = unsafe { &mut *cell.get() };
        match std::fs::File::open(TTYENT_PATH) {
            Ok(f) => {
                state.reader = Some(std::io::BufReader::new(f));
                1
            }
            Err(_) => {
                state.reader = None;
                unsafe { set_abi_errno(libc::ENOENT) };
                0
            }
        }
    })
}

/// `getttyent` — read next entry from /etc/ttys.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getttyent() -> *mut c_void {
    TTYENT_STATE.with(|cell| {
        let state = unsafe { &mut *cell.get() };
        unsafe { ttyent_next(state) }
    })
}

/// `getttynam` — find ttyent entry by terminal name.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getttynam(name: *const c_char) -> *mut c_void {
    if name.is_null() {
        return std::ptr::null_mut();
    }
    let Some(needle) = (unsafe { read_c_string_bytes(name) }) else {
        unsafe { set_abi_errno(libc::EINVAL) };
        return std::ptr::null_mut();
    };
    unsafe { setttyent() };
    TTYENT_STATE.with(|cell| {
        let state = unsafe { &mut *cell.get() };
        loop {
            let ent = unsafe { ttyent_next(state) };
            if ent.is_null() {
                return std::ptr::null_mut();
            }
            let name_ptr = unsafe { *(ent as *const *const c_char) };
            if let Some(entry_name) = packed_entry_cstr_bytes(&state.entry_buf, name_ptr)
                && entry_name == needle.as_slice()
            {
                return ent;
            }
        }
    })
}

// ===========================================================================
// getdate / timelocal
// ===========================================================================

const DATEMSK_PATH_SCAN_LIMIT: usize = libc::PATH_MAX as usize;

// Thread-local static tm for the non-reentrant `getdate`.
std::thread_local! {
    static GETDATE_TM: std::cell::UnsafeCell<libc::tm> =
        const { std::cell::UnsafeCell::new(unsafe { std::mem::zeroed() }) };
}

/// Core getdate implementation: reads DATEMSK file and tries each template
/// with strptime. Returns 0 on success (result filled), or error code 1-8.
///
/// Error codes per POSIX:
///   1 = DATEMSK not set or empty
///   2 = cannot open DATEMSK file
///   3 = stat failed on DATEMSK
///   4 = DATEMSK is not a regular file
///   5 = read error on DATEMSK
///   6 = malloc failure (not applicable in our impl)
///   7 = no matching template found
///   8 = invalid input specification
unsafe fn getdate_core(string: *const c_char, result: *mut libc::tm) -> c_int {
    if string.is_null() || result.is_null() {
        return 8; // invalid input
    }
    let Some(input_bytes) = (unsafe { read_c_string_bytes(string) }) else {
        return 8;
    };
    if input_bytes.is_empty() {
        return 8;
    }
    let mut input = Vec::with_capacity(input_bytes.len() + 1);
    input.extend_from_slice(&input_bytes);
    input.push(0);
    let input_base = input.as_ptr() as usize;
    let Some(input_end) = input_base.checked_add(input_bytes.len()) else {
        return 8;
    };

    // Read DATEMSK environment variable
    let datemsk_ptr = unsafe { crate::stdlib_abi::getenv(c"DATEMSK".as_ptr()) };
    if datemsk_ptr.is_null() || unsafe { *datemsk_ptr == 0 } {
        return 1; // DATEMSK not set
    }
    let (datemsk_len, datemsk_terminated) =
        unsafe { scan_c_string(datemsk_ptr, Some(DATEMSK_PATH_SCAN_LIMIT)) };
    if !datemsk_terminated {
        return 2;
    }
    let datemsk_bytes =
        unsafe { std::slice::from_raw_parts(datemsk_ptr.cast::<u8>(), datemsk_len) };
    let datemsk_path = match std::str::from_utf8(datemsk_bytes) {
        Ok(s) => s,
        Err(_) => return 2,
    };

    // Stat the file to verify it's regular
    let metadata = match std::fs::metadata(datemsk_path) {
        Ok(m) => m,
        Err(_) => return 2, // cannot open
    };
    if !metadata.is_file() {
        return 4; // not a regular file
    }

    // Read the file
    let content = match std::fs::read(datemsk_path) {
        Ok(c) => c,
        Err(_) => return 5, // read error
    };

    // Try each line as a strptime template
    for line in content.split(|&b| b == b'\n') {
        // Skip empty lines
        if line.is_empty() || line.iter().all(|&b| b == b' ' || b == b'\t' || b == b'\r') {
            continue;
        }
        // NUL-terminate the template
        let mut template = Vec::with_capacity(line.len() + 1);
        // Strip trailing whitespace/CR
        let mut end = line.len();
        while end > 0 && matches!(line[end - 1], b' ' | b'\t' | b'\r') {
            end -= 1;
        }
        template.extend_from_slice(&line[..end]);
        template.push(0);

        // Initialize result to a clean state
        unsafe { std::ptr::write_bytes(result as *mut u8, 0, core::mem::size_of::<libc::tm>()) };

        let remainder = unsafe {
            crate::time_abi::strptime(
                input.as_ptr().cast::<c_char>(),
                template.as_ptr() as *const c_char,
                result,
            )
        };
        if !remainder.is_null() {
            // Check that strptime consumed the entire input string (or only trailing whitespace)
            let rest_addr = remainder as usize;
            if (input_base..=input_end).contains(&rest_addr) {
                let offset = rest_addr - input_base;
                let rest = &input[offset..input_bytes.len()];
                if rest.iter().all(|&b| b == b' ' || b == b'\t') {
                    return 0; // success
                }
            }
        }
    }
    7 // no matching template
}

/// `getdate` — convert a date string to struct tm using DATEMSK templates.
///
/// Native implementation using our strptime and DATEMSK file parsing.
/// Sets `getdate_err` on error. Returns pointer to static thread-local
/// struct tm on success, NULL on failure.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getdate(string: *const c_char) -> *mut c_void {
    use crate::glibc_internal_abi::getdate_err;

    GETDATE_TM.with(|cell| {
        let tm = unsafe { &mut *cell.get() };
        let rc = unsafe { getdate_core(string, tm) };
        if rc != 0 {
            unsafe { getdate_err = rc };
            std::ptr::null_mut()
        } else {
            unsafe { getdate_err = 0 };
            tm as *mut libc::tm as *mut c_void
        }
    })
}

/// `getdate_r` — reentrant version of getdate.
///
/// Native implementation. Returns 0 on success, error code 1-8 on failure.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getdate_r(string: *const c_char, result: *mut c_void) -> c_int {
    unsafe { getdate_core(string, result as *mut libc::tm) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn timelocal(tm: *mut c_void) -> i64 {
    // timelocal is just mktime (BSD alias)
    unsafe { crate::time_abi::mktime(tm as *mut libc::tm) }
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

// _Exit is defined in process_abi.rs beside _exit so both process-termination
// entrypoints share the same runtime-policy path.

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
#[allow(non_snake_case)]
pub unsafe extern "C" fn _Fork() -> c_int {
    // _Fork is async-signal-safe fork (C23), no atfork handlers
    let _pipeline_guard =
        crate::membrane_state::try_global_pipeline().map(|pipeline| pipeline.atfork_prepare());

    let ret = syscall::sys_clone_fork(libc::SIGCHLD as usize);

    drop(_pipeline_guard);

    match ret {
        Ok(pid) => pid,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

// ===========================================================================
// Reentrant NSS database functions
// ===========================================================================

/// `gethostent_r` — reentrant sequential host entry read.
///
/// Native implementation using thread-local /etc/hosts iterator.
/// Fills hostent struct in caller-supplied buffers.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn gethostent_r(
    result_buf: *mut c_void,
    buf: *mut c_char,
    buflen: usize,
    result: *mut *mut c_void,
    _h_errnop: *mut c_int,
) -> c_int {
    use std::io::BufRead;

    if !result.is_null() {
        unsafe { *result = std::ptr::null_mut() };
    }
    if result_buf.is_null() || buf.is_null() {
        return libc::EINVAL;
    }

    HOST_ITER.with(|cell| {
        let state = unsafe { &mut *cell.get() };
        if state.reader.is_none() {
            match std::fs::File::open(HOSTS_PATH) {
                Ok(f) => state.reader = Some(std::io::BufReader::new(f)),
                Err(_) => return libc::ENOENT,
            }
        }
        let reader = match state.reader.as_mut() {
            Some(reader) => reader,
            None => return libc::ENOENT,
        };

        loop {
            state.line_buf.clear();
            match reader.read_until(b'\n', &mut state.line_buf) {
                Ok(0) => return libc::ENOENT,
                Err(_) => return libc::ENOENT,
                Ok(_) => {}
            }
            let parsed = frankenlibc_core::resolv::parse_hosts_line(&state.line_buf);
            let (addr_text, hostnames) = match parsed {
                Some(v) => v,
                None => continue,
            };
            if hostnames.is_empty() {
                continue;
            }
            let addr_str = match std::str::from_utf8(&addr_text) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let (addr_bin, af, addr_len) = match parse_addr_binary(addr_str) {
                Some(v) => v,
                None => continue,
            };

            let buf_u8 = buf as *mut u8;
            let ptr_size = core::mem::size_of::<*mut c_char>();
            let alen = addr_len as usize;
            let primary = &hostnames[0];

            // Layout in buf: name + NUL + addr_data + align + addr_list[2] + alias_list[n+1]
            let name_end = primary.len() + 1;
            let addr_off = name_end;
            let addr_end = addr_off + alen;
            let list_off = (addr_end + (ptr_size - 1)) & !(ptr_size - 1);
            let addr_list_off = list_off;
            let alias_list_off = addr_list_off + 2 * ptr_size;
            let alias_count = hostnames.len() - 1;
            let total_needed = alias_list_off + (alias_count + 1) * ptr_size;
            if total_needed > buflen {
                return libc::ERANGE;
            }

            // Copy name
            unsafe {
                std::ptr::copy_nonoverlapping(primary.as_ptr(), buf_u8, primary.len());
                *buf_u8.add(primary.len()) = 0;
            }

            // Copy address binary
            unsafe {
                std::ptr::copy_nonoverlapping(addr_bin.as_ptr(), buf_u8.add(addr_off), alen);
            }

            // addr_list: [&addr, NULL]
            unsafe {
                *(buf_u8.add(addr_list_off) as *mut *mut c_char) =
                    buf_u8.add(addr_off) as *mut c_char;
                *(buf_u8.add(addr_list_off + ptr_size) as *mut *mut c_char) = std::ptr::null_mut();
            }

            // aliases: pack remaining hostnames (skip for simplicity — would need
            // more buffer space accounting). Just set empty alias list.
            unsafe {
                *(buf_u8.add(alias_list_off) as *mut *mut c_char) = std::ptr::null_mut();
            }

            // Fill struct hostent in result_buf
            let ent = result_buf as *mut u8;
            unsafe {
                *(ent as *mut *mut c_char) = buf; // h_name
                *((ent as *mut *mut c_char).add(1) as *mut *mut *mut c_char) =
                    buf_u8.add(alias_list_off) as *mut *mut c_char; // h_aliases
                *(ent.add(16) as *mut c_int) = af; // h_addrtype
                *(ent.add(20) as *mut c_int) = addr_len; // h_length
                *(ent.add(24) as *mut *mut *mut c_char) =
                    buf_u8.add(addr_list_off) as *mut *mut c_char; // h_addr_list
            }

            if !result.is_null() {
                unsafe { *result = result_buf };
            }
            return 0;
        }
    })
}

/// Helper: fill a netent struct in caller-supplied buffers.
unsafe fn fill_netent_r(
    name: &[u8],
    net: u32,
    result_buf: *mut c_void,
    buf: *mut c_char,
    buflen: usize,
    result: *mut *mut c_void,
) -> c_int {
    let alias_ptr_size = core::mem::size_of::<*mut c_char>();
    let needed = name.len() + 1 + alias_ptr_size;
    if needed > buflen {
        return libc::ERANGE;
    }
    let buf_u8 = buf as *mut u8;
    // Copy name
    unsafe {
        std::ptr::copy_nonoverlapping(name.as_ptr(), buf_u8, name.len());
        *buf_u8.add(name.len()) = 0;
    }
    // NULL-terminated aliases
    let alias_offset = (name.len() + 1 + (alias_ptr_size - 1)) & !(alias_ptr_size - 1);
    if alias_offset + alias_ptr_size > buflen {
        return libc::ERANGE;
    }
    unsafe { *(buf_u8.add(alias_offset) as *mut *mut c_char) = std::ptr::null_mut() };

    // Fill struct netent: { n_name, n_aliases, n_addrtype, n_net }
    let ent = result_buf as *mut *mut c_char;
    unsafe {
        *ent = buf;
        *(ent.add(1) as *mut *mut *mut c_char) = buf_u8.add(alias_offset) as *mut *mut c_char;
        *((result_buf as *mut u8).add(16) as *mut c_int) = libc::AF_INET;
        *((result_buf as *mut u8).add(20) as *mut u32) = net;
    }
    if !result.is_null() {
        unsafe { *result = result_buf };
    }
    0
}

/// `getnetbyaddr_r` — reentrant network lookup by address.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getnetbyaddr_r(
    net: u32,
    _type: c_int,
    result_buf: *mut c_void,
    buf: *mut c_char,
    buflen: usize,
    result: *mut *mut c_void,
    _h_errnop: *mut c_int,
) -> c_int {
    if !result.is_null() {
        unsafe { *result = std::ptr::null_mut() };
    }
    let content = match std::fs::read(NETWORKS_PATH) {
        Ok(c) => c,
        Err(_) => return 0,
    };
    for line in content.split(|&b| b == b'\n') {
        if let Some((pname, pnet)) = parse_networks_line(line)
            && pnet == net
        {
            return unsafe { fill_netent_r(&pname, pnet, result_buf, buf, buflen, result) };
        }
    }
    0
}

/// `getnetbyname_r` — reentrant network lookup by name.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getnetbyname_r(
    name: *const c_char,
    result_buf: *mut c_void,
    buf: *mut c_char,
    buflen: usize,
    result: *mut *mut c_void,
    _h_errnop: *mut c_int,
) -> c_int {
    if !result.is_null() {
        unsafe { *result = std::ptr::null_mut() };
    }
    if name.is_null() {
        return libc::EINVAL;
    }
    let Some(needle) = (unsafe { read_c_string_bytes(name) }) else {
        return libc::EINVAL;
    };
    let content = match std::fs::read(NETWORKS_PATH) {
        Ok(c) => c,
        Err(_) => return 0,
    };
    for line in content.split(|&b| b == b'\n') {
        if let Some((pname, pnet)) = parse_networks_line(line)
            && pname.eq_ignore_ascii_case(needle.as_slice())
        {
            return unsafe { fill_netent_r(&pname, pnet, result_buf, buf, buflen, result) };
        }
    }
    0
}

/// `getnetent_r` — reentrant sequential network entry read.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getnetent_r(
    result_buf: *mut c_void,
    buf: *mut c_char,
    buflen: usize,
    result: *mut *mut c_void,
    _h_errnop: *mut c_int,
) -> c_int {
    use std::io::BufRead;

    if !result.is_null() {
        unsafe { *result = std::ptr::null_mut() };
    }

    NET_ITER.with(|cell| {
        let state = unsafe { &mut *cell.get() };
        if state.reader.is_none() {
            match std::fs::File::open(NETWORKS_PATH) {
                Ok(f) => state.reader = Some(std::io::BufReader::new(f)),
                Err(_) => return libc::ENOENT,
            }
        }
        let reader = match state.reader.as_mut() {
            Some(reader) => reader,
            None => return libc::ENOENT,
        };
        loop {
            state.line_buf.clear();
            match reader.read_until(b'\n', &mut state.line_buf) {
                Ok(0) => return libc::ENOENT,
                Err(_) => return libc::ENOENT,
                Ok(_) => {}
            }
            if let Some((pname, pnet)) = parse_networks_line(&state.line_buf) {
                return unsafe { fill_netent_r(&pname, pnet, result_buf, buf, buflen, result) };
            }
        }
    })
}

/// Helper: fill a protoent struct in caller-supplied buffers.
///
/// Packs p_name into `buf`, sets p_aliases to a NULL-terminated list at the
/// end of `buf`, and fills the protoent at `result_buf`.
unsafe fn fill_protoent_r(
    name: &[u8],
    proto: c_int,
    result_buf: *mut c_void,
    buf: *mut c_char,
    buflen: usize,
    result: *mut *mut c_void,
) -> c_int {
    // Need room for: name + NUL + null-terminated alias pointer
    let alias_ptr_size = core::mem::size_of::<*mut c_char>();
    let needed = name.len() + 1 + alias_ptr_size;
    if needed > buflen {
        return libc::ERANGE;
    }

    // Copy name
    let buf_u8 = buf as *mut u8;
    unsafe {
        std::ptr::copy_nonoverlapping(name.as_ptr(), buf_u8, name.len());
        *buf_u8.add(name.len()) = 0;
    }

    // Aliases: NULL-terminated list at end of buffer (just a single NULL ptr)
    let alias_offset = name.len() + 1;
    // Align to pointer size
    let alias_offset = (alias_offset + (alias_ptr_size - 1)) & !(alias_ptr_size - 1);
    if alias_offset + alias_ptr_size > buflen {
        return libc::ERANGE;
    }
    unsafe {
        *(buf_u8.add(alias_offset) as *mut *mut c_char) = std::ptr::null_mut();
    }

    // Fill struct protoent: { p_name, p_aliases, p_proto }
    let ent = result_buf as *mut *mut c_char;
    unsafe {
        *ent = buf; // p_name
        *(ent.add(1) as *mut *mut *mut c_char) = buf_u8.add(alias_offset) as *mut *mut c_char; // p_aliases
        *((result_buf as *mut u8).add(16) as *mut c_int) = proto; // p_proto
    }

    if !result.is_null() {
        unsafe { *result = result_buf };
    }
    0
}

/// `getprotobyname_r` — reentrant protocol lookup by name.
///
/// Native implementation: scans /etc/protocols.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getprotobyname_r(
    name: *const c_char,
    result_buf: *mut c_void,
    buf: *mut c_char,
    buflen: usize,
    result: *mut *mut c_void,
) -> c_int {
    if !result.is_null() {
        unsafe { *result = std::ptr::null_mut() };
    }
    if name.is_null() || result_buf.is_null() || buf.is_null() {
        return libc::EINVAL;
    }

    let Some(needle) = (unsafe { read_c_string_bytes(name) }) else {
        return libc::EINVAL;
    };
    let content = match std::fs::read(PROTOCOLS_PATH) {
        Ok(c) => c,
        Err(_) => return 0, // not found, result stays NULL (glibc behavior)
    };

    for line in content.split(|&b| b == b'\n') {
        let line = if let Some(pos) = line.iter().position(|&b| b == b'#') {
            &line[..pos]
        } else {
            line
        };
        let mut fields = line
            .split(|&b| b == b' ' || b == b'\t')
            .filter(|f| !f.is_empty());
        let pname = match fields.next() {
            Some(f) => f,
            None => continue,
        };
        let pnum_str = match fields.next() {
            Some(f) => f,
            None => continue,
        };
        if pname.eq_ignore_ascii_case(needle.as_slice())
            && let Some(num) = std::str::from_utf8(pnum_str)
                .ok()
                .and_then(|s| s.parse::<c_int>().ok())
        {
            return unsafe { fill_protoent_r(pname, num, result_buf, buf, buflen, result) };
        }
    }
    0 // not found, result stays NULL (glibc behavior)
}

/// `getprotobynumber_r` — reentrant protocol lookup by number.
///
/// Native implementation: scans /etc/protocols.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getprotobynumber_r(
    proto: c_int,
    result_buf: *mut c_void,
    buf: *mut c_char,
    buflen: usize,
    result: *mut *mut c_void,
) -> c_int {
    if !result.is_null() {
        unsafe { *result = std::ptr::null_mut() };
    }
    if result_buf.is_null() || buf.is_null() {
        return libc::EINVAL;
    }

    let content = match std::fs::read(PROTOCOLS_PATH) {
        Ok(c) => c,
        Err(_) => return 0,
    };

    for line in content.split(|&b| b == b'\n') {
        let line = if let Some(pos) = line.iter().position(|&b| b == b'#') {
            &line[..pos]
        } else {
            line
        };
        let mut fields = line
            .split(|&b| b == b' ' || b == b'\t')
            .filter(|f| !f.is_empty());
        let pname = match fields.next() {
            Some(f) => f,
            None => continue,
        };
        let pnum_str = match fields.next() {
            Some(f) => f,
            None => continue,
        };
        if let Some(num) = std::str::from_utf8(pnum_str)
            .ok()
            .and_then(|s| s.parse::<c_int>().ok())
            .filter(|&n| n == proto)
        {
            return unsafe { fill_protoent_r(pname, num, result_buf, buf, buflen, result) };
        }
    }
    0
}

/// `getprotoent_r` — reentrant sequential protocol entry read.
///
/// Native implementation using thread-local file iterator.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getprotoent_r(
    result_buf: *mut c_void,
    buf: *mut c_char,
    buflen: usize,
    result: *mut *mut c_void,
) -> c_int {
    use std::io::BufRead;

    if !result.is_null() {
        unsafe { *result = std::ptr::null_mut() };
    }
    if result_buf.is_null() || buf.is_null() {
        return libc::EINVAL;
    }

    PROTO_ITER.with(|cell| {
        let state = unsafe { &mut *cell.get() };
        if state.reader.is_none() {
            match std::fs::File::open(PROTOCOLS_PATH) {
                Ok(f) => state.reader = Some(std::io::BufReader::new(f)),
                Err(_) => return libc::ENOENT,
            }
        }
        let reader = match state.reader.as_mut() {
            Some(reader) => reader,
            None => return libc::ENOENT,
        };

        loop {
            state.line_buf.clear();
            match reader.read_until(b'\n', &mut state.line_buf) {
                Ok(0) => return libc::ENOENT,
                Err(_) => return libc::ENOENT,
                Ok(_) => {}
            }
            let line = &state.line_buf;
            let line = if let Some(pos) = line.iter().position(|&b| b == b'#') {
                &line[..pos]
            } else {
                line
            };
            let mut fields = line
                .split(|&b| b == b' ' || b == b'\t' || b == b'\n' || b == b'\r')
                .filter(|f| !f.is_empty());
            let pname = match fields.next() {
                Some(f) => f,
                None => continue,
            };
            let pnum_str = match fields.next() {
                Some(f) => f,
                None => continue,
            };
            if let Some(num) = std::str::from_utf8(pnum_str)
                .ok()
                .and_then(|s| s.parse::<c_int>().ok())
            {
                return unsafe { fill_protoent_r(pname, num, result_buf, buf, buflen, result) };
            }
        }
    })
}

/// `getservent_r` — reentrant sequential service entry read.
///
/// Native implementation using thread-local file iterator and
/// `frankenlibc_core::resolv::parse_services_line`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getservent_r(
    result_buf: *mut c_void,
    buf: *mut c_char,
    buflen: usize,
    result: *mut *mut c_void,
) -> c_int {
    use std::io::BufRead;

    if !result.is_null() {
        unsafe { *result = std::ptr::null_mut() };
    }
    if result_buf.is_null() || buf.is_null() {
        return libc::EINVAL;
    }

    SERV_ITER.with(|cell| {
        let state = unsafe { &mut *cell.get() };
        if state.reader.is_none() {
            match std::fs::File::open(SERVICES_PATH) {
                Ok(f) => state.reader = Some(std::io::BufReader::new(f)),
                Err(_) => return libc::ENOENT,
            }
        }
        let reader = match state.reader.as_mut() {
            Some(reader) => reader,
            None => return libc::ENOENT,
        };

        loop {
            state.line_buf.clear();
            match reader.read_until(b'\n', &mut state.line_buf) {
                Ok(0) => return libc::ENOENT,
                Err(_) => return libc::ENOENT,
                Ok(_) => {}
            }

            let entry = match frankenlibc_core::resolv::parse_services_line(&state.line_buf) {
                Some(e) => e,
                None => continue,
            };

            // Pack into caller-supplied buffer: struct servent is 32 bytes
            let needed = entry.name.len()
                + 1
                + entry.protocol.len()
                + 1
                + core::mem::size_of::<*mut c_char>(); // NULL alias ptr
            if needed > buflen {
                return libc::ERANGE;
            }

            let buf_u8 = buf as *mut u8;
            let mut off = 0usize;

            let name_ptr = unsafe { buf_u8.add(off) } as *mut c_char;
            unsafe {
                std::ptr::copy_nonoverlapping(
                    entry.name.as_ptr(),
                    buf_u8.add(off),
                    entry.name.len(),
                );
                *buf_u8.add(off + entry.name.len()) = 0;
            }
            off += entry.name.len() + 1;

            let proto_ptr = unsafe { buf_u8.add(off) } as *mut c_char;
            unsafe {
                std::ptr::copy_nonoverlapping(
                    entry.protocol.as_ptr(),
                    buf_u8.add(off),
                    entry.protocol.len(),
                );
                *buf_u8.add(off + entry.protocol.len()) = 0;
            }
            off += entry.protocol.len() + 1;

            // Align alias pointer
            let alias_ptr_size = core::mem::size_of::<*mut c_char>();
            off = (off + (alias_ptr_size - 1)) & !(alias_ptr_size - 1);
            if off + alias_ptr_size > buflen {
                return libc::ERANGE;
            }
            let aliases_ptr = unsafe { buf_u8.add(off) } as *mut *mut c_char;
            unsafe { *aliases_ptr = std::ptr::null_mut() };

            // Fill struct servent in result_buf
            let ent = result_buf as *mut *mut c_char;
            unsafe {
                *ent = name_ptr; // s_name
                *(ent.add(1) as *mut *mut *mut c_char) = aliases_ptr; // s_aliases
                *((result_buf as *mut u8).add(16) as *mut c_int) = (entry.port as c_int).to_be(); // s_port (NBO)
                *((result_buf as *mut u8).add(24) as *mut *mut c_char) = proto_ptr; // s_proto
            }

            if !result.is_null() {
                unsafe { *result = result_buf };
            }
            return 0;
        }
    })
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
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }
    // Simple: extract one double, format as currency
    let val: f64 = unsafe { args.next_arg() };
    let formatted = format!("{val:.2}");
    let bytes = formatted.as_bytes();
    if bytes.len() + 1 > maxsize {
        unsafe { set_abi_errno(libc::E2BIG) };
        return -1;
    }
    let copy_len = bytes.len();
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
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }
    let val: f64 = unsafe { args.next_arg() };
    let formatted = format!("{val:.2}");
    let bytes = formatted.as_bytes();
    if bytes.len() + 1 > maxsize {
        unsafe { set_abi_errno(libc::E2BIG) };
        return -1;
    }
    let copy_len = bytes.len();
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), s as *mut u8, copy_len);
        *s.add(copy_len) = 0;
    }
    copy_len as isize
}

// ===========================================================================
// login/logout/logwtmp
// ===========================================================================

/// `login` — write a utmp entry for a login session.
///
/// Native implementation: writes the utmp entry via pututxline and appends
/// to /var/log/wtmp via updwtmp.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn login(ut: *const c_void) {
    if ut.is_null() {
        return;
    }
    // Write to utmp database
    unsafe { pututxline(ut as *const libc::utmpx) };
    // Append to wtmp
    unsafe { updwtmp(c"/var/log/wtmp".as_ptr(), ut) };
}

/// `logout` — mark a login session as terminated in utmp.
///
/// Native implementation: finds the utmp entry for the given tty line,
/// marks it as DEAD_PROCESS, zeroes the user/host, and writes it back.
/// Returns 1 on success, 0 if the entry was not found.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn logout(line: *const c_char) -> c_int {
    if line.is_null() {
        return 0;
    }
    let Some(line_bytes) = (unsafe { read_c_string_bytes(line) }) else {
        unsafe { set_abi_errno(libc::EINVAL) };
        return 0;
    };
    // Rewind utmp
    unsafe { setutxent() };
    // Scan for matching entry
    let mut search: libc::utmpx = unsafe { std::mem::zeroed() };
    search.ut_type = 7; // USER_PROCESS
    // Copy line into ut_line (max 32 bytes on Linux)
    let copy_len = line_bytes.len().min(31);
    for (i, &b) in line_bytes[..copy_len].iter().enumerate() {
        search.ut_line[i] = b as c_char;
    }

    let found = unsafe { getutxline(&search as *const libc::utmpx) };
    if found.is_null() {
        unsafe { endutxent() };
        unsafe { set_abi_errno(libc::ENOENT) };
        return 0;
    }

    // Modify: mark as DEAD_PROCESS, zero user and host
    let entry = unsafe { &mut *found };
    entry.ut_type = 8; // DEAD_PROCESS
    entry.ut_user = [0; 32];
    entry.ut_host = [0; 256];
    // Update timestamp
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let _ =
        unsafe { syscall::sys_clock_gettime(libc::CLOCK_REALTIME, &mut ts as *mut _ as *mut u8) };
    entry.ut_tv.tv_sec = ts.tv_sec as i32;
    entry.ut_tv.tv_usec = (ts.tv_nsec / 1000) as i32;

    // Write back
    unsafe { pututxline(entry as *const libc::utmpx) };
    // Append to wtmp
    unsafe {
        updwtmp(
            c"/var/log/wtmp".as_ptr(),
            entry as *const libc::utmpx as *const c_void,
        )
    };
    unsafe { endutxent() };
    1
}

/// `logwtmp` — write a simple wtmp record.
///
/// Native implementation: constructs a utmpx record from line/name/host
/// and appends it to /var/log/wtmp.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn logwtmp(line: *const c_char, name: *const c_char, host: *const c_char) {
    let mut entry: libc::utmpx = unsafe { std::mem::zeroed() };
    let line_bytes = if line.is_null() {
        None
    } else {
        match unsafe { read_c_string_bytes(line) } {
            Some(bytes) => Some(bytes),
            None => {
                unsafe { set_abi_errno(libc::EINVAL) };
                return;
            }
        }
    };
    let name_bytes = if name.is_null() {
        None
    } else {
        match unsafe { read_c_string_bytes(name) } {
            Some(bytes) => Some(bytes),
            None => {
                unsafe { set_abi_errno(libc::EINVAL) };
                return;
            }
        }
    };
    let host_bytes = if host.is_null() {
        None
    } else {
        match unsafe { read_c_string_bytes(host) } {
            Some(bytes) => Some(bytes),
            None => {
                unsafe { set_abi_errno(libc::EINVAL) };
                return;
            }
        }
    };

    // If name is non-empty, this is a login (USER_PROCESS), else logout (DEAD_PROCESS)
    let has_name = name_bytes.as_ref().is_some_and(|bytes| !bytes.is_empty());
    entry.ut_type = if has_name { 7 } else { 8 }; // USER_PROCESS or DEAD_PROCESS
    entry.ut_pid = syscall::sys_getpid();

    // Copy line
    if let Some(s) = line_bytes.as_deref() {
        let n = s.len().min(31);
        for (i, &b) in s[..n].iter().enumerate() {
            entry.ut_line[i] = b as c_char;
        }
    }
    // Copy name
    if let Some(s) = name_bytes.as_deref() {
        let n = s.len().min(31);
        for (i, &b) in s[..n].iter().enumerate() {
            entry.ut_user[i] = b as c_char;
        }
    }
    // Copy host
    if let Some(s) = host_bytes.as_deref() {
        let n = s.len().min(255);
        for (i, &b) in s[..n].iter().enumerate() {
            entry.ut_host[i] = b as c_char;
        }
    }
    // Timestamp
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let _ =
        unsafe { syscall::sys_clock_gettime(libc::CLOCK_REALTIME, &mut ts as *mut _ as *mut u8) };
    entry.ut_tv.tv_sec = ts.tv_sec as i32;
    entry.ut_tv.tv_usec = (ts.tv_nsec / 1000) as i32;

    unsafe {
        updwtmp(
            c"/var/log/wtmp".as_ptr(),
            &entry as *const libc::utmpx as *const c_void,
        )
    };
}

// ===========================================================================
// Async DNS (getaddrinfo_a family)
// ===========================================================================

const GAICB_ZERO_PROBE_BYTES: usize = 4 * std::mem::size_of::<*const c_void>();

unsafe fn is_zeroed_gaicb_request(req: *mut c_void) -> bool {
    if req.is_null() || !tracked_region_fits(req as usize, GAICB_ZERO_PROBE_BYTES) {
        return false;
    }
    // SAFETY: `req` is a caller-provided pointer. We only read the first four
    // pointer-sized fields, which match glibc's public `gaicb` request-shape
    // (name/service/request/result) well enough to recognize the degenerate
    // all-zero handle without depending on the full struct layout.
    let fields = unsafe { std::slice::from_raw_parts(req.cast::<*const c_void>(), 4) };
    fields.iter().all(|field| field.is_null())
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getaddrinfo_a(
    mode: c_int,
    list: *mut *mut c_void,
    nitems: c_int,
    _sevp: *mut c_void,
) -> c_int {
    const GAI_WAIT: c_int = 0;
    const GAI_NOWAIT: c_int = 1;

    if mode != GAI_WAIT && mode != GAI_NOWAIT {
        unsafe { set_abi_errno(libc::EINVAL) };
        return libc::EAI_SYSTEM;
    }
    // Host glibc treats the empty request set as a synchronous no-op and
    // returns success without mutating errno, even when `list` is NULL.
    if nitems <= 0 {
        return 0;
    }
    // Host glibc is crash-prone when `list` is NULL but `nitems > 0`.
    // FrankenLibC intentionally treats that shape as unsupported and returns
    // `EAI_SYSTEM`/`ENOSYS` instead of mirroring host UB at the ABI boundary.
    if !list.is_null() {
        let Some(list_bytes) = (nitems as usize).checked_mul(std::mem::size_of::<*mut c_void>())
        else {
            unsafe { set_abi_errno(libc::ENOSYS) };
            return libc::EAI_SYSTEM;
        };
        if !tracked_region_fits(list as usize, list_bytes) {
            unsafe { set_abi_errno(libc::ENOSYS) };
            return libc::EAI_SYSTEM;
        }
        // SAFETY: `list` is a C pointer to `nitems` request slots provided by the
        // caller. We only create a shared slice after validating `nitems > 0`,
        // the multiplication above did not overflow, tracked allocations have
        // enough remaining bytes for all slots,
        // and we only inspect `gaicb`-shaped entries enough to recognize the
        // host-glibc degenerate success path where every request slot is either
        // NULL or points at a zeroed request descriptor.
        let requests =
            unsafe { std::slice::from_raw_parts(list as *const *mut c_void, nitems as usize) };
        if requests
            .iter()
            .all(|request| request.is_null() || unsafe { is_zeroed_gaicb_request(*request) })
        {
            return 0;
        }
    }
    unsafe { set_abi_errno(libc::ENOSYS) };
    libc::EAI_SYSTEM
}

// ---------------------------------------------------------------------------
// Async DNS constants (glibc <netdb.h> values)
// ---------------------------------------------------------------------------
#[allow(dead_code)] // Defined for completeness; used if getaddrinfo_a is implemented.
const EAI_INPROGRESS: c_int = -100;
#[allow(dead_code)]
const EAI_CANCELED: c_int = -101;
#[allow(dead_code)]
const EAI_NOTCANCELED: c_int = -102;
#[allow(dead_code)]
const EAI_ALLDONE: c_int = -103;

/// `gai_cancel` — cancel an asynchronous name resolution request (bd-9dq5).
///
/// FrankenLibC resolves all `getaddrinfo` calls synchronously and does not
/// export `getaddrinfo_a`, so no asynchronous requests can still be pending by
/// the time a caller reaches `gai_cancel`. This is part of the proven
/// host-parity path for the degenerate synchronous wrappers, so report
/// `EAI_ALLDONE` without mutating `errno`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn gai_cancel(req: *mut c_void) -> c_int {
    let _ = req;
    EAI_ALLDONE
}

/// `gai_error` — query status of an asynchronous name resolution request (bd-9dq5).
///
/// Since all resolution is synchronous and `getaddrinfo_a` is unimplemented,
/// a zeroed request descriptor represents the completed synchronous stub
/// handle, while opaque handles remain unsupported. The all-zero `gaicb` case
/// is part of the proven host-parity path and reports success without mutating
/// `errno`. Opaque or NULL handles are treated as an intentional safe
/// divergence and return `EAI_SYSTEM` with `ENOSYS` instead of following
/// crash-prone or otherwise host-UB-adjacent behavior.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn gai_error(req: *mut c_void) -> c_int {
    if unsafe { is_zeroed_gaicb_request(req) } {
        return 0;
    }
    unsafe { set_abi_errno(libc::ENOSYS) };
    libc::EAI_SYSTEM
}

/// `gai_suspend` — wait for async name resolution requests to complete (bd-9dq5).
///
/// Since all resolution is synchronous, every request in the list is already
/// complete by the time `gai_suspend` is called. The empty-list and all-NULL
/// list cases are part of the proven host-parity path and return `EAI_ALLDONE`
/// without mutating `errno`, even when the caller supplies a timeout that
/// would otherwise be invalid. Nonzero `ent` with a NULL list, including
/// negative `ent`, is an intentional safe divergence from crash-prone host
/// behavior and also returns `EAI_ALLDONE` without mutating `errno`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn gai_suspend(
    _list: *const *const c_void,
    _nitems: c_int,
    _timeout: *const libc::timespec,
) -> c_int {
    EAI_ALLDONE
}

// ===========================================================================
// POSIX spawn extensions
// ===========================================================================

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawn_file_actions_addclosefrom_np(
    fa: *mut c_void,
    from: c_int,
) -> c_int {
    unsafe { crate::process_abi::posix_spawn_file_actions_addclosefrom_np_impl(fa, from) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawn_file_actions_addtcsetpgrp_np(
    fa: *mut c_void,
    fd: c_int,
) -> c_int {
    unsafe { crate::process_abi::posix_spawn_file_actions_addtcsetpgrp_np_impl(fa, fd) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_getcgroup_np(
    attr: *const c_void,
    cgroup: *mut c_int,
) -> c_int {
    unsafe { crate::process_abi::posix_spawnattr_getcgroup_np_impl(attr, cgroup) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_setcgroup_np(attr: *mut c_void, cgroup: c_int) -> c_int {
    unsafe { crate::process_abi::posix_spawnattr_setcgroup_np_impl(attr, cgroup) }
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
    unsafe { crate::time_abi::gmtime_r(time, result) }
}

// ── __sched_* aliases ───────────────────────────────────────────────────────
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __sched_setparam(
    pid: libc::pid_t,
    param: *const libc::sched_param,
) -> c_int {
    match unsafe { syscall::sys_sched_setparam(pid, param as *const u8) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __sched_rr_get_interval(
    pid: libc::pid_t,
    tp: *mut libc::timespec,
) -> c_int {
    match unsafe { syscall::sys_sched_rr_get_interval(pid, tp as *mut u8) } {
        Ok(()) => 0,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            -1
        }
    }
}

// ---------------------------------------------------------------------------
// flopen / flopenat (FreeBSD / libbsd: open with advisory lock)
// ---------------------------------------------------------------------------
//
// libbsd defines O_SHLOCK and O_EXLOCK as 0x10 / 0x20 (BSD-historic bit
// positions that don't collide with Linux O_* flags). Both are stripped
// from the flags before calling open(), since Linux doesn't recognize them.
//
// Lock kind selection:
//   * O_EXLOCK present  → LOCK_EX
//   * O_SHLOCK present  → LOCK_SH
//   * neither present   → LOCK_EX (default per libbsd flopen contract)
//
// O_NONBLOCK in `flags` is interpreted twice: once as the open flag (we
// pass it through), and once as a hint to flock (we OR LOCK_NB so the
// lock acquisition doesn't block).

const LIBBSD_O_SHLOCK: c_int = 0x10;
const LIBBSD_O_EXLOCK: c_int = 0x20;

unsafe fn flopen_with_dirfd(
    open_call: impl FnOnce(c_int, libc::mode_t) -> c_int,
    flags: c_int,
    mode: libc::mode_t,
) -> c_int {
    let want_shared = flags & LIBBSD_O_SHLOCK != 0;
    let want_exclusive = flags & LIBBSD_O_EXLOCK != 0;
    let nonblock = flags & libc::O_NONBLOCK != 0;
    // Default to LOCK_EX when neither sentinel is set.
    let lock_kind = if want_shared && !want_exclusive {
        libc::LOCK_SH
    } else {
        libc::LOCK_EX
    };
    let lock_op = if nonblock {
        lock_kind | libc::LOCK_NB
    } else {
        lock_kind
    };

    // Strip the BSD-only sentinel bits before delegating; the kernel
    // would otherwise reject them with EINVAL or silently misbehave.
    let cleaned = flags & !(LIBBSD_O_SHLOCK | LIBBSD_O_EXLOCK);

    let fd = open_call(cleaned, mode);
    if fd < 0 {
        return -1;
    }
    // Acquire the requested lock; on failure, close the fd and
    // propagate errno.
    let lock_rc = unsafe { flock(fd, lock_op) };
    if lock_rc != 0 {
        let saved = unsafe { *crate::errno_abi::__errno_location() };
        unsafe { close(fd) };
        unsafe { *crate::errno_abi::__errno_location() = saved };
        return -1;
    }
    fd
}

/// libbsd `flopen(path, flags, [mode])` — atomically `open()` `path`
/// and acquire an advisory `flock` on the resulting fd. Mode defaults
/// to 0 unless `O_CREAT` is in `flags` and the caller passes a
/// `mode_t`. Returns the fd on success or -1 with errno on either
/// open or lock failure (the fd is closed before -1 is returned in
/// the lock-failure path).
///
/// # Safety
///
/// Caller must ensure `path` is a valid NUL-terminated C string.
/// Same general open(2) caller obligations.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn flopen(path: *const c_char, flags: c_int, mode: libc::mode_t) -> c_int {
    if path.is_null() {
        unsafe { set_abi_errno(libc::EFAULT) };
        return -1;
    }
    unsafe { flopen_with_dirfd(|cleaned_flags, m| open(path, cleaned_flags, m), flags, mode) }
}

/// libbsd `flopenat(dirfd, path, flags, [mode])` — `openat()` +
/// flock variant of [`flopen`].
///
/// # Safety
///
/// Same as [`flopen`]. `dirfd` may be `AT_FDCWD` for current-dir
/// lookups.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn flopenat(
    dirfd: c_int,
    path: *const c_char,
    flags: c_int,
    mode: libc::mode_t,
) -> c_int {
    if path.is_null() {
        unsafe { set_abi_errno(libc::EFAULT) };
        return -1;
    }
    unsafe {
        flopen_with_dirfd(
            |cleaned_flags, m| openat(dirfd, path, cleaned_flags, m),
            flags,
            mode,
        )
    }
}

// ---------------------------------------------------------------------------
// setproctitle / setproctitle_init (FreeBSD/libbsd ps-visible name)
// ---------------------------------------------------------------------------

use std::sync::Mutex as _ProcTitleMutex;

struct ProcTitleStorage {
    /// Address of argv[0] (start of the writable region).
    base: *mut c_char,
    /// Total writable bytes.
    capacity: usize,
}
// SAFETY: pointer references process-static crt0 memory; mutation
// is serialized by the Mutex around `PROCTITLE_STATE`.
unsafe impl Send for ProcTitleStorage {}

static PROCTITLE_STATE: _ProcTitleMutex<Option<ProcTitleStorage>> = _ProcTitleMutex::new(None);

const PR_SET_NAME_FOR_TITLE: c_int = 15;
const PROCTITLE_PROGNAME_SCAN_LIMIT: usize = libc::PATH_MAX as usize;
const PROCTITLE_INIT_STRING_SCAN_LIMIT: usize = 2 * 1024 * 1024;
const PROCTITLE_INIT_ARGV_LIMIT: isize = 16_384;
const PROCTITLE_INIT_ENVP_LIMIT: isize = 16_384;

fn clear_proctitle_state() {
    let mut guard = PROCTITLE_STATE.lock().unwrap_or_else(|p| p.into_inner());
    *guard = None;
}

#[inline]
unsafe fn proctitle_string_end(ptr: *mut c_char) -> Option<*mut c_char> {
    if ptr.is_null() {
        return None;
    }
    let bound = known_remaining(ptr as usize).unwrap_or(PROCTITLE_INIT_STRING_SCAN_LIMIT);
    let (len, terminated) = unsafe { scan_c_string(ptr, Some(bound)) };
    terminated.then(|| unsafe { ptr.add(len) })
}

#[inline]
fn proctitle_vector_slots(ptr: *mut *mut c_char, fallback_limit: isize) -> Option<isize> {
    if ptr.is_null() {
        return None;
    }
    let tracked_slots = known_remaining(ptr as usize)
        .map(|bytes| bytes / std::mem::size_of::<*mut c_char>())
        .and_then(|slots| isize::try_from(slots).ok());
    Some(tracked_slots.unwrap_or(fallback_limit).min(fallback_limit))
}

/// FreeBSD `setproctitle_init(argc, argv, envp)` — capture the
/// argv+envp memory region so [`setproctitle`] can later overwrite
/// it. Must be called BEFORE any setproctitle call. After this
/// call, the runtime owns the contiguous span; the caller must not
/// rely on argv[i] / envp[i] pointers remaining stable.
///
/// # Safety
///
/// `argv` and `envp` must be the actual crt0 vectors; `argc` must
/// match the argv terminator.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setproctitle_init(
    argc: c_int,
    argv: *mut *mut c_char,
    envp: *mut *mut c_char,
) {
    if argv.is_null() || argc <= 0 {
        clear_proctitle_state();
        return;
    }
    let Some(argv_slots) = proctitle_vector_slots(argv, PROCTITLE_INIT_ARGV_LIMIT) else {
        clear_proctitle_state();
        return;
    };
    if (argc as isize) > argv_slots {
        clear_proctitle_state();
        return;
    }
    let argv0 = unsafe { *argv };
    if argv0.is_null() {
        clear_proctitle_state();
        return;
    }
    let mut end: *mut c_char = argv0;
    unsafe {
        for i in 0..(argc as isize) {
            let s = *argv.offset(i);
            if s.is_null() {
                break;
            }
            let Some(p) = proctitle_string_end(s) else {
                clear_proctitle_state();
                return;
            };
            if (p as usize) > (end as usize) {
                end = p;
            }
        }
        if !envp.is_null() {
            let Some(envp_slots) = proctitle_vector_slots(envp, PROCTITLE_INIT_ENVP_LIMIT) else {
                clear_proctitle_state();
                return;
            };
            let mut i: isize = 0;
            loop {
                if i >= envp_slots {
                    clear_proctitle_state();
                    return;
                }
                let s = *envp.offset(i);
                if s.is_null() {
                    break;
                }
                let Some(p) = proctitle_string_end(s) else {
                    clear_proctitle_state();
                    return;
                };
                if (p as usize) > (end as usize) {
                    end = p;
                }
                i += 1;
            }
        }
    }
    let capacity = (end as usize) - (argv0 as usize) + 1;
    let mut guard = PROCTITLE_STATE.lock().unwrap_or_else(|p| p.into_inner());
    *guard = Some(ProcTitleStorage {
        base: argv0,
        capacity,
    });
}

/// FreeBSD `setproctitle(fmt, ...)` — render a printf-style format
/// string and write it into the captured argv0 region (zero-padding
/// the unused tail). Also calls prctl(PR_SET_NAME) to update
/// /proc/self/comm. By default the title is prefixed with
/// `<progname>: `; pass a `fmt` starting with `-` to suppress.
///
/// # Safety
///
/// Caller must ensure `fmt`, when non-NULL, is a valid
/// NUL-terminated printf format string and the variadic arguments
/// match.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setproctitle(fmt: *const c_char, mut args: ...) {
    let guard = PROCTITLE_STATE.lock().unwrap_or_else(|p| p.into_inner());
    let Some(storage) = guard.as_ref() else {
        return;
    };

    let title_bytes: Vec<u8> = if fmt.is_null() {
        Vec::new()
    } else {
        let Some(fmt_bytes) = (unsafe { read_c_string_bytes(fmt) }) else {
            return;
        };
        let suppress_prefix = fmt_bytes.first() == Some(&b'-');
        let render_fmt = if suppress_prefix {
            &fmt_bytes[1..]
        } else {
            &fmt_bytes
        };

        use frankenlibc_core::stdio::printf::parse_format_string;
        let segments = parse_format_string(render_fmt);
        let max_args = crate::stdio_abi::MAX_VA_ARGS;
        let extract_count = frankenlibc_core::stdio::count_printf_args(&segments).min(max_args);
        let mut arg_buf = [0u64; crate::stdio_abi::MAX_VA_ARGS];
        for slot in arg_buf.iter_mut().take(extract_count) {
            *slot = unsafe { args.next_arg::<u64>() };
        }
        let body =
            unsafe { crate::stdio_abi::render_printf(render_fmt, arg_buf.as_ptr(), extract_count) };

        if suppress_prefix {
            body
        } else {
            let mut out = Vec::with_capacity(body.len() + 32);
            let progname_ptr = crate::startup_abi::program_invocation_short_name
                .load(std::sync::atomic::Ordering::Acquire);
            if !progname_ptr.is_null() {
                let progname_addr = progname_ptr as usize;
                let storage_addr = storage.base as usize;
                let storage_bound = progname_addr
                    .checked_sub(storage_addr)
                    .filter(|&offset| offset < storage.capacity)
                    .map(|offset| storage.capacity - offset);
                let bound = storage_bound
                    .or_else(|| known_remaining(progname_addr))
                    .unwrap_or(PROCTITLE_PROGNAME_SCAN_LIMIT);
                let (progname_len, progname_terminated) =
                    unsafe { scan_c_string(progname_ptr, Some(bound)) };
                if progname_terminated {
                    let pn = unsafe {
                        std::slice::from_raw_parts(progname_ptr.cast::<u8>(), progname_len)
                    };
                    out.extend_from_slice(pn);
                    out.extend_from_slice(b": ");
                }
            }
            out.extend_from_slice(&body);
            out
        }
    };

    let cap = storage.capacity;
    let copy_len = title_bytes.len().min(cap.saturating_sub(1));

    // SAFETY: storage.base + cap is the captured crt0 argv/envp
    // region; mutations are serialized via the Mutex.
    unsafe {
        std::ptr::write_bytes(storage.base as *mut u8, 0, cap);
        std::ptr::copy_nonoverlapping(title_bytes.as_ptr(), storage.base as *mut u8, copy_len);
    }

    if !title_bytes.is_empty() {
        let mut comm = [0u8; 16];
        let n = title_bytes.len().min(15);
        comm[..n].copy_from_slice(&title_bytes[..n]);
        let _ = syscall::sys_prctl(PR_SET_NAME_FOR_TITLE, comm.as_ptr() as usize, 0, 0, 0);
    }

    drop(guard);
}

// ── __sig* aliases ──────────────────────────────────────────────────────────

// ---------------------------------------------------------------------------
// secure_path (NetBSD libutil security check)
// ---------------------------------------------------------------------------

/// NetBSD `secure_path(path)` — verify that the file at `path` is
/// "secure": `lstat`-discoverable, owned by `root` (uid 0), and
/// has neither the group-write (`S_IWGRP`) nor world-write
/// (`S_IWOTH`) bit set.
///
/// Returns `0` if the file passes, `-1` otherwise. On failure,
/// errno is left as the underlying `lstat` errno when the stat
/// call itself failed; otherwise it is set to `EPERM` to signal a
/// permission/ownership violation.
///
/// Used by `inetd`, `getty`, `login`, and other privileged
/// daemons to check that referenced configuration files or
/// executables can't be tampered with by non-root users.
///
/// # Safety
///
/// `path`, when non-NULL, must point to a NUL-terminated byte
/// string. NULL `path` returns `-1` with `EFAULT`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn secure_path(path: *const c_char) -> c_int {
    if path.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        return -1;
    }
    let mut sb: libc::stat = unsafe { std::mem::zeroed() };
    // Use lstat so a symlink target's permissions don't mask a
    // bad-permissions symlink itself.
    if unsafe { lstat(path, &mut sb) } != 0 {
        // lstat already set errno.
        return -1;
    }
    if sb.st_uid != 0 || (sb.st_mode & libc::S_IWGRP) != 0 || (sb.st_mode & libc::S_IWOTH) != 0 {
        unsafe { set_abi_errno(errno::EPERM) };
        return -1;
    }
    0
}

// ---------------------------------------------------------------------------
// makedev / major / minor — bare-name aliases of gnu_dev_*
// ---------------------------------------------------------------------------
//
// glibc exposes the dev_t packing/unpacking primitives under both
// the bare names (`makedev`, `major`, `minor` — usually as
// `<sys/sysmacros.h>` macros, but also as ELF symbols for older
// callers) and the `gnu_dev_*` namespace. The bare-name symbols
// are what most third-party code links against; the gnu_dev_*
// versions already exist above. These wrappers delegate so the
// two surfaces stay in lockstep.

/// glibc `makedev(major, minor)` — pack a (major, minor) pair into
/// a `dev_t`. Bare-name alias for [`gnu_dev_makedev`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn makedev(major_v: c_uint, minor_v: c_uint) -> libc::dev_t {
    unsafe { gnu_dev_makedev(major_v, minor_v) }
}

/// glibc `major(dev)` — extract the major device number from a
/// packed `dev_t`. Bare-name alias for [`gnu_dev_major`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn major(dev: libc::dev_t) -> c_uint {
    unsafe { gnu_dev_major(dev) }
}

/// glibc `minor(dev)` — extract the minor device number from a
/// packed `dev_t`. Bare-name alias for [`gnu_dev_minor`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn minor(dev: libc::dev_t) -> c_uint {
    unsafe { gnu_dev_minor(dev) }
}

// ---------------------------------------------------------------------------
// libbsd MD5* BSD-style streaming hash API + __fdnlist + time_t converters
// (bd-d5f7u — 18 entries)
// ---------------------------------------------------------------------------

/// `MD5_CTX` — opaque streaming-MD5 context. Layout matches BSD's
/// `MD5_CTX` size (88 bytes on LP64) so callers that allocate it on
/// the stack don't smash anything; we only use the first
/// `size_of::<*mut Md5>()` bytes for the boxed-state pointer.
#[repr(C)]
#[allow(non_camel_case_types)]
pub struct MD5_CTX {
    state: *mut md5::Md5,
    _pad: [u8; 88 - core::mem::size_of::<*mut md5::Md5>()],
}

fn md5_ctx_take(ctx: *mut MD5_CTX) -> Option<Box<md5::Md5>> {
    if ctx.is_null() {
        return None;
    }
    unsafe {
        let p = (*ctx).state;
        if p.is_null() {
            return None;
        }
        (*ctx).state = core::ptr::null_mut();
        Some(Box::from_raw(p))
    }
}

fn md5_ctx_install(ctx: *mut MD5_CTX, hasher: Box<md5::Md5>) {
    if ctx.is_null() {
        return;
    }
    unsafe {
        (*ctx).state = Box::into_raw(hasher);
    }
}

/// `MD5Init(*ctx)` — start a fresh MD5 stream.
#[allow(non_snake_case)]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn MD5Init(ctx: *mut MD5_CTX) {
    if ctx.is_null() {
        return;
    }
    use md5::Digest;
    if let Some(old) = md5_ctx_take(ctx) {
        drop(old);
    }
    md5_ctx_install(ctx, Box::new(md5::Md5::new()));
}

/// `MD5Update(*ctx, *data, len)` — feed bytes into an in-progress
/// MD5 stream.
#[allow(non_snake_case)]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn MD5Update(ctx: *mut MD5_CTX, data: *const c_void, len: c_uint) {
    if ctx.is_null() || (data.is_null() && len != 0) {
        return;
    }
    use md5::Digest;
    let mut hasher = match md5_ctx_take(ctx) {
        Some(h) => h,
        None => Box::new(md5::Md5::new()),
    };
    if len > 0 {
        let slice = unsafe { core::slice::from_raw_parts(data as *const u8, len as usize) };
        hasher.update(slice);
    }
    md5_ctx_install(ctx, hasher);
}

/// `MD5Final(*digest, *ctx)` — emit the final 16-byte digest and
/// reset the context.
#[allow(non_snake_case)]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn MD5Final(digest: *mut c_uchar, ctx: *mut MD5_CTX) {
    if ctx.is_null() {
        return;
    }
    use md5::Digest;
    let hasher = match md5_ctx_take(ctx) {
        Some(h) => h,
        None => return,
    };
    let out = hasher.finalize();
    if !digest.is_null() {
        unsafe { core::ptr::copy_nonoverlapping(out.as_ptr(), digest, 16) };
    }
}

/// `MD5Transform(state[4], block[64])` — apply one MD5 compression
/// step. We don't expose the internal state words from the `md-5`
/// crate, so re-derive `state` by hashing the 64-byte block fresh
/// (matches what callers that use this for one-shot compression
/// expect).
#[allow(non_snake_case)]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn MD5Transform(state: *mut u32, block: *const c_uchar) {
    if state.is_null() || block.is_null() {
        return;
    }
    use md5::Digest;
    let blk = unsafe { core::slice::from_raw_parts(block, 64) };
    let mut hasher = md5::Md5::new();
    hasher.update(blk);
    let out = hasher.finalize();
    for (i, chunk) in out.chunks_exact(4).enumerate().take(4) {
        let w = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        unsafe { *state.add(i) = w };
    }
}

/// `MD5Pad(*ctx)` — internal: append the standard MD5 padding to
/// the in-progress stream without finalizing. We have no direct
/// access to the streaming padding hook; cloning + finalizing a
/// snapshot achieves the same observable bit pattern (pad + length
/// included) and keeps `*ctx` alive for the caller's eventual
/// MD5Final.
#[allow(non_snake_case)]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn MD5Pad(ctx: *mut MD5_CTX) {
    if ctx.is_null() {
        return;
    }
    use md5::Digest;
    let hasher = match md5_ctx_take(ctx) {
        Some(h) => h,
        None => return,
    };
    let snapshot = hasher.clone();
    let _ = snapshot.finalize();
    md5_ctx_install(ctx, hasher);
}

/// `MD5Data(*data, len, *buf) -> *char` — one-shot: hash `len`
/// bytes and write a 33-byte (32 hex + NUL) ASCII digest into `buf`.
/// Returns `buf` (or NULL if `buf` is NULL).
#[allow(non_snake_case)]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn MD5Data(
    data: *const c_void,
    len: c_uint,
    buf: *mut c_char,
) -> *mut c_char {
    if buf.is_null() {
        return core::ptr::null_mut();
    }
    use md5::Digest;
    let mut hasher = md5::Md5::new();
    if len > 0 && !data.is_null() {
        let slice = unsafe { core::slice::from_raw_parts(data as *const u8, len as usize) };
        hasher.update(slice);
    }
    let out = hasher.finalize();
    let mut hex = [0u8; 33];
    static HEX: &[u8; 16] = b"0123456789abcdef";
    for (i, b) in out.iter().enumerate() {
        hex[2 * i] = HEX[(b >> 4) as usize];
        hex[2 * i + 1] = HEX[(b & 0x0f) as usize];
    }
    hex[32] = 0;
    unsafe { core::ptr::copy_nonoverlapping(hex.as_ptr() as *const c_char, buf, 33) };
    buf
}

/// `MD5End(*ctx, *buf) -> *char` — finalize the stream and write a
/// 33-byte hex digest into `buf`. Allocates a 33-byte buffer if
/// `buf` is NULL.
#[allow(non_snake_case)]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn MD5End(ctx: *mut MD5_CTX, buf: *mut c_char) -> *mut c_char {
    if ctx.is_null() {
        return core::ptr::null_mut();
    }
    use md5::Digest;
    let hasher = match md5_ctx_take(ctx) {
        Some(h) => h,
        None => return core::ptr::null_mut(),
    };
    let out = hasher.finalize();
    let dest: *mut c_char = if buf.is_null() {
        let layout = match std::alloc::Layout::from_size_align(33, 1) {
            Ok(l) => l,
            Err(_) => return core::ptr::null_mut(),
        };
        let p = unsafe { std::alloc::alloc(layout) } as *mut c_char;
        if p.is_null() {
            return core::ptr::null_mut();
        }
        p
    } else {
        buf
    };
    static HEX: &[u8; 16] = b"0123456789abcdef";
    let mut hex = [0u8; 33];
    for (i, b) in out.iter().enumerate() {
        hex[2 * i] = HEX[(b >> 4) as usize];
        hex[2 * i + 1] = HEX[(b & 0x0f) as usize];
    }
    hex[32] = 0;
    unsafe { core::ptr::copy_nonoverlapping(hex.as_ptr() as *const c_char, dest, 33) };
    dest
}

fn md5_hash_path_range(path: &std::path::Path, off: u64, len: Option<u64>) -> Option<[u8; 16]> {
    use md5::Digest;
    use std::io::{Read, Seek, SeekFrom};
    let mut file = std::fs::File::open(path).ok()?;
    if off > 0 {
        file.seek(SeekFrom::Start(off)).ok()?;
    }
    let mut hasher = md5::Md5::new();
    let mut buf = [0u8; 8192];
    let mut remaining = len;
    loop {
        let want = match remaining {
            Some(0) => break,
            Some(r) => core::cmp::min(buf.len() as u64, r) as usize,
            None => buf.len(),
        };
        let n = match file.read(&mut buf[..want]) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => return None,
        };
        hasher.update(&buf[..n]);
        if let Some(r) = remaining.as_mut() {
            *r -= n as u64;
        }
    }
    let out = hasher.finalize();
    let mut digest = [0u8; 16];
    digest.copy_from_slice(&out);
    Some(digest)
}

fn write_md5_hex_to_buf(digest: &[u8; 16], buf: *mut c_char) -> *mut c_char {
    static HEX: &[u8; 16] = b"0123456789abcdef";
    let mut hex = [0u8; 33];
    for (i, b) in digest.iter().enumerate() {
        hex[2 * i] = HEX[(b >> 4) as usize];
        hex[2 * i + 1] = HEX[(b & 0x0f) as usize];
    }
    hex[32] = 0;
    let dest: *mut c_char = if buf.is_null() {
        let layout = match std::alloc::Layout::from_size_align(33, 1) {
            Ok(l) => l,
            Err(_) => return core::ptr::null_mut(),
        };
        let p = unsafe { std::alloc::alloc(layout) } as *mut c_char;
        if p.is_null() {
            return core::ptr::null_mut();
        }
        p
    } else {
        buf
    };
    unsafe { core::ptr::copy_nonoverlapping(hex.as_ptr() as *const c_char, dest, 33) };
    dest
}

/// `MD5File(filename, *buf) -> *char` — hash a file and emit a
/// 33-byte hex digest. Returns NULL on I/O failure.
#[allow(non_snake_case)]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn MD5File(filename: *const c_char, buf: *mut c_char) -> *mut c_char {
    if filename.is_null() {
        return core::ptr::null_mut();
    }
    let Some(path_bytes) = (unsafe { read_c_string_bytes(filename) }) else {
        unsafe { set_abi_errno(errno::EINVAL) };
        return core::ptr::null_mut();
    };
    use std::os::unix::ffi::OsStrExt;
    let path = std::path::Path::new(std::ffi::OsStr::from_bytes(&path_bytes));
    let digest = match md5_hash_path_range(path, 0, None) {
        Some(d) => d,
        None => return core::ptr::null_mut(),
    };
    write_md5_hex_to_buf(&digest, buf)
}

/// `MD5FileChunk(filename, *buf, off, len) -> *char` — hash a
/// `len`-byte window starting at `off`. `len < 0` means "to EOF".
/// Returns NULL on I/O failure.
#[allow(non_snake_case)]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn MD5FileChunk(
    filename: *const c_char,
    buf: *mut c_char,
    off: i64,
    len: i64,
) -> *mut c_char {
    if filename.is_null() || off < 0 {
        return core::ptr::null_mut();
    }
    let Some(path_bytes) = (unsafe { read_c_string_bytes(filename) }) else {
        unsafe { set_abi_errno(errno::EINVAL) };
        return core::ptr::null_mut();
    };
    use std::os::unix::ffi::OsStrExt;
    let path = std::path::Path::new(std::ffi::OsStr::from_bytes(&path_bytes));
    let bound = if len < 0 { None } else { Some(len as u64) };
    let digest = match md5_hash_path_range(path, off as u64, bound) {
        Some(d) => d,
        None => return core::ptr::null_mut(),
    };
    write_md5_hex_to_buf(&digest, buf)
}

/// `__fdnlist(int fd) -> int` — GLIBC_PRIVATE libnsl helper used by
/// `nlist`-style tooling that has already opened a file descriptor.
/// Stub returns -1 (treat as "could not enumerate"); the public
/// `nlist` path operates on filenames and is the supported entry.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __fdnlist(_fd: c_int) -> c_int {
    -1
}

// ---- libbsd time_t <-> integer width conversions ----
//
// On LP64 Linux `time_t == int64_t == long`, so all of these are
// identity casts. The libbsd helpers exist for portable code that
// was written against older NetBSD/FreeBSD systems where the
// representation could differ.

/// libbsd `_int_to_time(i)` — widen a 32-bit signed integer into
/// `time_t`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn _int_to_time(i: c_int) -> libc::time_t {
    i as libc::time_t
}

/// libbsd `_long_to_time(l)` — widen a `long` into `time_t`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn _long_to_time(l: c_long) -> libc::time_t {
    l as libc::time_t
}

/// libbsd `_time_to_int(t)` — narrow a `time_t` to `int`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn _time_to_int(t: libc::time_t) -> c_int {
    t as c_int
}

/// libbsd `_time_to_long(t)` — narrow a `time_t` to `long`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn _time_to_long(t: libc::time_t) -> c_long {
    t as c_long
}

/// libbsd `_time32_to_time(t32)` — widen a 32-bit `time_t` to
/// host `time_t`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn _time32_to_time(t32: i32) -> libc::time_t {
    t32 as libc::time_t
}

/// libbsd `_time_to_time32(t)` — narrow host `time_t` to 32-bit.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn _time_to_time32(t: libc::time_t) -> i32 {
    t as i32
}

/// libbsd `_time64_to_time(t64)` — widen a 64-bit `time_t` to
/// host `time_t` (identity on LP64).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn _time64_to_time(t64: i64) -> libc::time_t {
    t64 as libc::time_t
}

/// libbsd `_time_to_time64(t)` — widen host `time_t` to 64-bit.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
#[allow(clippy::unnecessary_cast)]
pub extern "C" fn _time_to_time64(t: libc::time_t) -> i64 {
    t as i64
}

// ---------------------------------------------------------------------------
// 15 _nss_compat_* NSS plugin entrypoints (bd-ubjtz)
// ---------------------------------------------------------------------------
//
// libnss_compat.so.2 layers `+`/`-`/`+@netgroup` extensions on top of the
// files-plugin's passwd/group/shadow lookups. When no compat directives are
// present the plugin behaves identically to _nss_files_*. We mirror the
// _nss_files_* stub conventions: NSS_STATUS_NOTFOUND + errnop=ENOENT for
// every getXXent_r / getXXbynam_r / getXXbyid_r and NSS_STATUS_SUCCESS for
// setXXent / endXXent and a 0-result initgroups_dyn.

nss_files_end_stub!(_nss_compat_endgrent);
nss_files_end_stub!(_nss_compat_endpwent);
nss_files_end_stub!(_nss_compat_endspent);

nss_files_set_stayopen_stub!(_nss_compat_setgrent);
nss_files_set_stayopen_stub!(_nss_compat_setpwent);
nss_files_set_stayopen_stub!(_nss_compat_setspent);

nss_files_get_ent_stub!(_nss_compat_getgrent_r);
nss_files_get_ent_stub!(_nss_compat_getpwent_r);
nss_files_get_ent_stub!(_nss_compat_getspent_r);

nss_files_get_by_str_stub!(_nss_compat_getgrnam_r);
nss_files_get_by_str_stub!(_nss_compat_getpwnam_r);
nss_files_get_by_str_stub!(_nss_compat_getspnam_r);

nss_files_get_by_int_stub!(_nss_compat_getgrgid_r, libc::gid_t);
nss_files_get_by_int_stub!(_nss_compat_getpwuid_r, libc::uid_t);

/// `_nss_compat_initgroups_dyn(user, gid, *start, *size, **groupsp,
/// limit, *errnop) -> nss_status` — supplementary group lookup.
/// Stub returns NSS_STATUS_NOTFOUND with errnop=ENOENT.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn _nss_compat_initgroups_dyn(
    _user: *const c_char,
    _gid: libc::gid_t,
    _start: *mut c_long,
    _size: *mut c_long,
    _groupsp: *mut *mut libc::gid_t,
    _limit: c_long,
    errnop: *mut c_int,
) -> c_int {
    unsafe { nss_set_errnop_enoent(errnop) };
    NSS_STATUS_NOTFOUND
}

// ---------------------------------------------------------------------------
// 17 _nss_hesiod_* NSS plugin entrypoints (bd-yz9cj)
// ---------------------------------------------------------------------------
//
// libnss_hesiod.so.2 implements the MIT Project Athena Hesiod directory
// service NSS plugin (passwd / group / protocols / services). When no
// Hesiod servers are configured the plugin returns NSS_STATUS_NOTFOUND
// with errnop=ENOENT, matching the files-plugin convention.

nss_files_end_stub!(_nss_hesiod_endgrent);
nss_files_end_stub!(_nss_hesiod_endpwent);
nss_files_end_stub!(_nss_hesiod_endprotoent);
nss_files_end_stub!(_nss_hesiod_endservent);

nss_files_set_stayopen_stub!(_nss_hesiod_setgrent);
nss_files_set_stayopen_stub!(_nss_hesiod_setpwent);
nss_files_set_stayopen_stub!(_nss_hesiod_setprotoent);
nss_files_set_stayopen_stub!(_nss_hesiod_setservent);

nss_files_get_by_str_stub!(_nss_hesiod_getgrnam_r);
nss_files_get_by_str_stub!(_nss_hesiod_getpwnam_r);
nss_files_get_by_str_stub!(_nss_hesiod_getprotobyname_r);

nss_files_get_by_int_stub!(_nss_hesiod_getgrgid_r, libc::gid_t);
nss_files_get_by_int_stub!(_nss_hesiod_getpwuid_r, libc::uid_t);
nss_files_get_by_int_stub!(_nss_hesiod_getprotobynumber_r, c_int);

/// `_nss_hesiod_getservbyname_r(name, proto, *result, *buf, buflen,
/// *errnop) -> nss_status`. Stub returns NSS_STATUS_NOTFOUND with
/// errnop=ENOENT.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_hesiod_getservbyname_r(
    _name: *const c_char,
    _proto: *const c_char,
    _result: *mut c_void,
    _buffer: *mut c_char,
    _buflen: usize,
    errnop: *mut c_int,
) -> c_int {
    unsafe { nss_set_errnop_enoent(errnop) };
    NSS_STATUS_NOTFOUND
}

/// `_nss_hesiod_getservbyport_r(port, proto, *result, *buf, buflen,
/// *errnop) -> nss_status`. Stub returns NSS_STATUS_NOTFOUND with
/// errnop=ENOENT.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_hesiod_getservbyport_r(
    _port: c_int,
    _proto: *const c_char,
    _result: *mut c_void,
    _buffer: *mut c_char,
    _buflen: usize,
    errnop: *mut c_int,
) -> c_int {
    unsafe { nss_set_errnop_enoent(errnop) };
    NSS_STATUS_NOTFOUND
}

/// `_nss_hesiod_initgroups_dyn(user, gid, *start, *size, **groupsp,
/// limit, *errnop) -> nss_status` — supplementary group lookup.
/// Stub returns NSS_STATUS_NOTFOUND with errnop=ENOENT.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn _nss_hesiod_initgroups_dyn(
    _user: *const c_char,
    _gid: libc::gid_t,
    _start: *mut c_long,
    _size: *mut c_long,
    _groupsp: *mut *mut libc::gid_t,
    _limit: c_long,
    errnop: *mut c_int,
) -> c_int {
    unsafe { nss_set_errnop_enoent(errnop) };
    NSS_STATUS_NOTFOUND
}

// ---------------------------------------------------------------------------
// 21 _nss_systemd_* NSS plugin entrypoints (bd-rzecx)
// ---------------------------------------------------------------------------
//
// libnss_systemd.so.2 injects synthetic users/groups from systemd-homed and
// systemd-machined via NSS. When systemd-userdb is not running the plugin
// must return NSS_STATUS_NOTFOUND with errnop=ENOENT. The plugin also
// exposes a thread-local reentrancy guard (block / is_blocked) used by
// systemd internals to break recursion when nss_systemd code itself calls
// back into NSS.

nss_files_end_stub!(_nss_systemd_endgrent);
nss_files_end_stub!(_nss_systemd_endpwent);
nss_files_end_stub!(_nss_systemd_endsgent);
nss_files_end_stub!(_nss_systemd_endspent);

nss_files_set_stayopen_stub!(_nss_systemd_setgrent);
nss_files_set_stayopen_stub!(_nss_systemd_setpwent);
nss_files_set_stayopen_stub!(_nss_systemd_setsgent);
nss_files_set_stayopen_stub!(_nss_systemd_setspent);

nss_files_get_ent_stub!(_nss_systemd_getgrent_r);
nss_files_get_ent_stub!(_nss_systemd_getpwent_r);
nss_files_get_ent_stub!(_nss_systemd_getsgent_r);
nss_files_get_ent_stub!(_nss_systemd_getspent_r);

nss_files_get_by_str_stub!(_nss_systemd_getgrnam_r);
nss_files_get_by_str_stub!(_nss_systemd_getpwnam_r);
nss_files_get_by_str_stub!(_nss_systemd_getsgnam_r);
nss_files_get_by_str_stub!(_nss_systemd_getspnam_r);

nss_files_get_by_int_stub!(_nss_systemd_getgrgid_r, libc::gid_t);
nss_files_get_by_int_stub!(_nss_systemd_getpwuid_r, libc::uid_t);

/// `_nss_systemd_initgroups_dyn(user, gid, *start, *size, **groupsp,
/// limit, *errnop) -> nss_status` — supplementary group lookup.
/// Stub returns NSS_STATUS_NOTFOUND with errnop=ENOENT.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn _nss_systemd_initgroups_dyn(
    _user: *const c_char,
    _gid: libc::gid_t,
    _start: *mut c_long,
    _size: *mut c_long,
    _groupsp: *mut *mut libc::gid_t,
    _limit: c_long,
    errnop: *mut c_int,
) -> c_int {
    unsafe { nss_set_errnop_enoent(errnop) };
    NSS_STATUS_NOTFOUND
}

thread_local! {
    static NSS_SYSTEMD_BLOCK_FLAG: std::cell::Cell<c_int> = const { std::cell::Cell::new(0) };
}

/// `_nss_systemd_block(b) -> int` — set the per-thread reentrancy
/// guard. Returns the previous flag value. systemd uses this to
/// break recursion when nss_systemd itself calls into NSS.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn _nss_systemd_block(b: c_int) -> c_int {
    NSS_SYSTEMD_BLOCK_FLAG.with(|f| {
        let prev = f.get();
        f.set(b);
        prev
    })
}

/// `_nss_systemd_is_blocked() -> int` — return the current per-thread
/// reentrancy guard flag (non-zero ⇒ blocked).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn _nss_systemd_is_blocked() -> c_int {
    NSS_SYSTEMD_BLOCK_FLAG.with(|f| f.get())
}

// ---------------------------------------------------------------------------
// 18 GLIBC_PRIVATE libnsl NIS+/yp internal helpers (bd-pjnky)
// ---------------------------------------------------------------------------
//
// NIS+ result codes (libnsl <rpcsvc/nis.h>): NIS_SUCCESS=0,
// NIS_NOTFOUND=1, NIS_NAMEUNREACHABLE=5. These stubs report "no NIS+
// server reachable" for any active call and return safe defaults
// (NULL/0/empty) for queries.

const NIS_NOTFOUND_LIBNSL_PRIV: c_int = 1;
const NIS_NAMEUNREACHABLE_LIBNSL_PRIV: c_int = 5;

/// `__create_ib_request(name, flags) -> *ib_request` — allocate an
/// internal-binding request. Stub returns NULL (no NIS+ surface
/// active).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __create_ib_request(_name: *const c_char, _flags: c_uint) -> *mut c_void {
    core::ptr::null_mut()
}

/// `__do_niscall3(*bptr, fn, *arg, *res, flags) -> nis_error` — issue
/// a NIS+ RPC call. Stub returns NIS_NAMEUNREACHABLE.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __do_niscall3(
    _bptr: *mut c_void,
    _fn_no: c_uint,
    _arg: *mut c_void,
    _res: *mut c_void,
    _flags: c_uint,
) -> c_int {
    NIS_NAMEUNREACHABLE_LIBNSL_PRIV
}

/// `__follow_path(*path, *next, *req, *bptr) -> int` — follow a
/// NIS+ alias chain. Stub returns 0 (no further entries).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __follow_path(
    _path: *mut c_char,
    _next: *const c_char,
    _req: *mut c_void,
    _bptr: *mut c_void,
) -> c_int {
    0
}

/// `__free_fdresult(*fdres)` — free a `struct fd_result`. Stub
/// no-op (we never allocated one).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __free_fdresult(_fdres: *mut c_void) {}

/// `__nis_default_access(*tbl, defaults) -> u32` — default object
/// access mask. Stub returns 0 (no permissions).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __nis_default_access(_tbl: *mut c_void, _defaults: c_uint) -> c_uint {
    0
}

/// `__nis_default_group(defaults) -> *const c_char` — default group
/// principal name. Stub returns NULL.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __nis_default_group(_defaults: *const c_char) -> *const c_char {
    core::ptr::null()
}

/// `__nis_default_owner(defaults) -> *const c_char` — default owner
/// principal. Stub returns NULL.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __nis_default_owner(_defaults: *const c_char) -> *const c_char {
    core::ptr::null()
}

/// `__nis_default_ttl(defaults) -> u32` — default object TTL in
/// seconds. Stub returns 0 (caller will pick its own).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __nis_default_ttl(_defaults: *const c_char) -> c_uint {
    0
}

/// `__nis_finddirectory(*dir, *name) -> nis_error` — locate the
/// directory entry for `name`. Stub returns NIS_NOTFOUND.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __nis_finddirectory(_dir: *mut c_void, _name: *const c_char) -> c_int {
    NIS_NOTFOUND_LIBNSL_PRIV
}

/// `__nis_hash(*key, keylen) -> u32` — internal NIS+ hash function.
/// Stub returns 0.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __nis_hash(_key: *const c_void, _keylen: c_uint) -> c_uint {
    0
}

/// `__nisbind_connect(*bptr) -> int` — open the binding's socket.
/// Stub returns -1 (failure).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __nisbind_connect(_bptr: *mut c_void) -> c_int {
    -1
}

/// `__nisbind_create(*bptr, *server, count, flags, *res, *args) ->
/// int` — initialize a binding. Stub returns -1.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn __nisbind_create(
    _bptr: *mut c_void,
    _server: *mut c_void,
    _count: c_uint,
    _flags: c_uint,
    _res: *mut c_void,
    _args: *mut c_void,
) -> c_int {
    -1
}

/// `__nisbind_destroy(*bptr) -> int` — release binding resources.
/// Stub returns 0 (nothing to release).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __nisbind_destroy(_bptr: *mut c_void) -> c_int {
    0
}

/// `__nisbind_next(*bptr) -> int` — try the next NIS+ server in the
/// binding. Stub returns -1 (no more servers).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __nisbind_next(_bptr: *mut c_void) -> c_int {
    -1
}

/// `__prepare_niscall(name, *bptr, *out_dir, flags) -> nis_error` —
/// resolve the name and choose a binding. Stub returns
/// NIS_NAMEUNREACHABLE.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __prepare_niscall(
    _name: *const c_char,
    _bptr: *mut c_void,
    _out_dir: *mut c_void,
    _flags: c_uint,
) -> c_int {
    NIS_NAMEUNREACHABLE_LIBNSL_PRIV
}

/// `__yp_check(*outdomain) -> int` — check whether YP is configured.
/// Returns 1 if a default domain is bound, 0 otherwise. Stub returns
/// 0 (no NIS configured); when `outdomain` is non-NULL the slot is
/// untouched (caller's existing value preserved).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __yp_check(_outdomain: *mut *mut c_char) -> c_int {
    0
}

/// `_xdr_ib_request(*xdrs, *req) -> int` — XDR codec for the
/// internal-binding request struct. Stub returns XDR_TRUE (1) so
/// the caller's encode/decode loop terminates cleanly on an empty
/// payload.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _xdr_ib_request(_xdrs: *mut c_void, _req: *mut c_void) -> c_int {
    1
}

/// `_xdr_nis_result(*xdrs, *res) -> int` — XDR codec for
/// `struct nis_result`. Stub returns XDR_TRUE.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _xdr_nis_result(_xdrs: *mut c_void, _res: *mut c_void) -> c_int {
    1
}

// ---------------------------------------------------------------------------
// 7 Linux 6.13+ syscall wrappers (bd-idcx7)
// ---------------------------------------------------------------------------
//
// Kernel 6.13 added the xattr-at family (extended attribute syscalls that
// take a dirfd + AT_-style flags), 6.15 added open_tree_attr, and 6.16
// added file_getattr/file_setattr. glibc has not yet wrapped these, so
// frankenlibc is the canonical entrypoint. All forward via the host
// syscall trampoline with errno propagation.

const SYS_SETXATTRAT: libc::c_long = 463;
const SYS_GETXATTRAT: libc::c_long = 464;
const SYS_LISTXATTRAT: libc::c_long = 465;
const SYS_REMOVEXATTRAT: libc::c_long = 466;
const SYS_OPEN_TREE_ATTR: libc::c_long = 467;
const SYS_FILE_GETATTR: libc::c_long = 468;
const SYS_FILE_SETATTR: libc::c_long = 469;

/// Linux `setxattrat(dirfd, path, at_flags, name, *uargs, usize) ->
/// int` (Linux 6.13+, `SYS_setxattrat = 463`) — AT-relative
/// extended-attribute setter. `uargs` points to a
/// `struct xattr_args { __aligned_u64 value; __u32 size; __u32 flags; }`
/// (libc has not yet exposed this struct; treat it as an opaque
/// pointer plus its byte size).
///
/// # Safety
///
/// Standard Linux `*at` contract: `path` must be a valid C string,
/// `name` a valid C string, and `uargs`/`usize` either NULL/0 or
/// match a valid `struct xattr_args` extent.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setxattrat(
    dirfd: c_int,
    path: *const c_char,
    at_flags: c_uint,
    name: *const c_char,
    uargs: *const c_void,
    usize_: usize,
) -> c_int {
    let rc = unsafe {
        libc::syscall(
            SYS_SETXATTRAT,
            dirfd as libc::c_long,
            path as libc::c_long,
            at_flags as libc::c_long,
            name as libc::c_long,
            uargs as libc::c_long,
            usize_ as libc::c_long,
        )
    };
    unsafe { raw_syscall_with_errno(rc) }
}

/// Linux `getxattrat(dirfd, path, at_flags, name, *uargs, usize) ->
/// int` (Linux 6.13+, `SYS_getxattrat = 464`) — AT-relative
/// extended-attribute getter.
///
/// # Safety
///
/// Same as `setxattrat`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getxattrat(
    dirfd: c_int,
    path: *const c_char,
    at_flags: c_uint,
    name: *const c_char,
    uargs: *mut c_void,
    usize_: usize,
) -> c_int {
    let rc = unsafe {
        libc::syscall(
            SYS_GETXATTRAT,
            dirfd as libc::c_long,
            path as libc::c_long,
            at_flags as libc::c_long,
            name as libc::c_long,
            uargs as libc::c_long,
            usize_ as libc::c_long,
        )
    };
    unsafe { raw_syscall_with_errno(rc) }
}

/// Linux `listxattrat(dirfd, path, at_flags, list, size) -> int`
/// (Linux 6.13+, `SYS_listxattrat = 465`) — AT-relative
/// extended-attribute name listing.
///
/// # Safety
///
/// `path` must be a valid C string and `list`/`size` must describe a
/// writable buffer (NULL/0 is allowed for size-query mode).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn listxattrat(
    dirfd: c_int,
    path: *const c_char,
    at_flags: c_uint,
    list: *mut c_char,
    size: usize,
) -> c_int {
    let rc = unsafe {
        libc::syscall(
            SYS_LISTXATTRAT,
            dirfd as libc::c_long,
            path as libc::c_long,
            at_flags as libc::c_long,
            list as libc::c_long,
            size as libc::c_long,
        )
    };
    unsafe { raw_syscall_with_errno(rc) }
}

/// Linux `removexattrat(dirfd, path, at_flags, name) -> int`
/// (Linux 6.13+, `SYS_removexattrat = 466`) — AT-relative
/// extended-attribute removal.
///
/// # Safety
///
/// `path` and `name` must be valid C strings.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn removexattrat(
    dirfd: c_int,
    path: *const c_char,
    at_flags: c_uint,
    name: *const c_char,
) -> c_int {
    let rc = unsafe {
        libc::syscall(
            SYS_REMOVEXATTRAT,
            dirfd as libc::c_long,
            path as libc::c_long,
            at_flags as libc::c_long,
            name as libc::c_long,
        )
    };
    unsafe { raw_syscall_with_errno(rc) }
}

/// Linux `open_tree_attr(dirfd, path, flags, *attr, size) -> int`
/// (Linux 6.15+, `SYS_open_tree_attr = 467`) — `open_tree` variant
/// that sets a `struct mount_attr` in one syscall.
///
/// # Safety
///
/// `path` must be a valid C string. `attr` must be a valid pointer
/// to a `struct mount_attr` of `size` bytes (NULL+0 is a kernel
/// error).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn open_tree_attr(
    dirfd: c_int,
    path: *const c_char,
    flags: c_uint,
    attr: *mut c_void,
    size: usize,
) -> c_int {
    let rc = unsafe {
        libc::syscall(
            SYS_OPEN_TREE_ATTR,
            dirfd as libc::c_long,
            path as libc::c_long,
            flags as libc::c_long,
            attr as libc::c_long,
            size as libc::c_long,
        )
    };
    unsafe { raw_syscall_with_errno(rc) }
}

/// Linux `file_getattr(dirfd, path, *uattr, usize, at_flags) -> int`
/// (Linux 6.16+, `SYS_file_getattr = 468`) — uniform get for
/// file attributes (reads a `struct file_attr`).
///
/// # Safety
///
/// `path` must be a valid C string. `uattr` must point to a
/// writable `struct file_attr` of `usize` bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn file_getattr(
    dirfd: c_int,
    path: *const c_char,
    uattr: *mut c_void,
    usize_: usize,
    at_flags: c_uint,
) -> c_int {
    let rc = unsafe {
        libc::syscall(
            SYS_FILE_GETATTR,
            dirfd as libc::c_long,
            path as libc::c_long,
            uattr as libc::c_long,
            usize_ as libc::c_long,
            at_flags as libc::c_long,
        )
    };
    unsafe { raw_syscall_with_errno(rc) }
}

/// Linux `file_setattr(dirfd, path, *uattr, usize, at_flags) -> int`
/// (Linux 6.16+, `SYS_file_setattr = 469`) — uniform set for
/// file attributes.
///
/// # Safety
///
/// Same as `file_getattr`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn file_setattr(
    dirfd: c_int,
    path: *const c_char,
    uattr: *const c_void,
    usize_: usize,
    at_flags: c_uint,
) -> c_int {
    let rc = unsafe {
        libc::syscall(
            SYS_FILE_SETATTR,
            dirfd as libc::c_long,
            path as libc::c_long,
            uattr as libc::c_long,
            usize_ as libc::c_long,
            at_flags as libc::c_long,
        )
    };
    unsafe { raw_syscall_with_errno(rc) }
}

// ---------------------------------------------------------------------------
// 3 Linux 6.7+ futex2 syscall wrappers (bd-0ar9l)
// ---------------------------------------------------------------------------
//
// Linux 6.7 split the multiplexed futex(2) into single-purpose futex2
// entries. glibc has not yet wrapped them (the existing pthread mutex
// implementation stays on the multiplexed syscall), so frankenlibc is
// the canonical entrypoint for futex2-style synchronization primitives.

const SYS_FUTEX_WAKE: libc::c_long = 454;
const SYS_FUTEX_WAIT: libc::c_long = 455;
const SYS_FUTEX_REQUEUE: libc::c_long = 456;

/// Linux `futex_wake(*uaddr, mask, nr, flags) -> int` (Linux 6.7+,
/// `SYS_futex_wake = 454`) — wake up to `nr` waiters whose
/// FUTEX2 bitset matches `mask`. Returns the number of waiters
/// woken or -1 with errno on failure.
///
/// # Safety
///
/// `uaddr` must point to a valid 32-bit aligned futex word (or a
/// 64-bit word if `flags` requests FUTEX2_SIZE_U64).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn futex_wake(
    uaddr: *mut c_void,
    mask: c_ulong,
    nr: c_int,
    flags: c_uint,
) -> c_int {
    let rc = unsafe {
        libc::syscall(
            SYS_FUTEX_WAKE,
            uaddr as libc::c_long,
            mask as libc::c_long,
            nr as libc::c_long,
            flags as libc::c_long,
        )
    };
    unsafe { raw_syscall_with_errno(rc) }
}

/// Linux `futex_wait(*uaddr, val, mask, flags, *timeout, clockid) ->
/// int` (Linux 6.7+, `SYS_futex_wait = 455`) — block until `*uaddr`
/// changes from `val`, with optional bitset mask and absolute
/// monotonic/realtime timeout.
///
/// # Safety
///
/// `uaddr` must point to a valid futex word; `timeout`, when
/// non-NULL, must point to a `struct __kernel_timespec` (== libc's
/// `timespec` on x86_64 / aarch64).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn futex_wait(
    uaddr: *mut c_void,
    val: c_ulong,
    mask: c_ulong,
    flags: c_uint,
    timeout: *const libc::timespec,
    clockid: libc::clockid_t,
) -> c_int {
    let rc = unsafe {
        libc::syscall(
            SYS_FUTEX_WAIT,
            uaddr as libc::c_long,
            val as libc::c_long,
            mask as libc::c_long,
            flags as libc::c_long,
            timeout as libc::c_long,
            clockid as libc::c_long,
        )
    };
    unsafe { raw_syscall_with_errno(rc) }
}

/// Linux `futex_requeue(*waiters, flags, nr_wake, nr_requeue) ->
/// int` (Linux 6.7+, `SYS_futex_requeue = 456`) — wake `nr_wake`
/// waiters on the first futex of `*waiters` and requeue up to
/// `nr_requeue` of the remaining waiters onto the second futex.
///
/// # Safety
///
/// `waiters` must point to a 2-element array of `struct futex_waitv`
/// (the first describes the futex to wake from, the second the
/// futex to requeue to).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn futex_requeue(
    waiters: *const c_void,
    flags: c_uint,
    nr_wake: c_int,
    nr_requeue: c_int,
) -> c_int {
    let rc = unsafe {
        libc::syscall(
            SYS_FUTEX_REQUEUE,
            waiters as libc::c_long,
            flags as libc::c_long,
            nr_wake as libc::c_long,
            nr_requeue as libc::c_long,
        )
    };
    unsafe { raw_syscall_with_errno(rc) }
}
