//! Allocation-free Linux child-side support for native posix_spawn.
//!
//! Do not call interposable libc functions, policy hooks, allocator-backed
//! helpers, or Rust mutexes here: clone leaves other threads' locks behind.
//! All allocations and handle validation belong to the parent.

use std::ffi::c_int;

use frankenlibc_core::syscall as raw_syscall;

#[inline]
fn syscall_result(raw: usize) -> Result<usize, c_int> {
    let signed = raw as isize;
    if (-4095..0).contains(&signed) {
        Err((-signed) as c_int)
    } else {
        Ok(raw)
    }
}

#[inline]
fn fcntl(fd: c_int, command: c_int, argument: usize) -> Result<c_int, c_int> {
    // SAFETY: these callers use integer-only F_GETFD/F_SETFD/F_DUPFD_CLOEXEC.
    syscall_result(unsafe {
        raw_syscall::syscall3(
            libc::SYS_fcntl as usize,
            fd as usize,
            command as usize,
            argument,
        )
    })
    .map(|value| value as c_int)
}

/// Move the private pipe away from *all* explicit action operands, including
/// source descriptors. Otherwise a caller's invalid fd can accidentally become
/// valid, or dup2/open/close can destroy the only pre-exec error channel.
/// Update the owned descriptor after each successful move so callers can clean
/// up even when a later duplication fails with EMFILE.
pub(super) fn reserve_error_fd(fd: &mut c_int, is_user_fd: impl Fn(c_int) -> bool) -> Result<(), c_int> {
    while is_user_fd(*fd) {
        let minimum = fd.checked_add(1).ok_or(libc::EMFILE)?;
        let replacement = fcntl(*fd, libc::F_DUPFD_CLOEXEC, minimum as usize)?;
        let _ = raw_syscall::sys_close(*fd);
        *fd = replacement;
    }
    Ok(())
}

/// A close action on an already-closed but in-range descriptor is harmless.
/// Preserve EBADF for out-of-range numbers, including a limit lowered since
/// the action was constructed. A successfully closed fd needs no limit check.
pub(super) fn close_for_spawn(fd: c_int) -> Result<(), c_int> {
    match raw_syscall::sys_close(fd) {
        Ok(_) => Ok(()),
        Err(libc::EBADF) if fd >= 0 => {
            let mut limits = [0_u64; 2];
            // SAFETY: prlimit64 writes the two-u64 Linux rlimit structure.
            syscall_result(unsafe {
                raw_syscall::syscall4(
                    libc::SYS_prlimit64 as usize,
                    0,
                    libc::RLIMIT_NOFILE as usize,
                    0,
                    limits.as_mut_ptr() as usize,
                )
            })?;
            if (fd as u64) < limits[0] {
                Ok(())
            } else {
                Err(libc::EBADF)
            }
        }
        Err(error) => Err(error),
    }
}

/// A spawn dup2 action is deliberately not plain dup2 when both fds agree:
/// it must validate the descriptor and clear FD_CLOEXEC in this case too.
pub(super) fn duplicate_for_spawn(oldfd: c_int, newfd: c_int) -> Result<(), c_int> {
    if oldfd == newfd {
        let flags = fcntl(oldfd, libc::F_GETFD, 0)?;
        fcntl(oldfd, libc::F_SETFD, (flags & !libc::FD_CLOEXEC) as usize)?;
    } else {
        raw_syscall::sys_dup2(oldfd, newfd)?;
    }
    Ok(())
}

/// Close a range without closing the private CLOEXEC error descriptor.
pub(super) fn close_from(from: c_int, keep: c_int) -> Result<(), c_int> {
    if from < 0 || keep < 0 {
        return Err(libc::EBADF);
    }
    let first = from as u32;
    let kept = keep as u32;
    if first < kept {
        match raw_syscall::sys_close_range(first, kept - 1, 0) {
            Ok(_) => {}
            Err(libc::ENOSYS) => return close_from_proc(from, keep),
            Err(error) => return Err(error),
        }
    }
    let upper = first.max(kept + 1);
    match raw_syscall::sys_close_range(upper, u32::MAX, 0) {
        Ok(_) => Ok(()),
        Err(libc::ENOSYS) => close_from_proc(from, keep),
        Err(error) => Err(error),
    }
}

/// Older-kernel fallback: enumerate actual descriptors, not the current soft
/// RLIMIT_NOFILE. Open fds can outlive a lowered limit. No sysconf, allocation,
/// opendir/readdir, TLS initialization, or host-libc forwarding is permitted.
fn close_from_proc(from: c_int, keep: c_int) -> Result<(), c_int> {
    // SAFETY: the path is static and NUL-terminated.
    let directory = unsafe {
        raw_syscall::sys_openat(
            libc::AT_FDCWD,
            b"/proc/self/fd\0".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            0,
        )
    }?;
    let result = close_from_directory(directory, from, keep);
    let _ = raw_syscall::sys_close(directory);
    result
}

fn close_from_directory(directory: c_int, from: c_int, keep: c_int) -> Result<(), c_int> {
    // Avoid a bulk zero-fill that could lower to interposed memset after clone.
    // Only the prefix initialized by a successful kernel read becomes a slice.
    const CAPACITY: usize = 4096;
    let mut storage = std::mem::MaybeUninit::<[u8; CAPACITY]>::uninit();
    loop {
        // SAFETY: storage has CAPACITY writable bytes; no uninitialized byte is read.
        let count = match syscall_result(unsafe {
            raw_syscall::syscall3(
                libc::SYS_getdents64 as usize,
                directory as usize,
                storage.as_mut_ptr() as usize,
                CAPACITY,
            )
        }) {
            Ok(0) => return Ok(()),
            Ok(count) if count <= CAPACITY => count,
            Ok(_) => return Err(libc::EIO),
            Err(libc::EINTR) => continue,
            Err(error) => return Err(error),
        };
        // SAFETY: getdents64 initialized exactly this prefix, checked above.
        let buffer = unsafe { std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), count) };
        let mut offset = 0;
        while offset < count {
            // Linux dirent64: u64 ino, i64 off, u16 reclen, u8 type,
            // followed at byte 19 by a NUL-terminated name. No aligned loads.
            if count - offset < 20 {
                return Err(libc::EIO);
            }
            let length = u16::from_ne_bytes([buffer[offset + 16], buffer[offset + 17]]) as usize;
            if length < 20 || length > count - offset {
                return Err(libc::EIO);
            }
            let name = &buffer[offset + 19..offset + length];
            let end = name.iter().position(|&byte| byte == 0).ok_or(libc::EIO)?;
            let fd = name[..end].iter().try_fold(0_i32, |number, &byte| {
                if byte.is_ascii_digit() {
                    number.checked_mul(10)?.checked_add(c_int::from(byte - b'0'))
                } else {
                    None
                }
            });
            if end != 0
                && let Some(fd) = fd
                && fd >= from
                && fd != keep
                && fd != directory
            {
                // Linux releases the fd even when close reports EINTR; do
                // not retry and accidentally close a reused descriptor.
                let _ = raw_syscall::sys_close(fd);
            }
            offset += length;
        }
    }
}

/// None means a clean EOF before any status byte (exec closed CLOEXEC).
/// A partial record is never decoded as a successful spawn or a valid errno.
pub(super) fn read_child_error(fd: c_int) -> Result<Option<c_int>, c_int> {
    let mut bytes = [0_u8; std::mem::size_of::<c_int>()];
    let mut received = 0;
    while received < bytes.len() {
        // SAFETY: the unwritten suffix is a valid output buffer.
        match unsafe {
            raw_syscall::sys_read(fd, bytes.as_mut_ptr().add(received), bytes.len() - received)
        } {
            Ok(0) if received == 0 => return Ok(None),
            Ok(0) => return Err(libc::EIO),
            Ok(count) => received += count,
            Err(libc::EINTR) => continue,
            Err(error) => return Err(error),
        }
    }
    let error = c_int::from_ne_bytes(bytes);
    if (1..=4095).contains(&error) {
        Ok(Some(error))
    } else {
        Err(libc::EIO)
    }
}

pub(super) fn child_fail(fd: c_int, error: c_int) -> ! {
    let bytes = error.to_ne_bytes();
    let mut written = 0;
    while written < bytes.len() {
        // SAFETY: the remaining status bytes are readable until the syscall returns.
        match unsafe {
            raw_syscall::sys_write(fd, bytes.as_ptr().add(written), bytes.len() - written)
        } {
            Ok(0) => break,
            Ok(count) => written += count,
            Err(libc::EINTR) => continue,
            Err(_) => break,
        }
    }
    raw_syscall::sys_exit_group(127)
}

pub(super) fn reap_failed_child(pid: libc::pid_t) {
    loop {
        // SAFETY: null status/rusage are permitted; wait for this child only.
        match unsafe { raw_syscall::sys_wait4(pid, std::ptr::null_mut(), 0, std::ptr::null_mut()) } {
            Err(libc::EINTR) => continue,
            _ => break,
        }
    }
}

/// RESETIDS changes effective IDs to the parent's *real* IDs, not its
/// effective IDs. setres* leaves real/saved IDs alone until exec semantics
/// establish the new saved IDs. Perform the group operation before the uid
/// operation while privileges are still available.
pub(super) fn reset_effective_ids() -> Result<(), c_int> {
    // SAFETY: getuid/getgid have no pointer arguments and cannot fail on Linux.
    let uid = unsafe { raw_syscall::syscall0(libc::SYS_getuid as usize) };
    let gid = unsafe { raw_syscall::syscall0(libc::SYS_getgid as usize) };
    // SAFETY: all arguments are scalar uid_t/gid_t values; -1 means unchanged.
    syscall_result(unsafe {
        raw_syscall::syscall3(libc::SYS_setresgid as usize, usize::MAX, gid, usize::MAX)
    })?;
    syscall_result(unsafe {
        raw_syscall::syscall3(libc::SYS_setresuid as usize, usize::MAX, uid, usize::MAX)
    })?;
    Ok(())
}

/// Hold every blockable signal across clone and child setup. The parent drops
/// this guard before reading the error pipe, including every clone error path.
/// The child never unwinds or drops it: it explicitly installs the final mask
/// immediately before exec and exits through raw _exit on every failure.
pub(super) struct SignalMaskGuard {
    pub(super) original: u64,
}

impl SignalMaskGuard {
    pub(super) fn block_all() -> Result<Self, c_int> {
        let all = u64::MAX;
        let mut original = 0_u64;
        // SAFETY: Linux's kernel signal set is 8 bytes on both supported ISAs.
        unsafe {
            raw_syscall::sys_rt_sigprocmask(
                libc::SIG_SETMASK,
                (&all as *const u64).cast(),
                (&mut original as *mut u64).cast(),
                8,
            )
        }?;
        Ok(Self { original })
    }
}

impl Drop for SignalMaskGuard {
    fn drop(&mut self) {
        let _ = install_signal_mask(self.original);
    }
}

pub(super) fn install_signal_mask(mask: u64) -> Result<(), c_int> {
    // SAFETY: mask points to one complete kernel signal set.
    unsafe {
        raw_syscall::sys_rt_sigprocmask(
            libc::SIG_SETMASK,
            (&mask as *const u64).cast(),
            std::ptr::null_mut(),
            8,
        )
    }?;
    Ok(())
}

/// Emulate exec's disposition reset *before* unblocking any signals. Otherwise
/// an inherited application handler could run in the post-clone child and
/// acquire a lock whose owning thread no longer exists. SIG_IGN is inherited
/// unless SETSIGDEF overrides it. SIGKILL and SIGSTOP cannot be changed.
pub(super) fn reset_child_signals(defaults: u64) -> Result<(), c_int> {
    // Kernel sigaction on Linux x86_64/aarch64 consists of handler, flags,
    // restorer and an 8-byte mask, each word-sized. This is NOT libc::sigaction.
    let default_action = [0_usize; 4];
    for signal in 1..=64 {
        if signal == libc::SIGKILL || signal == libc::SIGSTOP {
            continue;
        }
        let force_default = defaults & (1_u64 << (signal - 1)) != 0;
        let mut old = [0_usize; 4];
        if !force_default {
            // SAFETY: old has the kernel layout and writable size described above.
            unsafe {
                raw_syscall::sys_rt_sigaction(
                    signal,
                    std::ptr::null(),
                    old.as_mut_ptr().cast(),
                    8,
                )
            }?;
        }
        if force_default || (old[0] != libc::SIG_DFL && old[0] != libc::SIG_IGN) {
            // SAFETY: all-zero kernel action means SIG_DFL with no flags/mask.
            unsafe {
                raw_syscall::sys_rt_sigaction(
                    signal,
                    default_action.as_ptr().cast(),
                    std::ptr::null_mut(),
                    8,
                )
            }?;
        }
    }
    Ok(())
}
