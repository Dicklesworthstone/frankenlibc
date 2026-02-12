//! Raw Linux x86_64 syscall veneer.
//!
//! Provides zero-dependency raw syscall primitives using inline assembly,
//! plus typed wrappers for the syscalls needed by frankenlibc ABI entrypoints.
//!
//! This module eliminates the dependency on `libc::syscall()` for the critical
//! path, which is essential since frankenlibc IS the libc replacement.
//!
//! # Architecture
//!
//! x86_64 Linux syscall ABI:
//! - Syscall number: `rax`
//! - Arguments: `rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9`
//! - Return: `rax` (negative values in `[-4095, -1]` indicate `-errno`)
//! - Clobbered: `rcx`, `r11`
//!
//! # Safety
//!
//! Each raw `syscallN` function is `unsafe` because the kernel trusts the
//! caller to supply valid arguments. The typed wrappers encode argument
//! types but cannot verify pointer validity — that remains the caller's
//! (or membrane's) responsibility.

#[allow(unsafe_code)]
mod raw;

pub use raw::*;

// -------------------------------------------------------------------------
// Syscall number constants (x86_64 Linux)
// -------------------------------------------------------------------------

pub const SYS_READ: usize = 0;
pub const SYS_WRITE: usize = 1;
pub const SYS_OPEN: usize = 2;
pub const SYS_CLOSE: usize = 3;
pub const SYS_FSTAT: usize = 5;
pub const SYS_LSEEK: usize = 8;
pub const SYS_MMAP: usize = 9;
pub const SYS_MPROTECT: usize = 10;
pub const SYS_MUNMAP: usize = 11;
pub const SYS_BRK: usize = 12;
pub const SYS_IOCTL: usize = 16;
pub const SYS_PIPE: usize = 22;
pub const SYS_DUP: usize = 32;
pub const SYS_DUP2: usize = 33;
pub const SYS_GETPID: usize = 39;
pub const SYS_CLONE: usize = 56;
pub const SYS_FORK: usize = 57;
pub const SYS_EXECVE: usize = 59;
pub const SYS_EXIT: usize = 60;
pub const SYS_WAIT4: usize = 61;
pub const SYS_FCNTL: usize = 72;
pub const SYS_FSYNC: usize = 74;
pub const SYS_PREAD64: usize = 17;
pub const SYS_PWRITE64: usize = 18;
pub const SYS_MSYNC: usize = 26;
pub const SYS_MADVISE: usize = 28;
pub const SYS_FDATASYNC: usize = 75;
pub const SYS_GETDENTS64: usize = 217;
pub const SYS_EXIT_GROUP: usize = 231;
pub const SYS_OPENAT: usize = 257;
pub const SYS_PIPE2: usize = 293;
pub const SYS_FUTEX: usize = 202;

// -------------------------------------------------------------------------
// Error handling
// -------------------------------------------------------------------------

/// Maximum errno value returned by Linux syscalls.
const MAX_ERRNO: usize = 4095;

/// Convert a raw syscall return value to `Result<usize, i32>`.
///
/// On x86_64 Linux, error returns are in the range `[-(MAX_ERRNO), -1]`
/// which in unsigned representation is `[usize::MAX - MAX_ERRNO + 1, usize::MAX]`.
#[inline]
pub fn syscall_result(ret: usize) -> Result<usize, i32> {
    if ret > usize::MAX - MAX_ERRNO {
        Err(-(ret as isize) as i32)
    } else {
        Ok(ret)
    }
}

// -------------------------------------------------------------------------
// Typed syscall wrappers
// -------------------------------------------------------------------------

/// `read(fd, buf, count)` — read from a file descriptor.
///
/// # Safety
///
/// `buf` must point to a writable region of at least `count` bytes.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_read(fd: i32, buf: *mut u8, count: usize) -> Result<usize, i32> {
    // SAFETY: caller guarantees buf validity and count bounds.
    let ret = unsafe { raw::syscall3(SYS_READ, fd as usize, buf as usize, count) };
    syscall_result(ret)
}

/// `write(fd, buf, count)` — write to a file descriptor.
///
/// # Safety
///
/// `buf` must point to a readable region of at least `count` bytes.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_write(fd: i32, buf: *const u8, count: usize) -> Result<usize, i32> {
    // SAFETY: caller guarantees buf validity and count bounds.
    let ret = unsafe { raw::syscall3(SYS_WRITE, fd as usize, buf as usize, count) };
    syscall_result(ret)
}

/// `openat(dirfd, pathname, flags, mode)` — open a file relative to a directory fd.
///
/// # Safety
///
/// `pathname` must be a valid null-terminated C string.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_openat(
    dirfd: i32,
    pathname: *const u8,
    flags: i32,
    mode: u32,
) -> Result<i32, i32> {
    // SAFETY: caller guarantees pathname is a valid C string.
    let ret = unsafe {
        raw::syscall4(
            SYS_OPENAT,
            dirfd as usize,
            pathname as usize,
            flags as usize,
            mode as usize,
        )
    };
    syscall_result(ret).map(|v| v as i32)
}

/// `close(fd)` — close a file descriptor.
#[inline]
#[allow(unsafe_code)]
pub fn sys_close(fd: i32) -> Result<(), i32> {
    // SAFETY: close is safe to call on any fd value (bad fd just returns EBADF).
    let ret = unsafe { raw::syscall1(SYS_CLOSE, fd as usize) };
    syscall_result(ret).map(|_| ())
}

/// `mmap(addr, length, prot, flags, fd, offset)` — map memory.
///
/// # Safety
///
/// The caller must ensure the mapping parameters are valid and that the
/// resulting memory region is used according to the requested protection.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_mmap(
    addr: *mut u8,
    length: usize,
    prot: i32,
    flags: i32,
    fd: i32,
    offset: i64,
) -> Result<*mut u8, i32> {
    // SAFETY: caller is responsible for mapping validity.
    let ret = unsafe {
        raw::syscall6(
            SYS_MMAP,
            addr as usize,
            length,
            prot as usize,
            flags as usize,
            fd as usize,
            offset as usize,
        )
    };
    syscall_result(ret).map(|v| v as *mut u8)
}

/// `munmap(addr, length)` — unmap memory.
///
/// # Safety
///
/// `addr` must be page-aligned and the range `[addr, addr+length)` must
/// be a valid mapped region.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_munmap(addr: *mut u8, length: usize) -> Result<(), i32> {
    // SAFETY: caller guarantees addr/length validity.
    let ret = unsafe { raw::syscall2(SYS_MUNMAP, addr as usize, length) };
    syscall_result(ret).map(|_| ())
}

/// `mprotect(addr, length, prot)` — set protection on a memory region.
///
/// # Safety
///
/// `addr` must be page-aligned and the range must be mapped.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_mprotect(addr: *mut u8, length: usize, prot: i32) -> Result<(), i32> {
    // SAFETY: caller guarantees addr/length validity.
    let ret = unsafe { raw::syscall3(SYS_MPROTECT, addr as usize, length, prot as usize) };
    syscall_result(ret).map(|_| ())
}

/// `futex(uaddr, futex_op, val, timeout, uaddr2, val3)` — fast userspace mutex.
///
/// # Safety
///
/// `uaddr` must point to a valid aligned `u32`. Other pointer arguments
/// depend on the specific futex operation.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_futex(
    uaddr: *const u32,
    futex_op: i32,
    val: u32,
    timeout: usize,
    uaddr2: usize,
    val3: u32,
) -> Result<isize, i32> {
    // SAFETY: caller guarantees uaddr validity and op-specific invariants.
    let ret = unsafe {
        raw::syscall6(
            SYS_FUTEX,
            uaddr as usize,
            futex_op as usize,
            val as usize,
            timeout,
            uaddr2,
            val3 as usize,
        )
    };
    syscall_result(ret).map(|v| v as isize)
}

/// `exit_group(status)` — terminate all threads in the process.
#[inline]
#[allow(unsafe_code)]
pub fn sys_exit_group(status: i32) -> ! {
    // SAFETY: exit_group never returns.
    unsafe { raw::syscall1(SYS_EXIT_GROUP, status as usize) };
    // Unreachable, but satisfy the type system.
    loop {
        core::hint::spin_loop();
    }
}

/// `getpid()` — get process ID.
#[inline]
#[allow(unsafe_code)]
pub fn sys_getpid() -> i32 {
    // SAFETY: getpid has no preconditions.
    let ret = unsafe { raw::syscall0(SYS_GETPID) };
    ret as i32
}

/// `pipe2(pipefd, flags)` — create a pipe with flags.
///
/// # Safety
///
/// `pipefd` must point to a writable `[i32; 2]`.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_pipe2(pipefd: *mut i32, flags: i32) -> Result<(), i32> {
    // SAFETY: caller guarantees pipefd points to valid [i32; 2].
    let ret = unsafe { raw::syscall2(SYS_PIPE2, pipefd as usize, flags as usize) };
    syscall_result(ret).map(|_| ())
}

/// `dup(oldfd)` — duplicate a file descriptor.
#[inline]
#[allow(unsafe_code)]
pub fn sys_dup(oldfd: i32) -> Result<i32, i32> {
    // SAFETY: dup is safe on any fd (bad fd returns EBADF).
    let ret = unsafe { raw::syscall1(SYS_DUP, oldfd as usize) };
    syscall_result(ret).map(|v| v as i32)
}

/// `ioctl(fd, request, arg)` — device control.
///
/// # Safety
///
/// The `arg` interpretation depends on the specific `request`.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_ioctl(fd: i32, request: usize, arg: usize) -> Result<i32, i32> {
    // SAFETY: caller guarantees request/arg validity.
    let ret = unsafe { raw::syscall3(SYS_IOCTL, fd as usize, request, arg) };
    syscall_result(ret).map(|v| v as i32)
}

/// `lseek(fd, offset, whence)` — reposition read/write file offset.
#[inline]
#[allow(unsafe_code)]
pub fn sys_lseek(fd: i32, offset: i64, whence: i32) -> Result<i64, i32> {
    // SAFETY: lseek is safe on any fd (bad fd returns EBADF).
    let ret = unsafe { raw::syscall3(SYS_LSEEK, fd as usize, offset as usize, whence as usize) };
    syscall_result(ret).map(|v| v as i64)
}

/// `fsync(fd)` — synchronize a file's in-core state with storage device.
#[inline]
#[allow(unsafe_code)]
pub fn sys_fsync(fd: i32) -> Result<(), i32> {
    // SAFETY: fsync is safe on any fd.
    let ret = unsafe { raw::syscall1(SYS_FSYNC, fd as usize) };
    syscall_result(ret).map(|_| ())
}

/// `getdents64(fd, dirp, count)` — get directory entries.
///
/// # Safety
///
/// `dirp` must point to a writable buffer of at least `count` bytes.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_getdents64(fd: i32, dirp: *mut u8, count: usize) -> Result<usize, i32> {
    // SAFETY: caller guarantees dirp/count validity.
    let ret = unsafe { raw::syscall3(SYS_GETDENTS64, fd as usize, dirp as usize, count) };
    syscall_result(ret)
}

/// `fcntl(fd, cmd, arg)` — file control.
///
/// # Safety
///
/// The `arg` interpretation depends on the specific `cmd`.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_fcntl(fd: i32, cmd: i32, arg: usize) -> Result<i32, i32> {
    // SAFETY: caller guarantees cmd/arg validity.
    let ret = unsafe { raw::syscall3(SYS_FCNTL, fd as usize, cmd as usize, arg) };
    syscall_result(ret).map(|v| v as i32)
}

/// `fdatasync(fd)` — synchronize a file's data (not metadata) with storage.
#[inline]
#[allow(unsafe_code)]
pub fn sys_fdatasync(fd: i32) -> Result<(), i32> {
    // SAFETY: fdatasync is safe on any fd.
    let ret = unsafe { raw::syscall1(SYS_FDATASYNC, fd as usize) };
    syscall_result(ret).map(|_| ())
}

/// `dup2(oldfd, newfd)` — duplicate a file descriptor to a specific fd.
#[inline]
#[allow(unsafe_code)]
pub fn sys_dup2(oldfd: i32, newfd: i32) -> Result<i32, i32> {
    // SAFETY: dup2 is safe on any fd values (bad fd returns EBADF).
    let ret = unsafe { raw::syscall2(SYS_DUP2, oldfd as usize, newfd as usize) };
    syscall_result(ret).map(|v| v as i32)
}

/// `msync(addr, length, flags)` — synchronize a file with a memory map.
///
/// # Safety
///
/// `addr` must be page-aligned and the range must be mapped.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_msync(addr: *mut u8, length: usize, flags: i32) -> Result<(), i32> {
    // SAFETY: caller guarantees addr/length validity.
    let ret = unsafe { raw::syscall3(SYS_MSYNC, addr as usize, length, flags as usize) };
    syscall_result(ret).map(|_| ())
}

/// `madvise(addr, length, advice)` — advise kernel about memory usage.
///
/// # Safety
///
/// `addr` must be page-aligned and the range must be mapped.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_madvise(addr: *mut u8, length: usize, advice: i32) -> Result<(), i32> {
    // SAFETY: caller guarantees addr/length validity.
    let ret = unsafe { raw::syscall3(SYS_MADVISE, addr as usize, length, advice as usize) };
    syscall_result(ret).map(|_| ())
}

/// `pread64(fd, buf, count, offset)` — read from a file descriptor at a given offset.
///
/// # Safety
///
/// `buf` must point to a writable region of at least `count` bytes.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_pread64(fd: i32, buf: *mut u8, count: usize, offset: i64) -> Result<usize, i32> {
    // SAFETY: caller guarantees buf validity and count bounds.
    let ret = unsafe {
        raw::syscall4(
            SYS_PREAD64,
            fd as usize,
            buf as usize,
            count,
            offset as usize,
        )
    };
    syscall_result(ret)
}

/// `pwrite64(fd, buf, count, offset)` — write to a file descriptor at a given offset.
///
/// # Safety
///
/// `buf` must point to a readable region of at least `count` bytes.
#[inline]
#[allow(unsafe_code)]
pub unsafe fn sys_pwrite64(
    fd: i32,
    buf: *const u8,
    count: usize,
    offset: i64,
) -> Result<usize, i32> {
    // SAFETY: caller guarantees buf validity and count bounds.
    let ret = unsafe {
        raw::syscall4(
            SYS_PWRITE64,
            fd as usize,
            buf as usize,
            count,
            offset as usize,
        )
    };
    syscall_result(ret)
}

// -------------------------------------------------------------------------
// Unit tests
// -------------------------------------------------------------------------

#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use super::*;

    #[test]
    fn getpid_returns_positive() {
        let pid = sys_getpid();
        assert!(pid > 0, "getpid should return a positive PID, got {pid}");
    }

    #[test]
    fn getpid_is_consistent() {
        let a = sys_getpid();
        let b = sys_getpid();
        assert_eq!(
            a, b,
            "getpid should return the same value on repeated calls"
        );
    }

    #[test]
    fn write_to_stdout() {
        let msg = b"";
        // SAFETY: msg is a valid byte slice.
        let result = unsafe { sys_write(1, msg.as_ptr(), msg.len()) };
        assert_eq!(result, Ok(0), "write of 0 bytes to stdout should succeed");
    }

    #[test]
    fn pipe_read_write_roundtrip() {
        let mut fds = [0i32; 2];
        // SAFETY: fds is a valid [i32; 2].
        let pipe_res = unsafe { sys_pipe2(fds.as_mut_ptr(), 0) };
        assert!(pipe_res.is_ok(), "pipe2 should succeed");

        let msg = b"hello veneer";
        // SAFETY: msg is valid, fds[1] is the write end.
        let written = unsafe { sys_write(fds[1], msg.as_ptr(), msg.len()) };
        assert_eq!(written, Ok(msg.len()), "write should write all bytes");

        let mut buf = [0u8; 32];
        // SAFETY: buf is valid, fds[0] is the read end.
        let read = unsafe { sys_read(fds[0], buf.as_mut_ptr(), buf.len()) };
        assert_eq!(read, Ok(msg.len()), "read should return same byte count");
        assert_eq!(
            &buf[..msg.len()],
            msg,
            "read data should match written data"
        );

        assert!(sys_close(fds[0]).is_ok());
        assert!(sys_close(fds[1]).is_ok());
    }

    #[test]
    fn close_bad_fd_returns_ebadf() {
        let result = sys_close(-1);
        assert_eq!(result, Err(9), "close(-1) should return EBADF (9)");
    }

    #[test]
    fn mmap_anonymous_roundtrip() {
        let page_size = 4096usize;
        // MAP_PRIVATE=0x02, MAP_ANONYMOUS=0x20, PROT_READ=0x1, PROT_WRITE=0x2
        // SAFETY: anonymous mmap with no fd.
        let ptr = unsafe {
            sys_mmap(
                core::ptr::null_mut(),
                page_size,
                0x1 | 0x2,   // PROT_READ | PROT_WRITE
                0x02 | 0x20, // MAP_PRIVATE | MAP_ANONYMOUS
                -1,
                0,
            )
        };
        assert!(ptr.is_ok(), "mmap should succeed, got {ptr:?}");
        let ptr = ptr.unwrap();
        assert!(!ptr.is_null(), "mmap should return non-null");

        // Write and read back.
        // SAFETY: we just mapped this region as RW.
        unsafe {
            *ptr = 42;
            assert_eq!(*ptr, 42, "should be able to write/read mapped memory");
        }

        // SAFETY: valid mapping.
        let unmap = unsafe { sys_munmap(ptr, page_size) };
        assert!(unmap.is_ok(), "munmap should succeed");
    }

    #[test]
    fn mprotect_removes_write_access() {
        let page_size = 4096usize;
        // SAFETY: anonymous mmap.
        let ptr = unsafe {
            sys_mmap(
                core::ptr::null_mut(),
                page_size,
                0x1 | 0x2,   // PROT_READ | PROT_WRITE
                0x02 | 0x20, // MAP_PRIVATE | MAP_ANONYMOUS
                -1,
                0,
            )
        }
        .expect("mmap should succeed");

        // SAFETY: valid mapping, changing to read-only.
        let protect = unsafe { sys_mprotect(ptr, page_size, 0x1) }; // PROT_READ only
        assert!(protect.is_ok(), "mprotect should succeed");

        // We don't test the SIGSEGV here — just that the syscall itself works.
        // SAFETY: valid mapping.
        let unmap = unsafe { sys_munmap(ptr, page_size) };
        assert!(unmap.is_ok());
    }

    #[test]
    fn syscall_result_success() {
        assert_eq!(syscall_result(0), Ok(0));
        assert_eq!(syscall_result(42), Ok(42));
        assert_eq!(syscall_result(usize::MAX - 4096), Ok(usize::MAX - 4096));
    }

    #[test]
    fn syscall_result_error() {
        // -1 as usize = usize::MAX → errno 1 (EPERM)
        assert_eq!(syscall_result(usize::MAX), Err(1));
        // -9 as usize → errno 9 (EBADF)
        assert_eq!(syscall_result((-9isize) as usize), Err(9));
        // -4095 as usize → errno 4095 (max)
        assert_eq!(syscall_result((-4095isize) as usize), Err(4095));
    }

    #[test]
    fn lseek_bad_fd() {
        let result = sys_lseek(-1, 0, 0);
        assert_eq!(result, Err(9), "lseek(-1) should return EBADF");
    }

    #[test]
    fn dup_bad_fd() {
        let result = sys_dup(-1);
        assert_eq!(result, Err(9), "dup(-1) should return EBADF");
    }

    #[test]
    fn fsync_bad_fd() {
        let result = sys_fsync(-1);
        assert_eq!(result, Err(9), "fsync(-1) should return EBADF");
    }

    #[test]
    fn openat_and_close_dev_null() {
        // O_RDONLY=0, AT_FDCWD=-100
        let path = b"/dev/null\0";
        // SAFETY: path is a valid C string.
        let fd = unsafe { sys_openat(-100, path.as_ptr(), 0, 0) };
        assert!(fd.is_ok(), "openat /dev/null should succeed, got {fd:?}");
        let fd = fd.unwrap();
        assert!(fd >= 0, "fd should be non-negative");
        assert!(sys_close(fd).is_ok(), "close should succeed");
    }
}
