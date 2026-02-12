//! Integration test: Raw syscall veneer (bd-cj0)
//!
//! Validates that the raw syscall veneer provides a complete, working
//! zero-dependency path to the Linux kernel without libc::syscall.
//!
//! Tests exercise each typed wrapper for correctness and error handling,
//! plus multi-syscall workflows (pipe+read+write, mmap+mprotect+munmap,
//! openat+write+lseek+read+close).
//!
//! Run: cargo test -p glibc-rs-core --test syscall_veneer_test

#![allow(unsafe_code)]

#[cfg(target_arch = "x86_64")]
mod x86_64_tests {
    use frankenlibc_core::syscall::*;

    // -----------------------------------------------------------------
    // Constants (matching kernel headers, no libc dependency)
    // -----------------------------------------------------------------

    const O_RDWR: i32 = 2;
    const O_CREAT: i32 = 0o100;
    const O_EXCL: i32 = 0o200;
    const O_CLOEXEC: i32 = 0o2000000;
    const AT_FDCWD: i32 = -100;

    const PROT_READ: i32 = 0x1;
    const PROT_WRITE: i32 = 0x2;
    const MAP_PRIVATE: i32 = 0x02;
    const MAP_ANONYMOUS: i32 = 0x20;

    const SEEK_SET: i32 = 0;
    const SEEK_END: i32 = 2;

    const EBADF: i32 = 9;
    const EINVAL: i32 = 22;

    // -----------------------------------------------------------------
    // 1. getpid correctness
    // -----------------------------------------------------------------

    #[test]
    fn getpid_positive_and_stable() {
        let a = sys_getpid();
        let b = sys_getpid();
        assert!(a > 0);
        assert_eq!(a, b);
    }

    // -----------------------------------------------------------------
    // 2. Pipe + read/write round-trip
    // -----------------------------------------------------------------

    #[test]
    fn pipe_roundtrip_multiple_messages() {
        let mut fds = [0i32; 2];
        unsafe { sys_pipe2(fds.as_mut_ptr(), O_CLOEXEC) }.expect("pipe2");

        for msg in &[b"hello" as &[u8], b"world", b"", b"test\x00data"] {
            let written = unsafe { sys_write(fds[1], msg.as_ptr(), msg.len()) }.expect("write");
            assert_eq!(written, msg.len());

            if !msg.is_empty() {
                let mut buf = vec![0u8; msg.len() + 16];
                let n = unsafe { sys_read(fds[0], buf.as_mut_ptr(), buf.len()) }.expect("read");
                assert_eq!(n, msg.len());
                assert_eq!(&buf[..n], *msg);
            }
        }

        sys_close(fds[0]).expect("close read end");
        sys_close(fds[1]).expect("close write end");
    }

    // -----------------------------------------------------------------
    // 3. openat + write + lseek + read + close
    // -----------------------------------------------------------------

    #[test]
    fn file_lifecycle_via_tmp() {
        // Create a temp file unique to this PID.
        let pid = sys_getpid();
        let unique = format!("/tmp/glibc_rust_syscall_test_{}\0", pid);
        let path_buf = unique.into_bytes();

        let fd = unsafe {
            sys_openat(
                AT_FDCWD,
                path_buf.as_ptr(),
                O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC,
                0o600,
            )
        }
        .expect("openat should create temp file");

        // Write data.
        let data = b"veneer integration test payload";
        let written =
            unsafe { sys_write(fd, data.as_ptr(), data.len()) }.expect("write to temp file");
        assert_eq!(written, data.len());

        // Seek back to start.
        let pos = sys_lseek(fd, 0, SEEK_SET).expect("lseek to start");
        assert_eq!(pos, 0);

        // Read back.
        let mut buf = [0u8; 64];
        let n = unsafe { sys_read(fd, buf.as_mut_ptr(), buf.len()) }.expect("read from temp file");
        assert_eq!(n, data.len());
        assert_eq!(&buf[..n], data);

        // Check file size via lseek SEEK_END.
        let size = sys_lseek(fd, 0, SEEK_END).expect("lseek to end");
        assert_eq!(size, data.len() as i64);

        // Close.
        sys_close(fd).expect("close temp file");

        // Cleanup: unlink the file.
        // SYS_unlinkat = 263, AT_FDCWD = -100, flags = 0
        let ret = unsafe { syscall3(263, AT_FDCWD as usize, path_buf.as_ptr() as usize, 0) };
        assert!(
            syscall_result(ret).is_ok(),
            "unlinkat should succeed for cleanup"
        );
    }

    // -----------------------------------------------------------------
    // 4. mmap + write + read + mprotect + munmap
    // -----------------------------------------------------------------

    #[test]
    fn mmap_full_lifecycle() {
        let page_size = 4096usize;
        let ptr = unsafe {
            sys_mmap(
                core::ptr::null_mut(),
                page_size,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            )
        }
        .expect("mmap anonymous");

        // Write a pattern.
        for i in 0..page_size {
            unsafe { *ptr.add(i) = (i & 0xFF) as u8 };
        }

        // Read back and verify.
        for i in 0..page_size {
            let val = unsafe { *ptr.add(i) };
            assert_eq!(val, (i & 0xFF) as u8, "mismatch at offset {i}");
        }

        // Change to read-only.
        unsafe { sys_mprotect(ptr, page_size, PROT_READ) }.expect("mprotect to PROT_READ");

        // Still readable.
        let val = unsafe { *ptr };
        assert_eq!(val, 0);

        // Unmap.
        unsafe { sys_munmap(ptr, page_size) }.expect("munmap");
    }

    // -----------------------------------------------------------------
    // 5. Multi-page mmap
    // -----------------------------------------------------------------

    #[test]
    fn mmap_multi_page() {
        let size = 16 * 4096;
        let ptr = unsafe {
            sys_mmap(
                core::ptr::null_mut(),
                size,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            )
        }
        .expect("mmap 64K");

        // Touch first and last byte.
        unsafe {
            *ptr = 0xAA;
            *ptr.add(size - 1) = 0xBB;
            assert_eq!(*ptr, 0xAA);
            assert_eq!(*ptr.add(size - 1), 0xBB);
        }

        unsafe { sys_munmap(ptr, size) }.expect("munmap");
    }

    // -----------------------------------------------------------------
    // 6. Error handling: EBADF on bad fd
    // -----------------------------------------------------------------

    #[test]
    fn error_ebadf_on_bad_fd() {
        assert_eq!(sys_close(99999), Err(EBADF));
        assert_eq!(sys_close(-1), Err(EBADF));
        assert_eq!(sys_fsync(-1), Err(EBADF));
        assert_eq!(sys_lseek(-1, 0, SEEK_SET), Err(EBADF));
        assert_eq!(sys_dup(-1), Err(EBADF));
    }

    // -----------------------------------------------------------------
    // 7. Error handling: invalid mmap
    // -----------------------------------------------------------------

    #[test]
    fn mmap_invalid_length_zero() {
        let result = unsafe {
            sys_mmap(
                core::ptr::null_mut(),
                0, // length = 0 is invalid
                PROT_READ,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert!(result.is_err(), "mmap with length=0 should fail");
        assert_eq!(result.unwrap_err(), EINVAL);
    }

    // -----------------------------------------------------------------
    // 8. dup produces a working fd
    // -----------------------------------------------------------------

    #[test]
    fn dup_produces_valid_fd() {
        let mut fds = [0i32; 2];
        unsafe { sys_pipe2(fds.as_mut_ptr(), O_CLOEXEC) }.expect("pipe2");

        let dup_fd = sys_dup(fds[1]).expect("dup write end");
        assert!(dup_fd >= 0);
        assert_ne!(dup_fd, fds[1], "dup should return a different fd");

        // Write via dup'd fd, read from original read end.
        let msg = b"via dup";
        let written = unsafe { sys_write(dup_fd, msg.as_ptr(), msg.len()) }.expect("write via dup");
        assert_eq!(written, msg.len());

        let mut buf = [0u8; 16];
        let n = unsafe { sys_read(fds[0], buf.as_mut_ptr(), buf.len()) }.expect("read from pipe");
        assert_eq!(n, msg.len());
        assert_eq!(&buf[..n], msg);

        sys_close(dup_fd).expect("close dup");
        sys_close(fds[0]).expect("close read");
        sys_close(fds[1]).expect("close write");
    }

    // -----------------------------------------------------------------
    // 9. Syscall numbers match expected values
    // -----------------------------------------------------------------

    #[test]
    fn syscall_number_constants() {
        assert_eq!(SYS_READ, 0);
        assert_eq!(SYS_WRITE, 1);
        assert_eq!(SYS_OPEN, 2);
        assert_eq!(SYS_CLOSE, 3);
        assert_eq!(SYS_MMAP, 9);
        assert_eq!(SYS_MPROTECT, 10);
        assert_eq!(SYS_MUNMAP, 11);
        assert_eq!(SYS_GETPID, 39);
        assert_eq!(SYS_CLONE, 56);
        assert_eq!(SYS_EXIT_GROUP, 231);
        assert_eq!(SYS_OPENAT, 257);
        assert_eq!(SYS_FUTEX, 202);
        assert_eq!(SYS_PIPE2, 293);
    }

    // -----------------------------------------------------------------
    // 10. API surface completeness check
    // -----------------------------------------------------------------

    #[test]
    #[allow(clippy::type_complexity)]
    fn api_surface_complete() {
        // Verify all typed wrappers exist and have the right signatures
        // by constructing function pointers. This is a compile-time check
        // that the API surface is complete — if any wrapper is missing or
        // has a wrong signature, this test won't compile.

        let _: unsafe fn(i32, *mut u8, usize) -> Result<usize, i32> = sys_read;
        let _: unsafe fn(i32, *const u8, usize) -> Result<usize, i32> = sys_write;
        let _: unsafe fn(i32, *const u8, i32, u32) -> Result<i32, i32> = sys_openat;
        let _: fn(i32) -> Result<(), i32> = sys_close;
        let _: unsafe fn(*mut u8, usize, i32, i32, i32, i64) -> Result<*mut u8, i32> = sys_mmap;
        let _: unsafe fn(*mut u8, usize) -> Result<(), i32> = sys_munmap;
        let _: unsafe fn(*mut u8, usize, i32) -> Result<(), i32> = sys_mprotect;
        let _: unsafe fn(*const u32, i32, u32, usize, usize, u32) -> Result<isize, i32> = sys_futex;
        let _: fn(i32) -> ! = sys_exit_group;
        let _: fn() -> i32 = sys_getpid;
        let _: unsafe fn(*mut i32, i32) -> Result<(), i32> = sys_pipe2;
        let _: fn(i32) -> Result<i32, i32> = sys_dup;
        let _: unsafe fn(i32, usize, usize) -> Result<i32, i32> = sys_ioctl;
        let _: fn(i32, i64, i32) -> Result<i64, i32> = sys_lseek;
        let _: fn(i32) -> Result<(), i32> = sys_fsync;
        let _: unsafe fn(i32, *mut u8, usize) -> Result<usize, i32> = sys_getdents64;
        let _: unsafe fn(i32, i32, usize) -> Result<i32, i32> = sys_fcntl;
    }

    // -----------------------------------------------------------------
    // 11. Raw syscallN functions accessible
    // -----------------------------------------------------------------

    #[test]
    fn raw_syscall_primitives_accessible() {
        // Verify the raw primitives are re-exported and callable.
        let pid = unsafe { syscall0(SYS_GETPID) };
        assert_eq!(pid as i32, sys_getpid());
    }

    // -----------------------------------------------------------------
    // 12. Futex basic wake (no waiters = returns 0)
    // -----------------------------------------------------------------

    #[test]
    fn futex_wake_no_waiters() {
        let futex_word: u32 = 0;
        const FUTEX_WAKE: i32 = 1;
        // Wake 1 waiter — but there are none, so returns 0.
        let result = unsafe {
            sys_futex(
                &futex_word as *const u32,
                FUTEX_WAKE,
                1, // wake at most 1
                0, // no timeout
                0, // no uaddr2
                0, // no val3
            )
        };
        assert_eq!(result, Ok(0), "futex wake with no waiters should return 0");
    }
}
