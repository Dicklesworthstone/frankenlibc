//! Integration test: Raw syscall veneer (bd-cj0)
//!
//! Validates that the raw syscall veneer provides a complete, working
//! zero-dependency path to the Linux kernel without libc::syscall.
//!
//! Tests exercise each typed wrapper for correctness and error handling,
//! plus multi-syscall workflows (pipe+read+write, mmap+mprotect+munmap,
//! openat+write+lseek+read+close).
//!
//! Run: cargo test -p frankenlibc-core --test syscall_veneer_test

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
    const O_NONBLOCK: i32 = 0o4000;
    const O_CLOEXEC: i32 = 0o2000000;
    const AF_INET: i32 = 2;
    const SOCK_STREAM: i32 = 1;
    const AT_FDCWD: i32 = -100;
    const AT_EACCESS: i32 = 0x200;
    const CLOCK_MONOTONIC: i32 = 1;
    const SIGUSR1: i32 = 10;
    const SIG_BLOCK: i32 = 0;
    const SIG_SETMASK: i32 = 2;
    const F_GETFD: i32 = 1;
    const F_GETFL: i32 = 3;
    const FD_CLOEXEC: i32 = 1;
    const SIGCHLD: usize = 17;
    const SIGCONT: i32 = 18;
    const SIGSTOP: i32 = 19;

    const PROT_READ: i32 = 0x1;
    const PROT_WRITE: i32 = 0x2;
    const MAP_PRIVATE: i32 = 0x02;
    const MAP_ANONYMOUS: i32 = 0x20;

    const SEEK_SET: i32 = 0;
    const SEEK_END: i32 = 2;

    const ENXIO: i32 = 6;
    const EBADF: i32 = 9;
    const EAGAIN: i32 = 11;
    const EFAULT: i32 = 14;
    const EINVAL: i32 = 22;
    const EACCES: i32 = 13;
    const ENOSYS: i32 = 38;
    const ENOTSUP: i32 = 95;
    const EPERM: i32 = 1;
    const ECHILD: i32 = 10;
    const MPOL_BIND: i32 = 2;
    const MPOL_F_NODE: u32 = 1;
    const MPOL_F_ADDR: u32 = 1 << 1;
    const SCHED_DEADLINE: u32 = 6;
    const CLD_EXITED: i32 = 1;
    const CLD_STOPPED: i32 = 5;

    #[repr(C)]
    #[derive(Clone, Copy, Debug, Default)]
    struct SockAddrIn {
        sin_family: u16,
        sin_port: u16,
        sin_addr: u32,
        sin_zero: [u8; 8],
    }

    static WAITID_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
        let unique = format!("/tmp/frankenlibc_syscall_test_{}\0", pid);
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

        // Cleanup via the typed veneer.
        unsafe { sys_unlinkat(AT_FDCWD, path_buf.as_ptr(), 0) }.expect("unlinkat cleanup");
    }

    #[test]
    fn lseek_seek_hole_and_seek_data_find_sparse_regions() {
        let path = format!(
            "/tmp/frankenlibc_seek_hole_{}_{}\0",
            sys_getpid(),
            sys_gettid()
        );
        let path = path.into_bytes();

        let fd = unsafe {
            sys_openat(
                AT_FDCWD,
                path.as_ptr(),
                O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC,
                0o600,
            )
        }
        .expect("open sparse temp file");

        unsafe { sys_write(fd, b"A".as_ptr(), 1) }.expect("write head extent");
        let second_extent = 8192i64;
        sys_lseek(fd, second_extent, SEEK_SET).expect("seek to sparse offset");
        unsafe { sys_write(fd, b"B".as_ptr(), 1) }.expect("write tail extent");

        let data_from_start =
            sys_lseek(fd, 0, frankenlibc_core::syscall::SEEK_DATA).expect("SEEK_DATA from start");
        assert_eq!(data_from_start, 0);

        let hole_from_start =
            sys_lseek(fd, 0, frankenlibc_core::syscall::SEEK_HOLE).expect("SEEK_HOLE from start");
        assert!(
            hole_from_start > 0 && hole_from_start <= second_extent,
            "expected first hole before second extent, got {hole_from_start}"
        );

        let data_from_gap = sys_lseek(fd, 4096, frankenlibc_core::syscall::SEEK_DATA)
            .expect("SEEK_DATA from sparse gap");
        assert_eq!(data_from_gap, second_extent);

        let file_end = sys_lseek(fd, 0, SEEK_END).expect("SEEK_END after sparse writes");
        let hole_after_data = sys_lseek(fd, second_extent, frankenlibc_core::syscall::SEEK_HOLE)
            .expect("SEEK_HOLE from second extent");
        assert_eq!(hole_after_data, file_end);

        sys_close(fd).expect("close sparse temp file");
        unsafe { sys_unlinkat(AT_FDCWD, path.as_ptr(), 0) }.expect("unlink sparse temp file");
    }

    #[test]
    fn lseek_seek_data_beyond_eof_returns_enxio() {
        let path = format!(
            "/tmp/frankenlibc_seek_data_eof_{}_{}\0",
            sys_getpid(),
            sys_gettid()
        );
        let path = path.into_bytes();

        let fd = unsafe {
            sys_openat(
                AT_FDCWD,
                path.as_ptr(),
                O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC,
                0o600,
            )
        }
        .expect("open EOF temp file");

        unsafe { sys_write(fd, b"data".as_ptr(), 4) }.expect("write file body");
        let eof = sys_lseek(fd, 0, SEEK_END).expect("SEEK_END");
        let err = sys_lseek(fd, eof, frankenlibc_core::syscall::SEEK_DATA)
            .expect_err("SEEK_DATA at EOF must fail");
        assert_eq!(err, ENXIO);

        sys_close(fd).expect("close EOF temp file");
        unsafe { sys_unlinkat(AT_FDCWD, path.as_ptr(), 0) }.expect("unlink EOF temp file");
    }

    #[test]
    fn renameat2_exchange_swaps_file_contents() {
        let base = format!(
            "/tmp/frankenlibc_rename_exchange_{}_{}",
            sys_getpid(),
            sys_gettid()
        );
        let left = format!("{base}_left\0").into_bytes();
        let right = format!("{base}_right\0").into_bytes();

        let left_fd = unsafe {
            sys_openat(
                AT_FDCWD,
                left.as_ptr(),
                O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC,
                0o600,
            )
        }
        .expect("open left temp file");
        let right_fd = unsafe {
            sys_openat(
                AT_FDCWD,
                right.as_ptr(),
                O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC,
                0o600,
            )
        }
        .expect("open right temp file");

        unsafe { sys_write(left_fd, b"left".as_ptr(), 4) }.expect("write left payload");
        unsafe { sys_write(right_fd, b"right".as_ptr(), 5) }.expect("write right payload");
        sys_close(left_fd).expect("close left seed fd");
        sys_close(right_fd).expect("close right seed fd");

        unsafe {
            sys_renameat2(
                AT_FDCWD,
                left.as_ptr(),
                AT_FDCWD,
                right.as_ptr(),
                frankenlibc_core::syscall::RENAME_EXCHANGE,
            )
        }
        .expect("renameat2(RENAME_EXCHANGE)");

        let left_fd = unsafe { sys_openat(AT_FDCWD, left.as_ptr(), O_RDWR | O_CLOEXEC, 0) }
            .expect("reopen left path");
        let right_fd = unsafe { sys_openat(AT_FDCWD, right.as_ptr(), O_RDWR | O_CLOEXEC, 0) }
            .expect("reopen right path");

        let mut left_buf = [0u8; 8];
        let left_len =
            unsafe { sys_read(left_fd, left_buf.as_mut_ptr(), left_buf.len()) }.expect("read left");
        let mut right_buf = [0u8; 8];
        let right_len = unsafe { sys_read(right_fd, right_buf.as_mut_ptr(), right_buf.len()) }
            .expect("read right");

        assert_eq!(&left_buf[..left_len], b"right");
        assert_eq!(&right_buf[..right_len], b"left");

        sys_close(left_fd).expect("close left fd");
        sys_close(right_fd).expect("close right fd");
        unsafe { sys_unlinkat(AT_FDCWD, left.as_ptr(), 0) }.expect("unlink left path");
        unsafe { sys_unlinkat(AT_FDCWD, right.as_ptr(), 0) }.expect("unlink right path");
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
        assert_eq!(SYS_PREAD64, 17);
        assert_eq!(SYS_PWRITE64, 18);
        assert_eq!(SYS_MSYNC, 26);
        assert_eq!(SYS_MADVISE, 28);
        assert_eq!(SYS_DUP, 32);
        assert_eq!(SYS_DUP2, 33);
        assert_eq!(SYS_MMAP, 9);
        assert_eq!(SYS_MPROTECT, 10);
        assert_eq!(SYS_MUNMAP, 11);
        assert_eq!(SYS_GETDENTS64, 217);
        assert_eq!(SYS_FCNTL, 72);
        assert_eq!(SYS_FACCESSAT, 269);
        assert_eq!(SYS_FACCESSAT2, 439);
        assert_eq!(SYS_FDATASYNC, 75);
        assert_eq!(SYS_FALLOCATE, 285);
        assert_eq!(SYS_GETPID, 39);
        assert_eq!(SYS_GETTID, 186);
        assert_eq!(SYS_CLONE, 56);
        assert_eq!(SYS_CLONE3, 435);
        assert_eq!(SYS_EXIT_GROUP, 231);
        assert_eq!(SYS_OPENAT, 257);
        assert_eq!(SYS_SOCKET, 41);
        assert_eq!(SYS_CONNECT, 42);
        assert_eq!(SYS_ACCEPT, 43);
        assert_eq!(SYS_SENDTO, 44);
        assert_eq!(SYS_RECVFROM, 45);
        assert_eq!(SYS_FUTEX, 202);
        assert_eq!(SYS_FUTEX_WAITV, 449);
        assert_eq!(FUTEX_WAIT_BITSET, 9);
        assert_eq!(FUTEX_BITSET_MATCH_ANY, u32::MAX);
        assert_eq!(SYS_MEMFD_SECRET, 447);
        assert_eq!(SYS_SET_MEMPOLICY, 238);
        assert_eq!(SYS_GET_MEMPOLICY, 239);
        assert_eq!(SYS_SCHED_GETAFFINITY, 204);
        assert_eq!(SYS_BIND, 49);
        assert_eq!(SYS_LISTEN, 50);
        assert_eq!(SYS_GETSOCKNAME, 51);
        assert_eq!(SYS_GETPEERNAME, 52);
        assert_eq!(SYS_SOCKETPAIR, 53);
        assert_eq!(SYS_ACCEPT4, 288);
        assert_eq!(SYS_SIGNALFD4, 289);
        assert_eq!(SYS_INOTIFY_INIT1, 294);
        assert_eq!(SYS_IO_URING_SETUP, 425);
        assert_eq!(SYS_IO_URING_ENTER, 426);
        assert_eq!(SYS_IO_URING_REGISTER, 427);
        assert_eq!(SYS_USERFAULTFD, 323);
        assert_eq!(SYS_CLOCK_NANOSLEEP, 230);
        assert_eq!(SYS_READLINKAT, 267);
        assert_eq!(SYS_RENAMEAT2, 316);
        assert_eq!(SYS_WAITID, 247);
        assert_eq!(SYS_TIMERFD_SETTIME, 286);
        assert_eq!(SYS_CAPSET, 126);
        assert_eq!(SYS_SCHED_SETATTR, 314);
        assert_eq!(SYS_SYSINFO, 99);
        assert_eq!(SYS_PIPE2, 293);
        assert_eq!(SYS_SET_TID_ADDRESS, 218);
        assert_eq!(UFFDIO_API, 0xc018aa3f);
        assert_eq!(UFFD_API, 0xAA);
        assert_eq!(UFFD_FEATURE_SIGBUS, 1 << 7);
        assert_eq!(LINUX_CAPABILITY_VERSION_3, 0x2008_0522);
        assert_eq!(LINUX_CAPABILITY_U32S_3, 2);
        assert_eq!(SFD_NONBLOCK, O_NONBLOCK);
        assert_eq!(SFD_CLOEXEC, O_CLOEXEC);
        assert_eq!(IN_NONBLOCK, O_NONBLOCK);
        assert_eq!(IN_CLOEXEC, O_CLOEXEC);
        assert_eq!(AF_UNIX, 1);
        assert_eq!(SOCK_NONBLOCK, O_NONBLOCK);
        assert_eq!(SOCK_CLOEXEC, O_CLOEXEC);
        assert_eq!(SOCK_SEQPACKET, 5);
        assert_eq!(CLOCK_BOOTTIME, 7);
        assert_eq!(frankenlibc_core::syscall::AT_FDCWD, AT_FDCWD);
        assert_eq!(frankenlibc_core::syscall::CLONE_PIDFD, 1 << 12);
        assert_eq!(frankenlibc_core::syscall::RENAME_EXCHANGE, 2);
        assert_eq!(frankenlibc_core::syscall::SEEK_DATA, 3);
        assert_eq!(frankenlibc_core::syscall::SEEK_HOLE, 4);
        assert_eq!(P_PID, 1);
        assert_eq!(frankenlibc_core::syscall::P_PIDFD, 3);
        assert_eq!(WSTOPPED, 2);
        assert_eq!(TIMER_ABSTIME, 1);
        assert_eq!(WEXITED, 4);
        assert_eq!(SIGEV_THREAD_ID, 4);
        assert_eq!(TFD_NONBLOCK, O_NONBLOCK);
        assert_eq!(TFD_CLOEXEC, O_CLOEXEC);
        assert_eq!(TFD_TIMER_ABSTIME, 1);
        assert_eq!(TFD_TIMER_CANCEL_ON_SET, 2);
        assert_eq!(IORING_ENTER_GETEVENTS, 1 << 0);
        assert_eq!(IORING_ENTER_SQ_WAKEUP, 1 << 1);
        assert_eq!(IORING_SETUP_SQPOLL, 1 << 1);
        assert_eq!(core::mem::size_of::<CpuSet>(), 128);
        assert_eq!(core::mem::size_of::<IoUringSqringOffsets>(), 40);
        assert_eq!(core::mem::size_of::<IoUringCqringOffsets>(), 40);
        assert_eq!(core::mem::size_of::<IoUringParams>(), 120);
        assert_eq!(core::mem::size_of::<SigEventThreadId>(), 64);
        assert_eq!(core::mem::size_of::<SignalfdSiginfo>(), 128);
        assert_eq!(core::mem::size_of::<Timespec>(), 16);
        assert_eq!(core::mem::size_of::<ItimerSpec>(), 32);
        assert_eq!(core::mem::size_of::<CapUserHeader>(), 8);
        assert_eq!(core::mem::size_of::<CapUserData>(), 12);
        assert_eq!(core::mem::size_of::<UffdApi>(), 24);
        assert_eq!(core::mem::size_of::<StatFsId>(), 8);
        assert_eq!(core::mem::size_of::<StatFs>(), 120);
        assert_eq!(core::mem::size_of::<WaitSigInfo>(), 128);
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
        let _: fn(i32, i32, i32) -> Result<i32, i32> = sys_socket;
        let _: unsafe fn(i32, *const u8, u32) -> Result<(), i32> = sys_bind;
        let _: fn(i32, i32) -> Result<(), i32> = sys_listen;
        let _: unsafe fn(i32, *mut u8, *mut u32) -> Result<i32, i32> = sys_accept;
        let _: unsafe fn(i32, *mut u8, *mut u32, i32) -> Result<i32, i32> = sys_accept4;
        let _: unsafe fn(i32, *const u8, u32) -> Result<(), i32> = sys_connect;
        let _: unsafe fn(i32, *mut u8, *mut u32) -> Result<(), i32> = sys_getsockname;
        let _: unsafe fn(i32, *mut u8, *mut u32) -> Result<(), i32> = sys_getpeername;
        let _: unsafe fn(i32, i32, i32, *mut i32) -> Result<(), i32> = sys_socketpair;
        let _: unsafe fn(i32, *const u8, usize, i32, *const u8, usize) -> Result<isize, i32> =
            sys_sendto;
        let _: unsafe fn(i32, *mut u8, usize, i32, *mut u8, *mut u32) -> Result<isize, i32> =
            sys_recvfrom;
        let _: unsafe fn(i32, i32, &Timespec, *mut Timespec) -> Result<(), i32> =
            sys_clock_nanosleep_spec;
        let _: unsafe fn(*const u8, *mut u8, usize) -> Result<isize, i32> = sys_readlink;
        let _: unsafe fn(i32, *const u8, *mut u8, usize) -> Result<isize, i32> = sys_readlinkat;
        let _: unsafe fn(i32, *const u8, i32, u32) -> Result<i32, i32> = sys_openat;
        let _: unsafe fn(i32, *const u8, i32, *const u8, u32) -> Result<(), i32> = sys_renameat2;
        let _: unsafe fn(i32, u32, *mut u8, i32, *mut u8) -> Result<(), i32> = sys_waitid;
        let _: unsafe fn(i32, u32, &mut WaitSigInfo, i32) -> Result<(), i32> = sys_waitid_info;
        let _: fn(i32) -> Result<(), i32> = sys_close;
        let _: unsafe fn(*mut u8, usize, i32, i32, i32, i64) -> Result<*mut u8, i32> = sys_mmap;
        let _: unsafe fn(*mut u8, usize) -> Result<(), i32> = sys_munmap;
        let _: unsafe fn(*mut u8, usize, i32) -> Result<(), i32> = sys_mprotect;
        let _: unsafe fn(i32, *const u8, i32) -> Result<(), i32> = sys_faccessat;
        let _: unsafe fn(i32, *const u8, i32, i32) -> Result<(), i32> = sys_faccessat2;
        let _: fn(i32) -> Result<i32, i32> = sys_inotify_init1;
        let _: unsafe fn(i32, &mut CpuSet) -> Result<usize, i32> = sys_sched_getaffinity_cpuset;
        let _: unsafe fn(i32, &SigEventThreadId, *mut i32) -> Result<(), i32> =
            sys_timer_create_sigevent;
        let _: unsafe fn(*mut Sysinfo) -> Result<(), i32> = sys_sysinfo;
        let _: unsafe fn(*const u8, *mut StatFs) -> Result<(), i32> = sys_statfs;
        let _: unsafe fn(i32, *mut StatFs) -> Result<(), i32> = sys_fstatfs;
        let _: unsafe fn(*const u32, i32, u32, usize, usize, u32) -> Result<isize, i32> = sys_futex;
        let _: unsafe fn(*const u32, u32, *const Timespec, u32) -> Result<(), i32> =
            sys_futex_wait_bitset;
        let _: unsafe fn(*const FutexWaitV, u32, u32, *const u8, i32) -> Result<i32, i32> =
            sys_futex_waitv;
        let _: unsafe fn(u32, *mut u8) -> Result<i32, i32> = sys_io_uring_setup;
        let _: unsafe fn(u32, *mut IoUringParams) -> Result<i32, i32> = sys_io_uring_setup_params;
        let _: unsafe fn(i32, u32, u32, u32, *const u8, usize) -> Result<i32, i32> =
            sys_io_uring_enter;
        let _: fn(i32) -> Result<i32, i32> = sys_io_uring_enter_sqpoll_wakeup;
        let _: unsafe fn(i32, u32, *const u8, u32) -> Result<i32, i32> = sys_io_uring_register;
        let _: fn(u32) -> Result<i32, i32> = sys_memfd_secret;
        let _: unsafe fn(i32, *const usize, usize) -> Result<(), i32> = sys_set_mempolicy;
        let _: unsafe fn(*mut i32, *mut usize, usize, *const u8, u32) -> Result<(), i32> =
            sys_get_mempolicy;
        let _: unsafe fn(i32, *const u8, usize, i32) -> Result<i32, i32> = sys_signalfd4;
        let _: fn(i32, i32) -> Result<i32, i32> = sys_timerfd_create;
        let _: unsafe fn(i32, i32, *const u8, *mut u8) -> Result<(), i32> = sys_timerfd_settime;
        let _: unsafe fn(i32, i32, *const ItimerSpec, *mut ItimerSpec) -> Result<(), i32> =
            sys_timerfd_settime_spec;
        let _: unsafe fn(i32, *mut u8) -> Result<(), i32> = sys_timerfd_gettime;
        let _: unsafe fn(i32, *mut ItimerSpec) -> Result<(), i32> = sys_timerfd_gettime_spec;
        let _: fn(i32) -> Result<u64, i32> = sys_timerfd_read_expirations;
        let _: unsafe fn(*mut u8, *mut u8) -> Result<(), i32> = sys_capget;
        let _: unsafe fn(*mut CapUserHeader, *mut CapUserData) -> Result<(), i32> = sys_capget_data;
        let _: unsafe fn(*const u8, *const u8) -> Result<(), i32> = sys_capset;
        let _: unsafe fn(*const CapUserHeader, *const CapUserData) -> Result<(), i32> =
            sys_capset_data;
        let _: fn(i32) -> Result<i32, i32> = sys_userfaultfd;
        let _: unsafe fn(i32, *mut UffdApi) -> Result<(), i32> = sys_userfaultfd_api;
        let _: unsafe fn(i32, *const SchedAttr, u32) -> Result<(), i32> = sys_sched_setattr;
        let _: fn(i32) -> ! = sys_exit_group;
        let _: fn() -> i32 = sys_getpid;
        let _: unsafe fn(*mut i32, i32) -> Result<(), i32> = sys_pipe2;
        let _: fn(i32) -> Result<i32, i32> = sys_dup;
        let _: unsafe fn(i32, usize, usize) -> Result<i32, i32> = sys_ioctl;
        let _: fn(i32, i64, i32) -> Result<i64, i32> = sys_lseek;
        let _: fn(i32) -> Result<(), i32> = sys_fsync;
        let _: unsafe fn(i32, *mut u8, usize) -> Result<usize, i32> = sys_getdents64;
        let _: unsafe fn(i32, i32, usize) -> Result<i32, i32> = sys_fcntl;
        let _: fn(i32) -> Result<(), i32> = sys_fdatasync;
        let _: fn(i32, i32, i64, i64) -> Result<(), i32> = sys_fallocate;
        let _: fn(i32, i32) -> Result<i32, i32> = sys_dup2;
        let _: unsafe fn(*mut u8, usize, i32) -> Result<(), i32> = sys_msync;
        let _: unsafe fn(*mut u8, usize, i32) -> Result<(), i32> = sys_madvise;
        let _: fn() -> i32 = sys_gettid;
        let _: fn(usize) -> i32 = sys_set_tid_address;
        let _: fn(i32) -> ! = sys_exit_thread;
        let _: unsafe fn(usize, usize, *mut i32, *mut i32, usize) -> Result<i32, i32> =
            sys_clone_thread;
        let _: unsafe fn(*const CloneArgs, usize) -> Result<i32, i32> = sys_clone3;
        let _: unsafe fn(i32, *mut u8, usize, i64) -> Result<usize, i32> = sys_pread64;
        let _: unsafe fn(i32, *const u8, usize, i64) -> Result<usize, i32> = sys_pwrite64;
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

    #[test]
    fn futex_wait_bitset_value_mismatch_returns_eagain() {
        let futex_word: u32 = 1;
        let err = unsafe {
            sys_futex_wait_bitset(
                &futex_word as *const u32,
                0,
                core::ptr::null(),
                FUTEX_BITSET_MATCH_ANY,
            )
        }
        .expect_err("FUTEX_WAIT_BITSET with a mismatched value must fail immediately");
        assert_eq!(err, EAGAIN);
    }

    #[test]
    fn futex_wait_bitset_zero_mask_is_invalid() {
        let futex_word: u32 = 0;
        let err =
            unsafe { sys_futex_wait_bitset(&futex_word as *const u32, 0, core::ptr::null(), 0) }
                .expect_err("FUTEX_WAIT_BITSET with a zero bitset must fail");
        assert_eq!(err, EINVAL);
    }

    #[test]
    fn futex_waitv_zero_waiters_rejected_or_unavailable() {
        let err = unsafe { sys_futex_waitv(core::ptr::null(), 0, 0, core::ptr::null(), 0) }
            .expect_err("futex_waitv(null, 0, ...) must fail");
        assert!(
            matches!(err, EINVAL | ENOSYS),
            "expected EINVAL/ENOSYS, got {err}"
        );
    }

    #[test]
    fn futex_waitv_null_waiters_faults_or_unavailable() {
        let err = unsafe { sys_futex_waitv(core::ptr::null(), 1, 0, core::ptr::null(), 0) }
            .expect_err("futex_waitv(null, 1, ...) must fail");
        assert!(
            matches!(err, EFAULT | EINVAL | ENOSYS),
            "expected EFAULT/EINVAL/ENOSYS, got {err}"
        );
    }

    /// Kernel ABI layout freeze for io_uring structs (bd-13n0).
    ///
    /// Field offsets and struct sizes must exactly match the layout the
    /// kernel consumes via SYS_io_uring_setup's `struct io_uring_params`
    /// out-parameter (Linux `include/uapi/linux/io_uring.h`). Any field
    /// reorder, padding regression, or accidental alignment change would
    /// silently corrupt kernel interop — this test fails loudly instead.
    #[test]
    fn io_uring_struct_layout_matches_kernel_abi() {
        use core::mem::offset_of;

        // struct io_sqring_offsets — 40 bytes, 8 × u32 + 1 × u64
        assert_eq!(offset_of!(IoUringSqringOffsets, head), 0);
        assert_eq!(offset_of!(IoUringSqringOffsets, tail), 4);
        assert_eq!(offset_of!(IoUringSqringOffsets, ring_mask), 8);
        assert_eq!(offset_of!(IoUringSqringOffsets, ring_entries), 12);
        assert_eq!(offset_of!(IoUringSqringOffsets, flags), 16);
        assert_eq!(offset_of!(IoUringSqringOffsets, dropped), 20);
        assert_eq!(offset_of!(IoUringSqringOffsets, array), 24);
        assert_eq!(offset_of!(IoUringSqringOffsets, resv1), 28);
        assert_eq!(offset_of!(IoUringSqringOffsets, resv2), 32);

        // struct io_cqring_offsets — same 40-byte shape with different
        // field names (the overflow/cqes pair replaces dropped/array).
        assert_eq!(offset_of!(IoUringCqringOffsets, head), 0);
        assert_eq!(offset_of!(IoUringCqringOffsets, tail), 4);
        assert_eq!(offset_of!(IoUringCqringOffsets, ring_mask), 8);
        assert_eq!(offset_of!(IoUringCqringOffsets, ring_entries), 12);
        assert_eq!(offset_of!(IoUringCqringOffsets, overflow), 16);
        assert_eq!(offset_of!(IoUringCqringOffsets, cqes), 20);
        assert_eq!(offset_of!(IoUringCqringOffsets, flags), 24);
        assert_eq!(offset_of!(IoUringCqringOffsets, resv1), 28);
        assert_eq!(offset_of!(IoUringCqringOffsets, resv2), 32);

        // struct io_uring_params — the big top-level layout.
        // Fields 0..28 are 7 × u32, then resv[3] (12 bytes) brings us
        // to offset 40 where sq_off starts. cq_off starts at offset 80.
        assert_eq!(offset_of!(IoUringParams, sq_entries), 0);
        assert_eq!(offset_of!(IoUringParams, cq_entries), 4);
        assert_eq!(offset_of!(IoUringParams, flags), 8);
        assert_eq!(offset_of!(IoUringParams, sq_thread_cpu), 12);
        assert_eq!(offset_of!(IoUringParams, sq_thread_idle), 16);
        assert_eq!(offset_of!(IoUringParams, features), 20);
        assert_eq!(offset_of!(IoUringParams, wq_fd), 24);
        assert_eq!(offset_of!(IoUringParams, resv), 28);
        assert_eq!(
            offset_of!(IoUringParams, sq_off),
            40,
            "sq_off must start right after resv[3]"
        );
        assert_eq!(
            offset_of!(IoUringParams, cq_off),
            80,
            "cq_off must start right after sq_off (40 + 40)"
        );
    }

    /// io_uring_enter flag bits (bd-13n0).
    ///
    /// These bit positions are part of the kernel ABI and must never
    /// drift. Freeze them against the constants the kernel expects in
    /// `enum io_uring_enter_flag`.
    #[test]
    fn io_uring_enter_flag_bits_match_kernel_abi() {
        // IORING_ENTER_GETEVENTS = (1U << 0)
        assert_eq!(IORING_ENTER_GETEVENTS, 1 << 0);
        // IORING_ENTER_SQ_WAKEUP = (1U << 1)
        assert_eq!(IORING_ENTER_SQ_WAKEUP, 1 << 1);
        // The two flags must be distinct bits.
        assert_eq!(
            IORING_ENTER_GETEVENTS & IORING_ENTER_SQ_WAKEUP,
            0,
            "GETEVENTS and SQ_WAKEUP must occupy different bits"
        );
    }

    #[test]
    fn io_uring_setup_zero_entries_rejected_or_unavailable() {
        let mut params = IoUringParams::default();
        let err = unsafe { sys_io_uring_setup_params(0, &mut params) }
            .expect_err("io_uring_setup(entries=0) must fail");
        assert!(
            matches!(err, EINVAL | ENOSYS),
            "expected EINVAL/ENOSYS, got {err}"
        );
    }

    #[test]
    fn io_uring_setup_sqpoll_supported_or_expected_fallback() {
        let mut params = IoUringParams {
            flags: IORING_SETUP_SQPOLL,
            ..IoUringParams::default()
        };
        match unsafe { sys_io_uring_setup_params(8, &mut params) } {
            Ok(fd) => {
                assert!(params.sq_entries > 0, "kernel must report SQ ring entries");
                assert!(params.cq_entries > 0, "kernel must report CQ ring entries");
                sys_close(fd).expect("close io_uring fd");
            }
            Err(err) => {
                assert!(
                    matches!(err, EPERM | EINVAL | ENOSYS),
                    "expected success or EPERM/EINVAL/ENOSYS, got {err}"
                );
            }
        }
    }

    #[test]
    fn io_uring_enter_sqpoll_wakeup_invalid_fd_rejected_or_unavailable() {
        let err = sys_io_uring_enter_sqpoll_wakeup(-1)
            .expect_err("io_uring SQPOLL wakeup on invalid fd must fail");
        assert!(
            matches!(err, EBADF | ENOSYS),
            "expected EBADF/ENOSYS, got {err}"
        );
    }

    #[test]
    fn memfd_secret_supported_or_unavailable() {
        match sys_memfd_secret(0) {
            Ok(fd) => sys_close(fd).expect("close memfd_secret fd"),
            Err(ENOSYS) => {}
            Err(err) => panic!("expected success or ENOSYS, got {err}"),
        }
    }

    #[test]
    fn memfd_secret_invalid_flags_rejected_or_unavailable() {
        let err = sys_memfd_secret(u32::MAX).expect_err("memfd_secret(all-bits-set) must fail");
        assert!(
            matches!(err, EINVAL | ENOSYS),
            "expected EINVAL/ENOSYS, got {err}"
        );
    }

    #[test]
    fn set_mempolicy_invalid_mode_rejected_or_unavailable() {
        let err = unsafe { sys_set_mempolicy(i32::MAX, core::ptr::null(), 0) }
            .expect_err("set_mempolicy(invalid mode, null, 0) must fail");
        assert!(
            matches!(err, EINVAL | ENOSYS),
            "expected EINVAL/ENOSYS, got {err}"
        );
    }

    #[test]
    fn set_mempolicy_bind_requires_nodemask_or_unavailable() {
        let err = unsafe { sys_set_mempolicy(MPOL_BIND, core::ptr::null(), 0) }
            .expect_err("set_mempolicy(MPOL_BIND, null, 0) must fail");
        assert!(
            matches!(err, EINVAL | ENOSYS),
            "expected EINVAL/ENOSYS, got {err}"
        );
    }

    #[test]
    fn get_mempolicy_mode_query_supported_or_unavailable() {
        let mut mode = -1;
        match unsafe {
            sys_get_mempolicy(&mut mode, core::ptr::null_mut(), 0, core::ptr::null(), 0)
        } {
            Ok(()) => assert!(
                (0..=7).contains(&mode),
                "expected policy mode in kernel range, got {mode}"
            ),
            Err(ENOSYS) => {}
            Err(err) => panic!("expected success or ENOSYS, got {err}"),
        }
    }

    #[test]
    fn get_mempolicy_addr_flag_requires_addr_or_unavailable() {
        let mut mode = 0;
        let err = unsafe {
            sys_get_mempolicy(
                &mut mode,
                core::ptr::null_mut(),
                0,
                core::ptr::null(),
                MPOL_F_ADDR,
            )
        }
        .expect_err("get_mempolicy(MPOL_F_ADDR, null addr) must fail");
        assert!(
            matches!(err, EFAULT | EINVAL | ENOSYS),
            "expected EFAULT/EINVAL/ENOSYS, got {err}"
        );
    }

    #[test]
    fn get_mempolicy_addrless_query_rejects_nonnull_addr_or_unavailable() {
        let mut mode = 0;
        let byte = 0u8;
        let err = unsafe { sys_get_mempolicy(&mut mode, core::ptr::null_mut(), 0, &byte, 0) }
            .expect_err("get_mempolicy(flags=0, non-null addr) must fail");
        assert!(
            matches!(err, EINVAL | ENOSYS),
            "expected EINVAL/ENOSYS, got {err}"
        );
    }

    #[test]
    fn get_mempolicy_node_flag_without_interleave_rejected_or_unavailable() {
        let mut mode = 0;
        let err = unsafe {
            sys_get_mempolicy(
                &mut mode,
                core::ptr::null_mut(),
                0,
                core::ptr::null(),
                MPOL_F_NODE,
            )
        }
        .expect_err("get_mempolicy(MPOL_F_NODE) should fail for default policy");
        assert!(
            matches!(err, EINVAL | ENOSYS),
            "expected EINVAL/ENOSYS, got {err}"
        );
    }

    #[test]
    fn faccessat2_at_eaccess_checks_current_directory() {
        let path = b".\0";
        unsafe { sys_faccessat2(AT_FDCWD, path.as_ptr(), 0, AT_EACCESS) }
            .expect("faccessat2(AT_EACCESS) should accept the current directory");
    }

    #[test]
    fn sysinfo_reports_memory_and_uptime() {
        let mut info = core::mem::MaybeUninit::<Sysinfo>::zeroed();
        unsafe { sys_sysinfo(info.as_mut_ptr()) }.expect("sysinfo");
        let info = unsafe { info.assume_init() };

        let mem_unit = u128::from(if info.mem_unit == 0 { 1 } else { info.mem_unit });
        let total_ram = (info.totalram as u128) * mem_unit;
        let free_ram = (info.freeram as u128) * mem_unit;

        assert!(info.uptime >= 0, "uptime should be non-negative");
        assert!(total_ram > 0, "total RAM should be positive");
        assert!(
            free_ram <= total_ram,
            "free RAM should not exceed total RAM"
        );
        assert!(info.procs > 0, "sysinfo should report at least one process");
    }

    #[test]
    fn sysinfo_null_pointer_faults() {
        let err =
            unsafe { sys_sysinfo(core::ptr::null_mut()) }.expect_err("sysinfo(null) must fail");
        assert_eq!(err, EFAULT);
    }

    #[test]
    fn statfs_matches_libc_and_fstatfs_for_current_directory() {
        const O_RDONLY: i32 = 0;

        let path = c".";
        let mut statfs = core::mem::MaybeUninit::<StatFs>::zeroed();
        unsafe { sys_statfs(path.as_ptr().cast(), statfs.as_mut_ptr()) }.expect("sys_statfs");
        let statfs = unsafe { statfs.assume_init() };

        let fd = unsafe { sys_openat(AT_FDCWD, path.as_ptr().cast(), O_RDONLY | O_CLOEXEC, 0) }
            .expect("open current directory");
        let mut fstatfs = core::mem::MaybeUninit::<StatFs>::zeroed();
        unsafe { sys_fstatfs(fd, fstatfs.as_mut_ptr()) }.expect("sys_fstatfs");
        let fstatfs = unsafe { fstatfs.assume_init() };
        sys_close(fd).expect("close current directory");

        assert_eq!(fstatfs.f_bsize, statfs.f_bsize);
        assert_eq!(fstatfs.f_frsize, statfs.f_frsize);
        assert_eq!(fstatfs.f_blocks, statfs.f_blocks);
        assert_eq!(fstatfs.f_bfree, statfs.f_bfree);
        assert_eq!(fstatfs.f_bavail, statfs.f_bavail);
        assert_eq!(fstatfs.f_files, statfs.f_files);
        assert_eq!(fstatfs.f_ffree, statfs.f_ffree);
        assert_eq!(fstatfs.f_namelen, statfs.f_namelen);
        assert!(
            statfs.f_bsize > 0,
            "filesystem block size should be positive"
        );
        assert!(
            statfs.f_frsize > 0,
            "filesystem fragment size should be positive"
        );
        assert!(
            statfs.f_namelen > 0,
            "filesystem name limit should be positive"
        );
    }

    #[test]
    fn statfs_null_buffer_faults() {
        let err = unsafe { sys_statfs(c".".as_ptr().cast(), core::ptr::null_mut()) }
            .expect_err("statfs(null buffer) must fail");
        assert_eq!(err, EFAULT);
    }

    #[test]
    fn inotify_init1_nonblock_and_cloexec_flags_apply_to_fd() {
        let fd = sys_inotify_init1(IN_NONBLOCK | IN_CLOEXEC).expect("inotify_init1");

        let fd_flags = unsafe { sys_fcntl(fd, F_GETFD, 0) }.expect("fcntl(F_GETFD)");
        assert_ne!(
            fd_flags & FD_CLOEXEC,
            0,
            "inotify_init1 should apply close-on-exec"
        );
        let file_status = unsafe { sys_fcntl(fd, F_GETFL, 0) }.expect("fcntl(F_GETFL)");
        assert_ne!(
            file_status & O_NONBLOCK,
            0,
            "inotify_init1 should apply nonblocking mode"
        );

        sys_close(fd).expect("close inotify fd");
    }

    #[test]
    fn inotify_init1_invalid_flags_are_rejected() {
        let err = sys_inotify_init1(i32::MIN).expect_err("inotify_init1(invalid flags) must fail");
        assert_eq!(err, EINVAL);
    }

    #[test]
    fn sched_getaffinity_cpuset_contains_current_cpu() {
        let mut cpuset = CpuSet::default();
        let bytes =
            unsafe { sys_sched_getaffinity_cpuset(0, &mut cpuset) }.expect("sched_getaffinity");
        assert!(
            bytes > 0 && bytes <= core::mem::size_of::<CpuSet>(),
            "kernel returned unexpected affinity size {bytes}"
        );

        let mut cpu = 0_u32;
        unsafe { sys_getcpu(&mut cpu, core::ptr::null_mut()) }.expect("getcpu");
        assert!(
            cpuset.contains_cpu(cpu),
            "affinity mask should contain current cpu {cpu}"
        );
    }

    #[test]
    fn timer_create_sigevent_targets_current_thread() {
        struct SignalMaskGuard {
            old_mask: u64,
        }

        impl Drop for SignalMaskGuard {
            fn drop(&mut self) {
                let _ = unsafe {
                    sys_rt_sigprocmask(
                        SIG_SETMASK,
                        (&self.old_mask as *const u64).cast::<u8>(),
                        core::ptr::null_mut(),
                        core::mem::size_of::<u64>(),
                    )
                };
            }
        }

        struct FdGuard(i32);

        impl Drop for FdGuard {
            fn drop(&mut self) {
                let _ = sys_close(self.0);
            }
        }

        struct TimerGuard(i32);

        impl Drop for TimerGuard {
            fn drop(&mut self) {
                let _ = sys_timer_delete(self.0);
            }
        }

        let signal_mask = 1u64 << ((SIGUSR1 - 1) as u32);
        let mut old_mask = 0u64;
        unsafe {
            sys_rt_sigprocmask(
                SIG_BLOCK,
                (&signal_mask as *const u64).cast::<u8>(),
                (&mut old_mask as *mut u64).cast::<u8>(),
                core::mem::size_of::<u64>(),
            )
        }
        .expect("rt_sigprocmask(SIG_BLOCK)");
        let _mask_guard = SignalMaskGuard { old_mask };

        let fd = unsafe {
            sys_signalfd4(
                -1,
                (&signal_mask as *const u64).cast::<u8>(),
                core::mem::size_of::<u64>(),
                SFD_CLOEXEC,
            )
        }
        .expect("signalfd4");
        let _fd_guard = FdGuard(fd);

        let sigevent = SigEventThreadId::new(SIGUSR1, sys_gettid());
        let mut timerid = -1;
        match unsafe { sys_timer_create_sigevent(CLOCK_MONOTONIC, &sigevent, &mut timerid) } {
            Ok(()) => {}
            Err(ENOSYS | EPERM | EACCES | ENOTSUP) => return,
            Err(err) => panic!("expected timer_create or ENOSYS/EPERM/EACCES/ENOTSUP, got {err}"),
        }
        let _timer_guard = TimerGuard(timerid);

        let new_value = ItimerSpec {
            it_interval: Timespec::default(),
            it_value: Timespec {
                tv_sec: 0,
                tv_nsec: 1_000_000,
            },
        };
        unsafe {
            sys_timer_settime(
                timerid,
                0,
                (&new_value as *const ItimerSpec).cast::<u8>(),
                core::ptr::null_mut(),
            )
        }
        .expect("timer_settime");

        let mut info = SignalfdSiginfo::default();
        let read = unsafe {
            sys_read(
                fd,
                (&mut info as *mut SignalfdSiginfo).cast::<u8>(),
                core::mem::size_of::<SignalfdSiginfo>(),
            )
        }
        .expect("read timer signal");
        assert_eq!(read, core::mem::size_of::<SignalfdSiginfo>());
        assert_eq!(info.ssi_signo, SIGUSR1 as u32);
        assert_eq!(info.ssi_tid, timerid as u32);
        assert_eq!(info.ssi_code, -2, "timer signal should report SI_TIMER");
    }

    #[test]
    fn accept4_sets_requested_fd_flags_while_accept_does_not() {
        struct FdGuard(i32);

        impl Drop for FdGuard {
            fn drop(&mut self) {
                if self.0 >= 0 {
                    let _ = sys_close(self.0);
                }
            }
        }

        fn loopback_addr(port: u16) -> SockAddrIn {
            SockAddrIn {
                sin_family: AF_INET as u16,
                sin_port: port.to_be(),
                sin_addr: u32::from_ne_bytes([127, 0, 0, 1]),
                sin_zero: [0; 8],
            }
        }

        fn connect_client(port: u16) -> FdGuard {
            let fd = sys_socket(AF_INET, SOCK_STREAM, 0).expect("socket client");
            let addr = loopback_addr(port);
            unsafe {
                sys_connect(
                    fd,
                    (&addr as *const SockAddrIn).cast::<u8>(),
                    core::mem::size_of::<SockAddrIn>() as u32,
                )
            }
            .expect("connect client");
            FdGuard(fd)
        }

        let listener = sys_socket(AF_INET, SOCK_STREAM, 0).expect("socket listener");
        let listener = FdGuard(listener);
        let bind_addr = loopback_addr(0);
        unsafe {
            sys_bind(
                listener.0,
                (&bind_addr as *const SockAddrIn).cast::<u8>(),
                core::mem::size_of::<SockAddrIn>() as u32,
            )
        }
        .expect("bind listener");
        sys_listen(listener.0, 2).expect("listen");

        let mut listen_addr = SockAddrIn::default();
        let mut listen_len = core::mem::size_of::<SockAddrIn>() as u32;
        unsafe {
            sys_getsockname(
                listener.0,
                (&mut listen_addr as *mut SockAddrIn).cast::<u8>(),
                &mut listen_len,
            )
        }
        .expect("getsockname listener");
        assert_eq!(listen_len as usize, core::mem::size_of::<SockAddrIn>());
        let port = u16::from_be(listen_addr.sin_port);
        assert_ne!(port, 0, "listener should get an ephemeral port");

        let client_plain = connect_client(port);
        let accepted_plain =
            unsafe { sys_accept(listener.0, core::ptr::null_mut(), core::ptr::null_mut()) }
                .expect("accept plain");
        let accepted_plain = FdGuard(accepted_plain);
        let plain_fd_flags =
            unsafe { sys_fcntl(accepted_plain.0, F_GETFD, 0) }.expect("fcntl plain F_GETFD");
        let plain_status =
            unsafe { sys_fcntl(accepted_plain.0, F_GETFL, 0) }.expect("fcntl plain F_GETFL");
        assert_eq!(
            plain_fd_flags & FD_CLOEXEC,
            0,
            "accept should not set close-on-exec"
        );
        assert_eq!(
            plain_status & O_NONBLOCK,
            0,
            "accept should not set nonblocking mode"
        );
        drop(accepted_plain);
        drop(client_plain);

        let client_flagged = connect_client(port);
        let accepted_flagged = unsafe {
            sys_accept4(
                listener.0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                SOCK_CLOEXEC | SOCK_NONBLOCK,
            )
        }
        .expect("accept4 flagged");
        let accepted_flagged = FdGuard(accepted_flagged);
        let flagged_fd_flags =
            unsafe { sys_fcntl(accepted_flagged.0, F_GETFD, 0) }.expect("fcntl flagged F_GETFD");
        let flagged_status =
            unsafe { sys_fcntl(accepted_flagged.0, F_GETFL, 0) }.expect("fcntl flagged F_GETFL");
        assert_ne!(
            flagged_fd_flags & FD_CLOEXEC,
            0,
            "accept4 should apply close-on-exec"
        );
        assert_ne!(
            flagged_status & O_NONBLOCK,
            0,
            "accept4 should apply nonblocking mode"
        );
        drop(accepted_flagged);
        drop(client_flagged);
    }

    #[test]
    fn socketpair_seqpacket_preserves_flags_and_allows_null_sendto_destination() {
        struct FdGuard(i32);

        impl Drop for FdGuard {
            fn drop(&mut self) {
                if self.0 >= 0 {
                    let _ = sys_close(self.0);
                }
            }
        }

        let mut sv = [-1i32; 2];
        unsafe {
            sys_socketpair(
                AF_UNIX,
                SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC,
                0,
                sv.as_mut_ptr(),
            )
        }
        .expect("socketpair(AF_UNIX, SOCK_SEQPACKET | flags)");

        let left = FdGuard(sv[0]);
        let right = FdGuard(sv[1]);
        for fd in [left.0, right.0] {
            let fd_flags = unsafe { sys_fcntl(fd, F_GETFD, 0) }.expect("fcntl(F_GETFD)");
            let status_flags = unsafe { sys_fcntl(fd, F_GETFL, 0) }.expect("fcntl(F_GETFL)");
            assert_ne!(
                fd_flags & FD_CLOEXEC,
                0,
                "socketpair should set close-on-exec"
            );
            assert_ne!(
                status_flags & O_NONBLOCK,
                0,
                "socketpair should set nonblocking mode"
            );
        }

        let payload = b"seqpacket";
        let sent = unsafe {
            sys_sendto(
                left.0,
                payload.as_ptr(),
                payload.len(),
                0,
                core::ptr::null(),
                0,
            )
        }
        .expect("sendto on connected socketpair");
        assert_eq!(sent as usize, payload.len());

        let mut buf = [0u8; 32];
        let received = unsafe {
            sys_recvfrom(
                right.0,
                buf.as_mut_ptr(),
                buf.len(),
                0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        }
        .expect("recvfrom on socketpair");
        assert_eq!(received as usize, payload.len());
        assert_eq!(&buf[..received as usize], payload);
    }

    #[test]
    fn clock_nanosleep_boottime_abstime_accepts_elapsed_deadline() {
        let mut now = Timespec::default();
        unsafe { sys_clock_gettime(CLOCK_BOOTTIME, (&mut now as *mut Timespec).cast::<u8>()) }
            .expect("clock_gettime(CLOCK_BOOTTIME)");

        let elapsed_deadline = if now.tv_nsec > 0 {
            Timespec {
                tv_sec: now.tv_sec,
                tv_nsec: now.tv_nsec - 1,
            }
        } else {
            Timespec {
                tv_sec: now.tv_sec.saturating_sub(1),
                tv_nsec: 999_999_999,
            }
        };

        unsafe {
            sys_clock_nanosleep_spec(
                CLOCK_BOOTTIME,
                TIMER_ABSTIME,
                &elapsed_deadline,
                core::ptr::null_mut(),
            )
        }
        .expect("clock_nanosleep(CLOCK_BOOTTIME, TIMER_ABSTIME)");
    }

    #[test]
    fn readlink_helper_matches_readlinkat_relative_dirfd() {
        struct FdGuard(i32);

        impl Drop for FdGuard {
            fn drop(&mut self) {
                if self.0 >= 0 {
                    let _ = sys_close(self.0);
                }
            }
        }

        let dir = std::path::PathBuf::from(format!(
            "/tmp/frankenlibc_readlink_{}_{}",
            sys_getpid(),
            sys_gettid()
        ));
        let mut dir_bytes = dir.to_string_lossy().into_owned().into_bytes();
        dir_bytes.push(0);

        unsafe { sys_mkdirat(AT_FDCWD, dir_bytes.as_ptr(), 0o700) }.expect("mkdirat temp dir");
        let dirfd =
            unsafe { sys_openat(AT_FDCWD, dir_bytes.as_ptr(), O_CLOEXEC, 0) }.expect("open dir");
        let dirfd = FdGuard(dirfd);

        let target = b"payload-target\0";
        let link_name = b"link\0";
        unsafe { sys_symlinkat(target.as_ptr(), dirfd.0, link_name.as_ptr()) }
            .expect("symlinkat link");

        let mut via_dirfd = [0u8; 64];
        let via_dirfd_len = unsafe {
            sys_readlinkat(
                dirfd.0,
                link_name.as_ptr(),
                via_dirfd.as_mut_ptr(),
                via_dirfd.len(),
            )
        }
        .expect("readlinkat relative");

        let mut full_link = dir.to_string_lossy().into_owned().into_bytes();
        full_link.extend_from_slice(b"/link\0");
        let mut via_readlink = [0u8; 64];
        let via_readlink_len = unsafe {
            sys_readlink(
                full_link.as_ptr(),
                via_readlink.as_mut_ptr(),
                via_readlink.len(),
            )
        }
        .expect("readlink helper");

        let expected = &target[..target.len() - 1];
        assert_eq!(via_dirfd_len as usize, expected.len());
        assert_eq!(via_readlink_len as usize, expected.len());
        assert_eq!(&via_dirfd[..via_dirfd_len as usize], expected);
        assert_eq!(&via_readlink[..via_readlink_len as usize], expected);

        std::fs::remove_file(dir.join("link")).expect("cleanup link");
        std::fs::remove_dir(&dir).expect("cleanup dir");
    }

    #[test]
    fn waitid_typed_helper_reports_stops_and_exits() {
        let _lock = WAITID_LOCK.lock().expect("waitid lock");

        let pid = match sys_clone_fork(SIGCHLD) {
            Ok(0) => {
                if sys_kill(sys_getpid(), SIGSTOP).is_err() {
                    sys_exit_group(127);
                }
                sys_exit_group(9);
            }
            Ok(pid) => pid,
            Err(err) => panic!("clone(SIGCHLD) failed: {err}"),
        };

        let mut stop_info = WaitSigInfo::default();
        unsafe { sys_waitid_info(P_PID, pid as u32, &mut stop_info, WSTOPPED) }
            .expect("waitid(WSTOPPED)");
        assert_eq!(stop_info.si_signo, SIGCHLD as i32);
        assert_eq!(stop_info.si_code, CLD_STOPPED);
        assert_eq!(stop_info.child_pid(), pid);
        assert_eq!(stop_info.child_status(), SIGSTOP);

        sys_kill(pid, SIGCONT).expect("SIGCONT child");

        let mut exit_info = WaitSigInfo::default();
        unsafe { sys_waitid_info(P_PID, pid as u32, &mut exit_info, WEXITED) }
            .expect("waitid(WEXITED)");
        assert_eq!(exit_info.si_signo, SIGCHLD as i32);
        assert_eq!(exit_info.si_code, CLD_EXITED);
        assert_eq!(exit_info.child_pid(), pid);
        assert_eq!(exit_info.child_status(), 9);

        let err = unsafe { sys_wait4(pid, core::ptr::null_mut(), 0, core::ptr::null_mut()) }
            .expect_err("waitid(WEXITED) should reap the child");
        assert_eq!(err, ECHILD);
    }

    #[test]
    fn clone3_clone_pidfd_reports_child_fd_or_expected_fallback() {
        let _lock = WAITID_LOCK.lock().expect("waitid lock");

        let mut pidfd = -1_i32;
        let args = CloneArgs {
            flags: frankenlibc_core::syscall::CLONE_PIDFD,
            pidfd: (&mut pidfd as *mut i32).cast::<()>() as u64,
            exit_signal: SIGCHLD as u64,
            ..CloneArgs::default()
        };

        match unsafe { sys_clone3(&args, core::mem::size_of::<CloneArgs>()) } {
            Ok(0) => sys_exit_group(23),
            Ok(pid) => {
                assert!(pidfd >= 0, "clone3(CLONE_PIDFD) did not populate pidfd");
                let fd_flags = unsafe { sys_fcntl(pidfd, F_GETFD, 0) }.expect("fcntl(F_GETFD)");
                assert!(fd_flags >= 0, "pidfd must be a valid descriptor");

                let mut exit_info = WaitSigInfo::default();
                unsafe { sys_waitid_info(P_PID, pid as u32, &mut exit_info, WEXITED) }
                    .expect("waitid(WEXITED)");
                assert_eq!(exit_info.si_signo, SIGCHLD as i32);
                assert_eq!(exit_info.si_code, CLD_EXITED);
                assert_eq!(exit_info.child_pid(), pid);
                assert_eq!(exit_info.child_status(), 23);

                sys_close(pidfd).expect("close pidfd");
            }
            Err(err) => {
                assert!(
                    matches!(err, ENOSYS | EPERM),
                    "expected ENOSYS/EPERM, got {err}"
                );
            }
        }
    }

    #[test]
    fn waitid_pidfd_selector_reports_clone3_child_or_expected_fallback() {
        let _lock = WAITID_LOCK.lock().expect("waitid lock");

        let mut pidfd = -1_i32;
        let args = CloneArgs {
            flags: frankenlibc_core::syscall::CLONE_PIDFD,
            pidfd: (&mut pidfd as *mut i32).cast::<()>() as u64,
            exit_signal: SIGCHLD as u64,
            ..CloneArgs::default()
        };

        match unsafe { sys_clone3(&args, core::mem::size_of::<CloneArgs>()) } {
            Ok(0) => sys_exit_group(41),
            Ok(pid) => {
                assert!(pidfd >= 0, "clone3(CLONE_PIDFD) did not populate pidfd");

                let mut exit_info = WaitSigInfo::default();
                match unsafe {
                    sys_waitid_info(
                        frankenlibc_core::syscall::P_PIDFD,
                        pidfd as u32,
                        &mut exit_info,
                        WEXITED,
                    )
                } {
                    Ok(()) => {
                        assert_eq!(exit_info.si_signo, SIGCHLD as i32);
                        assert_eq!(exit_info.si_code, CLD_EXITED);
                        assert_eq!(exit_info.child_pid(), pid);
                        assert_eq!(exit_info.child_status(), 41);

                        let err = unsafe {
                            sys_wait4(pid, core::ptr::null_mut(), 0, core::ptr::null_mut())
                        }
                        .expect_err("waitid(P_PIDFD, ...) should reap the child");
                        assert_eq!(err, ECHILD);
                    }
                    Err(err) => {
                        assert!(
                            matches!(err, EINVAL | ENOSYS),
                            "expected EINVAL/ENOSYS for unsupported P_PIDFD waitid, got {err}"
                        );

                        let mut fallback = WaitSigInfo::default();
                        unsafe { sys_waitid_info(P_PID, pid as u32, &mut fallback, WEXITED) }
                            .expect("fallback waitid(WEXITED)");
                        assert_eq!(fallback.child_pid(), pid);
                        assert_eq!(fallback.child_status(), 41);
                    }
                }

                sys_close(pidfd).expect("close pidfd");
            }
            Err(err) => {
                assert!(
                    matches!(err, ENOSYS | EPERM),
                    "expected ENOSYS/EPERM, got {err}"
                );
            }
        }
    }

    #[test]
    fn signalfd4_nonblock_and_cloexec_flags_deliver_signal() {
        struct SignalMaskGuard {
            old_mask: u64,
        }

        impl Drop for SignalMaskGuard {
            fn drop(&mut self) {
                let _ = unsafe {
                    sys_rt_sigprocmask(
                        SIG_SETMASK,
                        (&self.old_mask as *const u64).cast::<u8>(),
                        core::ptr::null_mut(),
                        core::mem::size_of::<u64>(),
                    )
                };
            }
        }

        struct FdGuard(i32);

        impl Drop for FdGuard {
            fn drop(&mut self) {
                let _ = sys_close(self.0);
            }
        }

        let signal_mask = 1u64 << ((SIGUSR1 - 1) as u32);
        let mut old_mask = 0u64;
        unsafe {
            sys_rt_sigprocmask(
                SIG_BLOCK,
                (&signal_mask as *const u64).cast::<u8>(),
                (&mut old_mask as *mut u64).cast::<u8>(),
                core::mem::size_of::<u64>(),
            )
        }
        .expect("rt_sigprocmask(SIG_BLOCK)");
        let _mask_guard = SignalMaskGuard { old_mask };

        let fd = unsafe {
            sys_signalfd4(
                -1,
                (&signal_mask as *const u64).cast::<u8>(),
                core::mem::size_of::<u64>(),
                SFD_NONBLOCK | SFD_CLOEXEC,
            )
        }
        .expect("signalfd4");
        let _fd_guard = FdGuard(fd);

        let fd_flags = unsafe { sys_fcntl(fd, F_GETFD, 0) }.expect("fcntl(F_GETFD)");
        assert_ne!(
            fd_flags & FD_CLOEXEC,
            0,
            "signalfd4 should apply close-on-exec"
        );
        let file_status = unsafe { sys_fcntl(fd, F_GETFL, 0) }.expect("fcntl(F_GETFL)");
        assert_ne!(
            file_status & O_NONBLOCK,
            0,
            "signalfd4 should apply nonblocking mode"
        );

        sys_tgkill(sys_getpid(), sys_gettid(), SIGUSR1).expect("tgkill(SIGUSR1)");

        let mut info = SignalfdSiginfo::default();
        let read = unsafe {
            sys_read(
                fd,
                (&mut info as *mut SignalfdSiginfo).cast::<u8>(),
                core::mem::size_of::<SignalfdSiginfo>(),
            )
        }
        .expect("read signalfd siginfo");
        assert_eq!(read, core::mem::size_of::<SignalfdSiginfo>());
        assert_eq!(info.ssi_signo, SIGUSR1 as u32);
        assert_eq!(info.ssi_pid, sys_getpid() as u32);
    }

    #[test]
    fn userfaultfd_api_negotiates_sigbus_or_reports_unavailable() {
        let fd = match sys_userfaultfd(O_CLOEXEC | O_NONBLOCK) {
            Ok(fd) => fd,
            Err(ENOSYS | EPERM) => return,
            Err(err) => panic!("expected userfaultfd or ENOSYS/EPERM, got {err}"),
        };

        let mut api = UffdApi {
            api: UFFD_API,
            features: UFFD_FEATURE_SIGBUS,
            ioctls: 0,
        };
        let result = unsafe { sys_userfaultfd_api(fd, &mut api) };
        sys_close(fd).expect("close userfaultfd");

        match result {
            Ok(()) => {
                assert_eq!(api.api, UFFD_API);
                assert_ne!(
                    api.features & UFFD_FEATURE_SIGBUS,
                    0,
                    "kernel handshake should preserve requested SIGBUS feature"
                );
                assert_ne!(api.ioctls, 0, "kernel should report non-empty uffd ioctls");
            }
            Err(EINVAL) => {}
            Err(err) => panic!("expected success or EINVAL for unsupported feature, got {err}"),
        }
    }

    #[test]
    fn userfaultfd_api_null_pointer_faults_or_unavailable() {
        let fd = match sys_userfaultfd(O_CLOEXEC | O_NONBLOCK) {
            Ok(fd) => fd,
            Err(ENOSYS | EPERM) => return,
            Err(err) => panic!("expected userfaultfd or ENOSYS/EPERM, got {err}"),
        };

        let err = unsafe { sys_userfaultfd_api(fd, core::ptr::null_mut()) }
            .expect_err("userfaultfd_api(null) must fail");
        sys_close(fd).expect("close userfaultfd");

        assert!(
            matches!(err, EFAULT | EINVAL),
            "expected EFAULT/EINVAL, got {err}"
        );
    }

    #[test]
    fn timerfd_settime_abstime_reports_old_state_and_expires() {
        let fd = sys_timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK)
            .expect("timerfd_create");

        let mut now = Timespec::default();
        unsafe { sys_clock_gettime(CLOCK_MONOTONIC, (&mut now as *mut Timespec).cast::<u8>()) }
            .expect("clock_gettime");

        let absolute = if now.tv_nsec > 0 {
            Timespec {
                tv_sec: now.tv_sec,
                tv_nsec: now.tv_nsec - 1,
            }
        } else {
            Timespec {
                tv_sec: now.tv_sec.saturating_sub(1),
                tv_nsec: 999_999_999,
            }
        };
        let new_value = ItimerSpec {
            it_interval: Timespec::default(),
            it_value: absolute,
        };
        let mut old_value = ItimerSpec::default();
        unsafe { sys_timerfd_settime_spec(fd, TFD_TIMER_ABSTIME, &new_value, &mut old_value) }
            .expect("timerfd_settime abstime");
        assert_eq!(
            old_value,
            ItimerSpec::default(),
            "new timerfd should report zero old state"
        );

        let mut current = ItimerSpec::default();
        unsafe { sys_timerfd_gettime_spec(fd, &mut current) }.expect("timerfd_gettime");
        assert_eq!(current.it_interval, Timespec::default());

        let expirations = sys_timerfd_read_expirations(fd).expect("timerfd read");
        assert_eq!(
            expirations, 1,
            "one-shot timer should report exactly one expiration"
        );

        sys_close(fd).expect("close timerfd");
    }

    #[test]
    fn timerfd_create_applies_cloexec_and_nonblock_flags() {
        let fd = sys_timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK)
            .expect("timerfd_create");

        let fd_flags = unsafe { sys_fcntl(fd, F_GETFD, 0) }.expect("fcntl(F_GETFD)");
        assert_ne!(
            fd_flags & FD_CLOEXEC,
            0,
            "timerfd_create should apply close-on-exec"
        );

        let status_flags = unsafe { sys_fcntl(fd, F_GETFL, 0) }.expect("fcntl(F_GETFL)");
        assert_ne!(
            status_flags & O_NONBLOCK,
            0,
            "timerfd_create should apply nonblocking mode"
        );

        sys_close(fd).expect("close timerfd");
    }

    #[test]
    fn timerfd_create_with_nonblock_keeps_cloexec_clear() {
        let fd = sys_timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK).expect("timerfd_create");

        let fd_flags = unsafe { sys_fcntl(fd, F_GETFD, 0) }.expect("fcntl(F_GETFD)");
        assert_eq!(
            fd_flags & FD_CLOEXEC,
            0,
            "timerfd_create with TFD_NONBLOCK alone should not set close-on-exec"
        );

        let status_flags = unsafe { sys_fcntl(fd, F_GETFL, 0) }.expect("fcntl(F_GETFL)");
        assert_ne!(
            status_flags & O_NONBLOCK,
            0,
            "timerfd_create with TFD_NONBLOCK should still set nonblocking mode"
        );

        sys_close(fd).expect("close timerfd");
    }

    #[test]
    fn timerfd_read_expirations_nonblocking_requires_ready_timer() {
        let fd = sys_timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK)
            .expect("timerfd_create");
        let err = sys_timerfd_read_expirations(fd)
            .expect_err("nonblocking timerfd read should fail before expiration");
        assert_eq!(err, EAGAIN);
        sys_close(fd).expect("close timerfd");
    }

    #[test]
    fn timerfd_settime_null_new_value_faults() {
        let fd = sys_timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC).expect("timerfd_create");

        let err =
            unsafe { sys_timerfd_settime_spec(fd, 0, core::ptr::null(), core::ptr::null_mut()) }
                .expect_err("timerfd_settime(null) must fail");
        assert!(matches!(err, EFAULT), "expected EFAULT, got {err}");

        sys_close(fd).expect("close timerfd");
    }

    #[test]
    fn capget_invalid_version_reports_preferred_v3() {
        let mut header = CapUserHeader { version: 0, pid: 0 };
        match unsafe { sys_capget_data(&mut header, core::ptr::null_mut()) } {
            Ok(()) => {}
            Err(EINVAL) => {}
            Err(err) => panic!("expected capget probe success or EINVAL, got {err}"),
        }
        assert_eq!(header.version, LINUX_CAPABILITY_VERSION_3);
    }

    #[test]
    fn capset_roundtrips_current_thread_capability_bitmap() {
        let mut header = CapUserHeader {
            version: LINUX_CAPABILITY_VERSION_3,
            pid: 0,
        };
        let mut before = [CapUserData::default(); LINUX_CAPABILITY_U32S_3];
        unsafe { sys_capget_data(&mut header, before.as_mut_ptr()) }.expect("capget before");
        assert_eq!(header.version, LINUX_CAPABILITY_VERSION_3);

        unsafe { sys_capset_data(&header, before.as_ptr()) }.expect("capset same bitmap");

        let mut after_header = CapUserHeader {
            version: LINUX_CAPABILITY_VERSION_3,
            pid: 0,
        };
        let mut after = [CapUserData::default(); LINUX_CAPABILITY_U32S_3];
        unsafe { sys_capget_data(&mut after_header, after.as_mut_ptr()) }.expect("capget after");

        assert_eq!(after_header.version, LINUX_CAPABILITY_VERSION_3);
        assert_eq!(after, before, "capability bitmap should remain unchanged");
    }

    #[test]
    fn sched_setattr_null_attr_faults_or_unavailable() {
        let err = unsafe { sys_sched_setattr(0, core::ptr::null(), 0) }
            .expect_err("sched_setattr(self, null, 0) must fail");
        assert!(
            matches!(err, EFAULT | EINVAL | ENOSYS),
            "expected EFAULT/EINVAL/ENOSYS, got {err}"
        );
    }

    #[test]
    fn sched_setattr_deadline_invalid_parameters_rejected_or_unavailable() {
        let attr = SchedAttr {
            size: core::mem::size_of::<SchedAttr>() as u32,
            sched_policy: SCHED_DEADLINE,
            sched_runtime: 0,
            sched_deadline: 0,
            sched_period: 0,
            ..SchedAttr::default()
        };
        let err = unsafe { sys_sched_setattr(0, &attr, 0) }
            .expect_err("sched_setattr(self, invalid deadline attr, 0) must fail");
        assert!(
            matches!(err, EINVAL | ENOSYS | EPERM),
            "expected EINVAL/ENOSYS/EPERM, got {err}"
        );
    }

    #[test]
    fn clone3_zero_size_rejected_or_unavailable() {
        let err =
            unsafe { sys_clone3(core::ptr::null(), 0) }.expect_err("clone3(null, 0) must fail");
        assert!(
            matches!(err, EINVAL | ENOSYS | EPERM),
            "expected EINVAL/ENOSYS/EPERM, got {err}"
        );
    }

    #[test]
    fn clone3_null_args_with_struct_size_faults_or_unavailable() {
        let err = unsafe { sys_clone3(core::ptr::null(), core::mem::size_of::<CloneArgs>()) }
            .expect_err("clone3(null, sizeof(CloneArgs)) must fail");
        assert!(
            matches!(err, EFAULT | ENOSYS | EPERM),
            "expected EFAULT/ENOSYS/EPERM, got {err}"
        );
    }

    // -----------------------------------------------------------------
    // Metamorphic: raw-syscall signal semantics (bd-imo7)
    // -----------------------------------------------------------------

    /// POSIX null-signal (sig=0) performs only permission and thread-
    /// existence checks; sending to the current process must succeed
    /// because the caller always has permission to signal itself.
    #[test]
    fn sys_kill_self_null_signal_succeeds() {
        let pid = sys_getpid();
        sys_kill(pid, 0).expect("kill(self, 0) must succeed as POSIX null signal");
    }

    /// Metamorphic (invertive): rt_sigprocmask get→set→restore is the
    /// identity. Save the current mask, block SIGUSR1, verify the mask
    /// reflects the block, restore to the saved mask, and verify the
    /// restored state matches the original word-for-word.
    ///
    /// Fences against: sigset_t ABI drift (wrong sigsetsize, endianness
    /// bugs in the block-word representation), `how` parameter swaps
    /// between SIG_SETMASK/SIG_BLOCK, and any path that silently loses
    /// bits between the kernel and userspace buffers.
    #[test]
    fn sys_rt_sigprocmask_get_set_restore_is_invertive() {
        const SIG_UNBLOCK: i32 = 1;
        let sigsetsize = core::mem::size_of::<u64>();

        // Phase 1: snapshot current mask with a no-op SIG_SETMASK query.
        let mut saved_mask: u64 = 0;
        unsafe {
            sys_rt_sigprocmask(
                SIG_UNBLOCK,
                core::ptr::null(),
                (&mut saved_mask as *mut u64).cast::<u8>(),
                sigsetsize,
            )
        }
        .expect("rt_sigprocmask snapshot");

        // Phase 2: block SIGUSR1, observe the new mask.
        let sigusr1_bit = 1u64 << ((SIGUSR1 - 1) as u32);
        let mut after_block: u64 = 0;
        unsafe {
            sys_rt_sigprocmask(
                SIG_BLOCK,
                (&sigusr1_bit as *const u64).cast::<u8>(),
                (&mut after_block as *mut u64).cast::<u8>(),
                sigsetsize,
            )
        }
        .expect("rt_sigprocmask(SIG_BLOCK, SIGUSR1)");
        assert_eq!(
            after_block, saved_mask,
            "oldset from SIG_BLOCK must equal the pre-block mask"
        );

        let mut observed: u64 = 0;
        unsafe {
            sys_rt_sigprocmask(
                SIG_UNBLOCK,
                core::ptr::null(),
                (&mut observed as *mut u64).cast::<u8>(),
                sigsetsize,
            )
        }
        .expect("rt_sigprocmask observe after block");
        assert_eq!(
            observed & sigusr1_bit,
            sigusr1_bit,
            "SIGUSR1 bit must be set after SIG_BLOCK"
        );

        // Phase 3: restore the saved mask verbatim via SIG_SETMASK.
        unsafe {
            sys_rt_sigprocmask(
                SIG_SETMASK,
                (&saved_mask as *const u64).cast::<u8>(),
                core::ptr::null_mut(),
                sigsetsize,
            )
        }
        .expect("rt_sigprocmask(SIG_SETMASK, saved)");

        // Phase 4: observe restored state; must equal saved_mask exactly.
        let mut restored: u64 = 0;
        unsafe {
            sys_rt_sigprocmask(
                SIG_UNBLOCK,
                core::ptr::null(),
                (&mut restored as *mut u64).cast::<u8>(),
                sigsetsize,
            )
        }
        .expect("rt_sigprocmask final snapshot");
        assert_eq!(
            restored, saved_mask,
            "get→set→restore must be invertive (saved={saved_mask:#x}, restored={restored:#x})"
        );
    }

    /// Metamorphic parity: for the current thread, sys_tgkill(getpid, gettid, 0)
    /// and sys_tkill(gettid, 0) must both succeed. tgkill is a refinement of
    /// tkill with an extra tgid guard against pid reuse races, so the two
    /// calls must agree on a thread the caller owns.
    #[test]
    fn sys_tgkill_tkill_parity_on_self_null_signal() {
        let pid = sys_getpid();
        let tid = sys_gettid();
        sys_tgkill(pid, tid, 0).expect("tgkill(self, 0) must succeed");
        sys_tkill(tid, 0).expect("tkill(self, 0) must succeed");
    }

    /// Metamorphic: sys_tgkill with a mismatched tgid must fail with ESRCH
    /// (thread no longer belongs to the named process), even when the tid
    /// itself is live. tkill has no tgid guard and would succeed on the
    /// same tid, so the divergence pins down tgkill's extra check.
    #[test]
    fn sys_tgkill_mismatched_tgid_is_esrch() {
        // Pick a tgid that cannot match: PID 1 (init) belongs to a different
        // thread group than our test binary, so our own tid cannot be a
        // thread of pid 1. tgkill must reject; tkill would not check tgid.
        const ESRCH: i32 = 3;
        let tid = sys_gettid();
        let err = sys_tgkill(1, tid, 0).expect_err("tgkill(1, self_tid, 0) must fail");
        assert_eq!(err, ESRCH, "expected ESRCH for mismatched tgid, got {err}");
    }

    /// sys_kill with an out-of-range signal number must fail with EINVAL,
    /// regardless of target pid. The kernel validates `sig` before
    /// running the permission check, so even an invalid pid/sig
    /// combination surfaces EINVAL rather than ESRCH or EPERM.
    #[test]
    fn sys_kill_self_rejects_out_of_range_signal() {
        let pid = sys_getpid();
        let err = sys_kill(pid, 65).expect_err("kill(self, 65) must fail");
        assert_eq!(err, EINVAL, "expected EINVAL for sig=65, got {err}");

        let err = sys_kill(pid, -1).expect_err("kill(self, -1) must fail");
        assert_eq!(err, EINVAL, "expected EINVAL for sig=-1, got {err}");
    }
}

#[cfg(target_arch = "aarch64")]
mod aarch64_tests {
    use frankenlibc_core::syscall::*;
    use std::path::PathBuf;

    const O_RDWR: i32 = 2;
    const O_CREAT: i32 = 0o100;
    const O_EXCL: i32 = 0o200;
    const O_NONBLOCK: i32 = 0o4000;
    const O_CLOEXEC: i32 = 0o2000000;
    const AT_EACCESS: i32 = 0x200;
    const AT_FDCWD: i32 = -100;

    const PROT_READ: i32 = 0x1;
    const PROT_WRITE: i32 = 0x2;
    const MAP_PRIVATE: i32 = 0x02;
    const MAP_ANONYMOUS: i32 = 0x20;

    const SEEK_SET: i32 = 0;
    const SEEK_END: i32 = 2;

    const EBADF: i32 = 9;

    fn temp_path_bytes(prefix: &str) -> (Vec<u8>, PathBuf) {
        let pid = sys_getpid();
        let path = PathBuf::from(format!("/tmp/{prefix}_{pid}"));
        let mut bytes = path.to_string_lossy().into_owned().into_bytes();
        bytes.push(0);
        (bytes, path)
    }

    #[test]
    fn getpid_positive_and_stable() {
        let a = sys_getpid();
        let b = sys_getpid();
        assert!(a > 0);
        assert_eq!(a, b);
    }

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

    #[test]
    fn file_lifecycle_via_tmp() {
        let (path_buf, path) = temp_path_bytes("frankenlibc_syscall_test_aarch64");

        let fd = unsafe {
            sys_openat(
                AT_FDCWD,
                path_buf.as_ptr(),
                O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC,
                0o600,
            )
        }
        .expect("openat should create temp file");

        let data = b"veneer integration test payload";
        let written =
            unsafe { sys_write(fd, data.as_ptr(), data.len()) }.expect("write to temp file");
        assert_eq!(written, data.len());

        let pos = sys_lseek(fd, 0, SEEK_SET).expect("lseek to start");
        assert_eq!(pos, 0);

        let mut buf = [0u8; 64];
        let n = unsafe { sys_read(fd, buf.as_mut_ptr(), buf.len()) }.expect("read from temp file");
        assert_eq!(n, data.len());
        assert_eq!(&buf[..n], data);

        let size = sys_lseek(fd, 0, SEEK_END).expect("lseek to end");
        assert_eq!(size, data.len() as i64);

        sys_close(fd).expect("close temp file");
        std::fs::remove_file(&path).expect("cleanup temp file");
    }

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

        for i in 0..page_size {
            unsafe { *ptr.add(i) = (i & 0xFF) as u8 };
        }

        for i in 0..page_size {
            let val = unsafe { *ptr.add(i) };
            assert_eq!(val, (i & 0xFF) as u8, "mismatch at offset {i}");
        }

        unsafe { sys_mprotect(ptr, page_size, PROT_READ) }.expect("mprotect to PROT_READ");
        let val = unsafe { *ptr };
        assert_eq!(val, 0);

        unsafe { sys_munmap(ptr, page_size) }.expect("munmap");
    }

    #[test]
    fn error_ebadf_on_bad_fd() {
        assert_eq!(sys_close(99999), Err(EBADF));
        assert_eq!(sys_close(-1), Err(EBADF));
        assert_eq!(sys_fsync(-1), Err(EBADF));
        assert_eq!(sys_lseek(-1, 0, SEEK_SET), Err(EBADF));
        assert_eq!(sys_dup(-1), Err(EBADF));
    }

    #[test]
    fn dup_produces_valid_fd() {
        let mut fds = [0i32; 2];
        unsafe { sys_pipe2(fds.as_mut_ptr(), O_CLOEXEC) }.expect("pipe2");

        let dup_fd = sys_dup(fds[1]).expect("dup write end");
        assert!(dup_fd >= 0);
        assert_ne!(dup_fd, fds[1], "dup should return a different fd");

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

    #[test]
    fn raw_syscall_primitives_accessible() {
        let pid = unsafe { syscall0(SYS_GETPID) };
        assert_eq!(pid as i32, sys_getpid());
    }

    #[test]
    fn futex_wake_no_waiters() {
        let futex_word: u32 = 0;
        const FUTEX_WAKE: i32 = 1;
        let result = unsafe { sys_futex(&futex_word as *const u32, FUTEX_WAKE, 1, 0, 0, 0) };
        assert_eq!(result, Ok(0), "futex wake with no waiters should return 0");
    }

    #[test]
    fn syscall_number_constants() {
        assert_eq!(SYS_READ, 63);
        assert_eq!(SYS_WRITE, 64);
        assert_eq!(SYS_OPENAT, 56);
        assert_eq!(SYS_CLOSE, 57);
        assert_eq!(SYS_PREAD64, 67);
        assert_eq!(SYS_PWRITE64, 68);
        assert_eq!(SYS_MMAP, 222);
        assert_eq!(SYS_MPROTECT, 226);
        assert_eq!(SYS_MUNMAP, 215);
        assert_eq!(SYS_MSYNC, 227);
        assert_eq!(SYS_MADVISE, 233);
        assert_eq!(SYS_DUP, 23);
        assert_eq!(SYS_DUP2, 24);
        assert_eq!(SYS_GETDENTS64, 61);
        assert_eq!(SYS_FCNTL, 25);
        assert_eq!(SYS_FDATASYNC, 83);
        assert_eq!(SYS_FALLOCATE, 47);
        assert_eq!(SYS_FACCESSAT, 48);
        assert_eq!(SYS_FACCESSAT2, 439);
        assert_eq!(SYS_GETPID, 172);
        assert_eq!(SYS_GETTID, 178);
        assert_eq!(SYS_CLONE, 220);
        assert_eq!(SYS_CLONE3, 435);
        assert_eq!(SYS_EXIT_GROUP, 94);
        assert_eq!(SYS_SOCKET, 198);
        assert_eq!(SYS_CONNECT, 203);
        assert_eq!(SYS_ACCEPT, 202);
        assert_eq!(SYS_SENDTO, 206);
        assert_eq!(SYS_RECVFROM, 207);
        assert_eq!(SYS_FUTEX, 98);
        assert_eq!(SYS_FUTEX_WAITV, 449);
        assert_eq!(FUTEX_WAIT_BITSET, 9);
        assert_eq!(FUTEX_BITSET_MATCH_ANY, u32::MAX);
        assert_eq!(SYS_MEMFD_SECRET, 447);
        assert_eq!(SYS_SET_MEMPOLICY, 237);
        assert_eq!(SYS_GET_MEMPOLICY, 236);
        assert_eq!(SYS_SCHED_GETAFFINITY, 123);
        assert_eq!(SYS_BIND, 200);
        assert_eq!(SYS_LISTEN, 201);
        assert_eq!(SYS_GETSOCKNAME, 204);
        assert_eq!(SYS_GETPEERNAME, 205);
        assert_eq!(SYS_SOCKETPAIR, 199);
        assert_eq!(SYS_ACCEPT4, 242);
        assert_eq!(SYS_SIGNALFD4, 74);
        assert_eq!(SYS_INOTIFY_INIT1, 26);
        assert_eq!(SYS_IO_URING_SETUP, 425);
        assert_eq!(SYS_IO_URING_ENTER, 426);
        assert_eq!(SYS_IO_URING_REGISTER, 427);
        assert_eq!(SYS_USERFAULTFD, 282);
        assert_eq!(SYS_CLOCK_NANOSLEEP, 115);
        assert_eq!(SYS_READLINKAT, 78);
        assert_eq!(SYS_RENAMEAT2, 276);
        assert_eq!(SYS_WAITID, 95);
        assert_eq!(SYS_TIMERFD_SETTIME, 86);
        assert_eq!(SYS_CAPSET, 91);
        assert_eq!(SYS_SCHED_SETATTR, 274);
        assert_eq!(SYS_SYSINFO, 179);
        assert_eq!(SYS_PIPE2, 59);
        assert_eq!(SYS_SET_TID_ADDRESS, 96);
        assert_eq!(UFFDIO_API, 0xc018aa3f);
        assert_eq!(UFFD_API, 0xAA);
        assert_eq!(UFFD_FEATURE_SIGBUS, 1 << 7);
        assert_eq!(LINUX_CAPABILITY_VERSION_3, 0x2008_0522);
        assert_eq!(LINUX_CAPABILITY_U32S_3, 2);
        assert_eq!(SFD_NONBLOCK, O_NONBLOCK);
        assert_eq!(SFD_CLOEXEC, 0o2000000);
        assert_eq!(IN_NONBLOCK, O_NONBLOCK);
        assert_eq!(IN_CLOEXEC, O_CLOEXEC);
        assert_eq!(AF_UNIX, 1);
        assert_eq!(SOCK_NONBLOCK, O_NONBLOCK);
        assert_eq!(SOCK_CLOEXEC, O_CLOEXEC);
        assert_eq!(SOCK_SEQPACKET, 5);
        assert_eq!(CLOCK_BOOTTIME, 7);
        assert_eq!(frankenlibc_core::syscall::AT_FDCWD, AT_FDCWD);
        assert_eq!(frankenlibc_core::syscall::CLONE_PIDFD, 1 << 12);
        assert_eq!(frankenlibc_core::syscall::RENAME_EXCHANGE, 2);
        assert_eq!(frankenlibc_core::syscall::SEEK_DATA, 3);
        assert_eq!(frankenlibc_core::syscall::SEEK_HOLE, 4);
        assert_eq!(P_PID, 1);
        assert_eq!(frankenlibc_core::syscall::P_PIDFD, 3);
        assert_eq!(WSTOPPED, 2);
        assert_eq!(TIMER_ABSTIME, 1);
        assert_eq!(WEXITED, 4);
        assert_eq!(SIGEV_THREAD_ID, 4);
        assert_eq!(TFD_NONBLOCK, 0o4000);
        assert_eq!(TFD_CLOEXEC, 0o2000000);
        assert_eq!(TFD_TIMER_ABSTIME, 1);
        assert_eq!(TFD_TIMER_CANCEL_ON_SET, 2);
        assert_eq!(IORING_ENTER_GETEVENTS, 1 << 0);
        assert_eq!(IORING_ENTER_SQ_WAKEUP, 1 << 1);
        assert_eq!(IORING_SETUP_SQPOLL, 1 << 1);
        assert_eq!(core::mem::size_of::<CpuSet>(), 128);
        assert_eq!(core::mem::size_of::<IoUringSqringOffsets>(), 40);
        assert_eq!(core::mem::size_of::<IoUringCqringOffsets>(), 40);
        assert_eq!(core::mem::size_of::<IoUringParams>(), 120);
        assert_eq!(core::mem::size_of::<SigEventThreadId>(), 64);
        assert_eq!(core::mem::size_of::<SignalfdSiginfo>(), 128);
        assert_eq!(core::mem::size_of::<Timespec>(), 16);
        assert_eq!(core::mem::size_of::<ItimerSpec>(), 32);
        assert_eq!(core::mem::size_of::<CapUserHeader>(), 8);
        assert_eq!(core::mem::size_of::<CapUserData>(), 12);
        assert_eq!(core::mem::size_of::<UffdApi>(), 24);
        assert_eq!(core::mem::size_of::<StatFsId>(), 8);
        assert_eq!(core::mem::size_of::<StatFs>(), 120);
        assert_eq!(core::mem::size_of::<WaitSigInfo>(), 128);
    }

    #[test]
    #[allow(clippy::type_complexity)]
    fn api_surface_complete() {
        // Compile-time API parity check with x86_64 veneer.
        let _: unsafe fn(i32, *mut u8, usize) -> Result<usize, i32> = sys_read;
        let _: unsafe fn(i32, *const u8, usize) -> Result<usize, i32> = sys_write;
        let _: unsafe fn(i32, *const u8, i32, u32) -> Result<i32, i32> = sys_openat;
        let _: fn(i32, i32, i32) -> Result<i32, i32> = sys_socket;
        let _: unsafe fn(i32, *const u8, u32) -> Result<(), i32> = sys_bind;
        let _: fn(i32, i32) -> Result<(), i32> = sys_listen;
        let _: unsafe fn(i32, *mut u8, *mut u32) -> Result<i32, i32> = sys_accept;
        let _: unsafe fn(i32, *mut u8, *mut u32, i32) -> Result<i32, i32> = sys_accept4;
        let _: unsafe fn(i32, *const u8, u32) -> Result<(), i32> = sys_connect;
        let _: unsafe fn(i32, *mut u8, *mut u32) -> Result<(), i32> = sys_getsockname;
        let _: unsafe fn(i32, *mut u8, *mut u32) -> Result<(), i32> = sys_getpeername;
        let _: unsafe fn(i32, i32, i32, *mut i32) -> Result<(), i32> = sys_socketpair;
        let _: unsafe fn(i32, *const u8, usize, i32, *const u8, usize) -> Result<isize, i32> =
            sys_sendto;
        let _: unsafe fn(i32, *mut u8, usize, i32, *mut u8, *mut u32) -> Result<isize, i32> =
            sys_recvfrom;
        let _: unsafe fn(i32, i32, &Timespec, *mut Timespec) -> Result<(), i32> =
            sys_clock_nanosleep_spec;
        let _: unsafe fn(*const u8, *mut u8, usize) -> Result<isize, i32> = sys_readlink;
        let _: unsafe fn(i32, *const u8, *mut u8, usize) -> Result<isize, i32> = sys_readlinkat;
        let _: unsafe fn(i32, *const u8, i32, *const u8, u32) -> Result<(), i32> = sys_renameat2;
        let _: unsafe fn(i32, u32, *mut u8, i32, *mut u8) -> Result<(), i32> = sys_waitid;
        let _: unsafe fn(i32, u32, &mut WaitSigInfo, i32) -> Result<(), i32> = sys_waitid_info;
        let _: fn(i32) -> Result<(), i32> = sys_close;
        let _: unsafe fn(*mut u8, usize, i32, i32, i32, i64) -> Result<*mut u8, i32> = sys_mmap;
        let _: unsafe fn(*mut u8, usize) -> Result<(), i32> = sys_munmap;
        let _: unsafe fn(*mut u8, usize, i32) -> Result<(), i32> = sys_mprotect;
        let _: unsafe fn(i32, *const u8, i32) -> Result<(), i32> = sys_faccessat;
        let _: unsafe fn(i32, *const u8, i32, i32) -> Result<(), i32> = sys_faccessat2;
        let _: fn(i32) -> Result<i32, i32> = sys_inotify_init1;
        let _: unsafe fn(i32, &mut CpuSet) -> Result<usize, i32> = sys_sched_getaffinity_cpuset;
        let _: unsafe fn(i32, &SigEventThreadId, *mut i32) -> Result<(), i32> =
            sys_timer_create_sigevent;
        let _: unsafe fn(*mut Sysinfo) -> Result<(), i32> = sys_sysinfo;
        let _: unsafe fn(*const u8, *mut StatFs) -> Result<(), i32> = sys_statfs;
        let _: unsafe fn(i32, *mut StatFs) -> Result<(), i32> = sys_fstatfs;
        let _: unsafe fn(*const u32, i32, u32, usize, usize, u32) -> Result<isize, i32> = sys_futex;
        let _: unsafe fn(*const u32, u32, *const Timespec, u32) -> Result<(), i32> =
            sys_futex_wait_bitset;
        let _: unsafe fn(*const FutexWaitV, u32, u32, *const u8, i32) -> Result<i32, i32> =
            sys_futex_waitv;
        let _: unsafe fn(u32, *mut u8) -> Result<i32, i32> = sys_io_uring_setup;
        let _: unsafe fn(u32, *mut IoUringParams) -> Result<i32, i32> = sys_io_uring_setup_params;
        let _: unsafe fn(i32, u32, u32, u32, *const u8, usize) -> Result<i32, i32> =
            sys_io_uring_enter;
        let _: fn(i32) -> Result<i32, i32> = sys_io_uring_enter_sqpoll_wakeup;
        let _: unsafe fn(i32, u32, *const u8, u32) -> Result<i32, i32> = sys_io_uring_register;
        let _: fn(u32) -> Result<i32, i32> = sys_memfd_secret;
        let _: unsafe fn(i32, *const usize, usize) -> Result<(), i32> = sys_set_mempolicy;
        let _: unsafe fn(*mut i32, *mut usize, usize, *const u8, u32) -> Result<(), i32> =
            sys_get_mempolicy;
        let _: unsafe fn(i32, *const u8, usize, i32) -> Result<i32, i32> = sys_signalfd4;
        let _: fn(i32, i32) -> Result<i32, i32> = sys_timerfd_create;
        let _: unsafe fn(i32, i32, *const u8, *mut u8) -> Result<(), i32> = sys_timerfd_settime;
        let _: unsafe fn(i32, i32, *const ItimerSpec, *mut ItimerSpec) -> Result<(), i32> =
            sys_timerfd_settime_spec;
        let _: unsafe fn(i32, *mut u8) -> Result<(), i32> = sys_timerfd_gettime;
        let _: unsafe fn(i32, *mut ItimerSpec) -> Result<(), i32> = sys_timerfd_gettime_spec;
        let _: fn(i32) -> Result<u64, i32> = sys_timerfd_read_expirations;
        let _: unsafe fn(*mut u8, *mut u8) -> Result<(), i32> = sys_capget;
        let _: unsafe fn(*mut CapUserHeader, *mut CapUserData) -> Result<(), i32> = sys_capget_data;
        let _: unsafe fn(*const u8, *const u8) -> Result<(), i32> = sys_capset;
        let _: unsafe fn(*const CapUserHeader, *const CapUserData) -> Result<(), i32> =
            sys_capset_data;
        let _: fn(i32) -> Result<i32, i32> = sys_userfaultfd;
        let _: unsafe fn(i32, *mut UffdApi) -> Result<(), i32> = sys_userfaultfd_api;
        let _: unsafe fn(i32, *const SchedAttr, u32) -> Result<(), i32> = sys_sched_setattr;
        let _: fn(i32) -> ! = sys_exit_group;
        let _: fn() -> i32 = sys_getpid;
        let _: unsafe fn(*mut i32, i32) -> Result<(), i32> = sys_pipe2;
        let _: fn(i32) -> Result<i32, i32> = sys_dup;
        let _: unsafe fn(i32, usize, usize) -> Result<i32, i32> = sys_ioctl;
        let _: fn(i32, i64, i32) -> Result<i64, i32> = sys_lseek;
        let _: fn(i32) -> Result<(), i32> = sys_fsync;
        let _: unsafe fn(i32, *mut u8, usize) -> Result<usize, i32> = sys_getdents64;
        let _: unsafe fn(i32, i32, usize) -> Result<i32, i32> = sys_fcntl;
        let _: fn(i32) -> Result<(), i32> = sys_fdatasync;
        let _: fn(i32, i32, i64, i64) -> Result<(), i32> = sys_fallocate;
        let _: fn(i32, i32) -> Result<i32, i32> = sys_dup2;
        let _: unsafe fn(*mut u8, usize, i32) -> Result<(), i32> = sys_msync;
        let _: unsafe fn(*mut u8, usize, i32) -> Result<(), i32> = sys_madvise;
        let _: fn() -> i32 = sys_gettid;
        let _: fn(usize) -> i32 = sys_set_tid_address;
        let _: fn(i32) -> ! = sys_exit_thread;
        let _: unsafe fn(usize, usize, *mut i32, *mut i32, usize) -> Result<i32, i32> =
            sys_clone_thread;
        let _: unsafe fn(*const CloneArgs, usize) -> Result<i32, i32> = sys_clone3;
        let _: unsafe fn(i32, *mut u8, usize, i64) -> Result<usize, i32> = sys_pread64;
        let _: unsafe fn(i32, *const u8, usize, i64) -> Result<usize, i32> = sys_pwrite64;
    }

    #[test]
    fn faccessat2_at_eaccess_checks_current_directory() {
        let path = b".\0";
        unsafe { sys_faccessat2(AT_FDCWD, path.as_ptr(), 0, AT_EACCESS) }
            .expect("faccessat2(AT_EACCESS) should accept the current directory");
    }
}
