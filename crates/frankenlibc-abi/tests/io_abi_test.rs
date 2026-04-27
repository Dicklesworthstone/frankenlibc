#![cfg(target_os = "linux")]

//! Integration tests for POSIX I/O ABI entrypoints.

use std::ffi::{c_int, c_uint, c_void};
use std::sync::atomic::{AtomicU64, Ordering};

use frankenlibc_abi::errno_abi::__errno_location;
use frankenlibc_abi::io_abi::{
    __dup3, __pipe2, __pread, __pwrite, __readv, __writev, copy_file_range, dup, dup2, dup3, fcntl,
    memfd_create, pipe, pipe2, pread, preadv, pwrite, pwritev, readv, sendfile, splice, writev,
};
use frankenlibc_abi::unistd_abi::close;

// ---------------------------------------------------------------------------
// Helper: create a disposable fd
// ---------------------------------------------------------------------------

fn temp_fd() -> c_int {
    // Create a pipe and return the read end (close write end)
    let mut fds = [0 as c_int; 2];
    let rc = unsafe { pipe(&mut fds as *mut c_int) };
    assert_eq!(rc, 0, "pipe() should succeed");
    unsafe { close(fds[1]) };
    fds[0]
}

/// Create a pipe pair and return (read_fd, write_fd).
fn temp_pipe() -> (c_int, c_int) {
    let mut fds = [0 as c_int; 2];
    let rc = unsafe { pipe(&mut fds as *mut c_int) };
    assert_eq!(rc, 0, "pipe() should succeed");
    (fds[0], fds[1])
}

/// Create a memfd with some content, seek back to start, return fd.
fn temp_memfd(content: &[u8]) -> c_int {
    let name = b"test\0";
    let fd = unsafe { memfd_create(name.as_ptr().cast(), 0 as c_uint) };
    assert!(fd >= 0, "memfd_create should succeed");
    let written = unsafe { libc::write(fd, content.as_ptr().cast(), content.len()) };
    assert_eq!(written, content.len() as isize);
    unsafe { libc::lseek(fd, 0, libc::SEEK_SET) };
    fd
}

fn tracked_zeroed_bytes(len: usize) -> *mut c_void {
    assert!(len > 0);
    let raw = unsafe { frankenlibc_abi::malloc_abi::malloc(len) };
    assert!(!raw.is_null());
    unsafe {
        std::ptr::write_bytes(raw.cast::<u8>(), 0, len);
    }
    raw
}

unsafe fn free_tracked(ptr: *mut c_void) {
    unsafe { frankenlibc_abi::malloc_abi::free(ptr) };
}

fn tracked_iovec(entry: libc::iovec) -> *mut libc::iovec {
    let raw = tracked_zeroed_bytes(std::mem::size_of::<libc::iovec>()).cast::<libc::iovec>();
    unsafe { raw.write(entry) };
    raw
}

// ---------------------------------------------------------------------------
// dup
// ---------------------------------------------------------------------------

#[test]
fn dup_returns_new_fd() {
    let fd = temp_fd();
    let new_fd = unsafe { dup(fd) };
    assert!(new_fd >= 0, "dup should return a valid fd, got {new_fd}");
    assert_ne!(fd, new_fd, "dup should return a different fd");
    unsafe { close(new_fd) };
    unsafe { close(fd) };
}

#[test]
fn dup_negative_fd_fails() {
    let new_fd = unsafe { dup(-1) };
    assert_eq!(new_fd, -1, "dup(-1) should fail");
}

// ---------------------------------------------------------------------------
// dup2
// ---------------------------------------------------------------------------

#[test]
fn dup2_to_specific_fd() {
    let fd = temp_fd();
    // Use a high fd number unlikely to be in use
    let target = 200;
    let rc = unsafe { dup2(fd, target) };
    assert_eq!(rc, target, "dup2 should return the target fd");
    unsafe { close(target) };
    unsafe { close(fd) };
}

#[test]
fn dup2_same_fd_is_noop() {
    let fd = temp_fd();
    let rc = unsafe { dup2(fd, fd) };
    assert_eq!(rc, fd, "dup2(fd, fd) should return fd unchanged");
    unsafe { close(fd) };
}

// ---------------------------------------------------------------------------
// dup3
// ---------------------------------------------------------------------------

#[test]
fn dup3_with_cloexec() {
    let fd = temp_fd();
    let target = 201;
    let rc = unsafe { dup3(fd, target, libc::O_CLOEXEC) };
    assert_eq!(rc, target, "dup3 should return the target fd");
    unsafe { close(target) };
    unsafe { close(fd) };
}

// ---------------------------------------------------------------------------
// pipe / pipe2
// ---------------------------------------------------------------------------

#[test]
fn pipe_creates_pair() {
    let mut fds = [0 as c_int; 2];
    let rc = unsafe { pipe(&mut fds as *mut c_int) };
    assert_eq!(rc, 0, "pipe() should succeed");
    assert!(fds[0] >= 0);
    assert!(fds[1] >= 0);
    assert_ne!(fds[0], fds[1]);

    // Write to write end, read from read end
    let msg = b"hello";
    let written = unsafe { libc::write(fds[1], msg.as_ptr() as *const _, msg.len()) };
    assert_eq!(written, msg.len() as isize);

    let mut buf = [0u8; 16];
    let read_n = unsafe { libc::read(fds[0], buf.as_mut_ptr() as *mut _, buf.len()) };
    assert_eq!(read_n, msg.len() as isize);
    assert_eq!(&buf[..msg.len()], msg);

    unsafe { close(fds[0]) };
    unsafe { close(fds[1]) };
}

#[test]
fn pipe2_cloexec() {
    let mut fds = [0 as c_int; 2];
    let rc = unsafe { pipe2(&mut fds as *mut c_int, libc::O_CLOEXEC) };
    assert_eq!(rc, 0, "pipe2 with O_CLOEXEC should succeed");
    assert!(fds[0] >= 0);
    assert!(fds[1] >= 0);
    unsafe { close(fds[0]) };
    unsafe { close(fds[1]) };
}

#[test]
fn pipe_null_fails() {
    let rc = unsafe { pipe(std::ptr::null_mut()) };
    assert_eq!(rc, -1, "pipe(NULL) should fail");
}

#[test]
fn pipe_rejects_tracked_short_fd_array() {
    let raw = tracked_zeroed_bytes(1);
    unsafe { *__errno_location() = 0 };

    let rc = unsafe { pipe(raw.cast::<c_int>()) };
    assert_eq!(rc, -1);
    assert_eq!(unsafe { *__errno_location() }, libc::EFAULT);

    unsafe { free_tracked(raw) };
}

#[test]
fn pipe2_rejects_tracked_short_fd_array() {
    let raw = tracked_zeroed_bytes(1);
    unsafe { *__errno_location() = 0 };

    let rc = unsafe { pipe2(raw.cast::<c_int>(), 0) };
    assert_eq!(rc, -1);
    assert_eq!(unsafe { *__errno_location() }, libc::EFAULT);

    unsafe { free_tracked(raw) };
}

// ---------------------------------------------------------------------------
// close
// ---------------------------------------------------------------------------

#[test]
fn close_valid_fd() {
    let fd = temp_fd();
    let rc = unsafe { close(fd) };
    assert_eq!(rc, 0, "close should succeed");
}

#[test]
fn close_invalid_fd() {
    let rc = unsafe { close(-1) };
    assert_eq!(rc, -1, "close(-1) should fail");
}

// ---------------------------------------------------------------------------
// fcntl
// ---------------------------------------------------------------------------

#[test]
fn fcntl_getfd() {
    let fd = temp_fd();
    let flags = unsafe { fcntl(fd, libc::F_GETFD, 0) };
    assert!(flags >= 0, "fcntl F_GETFD should succeed");
    unsafe { close(fd) };
}

#[test]
fn fcntl_setfd_cloexec() {
    let fd = temp_fd();
    let rc = unsafe { fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC as libc::c_long) };
    assert_eq!(rc, 0, "fcntl F_SETFD should succeed");

    let flags = unsafe { fcntl(fd, libc::F_GETFD, 0) };
    assert_ne!(flags & libc::FD_CLOEXEC, 0, "FD_CLOEXEC should be set");
    unsafe { close(fd) };
}

#[test]
fn fcntl_getfl() {
    let fd = temp_fd();
    let flags = unsafe { fcntl(fd, libc::F_GETFL, 0) };
    assert!(flags >= 0, "fcntl F_GETFL should succeed");
    unsafe { close(fd) };
}

#[test]
fn fcntl_setfl_nonblock() {
    let (rfd, wfd) = temp_pipe();
    let rc = unsafe { fcntl(wfd, libc::F_SETFL, libc::O_NONBLOCK as libc::c_long) };
    assert_eq!(rc, 0, "fcntl F_SETFL O_NONBLOCK should succeed");
    let flags = unsafe { fcntl(wfd, libc::F_GETFL, 0) };
    assert_ne!(flags & libc::O_NONBLOCK, 0, "O_NONBLOCK should be set");
    unsafe { close(rfd) };
    unsafe { close(wfd) };
}

#[test]
fn fcntl_dupfd() {
    let fd = temp_fd();
    let new_fd = unsafe { fcntl(fd, libc::F_DUPFD, 100) };
    assert!(
        new_fd >= 100,
        "F_DUPFD should return fd >= 100, got {new_fd}"
    );
    unsafe { close(new_fd) };
    unsafe { close(fd) };
}

// ---------------------------------------------------------------------------
// pread / pwrite
// ---------------------------------------------------------------------------

#[test]
fn pwrite_and_pread_roundtrip() {
    let fd = temp_memfd(b"");
    let data = b"hello pread/pwrite";
    let written = unsafe { pwrite(fd, data.as_ptr().cast(), data.len(), 0) };
    assert_eq!(written, data.len() as isize);

    let mut buf = [0u8; 32];
    let read_n = unsafe { pread(fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
    assert_eq!(read_n, data.len() as isize);
    assert_eq!(&buf[..data.len()], data);
    unsafe { close(fd) };
}

#[test]
fn pread_at_offset() {
    let content = b"abcdefghij";
    let fd = temp_memfd(content);

    let mut buf = [0u8; 5];
    let n = unsafe { pread(fd, buf.as_mut_ptr().cast(), 5, 3) };
    assert_eq!(n, 5);
    assert_eq!(&buf, b"defgh");
    unsafe { close(fd) };
}

#[test]
fn pwrite_at_offset() {
    let fd = temp_memfd(b"0123456789");
    let data = b"XYZ";
    let n = unsafe { pwrite(fd, data.as_ptr().cast(), data.len(), 4) };
    assert_eq!(n, 3);

    let mut buf = [0u8; 10];
    let n = unsafe { pread(fd, buf.as_mut_ptr().cast(), 10, 0) };
    assert_eq!(n, 10);
    assert_eq!(&buf, b"0123XYZ789");
    unsafe { close(fd) };
}

#[test]
fn pread_bad_fd() {
    let mut buf = [0u8; 16];
    let n = unsafe { pread(-1, buf.as_mut_ptr().cast(), buf.len(), 0) };
    assert_eq!(n, -1, "pread on bad fd should return -1");
}

#[test]
fn pread_rejects_tracked_short_buffer() {
    let fd = temp_memfd(b"xy");
    let raw = tracked_zeroed_bytes(1);
    unsafe { *__errno_location() = 0 };

    let n = unsafe { pread(fd, raw, 2, 0) };
    assert_eq!(n, -1);
    assert_eq!(unsafe { *__errno_location() }, libc::EFAULT);

    unsafe {
        close(fd);
        free_tracked(raw);
    }
}

#[test]
fn pwrite_rejects_tracked_short_buffer() {
    let fd = temp_memfd(b"");
    let raw = tracked_zeroed_bytes(1);
    unsafe { *__errno_location() = 0 };

    let n = unsafe { pwrite(fd, raw.cast_const(), 2, 0) };
    assert_eq!(n, -1);
    assert_eq!(unsafe { *__errno_location() }, libc::EFAULT);

    unsafe {
        close(fd);
        free_tracked(raw);
    }
}

// ---------------------------------------------------------------------------
// readv / writev
// ---------------------------------------------------------------------------

#[test]
fn writev_and_readv_scatter_gather() {
    let (rfd, wfd) = temp_pipe();

    let buf1 = b"hello ";
    let buf2 = b"world";
    let iovs_w = [
        libc::iovec {
            iov_base: buf1.as_ptr() as *mut _,
            iov_len: buf1.len(),
        },
        libc::iovec {
            iov_base: buf2.as_ptr() as *mut _,
            iov_len: buf2.len(),
        },
    ];
    let written = unsafe { writev(wfd, iovs_w.as_ptr(), 2) };
    assert_eq!(written, 11);

    let mut rbuf1 = [0u8; 6];
    let mut rbuf2 = [0u8; 5];
    let iovs_r = [
        libc::iovec {
            iov_base: rbuf1.as_mut_ptr().cast(),
            iov_len: rbuf1.len(),
        },
        libc::iovec {
            iov_base: rbuf2.as_mut_ptr().cast(),
            iov_len: rbuf2.len(),
        },
    ];
    let read_n = unsafe { readv(rfd, iovs_r.as_ptr(), 2) };
    assert_eq!(read_n, 11);
    assert_eq!(&rbuf1, b"hello ");
    assert_eq!(&rbuf2, b"world");

    unsafe { close(rfd) };
    unsafe { close(wfd) };
}

#[test]
fn writev_single_buffer() {
    let (rfd, wfd) = temp_pipe();
    let data = b"single";
    let iov = libc::iovec {
        iov_base: data.as_ptr() as *mut _,
        iov_len: data.len(),
    };
    let n = unsafe { writev(wfd, &iov, 1) };
    assert_eq!(n, 6);

    let mut buf = [0u8; 6];
    unsafe { libc::read(rfd, buf.as_mut_ptr().cast(), 6) };
    assert_eq!(&buf, b"single");

    unsafe { close(rfd) };
    unsafe { close(wfd) };
}

#[test]
fn readv_rejects_tracked_short_iovec_array() {
    let (rfd, wfd) = temp_pipe();
    unsafe { libc::write(wfd, b"x".as_ptr().cast(), 1) };

    let raw_iov = tracked_zeroed_bytes(1);
    unsafe { *__errno_location() = 0 };
    let n = unsafe { readv(rfd, raw_iov.cast::<libc::iovec>(), 1) };
    assert_eq!(n, -1);
    assert_eq!(unsafe { *__errno_location() }, libc::EFAULT);

    unsafe {
        close(rfd);
        close(wfd);
        free_tracked(raw_iov);
    }
}

#[test]
fn writev_rejects_tracked_short_iovec_array() {
    let fd = temp_memfd(b"");
    let raw_iov = tracked_zeroed_bytes(1);
    unsafe { *__errno_location() = 0 };

    let n = unsafe { writev(fd, raw_iov.cast::<libc::iovec>(), 1) };
    assert_eq!(n, -1);
    assert_eq!(unsafe { *__errno_location() }, libc::EFAULT);

    unsafe {
        close(fd);
        free_tracked(raw_iov);
    }
}

#[test]
fn readv_rejects_tracked_short_iov_base() {
    let (rfd, wfd) = temp_pipe();
    unsafe { libc::write(wfd, b"xy".as_ptr().cast(), 2) };

    let raw_buf = tracked_zeroed_bytes(1);
    let raw_iov = tracked_iovec(libc::iovec {
        iov_base: raw_buf,
        iov_len: 2,
    });
    unsafe { *__errno_location() = 0 };

    let n = unsafe { readv(rfd, raw_iov.cast_const(), 1) };
    assert_eq!(n, -1);
    assert_eq!(unsafe { *__errno_location() }, libc::EFAULT);

    unsafe {
        close(rfd);
        close(wfd);
        free_tracked(raw_iov.cast());
        free_tracked(raw_buf);
    }
}

#[test]
fn writev_rejects_tracked_short_iov_base() {
    let fd = temp_memfd(b"");
    let raw_buf = tracked_zeroed_bytes(1);
    let raw_iov = tracked_iovec(libc::iovec {
        iov_base: raw_buf,
        iov_len: 2,
    });
    unsafe { *__errno_location() = 0 };

    let n = unsafe { writev(fd, raw_iov.cast_const(), 1) };
    assert_eq!(n, -1);
    assert_eq!(unsafe { *__errno_location() }, libc::EFAULT);

    unsafe {
        close(fd);
        free_tracked(raw_iov.cast());
        free_tracked(raw_buf);
    }
}

#[test]
fn preadv_rejects_tracked_short_iov_base() {
    let fd = temp_memfd(b"xy");
    let raw_buf = tracked_zeroed_bytes(1);
    let raw_iov = tracked_iovec(libc::iovec {
        iov_base: raw_buf,
        iov_len: 2,
    });
    unsafe { *__errno_location() = 0 };

    let n = unsafe { preadv(fd, raw_iov.cast_const(), 1, 0) };
    assert_eq!(n, -1);
    assert_eq!(unsafe { *__errno_location() }, libc::EFAULT);

    unsafe {
        close(fd);
        free_tracked(raw_iov.cast());
        free_tracked(raw_buf);
    }
}

#[test]
fn pwritev_rejects_tracked_short_iov_base() {
    let fd = temp_memfd(b"");
    let raw_buf = tracked_zeroed_bytes(1);
    let raw_iov = tracked_iovec(libc::iovec {
        iov_base: raw_buf,
        iov_len: 2,
    });
    unsafe { *__errno_location() = 0 };

    let n = unsafe { pwritev(fd, raw_iov.cast_const(), 1, 0) };
    assert_eq!(n, -1);
    assert_eq!(unsafe { *__errno_location() }, libc::EFAULT);

    unsafe {
        close(fd);
        free_tracked(raw_iov.cast());
        free_tracked(raw_buf);
    }
}

// ---------------------------------------------------------------------------
// memfd_create
// ---------------------------------------------------------------------------

#[test]
fn memfd_create_basic() {
    let name = b"test_memfd\0";
    let fd = unsafe { memfd_create(name.as_ptr().cast(), 0 as c_uint) };
    assert!(fd >= 0, "memfd_create should succeed");

    // Write and read back
    let data = b"memfd content";
    let n = unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) };
    assert_eq!(n, data.len() as isize);

    unsafe { libc::lseek(fd, 0, libc::SEEK_SET) };
    let mut buf = [0u8; 32];
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    assert_eq!(n, data.len() as isize);
    assert_eq!(&buf[..data.len()], data);

    unsafe { close(fd) };
}

#[test]
fn memfd_create_cloexec() {
    let name = b"cloexec_test\0";
    let fd = unsafe { memfd_create(name.as_ptr().cast(), libc::MFD_CLOEXEC as c_uint) };
    assert!(fd >= 0, "memfd_create with MFD_CLOEXEC should succeed");

    let flags = unsafe { fcntl(fd, libc::F_GETFD, 0) };
    assert_ne!(
        flags & libc::FD_CLOEXEC,
        0,
        "MFD_CLOEXEC should set FD_CLOEXEC"
    );
    unsafe { close(fd) };
}

#[test]
fn memfd_create_null_name_fails() {
    let fd = unsafe { memfd_create(std::ptr::null(), 0 as c_uint) };
    assert_eq!(fd, -1, "memfd_create with null name should fail");
}

// ---------------------------------------------------------------------------
// sendfile
// ---------------------------------------------------------------------------

#[test]
fn sendfile_between_fds() {
    let content = b"sendfile test data here!";
    let in_fd = temp_memfd(content);
    let out_fd = temp_memfd(b"");

    let mut offset: i64 = 0;
    let n = unsafe { sendfile(out_fd, in_fd, &mut offset, content.len()) };
    assert_eq!(n, content.len() as isize);
    assert_eq!(offset, content.len() as i64);

    // Verify the data was copied
    unsafe { libc::lseek(out_fd, 0, libc::SEEK_SET) };
    let mut buf = [0u8; 32];
    let read_n = unsafe { libc::read(out_fd, buf.as_mut_ptr().cast(), buf.len()) };
    assert_eq!(read_n, content.len() as isize);
    assert_eq!(&buf[..content.len()], content);

    unsafe { close(in_fd) };
    unsafe { close(out_fd) };
}

#[test]
fn sendfile_partial() {
    let content = b"0123456789abcdef";
    let in_fd = temp_memfd(content);
    let out_fd = temp_memfd(b"");

    let mut offset: i64 = 4;
    let n = unsafe { sendfile(out_fd, in_fd, &mut offset, 8) };
    assert_eq!(n, 8);

    unsafe { libc::lseek(out_fd, 0, libc::SEEK_SET) };
    let mut buf = [0u8; 8];
    unsafe { libc::read(out_fd, buf.as_mut_ptr().cast(), 8) };
    assert_eq!(&buf, b"456789ab");

    unsafe { close(in_fd) };
    unsafe { close(out_fd) };
}

#[test]
fn sendfile_rejects_tracked_short_offset() {
    let in_fd = temp_memfd(b"xy");
    let out_fd = temp_memfd(b"");
    let raw_offset = tracked_zeroed_bytes(1);
    unsafe { *__errno_location() = 0 };

    let n = unsafe { sendfile(out_fd, in_fd, raw_offset.cast::<i64>(), 1) };
    assert_eq!(n, -1);
    assert_eq!(unsafe { *__errno_location() }, libc::EFAULT);

    unsafe {
        close(in_fd);
        close(out_fd);
        free_tracked(raw_offset);
    }
}

// ---------------------------------------------------------------------------
// copy_file_range
// ---------------------------------------------------------------------------

#[test]
fn copy_file_range_basic() {
    let content = b"copy_file_range works!";
    let in_fd = temp_memfd(content);
    let out_fd = temp_memfd(b"");

    let mut off_in: i64 = 0;
    let mut off_out: i64 = 0;
    let n = unsafe { copy_file_range(in_fd, &mut off_in, out_fd, &mut off_out, content.len(), 0) };
    assert_eq!(n, content.len() as isize);

    unsafe { libc::lseek(out_fd, 0, libc::SEEK_SET) };
    let mut buf = [0u8; 32];
    let read_n = unsafe { libc::read(out_fd, buf.as_mut_ptr().cast(), buf.len()) };
    assert_eq!(read_n, content.len() as isize);
    assert_eq!(&buf[..content.len()], content);

    unsafe { close(in_fd) };
    unsafe { close(out_fd) };
}

#[test]
fn copy_file_range_rejects_tracked_short_offsets() {
    let in_fd = temp_memfd(b"xy");
    let out_fd = temp_memfd(b"");
    let raw_off_in = tracked_zeroed_bytes(1);
    let mut off_out: i64 = 0;
    unsafe { *__errno_location() = 0 };

    let n = unsafe { copy_file_range(in_fd, raw_off_in.cast::<i64>(), out_fd, &mut off_out, 1, 0) };
    assert_eq!(n, -1);
    assert_eq!(unsafe { *__errno_location() }, libc::EFAULT);

    unsafe {
        close(in_fd);
        close(out_fd);
        free_tracked(raw_off_in);
    }
}

// ---------------------------------------------------------------------------
// splice
// ---------------------------------------------------------------------------

#[test]
fn splice_pipe_to_pipe() {
    let (rfd1, wfd1) = temp_pipe();
    let (rfd2, wfd2) = temp_pipe();

    // Write to first pipe
    let data = b"splice me";
    unsafe { libc::write(wfd1, data.as_ptr().cast(), data.len()) };

    // Splice from pipe1 read end to pipe2 write end
    let n = unsafe {
        splice(
            rfd1,
            std::ptr::null_mut(),
            wfd2,
            std::ptr::null_mut(),
            data.len(),
            0,
        )
    };
    assert_eq!(n, data.len() as isize, "splice should transfer all data");

    // Read from second pipe
    let mut buf = [0u8; 16];
    let read_n = unsafe { libc::read(rfd2, buf.as_mut_ptr().cast(), buf.len()) };
    assert_eq!(read_n, data.len() as isize);
    assert_eq!(&buf[..data.len()], data);

    unsafe { close(rfd1) };
    unsafe { close(wfd1) };
    unsafe { close(rfd2) };
    unsafe { close(wfd2) };
}

#[test]
fn splice_rejects_tracked_short_offsets() {
    let (rfd1, wfd1) = temp_pipe();
    let (rfd2, wfd2) = temp_pipe();
    unsafe { libc::write(wfd1, b"x".as_ptr().cast(), 1) };

    let raw_off_in = tracked_zeroed_bytes(1);
    unsafe { *__errno_location() = 0 };
    let n = unsafe {
        splice(
            rfd1,
            raw_off_in.cast::<i64>(),
            wfd2,
            std::ptr::null_mut(),
            1,
            0,
        )
    };
    assert_eq!(n, -1);
    assert_eq!(unsafe { *__errno_location() }, libc::EFAULT);

    unsafe {
        close(rfd1);
        close(wfd1);
        close(rfd2);
        close(wfd2);
        free_tracked(raw_off_in);
    }
}

// ---------------------------------------------------------------------------
// ioctl — FIONREAD on a pipe
// ---------------------------------------------------------------------------

#[test]
fn ioctl_fionread() {
    use frankenlibc_abi::io_abi::ioctl;
    let (rfd, wfd) = temp_pipe();

    let data = b"ioctl test";
    unsafe { libc::write(wfd, data.as_ptr().cast(), data.len()) };

    let mut bytes_available: c_int = 0;
    let rc = unsafe {
        ioctl(
            rfd,
            libc::FIONREAD as libc::c_ulong,
            &mut bytes_available as *mut c_int as libc::c_ulong,
        )
    };
    assert_eq!(rc, 0, "ioctl FIONREAD should succeed");
    assert_eq!(
        bytes_available,
        data.len() as c_int,
        "FIONREAD should report correct byte count"
    );

    unsafe { close(rfd) };
    unsafe { close(wfd) };
}

// ---------------------------------------------------------------------------
// pipe2 with O_NONBLOCK
// ---------------------------------------------------------------------------

#[test]
fn pipe2_nonblock() {
    let mut fds = [0 as c_int; 2];
    let rc = unsafe { pipe2(&mut fds as *mut c_int, libc::O_NONBLOCK) };
    assert_eq!(rc, 0);

    let flags = unsafe { fcntl(fds[0], libc::F_GETFL, 0) };
    assert_ne!(
        flags & libc::O_NONBLOCK,
        0,
        "read end should be non-blocking"
    );

    // Non-blocking read on empty pipe should return EAGAIN
    let mut buf = [0u8; 1];
    let n = unsafe { libc::read(fds[0], buf.as_mut_ptr().cast(), 1) };
    assert_eq!(n, -1);

    unsafe { close(fds[0]) };
    unsafe { close(fds[1]) };
}

// ---------------------------------------------------------------------------
// dup2 edge cases
// ---------------------------------------------------------------------------

#[test]
fn dup2_closes_target_fd() {
    let fd1 = temp_fd();
    let fd2 = temp_fd();
    let rc = unsafe { dup2(fd1, fd2) };
    assert_eq!(rc, fd2, "dup2 should return target fd");
    // fd2 should now refer to same as fd1; close both
    unsafe { close(fd1) };
    unsafe { close(fd2) };
}

#[test]
fn dup2_bad_fd_fails() {
    let rc = unsafe { dup2(-1, 200) };
    assert_eq!(rc, -1, "dup2 with invalid source should fail");
}

#[test]
fn dup3_same_fd_fails() {
    let fd = temp_fd();
    let rc = unsafe { dup3(fd, fd, 0) };
    assert_eq!(rc, -1, "dup3 with same old and new fd should fail (EINVAL)");
    unsafe { close(fd) };
}

// ---------------------------------------------------------------------------
// pwrite then pread at same offset — idempotent
// ---------------------------------------------------------------------------

#[test]
fn pwrite_pread_multiple_offsets() {
    let fd = temp_memfd(b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
    // Write at offsets 0, 4, 8, 12
    for i in 0..4u8 {
        let data = [b'A' + i; 4];
        let n = unsafe { pwrite(fd, data.as_ptr().cast(), 4, (i as i64) * 4) };
        assert_eq!(n, 4);
    }
    // Read back entire 16 bytes
    let mut buf = [0u8; 16];
    let n = unsafe { pread(fd, buf.as_mut_ptr().cast(), 16, 0) };
    assert_eq!(n, 16);
    assert_eq!(&buf[0..4], b"AAAA");
    assert_eq!(&buf[4..8], b"BBBB");
    assert_eq!(&buf[8..12], b"CCCC");
    assert_eq!(&buf[12..16], b"DDDD");
    unsafe { close(fd) };
}

// ---------------------------------------------------------------------------
// readv with zero-length iovec
// ---------------------------------------------------------------------------

#[test]
fn readv_single_iovec() {
    let (rfd, wfd) = temp_pipe();
    let data = b"readv1";
    unsafe { libc::write(wfd, data.as_ptr().cast(), data.len()) };

    let mut buf = [0u8; 16];
    let iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    let n = unsafe { readv(rfd, &iov, 1) };
    assert_eq!(n, data.len() as isize);
    assert_eq!(&buf[..data.len()], data);

    unsafe { close(rfd) };
    unsafe { close(wfd) };
}

// ---------------------------------------------------------------------------
// fcntl F_DUPFD_CLOEXEC
// ---------------------------------------------------------------------------

#[test]
fn fcntl_dupfd_cloexec() {
    let fd = temp_fd();
    let new_fd = unsafe { fcntl(fd, libc::F_DUPFD_CLOEXEC, 50) };
    assert!(new_fd >= 50, "F_DUPFD_CLOEXEC should return fd >= 50");

    let flags = unsafe { fcntl(new_fd, libc::F_GETFD, 0) };
    assert_ne!(
        flags & libc::FD_CLOEXEC,
        0,
        "F_DUPFD_CLOEXEC should set FD_CLOEXEC"
    );

    unsafe { close(new_fd) };
    unsafe { close(fd) };
}

// ---------------------------------------------------------------------------
// sendfile with null offset
// ---------------------------------------------------------------------------

#[test]
fn sendfile_null_offset() {
    let content = b"sendfile no offset";
    let in_fd = temp_memfd(content);
    let out_fd = temp_memfd(b"");

    let n = unsafe { sendfile(out_fd, in_fd, std::ptr::null_mut(), content.len()) };
    assert_eq!(n, content.len() as isize);

    unsafe { libc::lseek(out_fd, 0, libc::SEEK_SET) };
    let mut buf = [0u8; 32];
    let read_n = unsafe { libc::read(out_fd, buf.as_mut_ptr().cast(), buf.len()) };
    assert_eq!(read_n, content.len() as isize);
    assert_eq!(&buf[..content.len()], content);

    unsafe { close(in_fd) };
    unsafe { close(out_fd) };
}

// ---------------------------------------------------------------------------
// pipe2 with combined flags
// ---------------------------------------------------------------------------

#[test]
fn pipe2_cloexec_and_nonblock() {
    let mut fds = [0 as c_int; 2];
    let rc = unsafe { pipe2(&mut fds as *mut c_int, libc::O_CLOEXEC | libc::O_NONBLOCK) };
    assert_eq!(rc, 0);

    let fd_flags = unsafe { fcntl(fds[0], libc::F_GETFD, 0) };
    assert_ne!(fd_flags & libc::FD_CLOEXEC, 0);

    let fl_flags = unsafe { fcntl(fds[0], libc::F_GETFL, 0) };
    assert_ne!(fl_flags & libc::O_NONBLOCK, 0);

    unsafe { close(fds[0]) };
    unsafe { close(fds[1]) };
}

// ---------------------------------------------------------------------------
// copy_file_range — partial copy
// ---------------------------------------------------------------------------

#[test]
fn copy_file_range_partial() {
    let content = b"ABCDEFGHIJ";
    let in_fd = temp_memfd(content);
    let out_fd = temp_memfd(b"");

    let mut off_in: i64 = 3; // start at 'D'
    let mut off_out: i64 = 0;
    let n = unsafe { copy_file_range(in_fd, &mut off_in, out_fd, &mut off_out, 5, 0) };
    assert_eq!(n, 5);

    unsafe { libc::lseek(out_fd, 0, libc::SEEK_SET) };
    let mut buf = [0u8; 5];
    unsafe { libc::read(out_fd, buf.as_mut_ptr().cast(), 5) };
    assert_eq!(&buf, b"DEFGH");

    unsafe { close(in_fd) };
    unsafe { close(out_fd) };
}

// ---------------------------------------------------------------------------
// __dup3 / __pipe2 (glibc reserved-namespace aliases)
// ---------------------------------------------------------------------------

#[test]
fn under_pipe2_works_like_pipe2() {
    let mut fds: [c_int; 2] = [-1, -1];
    let rc = unsafe { __pipe2(fds.as_mut_ptr(), 0) };
    assert_eq!(rc, 0);
    assert!(fds[0] >= 0 && fds[1] >= 0);
    unsafe { close(fds[0]) };
    unsafe { close(fds[1]) };
}

#[test]
fn under_dup3_works_like_dup3() {
    let mut fds: [c_int; 2] = [-1, -1];
    assert_eq!(unsafe { __pipe2(fds.as_mut_ptr(), 0) }, 0);
    let target = unsafe { dup(fds[0]) };
    assert!(target >= 0);
    let new = unsafe { __dup3(fds[1], target, 0) };
    assert_eq!(new, target);
    unsafe { close(fds[0]) };
    unsafe { close(fds[1]) };
    unsafe { close(target) };
}

// ---------------------------------------------------------------------------
// __pread / __pwrite / __readv / __writev (glibc reserved aliases)
// ---------------------------------------------------------------------------

fn make_temp_file_fd() -> c_int {
    use std::os::unix::ffi::OsStrExt;
    static TEMP_FILE_SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = TEMP_FILE_SEQ.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "franken_io_alias_{}_{}_{:p}",
        std::process::id(),
        seq,
        &0u8 as *const u8
    ));
    let path_c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    let fd = unsafe {
        libc::open(
            path_c.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
            0o600,
        )
    };
    assert!(fd >= 0);
    // Unlink immediately so the file goes away on close.
    unsafe { libc::unlink(path_c.as_ptr()) };
    fd
}

#[test]
fn under_pwrite_pread_round_trip_at_offset() {
    let fd = make_temp_file_fd();
    let payload = b"hello, alias!";
    let n = unsafe {
        __pwrite(
            fd,
            payload.as_ptr() as *const std::ffi::c_void,
            payload.len(),
            0,
        )
    };
    assert_eq!(n as usize, payload.len());

    let mut buf = [0u8; 32];
    let n = unsafe { __pread(fd, buf.as_mut_ptr() as *mut std::ffi::c_void, buf.len(), 0) };
    assert_eq!(n as usize, payload.len());
    assert_eq!(&buf[..payload.len()], payload);
    unsafe { close(fd) };
}

#[test]
fn under_pipe_creates_pair() {
    use frankenlibc_abi::io_abi::__pipe;
    let mut fds: [c_int; 2] = [-1, -1];
    let rc = unsafe { __pipe(fds.as_mut_ptr()) };
    assert_eq!(rc, 0);
    assert!(fds[0] >= 0 && fds[1] >= 0);
    unsafe { close(fds[0]) };
    unsafe { close(fds[1]) };
}

#[test]
fn under_writev_readv_round_trip() {
    let fd = make_temp_file_fd();
    let part1 = b"alias-";
    let part2 = b"writev";
    let iov = [
        libc::iovec {
            iov_base: part1.as_ptr() as *mut std::ffi::c_void,
            iov_len: part1.len(),
        },
        libc::iovec {
            iov_base: part2.as_ptr() as *mut std::ffi::c_void,
            iov_len: part2.len(),
        },
    ];
    let n = unsafe { __writev(fd, iov.as_ptr(), 2) };
    assert_eq!(n as usize, part1.len() + part2.len());

    // Rewind via lseek then __readv.
    let pos = unsafe { libc::lseek(fd, 0, libc::SEEK_SET) };
    assert_eq!(pos, 0);
    let mut buf1 = [0u8; 6];
    let mut buf2 = [0u8; 6];
    let r_iov = [
        libc::iovec {
            iov_base: buf1.as_mut_ptr() as *mut std::ffi::c_void,
            iov_len: buf1.len(),
        },
        libc::iovec {
            iov_base: buf2.as_mut_ptr() as *mut std::ffi::c_void,
            iov_len: buf2.len(),
        },
    ];
    let n = unsafe { __readv(fd, r_iov.as_ptr(), 2) };
    assert_eq!(n as usize, part1.len() + part2.len());
    assert_eq!(&buf1, part1);
    assert_eq!(&buf2, part2);
    unsafe { close(fd) };
}
