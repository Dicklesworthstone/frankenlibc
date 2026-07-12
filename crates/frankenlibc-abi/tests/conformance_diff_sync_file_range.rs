#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-kernel syscall oracle

//! Differential coverage for Linux `sync_file_range`.
//!
//! The covered invalid-argument cases fail before any writeback can occur:
//! an invalid fd returns `EBADF`, while `/dev/null` with invalid flags or
//! negative ranges returns `EINVAL`.

use frankenlibc_abi::errno_abi::__errno_location as fl_errno_location;
use frankenlibc_abi::unistd_abi as fl;
use std::ffi::{c_char, c_int, c_long, c_uint};

const DEV_NULL: &[u8] = b"/dev/null\0";
const SYNC_FILE_RANGE_INVALID_FLAGS: c_uint = 8;

fn host_errno() -> c_int {
    unsafe { *libc::__errno_location() }
}

fn set_host_errno(value: c_int) {
    unsafe { *libc::__errno_location() = value };
}

fn fl_errno() -> c_int {
    unsafe { *fl_errno_location() }
}

fn set_fl_errno(value: c_int) {
    unsafe { *fl_errno_location() = value };
}

fn host_sync_file_range(fd: c_int, offset: i64, nbytes: i64, flags: c_uint) -> (c_int, c_int) {
    set_host_errno(0);
    let rc =
        unsafe { libc::syscall(libc::SYS_sync_file_range, fd, offset, nbytes, flags) as c_long };
    (rc as c_int, host_errno())
}

fn fl_sync_file_range(fd: c_int, offset: i64, nbytes: i64, flags: c_uint) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::sync_file_range(fd, offset, nbytes, flags) };
    (rc, fl_errno())
}

#[test]
fn sync_file_range_invalid_fd_matches_host_syscall() {
    let host = host_sync_file_range(-1, 0, 0, 0);
    let fl = fl_sync_file_range(-1, 0, 0, 0);

    assert_eq!(
        fl, host,
        "sync_file_range(invalid fd): fl={fl:?} host={host:?}"
    );
    assert_eq!(fl, (-1, libc::EBADF));
}

#[test]
fn sync_file_range_invalid_flags_and_ranges_match_host_syscall() {
    let fd = unsafe {
        libc::open(
            DEV_NULL.as_ptr() as *const c_char,
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    assert!(
        fd >= 0,
        "open(/dev/null) failed with errno {}",
        host_errno()
    );

    let cases = [
        ("invalid flags", 0, 1, SYNC_FILE_RANGE_INVALID_FLAGS),
        ("negative offset", -1, 1, 0),
        ("negative nbytes", 0, -1, 0),
    ];

    for (name, offset, nbytes, flags) in cases {
        let host = host_sync_file_range(fd, offset, nbytes, flags);
        let fl = fl_sync_file_range(fd, offset, nbytes, flags);

        assert_eq!(fl, host, "sync_file_range({name}): fl={fl:?} host={host:?}");
        assert_eq!(fl, (-1, libc::EINVAL), "sync_file_range({name})");
    }

    let close_rc = unsafe { libc::close(fd) };
    assert_eq!(close_rc, 0, "close(/dev/null) failed");
}
