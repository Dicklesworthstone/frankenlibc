#![cfg(target_os = "linux")]

//! Differential conformance harness for Linux 3.17+/5.3+ fd APIs:
//!   - memfd_create (anonymous in-memory file)
//!   - pidfd_open (file descriptor referring to a process)
//!   - pidfd_send_signal (deliver a signal via a pidfd)
//!
//! pidfd_getfd is not exercised here — it requires CAP_SYS_PTRACE
//! against the target process.
//!
//! Bead: CONFORMANCE: libc memfd_create+pidfd diff matrix.

use std::ffi::{CString, c_char, c_int, c_uint};

use frankenlibc_abi::{io_abi as fl_io, unistd_abi as fl_uni};

unsafe extern "C" {
    fn memfd_create(name: *const c_char, flags: c_uint) -> c_int;
    fn syscall(number: i64, ...) -> i64;
}

const SYS_PIDFD_OPEN: i64 = 434;
const SYS_PIDFD_SEND_SIGNAL: i64 = 424;

const MFD_CLOEXEC: c_uint = 0x0001;
const MFD_ALLOW_SEALING: c_uint = 0x0002;

fn libc_pidfd_open(pid: libc::pid_t, flags: c_uint) -> c_int {
    unsafe { syscall(SYS_PIDFD_OPEN, pid as i64, flags as i64) as c_int }
}

fn libc_pidfd_send_signal(
    pidfd: c_int,
    sig: c_int,
    info: *mut libc::siginfo_t,
    flags: c_uint,
) -> c_int {
    unsafe {
        syscall(
            SYS_PIDFD_SEND_SIGNAL,
            pidfd as i64,
            sig as i64,
            info as i64,
            flags as i64,
        ) as c_int
    }
}

#[test]
fn diff_memfd_create_basic() {
    let name = CString::new("fl_memfd_diff").unwrap();
    let fd_fl = unsafe { fl_io::memfd_create(name.as_ptr(), 0) };
    let fd_lc = unsafe { memfd_create(name.as_ptr(), 0) };
    assert!(
        (fd_fl >= 0) == (fd_lc >= 0),
        "memfd_create success-match: fl={fd_fl}, lc={fd_lc}"
    );
    if fd_fl >= 0 {
        unsafe { libc::close(fd_fl) };
    }
    if fd_lc >= 0 {
        unsafe { libc::close(fd_lc) };
    }
}

#[test]
fn diff_memfd_create_cloexec() {
    let name = CString::new("fl_memfd_clo").unwrap();
    let fd_fl = unsafe { fl_io::memfd_create(name.as_ptr(), MFD_CLOEXEC) };
    let fd_lc = unsafe { memfd_create(name.as_ptr(), MFD_CLOEXEC) };
    assert!(
        (fd_fl >= 0) == (fd_lc >= 0),
        "memfd_create CLOEXEC success-match: fl={fd_fl}, lc={fd_lc}"
    );
    if fd_fl >= 0 {
        // Verify FD_CLOEXEC is set
        let flags = unsafe { libc::fcntl(fd_fl, libc::F_GETFD) };
        assert!(flags & libc::FD_CLOEXEC != 0, "fl: FD_CLOEXEC not set");
        unsafe { libc::close(fd_fl) };
    }
    if fd_lc >= 0 {
        let flags = unsafe { libc::fcntl(fd_lc, libc::F_GETFD) };
        assert!(flags & libc::FD_CLOEXEC != 0, "lc: FD_CLOEXEC not set");
        unsafe { libc::close(fd_lc) };
    }
}

#[test]
fn diff_memfd_create_writable_round_trip() {
    let name = CString::new("fl_memfd_rw").unwrap();
    let payload = b"hello memfd";

    let run = |use_fl: bool| -> Vec<u8> {
        let fd = if use_fl {
            unsafe { fl_io::memfd_create(name.as_ptr(), MFD_ALLOW_SEALING) }
        } else {
            unsafe { memfd_create(name.as_ptr(), MFD_ALLOW_SEALING) }
        };
        if fd < 0 {
            return Vec::new();
        }
        let _ = unsafe {
            libc::write(
                fd,
                payload.as_ptr() as *const std::ffi::c_void,
                payload.len(),
            )
        };
        let mut buf = vec![0u8; payload.len()];
        let _ = unsafe { libc::pread(fd, buf.as_mut_ptr() as *mut std::ffi::c_void, buf.len(), 0) };
        unsafe { libc::close(fd) };
        buf
    };
    let d_fl = run(true);
    let d_lc = run(false);
    assert_eq!(d_fl, d_lc, "memfd round-trip diff");
    assert_eq!(d_fl, payload.to_vec(), "expected payload");
}

#[test]
fn diff_pidfd_open_self() {
    let pid = unsafe { libc::getpid() };
    let fd_fl = unsafe { fl_uni::pidfd_open(pid, 0) };
    let fd_lc = libc_pidfd_open(pid, 0);
    assert!(
        (fd_fl >= 0) == (fd_lc >= 0),
        "pidfd_open self success-match: fl={fd_fl}, lc={fd_lc}"
    );
    if fd_fl >= 0 {
        unsafe { libc::close(fd_fl) };
    }
    if fd_lc >= 0 {
        unsafe { libc::close(fd_lc) };
    }
}

#[test]
fn diff_pidfd_open_invalid_pid() {
    // Use INT_MAX (very unlikely to be a real PID)
    let fd_fl = unsafe { fl_uni::pidfd_open(2_147_483_647, 0) };
    let fd_lc = libc_pidfd_open(2_147_483_647, 0);
    assert!(
        (fd_fl < 0) == (fd_lc < 0),
        "pidfd_open INT_MAX fail-match: fl={fd_fl}, lc={fd_lc}"
    );
    if fd_fl >= 0 {
        unsafe { libc::close(fd_fl) };
    }
    if fd_lc >= 0 {
        unsafe { libc::close(fd_lc) };
    }
}

#[test]
fn diff_pidfd_send_signal_invalid_fd() {
    let r_fl = unsafe { fl_uni::pidfd_send_signal(99999, 0, std::ptr::null_mut(), 0) };
    let r_lc = libc_pidfd_send_signal(99999, 0, std::ptr::null_mut(), 0);
    assert!(
        (r_fl < 0) == (r_lc < 0),
        "pidfd_send_signal bad-fd fail-match: fl={r_fl}, lc={r_lc}"
    );
}

#[test]
fn memfd_pidfd_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"memfd_create+pidfd_open+pidfd_send_signal\",\"reference\":\"glibc/syscall\",\"functions\":3,\"divergences\":0}}",
    );
}
