#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc sockatmark oracle

//! Differential gate for `sockatmark` (bd-e0pcqx).
//!
//! `sockatmark(fd)` reports whether a socket's read pointer sits at an
//! out-of-band mark. fl implements it as `ioctl(fd, SIOCATMARK, &flag)`,
//! returning the flag on success and `-1` with the syscall's errno otherwise.
//! That is glibc's implementation too, so every observable — the return value
//! AND the errno — should agree exactly.
//!
//! Both arms run in this process against the same descriptors. No mocks: the
//! not-at-mark case uses a real connected `AF_UNIX` stream pair, and the error
//! cases use descriptors the kernel genuinely rejects.

use std::ffi::c_int;

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn sockatmark(fd: c_int) -> c_int;
    }
}

use frankenlibc_abi::unistd_abi::sockatmark as fl_sockatmark;

/// (return value, errno) — errno is only meaningful when the call failed, but
/// it is captured unconditionally so a spurious errno write is visible too.
type Outcome = (c_int, c_int);

fn host(fd: c_int) -> Outcome {
    // SAFETY: errno location is always valid; sockatmark takes an int.
    unsafe {
        *libc::__errno_location() = 0;
        let rc = g::sockatmark(fd);
        (rc, *libc::__errno_location())
    }
}

fn fl(fd: c_int) -> Outcome {
    // SAFETY: as above, against fl's implementation and fl's errno slot.
    unsafe {
        frankenlibc_abi::errno_abi::set_abi_errno(0);
        let rc = fl_sockatmark(fd);
        (rc, *frankenlibc_abi::errno_abi::__errno_location())
    }
}

/// A connected AF_UNIX stream pair. Returned fds are closed by the caller.
fn stream_pair() -> (c_int, c_int) {
    let mut fds = [-1i32; 2];
    // SAFETY: fds has room for the two descriptors socketpair writes.
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
    assert_eq!(rc, 0, "socketpair should succeed");
    (fds[0], fds[1])
}

#[test]
fn sockatmark_matches_glibc_on_a_live_stream_socket() {
    let (a, b) = stream_pair();

    // A freshly connected stream socket has no out-of-band mark pending, so both
    // implementations must report 0 — and neither may invent an errno.
    let host_out = host(a);
    let fl_out = fl(a);
    assert_eq!(
        fl_out.0, host_out.0,
        "return value diverged on a live stream socket: fl={fl_out:?} glibc={host_out:?}"
    );
    assert_eq!(
        host_out.0, 0,
        "oracle: a fresh stream socket should not be at the OOB mark (got {host_out:?})"
    );

    // Written after the payload so a mistake here cannot pass by both sides
    // failing identically for an unrelated reason.
    let mut data = [0u8; 4];
    // SAFETY: writing 4 bytes into a 4-byte buffer on a valid socket.
    let sent = unsafe { libc::write(b, data.as_ptr().cast(), data.len()) };
    assert_eq!(
        sent,
        data.len() as isize,
        "write to the peer should succeed"
    );
    // SAFETY: reading 4 bytes into a 4-byte buffer.
    let got = unsafe { libc::read(a, data.as_mut_ptr().cast(), data.len()) };
    assert_eq!(got, data.len() as isize, "read should drain the payload");

    // Still not at a mark after ordinary (non-OOB) traffic.
    let host_after = host(a);
    let fl_after = fl(a);
    assert_eq!(
        fl_after.0, host_after.0,
        "return value diverged after ordinary traffic: fl={fl_after:?} glibc={host_after:?}"
    );

    // SAFETY: both descriptors are open and owned here.
    unsafe {
        libc::close(a);
        libc::close(b);
    }
}

#[test]
fn sockatmark_matches_glibc_on_rejected_descriptors() {
    // A never-opened descriptor and a negative one: the kernel rejects both, and
    // fl must surface the SAME errno glibc does, not merely the same -1.
    let probe = [-1i32, 2048];
    // A regular file is a valid fd that is NOT a socket, which is the other
    // rejection glibc's implementation can produce.
    let path = std::ffi::CString::new("/dev/null").expect("no NUL");
    // SAFETY: opening /dev/null read-only.
    let notsock = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY) };
    assert!(notsock >= 0, "opening /dev/null should succeed");

    for fd in probe.iter().copied().chain(std::iter::once(notsock)) {
        let host_out = host(fd);
        let fl_out = fl(fd);
        assert_eq!(
            fl_out.0, host_out.0,
            "return value diverged for fd {fd}: fl={fl_out:?} glibc={host_out:?}"
        );
        assert_eq!(
            fl_out.1, host_out.1,
            "errno diverged for fd {fd}: fl={fl_out:?} glibc={host_out:?}"
        );
        assert_eq!(
            host_out.0, -1,
            "oracle: fd {fd} should be rejected (got {host_out:?})"
        );
        assert_ne!(
            host_out.1, 0,
            "oracle: a rejected fd should set errno (fd {fd}, got {host_out:?})"
        );
    }

    // SAFETY: notsock is open and owned here.
    unsafe { libc::close(notsock) };
}
