//! Differential gate: preadv2/pwritev2 deliver the `flags` argument to the
//! kernel, matching glibc.
//!
//! The kernel preadv2/pwritev2 are 6-arg syscalls (fd, iov, iovcnt, pos_l,
//! pos_h, flags). fl previously used a 5-arg form, putting `flags` in the pos_h
//! slot (ignored on LP64) and leaving the real flags register uninitialized — so
//! the caller's flags were dropped. We verify (1) a flags=0 call reads/writes at
//! the right offset and (2) an UNSUPPORTED flag produces the same rc+errno as
//! glibc (which only happens if the flag actually reaches the kernel).
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::io_abi as fl;
use std::ffi::{c_int, c_void};

unsafe extern "C" {
    fn preadv2(
        fd: c_int,
        iov: *const libc::iovec,
        iovcnt: c_int,
        offset: libc::off_t,
        flags: c_int,
    ) -> libc::ssize_t;
    fn pwritev2(
        fd: c_int,
        iov: *const libc::iovec,
        iovcnt: c_int,
        offset: libc::off_t,
        flags: c_int,
    ) -> libc::ssize_t;
}

// An undefined RWF_* bit — far above any supported flag, so the kernel rejects
// it (only if the flag is actually delivered).
const BAD_FLAG: c_int = 0x4000_0000;
const CONTENT: &[u8] = b"0123456789ABCDEF";

fn errno() -> c_int {
    unsafe { *libc::__errno_location() }
}

fn make_file(content: &[u8]) -> c_int {
    let path = format!("/tmp/fl_preadv2_{}\0", std::process::id());
    let fd = unsafe {
        libc::open(
            path.as_ptr().cast(),
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
            0o600,
        )
    };
    assert!(fd >= 0, "open temp");
    // Unlink immediately; the open fd keeps it alive.
    unsafe { libc::unlink(path.as_ptr().cast()) };
    assert_eq!(
        unsafe { libc::pwrite(fd, content.as_ptr().cast(), content.len(), 0) },
        content.len() as isize
    );
    fd
}

fn iov_of(buf: &mut [u8]) -> libc::iovec {
    libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut c_void,
        iov_len: buf.len(),
    }
}

#[test]
fn preadv2_reads_at_offset_with_valid_flags() {
    let fd = make_file(CONTENT);
    let mut gbuf = [0u8; 5];
    let mut fbuf = [0u8; 5];
    let giov = iov_of(&mut gbuf);
    let fiov = iov_of(&mut fbuf);
    let gr = unsafe { preadv2(fd, &giov, 1, 3, 0) };
    let fr = unsafe { fl::preadv2(fd, &fiov, 1, 3, 0) };
    assert_eq!(gr, 5, "glibc preadv2 should read 5 bytes");
    assert_eq!(&gbuf, b"34567", "glibc read at offset 3");
    assert_eq!(fr, gr, "rc: glibc={gr} fl={fr}");
    assert_eq!(fbuf, gbuf, "fl read the wrong bytes: {fbuf:?} vs {gbuf:?}");
    unsafe { libc::close(fd) };
}

#[test]
fn preadv2_unsupported_flag_matches_glibc() {
    let fd = make_file(CONTENT);
    let mut gbuf = [0u8; 5];
    let mut fbuf = [0u8; 5];
    let giov = iov_of(&mut gbuf);
    let fiov = iov_of(&mut fbuf);

    unsafe { *libc::__errno_location() = 0 };
    let gr = unsafe { preadv2(fd, &giov, 1, 0, BAD_FLAG) };
    let ge = errno();
    unsafe { *libc::__errno_location() = 0 };
    let fr = unsafe { fl::preadv2(fd, &fiov, 1, 0, BAD_FLAG) };
    let fe = errno();

    assert_eq!(gr, -1, "glibc should reject the unsupported flag");
    assert_eq!(
        fr, gr,
        "rc on unsupported flag: glibc={gr} fl={fr} (fl dropped the flag before the fix)"
    );
    assert_eq!(fe, ge, "errno on unsupported flag: glibc={ge} fl={fe}");
    unsafe { libc::close(fd) };
}

#[test]
fn pwritev2_unsupported_flag_matches_glibc() {
    let fd = make_file(CONTENT);
    let mut buf = *b"XYZ";
    let iov = iov_of(&mut buf);

    unsafe { *libc::__errno_location() = 0 };
    let gr = unsafe { pwritev2(fd, &iov, 1, 0, BAD_FLAG) };
    let ge = errno();
    unsafe { *libc::__errno_location() = 0 };
    let fr = unsafe { fl::pwritev2(fd, &iov, 1, 0, BAD_FLAG) };
    let fe = errno();

    assert_eq!(gr, -1, "glibc should reject the unsupported flag");
    assert_eq!(fr, gr, "rc on unsupported flag: glibc={gr} fl={fr}");
    assert_eq!(fe, ge, "errno on unsupported flag: glibc={ge} fl={fe}");
    unsafe { libc::close(fd) };
}

#[test]
fn pwritev2_writes_at_offset_with_valid_flags() {
    // glibc and fl write the same bytes at the same offset to two fresh files;
    // the resulting contents must be identical.
    let gfd = make_file(CONTENT);
    let ffd = make_file(CONTENT);
    let mut gbuf = *b"XYZ";
    let mut fbuf = *b"XYZ";
    let giov = iov_of(&mut gbuf);
    let fiov = iov_of(&mut fbuf);
    let gr = unsafe { pwritev2(gfd, &giov, 1, 2, 0) };
    let fr = unsafe { fl::pwritev2(ffd, &fiov, 1, 2, 0) };
    assert_eq!(gr, 3, "glibc pwritev2 should write 3 bytes");
    assert_eq!(fr, gr, "rc: glibc={gr} fl={fr}");

    let mut gout = [0u8; 16];
    let mut fout = [0u8; 16];
    assert_eq!(
        unsafe { libc::pread(gfd, gout.as_mut_ptr().cast(), 16, 0) },
        16
    );
    assert_eq!(
        unsafe { libc::pread(ffd, fout.as_mut_ptr().cast(), 16, 0) },
        16
    );
    assert_eq!(fout, gout, "file contents diverged after pwritev2");
    assert_eq!(&gout, b"01XYZ56789ABCDEF", "glibc wrote at offset 2");
    unsafe {
        libc::close(gfd);
        libc::close(ffd)
    };
}
