#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // exercises fl's LFS *64 aliases against their bases

//! Wiring gate for the *64 LFS aliases (bd-6pvt1k). On 64-bit Linux off_t and
//! the size types are already 64-bit, so `foo64` must produce identical results
//! to `foo`. These were untested; a mis-wired alias (calling the wrong base /
//! wrong syscall) would diverge. Self-consistency of fl's own exports — no mocks.

use std::ffi::{c_char, c_int, c_void};

use frankenlibc_abi::resource_abi;
use frankenlibc_abi::unistd_abi as u;

#[test]
fn getrlimit64_matches_getrlimit() {
    for res in [
        libc::RLIMIT_NOFILE,
        libc::RLIMIT_STACK,
        libc::RLIMIT_NPROC,
        libc::RLIMIT_AS,
    ] {
        let mut a: libc::rlimit = unsafe { std::mem::zeroed() };
        let mut b: libc::rlimit = unsafe { std::mem::zeroed() };
        let ra = unsafe { resource_abi::getrlimit(res as c_int, &mut a) };
        let rb = unsafe { u::getrlimit64(res as c_int, &mut b) };
        assert_eq!(ra, rb, "getrlimit/getrlimit64 rc differ (res={res})");
        if ra == 0 {
            assert_eq!(a.rlim_cur, b.rlim_cur, "rlim_cur differs (res={res})");
            assert_eq!(a.rlim_max, b.rlim_max, "rlim_max differs (res={res})");
        }
    }
}

#[test]
fn statfs64_matches_statfs() {
    let path = c"/";
    let mut a: libc::statfs = unsafe { std::mem::zeroed() };
    let mut b: libc::statfs64 = unsafe { std::mem::zeroed() };
    let ra = unsafe {
        u::statfs(
            path.as_ptr() as *const c_char,
            &mut a as *mut _ as *mut c_void,
        )
    };
    let rb = unsafe {
        u::statfs64(
            path.as_ptr() as *const c_char,
            &mut b as *mut _ as *mut c_void,
        )
    };
    assert_eq!(ra, rb, "statfs/statfs64 rc differ");
    if ra == 0 {
        assert_eq!(a.f_type, b.f_type, "f_type differs");
        assert_eq!(a.f_bsize, b.f_bsize, "f_bsize differs");
        assert_eq!(a.f_blocks, b.f_blocks, "f_blocks differs");
        assert_eq!(a.f_files, b.f_files, "f_files differs");
        assert_eq!(a.f_namelen, b.f_namelen, "f_namelen differs");
    }
}

/// The fourth alias bd-6pvt1k names. It was missing from this gate while the
/// other three were covered, so the bead's ask was only three-quarters met.
///
/// Uses a file descriptor rather than a path, which is the whole difference
/// between this pair and `statfs64`/`statfs`: a mis-wired `fstatfs64` that
/// forwarded to the PATH-taking `statfs` would interpret the fd as a pointer,
/// so this arm covers a failure mode the statfs64 arm cannot reach.
#[test]
fn fstatfs64_matches_fstatfs() {
    // SAFETY: "/" is a NUL-terminated constant and O_RDONLY|O_DIRECTORY opens a
    // directory fd suitable for fstatfs.
    let fd = unsafe { libc::open(c"/".as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
    assert!(fd >= 0, "opening / for fstatfs failed");

    let mut a: libc::statfs = unsafe { std::mem::zeroed() };
    let mut b: libc::statfs64 = unsafe { std::mem::zeroed() };
    let ra = unsafe { u::fstatfs(fd, &mut a as *mut _ as *mut c_void) };
    let rb = unsafe { u::fstatfs64(fd, &mut b as *mut _ as *mut c_void) };
    // SAFETY: fd was opened above and is not used after this point.
    unsafe { libc::close(fd) };

    assert_eq!(ra, rb, "fstatfs/fstatfs64 rc differ");
    if ra == 0 {
        assert_eq!(a.f_type, b.f_type, "f_type differs");
        assert_eq!(a.f_bsize, b.f_bsize, "f_bsize differs");
        assert_eq!(a.f_blocks, b.f_blocks, "f_blocks differs");
        assert_eq!(a.f_files, b.f_files, "f_files differs");
        assert_eq!(a.f_namelen, b.f_namelen, "f_namelen differs");
        // The point of the alias: same fd, same filesystem, so the two calls
        // must agree on free space as well, not merely on the static geometry.
        assert_eq!(a.f_bfree, b.f_bfree, "f_bfree differs");
    }
}

#[test]
fn statvfs64_matches_statvfs() {
    let path = c"/";
    let mut a: libc::statvfs = unsafe { std::mem::zeroed() };
    let mut b: libc::statvfs = unsafe { std::mem::zeroed() };
    let ra = unsafe { u::statvfs(path.as_ptr() as *const c_char, &mut a) };
    let rb = unsafe { u::statvfs64(path.as_ptr() as *const c_char, &mut b) };
    assert_eq!(ra, rb, "statvfs/statvfs64 rc differ");
    if ra == 0 {
        assert_eq!(a.f_bsize, b.f_bsize, "f_bsize differs");
        assert_eq!(a.f_blocks, b.f_blocks, "f_blocks differs");
        assert_eq!(a.f_namemax, b.f_namemax, "f_namemax differs");
        assert_eq!(a.f_flag, b.f_flag, "f_flag differs");
    }
}
