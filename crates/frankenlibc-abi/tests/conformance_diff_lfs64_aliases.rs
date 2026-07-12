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
