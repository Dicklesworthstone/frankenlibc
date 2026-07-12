//! Differential gate: fchmodat() honors AT_SYMLINK_NOFOLLOW and rejects invalid
//! flags, matching glibc.
//!
//! The classic fchmodat syscall is 3-arg and IGNORES the flags word, so fl
//! previously: (a) accepted invalid flag bits glibc rejects with EINVAL, and
//! (b) silently followed a symlink under AT_SYMLINK_NOFOLLOW instead of failing
//! with EOPNOTSUPP (chmod-on-symlink is unsupported). The fix routes
//! AT_SYMLINK_NOFOLLOW through fchmodat2 and validates the flag set. We compare
//! fl against the host's fchmodat across the four cases.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::unistd_abi as fl;
use std::ffi::{CString, c_char, c_int};

unsafe extern "C" {
    fn fchmodat(dirfd: c_int, path: *const c_char, mode: libc::mode_t, flags: c_int) -> c_int;
}
type FchmodatFn = unsafe extern "C" fn(c_int, *const c_char, libc::mode_t, c_int) -> c_int;

fn errno() -> c_int {
    unsafe { *libc::__errno_location() }
}

fn cs(s: &str) -> CString {
    CString::new(s).unwrap()
}

/// Create a fresh 0644 regular file and a symlink to it under a unique dir.
/// Returns (target_path, symlink_path).
fn make_pair(tag: &str) -> (CString, CString) {
    let dir = format!("/tmp/fl_fchmodat_{}_{}", std::process::id(), tag);
    unsafe { libc::mkdir(cs(&dir).as_ptr(), 0o755) };
    let tgt = format!("{dir}/tgt");
    let lnk = format!("{dir}/lnk");
    let ctgt = cs(&tgt);
    let clnk = cs(&lnk);
    let fd = unsafe { libc::open(ctgt.as_ptr(), libc::O_CREAT | libc::O_WRONLY, 0o644) };
    assert!(fd >= 0, "create target");
    unsafe { libc::close(fd) };
    unsafe { libc::chmod(ctgt.as_ptr(), 0o644) };
    unsafe { libc::symlink(ctgt.as_ptr(), clnk.as_ptr()) };
    (ctgt, clnk)
}

fn mode_of(path: &CString) -> u32 {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::stat(path.as_ptr(), &mut st) }, 0, "stat");
    st.st_mode & 0o777
}

/// (rc, errno-or-0)
fn call(f: FchmodatFn, path: &CString, mode: libc::mode_t, flags: c_int) -> (c_int, c_int) {
    unsafe { *libc::__errno_location() = 0 };
    let rc = unsafe { f(libc::AT_FDCWD, path.as_ptr(), mode, flags) };
    (rc, if rc != 0 { errno() } else { 0 })
}

#[test]
fn fchmodat_symlink_nofollow_matches_glibc() {
    // chmod a symlink with AT_SYMLINK_NOFOLLOW: both must fail identically and
    // leave the target's mode unchanged.
    let (gt, gl) = make_pair("g_sym");
    let (ft, flk) = make_pair("f_sym");
    let g = call(fchmodat, &gl, 0o600, libc::AT_SYMLINK_NOFOLLOW);
    let f = call(fl::fchmodat, &flk, 0o600, libc::AT_SYMLINK_NOFOLLOW);
    assert_eq!(g.0, -1, "glibc should fail chmod-on-symlink");
    assert_eq!(
        f, g,
        "rc/errno: glibc={g:?} fl={f:?} (fl followed the symlink before the fix)"
    );
    assert_eq!(mode_of(&gt), 0o644, "glibc left the target unchanged");
    assert_eq!(
        mode_of(&ft),
        mode_of(&gt),
        "fl changed the symlink target (followed the link)"
    );
}

#[test]
fn fchmodat_invalid_flag_matches_glibc() {
    let (_gt, _) = make_pair("g_bad");
    let (_ft, _) = make_pair("f_bad");
    let gt = make_pair("g_bad2").0;
    let ft = make_pair("f_bad2").0;
    let g = call(fchmodat, &gt, 0o600, 0x4);
    let f = call(fl::fchmodat, &ft, 0o600, 0x4);
    assert_eq!(g.0, -1, "glibc rejects invalid flag");
    assert_eq!(f, g, "rc/errno on invalid flag: glibc={g:?} fl={f:?}");
    assert_eq!(mode_of(&gt), 0o644, "glibc left mode unchanged on EINVAL");
    assert_eq!(mode_of(&ft), 0o644, "fl must not chmod on an invalid flag");
}

#[test]
fn fchmodat_regfile_paths_match_glibc() {
    // NOFOLLOW on a regular file, and flags==0, both succeed.
    let gt = make_pair("g_reg").0;
    let ft = make_pair("f_reg").0;
    let g1 = call(fchmodat, &gt, 0o640, libc::AT_SYMLINK_NOFOLLOW);
    let f1 = call(fl::fchmodat, &ft, 0o640, libc::AT_SYMLINK_NOFOLLOW);
    assert_eq!(f1, g1, "regfile+NOFOLLOW rc: glibc={g1:?} fl={f1:?}");
    assert_eq!(mode_of(&ft), mode_of(&gt), "regfile+NOFOLLOW mode mismatch");

    let g2 = call(fchmodat, &gt, 0o600, 0);
    let f2 = call(fl::fchmodat, &ft, 0o600, 0);
    assert_eq!(f2, g2, "regfile+flag0 rc: glibc={g2:?} fl={f2:?}");
    assert_eq!(mode_of(&ft), mode_of(&gt), "regfile+flag0 mode mismatch");
}
