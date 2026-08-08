#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc fchmodat/lchmod oracle on a real filesystem

//! Differential gate for `AT_SYMLINK_NOFOLLOW` handling in `fchmodat` and
//! `lchmod` (bd-f29d1s). No mocks: every case creates a real file and a real
//! symlink in a temp dir, runs glibc and fl on byte-identical trees, and
//! compares BOTH the return contract and the resulting on-disk mode.
//!
//! Why this exists: the classic `fchmodat(2)` syscall takes only three
//! arguments, so passing flags to it is discarded by the kernel. fl's
//! `sys_fchmodat` accepted a `flags` parameter and passed it as a fourth
//! argument, which meant `lchmod` — whose entire purpose is to not follow
//! symlinks — chmod'd the symlink TARGET. Measured directly on this host before
//! the fix:
//!   syscall(SYS_fchmodat, AT_FDCWD, <symlink>, 0707, AT_SYMLINK_NOFOLLOW)
//!     -> rc=0, target mode 0644 -> 0707
//! while glibc's lchmod on the same tree returns -1/ENOTSUP and leaves 0644.
//!
//! The `regular file + AT_SYMLINK_NOFOLLOW` case is load-bearing in the other
//! direction: it must still SUCCEED. A fix that rejected every flag-bearing call
//! would satisfy the symlink cases and be just as wrong.

use std::ffi::{CString, c_char, c_int, c_uint};
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicU32, Ordering};

const AT_SYMLINK_NOFOLLOW: c_int = 0x100;

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn fchmodat(dirfd: c_int, path: *const c_char, mode: c_uint, flags: c_int) -> c_int;
        pub fn lchmod(path: *const c_char, mode: c_uint) -> c_int;
        pub fn __errno_location() -> *mut c_int;
    }
}

static SEQ: AtomicU32 = AtomicU32::new(0);

/// A fresh temp dir holding `target` (mode 0644) and `link -> target`.
struct Tree {
    dir: std::path::PathBuf,
    target: std::path::PathBuf,
    link: std::path::PathBuf,
}

fn tree(tag: &str) -> Tree {
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let mut dir = std::env::temp_dir();
    dir.push(format!("fl-fchmodat-{}-{}-{}", std::process::id(), tag, n));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let target = dir.join("target");
    std::fs::write(&target, b"x").expect("write target");
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).expect("chmod");
    let link = dir.join("link");
    std::os::unix::fs::symlink("target", &link).expect("symlink");
    Tree { dir, target, link }
}

fn mode_of(p: &std::path::Path) -> u32 {
    std::fs::metadata(p).expect("stat target").permissions().mode() & 0o7777
}

fn cpath(p: &std::path::Path) -> CString {
    CString::new(p.as_os_str().to_str().unwrap()).unwrap()
}

/// (rc, errno-if-rc-nonzero, resulting target mode)
type Outcome = (c_int, c_int, u32);

fn run_glibc_fchmodat(which: &str, flags: c_int, mode: c_uint) -> Outcome {
    let t = tree("g");
    let p = cpath(if which == "link" { &t.link } else { &t.target });
    unsafe { *g::__errno_location() = 0 };
    let rc = unsafe { g::fchmodat(libc::AT_FDCWD, p.as_ptr(), mode, flags) };
    let e = if rc == 0 {
        0
    } else {
        unsafe { *g::__errno_location() }
    };
    let m = mode_of(&t.target);
    let _ = std::fs::remove_dir_all(&t.dir);
    (rc, e, m)
}

fn run_fl_fchmodat(which: &str, flags: c_int, mode: c_uint) -> Outcome {
    let t = tree("f");
    let p = cpath(if which == "link" { &t.link } else { &t.target });
    unsafe { *g::__errno_location() = 0 };
    let rc = unsafe {
        frankenlibc_abi::unistd_abi::fchmodat(
            libc::AT_FDCWD,
            p.as_ptr(),
            mode as libc::mode_t,
            flags,
        )
    };
    let e = if rc == 0 {
        0
    } else {
        unsafe { *g::__errno_location() }
    };
    let m = mode_of(&t.target);
    let _ = std::fs::remove_dir_all(&t.dir);
    (rc, e, m)
}

#[test]
fn fchmodat_symlink_nofollow_matches_glibc() {
    // (label, which path, flags)
    let cases: &[(&str, &str, c_int)] = &[
        ("regular file, flags=0", "file", 0),
        ("regular file, NOFOLLOW", "file", AT_SYMLINK_NOFOLLOW),
        ("symlink, flags=0 (follows)", "link", 0),
        ("symlink, NOFOLLOW", "link", AT_SYMLINK_NOFOLLOW),
        ("regular file, bogus flag", "file", 0x4000),
    ];
    for &(label, which, flags) in cases {
        let gout = run_glibc_fchmodat(which, flags, 0o707);
        let fout = run_fl_fchmodat(which, flags, 0o707);
        assert_eq!(
            fout, gout,
            "fchmodat [{label}]: fl=(rc={},errno={},mode={:04o}) glibc=(rc={},errno={},mode={:04o})",
            fout.0, fout.1, fout.2, gout.0, gout.1, gout.2
        );
    }
}

/// The specific defect, asserted as a positive fact rather than only as
/// fl==glibc: chmod through a symlink with NOFOLLOW must leave the target alone.
/// Stated separately so that if BOTH sides ever regressed together, this still
/// fails.
#[test]
fn fchmodat_nofollow_never_touches_the_symlink_target() {
    let t = tree("inv");
    let p = cpath(&t.link);
    let before = mode_of(&t.target);
    let rc = unsafe {
        frankenlibc_abi::unistd_abi::fchmodat(
            libc::AT_FDCWD,
            p.as_ptr(),
            0o707,
            AT_SYMLINK_NOFOLLOW,
        )
    };
    let after = mode_of(&t.target);
    assert_eq!(before, 0o644, "fixture should start at 0644");
    assert_eq!(
        after, before,
        "fchmodat(AT_SYMLINK_NOFOLLOW) on a symlink modified its TARGET \
         ({before:04o} -> {after:04o}); the flag was dropped"
    );
    assert_eq!(rc, -1, "Linux cannot chmod a symlink, so this must fail");
    let _ = std::fs::remove_dir_all(&t.dir);
}

#[test]
fn lchmod_matches_glibc_and_spares_the_target() {
    // glibc arm
    let gt = tree("lg");
    let gp = cpath(&gt.link);
    unsafe { *g::__errno_location() = 0 };
    let g_rc = unsafe { g::lchmod(gp.as_ptr(), 0o777) };
    let g_err = if g_rc == 0 {
        0
    } else {
        unsafe { *g::__errno_location() }
    };
    let g_mode = mode_of(&gt.target);
    let _ = std::fs::remove_dir_all(&gt.dir);

    // fl arm
    let ft = tree("lf");
    let fp = cpath(&ft.link);
    unsafe { *g::__errno_location() = 0 };
    let f_rc = unsafe { frankenlibc_abi::glibc_internal_abi::lchmod(fp.as_ptr(), 0o777) };
    let f_err = if f_rc == 0 {
        0
    } else {
        unsafe { *g::__errno_location() }
    };
    let f_mode = mode_of(&ft.target);
    let _ = std::fs::remove_dir_all(&ft.dir);

    assert_eq!(
        (f_rc, f_err, f_mode),
        (g_rc, g_err, g_mode),
        "lchmod(symlink): fl=(rc={f_rc},errno={f_err},mode={f_mode:04o}) \
         glibc=(rc={g_rc},errno={g_err},mode={g_mode:04o})"
    );
    assert_eq!(
        f_mode, 0o644,
        "lchmod must not chmod the symlink's target"
    );
}
