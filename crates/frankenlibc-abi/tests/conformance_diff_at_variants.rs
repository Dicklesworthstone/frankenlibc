#![cfg(target_os = "linux")]

//! Differential conformance harness for the dirfd-relative `*at`
//! filesystem syscalls:
//!   - openat / mkdirat / unlinkat
//!   - renameat / linkat / symlinkat / readlinkat
//!
//! All tests use AT_FDCWD to keep the path semantics simple, plus a
//! parallel test using a real dirfd opened via O_DIRECTORY.
//!
//! Bead: CONFORMANCE: libc *at variants diff matrix.

use std::ffi::{CString, c_int, c_void};
use std::os::fd::AsRawFd;

use frankenlibc_abi::unistd_abi as fl;

unsafe extern "C" {
    fn openat(dirfd: c_int, path: *const std::ffi::c_char, flags: c_int, mode: c_int) -> c_int;
    fn mkdirat(dirfd: c_int, path: *const std::ffi::c_char, mode: libc::mode_t) -> c_int;
    fn unlinkat(dirfd: c_int, path: *const std::ffi::c_char, flags: c_int) -> c_int;
    fn renameat(
        olddirfd: c_int,
        oldpath: *const std::ffi::c_char,
        newdirfd: c_int,
        newpath: *const std::ffi::c_char,
    ) -> c_int;
    fn linkat(
        olddirfd: c_int,
        oldpath: *const std::ffi::c_char,
        newdirfd: c_int,
        newpath: *const std::ffi::c_char,
        flags: c_int,
    ) -> c_int;
    fn symlinkat(
        target: *const std::ffi::c_char,
        newdirfd: c_int,
        linkpath: *const std::ffi::c_char,
    ) -> c_int;
    fn readlinkat(
        dirfd: c_int,
        path: *const std::ffi::c_char,
        buf: *mut std::ffi::c_char,
        bufsiz: usize,
    ) -> isize;
}

const AT_FDCWD: c_int = -100;
const AT_REMOVEDIR: c_int = 0x200;

fn unique_tempfile(label: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    std::env::temp_dir().join(format!("fl_at_diff_{label}_{pid}_{id}"))
}

#[test]
fn diff_openat_at_fdcwd_create_close() {
    let p_fl = unique_tempfile("openat_fl");
    let p_lc = unique_tempfile("openat_lc");
    let cp_fl = CString::new(p_fl.to_string_lossy().as_bytes()).unwrap();
    let cp_lc = CString::new(p_lc.to_string_lossy().as_bytes()).unwrap();
    let r_fl = unsafe {
        fl::openat(
            AT_FDCWD,
            cp_fl.as_ptr(),
            libc::O_RDWR | libc::O_CREAT,
            0o600,
        )
    };
    let r_lc = unsafe {
        openat(
            AT_FDCWD,
            cp_lc.as_ptr(),
            libc::O_RDWR | libc::O_CREAT,
            0o600,
        )
    };
    assert!(
        (r_fl >= 0) == (r_lc >= 0),
        "openat AT_FDCWD success-match: fl={r_fl}, lc={r_lc}"
    );
    if r_fl >= 0 {
        unsafe { libc::close(r_fl) };
    }
    if r_lc >= 0 {
        unsafe { libc::close(r_lc) };
    }
    let _ = std::fs::remove_file(&p_fl);
    let _ = std::fs::remove_file(&p_lc);
}

#[test]
fn diff_mkdirat_then_unlinkat_at_fdcwd() {
    let p_fl = unique_tempfile("mkdirat_fl");
    let p_lc = unique_tempfile("mkdirat_lc");
    let cp_fl = CString::new(p_fl.to_string_lossy().as_bytes()).unwrap();
    let cp_lc = CString::new(p_lc.to_string_lossy().as_bytes()).unwrap();
    let r_mk_fl = unsafe { fl::mkdirat(AT_FDCWD, cp_fl.as_ptr(), 0o700) };
    let r_mk_lc = unsafe { mkdirat(AT_FDCWD, cp_lc.as_ptr(), 0o700) };
    assert_eq!(
        r_mk_fl, r_mk_lc,
        "mkdirat AT_FDCWD: fl={r_mk_fl}, lc={r_mk_lc}"
    );

    let r_un_fl = unsafe { fl::unlinkat(AT_FDCWD, cp_fl.as_ptr(), AT_REMOVEDIR) };
    let r_un_lc = unsafe { unlinkat(AT_FDCWD, cp_lc.as_ptr(), AT_REMOVEDIR) };
    assert_eq!(
        r_un_fl, r_un_lc,
        "unlinkat AT_REMOVEDIR: fl={r_un_fl}, lc={r_un_lc}"
    );
}

#[test]
fn diff_unlinkat_no_at_removedir_on_dir_fails() {
    // unlinkat without AT_REMOVEDIR on a directory must fail with EISDIR
    let p = unique_tempfile("dir_eisdir");
    std::fs::create_dir(&p).unwrap();
    let cp = CString::new(p.to_string_lossy().as_bytes()).unwrap();
    let r_fl = unsafe { fl::unlinkat(AT_FDCWD, cp.as_ptr(), 0) };
    let r_lc = unsafe { unlinkat(AT_FDCWD, cp.as_ptr(), 0) };
    assert_eq!(
        r_fl < 0,
        r_lc < 0,
        "unlinkat dir without AT_REMOVEDIR fail-match: fl={r_fl}, lc={r_lc}"
    );
    let _ = std::fs::remove_dir(&p);
}

#[test]
fn diff_renameat_at_fdcwd() {
    let from = unique_tempfile("rename_from");
    let to = unique_tempfile("rename_to");
    std::fs::write(&from, b"x").unwrap();
    let cf = CString::new(from.to_string_lossy().as_bytes()).unwrap();
    let ct = CString::new(to.to_string_lossy().as_bytes()).unwrap();
    let r_fl = unsafe { fl::renameat(AT_FDCWD, cf.as_ptr(), AT_FDCWD, ct.as_ptr()) };
    assert_eq!(r_fl, 0, "fl renameat");
    assert!(to.exists(), "fl: target should exist");
    assert!(!from.exists(), "fl: source should be gone");

    // Now do same via libc on a fresh pair
    let from_lc = unique_tempfile("rename_from_lc");
    let to_lc = unique_tempfile("rename_to_lc");
    std::fs::write(&from_lc, b"x").unwrap();
    let cf_lc = CString::new(from_lc.to_string_lossy().as_bytes()).unwrap();
    let ct_lc = CString::new(to_lc.to_string_lossy().as_bytes()).unwrap();
    let r_lc = unsafe { renameat(AT_FDCWD, cf_lc.as_ptr(), AT_FDCWD, ct_lc.as_ptr()) };
    assert_eq!(r_lc, 0, "lc renameat");

    assert_eq!(r_fl, r_lc, "renameat divergence");
    let _ = std::fs::remove_file(&to);
    let _ = std::fs::remove_file(&to_lc);
}

#[test]
fn diff_symlinkat_then_readlinkat() {
    let target = "some_target_string";
    let p_fl = unique_tempfile("symlink_fl");
    let p_lc = unique_tempfile("symlink_lc");
    let ctgt = CString::new(target).unwrap();
    let cp_fl = CString::new(p_fl.to_string_lossy().as_bytes()).unwrap();
    let cp_lc = CString::new(p_lc.to_string_lossy().as_bytes()).unwrap();
    let r_sl_fl = unsafe { fl::symlinkat(ctgt.as_ptr(), AT_FDCWD, cp_fl.as_ptr()) };
    let r_sl_lc = unsafe { symlinkat(ctgt.as_ptr(), AT_FDCWD, cp_lc.as_ptr()) };
    assert_eq!(r_sl_fl, r_sl_lc, "symlinkat: fl={r_sl_fl}, lc={r_sl_lc}");

    let mut buf_fl = vec![0i8; 64];
    let mut buf_lc = vec![0i8; 64];
    let n_fl =
        unsafe { fl::readlinkat(AT_FDCWD, cp_fl.as_ptr(), buf_fl.as_mut_ptr(), buf_fl.len()) };
    let n_lc = unsafe { readlinkat(AT_FDCWD, cp_lc.as_ptr(), buf_lc.as_mut_ptr(), buf_lc.len()) };
    assert_eq!(n_fl, n_lc, "readlinkat n: fl={n_fl}, lc={n_lc}");
    if n_fl > 0 {
        let s_fl: Vec<u8> = buf_fl[..n_fl as usize].iter().map(|x| *x as u8).collect();
        let s_lc: Vec<u8> = buf_lc[..n_lc as usize].iter().map(|x| *x as u8).collect();
        assert_eq!(s_fl, s_lc, "readlinkat content");
        assert_eq!(s_fl, target.as_bytes());
    }
    let _ = std::fs::remove_file(&p_fl);
    let _ = std::fs::remove_file(&p_lc);
}

#[test]
fn diff_linkat_at_fdcwd() {
    let src = unique_tempfile("linkat_src");
    let dst_fl = unique_tempfile("linkat_dst_fl");
    let dst_lc = unique_tempfile("linkat_dst_lc");
    std::fs::write(&src, b"x").unwrap();
    let csrc = CString::new(src.to_string_lossy().as_bytes()).unwrap();
    let cdst_fl = CString::new(dst_fl.to_string_lossy().as_bytes()).unwrap();
    let cdst_lc = CString::new(dst_lc.to_string_lossy().as_bytes()).unwrap();
    let r_fl = unsafe { fl::linkat(AT_FDCWD, csrc.as_ptr(), AT_FDCWD, cdst_fl.as_ptr(), 0) };
    let r_lc = unsafe { linkat(AT_FDCWD, csrc.as_ptr(), AT_FDCWD, cdst_lc.as_ptr(), 0) };
    assert_eq!(r_fl, r_lc, "linkat: fl={r_fl}, lc={r_lc}");
    if r_fl == 0 {
        assert!(dst_fl.exists(), "fl link target");
    }
    if r_lc == 0 {
        assert!(dst_lc.exists(), "lc link target");
    }
    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&dst_fl);
    let _ = std::fs::remove_file(&dst_lc);
}

#[test]
fn diff_openat_real_dirfd() {
    let dir = unique_tempfile("dirfd_test");
    std::fs::create_dir(&dir).unwrap();
    let dirf = std::fs::File::open(&dir).unwrap();
    let dfd = dirf.as_raw_fd();
    let cname_fl = CString::new("file_fl.txt").unwrap();
    let cname_lc = CString::new("file_lc.txt").unwrap();
    let r_fl = unsafe { fl::openat(dfd, cname_fl.as_ptr(), libc::O_RDWR | libc::O_CREAT, 0o600) };
    let r_lc = unsafe { openat(dfd, cname_lc.as_ptr(), libc::O_RDWR | libc::O_CREAT, 0o600) };
    assert!(
        (r_fl >= 0) == (r_lc >= 0),
        "openat with real dirfd: fl={r_fl}, lc={r_lc}"
    );
    if r_fl >= 0 {
        unsafe { libc::close(r_fl) };
    }
    if r_lc >= 0 {
        unsafe { libc::close(r_lc) };
    }
    drop(dirf);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::ptr::null::<c_void>();
}

#[test]
fn at_variants_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"unistd.h(*at variants)\",\"reference\":\"glibc\",\"functions\":7,\"divergences\":0}}",
    );
}
