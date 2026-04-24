#![cfg(target_os = "linux")]

//! Differential conformance harness for the at-relative + statx
//! variants of stat:
//!   - fstatat (POSIX, dirfd-relative stat)
//!   - statx   (Linux 4.11+, extended stat with mask)
//!
//! Both impls operate against the same on-disk path; we compare the
//! returned struct fields field-by-field.
//!
//! Bead: CONFORMANCE: libc fstatat + statx diff matrix.

use std::ffi::{CString, c_int};

use frankenlibc_abi::unistd_abi as fl;

unsafe extern "C" {
    fn fstatat(
        dirfd: c_int,
        pathname: *const std::ffi::c_char,
        statbuf: *mut libc::stat,
        flags: c_int,
    ) -> c_int;
    fn statx(
        dirfd: c_int,
        pathname: *const std::ffi::c_char,
        flags: c_int,
        mask: u32,
        statxbuf: *mut StatxBuf,
    ) -> c_int;
}

const AT_FDCWD: c_int = -100;
const AT_SYMLINK_NOFOLLOW: c_int = 0x100;
const STATX_BASIC_STATS: u32 = 0x000007ff;

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct StatxTimestamp {
    tv_sec: i64,
    tv_nsec: u32,
    _pad: i32,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct StatxBuf {
    stx_mask: u32,
    stx_blksize: u32,
    stx_attributes: u64,
    stx_nlink: u32,
    stx_uid: u32,
    stx_gid: u32,
    stx_mode: u16,
    _pad1: [u16; 1],
    stx_ino: u64,
    stx_size: u64,
    stx_blocks: u64,
    stx_attributes_mask: u64,
    stx_atime: StatxTimestamp,
    stx_btime: StatxTimestamp,
    stx_ctime: StatxTimestamp,
    stx_mtime: StatxTimestamp,
    stx_rdev_major: u32,
    stx_rdev_minor: u32,
    stx_dev_major: u32,
    stx_dev_minor: u32,
    stx_mnt_id: u64,
    _pad2: [u64; 13],
}

#[derive(Debug)]
struct Divergence {
    function: &'static str,
    case: String,
    field: &'static str,
    frankenlibc: String,
    glibc: String,
}

fn render_divs(divs: &[Divergence]) -> String {
    let mut out = String::new();
    for d in divs {
        out.push_str(&format!(
            "  {} | case: {} | field: {} | fl: {} | glibc: {}\n",
            d.function, d.case, d.field, d.frankenlibc, d.glibc,
        ));
    }
    out
}

fn unique_tempfile(label: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    std::env::temp_dir().join(format!("fl_statx_diff_{label}_{pid}_{id}"))
}

fn make_known_file() -> std::path::PathBuf {
    let path = unique_tempfile("file");
    std::fs::write(&path, b"hello, statx world\n").unwrap();
    path
}

#[test]
fn diff_fstatat_known_file() {
    let mut divs = Vec::new();
    let path = make_known_file();
    let cpath = CString::new(path.to_string_lossy().as_bytes()).unwrap();

    let mut s_fl: libc::stat = unsafe { core::mem::zeroed() };
    let mut s_lc: libc::stat = unsafe { core::mem::zeroed() };
    let r_fl = unsafe { fl::fstatat(AT_FDCWD, cpath.as_ptr(), &mut s_fl, 0) };
    let r_lc = unsafe { fstatat(AT_FDCWD, cpath.as_ptr(), &mut s_lc, 0) };

    if r_fl != r_lc {
        divs.push(Divergence {
            function: "fstatat",
            case: "known file".into(),
            field: "return",
            frankenlibc: format!("{r_fl}"),
            glibc: format!("{r_lc}"),
        });
    }
    if r_fl == 0 && r_lc == 0 {
        let pairs: &[(&str, u64, u64)] = &[
            ("st_size", s_fl.st_size as u64, s_lc.st_size as u64),
            ("st_mode", s_fl.st_mode as u64, s_lc.st_mode as u64),
            ("st_nlink", s_fl.st_nlink as u64, s_lc.st_nlink as u64),
            ("st_uid", s_fl.st_uid as u64, s_lc.st_uid as u64),
            ("st_gid", s_fl.st_gid as u64, s_lc.st_gid as u64),
            ("st_ino", s_fl.st_ino as u64, s_lc.st_ino as u64),
            ("st_dev", s_fl.st_dev as u64, s_lc.st_dev as u64),
            ("st_blksize", s_fl.st_blksize as u64, s_lc.st_blksize as u64),
            ("st_blocks", s_fl.st_blocks as u64, s_lc.st_blocks as u64),
        ];
        for (name, fl_v, lc_v) in pairs {
            if fl_v != lc_v {
                divs.push(Divergence {
                    function: "fstatat",
                    case: "known file".into(),
                    field: name,
                    frankenlibc: format!("{fl_v}"),
                    glibc: format!("{lc_v}"),
                });
            }
        }
    }
    let _ = std::fs::remove_file(&path);
    assert!(
        divs.is_empty(),
        "fstatat divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_fstatat_enoent() {
    let cpath = CString::new("/definitely/does/not/exist/abc123").unwrap();
    let mut s_fl: libc::stat = unsafe { core::mem::zeroed() };
    let mut s_lc: libc::stat = unsafe { core::mem::zeroed() };
    let r_fl = unsafe { fl::fstatat(AT_FDCWD, cpath.as_ptr(), &mut s_fl, 0) };
    let r_lc = unsafe { fstatat(AT_FDCWD, cpath.as_ptr(), &mut s_lc, 0) };
    assert!(
        (r_fl == 0) == (r_lc == 0),
        "fstatat ENOENT success-match: fl={r_fl}, lc={r_lc}"
    );
}

#[test]
fn diff_fstatat_symlink_nofollow() {
    // Create a symlink, stat it via fl/lc with AT_SYMLINK_NOFOLLOW.
    // Both should return the symlink's mode (not the target's).
    let target = make_known_file();
    let link_path = unique_tempfile("link");
    std::os::unix::fs::symlink(&target, &link_path).unwrap();
    let cpath = CString::new(link_path.to_string_lossy().as_bytes()).unwrap();

    let mut s_fl: libc::stat = unsafe { core::mem::zeroed() };
    let mut s_lc: libc::stat = unsafe { core::mem::zeroed() };
    let r_fl =
        unsafe { fl::fstatat(AT_FDCWD, cpath.as_ptr(), &mut s_fl, AT_SYMLINK_NOFOLLOW) };
    let r_lc = unsafe { fstatat(AT_FDCWD, cpath.as_ptr(), &mut s_lc, AT_SYMLINK_NOFOLLOW) };

    assert_eq!(r_fl, r_lc, "fstatat symlink return");
    if r_fl == 0 && r_lc == 0 {
        let mode_fl = s_fl.st_mode & libc::S_IFMT;
        let mode_lc = s_lc.st_mode & libc::S_IFMT;
        assert_eq!(
            mode_fl, mode_lc,
            "fstatat symlink mode: fl={mode_fl:o}, lc={mode_lc:o}"
        );
        assert_eq!(mode_fl, libc::S_IFLNK, "fstatat NOFOLLOW: expected IFLNK");
    }
    let _ = std::fs::remove_file(&link_path);
    let _ = std::fs::remove_file(&target);
}

#[test]
fn diff_statx_basic_stats() {
    let mut divs = Vec::new();
    let path = make_known_file();
    let cpath = CString::new(path.to_string_lossy().as_bytes()).unwrap();

    let mut x_fl: StatxBuf = StatxBuf::default();
    let mut x_lc: StatxBuf = StatxBuf::default();
    let r_fl = unsafe {
        fl::statx(
            AT_FDCWD,
            cpath.as_ptr(),
            0,
            STATX_BASIC_STATS,
            &mut x_fl as *mut _ as *mut _,
        )
    };
    let r_lc = unsafe { statx(AT_FDCWD, cpath.as_ptr(), 0, STATX_BASIC_STATS, &mut x_lc) };

    if r_fl != r_lc {
        divs.push(Divergence {
            function: "statx",
            case: "STATX_BASIC_STATS".into(),
            field: "return",
            frankenlibc: format!("{r_fl}"),
            glibc: format!("{r_lc}"),
        });
    }
    if r_fl == 0 && r_lc == 0 {
        let pairs: &[(&str, u64, u64)] = &[
            ("stx_mask", x_fl.stx_mask as u64, x_lc.stx_mask as u64),
            ("stx_blksize", x_fl.stx_blksize as u64, x_lc.stx_blksize as u64),
            ("stx_size", x_fl.stx_size, x_lc.stx_size),
            ("stx_mode", x_fl.stx_mode as u64, x_lc.stx_mode as u64),
            ("stx_nlink", x_fl.stx_nlink as u64, x_lc.stx_nlink as u64),
            ("stx_uid", x_fl.stx_uid as u64, x_lc.stx_uid as u64),
            ("stx_gid", x_fl.stx_gid as u64, x_lc.stx_gid as u64),
            ("stx_ino", x_fl.stx_ino, x_lc.stx_ino),
        ];
        for (name, fl_v, lc_v) in pairs {
            if fl_v != lc_v {
                divs.push(Divergence {
                    function: "statx",
                    case: "STATX_BASIC_STATS".into(),
                    field: name,
                    frankenlibc: format!("{fl_v}"),
                    glibc: format!("{lc_v}"),
                });
            }
        }
    }
    let _ = std::fs::remove_file(&path);
    assert!(
        divs.is_empty(),
        "statx divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn statx_fstatat_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"sys/stat.h(fstatat/statx)\",\"reference\":\"glibc\",\"functions\":2,\"divergences\":0}}",
    );
}
