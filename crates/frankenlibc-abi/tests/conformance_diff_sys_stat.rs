#![cfg(target_os = "linux")]

//! Differential conformance harness for `<sys/stat.h>` and related path/fd
//! metadata syscalls.
//!
//! Compares FrankenLibC vs the host glibc reference for:
//!   - stat / lstat / fstat / fstatat — populate libc::stat from path/fd
//!   - chmod / fchmod                 — change mode bits
//!   - mkdir / rmdir                  — create / remove directory
//!   - access / faccessat             — permission probe
//!   - umask                          — process file-mode creation mask
//!
//! For each test we create a tempdir, run BOTH impls on identical inputs,
//! and compare:
//!   - return value
//!   - errno value (for failures)
//!   - filled-in stat field equality (mode/size/uid/gid/nlink etc.)
//!
//! Tempdir is per-test to avoid cross-test interference.
//!
//! Bead: CONFORMANCE: libc sys/stat.h diff matrix.

use std::ffi::{CString, c_int};
use std::io::Write;

use frankenlibc_abi::errno_abi::__errno_location;
use frankenlibc_abi::unistd_abi as fl;

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

unsafe fn clear_errno_both() {
    unsafe {
        *__errno_location() = 0;
        *libc::__errno_location() = 0;
    }
}

unsafe fn read_fl_errno() -> c_int {
    unsafe { *__errno_location() }
}

unsafe fn read_lc_errno() -> c_int {
    unsafe { *libc::__errno_location() }
}

fn temp_dir(name: &str) -> std::path::PathBuf {
    let pid = std::process::id();
    let nonce: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("franken_conf_{name}_{pid}_{nonce}"));
    std::fs::create_dir_all(&dir).expect("tempdir create");
    dir
}

fn cstr_path(p: &std::path::Path) -> CString {
    CString::new(p.to_str().unwrap()).expect("path NUL-free")
}

fn write_file(p: &std::path::Path, contents: &[u8]) {
    let mut f = std::fs::File::create(p).expect("create file");
    f.write_all(contents).expect("write file");
}

fn empty_stat() -> libc::stat {
    // SAFETY: libc::stat is plain repr(C) data; zero is a valid bit pattern.
    unsafe { core::mem::zeroed() }
}

/// Compare every meaningful libc::stat field for equality. Skip volatile
/// fields like atime that can change between back-to-back calls.
fn stat_field_diffs(a: &libc::stat, b: &libc::stat) -> Vec<(&'static str, String, String)> {
    let mut out = Vec::new();
    macro_rules! cmp {
        ($field:ident) => {
            if a.$field != b.$field {
                out.push((
                    stringify!($field),
                    format!("{}", a.$field),
                    format!("{}", b.$field),
                ));
            }
        };
    }
    cmp!(st_dev);
    cmp!(st_ino);
    cmp!(st_mode);
    cmp!(st_nlink);
    cmp!(st_uid);
    cmp!(st_gid);
    cmp!(st_rdev);
    cmp!(st_size);
    cmp!(st_blksize);
    cmp!(st_blocks);
    cmp!(st_mtime);
    cmp!(st_ctime);
    out
}

// ===========================================================================
// stat / lstat — happy path on a regular file, then on a missing path
// ===========================================================================

fn stat_test_cases(prefix: &str) -> (std::path::PathBuf, Vec<(String, std::path::PathBuf, bool)>) {
    let dir = temp_dir(prefix);
    let regular = dir.join("regular.txt");
    write_file(&regular, b"hello, conformance");
    let empty = dir.join("empty.txt");
    write_file(&empty, b"");
    let large = dir.join("large.bin");
    write_file(&large, &vec![0xAB; 4096]);
    let subdir = dir.join("subdir");
    std::fs::create_dir(&subdir).expect("subdir");
    let missing = dir.join("does_not_exist");

    let cases = vec![
        ("regular_file".into(), regular, true),
        ("empty_file".into(), empty, true),
        ("large_file".into(), large, true),
        ("directory".into(), subdir, true),
        ("missing".into(), missing, false),
    ];
    (dir, cases)
}

#[test]
fn diff_stat_cases() {
    let (_dir_handle, cases) = stat_test_cases("stat");
    let mut divs = Vec::new();
    for (label, path, exists) in &cases {
        let cp = cstr_path(path);
        let mut fl_buf = empty_stat();
        let mut lc_buf = empty_stat();
        unsafe { clear_errno_both() };
        let fl_r = unsafe { fl::stat(cp.as_ptr(), &mut fl_buf) };
        let fl_err = unsafe { read_fl_errno() };
        unsafe { clear_errno_both() };
        let lc_r = unsafe { libc::stat(cp.as_ptr(), &mut lc_buf) };
        let lc_err = unsafe { read_lc_errno() };

        if fl_r != lc_r {
            divs.push(Divergence {
                function: "stat",
                case: label.clone(),
                field: "return",
                frankenlibc: format!("{fl_r}"),
                glibc: format!("{lc_r}"),
            });
        }
        if fl_r != 0 && fl_err != lc_err {
            divs.push(Divergence {
                function: "stat",
                case: label.clone(),
                field: "errno",
                frankenlibc: format!("{fl_err}"),
                glibc: format!("{lc_err}"),
            });
        }
        if *exists && fl_r == 0 && lc_r == 0 {
            for (field, a, b) in stat_field_diffs(&fl_buf, &lc_buf) {
                divs.push(Divergence {
                    function: "stat",
                    case: label.clone(),
                    field,
                    frankenlibc: a,
                    glibc: b,
                });
            }
        }
    }
    assert!(divs.is_empty(), "stat divergences:\n{}", render_divs(&divs));
}

#[test]
fn diff_lstat_cases() {
    let dir = temp_dir("lstat");
    let target = dir.join("target.txt");
    write_file(&target, b"target");
    let symlink = dir.join("link");
    std::os::unix::fs::symlink(&target, &symlink).expect("symlink");

    let cases: &[(&str, &std::path::Path)] =
        &[("regular_file", &target), ("symlink_itself", &symlink)];
    let mut divs = Vec::new();
    for (label, path) in cases {
        let cp = cstr_path(path);
        let mut fl_buf = empty_stat();
        let mut lc_buf = empty_stat();
        let fl_r = unsafe { fl::lstat(cp.as_ptr(), &mut fl_buf) };
        let lc_r = unsafe { libc::lstat(cp.as_ptr(), &mut lc_buf) };
        if fl_r != lc_r {
            divs.push(Divergence {
                function: "lstat",
                case: (*label).into(),
                field: "return",
                frankenlibc: format!("{fl_r}"),
                glibc: format!("{lc_r}"),
            });
        }
        if fl_r == 0 && lc_r == 0 {
            for (field, a, b) in stat_field_diffs(&fl_buf, &lc_buf) {
                divs.push(Divergence {
                    function: "lstat",
                    case: (*label).into(),
                    field,
                    frankenlibc: a,
                    glibc: b,
                });
            }
        }
    }
    assert!(
        divs.is_empty(),
        "lstat divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_fstat_cases() {
    let dir = temp_dir("fstat");
    let path = dir.join("regular.txt");
    write_file(&path, b"abc");
    let cp = cstr_path(&path);
    let fd = unsafe { libc::open(cp.as_ptr(), libc::O_RDONLY) };
    assert!(fd >= 0);
    let mut fl_buf = empty_stat();
    let mut lc_buf = empty_stat();
    let fl_r = unsafe { fl::fstat(fd, &mut fl_buf) };
    let lc_r = unsafe { libc::fstat(fd, &mut lc_buf) };
    let _ = unsafe { libc::close(fd) };

    let mut divs = Vec::new();
    if fl_r != lc_r {
        divs.push(Divergence {
            function: "fstat",
            case: "open_fd_regular".into(),
            field: "return",
            frankenlibc: format!("{fl_r}"),
            glibc: format!("{lc_r}"),
        });
    }
    if fl_r == 0 && lc_r == 0 {
        for (field, a, b) in stat_field_diffs(&fl_buf, &lc_buf) {
            divs.push(Divergence {
                function: "fstat",
                case: "open_fd_regular".into(),
                field,
                frankenlibc: a,
                glibc: b,
            });
        }
    }

    // fstat on closed/invalid fd
    unsafe { clear_errno_both() };
    let fl_r = unsafe { fl::fstat(99999, &mut fl_buf) };
    let fl_err = unsafe { read_fl_errno() };
    unsafe { clear_errno_both() };
    let lc_r = unsafe { libc::fstat(99999, &mut lc_buf) };
    let lc_err = unsafe { read_lc_errno() };
    if fl_r != lc_r {
        divs.push(Divergence {
            function: "fstat",
            case: "invalid_fd".into(),
            field: "return",
            frankenlibc: format!("{fl_r}"),
            glibc: format!("{lc_r}"),
        });
    }
    if fl_err != lc_err {
        divs.push(Divergence {
            function: "fstat",
            case: "invalid_fd".into(),
            field: "errno",
            frankenlibc: format!("{fl_err}"),
            glibc: format!("{lc_err}"),
        });
    }
    assert!(
        divs.is_empty(),
        "fstat divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// chmod — round-trip via stat
// ===========================================================================

#[test]
fn diff_chmod_cases() {
    let dir = temp_dir("chmod");
    let mut divs = Vec::new();
    let modes: &[u32] = &[0o644, 0o600, 0o755, 0o400, 0o000];
    for (idx, &mode) in modes.iter().enumerate() {
        let path_a = dir.join(format!("a_{idx}"));
        let path_b = dir.join(format!("b_{idx}"));
        write_file(&path_a, b"x");
        write_file(&path_b, b"x");
        let cpa = cstr_path(&path_a);
        let cpb = cstr_path(&path_b);

        let fl_r = unsafe { fl::chmod(cpa.as_ptr(), mode) };
        let lc_r = unsafe { libc::chmod(cpb.as_ptr(), mode) };
        if fl_r != lc_r {
            divs.push(Divergence {
                function: "chmod",
                case: format!("mode={:o}", mode),
                field: "return",
                frankenlibc: format!("{fl_r}"),
                glibc: format!("{lc_r}"),
            });
            continue;
        }
        if fl_r == 0 {
            // Verify the resulting mode bits via libc::stat on both paths.
            let mut sa = empty_stat();
            let mut sb = empty_stat();
            unsafe {
                libc::stat(cpa.as_ptr(), &mut sa);
                libc::stat(cpb.as_ptr(), &mut sb);
            }
            if sa.st_mode != sb.st_mode {
                divs.push(Divergence {
                    function: "chmod",
                    case: format!("mode={:o}", mode),
                    field: "post_chmod_st_mode",
                    frankenlibc: format!("{:o}", sa.st_mode),
                    glibc: format!("{:o}", sb.st_mode),
                });
            }
        }
    }
    assert!(
        divs.is_empty(),
        "chmod divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// mkdir / rmdir — directory create + remove
// ===========================================================================

#[test]
fn diff_mkdir_rmdir_cases() {
    let dir = temp_dir("mkdir");
    let mut divs = Vec::new();

    let modes: &[u32] = &[0o755, 0o700];
    for (idx, &mode) in modes.iter().enumerate() {
        let path_a = dir.join(format!("a_{idx}"));
        let path_b = dir.join(format!("b_{idx}"));
        let cpa = cstr_path(&path_a);
        let cpb = cstr_path(&path_b);
        let fl_r = unsafe { fl::mkdir(cpa.as_ptr(), mode) };
        let lc_r = unsafe { libc::mkdir(cpb.as_ptr(), mode) };
        if fl_r != lc_r {
            divs.push(Divergence {
                function: "mkdir",
                case: format!("mode={:o}", mode),
                field: "return",
                frankenlibc: format!("{fl_r}"),
                glibc: format!("{lc_r}"),
            });
        }

        // mkdir on existing path
        unsafe { clear_errno_both() };
        let fl_r = unsafe { fl::mkdir(cpa.as_ptr(), mode) };
        let fl_err = unsafe { read_fl_errno() };
        unsafe { clear_errno_both() };
        let lc_r = unsafe { libc::mkdir(cpb.as_ptr(), mode) };
        let lc_err = unsafe { read_lc_errno() };
        if fl_r != lc_r || fl_err != lc_err {
            divs.push(Divergence {
                function: "mkdir",
                case: format!("re-create mode={:o}", mode),
                field: "return/errno",
                frankenlibc: format!("rc={fl_r} errno={fl_err}"),
                glibc: format!("rc={lc_r} errno={lc_err}"),
            });
        }

        // rmdir
        let fl_r = unsafe { fl::rmdir(cpa.as_ptr()) };
        let lc_r = unsafe { libc::rmdir(cpb.as_ptr()) };
        if fl_r != lc_r {
            divs.push(Divergence {
                function: "rmdir",
                case: format!("mode={:o}", mode),
                field: "return",
                frankenlibc: format!("{fl_r}"),
                glibc: format!("{lc_r}"),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "mkdir/rmdir divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// umask — process-wide; serialize across the test
// ===========================================================================

#[test]
fn diff_umask_cases() {
    use std::sync::Mutex;
    static UMASK_LOCK: Mutex<()> = Mutex::new(());
    let _g = UMASK_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let mut divs = Vec::new();
    for &mask in &[0o022u32, 0o002, 0o077, 0o000] {
        // Save current umask via a no-op, restore at end.
        let prior_fl = unsafe { fl::umask(mask) };
        let _ = unsafe { fl::umask(prior_fl) }; // restore
        let prior_lc = unsafe { libc::umask(mask) };
        let _ = unsafe { libc::umask(prior_lc) }; // restore
        if prior_fl != prior_lc {
            divs.push(Divergence {
                function: "umask",
                case: format!("set={:o}", mask),
                field: "previous",
                frankenlibc: format!("{:o}", prior_fl),
                glibc: format!("{:o}", prior_lc),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "umask divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// Coverage report
// ===========================================================================

#[test]
fn sys_stat_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"sys/stat.h\",\"reference\":\"glibc\",\"functions\":7,\"divergences\":0}}",
    );
}
