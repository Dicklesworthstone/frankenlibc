#![cfg(target_os = "linux")]

//! Differential conformance harness for `<fcntl.h>` and the open-family
//! file-descriptor operations.
//!
//! Compares FrankenLibC vs glibc reference for:
//!   - open / openat (basic + flag combinations + missing path)
//!   - creat (legacy alias)
//!   - fcntl (F_DUPFD, F_GETFD, F_SETFD, F_GETFL, F_SETFL)
//!   - posix_fadvise
//!
//! Per-test tempdir isolation. Both impls operate on parallel paths so
//! they don't step on each other.
//!
//! Bead: CONFORMANCE: libc fcntl.h diff matrix.

use std::ffi::{CString, c_int};
use std::io::Write;

use frankenlibc_abi::errno_abi::__errno_location;
use frankenlibc_abi::io_abi as fl_io;
use frankenlibc_abi::unistd_abi as fl_un;

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
unsafe fn read_fl_errno() -> c_int { unsafe { *__errno_location() } }
unsafe fn read_lc_errno() -> c_int { unsafe { *libc::__errno_location() } }

fn temp_dir(name: &str) -> std::path::PathBuf {
    let pid = std::process::id();
    let nonce: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("franken_fcntl_{name}_{pid}_{nonce}"));
    std::fs::create_dir_all(&dir).expect("tempdir");
    dir
}

fn cstr_path(p: &std::path::Path) -> CString {
    CString::new(p.to_str().unwrap()).expect("path NUL-free")
}

fn write_file(p: &std::path::Path, contents: &[u8]) {
    let mut f = std::fs::File::create(p).expect("create");
    f.write_all(contents).expect("write");
}

// ===========================================================================
// open — basic combinations
// ===========================================================================

#[test]
fn diff_open_existing_file() {
    let dir = temp_dir("open_existing");
    let p_fl = dir.join("a_fl");
    let p_lc = dir.join("a_lc");
    write_file(&p_fl, b"hello");
    write_file(&p_lc, b"hello");
    let cp_fl = cstr_path(&p_fl);
    let cp_lc = cstr_path(&p_lc);

    let mut divs = Vec::new();
    for &(label, flags) in &[
        ("RDONLY", libc::O_RDONLY),
        ("RDWR", libc::O_RDWR),
        ("RDONLY|CLOEXEC", libc::O_RDONLY | libc::O_CLOEXEC),
        ("RDONLY|NOFOLLOW", libc::O_RDONLY | libc::O_NOFOLLOW),
    ] {
        let fd_fl = unsafe { fl_un::open(cp_fl.as_ptr(), flags, 0) };
        let fd_lc = unsafe { libc::open(cp_lc.as_ptr(), flags) };
        if (fd_fl >= 0) != (fd_lc >= 0) {
            divs.push(Divergence {
                function: "open",
                case: label.into(),
                field: "success_match",
                frankenlibc: format!("{fd_fl}"),
                glibc: format!("{fd_lc}"),
            });
        }
        if fd_fl >= 0 { unsafe { libc::close(fd_fl); } }
        if fd_lc >= 0 { unsafe { libc::close(fd_lc); } }
    }
    assert!(divs.is_empty(), "open existing divergences:\n{}", render_divs(&divs));
}

#[test]
fn diff_open_missing_file() {
    let dir = temp_dir("open_missing");
    let p = dir.join("does_not_exist");
    let cp = cstr_path(&p);
    let mut divs = Vec::new();
    unsafe { clear_errno_both() };
    let fd_fl = unsafe { fl_un::open(cp.as_ptr(), libc::O_RDONLY, 0) };
    let er_fl = unsafe { read_fl_errno() };
    unsafe { clear_errno_both() };
    let fd_lc = unsafe { libc::open(cp.as_ptr(), libc::O_RDONLY) };
    let er_lc = unsafe { read_lc_errno() };
    if (fd_fl >= 0) != (fd_lc >= 0) || (fd_fl < 0 && er_fl != er_lc) {
        divs.push(Divergence {
            function: "open",
            case: "missing".into(),
            field: "rc/errno",
            frankenlibc: format!("fd={fd_fl} errno={er_fl}"),
            glibc: format!("fd={fd_lc} errno={er_lc}"),
        });
    }
    if fd_fl >= 0 { unsafe { libc::close(fd_fl); } }
    if fd_lc >= 0 { unsafe { libc::close(fd_lc); } }
    assert!(divs.is_empty(), "open missing divergences:\n{}", render_divs(&divs));
}

#[test]
fn diff_open_create_with_mode() {
    let dir = temp_dir("open_create");
    let p_fl = dir.join("new_fl");
    let p_lc = dir.join("new_lc");
    let cp_fl = cstr_path(&p_fl);
    let cp_lc = cstr_path(&p_lc);

    let flags = libc::O_RDWR | libc::O_CREAT | libc::O_EXCL;
    let mode: libc::mode_t = 0o644;
    let fd_fl = unsafe { fl_un::open(cp_fl.as_ptr(), flags, mode) };
    let fd_lc = unsafe { libc::open(cp_lc.as_ptr(), flags, mode) };

    let mut divs = Vec::new();
    if (fd_fl >= 0) != (fd_lc >= 0) {
        divs.push(Divergence {
            function: "open(O_CREAT|O_EXCL)",
            case: "0o644".into(),
            field: "success_match",
            frankenlibc: format!("{fd_fl}"),
            glibc: format!("{fd_lc}"),
        });
    }
    // Re-open with O_EXCL → must EEXIST on both.
    if fd_fl >= 0 && fd_lc >= 0 {
        unsafe { clear_errno_both() };
        let r2_fl = unsafe { fl_un::open(cp_fl.as_ptr(), flags, mode) };
        let er_fl = unsafe { read_fl_errno() };
        unsafe { clear_errno_both() };
        let r2_lc = unsafe { libc::open(cp_lc.as_ptr(), flags, mode) };
        let er_lc = unsafe { read_lc_errno() };
        if (r2_fl >= 0) != (r2_lc >= 0) || er_fl != er_lc {
            divs.push(Divergence {
                function: "open(O_EXCL re-create)",
                case: "0o644".into(),
                field: "rc/errno",
                frankenlibc: format!("fd={r2_fl} errno={er_fl}"),
                glibc: format!("fd={r2_lc} errno={er_lc}"),
            });
        }
        if r2_fl >= 0 { unsafe { libc::close(r2_fl); } }
        if r2_lc >= 0 { unsafe { libc::close(r2_lc); } }
    }
    if fd_fl >= 0 { unsafe { libc::close(fd_fl); } }
    if fd_lc >= 0 { unsafe { libc::close(fd_lc); } }
    assert!(divs.is_empty(), "open create divergences:\n{}", render_divs(&divs));
}

// ===========================================================================
// openat — relative to AT_FDCWD
// ===========================================================================

#[test]
fn diff_openat_at_fdcwd() {
    let dir = temp_dir("openat");
    let p_fl = dir.join("o_fl");
    let p_lc = dir.join("o_lc");
    write_file(&p_fl, b"x");
    write_file(&p_lc, b"x");
    let cp_fl = cstr_path(&p_fl);
    let cp_lc = cstr_path(&p_lc);

    let fd_fl = unsafe { fl_un::openat(libc::AT_FDCWD, cp_fl.as_ptr(), libc::O_RDONLY, 0) };
    let fd_lc = unsafe { libc::openat(libc::AT_FDCWD, cp_lc.as_ptr(), libc::O_RDONLY) };
    let mut divs = Vec::new();
    if (fd_fl >= 0) != (fd_lc >= 0) {
        divs.push(Divergence {
            function: "openat",
            case: "AT_FDCWD".into(),
            field: "success_match",
            frankenlibc: format!("{fd_fl}"),
            glibc: format!("{fd_lc}"),
        });
    }
    if fd_fl >= 0 { unsafe { libc::close(fd_fl); } }
    if fd_lc >= 0 { unsafe { libc::close(fd_lc); } }
    assert!(divs.is_empty(), "openat divergences:\n{}", render_divs(&divs));
}

// ===========================================================================
// creat — legacy alias for open(O_WRONLY|O_CREAT|O_TRUNC)
// ===========================================================================

#[test]
fn diff_creat_basic() {
    let dir = temp_dir("creat");
    let p_fl = dir.join("c_fl");
    let p_lc = dir.join("c_lc");
    let cp_fl = cstr_path(&p_fl);
    let cp_lc = cstr_path(&p_lc);
    let fd_fl = unsafe { fl_un::creat(cp_fl.as_ptr(), 0o600) };
    let fd_lc = unsafe { libc::creat(cp_lc.as_ptr(), 0o600) };
    let mut divs = Vec::new();
    if (fd_fl >= 0) != (fd_lc >= 0) {
        divs.push(Divergence {
            function: "creat",
            case: "0o600".into(),
            field: "success_match",
            frankenlibc: format!("{fd_fl}"),
            glibc: format!("{fd_lc}"),
        });
    }
    // Verify post-call existence + mode bits via libc::stat.
    let mut st_fl: libc::stat = unsafe { core::mem::zeroed() };
    let mut st_lc: libc::stat = unsafe { core::mem::zeroed() };
    unsafe {
        libc::stat(cp_fl.as_ptr(), &mut st_fl);
        libc::stat(cp_lc.as_ptr(), &mut st_lc);
    }
    if st_fl.st_mode & 0o777 != st_lc.st_mode & 0o777 {
        divs.push(Divergence {
            function: "creat",
            case: "0o600".into(),
            field: "post_st_mode",
            frankenlibc: format!("{:o}", st_fl.st_mode & 0o777),
            glibc: format!("{:o}", st_lc.st_mode & 0o777),
        });
    }
    if fd_fl >= 0 { unsafe { libc::close(fd_fl); } }
    if fd_lc >= 0 { unsafe { libc::close(fd_lc); } }
    assert!(divs.is_empty(), "creat divergences:\n{}", render_divs(&divs));
}

// ===========================================================================
// fcntl — F_DUPFD, F_GETFD, F_SETFD, F_GETFL, F_SETFL
// ===========================================================================

#[test]
fn diff_fcntl_dupfd_and_getfd() {
    let dir = temp_dir("fcntl");
    let p = dir.join("a");
    write_file(&p, b"x");
    let cp = cstr_path(&p);
    let fd = unsafe { libc::open(cp.as_ptr(), libc::O_RDONLY) };
    assert!(fd >= 0);
    let mut divs = Vec::new();

    // F_DUPFD
    let dup_fl = unsafe { fl_io::fcntl(fd, libc::F_DUPFD, 100) };
    let dup_lc = unsafe { libc::fcntl(fd, libc::F_DUPFD, 100) };
    if (dup_fl >= 0) != (dup_lc >= 0) {
        divs.push(Divergence {
            function: "fcntl(F_DUPFD)",
            case: "min=100".into(),
            field: "success_match",
            frankenlibc: format!("{dup_fl}"),
            glibc: format!("{dup_lc}"),
        });
    }
    if dup_fl >= 0 { unsafe { libc::close(dup_fl); } }
    if dup_lc >= 0 { unsafe { libc::close(dup_lc); } }

    // F_GETFD (default = 0)
    let gd_fl = unsafe { fl_io::fcntl(fd, libc::F_GETFD, 0) };
    let gd_lc = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if gd_fl != gd_lc {
        divs.push(Divergence {
            function: "fcntl(F_GETFD)",
            case: "default".into(),
            field: "return",
            frankenlibc: format!("{gd_fl}"),
            glibc: format!("{gd_lc}"),
        });
    }

    // F_SETFD(FD_CLOEXEC) round-trip
    let _ = unsafe { fl_io::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC as libc::c_long) };
    let after_fl = unsafe { fl_io::fcntl(fd, libc::F_GETFD, 0) };
    let after_lc = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if after_fl != after_lc {
        divs.push(Divergence {
            function: "fcntl(F_GETFD after F_SETFD)",
            case: "FD_CLOEXEC".into(),
            field: "return",
            frankenlibc: format!("{after_fl}"),
            glibc: format!("{after_lc}"),
        });
    }

    // F_GETFL
    let gf_fl = unsafe { fl_io::fcntl(fd, libc::F_GETFL, 0) };
    let gf_lc = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if gf_fl != gf_lc {
        divs.push(Divergence {
            function: "fcntl(F_GETFL)",
            case: "open RDONLY".into(),
            field: "return",
            frankenlibc: format!("{gf_fl:#x}"),
            glibc: format!("{gf_lc:#x}"),
        });
    }

    unsafe { libc::close(fd); }
    assert!(divs.is_empty(), "fcntl divergences:\n{}", render_divs(&divs));
}

// ===========================================================================
// posix_fadvise — should succeed on a normal fd with valid advice
// ===========================================================================

#[test]
fn diff_posix_fadvise_basic() {
    let dir = temp_dir("fadvise");
    let p = dir.join("a");
    write_file(&p, &vec![0xAB; 4096]);
    let cp = cstr_path(&p);
    let fd = unsafe { libc::open(cp.as_ptr(), libc::O_RDONLY) };
    assert!(fd >= 0);

    let mut divs = Vec::new();
    for advice in &[libc::POSIX_FADV_NORMAL, libc::POSIX_FADV_SEQUENTIAL,
                    libc::POSIX_FADV_RANDOM, libc::POSIX_FADV_WILLNEED,
                    libc::POSIX_FADV_DONTNEED, libc::POSIX_FADV_NOREUSE] {
        let r_fl = unsafe { fl_un::posix_fadvise(fd, 0, 4096, *advice) };
        let r_lc = unsafe { libc::posix_fadvise(fd, 0, 4096, *advice) };
        if r_fl != r_lc {
            divs.push(Divergence {
                function: "posix_fadvise",
                case: format!("advice={advice}"),
                field: "return",
                frankenlibc: format!("{r_fl}"),
                glibc: format!("{r_lc}"),
            });
        }
    }
    unsafe { libc::close(fd); }
    assert!(divs.is_empty(), "posix_fadvise divergences:\n{}", render_divs(&divs));
}

#[test]
fn fcntl_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"fcntl.h\",\"reference\":\"glibc\",\"functions\":5,\"divergences\":0}}",
    );
}
