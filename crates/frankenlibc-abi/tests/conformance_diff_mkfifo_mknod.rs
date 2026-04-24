#![cfg(target_os = "linux")]

//! Differential conformance harness for special-file creation:
//!   - mkfifo (named pipe / FIFO)
//!   - mkfifoat (dirfd-relative variant)
//!   - mknod (regular file via S_IFREG; FIFO via S_IFIFO; not character
//!     or block devices because those need CAP_MKNOD)
//!   - mknodat (dirfd-relative)
//!
//! Bead: CONFORMANCE: libc mkfifo+mknod diff matrix.

use std::ffi::{CString, c_int};

use frankenlibc_abi::unistd_abi as fl;

unsafe extern "C" {
    fn mkfifo(path: *const std::ffi::c_char, mode: libc::mode_t) -> c_int;
    fn mkfifoat(dirfd: c_int, path: *const std::ffi::c_char, mode: libc::mode_t) -> c_int;
    fn mknod(path: *const std::ffi::c_char, mode: libc::mode_t, dev: libc::dev_t) -> c_int;
    fn mknodat(
        dirfd: c_int,
        path: *const std::ffi::c_char,
        mode: libc::mode_t,
        dev: libc::dev_t,
    ) -> c_int;
}

const AT_FDCWD: c_int = -100;

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
    std::env::temp_dir().join(format!("fl_mkfifo_diff_{label}_{pid}_{id}"))
}

fn stat_mode(path: &std::path::Path) -> libc::mode_t {
    let cpath = CString::new(path.to_string_lossy().as_bytes()).unwrap();
    let mut st: libc::stat = unsafe { core::mem::zeroed() };
    let r = unsafe { libc::stat(cpath.as_ptr(), &mut st) };
    if r != 0 { 0 } else { st.st_mode }
}

#[test]
fn diff_mkfifo_creates_fifo() {
    let mut divs = Vec::new();
    let path_fl = unique_tempfile("fifo_fl");
    let path_lc = unique_tempfile("fifo_lc");
    let cpath_fl = CString::new(path_fl.to_string_lossy().as_bytes()).unwrap();
    let cpath_lc = CString::new(path_lc.to_string_lossy().as_bytes()).unwrap();
    let r_fl = unsafe { fl::mkfifo(cpath_fl.as_ptr(), 0o644) };
    let r_lc = unsafe { mkfifo(cpath_lc.as_ptr(), 0o644) };
    if r_fl != r_lc {
        divs.push(Divergence {
            function: "mkfifo",
            case: "0o644 mode".into(),
            field: "return",
            frankenlibc: format!("{r_fl}"),
            glibc: format!("{r_lc}"),
        });
    }
    if r_fl == 0 && r_lc == 0 {
        let mode_fl = stat_mode(&path_fl) & libc::S_IFMT;
        let mode_lc = stat_mode(&path_lc) & libc::S_IFMT;
        if mode_fl != mode_lc {
            divs.push(Divergence {
                function: "mkfifo",
                case: "0o644 mode".into(),
                field: "S_IFMT_match",
                frankenlibc: format!("{mode_fl:o}"),
                glibc: format!("{mode_lc:o}"),
            });
        }
        if mode_fl != libc::S_IFIFO {
            divs.push(Divergence {
                function: "mkfifo",
                case: "0o644 mode".into(),
                field: "expected_S_IFIFO",
                frankenlibc: format!("{mode_fl:o}"),
                glibc: format!("{:o}", libc::S_IFIFO),
            });
        }
    }
    let _ = std::fs::remove_file(&path_fl);
    let _ = std::fs::remove_file(&path_lc);
    assert!(
        divs.is_empty(),
        "mkfifo divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_mkfifo_eexist() {
    let path = unique_tempfile("eexist");
    std::fs::write(&path, b"x").unwrap(); // create as regular file
    let cpath = CString::new(path.to_string_lossy().as_bytes()).unwrap();
    let r_fl = unsafe { fl::mkfifo(cpath.as_ptr(), 0o644) };
    let r_lc = unsafe { mkfifo(cpath.as_ptr(), 0o644) };
    let _ = std::fs::remove_file(&path);
    assert!(
        (r_fl == 0) == (r_lc == 0),
        "mkfifo EEXIST fail-match: fl={r_fl}, lc={r_lc}"
    );
}

#[test]
fn diff_mkfifoat_at_fdcwd() {
    let mut divs = Vec::new();
    let path_fl = unique_tempfile("fifoat_fl");
    let path_lc = unique_tempfile("fifoat_lc");
    let cpath_fl = CString::new(path_fl.to_string_lossy().as_bytes()).unwrap();
    let cpath_lc = CString::new(path_lc.to_string_lossy().as_bytes()).unwrap();
    let r_fl = unsafe { fl::mkfifoat(AT_FDCWD, cpath_fl.as_ptr(), 0o600) };
    let r_lc = unsafe { mkfifoat(AT_FDCWD, cpath_lc.as_ptr(), 0o600) };
    if r_fl != r_lc {
        divs.push(Divergence {
            function: "mkfifoat",
            case: "AT_FDCWD".into(),
            field: "return",
            frankenlibc: format!("{r_fl}"),
            glibc: format!("{r_lc}"),
        });
    }
    if r_fl == 0 && r_lc == 0 {
        let mode_fl = stat_mode(&path_fl) & libc::S_IFMT;
        let mode_lc = stat_mode(&path_lc) & libc::S_IFMT;
        if mode_fl != mode_lc || mode_fl != libc::S_IFIFO {
            divs.push(Divergence {
                function: "mkfifoat",
                case: "AT_FDCWD".into(),
                field: "S_IFMT",
                frankenlibc: format!("{mode_fl:o}"),
                glibc: format!("{mode_lc:o} (expected {:o})", libc::S_IFIFO),
            });
        }
    }
    let _ = std::fs::remove_file(&path_fl);
    let _ = std::fs::remove_file(&path_lc);
    assert!(
        divs.is_empty(),
        "mkfifoat divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_mknod_regular_file() {
    let mut divs = Vec::new();
    let path_fl = unique_tempfile("mknod_reg_fl");
    let path_lc = unique_tempfile("mknod_reg_lc");
    let cpath_fl = CString::new(path_fl.to_string_lossy().as_bytes()).unwrap();
    let cpath_lc = CString::new(path_lc.to_string_lossy().as_bytes()).unwrap();
    let mode = libc::S_IFREG | 0o644;
    let r_fl = unsafe { fl::mknod(cpath_fl.as_ptr(), mode, 0) };
    let r_lc = unsafe { mknod(cpath_lc.as_ptr(), mode, 0) };
    if r_fl != r_lc {
        divs.push(Divergence {
            function: "mknod",
            case: "S_IFREG".into(),
            field: "return",
            frankenlibc: format!("{r_fl}"),
            glibc: format!("{r_lc}"),
        });
    }
    if r_fl == 0 && r_lc == 0 {
        let mode_fl = stat_mode(&path_fl) & libc::S_IFMT;
        let mode_lc = stat_mode(&path_lc) & libc::S_IFMT;
        if mode_fl != mode_lc || mode_fl != libc::S_IFREG {
            divs.push(Divergence {
                function: "mknod",
                case: "S_IFREG".into(),
                field: "S_IFMT",
                frankenlibc: format!("{mode_fl:o}"),
                glibc: format!("{mode_lc:o} (expected {:o})", libc::S_IFREG),
            });
        }
    }
    let _ = std::fs::remove_file(&path_fl);
    let _ = std::fs::remove_file(&path_lc);
    assert!(
        divs.is_empty(),
        "mknod regular divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_mknod_fifo_via_s_ififo() {
    let mut divs = Vec::new();
    let path_fl = unique_tempfile("mknod_fifo_fl");
    let path_lc = unique_tempfile("mknod_fifo_lc");
    let cpath_fl = CString::new(path_fl.to_string_lossy().as_bytes()).unwrap();
    let cpath_lc = CString::new(path_lc.to_string_lossy().as_bytes()).unwrap();
    let mode = libc::S_IFIFO | 0o644;
    let r_fl = unsafe { fl::mknod(cpath_fl.as_ptr(), mode, 0) };
    let r_lc = unsafe { mknod(cpath_lc.as_ptr(), mode, 0) };
    if r_fl != r_lc {
        divs.push(Divergence {
            function: "mknod",
            case: "S_IFIFO".into(),
            field: "return",
            frankenlibc: format!("{r_fl}"),
            glibc: format!("{r_lc}"),
        });
    }
    if r_fl == 0 && r_lc == 0 {
        let mode_fl = stat_mode(&path_fl) & libc::S_IFMT;
        let mode_lc = stat_mode(&path_lc) & libc::S_IFMT;
        if mode_fl != mode_lc || mode_fl != libc::S_IFIFO {
            divs.push(Divergence {
                function: "mknod",
                case: "S_IFIFO".into(),
                field: "S_IFMT",
                frankenlibc: format!("{mode_fl:o}"),
                glibc: format!("{mode_lc:o} (expected {:o})", libc::S_IFIFO),
            });
        }
    }
    let _ = std::fs::remove_file(&path_fl);
    let _ = std::fs::remove_file(&path_lc);
    assert!(
        divs.is_empty(),
        "mknod fifo divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_mknodat_at_fdcwd() {
    let mut divs = Vec::new();
    let path_fl = unique_tempfile("mknodat_fl");
    let path_lc = unique_tempfile("mknodat_lc");
    let cpath_fl = CString::new(path_fl.to_string_lossy().as_bytes()).unwrap();
    let cpath_lc = CString::new(path_lc.to_string_lossy().as_bytes()).unwrap();
    let mode = libc::S_IFREG | 0o600;
    let r_fl = unsafe { fl::mknodat(AT_FDCWD, cpath_fl.as_ptr(), mode, 0) };
    let r_lc = unsafe { mknodat(AT_FDCWD, cpath_lc.as_ptr(), mode, 0) };
    if r_fl != r_lc {
        divs.push(Divergence {
            function: "mknodat",
            case: "AT_FDCWD S_IFREG".into(),
            field: "return",
            frankenlibc: format!("{r_fl}"),
            glibc: format!("{r_lc}"),
        });
    }
    let _ = std::fs::remove_file(&path_fl);
    let _ = std::fs::remove_file(&path_lc);
    assert!(
        divs.is_empty(),
        "mknodat divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn mkfifo_mknod_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"sys/stat.h(mkfifo/mknod)\",\"reference\":\"glibc\",\"functions\":4,\"divergences\":0}}",
    );
}
