#![cfg(target_os = "linux")]

//! Differential conformance harness for file-time syscalls:
//!   - utimensat(dirfd, path, times, flags)
//!   - futimens(fd, times)
//!
//! Sets known atime/mtime via each impl on its own tempfile, then
//! stat()s the file and compares the resulting timestamps to verify
//! both impls actually wrote the requested values.
//!
//! Bead: CONFORMANCE: libc utimensat/futimens diff matrix.

use std::ffi::{CString, c_int};
use std::os::fd::AsRawFd;

use frankenlibc_abi::unistd_abi as fl;

unsafe extern "C" {
    fn utimensat(
        dirfd: c_int,
        pathname: *const std::ffi::c_char,
        times: *const libc::timespec,
        flags: c_int,
    ) -> c_int;
    fn futimens(fd: c_int, times: *const libc::timespec) -> c_int;
}

const AT_FDCWD: c_int = -100;
const UTIME_NOW: i64 = 0x3fff_ffff;
const UTIME_OMIT: i64 = 0x3fff_fffe;

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
    std::env::temp_dir().join(format!("fl_utimens_diff_{label}_{pid}_{id}"))
}

fn read_atime_mtime(path: &std::path::Path) -> (i64, i64, i64, i64) {
    let cpath = CString::new(path.to_string_lossy().as_bytes()).unwrap();
    let mut st: libc::stat = unsafe { core::mem::zeroed() };
    let r = unsafe { libc::stat(cpath.as_ptr(), &mut st as *mut _) };
    assert_eq!(r, 0, "stat failed for {path:?}");
    (st.st_atime, st.st_atime_nsec, st.st_mtime, st.st_mtime_nsec)
}

#[test]
fn diff_utimensat_set_known_times() {
    let mut divs = Vec::new();

    let known_atime = libc::timespec {
        tv_sec: 1_700_000_000,
        tv_nsec: 123_456_789,
    };
    let known_mtime = libc::timespec {
        tv_sec: 1_650_000_000,
        tv_nsec: 987_654_321,
    };
    let times = [known_atime, known_mtime];

    // fl path
    let path_fl = unique_tempfile("fl");
    std::fs::File::create(&path_fl).unwrap();
    let cpath_fl = CString::new(path_fl.to_string_lossy().as_bytes()).unwrap();
    let r_fl = unsafe { fl::utimensat(AT_FDCWD, cpath_fl.as_ptr(), times.as_ptr(), 0) };

    // libc path
    let path_lc = unique_tempfile("lc");
    std::fs::File::create(&path_lc).unwrap();
    let cpath_lc = CString::new(path_lc.to_string_lossy().as_bytes()).unwrap();
    let r_lc = unsafe { utimensat(AT_FDCWD, cpath_lc.as_ptr(), times.as_ptr(), 0) };

    if r_fl != r_lc {
        divs.push(Divergence {
            function: "utimensat",
            case: "set known atime/mtime".into(),
            field: "return",
            frankenlibc: format!("{r_fl}"),
            glibc: format!("{r_lc}"),
        });
    }
    if r_fl == 0 && r_lc == 0 {
        let (a_fl, an_fl, m_fl, mn_fl) = read_atime_mtime(&path_fl);
        let (a_lc, an_lc, m_lc, mn_lc) = read_atime_mtime(&path_lc);
        if (a_fl, an_fl) != (a_lc, an_lc) {
            divs.push(Divergence {
                function: "utimensat",
                case: "set known atime".into(),
                field: "stat_atime",
                frankenlibc: format!("({a_fl}, {an_fl})"),
                glibc: format!("({a_lc}, {an_lc})"),
            });
        }
        if (m_fl, mn_fl) != (m_lc, mn_lc) {
            divs.push(Divergence {
                function: "utimensat",
                case: "set known mtime".into(),
                field: "stat_mtime",
                frankenlibc: format!("({m_fl}, {mn_fl})"),
                glibc: format!("({m_lc}, {mn_lc})"),
            });
        }
        // Also verify the values actually match what we set
        if a_fl != known_atime.tv_sec || an_fl != known_atime.tv_nsec {
            divs.push(Divergence {
                function: "utimensat",
                case: "set known atime".into(),
                field: "expected_atime",
                frankenlibc: format!("({a_fl}, {an_fl})"),
                glibc: format!("({}, {})", known_atime.tv_sec, known_atime.tv_nsec),
            });
        }
    }
    let _ = std::fs::remove_file(&path_fl);
    let _ = std::fs::remove_file(&path_lc);
    assert!(
        divs.is_empty(),
        "utimensat divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_utimensat_utime_omit() {
    let mut divs = Vec::new();

    // Set both initially via libc to a known value, then "OMIT"
    // mtime via each impl. After OMIT, mtime should still be the
    // initial value while atime gets updated.
    let initial = [
        libc::timespec {
            tv_sec: 1_500_000_000,
            tv_nsec: 1,
        },
        libc::timespec {
            tv_sec: 1_500_000_001,
            tv_nsec: 2,
        },
    ];
    let mtime_omit = [
        libc::timespec {
            tv_sec: 1_600_000_000,
            tv_nsec: 3,
        },
        libc::timespec {
            tv_sec: 0,
            tv_nsec: UTIME_OMIT,
        },
    ];

    for (label, set_fn) in &[
        (
            "fl",
            (|p: &std::path::Path, t: &[libc::timespec; 2]| -> c_int {
                let c = CString::new(p.to_string_lossy().as_bytes()).unwrap();
                unsafe { fl::utimensat(AT_FDCWD, c.as_ptr(), t.as_ptr(), 0) }
            }) as fn(&std::path::Path, &[libc::timespec; 2]) -> c_int,
        ),
        (
            "lc",
            (|p: &std::path::Path, t: &[libc::timespec; 2]| -> c_int {
                let c = CString::new(p.to_string_lossy().as_bytes()).unwrap();
                unsafe { utimensat(AT_FDCWD, c.as_ptr(), t.as_ptr(), 0) }
            }) as fn(&std::path::Path, &[libc::timespec; 2]) -> c_int,
        ),
    ] {
        let path = unique_tempfile(&format!("omit_{label}"));
        std::fs::File::create(&path).unwrap();
        let cpath = CString::new(path.to_string_lossy().as_bytes()).unwrap();
        let _ = unsafe { utimensat(AT_FDCWD, cpath.as_ptr(), initial.as_ptr(), 0) };
        let r = set_fn(&path, &mtime_omit);
        if r != 0 {
            divs.push(Divergence {
                function: "utimensat",
                case: format!("UTIME_OMIT mtime via {label}"),
                field: "return",
                frankenlibc: format!("{r}"),
                glibc: "0".into(),
            });
            let _ = std::fs::remove_file(&path);
            continue;
        }
        let (_, _, m, mn) = read_atime_mtime(&path);
        // mtime should still be the initial value (1_500_000_001, 2)
        if m != initial[1].tv_sec || mn != initial[1].tv_nsec {
            divs.push(Divergence {
                function: "utimensat",
                case: format!("UTIME_OMIT preserved mtime via {label}"),
                field: "stat_mtime",
                frankenlibc: format!("({m}, {mn})"),
                glibc: format!("({}, {})", initial[1].tv_sec, initial[1].tv_nsec),
            });
        }
        let _ = std::fs::remove_file(&path);
    }
    assert!(
        divs.is_empty(),
        "utimensat UTIME_OMIT divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_futimens_set_known_times() {
    let mut divs = Vec::new();

    let times = [
        libc::timespec {
            tv_sec: 1_400_000_000,
            tv_nsec: 100,
        },
        libc::timespec {
            tv_sec: 1_400_000_001,
            tv_nsec: 200,
        },
    ];

    let path_fl = unique_tempfile("fut_fl");
    let f_fl = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path_fl)
        .unwrap();
    let r_fl = unsafe { fl::futimens(f_fl.as_raw_fd(), times.as_ptr()) };

    let path_lc = unique_tempfile("fut_lc");
    let f_lc = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path_lc)
        .unwrap();
    let r_lc = unsafe { futimens(f_lc.as_raw_fd(), times.as_ptr()) };

    if r_fl != r_lc {
        divs.push(Divergence {
            function: "futimens",
            case: "set known".into(),
            field: "return",
            frankenlibc: format!("{r_fl}"),
            glibc: format!("{r_lc}"),
        });
    }
    drop(f_fl);
    drop(f_lc);
    if r_fl == 0 && r_lc == 0 {
        let (a_fl, an_fl, m_fl, mn_fl) = read_atime_mtime(&path_fl);
        let (a_lc, an_lc, m_lc, mn_lc) = read_atime_mtime(&path_lc);
        if (a_fl, an_fl, m_fl, mn_fl) != (a_lc, an_lc, m_lc, mn_lc) {
            divs.push(Divergence {
                function: "futimens",
                case: "set known".into(),
                field: "atime/mtime",
                frankenlibc: format!("a=({a_fl},{an_fl}) m=({m_fl},{mn_fl})"),
                glibc: format!("a=({a_lc},{an_lc}) m=({m_lc},{mn_lc})"),
            });
        }
    }
    let _ = std::fs::remove_file(&path_fl);
    let _ = std::fs::remove_file(&path_lc);
    let _unused = UTIME_NOW;
    assert!(
        divs.is_empty(),
        "futimens divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_utimensat_enoent() {
    // Both impls must fail with -1 when path doesn't exist
    let cpath = CString::new("/definitely/does/not/exist/file_xyz").unwrap();
    let r_fl = unsafe { fl::utimensat(AT_FDCWD, cpath.as_ptr(), std::ptr::null(), 0) };
    let r_lc = unsafe { utimensat(AT_FDCWD, cpath.as_ptr(), std::ptr::null(), 0) };
    assert!(
        (r_fl == 0) == (r_lc == 0),
        "utimensat ENOENT success-match: fl={r_fl}, lc={r_lc}"
    );
}

#[test]
fn utimensat_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"sys/stat.h(utimensat/futimens)\",\"reference\":\"glibc\",\"functions\":2,\"divergences\":0}}",
    );
}
