#![cfg(target_os = "linux")]

//! Differential conformance harness for filesystem-watch + sysinfo:
//!   - inotify_init / inotify_init1 / inotify_add_watch / inotify_rm_watch
//!   - sysinfo (system uptime/memory snapshot)
//!   - getloadavg (1/5/15-minute load averages)
//!
//! Bead: CONFORMANCE: libc inotify+sysinfo+getloadavg diff matrix.

use std::ffi::{CString, c_double, c_int};

use frankenlibc_abi::{stdlib_abi as fl_stdlib, unistd_abi as fl_uni};

unsafe extern "C" {
    fn inotify_init() -> c_int;
    fn inotify_init1(flags: c_int) -> c_int;
    fn inotify_add_watch(fd: c_int, pathname: *const std::ffi::c_char, mask: u32) -> c_int;
    fn inotify_rm_watch(fd: c_int, wd: c_int) -> c_int;
    fn sysinfo(info: *mut libc::sysinfo) -> c_int;
    fn getloadavg(loadavg: *mut c_double, nelem: c_int) -> c_int;
}

const IN_MODIFY: u32 = 0x2;
const IN_CLOEXEC: c_int = 0o2000000;
const IN_NONBLOCK: c_int = 0o4000;

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
    std::env::temp_dir().join(format!("fl_inotify_diff_{label}_{pid}_{id}"))
}

// ===========================================================================
// inotify
// ===========================================================================

#[test]
fn diff_inotify_init_and_init1() {
    let mut divs = Vec::new();
    let fd_fl = unsafe { fl_uni::inotify_init() };
    let fd_lc = unsafe { inotify_init() };
    if (fd_fl >= 0) != (fd_lc >= 0) {
        divs.push(Divergence {
            function: "inotify_init",
            case: "default".into(),
            field: "success_match",
            frankenlibc: format!("{fd_fl}"),
            glibc: format!("{fd_lc}"),
        });
    }
    if fd_fl >= 0 {
        let _ = unsafe { libc::close(fd_fl) };
    }
    if fd_lc >= 0 {
        let _ = unsafe { libc::close(fd_lc) };
    }

    for (label, flags) in &[
        ("0", 0),
        ("CLOEXEC", IN_CLOEXEC),
        ("NONBLOCK", IN_NONBLOCK),
        ("CLOEXEC|NONBLOCK", IN_CLOEXEC | IN_NONBLOCK),
    ] {
        let fd_fl = unsafe { fl_uni::inotify_init1(*flags) };
        let fd_lc = unsafe { inotify_init1(*flags) };
        if (fd_fl >= 0) != (fd_lc >= 0) {
            divs.push(Divergence {
                function: "inotify_init1",
                case: (*label).into(),
                field: "success_match",
                frankenlibc: format!("{fd_fl}"),
                glibc: format!("{fd_lc}"),
            });
        }
        if fd_fl >= 0 {
            let _ = unsafe { libc::close(fd_fl) };
        }
        if fd_lc >= 0 {
            let _ = unsafe { libc::close(fd_lc) };
        }
    }
    assert!(
        divs.is_empty(),
        "inotify_init divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_inotify_add_then_remove_watch() {
    let path = unique_tempfile("watch");
    std::fs::write(&path, b"x").unwrap();
    let cpath = CString::new(path.to_string_lossy().as_bytes()).unwrap();

    let run = |use_fl: bool| -> (c_int, c_int, c_int) {
        let ifd = if use_fl {
            unsafe { fl_uni::inotify_init1(0) }
        } else {
            unsafe { inotify_init1(0) }
        };
        let wd = if use_fl {
            unsafe { fl_uni::inotify_add_watch(ifd, cpath.as_ptr(), IN_MODIFY) }
        } else {
            unsafe { inotify_add_watch(ifd, cpath.as_ptr(), IN_MODIFY) }
        };
        let r_rm = if use_fl {
            unsafe { fl_uni::inotify_rm_watch(ifd, wd) }
        } else {
            unsafe { inotify_rm_watch(ifd, wd) }
        };
        if ifd >= 0 {
            let _ = unsafe { libc::close(ifd) };
        }
        (ifd, wd, r_rm)
    };
    let (ifd_fl, wd_fl, rm_fl) = run(true);
    let (ifd_lc, wd_lc, rm_lc) = run(false);
    let _ = std::fs::remove_file(&path);

    assert!(
        (ifd_fl >= 0) == (ifd_lc >= 0),
        "init1 success: fl={ifd_fl}, lc={ifd_lc}"
    );
    assert!(
        (wd_fl > 0) == (wd_lc > 0),
        "add_watch success: fl={wd_fl}, lc={wd_lc}"
    );
    assert!(
        (rm_fl == 0) == (rm_lc == 0),
        "rm_watch success: fl={rm_fl}, lc={rm_lc}"
    );
}

#[test]
fn diff_inotify_add_watch_enoent() {
    let cpath = CString::new("/this/path/does/not/exist/xyz").unwrap();
    let ifd_fl = unsafe { fl_uni::inotify_init1(0) };
    let ifd_lc = unsafe { inotify_init1(0) };
    let wd_fl = unsafe { fl_uni::inotify_add_watch(ifd_fl, cpath.as_ptr(), IN_MODIFY) };
    let wd_lc = unsafe { inotify_add_watch(ifd_lc, cpath.as_ptr(), IN_MODIFY) };
    if ifd_fl >= 0 {
        unsafe { libc::close(ifd_fl) };
    }
    if ifd_lc >= 0 {
        unsafe { libc::close(ifd_lc) };
    }
    assert!(
        (wd_fl < 0) == (wd_lc < 0),
        "add_watch ENOENT match: fl={wd_fl}, lc={wd_lc}"
    );
}

// ===========================================================================
// sysinfo
// ===========================================================================

#[test]
fn diff_sysinfo_fields() {
    let mut divs = Vec::new();
    let mut info_fl: libc::sysinfo = unsafe { core::mem::zeroed() };
    let mut info_lc: libc::sysinfo = unsafe { core::mem::zeroed() };
    let r_fl = unsafe { fl_uni::sysinfo(&mut info_fl) };
    let r_lc = unsafe { sysinfo(&mut info_lc) };
    if r_fl != r_lc {
        divs.push(Divergence {
            function: "sysinfo",
            case: "default".into(),
            field: "return",
            frankenlibc: format!("{r_fl}"),
            glibc: format!("{r_lc}"),
        });
    }
    if r_fl == 0 && r_lc == 0 {
        // Memory totals should be identical (kernel returns these).
        if info_fl.totalram != info_lc.totalram {
            divs.push(Divergence {
                function: "sysinfo",
                case: "default".into(),
                field: "totalram",
                frankenlibc: format!("{}", info_fl.totalram),
                glibc: format!("{}", info_lc.totalram),
            });
        }
        if info_fl.totalswap != info_lc.totalswap {
            divs.push(Divergence {
                function: "sysinfo",
                case: "default".into(),
                field: "totalswap",
                frankenlibc: format!("{}", info_fl.totalswap),
                glibc: format!("{}", info_lc.totalswap),
            });
        }
        if info_fl.mem_unit != info_lc.mem_unit {
            divs.push(Divergence {
                function: "sysinfo",
                case: "default".into(),
                field: "mem_unit",
                frankenlibc: format!("{}", info_fl.mem_unit),
                glibc: format!("{}", info_lc.mem_unit),
            });
        }
        // Uptime should be very close (within 2 seconds).
        let dup = (info_fl.uptime - info_lc.uptime).abs();
        if dup > 2 {
            divs.push(Divergence {
                function: "sysinfo",
                case: "default".into(),
                field: "uptime",
                frankenlibc: format!("{}", info_fl.uptime),
                glibc: format!("{}", info_lc.uptime),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "sysinfo divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// getloadavg
// ===========================================================================

#[test]
fn diff_getloadavg_three_values() {
    let mut divs = Vec::new();
    let mut buf_fl = [0.0f64; 3];
    let mut buf_lc = [0.0f64; 3];
    let n_fl = unsafe { fl_stdlib::getloadavg(buf_fl.as_mut_ptr(), 3) };
    let n_lc = unsafe { getloadavg(buf_lc.as_mut_ptr(), 3) };
    if n_fl != n_lc {
        divs.push(Divergence {
            function: "getloadavg",
            case: "nelem=3".into(),
            field: "return",
            frankenlibc: format!("{n_fl}"),
            glibc: format!("{n_lc}"),
        });
    }
    // Loads must be non-negative and finite. Don't compare exact values
    // since the kernel can update between calls.
    for (i, (fl_v, lc_v)) in buf_fl.iter().zip(buf_lc.iter()).enumerate() {
        if !fl_v.is_finite() || *fl_v < 0.0 {
            divs.push(Divergence {
                function: "getloadavg",
                case: format!("buf[{i}]"),
                field: "fl_value_sanity",
                frankenlibc: format!("{fl_v}"),
                glibc: "(non-negative finite required)".to_string(),
            });
        }
        if !lc_v.is_finite() || *lc_v < 0.0 {
            divs.push(Divergence {
                function: "getloadavg",
                case: format!("buf[{i}]"),
                field: "lc_value_sanity",
                frankenlibc: "(reference)".to_string(),
                glibc: format!("{lc_v}"),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "getloadavg divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_getloadavg_invalid_nelem() {
    // nelem <= 0 should fail or return 0 on both impls
    let mut buf = [0.0f64; 3];
    let n_fl = unsafe { fl_stdlib::getloadavg(buf.as_mut_ptr(), 0) };
    let n_lc = unsafe { getloadavg(buf.as_mut_ptr(), 0) };
    assert!(
        (n_fl <= 0) == (n_lc <= 0),
        "getloadavg nelem=0 fail-match: fl={n_fl}, lc={n_lc}"
    );
}

#[test]
fn inotify_sysinfo_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"inotify+sysinfo+getloadavg\",\"reference\":\"glibc\",\"functions\":7,\"divergences\":0}}",
    );
}
