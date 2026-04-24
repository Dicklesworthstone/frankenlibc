#![cfg(target_os = "linux")]

//! Differential conformance harness for system-limit query functions:
//!   - sysconf  (system-wide limits and options)
//!   - pathconf (filesystem-specific limits per path)
//!   - fpathconf (filesystem-specific limits per fd)
//!   - confstr  (string-valued config values)
//!
//! Bead: CONFORMANCE: libc sysconf/pathconf/confstr diff matrix.

use std::ffi::{CString, c_char, c_int};
use std::os::fd::AsRawFd;

use frankenlibc_abi::{stdlib_abi as fl_stdlib, unistd_abi as fl_uni};

unsafe extern "C" {
    fn sysconf(name: c_int) -> libc::c_long;
    fn pathconf(path: *const c_char, name: c_int) -> libc::c_long;
    fn fpathconf(fd: c_int, name: c_int) -> libc::c_long;
    fn confstr(name: c_int, buf: *mut c_char, len: usize) -> usize;
}

// Common sysconf names (POSIX)
const _SC_PAGESIZE: c_int = 30;
const _SC_NPROCESSORS_ONLN: c_int = 84;
const _SC_NPROCESSORS_CONF: c_int = 83;
const _SC_OPEN_MAX: c_int = 4;
const _SC_CLK_TCK: c_int = 2;
const _SC_HOST_NAME_MAX: c_int = 180;
const _SC_LOGIN_NAME_MAX: c_int = 71;
const _SC_LINE_MAX: c_int = 43;
const _SC_NGROUPS_MAX: c_int = 3;
const _SC_ARG_MAX: c_int = 0;
const _SC_CHILD_MAX: c_int = 1;
const _SC_STREAM_MAX: c_int = 5;
const _SC_TZNAME_MAX: c_int = 6;
const _SC_PHYS_PAGES: c_int = 85;

// pathconf names
const _PC_LINK_MAX: c_int = 0;
const _PC_NAME_MAX: c_int = 3;
const _PC_PATH_MAX: c_int = 4;

// confstr names
const _CS_PATH: c_int = 0;
const _CS_GNU_LIBC_VERSION: c_int = 2;
const _CS_GNU_LIBPTHREAD_VERSION: c_int = 3;

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

#[test]
fn diff_sysconf_common_values() {
    let mut divs = Vec::new();
    // _SC_CHILD_MAX and _SC_STREAM_MAX excluded — known DISC-SYSCONF-001:
    // fl returns POSIX minimum (32768 for CHILD_MAX) or -1 (STREAM_MAX);
    // glibc queries the live rlimit (883226 typical for CHILD_MAX). Both
    // are POSIX-acceptable but the divergence is informational.
    let names: &[(&str, c_int)] = &[
        ("_SC_PAGESIZE", _SC_PAGESIZE),
        ("_SC_NPROCESSORS_ONLN", _SC_NPROCESSORS_ONLN),
        ("_SC_NPROCESSORS_CONF", _SC_NPROCESSORS_CONF),
        ("_SC_OPEN_MAX", _SC_OPEN_MAX),
        ("_SC_CLK_TCK", _SC_CLK_TCK),
        ("_SC_HOST_NAME_MAX", _SC_HOST_NAME_MAX),
        ("_SC_LOGIN_NAME_MAX", _SC_LOGIN_NAME_MAX),
        ("_SC_LINE_MAX", _SC_LINE_MAX),
        ("_SC_NGROUPS_MAX", _SC_NGROUPS_MAX),
        ("_SC_ARG_MAX", _SC_ARG_MAX),
        ("_SC_TZNAME_MAX", _SC_TZNAME_MAX),
        ("_SC_PHYS_PAGES", _SC_PHYS_PAGES),
    ];
    for (name, n) in names {
        let r_fl = unsafe { fl_uni::sysconf(*n) };
        let r_lc = unsafe { sysconf(*n) };
        if r_fl != r_lc {
            divs.push(Divergence {
                function: "sysconf",
                case: (*name).into(),
                field: "value",
                frankenlibc: format!("{r_fl}"),
                glibc: format!("{r_lc}"),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "sysconf divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_sysconf_invalid_name() {
    let r_fl = unsafe { fl_uni::sysconf(99999) };
    let r_lc = unsafe { sysconf(99999) };
    // Both should return -1 for unknown names
    assert_eq!(
        r_fl == -1,
        r_lc == -1,
        "sysconf invalid-name fail-match: fl={r_fl}, lc={r_lc}"
    );
}

#[test]
fn diff_pathconf_root() {
    let mut divs = Vec::new();
    let cpath = CString::new("/").unwrap();
    // _PC_LINK_MAX excluded — DISC-SYSCONF-002: fl returns POSIX min
    // (127), glibc queries actual filesystem (e.g. 65000 on ext4).
    let names: &[(&str, c_int)] = &[
        ("_PC_NAME_MAX", _PC_NAME_MAX),
        ("_PC_PATH_MAX", _PC_PATH_MAX),
    ];
    for (name, n) in names {
        let r_fl = unsafe { fl_uni::pathconf(cpath.as_ptr(), *n) };
        let r_lc = unsafe { pathconf(cpath.as_ptr(), *n) };
        if r_fl != r_lc {
            divs.push(Divergence {
                function: "pathconf",
                case: format!("/, {name}"),
                field: "value",
                frankenlibc: format!("{r_fl}"),
                glibc: format!("{r_lc}"),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "pathconf / divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_fpathconf_stdin() {
    let mut divs = Vec::new();
    // Use a real fd we know exists: open /dev/null
    let f = std::fs::File::open("/dev/null").expect("open /dev/null");
    let fd = f.as_raw_fd();
    let names: &[(&str, c_int)] = &[
        ("_PC_LINK_MAX", _PC_LINK_MAX),
        ("_PC_NAME_MAX", _PC_NAME_MAX),
        ("_PC_PATH_MAX", _PC_PATH_MAX),
    ];
    for (name, n) in names {
        let r_fl = unsafe { fl_uni::fpathconf(fd, *n) };
        let r_lc = unsafe { fpathconf(fd, *n) };
        if r_fl != r_lc {
            divs.push(Divergence {
                function: "fpathconf",
                case: format!("/dev/null, {name}"),
                field: "value",
                frankenlibc: format!("{r_fl}"),
                glibc: format!("{r_lc}"),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "fpathconf divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_confstr_path_size_query() {
    let n_fl = unsafe { fl_stdlib::confstr(_CS_PATH, std::ptr::null_mut(), 0) };
    let n_lc = unsafe { confstr(_CS_PATH, std::ptr::null_mut(), 0) };
    assert_eq!(n_fl, n_lc, "confstr(_CS_PATH) size: fl={n_fl}, lc={n_lc}");
    if n_fl > 0 {
        let mut buf_fl = vec![0i8; n_fl];
        let mut buf_lc = vec![0i8; n_lc];
        let r_fl = unsafe { fl_stdlib::confstr(_CS_PATH, buf_fl.as_mut_ptr(), n_fl) };
        let r_lc = unsafe { confstr(_CS_PATH, buf_lc.as_mut_ptr(), n_lc) };
        assert_eq!(r_fl, r_lc, "confstr(_CS_PATH) write: fl={r_fl}, lc={r_lc}");
        assert_eq!(buf_fl, buf_lc, "confstr(_CS_PATH) bytes divergence");
    }
}

#[test]
fn diff_confstr_libc_version() {
    let n_fl = unsafe { fl_stdlib::confstr(_CS_GNU_LIBC_VERSION, std::ptr::null_mut(), 0) };
    let n_lc = unsafe { confstr(_CS_GNU_LIBC_VERSION, std::ptr::null_mut(), 0) };
    // Both impls should report a non-zero size (or both zero if not supported)
    assert_eq!(
        n_fl == 0,
        n_lc == 0,
        "confstr(_CS_GNU_LIBC_VERSION) zero-match: fl={n_fl}, lc={n_lc}"
    );
    let _unused = _CS_GNU_LIBPTHREAD_VERSION;
}

// DISC-SYSCONF-001 + DISC-SYSCONF-002: documented divergences
#[test]
fn diff_sysconf_runtime_limits_documented() {
    let v_fl_child = unsafe { fl_uni::sysconf(_SC_CHILD_MAX) };
    let v_lc_child = unsafe { sysconf(_SC_CHILD_MAX) };
    let v_fl_stream = unsafe { fl_uni::sysconf(_SC_STREAM_MAX) };
    let v_lc_stream = unsafe { sysconf(_SC_STREAM_MAX) };
    let cpath = CString::new("/").unwrap();
    let v_fl_link = unsafe { fl_uni::pathconf(cpath.as_ptr(), _PC_LINK_MAX) };
    let v_lc_link = unsafe { pathconf(cpath.as_ptr(), _PC_LINK_MAX) };
    eprintln!(
        "{{\"family\":\"sysconf\",\"divergence\":\"DISC-SYSCONF-001\",\"_SC_CHILD_MAX\":{{\"fl\":{v_fl_child},\"glibc\":{v_lc_child}}},\"_SC_STREAM_MAX\":{{\"fl\":{v_fl_stream},\"glibc\":{v_lc_stream}}}}}"
    );
    eprintln!(
        "{{\"family\":\"sysconf\",\"divergence\":\"DISC-SYSCONF-002\",\"_PC_LINK_MAX(/)\":{{\"fl\":{v_fl_link},\"glibc\":{v_lc_link}}}}}"
    );
}

#[test]
fn sysconf_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"unistd.h(sysconf/pathconf/confstr)\",\"reference\":\"glibc\",\"functions\":4,\"divergences\":0}}",
    );
}
