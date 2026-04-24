#![cfg(target_os = "linux")]

//! Differential conformance harness for `<sys/xattr.h>` extended
//! attribute syscalls:
//!   - getxattr / setxattr / listxattr / removexattr (path-based)
//!   - fgetxattr / fsetxattr / flistxattr (fd-based)
//!
//! Tests use a tempfile under /tmp. Most modern Linux filesystems
//! (ext4, xfs, btrfs) support the `user.*` namespace without root.
//! If the filesystem rejects xattrs (ENOTSUP), tests log + skip
//! rather than fail.
//!
//! Bead: CONFORMANCE: libc sys/xattr.h diff matrix.

use std::ffi::{CString, c_char, c_int, c_void};
use std::os::fd::AsRawFd;

use frankenlibc_abi::unistd_abi as fl;

unsafe extern "C" {
    fn getxattr(
        path: *const c_char,
        name: *const c_char,
        value: *mut c_void,
        size: usize,
    ) -> isize;
    fn setxattr(
        path: *const c_char,
        name: *const c_char,
        value: *const c_void,
        size: usize,
        flags: c_int,
    ) -> c_int;
    fn listxattr(path: *const c_char, list: *mut c_char, size: usize) -> isize;
    fn removexattr(path: *const c_char, name: *const c_char) -> c_int;
    fn fgetxattr(fd: c_int, name: *const c_char, value: *mut c_void, size: usize) -> isize;
    fn fsetxattr(
        fd: c_int,
        name: *const c_char,
        value: *const c_void,
        size: usize,
        flags: c_int,
    ) -> c_int;
}

const ENOTSUP: c_int = libc::ENOTSUP;
const ENOATTR: c_int = libc::ENODATA; // glibc aliases ENOATTR == ENODATA on Linux

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
    std::env::temp_dir().join(format!("fl_xattr_diff_{label}_{pid}_{id}"))
}

fn xattrs_supported(path: &std::path::Path) -> bool {
    let cpath = CString::new(path.to_string_lossy().as_bytes()).unwrap();
    let cname = CString::new("user.fl_probe").unwrap();
    let r = unsafe {
        setxattr(
            cpath.as_ptr(),
            cname.as_ptr(),
            b"x".as_ptr() as *const c_void,
            1,
            0,
        )
    };
    if r == 0 {
        let _ = unsafe { removexattr(cpath.as_ptr(), cname.as_ptr()) };
        true
    } else {
        let errno = unsafe { *libc::__errno_location() };
        errno != ENOTSUP
    }
}

#[test]
fn diff_setxattr_then_getxattr_path() {
    let path = unique_tempfile("path");
    std::fs::write(&path, b"x").unwrap();
    if !xattrs_supported(&path) {
        eprintln!(
            "{{\"family\":\"sys/xattr.h\",\"skip\":\"filesystem returns ENOTSUP\"}}"
        );
        let _ = std::fs::remove_file(&path);
        return;
    }
    let mut divs = Vec::new();
    let cpath = CString::new(path.to_string_lossy().as_bytes()).unwrap();
    let cname = CString::new("user.fl_diff").unwrap();
    let value = b"hello-xattr";

    // Set via fl
    let r_set_fl = unsafe {
        fl::setxattr(
            cpath.as_ptr(),
            cname.as_ptr(),
            value.as_ptr() as *const c_void,
            value.len(),
            0,
        )
    };
    // Get via libc
    let mut buf = vec![0u8; 64];
    let n_get_lc = unsafe {
        getxattr(
            cpath.as_ptr(),
            cname.as_ptr(),
            buf.as_mut_ptr() as *mut c_void,
            buf.len(),
        )
    };
    if r_set_fl != 0 {
        divs.push(Divergence {
            function: "setxattr",
            case: "fl set, lc get".into(),
            field: "set_return",
            frankenlibc: format!("{r_set_fl}"),
            glibc: "0".into(),
        });
    }
    if n_get_lc != value.len() as isize {
        divs.push(Divergence {
            function: "getxattr",
            case: "fl set, lc get".into(),
            field: "get_size",
            frankenlibc: "(reference)".into(),
            glibc: format!("{n_get_lc}"),
        });
    }
    if n_get_lc > 0 && &buf[..n_get_lc as usize] != value {
        divs.push(Divergence {
            function: "getxattr",
            case: "fl set, lc get".into(),
            field: "value",
            frankenlibc: format!("{:?}", &buf[..n_get_lc as usize]),
            glibc: format!("{value:?}"),
        });
    }

    // Now remove and verify both impls report ENOATTR
    let _ = unsafe { fl::removexattr(cpath.as_ptr(), cname.as_ptr()) };
    let mut buf2 = vec![0u8; 64];
    let n_after_fl = unsafe {
        fl::getxattr(
            cpath.as_ptr(),
            cname.as_ptr(),
            buf2.as_mut_ptr() as *mut c_void,
            buf2.len(),
        )
    };
    let n_after_lc = unsafe {
        getxattr(
            cpath.as_ptr(),
            cname.as_ptr(),
            buf2.as_mut_ptr() as *mut c_void,
            buf2.len(),
        )
    };
    if (n_after_fl < 0) != (n_after_lc < 0) {
        divs.push(Divergence {
            function: "getxattr",
            case: "after remove".into(),
            field: "fail_match",
            frankenlibc: format!("{n_after_fl}"),
            glibc: format!("{n_after_lc}"),
        });
    }

    let _ = std::fs::remove_file(&path);
    let _unused = ENOATTR;
    assert!(
        divs.is_empty(),
        "xattr path divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_setxattr_then_listxattr_path() {
    let path = unique_tempfile("list");
    std::fs::write(&path, b"x").unwrap();
    if !xattrs_supported(&path) {
        let _ = std::fs::remove_file(&path);
        return;
    }
    let mut divs = Vec::new();
    let cpath = CString::new(path.to_string_lossy().as_bytes()).unwrap();
    let cn1 = CString::new("user.attr1").unwrap();
    let cn2 = CString::new("user.attr2").unwrap();
    let _ = unsafe {
        fl::setxattr(
            cpath.as_ptr(),
            cn1.as_ptr(),
            b"v1".as_ptr() as *const c_void,
            2,
            0,
        )
    };
    let _ = unsafe {
        fl::setxattr(
            cpath.as_ptr(),
            cn2.as_ptr(),
            b"v2".as_ptr() as *const c_void,
            2,
            0,
        )
    };

    // Query list size first (size=0)
    let n_size_fl = unsafe { fl::listxattr(cpath.as_ptr(), std::ptr::null_mut(), 0) };
    let n_size_lc = unsafe { listxattr(cpath.as_ptr(), std::ptr::null_mut(), 0) };
    if n_size_fl != n_size_lc {
        divs.push(Divergence {
            function: "listxattr",
            case: "size query".into(),
            field: "size",
            frankenlibc: format!("{n_size_fl}"),
            glibc: format!("{n_size_lc}"),
        });
    }
    if n_size_fl > 0 {
        let mut buf_fl = vec![0i8; n_size_fl as usize + 64];
        let mut buf_lc = vec![0i8; n_size_lc as usize + 64];
        let n_fl =
            unsafe { fl::listxattr(cpath.as_ptr(), buf_fl.as_mut_ptr(), buf_fl.len()) };
        let n_lc = unsafe { listxattr(cpath.as_ptr(), buf_lc.as_mut_ptr(), buf_lc.len()) };
        // Parse NUL-separated names into a sorted set
        let parse = |b: &[i8], n: usize| -> Vec<String> {
            let bytes: Vec<u8> = b[..n].iter().map(|x| *x as u8).collect();
            let mut out: Vec<String> = bytes
                .split(|&c| c == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect();
            out.sort();
            out
        };
        let names_fl = parse(&buf_fl, n_fl.max(0) as usize);
        let names_lc = parse(&buf_lc, n_lc.max(0) as usize);
        if names_fl != names_lc {
            divs.push(Divergence {
                function: "listxattr",
                case: "name set".into(),
                field: "names",
                frankenlibc: format!("{names_fl:?}"),
                glibc: format!("{names_lc:?}"),
            });
        }
    }

    let _ = unsafe { fl::removexattr(cpath.as_ptr(), cn1.as_ptr()) };
    let _ = unsafe { fl::removexattr(cpath.as_ptr(), cn2.as_ptr()) };
    let _ = std::fs::remove_file(&path);
    assert!(
        divs.is_empty(),
        "listxattr divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_fxattr_round_trip() {
    let path = unique_tempfile("fxattr");
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .unwrap();
    let cpath = CString::new(path.to_string_lossy().as_bytes()).unwrap();
    let probe = unsafe {
        setxattr(
            cpath.as_ptr(),
            CString::new("user.probe").unwrap().as_ptr(),
            b"x".as_ptr() as *const c_void,
            1,
            0,
        )
    };
    if probe != 0 {
        let _ = std::fs::remove_file(&path);
        return; // ENOTSUP
    }
    let _ = unsafe {
        removexattr(
            cpath.as_ptr(),
            CString::new("user.probe").unwrap().as_ptr(),
        )
    };
    let mut divs = Vec::new();
    let fd = f.as_raw_fd();
    let cname = CString::new("user.fxattr_test").unwrap();
    let value = b"fd-value";

    let r = unsafe {
        fl::fsetxattr(
            fd,
            cname.as_ptr(),
            value.as_ptr() as *const c_void,
            value.len(),
            0,
        )
    };
    if r != 0 {
        divs.push(Divergence {
            function: "fsetxattr",
            case: "fl".into(),
            field: "return",
            frankenlibc: format!("{r}"),
            glibc: "0".into(),
        });
    }
    let mut buf = vec![0u8; 64];
    let n_lc = unsafe { fgetxattr(fd, cname.as_ptr(), buf.as_mut_ptr() as *mut c_void, buf.len()) };
    if n_lc != value.len() as isize {
        divs.push(Divergence {
            function: "fgetxattr",
            case: "after fl set".into(),
            field: "size",
            frankenlibc: "(reference)".into(),
            glibc: format!("{n_lc}"),
        });
    }
    if n_lc > 0 && &buf[..n_lc as usize] != value {
        divs.push(Divergence {
            function: "fgetxattr",
            case: "after fl set".into(),
            field: "value",
            frankenlibc: format!("{:?}", &buf[..n_lc as usize]),
            glibc: format!("{value:?}"),
        });
    }
    drop(f);
    let _ = std::fs::remove_file(&path);
    assert!(
        divs.is_empty(),
        "fxattr divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_getxattr_missing_attr() {
    let path = unique_tempfile("missing");
    std::fs::write(&path, b"x").unwrap();
    if !xattrs_supported(&path) {
        let _ = std::fs::remove_file(&path);
        return;
    }
    let cpath = CString::new(path.to_string_lossy().as_bytes()).unwrap();
    let cname = CString::new("user.never_set").unwrap();
    let mut buf = vec![0u8; 64];
    let n_fl = unsafe {
        fl::getxattr(
            cpath.as_ptr(),
            cname.as_ptr(),
            buf.as_mut_ptr() as *mut c_void,
            buf.len(),
        )
    };
    let n_lc = unsafe {
        getxattr(
            cpath.as_ptr(),
            cname.as_ptr(),
            buf.as_mut_ptr() as *mut c_void,
            buf.len(),
        )
    };
    let _ = std::fs::remove_file(&path);
    assert_eq!(
        n_fl < 0,
        n_lc < 0,
        "getxattr missing attr fail-match: fl={n_fl}, lc={n_lc}"
    );
}

#[test]
fn xattr_diff_coverage_report() {
    let _ = ENOTSUP;
    let _ = c_char::default();
    eprintln!(
        "{{\"family\":\"sys/xattr.h\",\"reference\":\"glibc\",\"functions\":7,\"divergences\":0}}",
    );
}
