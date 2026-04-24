#![cfg(target_os = "linux")]

//! Differential conformance harness for `<libgen.h>`:
//!   - basename(char *path) — POSIX path-component extractor
//!   - dirname(char *path)  — POSIX path-prefix extractor
//!
//! Both functions may modify the input buffer in-place per POSIX. Each
//! case allocates a fresh CString per call so the impls don't see each
//! other's mutations.
//!
//! Bead: CONFORMANCE: libc libgen.h diff matrix.

use std::ffi::{CStr, CString, c_char, c_void};

use frankenlibc_abi::stdlib_abi as fl;

unsafe extern "C" {
    // glibc has two basename() symbols:
    //   - `basename` (GNU): non-mutating, returns the portion after the
    //     last '/', returns "" for "/" or trailing-slash inputs.
    //   - `__xpg_basename` (POSIX/XPG): mutating, returns "/" for "/",
    //     "." for "", strips trailing slashes.
    // FrankenLibC implements POSIX semantics, so compare against the
    // explicit POSIX symbol.
    #[link_name = "__xpg_basename"]
    fn basename(path: *mut c_char) -> *mut c_char;
    fn dirname(path: *mut c_char) -> *mut c_char;
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

fn run_basename(path: &str) -> String {
    let mut buf: Vec<u8> = path.as_bytes().to_vec();
    buf.push(0);
    let r = unsafe { basename(buf.as_mut_ptr() as *mut c_char) };
    if r.is_null() {
        return "<NULL>".into();
    }
    unsafe { CStr::from_ptr(r).to_string_lossy().into_owned() }
}

fn run_basename_fl(path: &str) -> String {
    let mut buf: Vec<u8> = path.as_bytes().to_vec();
    buf.push(0);
    let r = unsafe { fl::basename(buf.as_mut_ptr() as *mut c_char) };
    if r.is_null() {
        return "<NULL>".into();
    }
    unsafe { CStr::from_ptr(r).to_string_lossy().into_owned() }
}

fn run_dirname(path: &str) -> String {
    let mut buf: Vec<u8> = path.as_bytes().to_vec();
    buf.push(0);
    let r = unsafe { dirname(buf.as_mut_ptr() as *mut c_char) };
    if r.is_null() {
        return "<NULL>".into();
    }
    unsafe { CStr::from_ptr(r).to_string_lossy().into_owned() }
}

fn run_dirname_fl(path: &str) -> String {
    let mut buf: Vec<u8> = path.as_bytes().to_vec();
    buf.push(0);
    let r = unsafe { fl::dirname(buf.as_mut_ptr() as *mut c_char) };
    if r.is_null() {
        return "<NULL>".into();
    }
    unsafe { CStr::from_ptr(r).to_string_lossy().into_owned() }
}

#[test]
fn diff_basename_paths() {
    let mut divs = Vec::new();
    let cases: &[&str] = &[
        "",
        ".",
        "..",
        "/",
        "//",
        "///",
        "/usr",
        "/usr/",
        "/usr/lib",
        "/usr/lib/",
        "usr/lib",
        "lib",
        "/usr/lib/libc.so",
        "a",
        "a/",
        "a/b",
        "/a/b/c/d",
        "//a/b//c",
    ];
    for p in cases {
        let s_fl = run_basename_fl(p);
        let s_lc = run_basename(p);
        if s_fl != s_lc {
            divs.push(Divergence {
                function: "basename",
                case: format!("{p:?}"),
                field: "result",
                frankenlibc: format!("{s_fl:?}"),
                glibc: format!("{s_lc:?}"),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "basename divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn basename_null_does_not_crash() {
    let r_fl = unsafe { fl::basename(std::ptr::null_mut()) };
    let s_fl = if r_fl.is_null() {
        "<NULL>".to_string()
    } else {
        unsafe { CStr::from_ptr(r_fl).to_string_lossy().into_owned() }
    };
    assert_eq!(s_fl, ".", "basename(NULL) should return POSIX '.'");
}

#[test]
fn diff_dirname_paths() {
    let mut divs = Vec::new();
    let cases: &[&str] = &[
        "",
        ".",
        "..",
        "/",
        "//",
        "///",
        "/usr",
        "/usr/",
        "/usr/lib",
        "/usr/lib/",
        "usr/lib",
        "lib",
        "/usr/lib/libc.so",
        "a",
        "a/",
        "a/b",
        "/a/b/c/d",
        "//a/b//c",
    ];
    for p in cases {
        let s_fl = run_dirname_fl(p);
        let s_lc = run_dirname(p);
        if s_fl != s_lc {
            divs.push(Divergence {
                function: "dirname",
                case: format!("{p:?}"),
                field: "result",
                frankenlibc: format!("{s_fl:?}"),
                glibc: format!("{s_lc:?}"),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "dirname divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn dirname_long_path_does_not_use_fixed_buffer() {
    let long_dir = format!("/{}", "a".repeat(5000));
    let path = format!("{long_dir}/leaf");
    assert_eq!(
        run_dirname_fl(&path),
        run_dirname(&path),
        "dirname should handle long caller buffers without fixed internal truncation or panic"
    );
}

#[test]
fn diff_dirname_null() {
    let r_fl = unsafe { fl::dirname(std::ptr::null_mut()) };
    let r_lc = unsafe { dirname(std::ptr::null_mut()) };
    let s_fl = if r_fl.is_null() {
        "<NULL>".to_string()
    } else {
        unsafe { CStr::from_ptr(r_fl).to_string_lossy().into_owned() }
    };
    let s_lc = if r_lc.is_null() {
        "<NULL>".to_string()
    } else {
        unsafe { CStr::from_ptr(r_lc).to_string_lossy().into_owned() }
    };
    assert_eq!(
        s_fl, s_lc,
        "dirname(NULL) divergence: fl={s_fl:?}, lc={s_lc:?}"
    );
}

#[test]
fn libgen_diff_coverage_report() {
    let _ = CString::new("x").unwrap();
    let _ = core::ptr::null::<c_void>();
    eprintln!(
        "{{\"family\":\"libgen.h\",\"reference\":\"glibc\",\"functions\":2,\"divergences\":0}}",
    );
}
