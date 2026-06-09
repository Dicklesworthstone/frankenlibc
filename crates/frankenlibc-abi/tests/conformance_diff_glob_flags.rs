#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc glob oracle

//! `glob` flag-semantics parity vs host glibc (bd-2g7oyh.NEW — coverage).
//!
//! The existing glob_differential_fuzz only exercises GLOB_BRACE / GLOB_NOSORT,
//! while the core implements GLOB_MARK, GLOB_NOCHECK, GLOB_PERIOD, GLOB_NOMAGIC,
//! GLOB_NOESCAPE and GLOB_ONLYDIR. This gate drives both engines over a fixed
//! temp directory (regular files, a hidden file, a subdir) and compares the
//! return code and the sorted match list for each flag and a few combinations.

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use frankenlibc_abi::string_abi as fl;

#[repr(C)]
struct GlobT {
    gl_pathc: usize,
    gl_pathv: *mut *mut c_char,
    gl_offs: usize,
    gl_flags: c_int,
    p1: *mut c_void,
    p2: *mut c_void,
    p3: *mut c_void,
    p4: *mut c_void,
    p5: *mut c_void,
}

unsafe extern "C" {
    fn glob(p: *const c_char, f: c_int, errf: *mut c_void, g: *mut GlobT) -> c_int;
    fn globfree(g: *mut GlobT);
}

const MARK: c_int = 0x0002;
const NOCHECK: c_int = 0x0010;
const NOESCAPE: c_int = 0x0040;
const PERIOD: c_int = 0x0080;
const NOMAGIC: c_int = 0x0800;
const ONLYDIR: c_int = 0x2000;

fn paths(g: &GlobT) -> Vec<String> {
    (0..g.gl_pathc)
        .map(|i| {
            let p = unsafe { *g.gl_pathv.add(i) };
            unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
        })
        .collect()
}

fn run(eng: u8, pat: &str, flags: c_int, dir: &str) -> (c_int, Vec<String>) {
    let cp = CString::new(pat).unwrap();
    let mut g: GlobT = unsafe { std::mem::zeroed() };
    let rc = if eng == 0 {
        unsafe { fl::glob(cp.as_ptr(), flags, None, (&mut g as *mut GlobT).cast()) }
    } else {
        unsafe { glob(cp.as_ptr(), flags, std::ptr::null_mut(), &mut g) }
    };
    let mut ps = if rc == 0 { paths(&g) } else { vec![] };
    // Compare directory-relative paths so the test is location-independent.
    for p in &mut ps {
        *p = p.replace(dir, "");
    }
    ps.sort();
    if rc == 0 {
        if eng == 0 {
            unsafe { fl::globfree((&mut g as *mut GlobT).cast()) };
        } else {
            unsafe { globfree(&mut g) };
        }
    }
    (rc, ps)
}

#[test]
fn glob_flags_match_glibc() {
    let dir = format!("/tmp/fl_glob_flags_{}", std::process::id());
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(format!("{dir}/a.txt"), "").unwrap();
    std::fs::write(format!("{dir}/b.txt"), "").unwrap();
    std::fs::write(format!("{dir}/.hidden"), "").unwrap();
    std::fs::write(format!("{dir}/plain"), "").unwrap();
    std::fs::create_dir(format!("{dir}/subdir")).unwrap();

    let p = |s: &str| format!("{dir}{s}");
    let cases: &[(String, c_int)] = &[
        (p("/*"), 0),
        (p("/*"), MARK),
        (p("/*"), PERIOD),
        (p("/*"), MARK | PERIOD),
        (p("/.*"), 0),
        (p("/sub*"), MARK),
        (p("/*.txt"), MARK),
        (p("/nomatch*"), 0),
        (p("/nomatch*"), NOCHECK),
        (p("/nomatch"), NOMAGIC),
        (p("/a.txt"), NOMAGIC),
        (p("/*"), ONLYDIR),
        (p("/a*"), NOESCAPE),
        (p("/[a-b].txt"), 0),
        (p("/[a-b].txt"), MARK),
        (p("/*"), NOCHECK | MARK),
    ];
    for (pat, flags) in cases {
        let a = run(0, pat, *flags, &dir);
        let b = run(1, pat, *flags, &dir);
        assert_eq!(a, b, "glob({pat:?}, {flags:#x}): fl={a:?} glibc={b:?}");
    }

    let _ = std::fs::remove_dir_all(&dir);
}
