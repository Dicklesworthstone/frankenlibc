#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // GLOB_ALTDIRFUNC callbacks + live host-glibc oracle

//! Differential test for `glob` GLOB_ALTDIRFUNC (bd-2g7oyh.92): the caller's
//! gl_opendir/gl_readdir/gl_closedir/gl_stat/gl_lstat callbacks must drive the
//! whole walk. The `cb_readdir` callback here wraps the real `readdir` but SKIPS
//! any entry whose name starts with `x`. So an engine that honours
//! GLOB_ALTDIRFUNC never sees `xhidden.txt`, whereas one that bypassed the
//! callbacks and used `std::fs` directly WOULD — proving fl actually routes
//! through the callbacks, and that it matches host glibc step for step.

use std::ffi::{CString, c_char, c_int, c_void};

use frankenlibc_abi::string_abi as fl;

// glibc's `glob_t` with the GNU GLOB_ALTDIRFUNC callbacks (x86_64 layout). The
// `libc` crate's `glob_t` doesn't expose these fields, so mirror it here.
#[repr(C)]
struct GlobT {
    gl_pathc: usize,
    gl_pathv: *mut *mut c_char,
    gl_offs: usize,
    gl_flags: c_int,
    gl_closedir: Option<unsafe extern "C" fn(*mut c_void)>,
    gl_readdir: Option<unsafe extern "C" fn(*mut c_void) -> *mut c_void>,
    gl_opendir: Option<unsafe extern "C" fn(*const c_char) -> *mut c_void>,
    gl_lstat: Option<unsafe extern "C" fn(*const c_char, *mut c_void) -> c_int>,
    gl_stat: Option<unsafe extern "C" fn(*const c_char, *mut c_void) -> c_int>,
}

unsafe extern "C" {
    fn glob(
        p: *const c_char,
        f: c_int,
        ef: Option<unsafe extern "C" fn(*const c_char, c_int) -> c_int>,
        g: *mut c_void,
    ) -> c_int;
    fn globfree(g: *mut c_void);
}

const GLOB_ALTDIRFUNC: c_int = 0x200;
const GLOB_MARK: c_int = 0x08;

unsafe extern "C" fn cb_opendir(p: *const c_char) -> *mut c_void {
    unsafe { libc::opendir(p) as *mut c_void }
}
unsafe extern "C" fn cb_readdir(d: *mut c_void) -> *mut c_void {
    loop {
        let e = unsafe { libc::readdir(d as *mut libc::DIR) };
        if e.is_null() {
            return std::ptr::null_mut();
        }
        // Skip entries whose name begins with 'x' — the marker that proves the
        // glob engine is going through THIS callback, not std::fs.
        let first = unsafe { (*e).d_name[0] } as u8;
        if first != b'x' {
            return e as *mut c_void;
        }
    }
}
unsafe extern "C" fn cb_closedir(d: *mut c_void) {
    unsafe { libc::closedir(d as *mut libc::DIR) };
}
unsafe extern "C" fn cb_stat(p: *const c_char, b: *mut c_void) -> c_int {
    unsafe { libc::stat(p, b as *mut libc::stat) }
}
unsafe extern "C" fn cb_lstat(p: *const c_char, b: *mut c_void) -> c_int {
    unsafe { libc::lstat(p, b as *mut libc::stat) }
}

fn install_callbacks(g: &mut GlobT) {
    g.gl_opendir = Some(cb_opendir);
    g.gl_readdir = Some(cb_readdir);
    g.gl_closedir = Some(cb_closedir);
    g.gl_stat = Some(cb_stat);
    g.gl_lstat = Some(cb_lstat);
}

fn collect(g: &GlobT, ret: c_int, dir: &str) -> Vec<String> {
    if ret != 0 || g.gl_pathv.is_null() {
        return vec![format!("<ret={ret}>")];
    }
    let mut out = vec![];
    for i in 0..g.gl_pathc {
        let p = unsafe { *g.gl_pathv.add(i) };
        if p.is_null() {
            break;
        }
        let mut b = vec![];
        let mut j = 0isize;
        loop {
            let c = unsafe { *p.offset(j) } as u8;
            if c == 0 {
                break;
            }
            b.push(c);
            j += 1;
        }
        // Strip the temp-dir prefix so results are comparable + path-independent.
        let s = String::from_utf8_lossy(&b).into_owned();
        out.push(s.strip_prefix(dir).map(|r| r.to_string()).unwrap_or(s));
    }
    out.sort();
    out
}

fn run_fl(pat: &str, flags: c_int, dir: &str) -> (c_int, Vec<String>) {
    let cp = CString::new(pat).unwrap();
    let mut g: GlobT = unsafe { std::mem::zeroed() };
    install_callbacks(&mut g);
    let r = unsafe { fl::glob(cp.as_ptr(), flags, None, (&mut g) as *mut GlobT as *mut c_void) };
    let out = collect(&g, r, dir);
    if r == 0 {
        unsafe { fl::globfree((&mut g) as *mut GlobT as *mut c_void) };
    }
    (r, out)
}

fn run_host(pat: &str, flags: c_int, dir: &str) -> (c_int, Vec<String>) {
    let cp = CString::new(pat).unwrap();
    let mut g: GlobT = unsafe { std::mem::zeroed() };
    install_callbacks(&mut g);
    let r = unsafe { glob(cp.as_ptr(), flags, None, (&mut g) as *mut GlobT as *mut c_void) };
    let out = collect(&g, r, dir);
    if r == 0 {
        unsafe { globfree((&mut g) as *mut GlobT as *mut c_void) };
    }
    (r, out)
}

#[test]
fn glob_altdirfunc_matches_glibc() {
    let dir = std::env::temp_dir().join(format!("fl_glob_altdir_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    for f in ["a.txt", "b.txt", "c.log", "xhidden.txt", "xskip.log"] {
        std::fs::write(dir.join(f), b"x").unwrap();
    }
    std::fs::create_dir_all(dir.join("sub")).unwrap();
    std::fs::write(dir.join("sub").join("deep.txt"), b"x").unwrap();
    std::fs::create_dir_all(dir.join("xsubdir")).unwrap();
    let dprefix = format!("{}/", dir.display());

    for (pat, flags) in [
        ("*", GLOB_ALTDIRFUNC),
        ("*.txt", GLOB_ALTDIRFUNC),
        ("*", GLOB_ALTDIRFUNC | GLOB_MARK),
        ("*/deep.txt", GLOB_ALTDIRFUNC),
        ("?.txt", GLOB_ALTDIRFUNC),
        ("[ab].txt", GLOB_ALTDIRFUNC),
        ("x*", GLOB_ALTDIRFUNC), // pattern targets the skipped names -> NOMATCH both
        ("sub/*", GLOB_ALTDIRFUNC),
    ] {
        let full = format!("{dprefix}{pat}");
        let f = run_fl(&full, flags, &dprefix);
        let h = run_host(&full, flags, &dprefix);
        assert_eq!(f, h, "glob({pat:?}, {flags:#x}) ALTDIRFUNC diverged: fl={f:?} glibc={h:?}");
    }

    // Sanity: the marker file must actually be filtered (proves callbacks ran).
    let (_, paths) = run_fl(&format!("{dprefix}*"), GLOB_ALTDIRFUNC, &dprefix);
    assert!(
        !paths.iter().any(|p| p.starts_with('x')),
        "GLOB_ALTDIRFUNC readdir filter not honoured (std::fs bypass?): {paths:?}"
    );
    assert!(paths.contains(&"a.txt".to_string()), "expected a.txt in {paths:?}");

    let _ = std::fs::remove_dir_all(&dir);
}
