#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc fts oracle; controlled temp dir tree

//! Differential gate for the BSD fts tree walk (bd-966cpn): fts_open / fts_read
//! / fts_close. Builds a CONTROLLED temp directory tree and walks it with both
//! impls (FTS_PHYSICAL, no comparator). The traversal order without a
//! comparator is filesystem-defined, so the set of visited entries — each
//! (path-relative, fts_info, fts_level) — is sorted and compared vs glibc.
//! fts visits directories twice (preorder FTS_D=1 + postorder FTS_DP=6) and
//! files once (FTS_F=8). fl's pub FTSENT layout is used to read both impls'
//! results (a misread would itself surface a layout divergence). No mocks.

use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::sync::atomic::{AtomicU64, Ordering};
use frankenlibc_abi::unistd_abi::{self as fl, FTSENT};

const FTS_PHYSICAL: c_int = 0x0010;
static CNT: AtomicU64 = AtomicU64::new(0);

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn fts_open(path_argv: *const *const c_char, options: c_int, compar: *const c_void) -> *mut c_void;
        pub fn fts_read(ftsp: *mut c_void) -> *mut FTSENT;
        pub fn fts_close(ftsp: *mut c_void) -> c_int;
    }
}

fn make_tree() -> std::path::PathBuf {
    let n = CNT.fetch_add(1, Ordering::Relaxed);
    let mut root = std::env::temp_dir();
    root.push(format!("fl-fts-{}-{}", std::process::id(), n));
    std::fs::create_dir_all(root.join("sub")).unwrap();
    std::fs::write(root.join("a.txt"), b"a").unwrap();
    std::fs::write(root.join("b.txt"), b"bb").unwrap();
    std::fs::write(root.join("sub/c.txt"), b"ccc").unwrap();
    root
}

/// Walk via fts_read; collect (path relative to `root`, fts_info, fts_level), sorted.
fn walk(
    root: &str,
    open: unsafe extern "C" fn(*const *const c_char, c_int, *const c_void) -> *mut c_void,
    read: unsafe extern "C" fn(*mut c_void) -> *mut FTSENT,
    close: unsafe extern "C" fn(*mut c_void) -> c_int,
) -> Vec<(String, u16, i16)> {
    let cpath = CString::new(root).unwrap();
    let argv = [cpath.as_ptr(), std::ptr::null()];
    let mut out = Vec::new();
    unsafe {
        let ftsp = open(argv.as_ptr(), FTS_PHYSICAL, std::ptr::null());
        if ftsp.is_null() {
            return out;
        }
        loop {
            let e = read(ftsp);
            if e.is_null() {
                break;
            }
            let full = CStr::from_ptr((*e).fts_path).to_string_lossy().into_owned();
            // Make relative to root so the (random) temp prefix doesn't matter.
            let rel = full.strip_prefix(root).unwrap_or(&full).trim_start_matches('/').to_string();
            out.push((rel, (*e).fts_info, (*e).fts_level));
        }
        close(ftsp);
    }
    out.sort();
    out
}

#[test]
fn fts_traversal_matches_glibc() {
    let root = make_tree();
    let rs = root.to_string_lossy().into_owned();
    let g = walk(&rs, g::fts_open, g::fts_read, g::fts_close);
    // fl::fts_open's 3rd arg is Option<fn> (a nullable fn pointer) — ABI-identical
    // to *const c_void, so transmute it to the walk-helper signature (we pass null).
    type OpenFn = unsafe extern "C" fn(*const *const c_char, c_int, *const c_void) -> *mut c_void;
    let fl_open: OpenFn = unsafe { std::mem::transmute(fl::fts_open as *const ()) };
    let f = walk(&rs, fl_open, fl::fts_read, fl::fts_close);
    let _ = std::fs::remove_dir_all(&root);
    assert_eq!(f, g, "fts traversal entry set:\n fl={f:#?}\n glibc={g:#?}");
    // sanity: glibc must visit each dir twice (D + DP) and 3 files once.
    assert!(g.iter().filter(|(_, info, _)| *info == 8).count() == 3, "expected 3 files (FTS_F)");
    assert!(g.iter().filter(|(_, info, _)| *info == 1).count() == 2, "expected 2 preorder dirs (root+sub)");
}
