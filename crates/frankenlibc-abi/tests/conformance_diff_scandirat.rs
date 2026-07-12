#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc scandirat oracle; real temp dir

//! Differential gate for scandirat (bd-kpmvw7) — the *at variant of scandir had
//! NO test at all. Creates a temp directory with a known set of entries, then
//! scans it relative to AT_FDCWD with both glibc's and fl's scandirat (NULL
//! filter + NULL comparator, so all entries in directory order — avoids passing
//! function-pointer ABIs). The returned entry-name SETS (sorted Rust-side) and
//! the count must match. Each impl's namelist is freed with its own allocator.
//! No mocks.

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::sync::atomic::{AtomicU64, Ordering};

const AT_FDCWD: c_int = -100;

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn scandirat(
            dirfd: c_int,
            dirp: *const c_char,
            namelist: *mut *mut *mut c_void,
            filter: *mut c_void,
            compar: *mut c_void,
        ) -> c_int;
        pub fn free(p: *mut c_void);
    }
}
use frankenlibc_abi::{glibc_internal_abi as flg, malloc_abi as flm};

static CNT: AtomicU64 = AtomicU64::new(0);

fn d_name(entry: *mut c_void) -> String {
    // struct dirent: d_ino(8) d_off(8) d_reclen(2) d_type(1) d_name[]@19
    let name_ptr = unsafe { (entry as *const u8).add(19) as *const c_char };
    unsafe { CStr::from_ptr(name_ptr) }
        .to_string_lossy()
        .into_owned()
}

/// Collect (count, sorted names) and free the namelist with `freefn`.
fn collect(nl: *mut *mut c_void, n: c_int, freefn: unsafe fn(*mut c_void)) -> (i32, Vec<String>) {
    let mut names = Vec::new();
    if n >= 0 && !nl.is_null() {
        for i in 0..n as isize {
            let entry = unsafe { *nl.offset(i) };
            names.push(d_name(entry));
            unsafe { freefn(entry) };
        }
        unsafe { freefn(nl as *mut c_void) };
    }
    names.sort();
    (n, names)
}

#[test]
fn scandirat_matches_glibc() {
    // Build a temp directory with a known entry set.
    let id = CNT.fetch_add(1, Ordering::Relaxed);
    let mut dir = std::env::temp_dir();
    dir.push(format!("fl-scandirat-{}-{}", std::process::id(), id));
    std::fs::create_dir_all(&dir).unwrap();
    for name in ["alpha.txt", "beta.log", "gamma", "zeta.dat"] {
        std::fs::write(dir.join(name), b"x").unwrap();
    }
    std::fs::create_dir_all(dir.join("subdir")).unwrap();
    let cdir = CString::new(dir.to_string_lossy().as_bytes()).unwrap();

    // glibc
    let mut gnl: *mut *mut c_void = std::ptr::null_mut();
    let gn = unsafe {
        g::scandirat(
            AT_FDCWD,
            cdir.as_ptr(),
            &mut gnl,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    let (gc, gnames) = collect(gnl, gn, |p| unsafe { g::free(p) });

    // fl
    let mut fnl: *mut *mut c_void = std::ptr::null_mut();
    let fnn = unsafe {
        flg::scandirat(
            AT_FDCWD,
            cdir.as_ptr(),
            &mut fnl,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    let (fc, fnames) = collect(fnl, fnn, |p| unsafe { flm::free(p) });

    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(fc, gc, "scandirat count: fl={fc} glibc={gc}");
    assert_eq!(
        fnames, gnames,
        "scandirat entry set: fl={fnames:?} glibc={gnames:?}"
    );
    // sanity: must include the entries we created plus "." and ".."
    assert!(gnames.contains(&"alpha.txt".to_string()) && gnames.contains(&"subdir".to_string()));
    assert!(gnames.contains(&".".to_string()) && gnames.contains(&"..".to_string()));
}
