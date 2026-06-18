#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc setmntent/getmntent oracle over a temp file

//! Differential gate for the non-reentrant getmntent (static-buffer variant) vs
//! host glibc (bd-35m9c7). getmntent_r has a gate (mntent_escape), but the
//! static-buffer getmntent — which parses the same fstab/mtab line grammar but
//! returns a pointer into a per-stream/static buffer — was fl-internal only.
//! Parses a temp mtab covering octal escapes (\040 space), comment lines,
//! short lines (missing freq/passno default to 0), and multiple opts, then
//! compares fl's parsed entries field-by-field against glibc. Strings are
//! copied before the next getmntent overwrites the buffer. No mocks.

use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::sync::atomic::{AtomicU64, Ordering};

#[repr(C)]
struct Mntent {
    mnt_fsname: *mut c_char,
    mnt_dir: *mut c_char,
    mnt_type: *mut c_char,
    mnt_opts: *mut c_char,
    mnt_freq: c_int,
    mnt_passno: c_int,
}

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn setmntent(file: *const c_char, mode: *const c_char) -> *mut c_void;
        pub fn getmntent(stream: *mut c_void) -> *mut Mntent;
        pub fn endmntent(stream: *mut c_void) -> c_int;
    }
}
use frankenlibc_abi::unistd_abi as fl;

static CNT: AtomicU64 = AtomicU64::new(0);

const MTAB: &str =
    "/dev/sda1 / ext4 rw,relatime 0 1\n\
     proc /proc proc rw,nosuid,nodev 0 0\n\
     # this is a comment line, must be skipped\n\
     tmpfs /tmp\\040dir tmpfs rw,size=1G 0 0\n\
     /dev/sdb /mnt defaults\n\
     none /sys/fs/cgroup\\040x cgroup2 rw 0 0\n";

type Entry = (String, String, String, String, c_int, c_int);

unsafe fn cstr(p: *const c_char) -> String {
    if p.is_null() {
        String::from("<null>")
    } else {
        unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
    }
}

fn parse_fl(path: &CStr) -> Vec<Entry> {
    let mut out = Vec::new();
    unsafe {
        let s = fl::setmntent(path.as_ptr(), c"r".as_ptr());
        assert!(!s.is_null(), "fl setmntent");
        loop {
            let e = fl::getmntent(s) as *mut Mntent;
            if e.is_null() {
                break;
            }
            let e = &*e;
            out.push((
                cstr(e.mnt_fsname), cstr(e.mnt_dir), cstr(e.mnt_type),
                cstr(e.mnt_opts), e.mnt_freq, e.mnt_passno,
            ));
        }
        fl::endmntent(s);
    }
    out
}

fn parse_glibc(path: &CStr) -> Vec<Entry> {
    let mut out = Vec::new();
    unsafe {
        let s = g::setmntent(path.as_ptr(), c"r".as_ptr());
        assert!(!s.is_null(), "glibc setmntent");
        loop {
            let e = g::getmntent(s);
            if e.is_null() {
                break;
            }
            let e = &*e;
            out.push((
                cstr(e.mnt_fsname), cstr(e.mnt_dir), cstr(e.mnt_type),
                cstr(e.mnt_opts), e.mnt_freq, e.mnt_passno,
            ));
        }
        g::endmntent(s);
    }
    out
}

#[test]
fn getmntent_matches_glibc() {
    let n = CNT.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("fl-mtab-{}-{}", std::process::id(), n));
    std::fs::write(&p, MTAB).unwrap();
    let cpath = CString::new(p.to_string_lossy().as_bytes()).unwrap();

    let fl_entries = parse_fl(&cpath);
    let g_entries = parse_glibc(&cpath);
    let _ = std::fs::remove_file(&p);

    assert_eq!(fl_entries.len(), g_entries.len(), "entry count: fl={} glibc={}", fl_entries.len(), g_entries.len());
    for (i, (f, gg)) in fl_entries.iter().zip(g_entries.iter()).enumerate() {
        assert_eq!(f, gg, "mntent entry {i}: fl={f:?} glibc={gg:?}");
    }
    // sanity: comment skipped, escape decoded, short line defaults to 0/0.
    assert!(g_entries.iter().any(|e| e.1 == "/tmp dir"), "octal escape \\040 should decode to space");
    assert_eq!(g_entries.len(), 5, "comment line must be skipped (5 real entries)");
}
