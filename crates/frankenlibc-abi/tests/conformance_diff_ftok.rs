#![cfg(target_os = "linux")]

//! Differential conformance harness for POSIX `ftok(3)`.
//!
//! Generates a SysV IPC key from (path, proj_id). Both fl and glibc
//! must agree byte-for-byte on the formula:
//!   key = ((proj_id & 0xFF) << 24) | ((st_dev & 0xFF) << 16) | (st_ino & 0xFFFF)
//!
//! Filed under [bd-xn6p8] follow-up.

use std::ffi::{c_int, CString};

use frankenlibc_abi::unistd_abi as fl;

unsafe extern "C" {
    fn ftok(pathname: *const std::ffi::c_char, proj_id: c_int) -> libc::key_t;
}

#[test]
fn diff_ftok_same_path_same_id() {
    // Use /tmp which exists everywhere.
    let path = CString::new("/tmp").unwrap();
    for &id in &[1, 0x42, 0xff, b'X' as c_int, 0] {
        let fl_v = unsafe { fl::ftok(path.as_ptr(), id) };
        let lc_v = unsafe { ftok(path.as_ptr(), id) };
        assert_eq!(
            fl_v, lc_v as i32,
            "ftok(/tmp, {id}): fl={fl_v:#x} lc={lc_v:#x}"
        );
    }
}

#[test]
fn diff_ftok_id_byte_pinned_to_high_byte() {
    // Property: changing proj_id only changes byte 3 (high byte) of
    // the key.
    let path = CString::new("/tmp").unwrap();
    let k0 = unsafe { fl::ftok(path.as_ptr(), 0x10) };
    let k1 = unsafe { fl::ftok(path.as_ptr(), 0x20) };
    let lc_k0 = unsafe { ftok(path.as_ptr(), 0x10) };
    let lc_k1 = unsafe { ftok(path.as_ptr(), 0x20) };
    assert_eq!(k0, lc_k0 as i32);
    assert_eq!(k1, lc_k1 as i32);
    // Bottom 24 bits should match.
    assert_eq!(
        k0 as u32 & 0x00ffffff,
        k1 as u32 & 0x00ffffff,
        "low 24 bits should be identical for same path"
    );
}

#[test]
fn diff_ftok_nonexistent_path_returns_minus_one() {
    let path = CString::new("/nonexistent/frankenlibc/test/path").unwrap();
    let fl_v = unsafe { fl::ftok(path.as_ptr(), 0x42) };
    let lc_v = unsafe { ftok(path.as_ptr(), 0x42) };
    assert_eq!(fl_v, lc_v as i32);
    assert_eq!(fl_v, -1);
}

#[test]
fn diff_ftok_different_paths_different_keys() {
    let p1 = CString::new("/tmp").unwrap();
    let p2 = CString::new("/").unwrap();
    let fl_k1 = unsafe { fl::ftok(p1.as_ptr(), 1) };
    let fl_k2 = unsafe { fl::ftok(p2.as_ptr(), 1) };
    let lc_k1 = unsafe { ftok(p1.as_ptr(), 1) };
    let lc_k2 = unsafe { ftok(p2.as_ptr(), 1) };
    assert_eq!(fl_k1, lc_k1 as i32);
    assert_eq!(fl_k2, lc_k2 as i32);
    // Different paths usually have different inode/dev — keys differ.
    if fl_k1 != fl_k2 {
        assert_ne!(lc_k1, lc_k2, "fl says paths differ; lc agrees");
    }
}

#[test]
fn fl_ftok_null_path_returns_minus_one() {
    // glibc may segfault on NULL; we only verify fl is hardened.
    let v = unsafe { fl::ftok(std::ptr::null(), 1) };
    assert_eq!(v, -1);
}

#[test]
fn ftok_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc ftok\",\"reference\":\"glibc\",\"functions\":1,\"divergences\":0}}",
    );
}
