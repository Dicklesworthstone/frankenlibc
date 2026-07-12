#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc reentrant lookup oracle; reads the system db

//! Differential gate for the reentrant by-id/by-name lookups getpwuid_r /
//! getgrgid_r / getgrnam_r (bd-c6trbg) — these had no differential gate
//! (getpwnam_r already does). They read the system passwd/group databases, so
//! fl and glibc see the same files. Looks up stable entries (uid 0 / gid 0 /
//! the gid-0 group by its name) and compares the resolved fields + the
//! small-buffer ERANGE path vs glibc. No mocks.

use std::ffi::{CStr, CString, c_char, c_int};

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn getpwuid_r(
            uid: u32,
            pw: *mut libc::passwd,
            buf: *mut c_char,
            n: usize,
            res: *mut *mut libc::passwd,
        ) -> c_int;
        pub fn getgrgid_r(
            gid: u32,
            gr: *mut libc::group,
            buf: *mut c_char,
            n: usize,
            res: *mut *mut libc::group,
        ) -> c_int;
        pub fn getgrnam_r(
            name: *const c_char,
            gr: *mut libc::group,
            buf: *mut c_char,
            n: usize,
            res: *mut *mut libc::group,
        ) -> c_int;
    }
}
use frankenlibc_abi::{grp_abi as flg, pwd_abi as flp};

fn cstr(p: *const c_char) -> String {
    if p.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
    }
}

#[test]
fn getpwuid_r_uid0_matches_glibc() {
    let g = unsafe {
        let mut pw: libc::passwd = std::mem::zeroed();
        let mut buf = [0u8; 2048];
        let mut res: *mut libc::passwd = std::ptr::null_mut();
        let rc = g::getpwuid_r(
            0,
            &mut pw,
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            &mut res,
        );
        (
            rc,
            res.is_null(),
            cstr(pw.pw_name),
            pw.pw_uid,
            pw.pw_gid,
            cstr(pw.pw_dir),
        )
    };
    let f = unsafe {
        let mut pw: libc::passwd = std::mem::zeroed();
        let mut buf = [0u8; 2048];
        let mut res: *mut libc::passwd = std::ptr::null_mut();
        let rc = flp::getpwuid_r(
            0,
            &mut pw,
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            &mut res,
        );
        (
            rc,
            res.is_null(),
            cstr(pw.pw_name),
            pw.pw_uid,
            pw.pw_gid,
            cstr(pw.pw_dir),
        )
    };
    assert_eq!(f, g, "getpwuid_r(0): fl={f:?} glibc={g:?}");
    assert_eq!(g.0, 0, "uid 0 should resolve");
    assert_eq!(g.2, "root");
}

fn members(gr: &libc::group) -> Vec<String> {
    let mut v = Vec::new();
    if !gr.gr_mem.is_null() {
        unsafe {
            let mut i = 0isize;
            while !(*gr.gr_mem.offset(i)).is_null() {
                v.push(cstr(*gr.gr_mem.offset(i)));
                i += 1;
            }
        }
    }
    v
}

#[test]
fn getgrgid_r_gid0_matches_glibc() {
    let g = unsafe {
        let mut gr: libc::group = std::mem::zeroed();
        let mut buf = [0u8; 4096];
        let mut res: *mut libc::group = std::ptr::null_mut();
        let rc = g::getgrgid_r(
            0,
            &mut gr,
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            &mut res,
        );
        (rc, res.is_null(), cstr(gr.gr_name), gr.gr_gid, members(&gr))
    };
    let f = unsafe {
        let mut gr: libc::group = std::mem::zeroed();
        let mut buf = [0u8; 4096];
        let mut res: *mut libc::group = std::ptr::null_mut();
        let rc = flg::getgrgid_r(
            0,
            &mut gr,
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            &mut res,
        );
        (rc, res.is_null(), cstr(gr.gr_name), gr.gr_gid, members(&gr))
    };
    assert_eq!(f, g, "getgrgid_r(0): fl={f:?} glibc={g:?}");
    assert_eq!(g.0, 0, "gid 0 should resolve");

    // getgrnam_r by the same group's name must agree with getgrgid_r(0).
    if let (false, name) = (g.1, &g.2) {
        let cn = CString::new(name.as_str()).unwrap();
        let gn = unsafe {
            let mut gr: libc::group = std::mem::zeroed();
            let mut buf = [0u8; 4096];
            let mut res: *mut libc::group = std::ptr::null_mut();
            let rc = g::getgrnam_r(
                cn.as_ptr(),
                &mut gr,
                buf.as_mut_ptr() as *mut c_char,
                buf.len(),
                &mut res,
            );
            (rc, cstr(gr.gr_name), gr.gr_gid)
        };
        let fn_ = unsafe {
            let mut gr: libc::group = std::mem::zeroed();
            let mut buf = [0u8; 4096];
            let mut res: *mut libc::group = std::ptr::null_mut();
            let rc = flg::getgrnam_r(
                cn.as_ptr(),
                &mut gr,
                buf.as_mut_ptr() as *mut c_char,
                buf.len(),
                &mut res,
            );
            (rc, cstr(gr.gr_name), gr.gr_gid)
        };
        assert_eq!(fn_, gn, "getgrnam_r({name:?}): fl={fn_:?} glibc={gn:?}");
    }
}

#[test]
fn getpwuid_r_small_buffer_matches_glibc() {
    let g = unsafe {
        let mut pw: libc::passwd = std::mem::zeroed();
        let mut buf = [0u8; 1];
        let mut res: *mut libc::passwd = std::ptr::null_mut();
        let rc = g::getpwuid_r(
            0,
            &mut pw,
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            &mut res,
        );
        (rc, res.is_null())
    };
    let f = unsafe {
        let mut pw: libc::passwd = std::mem::zeroed();
        let mut buf = [0u8; 1];
        let mut res: *mut libc::passwd = std::ptr::null_mut();
        let rc = flp::getpwuid_r(
            0,
            &mut pw,
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
            &mut res,
        );
        (rc, res.is_null())
    };
    assert_eq!(f, g, "getpwuid_r(0, tiny buf): fl={f:?} glibc={g:?}");
    assert_eq!(
        g.0,
        libc::ERANGE,
        "glibc returns ERANGE on too-small buffer"
    );
}
