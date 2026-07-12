#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc reentrant-utmp oracle; controlled temp utmp file

//! Differential gate for the reentrant utmp accessors (bd-2kfbv6): getutent_r /
//! getutid_r / getutline_r. Distinct from the non-_r forms via the caller-buffer
//! protocol (buffer + result-pointer, returns 0/-1). Driven via utmpname against
//! a CONTROLLED temp utmp file of crafted struct utmp records; compares the
//! getutent_r enumeration, a getutline_r(ut_line) search, and a getutid_r
//! (ut_type) search vs glibc by resolved (ut_type, ut_pid, ut_line, ut_user)
//! plus each call's return code. No mocks.

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::sync::atomic::{AtomicU64, Ordering};

const USER_PROCESS: i16 = 7;
const DEAD_PROCESS: i16 = 8;

#[repr(C)]
#[derive(Clone, Copy)]
struct Utmp {
    ut_type: i16,
    __pad: i16,
    ut_pid: i32,
    ut_line: [c_char; 32],
    ut_id: [c_char; 4],
    ut_user: [c_char; 32],
    ut_host: [c_char; 256],
    ut_exit: [i16; 2],
    ut_session: i32,
    ut_tv: [i32; 2],
    ut_addr_v6: [i32; 4],
    __reserved: [u8; 20],
}
const _: () = assert!(std::mem::size_of::<Utmp>() == 384);

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn utmpname(file: *const c_char) -> i32;
        pub fn setutent();
        pub fn endutent();
        pub fn getutent_r(buf: *mut Utmp, res: *mut *mut Utmp) -> c_int;
        pub fn getutline_r(line: *const Utmp, buf: *mut Utmp, res: *mut *mut Utmp) -> c_int;
        pub fn getutid_r(id: *const Utmp, buf: *mut Utmp, res: *mut *mut Utmp) -> c_int;
    }
}
use frankenlibc_abi::unistd_abi as fl;

static CNT: AtomicU64 = AtomicU64::new(0);
fn set_arr(d: &mut [c_char], s: &str) {
    for (x, b) in d.iter_mut().zip(s.bytes()) {
        *x = b as c_char;
    }
}
fn rec(typ: i16, pid: i32, line: &str, id: &str, user: &str) -> Utmp {
    let mut u: Utmp = unsafe { std::mem::zeroed() };
    u.ut_type = typ;
    u.ut_pid = pid;
    set_arr(&mut u.ut_line, line);
    set_arr(&mut u.ut_id, id);
    set_arr(&mut u.ut_user, user);
    u
}
fn fields(u: &Utmp) -> (i16, i32, String, String) {
    let s = |a: &[c_char]| {
        unsafe { CStr::from_ptr(a.as_ptr()) }
            .to_string_lossy()
            .into_owned()
    };
    (u.ut_type, u.ut_pid, s(&u.ut_line), s(&u.ut_user))
}
fn write_utmp() -> (std::path::PathBuf, CString) {
    let n = CNT.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("fl-utmpr-{}-{}", std::process::id(), n));
    let recs = [
        rec(USER_PROCESS, 1234, "tty1", "1", "alice"),
        rec(USER_PROCESS, 5678, "tty2", "2", "bob"),
        rec(DEAD_PROCESS, 0, "tty1", "1", ""),
    ];
    let mut bytes = Vec::new();
    for r in &recs {
        bytes.extend_from_slice(unsafe {
            std::slice::from_raw_parts(r as *const Utmp as *const u8, 384)
        });
    }
    std::fs::write(&p, &bytes).unwrap();
    (
        p.clone(),
        CString::new(p.to_string_lossy().as_bytes()).unwrap(),
    )
}

type Probe = (
    i32,
    Vec<(c_int, (i16, i32, String, String))>,
    (c_int, Option<(i16, i32, String, String)>),
    (c_int, Option<(i16, i32, String, String)>),
);

fn glibc_probe(path: &CString) -> Probe {
    unsafe {
        let un = g::utmpname(path.as_ptr());
        let mut all = Vec::new();
        g::setutent();
        loop {
            let mut buf: Utmp = std::mem::zeroed();
            let mut res: *mut Utmp = std::ptr::null_mut();
            let rc = g::getutent_r(&mut buf, &mut res);
            if res.is_null() {
                break;
            }
            all.push((rc, fields(&*res)));
        }
        g::setutent();
        let q = rec(USER_PROCESS, 0, "tty2", "", "");
        let mut buf: Utmp = std::mem::zeroed();
        let mut res: *mut Utmp = std::ptr::null_mut();
        let lrc = g::getutline_r(&q, &mut buf, &mut res);
        let line = (
            lrc,
            if res.is_null() {
                None
            } else {
                Some(fields(&*res))
            },
        );
        g::setutent();
        let qid = rec(USER_PROCESS, 0, "", "1", "");
        let mut buf2: Utmp = std::mem::zeroed();
        let mut res2: *mut Utmp = std::ptr::null_mut();
        let irc = g::getutid_r(&qid, &mut buf2, &mut res2);
        let id = (
            irc,
            if res2.is_null() {
                None
            } else {
                Some(fields(&*res2))
            },
        );
        g::endutent();
        (un, all, line, id)
    }
}
fn fl_probe(path: &CString) -> Probe {
    unsafe {
        let un = fl::utmpname(path.as_ptr());
        let mut all = Vec::new();
        fl::setutent();
        loop {
            let mut buf: Utmp = std::mem::zeroed();
            let mut res: *mut c_void = std::ptr::null_mut();
            let rc = fl::getutent_r(&mut buf as *mut _ as *mut c_void, &mut res);
            if res.is_null() {
                break;
            }
            all.push((rc, fields(&*(res as *const Utmp))));
        }
        fl::setutent();
        let q = rec(USER_PROCESS, 0, "tty2", "", "");
        let mut buf: Utmp = std::mem::zeroed();
        let mut res: *mut c_void = std::ptr::null_mut();
        let lrc = fl::getutline_r(
            &q as *const _ as *const c_void,
            &mut buf as *mut _ as *mut c_void,
            &mut res,
        );
        let line = (
            lrc,
            if res.is_null() {
                None
            } else {
                Some(fields(&*(res as *const Utmp)))
            },
        );
        fl::setutent();
        let qid = rec(USER_PROCESS, 0, "", "1", "");
        let mut buf2: Utmp = std::mem::zeroed();
        let mut res2: *mut c_void = std::ptr::null_mut();
        let irc = fl::getutid_r(
            &qid as *const _ as *const c_void,
            &mut buf2 as *mut _ as *mut c_void,
            &mut res2,
        );
        let id = (
            irc,
            if res2.is_null() {
                None
            } else {
                Some(fields(&*(res2 as *const Utmp)))
            },
        );
        fl::endutent();
        (un, all, line, id)
    }
}

#[test]
fn reentrant_utmp_accessors_match_glibc() {
    let (path, c) = write_utmp();
    let gp = glibc_probe(&c);
    let fp = fl_probe(&c);
    let _ = std::fs::remove_file(&path);
    assert_eq!(fp.0, gp.0, "utmpname rc");
    assert_eq!(
        fp.1, gp.1,
        "getutent_r enumeration: fl={:?} glibc={:?}",
        fp.1, gp.1
    );
    assert_eq!(fp.2, gp.2, "getutline_r: fl={:?} glibc={:?}", fp.2, gp.2);
    assert_eq!(fp.3, gp.3, "getutid_r: fl={:?} glibc={:?}", fp.3, gp.3);
    assert_eq!(gp.1.len(), 3, "glibc should enumerate 3 records");
}
