#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc utmp oracle; controlled temp utmp file

//! Differential gate for the utmp accessors (bd-x4lczy): utmpname / setutent /
//! getutent / getutline / getutid / endutent. The real /var/run/utmp is
//! volatile, so this points both impls at a CONTROLLED temp utmp file (crafted
//! struct utmp records) via utmpname() and compares: the full getutent
//! enumeration, a getutline(ut_line) search, and a getutid(ut_type) search vs
//! glibc — by the resolved (ut_type, ut_pid, ut_line, ut_user) fields. No mocks.

use std::ffi::{c_char, c_void, CStr, CString};
use std::sync::atomic::{AtomicU64, Ordering};

const USER_PROCESS: i16 = 7;
const DEAD_PROCESS: i16 = 8;

// struct utmp — Linux x86-64 layout (384 bytes); libc crate doesn't bind it.
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
const _: () = assert!(std::mem::size_of::<Utmp>() == 384, "struct utmp must be 384 bytes on x86-64");

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn utmpname(file: *const c_char) -> i32;
        pub fn setutent();
        pub fn endutent();
        pub fn getutent() -> *mut Utmp;
        pub fn getutline(line: *const Utmp) -> *mut Utmp;
        pub fn getutid(id: *const Utmp) -> *mut Utmp;
    }
}
use frankenlibc_abi::unistd_abi as fl;

fn set_arr(dst: &mut [c_char], s: &str) {
    for (d, b) in dst.iter_mut().zip(s.bytes()) {
        *d = b as c_char;
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
        let p = a.as_ptr();
        unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
    };
    (u.ut_type, u.ut_pid, s(&u.ut_line), s(&u.ut_user))
}

fn write_utmp() -> (std::path::PathBuf, CString) {
    let n = CNT.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("fl-utmp-{}-{}", std::process::id(), n));
    let recs = [
        rec(USER_PROCESS, 1234, "tty1", "1", "alice"),
        rec(USER_PROCESS, 5678, "tty2", "2", "bob"),
        rec(DEAD_PROCESS, 0, "tty1", "1", ""),
    ];
    let mut bytes = Vec::new();
    for r in &recs {
        let b = unsafe { std::slice::from_raw_parts(r as *const Utmp as *const u8, std::mem::size_of::<Utmp>()) };
        bytes.extend_from_slice(b);
    }
    std::fs::write(&p, &bytes).unwrap();
    (p.clone(), CString::new(p.to_string_lossy().as_bytes()).unwrap())
}

static CNT: AtomicU64 = AtomicU64::new(0);

type Probe = (i32, Vec<(i16, i32, String, String)>, Option<(i16, i32, String, String)>, Option<(i16, i32, String, String)>);

fn glibc_probe(path: &CString) -> Probe {
    unsafe {
        let un = g::utmpname(path.as_ptr());
        let mut all = Vec::new();
        g::setutent();
        loop {
            let e = g::getutent();
            if e.is_null() { break; }
            all.push(fields(&*e));
        }
        // getutline by ut_line "tty2"
        g::setutent();
        let q = rec(USER_PROCESS, 0, "tty2", "", "");
        let l = g::getutline(&q);
        let line = if l.is_null() { None } else { Some(fields(&*l)) };
        // getutid by ut_type USER_PROCESS
        g::setutent();
        let qid = rec(USER_PROCESS, 0, "", "1", "");
        let i = g::getutid(&qid);
        let id = if i.is_null() { None } else { Some(fields(&*i)) };
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
            let e = fl::getutent() as *mut Utmp;
            if e.is_null() { break; }
            all.push(fields(&*e));
        }
        fl::setutent();
        let q = rec(USER_PROCESS, 0, "tty2", "", "");
        let l = fl::getutline(&q as *const _ as *const c_void) as *mut Utmp;
        let line = if l.is_null() { None } else { Some(fields(&*l)) };
        fl::setutent();
        let qid = rec(USER_PROCESS, 0, "", "1", "");
        let i = fl::getutid(&qid as *const _ as *const c_void) as *mut Utmp;
        let id = if i.is_null() { None } else { Some(fields(&*i)) };
        fl::endutent();
        (un, all, line, id)
    }
}

#[test]
fn utmp_accessors_match_glibc() {
    let (path, c) = write_utmp();
    let gp = glibc_probe(&c);
    let fp = fl_probe(&c);
    let _ = std::fs::remove_file(&path);
    assert_eq!(fp.0, gp.0, "utmpname rc: fl={} glibc={}", fp.0, gp.0);
    assert_eq!(fp.1, gp.1, "getutent enumeration: fl={:?} glibc={:?}", fp.1, gp.1);
    assert_eq!(fp.2, gp.2, "getutline(tty2): fl={:?} glibc={:?}", fp.2, gp.2);
    assert_eq!(fp.3, gp.3, "getutid(USER_PROCESS): fl={:?} glibc={:?}", fp.3, gp.3);
    assert_eq!(gp.1.len(), 3, "glibc should enumerate all 3 records");
}
