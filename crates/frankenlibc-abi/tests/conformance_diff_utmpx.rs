#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc utmpx oracle; controlled temp utmpx file

//! Differential gate for the utmpx read accessors (bd-8pl5to): getutxent /
//! getutxid / getutxline (zero tests), driven via utmpxname/setutxent against a
//! CONTROLLED temp utmpx file (crafted struct utmpx records — same 384-byte
//! layout as struct utmp on Linux). Compares the full getutxent enumeration, a
//! getutxline(ut_line) search, and a getutxid(ut_type) search vs glibc by the
//! resolved (ut_type, ut_pid, ut_line, ut_user) fields. No mocks.

use std::ffi::{CStr, CString, c_char};
use std::sync::atomic::{AtomicU64, Ordering};

const USER_PROCESS: i16 = 7;
const DEAD_PROCESS: i16 = 8;

// struct utmpx — identical to struct utmp on Linux x86-64 (384 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
struct Utmpx {
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
const _: () = assert!(
    std::mem::size_of::<Utmpx>() == 384,
    "struct utmpx must be 384 bytes on x86-64"
);

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn utmpxname(file: *const c_char) -> i32;
        pub fn setutxent();
        pub fn endutxent();
        pub fn getutxent() -> *mut Utmpx;
        pub fn getutxline(line: *const Utmpx) -> *mut Utmpx;
        pub fn getutxid(id: *const Utmpx) -> *mut Utmpx;
    }
}
use frankenlibc_abi::unistd_abi as fl;

static CNT: AtomicU64 = AtomicU64::new(0);

fn set_arr(dst: &mut [c_char], s: &str) {
    for (d, b) in dst.iter_mut().zip(s.bytes()) {
        *d = b as c_char;
    }
}
fn rec(typ: i16, pid: i32, line: &str, id: &str, user: &str) -> Utmpx {
    let mut u: Utmpx = unsafe { std::mem::zeroed() };
    u.ut_type = typ;
    u.ut_pid = pid;
    set_arr(&mut u.ut_line, line);
    set_arr(&mut u.ut_id, id);
    set_arr(&mut u.ut_user, user);
    u
}
fn fields(u: &Utmpx) -> (i16, i32, String, String) {
    let s = |a: &[c_char]| {
        unsafe { CStr::from_ptr(a.as_ptr()) }
            .to_string_lossy()
            .into_owned()
    };
    (u.ut_type, u.ut_pid, s(&u.ut_line), s(&u.ut_user))
}

fn write_utmpx() -> (std::path::PathBuf, CString) {
    let n = CNT.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("fl-utmpx-{}-{}", std::process::id(), n));
    let recs = [
        rec(USER_PROCESS, 1111, "pts/0", "p0", "carol"),
        rec(USER_PROCESS, 2222, "pts/1", "p1", "dave"),
        rec(DEAD_PROCESS, 0, "pts/0", "p0", ""),
    ];
    let mut bytes = Vec::new();
    for r in &recs {
        bytes.extend_from_slice(unsafe {
            std::slice::from_raw_parts(r as *const Utmpx as *const u8, std::mem::size_of::<Utmpx>())
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
    Vec<(i16, i32, String, String)>,
    Option<(i16, i32, String, String)>,
    Option<(i16, i32, String, String)>,
);

fn glibc_probe(path: &CString) -> Probe {
    unsafe {
        let un = g::utmpxname(path.as_ptr());
        let mut all = Vec::new();
        g::setutxent();
        loop {
            let e = g::getutxent();
            if e.is_null() {
                break;
            }
            all.push(fields(&*e));
        }
        g::setutxent();
        let q = rec(USER_PROCESS, 0, "pts/1", "", "");
        let l = g::getutxline(&q);
        let line = if l.is_null() { None } else { Some(fields(&*l)) };
        g::setutxent();
        let qid = rec(USER_PROCESS, 0, "", "p0", "");
        let i = g::getutxid(&qid);
        let id = if i.is_null() { None } else { Some(fields(&*i)) };
        g::endutxent();
        (un, all, line, id)
    }
}
fn fl_probe(path: &CString) -> Probe {
    unsafe {
        let un = fl::utmpxname(path.as_ptr());
        let mut all = Vec::new();
        fl::setutxent();
        loop {
            let e = fl::getutxent() as *mut Utmpx;
            if e.is_null() {
                break;
            }
            all.push(fields(&*e));
        }
        fl::setutxent();
        let q = rec(USER_PROCESS, 0, "pts/1", "", "");
        let l = fl::getutxline(&q as *const Utmpx as *const libc::utmpx) as *mut Utmpx;
        let line = if l.is_null() { None } else { Some(fields(&*l)) };
        fl::setutxent();
        let qid = rec(USER_PROCESS, 0, "", "p0", "");
        let i = fl::getutxid(&qid as *const Utmpx as *const libc::utmpx) as *mut Utmpx;
        let id = if i.is_null() { None } else { Some(fields(&*i)) };
        fl::endutxent();
        (un, all, line, id)
    }
}

#[test]
fn utmpx_accessors_match_glibc() {
    let (path, c) = write_utmpx();
    let gp = glibc_probe(&c);
    let fp = fl_probe(&c);
    let _ = std::fs::remove_file(&path);
    assert_eq!(fp.0, gp.0, "utmpxname rc: fl={} glibc={}", fp.0, gp.0);
    assert_eq!(
        fp.1, gp.1,
        "getutxent enumeration: fl={:?} glibc={:?}",
        fp.1, gp.1
    );
    assert_eq!(
        fp.2, gp.2,
        "getutxline(pts/1): fl={:?} glibc={:?}",
        fp.2, gp.2
    );
    assert_eq!(fp.3, gp.3, "getutxid: fl={:?} glibc={:?}", fp.3, gp.3);
    assert_eq!(gp.1.len(), 3, "glibc should enumerate all 3 records");
}
