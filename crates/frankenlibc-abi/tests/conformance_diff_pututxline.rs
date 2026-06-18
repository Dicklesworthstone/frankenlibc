#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc utmpx oracle + real temp utmp files

//! Differential gate for pututxline overwrite-vs-append (bd-mx8ikd). Writing a
//! record and then writing it again with the SAME ut_id must OVERWRITE in place
//! (1 record on disk), not append a duplicate; two DISTINCT ut_ids must produce
//! two records. fl must match host glibc on the resulting file size. fl and
//! glibc keep independent utmp state (separate utmpxname paths), so the two are
//! driven on separate temp files. No mocks.

use std::ffi::{c_char, c_int, CString};
use std::sync::atomic::{AtomicU64, Ordering};

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn utmpxname(file: *const c_char) -> c_int;
        pub fn setutxent();
        pub fn pututxline(ut: *const libc::utmpx) -> *mut libc::utmpx;
        pub fn endutxent();
    }
}
use frankenlibc_abi::unistd_abi as fl;

static CNT: AtomicU64 = AtomicU64::new(0);
fn tmp_path(tag: &str) -> (std::path::PathBuf, CString) {
    let n = CNT.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("fl-utmpx-{}-{}-{}", std::process::id(), tag, n));
    let _ = std::fs::remove_file(&p);
    let c = CString::new(p.to_string_lossy().as_bytes()).unwrap();
    (p, c)
}

fn rec(id: &[u8], line: &[u8], pid: c_int) -> libc::utmpx {
    let mut u: libc::utmpx = unsafe { std::mem::zeroed() };
    u.ut_type = libc::USER_PROCESS;
    u.ut_pid = pid;
    for (i, b) in id.iter().take(u.ut_id.len()).enumerate() {
        u.ut_id[i] = *b as c_char;
    }
    for (i, b) in line.iter().take(u.ut_line.len()).enumerate() {
        u.ut_line[i] = *b as c_char;
    }
    u
}

const RS: u64 = std::mem::size_of::<libc::utmpx>() as u64;

fn fl_run(seq: &[(&[u8], &[u8], c_int)]) -> u64 {
    let (path, c) = tmp_path("f");
    unsafe { fl::utmpxname(c.as_ptr()) };
    unsafe { fl::setutxent() };
    for (id, line, pid) in seq {
        unsafe { fl::pututxline(&rec(id, line, *pid)) };
    }
    unsafe { fl::endutxent() };
    let len = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(u64::MAX);
    let _ = std::fs::remove_file(&path);
    len
}

fn glibc_run(seq: &[(&[u8], &[u8], c_int)]) -> u64 {
    let (path, c) = tmp_path("g");
    unsafe { g::utmpxname(c.as_ptr()) };
    unsafe { g::setutxent() };
    for (id, line, pid) in seq {
        unsafe { g::pututxline(&rec(id, line, *pid)) };
    }
    unsafe { g::endutxent() };
    let len = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(u64::MAX);
    let _ = std::fs::remove_file(&path);
    len
}

#[test]
fn pututxline_overwrites_same_id() {
    // Same ut_id twice -> one record (overwrite).
    let seq: &[(&[u8], &[u8], c_int)] = &[(b"t1", b"pts/1", 100), (b"t1", b"pts/1", 200)];
    let f = fl_run(seq);
    let gg = glibc_run(seq);
    assert_eq!(gg, RS, "glibc: same-id must overwrite (1 record)");
    assert_eq!(f, gg, "fl produced {} records, glibc {} (RS={RS})", f / RS, gg / RS);
}

#[test]
fn pututxline_appends_distinct_ids() {
    // Distinct ut_ids -> two records.
    let seq: &[(&[u8], &[u8], c_int)] = &[(b"t1", b"pts/1", 100), (b"t2", b"pts/2", 200)];
    let f = fl_run(seq);
    let gg = glibc_run(seq);
    assert_eq!(gg, 2 * RS, "glibc: distinct ids -> 2 records");
    assert_eq!(f, gg, "fl produced {} records, glibc {}", f / RS, gg / RS);
}
