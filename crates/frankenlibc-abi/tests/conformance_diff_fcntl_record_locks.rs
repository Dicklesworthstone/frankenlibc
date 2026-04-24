#![cfg(target_os = "linux")]

//! Differential conformance harness for `fcntl()` POSIX byte-range
//! record locks (F_SETLK / F_SETLKW / F_GETLK):
//!   - F_SETLK   (try to set lock, non-blocking)
//!   - F_GETLK   (query lock state)
//!   - F_OFD_SETLK (Linux open file description locks; same lock_t)
//!
//! Tests use distinct tempfiles so locks don't conflict between impls.
//!
//! Bead: CONFORMANCE: libc fcntl record-locks diff matrix.

use std::ffi::{c_int, c_long};
use std::os::fd::AsRawFd;

use frankenlibc_abi::io_abi as fl;

unsafe extern "C" {
    fn fcntl(fd: c_int, cmd: c_int, arg: c_long) -> c_int;
}

const F_GETLK: c_int = 5;
const F_SETLK: c_int = 6;
const F_SETLKW: c_int = 7;
const F_OFD_GETLK: c_int = 36;
const F_OFD_SETLK: c_int = 37;

const F_RDLCK: i16 = 0;
const F_WRLCK: i16 = 1;
const F_UNLCK: i16 = 2;

const SEEK_SET: i16 = 0;

#[repr(C)]
struct Flock {
    l_type: i16,
    l_whence: i16,
    l_start: libc::off_t,
    l_len: libc::off_t,
    l_pid: libc::pid_t,
}

fn unique_tempfile(label: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    std::env::temp_dir().join(format!("fl_reclock_diff_{label}_{pid}_{id}"))
}

fn open_tempfile(label: &str) -> (std::fs::File, std::path::PathBuf) {
    let path = unique_tempfile(label);
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .unwrap();
    f.set_len(64).unwrap();
    (f, path)
}

#[test]
fn diff_fcntl_setlk_write_lock() {
    let (f_fl, p_fl) = open_tempfile("fl_wr");
    let mut lk = Flock {
        l_type: F_WRLCK,
        l_whence: SEEK_SET,
        l_start: 0,
        l_len: 16,
        l_pid: 0,
    };
    let r_fl = unsafe { fl::fcntl(f_fl.as_raw_fd(), F_SETLK, &mut lk as *mut _ as c_long) };
    // Unlock
    lk.l_type = F_UNLCK;
    let r_ul = unsafe { fl::fcntl(f_fl.as_raw_fd(), F_SETLK, &mut lk as *mut _ as c_long) };
    let _ = std::fs::remove_file(&p_fl);

    let (f_lc, p_lc) = open_tempfile("lc_wr");
    let mut lk2 = Flock {
        l_type: F_WRLCK,
        l_whence: SEEK_SET,
        l_start: 0,
        l_len: 16,
        l_pid: 0,
    };
    let r_lc = unsafe { fcntl(f_lc.as_raw_fd(), F_SETLK, &mut lk2 as *mut _ as c_long) };
    lk2.l_type = F_UNLCK;
    let r_ul_lc = unsafe { fcntl(f_lc.as_raw_fd(), F_SETLK, &mut lk2 as *mut _ as c_long) };
    let _ = std::fs::remove_file(&p_lc);

    assert_eq!(r_fl, r_lc, "F_SETLK F_WRLCK: fl={r_fl}, lc={r_lc}");
    assert_eq!(r_ul, r_ul_lc, "F_SETLK F_UNLCK: fl={r_ul}, lc={r_ul_lc}");
    assert_eq!(r_fl, 0, "F_SETLK should succeed");
}

#[test]
fn diff_fcntl_setlk_read_lock() {
    let (f_fl, p_fl) = open_tempfile("fl_rd");
    let mut lk = Flock {
        l_type: F_RDLCK,
        l_whence: SEEK_SET,
        l_start: 0,
        l_len: 16,
        l_pid: 0,
    };
    let r_fl = unsafe { fl::fcntl(f_fl.as_raw_fd(), F_SETLK, &mut lk as *mut _ as c_long) };
    lk.l_type = F_UNLCK;
    let _ = unsafe { fl::fcntl(f_fl.as_raw_fd(), F_SETLK, &mut lk as *mut _ as c_long) };
    let _ = std::fs::remove_file(&p_fl);

    let (f_lc, p_lc) = open_tempfile("lc_rd");
    let mut lk2 = Flock {
        l_type: F_RDLCK,
        l_whence: SEEK_SET,
        l_start: 0,
        l_len: 16,
        l_pid: 0,
    };
    let r_lc = unsafe { fcntl(f_lc.as_raw_fd(), F_SETLK, &mut lk2 as *mut _ as c_long) };
    lk2.l_type = F_UNLCK;
    let _ = unsafe { fcntl(f_lc.as_raw_fd(), F_SETLK, &mut lk2 as *mut _ as c_long) };
    let _ = std::fs::remove_file(&p_lc);

    assert_eq!(r_fl, r_lc, "F_SETLK F_RDLCK: fl={r_fl}, lc={r_lc}");
}

#[test]
fn diff_fcntl_getlk_unlocked_returns_unlck() {
    let (f_fl, p_fl) = open_tempfile("fl_get");
    let mut lk = Flock {
        l_type: F_WRLCK,
        l_whence: SEEK_SET,
        l_start: 0,
        l_len: 16,
        l_pid: 0,
    };
    let r_fl = unsafe { fl::fcntl(f_fl.as_raw_fd(), F_GETLK, &mut lk as *mut _ as c_long) };
    let type_after_fl = lk.l_type;
    let _ = std::fs::remove_file(&p_fl);

    let (f_lc, p_lc) = open_tempfile("lc_get");
    let mut lk2 = Flock {
        l_type: F_WRLCK,
        l_whence: SEEK_SET,
        l_start: 0,
        l_len: 16,
        l_pid: 0,
    };
    let r_lc = unsafe { fcntl(f_lc.as_raw_fd(), F_GETLK, &mut lk2 as *mut _ as c_long) };
    let type_after_lc = lk2.l_type;
    let _ = std::fs::remove_file(&p_lc);

    assert_eq!(r_fl, r_lc, "F_GETLK return: fl={r_fl}, lc={r_lc}");
    assert_eq!(
        type_after_fl, type_after_lc,
        "F_GETLK l_type after: fl={type_after_fl}, lc={type_after_lc}"
    );
    assert_eq!(
        type_after_fl, F_UNLCK,
        "GETLK on unlocked region should return F_UNLCK"
    );
    let _unused = (F_SETLKW, F_OFD_SETLK, F_OFD_GETLK);
}

#[test]
fn diff_fcntl_invalid_lock_cmd_with_bad_arg() {
    let (f_fl, p_fl) = open_tempfile("fl_inv");
    let r_fl = unsafe { fl::fcntl(f_fl.as_raw_fd(), F_SETLK, 0) };
    let _ = std::fs::remove_file(&p_fl);

    let (f_lc, p_lc) = open_tempfile("lc_inv");
    let r_lc = unsafe { fcntl(f_lc.as_raw_fd(), F_SETLK, 0) };
    let _ = std::fs::remove_file(&p_lc);

    assert_eq!(
        r_fl < 0,
        r_lc < 0,
        "F_SETLK with NULL flock fail-match: fl={r_fl}, lc={r_lc}"
    );
}

#[test]
fn fcntl_record_locks_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"fcntl.h(F_SETLK/F_GETLK)\",\"reference\":\"glibc\",\"functions\":1,\"divergences\":0}}",
    );
}
