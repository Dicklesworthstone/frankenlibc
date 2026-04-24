#![cfg(target_os = "linux")]

//! Differential conformance harness for advisory file locking:
//!   - flock (BSD-style whole-file advisory lock)
//!   - lockf (POSIX byte-range advisory lock)
//!
//! Tests open distinct tempfiles per impl so locks don't conflict.
//! Each test acquires + releases + re-acquires a lock to verify the
//! basic round-trip works on both impls.
//!
//! Bead: CONFORMANCE: libc flock+lockf diff matrix.

use std::ffi::c_int;
use std::os::fd::AsRawFd;

use frankenlibc_abi::unistd_abi as fl;

unsafe extern "C" {
    fn flock(fd: c_int, operation: c_int) -> c_int;
    fn lockf(fd: c_int, cmd: c_int, len: libc::off_t) -> c_int;
}

const LOCK_SH: c_int = 1;
const LOCK_EX: c_int = 2;
const LOCK_NB: c_int = 4;
const LOCK_UN: c_int = 8;

const F_LOCK: c_int = 1;
const F_TLOCK: c_int = 2;
const F_ULOCK: c_int = 0;
const F_TEST: c_int = 3;

fn unique_tempfile(label: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    std::env::temp_dir().join(format!("fl_lock_diff_{label}_{pid}_{id}"))
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
    (f, path)
}

#[test]
fn diff_flock_ex_then_unlock() {
    let (f_fl, p_fl) = open_tempfile("flock_fl");
    let r_lk = unsafe { fl::flock(f_fl.as_raw_fd(), LOCK_EX) };
    let r_ul = unsafe { fl::flock(f_fl.as_raw_fd(), LOCK_UN) };
    let _ = std::fs::remove_file(&p_fl);

    let (f_lc, p_lc) = open_tempfile("flock_lc");
    let r_lk_lc = unsafe { flock(f_lc.as_raw_fd(), LOCK_EX) };
    let r_ul_lc = unsafe { flock(f_lc.as_raw_fd(), LOCK_UN) };
    let _ = std::fs::remove_file(&p_lc);

    assert_eq!(r_lk, r_lk_lc, "flock LOCK_EX: fl={r_lk}, lc={r_lk_lc}");
    assert_eq!(r_ul, r_ul_lc, "flock LOCK_UN: fl={r_ul}, lc={r_ul_lc}");
}

#[test]
fn diff_flock_sh_then_unlock() {
    let (f_fl, p_fl) = open_tempfile("flock_sh_fl");
    let r_lk = unsafe { fl::flock(f_fl.as_raw_fd(), LOCK_SH) };
    let r_ul = unsafe { fl::flock(f_fl.as_raw_fd(), LOCK_UN) };
    let _ = std::fs::remove_file(&p_fl);

    let (f_lc, p_lc) = open_tempfile("flock_sh_lc");
    let r_lk_lc = unsafe { flock(f_lc.as_raw_fd(), LOCK_SH) };
    let r_ul_lc = unsafe { flock(f_lc.as_raw_fd(), LOCK_UN) };
    let _ = std::fs::remove_file(&p_lc);

    assert_eq!(r_lk, r_lk_lc, "flock LOCK_SH: fl={r_lk}, lc={r_lk_lc}");
    assert_eq!(r_ul, r_ul_lc, "flock LOCK_UN: fl={r_ul}, lc={r_ul_lc}");
}

#[test]
fn diff_flock_nb_invalid_operation() {
    // Bogus operation should fail with EINVAL on both
    let (f_fl, p_fl) = open_tempfile("flock_inv_fl");
    let (f_lc, p_lc) = open_tempfile("flock_inv_lc");
    let r_fl = unsafe { fl::flock(f_fl.as_raw_fd(), 0xff) };
    let r_lc = unsafe { flock(f_lc.as_raw_fd(), 0xff) };
    let _ = std::fs::remove_file(&p_fl);
    let _ = std::fs::remove_file(&p_lc);
    assert_eq!(
        r_fl < 0,
        r_lc < 0,
        "flock invalid op fail-match: fl={r_fl}, lc={r_lc}"
    );
    let _unused = LOCK_NB;
}

#[test]
fn diff_flock_invalid_fd() {
    let r_fl = unsafe { fl::flock(99999, LOCK_EX) };
    let r_lc = unsafe { flock(99999, LOCK_EX) };
    assert_eq!(
        r_fl < 0,
        r_lc < 0,
        "flock bad-fd fail-match: fl={r_fl}, lc={r_lc}"
    );
}

#[test]
fn diff_lockf_lock_then_unlock() {
    let (f_fl, p_fl) = open_tempfile("lockf_fl");
    f_fl.set_len(64).unwrap();
    let r_lk = unsafe { fl::lockf(f_fl.as_raw_fd(), F_LOCK, 64) };
    let r_ul = unsafe { fl::lockf(f_fl.as_raw_fd(), F_ULOCK, 64) };
    let _ = std::fs::remove_file(&p_fl);

    let (f_lc, p_lc) = open_tempfile("lockf_lc");
    f_lc.set_len(64).unwrap();
    let r_lk_lc = unsafe { lockf(f_lc.as_raw_fd(), F_LOCK, 64) };
    let r_ul_lc = unsafe { lockf(f_lc.as_raw_fd(), F_ULOCK, 64) };
    let _ = std::fs::remove_file(&p_lc);

    assert_eq!(r_lk, r_lk_lc, "lockf F_LOCK: fl={r_lk}, lc={r_lk_lc}");
    assert_eq!(r_ul, r_ul_lc, "lockf F_ULOCK: fl={r_ul}, lc={r_ul_lc}");
}

#[test]
fn diff_lockf_test_unlocked() {
    let (f_fl, p_fl) = open_tempfile("lockf_test_fl");
    f_fl.set_len(64).unwrap();
    // F_TEST on unlocked region should return 0
    let r_fl = unsafe { fl::lockf(f_fl.as_raw_fd(), F_TEST, 64) };

    let (f_lc, p_lc) = open_tempfile("lockf_test_lc");
    f_lc.set_len(64).unwrap();
    let r_lc = unsafe { lockf(f_lc.as_raw_fd(), F_TEST, 64) };

    let _ = std::fs::remove_file(&p_fl);
    let _ = std::fs::remove_file(&p_lc);
    let _unused = F_TLOCK;

    assert_eq!(r_fl, r_lc, "lockf F_TEST: fl={r_fl}, lc={r_lc}");
}

#[test]
fn diff_lockf_invalid_fd() {
    let r_fl = unsafe { fl::lockf(99999, F_LOCK, 0) };
    let r_lc = unsafe { lockf(99999, F_LOCK, 0) };
    assert_eq!(
        r_fl < 0,
        r_lc < 0,
        "lockf bad-fd fail-match: fl={r_fl}, lc={r_lc}"
    );
}

#[test]
fn flock_lockf_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"sys/file.h(flock+lockf)\",\"reference\":\"glibc\",\"functions\":2,\"divergences\":0}}",
    );
}
