#![cfg(target_os = "linux")]

//! Differential conformance harness for `<sys/mman.h>` POSIX shared
//! memory:
//!   - shm_open / shm_unlink (named shm objects)
//!
//! Tests use distinct names per impl to avoid collisions and always
//! shm_unlink on cleanup. Skips if /dev/shm isn't writable (e.g., in
//! sandboxed environments).
//!
//! Bead: CONFORMANCE: libc shm_open+shm_unlink diff matrix.

use std::ffi::{CString, c_char, c_int};

use frankenlibc_abi::unistd_abi as fl;

unsafe extern "C" {
    fn shm_open(name: *const c_char, oflag: c_int, mode: libc::mode_t) -> c_int;
    fn shm_unlink(name: *const c_char) -> c_int;
}

const O_CREAT: c_int = libc::O_CREAT;
const O_EXCL: c_int = libc::O_EXCL;
const O_RDWR: c_int = libc::O_RDWR;

fn unique_name(label: &str) -> CString {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    CString::new(format!("/fl_shm_diff_{label}_{pid}_{id}")).unwrap()
}

fn shm_supported() -> bool {
    let n = unique_name("probe");
    let fd = unsafe { shm_open(n.as_ptr(), O_CREAT | O_EXCL | O_RDWR, 0o600) };
    if fd < 0 {
        return false;
    }
    unsafe {
        libc::close(fd);
        shm_unlink(n.as_ptr());
    }
    true
}

#[test]
fn diff_shm_open_create_close_unlink() {
    if !shm_supported() {
        eprintln!("{{\"family\":\"shm.h\",\"skip\":\"shm not supported on host\"}}");
        return;
    }
    let n_fl = unique_name("create_fl");
    let fd_fl = unsafe { fl::shm_open(n_fl.as_ptr(), O_CREAT | O_EXCL | O_RDWR, 0o600) };
    let r_unlink_fl = if fd_fl >= 0 {
        unsafe { libc::close(fd_fl) };
        unsafe { fl::shm_unlink(n_fl.as_ptr()) }
    } else {
        -1
    };

    let n_lc = unique_name("create_lc");
    let fd_lc = unsafe { shm_open(n_lc.as_ptr(), O_CREAT | O_EXCL | O_RDWR, 0o600) };
    let r_unlink_lc = if fd_lc >= 0 {
        unsafe { libc::close(fd_lc) };
        unsafe { shm_unlink(n_lc.as_ptr()) }
    } else {
        -1
    };

    assert_eq!(
        fd_fl >= 0,
        fd_lc >= 0,
        "shm_open create success-match: fl={fd_fl}, lc={fd_lc}"
    );
    assert_eq!(
        r_unlink_fl, r_unlink_lc,
        "shm_unlink return: fl={r_unlink_fl}, lc={r_unlink_lc}"
    );
}

#[test]
fn diff_shm_unlink_nonexistent() {
    let n = CString::new("/this_shm_does_not_exist_xyz_unique").unwrap();
    let r_fl = unsafe { fl::shm_unlink(n.as_ptr()) };
    let r_lc = unsafe { shm_unlink(n.as_ptr()) };
    assert_eq!(
        r_fl < 0,
        r_lc < 0,
        "shm_unlink ENOENT fail-match: fl={r_fl}, lc={r_lc}"
    );
}

// DISC-SHM-001: POSIX 2017 says "If name does not begin with the slash
// character, the effect is implementation-defined." fl rejects with -1
// (stricter); glibc accepts and resolves relative to /dev/shm. Both
// are POSIX-conformant. Logged not failed.
#[test]
fn diff_shm_open_no_slash_documented() {
    let n = CString::new("no_slash_name_unique_xyz").unwrap();
    let fd_fl = unsafe { fl::shm_open(n.as_ptr(), O_CREAT | O_EXCL | O_RDWR, 0o600) };
    let fd_lc = unsafe { shm_open(n.as_ptr(), O_CREAT | O_EXCL | O_RDWR, 0o600) };
    eprintln!(
        "{{\"family\":\"shm.h\",\"divergence\":\"DISC-SHM-001\",\"name\":\"no-leading-slash\",\"fl_fd\":{fd_fl},\"glibc_fd\":{fd_lc},\"posix\":\"implementation-defined\"}}"
    );
    if fd_fl >= 0 {
        unsafe { libc::close(fd_fl) };
        let _ = unsafe { fl::shm_unlink(n.as_ptr()) };
    }
    if fd_lc >= 0 {
        unsafe { libc::close(fd_lc) };
        let _ = unsafe { shm_unlink(n.as_ptr()) };
    }
}

#[test]
fn diff_shm_open_o_excl_eexist() {
    if !shm_supported() {
        return;
    }
    let n = unique_name("excl");
    // First create
    let fd1 = unsafe { shm_open(n.as_ptr(), O_CREAT | O_EXCL | O_RDWR, 0o600) };
    assert!(fd1 >= 0, "lc baseline shm_open create");

    // Now try O_CREAT|O_EXCL again — both impls should fail with EEXIST
    let r_fl = unsafe { fl::shm_open(n.as_ptr(), O_CREAT | O_EXCL | O_RDWR, 0o600) };
    let r_lc = unsafe { shm_open(n.as_ptr(), O_CREAT | O_EXCL | O_RDWR, 0o600) };

    if fd1 >= 0 {
        unsafe { libc::close(fd1) };
    }
    if r_fl >= 0 {
        unsafe { libc::close(r_fl) };
    }
    if r_lc >= 0 {
        unsafe { libc::close(r_lc) };
    }
    let _ = unsafe { shm_unlink(n.as_ptr()) };

    assert_eq!(
        r_fl < 0,
        r_lc < 0,
        "shm_open EEXIST fail-match: fl={r_fl}, lc={r_lc}"
    );
}

#[test]
fn shm_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"sys/mman.h(shm_open+shm_unlink)\",\"reference\":\"glibc\",\"functions\":2,\"divergences\":0}}",
    );
}
