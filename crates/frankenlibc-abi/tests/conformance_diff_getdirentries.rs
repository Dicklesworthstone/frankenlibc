//! Differential gate: getdirentries `*basep` semantics vs live host glibc.
//!
//! fl wrote *basep unconditionally before the read, clobbering the caller's
//! value when getdents fails (e.g. a non-directory fd → ENOTDIR). glibc writes
//! *basep ONLY on a successful read. We pin both the success offset and the
//! untouched-on-error behavior against the host (glibc via dlsym).
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::glibc_internal_abi as fl;
use std::ffi::{CString, c_char, c_int, c_long, c_void};

unsafe extern "C" {
    fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    fn open(path: *const c_char, flags: c_int) -> c_int;
    fn close(fd: c_int) -> c_int;
}
type GdeFn = unsafe extern "C" fn(c_int, *mut c_char, usize, *mut c_long) -> isize;

fn glibc_getdirentries() -> GdeFn {
    unsafe {
        let h = dlopen(c"libc.so.6".as_ptr(), 2);
        assert!(!h.is_null());
        std::mem::transmute(dlsym(h, c"getdirentries".as_ptr()))
    }
}

const O_RDONLY: c_int = 0;
const O_DIRECTORY: c_int = 0o200000;
const SENTINEL: c_long = -987654321;

/// (rc_sign, basep_value) — basep starts at SENTINEL so we can see if it was written.
fn run(f: GdeFn, path: &str, flags: c_int) -> (isize, c_long) {
    let cpath = CString::new(path).unwrap();
    unsafe {
        let fd = open(cpath.as_ptr(), flags);
        assert!(fd >= 0, "open({path}) failed");
        let mut buf = vec![0i8; 4096];
        let mut base: c_long = SENTINEL;
        let rc = f(fd, buf.as_mut_ptr(), 4096, &mut base);
        close(fd);
        (rc.signum(), base)
    }
}

#[test]
fn success_basep_matches_glibc() {
    let g = glibc_getdirentries();
    // Reading a directory succeeds; *basep is the pre-read offset (0 at start).
    let (grc, gbase) = run(g, "/", O_RDONLY | O_DIRECTORY);
    let (frc, fbase) = run(fl::getdirentries, "/", O_RDONLY | O_DIRECTORY);
    assert_eq!(grc, frc, "dir read rc sign: glibc={grc} fl={frc}");
    assert!(grc > 0, "expected a non-empty directory read");
    assert_eq!(gbase, fbase, "dir read *basep: glibc={gbase} fl={fbase}");
    assert_ne!(
        gbase, SENTINEL,
        "glibc should have written *basep on success"
    );
}

#[test]
fn error_leaves_basep_untouched_like_glibc() {
    let g = glibc_getdirentries();
    // A regular file fd makes getdents fail (ENOTDIR); *basep must stay SENTINEL.
    let (grc, gbase) = run(g, "/etc/hostname", O_RDONLY);
    let (frc, fbase) = run(fl::getdirentries, "/etc/hostname", O_RDONLY);
    assert_eq!(grc, frc, "error rc sign: glibc={grc} fl={frc}");
    assert_eq!(grc, -1, "expected getdents failure on a non-directory");
    assert_eq!(gbase, SENTINEL, "glibc must NOT write *basep on error");
    assert_eq!(
        fbase, SENTINEL,
        "fl must NOT write *basep on error (was the bug)"
    );
}
