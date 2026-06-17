//! Differential gate: getpt() open flags vs live host glibc.
//!
//! glibc's getpt is `posix_openpt(O_RDWR)` — `/dev/ptmx` opened with O_RDWR only.
//! fl additionally set O_NOCTTY|O_CLOEXEC, so its master fd had FD_CLOEXEC set
//! (glibc's is clear, surviving exec). We compare the fd's F_GETFD (close-on-exec)
//! and F_GETFL (access mode) between fl and glibc. glibc reached via dlsym.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::unistd_abi as fl;
use std::ffi::{c_int, c_void};

unsafe extern "C" {
    fn dlopen(filename: *const i8, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const i8) -> *mut c_void;
    fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
    fn close(fd: c_int) -> c_int;
}
type GetptFn = unsafe extern "C" fn() -> c_int;

const F_GETFD: c_int = 1;
const F_GETFL: c_int = 3;
const FD_CLOEXEC: c_int = 1;
const O_ACCMODE: c_int = 0o3;
const O_RDWR: c_int = 2;

fn glibc_getpt() -> GetptFn {
    unsafe {
        let h = dlopen(c"libc.so.6".as_ptr(), 2);
        assert!(!h.is_null());
        std::mem::transmute(dlsym(h, c"getpt".as_ptr()))
    }
}

#[test]
fn getpt_open_flags_match_glibc() {
    let g = glibc_getpt();
    unsafe {
        let gfd = g();
        let ffd = fl::getpt();
        assert!(gfd >= 0 && ffd >= 0, "getpt failed (glibc={gfd} fl={ffd})");

        let g_cloexec = fcntl(gfd, F_GETFD) & FD_CLOEXEC;
        let f_cloexec = fcntl(ffd, F_GETFD) & FD_CLOEXEC;
        assert_eq!(g_cloexec, f_cloexec, "FD_CLOEXEC: glibc={g_cloexec} fl={f_cloexec}");
        assert_eq!(g_cloexec, 0, "glibc getpt fd should not be close-on-exec");

        let g_acc = fcntl(gfd, F_GETFL) & O_ACCMODE;
        let f_acc = fcntl(ffd, F_GETFL) & O_ACCMODE;
        assert_eq!(g_acc, f_acc, "access mode: glibc={g_acc} fl={f_acc}");
        assert_eq!(g_acc, O_RDWR, "getpt should open O_RDWR");

        close(gfd);
        close(ffd);
    }
}
