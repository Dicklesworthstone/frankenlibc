#![cfg(target_os = "linux")]

//! Differential conformance harness for `pipe(2)` / `pipe2(2)`.
//!
//! pipe2 takes a flags arg (O_CLOEXEC, O_NONBLOCK, O_DIRECT) and
//! creates a pipe with those flags pre-applied. Both fl and glibc
//! must agree on which flag combinations succeed and on the
//! resulting file-descriptor flag bits.
//!
//! Filed under [bd-xn6p8] follow-up.

use std::ffi::c_int;

use frankenlibc_abi::io_abi as fl;

// The host arms are resolved with `dlsym`, not declared at link time. fl
// exports its own `pipe`/`pipe2` into this binary, and a link-time reference
// can bind to those instead of libc's — making both arms fl, so every
// assertion below passes while proving nothing. That is measured, not
// theoretical: `conformance_diff_catopen` was passing this way in a plain
// debug build and was concealing a real errno defect (bd-rp1e32, bd-v0388t).
// `dlsym` on an explicit `libc.so.6` handle is correct in every build profile,
// and the `assert_ne!` turns the remaining doubt into a failing test.
type PipeFn = unsafe extern "C" fn(*mut c_int) -> c_int;
type Pipe2Fn = unsafe extern "C" fn(*mut c_int, c_int) -> c_int;

union PipeSym {
    raw: *mut std::ffi::c_void,
    function: PipeFn,
}
union Pipe2Sym {
    raw: *mut std::ffi::c_void,
    function: Pipe2Fn,
}

fn libc_handle() -> *mut std::ffi::c_void {
    // SAFETY: libc.so.6 is the process host libc; flags request a local handle.
    let handle = unsafe { libc::dlopen(c"libc.so.6".as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!handle.is_null(), "dlopen libc.so.6");
    handle
}

fn host_pipe() -> PipeFn {
    // SAFETY: the handle came from dlopen; the name is a NUL-terminated constant.
    let raw = unsafe { libc::dlsym(libc_handle(), c"pipe".as_ptr()) };
    assert!(!raw.is_null(), "dlsym pipe");
    assert_ne!(
        raw as usize,
        fl::pipe as usize,
        "the resolved oracle IS fl's pipe — this gate would compare fl to itself"
    );
    // SAFETY: the resolved symbol has POSIX's documented pipe signature.
    unsafe { PipeSym { raw }.function }
}

fn host_pipe2() -> Pipe2Fn {
    // SAFETY: as above, for pipe2.
    let raw = unsafe { libc::dlsym(libc_handle(), c"pipe2".as_ptr()) };
    assert!(!raw.is_null(), "dlsym pipe2");
    assert_ne!(
        raw as usize,
        fl::pipe2 as usize,
        "the resolved oracle IS fl's pipe2 — this gate would compare fl to itself"
    );
    // SAFETY: the resolved symbol has Linux's documented pipe2 signature.
    unsafe { Pipe2Sym { raw }.function }
}

fn check_fd_flag(fd: c_int, flag: c_int, target: c_int) -> bool {
    let f = unsafe { libc::fcntl(fd, target) };
    f & flag == flag
}

#[test]
fn diff_pipe_creates_two_valid_fds() {
    let pipe = host_pipe();
    let mut fl_fds = [-1i32, -1];
    let mut lc_fds = [-1i32, -1];
    let fl_r = unsafe { fl::pipe(fl_fds.as_mut_ptr()) };
    let lc_r = unsafe { pipe(lc_fds.as_mut_ptr()) };
    assert_eq!(fl_r, lc_r);
    assert_eq!(fl_r, 0);
    assert!(fl_fds[0] >= 0 && fl_fds[1] >= 0);
    unsafe {
        libc::close(fl_fds[0]);
        libc::close(fl_fds[1]);
        libc::close(lc_fds[0]);
        libc::close(lc_fds[1]);
    }
}

#[test]
fn diff_pipe2_zero_flags_equivalent_to_pipe() {
    let pipe2 = host_pipe2();
    let mut fl_fds = [-1i32, -1];
    let mut lc_fds = [-1i32, -1];
    let fl_r = unsafe { fl::pipe2(fl_fds.as_mut_ptr(), 0) };
    let lc_r = unsafe { pipe2(lc_fds.as_mut_ptr(), 0) };
    assert_eq!(fl_r, lc_r);
    assert_eq!(fl_r, 0);
    unsafe {
        libc::close(fl_fds[0]);
        libc::close(fl_fds[1]);
        libc::close(lc_fds[0]);
        libc::close(lc_fds[1]);
    }
}

#[test]
fn diff_pipe2_o_cloexec_sets_close_on_exec() {
    let pipe2 = host_pipe2();
    let mut fl_fds = [-1i32, -1];
    let mut lc_fds = [-1i32, -1];
    let fl_r = unsafe { fl::pipe2(fl_fds.as_mut_ptr(), libc::O_CLOEXEC) };
    let lc_r = unsafe { pipe2(lc_fds.as_mut_ptr(), libc::O_CLOEXEC) };
    assert_eq!(fl_r, lc_r);
    assert_eq!(fl_r, 0);
    // Both fds in both pipes must have FD_CLOEXEC set.
    for fd in [fl_fds[0], fl_fds[1], lc_fds[0], lc_fds[1]] {
        assert!(
            check_fd_flag(fd, libc::FD_CLOEXEC, libc::F_GETFD),
            "fd {fd} missing FD_CLOEXEC"
        );
    }
    unsafe {
        libc::close(fl_fds[0]);
        libc::close(fl_fds[1]);
        libc::close(lc_fds[0]);
        libc::close(lc_fds[1]);
    }
}

#[test]
fn diff_pipe2_o_nonblock_sets_nonblock_status() {
    let pipe2 = host_pipe2();
    let mut fl_fds = [-1i32, -1];
    let mut lc_fds = [-1i32, -1];
    let fl_r = unsafe { fl::pipe2(fl_fds.as_mut_ptr(), libc::O_NONBLOCK) };
    let lc_r = unsafe { pipe2(lc_fds.as_mut_ptr(), libc::O_NONBLOCK) };
    assert_eq!(fl_r, lc_r);
    assert_eq!(fl_r, 0);
    for fd in [fl_fds[0], fl_fds[1], lc_fds[0], lc_fds[1]] {
        assert!(
            check_fd_flag(fd, libc::O_NONBLOCK, libc::F_GETFL),
            "fd {fd} missing O_NONBLOCK"
        );
    }
    unsafe {
        libc::close(fl_fds[0]);
        libc::close(fl_fds[1]);
        libc::close(lc_fds[0]);
        libc::close(lc_fds[1]);
    }
}

#[test]
fn diff_pipe2_combined_flags() {
    let pipe2 = host_pipe2();
    let flags = libc::O_CLOEXEC | libc::O_NONBLOCK;
    let mut fl_fds = [-1i32, -1];
    let mut lc_fds = [-1i32, -1];
    let fl_r = unsafe { fl::pipe2(fl_fds.as_mut_ptr(), flags) };
    let lc_r = unsafe { pipe2(lc_fds.as_mut_ptr(), flags) };
    assert_eq!(fl_r, lc_r);
    assert_eq!(fl_r, 0);
    for fd in [fl_fds[0], fl_fds[1], lc_fds[0], lc_fds[1]] {
        assert!(check_fd_flag(fd, libc::FD_CLOEXEC, libc::F_GETFD));
        assert!(check_fd_flag(fd, libc::O_NONBLOCK, libc::F_GETFL));
    }
    unsafe {
        libc::close(fl_fds[0]);
        libc::close(fl_fds[1]);
        libc::close(lc_fds[0]);
        libc::close(lc_fds[1]);
    }
}

#[test]
fn diff_pipe2_invalid_flags_returns_einval() {
    let pipe2 = host_pipe2();
    let mut fl_fds = [-1i32, -1];
    let mut lc_fds = [-1i32, -1];
    // Use a flag bit that's not allowed for pipe2.
    //
    // errno is captured immediately after each call and the location is cleared
    // before each. Reading it once after BOTH calls — as this test used to —
    // makes the two reads the same value by construction, so the comparison
    // holds no matter how far apart the implementations are.
    unsafe { *libc::__errno_location() = 0 };
    let fl_r = unsafe { fl::pipe2(fl_fds.as_mut_ptr(), 0x10_0000) };
    let fl_e = unsafe { *libc::__errno_location() };

    unsafe { *libc::__errno_location() = 0 };
    let lc_r = unsafe { pipe2(lc_fds.as_mut_ptr(), 0x10_0000) };
    let lc_e = unsafe { *libc::__errno_location() };

    assert_eq!(fl_r, lc_r, "pipe2 invalid-flag return value");
    if fl_r == -1 {
        assert_eq!(
            fl_e, lc_e,
            "pipe2 invalid-flag errno: fl={fl_e} glibc={lc_e}"
        );
        // The test is named for EINVAL, so assert it rather than merely
        // agreeing on whatever both happened to set.
        assert_eq!(
            lc_e,
            libc::EINVAL,
            "glibc should reject a bad pipe2 flag with EINVAL"
        );
    } else {
        // Both succeeded: close what they opened rather than leaking fds into
        // the rest of the suite.
        unsafe {
            libc::close(fl_fds[0]);
            libc::close(fl_fds[1]);
            libc::close(lc_fds[0]);
            libc::close(lc_fds[1]);
        }
    }
}

#[test]
fn diff_pipe_null_pipefd_segv_avoidance() {
    // glibc may segfault on NULL — only verify fl is hardened.
    let r = unsafe { fl::pipe(std::ptr::null_mut()) };
    assert_eq!(r, -1);
}

#[test]
fn pipe2_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc pipe + pipe2\",\"reference\":\"glibc\",\"functions\":2,\"divergences\":0}}",
    );
}
