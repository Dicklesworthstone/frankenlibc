//! Differential gate: ppoll()/pselect() must NOT modify the caller's timeout,
//! matching glibc (POSIX requirement).
//!
//! The Linux ppoll/pselect6 syscalls write the remaining time back into the
//! timeout struct. glibc hides this by passing a local copy to the kernel, so
//! the caller's timeout is left untouched. fl previously passed the caller's
//! pointer straight through, clobbering it.
//!
//! Non-vacuity: we first issue the RAW SYS_ppoll on a not-ready fd and show the
//! kernel zeroes the timeout. Then we require glibc and fl both leave an
//! identical input timeout UNCHANGED after timing out.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use std::ffi::{c_int, c_void};

unsafe extern "C" {
    fn dlopen(filename: *const i8, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const i8) -> *mut c_void;
}

type PpollFn = unsafe extern "C" fn(
    *mut libc::pollfd,
    libc::nfds_t,
    *const libc::timespec,
    *const libc::sigset_t,
) -> c_int;
type PselectFn = unsafe extern "C" fn(
    c_int,
    *mut libc::fd_set,
    *mut libc::fd_set,
    *mut libc::fd_set,
    *const libc::timespec,
    *const libc::sigset_t,
) -> c_int;

fn glibc(sym: &std::ffi::CStr) -> *mut c_void {
    unsafe {
        let h = dlopen(c"libc.so.6".as_ptr(), 2);
        assert!(!h.is_null());
        let p = dlsym(h, sym.as_ptr());
        assert!(!p.is_null());
        p
    }
}

/// A pipe whose read end is never ready (nothing is written) — so a poll/select
/// on POLLIN always times out.
fn idle_pipe() -> (c_int, c_int) {
    let mut fds = [0 as c_int; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
    (fds[0], fds[1])
}

const TMO: libc::timespec = libc::timespec { tv_sec: 0, tv_nsec: 20_000_000 }; // 20ms

fn ts_eq(a: &libc::timespec, b: &libc::timespec) -> bool {
    a.tv_sec == b.tv_sec && a.tv_nsec == b.tv_nsec
}

#[test]
fn ppoll_does_not_clobber_caller_timeout_like_glibc() {
    let (rfd, _w) = idle_pipe();

    // Non-vacuity: the raw kernel syscall DOES write back remaining time (=0 on
    // a timeout). If this ever stops being true the whole gate is meaningless.
    {
        let mut pfd = libc::pollfd { fd: rfd, events: libc::POLLIN, revents: 0 };
        let mut t = TMO;
        let sz = core::mem::size_of::<libc::c_ulong>();
        let rc = unsafe {
            libc::syscall(
                libc::SYS_ppoll,
                &mut pfd as *mut libc::pollfd,
                1usize as libc::nfds_t,
                &mut t as *mut libc::timespec,
                std::ptr::null::<libc::sigset_t>(),
                sz,
            )
        };
        assert_eq!(rc, 0, "raw ppoll should time out");
        assert!(
            !ts_eq(&t, &TMO),
            "expected kernel to modify the timeout (non-vacuity); got it unchanged"
        );
    }

    let g: PpollFn = unsafe { std::mem::transmute(glibc(c"ppoll")) };
    let f: PpollFn = frankenlibc_abi::poll_abi::ppoll;

    for (name, func) in [("glibc", g), ("fl", f)] {
        let mut pfd = libc::pollfd { fd: rfd, events: libc::POLLIN, revents: 0 };
        let mut t = TMO;
        let rc = unsafe { func(&mut pfd, 1, &mut t, std::ptr::null()) };
        assert_eq!(rc, 0, "{name} ppoll should time out");
        assert!(
            ts_eq(&t, &TMO),
            "{name} ppoll modified the caller's timeout: {{{},{}}} != {{{},{}}}",
            t.tv_sec, t.tv_nsec, TMO.tv_sec, TMO.tv_nsec
        );
    }
}

#[test]
fn pselect_does_not_clobber_caller_timeout_like_glibc() {
    let (rfd, _w) = idle_pipe();
    let g: PselectFn = unsafe { std::mem::transmute(glibc(c"pselect")) };
    let f: PselectFn = frankenlibc_abi::poll_abi::pselect;

    for (name, func) in [("glibc", g), ("fl", f)] {
        let mut rset: libc::fd_set = unsafe { std::mem::zeroed() };
        unsafe {
            libc::FD_ZERO(&mut rset);
            libc::FD_SET(rfd, &mut rset);
        }
        let mut t = TMO;
        let rc = unsafe {
            func(rfd + 1, &mut rset, std::ptr::null_mut(), std::ptr::null_mut(), &mut t, std::ptr::null())
        };
        assert_eq!(rc, 0, "{name} pselect should time out");
        assert!(
            ts_eq(&t, &TMO),
            "{name} pselect modified the caller's timeout: {{{},{}}} != {{{},{}}}",
            t.tv_sec, t.tv_nsec, TMO.tv_sec, TMO.tv_nsec
        );
    }
}
