#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc sigblock/sigsetmask oracle

//! Differential gate for the BSD 4.2 mask calls vs live host glibc (bd-z1wq9a,
//! and the roundtrip half of bd-ltggi7).
//!
//! These take an `int` mask, which has to be widened into a 64-bit kernel
//! `sigset_t`. fl widened with `mask as u64`, sign-extending, so `sigblock(-1)`
//! asked to block signals 1..64 rather than 1..32 -- reaching signals this API
//! cannot even name, including glibc's reserved SIGCANCEL/SIGSETXID.
//!
//! Rather than assert a mask value, each arm compares the mask the KERNEL ends
//! up holding after fl and after glibc. That observable catches the sign
//! extension and the SIGCANCEL filter together, and would catch any further
//! widening divergence without having to be told about it in advance.
//!
//! Every arm runs in a forked child, because it changes the signal mask and the
//! harness runs tests in parallel threads of one process. The child reports
//! through a pipe using nothing but `sigprocmask` and `write` -- both plain
//! syscalls -- since allocating after a fork in a multithreaded process can
//! deadlock on a lock another thread held. glibc is reached by dlsym and
//! asserted to be a distinct entry point from fl's.

use std::ffi::{c_int, c_void};

use frankenlibc_abi::unistd_abi as fl;

type MaskFn = unsafe extern "C" fn(c_int) -> c_int;

unsafe extern "C" {
    fn dlopen(filename: *const i8, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const i8) -> *mut c_void;
}

fn glibc_sym(name: &std::ffi::CStr, fl_addr: usize) -> MaskFn {
    unsafe {
        let h = dlopen(c"libc.so.6".as_ptr(), 2 /* RTLD_NOW */);
        assert!(!h.is_null(), "dlopen(libc.so.6) failed");
        let s = dlsym(h, name.as_ptr());
        assert!(!s.is_null(), "dlsym({name:?}) failed");
        assert_ne!(
            s as usize, fl_addr,
            "{name:?} resolved to fl's own symbol — the arms are not distinct"
        );
        std::mem::transmute::<*mut c_void, MaskFn>(s)
    }
}

/// The calling thread's blocked-signal mask as the KERNEL holds it, via a pure
/// query (`set` is NULL, so nothing is changed and no filtering applies).
///
/// Deliberately not read back through the function under test: an
/// implementation that mis-widens a mask would report its own mistaken view.
fn kernel_blocked_mask() -> u64 {
    let mut oset: libc::sigset_t = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::sigprocmask(libc::SIG_BLOCK, std::ptr::null(), &mut oset) };
    assert_eq!(rc, 0, "sigprocmask query failed");
    // The kernel fills the first 8 bytes; the rest of sigset_t is padding.
    let mut word = [0u8; 8];
    unsafe {
        std::ptr::copy_nonoverlapping(
            (&raw const oset).cast::<u8>(),
            word.as_mut_ptr(),
            word.len(),
        )
    };
    u64::from_ne_bytes(word)
}

/// Run `f(mask)` in a forked child and return the kernel mask it was left with.
fn resulting_mask(f: MaskFn, mask: c_int) -> u64 {
    let mut fds = [0 as c_int; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe failed");
    let (r, w) = (fds[0], fds[1]);

    let child = unsafe { libc::fork() };
    assert!(child >= 0, "fork failed");
    if child == 0 {
        unsafe {
            libc::close(r);
            f(mask);
            let m = kernel_blocked_mask().to_ne_bytes();
            let n = libc::write(w, m.as_ptr().cast(), m.len());
            libc::_exit(if n == m.len() as isize { 0 } else { 1 });
        }
    }

    unsafe { libc::close(w) };
    let mut buf = [0u8; 8];
    let n = unsafe { libc::read(r, buf.as_mut_ptr().cast(), buf.len()) };
    unsafe { libc::close(r) };
    let mut status: c_int = 0;
    assert_eq!(
        unsafe { libc::waitpid(child, &mut status, 0) },
        child,
        "waitpid failed"
    );
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "child did not report cleanly (status {status:#x})"
    );
    assert_eq!(n, 8, "short read from child");
    u64::from_ne_bytes(buf)
}

fn glibc_sigblock() -> MaskFn {
    glibc_sym(c"sigblock", fl::sigblock as *const () as usize)
}

fn glibc_sigsetmask() -> MaskFn {
    glibc_sym(c"sigsetmask", fl::sigsetmask as *const () as usize)
}

/// The all-ones case exposes sign extension; the sign bit alone isolates it;
/// then an ordinary high bit, a single low signal, and the empty mask.
const MASKS: &[(c_int, &str)] = &[
    (-1, "-1 (all bits)"),
    (i32::MIN, "INT_MIN (sign bit only)"),
    (0x4000_0000, "bit 30"),
    (1 << 9, "SIGUSR1 only"),
    (0, "empty"),
];

#[test]
fn sigblock_widens_the_mask_like_glibc() {
    let g = glibc_sigblock();
    for &(mask, label) in MASKS {
        let mg = resulting_mask(g, mask);
        let mf = resulting_mask(fl::sigblock, mask);
        assert_eq!(
            mf, mg,
            "sigblock({label}) left a different kernel mask: fl={mf:#018x} glibc={mg:#018x}"
        );
    }
}

#[test]
fn sigsetmask_widens_the_mask_like_glibc() {
    let g = glibc_sigsetmask();
    for &(mask, label) in MASKS {
        let mg = resulting_mask(g, mask);
        let mf = resulting_mask(fl::sigsetmask, mask);
        assert_eq!(
            mf, mg,
            "sigsetmask({label}) left a different kernel mask: fl={mf:#018x} glibc={mg:#018x}"
        );
    }
}

#[test]
fn sigblock_all_ones_stays_within_the_int_mask_range() {
    // States what the differential arms enforce, so a regression reads as the
    // bug rather than as two opaque hex words: an int mask can only describe
    // signals 1..32, so nothing at or above bit 31 may end up blocked.
    let mf = resulting_mask(fl::sigblock, -1);
    assert_eq!(
        mf >> 32,
        0,
        "sigblock(-1) blocked signals 33..64 (mask {mf:#018x}); the int mask cannot name \
         them, so this is sign extension"
    );
    assert_eq!(
        mf & (1 << 31),
        0,
        "sigblock(-1) blocked signal 32 (SIGCANCEL), which glibc deletes from every set \
         handed to sigprocmask (mask {mf:#018x})"
    );
}

#[test]
fn siggetmask_reports_the_kernel_mask_without_changing_it() {
    // siggetmask() is sigblock(0): it must report the current mask and change
    // nothing. bd-ltggi7's roundtrip, checked against the kernel's own view.
    let mut fds = [0 as c_int; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe failed");
    let (r, w) = (fds[0], fds[1]);

    let child = unsafe { libc::fork() };
    assert!(child >= 0, "fork failed");
    if child == 0 {
        unsafe {
            libc::close(r);
            fl::sigblock(1 << 9);
            let before = kernel_blocked_mask();
            let reported = fl::siggetmask() as u32 as u64;
            let after = kernel_blocked_mask();
            let out = [before, reported, after];
            let bytes = std::slice::from_raw_parts(out.as_ptr().cast::<u8>(), 24);
            let n = libc::write(w, bytes.as_ptr().cast(), 24);
            libc::_exit(if n == 24 { 0 } else { 1 });
        }
    }

    unsafe { libc::close(w) };
    let mut buf = [0u8; 24];
    let n = unsafe { libc::read(r, buf.as_mut_ptr().cast(), buf.len()) };
    unsafe { libc::close(r) };
    let mut status: c_int = 0;
    assert_eq!(
        unsafe { libc::waitpid(child, &mut status, 0) },
        child,
        "waitpid failed"
    );
    assert_eq!(n, 24, "short read from child");

    let word = |i: usize| u64::from_ne_bytes(buf[i * 8..i * 8 + 8].try_into().unwrap());
    let (before, reported, after) = (word(0), word(1), word(2));
    assert_eq!(
        before,
        1 << 9,
        "setup: sigblock(1<<9) should leave exactly that signal blocked, got {before:#018x}"
    );
    assert_eq!(
        after, before,
        "siggetmask must not change the mask it reports ({before:#018x} -> {after:#018x})"
    );
    assert_eq!(
        reported, before,
        "siggetmask reported {reported:#018x} but the kernel holds {before:#018x}"
    );
}
