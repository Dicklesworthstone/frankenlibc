#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc SysV signal-mgmt oracle; this process's mask/dispositions

//! Differential gate for the SysV signal-management trio sighold / sigrelse /
//! sigignore (bd-17b4bl) — no differential gate existed. sighold(sig) adds sig
//! to the process's blocked mask; sigrelse(sig) removes it; sigignore(sig) sets
//! the disposition to SIG_IGN. Each impl runs its own round-trip on SIGUSR1
//! (mask) / SIGUSR2 (disposition), observed through a NEUTRAL glibc
//! sigprocmask/sigaction query, with the original mask + disposition restored.
//! The observed (rc, blocked/ignored) states are compared vs glibc. No mocks.

use std::ffi::c_int;
use std::mem::MaybeUninit;

unsafe extern "C" {
    fn sighold(sig: c_int) -> c_int;
    fn sigrelse(sig: c_int) -> c_int;
    fn sigignore(sig: c_int) -> c_int;
}

fn blocked(sig: c_int) -> bool {
    unsafe {
        let mut set = MaybeUninit::<libc::sigset_t>::zeroed();
        libc::sigprocmask(0, std::ptr::null(), set.as_mut_ptr());
        libc::sigismember(set.as_ptr(), sig) == 1
    }
}
fn is_ignored(sig: c_int) -> bool {
    unsafe {
        let mut act = MaybeUninit::<libc::sigaction>::zeroed();
        libc::sigaction(sig, std::ptr::null(), act.as_mut_ptr());
        act.assume_init().sa_sigaction == libc::SIG_IGN
    }
}

/// (hold_rc, blocked_after_hold, relse_rc, blocked_after_relse)
fn mask_seq(hold: unsafe extern "C" fn(c_int) -> c_int, relse: unsafe extern "C" fn(c_int) -> c_int) -> (c_int, bool, c_int, bool) {
    let sig = libc::SIGUSR1;
    // ensure released first
    unsafe { sigrelse(sig); }
    let hr = unsafe { hold(sig) };
    let b1 = blocked(sig);
    let rr = unsafe { relse(sig) };
    let b2 = blocked(sig);
    (hr, b1, rr, b2)
}

#[test]
fn sighold_sigrelse_match_glibc() {
    let save = unsafe {
        let mut s = MaybeUninit::<libc::sigset_t>::zeroed();
        libc::sigprocmask(0, std::ptr::null(), s.as_mut_ptr());
        s.assume_init()
    };
    let g = mask_seq(sighold, sigrelse);
    let f = mask_seq(frankenlibc_abi::signal_abi::sighold, frankenlibc_abi::signal_abi::sigrelse);
    unsafe { libc::sigprocmask(libc::SIG_SETMASK, &save, std::ptr::null_mut()); }
    assert_eq!(f, g, "sighold/sigrelse: fl={f:?} glibc={g:?}");
    assert_eq!(g, (0, true, 0, false), "glibc: hold blocks, relse unblocks");
}

#[test]
fn sigignore_matches_glibc() {
    let sig = libc::SIGUSR2;
    let probe = |ign: unsafe extern "C" fn(c_int) -> c_int| unsafe {
        let mut orig = MaybeUninit::<libc::sigaction>::zeroed();
        libc::sigaction(sig, std::ptr::null(), orig.as_mut_ptr());
        let rc = ign(sig);
        let ignored = is_ignored(sig);
        libc::sigaction(sig, orig.as_ptr(), std::ptr::null_mut()); // restore
        (rc, ignored)
    };
    let g = probe(sigignore);
    let f = probe(frankenlibc_abi::signal_abi::sigignore);
    assert_eq!(f, g, "sigignore: fl={f:?} glibc={g:?}");
    assert_eq!(g, (0, true), "glibc: sigignore sets SIG_IGN");
}
