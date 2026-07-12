#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // exercises real signal disposition/mask state

//! Gate for sigset's reliable XSI semantics (bd-npv3br, pinning bd-566mlx).
//! sigset must install a PERSISTENT handler (sa_flags without SA_RESETHAND /
//! SA_NODEFER) — the old fl delegated to sysv_signal, which set one-shot
//! SA_RESETHAND|SA_NODEFER. It must also handle SIG_HOLD by blocking the
//! signal. Uses SIGUSR1 and carefully saves/restores the disposition + mask so
//! the test process is left untouched. No mocks (real sigaction/sigprocmask).

use std::ffi::c_int;

const SIGUSR1: c_int = 10;
const SIG_HOLD: usize = 2;
const SIG_IGN: usize = 1;

unsafe extern "C" {
    fn sigaction(sig: c_int, act: *const libc::sigaction, old: *mut libc::sigaction) -> c_int;
    fn sigprocmask(how: c_int, set: *const libc::sigset_t, old: *mut libc::sigset_t) -> c_int;
    fn sigismember(set: *const libc::sigset_t, sig: c_int) -> c_int;
}

fn cur_action(sig: c_int) -> libc::sigaction {
    let mut oa: libc::sigaction = unsafe { std::mem::zeroed() };
    let rc = unsafe { sigaction(sig, std::ptr::null(), &mut oa) };
    assert_eq!(rc, 0);
    oa
}

fn signal_blocked(sig: c_int) -> bool {
    let mut cur: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        sigprocmask(
            0, /*SIG_SETMASK query via 0 set=null*/
            std::ptr::null(),
            &mut cur,
        )
    };
    unsafe { sigismember(&cur, sig) == 1 }
}

#[test]
fn sigset_installs_persistent_handler_and_handles_hold() {
    // Save original disposition + whether SIGUSR1 is currently blocked.
    let saved = cur_action(SIGUSR1);
    let was_blocked = signal_blocked(SIGUSR1);

    // sigset(SIGUSR1, SIG_IGN) installs a persistent SIG_IGN disposition.
    let _prev = unsafe { frankenlibc_abi::unistd_abi::sigset(SIGUSR1, SIG_IGN) };
    let act = cur_action(SIGUSR1);
    assert_eq!(act.sa_sigaction, SIG_IGN, "sigset should install SIG_IGN");
    assert_eq!(
        act.sa_flags & libc::SA_RESETHAND,
        0,
        "sigset handler must be persistent (no SA_RESETHAND) — the bug delegated to one-shot sysv_signal"
    );
    assert_eq!(
        act.sa_flags & libc::SA_NODEFER,
        0,
        "sigset must block the signal during its handler (no SA_NODEFER)"
    );

    // sigset(SIGUSR1, SIG_HOLD) blocks the signal; with the prior disposition
    // installed (not previously blocked) it returns the previous handler.
    let r = unsafe { frankenlibc_abi::unistd_abi::sigset(SIGUSR1, SIG_HOLD) };
    assert!(
        signal_blocked(SIGUSR1),
        "sigset(SIG_HOLD) must block the signal"
    );
    assert_eq!(
        r, SIG_IGN,
        "sigset(SIG_HOLD) returns the previous (non-blocked) handler"
    );

    // A second SIG_HOLD while already blocked reports SIG_HOLD.
    let r2 = unsafe { frankenlibc_abi::unistd_abi::sigset(SIGUSR1, SIG_HOLD) };
    assert_eq!(
        r2, SIG_HOLD as usize,
        "sigset(SIG_HOLD) on an already-blocked signal returns SIG_HOLD"
    );

    // ---- restore original state ----
    unsafe { sigaction(SIGUSR1, &saved, std::ptr::null_mut()) };
    let mut one: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut one);
        libc::sigaddset(&mut one, SIGUSR1)
    };
    let how = if was_blocked {
        libc::SIG_BLOCK
    } else {
        libc::SIG_UNBLOCK
    };
    unsafe { sigprocmask(how, &one, std::ptr::null_mut()) };
}

#[test]
fn sigset_rejects_invalid_signal() {
    let r = unsafe { frankenlibc_abi::unistd_abi::sigset(-1, SIG_IGN) };
    assert_eq!(r, libc::SIG_ERR, "sigset(invalid sig) must return SIG_ERR");
}
