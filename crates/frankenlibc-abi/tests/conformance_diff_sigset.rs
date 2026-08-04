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

// ---------------------------------------------------------------------------
// bd-566mlx: sigset also owns the signal MASK, and its handler must be reliable
// in the only sense that matters — surviving an actual delivery.
// ---------------------------------------------------------------------------

const SIGUSR2: c_int = 12; // distinct from SIGUSR1 above: dispositions are
// process-wide, so sharing a signal with the test above would race under the
// harness's parallel threads. Masks are per-thread, so this test is isolated.

type SigsetFn = unsafe extern "C" fn(c_int, usize) -> usize;

unsafe extern "C" {
    fn dlopen(filename: *const i8, flag: c_int) -> *mut std::ffi::c_void;
    fn dlsym(handle: *mut std::ffi::c_void, symbol: *const i8) -> *mut std::ffi::c_void;
    fn fork() -> c_int;
    fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int;
    fn raise(sig: c_int) -> c_int;
    fn _exit(code: c_int) -> !;
}

/// Live host glibc's `sigset`, asserted to be a different entry point from fl's
/// so the differential arms cannot collapse into fl-vs-fl.
fn glibc_sigset() -> SigsetFn {
    unsafe {
        let h = dlopen(c"libc.so.6".as_ptr(), 2 /* RTLD_NOW */);
        assert!(!h.is_null(), "dlopen(libc.so.6) failed");
        let s = dlsym(h, c"sigset".as_ptr());
        assert!(!s.is_null(), "dlsym(sigset) failed");
        assert_ne!(
            s as usize,
            frankenlibc_abi::unistd_abi::sigset as *const () as usize,
            "glibc sigset resolved to fl's own symbol — the arms are not distinct"
        );
        std::mem::transmute::<*mut std::ffi::c_void, SigsetFn>(s)
    }
}

#[test]
fn sigset_unblocks_the_signal_and_reports_prior_hold() {
    let saved = cur_action(SIGUSR2);
    let was_blocked = signal_blocked(SIGUSR2);

    // Put SIGUSR2 in the mask, then install a disposition. XSI sigset must
    // release the signal from the mask as part of installing a disposition,
    // and report the prior blocked state as SIG_HOLD rather than as a handler.
    let mut one: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut one);
        libc::sigaddset(&mut one, SIGUSR2);
        sigprocmask(libc::SIG_BLOCK, &one, std::ptr::null_mut());
    }
    assert!(
        signal_blocked(SIGUSR2),
        "test setup: SIGUSR2 should be blocked"
    );

    let prev = unsafe { frankenlibc_abi::unistd_abi::sigset(SIGUSR2, SIG_IGN) };
    assert_eq!(
        prev, SIG_HOLD,
        "sigset over a blocked signal returns SIG_HOLD, not the old handler"
    );
    assert!(
        !signal_blocked(SIGUSR2),
        "sigset(disposition) must unblock the signal — delegating to sysv_signal leaves it blocked"
    );

    // ---- restore ----
    unsafe { sigaction(SIGUSR2, &saved, std::ptr::null_mut()) };
    let how = if was_blocked {
        libc::SIG_BLOCK
    } else {
        libc::SIG_UNBLOCK
    };
    unsafe { sigprocmask(how, &one, std::ptr::null_mut()) };
}

static DELIVERIES: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

extern "C" fn count_delivery(_sig: c_int) {
    DELIVERIES.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
}

/// How a child that installed a handler with `f` and then raised SIGUSR1 twice
/// terminated. A one-shot (SA_RESETHAND) disposition resets to SIG_DFL after
/// the first delivery, so the second raise kills the child.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Delivered(c_int),
    Killed(c_int),
}

fn deliveries_under(f: SigsetFn) -> Outcome {
    let handler = count_delivery as *const () as usize;
    unsafe {
        let child = fork();
        assert!(child >= 0, "fork failed");
        if child == 0 {
            if f(SIGUSR1, handler) == libc::SIG_ERR {
                _exit(90);
            }
            raise(SIGUSR1);
            raise(SIGUSR1);
            _exit(DELIVERIES.load(std::sync::atomic::Ordering::SeqCst) as c_int);
        }
        let mut status: c_int = 0;
        assert_eq!(waitpid(child, &mut status, 0), child, "waitpid failed");
        if (status & 0x7f) == 0 {
            Outcome::Delivered((status >> 8) & 0xff)
        } else {
            Outcome::Killed(status & 0x7f)
        }
    }
}

#[test]
fn sigset_handler_survives_delivery_like_glibc() {
    // Each arm runs in its own forked child, so the disposition change and the
    // raised signals never touch the test process.
    let g = deliveries_under(glibc_sigset());
    let f = deliveries_under(frankenlibc_abi::unistd_abi::sigset);
    assert_eq!(
        g,
        Outcome::Delivered(2),
        "glibc sigset must deliver both raises (reliable, not one-shot)"
    );
    assert_eq!(
        f, g,
        "sigset delivery: fl={f:?} glibc={g:?} — a one-shot SA_RESETHAND disposition \
         resets to SIG_DFL after the first delivery, so the second raise kills the child"
    );
}
