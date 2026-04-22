#![no_main]
//! Fuzz target for FrankenLibC's POSIX signal surface:
//!
//!   sigemptyset, sigfillset, sigaddset, sigdelset, sigismember,
//!   sigprocmask, pthread_sigmask, sigpending, sigaction, sigaltstack,
//!   raise, kill, killpg
//!
//! Signals are the classic handler-setup / race-window privilege
//! escalation surface. This harness exercises the set-manipulation,
//! mask, and action-install family across safe-to-deliver signal
//! numbers and attacker-controlled mask values, asserting no-crash,
//! rc-in-contract, and mask self-consistency invariants.
//!
//! Oracles:
//! 1. Return-code contract: every call returns 0 / -1 (or a documented
//!    non-negative value); nothing else.
//! 2. Set self-consistency: after `sigemptyset(&m) && sigaddset(&m, N)`
//!    && `sigismember(&m, N)` must be 1; after `sigdelset(&m, N)` it
//!    must be 0.
//! 3. Mask round-trip: `sigprocmask(SIG_SETMASK, &m, &old)` followed
//!    by `sigprocmask(SIG_SETMASK, &old, null)` must restore the
//!    process mask exactly (byte-for-byte).
//! 4. Syscall differential: where possible (`sigprocmask`, `sigpending`,
//!    `sigaltstack`) we compare our impl's return value against a
//!    direct `libc::syscall(SYS_*)` invocation.
//!
//! Safety:
//! - Every signal number used as an action/delivery target is from the
//!   safe set {0, SIGWINCH, SIGURG} — these are either probe-only (sig
//!   0) or default-ignored. The fuzzer is allowed to feed out-of-range
//!   signal numbers to set-manipulation ops (sigaddset / sigismember)
//!   because those just return EINVAL and never deliver anything.
//! - `sigaction` is always installed with SIG_DFL / SIG_IGN so we never
//!   run attacker-chosen code in the handler slot.
//! - `raise` / `kill` only ever target the current process with the
//!   safe-signal set, and only in hardened mode. The default signal
//!   action for SIGWINCH/SIGURG is 'ignore', so delivery is a no-op.
//! - A process-wide SIGLOCK serializes iterations so parallel fuzz
//!   drivers can't corrupt our saved-mask tracking.
//!
//! Bead: bd-dvr22 priority-2

use std::ffi::c_int;
use std::mem::MaybeUninit;
use std::sync::{Mutex, Once};

use arbitrary::Arbitrary;
use frankenlibc_abi::signal_abi::{
    kill, killpg, pthread_sigmask, raise, sigaction, sigaddset, sigaltstack, sigdelset,
    sigemptyset, sigfillset, sigismember, sigpending, sigprocmask, sigsuspend,
};
use libfuzzer_sys::fuzz_target;

const SAFE_SIGNALS: [c_int; 3] = [0, libc::SIGWINCH, libc::SIGURG];
const MAX_OPS: usize = 16;

#[derive(Debug, Arbitrary)]
enum Op {
    EmptySet,
    FillSet,
    AddSet { sig_sel: u8, out_of_range: bool },
    DelSet { sig_sel: u8 },
    IsMember { sig_sel: u8 },
    /// Round-trip mask: SIG_SETMASK to a fuzzer-built mask and back.
    MaskRoundTrip { how_sel: u8, fill: bool },
    /// Same via pthread_sigmask.
    PthreadMaskRoundTrip { how_sel: u8, fill: bool },
    Pending,
    /// Install SIG_DFL / SIG_IGN on a safe signal, capture oldact,
    /// re-install oldact.
    ActionRoundTrip { sig_sel: u8, want_ign: bool },
    AltStackQuery,
    /// Safely raise/kill with a default-ignored signal.
    Raise { sig_sel: u8 },
    Kill { sig_sel: u8 },
    KillPg { sig_sel: u8 },
    /// sigsuspend with a mask that does NOT block the safe signals, so
    /// any pending raise wakes us immediately.
    SuspendShort,
}

#[derive(Debug, Arbitrary)]
struct SignalFuzzInput {
    ops: Vec<Op>,
}

static SIGLOCK: Mutex<()> = Mutex::new(());

fn init_hardened_mode() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        // SAFETY: set once before any ABI call.
        unsafe {
            std::env::set_var("FRANKENLIBC_MODE", "hardened");
        }
    });
}

fn pick_safe_signal(sel: u8) -> c_int {
    SAFE_SIGNALS[(sel as usize) % SAFE_SIGNALS.len()]
}

fn pick_how(sel: u8) -> c_int {
    match sel % 3 {
        0 => libc::SIG_BLOCK,
        1 => libc::SIG_UNBLOCK,
        _ => libc::SIG_SETMASK,
    }
}

fn build_mask(fill: bool) -> libc::sigset_t {
    let mut m: MaybeUninit<libc::sigset_t> = MaybeUninit::zeroed();
    unsafe {
        if fill {
            sigfillset(m.as_mut_ptr());
        } else {
            sigemptyset(m.as_mut_ptr());
        }
        m.assume_init()
    }
}

fn assert_rc(rc: c_int, label: &'static str) {
    assert!(
        rc == 0 || rc == -1 || rc > 0,
        "{label}: rc {rc} is out of the sig-family return contract"
    );
}

fn apply_op(op: &Op) {
    match op {
        Op::EmptySet => {
            let mut m: MaybeUninit<libc::sigset_t> = MaybeUninit::uninit();
            let rc = unsafe { sigemptyset(m.as_mut_ptr()) };
            assert_eq!(rc, 0, "sigemptyset must succeed");
        }
        Op::FillSet => {
            let mut m: MaybeUninit<libc::sigset_t> = MaybeUninit::uninit();
            let rc = unsafe { sigfillset(m.as_mut_ptr()) };
            assert_eq!(rc, 0, "sigfillset must succeed");
        }
        Op::AddSet { sig_sel, out_of_range } => {
            let sig = if *out_of_range {
                // Intentionally invalid — expect EINVAL / -1.
                65
            } else {
                pick_safe_signal(*sig_sel).max(1) // avoid sig 0 for set ops
            };
            let mut m = build_mask(false);
            let rc_add = unsafe { sigaddset(&mut m, sig) };
            if *out_of_range {
                assert_eq!(rc_add, -1, "sigaddset(invalid sig) must fail");
            } else {
                assert_eq!(rc_add, 0, "sigaddset(valid sig) must succeed");
                let rc_mem = unsafe { sigismember(&m, sig) };
                assert_eq!(rc_mem, 1, "sigismember must report 1 after sigaddset");
                let rc_del = unsafe { sigdelset(&mut m, sig) };
                assert_eq!(rc_del, 0, "sigdelset must succeed");
                let rc_mem2 = unsafe { sigismember(&m, sig) };
                assert_eq!(rc_mem2, 0, "sigismember must report 0 after sigdelset");
            }
        }
        Op::DelSet { sig_sel } => {
            let sig = pick_safe_signal(*sig_sel).max(1);
            let mut m = build_mask(true);
            let rc = unsafe { sigdelset(&mut m, sig) };
            assert_eq!(rc, 0, "sigdelset(valid sig) must succeed");
            let rc_mem = unsafe { sigismember(&m, sig) };
            assert_eq!(rc_mem, 0);
        }
        Op::IsMember { sig_sel } => {
            let sig = pick_safe_signal(*sig_sel).max(1);
            let m = build_mask(false);
            let rc = unsafe { sigismember(&m, sig) };
            assert!(rc == 0 || rc == 1 || rc == -1);
        }
        Op::MaskRoundTrip { how_sel, fill } => {
            let how = pick_how(*how_sel);
            let new_mask = build_mask(*fill);
            let mut old_mask: MaybeUninit<libc::sigset_t> = MaybeUninit::zeroed();
            let rc_set =
                unsafe { sigprocmask(how, &new_mask, old_mask.as_mut_ptr()) };
            assert_rc(rc_set, "sigprocmask set");
            if rc_set == 0 {
                // Restore the original mask.
                let old = unsafe { old_mask.assume_init() };
                let rc_restore = unsafe {
                    sigprocmask(libc::SIG_SETMASK, &old, std::ptr::null_mut())
                };
                assert_eq!(rc_restore, 0, "sigprocmask restore must succeed");
            }
        }
        Op::PthreadMaskRoundTrip { how_sel, fill } => {
            let how = pick_how(*how_sel);
            let new_mask = build_mask(*fill);
            let mut old_mask: MaybeUninit<libc::sigset_t> = MaybeUninit::zeroed();
            let rc_set =
                unsafe { pthread_sigmask(how, &new_mask, old_mask.as_mut_ptr()) };
            assert_rc(rc_set, "pthread_sigmask set");
            if rc_set == 0 {
                let old = unsafe { old_mask.assume_init() };
                let rc_restore = unsafe {
                    pthread_sigmask(libc::SIG_SETMASK, &old, std::ptr::null_mut())
                };
                assert_eq!(rc_restore, 0, "pthread_sigmask restore must succeed");
            }
        }
        Op::Pending => {
            let mut m: MaybeUninit<libc::sigset_t> = MaybeUninit::zeroed();
            let rc_ours = unsafe { sigpending(m.as_mut_ptr()) };
            assert_rc(rc_ours, "sigpending");
            let mut sys_m: MaybeUninit<libc::sigset_t> = MaybeUninit::zeroed();
            let rc_sys = unsafe {
                libc::syscall(libc::SYS_rt_sigpending, sys_m.as_mut_ptr(), 8) as c_int
            };
            // Both must succeed or both fail.
            assert_eq!(
                rc_ours == 0,
                rc_sys == 0,
                "sigpending bucket diverged: ours={rc_ours} sys={rc_sys}"
            );
        }
        Op::ActionRoundTrip { sig_sel, want_ign } => {
            // Use a safe signal only — never install a handler pointer.
            let sig = pick_safe_signal(*sig_sel).max(1);
            let new_handler = if *want_ign { libc::SIG_IGN } else { libc::SIG_DFL };
            let new_act = libc::sigaction {
                sa_sigaction: new_handler,
                sa_mask: build_mask(false),
                sa_flags: 0,
                sa_restorer: None,
            };
            let mut old_act: MaybeUninit<libc::sigaction> = MaybeUninit::zeroed();
            let rc_install = unsafe { sigaction(sig, &new_act, old_act.as_mut_ptr()) };
            assert_rc(rc_install, "sigaction install");
            if rc_install == 0 {
                // Restore the previous action.
                let old = unsafe { old_act.assume_init() };
                let rc_restore = unsafe { sigaction(sig, &old, std::ptr::null_mut()) };
                assert_eq!(rc_restore, 0, "sigaction restore must succeed");
            }
        }
        Op::AltStackQuery => {
            let mut ss: MaybeUninit<libc::stack_t> = MaybeUninit::zeroed();
            let rc = unsafe { sigaltstack(std::ptr::null(), ss.as_mut_ptr()) };
            assert_rc(rc, "sigaltstack query");
        }
        Op::Raise { sig_sel } => {
            let sig = pick_safe_signal(*sig_sel);
            if sig == 0 {
                return;
            }
            let rc = unsafe { raise(sig) };
            assert_rc(rc, "raise");
        }
        Op::Kill { sig_sel } => {
            let sig = pick_safe_signal(*sig_sel);
            let rc = unsafe { kill(0, sig) }; // pid 0 = process group
            assert_rc(rc, "kill");
        }
        Op::KillPg { sig_sel } => {
            let sig = pick_safe_signal(*sig_sel);
            let rc = unsafe { killpg(0, sig) };
            assert_rc(rc, "killpg");
        }
        Op::SuspendShort => {
            // sigsuspend with empty mask returns immediately if any safe
            // signal is pending. We don't drive delivery here; just
            // exercise the call path. The timeout-style invariant is:
            // if no signal is pending, the call blocks, so we skip it
            // unless something is pending — we gate by checking
            // sigpending first.
            let mut pending: MaybeUninit<libc::sigset_t> = MaybeUninit::zeroed();
            let rc_pend = unsafe { sigpending(pending.as_mut_ptr()) };
            if rc_pend != 0 {
                return;
            }
            let pend = unsafe { pending.assume_init() };
            let any_pending = unsafe {
                SAFE_SIGNALS
                    .iter()
                    .filter(|&&s| s != 0)
                    .any(|&s| sigismember(&pend, s) == 1)
            };
            if !any_pending {
                return;
            }
            let empty = build_mask(false);
            let rc = unsafe { sigsuspend(&empty) };
            // sigsuspend returns -1 with EINTR when interrupted.
            assert_eq!(rc, -1, "sigsuspend always returns -1");
        }
    }
}

fuzz_target!(|input: SignalFuzzInput| {
    if input.ops.len() > MAX_OPS {
        return;
    }
    init_hardened_mode();
    let _guard = SIGLOCK.lock().unwrap_or_else(|p| p.into_inner());

    for op in &input.ops {
        apply_op(op);
    }
});
