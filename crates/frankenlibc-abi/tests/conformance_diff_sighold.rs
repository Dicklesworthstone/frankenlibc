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
fn mask_seq(
    hold: unsafe extern "C" fn(c_int) -> c_int,
    relse: unsafe extern "C" fn(c_int) -> c_int,
) -> (c_int, bool, c_int, bool) {
    let sig = libc::SIGUSR1;
    // ensure released first
    unsafe {
        sigrelse(sig);
    }
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
    let f = mask_seq(
        frankenlibc_abi::signal_abi::sighold,
        frankenlibc_abi::signal_abi::sigrelse,
    );
    unsafe {
        libc::sigprocmask(libc::SIG_SETMASK, &save, std::ptr::null_mut());
    }
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

// ---------------------------------------------------------------------------
// Invalid-signal rejection (bd-5zrf92)
//
// All three wrappers must fail with -1/EINVAL for a signal outside 1..=64, and
// for glibc's two reserved signals. Measured on live glibc 2.42:
//
//   sighold/sigrelse/sigignore(0)    -> -1 EINVAL
//                            (-1)    -> -1 EINVAL
//                            (32)    -> -1 EINVAL   SIGCANCEL, reserved
//                            (33)    -> -1 EINVAL   SIGSETXID, reserved
//                            (64)    ->  0          highest VALID signal
//                            (65)    -> -1 EINVAL
//                          (9999)    -> -1 EINVAL
//
// e15ca8951 fixed the rejection and added a regression test, but that test
// passes only signal 0 — which cannot tell a real range check from an
// implementation that special-cases zero. The 64-accepted row is what pins the
// upper bound; without it, "reject everything above 31" would also pass.
// ---------------------------------------------------------------------------

use std::ffi::c_void;

unsafe extern "C" {
    fn dlopen(filename: *const i8, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const i8) -> *mut c_void;
}

type SigFn = unsafe extern "C" fn(c_int) -> c_int;

/// glibc's wrapper by dlsym, asserted distinct from fl's — the plain `extern`
/// declarations above bind to fl's own symbols in a release test build, where
/// `no_mangle` is active, which would compare fl against itself.
fn glibc_sig_fn(name: &std::ffi::CStr, fl_addr: usize) -> SigFn {
    unsafe {
        let h = dlopen(c"libc.so.6".as_ptr(), 2 /* RTLD_NOW */);
        assert!(!h.is_null(), "dlopen(libc.so.6) failed");
        let s = dlsym(h, name.as_ptr());
        assert!(!s.is_null(), "dlsym({name:?}) failed");
        assert_ne!(
            s as usize, fl_addr,
            "{name:?} resolved to fl's own symbol — the arms are not distinct"
        );
        std::mem::transmute::<*mut c_void, SigFn>(s)
    }
}

/// Call through one implementation and report (rc, errno), reading each side's
/// own errno slot.
fn call_glibc(f: SigFn, sig: c_int) -> (c_int, c_int) {
    unsafe {
        *libc::__errno_location() = 0;
        let rc = f(sig);
        (rc, *libc::__errno_location())
    }
}
fn call_fl(f: SigFn, sig: c_int) -> (c_int, c_int) {
    unsafe {
        *frankenlibc_abi::errno_abi::__errno_location() = 0;
        let rc = f(sig);
        (rc, *frankenlibc_abi::errno_abi::__errno_location())
    }
}

#[test]
fn obsolete_wrappers_reject_invalid_signals_like_glibc() {
    let trio: &[(&std::ffi::CStr, SigFn, SigFn)] = &[
        (
            c"sighold",
            frankenlibc_abi::signal_abi::sighold,
            glibc_sig_fn(c"sighold", frankenlibc_abi::signal_abi::sighold as *const () as usize),
        ),
        (
            c"sigrelse",
            frankenlibc_abi::signal_abi::sigrelse,
            glibc_sig_fn(c"sigrelse", frankenlibc_abi::signal_abi::sigrelse as *const () as usize),
        ),
        (
            c"sigignore",
            frankenlibc_abi::signal_abi::sigignore,
            glibc_sig_fn(
                c"sigignore",
                frankenlibc_abi::signal_abi::sigignore as *const () as usize,
            ),
        ),
    ];

    // 32 and 33 are SIGCANCEL/SIGSETXID, which glibc reserves for its own
    // threading internals and refuses to name through sigaddset.
    let invalid: &[(c_int, &str)] = &[
        (0, "zero"),
        (-1, "negative"),
        (32, "SIGCANCEL (reserved)"),
        (33, "SIGSETXID (reserved)"),
        (65, "one past the top"),
        (9999, "far out of range"),
    ];

    for (name, fl_fn, g_fn) in trio {
        for (sig, label) in invalid {
            let g = call_glibc(*g_fn, *sig);
            let f = call_fl(*fl_fn, *sig);
            assert_eq!(
                f, g,
                "{name:?}({sig}) [{label}]: (rc, errno) differs; fl={f:?} glibc={g:?}"
            );
            // Assert what the ORACLE produced: if BOTH impls started accepting
            // these, the equality above would still hold.
            assert_eq!(
                g,
                (-1, libc::EINVAL),
                "{name:?}({sig}) [{label}]: glibc should fail with EINVAL, got {g:?}"
            );
        }
    }
}

#[test]
fn obsolete_wrappers_accept_signal_64_the_top_of_the_range() {
    // The negative half of the arm above: signal 64 is the HIGHEST valid signal
    // and all three must accept it. Without this, an implementation that
    // rejected everything above 31 — or rejected every signal outright — would
    // satisfy every rejection assertion.
    //
    // These three calls have real side effects (64 gets blocked, then released,
    // then set to SIG_IGN), so the mask and disposition are saved and restored.
    const SIG: c_int = 64;

    let save_mask = unsafe {
        let mut set = MaybeUninit::<libc::sigset_t>::zeroed();
        libc::sigprocmask(0, std::ptr::null(), set.as_mut_ptr());
        set.assume_init()
    };
    let save_act = unsafe {
        let mut act = MaybeUninit::<libc::sigaction>::zeroed();
        libc::sigaction(SIG, std::ptr::null(), act.as_mut_ptr());
        act.assume_init()
    };

    let g_hold = glibc_sig_fn(c"sighold", frankenlibc_abi::signal_abi::sighold as *const () as usize);
    let g_relse =
        glibc_sig_fn(c"sigrelse", frankenlibc_abi::signal_abi::sigrelse as *const () as usize);
    let g_ign = glibc_sig_fn(
        c"sigignore",
        frankenlibc_abi::signal_abi::sigignore as *const () as usize,
    );

    let results = [
        (
            "sighold",
            call_glibc(g_hold, SIG),
            call_fl(frankenlibc_abi::signal_abi::sighold, SIG),
        ),
        (
            "sigrelse",
            call_glibc(g_relse, SIG),
            call_fl(frankenlibc_abi::signal_abi::sigrelse, SIG),
        ),
        (
            "sigignore",
            call_glibc(g_ign, SIG),
            call_fl(frankenlibc_abi::signal_abi::sigignore, SIG),
        ),
    ];

    unsafe {
        libc::sigprocmask(libc::SIG_SETMASK, &save_mask, std::ptr::null_mut());
        libc::sigaction(SIG, &save_act, std::ptr::null_mut());
    }

    for (name, g, f) in results {
        assert_eq!(
            g.0, 0,
            "glibc's {name}({SIG}) should succeed — 64 is the top of the valid range, got {g:?}"
        );
        assert_eq!(
            f.0, g.0,
            "{name}({SIG}): fl returned {f:?} where glibc returned {g:?}"
        );
    }
}
