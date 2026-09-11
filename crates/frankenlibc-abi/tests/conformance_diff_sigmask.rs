#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // mutates this thread's signal mask, save/restored

//! Roundtrip AND host-differential gate for the BSD signal-mask trio
//! sigblock/sigsetmask/siggetmask (bd-ltggi7).
//!
//! The mask is a per-thread bitmask where bit (signo-1) selects signo. This
//! gate now runs the SAME script twice — once against fl, once against host
//! glibc — and requires the two traces to be identical, because the previous
//! version only checked fl against itself. Self-consistency cannot see a
//! divergence in the reserved-bit policy, the sign/width of the mask widening,
//! or the value returned as the *previous* mask, and all three are settled by
//! glibc rather than by POSIX (bd-reality-202609-lx578q.7; the file was reported
//! by `scripts/audit_oracle_arms.py --no-host-arm` as a differential with no
//! host arm at all).
//!
//! `sigblock`, `sigsetmask` and `siggetmask` all exist in host libc, so a real
//! oracle is available. Resolution goes through `common/dlsym_oracle`, which
//! asserts the resolved address is NOT fl's own export: fl exports all three
//! into this same test binary, so a link-time declaration is only an oracle
//! while the linker happens to pick libc.so.6.
//!
//! THE INDEPENDENT WITNESS. Comparing return values alone would miss a case
//! where both implementations agree on the *reported* mask while disagreeing
//! about what they actually installed in the kernel. Each step therefore also
//! reads the thread's real mask through host glibc's `pthread_sigmask` (a NULL
//! set is a pure read) and records it, so the trace carries both the API's
//! opinion and an outside view of the kernel state.
//!
//! THE CASE THAT MATTERS MOST is `sigblock(-1)`: a 32-bit mask cannot name
//! signals 33..64, and glibc's `sigprocmask` deletes its own reserved signals
//! from every set it is handed. fl documents both behaviours
//! (`bsd_mask_to_sigset` in `unistd_abi.rs`), and this gate is where the claim
//! is measured against the host instead of asserted.
//!
//! SIGUSR1/SIGUSR2 (safe to block briefly) are used, and the original mask is
//! restored at the end. rt_sigprocmask is per-thread, so this cannot disturb
//! sibling test threads.

use std::ffi::c_int;

use frankenlibc_abi::unistd_abi as u;

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;
use dlsym_oracle::{host_addr, host_fn};

const SIGUSR1: c_int = 10;
const SIGUSR2: c_int = 12;

/// SIG_BLOCK, for the read-only witness call.
const SIG_BLOCK: c_int = 0;

fn bsd_mask(sig: c_int) -> c_int {
    1 << (sig - 1)
}

type Sigblock = unsafe extern "C" fn(c_int) -> c_int;
type Sigsetmask = unsafe extern "C" fn(c_int) -> c_int;
type Siggetmask = unsafe extern "C" fn() -> c_int;
type PthreadSigmask =
    unsafe extern "C" fn(c_int, *const libc::sigset_t, *mut libc::sigset_t) -> c_int;

struct Masks {
    sigblock: Sigblock,
    sigsetmask: Sigsetmask,
    siggetmask: Siggetmask,
}

fn fl_masks() -> Masks {
    Masks {
        sigblock: u::sigblock,
        sigsetmask: u::sigsetmask,
        siggetmask: u::siggetmask,
    }
}

fn host_masks() -> Masks {
    // SAFETY: each address is given the declared type of its C prototype, and
    // `host_fn` rejects any resolution that aliases fl's own definition.
    unsafe {
        Masks {
            sigblock: host_fn(c"sigblock", u::sigblock as *const ()),
            sigsetmask: host_fn(c"sigsetmask", u::sigsetmask as *const ()),
            siggetmask: host_fn(c"siggetmask", u::siggetmask as *const ()),
        }
    }
}

/// Host glibc's view of this thread's kernel mask, read without mutating it.
///
/// # Safety
///
/// `witness` must be host glibc's `pthread_sigmask`.
unsafe fn kernel_mask(witness: PthreadSigmask) -> u64 {
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    let rc = unsafe { witness(SIG_BLOCK, std::ptr::null(), &mut set) };
    assert_eq!(rc, 0, "reading the thread mask must succeed");
    // SAFETY: sigset_t is an array of c_ulong; the first word is the low 64
    // signals on Linux, which is the whole range a BSD int mask can name.
    unsafe { *(&set as *const libc::sigset_t).cast::<u64>() }
}

/// Run the shared script and return every observable value, in order.
///
/// # Safety
///
/// `m` and `witness` must belong to the same provider, and the caller is
/// responsible for leaving the thread's mask restored.
unsafe fn trace(m: &Masks, witness: PthreadSigmask, orig: c_int) -> Vec<String> {
    let mut t = Vec::new();
    let step = |label: &str, rc: c_int, t: &mut Vec<String>| {
        // SAFETY: `m` is a valid provider; the witness read never mutates.
        let here = unsafe { (m.siggetmask)() };
        let kern = unsafe { kernel_mask(witness) };
        t.push(format!(
            "{label}->{rc} getmask=0x{here:08x} kernel=0x{kern:016x}"
        ));
    };

    // SAFETY: all providers were resolved above; the script restores `orig`.
    unsafe {
        let rc = (m.sigsetmask)(0);
        step("clear", rc, &mut t);

        let rc = (m.sigblock)(bsd_mask(SIGUSR1));
        step("block_usr1", rc, &mut t);

        let rc = (m.sigblock)(bsd_mask(SIGUSR2));
        step("block_usr2", rc, &mut t);

        let rc = (m.sigsetmask)(bsd_mask(SIGUSR2));
        step("replace_usr2", rc, &mut t);

        // The case that pins the reserved-bit policy and the zero-extension of a
        // negative int mask.
        let rc = (m.sigblock)(-1);
        step("block_all", rc, &mut t);

        let rc = (m.sigsetmask)(0);
        step("clear_again", rc, &mut t);

        let rc = (m.sigsetmask)(orig);
        step("restore", rc, &mut t);
    }
    t
}

#[test]
fn bsd_mask_trio_matches_host_glibc() {
    // SAFETY: resolved to host glibc explicitly, never to fl's own export. This
    // arm is the independent witness for BOTH provider runs below.
    let witness =
        unsafe { host_fn::<PthreadSigmask>(c"pthread_sigmask", fl_pthread_sigmask_def()) };

    // Establish the baseline once, from fl, then run both arms from it: the fl
    // arm restores the mask at its end, so the host arm starts where fl did.
    let orig = unsafe { (fl_masks().sigsetmask)(0) };
    let fl_trace = unsafe { trace(&fl_masks(), witness, orig) };
    let host_trace = unsafe { trace(&host_masks(), witness, orig) };
    // Leave the thread as we found it, through whichever provider.
    let _ = unsafe { (host_masks().sigsetmask)(orig) };

    assert_eq!(
        fl_trace, host_trace,
        "BSD signal-mask trace diverged from host glibc"
    );

    // Pinned reference values, so a host glibc behaviour change is visible
    // instead of silently absorbed into a passing comparison. Kernel words are
    // masked to the signals a 32-bit BSD mask can name plus the reserved bit,
    // because the exact SigBlk word also carries whatever the harness blocked.
    let expect = |row: &str, field: &str| -> u64 {
        let tok = row
            .split_whitespace()
            .find_map(|f| f.strip_prefix(field))
            .unwrap_or_else(|| panic!("no {field} in {row}"));
        let hex = tok.trim_start_matches("0x");
        u64::from_str_radix(hex, 16).unwrap()
    };
    assert_eq!(
        fl_trace.len(),
        7,
        "script did not run in full: {fl_trace:?}"
    );
    // clear -> 0, and the two USR bits set the expected bits.
    assert_eq!(expect(&fl_trace[0], "getmask="), 0);
    assert_eq!(
        expect(&fl_trace[1], "getmask="),
        bsd_mask(SIGUSR1) as u32 as u64
    );
    assert_eq!(
        expect(&fl_trace[2], "getmask="),
        (bsd_mask(SIGUSR1) | bsd_mask(SIGUSR2)) as u32 as u64
    );
    assert_eq!(
        expect(&fl_trace[3], "getmask="),
        bsd_mask(SIGUSR2) as u32 as u64
    );
    // block_all: three bits are cleared out of the 32 a BSD mask can name.
    // glibc's sigprocmask deletes its own SIGCANCEL (bit 31), and the kernel
    // silently refuses to block SIGKILL (bit 8) and SIGSTOP (bit 18). The
    // expected word is therefore 0x7ffbfeff, which is also the value recorded
    // in fl's `bsd_mask_to_sigset` documentation — this assertion is what keeps
    // that comment honest.
    assert_eq!(
        expect(&fl_trace[4], "getmask="),
        0x7ffb_feff,
        "sigblock(-1) must leave SIGCANCEL, SIGKILL and SIGSTOP unblocked"
    );
    assert_eq!(
        expect(&fl_trace[4], "kernel=") & 0xffff_ffff,
        0x7ffb_feff,
        "kernel view must agree on the same three bits"
    );
    assert_eq!(expect(&fl_trace[5], "getmask="), 0);
    assert_eq!(expect(&fl_trace[6], "getmask="), orig as u32 as u64);
}

/// The provider-identity control: a "glibc" arm that IS fl must be refused, not
/// compared. Without this, a collapsed oracle would make the gate above pass
/// unconditionally.
#[test]
fn sigmask_oracle_rejects_identical_candidate_provider() {
    // SAFETY: only resolves and compares code addresses; no mismatched call.
    let host = unsafe { host_addr(c"sigblock", u::sigblock as *const ()) };
    let rejected = std::panic::catch_unwind(|| unsafe {
        host_addr(c"sigblock", host.cast());
    });
    let error = rejected.expect_err("an identical candidate/oracle provider must be rejected");
    let message = error
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| error.downcast_ref::<&str>().copied())
        .expect("provider rejection must report a diagnostic");
    assert!(
        message.contains("IS fl's own definition"),
        "expected the provider-identity rejection, got: {message}"
    );
}

#[test]
fn sigblock_sigsetmask_siggetmask_roundtrip() {
    let m1 = bsd_mask(SIGUSR1); // bit 9
    let m2 = bsd_mask(SIGUSR2); // bit 11

    // Save the original mask (sigsetmask returns the previous mask), then clear.
    let orig = unsafe { u::sigsetmask(0) };

    // After clearing, the (low-32) mask must be empty.
    assert_eq!(unsafe { u::siggetmask() }, 0, "siggetmask after clear");

    // sigblock(m1): blocks SIGUSR1, returns the previous (empty) mask.
    let prev = unsafe { u::sigblock(m1) };
    assert_eq!(prev, 0, "sigblock returns previous mask");
    assert_eq!(unsafe { u::siggetmask() }, m1, "SIGUSR1 now blocked");

    // sigblock(m2): ORs in SIGUSR2, returns previous (m1).
    let prev2 = unsafe { u::sigblock(m2) };
    assert_eq!(prev2, m1, "sigblock returns prior mask (m1)");
    assert_eq!(
        unsafe { u::siggetmask() },
        m1 | m2,
        "both USR1+USR2 blocked"
    );

    // sigsetmask(m2): REPLACES the mask with just m2, returns previous (m1|m2).
    let prev3 = unsafe { u::sigsetmask(m2) };
    assert_eq!(prev3, m1 | m2, "sigsetmask returns prior full mask");
    assert_eq!(
        unsafe { u::siggetmask() },
        m2,
        "sigsetmask replaced, not OR'd"
    );

    // Restore the original mask.
    let _ = unsafe { u::sigsetmask(orig) };
    assert_eq!(unsafe { u::siggetmask() }, orig, "original mask restored");
}

/// fl's own `pthread_sigmask`, needed only so `host_fn` can refuse a resolution
/// that lands on it.
fn fl_pthread_sigmask_def() -> *const () {
    frankenlibc_abi::signal_abi::pthread_sigmask as *const ()
}
