#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // mutates this thread's signal mask, save/restored

//! Roundtrip gate for the BSD signal-mask trio sigblock/sigsetmask/siggetmask
//! (bd-ltggi7) — previously uncovered. The mask is a per-thread bitmask where
//! bit (signo-1) selects signo. Verifies: sigsetmask replaces the mask and
//! returns the old one; sigblock ORs in and returns the old one; siggetmask
//! reads the current mask. Uses SIGUSR1/SIGUSR2 (safe to block briefly) and
//! restores the original mask at the end. rt_sigprocmask is per-thread, so this
//! cannot disturb sibling cargo test threads. No mocks — pure self-consistency.

use std::ffi::c_int;

use frankenlibc_abi::unistd_abi as u;

const SIGUSR1: c_int = 10;
const SIGUSR2: c_int = 12;

fn bsd_mask(sig: c_int) -> c_int {
    1 << (sig - 1)
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
    assert_eq!(unsafe { u::siggetmask() }, m1 | m2, "both USR1+USR2 blocked");

    // sigsetmask(m2): REPLACES the mask with just m2, returns previous (m1|m2).
    let prev3 = unsafe { u::sigsetmask(m2) };
    assert_eq!(prev3, m1 | m2, "sigsetmask returns prior full mask");
    assert_eq!(unsafe { u::siggetmask() }, m2, "sigsetmask replaced, not OR'd");

    // Restore the original mask.
    let _ = unsafe { u::sigsetmask(orig) };
    assert_eq!(unsafe { u::siggetmask() }, orig, "original mask restored");
}
