#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc sigabbrev_np / sigdescr_np oracle

//! `sigabbrev_np` / `sigdescr_np` parity vs host glibc (bd-2g7oyh.312).
//!
//! These GNU helpers return the short abbreviation ("HUP", "INT", …) and the
//! human-readable description ("Hangup", "Interrupt", …) for a signal number.
//! fl's existing coverage (signal_abi_test) pins them against *hardcoded*
//! expectation strings, so a glibc table revision (or an fl edit) could silently
//! drift without a live oracle catching it — and the hardcoded set thinly
//! covers the realtime-signal band (SIGRTMIN..=SIGRTMAX), where glibc renders
//! "Real-time signal N" descriptions and abbreviations.
//!
//! This gate sweeps the whole practical range (including invalid negatives, 0,
//! every standard signal, the realtime band, and out-of-range values past
//! SIGRTMAX) and requires byte-exact agreement with the running glibc for both
//! the returned string and its null/non-null status.

use std::ffi::{CStr, c_char, c_int};

use frankenlibc_abi::signal_abi as fl;

unsafe extern "C" {
    fn sigabbrev_np(sig: c_int) -> *const c_char;
    fn sigdescr_np(sig: c_int) -> *const c_char;
}

/// Render a returned C string pointer to an owned form that distinguishes NULL
/// from the empty string, so the comparison catches a wrong null/non-null status
/// as well as a wrong message.
fn render(p: *const c_char) -> Option<String> {
    if p.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
    }
}

#[test]
fn sigabbrev_np_matches_glibc_full_range() {
    for sig in -8..=140 {
        let f = render(unsafe { fl::sigabbrev_np(sig) });
        let g = render(unsafe { sigabbrev_np(sig) });
        assert_eq!(f, g, "sigabbrev_np({sig}): fl={f:?} glibc={g:?}");
    }
}

#[test]
fn sigdescr_np_matches_glibc_full_range() {
    for sig in -8..=140 {
        let f = render(unsafe { fl::sigdescr_np(sig) });
        let g = render(unsafe { sigdescr_np(sig) });
        assert_eq!(f, g, "sigdescr_np({sig}): fl={f:?} glibc={g:?}");
    }
}
