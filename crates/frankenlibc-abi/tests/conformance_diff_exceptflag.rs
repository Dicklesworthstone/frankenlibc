#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc fenv oracle (libm); mutates this thread's fenv

//! Differential gate for fegetexceptflag/fesetexceptflag vs host glibc
//! (bd-v6t3e6) — previously fl-internal only. fegetexceptflag saves the state
//! of the selected exception flags into an fexcept_t; fesetexceptflag restores
//! them WITHOUT raising (sets the status bits, never traps) and honours the
//! `excepts` mask (a subset restore touches only those flags). Pins: full
//! round-trip restores the saved flags; a subset mask restores only the masked
//! flags; the saved fexcept_t value matches glibc (fl uses the glibc-compatible
//! u16 layout). fl must match glibc; thread fenv restored. No mocks.

use std::ffi::c_int;

const FE_INVALID: c_int = 0x01;
const FE_OVERFLOW: c_int = 0x08;
const FE_ALL: c_int = 0x3D;

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn feclearexcept(e: c_int) -> c_int;
        pub fn feraiseexcept(e: c_int) -> c_int;
        pub fn fetestexcept(e: c_int) -> c_int;
        pub fn fegetexceptflag(flagp: *mut u16, e: c_int) -> c_int;
        pub fn fesetexceptflag(flagp: *const u16, e: c_int) -> c_int;
    }
}
use frankenlibc_abi::fenv_abi as fl;

/// Returns (saved fexcept_t, flags after full restore, flags after subset
/// restore of FE_INVALID only) for one impl.
fn run(fl_impl: bool) -> (u16, c_int, c_int) {
    let mut saved: u16 = 0;
    unsafe {
        if fl_impl {
            fl::feclearexcept(FE_ALL);
            fl::feraiseexcept(FE_INVALID | FE_OVERFLOW);
            assert_eq!(fl::fegetexceptflag(&mut saved, FE_ALL), 0);
            // full restore
            fl::feclearexcept(FE_ALL);
            assert_eq!(fl::fesetexceptflag(&saved, FE_ALL), 0);
            let full = fl::fetestexcept(FE_ALL) & FE_ALL;
            // subset restore: only FE_INVALID
            fl::feclearexcept(FE_ALL);
            assert_eq!(fl::fesetexceptflag(&saved, FE_INVALID), 0);
            let subset = fl::fetestexcept(FE_ALL) & FE_ALL;
            fl::feclearexcept(FE_ALL);
            (saved, full, subset)
        } else {
            g::feclearexcept(FE_ALL);
            g::feraiseexcept(FE_INVALID | FE_OVERFLOW);
            assert_eq!(g::fegetexceptflag(&mut saved, FE_ALL), 0);
            g::feclearexcept(FE_ALL);
            assert_eq!(g::fesetexceptflag(&saved, FE_ALL), 0);
            let full = g::fetestexcept(FE_ALL) & FE_ALL;
            g::feclearexcept(FE_ALL);
            assert_eq!(g::fesetexceptflag(&saved, FE_INVALID), 0);
            let subset = g::fetestexcept(FE_ALL) & FE_ALL;
            g::feclearexcept(FE_ALL);
            (saved, full, subset)
        }
    }
}

#[test]
fn fegetexceptflag_fesetexceptflag_match_glibc() {
    let gr = run(false);
    let fr = run(true);
    assert_eq!(fr.1, gr.1, "full restore flags: fl={:#x} glibc={:#x}", fr.1, gr.1);
    assert_eq!(fr.2, gr.2, "subset restore flags: fl={:#x} glibc={:#x}", fr.2, gr.2);
    // saved fexcept_t value should match the glibc-compatible layout.
    assert_eq!(fr.0, gr.0, "saved fexcept_t: fl={:#x} glibc={:#x}", fr.0, gr.0);
    // sanity
    assert_eq!(gr.1, FE_INVALID | FE_OVERFLOW, "full restore must reinstate both");
    assert_eq!(gr.2, FE_INVALID, "subset restore must reinstate only FE_INVALID");
    unsafe { g::feclearexcept(FE_ALL) };
}
