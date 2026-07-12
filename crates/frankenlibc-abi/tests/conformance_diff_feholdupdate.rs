#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc fenv oracle; mutates this thread's fenv

//! Differential gate for feholdexcept/feupdateenv observable behaviour vs host
//! glibc (bd-5zeg52). The existing fenv_abi_test does an fl-only round-trip;
//! this compares the OBSERVABLE flag outcome of the canonical sequence against
//! glibc. The subtle, bug-prone semantics: feholdexcept saves the env and
//! CLEARS the raised flags; feupdateenv restores the saved env (re-instating
//! its flags) and then RE-RAISES whatever exceptions are currently raised. So
//! after holding with FE_INVALID set then raising FE_OVERFLOW then updating,
//! the flags must be FE_INVALID|FE_OVERFLOW. fl must match glibc. fl's fenv_t is
//! glibc-x86-64-layout-compatible, so libc::fenv_t works for both. The mutated
//! fenv is restored. No mocks.

use std::ffi::{c_int, c_void};
use std::mem::MaybeUninit;

const FE_INVALID: c_int = 0x01;
const FE_OVERFLOW: c_int = 0x08;
const FE_ALL: c_int = 0x3D;

// Opaque fenv_t storage: glibc x86-64 fenv_t is 28 bytes; 64 bytes 16-aligned
// is an ample superset for both impls (fl validates >= the glibc size).
#[repr(C, align(16))]
struct EnvBuf([u8; 64]);

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn feclearexcept(e: c_int) -> c_int;
        pub fn feraiseexcept(e: c_int) -> c_int;
        pub fn fetestexcept(e: c_int) -> c_int;
        pub fn feholdexcept(envp: *mut c_void) -> c_int;
        pub fn feupdateenv(envp: *const c_void) -> c_int;
    }
}
use frankenlibc_abi::fenv_abi as fl;

/// Run the canonical hold/update sequence with one impl; return
/// (flags-after-hold, flags-after-update). `which` selects fl (true) or glibc.
fn sequence(fl_impl: bool) -> (c_int, c_int) {
    let mut env = MaybeUninit::<EnvBuf>::uninit();
    let p = env.as_mut_ptr().cast::<c_void>();
    unsafe {
        if fl_impl {
            fl::feclearexcept(FE_ALL);
            fl::feraiseexcept(FE_INVALID);
            assert_eq!(fl::feholdexcept(p), 0);
            let after_hold = fl::fetestexcept(FE_ALL) & FE_ALL;
            fl::feraiseexcept(FE_OVERFLOW);
            assert_eq!(fl::feupdateenv(p.cast_const()), 0);
            let after_update = fl::fetestexcept(FE_ALL) & FE_ALL;
            fl::feclearexcept(FE_ALL);
            (after_hold, after_update)
        } else {
            g::feclearexcept(FE_ALL);
            g::feraiseexcept(FE_INVALID);
            assert_eq!(g::feholdexcept(p), 0);
            let after_hold = g::fetestexcept(FE_ALL) & FE_ALL;
            g::feraiseexcept(FE_OVERFLOW);
            assert_eq!(g::feupdateenv(p.cast_const()), 0);
            let after_update = g::fetestexcept(FE_ALL) & FE_ALL;
            g::feclearexcept(FE_ALL);
            (after_hold, after_update)
        }
    }
}

#[test]
fn feholdexcept_feupdateenv_match_glibc() {
    let g_res = sequence(false);
    let fl_res = sequence(true);
    assert_eq!(
        fl_res, g_res,
        "hold/update flag outcome: fl={fl_res:?} glibc={g_res:?}"
    );
    // Sanity: feholdexcept clears, feupdateenv re-raises INVALID|OVERFLOW.
    assert_eq!(g_res.0, 0, "feholdexcept must clear raised flags");
    assert_eq!(
        g_res.1,
        FE_INVALID | FE_OVERFLOW,
        "feupdateenv must restore+re-raise"
    );
    // restore a clean fenv for sibling tests
    unsafe { g::feclearexcept(FE_ALL) };
}
