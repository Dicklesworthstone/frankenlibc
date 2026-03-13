#![cfg(target_os = "linux")]

//! Integration tests for `<fenv.h>` ABI entrypoints.

use std::ffi::c_void;

use frankenlibc_abi::fenv_abi::{
    feclearexcept, fegetenv, fegetexceptflag, fegetround, feholdexcept, feraiseexcept, fesetenv,
    fesetexceptflag, fesetround, fetestexcept, feupdateenv,
};

// Linux x86_64 fenv constants from `<fenv.h>` (glibc ABI).
const FE_INVALID: i32 = 0x01;
const FE_DIVBYZERO: i32 = 0x04;
const FE_ALL_EXCEPT: i32 = 0x3f;
const FE_TONEAREST: i32 = 0x0000;
const FE_DOWNWARD: i32 = 0x0400;
const FE_UPWARD: i32 = 0x0800;
const FE_TOWARDZERO: i32 = 0x0c00;

struct RoundingGuard {
    saved_mode: i32,
}

impl RoundingGuard {
    fn new() -> Self {
        // SAFETY: reads process FPU rounding mode and does not mutate memory.
        let saved_mode = unsafe { fegetround() };
        assert_ne!(saved_mode, -1, "fegetround should be available");
        Self { saved_mode }
    }
}

impl Drop for RoundingGuard {
    fn drop(&mut self) {
        // SAFETY: restores previously observed mode.
        let _ = unsafe { fesetround(self.saved_mode) };
    }
}

#[test]
fn fesetround_round_trips_supported_modes() {
    let _guard = RoundingGuard::new();
    let mut switched_modes = 0;

    for mode in [FE_TONEAREST, FE_UPWARD, FE_DOWNWARD, FE_TOWARDZERO] {
        // SAFETY: setting process rounding mode is defined by fenv API.
        let rc = unsafe { fesetround(mode) };
        if rc == 0 {
            switched_modes += 1;
            // SAFETY: reads process FPU rounding mode.
            let current = unsafe { fegetround() };
            assert_eq!(current, mode);
        }
    }

    assert!(
        switched_modes > 0,
        "expected at least one supported rounding mode transition"
    );
}

#[test]
fn fesetround_rejects_invalid_mode() {
    let _guard = RoundingGuard::new();
    // SAFETY: invalid mode should be rejected by host implementation.
    assert_ne!(unsafe { fesetround(i32::MAX) }, 0);
}

#[test]
fn exception_flags_raise_and_clear() {
    // SAFETY: clearing/testing/raising exception flags is defined by fenv API.
    unsafe {
        assert_eq!(feclearexcept(FE_ALL_EXCEPT), 0);
        assert_eq!(fetestexcept(FE_ALL_EXCEPT), 0);

        assert_eq!(feraiseexcept(FE_DIVBYZERO), 0);
        let raised = fetestexcept(FE_DIVBYZERO);
        assert_ne!(raised & FE_DIVBYZERO, 0);

        assert_eq!(feclearexcept(FE_DIVBYZERO), 0);
        assert_eq!(fetestexcept(FE_DIVBYZERO), 0);
    }
}

#[test]
fn exceptflag_round_trip_restores_flag_bits() {
    // SAFETY: byte buffers are large enough for `fexcept_t` payload on glibc targets.
    unsafe {
        assert_eq!(feclearexcept(FE_ALL_EXCEPT), 0);
        assert_eq!(feraiseexcept(FE_INVALID), 0);

        let mut saved: u16 = 0;
        assert_eq!(fegetexceptflag(&mut saved, FE_INVALID), 0);

        assert_eq!(feclearexcept(FE_INVALID), 0);
        assert_eq!(fetestexcept(FE_INVALID), 0);

        assert_eq!(fesetexceptflag(&saved, FE_INVALID), 0);
        let restored = fetestexcept(FE_INVALID);
        assert_ne!(restored & FE_INVALID, 0);

        assert_eq!(feclearexcept(FE_ALL_EXCEPT), 0);
    }
}

#[test]
fn null_pointer_contracts_are_enforced_for_pointer_outputs() {
    // SAFETY: null pointers should be rejected by ABI guard code.
    unsafe {
        assert_eq!(
            fegetexceptflag(std::ptr::null_mut::<u16>(), FE_ALL_EXCEPT),
            -1
        );
        assert_eq!(fesetexceptflag(std::ptr::null::<u16>(), FE_ALL_EXCEPT), -1);
        assert_eq!(fegetenv(std::ptr::null_mut()), -1);
        assert_eq!(feholdexcept(std::ptr::null_mut()), -1);
    }
}

#[test]
fn fegetenv_and_fesetenv_restore_rounding_state() {
    let _guard = RoundingGuard::new();

    // SAFETY: `env` buffer is large enough for glibc `fenv_t`; pointer is valid for read/write.
    unsafe {
        let original = fegetround();
        let mut env = [0_u8; 256];
        assert_eq!(fegetenv(env.as_mut_ptr().cast::<c_void>()), 0);

        if fesetround(FE_UPWARD) == 0 {
            assert_eq!(fegetround(), FE_UPWARD);
            assert_eq!(fesetenv(env.as_ptr().cast::<c_void>()), 0);
            assert_eq!(fegetround(), original);
        }
    }
}

#[test]
fn feholdexcept_and_feupdateenv_round_trip_saved_exceptions() {
    // SAFETY: `env` buffer is large enough for glibc `fenv_t`; pointer is valid for read/write.
    unsafe {
        assert_eq!(feclearexcept(FE_ALL_EXCEPT), 0);
        assert_eq!(feraiseexcept(FE_DIVBYZERO), 0);
        assert_ne!(fetestexcept(FE_DIVBYZERO) & FE_DIVBYZERO, 0);

        let mut env = [0_u8; 256];
        assert_eq!(feholdexcept(env.as_mut_ptr().cast::<c_void>()), 0);
        assert_eq!(fetestexcept(FE_ALL_EXCEPT), 0);

        assert_eq!(feupdateenv(env.as_ptr().cast::<c_void>()), 0);
        assert_ne!(fetestexcept(FE_DIVBYZERO) & FE_DIVBYZERO, 0);

        assert_eq!(feclearexcept(FE_ALL_EXCEPT), 0);
    }
}

// ---------------------------------------------------------------------------
// Multiple exception flags
// ---------------------------------------------------------------------------

#[test]
fn raise_multiple_exceptions_and_test_individually() {
    unsafe {
        assert_eq!(feclearexcept(FE_ALL_EXCEPT), 0);

        // Raise both invalid and divbyzero
        assert_eq!(feraiseexcept(FE_INVALID | FE_DIVBYZERO), 0);

        // Both should be set
        let flags = fetestexcept(FE_INVALID | FE_DIVBYZERO);
        assert_ne!(flags & FE_INVALID, 0, "FE_INVALID should be raised");
        assert_ne!(flags & FE_DIVBYZERO, 0, "FE_DIVBYZERO should be raised");

        // Clear only one
        assert_eq!(feclearexcept(FE_INVALID), 0);
        assert_eq!(fetestexcept(FE_INVALID), 0, "FE_INVALID should be cleared");
        assert_ne!(
            fetestexcept(FE_DIVBYZERO) & FE_DIVBYZERO,
            0,
            "FE_DIVBYZERO should remain"
        );

        assert_eq!(feclearexcept(FE_ALL_EXCEPT), 0);
    }
}

#[test]
fn feclearexcept_zero_is_noop() {
    unsafe {
        assert_eq!(feclearexcept(0), 0);
    }
}

#[test]
fn feraiseexcept_zero_is_noop() {
    unsafe {
        assert_eq!(feraiseexcept(0), 0);
    }
}

#[test]
fn fegetround_returns_valid_mode() {
    let mode = unsafe { fegetround() };
    assert!(
        mode == FE_TONEAREST || mode == FE_DOWNWARD || mode == FE_UPWARD || mode == FE_TOWARDZERO,
        "fegetround should return a known rounding mode, got {mode}"
    );
}

// ---------------------------------------------------------------------------
// Exception flag isolation
// ---------------------------------------------------------------------------

#[test]
fn clear_one_exception_preserves_others() {
    unsafe {
        assert_eq!(feclearexcept(FE_ALL_EXCEPT), 0);
        // Raise invalid and divbyzero
        assert_eq!(feraiseexcept(FE_INVALID | FE_DIVBYZERO), 0);

        // Clear only divbyzero
        assert_eq!(feclearexcept(FE_DIVBYZERO), 0);

        // Invalid should still be set
        assert_ne!(
            fetestexcept(FE_INVALID) & FE_INVALID,
            0,
            "FE_INVALID should remain after clearing FE_DIVBYZERO"
        );
        // Divbyzero should be cleared
        assert_eq!(
            fetestexcept(FE_DIVBYZERO) & FE_DIVBYZERO,
            0,
            "FE_DIVBYZERO should be cleared"
        );

        assert_eq!(feclearexcept(FE_ALL_EXCEPT), 0);
    }
}

#[test]
fn fetestexcept_returns_only_requested_flags() {
    unsafe {
        assert_eq!(feclearexcept(FE_ALL_EXCEPT), 0);
        assert_eq!(feraiseexcept(FE_INVALID | FE_DIVBYZERO), 0);

        // Test for only FE_INVALID — should not include FE_DIVBYZERO
        let result = fetestexcept(FE_INVALID);
        assert_ne!(result & FE_INVALID, 0);
        assert_eq!(
            result & FE_DIVBYZERO,
            0,
            "fetestexcept(FE_INVALID) should not report FE_DIVBYZERO"
        );

        assert_eq!(feclearexcept(FE_ALL_EXCEPT), 0);
    }
}

// ---------------------------------------------------------------------------
// Rounding mode edge cases
// ---------------------------------------------------------------------------

#[test]
fn fesetround_all_modes_round_trip() {
    let _guard = RoundingGuard::new();
    let modes = [FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO];

    for &mode in &modes {
        unsafe {
            let rc = fesetround(mode);
            assert_eq!(rc, 0, "fesetround({mode}) should succeed");
            let current = fegetround();
            assert_eq!(
                current, mode,
                "fegetround after fesetround({mode}) should return {mode}"
            );
        }
    }
}

#[test]
fn fesetround_zero_is_tonearest() {
    let _guard = RoundingGuard::new();
    unsafe {
        let rc = fesetround(0);
        assert_eq!(rc, 0, "fesetround(0) should succeed");
        let mode = fegetround();
        assert_eq!(mode, FE_TONEAREST, "mode 0 should be FE_TONEAREST");
    }
}

// ---------------------------------------------------------------------------
// Environment save/restore with exceptions
// ---------------------------------------------------------------------------

#[test]
fn fegetenv_fesetenv_restores_exception_flags() {
    unsafe {
        // Start clean
        assert_eq!(feclearexcept(FE_ALL_EXCEPT), 0);
        assert_eq!(feraiseexcept(FE_INVALID), 0);

        // Save environment with FE_INVALID set
        let mut env = [0_u8; 256];
        assert_eq!(fegetenv(env.as_mut_ptr().cast::<c_void>()), 0);

        // Clear exceptions
        assert_eq!(feclearexcept(FE_ALL_EXCEPT), 0);
        assert_eq!(fetestexcept(FE_INVALID), 0);

        // Restore environment — FE_INVALID should come back
        assert_eq!(fesetenv(env.as_ptr().cast::<c_void>()), 0);
        assert_ne!(
            fetestexcept(FE_INVALID) & FE_INVALID,
            0,
            "FE_INVALID should be restored by fesetenv"
        );

        assert_eq!(feclearexcept(FE_ALL_EXCEPT), 0);
    }
}

#[test]
fn feholdexcept_clears_all_exceptions() {
    unsafe {
        // Raise some exceptions
        assert_eq!(feclearexcept(FE_ALL_EXCEPT), 0);
        assert_eq!(feraiseexcept(FE_INVALID | FE_DIVBYZERO), 0);

        // feholdexcept should save state and clear
        let mut env = [0_u8; 256];
        assert_eq!(feholdexcept(env.as_mut_ptr().cast::<c_void>()), 0);

        // All exceptions should be cleared
        assert_eq!(
            fetestexcept(FE_ALL_EXCEPT),
            0,
            "feholdexcept should clear all exception flags"
        );

        // Restore
        assert_eq!(feupdateenv(env.as_ptr().cast::<c_void>()), 0);

        // Original exceptions should be restored
        assert_ne!(fetestexcept(FE_INVALID) & FE_INVALID, 0);
        assert_ne!(fetestexcept(FE_DIVBYZERO) & FE_DIVBYZERO, 0);

        assert_eq!(feclearexcept(FE_ALL_EXCEPT), 0);
    }
}

// ---------------------------------------------------------------------------
// Exception flag get/set round-trip
// ---------------------------------------------------------------------------

#[test]
fn fegetexceptflag_fesetexceptflag_round_trip_multiple() {
    unsafe {
        assert_eq!(feclearexcept(FE_ALL_EXCEPT), 0);
        assert_eq!(feraiseexcept(FE_DIVBYZERO | FE_INVALID), 0);

        // Save both flags
        let mut saved: u16 = 0;
        assert_eq!(fegetexceptflag(&mut saved, FE_DIVBYZERO | FE_INVALID), 0);

        // Clear them
        assert_eq!(feclearexcept(FE_ALL_EXCEPT), 0);

        // Restore both
        assert_eq!(fesetexceptflag(&saved, FE_DIVBYZERO | FE_INVALID), 0);
        assert_ne!(fetestexcept(FE_DIVBYZERO) & FE_DIVBYZERO, 0);
        assert_ne!(fetestexcept(FE_INVALID) & FE_INVALID, 0);

        assert_eq!(feclearexcept(FE_ALL_EXCEPT), 0);
    }
}

#[test]
fn feclearexcept_all_then_test_returns_zero() {
    unsafe {
        // Raise everything then clear everything
        assert_eq!(feraiseexcept(FE_ALL_EXCEPT), 0);
        assert_eq!(feclearexcept(FE_ALL_EXCEPT), 0);
        assert_eq!(
            fetestexcept(FE_ALL_EXCEPT),
            0,
            "all exceptions should be cleared"
        );
    }
}
