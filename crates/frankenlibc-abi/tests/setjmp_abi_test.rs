#![cfg(target_os = "linux")]

//! Integration tests for `<setjmp.h>` ABI entrypoints.
//!
//! In integration test mode (not `#[cfg(test)]` from the library crate's
//! perspective), `longjmp`/`siglongjmp` call `abort()` rather than panicking.
//! Therefore we can only exercise the capture path (`setjmp`, `_setjmp`,
//! `sigsetjmp`) and verify null-pointer error handling.

use std::ffi::c_void;
use std::ptr;

use frankenlibc_abi::setjmp_abi::{_setjmp, setjmp, sigsetjmp};

// ---------------------------------------------------------------------------
// setjmp — capture returns 0
// ---------------------------------------------------------------------------

#[test]
fn setjmp_returns_zero_on_capture() {
    let mut env = [0u64; 32]; // generous buffer for jmp_buf
    let env_ptr = env.as_mut_ptr().cast::<c_void>();
    let rc = unsafe { setjmp(env_ptr) };
    assert_eq!(rc, 0, "setjmp should return 0 on first (capture) call");
}

#[test]
fn setjmp_null_env_returns_negative() {
    let rc = unsafe { setjmp(ptr::null_mut()) };
    assert_eq!(rc, -1, "setjmp(NULL) should return -1");
}

// ---------------------------------------------------------------------------
// _setjmp — BSD variant, same contract
// ---------------------------------------------------------------------------

#[test]
fn _setjmp_returns_zero_on_capture() {
    let mut env = [0u64; 32];
    let env_ptr = env.as_mut_ptr().cast::<c_void>();
    let rc = unsafe { _setjmp(env_ptr) };
    assert_eq!(rc, 0, "_setjmp should return 0 on first (capture) call");
}

#[test]
fn _setjmp_null_env_returns_negative() {
    let rc = unsafe { _setjmp(ptr::null_mut()) };
    assert_eq!(rc, -1, "_setjmp(NULL) should return -1");
}

// ---------------------------------------------------------------------------
// sigsetjmp — with and without signal mask save
// ---------------------------------------------------------------------------

#[test]
fn sigsetjmp_no_mask_returns_zero() {
    let mut env = [0u64; 32];
    let env_ptr = env.as_mut_ptr().cast::<c_void>();
    let rc = unsafe { sigsetjmp(env_ptr, 0) };
    assert_eq!(rc, 0, "sigsetjmp(env, 0) should return 0 on capture");
}

#[test]
fn sigsetjmp_with_mask_returns_zero() {
    let mut env = [0u64; 32];
    let env_ptr = env.as_mut_ptr().cast::<c_void>();
    let rc = unsafe { sigsetjmp(env_ptr, 1) };
    assert_eq!(rc, 0, "sigsetjmp(env, 1) should return 0 on capture");
}

#[test]
fn sigsetjmp_null_env_returns_negative() {
    let rc = unsafe { sigsetjmp(ptr::null_mut(), 0) };
    assert_eq!(rc, -1, "sigsetjmp(NULL, 0) should return -1");
}

// ---------------------------------------------------------------------------
// Multiple captures don't interfere
// ---------------------------------------------------------------------------

#[test]
fn multiple_captures_independent() {
    let mut env_a = [0u64; 32];
    let mut env_b = [0u64; 32];
    let rc_a = unsafe { setjmp(env_a.as_mut_ptr().cast::<c_void>()) };
    let rc_b = unsafe { sigsetjmp(env_b.as_mut_ptr().cast::<c_void>(), 1) };
    assert_eq!(rc_a, 0);
    assert_eq!(rc_b, 0);
}

// ---------------------------------------------------------------------------
// Repeated capture on same buffer succeeds
// ---------------------------------------------------------------------------

#[test]
fn setjmp_repeated_capture_same_buffer() {
    let mut env = [0u64; 32];
    let env_ptr = env.as_mut_ptr().cast::<c_void>();
    for _ in 0..5 {
        let rc = unsafe { setjmp(env_ptr) };
        assert_eq!(rc, 0, "repeated setjmp on same buffer should return 0");
    }
}

// ---------------------------------------------------------------------------
// sigsetjmp with various savemask values
// ---------------------------------------------------------------------------

#[test]
fn sigsetjmp_nonzero_savemask_treated_as_true() {
    let mut env = [0u64; 32];
    let env_ptr = env.as_mut_ptr().cast::<c_void>();
    // Any nonzero savemask should be treated as "save mask"
    for mask in [1i32, 42, -1, i32::MAX] {
        let rc = unsafe { sigsetjmp(env_ptr, mask) };
        assert_eq!(rc, 0, "sigsetjmp(env, {mask}) should return 0");
    }
}

// ---------------------------------------------------------------------------
// Capture with pre-filled buffer succeeds
// ---------------------------------------------------------------------------

#[test]
fn setjmp_succeeds_on_prefilled_buffer() {
    let mut env = [0xFFu64; 32];
    let rc = unsafe { setjmp(env.as_mut_ptr().cast::<c_void>()) };
    assert_eq!(rc, 0, "setjmp should succeed even on pre-filled buffer");
}

#[test]
fn _setjmp_succeeds_on_prefilled_buffer() {
    let mut env = [0xFFu64; 32];
    let rc = unsafe { _setjmp(env.as_mut_ptr().cast::<c_void>()) };
    assert_eq!(rc, 0, "_setjmp should succeed even on pre-filled buffer");
}

#[test]
fn sigsetjmp_succeeds_on_prefilled_buffer() {
    let mut env = [0xFFu64; 32];
    let rc = unsafe { sigsetjmp(env.as_mut_ptr().cast::<c_void>(), 1) };
    assert_eq!(rc, 0, "sigsetjmp should succeed even on pre-filled buffer");
}

// ---------------------------------------------------------------------------
// Distinct buffers both succeed independently
// ---------------------------------------------------------------------------

#[test]
fn distinct_buffers_are_independent() {
    let mut env_a = [0u64; 32];
    let mut env_b = [0u64; 32];
    let rc_a = unsafe { setjmp(env_a.as_mut_ptr().cast::<c_void>()) };
    let rc_b = unsafe { setjmp(env_b.as_mut_ptr().cast::<c_void>()) };
    assert_eq!(rc_a, 0);
    assert_eq!(rc_b, 0);
}

// ---------------------------------------------------------------------------
// _setjmp repeated capture
// ---------------------------------------------------------------------------

#[test]
fn _setjmp_repeated_capture_same_buffer() {
    let mut env = [0u64; 32];
    let env_ptr = env.as_mut_ptr().cast::<c_void>();
    for _ in 0..5 {
        let rc = unsafe { _setjmp(env_ptr) };
        assert_eq!(rc, 0, "repeated _setjmp on same buffer should return 0");
    }
}

// ---------------------------------------------------------------------------
// sigsetjmp repeated capture
// ---------------------------------------------------------------------------

#[test]
fn sigsetjmp_repeated_capture_same_buffer() {
    let mut env = [0u64; 32];
    let env_ptr = env.as_mut_ptr().cast::<c_void>();
    for mask in [0, 1, 0, 1, 0] {
        let rc = unsafe { sigsetjmp(env_ptr, mask) };
        assert_eq!(rc, 0, "repeated sigsetjmp on same buffer should return 0");
    }
}

// ---------------------------------------------------------------------------
// Null env for all variants (defensive)
// ---------------------------------------------------------------------------

#[test]
fn all_capture_variants_reject_null() {
    assert_eq!(unsafe { setjmp(ptr::null_mut()) }, -1);
    assert_eq!(unsafe { _setjmp(ptr::null_mut()) }, -1);
    assert_eq!(unsafe { sigsetjmp(ptr::null_mut(), 0) }, -1);
    assert_eq!(unsafe { sigsetjmp(ptr::null_mut(), 1) }, -1);
}

// ---------------------------------------------------------------------------
// Capture with mask 0 vs 1 produces the same return code
// ---------------------------------------------------------------------------

#[test]
fn sigsetjmp_mask_zero_vs_one_both_return_zero() {
    let mut env0 = [0u64; 32];
    let mut env1 = [0u64; 32];
    let rc0 = unsafe { sigsetjmp(env0.as_mut_ptr().cast::<c_void>(), 0) };
    let rc1 = unsafe { sigsetjmp(env1.as_mut_ptr().cast::<c_void>(), 1) };
    assert_eq!(rc0, 0);
    assert_eq!(rc1, 0);
}

// ---------------------------------------------------------------------------
// Null pointer rejection is deterministic across repeated calls
// ---------------------------------------------------------------------------

#[test]
fn null_env_rejection_is_deterministic() {
    for _ in 0..10 {
        assert_eq!(unsafe { setjmp(ptr::null_mut()) }, -1);
        assert_eq!(unsafe { _setjmp(ptr::null_mut()) }, -1);
        assert_eq!(unsafe { sigsetjmp(ptr::null_mut(), 0) }, -1);
    }
}

// ---------------------------------------------------------------------------
// All three variants succeed with aligned stack buffer
// ---------------------------------------------------------------------------

#[test]
fn all_variants_succeed_with_stack_allocated_buffer() {
    #[repr(align(64))]
    struct AlignedBuf([u64; 32]);

    let mut buf = AlignedBuf([0u64; 32]);
    let ptr = buf.0.as_mut_ptr().cast::<c_void>();
    assert_eq!(unsafe { setjmp(ptr) }, 0);
    assert_eq!(unsafe { _setjmp(ptr) }, 0);
    assert_eq!(unsafe { sigsetjmp(ptr, 0) }, 0);
    assert_eq!(unsafe { sigsetjmp(ptr, 1) }, 0);
}

// ---------------------------------------------------------------------------
// Sequential captures across all three variants on same buffer
// ---------------------------------------------------------------------------

#[test]
fn sequential_captures_all_variants_same_buffer() {
    let mut env = [0u64; 32];
    let ptr = env.as_mut_ptr().cast::<c_void>();
    // Cycle through variants on the same buffer.
    for _ in 0..3 {
        assert_eq!(unsafe { setjmp(ptr) }, 0);
        assert_eq!(unsafe { _setjmp(ptr) }, 0);
        assert_eq!(unsafe { sigsetjmp(ptr, 0) }, 0);
        assert_eq!(unsafe { sigsetjmp(ptr, 1) }, 0);
    }
}
