#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc allocator oracle

//! Differential gate for allocator edge-case semantics (bd-s7if9o) — these had
//! no differential gate. Pointer VALUES differ between fl and glibc, so each
//! property is checked as a CONTRACT that must hold identically for both:
//!   - malloc(0) returns a unique non-NULL freeable pointer
//!   - realloc(NULL, n) == malloc(n)  (non-NULL)
//!   - realloc(p, 0) frees and returns NULL
//!   - realloc preserves existing bytes when growing
//!   - free(NULL) is a no-op (no crash)
//!   - calloc zero-fills, and calloc with a zero dimension returns non-NULL
//!   - calloc detects multiplication overflow (returns NULL)
//! Each impl is exercised with its own paired malloc/free so pointers never
//! cross allocators. No mocks.

use std::ffi::c_void;

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;
use frankenlibc_abi::malloc_abi as fl;

/// Run the full edge-contract suite against one allocator; returns a tuple of
/// booleans capturing each observable contract outcome.
unsafe fn probe(
    malloc: unsafe extern "C" fn(usize) -> *mut c_void,
    free: unsafe extern "C" fn(*mut c_void),
    realloc: unsafe extern "C" fn(*mut c_void, usize) -> *mut c_void,
    calloc: unsafe extern "C" fn(usize, usize) -> *mut c_void,
) -> (bool, bool, bool, bool, bool, bool, bool) {
    // malloc(0) -> non-NULL, freeable
    let z = unsafe { malloc(0) };
    let malloc0_nonnull = !z.is_null();
    unsafe { free(z) };

    // realloc(NULL, 32) == malloc(32)
    let r = unsafe { realloc(std::ptr::null_mut(), 32) };
    let realloc_null_nonnull = !r.is_null();

    // grow + preserve bytes
    let preserved = if !r.is_null() {
        unsafe {
            for i in 0..32usize {
                *(r as *mut u8).add(i) = (i as u8) ^ 0x5a;
            }
            let r2 = realloc(r, 4096);
            let ok = !r2.is_null()
                && (0..32usize).all(|i| *(r2 as *const u8).add(i) == (i as u8) ^ 0x5a);
            // realloc(p, 0) -> NULL
            let z2 = realloc(r2, 0);
            (ok, z2.is_null())
        }
    } else {
        (false, false)
    };

    // free(NULL) no-op
    unsafe { free(std::ptr::null_mut()) };

    // calloc zero-fills
    let c = unsafe { calloc(8, 8) };
    let calloc_zeroed =
        !c.is_null() && unsafe { (0..64usize).all(|i| *(c as *const u8).add(i) == 0) };
    unsafe { free(c) };

    // calloc with a zero dimension -> non-NULL
    let cz = unsafe { calloc(0, 16) };
    let calloc_zero_dim = !cz.is_null();
    unsafe { free(cz) };

    // calloc overflow (nmemb * size overflows usize) -> NULL
    let calloc = std::hint::black_box(calloc);
    let co = unsafe { calloc(std::hint::black_box(usize::MAX), std::hint::black_box(2)) };
    let calloc_overflow_null = co.is_null();
    if !co.is_null() {
        unsafe { free(co) };
    }

    (
        malloc0_nonnull,
        realloc_null_nonnull,
        preserved.0,
        preserved.1,
        calloc_zeroed,
        calloc_zero_dim,
        calloc_overflow_null,
    )
}

#[test]
fn malloc_edge_contracts_match_glibc() {
    // Resolve the oracle from explicit host-library handles and reject any
    // address that aliases the candidate. Link-time extern declarations alone
    // do not establish which allocator this binary actually calls.
    // SAFETY: probe's parameter types specify each symbol's C signature.
    let gp = unsafe {
        probe(
            dlsym_oracle::host_fn(c"malloc", fl::malloc as *const ()),
            dlsym_oracle::host_fn(c"free", fl::free as *const ()),
            dlsym_oracle::host_fn(c"realloc", fl::realloc as *const ()),
            dlsym_oracle::host_fn(c"calloc", fl::calloc as *const ()),
        )
    };
    let fp = unsafe { probe(fl::malloc, fl::free, fl::realloc, fl::calloc) };
    assert_eq!(
        fp, gp,
        "allocator edge contracts (malloc0_nonnull, realloc_null, grow_preserves, realloc0_null, calloc_zeroed, calloc_zero_dim, calloc_overflow_null): fl={fp:?} glibc={gp:?}"
    );
    // glibc reference values, pinned so a future glibc change is visible.
    assert_eq!(
        gp,
        (true, true, true, true, true, true, true),
        "glibc reference contracts"
    );

    // Environment selection alone does not leave allocator bootstrap. Exercise
    // the initialized path explicitly; this is not deployed-startup evidence.
    fl::signal_runtime_ready_for_tests();
    let _ = fl::take_last_decision_gate_for_tests();
    // SAFETY: request a small allocation and release it through its own provider.
    let witness = unsafe { fl::malloc(64) };
    assert!(!witness.is_null(), "initialized allocator must allocate");
    let decision = fl::take_last_decision_gate_for_tests();
    let segment_owned = fl::malloc_segment_owned_for_tests(witness);
    // SAFETY: witness is live and was returned by fl::malloc above. Starting
    // with malloc (not realloc(NULL, n)) also exercises native-owned teardown.
    assert!(unsafe { fl::realloc(witness, 0) }.is_null());
    if std::env::var("FRANKENLIBC_MODE").as_deref() == Ok("hardened") {
        assert!(
            decision.is_some(),
            "hardened allocator must record a decision"
        );
    } else if !cfg!(feature = "standalone") {
        assert!(
            segment_owned,
            "strict small allocation must use a native segment"
        );
    }
    // SAFETY: probe pairs each allocation with the same allocator's operations.
    let initialized = unsafe { probe(fl::malloc, fl::free, fl::realloc, fl::calloc) };
    assert_eq!(initialized, gp, "initialized allocator edge contracts");
}

#[test]
fn malloc_oracle_rejects_identical_candidate_provider() {
    // SAFETY: only resolve/compare code addresses; no mismatched call is made.
    let host = unsafe { dlsym_oracle::host_addr(c"malloc", fl::malloc as *const ()) };
    let rejected = std::panic::catch_unwind(|| unsafe {
        dlsym_oracle::host_addr(c"malloc", host.cast());
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
