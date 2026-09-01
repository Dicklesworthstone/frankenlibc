#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // drives the raw handoff-context address, as production does

//! Gate for the host-thread handoff rendezvous (bd-xh08pf).
//!
//! ## The dead test this replaces could not compile, and covered the wrong half
//!
//! `pthread_abi.rs` is `#[cfg(not(test))] pub mod` in lib.rs, so its inline
//! `#[cfg(test)]` block is dead. The last of its six stranded tests,
//! `host_thread_handoff_waiter_observes_parent_publication`, fails to build for
//! a reason distinct from the cancel pair burned down alongside it (those
//! compiled and would have killed the libtest worker): it moved an
//! `Arc<HostThreadStartContext>` into `std::thread::spawn`, but that struct
//! holds the caller's `*mut c_void` and carries no `unsafe impl Send`/`Sync`.
//! `Arc<T>: Send` requires `T: Send + Sync`, so it is E0277, "`*mut c_void`
//! cannot be shared between threads safely".
//!
//! That is NOT fixed by adding the impls. The type is correctly non-`Send`:
//! production never shares it as an `Arc`. The parent owns the context and
//! hands the child trampoline a raw address, which is why the test hooks below
//! are address-based — a `usize` crosses a thread boundary on its own, so this
//! file needs no fabricated auto-trait impl to do what production does.
//!
//! ## What is actually uncovered
//!
//! The rendezvous has two halves. `wait_for_host_thread_handoff` spins
//! `HOST_THREAD_HANDOFF_SPIN_LIMIT` times looking for the published handle, and
//! only then blocks on a futex. **No existing test targets the blocking half or
//! asserts it was taken.** `thread_create_join` and the other host-backed arms
//! in `pthread_abi_test.rs` create real threads and so do drive this code, but
//! they neither control nor observe which path runs, and in practice the parent
//! publishes before the child's first load — so they exercise the spin half.
//! (That is an inference from the timing, not a measurement: before this file
//! there was no counter with which to measure it. What is certain is that
//! nothing *asserted* either path.) The dead test was no better — it spawned
//! the waiter and published immediately, so it too returned on spin iteration
//! 0, never spinning, let alone blocking.
//!
//! So the futex fallback — its retry loop, its `EAGAIN`/`EINTR` handling and
//! its volatile errno read — had no coverage at all. That is what this file
//! gates, and `HOST_THREAD_HANDOFF_FUTEX_WAITS` (exposed as
//! `pthread_host_thread_handoff_futex_waits_for_tests`) exists so the gate can
//! prove which path ran instead of assuming it.
//!
//! ## Why the exact-handle assertion is the load-bearing one
//!
//! When the waiter cannot resolve a handle it falls back to the host
//! `pthread_self()`. That is correct in production — the waiter IS the child,
//! learning its own handle — but it means a broken rendezvous returns a
//! plausible non-zero handle rather than 0. Comparing against a sentinel the
//! parent chose is what distinguishes "observed the publication" from "gave up
//! and reported itself".
//!
//! ## Counter scope
//!
//! The counter is process-global, but a file in `tests/` is its own binary, so
//! only this file's tests share it. `handle_fidelity_*` never blocks (it
//! publishes before it waits, so the waiter's first load already succeeds and
//! it cannot reach the futex), which is what keeps the `delta == 0` assertion
//! in the spin-path half free of a spurious-failure mode.

use std::time::{Duration, Instant};

use frankenlibc_abi::pthread_abi::{
    pthread_host_thread_handoff_futex_waits_for_tests,
    pthread_host_thread_handoff_probe_free_for_tests,
    pthread_host_thread_handoff_probe_new_for_tests,
    pthread_host_thread_handoff_probe_publish_for_tests,
    pthread_host_thread_handoff_probe_wait_for_tests,
};

/// A handle no real `pthread_t` will collide with, and which is not the
/// `pthread_self()` of any thread here — so receiving it proves the waiter read
/// the parent's publication rather than falling back to reporting itself.
const SENTINEL: libc::pthread_t = 0x5A5A_5A5A_0000_1234;

#[test]
fn handoff_spins_when_published_early_and_blocks_on_the_futex_when_published_late() {
    // Both halves live in ONE test on purpose: the spin half asserts the
    // slow-path counter did not move, so it must not run concurrently with the
    // half that deliberately moves it.

    // --- Half 1: publication precedes the wait. Resolves on the first load.
    let probe = pthread_host_thread_handoff_probe_new_for_tests();
    let before_spin = pthread_host_thread_handoff_futex_waits_for_tests();
    // SAFETY: `probe` is live and unfreed for both calls.
    let observed = unsafe {
        pthread_host_thread_handoff_probe_publish_for_tests(probe, SENTINEL);
        pthread_host_thread_handoff_probe_wait_for_tests(probe)
    };
    let after_spin = pthread_host_thread_handoff_futex_waits_for_tests();
    // SAFETY: no waiter is blocked on `probe` — the wait above returned.
    unsafe { pthread_host_thread_handoff_probe_free_for_tests(probe) };

    assert_eq!(
        observed, SENTINEL,
        "an already-published handoff must deliver the parent's handle"
    );
    assert_eq!(
        after_spin, before_spin,
        "a waiter that finds the handle already published must NOT reach the \
         futex: slow-path counter moved {before_spin} -> {after_spin}"
    );

    // --- Half 2: publication follows the wait. The waiter must exhaust the
    // spin limit, block, and be woken with the right handle.
    let probe = pthread_host_thread_handoff_probe_new_for_tests();
    let before_block = pthread_host_thread_handoff_futex_waits_for_tests();

    let waiter = std::thread::spawn(move || {
        // SAFETY: the parent keeps `probe` alive until after this join.
        unsafe { pthread_host_thread_handoff_probe_wait_for_tests(probe) }
    });

    // Poll — not sleep — until the waiter has actually entered the futex path,
    // so this cannot flake under parallel load the way a fixed delay does
    // (bd-d3tvn3). On timeout we still publish before failing, otherwise the
    // join below would hang forever instead of reporting.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut reached_futex = true;
    while pthread_host_thread_handoff_futex_waits_for_tests() == before_block {
        if Instant::now() >= deadline {
            reached_futex = false;
            break;
        }
        std::thread::yield_now();
    }

    // SAFETY: `probe` is live; the waiter holds only its address.
    unsafe { pthread_host_thread_handoff_probe_publish_for_tests(probe, SENTINEL) };
    let observed = waiter.join().expect("waiter thread panicked");
    // SAFETY: the waiter has been joined, so nothing is blocked on `probe`.
    unsafe { pthread_host_thread_handoff_probe_free_for_tests(probe) };

    assert!(
        reached_futex,
        "waiter never entered the futex path within 5s (slow-path counter stuck \
         at {before_block}) — the blocking half of the rendezvous was not exercised"
    );
    assert_eq!(
        observed, SENTINEL,
        "a waiter woken from the futex must adopt the handle the parent \
         published, not its own pthread_self() fallback"
    );
}

#[test]
fn the_waiter_adopts_exactly_the_handle_the_parent_published() {
    // Publishes before waiting, so every iteration resolves on the spin path
    // and this test never touches the slow-path counter the other one asserts
    // on. Values chosen to catch a truncating or sign-extending handoff: the
    // handle travels through `AtomicUsize` as a `usize` and back.
    let cases: [libc::pthread_t; 6] = [
        1,
        0x1234,
        u32::MAX as libc::pthread_t,
        u32::MAX as libc::pthread_t + 1,
        libc::pthread_t::MAX - 1,
        libc::pthread_t::MAX,
    ];
    for expected in cases {
        let probe = pthread_host_thread_handoff_probe_new_for_tests();
        // SAFETY: `probe` is live and unfreed across all three calls, and no
        // other thread observes it.
        let observed = unsafe {
            pthread_host_thread_handoff_probe_publish_for_tests(probe, expected);
            let observed = pthread_host_thread_handoff_probe_wait_for_tests(probe);
            pthread_host_thread_handoff_probe_free_for_tests(probe);
            observed
        };
        assert_eq!(
            observed, expected,
            "handoff of {expected:#x} came back as {observed:#x}"
        );
    }
}
