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
#[cfg(all(
    feature = "conformance-testing",
    debug_assertions,
    not(feature = "standalone")
))]
fn first_native_create_preserves_live_hosted_policy_scopes() {
    use std::ffi::c_void;
    use std::sync::atomic::{AtomicBool, Ordering};

    use frankenlibc_abi::{conformance_testing as policy, pthread_abi};

    const CHILD: &str = "FRANKENLIBC_MIXED_POLICY_CHILD";
    const NAME: &str = "first_native_create_preserves_live_hosted_policy_scopes";
    if std::env::var_os(CHILD).is_none() {
        for mode in ["strict", "hardened"] {
            let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", NAME, "--nocapture", "--test-threads=1"])
                .env(CHILD, "1")
                .env("FRANKENLIBC_MODE", mode)
                .env("FRANKENLIBC_RUNTIME_MATH", "off")
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .expect("start mixed hosted/native policy child");
            let deadline = Instant::now() + Duration::from_secs(30);
            let mut timed_out = false;
            while child.try_wait().unwrap().is_none() {
                if Instant::now() >= deadline {
                    timed_out = true;
                    let _ = child.kill();
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            let output = child.wait_with_output().unwrap();
            assert!(
                !timed_out
                    && output.status.success()
                    && String::from_utf8_lossy(&output.stdout).contains("1 passed;"),
                "mixed policy {mode} timeout={timed_out} status={}\n{}\n{}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
        }
        return;
    }

    unsafe extern "C" fn native_worker(_: *mut c_void) -> *mut c_void {
        // Keep the actual clone worker allocation-free: no assertions,
        // formatting, host thread APIs or borrowed creator TLS.
        let mut failures = 0usize;
        if frankenlibc_core::pthread::thread::current_thread_handle().is_none() {
            failures |= 1;
        }
        let fresh = policy::policy_state_snapshot();
        if fresh.reentry_depth != Some(0) || fresh.trace.is_some() || fresh.record.is_some() {
            failures |= 2;
        }
        let observed = policy::with_policy_scope("mixed-native-policy", 33, || ());
        if !observed.is_some_and(|(_, state)| {
            state.before.reentry_depth == Some(1)
                && state.before == state.after
                && state.borrowed_record_unchanged
                && state.after_drop.reentry_depth == Some(0)
                && state.after_drop.trace.is_none()
        }) {
            failures |= 4;
        }
        failures as *mut c_void
    }

    struct RestoreBackend(bool);
    impl Drop for RestoreBackend {
        fn drop(&mut self) {
            pthread_abi::pthread_threading_restore_for_tests(self.0);
        }
    }

    assert!(
        !frankenlibc_core::pthread::tls::native_threads_may_exist(),
        "the child must exercise the first native admission"
    );
    let _ = policy::current_mode_debug();
    let baseline_guards = policy::active_policy_guard_count();
    let hosted_ready = AtomicBool::new(false);
    let release_hosted = AtomicBool::new(false);
    let (creator, hosted, create_result, join_result, worker_result) =
        std::thread::scope(|threads| {
            let hosted = threads.spawn(|| {
                policy::with_policy_scope("mixed-hosted-policy", 11, || {
                    hosted_ready.store(true, Ordering::Release);
                    while !release_hosted.load(Ordering::Acquire) {
                        std::hint::spin_loop();
                    }
                })
            });
            let deadline = Instant::now() + Duration::from_secs(5);
            while !hosted_ready.load(Ordering::Acquire) && Instant::now() < deadline {
                std::thread::yield_now();
            }
            if !hosted_ready.load(Ordering::Acquire) {
                release_hosted.store(true, Ordering::Release);
                let _ = hosted.join();
                panic!("hosted thread did not enter its live policy scope");
            }

            let _restore =
                RestoreBackend(pthread_abi::pthread_threading_swap_force_native_for_tests());
            let mut create_result = -1;
            let mut join_result = -1;
            let mut worker_result = usize::MAX;
            let creator = policy::with_policy_scope("mixed-creator-policy", 22, || {
                let mut native = 0;
                // SAFETY: native is writable, the callback has the pthread C
                // ABI, and no argument storage is needed by the worker.
                create_result = unsafe {
                    pthread_abi::pthread_create(
                        &mut native,
                        std::ptr::null(),
                        Some(native_worker),
                        std::ptr::null_mut(),
                    )
                };
                if create_result == 0 {
                    let mut result = std::ptr::null_mut();
                    // SAFETY: this is the live joinable native handle and
                    // result remains writable until the join completes.
                    join_result = unsafe { pthread_abi::pthread_join(native, &mut result) };
                    worker_result = result as usize;
                }
            });
            release_hosted.store(true, Ordering::Release);
            let hosted = hosted.join().expect("hosted policy thread panicked");
            (creator, hosted, create_result, join_result, worker_result)
        });

    assert_eq!(create_result, 0, "actual public native pthread_create");
    assert_eq!(join_result, 0, "actual public native pthread_join");
    assert_eq!(worker_result, 0, "native policy isolation bitmask");
    let (_, creator) = creator.expect("creator's live policy scope");
    let (_, hosted) = hosted.expect("other hosted thread's live policy scope");
    for (name, state, marker) in [("creator", creator, 22), ("hosted", hosted, 11)] {
        assert_eq!(state.before.reentry_depth, Some(1), "{name} entered");
        assert_eq!(state.after.reentry_depth, Some(1), "{name} retained guard");
        assert_eq!(
            state.after.trace, state.before.trace,
            "{name} retained trace"
        );
        assert_eq!(
            state.after.record, state.before.record,
            "{name} retained record"
        );
        assert_eq!(
            state.after.mode_cache, state.before.mode_cache,
            "{name} retained mode"
        );
        assert_eq!(state.before.record.map(|record| record.3), Some(marker));
        assert!(
            state.borrowed_record_unchanged,
            "{name} lost live record borrow"
        );
        assert_eq!(
            state.after_drop.reentry_depth,
            Some(0),
            "{name} balanced guard"
        );
        assert!(
            state.after_drop.trace.is_none(),
            "{name} restored outer trace"
        );
        assert!(state.after.trace_counter >= state.before.trace_counter);
        assert!(state.after.decision_counter >= state.before.decision_counter);
    }
    // This thread made no policy calls while waiting; none of its counters or
    // records may reset just because a different hosted thread created a clone.
    assert_eq!(hosted.after, hosted.before, "inactive hosted state changed");
    assert_eq!(
        policy::active_policy_guard_count(),
        baseline_guards,
        "transition leaked an active guard into process-wide policy accounting"
    );
}

#[test]
#[cfg(all(debug_assertions, not(feature = "standalone")))]
fn host_tls_late_callback_repopulates_owned_cache() {
    const CHILD: &str = "FRANKENLIBC_HOST_TLS_REARM_CHILD";
    const NAME: &str = "host_tls_late_callback_repopulates_owned_cache";
    if std::env::var_os(CHILD).is_none() {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", NAME, "--nocapture", "--test-threads=1"])
            .env(CHILD, "1")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("start host TLS rearm child");
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut timed_out = false;
        while child.try_wait().unwrap().is_none() {
            if Instant::now() >= deadline {
                timed_out = true;
                let _ = child.kill();
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let output = child.wait_with_output().unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !timed_out && output.status.success() && stdout.contains("1 passed;"),
            "host TLS child timeout={timed_out} status={}\n{stdout}\n{stderr}",
            output.status
        );
        return;
    }

    let observed =
        frankenlibc_abi::pthread_abi::pthread_host_cache_late_callback_counts_for_tests();
    #[cfg(not(feature = "owned-tls-cache"))]
    // The late callback recreates state after the first DSO-pinned cxa drain;
    // automatic bridge registration must arrange a second drain for it.
    assert_eq!(observed, (5, 2));
    #[cfg(feature = "owned-tls-cache")]
    // The POSIX-key bridge preserves the original cache through all host C++
    // TLS callbacks, then destroys its payload once.
    assert_eq!(observed, (55, 1));
}

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
