#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#![allow(unsafe_code)]

//! A native clone must stop both itself and its creator from using shared
//! compiler TLS for membrane caches and epoch registrations.

use frankenlibc_core::pthread::thread::{create_thread, join_thread};
use frankenlibc_core::syscall;
use frankenlibc_membrane::arena::FreeResult;
use frankenlibc_membrane::lattice::SafetyState;
use frankenlibc_membrane::ptr_validator::ValidationPipeline;
use frankenlibc_membrane::tls_cache::{CachedValidation, snapshot_shard_epochs, with_tls_cache};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const CHILD: &str = "FRANKENLIBC_NATIVE_MEMBRANE_TLS_CHILD";
const TEST_NAME: &str = "native_clone_keeps_membrane_state_thread_owned";
const SIZE: usize = 64;
// A synthetic cache key only: no code dereferences this address.
const MARKER: usize = usize::MAX - 4096;
const EXPECTED_NATIVE_CHECKS: usize = (1 << 9) - 1;

fn marker_entry() -> CachedValidation {
    CachedValidation {
        user_base: MARKER,
        user_size: SIZE,
        generation: 1,
        state: SafetyState::Valid,
    }
}

struct NativeProbe<'a> {
    pipeline: &'a ValidationPipeline,
    allocation: usize,
    creator_allocation: usize,
    creator_tid: i32,
    creator_cache: AtomicUsize,
}

// No assertion, channel, formatting, or panic runs in this raw native callback.
// Its references point to hosted-parent storage retained through join.
unsafe extern "C" fn native_probe(arg: usize) -> usize {
    // SAFETY: the creating parent keeps this context and both pipelines alive.
    let probe = unsafe { &*(arg as *const NativeProbe<'_>) };
    let mut checks = 0;
    if syscall::sys_gettid() != probe.creator_tid {
        checks |= 1;
    }

    checks |= with_tls_cache(|cache| {
        let cache_address = std::ptr::from_mut(cache) as usize;
        let mut cache_checks = 0;
        if cache_address != probe.creator_cache.load(Ordering::Acquire) {
            cache_checks |= 1 << 1;
        }
        if cache.lookup(probe.creator_allocation).is_none() {
            cache_checks |= 1 << 2;
        }
        cache.insert(MARKER, marker_entry(), &snapshot_shard_epochs());
        if cache.lookup(MARKER).is_some() {
            cache_checks |= 1 << 3;
        }
        let nested_is_fresh = with_tls_cache(|nested| {
            std::ptr::from_mut(nested) as usize != cache_address
                && nested.lookup(MARKER).is_none()
        });
        if nested_is_fresh {
            cache_checks |= 1 << 4;
        }
        cache_checks
    });
    if with_tls_cache(|cache| cache.lookup(MARKER).is_none()) {
        checks |= 1 << 5;
    }

    let outcome = probe.pipeline.validate(probe.allocation);
    if outcome.can_read()
        && outcome.can_write()
        && outcome
            .abstraction()
            .is_some_and(|value| value.remaining == Some(SIZE))
    {
        checks |= 1 << 6;
    }
    if probe
        .pipeline
        .try_validate_cached_remaining(probe.allocation)
        .is_none()
    {
        checks |= 1 << 7;
    }
    let diagnostics = probe.pipeline.collector.diagnostics();
    if diagnostics.active_threads == 0 && diagnostics.pinned_threads == 0 {
        checks |= 1 << 8;
    }
    checks
}

fn run_child() {
    // Resolve mode/runtime state in the hosted parent before native entry.
    let pipeline_a = ValidationPipeline::with_runtime_math(false);
    let pipeline_b = ValidationPipeline::with_runtime_math(false);
    let allocation_a = pipeline_a.allocate(SIZE).expect("creator allocation");
    let allocation_b = pipeline_b.allocate(SIZE).expect("native allocation");

    // Prime B's reusable collector slot without touching the compiler-TLS
    // EBR_HANDLE. The native registration can then reuse hosted storage.
    let warm = pipeline_b.collector.register();
    drop(warm.pin());
    drop(warm);
    assert_eq!(pipeline_b.collector.diagnostics().active_threads, 0);

    let primed = pipeline_a.validate(allocation_a as usize);
    assert!(primed.can_read() && primed.can_write());
    assert_eq!(
        primed.abstraction().and_then(|value| value.remaining),
        Some(SIZE)
    );
    let cached_before = pipeline_a.try_validate_cached_remaining(allocation_a as usize);
    let creator_before = pipeline_a.collector.diagnostics();
    // Core's feature does not forward membrane's feature. Observe the actual
    // pre-clone lane instead of inferring it from the core Cargo feature.
    assert!(creator_before.active_threads <= 1);
    if creator_before.active_threads == 1 {
        assert_eq!(cached_before, Some(Some(SIZE)));
    } else {
        assert_eq!(cached_before, None);
    }
    assert_eq!(creator_before.pinned_threads, 0);

    let probe = NativeProbe {
        pipeline: &pipeline_b,
        allocation: allocation_b as usize,
        creator_allocation: allocation_a as usize,
        creator_tid: syscall::sys_gettid(),
        creator_cache: AtomicUsize::new(0),
    };
    let (joined, borrowed_before, borrowed_after) = with_tls_cache(|cache| {
        probe
            .creator_cache
            .store(std::ptr::from_mut(cache) as usize, Ordering::Release);
        let before = cache.lookup(allocation_a as usize).is_some();
        // SAFETY: callback/context remain live until the sole owner joins.
        // This is the real core lifecycle; the test never calls the TLS latch.
        let created = unsafe {
            create_thread(
                native_probe as *const () as usize,
                std::ptr::from_ref(&probe) as usize,
                0,
            )
        };
        let joined = match created {
            Ok(handle) => {
                // SAFETY: this is the only join of this joinable live handle.
                let result = unsafe { join_thread(handle) };
                if result.is_err() {
                    // Do not unwind/free parent storage if a broken join could
                    // leave a native callback using it. The outer test reports
                    // this isolated child's abnormal exit.
                    std::process::abort();
                }
                result
            }
            Err(error) => Err(error),
        };
        let after = cache.lookup(allocation_a as usize).is_some();
        (joined, before, after)
    });

    // Capture both collectors before the creator validates through any other
    // pipeline. A leaked child EBR_HANDLE must not be repaired by this oracle.
    let creator_after = pipeline_a.collector.diagnostics();
    let native_after = pipeline_b.collector.diagnostics();
    let cached_after = pipeline_a.try_validate_cached_remaining(allocation_a as usize);
    let (creator_cache_is_fresh, local_insert_works) = with_tls_cache(|cache| {
        let fresh = cache.lookup(allocation_a as usize).is_none();
        cache.insert(MARKER, marker_entry(), &snapshot_shard_epochs());
        (fresh, cache.lookup(MARKER).is_some())
    });
    let next_cache_is_fresh = with_tls_cache(|cache| cache.lookup(MARKER).is_none());

    // The creator must also use short-lived registrations after the transition.
    let parent_validation = pipeline_b.validate(allocation_b as usize);
    let parent_validated_owned = parent_validation.can_read()
        && parent_validation
            .abstraction()
            .is_some_and(|value| value.remaining == Some(SIZE));
    let native_after_parent = pipeline_b.collector.diagnostics();
    let creator_after_parent = pipeline_a.collector.diagnostics();

    let freed_a = pipeline_a.free(allocation_a);
    let freed_b = pipeline_b.free(allocation_b);

    assert_eq!(joined, Ok(EXPECTED_NATIVE_CHECKS), "native cache/EBR checks");
    assert_eq!(borrowed_before, cached_before.is_some());
    assert_eq!(borrowed_after, borrowed_before, "in-flight cache changed");
    assert_eq!(
        creator_after.active_threads, creator_before.active_threads,
        "native validation replaced the creator's cached EBR registration"
    );
    assert_eq!(creator_after.pinned_threads, 0);
    assert_eq!(native_after.active_threads, 0, "native EBR registration leaked");
    assert_eq!(native_after.pinned_threads, 0);
    assert_eq!(cached_after, None, "post-clone hit query used compiler TLS");
    assert!(creator_cache_is_fresh, "creator reused its dormant TLS cache");
    assert!(local_insert_works, "temporary cache lost its local insertion");
    assert!(next_cache_is_fresh, "temporary cache escaped its closure");
    assert!(parent_validated_owned);
    assert_eq!(native_after_parent.active_threads, 0);
    assert_eq!(native_after_parent.pinned_threads, 0);
    assert_eq!(
        creator_after_parent.active_threads,
        creator_before.active_threads,
        "post-clone creator validation replaced its dormant registration"
    );
    assert_eq!(freed_a, FreeResult::Freed);
    assert_eq!(freed_b, FreeResult::Freed);
}

#[test]
fn native_clone_keeps_membrane_state_thread_owned() {
    if std::env::var_os(CHILD).is_some() {
        run_child();
        return;
    }

    // The transition is intentionally process-wide and irreversible. Keep it
    // out of every other integration/unit test process.
    let executable = std::env::current_exe().expect("test executable");
    let mut child = Command::new(executable)
        .args(["--exact", TEST_NAME, "--nocapture", "--test-threads=1"])
        .env(CHILD, "1")
        .env("FRANKENLIBC_MODE", "hardened")
        .env("FRANKENLIBC_RUNTIME_MATH", "off")
        .env_remove("FRANKENLIBC_LOG")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start native membrane child");
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut timed_out = false;
    while child
        .try_wait()
        .expect("poll native membrane child")
        .is_none()
    {
        if Instant::now() >= deadline {
            timed_out = true;
            let _ = child.kill();
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child
        .wait_with_output()
        .expect("collect native membrane child");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !timed_out && output.status.success() && stdout.contains("1 passed;"),
        "native membrane child timeout={timed_out} status={}\n{stdout}\n{stderr}",
        output.status
    );
}
