//! End-to-end tests for the Transparent Safety Membrane (TSM) validation pipeline.
//!
//! Exercises the full validation pipeline with:
//! - Realistic mixed alloc/free/validate workloads
//! - Concurrent access patterns
//! - Adversarial inputs (double-free, UAF, foreign pointers, null)
//! - Latency budget verification
//! - Monotone lattice transition enforcement
//!
//! Bead: bd-32e.6

use frankenlibc_membrane::{SafetyState, ValidationOutcome, ValidationPipeline};
use std::sync::Arc;
use std::thread;
use std::time::Instant;

// ---------------------------------------------------------------------------
// Deterministic PRNG (same as allocator test)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 1 } else { seed },
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn gen_range(&mut self, low: usize, high_inclusive: usize) -> usize {
        let span = high_inclusive - low + 1;
        low + (self.next_u64() as usize % span)
    }
}

// ===========================================================================
// 1. Null pointer validation
// ===========================================================================

#[test]
fn null_pointer_validates_as_null() {
    let pipeline = ValidationPipeline::new();
    let outcome = pipeline.validate(0);
    assert!(
        matches!(outcome, ValidationOutcome::Null),
        "address 0 should be Null, got {outcome:?}"
    );
    assert!(!outcome.can_read(), "null should not be readable");
    assert!(!outcome.can_write(), "null should not be writable");
}

#[test]
fn low_addresses_validate_as_null_or_invalid() {
    let pipeline = ValidationPipeline::new();
    for addr in [1, 2, 4, 8, 16, 64, 4095] {
        let outcome = pipeline.validate(addr);
        // Low addresses should be Null or Invalid (never Valid)
        assert!(
            !matches!(
                outcome,
                ValidationOutcome::Validated(_) | ValidationOutcome::CachedValid(_)
            ),
            "low addr {addr} should not validate as live pointer"
        );
    }
}

// ===========================================================================
// 2. Foreign pointer handling
// ===========================================================================

#[test]
fn foreign_pointer_is_allowed_with_unknown_state() {
    let pipeline = ValidationPipeline::new();
    let addr = 0xDEAD_BEEF_usize;
    let outcome = pipeline.validate(addr);
    assert!(
        matches!(outcome, ValidationOutcome::Foreign(_)),
        "unknown addr should be Foreign, got {outcome:?}"
    );
    assert!(outcome.can_read(), "foreign should be readable");
    assert!(outcome.can_write(), "foreign should be writable");
    let abs = outcome
        .abstraction()
        .expect("foreign should have abstraction");
    assert_eq!(abs.state, SafetyState::Unknown);
    assert!(abs.remaining.is_none(), "foreign should have no bounds");
}

#[test]
fn multiple_foreign_addresses_all_recognized() {
    let pipeline = ValidationPipeline::new();
    let addrs = [0x1000_0000, 0x7FFF_FFFF, 0xCAFE_BABE, 0x1234_5678];
    for addr in addrs {
        let outcome = pipeline.validate(addr);
        assert!(
            matches!(outcome, ValidationOutcome::Foreign(_)),
            "addr {addr:#x} should be Foreign, got {outcome:?}"
        );
    }
}

// ===========================================================================
// 3. Allocation → validation → free lifecycle
// ===========================================================================

#[test]
fn alloc_validate_free_lifecycle() {
    let pipeline = ValidationPipeline::new();

    // Allocate
    let ptr = pipeline.allocate(128).expect("allocate 128 bytes");
    let addr = ptr as usize;

    // Validate live pointer
    let outcome = pipeline.validate(addr);
    assert!(
        matches!(
            outcome,
            ValidationOutcome::Validated(_) | ValidationOutcome::CachedValid(_)
        ),
        "live pointer should be Validated/CachedValid, got {outcome:?}"
    );
    assert!(outcome.can_read());
    assert!(outcome.can_write());
    let abs = outcome.abstraction().expect("live abstraction");
    assert_eq!(abs.state, SafetyState::Valid);
    assert_eq!(abs.remaining, Some(128));

    // Free
    let result = pipeline.free(ptr);
    assert!(
        matches!(result, frankenlibc_membrane::arena::FreeResult::Freed),
        "first free should succeed"
    );

    // Validate after free — should be TemporalViolation
    let outcome = pipeline.validate(addr);
    assert!(
        matches!(outcome, ValidationOutcome::TemporalViolation(_)),
        "freed pointer should be TemporalViolation, got {outcome:?}"
    );
    assert!(!outcome.can_read());
    assert!(!outcome.can_write());
}

// ===========================================================================
// 4. Double-free detection
// ===========================================================================

#[test]
fn double_free_detected() {
    let pipeline = ValidationPipeline::new();
    let ptr = pipeline.allocate(64).expect("allocate");
    let result = pipeline.free(ptr);
    assert!(matches!(
        result,
        frankenlibc_membrane::arena::FreeResult::Freed
    ));

    // Second free should be detected
    let result2 = pipeline.free(ptr);
    assert!(
        matches!(result2, frankenlibc_membrane::arena::FreeResult::DoubleFree),
        "double free should be detected, got {result2:?}"
    );
}

// ===========================================================================
// 5. Foreign pointer free
// ===========================================================================

#[test]
fn foreign_pointer_free_detected() {
    let pipeline = ValidationPipeline::new();
    let fake_ptr = 0xDEAD_BEEF as *mut u8;
    let result = pipeline.free(fake_ptr);
    assert!(
        matches!(
            result,
            frankenlibc_membrane::arena::FreeResult::ForeignPointer
        ),
        "foreign pointer free should be detected, got {result:?}"
    );
}

// ===========================================================================
// 6. Multiple allocations with independent validation
// ===========================================================================

#[test]
fn multiple_allocations_independent() {
    let pipeline = ValidationPipeline::new();
    let sizes = [16, 64, 256, 1024, 4096];
    let mut ptrs: Vec<(*mut u8, usize)> = Vec::new();

    // Allocate all
    for &size in &sizes {
        let ptr = pipeline.allocate(size).expect("allocate");
        ptrs.push((ptr, size));
    }

    // Validate all — each should be valid with correct bounds
    for &(ptr, size) in &ptrs {
        let outcome = pipeline.validate(ptr as usize);
        assert!(
            matches!(
                outcome,
                ValidationOutcome::Validated(_) | ValidationOutcome::CachedValid(_)
            ),
            "ptr for size {size} should be valid"
        );
        let abs = outcome.abstraction().expect("abstraction");
        assert_eq!(abs.remaining, Some(size), "bounds mismatch for size {size}");
    }

    // Free first and last, validate middle still live
    pipeline.free(ptrs[0].0);
    pipeline.free(ptrs[4].0);

    // First and last should be temporal violations
    assert!(matches!(
        pipeline.validate(ptrs[0].0 as usize),
        ValidationOutcome::TemporalViolation(_)
    ));
    assert!(matches!(
        pipeline.validate(ptrs[4].0 as usize),
        ValidationOutcome::TemporalViolation(_)
    ));

    // Middle three should still be valid
    for &(ptr, _size) in &ptrs[1..4] {
        let outcome = pipeline.validate(ptr as usize);
        assert!(
            matches!(
                outcome,
                ValidationOutcome::Validated(_) | ValidationOutcome::CachedValid(_)
            ),
            "middle pointer should still be valid"
        );
    }

    // Cleanup
    for &(ptr, _) in &ptrs[1..4] {
        pipeline.free(ptr);
    }
}

// ===========================================================================
// 7. Safety state lattice monotonicity
// ===========================================================================

#[test]
fn safety_state_lattice_monotonicity() {
    // SafetyState transitions must be monotonic:
    // Unknown → Valid (on allocation)
    // Valid → Freed (on free)
    // There should be no Valid → Unknown or Freed → Valid transitions
    let pipeline = ValidationPipeline::new();
    let ptr = pipeline.allocate(100).expect("allocate");
    let addr = ptr as usize;

    // Step 1: Valid
    let outcome = pipeline.validate(addr);
    let state1 = outcome.abstraction().map(|a| a.state);
    assert_eq!(state1, Some(SafetyState::Valid));

    // Step 2: Free → TemporalViolation
    pipeline.free(ptr);
    let outcome = pipeline.validate(addr);
    assert!(matches!(outcome, ValidationOutcome::TemporalViolation(_)));

    // Step 3: Should remain TemporalViolation (monotonic — cannot go back to Valid)
    let outcome = pipeline.validate(addr);
    assert!(
        matches!(outcome, ValidationOutcome::TemporalViolation(_)),
        "freed pointer should remain TemporalViolation"
    );
}

// ===========================================================================
// 8. Concurrent validation (shared pipeline, multiple threads)
// ===========================================================================

#[test]
fn concurrent_validate_on_shared_pipeline() {
    let pipeline = Arc::new(ValidationPipeline::new());
    let n_threads = 4;
    let n_allocs_per_thread = 50;

    let handles: Vec<_> = (0..n_threads)
        .map(|tid| {
            let p = Arc::clone(&pipeline);
            thread::spawn(move || {
                let mut ptrs = Vec::new();

                // Each thread allocates its own pointers
                for i in 0..n_allocs_per_thread {
                    let size = 16 + (i % 8) * 16;
                    let ptr = p.allocate(size).expect("allocate");

                    // Validate immediately
                    let outcome = p.validate(ptr as usize);
                    assert!(
                        matches!(
                            outcome,
                            ValidationOutcome::Validated(_) | ValidationOutcome::CachedValid(_)
                        ),
                        "thread {tid} alloc {i}: should be valid"
                    );

                    ptrs.push(ptr);
                }

                // Free all
                for ptr in ptrs {
                    let result = p.free(ptr);
                    assert!(
                        matches!(result, frankenlibc_membrane::arena::FreeResult::Freed),
                        "thread {tid}: free should succeed"
                    );
                }
            })
        })
        .collect();

    for h in handles {
        h.join().expect("thread should not panic");
    }
}

// ===========================================================================
// 9. Concurrent read-validate (no mutation race)
// ===========================================================================

#[test]
fn concurrent_read_validate_live_pointer() {
    let pipeline = Arc::new(ValidationPipeline::new());
    let ptr = pipeline.allocate(256).expect("allocate");
    let addr = ptr as usize;
    let n_threads = 8;

    let handles: Vec<_> = (0..n_threads)
        .map(|_| {
            let p = Arc::clone(&pipeline);
            thread::spawn(move || {
                for _ in 0..100 {
                    let outcome = p.validate(addr);
                    assert!(
                        matches!(
                            outcome,
                            ValidationOutcome::Validated(_) | ValidationOutcome::CachedValid(_)
                        ),
                        "concurrent read should see valid pointer"
                    );
                }
            })
        })
        .collect();

    for h in handles {
        h.join().expect("thread should not panic");
    }

    pipeline.free(ptr);
}

// ===========================================================================
// 10. Validation latency budget (informational)
// ===========================================================================

#[test]
fn validation_latency_within_budget() {
    let pipeline = ValidationPipeline::new();
    let ptr = pipeline.allocate(64).expect("allocate");
    let addr = ptr as usize;

    // Warm up the TLS cache
    for _ in 0..100 {
        pipeline.validate(addr);
    }

    // Measure
    let iterations = 10_000;
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = pipeline.validate(addr);
    }
    let elapsed = start.elapsed();
    let avg_ns = elapsed.as_nanos() / iterations as u128;

    // Strict budget: <20ns per validation (informational, not hard fail)
    // We use a generous 50000ns threshold to avoid CI flake on remote workers
    // under load or with virtualization overhead
    assert!(
        avg_ns < 50000,
        "average validation latency {avg_ns}ns exceeds 50000ns budget"
    );

    pipeline.free(ptr);
}

// ===========================================================================
// 11. Mixed workload (alloc/validate/free interleaved)
// ===========================================================================

#[test]
fn mixed_workload_deterministic() {
    let pipeline = ValidationPipeline::new();
    let mut rng = XorShift64::new(42);
    let mut live_ptrs: Vec<(*mut u8, usize)> = Vec::new();
    let max_live = 64;
    let steps = 5_000;

    for _step in 0..steps {
        let op = rng.gen_range(0, 99);
        match op {
            // Allocate
            0..=39 if live_ptrs.len() < max_live => {
                let size = rng.gen_range(1, 2048);
                if let Some(ptr) = pipeline.allocate(size) {
                    live_ptrs.push((ptr, size));
                }
            }
            // Validate random live pointer
            40..=69 if !live_ptrs.is_empty() => {
                let idx = rng.gen_range(0, live_ptrs.len() - 1);
                let (ptr, _size) = live_ptrs[idx];
                let outcome = pipeline.validate(ptr as usize);
                assert!(
                    matches!(
                        outcome,
                        ValidationOutcome::Validated(_) | ValidationOutcome::CachedValid(_)
                    ),
                    "live pointer should validate"
                );
            }
            // Free random live pointer
            70..=89 if !live_ptrs.is_empty() => {
                let idx = rng.gen_range(0, live_ptrs.len() - 1);
                let (ptr, _size) = live_ptrs.swap_remove(idx);
                let result = pipeline.free(ptr);
                assert!(
                    matches!(result, frankenlibc_membrane::arena::FreeResult::Freed),
                    "free should succeed"
                );
            }
            // Validate foreign address
            90..=94 => {
                let fake = rng.next_u64() as usize | 0x1000_0000;
                let outcome = pipeline.validate(fake);
                assert!(matches!(outcome, ValidationOutcome::Foreign(_)));
            }
            // Validate null
            _ => {
                let outcome = pipeline.validate(0);
                assert!(matches!(outcome, ValidationOutcome::Null));
            }
        }
    }

    // Cleanup
    for (ptr, _) in live_ptrs {
        pipeline.free(ptr);
    }
}

// ===========================================================================
// 12. Allocation size ranges
// ===========================================================================

#[test]
fn small_allocation_validated() {
    let pipeline = ValidationPipeline::new();
    let ptr = pipeline.allocate(1).expect("allocate 1 byte");
    let outcome = pipeline.validate(ptr as usize);
    assert!(matches!(
        outcome,
        ValidationOutcome::Validated(_) | ValidationOutcome::CachedValid(_)
    ));
    let abs = outcome.abstraction().expect("abstraction");
    assert_eq!(abs.remaining, Some(1));
    pipeline.free(ptr);
}

#[test]
fn large_allocation_validated() {
    let pipeline = ValidationPipeline::new();
    let size = 65536;
    let ptr = pipeline.allocate(size).expect("allocate 64K");
    let outcome = pipeline.validate(ptr as usize);
    assert!(matches!(
        outcome,
        ValidationOutcome::Validated(_) | ValidationOutcome::CachedValid(_)
    ));
    let abs = outcome.abstraction().expect("abstraction");
    assert_eq!(abs.remaining, Some(size));
    pipeline.free(ptr);
}

// ===========================================================================
// 13. Rapid alloc-free cycles (stress arena generation tracking)
// ===========================================================================

#[test]
fn rapid_alloc_free_cycles() {
    let pipeline = ValidationPipeline::new();
    for _ in 0..1000 {
        let ptr = pipeline.allocate(32).expect("allocate");
        let outcome = pipeline.validate(ptr as usize);
        assert!(matches!(
            outcome,
            ValidationOutcome::Validated(_) | ValidationOutcome::CachedValid(_)
        ));
        pipeline.free(ptr);
    }
}

// ===========================================================================
// 14. Concurrent mixed workload (multiple threads, shared pipeline)
// ===========================================================================

#[test]
fn concurrent_mixed_workload() {
    let pipeline = Arc::new(ValidationPipeline::new());
    let n_threads = 4;

    let handles: Vec<_> = (0..n_threads)
        .map(|tid| {
            let p = Arc::clone(&pipeline);
            thread::spawn(move || {
                let mut rng = XorShift64::new(100 + tid as u64);
                let mut live: Vec<*mut u8> = Vec::new();
                let max_live = 20;

                for _ in 0..500 {
                    let op = rng.gen_range(0, 99);
                    match op {
                        0..=49 if live.len() < max_live => {
                            let size = rng.gen_range(8, 512);
                            if let Some(ptr) = p.allocate(size) {
                                let outcome = p.validate(ptr as usize);
                                assert!(outcome.can_read() && outcome.can_write());
                                live.push(ptr);
                            }
                        }
                        50..=89 if !live.is_empty() => {
                            let idx = rng.gen_range(0, live.len() - 1);
                            let ptr = live.swap_remove(idx);
                            let result = p.free(ptr);
                            assert!(matches!(
                                result,
                                frankenlibc_membrane::arena::FreeResult::Freed
                            ));
                        }
                        _ => {
                            let outcome = p.validate(0xBAAD_F00D);
                            assert!(matches!(outcome, ValidationOutcome::Foreign(_)));
                        }
                    }
                }

                // Cleanup
                for ptr in live {
                    p.free(ptr);
                }
            })
        })
        .collect();

    for h in handles {
        h.join().expect("concurrent mixed workload thread panicked");
    }
}

// ===========================================================================
// 15. TLS cache effectiveness (repeated validation hits cache)
// ===========================================================================

#[test]
fn tls_cache_hits_on_repeated_validation() {
    let pipeline = ValidationPipeline::new();
    let ptr = pipeline.allocate(128).expect("allocate");
    let addr = ptr as usize;

    // First validation populates cache
    let outcome1 = pipeline.validate(addr);
    assert!(matches!(
        outcome1,
        ValidationOutcome::Validated(_) | ValidationOutcome::CachedValid(_)
    ));

    // Subsequent validations should hit TLS cache (CachedValid)
    let mut cached_count = 0;
    for _ in 0..100 {
        let outcome = pipeline.validate(addr);
        if matches!(outcome, ValidationOutcome::CachedValid(_)) {
            cached_count += 1;
        }
    }

    // Most should be cache hits in isolation. However, parallel tests can
    // bump the global epoch which invalidates cache entries, so we use a
    // relaxed threshold that tolerates some epoch interference.
    assert!(
        cached_count > 10,
        "expected >10 cache hits out of 100, got {cached_count}"
    );

    pipeline.free(ptr);
}

// ===========================================================================
// 16. Null free returns InvalidPointer
// ===========================================================================

#[test]
fn null_free_returns_invalid() {
    let pipeline = ValidationPipeline::new();
    let result = pipeline.free(std::ptr::null_mut());
    // Implementation returns ForeignPointer for null (null was never allocated)
    assert!(
        matches!(
            result,
            frankenlibc_membrane::arena::FreeResult::ForeignPointer
                | frankenlibc_membrane::arena::FreeResult::InvalidPointer
        ),
        "free(null) should return ForeignPointer or InvalidPointer, got {result:?}"
    );
}

// ===========================================================================
// 17. Pipeline metrics are available after workload
// ===========================================================================

#[test]
fn pipeline_metrics_after_workload() {
    let pipeline = ValidationPipeline::new();

    // Do some work
    let mut ptrs = Vec::new();
    for _ in 0..10 {
        let ptr = pipeline.allocate(64).expect("allocate");
        pipeline.validate(ptr as usize);
        ptrs.push(ptr);
    }
    for ptr in &ptrs {
        pipeline.free(*ptr);
    }

    // Pipeline should have processed requests
    // (Basic smoke test that metrics don't crash)
    let outcome = pipeline.validate(0);
    assert!(matches!(outcome, ValidationOutcome::Null));
}

// ===========================================================================
// 18. Validation outcome abstraction fields
// ===========================================================================

#[test]
fn validation_outcome_abstraction_fields() {
    let pipeline = ValidationPipeline::new();

    // Foreign pointer
    let outcome = pipeline.validate(0xCAFE_0000);
    let abs = outcome.abstraction().expect("foreign abstraction");
    assert_eq!(abs.state, SafetyState::Unknown);
    assert!(abs.remaining.is_none());

    // Live pointer
    let ptr = pipeline.allocate(256).expect("allocate");
    let outcome = pipeline.validate(ptr as usize);
    let abs = outcome.abstraction().expect("live abstraction");
    assert_eq!(abs.state, SafetyState::Valid);
    assert_eq!(abs.remaining, Some(256));

    // Freed pointer
    pipeline.free(ptr);
    let outcome = pipeline.validate(ptr as usize);
    assert!(matches!(outcome, ValidationOutcome::TemporalViolation(_)));
}

// ===========================================================================
// 19. Dual-key CSPRNG seeding & header-leak canary non-derivability (VR.8.3/.8.4)
// ===========================================================================

#[test]
fn dual_key_csprng_canary_domain_separation_e2e() {
    use frankenlibc_membrane::fingerprint::{
        AllocationFingerprint, Canary, keys_seeded_from_csprng,
    };

    let sample_fp = AllocationFingerprint::compute(0x4000_0000, 128, 1);
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    assert!(
        keys_seeded_from_csprng(),
        "Linux key initialization must seed 256-bit header/tail SipHash keys from SYS_getrandom"
    );

    // Same 24-byte header bytes `(hash, size, generation)` under two independent `K_tail`
    // keys must yield unrelated trailing canaries.
    let tail_a = Canary::derive_with_tail_keys(
        0x1122_3344_5566_7788,
        0x99AA_BBCC_DDEE_FF00,
        0x4000_0000,
        sample_fp.size,
        sample_fp.generation,
        sample_fp.hash,
    );
    let tail_b = Canary::derive_with_tail_keys(
        0xCAFE_F00D_1234_5678,
        0x8765_4321_DEAD_BEEF,
        0x4000_0000,
        sample_fp.size,
        sample_fp.generation,
        sample_fp.hash,
    );
    assert_ne!(tail_a.as_u64(), tail_b.as_u64());
    assert_ne!(tail_a.as_u64(), sample_fp.hash);
    assert_ne!(tail_a.as_u64(), sample_fp.hash ^ 0xDEAD_BEEF_CAFE_BABEu64);

    // Across 10,000 allocations, `canary ^ hash` must never collapse to any fixed XOR mask.
    let first_fp = AllocationFingerprint::compute(0x5000_0000, 64, 1);
    let first_xor = first_fp.canary_for(0x5000_0000).as_u64() ^ first_fp.hash;
    let mut distinct_xors = 0usize;
    for step in 1..10_000u64 {
        let addr = 0x5000_0000usize + (step as usize) * 64;
        let fp = AllocationFingerprint::compute(addr, 64 + (step & 63), step + 1);
        let xor_mask = fp.canary_for(addr).as_u64() ^ fp.hash;
        if xor_mask != first_xor {
            distinct_xors += 1;
        }
    }
    assert!(
        distinct_xors >= 9_990,
        "expected independent K_tail PRF outputs across 10,000 allocations, got {distinct_xors}"
    );
}

// ===========================================================================
// 20. Warm TLS_CACHE tail-canary & prepended-header corruption detection
// ===========================================================================

#[test]
fn warm_tls_cache_detects_tail_and_header_corruption_e2e() {
    use frankenlibc_membrane::arena::FreeResult;
    use frankenlibc_membrane::fingerprint::FINGERPRINT_SIZE;
    use frankenlibc_membrane::heal::global_healing_policy;
    use frankenlibc_membrane::metrics::{MembraneMetrics, global_metrics};

    let pipeline = ValidationPipeline::new();
    let metrics = global_metrics();
    let heal_policy = global_healing_policy();

    // Case A: Warm TLS_CACHE + near-tail write catches 1-byte trailing canary smash immediately.
    // Parallel tests in this binary call `free()` concurrently and can bump the global
    // `SHARD_EPOCHS` between warming `TLS_CACHE` and probing it; retry warming until an
    // uninterrupted warm-cache probe directly observes the corrupted canary.
    let ptr = pipeline.allocate(128).expect("allocate 128");
    let addr = ptr as usize;
    assert!(matches!(
        pipeline.validate(addr),
        ValidationOutcome::Validated(_) | ValidationOutcome::CachedValid(_)
    ));

    let mode = frankenlibc_membrane::config::safety_level();
    if mode.validation_enabled() {
        let mut warmed = false;
        for _ in 0..64 {
            let _ = pipeline.validate(addr);
            if pipeline.try_validate_cached_remaining(addr) == Some(Some(128)) {
                warmed = true;
                break;
            }
        }
        assert!(warmed, "expected warm TLS_CACHE hit within 64 attempts");

        let clamps_before = heal_policy
            .size_clamps
            .load(std::sync::atomic::Ordering::Relaxed);
        let mut observed_warm_canary_failure = false;
        for _ in 0..64 {
            let _ = pipeline.validate(addr);
            let canary_fails_before = MembraneMetrics::get(&metrics.canary_failures);
            assert!(pipeline.inject_trailing_canary_corruption(addr, 128, 0xEE));

            // Near-tail write (`addr + 96`, remaining 32 <= 64) clamps to 0 in Hardened
            // mode and misses cleanly (zero heals) in Strict mode so `validate()` surfaces
            // `TemporalViolation`.
            let clamped = pipeline.try_validate_cached_write_remaining(addr + 96, 8);
            if MembraneMetrics::get(&metrics.canary_failures) > canary_fails_before {
                observed_warm_canary_failure = true;
                if mode.heals_enabled() {
                    assert_eq!(
                        clamped,
                        Some(Some(0)),
                        "hardened warm TLS near-tail write must clamp corrupted buffer to 0 bytes"
                    );
                    assert!(
                        heal_policy
                            .size_clamps
                            .load(std::sync::atomic::Ordering::Relaxed)
                            > clamps_before
                    );
                } else {
                    assert_eq!(
                        clamped, None,
                        "strict warm TLS near-tail write must evict cache without recording heals"
                    );
                    assert_eq!(
                        heal_policy
                            .size_clamps
                            .load(std::sync::atomic::Ordering::Relaxed),
                        clamps_before
                    );
                }
                assert_eq!(
                    pipeline.try_validate_cached_remaining(addr),
                    None,
                    "corrupted allocation must be evicted from warm TLS_CACHE"
                );
                break;
            }
            // A parallel test bumped `SHARD_EPOCHS` before our probe; un-corrupt via XOR
            // so `validate(addr)` can re-warm `TLS_CACHE` for the next attempt.
            assert!(pipeline.inject_trailing_canary_corruption(addr, 128, 0xEE));
        }
        assert!(
            observed_warm_canary_failure,
            "expected warm TLS near-tail write to directly catch corrupted canary"
        );
    } else {
        assert!(pipeline.inject_trailing_canary_corruption(addr, 128, 0xEE));
    }
    assert_eq!(pipeline.free(ptr), FreeResult::FreedWithCanaryCorruption);

    // Case B: Warm TLS_CACHE + 1-in-16 read cadence catches corruption on large buffer front reads.
    let ptr_cadence = pipeline.allocate(256).expect("allocate 256");
    let addr_cadence = ptr_cadence as usize;
    let _ = pipeline.validate(addr_cadence);
    if mode.validation_enabled() {
        let mut observed_cadence_canary_failure = false;
        for _ in 0..64 {
            let _ = pipeline.validate(addr_cadence);
            let canary_fails_before = MembraneMetrics::get(&metrics.canary_failures);
            assert!(pipeline.inject_trailing_canary_corruption(addr_cadence, 256, 0xAA));
            let mut saw_clamp_or_evict = false;
            for _ in 0..16 {
                match pipeline.try_validate_cached_remaining(addr_cadence) {
                    Some(Some(0)) | None => {
                        saw_clamp_or_evict = true;
                        break;
                    }
                    Some(Some(256)) => {}
                    other => panic!("unexpected warm-cache cadence result: {other:?}"),
                }
            }
            assert!(
                saw_clamp_or_evict,
                "1-in-16 warm-TLS read cadence must detect or evict within 16 probes"
            );
            if MembraneMetrics::get(&metrics.canary_failures) > canary_fails_before {
                observed_cadence_canary_failure = true;
                break;
            }
            assert!(pipeline.inject_trailing_canary_corruption(addr_cadence, 256, 0xAA));
        }
        assert!(
            observed_cadence_canary_failure,
            "expected 1-in-16 warm-TLS read cadence to directly catch corrupted canary"
        );
    } else {
        assert!(pipeline.inject_trailing_canary_corruption(addr_cadence, 256, 0xAA));
    }
    assert_eq!(
        pipeline.free(ptr_cadence),
        FreeResult::FreedWithCanaryCorruption
    );

    // Case C: Warm TLS_CACHE catches 1-bit prepended 24B header corruption (`addr - 24`).
    let ptr_hdr = pipeline.allocate(64).expect("allocate 64");
    let addr_hdr = ptr_hdr as usize;
    let _ = pipeline.validate(addr_hdr);
    let hdr_byte_ptr = (addr_hdr - FINGERPRINT_SIZE) as *mut u8;
    let saved_hdr_byte = unsafe { *hdr_byte_ptr };
    unsafe { *hdr_byte_ptr = saved_hdr_byte ^ 0x80 };
    if frankenlibc_membrane::config::safety_level().validation_enabled() {
        let fp_fails_before = MembraneMetrics::get(&metrics.fingerprint_failures);
        let hdr_clamped = pipeline.try_validate_cached_write_remaining(addr_hdr, 8);
        if hdr_clamped == Some(Some(0)) {
            assert!(MembraneMetrics::get(&metrics.fingerprint_failures) > fp_fails_before);
        }
        assert!(matches!(
            pipeline.validate(addr_hdr),
            ValidationOutcome::TemporalViolation(_)
        ));
    }
    unsafe { *hdr_byte_ptr = saved_hdr_byte };
    assert_eq!(pipeline.free(ptr_hdr), FreeResult::Freed);
}

// ===========================================================================
// 21. CI / smoke wiring & FreedWithCanaryCorruption audit emission check
// ===========================================================================

#[test]
fn smoke_script_wires_all_canary_cases_and_audit_emission() {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root");

    let smoke_script = std::fs::read_to_string(repo_root.join("scripts/ld_preload_smoke.sh"))
        .expect("read scripts/ld_preload_smoke.sh");
    for required_case in [
        "--canary-case",
        "intact",
        "corrupt-legacy-fold",
        "corrupt-symmetric-pair",
        "corrupt-header",
        "corrupt-after-warm-tls-write",
        "corrupt-header-after-warm-tls",
        "fork-preserves-canary-exec-reseeds",
    ] {
        assert!(
            smoke_script.contains(required_case),
            "scripts/ld_preload_smoke.sh missing wired canary probe token `{required_case}`"
        );
    }

    let malloc_abi =
        std::fs::read_to_string(repo_root.join("crates/frankenlibc-abi/src/malloc_abi.rs"))
            .expect("read malloc_abi.rs");
    assert!(
        malloc_abi.contains("FreeResult::FreedWithCanaryCorruption =>")
            && malloc_abi.contains("let record_canary_heal = canary_corrupted")
            && malloc_abi.contains("\"realloc\""),
        "malloc_abi.rs must emit structured healing audit records on FreedWithCanaryCorruption in free and realloc"
    );
}
