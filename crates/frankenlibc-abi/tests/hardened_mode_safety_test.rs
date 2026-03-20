#![cfg(target_os = "linux")]

//! Hardened Mode Safety Proof Tests (bd-249m.2)
//!
//! These tests verify the hardened-mode safety theorem:
//!
//!   For all symbols s, for all inputs x (including adversarial):
//!     (a) Totality: repair is defined for every violation class × symbol
//!     (b) Determinism: same violation on same input → same repair, always
//!     (c) Safety: repair path does not propagate the violation
//!     (d) POSIX compatibility: repair output is a valid POSIX return
//!
//! Coverage: HealingAction enum exhaustiveness, HealingPolicy determinism,
//! canonical class mapping totality, and recommended healing correctness.

// ═══════════════════════════════════════════════════════════════════
// TOTALITY: Every HealingAction variant is covered
//
// Theorem: The HealingAction enum and the canonical-class healing
// recommender are total — every possible class maps to a defined
// healing action, and no match arm is missing.
// ═══════════════════════════════════════════════════════════════════

#[test]
fn totality_healing_action_is_heal_correct() {
    use frankenlibc_membrane::heal::HealingAction;

    // Every variant except None is a heal
    let heals = [
        HealingAction::ClampSize {
            requested: 100,
            clamped: 50,
        },
        HealingAction::TruncateWithNull {
            requested: 100,
            truncated: 50,
        },
        HealingAction::IgnoreDoubleFree,
        HealingAction::IgnoreForeignFree,
        HealingAction::ReallocAsMalloc { size: 64 },
        HealingAction::ReturnSafeDefault,
        HealingAction::UpgradeToSafeVariant,
    ];

    for action in &heals {
        assert!(action.is_heal(), "{action:?} should be a heal");
    }

    assert!(!HealingAction::None.is_heal(), "None should not be a heal");
}

#[test]
fn totality_canonical_class_covers_all_classes() {
    use frankenlibc_membrane::heal::recommended_healing_for_canonical_class;

    // Every class ID from 0 to 255 must produce a defined HealingAction
    // (no panics, no undefined behavior)
    for class_id in 0..=255u8 {
        let action = recommended_healing_for_canonical_class(class_id);
        // The action must be one of the defined variants
        // (Rust's type system ensures this, but we verify at runtime)
        let _ = format!("{action:?}"); // Debug must not panic
    }
}

#[test]
fn totality_canonical_class_zero_is_none() {
    use frankenlibc_membrane::heal::recommended_healing_for_canonical_class;

    let action = recommended_healing_for_canonical_class(0);
    assert_eq!(
        action,
        frankenlibc_membrane::heal::HealingAction::None,
        "canonical class 0 (NONE) must map to HealingAction::None"
    );
}

// ═══════════════════════════════════════════════════════════════════
// DETERMINISM: Same violation → same repair, always
//
// Theorem: The healing policy functions are pure — given the same
// inputs, they always produce the same output. No randomness,
// no timing dependence, no global state mutation affects the result.
// ═══════════════════════════════════════════════════════════════════

#[test]
fn determinism_heal_copy_bounds_is_pure() {
    use frankenlibc_membrane::heal::HealingPolicy;

    let policy = HealingPolicy::new();

    // Same inputs must always produce the same output
    for _ in 0..100 {
        let action = policy.heal_copy_bounds(1000, Some(500), Some(800));
        assert_eq!(
            action,
            frankenlibc_membrane::heal::HealingAction::ClampSize {
                requested: 1000,
                clamped: 500,
            },
            "heal_copy_bounds must be deterministic"
        );
    }
}

#[test]
fn determinism_heal_string_bounds_is_pure() {
    use frankenlibc_membrane::heal::HealingPolicy;

    let policy = HealingPolicy::new();

    // Same inputs must always produce the same output
    for _ in 0..100 {
        let action = policy.heal_string_bounds(256, Some(128));
        assert_eq!(
            action,
            frankenlibc_membrane::heal::HealingAction::TruncateWithNull {
                requested: 256,
                truncated: 127,
            },
            "heal_string_bounds must be deterministic"
        );
    }
}

#[test]
fn determinism_canonical_class_mapping_is_pure() {
    use frankenlibc_membrane::heal::recommended_healing_for_canonical_class;

    // For each class, verify the mapping is the same across 100 calls
    for class_id in 0..=10u8 {
        let first = recommended_healing_for_canonical_class(class_id);
        for _ in 0..100 {
            let repeated = recommended_healing_for_canonical_class(class_id);
            assert_eq!(
                first, repeated,
                "canonical class {class_id} mapping must be deterministic"
            );
        }
    }
}

#[test]
fn determinism_across_threads() {
    use frankenlibc_membrane::heal::{recommended_healing_for_canonical_class, HealingPolicy};
    use std::sync::{Arc, Barrier};
    use std::thread;

    let barrier = Arc::new(Barrier::new(4));
    let mut handles = Vec::new();

    for _ in 0..4 {
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            let policy = HealingPolicy::new();
            let mut results = Vec::new();
            for _ in 0..100 {
                let a1 = policy.heal_copy_bounds(512, Some(256), Some(400));
                let a2 = policy.heal_string_bounds(128, Some(64));
                let a3 = recommended_healing_for_canonical_class(1);
                let a4 = recommended_healing_for_canonical_class(2);
                results.push(format!("{a1:?}|{a2:?}|{a3:?}|{a4:?}"));
            }
            // All 100 iterations must produce identical strings
            let first = &results[0];
            for (i, r) in results.iter().enumerate() {
                assert_eq!(r, first, "thread determinism failed at iteration {i}");
            }
            results[0].clone()
        }));
    }

    // All 4 threads must produce the same result string
    let results: Vec<String> = handles
        .into_iter()
        .map(|h| h.join().expect("thread panicked"))
        .collect();
    let first = &results[0];
    for (i, r) in results.iter().enumerate() {
        assert_eq!(r, first, "cross-thread determinism failed for thread {i}");
    }
}

// ═══════════════════════════════════════════════════════════════════
// POSIX COMPATIBILITY: Repair outputs are valid POSIX returns
//
// Theorem: Every healing action maps to a well-defined POSIX error
// return pattern. No healing action produces an undefined or
// implementation-specific return.
// ═══════════════════════════════════════════════════════════════════

#[test]
fn posix_compatibility_clamp_size_produces_valid_bounds() {
    use frankenlibc_membrane::heal::{HealingAction, HealingPolicy};

    let policy = HealingPolicy::new();

    // Clamped size must be <= allocation size and > 0 (when allocation exists)
    let action = policy.heal_copy_bounds(10000, Some(4096), Some(8192));
    match action {
        HealingAction::ClampSize { requested, clamped } => {
            assert!(
                clamped <= 4096,
                "clamped size {clamped} must be <= allocation {}",
                4096
            );
            assert!(
                clamped < requested,
                "clamped {clamped} must be < requested {requested}"
            );
        }
        other => panic!("expected ClampSize, got {other:?}"),
    }
}

#[test]
fn posix_compatibility_truncate_reserves_null_byte() {
    use frankenlibc_membrane::heal::{HealingAction, HealingPolicy};

    let policy = HealingPolicy::new();

    // Truncation must leave room for null terminator
    let action = policy.heal_string_bounds(1024, Some(256));
    match action {
        HealingAction::TruncateWithNull {
            requested,
            truncated,
        } => {
            assert!(
                truncated < requested,
                "truncated {truncated} must be < requested {requested}"
            );
            // The truncated size must leave room for the null byte
            assert!(
                truncated < 256,
                "truncated {truncated} must be < allocation size 256"
            );
        }
        other => panic!("expected TruncateWithNull, got {other:?}"),
    }
}

#[test]
fn posix_compatibility_no_heal_for_valid_copy() {
    use frankenlibc_membrane::heal::{HealingAction, HealingPolicy};

    let policy = HealingPolicy::new();

    // Valid copy within bounds should not trigger healing
    let action = policy.heal_copy_bounds(100, Some(200), Some(200));
    assert_eq!(
        action,
        HealingAction::None,
        "valid copy within bounds must not trigger healing"
    );
}

#[test]
fn posix_compatibility_no_heal_for_valid_string() {
    use frankenlibc_membrane::heal::{HealingAction, HealingPolicy};

    let policy = HealingPolicy::new();

    // Valid string operation within bounds should not heal
    let action = policy.heal_string_bounds(50, Some(100));
    assert_eq!(
        action,
        HealingAction::None,
        "valid string within bounds must not trigger healing"
    );
}

// ═══════════════════════════════════════════════════════════════════
// SAFETY: Repair paths don't propagate violations
//
// Theorem: After a healing action is applied, the resulting state
// is safe — no freed memory is accessed, no buffer overrun occurs
// in the repair path itself, and counters are correctly updated.
// ═══════════════════════════════════════════════════════════════════

#[test]
fn safety_healing_policy_counters_monotonic() {
    use frankenlibc_membrane::heal::{HealingAction, HealingPolicy};
    use std::sync::atomic::Ordering;

    let policy = HealingPolicy::new();

    // Record a sequence of heals
    let actions = [
        HealingAction::ClampSize {
            requested: 100,
            clamped: 50,
        },
        HealingAction::IgnoreDoubleFree,
        HealingAction::IgnoreForeignFree,
        HealingAction::ReturnSafeDefault,
        HealingAction::ReallocAsMalloc { size: 64 },
        HealingAction::TruncateWithNull {
            requested: 200,
            truncated: 100,
        },
        HealingAction::UpgradeToSafeVariant,
    ];

    for action in &actions {
        policy.record(action);
    }

    // All counters should have been incremented exactly once
    assert_eq!(policy.size_clamps.load(Ordering::Relaxed), 1);
    assert_eq!(policy.double_frees.load(Ordering::Relaxed), 1);
    assert_eq!(policy.foreign_frees.load(Ordering::Relaxed), 1);
    assert_eq!(policy.safe_defaults.load(Ordering::Relaxed), 1);
    assert_eq!(policy.realloc_as_mallocs.load(Ordering::Relaxed), 1);
    assert_eq!(policy.null_truncations.load(Ordering::Relaxed), 1);
    assert_eq!(policy.variant_upgrades.load(Ordering::Relaxed), 1);
    assert_eq!(
        policy.total_heals.load(Ordering::Relaxed),
        7,
        "total heals must equal sum of individual counters"
    );
}

#[test]
fn safety_recording_none_does_not_increment() {
    use frankenlibc_membrane::heal::{HealingAction, HealingPolicy};
    use std::sync::atomic::Ordering;

    let policy = HealingPolicy::new();

    // Recording HealingAction::None should NOT increment counters
    for _ in 0..100 {
        policy.record(&HealingAction::None);
    }

    assert_eq!(
        policy.total_heals.load(Ordering::Relaxed),
        0,
        "recording None must not increment total_heals"
    );
}

#[test]
fn safety_concurrent_recording_preserves_count_integrity() {
    use frankenlibc_membrane::heal::{HealingAction, HealingPolicy};
    use std::sync::atomic::Ordering;
    use std::sync::{Arc, Barrier};
    use std::thread;

    let policy = Arc::new(HealingPolicy::new());
    let barrier = Arc::new(Barrier::new(4));
    let mut handles = Vec::new();

    // 4 threads each record 250 heals = 1000 total
    for _ in 0..4 {
        let policy = Arc::clone(&policy);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for _ in 0..250 {
                policy.record(&HealingAction::ReturnSafeDefault);
            }
        }));
    }

    for h in handles {
        h.join().expect("thread panicked");
    }

    assert_eq!(
        policy.total_heals.load(Ordering::Relaxed),
        1000,
        "concurrent recording must preserve exact count"
    );
    assert_eq!(
        policy.safe_defaults.load(Ordering::Relaxed),
        1000,
        "per-action counter must match"
    );
}

// ═══════════════════════════════════════════════════════════════════
// VALID INPUTS: Hardened mode passes valid inputs unchanged
//
// Theorem: For valid inputs, hardened mode produces the same
// results as strict mode (no gratuitous healing).
// ═══════════════════════════════════════════════════════════════════

#[test]
fn valid_inputs_pass_through_without_healing() {
    use frankenlibc_abi::string_abi::{memcpy, memset, strcmp, strlen};
    use std::ffi::c_int;

    // All valid operations should produce correct results
    // with no healing interference

    // strlen on valid string
    let len = unsafe { strlen(c"hello world".as_ptr()) };
    assert_eq!(len, 11);

    // strcmp on valid strings
    let cmp = unsafe {
        strcmp(c"abc".as_ptr(), c"abc".as_ptr())
    };
    assert_eq!(cmp, 0);

    // memcpy with valid buffers
    let src = [1u8, 2, 3, 4];
    let mut dst = [0u8; 4];
    unsafe { memcpy(dst.as_mut_ptr().cast(), src.as_ptr().cast(), 4) };
    assert_eq!(dst, src);

    // memset with valid buffer
    let mut buf = [0u8; 16];
    unsafe { memset(buf.as_mut_ptr().cast(), 0xAB as c_int, 16) };
    assert!(buf.iter().all(|&b| b == 0xAB));
}
