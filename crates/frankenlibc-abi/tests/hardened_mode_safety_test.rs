#![cfg(target_os = "linux")]

//! Hardened Mode Safety Invariant Catalog & Deployed Boundary Probes
//! (`bd-249m.2` / `bd-reality-202609-lx578q.8`)
//!
//! Evidence-class scope (see `docs/proofs/hardened_mode_safety.md` and
//! `tests/conformance/proof_obligations_binder.v1.json`):
//! - Formal proof obligation `PO-02` (`Hardened Safety Theorem`) and all 24
//!   binder obligations remain `deferred` under `bd-e4phe.1` / `bd-e4phe.2`
//!   (no machine-checked theorem artifact is committed; finite tests do not
//!   establish a universal all-symbol / all-input / all-interleaving proof).
//! - Section I exercises **unit policy-catalog invariants** over `HealingAction`
//!   and `HealingPolicy`:
//!   - (a) Totality over canonical class IDs `0..=255`
//!   - (b) Pure determinism of policy mapping across calls and threads
//!   - (c) Bounded clamp/truncation arithmetic on declared inputs
//!   - (d) Valid POSIX-shaped fallback values
//! - Section II exercises **contained deployed ABI subprocess probes** in both
//!   `FRANKENLIBC_MODE=strict` and `FRANKENLIBC_MODE=hardened`, testing real
//!   `malloc`/`free`/`memcpy`/`strncpy`/`sigaction`/`raise` routes across live
//!   bounds, size-overflow arithmetic, pre-reuse quarantine clamping, post-drain
//!   eviction, same-address reuse C-ABI provenance limits, concurrent
//!   `free`/validate races, and signal-handler reentry deadlock avoidance.

// ═══════════════════════════════════════════════════════════════════
// SECTION I — UNIT POLICY CATALOG: HealingAction & canonical-class totality
//
// Invariant: `HealingAction` and `recommended_healing_for_canonical_class`
// map every `u8` class ID (`0..=255`) to a defined variant without panicking.
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
    use frankenlibc_membrane::heal::{HealingPolicy, recommended_healing_for_canonical_class};
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
    use frankenlibc_membrane::heal::{HealingAction, HealingPolicy, RepairLogContext};
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
        policy.record(
            "test",
            "hardened_mode_safety",
            action,
            RepairLogContext::new(0, None),
        );
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
    use frankenlibc_membrane::heal::{HealingAction, HealingPolicy, RepairLogContext};
    use std::sync::atomic::Ordering;

    let policy = HealingPolicy::new();

    // Recording HealingAction::None should NOT increment counters
    for _ in 0..100 {
        policy.record(
            "test",
            "hardened_mode_safety",
            &HealingAction::None,
            RepairLogContext::new(0, None),
        );
    }

    assert_eq!(
        policy.total_heals.load(Ordering::Relaxed),
        0,
        "recording None must not increment total_heals"
    );
}

#[test]
fn safety_concurrent_recording_preserves_count_integrity() {
    use frankenlibc_membrane::heal::{HealingAction, HealingPolicy, RepairLogContext};
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
                policy.record(
                    "test",
                    "hardened_mode_safety",
                    &HealingAction::ReturnSafeDefault,
                    RepairLogContext::new(0, None),
                );
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
    let cmp = unsafe { strcmp(c"abc".as_ptr(), c"abc".as_ptr()) };
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

/// Env var that turns `hardened_bounded_string_ops_child` into the real case.
const BOUNDED_STRING_CHILD_ENV: &str = "FRANKENLIBC_BOUNDED_STRING_HEAL_CHILD";

/// Child half of `hardened_bounded_string_ops_heal_only_real_overreads`: the
/// runtime mode is resolved once per process, so hardened mode needs its own.
#[test]
fn hardened_bounded_string_ops_child() {
    use frankenlibc_abi::malloc_abi::{free, malloc};
    use frankenlibc_abi::string_abi::{strncasecmp, strncmp, strncpy};
    use std::ffi::c_char;
    use std::sync::atomic::Ordering;

    if std::env::var_os(BOUNDED_STRING_CHILD_ENV).is_none() {
        return;
    }
    let heals = || {
        frankenlibc_membrane::heal::global_healing_policy()
            .total_heals
            .load(Ordering::Relaxed)
    };
    unsafe {
        // A tracked 4-byte allocation holding a terminated string, like the
        // `tm_zone` Python copies with `strncpy(janname, tm->tm_zone, 9)`.
        let zone = malloc(4).cast::<c_char>();
        zone.copy_from_nonoverlapping(c"EDT".as_ptr(), 4);
        let before = heals();
        let mut dst = [0x55u8; 12];
        strncpy(dst.as_mut_ptr().cast(), zone, 9);
        let padded = dst[..9] == *b"EDT\0\0\0\0\0\0" && dst[9] == 0x55;
        let cmp_ok = strncmp(zone, c"EDT".as_ptr(), 8) == 0
            && strncmp(zone, c"EDTX".as_ptr(), 8) < 0
            && strncasecmp(zone, c"edt".as_ptr(), 8) == 0;
        let false_heals = heals() - before;

        // The same calls on an UNTERMINATED tracked allocation do over-read:
        // those must still be repaired.
        let raw = malloc(4).cast::<c_char>();
        raw.copy_from_nonoverlapping(c"ABCD".as_ptr(), 4);
        let before = heals();
        let mut dst = [0u8; 12];
        strncpy(dst.as_mut_ptr().cast(), raw, 9);
        let _ = strncmp(raw, c"ABCDEFG".as_ptr(), 8);
        let _ = strncasecmp(raw, c"abcdefg".as_ptr(), 8);
        let real_heals = heals() - before;

        free(zone.cast());
        free(raw.cast());
        println!("BOUNDED_STRING {padded} {cmp_ok} {false_heals} {real_heals}");
    }
}

/// Hardened strncpy/strncmp/strncasecmp clamp `n` to a tracked allocation's
/// extent, but a source terminated inside its allocation is never read past
/// the NUL, so nothing was repaired. They used to record a heal anyway, on
/// every such call in ordinary programs (Python's time-module init, OpenSSL's
/// config loader), skewing the repair counters and the runtime risk signal.
#[test]
fn hardened_bounded_string_ops_heal_only_real_overreads() {
    let current_exe = std::env::current_exe().expect("current_exe");
    let output = std::process::Command::new(&current_exe)
        .args([
            "--exact",
            "hardened_bounded_string_ops_child",
            "--nocapture",
            "--test-threads",
            "1",
        ])
        .env("FRANKENLIBC_MODE", "hardened")
        .env(BOUNDED_STRING_CHILD_ENV, "1")
        .output()
        .expect("spawn child");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let Some(at) = stdout.find("BOUNDED_STRING ") else {
        panic!(
            "child printed no verdict. status: {:?}\nstdout:\n{stdout}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    };
    let fields: Vec<&str> = stdout[at..]
        .lines()
        .next()
        .unwrap_or_default()
        .split_whitespace()
        .collect();
    assert_eq!(fields[1], "true", "strncpy must NUL-pad to n: {stdout}");
    assert_eq!(fields[2], "true", "compare results: {stdout}");
    assert_eq!(
        fields[3], "0",
        "terminated sources recorded heals: {stdout}"
    );
    assert_eq!(
        fields[4], "3",
        "unterminated sources must each heal: {stdout}"
    );
}

// ═══════════════════════════════════════════════════════════════════
// SECTION II — CONTAINED DEPLOYED ABI GUARANTEE-BOUNDARY PROBES
// (`bd-reality-202609-lx578q.8`)
// ═══════════════════════════════════════════════════════════════════

const BOUNDARY_PROBE_CHILD_ENV: &str = "FRANKENLIBC_BOUNDARY_PROBE_CHILD";

static SIGNAL_PROBE_TARGET_ADDR: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
static SIGNAL_PROBE_RAN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static SIGNAL_PROBE_BYPASSED_ARENA: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

extern "C" fn boundary_sigusr1_handler(_sig: std::ffi::c_int) {
    use std::sync::atomic::Ordering;
    let addr = SIGNAL_PROBE_TARGET_ADDR.load(Ordering::Acquire);
    let rem = frankenlibc_abi::malloc_abi::known_remaining_for_tests(addr);
    SIGNAL_PROBE_BYPASSED_ARENA.store(rem.is_none(), Ordering::Release);
    SIGNAL_PROBE_RAN.store(true, Ordering::Release);
}

#[test]
fn abi_guarantee_boundary_probe_child() {
    use frankenlibc_abi::errno_abi::__errno_location;
    use frankenlibc_abi::malloc_abi::{free, known_remaining_for_tests, malloc};
    use frankenlibc_abi::signal_abi::{raise, sigaction};
    use frankenlibc_abi::string_abi::{memcpy, strncpy};
    use std::collections::HashSet;
    use std::ffi::{c_char, c_void};
    use std::sync::{
        Arc, Barrier,
        atomic::{AtomicBool, Ordering},
    };

    let Some(expected_mode) = std::env::var_os(BOUNDARY_PROBE_CHILD_ENV) else {
        return;
    };
    let is_hardened = expected_mode == "hardened";
    let policy = frankenlibc_membrane::heal::global_healing_policy();

    unsafe {
        // 1. Size-arithmetic overflow fails closed (`NULL` + `ENOMEM`) in BOTH modes.
        for bad_size in [usize::MAX, usize::MAX - 16, isize::MAX as usize + 1] {
            *__errno_location() = 0;
            let p = malloc(bad_size);
            assert!(
                p.is_null(),
                "malloc({bad_size:#x}) must return NULL without wrapping"
            );
            assert_eq!(
                *__errno_location(),
                libc::ENOMEM,
                "malloc({bad_size:#x}) must set ENOMEM"
            );
        }

        if !is_hardened {
            // Strict mode (`FRANKENLIBC_MODE=strict`): verify valid copy runs with 0 heals
            // and freed pointers do not retain hardened quarantine clamp state.
            let heals_before = policy.total_heals.load(Ordering::Relaxed);
            let p = malloc(32).cast::<u8>();
            assert!(!p.is_null());
            let src = [0x42u8; 32];
            memcpy(p.cast::<c_void>(), src.as_ptr().cast::<c_void>(), 32);
            assert_eq!(
                std::slice::from_raw_parts(p, 32),
                &src[..],
                "strict memcpy must copy exact payload"
            );
            free(p.cast::<c_void>());
            let post_free_rem = known_remaining_for_tests(p as usize);
            let heals_delta = policy.total_heals.load(Ordering::Relaxed) - heals_before;
            println!(
                "ABI_BOUNDARY_STRICT overflow_enomem=true heals_delta={heals_delta} post_free_rem_none={}",
                post_free_rem.is_none()
            );
            return;
        }

        // Hardened mode (`FRANKENLIBC_MODE=hardened`):
        // 2. Live base, interior, and past-end bounds + overflow clamp.
        let p_live = malloc(64).cast::<u8>();
        assert!(!p_live.is_null());
        let addr_live = p_live as usize;
        assert_eq!(known_remaining_for_tests(addr_live), Some(64));
        assert_eq!(known_remaining_for_tests(addr_live + 20), Some(44));
        assert_eq!(known_remaining_for_tests(addr_live + 64), Some(0));

        let src96 = [0x5Au8; 96];
        let clamps_before = policy.size_clamps.load(Ordering::Relaxed);
        memcpy(p_live.cast::<c_void>(), src96.as_ptr().cast::<c_void>(), 96);
        assert!(
            policy.size_clamps.load(Ordering::Relaxed) > clamps_before,
            "hardened 96B memcpy into 64B allocation must record ClampSize"
        );
        assert!(
            std::slice::from_raw_parts(p_live, 64)
                .iter()
                .all(|&b| b == 0x5A)
        );
        free(p_live.cast::<c_void>());

        // 3. Pre-reuse quarantined pointer: `known_remaining == Some(0)`, `memcpy` clamps to 0,
        //    and double-`free` heals via `IgnoreDoubleFree`.
        let mut candidates = Vec::with_capacity(64);
        for _ in 0..64 {
            let p = malloc(64).cast::<u8>();
            assert!(!p.is_null());
            std::ptr::write_bytes(p, 0x41, 64);
            candidates.push((p, p as usize));
        }
        let (p0, addr0) = candidates[0];
        for &(p, _) in &candidates {
            free(p.cast::<c_void>());
        }
        assert_eq!(
            known_remaining_for_tests(addr0),
            Some(0),
            "quarantined pointer must expose 0 remaining bytes"
        );
        let clamps_q_before = policy.size_clamps.load(Ordering::Relaxed);
        let overwrite = [0xEEu8; 16];
        memcpy(p0.cast::<c_void>(), overwrite.as_ptr().cast::<c_void>(), 16);
        let quar_clamped = policy.size_clamps.load(Ordering::Relaxed) > clamps_q_before;

        let df_before = policy.double_frees.load(Ordering::Relaxed);
        free(p0.cast::<c_void>());
        let double_free_healed = policy.double_frees.load(Ordering::Relaxed) > df_before;

        // 4. Drain quarantine (`> 64 MiB` + shard batch flush) -> `known_remaining` transitions
        //    from `Some(0)` (quarantined) to `None` (drained / foreign), and `free` heals via
        //    `IgnoreForeignFree`.
        let filler = malloc(63 * 1024 * 1024);
        assert!(!filler.is_null());
        free(filler);
        let mut flushers = Vec::with_capacity(32);
        for _ in 0..32 {
            let q = malloc(256 * 1024);
            if !q.is_null() {
                flushers.push(q);
            }
        }
        for q in flushers {
            free(q);
        }
        let mut shard_flush = Vec::with_capacity(1024);
        for _ in 0..1024 {
            let q = malloc(1536);
            if !q.is_null() {
                shard_flush.push(q);
            }
        }
        for q in shard_flush {
            free(q);
        }
        // Advance EBR grace period via >= 1 MiB retire batches.
        for _ in 0..6 {
            let batch = malloc(2 * 1024 * 1024);
            if !batch.is_null() {
                free(batch);
            }
        }

        let drained_is_none = known_remaining_for_tests(addr0).is_none();
        let ff_before = policy.foreign_frees.load(Ordering::Relaxed);
        if drained_is_none {
            free(p0.cast::<c_void>());
        }
        let foreign_free_healed =
            !drained_is_none || policy.foreign_frees.load(Ordering::Relaxed) > ff_before;

        // 5. Same-address reuse C-ABI provenance boundary: allocate 48B blocks; any reused
        //    `user_base` (and every new live 48B block) reports `Some(48)`, clamping 64B writes
        //    to 48B while allowing 32B writes through the identical raw `usize` address.
        let old_addrs: HashSet<usize> = candidates.iter().map(|&(_, a)| a).collect();
        let mut new_blocks = Vec::with_capacity(256);
        let mut reused_addr: Option<*mut u8> = None;
        for _ in 0..256 {
            let np = malloc(48).cast::<u8>();
            assert!(!np.is_null());
            std::ptr::write_bytes(np, 0x11, 48);
            if reused_addr.is_none() && old_addrs.contains(&(np as usize)) {
                reused_addr = Some(np);
            }
            new_blocks.push(np);
        }
        let target = reused_addr.unwrap_or(new_blocks[0]);
        assert_eq!(known_remaining_for_tests(target as usize), Some(48));

        let clamps_reuse_before = policy.size_clamps.load(Ordering::Relaxed);
        let src32 = [0x22u8; 32];
        // Write within new 48B bound via raw address: indistinguishable from new owner under C ABI.
        memcpy(
            (target as usize) as *mut c_void,
            src32.as_ptr().cast::<c_void>(),
            32,
        );
        let in_bound_alias_unhealed = policy.size_clamps.load(Ordering::Relaxed)
            == clamps_reuse_before
            && std::slice::from_raw_parts(target, 32) == &src32[..];

        // Write 64B (old size) past new 48B bound: spatial overflow IS caught and clamped to 48B!
        let src64 = [0x33u8; 64];
        memcpy(
            (target as usize) as *mut c_void,
            src64.as_ptr().cast::<c_void>(),
            64,
        );
        let reuse_overflow_clamped = policy.size_clamps.load(Ordering::Relaxed)
            > clamps_reuse_before
            && std::slice::from_raw_parts(target, 48)
                .iter()
                .all(|&b| b == 0x33);

        for np in new_blocks {
            free(np.cast::<c_void>());
        }

        // 6. Concurrent `free` vs `known_remaining` / `strncpy` race across threads.
        for _ in 0..16 {
            let race_ptr = malloc(96).cast::<c_char>();
            assert!(!race_ptr.is_null());
            std::ptr::write_bytes(race_ptr.cast::<u8>(), b'A', 95);
            *race_ptr.add(95) = 0;
            let race_addr = race_ptr as usize;
            let barrier = Arc::new(Barrier::new(5));
            let freed = Arc::new(AtomicBool::new(false));
            let mut joins = Vec::with_capacity(4);
            for _ in 0..4 {
                let b = Arc::clone(&barrier);
                let f = Arc::clone(&freed);
                joins.push(std::thread::spawn(move || {
                    assert_eq!(known_remaining_for_tests(race_addr), Some(96));
                    b.wait();
                    let mut local = [0 as c_char; 32];
                    for _ in 0..32 {
                        let _ = known_remaining_for_tests(race_addr);
                        strncpy(local.as_mut_ptr(), race_addr as *const c_char, 16);
                    }
                    while !f.load(Ordering::Acquire) {
                        std::hint::spin_loop();
                    }
                    let after = known_remaining_for_tests(race_addr);
                    assert_ne!(
                        after,
                        Some(96),
                        "post-free thread lookup must not return stale live Some(96)"
                    );
                }));
            }
            barrier.wait();
            free(race_ptr.cast::<c_void>());
            freed.store(true, Ordering::Release);
            for j in joins {
                j.join().expect("race worker panicked");
            }
        }

        // 7. Signal-handler (`SIGUSR1`) reentry bypass (`in_signal_handler` / `in_validation_context`).
        let sig_buf = malloc(32).cast::<u8>();
        assert!(!sig_buf.is_null());
        let sig_addr = sig_buf as usize;
        assert_eq!(known_remaining_for_tests(sig_addr), Some(32));
        SIGNAL_PROBE_TARGET_ADDR.store(sig_addr, Ordering::Release);
        SIGNAL_PROBE_RAN.store(false, Ordering::Release);
        SIGNAL_PROBE_BYPASSED_ARENA.store(false, Ordering::Release);

        let mut act: libc::sigaction = std::mem::zeroed();
        act.sa_sigaction = boundary_sigusr1_handler as *const () as usize;
        libc::sigemptyset(&raw mut act.sa_mask);
        act.sa_flags = 0;
        let mut oldact: libc::sigaction = std::mem::zeroed();
        assert_eq!(sigaction(libc::SIGUSR1, &raw const act, &raw mut oldact), 0);
        assert_eq!(raise(libc::SIGUSR1), 0);
        assert_eq!(
            sigaction(libc::SIGUSR1, &raw const oldact, std::ptr::null_mut()),
            0
        );

        let sig_ran = SIGNAL_PROBE_RAN.load(Ordering::Acquire);
        let sig_bypassed = SIGNAL_PROBE_BYPASSED_ARENA.load(Ordering::Acquire);
        let post_sig_restored = known_remaining_for_tests(sig_addr) == Some(32);
        free(sig_buf.cast::<c_void>());

        println!(
            "ABI_BOUNDARY_HARDENED quar_clamped={quar_clamped} double_free={double_free_healed} drained_none={drained_is_none} foreign_free={foreign_free_healed} alias_unhealed={in_bound_alias_unhealed} reuse_overflow_clamped={reuse_overflow_clamped} reused_hit={} sig_ran={sig_ran} sig_bypassed={sig_bypassed} post_sig_restored={post_sig_restored}",
            reused_addr.is_some()
        );
    }
}

#[test]
fn abi_guarantee_boundary_strict_vs_hardened_subprocesses() {
    let current_exe = std::env::current_exe().expect("current_exe");

    // 1. Strict subprocess probe.
    let strict_out = std::process::Command::new(&current_exe)
        .args([
            "--exact",
            "abi_guarantee_boundary_probe_child",
            "--nocapture",
            "--test-threads",
            "1",
        ])
        .env("FRANKENLIBC_MODE", "strict")
        .env(BOUNDARY_PROBE_CHILD_ENV, "strict")
        .output()
        .expect("spawn strict boundary probe");
    let strict_stdout = String::from_utf8_lossy(&strict_out.stdout).into_owned();
    assert!(
        strict_out.status.success(),
        "strict boundary probe failed ({:?}):\nstdout:\n{strict_stdout}\nstderr:\n{}",
        strict_out.status,
        String::from_utf8_lossy(&strict_out.stderr)
    );
    assert!(
        strict_stdout.contains(
            "ABI_BOUNDARY_STRICT overflow_enomem=true heals_delta=0 post_free_rem_none=true"
        ),
        "unexpected strict boundary output:\n{strict_stdout}"
    );

    // 2. Hardened subprocess probe.
    let hardened_out = std::process::Command::new(&current_exe)
        .args([
            "--exact",
            "abi_guarantee_boundary_probe_child",
            "--nocapture",
            "--test-threads",
            "1",
        ])
        .env("FRANKENLIBC_MODE", "hardened")
        .env(BOUNDARY_PROBE_CHILD_ENV, "hardened")
        .output()
        .expect("spawn hardened boundary probe");
    let hardened_stdout = String::from_utf8_lossy(&hardened_out.stdout).into_owned();
    assert!(
        hardened_out.status.success(),
        "hardened boundary probe failed ({:?}):\nstdout:\n{hardened_stdout}\nstderr:\n{}",
        hardened_out.status,
        String::from_utf8_lossy(&hardened_out.stderr)
    );
    for expected in [
        "quar_clamped=true",
        "double_free=true",
        "drained_none=true",
        "foreign_free=true",
        "alias_unhealed=true",
        "reuse_overflow_clamped=true",
        "sig_ran=true",
        "sig_bypassed=true",
        "post_sig_restored=true",
    ] {
        assert!(
            hardened_stdout.contains(expected),
            "hardened boundary probe missing `{expected}`:\n{hardened_stdout}"
        );
    }
}
