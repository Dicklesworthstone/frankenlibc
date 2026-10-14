//! Access projections must preserve rejection, not just allocation geometry.

use frankenlibc_membrane::fingerprint::FINGERPRINT_SIZE;
use frankenlibc_membrane::galois::{ConcreteAction, PointerAbstraction, SafetyAbstraction};
use frankenlibc_membrane::lattice::SafetyState;
use frankenlibc_membrane::ptr_validator::{ValidationOutcome, ValidationPipeline};

const STATES: [SafetyState; 7] = [
    SafetyState::Unknown,
    SafetyState::Valid,
    SafetyState::Readable,
    SafetyState::Writable,
    SafetyState::Quarantined,
    SafetyState::Freed,
    SafetyState::Invalid,
];

fn allocation(state: SafetyState, remaining: Option<usize>) -> PointerAbstraction {
    PointerAbstraction {
        addr: 0x1010,
        state,
        alloc_base: Some(0x1000),
        remaining,
        generation: Some(7),
    }
}

fn assert_rejected(outcome: ValidationOutcome, expected_state: SafetyState) {
    let diagnostic = outcome
        .abstraction()
        .expect("diagnostic allocation metadata");
    let access = outcome.access_abstraction().expect("access classification");
    assert_eq!(access.state, expected_state);
    assert_eq!(access.remaining, Some(0));
    assert_eq!(access.addr, diagnostic.addr);
    assert_eq!(access.alloc_base, diagnostic.alloc_base);
    assert_eq!(access.generation, diagnostic.generation);
    assert!(!access.state.can_read());
    assert!(!access.state.can_write());
    for requested in [0, 1, 64, usize::MAX] {
        assert_eq!(
            SafetyAbstraction::concretize_decision(&access, requested),
            ConcreteAction::Deny,
            "rejected access must never become Proceed or Heal: {outcome:?}"
        );
    }
    assert_eq!(outcome.abstraction(), Some(diagnostic));
}

#[test]
fn explicit_denial_overrides_every_recorded_state_and_extent() {
    for state in STATES {
        for remaining in [None, Some(0), Some(48), Some(usize::MAX)] {
            assert_rejected(
                ValidationOutcome::Denied(allocation(state, remaining)),
                SafetyState::Invalid,
            );
        }
    }
}

#[test]
fn invalid_verdict_overrides_every_recorded_state_and_extent() {
    for state in STATES {
        for remaining in [None, Some(0), Some(48), Some(usize::MAX)] {
            assert_rejected(
                ValidationOutcome::Invalid(allocation(state, remaining)),
                SafetyState::Invalid,
            );
        }
    }
}

#[test]
fn integrity_failure_cannot_resurrect_a_live_slot() {
    for state in [
        SafetyState::Valid,
        SafetyState::Readable,
        SafetyState::Writable,
        SafetyState::Unknown,
        SafetyState::Invalid,
    ] {
        for remaining in [None, Some(0), Some(48), Some(usize::MAX)] {
            assert_rejected(
                ValidationOutcome::TemporalViolation(allocation(state, remaining)),
                SafetyState::Invalid,
            );
        }
    }
}

#[test]
fn quarantine_retains_temporal_identity_but_no_usable_bytes() {
    assert_rejected(
        ValidationOutcome::TemporalViolation(allocation(SafetyState::Quarantined, Some(48))),
        SafetyState::Quarantined,
    );
}

#[test]
fn retired_records_do_not_claim_ownership_of_reused_host_storage() {
    let stale = allocation(SafetyState::Freed, Some(48));
    let outcome = ValidationOutcome::TemporalViolation(stale);
    assert_eq!(outcome.access_abstraction(), Some(stale));
    // This retained metadata is NOT access permission. ABI bounds consumers
    // must reject the stale extent by state before consulting current owners.
    assert!(!outcome.can_read());
    assert!(!outcome.can_write());
    assert_eq!(
        SafetyAbstraction::concretize_decision(&stale, 1),
        ConcreteAction::Deny
    );
}

#[test]
fn successful_validations_keep_their_original_bounds_and_permissions() {
    for state in [
        SafetyState::Valid,
        SafetyState::Readable,
        SafetyState::Writable,
    ] {
        for remaining in [None, Some(0), Some(48), Some(usize::MAX)] {
            let a = allocation(state, remaining);
            for outcome in [
                ValidationOutcome::CachedValid(a),
                ValidationOutcome::Validated(a),
            ] {
                assert_eq!(outcome.access_abstraction(), Some(a));
            }
        }
    }
}

#[test]
fn null_foreign_and_bypassed_outcomes_keep_their_existing_contract() {
    let foreign = ValidationOutcome::Foreign(PointerAbstraction::unknown(0xABCD));
    assert_eq!(foreign.access_abstraction(), foreign.abstraction());
    assert_eq!(
        ValidationOutcome::Null.access_abstraction(),
        Some(PointerAbstraction::null())
    );
    assert_eq!(ValidationOutcome::Bypassed.access_abstraction(), None);
}

// These probes use actual pipeline allocations and actual metadata corruption,
// not a fabricated outcome. No validation occurs before corruption, so the
// allocation has not been inserted into this thread's validation cache.
fn probe_integrity_failure(header: bool) {
    let pipeline = ValidationPipeline::with_runtime_math(false);
    let size = 64;
    let ptr = pipeline.allocate(size).expect("pipeline allocation");
    // SAFETY: pipeline allocations include a FINGERPRINT_SIZE-byte header and
    // trailing canary. This test owns the allocation and toggles one metadata
    // byte, restoring it before freeing. No concurrent access is possible.
    let (metadata, saved) = unsafe {
        let metadata = if header {
            ptr.sub(FINGERPRINT_SIZE)
        } else {
            ptr.add(size)
        };
        let saved = metadata.read_volatile();
        metadata.write_volatile(saved ^ 1);
        (metadata, saved)
    };
    let outcome = pipeline.validate(ptr as usize);
    // SAFETY: the allocation remains owned and live until the following free.
    unsafe { metadata.write_volatile(saved) };
    let released = pipeline.free(ptr);
    assert_eq!(released, frankenlibc_membrane::arena::FreeResult::Freed);
    assert!(
        matches!(outcome, ValidationOutcome::TemporalViolation(_)),
        "the real validator must detect corrupted metadata, got {outcome:?}"
    );
    assert_eq!(
        outcome.abstraction().expect("recorded live slot").state,
        SafetyState::Valid
    );
    assert_rejected(outcome, SafetyState::Invalid);
}

#[test]
fn real_fingerprint_failure_keeps_diagnostics_but_denies_access() {
    probe_integrity_failure(true);
}

#[test]
fn real_canary_failure_keeps_diagnostics_but_denies_access() {
    probe_integrity_failure(false);
}
