//! The allocation lifetime classification must survive a bounds failure.

use super::{ArenaSlot, ValidationOutcome, ValidationPipeline};
use crate::lattice::SafetyState;

fn slot(state: SafetyState, size: usize) -> ArenaSlot {
    ArenaSlot {
        raw_base: 0x1000,
        user_base: 0x1018,
        user_size: size,
        generation: 17,
        state,
    }
}

#[test]
fn retired_header_and_canary_addresses_retain_freed_classification() {
    let pipeline = ValidationPipeline::with_runtime_math(false);
    for size in [0, 64] {
        let retired = slot(SafetyState::Freed, size);
        for addr in [
            retired.raw_base,
            retired.user_base - 1,
            retired.user_base,
            retired.user_base + size,
            retired.user_base + size + 7,
        ] {
            let diagnostic = pipeline.abstraction_from_slot(addr, &retired);
            assert_eq!(diagnostic.state, SafetyState::Freed);
            let projected = ValidationOutcome::TemporalViolation(diagnostic)
                .access_abstraction()
                .expect("retired metadata");
            assert_eq!(projected, diagnostic);
            // The ABI ignores Freed extents and consults current ownership.
            // Turning these header/tail addresses into Invalid would instead
            // deny legitimate host allocations reusing the retired block.
            assert_eq!(projected.state, SafetyState::Freed);
        }
    }
}

#[test]
fn quarantined_header_and_canary_addresses_remain_temporal_violations() {
    let pipeline = ValidationPipeline::with_runtime_math(false);
    for size in [0, 64] {
        let quarantined = slot(SafetyState::Quarantined, size);
        for addr in [
            quarantined.raw_base,
            quarantined.user_base - 1,
            quarantined.user_base,
            quarantined.user_base + size,
            quarantined.user_base + size + 7,
        ] {
            let diagnostic = pipeline.abstraction_from_slot(addr, &quarantined);
            assert_eq!(diagnostic.state, SafetyState::Quarantined);
            let access = ValidationOutcome::TemporalViolation(diagnostic)
                .access_abstraction()
                .expect("quarantined metadata");
            assert_eq!(access.state, SafetyState::Quarantined);
            assert_eq!(access.remaining, Some(0));
        }
    }
}

#[test]
fn live_allocation_bounds_still_reject_metadata_addresses() {
    let pipeline = ValidationPipeline::with_runtime_math(false);
    let live = slot(SafetyState::Valid, 64);
    for addr in [live.raw_base, live.user_base - 1, live.user_base + 64] {
        let access = pipeline.abstraction_from_slot(addr, &live);
        assert_eq!(access.state, SafetyState::Invalid);
        assert_eq!(access.remaining, Some(0));
    }
    let first = pipeline.abstraction_from_slot(live.user_base, &live);
    assert_eq!(first.state, SafetyState::Valid);
    assert_eq!(first.remaining, Some(64));
    let last = pipeline.abstraction_from_slot(live.user_base + 63, &live);
    assert_eq!(last.state, SafetyState::Valid);
    assert_eq!(last.remaining, Some(1));
}
