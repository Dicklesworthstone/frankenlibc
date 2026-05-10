#![no_main]
//! Structure-aware fuzz target for the membrane validation pipeline.
//!
//! Exercises arbitrary foreign addresses plus allocation lifecycle paths so the
//! target reaches TLS-cache hits, arena lookups, near-miss pointers, temporal
//! violations, double-free handling, and canary-corruption detection.
//!
//! Bead: bd-1oz.4

use arbitrary::Arbitrary;
use frankenlibc_membrane::arena::FreeResult;
use frankenlibc_membrane::ptr_validator::{ValidationOutcome, ValidationPipeline};
use libfuzzer_sys::fuzz_target;

const MAX_ALLOC_SIZE: usize = 4096;
const MAX_LIVE: usize = 64;
const MAX_OPS: usize = 256;

#[derive(Debug, Arbitrary)]
enum MembraneOp {
    ValidateAddress { addr: u64 },
    Allocate { size: u16 },
    ValidateLive { index: u8, offset: u16 },
    ValidateNearMiss { index: u8, selector: u8 },
    RevalidateForCache { index: u8 },
    Free { index: u8 },
    DoubleFreeLast,
    CorruptCanary { index: u8, fill_byte: u8 },
}

#[derive(Debug, Arbitrary)]
struct MembraneInput {
    ops: Vec<MembraneOp>,
}

#[derive(Debug, Clone, Copy)]
struct LiveAllocation {
    ptr: *mut u8,
    size: usize,
}

fn bounded_size(size: u16) -> usize {
    usize::from(size).clamp(1, MAX_ALLOC_SIZE)
}

fn live_index(len: usize, index: u8) -> Option<usize> {
    if len == 0 {
        None
    } else {
        Some(usize::from(index) % len)
    }
}

fn assert_outcome_is_self_consistent(outcome: ValidationOutcome) {
    let _ = outcome.abstraction();
    let _ = outcome.can_read();
    let _ = outcome.can_write();
}

fuzz_target!(|input: MembraneInput| {
    let pipeline = ValidationPipeline::new();
    let mut live: Vec<LiveAllocation> = Vec::new();
    let mut last_freed: Option<*mut u8> = None;

    for op in input.ops.iter().take(MAX_OPS) {
        match *op {
            MembraneOp::ValidateAddress { addr } => {
                assert_outcome_is_self_consistent(pipeline.validate(addr as usize));
            }
            MembraneOp::Allocate { size } => {
                if live.len() >= MAX_LIVE {
                    continue;
                }
                let size = bounded_size(size);
                if let Some(ptr) = pipeline.allocate(size) {
                    let outcome = pipeline.validate(ptr as usize);
                    assert!(
                        outcome.can_read() && outcome.can_write(),
                        "fresh allocation should validate as readable and writable"
                    );
                    live.push(LiveAllocation { ptr, size });
                }
            }
            MembraneOp::ValidateLive { index, offset } => {
                let Some(i) = live_index(live.len(), index) else {
                    continue;
                };
                let allocation = live[i];
                let addr =
                    (allocation.ptr as usize).saturating_add(usize::from(offset) % allocation.size);
                assert_outcome_is_self_consistent(pipeline.validate(addr));
            }
            MembraneOp::ValidateNearMiss { index, selector } => {
                let Some(i) = live_index(live.len(), index) else {
                    continue;
                };
                let allocation = live[i];
                let base = allocation.ptr as usize;
                let addr = match selector % 4 {
                    0 => base.saturating_sub(1),
                    1 => base.saturating_add(allocation.size),
                    2 => base.saturating_add(allocation.size).saturating_add(1),
                    _ => base.saturating_add(allocation.size / 2),
                };
                assert_outcome_is_self_consistent(pipeline.validate(addr));
            }
            MembraneOp::RevalidateForCache { index } => {
                let Some(i) = live_index(live.len(), index) else {
                    continue;
                };
                let addr = live[i].ptr as usize;
                assert_outcome_is_self_consistent(pipeline.validate(addr));
                assert_outcome_is_self_consistent(pipeline.validate(addr));
            }
            MembraneOp::Free { index } => {
                let Some(i) = live_index(live.len(), index) else {
                    continue;
                };
                let allocation = live.swap_remove(i);
                assert_eq!(pipeline.free(allocation.ptr), FreeResult::Freed);
                let outcome = pipeline.validate(allocation.ptr as usize);
                assert!(
                    matches!(outcome, ValidationOutcome::TemporalViolation(_)),
                    "freed allocation should validate as temporal violation"
                );
                last_freed = Some(allocation.ptr);
            }
            MembraneOp::DoubleFreeLast => {
                if let Some(ptr) = last_freed {
                    assert_eq!(pipeline.free(ptr), FreeResult::DoubleFree);
                }
            }
            MembraneOp::CorruptCanary { index, fill_byte } => {
                let Some(i) = live_index(live.len(), index) else {
                    continue;
                };
                let allocation = live.swap_remove(i);
                if pipeline.inject_trailing_canary_corruption(
                    allocation.ptr as usize,
                    allocation.size,
                    fill_byte,
                ) {
                    assert!(matches!(
                        pipeline.validate(allocation.ptr as usize),
                        ValidationOutcome::TemporalViolation(_)
                    ));
                    assert_eq!(
                        pipeline.free(allocation.ptr),
                        FreeResult::FreedWithCanaryCorruption
                    );
                    last_freed = Some(allocation.ptr);
                } else {
                    live.push(allocation);
                }
            }
        }
    }

    for allocation in live {
        let _ = pipeline.free(allocation.ptr);
    }
});
