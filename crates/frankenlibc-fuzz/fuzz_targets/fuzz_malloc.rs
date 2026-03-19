#![no_main]
//! Structure-aware fuzz target for FrankenLibC allocator (arena + validation pipeline).
//!
//! Exercises allocation/free sequences with varying sizes, alignment, and
//! deliberate error patterns (double-free, UAF, foreign pointer free).
//! Verifies that the membrane arena handles all patterns without panic,
//! memory corruption, or inconsistent state.
//!
//! Coverage goals:
//! - AllocationArena: allocate, allocate_aligned, free, lookup, contains
//! - ValidationPipeline: validate, free
//! - Quarantine queue: overflow, drain, generation monotonicity
//! - Error handling: double-free, foreign-pointer free, UAF validation
//! - Varying sizes: 0, 1, small, medium, large, huge
//! - Varying alignment: 16, 32, 64, 128, 256, 512, 1024, 2048, 4096
//!
//! Bead: bd-1oz.2

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use frankenlibc_core::malloc::MallocState;
use frankenlibc_membrane::arena::FreeResult;
use frankenlibc_membrane::ptr_validator::ValidationPipeline;

/// Maximum allocation size to prevent OOM.
const MAX_ALLOC: usize = 65536;

/// Maximum number of live allocations to bound memory usage.
const MAX_LIVE: usize = 256;

/// Maximum number of operations per fuzz input to bound execution time.
const MAX_OPS: usize = 512;

/// A single allocator operation driven by the fuzzer.
#[derive(Debug, Arbitrary)]
enum AllocOp {
    /// Allocate with default alignment.
    Alloc { size: u16 },
    /// Allocate with specific alignment (power of 2).
    AllocAligned { size: u16, align_shift: u8 },
    /// Free the allocation at the given index (modulo live count).
    Free { index: u8 },
    /// Free the most recently allocated pointer.
    FreeLast,
    /// Attempt double-free on the last freed pointer (should be handled gracefully).
    DoubleFree,
    /// Validate a live allocation pointer.
    ValidateLive { index: u8 },
    /// Validate a completely bogus pointer value.
    ValidateBogus { addr_lo: u32 },
    /// Look up a live allocation in the arena.
    Lookup { index: u8 },
    /// Check arena containment for a live pointer.
    Contains { index: u8 },
    /// Check arena containment for a bogus address.
    ContainsBogus { addr_lo: u32 },
    /// Allocate through the core allocator state machine.
    StateMalloc { size: u16 },
    /// calloc through the core allocator state machine.
    StateCalloc { count: u8, size: u16 },
    /// realloc a live state allocation.
    StateRealloc { index: u8, new_size: u16 },
    /// realloc a foreign/unknown pointer.
    StateReallocBogus { addr_lo: u32, new_size: u16 },
    /// free a live state allocation.
    StateFree { index: u8 },
    /// free an unknown pointer in the state allocator.
    StateFreeBogus { addr_lo: u32 },
    /// Query allocator lookup for a live pointer.
    StateLookup { index: u8 },
    /// Force a calloc overflow path.
    StateCallocOverflow,
}

/// Structured fuzz input: a sequence of allocator operations.
#[derive(Debug, Arbitrary)]
struct AllocFuzzInput {
    ops: Vec<AllocOp>,
}

fn synthetic_state_bogus(addr_lo: u32, state_live: &[usize]) -> usize {
    let mut candidate = ((addr_lo as usize).wrapping_mul(4099) | 1).max(1);
    while state_live.contains(&candidate) {
        candidate = candidate.wrapping_add(8191).max(1);
    }
    candidate
}

fuzz_target!(|input: AllocFuzzInput| {
    let pipeline = ValidationPipeline::new();
    let mut state = MallocState::new();
    let mut live: Vec<*mut u8> = Vec::new();
    let mut last_freed: Option<*mut u8> = None;
    let mut state_live: Vec<usize> = Vec::new();

    let ops = &input.ops[..input.ops.len().min(MAX_OPS)];

    for op in ops {
        match op {
            AllocOp::Alloc { size } => {
                if live.len() >= MAX_LIVE {
                    continue;
                }
                let sz = (*size as usize).clamp(1, MAX_ALLOC);
                if let Some(ptr) = pipeline.arena.allocate(sz) {
                    assert!(!ptr.is_null());
                    // Verify the pointer is in the arena
                    assert!(pipeline.arena.contains(ptr as usize));
                    // Verify lookup succeeds
                    let slot = pipeline.arena.lookup(ptr as usize);
                    assert!(slot.is_some());
                    if let Some(s) = slot {
                        assert_eq!(s.user_base, ptr as usize);
                        assert_eq!(s.user_size, sz);
                    }
                    live.push(ptr);
                }
            }

            AllocOp::AllocAligned { size, align_shift } => {
                if live.len() >= MAX_LIVE {
                    continue;
                }
                let sz = (*size as usize).clamp(1, MAX_ALLOC);
                // Alignment must be power of 2; shift 4..12 gives 16..4096
                let shift = (*align_shift % 9) + 4; // 4..12
                let align = 1usize << shift;
                if let Some(ptr) = pipeline.arena.allocate_aligned(sz, align) {
                    assert!(!ptr.is_null());
                    // User pointer should be aligned
                    assert_eq!(
                        (ptr as usize) % align,
                        0,
                        "allocate_aligned({sz}, {align}) returned unaligned pointer"
                    );
                    assert!(pipeline.arena.contains(ptr as usize));
                    live.push(ptr);
                }
            }

            AllocOp::Free { index } => {
                if live.is_empty() {
                    continue;
                }
                let idx = (*index as usize) % live.len();
                let ptr = live.swap_remove(idx);
                let (result, _drained) = pipeline.arena.free(ptr);
                match result {
                    FreeResult::Freed | FreeResult::FreedWithCanaryCorruption => {}
                    other => {
                        panic!("Unexpected free result for valid ptr: {other:?}");
                    }
                }
                last_freed = Some(ptr);
            }

            AllocOp::FreeLast => {
                if let Some(ptr) = live.pop() {
                    let (result, _drained) = pipeline.arena.free(ptr);
                    match result {
                        FreeResult::Freed | FreeResult::FreedWithCanaryCorruption => {}
                        other => {
                            panic!("Unexpected free result for valid ptr: {other:?}");
                        }
                    }
                    last_freed = Some(ptr);
                }
            }

            AllocOp::DoubleFree => {
                if let Some(ptr) = last_freed {
                    // Double-free should be detected, not crash
                    let (result, _drained) = pipeline.arena.free(ptr);
                    match result {
                        FreeResult::DoubleFree
                        | FreeResult::ForeignPointer
                        | FreeResult::InvalidPointer
                        | FreeResult::Freed
                        | FreeResult::FreedWithCanaryCorruption => {
                            // All of these are acceptable responses to double-free
                        }
                    }
                }
            }

            AllocOp::ValidateLive { index } => {
                if live.is_empty() {
                    continue;
                }
                let idx = (*index as usize) % live.len();
                let ptr = live[idx];
                let outcome = pipeline.validate(ptr as usize);
                // Just ensure no panic — outcome varies by pipeline state
                let _ = outcome;
            }

            AllocOp::ValidateBogus { addr_lo } => {
                // Validate a completely made-up pointer
                let addr = *addr_lo as usize;
                let outcome = pipeline.validate(addr);
                // Should not panic, regardless of result
                let _ = outcome;
            }

            AllocOp::Lookup { index } => {
                if live.is_empty() {
                    continue;
                }
                let idx = (*index as usize) % live.len();
                let ptr = live[idx];
                let slot = pipeline.arena.lookup(ptr as usize);
                // Live pointer should always be found
                assert!(
                    slot.is_some(),
                    "lookup failed for live allocation at {ptr:?}"
                );
            }

            AllocOp::Contains { index } => {
                if live.is_empty() {
                    continue;
                }
                let idx = (*index as usize) % live.len();
                let ptr = live[idx];
                assert!(
                    pipeline.arena.contains(ptr as usize),
                    "contains() returned false for live allocation at {ptr:?}"
                );
            }

            AllocOp::ContainsBogus { addr_lo } => {
                // Bogus address — should not panic
                let _ = pipeline.arena.contains(*addr_lo as usize);
            }

            AllocOp::StateMalloc { size } => {
                if state_live.len() >= MAX_LIVE {
                    continue;
                }
                let sz = (*size as usize).min(MAX_ALLOC);
                if let Some(ptr) = state.malloc(sz) {
                    state_live.push(ptr);
                    assert!(state.lookup(ptr).is_some());
                }
            }

            AllocOp::StateCalloc { count, size } => {
                if state_live.len() >= MAX_LIVE {
                    continue;
                }
                let ct = (*count as usize).max(1);
                let sz = (*size as usize).min(MAX_ALLOC / ct.max(1));
                if let Some(ptr) = state.calloc(ct, sz) {
                    state_live.push(ptr);
                    assert!(state.lookup(ptr).is_some());
                }
            }

            AllocOp::StateRealloc { index, new_size } => {
                if state_live.is_empty() {
                    continue;
                }
                let idx = (*index as usize) % state_live.len();
                let old_ptr = state_live[idx];
                let requested = (*new_size as usize).min(MAX_ALLOC);
                if let Some(new_ptr) = state.realloc(old_ptr, requested) {
                    state_live[idx] = new_ptr;
                    let expected_size = requested.max(1);
                    assert_eq!(state.lookup(new_ptr), Some(expected_size));
                } else if state.lookup(old_ptr).is_none() {
                    state_live.swap_remove(idx);
                }
            }

            AllocOp::StateReallocBogus { addr_lo, new_size } => {
                if state_live.len() >= MAX_LIVE {
                    continue;
                }
                let bogus = synthetic_state_bogus(*addr_lo, &state_live);
                let requested = (*new_size as usize).min(MAX_ALLOC);
                if let Some(new_ptr) = state.realloc(bogus, requested) {
                    state_live.push(new_ptr);
                    assert_eq!(state.lookup(new_ptr), Some(requested.max(1)));
                }
            }

            AllocOp::StateFree { index } => {
                if state_live.is_empty() {
                    continue;
                }
                let idx = (*index as usize) % state_live.len();
                let ptr = state_live.swap_remove(idx);
                state.free(ptr);
                assert!(state.lookup(ptr).is_none());
            }

            AllocOp::StateFreeBogus { addr_lo } => {
                state.free(synthetic_state_bogus(*addr_lo, &state_live));
            }

            AllocOp::StateLookup { index } => {
                if state_live.is_empty() {
                    continue;
                }
                let idx = (*index as usize) % state_live.len();
                let ptr = state_live[idx];
                assert!(state.lookup(ptr).is_some());
            }

            AllocOp::StateCallocOverflow => {
                let _ = state.calloc(usize::MAX, 2);
            }
        }

        let expected_total = state_live.len();
        assert_eq!(state.active_count(), expected_total);
        for ptr in &state_live {
            assert!(state.lookup(*ptr).is_some());
        }
    }

    // Clean up: free all remaining live allocations
    for ptr in &live {
        let (result, _drained) = pipeline.arena.free(*ptr);
        match result {
            FreeResult::Freed | FreeResult::FreedWithCanaryCorruption => {}
            other => {
                panic!("Unexpected free result during cleanup: {other:?}");
            }
        }
    }

    for ptr in &state_live {
        state.free(*ptr);
        assert!(state.lookup(*ptr).is_none());
    }
    assert_eq!(state.active_count(), 0);
});
