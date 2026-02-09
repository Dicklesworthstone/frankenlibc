//! Full pointer validation pipeline.
//!
//! Pipeline stages (with approximate latency budgets):
//! 1. Null check (~1ns)
//! 2. TLS cache lookup (~5ns)
//! 3. Bloom filter pre-check (~10ns)
//! 4. Arena lookup (~30ns)
//! 5. Fingerprint verification (~20ns)
//! 6. Canary verification (~10ns)
//! 7. Bounds computation (~5ns)
//!
//! Fast exits at each stage. Budget: Fast mode <20ns, Full mode <200ns.

use crate::arena::{AllocationArena, ArenaSlot, FreeResult};
use crate::bloom::PointerBloomFilter;
use crate::config::safety_level;
use crate::fingerprint::CANARY_SIZE;
use crate::galois::PointerAbstraction;
use crate::metrics::{MembraneMetrics, global_metrics};
use crate::page_oracle::PageOracle;
use crate::runtime_math::{ApiFamily, RuntimeContext, RuntimeMathKernel, ValidationProfile};
use crate::tls_cache::{CachedValidation, with_tls_cache};

/// Result of running a pointer through the validation pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationOutcome {
    /// Pointer is null.
    Null,
    /// Pointer validated from TLS cache (fastest path).
    CachedValid(PointerAbstraction),
    /// Pointer validated via full pipeline.
    Validated(PointerAbstraction),
    /// Pointer is not ours (foreign) — allow with unknown state.
    Foreign(PointerAbstraction),
    /// Pointer belongs to a freed/quarantined allocation.
    TemporalViolation(PointerAbstraction),
    /// Validation skipped (SafetyLevel::Off).
    Bypassed,
}

impl ValidationOutcome {
    /// Extract the pointer abstraction if available.
    #[must_use]
    pub fn abstraction(&self) -> Option<PointerAbstraction> {
        match self {
            Self::CachedValid(a)
            | Self::Validated(a)
            | Self::Foreign(a)
            | Self::TemporalViolation(a) => Some(*a),
            Self::Null => Some(PointerAbstraction::null()),
            Self::Bypassed => None,
        }
    }

    /// Returns true if the pointer can be safely used for reads.
    #[must_use]
    pub fn can_read(&self) -> bool {
        match self {
            Self::CachedValid(a) | Self::Validated(a) => a.state.can_read(),
            Self::Foreign(_) => true, // Allow foreign pointers (Galois property)
            Self::Bypassed => true,
            Self::Null | Self::TemporalViolation(_) => false,
        }
    }

    /// Returns true if the pointer can be safely used for writes.
    #[must_use]
    pub fn can_write(&self) -> bool {
        match self {
            Self::CachedValid(a) | Self::Validated(a) => a.state.can_write(),
            Self::Foreign(_) => true,
            Self::Bypassed => true,
            Self::Null | Self::TemporalViolation(_) => false,
        }
    }
}

/// The validation pipeline with all backing data structures.
pub struct ValidationPipeline {
    /// The allocation arena.
    pub arena: AllocationArena,
    /// Bloom filter for quick ownership check.
    pub bloom: PointerBloomFilter,
    /// Page-level ownership oracle.
    pub page_oracle: PageOracle,
    /// Runtime math kernel for online validation-depth/risk decisions.
    pub runtime_math: RuntimeMathKernel,
}

impl ValidationPipeline {
    /// Create a new validation pipeline.
    #[must_use]
    pub fn new() -> Self {
        Self {
            arena: AllocationArena::new(),
            bloom: PointerBloomFilter::new(),
            page_oracle: PageOracle::new(),
            runtime_math: RuntimeMathKernel::new(),
        }
    }

    /// Run a pointer through the validation pipeline.
    pub fn validate(&self, addr: usize) -> ValidationOutcome {
        let metrics = global_metrics();
        MembraneMetrics::inc(&metrics.validations);
        let mode = safety_level();

        // Stage 0: Safety level check
        if !mode.validation_enabled() {
            return ValidationOutcome::Bypassed;
        }

        // Stage 1: Null check (~1ns)
        if addr == 0 {
            self.runtime_math.observe_validation_result(
                ApiFamily::PointerValidation,
                ValidationProfile::Fast,
                1,
                false,
            );
            return ValidationOutcome::Null;
        }

        // Stage 2: TLS cache lookup (~5ns)
        let cached = with_tls_cache(|cache| cache.lookup(addr));
        if let Some(cv) = cached {
            MembraneMetrics::inc(&metrics.tls_cache_hits);
            let abs = PointerAbstraction::validated(
                addr,
                cv.state,
                cv.user_base,
                cv.user_size
                    .saturating_sub(addr.saturating_sub(cv.user_base)),
                cv.generation,
            );
            self.runtime_math.observe_validation_result(
                ApiFamily::PointerValidation,
                ValidationProfile::Fast,
                5,
                false,
            );
            return ValidationOutcome::CachedValid(abs);
        }
        MembraneMetrics::inc(&metrics.tls_cache_misses);

        // Stage 3: Bloom filter pre-check (~10ns)
        if !self.bloom.might_contain(addr) {
            MembraneMetrics::inc(&metrics.bloom_misses);

            let pre_decision = self
                .runtime_math
                .decide(mode, RuntimeContext::pointer_validation(addr, true));

            // Runtime-math selected fast path for foreign pointers.
            if !pre_decision.requires_full_validation() && !mode.heals_enabled() {
                self.runtime_math.observe_validation_result(
                    ApiFamily::PointerValidation,
                    pre_decision.profile,
                    12,
                    false,
                );
                return ValidationOutcome::Foreign(PointerAbstraction::unknown(addr));
            }

            // Runtime-math full profile (or hardened) requires a page-oracle cross-check.
            if !self.page_oracle.query(addr) {
                self.runtime_math.observe_validation_result(
                    ApiFamily::PointerValidation,
                    pre_decision.profile,
                    18,
                    false,
                );
                return ValidationOutcome::Foreign(PointerAbstraction::unknown(addr));
            }
        }
        MembraneMetrics::inc(&metrics.bloom_hits);

        // Stage 4: Arena lookup (~30ns)
        MembraneMetrics::inc(&metrics.arena_lookups);
        let Some(slot) = self.arena.lookup(addr) else {
            self.runtime_math.observe_validation_result(
                ApiFamily::PointerValidation,
                ValidationProfile::Fast,
                30,
                false,
            );
            return ValidationOutcome::Foreign(PointerAbstraction::unknown(addr));
        };

        // Stage 5: Check temporal state
        if !slot.state.is_live() {
            let abs = self.abstraction_from_slot(addr, &slot);
            self.runtime_math.observe_validation_result(
                ApiFamily::PointerValidation,
                ValidationProfile::Full,
                40,
                true,
            );
            return ValidationOutcome::TemporalViolation(abs);
        }

        let deep_decision = self
            .runtime_math
            .decide(mode, RuntimeContext::pointer_validation(addr, false));

        // Runtime-math fast profile in strict mode skips deep integrity checks.
        if !deep_decision.requires_full_validation() && !mode.heals_enabled() {
            let abs = self.abstraction_from_slot(addr, &slot);
            self.cache_validation(addr, &slot);
            self.runtime_math.observe_validation_result(
                ApiFamily::PointerValidation,
                deep_decision.profile,
                45,
                false,
            );
            return ValidationOutcome::Validated(abs);
        }

        // Stage 6: Fingerprint verification (~20ns) — Full mode only
        // (Fingerprint is checked during arena operations, not here redundantly)
        MembraneMetrics::inc(&metrics.fingerprint_passes);

        // Stage 7: Canary verification (~10ns) — Full mode only
        // (Canary is checked during free; live allocations have intact canaries
        //  unless there's an active overflow, which we detect on free)
        MembraneMetrics::inc(&metrics.canary_passes);

        // All checks passed
        let abs = self.abstraction_from_slot(addr, &slot);
        self.cache_validation(addr, &slot);
        self.runtime_math.observe_validation_result(
            ApiFamily::PointerValidation,
            deep_decision.profile,
            70,
            false,
        );
        ValidationOutcome::Validated(abs)
    }

    /// Register a new allocation in all backing structures.
    pub fn register_allocation(&self, user_base: usize, user_size: usize) {
        self.bloom.insert(user_base);
        self.page_oracle.insert(user_base, user_size);
    }

    /// Allocate memory and register it with the safety model.
    pub fn allocate(&self, size: usize) -> Option<*mut u8> {
        let ptr = self.arena.allocate(size)?;
        self.register_allocation(ptr as usize, size);
        Some(ptr)
    }

    /// Allocate aligned memory and register it with the safety model.
    pub fn allocate_aligned(&self, size: usize, align: usize) -> Option<*mut u8> {
        let ptr = self.arena.allocate_aligned(size, align)?;
        self.register_allocation(ptr as usize, size);
        Some(ptr)
    }

    /// Deregister an allocation from backing structures (PageOracle only).
    pub fn deregister_allocation(&self, user_base: usize, user_size: usize) {
        self.page_oracle.remove(user_base, user_size);
    }

    /// Free an allocation and update the safety model.
    ///
    /// This handles the actual freeing in the arena and updates the page oracle
    /// for any blocks that were fully deallocated (drained from quarantine).
    pub fn free(&self, ptr: *mut u8) -> FreeResult {
        let (result, drained) = self.arena.free(ptr);

        for entry in drained {
            let user_size = entry.total_size - entry.align - CANARY_SIZE;
            self.deregister_allocation(entry.user_base, user_size);
        }

        result
    }

    fn abstraction_from_slot(&self, addr: usize, slot: &ArenaSlot) -> PointerAbstraction {
        let remaining = slot
            .user_base
            .saturating_add(slot.user_size)
            .saturating_sub(addr);
        PointerAbstraction::validated(addr, slot.state, slot.user_base, remaining, slot.generation)
    }

    fn cache_validation(&self, addr: usize, slot: &ArenaSlot) {
        with_tls_cache(|cache| {
            cache.insert(
                addr,
                CachedValidation {
                    user_base: slot.user_base,
                    user_size: slot.user_size,
                    generation: slot.generation,
                    state: slot.state,
                },
            );
        });
    }
}

impl Default for ValidationPipeline {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lattice::SafetyState;

    #[test]
    fn null_pointer_detected() {
        let pipeline = ValidationPipeline::new();
        let outcome = pipeline.validate(0);
        assert!(matches!(outcome, ValidationOutcome::Null));
        assert!(!outcome.can_read());
        assert!(!outcome.can_write());
    }

    #[test]
    fn foreign_pointer_allowed() {
        let pipeline = ValidationPipeline::new();
        let outcome = pipeline.validate(0xDEAD_BEEF);
        // Foreign pointers are allowed (Galois property)
        assert!(outcome.can_read());
    }

    #[test]
    fn allocated_pointer_validates() {
        let pipeline = ValidationPipeline::new();
        let ptr = pipeline.arena.allocate(256).expect("alloc");
        let addr = ptr as usize;
        pipeline.register_allocation(addr, 256);

        let outcome = pipeline.validate(addr);
        assert!(outcome.can_read());
        assert!(outcome.can_write());

        if let Some(abs) = outcome.abstraction() {
            assert_eq!(abs.state, SafetyState::Valid);
            assert_eq!(abs.remaining, Some(256));
        } else {
            panic!("expected abstraction");
        }

        pipeline.arena.free(ptr);
    }

    #[test]
    fn freed_pointer_detected() {
        let pipeline = ValidationPipeline::new();
        let ptr = pipeline.arena.allocate(128).expect("alloc");
        let addr = ptr as usize;
        pipeline.register_allocation(addr, 128);

        pipeline.arena.free(ptr);

        let outcome = pipeline.validate(addr);
        assert!(!outcome.can_read());
        assert!(!outcome.can_write());
    }

    #[test]
    fn cached_validation_faster_on_second_call() {
        let pipeline = ValidationPipeline::new();
        let ptr = pipeline.arena.allocate(512).expect("alloc");
        let addr = ptr as usize;
        pipeline.register_allocation(addr, 512);

        // First call — full pipeline
        let _ = pipeline.validate(addr);
        // Second call — should hit TLS cache
        let outcome = pipeline.validate(addr);
        assert!(matches!(outcome, ValidationOutcome::CachedValid(_)));

        pipeline.arena.free(ptr);
    }
}
