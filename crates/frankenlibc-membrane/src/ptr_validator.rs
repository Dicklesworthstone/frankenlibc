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
use crate::check_oracle::CheckStage;
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
                mode,
                ApiFamily::PointerValidation,
                ValidationProfile::Fast,
                1,
                false,
            );
            return ValidationOutcome::Null;
        }
        let aligned = addr & 0x7 == 0;
        let recent_page = self.page_oracle.query(addr);
        let raw_order =
            self.runtime_math
                .check_ordering(ApiFamily::PointerValidation, aligned, recent_page);
        let ordering = Self::dependency_safe_order(raw_order);

        let mut elapsed_ns = 1_u64;
        let mut slot: Option<ArenaSlot> = None;
        let mut bloom_negative = false;
        let mut saw_fingerprint = false;
        let mut saw_canary = false;

        for (idx, stage) in ordering.iter().enumerate() {
            match *stage {
                CheckStage::Null => {}
                CheckStage::TlsCache => {
                    elapsed_ns =
                        elapsed_ns.saturating_add(u64::from(CheckStage::TlsCache.cost_ns()));
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
                        self.runtime_math.note_check_order_outcome(
                            mode,
                            ApiFamily::PointerValidation,
                            aligned,
                            recent_page,
                            &ordering,
                            Some(idx),
                        );
                        self.runtime_math.observe_validation_result(
                            mode,
                            ApiFamily::PointerValidation,
                            ValidationProfile::Fast,
                            elapsed_ns,
                            false,
                        );
                        return ValidationOutcome::CachedValid(abs);
                    }
                    MembraneMetrics::inc(&metrics.tls_cache_misses);
                }
                CheckStage::Bloom => {
                    if slot.is_some() {
                        continue;
                    }
                    elapsed_ns = elapsed_ns.saturating_add(u64::from(CheckStage::Bloom.cost_ns()));
                    if !self.bloom.might_contain(addr) {
                        bloom_negative = true;
                        MembraneMetrics::inc(&metrics.bloom_misses);

                        let pre_decision = self
                            .runtime_math
                            .decide(mode, RuntimeContext::pointer_validation(addr, true));

                        // Runtime-math selected fast path for foreign pointers.
                        if !pre_decision.requires_full_validation() && !mode.heals_enabled() {
                            self.runtime_math.note_check_order_outcome(
                                mode,
                                ApiFamily::PointerValidation,
                                aligned,
                                recent_page,
                                &ordering,
                                Some(idx),
                            );
                            self.runtime_math.observe_validation_result(
                                mode,
                                ApiFamily::PointerValidation,
                                pre_decision.profile,
                                elapsed_ns,
                                false,
                            );
                            return ValidationOutcome::Foreign(PointerAbstraction::unknown(addr));
                        }

                        // Runtime-math full profile (or hardened) requires page-oracle cross-check.
                        if !self.page_oracle.query(addr) {
                            elapsed_ns = elapsed_ns.saturating_add(6);
                            self.runtime_math.note_check_order_outcome(
                                mode,
                                ApiFamily::PointerValidation,
                                aligned,
                                recent_page,
                                &ordering,
                                Some(idx),
                            );
                            self.runtime_math.observe_validation_result(
                                mode,
                                ApiFamily::PointerValidation,
                                pre_decision.profile,
                                elapsed_ns,
                                false,
                            );
                            return ValidationOutcome::Foreign(PointerAbstraction::unknown(addr));
                        }
                    } else {
                        MembraneMetrics::inc(&metrics.bloom_hits);
                    }
                }
                CheckStage::Arena => {
                    if slot.is_some() {
                        continue;
                    }
                    elapsed_ns = elapsed_ns.saturating_add(u64::from(CheckStage::Arena.cost_ns()));
                    MembraneMetrics::inc(&metrics.arena_lookups);
                    let Some(found) = self.arena.lookup(addr) else {
                        self.runtime_math.note_check_order_outcome(
                            mode,
                            ApiFamily::PointerValidation,
                            aligned,
                            recent_page,
                            &ordering,
                            Some(idx),
                        );
                        self.runtime_math.observe_validation_result(
                            mode,
                            ApiFamily::PointerValidation,
                            ValidationProfile::Fast,
                            elapsed_ns,
                            false,
                        );
                        return ValidationOutcome::Foreign(PointerAbstraction::unknown(addr));
                    };
                    if !found.state.is_live() {
                        let abs = self.abstraction_from_slot(addr, &found);
                        self.runtime_math.note_check_order_outcome(
                            mode,
                            ApiFamily::PointerValidation,
                            aligned,
                            recent_page,
                            &ordering,
                            Some(idx),
                        );
                        self.runtime_math.observe_validation_result(
                            mode,
                            ApiFamily::PointerValidation,
                            ValidationProfile::Full,
                            elapsed_ns,
                            true,
                        );
                        return ValidationOutcome::TemporalViolation(abs);
                    }
                    slot = Some(found);
                }
                CheckStage::Fingerprint => {
                    if slot.is_some() {
                        elapsed_ns =
                            elapsed_ns.saturating_add(u64::from(CheckStage::Fingerprint.cost_ns()));
                        MembraneMetrics::inc(&metrics.fingerprint_passes);
                        saw_fingerprint = true;
                    }
                }
                CheckStage::Canary => {
                    if slot.is_some() {
                        elapsed_ns =
                            elapsed_ns.saturating_add(u64::from(CheckStage::Canary.cost_ns()));
                        MembraneMetrics::inc(&metrics.canary_passes);
                        saw_canary = true;
                    }
                }
                CheckStage::Bounds => {
                    if slot.is_some() {
                        elapsed_ns =
                            elapsed_ns.saturating_add(u64::from(CheckStage::Bounds.cost_ns()));
                    }
                }
            }
        }

        let Some(slot) = slot else {
            self.runtime_math.note_check_order_outcome(
                mode,
                ApiFamily::PointerValidation,
                aligned,
                recent_page,
                &ordering,
                None,
            );
            self.runtime_math.observe_validation_result(
                mode,
                ApiFamily::PointerValidation,
                ValidationProfile::Fast,
                elapsed_ns,
                false,
            );
            return ValidationOutcome::Foreign(PointerAbstraction::unknown(addr));
        };

        let deep_decision = self.runtime_math.decide(
            mode,
            RuntimeContext::pointer_validation(addr, bloom_negative),
        );

        // Runtime-math fast profile in strict mode skips deep integrity checks.
        if !deep_decision.requires_full_validation() && !mode.heals_enabled() {
            let abs = self.abstraction_from_slot(addr, &slot);
            self.cache_validation(addr, &slot);
            self.runtime_math.note_check_order_outcome(
                mode,
                ApiFamily::PointerValidation,
                aligned,
                recent_page,
                &ordering,
                None,
            );
            self.runtime_math.observe_validation_result(
                mode,
                ApiFamily::PointerValidation,
                deep_decision.profile,
                elapsed_ns,
                false,
            );
            return ValidationOutcome::Validated(abs);
        }

        // If full path is required and these stages were delayed by ordering,
        // force their accounting now so integrity checks remain complete.
        if !saw_fingerprint {
            elapsed_ns = elapsed_ns.saturating_add(u64::from(CheckStage::Fingerprint.cost_ns()));
            MembraneMetrics::inc(&metrics.fingerprint_passes);
        }
        if !saw_canary {
            elapsed_ns = elapsed_ns.saturating_add(u64::from(CheckStage::Canary.cost_ns()));
            MembraneMetrics::inc(&metrics.canary_passes);
        }

        let abs = self.abstraction_from_slot(addr, &slot);
        self.cache_validation(addr, &slot);
        self.runtime_math.note_check_order_outcome(
            mode,
            ApiFamily::PointerValidation,
            aligned,
            recent_page,
            &ordering,
            None,
        );
        self.runtime_math.observe_validation_result(
            mode,
            ApiFamily::PointerValidation,
            deep_decision.profile,
            elapsed_ns,
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

    fn dependency_safe_order(ordering: [CheckStage; 7]) -> [CheckStage; 7] {
        let mut out = [CheckStage::Null; 7];
        let mut n = 0_usize;

        for stage in ordering.iter().copied() {
            if matches!(stage, CheckStage::Null) {
                out[n] = stage;
                n += 1;
                break;
            }
        }
        if n == 0 {
            out[n] = CheckStage::Null;
            n += 1;
        }

        for stage in ordering.iter().copied() {
            if matches!(
                stage,
                CheckStage::TlsCache | CheckStage::Bloom | CheckStage::Arena
            ) {
                out[n] = stage;
                n += 1;
            }
        }
        for stage in ordering.iter().copied() {
            if matches!(
                stage,
                CheckStage::Fingerprint | CheckStage::Canary | CheckStage::Bounds
            ) {
                out[n] = stage;
                n += 1;
            }
        }

        debug_assert_eq!(n, 7);
        out
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
    use crate::check_oracle::CheckStage;
    use crate::lattice::SafetyState;
    use crate::tls_cache::lock_tls_cache_epoch_for_tests;

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
        // Foreign pointers are allowed (Galois property), but must remain Unknown/unbounded.
        assert!(matches!(outcome, ValidationOutcome::Foreign(_)));
        assert!(outcome.can_read());
        assert!(outcome.can_write());
        let abs = outcome.abstraction().expect("foreign abstraction");
        assert_eq!(abs.state, SafetyState::Unknown);
        assert!(abs.alloc_base.is_none());
        assert!(abs.remaining.is_none());
        assert!(abs.generation.is_none());
    }

    #[test]
    fn allocated_pointer_validates() {
        let pipeline = ValidationPipeline::new();
        let ptr = pipeline.allocate(256).expect("alloc");
        let addr = ptr as usize;

        let outcome = pipeline.validate(addr);
        assert!(outcome.can_read());
        assert!(outcome.can_write());

        if let Some(abs) = outcome.abstraction() {
            assert_eq!(abs.state, SafetyState::Valid);
            assert_eq!(abs.remaining, Some(256));
        } else {
            panic!("expected abstraction");
        }

        let result = pipeline.free(ptr);
        assert_eq!(result, FreeResult::Freed);
    }

    #[test]
    fn freed_pointer_detected() {
        let pipeline = ValidationPipeline::new();
        let ptr = pipeline.allocate(128).expect("alloc");
        let addr = ptr as usize;

        let result = pipeline.free(ptr);
        assert_eq!(result, FreeResult::Freed);

        let outcome = pipeline.validate(addr);
        assert!(!outcome.can_read());
        assert!(!outcome.can_write());
    }

    #[test]
    fn cached_validation_faster_on_second_call() {
        let pipeline = ValidationPipeline::new();
        let ptr = pipeline.allocate(512).expect("alloc");
        let addr = ptr as usize;

        {
            // Guard against unrelated concurrent frees in other tests bumping the epoch
            // and causing flaky cache-hit expectations.
            let _epoch_guard = lock_tls_cache_epoch_for_tests();
            // First call — full pipeline
            let _ = pipeline.validate(addr);
            // Second call — should hit TLS cache
            let outcome = pipeline.validate(addr);
            assert!(matches!(outcome, ValidationOutcome::CachedValid(_)));
        }

        let result = pipeline.free(ptr);
        assert_eq!(result, FreeResult::Freed);
    }

    #[test]
    fn tls_cache_does_not_allow_uaf_after_free() {
        let pipeline = ValidationPipeline::new();
        let ptr = pipeline.allocate(64).expect("alloc");
        let addr = ptr as usize;

        {
            let _epoch_guard = lock_tls_cache_epoch_for_tests();
            // Populate TLS cache.
            let _ = pipeline.validate(addr);
            let cached = pipeline.validate(addr);
            assert!(
                matches!(cached, ValidationOutcome::CachedValid(_)),
                "expected TLS cache hit on second validate()"
            );
        }

        let result = pipeline.free(ptr);
        assert_eq!(result, FreeResult::Freed);

        // After free, the TLS cache must not report a stale valid pointer.
        let outcome = pipeline.validate(addr);
        assert!(
            !matches!(outcome, ValidationOutcome::CachedValid(_)),
            "TLS cache returned CachedValid for freed pointer"
        );
        assert!(!outcome.can_read());
        assert!(!outcome.can_write());
    }

    #[test]
    fn foreign_free_reported() {
        let pipeline = ValidationPipeline::new();
        let local = 42_u64;
        let ptr = std::ptr::addr_of!(local) as *mut u64 as *mut u8;
        let result = pipeline.free(ptr);
        assert_eq!(result, FreeResult::ForeignPointer);
    }

    #[test]
    fn double_free_reported() {
        let pipeline = ValidationPipeline::new();
        let ptr = pipeline.allocate(32).expect("alloc");

        let first = pipeline.free(ptr);
        assert_eq!(first, FreeResult::Freed);

        let second = pipeline.free(ptr);
        assert_eq!(second, FreeResult::DoubleFree);
    }

    #[test]
    #[allow(unsafe_code)]
    fn canary_corruption_detected_via_pipeline_free() {
        let pipeline = ValidationPipeline::new();
        let size = 32_usize;
        let ptr = pipeline.allocate(size).expect("alloc");
        let addr = ptr as usize;

        // Corrupt trailing canary by writing past the user buffer.
        // SAFETY: Intentional out-of-bounds write to verify canary detection.
        unsafe {
            std::ptr::write_bytes(ptr.add(size), 0xFF, CANARY_SIZE);
        }

        let result = pipeline.free(ptr);
        assert_eq!(result, FreeResult::FreedWithCanaryCorruption);

        // Canary corruption is still a free; pointer is quarantined and must not be readable/writable.
        let outcome = pipeline.validate(addr);
        assert!(!outcome.can_read());
        assert!(!outcome.can_write());
        assert!(
            !matches!(outcome, ValidationOutcome::CachedValid(_)),
            "must not yield CachedValid for freed/corrupted pointer"
        );
    }

    #[test]
    fn dependency_safe_order_delays_deep_checks_until_after_arena() {
        let scrambled = [
            CheckStage::Null,
            CheckStage::Fingerprint,
            CheckStage::Canary,
            CheckStage::Bounds,
            CheckStage::TlsCache,
            CheckStage::Bloom,
            CheckStage::Arena,
        ];
        let ordered = ValidationPipeline::dependency_safe_order(scrambled);
        let arena_idx = ordered
            .iter()
            .position(|s| matches!(s, CheckStage::Arena))
            .expect("arena in ordering");
        let fingerprint_idx = ordered
            .iter()
            .position(|s| matches!(s, CheckStage::Fingerprint))
            .expect("fingerprint in ordering");
        let canary_idx = ordered
            .iter()
            .position(|s| matches!(s, CheckStage::Canary))
            .expect("canary in ordering");
        let bounds_idx = ordered
            .iter()
            .position(|s| matches!(s, CheckStage::Bounds))
            .expect("bounds in ordering");
        assert!(arena_idx < fingerprint_idx);
        assert!(arena_idx < canary_idx);
        assert!(arena_idx < bounds_idx);
    }
}
