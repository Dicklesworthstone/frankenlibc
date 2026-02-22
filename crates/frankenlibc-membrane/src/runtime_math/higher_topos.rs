//! # Higher-Topos Internal Logic and Descent Diagnostics
//!
//! Monitors locale/catalog coherence via higher-categorical descent
//! conditions, targeting the i18n catalog stack (`intl`, `catgets`,
//! `localedata`) where fallback/version incoherence and catalog/version
//! skew are the primary failure modes.
//!
//! ## Mathematical Foundation
//!
//! A **locale fallback chain** (e.g., `en_US.UTF-8 -> en_US -> en -> C`)
//! forms a finite category whose nerve is a simplicial set. The
//! **descent condition** (higher-topos internal logic) requires that
//! restriction maps along this chain be compatible: if locale scopes
//! `U` and `V` overlap and their resolutions agree on `U cap V`, then
//! the gluing axiom produces a unique consistent global section.
//!
//! Formally, for a presheaf `F` on the locale category `C`, the
//! sheaf condition requires the following diagram to be an equalizer:
//!
//! ```text
//! F(U cup V) --> F(U) x F(V) ===> F(U cap V)
//! ```
//!
//! A **descent datum** for a covering `{U_i -> X}` is an assignment of
//! objects `x_i in F(U_i)` together with isomorphisms on overlaps:
//!
//! ```text
//! phi_{ij}: x_i |_{U_ij} ~= x_j |_{U_ij}
//! ```
//!
//! satisfying the cocycle condition `phi_{jk} . phi_{ij} = phi_{ik}`
//! on triple overlaps. A **descent violation** occurs when this cocycle
//! condition fails — concretely, when the same locale key resolves to
//! different values through different fallback paths.
//!
//! ## Runtime Compact Implementation
//!
//! The controller maintains a fixed-size hash table of locale scope
//! slots (64 entries, hash-indexed). Each slot records the last known
//! resolution hash for that scope. When a new observation arrives, the
//! controller checks whether the scope's resolution is consistent with
//! prior observations (coherence witness). Violations are tracked via
//! an EWMA anomaly rate, and state transitions follow threshold logic.
//!
//! ## Connection to Math Item #42
//!
//! Higher-topos internal logic and descent diagnostics for
//! locale/catalog coherence proofs.

#![deny(unsafe_code)]

/// Number of warmup observations before leaving `Calibrating` state.
const WARMUP_COUNT: u64 = 32;

/// Fixed-size locale slot table (hash-indexed).
const MAX_LOCALES: usize = 64;

/// EWMA violation rate threshold for `DescentViolation` state.
const VIOLATION_THRESHOLD: f64 = 0.05;

/// EWMA violation rate threshold for `Incoherent` state.
const INCOHERENCE_THRESHOLD: f64 = 0.15;

/// EWMA decay factor (alpha).
const EWMA_ALPHA: f64 = 0.02;

/// State of the higher-topos descent monitor.
///
/// Tracks whether locale/catalog resolution satisfies the sheaf
/// (descent) condition or has entered an incoherent regime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToposState {
    /// Fewer than `WARMUP_COUNT` observations; insufficient data.
    Calibrating,
    /// Descent condition satisfied; violation rate below threshold.
    Coherent,
    /// Recent descent violations detected; rate > `VIOLATION_THRESHOLD`.
    DescentViolation,
    /// Sustained high violation rate; coherence breakdown (rate > `INCOHERENCE_THRESHOLD`).
    Incoherent,
}

/// Point-in-time summary of descent diagnostics.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ToposSummary {
    /// Current controller state.
    pub state: ToposState,
    /// EWMA of violation rate (0.0 .. 1.0).
    pub violation_rate: f64,
    /// Running XOR-hash of all consistent resolution witnesses.
    pub coherence_witness_hash: u64,
    /// Total descent violations detected.
    pub violation_count: u64,
    /// Total observations processed.
    pub total_observations: u64,
    /// Maximum fallback depth observed.
    pub max_fallback_depth: u8,
}

/// A single locale scope slot in the coherence witness table.
#[derive(Debug, Clone, Copy, Default)]
struct LocaleSlot {
    /// Scope hash that occupies this slot (0 = empty).
    scope_hash: u64,
    /// Last observed resolution hash for this scope.
    result_hash: u64,
}

/// Higher-topos descent controller for locale/catalog coherence.
///
/// Monitors the i18n catalog stack for fallback incoherence by
/// maintaining a compact hash-based coherence witness table and
/// tracking the violation rate via EWMA.
pub struct HigherToposController {
    /// Fixed-size locale scope slot table.
    slots: [LocaleSlot; MAX_LOCALES],
    /// Total observations processed.
    total_observations: u64,
    /// Total descent violations detected.
    violation_count: u64,
    /// EWMA of violation rate.
    violation_rate_ewma: f64,
    /// Running XOR coherence witness hash (all consistent resolutions).
    coherence_witness_hash: u64,
    /// Maximum fallback depth observed.
    max_fallback_depth: u8,
    /// Current state.
    state: ToposState,
}

impl HigherToposController {
    /// Create a new controller in `Calibrating` state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            slots: [LocaleSlot::default(); MAX_LOCALES],
            total_observations: 0,
            violation_count: 0,
            violation_rate_ewma: 0.0,
            coherence_witness_hash: 0,
            max_fallback_depth: 0,
            state: ToposState::Calibrating,
        }
    }

    /// Observe a locale resolution event.
    ///
    /// # Arguments
    ///
    /// * `scope_hash` - Hash of the locale scope being resolved (e.g.,
    ///   hash of `"en_US.UTF-8/LC_MESSAGES"`).
    /// * `result_hash` - Hash of the resolution result (e.g., hash of
    ///   the catalog entry value).
    /// * `fallback_depth` - Depth in the fallback chain (0 = exact
    ///   match, 1+ = fallback level).
    pub fn observe(&mut self, scope_hash: u64, result_hash: u64, fallback_depth: u8) {
        self.total_observations += 1;

        if fallback_depth > self.max_fallback_depth {
            self.max_fallback_depth = fallback_depth;
        }

        let is_violation = self.check_and_update_slot(scope_hash, result_hash);

        if is_violation {
            self.violation_count += 1;
        } else {
            // Fold consistent resolution into coherence witness.
            self.coherence_witness_hash = self.coherence_witness_hash.rotate_left(13)
                ^ scope_hash.wrapping_mul(0x517cc1b727220a95)
                ^ result_hash.wrapping_mul(0x6c62272e07bb0142);
        }

        // Update EWMA violation rate.
        let sample = if is_violation { 1.0 } else { 0.0 };
        self.violation_rate_ewma =
            EWMA_ALPHA * sample + (1.0 - EWMA_ALPHA) * self.violation_rate_ewma;

        // State transition logic.
        self.state = self.compute_state();
    }

    /// Current controller state.
    #[must_use]
    pub fn state(&self) -> ToposState {
        self.state
    }

    /// Point-in-time summary of descent diagnostics.
    #[must_use]
    pub fn summary(&self) -> ToposSummary {
        ToposSummary {
            state: self.state,
            violation_rate: self.violation_rate_ewma,
            coherence_witness_hash: self.coherence_witness_hash,
            violation_count: self.violation_count,
            total_observations: self.total_observations,
            max_fallback_depth: self.max_fallback_depth,
        }
    }

    /// Check the slot table and update. Returns `true` if a descent
    /// violation is detected (scope seen before with a different result).
    fn check_and_update_slot(&mut self, scope_hash: u64, result_hash: u64) -> bool {
        let idx = (scope_hash as usize) % MAX_LOCALES;
        let slot = &mut self.slots[idx];

        if slot.scope_hash == 0 {
            // Empty slot: first observation for this scope (or hash bucket).
            slot.scope_hash = scope_hash;
            slot.result_hash = result_hash;
            return false;
        }

        if slot.scope_hash == scope_hash {
            // Same scope: check consistency.
            if slot.result_hash == result_hash {
                // Consistent resolution — descent condition holds.
                false
            } else {
                // Descent violation: same scope, different result.
                // Update slot to latest observation.
                slot.result_hash = result_hash;
                true
            }
        } else {
            // Hash collision: evict and replace (no violation signal).
            slot.scope_hash = scope_hash;
            slot.result_hash = result_hash;
            false
        }
    }

    /// Compute the current state from internal metrics.
    fn compute_state(&self) -> ToposState {
        if self.total_observations < WARMUP_COUNT {
            return ToposState::Calibrating;
        }

        if self.violation_rate_ewma >= INCOHERENCE_THRESHOLD {
            ToposState::Incoherent
        } else if self.violation_rate_ewma >= VIOLATION_THRESHOLD {
            ToposState::DescentViolation
        } else {
            ToposState::Coherent
        }
    }
}

impl Default for HigherToposController {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_calibrating() {
        let ctrl = HigherToposController::new();
        assert_eq!(ctrl.state(), ToposState::Calibrating);
        let s = ctrl.summary();
        assert_eq!(s.total_observations, 0);
        assert_eq!(s.violation_count, 0);
        assert_eq!(s.max_fallback_depth, 0);
        assert!((s.violation_rate - 0.0).abs() < 1e-12);
    }

    #[test]
    fn coherent_with_consistent_resolutions() {
        let mut ctrl = HigherToposController::new();
        // Feed consistent (scope, result) pairs through warmup and beyond.
        for i in 0..128u64 {
            // Each scope always resolves to the same result.
            let scope = i % 16 + 1; // 1..16
            let result = scope * 1000;
            ctrl.observe(scope, result, 0);
        }
        assert_eq!(ctrl.state(), ToposState::Coherent);
        let s = ctrl.summary();
        assert_eq!(s.total_observations, 128);
        assert_eq!(s.violation_count, 0);
        assert!(s.violation_rate < VIOLATION_THRESHOLD);
    }

    #[test]
    fn descent_violation_on_inconsistent_scope() {
        let mut ctrl = HigherToposController::new();
        // Warm up with consistent observations.
        for i in 0..40u64 {
            ctrl.observe(i % 8 + 1, 42, 1);
        }
        assert_eq!(ctrl.state(), ToposState::Coherent);

        // Now produce violations: scope 1 resolves to a different result each time.
        let scope = 1u64;
        for i in 0..100u64 {
            ctrl.observe(scope, 1000 + i, 2);
        }
        // The violation rate should have risen above the threshold.
        assert!(
            ctrl.state() == ToposState::DescentViolation || ctrl.state() == ToposState::Incoherent,
            "expected violation or incoherent, got {:?}",
            ctrl.state()
        );
        assert!(ctrl.summary().violation_count > 0);
    }

    #[test]
    fn incoherent_under_sustained_violations() {
        let mut ctrl = HigherToposController::new();
        // Warm up minimally.
        for i in 0..WARMUP_COUNT {
            ctrl.observe(i + 1, 42, 0);
        }

        // Flood with violations: same scope, always different result.
        // With EWMA alpha=0.02, after enough violations the rate
        // approaches 1.0 which is well above INCOHERENCE_THRESHOLD.
        for i in 0..500u64 {
            ctrl.observe(1, 5000 + i, 3);
        }
        assert_eq!(ctrl.state(), ToposState::Incoherent);
        let s = ctrl.summary();
        assert!(s.violation_rate >= INCOHERENCE_THRESHOLD);
    }

    #[test]
    fn recovery_to_coherent_after_violations_stop() {
        let mut ctrl = HigherToposController::new();
        // Phase 1: warmup with consistent data.
        for i in 0..WARMUP_COUNT {
            ctrl.observe(i + 1, 42, 0);
        }

        // Phase 2: produce violations to push into DescentViolation/Incoherent.
        for i in 0..300u64 {
            ctrl.observe(1, 10000 + i, 1);
        }
        let elevated_state = ctrl.state();
        assert!(
            elevated_state == ToposState::DescentViolation
                || elevated_state == ToposState::Incoherent,
            "expected elevated state, got {:?}",
            elevated_state
        );

        // Phase 3: long run of consistent observations to let EWMA decay.
        // With alpha=0.02, EWMA halves roughly every 34 observations.
        // From rate ~1.0, need ~(ln(0.05/1.0)/ln(0.98)) ~ 148 clean
        // observations to drop below 0.05. Use plenty to be safe.
        for i in 0..1000u64 {
            // Use different scopes to avoid triggering violation on scope 1.
            let scope = (i % 50) + 100;
            ctrl.observe(scope, 42, 0);
        }
        assert_eq!(
            ctrl.state(),
            ToposState::Coherent,
            "expected recovery to Coherent, got {:?} with rate {}",
            ctrl.state(),
            ctrl.summary().violation_rate
        );
    }

    #[test]
    fn zero_depth_observations() {
        let mut ctrl = HigherToposController::new();
        for i in 0..64u64 {
            ctrl.observe(i + 1, 999, 0);
        }
        let s = ctrl.summary();
        assert_eq!(s.max_fallback_depth, 0);
        assert_eq!(s.total_observations, 64);
        assert_eq!(ctrl.state(), ToposState::Coherent);
    }

    #[test]
    fn summary_correctness() {
        let mut ctrl = HigherToposController::new();

        // Feed some observations at various fallback depths.
        ctrl.observe(10, 100, 0);
        ctrl.observe(20, 200, 2);
        ctrl.observe(30, 300, 5);
        ctrl.observe(10, 100, 1); // consistent with prior scope 10

        let s = ctrl.summary();
        assert_eq!(s.total_observations, 4);
        assert_eq!(s.violation_count, 0);
        assert_eq!(s.max_fallback_depth, 5);
        assert_eq!(s.state, ToposState::Calibrating);
        // Coherence witness should be non-zero after consistent observations.
        assert_ne!(s.coherence_witness_hash, 0);

        // Now trigger a violation.
        ctrl.observe(10, 999, 0); // scope 10 was 100, now 999
        let s2 = ctrl.summary();
        assert_eq!(s2.violation_count, 1);
        assert_eq!(s2.total_observations, 5);
    }

    #[test]
    fn state_transition_edges() {
        let mut ctrl = HigherToposController::new();

        // Edge: exactly at WARMUP_COUNT - 1 should still be Calibrating.
        for i in 0..(WARMUP_COUNT - 1) {
            ctrl.observe(i + 1, 42, 0);
        }
        assert_eq!(ctrl.state(), ToposState::Calibrating);

        // Edge: at WARMUP_COUNT should transition to Coherent (no violations).
        ctrl.observe(WARMUP_COUNT, 42, 0);
        assert_eq!(ctrl.state(), ToposState::Coherent);

        // Now push violation rate just above VIOLATION_THRESHOLD.
        // We need enough consecutive violations for EWMA to cross 0.05.
        // Starting from ~0.0, after N violations EWMA ~ 1 - (1-alpha)^N.
        // Solve 1 - 0.98^N = 0.05 => N = ln(0.95)/ln(0.98) ~ 2.5.
        // But we need several more because we also had many clean
        // observations diluting the rate. Use a fresh controller.
        let mut ctrl2 = HigherToposController::new();
        for i in 0..WARMUP_COUNT {
            ctrl2.observe(i + 1, 42, 0);
        }
        assert_eq!(ctrl2.state(), ToposState::Coherent);

        // Feed violations until we cross VIOLATION_THRESHOLD.
        let mut hit_violation = false;
        let mut hit_incoherent = false;
        for i in 0..500u64 {
            ctrl2.observe(1, 50000 + i, 0);
            if ctrl2.state() == ToposState::DescentViolation && !hit_violation {
                hit_violation = true;
            }
            if ctrl2.state() == ToposState::Incoherent && !hit_incoherent {
                hit_incoherent = true;
            }
        }
        assert!(
            hit_violation,
            "should have passed through DescentViolation state"
        );
        assert!(hit_incoherent, "should have reached Incoherent state");
    }

    #[test]
    fn max_fallback_depth_tracking() {
        let mut ctrl = HigherToposController::new();
        ctrl.observe(1, 100, 3);
        assert_eq!(ctrl.summary().max_fallback_depth, 3);
        ctrl.observe(2, 200, 1);
        assert_eq!(ctrl.summary().max_fallback_depth, 3);
        ctrl.observe(3, 300, 7);
        assert_eq!(ctrl.summary().max_fallback_depth, 7);
        ctrl.observe(4, 400, 0);
        assert_eq!(ctrl.summary().max_fallback_depth, 7);
    }
}
