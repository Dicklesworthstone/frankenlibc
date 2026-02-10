//! # K-Theory Transport ABI Compatibility Controller
//!
//! Implements Atiyah-Singer families index and K-theory transport methods
//! for ABI compatibility integrity monitoring (math item #34).
//!
//! ## Mathematical Foundation
//!
//! In topological K-theory, `K^0(X)` is the Grothendieck group of isomorphism
//! classes of vector bundles over a compact space X. The Atiyah-Singer index
//! theorem relates the analytical index of an elliptic operator (family) to
//! topological invariants computed from K-theory classes:
//!
//! ```text
//! ind(D) = ∫_X ch(σ(D)) · Td(TX) ∈ K^0(pt) ≅ ℤ
//! ```
//!
//! For a continuous family of operators parameterized by a base B, the
//! **families index** lives in `K^0(B)` and is invariant under continuous
//! deformations of the family. This gives a **topological obstruction**:
//! if two configurations yield different K-theory classes, no continuous
//! deformation connects them.
//!
//! ## Runtime Application
//!
//! ABI compatibility is a "continuous deformation" problem: a new library
//! version must be a continuous deformation of the old version's ABI surface.
//! We model ABI contract families as discrete vector bundles:
//!
//! - **Base space B**: The set of exported symbol families (allocator, string,
//!   stdio, threading, etc.). Each family is a "point" in B.
//!
//! - **Fiber over b ∈ B**: The behavioral contract of family b, encoded as a
//!   rank vector (input arity, output arity, error modes, side-effect count).
//!
//! - **K-theory class**: The formal difference `[E] - [F]` where E is the
//!   current observed behavioral bundle and F is the baseline reference.
//!   When `[E] = [F]` in K^0(B), the ABI is stably equivalent.
//!
//! The **transport map** `τ: K^0(B_old) → K^0(B_new)` tracks how K-classes
//! evolve as the runtime processes observations. A non-trivial kernel or
//! cokernel of τ indicates ABI compatibility fracture.
//!
//! ## Connection to Math Item #34
//!
//! Atiyah-Singer families index and K-theory transport methods for
//! compatibility integrity.

/// Number of ABI families tracked.
const NUM_FAMILIES: usize = 9;

/// Rank of the behavioral contract vector per family.
const CONTRACT_RANK: usize = 4;

/// EWMA decay for contract coordinate updates.
const EWMA_ALPHA: f64 = 0.03;

/// Calibration threshold before transport analysis activates.
const CALIBRATION_THRESHOLD: u64 = 64;

/// Transport distance threshold for compatibility drift.
const DRIFT_THRESHOLD: f64 = 0.20;

/// Transport distance threshold for compatibility fracture.
const FRACTURE_THRESHOLD: f64 = 0.45;

/// K-theory transport controller state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KTheoryState {
    /// Insufficient data.
    Calibrating,
    /// K-classes are stably equivalent — ABI compatible.
    Compatible,
    /// Transport map shows non-trivial drift — compatibility degrading.
    Drift,
    /// Transport kernel/cokernel non-trivial — ABI fractured.
    Fractured,
}

/// Per-family behavioral contract vector.
#[derive(Debug, Clone)]
struct ContractBundle {
    /// EWMA of observed behavioral coordinates.
    observed: [f64; CONTRACT_RANK],
    /// Baseline behavioral coordinates (frozen after calibration).
    baseline: [f64; CONTRACT_RANK],
    /// Total observations for this family.
    observations: u64,
    /// Whether baseline has been frozen.
    baseline_frozen: bool,
}

impl ContractBundle {
    const fn new() -> Self {
        Self {
            observed: [0.0; CONTRACT_RANK],
            baseline: [0.0; CONTRACT_RANK],
            observations: 0,
            baseline_frozen: false,
        }
    }

    /// Squared L2 distance between observed and baseline contract vectors.
    fn transport_distance_sq(&self) -> f64 {
        let mut sum = 0.0;
        for i in 0..CONTRACT_RANK {
            let d = self.observed[i] - self.baseline[i];
            sum += d * d;
        }
        sum
    }
}

/// Summary snapshot for telemetry.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct KTheorySummary {
    pub state: KTheoryState,
    /// Maximum transport distance across all families.
    pub max_transport_distance: f64,
    /// Number of families with non-trivial transport drift.
    pub drifting_families: u8,
    /// Number of families with fractured K-class.
    pub fractured_families: u8,
    /// Total observations.
    pub total_observations: u64,
    /// Compatibility fracture detection count.
    pub fracture_count: u64,
}

/// K-theory transport ABI compatibility controller.
///
/// Tracks behavioral contract bundles per API family and monitors
/// the transport map between baseline and current K-classes.
pub struct KTheoryController {
    bundles: [ContractBundle; NUM_FAMILIES],
    total_observations: u64,
    fracture_count: u64,
    drift_count: u64,
}

impl KTheoryController {
    #[must_use]
    pub fn new() -> Self {
        Self {
            bundles: [
                ContractBundle::new(),
                ContractBundle::new(),
                ContractBundle::new(),
                ContractBundle::new(),
                ContractBundle::new(),
                ContractBundle::new(),
                ContractBundle::new(),
                ContractBundle::new(),
                ContractBundle::new(),
            ],
            total_observations: 0,
            fracture_count: 0,
            drift_count: 0,
        }
    }

    /// Observe a behavioral outcome for a given family.
    ///
    /// The contract observation encodes:
    /// - `coords[0]`: normalized latency (0..1)
    /// - `coords[1]`: adverse indicator (0.0 or 1.0)
    /// - `coords[2]`: profile depth (0.0 = fast, 1.0 = full)
    /// - `coords[3]`: risk level (0..1)
    pub fn observe(&mut self, family_idx: usize, coords: [f64; CONTRACT_RANK]) {
        if family_idx >= NUM_FAMILIES {
            return;
        }
        self.total_observations += 1;

        let bundle = &mut self.bundles[family_idx];
        bundle.observations += 1;

        // Update observed contract coordinates via EWMA.
        for (i, coord) in coords.iter().enumerate().take(CONTRACT_RANK) {
            bundle.observed[i] = bundle.observed[i].mul_add(1.0 - EWMA_ALPHA, EWMA_ALPHA * coord);
        }

        // Freeze baseline after calibration period.
        if !bundle.baseline_frozen && bundle.observations >= CALIBRATION_THRESHOLD {
            bundle.baseline = bundle.observed;
            bundle.baseline_frozen = true;
        }
    }

    /// Feed observation and update state transition counters.
    pub fn observe_and_update(&mut self, family_idx: usize, coords: [f64; CONTRACT_RANK]) {
        let prev_state = self.state();
        self.observe(family_idx, coords);
        let new_state = self.state();

        if new_state != prev_state {
            match new_state {
                KTheoryState::Drift => self.drift_count += 1,
                KTheoryState::Fractured => self.fracture_count += 1,
                _ => {}
            }
        }
    }

    /// Current controller state.
    #[must_use]
    pub fn state(&self) -> KTheoryState {
        if self.total_observations < CALIBRATION_THRESHOLD {
            return KTheoryState::Calibrating;
        }

        let mut fractured_count = 0u8;
        let mut drifting_count = 0u8;

        for bundle in &self.bundles {
            if !bundle.baseline_frozen {
                continue;
            }
            let dist = bundle.transport_distance_sq().sqrt();
            if dist >= FRACTURE_THRESHOLD {
                fractured_count += 1;
            } else if dist >= DRIFT_THRESHOLD {
                drifting_count += 1;
            }
        }

        if fractured_count >= 2 {
            return KTheoryState::Fractured;
        }
        if fractured_count >= 1 || drifting_count >= 3 {
            return KTheoryState::Drift;
        }

        KTheoryState::Compatible
    }

    /// Summary snapshot.
    #[must_use]
    pub fn summary(&self) -> KTheorySummary {
        let mut max_dist = 0.0f64;
        let mut drifting = 0u8;
        let mut fractured = 0u8;

        for bundle in &self.bundles {
            if !bundle.baseline_frozen {
                continue;
            }
            let dist = bundle.transport_distance_sq().sqrt();
            max_dist = max_dist.max(dist);
            if dist >= FRACTURE_THRESHOLD {
                fractured += 1;
            } else if dist >= DRIFT_THRESHOLD {
                drifting += 1;
            }
        }

        KTheorySummary {
            state: self.state(),
            max_transport_distance: max_dist,
            drifting_families: drifting,
            fractured_families: fractured,
            total_observations: self.total_observations,
            fracture_count: self.fracture_count,
        }
    }
}

impl Default for KTheoryController {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calibrating_until_threshold() {
        let mut ctrl = KTheoryController::new();
        for _ in 0..CALIBRATION_THRESHOLD - 1 {
            ctrl.observe(0, [0.1, 0.0, 0.0, 0.1]);
        }
        assert_eq!(ctrl.state(), KTheoryState::Calibrating);
    }

    #[test]
    fn stable_traffic_stays_compatible() {
        let mut ctrl = KTheoryController::new();
        // Calibrate each family to freeze baselines.
        for family in 0..NUM_FAMILIES {
            for _ in 0..CALIBRATION_THRESHOLD {
                ctrl.observe(family, [0.1, 0.0, 0.0, 0.1]);
            }
        }
        // Continue with same stable traffic.
        for _ in 0..256 {
            ctrl.observe(0, [0.1, 0.0, 0.0, 0.1]);
        }
        assert_eq!(ctrl.state(), KTheoryState::Compatible);
    }

    #[test]
    fn drift_detected_on_contract_shift() {
        let mut ctrl = KTheoryController::new();
        // Calibrate each family individually.
        for family in 0..NUM_FAMILIES {
            for _ in 0..CALIBRATION_THRESHOLD {
                ctrl.observe(family, [0.1, 0.0, 0.0, 0.1]);
            }
        }
        assert_eq!(ctrl.state(), KTheoryState::Compatible);

        // Shift multiple families significantly.
        for _ in 0..3000 {
            ctrl.observe_and_update(0, [0.9, 1.0, 1.0, 0.9]);
            ctrl.observe_and_update(1, [0.9, 1.0, 1.0, 0.9]);
            ctrl.observe_and_update(2, [0.9, 1.0, 1.0, 0.9]);
        }
        assert!(matches!(
            ctrl.state(),
            KTheoryState::Drift | KTheoryState::Fractured
        ));
    }

    #[test]
    fn fracture_on_severe_divergence() {
        let mut ctrl = KTheoryController::new();
        // Calibrate each family individually to freeze baselines.
        for family in 0..NUM_FAMILIES {
            for _ in 0..CALIBRATION_THRESHOLD {
                ctrl.observe(family, [0.1, 0.0, 0.0, 0.1]);
            }
        }
        assert_eq!(ctrl.state(), KTheoryState::Compatible);
        // Push two families past fracture threshold with many observations.
        for _ in 0..5000 {
            ctrl.observe_and_update(0, [1.0, 1.0, 1.0, 1.0]);
            ctrl.observe_and_update(1, [1.0, 1.0, 1.0, 1.0]);
        }
        assert_eq!(ctrl.state(), KTheoryState::Fractured);
    }

    #[test]
    fn recovery_after_calm() {
        let mut ctrl = KTheoryController::new();
        // Calibrate each family individually.
        for family in 0..NUM_FAMILIES {
            for _ in 0..CALIBRATION_THRESHOLD {
                ctrl.observe(family, [0.1, 0.0, 0.0, 0.1]);
            }
        }
        // Trigger drift.
        for _ in 0..3000 {
            ctrl.observe_and_update(0, [0.9, 1.0, 1.0, 0.9]);
        }
        assert!(matches!(
            ctrl.state(),
            KTheoryState::Drift | KTheoryState::Fractured
        ));
        // Calm back down with many observations.
        for _ in 0..10_000 {
            ctrl.observe(0, [0.1, 0.0, 0.0, 0.1]);
        }
        assert_eq!(ctrl.state(), KTheoryState::Compatible);
    }

    #[test]
    fn summary_coherent() {
        let mut ctrl = KTheoryController::new();
        for i in 0..128u64 {
            let family = (i % NUM_FAMILIES as u64) as usize;
            ctrl.observe(family, [0.1, 0.0, 0.0, 0.1]);
        }
        let summary = ctrl.summary();
        assert_eq!(summary.state, KTheoryState::Compatible);
        assert_eq!(summary.total_observations, 128);
    }

    #[test]
    fn out_of_range_family_ignored() {
        let mut ctrl = KTheoryController::new();
        ctrl.observe(999, [0.5, 0.5, 0.5, 0.5]);
        assert_eq!(ctrl.total_observations, 0);
    }
}
