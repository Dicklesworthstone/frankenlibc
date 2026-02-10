//! # Derived-Category t-Structure Bootstrap Ordering Controller
//!
//! Implements derived-category/t-structure decomposition methods for
//! process-bootstrap ordering invariants (math item #38).
//!
//! ## Mathematical Foundation
//!
//! A **t-structure** on a triangulated category D is a pair (D^≤0, D^≥0) of
//! full subcategories satisfying:
//!
//! 1. **Shift compatibility**: D^≤0[1] ⊆ D^≤0 and D^≥0[-1] ⊆ D^≥0.
//! 2. **Orthogonality**: Hom(X, Y) = 0 for X ∈ D^≤0, Y ∈ D^≥1.
//! 3. **Decomposition**: Every X ∈ D fits in a distinguished triangle
//!    `τ^≤0(X) → X → τ^≥1(X) → τ^≤0(X)[1]`.
//!
//! The **heart** A = D^≤0 ∩ D^≥0 is an abelian category. The truncation
//! functors τ^≤n, τ^≥n give a filtration of any object by its cohomology
//! objects H^n(X) ∈ A.
//!
//! For the bounded derived category D^b(A), the standard t-structure has:
//! - D^≤0 = complexes with H^n = 0 for n > 0
//! - D^≥0 = complexes with H^n = 0 for n < 0
//!
//! ## Runtime Application
//!
//! Process bootstrap (csu, TLS init, auxv parsing, secure mode) forms a
//! directed dependency DAG. We model this as a bounded complex in D^b(A):
//!
//! - **Objects (stages)**: Each bootstrap stage is a degree-n object in the
//!   complex. Lower degree = earlier in the bootstrap order.
//!
//! - **Morphisms (dependencies)**: A dependency S_i → S_j is a morphism
//!   between objects at appropriate degrees.
//!
//! - **t-structure filtration**: The standard t-structure truncates the
//!   bootstrap complex at each degree, giving a strict ordering invariant:
//!   stage at degree n must complete before degree n+1 begins.
//!
//! - **Violation detection**: An out-of-order execution appears as a
//!   non-zero morphism from D^≥1 to D^≤0, violating orthogonality.
//!   This is our runtime invariant monitor.
//!
//! ## Connection to Math Item #38
//!
//! Derived-category/t-structure decomposition methods for process-bootstrap
//! ordering invariants.

/// Maximum number of bootstrap stages tracked.
const MAX_STAGES: usize = 8;

/// EWMA decay for ordering violation rates.
const EWMA_ALPHA: f64 = 0.02;

/// Calibration threshold.
const CALIBRATION_THRESHOLD: u64 = 32;

/// Ordering violation rate threshold for minor disorder.
const DISORDER_THRESHOLD: f64 = 0.15;

/// Ordering violation rate threshold for severe violation.
const SEVERE_THRESHOLD: f64 = 0.35;

/// Bootstrap stage degree in the t-structure filtration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct StageDegree(pub u8);

/// Derived-category t-structure controller state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TStructureState {
    /// Insufficient data.
    Calibrating,
    /// All stage orderings satisfy the t-structure filtration.
    WellOrdered,
    /// Minor ordering violations — some stages slightly out of order.
    Disorder,
    /// Severe t-structure violation — orthogonality broken.
    OrthogonalityViolation,
}

/// Per-stage tracking state.
#[derive(Debug, Clone)]
struct StageTracker {
    /// Assigned degree in the t-structure filtration.
    degree: u8,
    /// EWMA of out-of-order execution events.
    violation_rate: f64,
    /// Total observations for this stage.
    observations: u64,
    /// Out-of-order executions (predecessor not complete).
    violations: u64,
    /// Highest predecessor degree observed as incomplete when this stage runs.
    max_incomplete_predecessor: Option<u8>,
}

impl StageTracker {
    const fn new(degree: u8) -> Self {
        Self {
            degree,
            violation_rate: 0.0,
            observations: 0,
            violations: 0,
            max_incomplete_predecessor: None,
        }
    }
}

/// Summary snapshot for telemetry.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TStructureSummary {
    pub state: TStructureState,
    /// Maximum violation rate across all stages.
    pub max_violation_rate: f64,
    /// Number of stages with non-zero violation rate.
    pub disordered_stages: u8,
    /// Total ordering violations.
    pub total_violations: u64,
    /// Total observations.
    pub total_observations: u64,
    /// Orthogonality violation count (state transitions to severe).
    pub orthogonality_violation_count: u64,
}

/// Derived-category t-structure bootstrap ordering controller.
///
/// Monitors that bootstrap stage execution respects the degree filtration
/// imposed by the standard t-structure on the bootstrap complex.
pub struct TStructureController {
    stages: [StageTracker; MAX_STAGES],
    /// Bitset: bit k set iff stage k has been observed to complete.
    completed_mask: u8,
    /// Highest degree observed to have completed in current cycle.
    max_completed_degree: u8,
    total_observations: u64,
    orthogonality_violation_count: u64,
    disorder_count: u64,
}

impl TStructureController {
    #[must_use]
    pub fn new() -> Self {
        Self {
            stages: [
                StageTracker::new(0),
                StageTracker::new(1),
                StageTracker::new(2),
                StageTracker::new(3),
                StageTracker::new(4),
                StageTracker::new(5),
                StageTracker::new(6),
                StageTracker::new(7),
            ],
            completed_mask: 0,
            max_completed_degree: 0,
            total_observations: 0,
            orthogonality_violation_count: 0,
            disorder_count: 0,
        }
    }

    /// Observe a stage execution event.
    ///
    /// `stage_idx` is the stage index (0..MAX_STAGES).
    /// `predecessors_complete` indicates whether all predecessor stages
    /// (those with lower degree) have completed.
    pub fn observe(&mut self, stage_idx: usize, predecessors_complete: bool) {
        if stage_idx >= MAX_STAGES {
            return;
        }
        self.total_observations += 1;

        let tracker = &mut self.stages[stage_idx];
        tracker.observations += 1;

        if !predecessors_complete {
            tracker.violations += 1;
            // Record the violation in the EWMA.
            tracker.violation_rate = tracker.violation_rate.mul_add(1.0 - EWMA_ALPHA, EWMA_ALPHA);

            // Track worst incomplete predecessor.
            let degree = tracker.degree;
            if degree > 0 {
                // Check which lower-degree stages are not yet complete.
                for d in (0..degree).rev() {
                    if self.completed_mask & (1u8 << d) == 0 {
                        let tracker = &mut self.stages[stage_idx];
                        match tracker.max_incomplete_predecessor {
                            Some(prev) if d > prev => {
                                tracker.max_incomplete_predecessor = Some(d);
                            }
                            None => {
                                tracker.max_incomplete_predecessor = Some(d);
                            }
                            _ => {}
                        }
                        break;
                    }
                }
            }
        } else {
            tracker.violation_rate *= 1.0 - EWMA_ALPHA;

            // Mark this stage as completed.
            self.completed_mask |= 1u8 << stage_idx;
            if tracker.degree > self.max_completed_degree {
                self.max_completed_degree = tracker.degree;
            }
        }
    }

    /// Feed observation and update state transition counters.
    pub fn observe_and_update(&mut self, stage_idx: usize, predecessors_complete: bool) {
        let prev_state = self.state();
        self.observe(stage_idx, predecessors_complete);
        let new_state = self.state();

        if new_state != prev_state {
            match new_state {
                TStructureState::Disorder => self.disorder_count += 1,
                TStructureState::OrthogonalityViolation => {
                    self.orthogonality_violation_count += 1;
                }
                _ => {}
            }
        }
    }

    /// Reset the completed mask for a new bootstrap cycle.
    pub fn reset_cycle(&mut self) {
        self.completed_mask = 0;
        self.max_completed_degree = 0;
    }

    /// Current controller state.
    #[must_use]
    pub fn state(&self) -> TStructureState {
        if self.total_observations < CALIBRATION_THRESHOLD {
            return TStructureState::Calibrating;
        }

        let mut max_vr = 0.0f64;
        let mut disordered = 0u8;

        for tracker in &self.stages {
            if tracker.observations == 0 {
                continue;
            }
            if tracker.violation_rate > 0.01 {
                disordered += 1;
            }
            max_vr = max_vr.max(tracker.violation_rate);
        }

        if max_vr >= SEVERE_THRESHOLD || disordered >= 4 {
            return TStructureState::OrthogonalityViolation;
        }
        if max_vr >= DISORDER_THRESHOLD || disordered >= 2 {
            return TStructureState::Disorder;
        }

        TStructureState::WellOrdered
    }

    /// Summary snapshot.
    #[must_use]
    pub fn summary(&self) -> TStructureSummary {
        let mut max_vr = 0.0f64;
        let mut disordered = 0u8;
        let mut total_violations = 0u64;

        for tracker in &self.stages {
            if tracker.observations == 0 {
                continue;
            }
            if tracker.violation_rate > 0.01 {
                disordered += 1;
            }
            max_vr = max_vr.max(tracker.violation_rate);
            total_violations += tracker.violations;
        }

        TStructureSummary {
            state: self.state(),
            max_violation_rate: max_vr,
            disordered_stages: disordered,
            total_violations,
            total_observations: self.total_observations,
            orthogonality_violation_count: self.orthogonality_violation_count,
        }
    }
}

impl Default for TStructureController {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calibrating_until_threshold() {
        let mut ctrl = TStructureController::new();
        for _ in 0..CALIBRATION_THRESHOLD - 1 {
            ctrl.observe(0, true);
        }
        assert_eq!(ctrl.state(), TStructureState::Calibrating);
    }

    #[test]
    fn well_ordered_execution() {
        let mut ctrl = TStructureController::new();
        // Execute stages in order, all predecessors complete.
        for _ in 0..64 {
            for stage in 0..MAX_STAGES {
                ctrl.observe(stage, true);
            }
            ctrl.reset_cycle();
        }
        assert_eq!(ctrl.state(), TStructureState::WellOrdered);
    }

    #[test]
    fn disorder_on_out_of_order() {
        let mut ctrl = TStructureController::new();
        // Calibrate with good orderings.
        for _ in 0..16 {
            for stage in 0..MAX_STAGES {
                ctrl.observe(stage, true);
            }
            ctrl.reset_cycle();
        }
        assert_eq!(ctrl.state(), TStructureState::WellOrdered);

        // Now execute with violations.
        for _ in 0..200 {
            ctrl.observe_and_update(3, false); // stage 3 without predecessors
            ctrl.observe_and_update(5, false); // stage 5 without predecessors
        }
        assert!(matches!(
            ctrl.state(),
            TStructureState::Disorder | TStructureState::OrthogonalityViolation
        ));
    }

    #[test]
    fn severe_violation_on_many_disorders() {
        let mut ctrl = TStructureController::new();
        // Calibrate.
        for _ in 0..16 {
            for stage in 0..MAX_STAGES {
                ctrl.observe(stage, true);
            }
            ctrl.reset_cycle();
        }
        // Trigger violations on many stages.
        for _ in 0..500 {
            for stage in 2..MAX_STAGES {
                ctrl.observe_and_update(stage, false);
            }
        }
        assert_eq!(ctrl.state(), TStructureState::OrthogonalityViolation);
    }

    #[test]
    fn recovery_after_good_behavior() {
        let mut ctrl = TStructureController::new();
        // Calibrate.
        for _ in 0..16 {
            for stage in 0..MAX_STAGES {
                ctrl.observe(stage, true);
            }
            ctrl.reset_cycle();
        }
        // Trigger violations.
        for _ in 0..200 {
            ctrl.observe_and_update(4, false);
        }
        assert!(matches!(
            ctrl.state(),
            TStructureState::Disorder | TStructureState::OrthogonalityViolation
        ));
        // Recover with good behavior.
        for _ in 0..3000 {
            for stage in 0..MAX_STAGES {
                ctrl.observe(stage, true);
            }
            ctrl.reset_cycle();
        }
        assert_eq!(ctrl.state(), TStructureState::WellOrdered);
    }

    #[test]
    fn summary_coherent() {
        let mut ctrl = TStructureController::new();
        for _ in 0..64 {
            for stage in 0..MAX_STAGES {
                ctrl.observe(stage, true);
            }
            ctrl.reset_cycle();
        }
        let summary = ctrl.summary();
        assert_eq!(summary.state, TStructureState::WellOrdered);
        assert_eq!(summary.total_violations, 0);
    }

    #[test]
    fn out_of_range_stage_ignored() {
        let mut ctrl = TStructureController::new();
        ctrl.observe(999, true);
        assert_eq!(ctrl.total_observations, 0);
    }

    #[test]
    fn reset_cycle_clears_mask() {
        let mut ctrl = TStructureController::new();
        for stage in 0..MAX_STAGES {
            ctrl.observe(stage, true);
        }
        assert_ne!(ctrl.completed_mask, 0);
        ctrl.reset_cycle();
        assert_eq!(ctrl.completed_mask, 0);
    }
}
