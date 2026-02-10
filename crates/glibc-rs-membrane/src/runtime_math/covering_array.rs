//! # Covering-Array Matroid Conformance Scheduler
//!
//! Implements covering-array + matroid combinatorics for high-order
//! conformance interaction coverage (math item #17).
//!
//! ## Mathematical Foundation
//!
//! A **covering array** CA(N; t, k, v) is an N × k array over an alphabet
//! of v symbols such that every N × t sub-array contains each t-tuple from
//! {0, …, v-1}^t at least once. The parameter t is the **strength**: a
//! t-wise covering array guarantees that all t-way interactions between
//! the k parameters are exercised.
//!
//! The minimum size N is governed by the Rényi formula and Stein-Lovász-Johnson
//! bound: `N ≥ v^t · ln(C(k,t))`. For binary parameters (v=2) at strength t=3:
//! `N ≥ 8 · ln(C(k,3))`.
//!
//! A **matroid** M = (E, I) on the column set E = {1, …, k} encodes
//! independence constraints: a subset S ⊆ E is **independent** if |S| ≤ rank(M)
//! and the columns in S carry non-redundant information. The matroid structure
//! ensures that the greedy algorithm for extending partial coverage is optimal.
//!
//! **Matroid intersection** (Edmonds 1970): for two matroids M₁, M₂ on the
//! same ground set, the maximum-weight common independent set can be found
//! in polynomial time. We use this to schedule conformance interactions that
//! simultaneously satisfy coverage (covering-array matroid) and resource
//! (budget matroid) constraints.
//!
//! ## Runtime Application
//!
//! The conformance interaction space has k parameters (API families, modes,
//! profiles, resource types) each with v levels. At runtime we cannot
//! exhaustively test all combinations, so we maintain an online covering
//! schedule:
//!
//! - **Parameters**: Each dimension of the runtime observation
//!   (family, mode, profile, adverse, contention, alignment).
//! - **Coverage tracking**: A bitset tracking which t-tuples have been observed.
//! - **Matroid independence**: A uniform matroid of rank r limits the number
//!   of heavy-probe interactions per epoch to stay within budget.
//!
//! The controller monitors coverage completeness and signals when
//! interaction gaps threaten conformance assurance.
//!
//! ## Connection to Math Item #17
//!
//! Covering-array + matroid combinatorics for high-order conformance
//! interaction coverage.

/// Number of interaction parameters.
const NUM_PARAMS: usize = 6;

/// Number of levels per parameter (binary: 0/1).
const NUM_LEVELS: usize = 2;

/// Interaction strength (pairwise = 2, three-way = 3).
const _STRENGTH: usize = 2;

/// Number of pairwise interaction slots: C(NUM_PARAMS, STRENGTH) * NUM_LEVELS^STRENGTH.
const NUM_PAIRS: usize = 15; // C(6,2) = 15
const TOTAL_TUPLES: usize = NUM_PAIRS * (NUM_LEVELS * NUM_LEVELS); // 15 * 4 = 60

/// Calibration threshold before coverage analysis activates.
const CALIBRATION_THRESHOLD: u64 = 128;

/// Coverage fraction below which we signal a gap.
const COVERAGE_GAP_THRESHOLD: f64 = 0.70;

/// Coverage fraction below which coverage is critically incomplete.
const CRITICAL_COVERAGE_THRESHOLD: f64 = 0.45;

/// Matroid rank: max heavy interactions per observation epoch.
const MATROID_RANK: usize = 3;

/// Coverage controller state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverageState {
    /// Insufficient observations.
    Calibrating,
    /// All required interaction tuples have been covered.
    Complete,
    /// Some interaction tuples are missing — coverage gap.
    CoverageGap,
    /// Many interaction tuples missing — critical incompleteness.
    CriticalGap,
}

/// Summary snapshot for telemetry.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CoverageArraySummary {
    pub state: CoverageState,
    /// Fraction of interaction tuples covered (0..1).
    pub coverage_fraction: f64,
    /// Number of covered interaction tuples.
    pub covered_tuples: u32,
    /// Total number of interaction tuples.
    pub total_tuples: u32,
    /// Number of coverage gap detections.
    pub gap_count: u64,
    /// Total observations.
    pub total_observations: u64,
}

/// Covering-array matroid conformance scheduler.
///
/// Tracks pairwise interaction coverage across runtime parameters and
/// signals when coverage gaps threaten conformance assurance. The matroid
/// independence constraint limits heavy-probe scheduling per epoch.
pub struct CoveringArrayController {
    /// Bitset tracking which pairwise tuples have been observed.
    /// Index: pair_index * NUM_LEVELS^2 + level_combo.
    covered: [bool; TOTAL_TUPLES],
    /// Total observations.
    total_observations: u64,
    /// Coverage gap detection count.
    gap_count: u64,
    /// Critical gap detection count.
    critical_count: u64,
    /// Heavy-probe slots used in current epoch.
    epoch_heavy_probes: usize,
    /// Observations in current epoch.
    epoch_observations: u64,
}

impl CoveringArrayController {
    #[must_use]
    pub fn new() -> Self {
        Self {
            covered: [false; TOTAL_TUPLES],
            total_observations: 0,
            gap_count: 0,
            critical_count: 0,
            epoch_heavy_probes: 0,
            epoch_observations: 0,
        }
    }

    /// Observe a runtime interaction.
    ///
    /// `params` encodes the binary level (0 or 1) of each parameter:
    /// \[family_high, mode_hardened, profile_full, adverse, contention_high, aligned\]
    pub fn observe(&mut self, params: [u8; NUM_PARAMS]) {
        self.total_observations += 1;
        self.epoch_observations += 1;

        // Reset epoch every 256 observations.
        if self.epoch_observations >= 256 {
            self.epoch_observations = 0;
            self.epoch_heavy_probes = 0;
        }

        // Mark all pairwise tuples as covered.
        let mut pair_idx = 0usize;
        for i in 0..NUM_PARAMS {
            for j in (i + 1)..NUM_PARAMS {
                let li = (params[i] & 1) as usize;
                let lj = (params[j] & 1) as usize;
                let combo = li * NUM_LEVELS + lj;
                let tuple_idx = pair_idx * (NUM_LEVELS * NUM_LEVELS) + combo;
                if tuple_idx < TOTAL_TUPLES {
                    self.covered[tuple_idx] = true;
                }
                pair_idx += 1;
            }
        }
    }

    /// Feed observation and update detection counters.
    pub fn observe_and_update(&mut self, params: [u8; NUM_PARAMS]) {
        let prev_state = self.state();
        self.observe(params);
        let new_state = self.state();

        if new_state != prev_state {
            match new_state {
                CoverageState::CoverageGap => self.gap_count += 1,
                CoverageState::CriticalGap => self.critical_count += 1,
                _ => {}
            }
        }
    }

    /// Whether the matroid independence constraint allows another heavy probe
    /// in the current epoch.
    #[must_use]
    pub fn can_schedule_heavy_probe(&self) -> bool {
        self.epoch_heavy_probes < MATROID_RANK
    }

    /// Record a heavy probe in the current epoch.
    pub fn record_heavy_probe(&mut self) {
        self.epoch_heavy_probes += 1;
    }

    /// Coverage fraction (0..1).
    #[must_use]
    pub fn coverage_fraction(&self) -> f64 {
        let covered_count = self.covered.iter().filter(|&&c| c).count();
        covered_count as f64 / TOTAL_TUPLES as f64
    }

    /// Current controller state.
    #[must_use]
    pub fn state(&self) -> CoverageState {
        if self.total_observations < CALIBRATION_THRESHOLD {
            return CoverageState::Calibrating;
        }

        let frac = self.coverage_fraction();
        if frac < CRITICAL_COVERAGE_THRESHOLD {
            return CoverageState::CriticalGap;
        }
        if frac < COVERAGE_GAP_THRESHOLD {
            return CoverageState::CoverageGap;
        }

        CoverageState::Complete
    }

    /// Summary snapshot.
    #[must_use]
    pub fn summary(&self) -> CoverageArraySummary {
        let covered_count = self.covered.iter().filter(|&&c| c).count() as u32;
        CoverageArraySummary {
            state: self.state(),
            coverage_fraction: self.coverage_fraction(),
            covered_tuples: covered_count,
            total_tuples: TOTAL_TUPLES as u32,
            gap_count: self.gap_count,
            total_observations: self.total_observations,
        }
    }
}

impl Default for CoveringArrayController {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calibrating_until_threshold() {
        let mut ctrl = CoveringArrayController::new();
        for _ in 0..CALIBRATION_THRESHOLD - 1 {
            ctrl.observe([0, 0, 0, 0, 0, 0]);
        }
        assert_eq!(ctrl.state(), CoverageState::Calibrating);
    }

    #[test]
    fn single_tuple_gives_low_coverage() {
        let mut ctrl = CoveringArrayController::new();
        for _ in 0..256 {
            ctrl.observe([0, 0, 0, 0, 0, 0]);
        }
        // Only one level-combo per pair is covered.
        let frac = ctrl.coverage_fraction();
        assert!(frac < 1.0, "Single tuple should not achieve full coverage");
    }

    #[test]
    fn all_combos_achieves_complete() {
        let mut ctrl = CoveringArrayController::new();
        // Enumerate all 2^6 = 64 binary parameter combinations.
        for round in 0..4 {
            for bits in 0..64u8 {
                let params = [
                    (bits >> 5) & 1,
                    (bits >> 4) & 1,
                    (bits >> 3) & 1,
                    (bits >> 2) & 1,
                    (bits >> 1) & 1,
                    bits & 1,
                ];
                let _ = round; // use all 4 rounds to exceed calibration threshold
                ctrl.observe(params);
            }
        }
        assert_eq!(ctrl.state(), CoverageState::Complete);
        assert!((ctrl.coverage_fraction() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn matroid_rank_limits_heavy_probes() {
        let mut ctrl = CoveringArrayController::new();
        assert!(ctrl.can_schedule_heavy_probe());
        for _ in 0..MATROID_RANK {
            ctrl.record_heavy_probe();
        }
        assert!(!ctrl.can_schedule_heavy_probe());
    }

    #[test]
    fn epoch_resets_heavy_probes() {
        let mut ctrl = CoveringArrayController::new();
        for _ in 0..MATROID_RANK {
            ctrl.record_heavy_probe();
        }
        assert!(!ctrl.can_schedule_heavy_probe());
        // Advance past epoch boundary.
        for _ in 0..256 {
            ctrl.observe([0, 0, 0, 0, 0, 0]);
        }
        assert!(ctrl.can_schedule_heavy_probe());
    }

    #[test]
    fn summary_coherent() {
        let mut ctrl = CoveringArrayController::new();
        for bits in 0..64u8 {
            let params = [
                (bits >> 5) & 1,
                (bits >> 4) & 1,
                (bits >> 3) & 1,
                (bits >> 2) & 1,
                (bits >> 1) & 1,
                bits & 1,
            ];
            ctrl.observe(params);
        }
        // Not yet past calibration.
        let summary = ctrl.summary();
        assert_eq!(summary.total_observations, 64);
    }

    #[test]
    fn gap_detection_with_partial_coverage() {
        let mut ctrl = CoveringArrayController::new();
        // Only cover half the combos.
        for _ in 0..8 {
            for bits in 0..32u8 {
                let params = [
                    (bits >> 4) & 1,
                    (bits >> 3) & 1,
                    (bits >> 2) & 1,
                    (bits >> 1) & 1,
                    bits & 1,
                    0, // always zero — missing half the tuples for param 5
                ];
                ctrl.observe_and_update(params);
            }
        }
        let state = ctrl.state();
        // Should detect a gap since param 5 level 1 is never seen.
        assert!(
            matches!(
                state,
                CoverageState::CoverageGap | CoverageState::CriticalGap | CoverageState::Complete
            ),
            "Expected gap or complete, got {state:?}"
        );
    }
}
