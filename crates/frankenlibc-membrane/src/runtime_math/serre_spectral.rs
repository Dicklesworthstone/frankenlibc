//! # Serre Spectral Sequence Multi-Layer Invariant Lifting Controller
//!
//! Implements Serre spectral sequence methods for detecting cross-layer
//! consistency defects between the ABI boundary, membrane, and core
//! implementation layers (math item #32).
//!
//! ## Mathematical Foundation
//!
//! Given a fibration F → E → B, the **Serre spectral sequence** is a
//! sequence of bigraded differential modules (E_r, d_r) converging to
//! the homology of E:
//!
//! ```text
//! E_2^{p,q} = H_p(B; H_q(F))  ⟹  H_{p+q}(E)
//! ```
//!
//! The key structure is the sequence of **differentials** d_r : E_r^{p,q} →
//! E_r^{p-r,q+r-1} on each "page" E_r. When d_r ≠ 0, there is a
//! **non-trivial extension** — information from the fiber does not lift
//! cleanly to the total space.
//!
//! **Convergence**: The spectral sequence converges when all differentials
//! vanish (E_r = E_{r+1} for all subsequent r). At this point, the
//! associated graded of H_*(E) is fully determined.
//!
//! ## Runtime Application
//!
//! The frankenlibc layered architecture forms a fibration:
//!
//! ```text
//! Core (fiber F) → Membrane (total space E) → ABI (base B)
//! ```
//!
//! - **E_2 page**: The "expected" behavior when core implementations
//!   compose cleanly through the membrane to the ABI surface.
//!
//! - **Non-trivial d_2 differential**: A core function's behavior changes
//!   when lifted through the membrane (e.g., safety checks alter return
//!   values or semantics in ways that don't compose).
//!
//! - **Extension problem**: Even if each layer is individually correct,
//!   their composition may have non-trivial extensions — behaviors that
//!   emerge only at the total space level.
//!
//! We track a discrete approximation: for each (layer_pair, invariant_class)
//! we maintain a "differential density" measuring how often behaviors
//! fail to lift cleanly. When differentials are persistently non-zero,
//! we detect a **lifting failure**.
//!
//! ## Convergence Monitoring
//!
//! We track the E_2 → E_3 → E_∞ progression by monitoring whether
//! differential densities decrease across successive observation windows.
//! If the sequence "converges" (differentials approach zero), the layers
//! are consistent. If differentials persist or grow, there is a
//! structural cross-layer defect.
//!
//! ## Connection to Math Item #32
//!
//! Serre spectral-sequence methods for multi-layer invariant lifting.

/// Number of layer pairs tracked (ABI→Membrane, Membrane→Core, ABI→Core).
const NUM_LAYER_PAIRS: usize = 3;

/// Number of invariant classes per layer pair.
const NUM_INVARIANT_CLASSES: usize = 4;

/// Total bigraded cells in the E_2 page.
const TOTAL_CELLS: usize = NUM_LAYER_PAIRS * NUM_INVARIANT_CLASSES;

/// Observation window for differential density tracking.
const SPECTRAL_WINDOW: usize = 256;

/// Calibration threshold.
const CALIBRATION_THRESHOLD: u64 = 64;

/// EWMA decay for differential density.
const EWMA_ALPHA: f64 = 0.015;

/// Threshold: differential density above this indicates non-trivial extension.
const DIFFERENTIAL_THRESHOLD: f64 = 0.10;

/// Threshold: if max differential grows across pages, lifting is failing.
const LIFTING_FAILURE_THRESHOLD: f64 = 0.30;

/// Threshold: convergence — max differential below this on all cells.
const CONVERGENCE_THRESHOLD: f64 = 0.03;

/// Layer pair in the fibration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum LayerPair {
    /// ABI → Membrane transition.
    AbiToMembrane = 0,
    /// Membrane → Core transition.
    MembraneToCore = 1,
    /// ABI → Core (full composition).
    AbiToCore = 2,
}

/// Invariant class being tracked across layers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum InvariantClass {
    /// Return value / errno consistency.
    ReturnSemantics = 0,
    /// Side-effect ordering (write order, signal delivery order).
    SideEffectOrder = 1,
    /// Resource lifecycle (allocation/deallocation pairing).
    ResourceLifecycle = 2,
    /// Error handling / recovery path consistency.
    ErrorRecovery = 3,
}

/// Spectral sequence controller state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpectralSequenceState {
    /// Insufficient data.
    Calibrating,
    /// All differentials near zero — layers compose cleanly.
    Converged,
    /// Non-trivial differentials detected but bounded.
    LiftingFailure,
    /// Differentials growing — sequence diverging, structural defect.
    Collapsed,
}

/// Summary snapshot for telemetry.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SpectralSequenceSummary {
    /// Current state.
    pub state: SpectralSequenceState,
    /// Maximum differential density across all bigraded cells.
    pub max_differential: f64,
    /// Mean differential density.
    pub mean_differential: f64,
    /// Number of cells with non-trivial differentials.
    pub nontrivial_cells: u8,
    /// Convergence trend: negative = converging, positive = diverging.
    pub convergence_trend: f64,
    /// Lifting failure count.
    pub lifting_failure_count: u64,
    /// Collapse count.
    pub collapse_count: u64,
    /// Total observations.
    pub total_observations: u64,
}

/// Per-cell differential state.
#[derive(Debug, Clone)]
struct CellState {
    /// EWMA differential density (rate of lifting failures for this cell).
    differential_density: f64,
    /// Previous-window differential density (for convergence tracking).
    prev_density: f64,
    /// Number of observations for this cell.
    observations: u64,
    /// Number of lifting failures for this cell.
    failures: u64,
}

impl CellState {
    const fn new() -> Self {
        Self {
            differential_density: 0.0,
            prev_density: 0.0,
            observations: 0,
            failures: 0,
        }
    }
}

/// Serre spectral sequence controller.
///
/// Tracks differential densities across the (layer_pair, invariant_class)
/// bigraded complex, detecting non-trivial extensions and convergence
/// failures in the layered architecture.
pub struct SerreSpectralController {
    /// Bigraded cell states: cells[pair * NUM_INVARIANT_CLASSES + class].
    cells: [CellState; TOTAL_CELLS],
    /// Total observations.
    total_observations: u64,
    /// Page counter (incremented every SPECTRAL_WINDOW observations).
    current_page: u64,
    /// Lifting failure count.
    lifting_failure_count: u64,
    /// Collapse count.
    collapse_count: u64,
}

impl SerreSpectralController {
    /// Create a new spectral sequence controller.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cells: std::array::from_fn(|_| CellState::new()),
            total_observations: 0,
            current_page: 2, // Start at E_2 page.
            lifting_failure_count: 0,
            collapse_count: 0,
        }
    }

    /// Observe a cross-layer behavior check.
    ///
    /// `layer_pair` identifies which layer transition is being checked.
    /// `invariant_class` identifies the type of invariant.
    /// `lifted_ok` is true if the behavior lifts cleanly across layers,
    /// false if there is a non-trivial differential (lifting failure).
    pub fn observe(
        &mut self,
        layer_pair: LayerPair,
        invariant_class: InvariantClass,
        lifted_ok: bool,
    ) {
        self.total_observations += 1;

        let idx = (layer_pair as usize) * NUM_INVARIANT_CLASSES + (invariant_class as usize);
        let cell = &mut self.cells[idx];
        cell.observations += 1;
        if !lifted_ok {
            cell.failures += 1;
        }

        let signal = if lifted_ok { 0.0 } else { 1.0 };
        cell.differential_density = super::internal_fma::mul_add(
            cell.differential_density,
            1.0 - EWMA_ALPHA,
            EWMA_ALPHA * signal,
        );

        // Page transition: snapshot previous densities for convergence tracking.
        if self
            .total_observations
            .is_multiple_of(SPECTRAL_WINDOW as u64)
        {
            for c in &mut self.cells {
                c.prev_density = c.differential_density;
            }
            self.current_page += 1;
        }
    }

    /// Current state of the spectral sequence.
    #[must_use]
    pub fn state(&self) -> SpectralSequenceState {
        if self.total_observations < CALIBRATION_THRESHOLD {
            return SpectralSequenceState::Calibrating;
        }

        let max_diff = self
            .cells
            .iter()
            .map(|c| c.differential_density)
            .fold(0.0f64, f64::max);
        let trend = self.convergence_trend();

        // Collapsed: high differentials AND diverging.
        if max_diff >= LIFTING_FAILURE_THRESHOLD && trend > 0.01 {
            return SpectralSequenceState::Collapsed;
        }

        // Lifting failure: non-trivial differentials.
        if max_diff >= DIFFERENTIAL_THRESHOLD {
            return SpectralSequenceState::LiftingFailure;
        }

        // Converged: all differentials near zero.
        if max_diff < CONVERGENCE_THRESHOLD {
            return SpectralSequenceState::Converged;
        }

        // Between convergence and lifting failure: treat as converged
        // if trend is non-positive (converging).
        if trend <= 0.0 {
            SpectralSequenceState::Converged
        } else {
            SpectralSequenceState::LiftingFailure
        }
    }

    /// Convergence trend: average change in differential density across pages.
    /// Negative = converging, positive = diverging.
    fn convergence_trend(&self) -> f64 {
        if self.current_page <= 2 {
            return 0.0;
        }
        let sum: f64 = self
            .cells
            .iter()
            .map(|c| c.differential_density - c.prev_density)
            .sum();
        sum / TOTAL_CELLS as f64
    }

    /// Summary snapshot.
    #[must_use]
    pub fn summary(&self) -> SpectralSequenceSummary {
        let max_diff = self
            .cells
            .iter()
            .map(|c| c.differential_density)
            .fold(0.0f64, f64::max);
        let mean_diff: f64 = self
            .cells
            .iter()
            .map(|c| c.differential_density)
            .sum::<f64>()
            / TOTAL_CELLS as f64;
        let nontrivial = self
            .cells
            .iter()
            .filter(|c| c.differential_density >= DIFFERENTIAL_THRESHOLD)
            .count() as u8;

        SpectralSequenceSummary {
            state: self.state(),
            max_differential: max_diff,
            mean_differential: mean_diff,
            nontrivial_cells: nontrivial,
            convergence_trend: self.convergence_trend(),
            lifting_failure_count: self.lifting_failure_count,
            collapse_count: self.collapse_count,
            total_observations: self.total_observations,
        }
    }

    /// Observe and update counters.
    pub fn observe_and_update(
        &mut self,
        layer_pair: LayerPair,
        invariant_class: InvariantClass,
        lifted_ok: bool,
    ) {
        let prev_state = self.state();
        self.observe(layer_pair, invariant_class, lifted_ok);
        let new_state = self.state();

        if new_state != prev_state {
            match new_state {
                SpectralSequenceState::LiftingFailure => self.lifting_failure_count += 1,
                SpectralSequenceState::Collapsed => self.collapse_count += 1,
                _ => {}
            }
        }
    }

    /// Current page number (E_r).
    #[must_use]
    pub fn current_page(&self) -> u64 {
        self.current_page
    }
}

impl Default for SerreSpectralController {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calibrating_until_threshold() {
        let mut ssc = SerreSpectralController::new();
        for _ in 0..CALIBRATION_THRESHOLD - 1 {
            ssc.observe(
                LayerPair::AbiToMembrane,
                InvariantClass::ReturnSemantics,
                true,
            );
        }
        assert_eq!(ssc.state(), SpectralSequenceState::Calibrating);
    }

    #[test]
    fn clean_lifting_converges() {
        let mut ssc = SerreSpectralController::new();
        for _ in 0..512 {
            ssc.observe(
                LayerPair::AbiToMembrane,
                InvariantClass::ReturnSemantics,
                true,
            );
            ssc.observe(
                LayerPair::MembraneToCore,
                InvariantClass::SideEffectOrder,
                true,
            );
            ssc.observe(
                LayerPair::AbiToCore,
                InvariantClass::ResourceLifecycle,
                true,
            );
        }
        assert_eq!(ssc.state(), SpectralSequenceState::Converged);
    }

    #[test]
    fn persistent_failures_trigger_lifting_failure() {
        let mut ssc = SerreSpectralController::new();
        // Calibrate.
        for _ in 0..64 {
            ssc.observe(
                LayerPair::AbiToMembrane,
                InvariantClass::ReturnSemantics,
                true,
            );
        }
        // All failures on one cell.
        for _ in 0..256 {
            ssc.observe_and_update(
                LayerPair::AbiToMembrane,
                InvariantClass::ReturnSemantics,
                false,
            );
        }
        let state = ssc.state();
        assert!(
            matches!(
                state,
                SpectralSequenceState::LiftingFailure | SpectralSequenceState::Collapsed
            ),
            "Expected LiftingFailure or Collapsed, got {state:?}"
        );
    }

    #[test]
    fn recovery_after_clean_observations() {
        let mut ssc = SerreSpectralController::new();
        for _ in 0..64 {
            ssc.observe(
                LayerPair::AbiToMembrane,
                InvariantClass::ReturnSemantics,
                true,
            );
        }
        for _ in 0..256 {
            ssc.observe(
                LayerPair::AbiToMembrane,
                InvariantClass::ReturnSemantics,
                false,
            );
        }
        // Now recover.
        for _ in 0..2000 {
            ssc.observe(
                LayerPair::AbiToMembrane,
                InvariantClass::ReturnSemantics,
                true,
            );
        }
        assert_eq!(ssc.state(), SpectralSequenceState::Converged);
    }

    #[test]
    fn page_advances() {
        let mut ssc = SerreSpectralController::new();
        assert_eq!(ssc.current_page(), 2);
        for _ in 0..SPECTRAL_WINDOW {
            ssc.observe(LayerPair::AbiToCore, InvariantClass::ErrorRecovery, true);
        }
        assert_eq!(ssc.current_page(), 3);
    }

    #[test]
    fn summary_coherent() {
        let mut ssc = SerreSpectralController::new();
        for _ in 0..128 {
            ssc.observe(
                LayerPair::AbiToMembrane,
                InvariantClass::ReturnSemantics,
                true,
            );
        }
        let s = ssc.summary();
        assert_eq!(s.total_observations, 128);
        assert!(s.max_differential < DIFFERENTIAL_THRESHOLD);
    }

    #[test]
    fn nontrivial_cells_counted() {
        let mut ssc = SerreSpectralController::new();
        for _ in 0..64 {
            ssc.observe(
                LayerPair::AbiToMembrane,
                InvariantClass::ReturnSemantics,
                true,
            );
        }
        // Create failures in two different cells.
        for _ in 0..200 {
            ssc.observe(
                LayerPair::AbiToMembrane,
                InvariantClass::ReturnSemantics,
                false,
            );
            ssc.observe(
                LayerPair::MembraneToCore,
                InvariantClass::SideEffectOrder,
                false,
            );
        }
        let s = ssc.summary();
        assert!(s.nontrivial_cells >= 2);
    }

    // ═══════════════════════════════════════════════════════════════
    // FORMAL PROOF: Bigraded Complex Coverage
    //
    // Theorem: The bigraded complex covers exactly
    // NUM_LAYER_PAIRS × NUM_INVARIANT_CLASSES = TOTAL_CELLS cells.
    // Every (LayerPair, InvariantClass) combination maps to a unique
    // cell index in [0, TOTAL_CELLS), and every cell is reachable.
    // This ensures no cross-layer behavior goes unmonitored.
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn proof_bigraded_complex_complete_coverage() {
        let all_pairs = [
            LayerPair::AbiToMembrane,
            LayerPair::MembraneToCore,
            LayerPair::AbiToCore,
        ];
        let all_classes = [
            InvariantClass::ReturnSemantics,
            InvariantClass::SideEffectOrder,
            InvariantClass::ResourceLifecycle,
            InvariantClass::ErrorRecovery,
        ];

        assert_eq!(
            all_pairs.len(),
            NUM_LAYER_PAIRS,
            "All layer pairs must be enumerated"
        );
        assert_eq!(
            all_classes.len(),
            NUM_INVARIANT_CLASSES,
            "All invariant classes must be enumerated"
        );
        assert_eq!(
            TOTAL_CELLS,
            NUM_LAYER_PAIRS * NUM_INVARIANT_CLASSES,
            "TOTAL_CELLS must equal product"
        );

        use std::collections::HashSet;
        let mut seen_indices = HashSet::new();

        for &pair in &all_pairs {
            for &class in &all_classes {
                let idx = (pair as usize) * NUM_INVARIANT_CLASSES + (class as usize);
                assert!(
                    idx < TOTAL_CELLS,
                    "Cell index {idx} exceeds TOTAL_CELLS={TOTAL_CELLS}"
                );
                assert!(
                    seen_indices.insert(idx),
                    "Duplicate cell index {idx} for ({pair:?}, {class:?})"
                );
            }
        }

        assert_eq!(
            seen_indices.len(),
            TOTAL_CELLS,
            "Must cover all {TOTAL_CELLS} cells"
        );
    }

    // ═══════════════════════════════════════════════════════════════
    // FORMAL PROOF: Page Monotonicity
    //
    // Theorem: The spectral sequence page counter is monotonically
    // non-decreasing: E_r → E_{r+1} → ... Each page advancement
    // represents an irreversible progress step in the convergence
    // analysis. Pages never regress.
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn proof_page_monotonicity() {
        let mut ssc = SerreSpectralController::new();
        assert_eq!(ssc.current_page(), 2, "Must start at E_2 page");

        let mut prev_page = ssc.current_page();

        for i in 0..5000u64 {
            ssc.observe(
                LayerPair::AbiToMembrane,
                InvariantClass::ReturnSemantics,
                i % 7 != 0,
            );
            let current_page = ssc.current_page();
            assert!(
                current_page >= prev_page,
                "Page regressed from E_{prev_page} to E_{current_page} at observation {i}"
            );
            prev_page = current_page;
        }

        // After 5000 observations with SPECTRAL_WINDOW=256, expect
        // at least 5000/256 = 19 page advances.
        assert!(
            ssc.current_page() >= 2 + 19,
            "Expected at least 19 page advances, got page E_{}",
            ssc.current_page()
        );
    }

    // ═══════════════════════════════════════════════════════════════
    // FORMAL PROOF: Differential Density Boundedness
    //
    // Theorem: All differential density values are bounded in [0, 1].
    // This follows from the EWMA update rule applied to binary
    // signals (0 or 1):
    //   d' = (1-α)·d + α·x, where x ∈ {0, 1}
    // By induction, d ∈ [0, 1] for all time steps.
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn proof_differential_density_bounded() {
        let mut ssc = SerreSpectralController::new();

        // Feed adversarial mix of failures and successes.
        for i in 0..3000u64 {
            let pair = match i % 3 {
                0 => LayerPair::AbiToMembrane,
                1 => LayerPair::MembraneToCore,
                _ => LayerPair::AbiToCore,
            };
            let class = match i % 4 {
                0 => InvariantClass::ReturnSemantics,
                1 => InvariantClass::SideEffectOrder,
                2 => InvariantClass::ResourceLifecycle,
                _ => InvariantClass::ErrorRecovery,
            };
            let lifted_ok = i % 5 != 0; // 20% failure rate
            ssc.observe(pair, class, lifted_ok);
        }

        let s = ssc.summary();
        assert!(
            (0.0..=1.0).contains(&s.max_differential),
            "max_differential {:.6} must be in [0, 1]",
            s.max_differential
        );
        assert!(
            (0.0..=1.0).contains(&s.mean_differential),
            "mean_differential {:.6} must be in [0, 1]",
            s.mean_differential
        );
        assert!(
            s.nontrivial_cells <= TOTAL_CELLS as u8,
            "nontrivial_cells {} must be ≤ TOTAL_CELLS={}",
            s.nontrivial_cells,
            TOTAL_CELLS
        );
    }

    // ═══════════════════════════════════════════════════════════════
    // FORMAL PROOF: Convergence Detection Correctness
    //
    // Theorem: When all observations are clean (lifted_ok = true),
    // the spectral sequence must converge (state = Converged) after
    // sufficient observations. This proves that the E_∞ page is
    // reached when layers compose without defect.
    //
    // Conversely, when all observations are failures, the sequence
    // must detect a structural defect (LiftingFailure or Collapsed).
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn proof_convergence_detection_correctness() {
        // Part 1: All clean → Converged
        let mut ssc_clean = SerreSpectralController::new();
        for _ in 0..2000 {
            for &pair in &[
                LayerPair::AbiToMembrane,
                LayerPair::MembraneToCore,
                LayerPair::AbiToCore,
            ] {
                for &class in &[
                    InvariantClass::ReturnSemantics,
                    InvariantClass::SideEffectOrder,
                    InvariantClass::ResourceLifecycle,
                    InvariantClass::ErrorRecovery,
                ] {
                    ssc_clean.observe(pair, class, true);
                }
            }
        }
        assert_eq!(
            ssc_clean.state(),
            SpectralSequenceState::Converged,
            "All-clean observations must converge"
        );
        let s = ssc_clean.summary();
        assert!(
            s.max_differential < CONVERGENCE_THRESHOLD,
            "Max differential {:.6} must be below convergence threshold {:.4}",
            s.max_differential,
            CONVERGENCE_THRESHOLD
        );

        // Part 2: All failures → LiftingFailure or Collapsed
        let mut ssc_fail = SerreSpectralController::new();
        for _ in 0..1000 {
            ssc_fail.observe(
                LayerPair::AbiToMembrane,
                InvariantClass::ReturnSemantics,
                false,
            );
        }
        assert!(
            matches!(
                ssc_fail.state(),
                SpectralSequenceState::LiftingFailure | SpectralSequenceState::Collapsed
            ),
            "All-failure observations must detect structural defect, got {:?}",
            ssc_fail.state()
        );
    }

    // ═══════════════════════════════════════════════════════════════
    // FORMAL PROOF: Threshold Partition Completeness
    //
    // Theorem: The state thresholds form a complete partition of
    // [0, ∞) for differential densities after calibration:
    //   [0, CONVERGENCE_THRESHOLD) → Converged
    //   [CONVERGENCE_THRESHOLD, DIFFERENTIAL_THRESHOLD) → Converged or LiftingFailure (trend-dependent)
    //   [DIFFERENTIAL_THRESHOLD, LIFTING_FAILURE_THRESHOLD) → LiftingFailure
    //   [LIFTING_FAILURE_THRESHOLD, ∞) → LiftingFailure or Collapsed (trend-dependent)
    //
    // The thresholds form a strict increasing sequence:
    //   0 < CONVERGENCE_THRESHOLD < DIFFERENTIAL_THRESHOLD < LIFTING_FAILURE_THRESHOLD
    // ═══════════════════════════════════════════════════════════════

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn proof_threshold_partition_complete() {
        // Verify strict ordering.
        assert!(
            CONVERGENCE_THRESHOLD > 0.0,
            "CONVERGENCE_THRESHOLD must be positive"
        );
        assert!(
            CONVERGENCE_THRESHOLD < DIFFERENTIAL_THRESHOLD,
            "CONVERGENCE < DIFFERENTIAL threshold"
        );
        assert!(
            DIFFERENTIAL_THRESHOLD < LIFTING_FAILURE_THRESHOLD,
            "DIFFERENTIAL < LIFTING_FAILURE threshold"
        );
        assert!(
            EWMA_ALPHA > 0.0 && EWMA_ALPHA < 1.0,
            "EWMA alpha must be in (0, 1)"
        );

        // Verify calibration threshold is positive.
        assert!(CALIBRATION_THRESHOLD > 0);

        // Verify spectral window is positive.
        assert!(SPECTRAL_WINDOW > 0);

        // Verify TOTAL_CELLS is consistent with enums.
        assert_eq!(TOTAL_CELLS, 12, "3 layer pairs × 4 invariant classes = 12");
    }
}
