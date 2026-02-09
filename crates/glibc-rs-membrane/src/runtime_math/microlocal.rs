//! # Microlocal Sheaf Propagation Controller
//!
//! Implements Kashiwara-Schapira style microlocal sheaf propagation for
//! signal/unwind fault-surface control (math item #37).
//!
//! ## Mathematical Foundation
//!
//! In microlocal sheaf theory (Kashiwara-Schapira 1990), the **microsupport**
//! (singular support) SS(F) of a sheaf F on a manifold M is a closed conic
//! involutive subset of the cotangent bundle T\*M that encodes the
//! propagation directions along which the sheaf fails to be locally constant.
//!
//! For a constructible sheaf F on M with stratification S:
//!
//! ```text
//! SS(F) ⊆ ⋃_{S ∈ S} T*_S M
//! ```
//!
//! where T\*\_S M is the conormal bundle to stratum S.
//!
//! **Propagation theorem** (KS, Theorem 5.2.1): If the microsupport of F
//! does not intersect a given half-space in the cotangent fiber, then F is
//! locally constant along the corresponding direction. Formally:
//!
//! ```text
//! SS(F) ∩ {(x, ξ) : φ(x,ξ) ≥ 0} = ∅  ⟹  F is non-characteristic for φ
//! ```
//!
//! This gives a **directional propagation guarantee**: sections propagate
//! smoothly along covector directions that avoid the microsupport.
//!
//! ## Runtime Application
//!
//! The signal/unwind/setjmp fault surface in glibc is a stratified space:
//!
//! - **Stratum 0** (innermost): Normal execution flow. Control transfers are
//!   local (function call/return). The sheaf of valid states is constant here.
//!
//! - **Stratum 1**: Signal delivery boundary. Control transfers are non-local
//!   but structured (sigaction handler entry/exit). The microsupport may
//!   include conormal directions to the signal mask change surface.
//!
//! - **Stratum 2**: Longjmp/setjmp boundary. Non-local, non-structured
//!   transfers that bypass cleanup. The singular support concentrates here.
//!
//! - **Stratum 3** (outermost): Cancellation/thread-exit. Irreversible
//!   destruction of thread context.
//!
//! We track the **wavefront set** — a discrete approximation of the
//! microsupport — as a bitvector encoding which strata have recently seen
//! fault-surface crossings. The propagation check verifies that the
//! current control transfer direction is "non-characteristic" (safe)
//! relative to the current wavefront.
//!
//! ## Involutivity Constraint (KS, Proposition 5.1.1)
//!
//! The microsupport is always involutive (coisotropic) in T\*M with respect
//! to the canonical symplectic form ω = Σ dξ_i ∧ dx_i. For our discrete
//! model, this means the wavefront bitvector must satisfy a monotonicity
//! constraint: if stratum k is in the wavefront, all strata ≤ k must also
//! be (the singular support propagates inward). We enforce this via a
//! prefix-closed invariant on the bitvector.
//!
//! ## Connection to Math Item #37
//!
//! Microlocal sheaf-theoretic propagation methods (Kashiwara-Schapira style)
//! for unwind/signal fault-surface control.

/// Number of strata in the fault-surface stratification.
const NUM_STRATA: usize = 4;

/// Calibration observations before state transitions.
const CALIBRATION_THRESHOLD: u64 = 64;

/// EWMA decay for stratum activity rates.
const EWMA_ALPHA: f64 = 0.02;

/// Threshold: if conormal density exceeds this, stratum is "active" in wavefront.
const CONORMAL_THRESHOLD: f64 = 0.15;

/// Threshold: if propagation failure rate exceeds this, fault boundary detected.
const FAULT_BOUNDARY_THRESHOLD: f64 = 0.25;

/// Threshold: if singular support density exceeds this, full singular regime.
const SINGULAR_SUPPORT_THRESHOLD: f64 = 0.40;

/// Discrete stratum in the fault-surface stratification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Stratum {
    /// Normal execution flow — local control transfers only.
    NormalFlow = 0,
    /// Signal delivery boundary — structured non-local transfers.
    SignalBoundary = 1,
    /// Longjmp/setjmp boundary — non-structured non-local transfers.
    LongjmpBoundary = 2,
    /// Cancellation/thread-exit — irreversible context destruction.
    CancellationExit = 3,
}

impl Stratum {
    const ALL: [Self; NUM_STRATA] = [
        Self::NormalFlow,
        Self::SignalBoundary,
        Self::LongjmpBoundary,
        Self::CancellationExit,
    ];

    /// Stratum depth (higher = more singular).
    const fn depth(self) -> u8 {
        self as u8
    }
}

/// Direction of control transfer relative to stratification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferDirection {
    /// Moving toward higher strata (deeper into fault surface).
    Inward,
    /// Moving toward lower strata (returning from fault surface).
    Outward,
    /// Staying within the same stratum.
    Tangential,
}

/// Microlocal controller state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MicrolocalState {
    /// Insufficient data for classification.
    Calibrating,
    /// Microsupport is empty — all transfers propagate smoothly.
    Propagating,
    /// Wavefront set is non-empty, concentrated near stratum boundaries.
    FaultBoundary,
    /// Singular support is dense — multiple strata active simultaneously.
    SingularSupport,
}

/// Summary snapshot for telemetry integration.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MicrolocalSummary {
    /// Current controller state.
    pub state: MicrolocalState,
    /// Wavefront bitvector (bit k = stratum k is in microsupport).
    pub wavefront_bits: u8,
    /// Number of active strata in the wavefront set.
    pub active_strata: u8,
    /// Maximum conormal density across all strata.
    pub max_conormal_density: f64,
    /// Propagation failure rate (EWMA).
    pub propagation_failure_rate: f64,
    /// Total fault-boundary detections.
    pub fault_boundary_count: u64,
    /// Total singular-support detections.
    pub singular_support_count: u64,
    /// Total observations.
    pub total_observations: u64,
}

/// Per-stratum tracking state.
#[derive(Debug, Clone)]
struct StratumTracker {
    /// EWMA of crossing events (conormal density proxy).
    conormal_density: f64,
    /// EWMA of propagation failures from this stratum.
    failure_rate: f64,
    /// Count of inward crossings observed.
    inward_crossings: u64,
    /// Count of outward crossings observed.
    outward_crossings: u64,
    /// Count of propagation failures (non-characteristic violation).
    propagation_failures: u64,
}

impl StratumTracker {
    const fn new() -> Self {
        Self {
            conormal_density: 0.0,
            failure_rate: 0.0,
            inward_crossings: 0,
            outward_crossings: 0,
            propagation_failures: 0,
        }
    }
}

/// Microlocal sheaf propagation controller.
///
/// Tracks the wavefront set (discrete microsupport) of the control-transfer
/// sheaf across the fault-surface stratification, detecting when signal/unwind
/// transfers cross stratum boundaries in non-characteristic directions.
pub struct MicrolocalController {
    /// Per-stratum tracking.
    strata: [StratumTracker; NUM_STRATA],
    /// Current stratum the system is observed to be in.
    current_stratum: Stratum,
    /// Wavefront bitvector: bit k set iff stratum k is in microsupport.
    wavefront: u8,
    /// Overall propagation failure EWMA.
    overall_failure_rate: f64,
    /// Total observations.
    total_observations: u64,
    /// Fault boundary detection count.
    fault_boundary_count: u64,
    /// Singular support detection count.
    singular_support_count: u64,
}

impl MicrolocalController {
    /// Create a new microlocal controller.
    #[must_use]
    pub fn new() -> Self {
        Self {
            strata: [
                StratumTracker::new(),
                StratumTracker::new(),
                StratumTracker::new(),
                StratumTracker::new(),
            ],
            current_stratum: Stratum::NormalFlow,
            wavefront: 0,
            overall_failure_rate: 0.0,
            total_observations: 0,
            fault_boundary_count: 0,
            singular_support_count: 0,
        }
    }

    /// Observe a control transfer event.
    ///
    /// `from_stratum` and `to_stratum` identify the strata involved.
    /// `adverse` indicates whether the transfer resulted in an error or
    /// required repair (propagation failure = non-characteristic crossing).
    pub fn observe(&mut self, from_stratum: Stratum, to_stratum: Stratum, adverse: bool) {
        self.total_observations += 1;

        // Determine transfer direction.
        let direction = if to_stratum.depth() > from_stratum.depth() {
            TransferDirection::Inward
        } else if to_stratum.depth() < from_stratum.depth() {
            TransferDirection::Outward
        } else {
            TransferDirection::Tangential
        };

        // Update crossing counts for the target stratum.
        let to_idx = to_stratum.depth() as usize;
        match direction {
            TransferDirection::Inward => {
                self.strata[to_idx].inward_crossings += 1;
            }
            TransferDirection::Outward => {
                self.strata[to_idx].outward_crossings += 1;
            }
            TransferDirection::Tangential => {}
        }

        // Update conormal density: crossing events contribute to the
        // conormal bundle density at the target stratum boundary.
        let is_crossing = direction != TransferDirection::Tangential;
        let crossing_signal = if is_crossing { 1.0 } else { 0.0 };
        self.strata[to_idx].conormal_density = self.strata[to_idx]
            .conormal_density
            .mul_add(1.0 - EWMA_ALPHA, EWMA_ALPHA * crossing_signal);

        // Propagation failure tracking: an adverse outcome during a
        // non-tangential transfer is a "non-characteristic" crossing —
        // the sheaf fails to propagate smoothly.
        if is_crossing && adverse {
            self.strata[to_idx].propagation_failures += 1;
        }
        let failure_signal = if is_crossing && adverse { 1.0 } else { 0.0 };
        self.strata[to_idx].failure_rate = self.strata[to_idx]
            .failure_rate
            .mul_add(1.0 - EWMA_ALPHA, EWMA_ALPHA * failure_signal);

        // Update overall propagation failure rate.
        self.overall_failure_rate = self
            .overall_failure_rate
            .mul_add(1.0 - EWMA_ALPHA, EWMA_ALPHA * failure_signal);

        // Update current stratum.
        self.current_stratum = to_stratum;

        // Recompute wavefront set with involutivity (prefix-closed) constraint.
        self.recompute_wavefront();
    }

    /// Recompute the wavefront bitvector.
    ///
    /// A stratum is "active" in the wavefront if its conormal density
    /// exceeds the threshold. The involutivity constraint (KS Prop 5.1.1)
    /// requires the wavefront to be prefix-closed: if stratum k is active,
    /// all strata j < k must also be active. We enforce this by including
    /// the highest active stratum and all lower ones.
    fn recompute_wavefront(&mut self) {
        let mut max_active: Option<u8> = None;

        for s in Stratum::ALL {
            let idx = s.depth() as usize;
            if self.strata[idx].conormal_density >= CONORMAL_THRESHOLD {
                match max_active {
                    Some(prev) if s.depth() > prev => max_active = Some(s.depth()),
                    None => max_active = Some(s.depth()),
                    _ => {}
                }
            }
        }

        // Build prefix-closed wavefront.
        self.wavefront = match max_active {
            Some(d) => {
                // Set bits 0..=d.
                (1u8 << (d + 1)) - 1
            }
            None => 0,
        };
    }

    /// Current controller state.
    #[must_use]
    pub fn state(&self) -> MicrolocalState {
        if self.total_observations < CALIBRATION_THRESHOLD {
            return MicrolocalState::Calibrating;
        }

        let active_count = self.wavefront.count_ones();

        // Singular support: dense wavefront with high failure rate.
        if active_count >= 3 || self.overall_failure_rate >= SINGULAR_SUPPORT_THRESHOLD {
            return MicrolocalState::SingularSupport;
        }

        // Fault boundary: non-empty wavefront with moderate failure rate.
        if active_count >= 1 && self.overall_failure_rate >= FAULT_BOUNDARY_THRESHOLD {
            return MicrolocalState::FaultBoundary;
        }

        // Propagating: microsupport is effectively empty or benign.
        MicrolocalState::Propagating
    }

    /// Summary snapshot for telemetry.
    #[must_use]
    pub fn summary(&self) -> MicrolocalSummary {
        let max_conormal = self
            .strata
            .iter()
            .map(|s| s.conormal_density)
            .fold(0.0f64, f64::max);

        let state = self.state();
        // Count state transitions.
        let fb_count = self.fault_boundary_count;
        let ss_count = self.singular_support_count;

        MicrolocalSummary {
            state,
            wavefront_bits: self.wavefront,
            active_strata: self.wavefront.count_ones() as u8,
            max_conormal_density: max_conormal,
            propagation_failure_rate: self.overall_failure_rate,
            fault_boundary_count: fb_count,
            singular_support_count: ss_count,
            total_observations: self.total_observations,
        }
    }

    /// Feed an observation and update detection counters.
    ///
    /// This is the primary entry point combining `observe` + counter updates.
    pub fn observe_and_update(
        &mut self,
        from_stratum: Stratum,
        to_stratum: Stratum,
        adverse: bool,
    ) {
        let prev_state = self.state();
        self.observe(from_stratum, to_stratum, adverse);
        let new_state = self.state();

        if new_state != prev_state {
            match new_state {
                MicrolocalState::FaultBoundary => self.fault_boundary_count += 1,
                MicrolocalState::SingularSupport => self.singular_support_count += 1,
                _ => {}
            }
        }
    }

    /// Check if a proposed transfer direction is non-characteristic
    /// (safe to propagate) given the current wavefront.
    ///
    /// Returns true if the transfer is safe, false if it crosses into
    /// an active region of the microsupport.
    #[must_use]
    pub fn is_non_characteristic(&self, target_stratum: Stratum) -> bool {
        let bit = 1u8 << target_stratum.depth();
        // Non-characteristic iff the target stratum is NOT in the wavefront.
        self.wavefront & bit == 0
    }

    /// Current wavefront bitvector.
    #[must_use]
    pub fn wavefront_bits(&self) -> u8 {
        self.wavefront
    }

    /// Total observations.
    #[must_use]
    pub fn total_observations(&self) -> u64 {
        self.total_observations
    }
}

impl Default for MicrolocalController {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calibrating_until_threshold() {
        let mut mc = MicrolocalController::new();
        for _ in 0..CALIBRATION_THRESHOLD - 1 {
            mc.observe(Stratum::NormalFlow, Stratum::NormalFlow, false);
        }
        assert_eq!(mc.state(), MicrolocalState::Calibrating);
    }

    #[test]
    fn quiet_traffic_stays_propagating() {
        let mut mc = MicrolocalController::new();
        for _ in 0..256 {
            mc.observe(Stratum::NormalFlow, Stratum::NormalFlow, false);
        }
        assert_eq!(mc.state(), MicrolocalState::Propagating);
        assert_eq!(mc.wavefront_bits(), 0);
    }

    #[test]
    fn signal_crossings_activate_wavefront() {
        let mut mc = MicrolocalController::new();
        // Calibration phase.
        for _ in 0..64 {
            mc.observe(Stratum::NormalFlow, Stratum::NormalFlow, false);
        }
        // Now flood with signal boundary crossings.
        for _ in 0..128 {
            mc.observe(Stratum::NormalFlow, Stratum::SignalBoundary, false);
        }
        // Signal boundary should be in wavefront; involutivity means
        // NormalFlow is also included.
        assert!(mc.wavefront_bits() & (1 << Stratum::SignalBoundary.depth()) != 0);
        assert!(mc.wavefront_bits() & (1 << Stratum::NormalFlow.depth()) != 0);
    }

    #[test]
    fn adverse_crossings_trigger_fault_boundary() {
        let mut mc = MicrolocalController::new();
        for _ in 0..64 {
            mc.observe(Stratum::NormalFlow, Stratum::NormalFlow, false);
        }
        // All adverse crossings to signal boundary.
        for _ in 0..128 {
            mc.observe_and_update(Stratum::NormalFlow, Stratum::SignalBoundary, true);
        }
        let state = mc.state();
        assert!(
            matches!(
                state,
                MicrolocalState::FaultBoundary | MicrolocalState::SingularSupport
            ),
            "Expected FaultBoundary or SingularSupport, got {state:?}"
        );
    }

    #[test]
    fn dense_crossings_trigger_singular_support() {
        let mut mc = MicrolocalController::new();
        for _ in 0..64 {
            mc.observe(Stratum::NormalFlow, Stratum::NormalFlow, false);
        }
        // Flood all strata with adverse crossings.
        for _ in 0..128 {
            mc.observe_and_update(Stratum::NormalFlow, Stratum::SignalBoundary, true);
            mc.observe_and_update(Stratum::SignalBoundary, Stratum::LongjmpBoundary, true);
            mc.observe_and_update(Stratum::LongjmpBoundary, Stratum::CancellationExit, true);
        }
        assert_eq!(mc.state(), MicrolocalState::SingularSupport);
    }

    #[test]
    fn non_characteristic_check() {
        let mut mc = MicrolocalController::new();
        for _ in 0..64 {
            mc.observe(Stratum::NormalFlow, Stratum::NormalFlow, false);
        }
        // Activate signal boundary in wavefront.
        for _ in 0..128 {
            mc.observe(Stratum::NormalFlow, Stratum::SignalBoundary, false);
        }
        // SignalBoundary is in wavefront -> characteristic (not safe).
        assert!(!mc.is_non_characteristic(Stratum::SignalBoundary));
        // CancellationExit is not in wavefront -> non-characteristic (safe).
        assert!(mc.is_non_characteristic(Stratum::CancellationExit));
    }

    #[test]
    fn involutivity_prefix_closed() {
        let mut mc = MicrolocalController::new();
        for _ in 0..64 {
            mc.observe(Stratum::NormalFlow, Stratum::NormalFlow, false);
        }
        // Activate longjmp boundary (stratum 2) directly.
        for _ in 0..128 {
            mc.observe(Stratum::NormalFlow, Stratum::LongjmpBoundary, false);
        }
        let wf = mc.wavefront_bits();
        // If stratum 2 is active, strata 0 and 1 must also be active
        // (prefix-closed / involutivity).
        if wf & (1 << 2) != 0 {
            assert_ne!(
                wf & (1 << 0),
                0,
                "Stratum 0 must be in prefix-closed wavefront"
            );
            assert_ne!(
                wf & (1 << 1),
                0,
                "Stratum 1 must be in prefix-closed wavefront"
            );
        }
    }

    #[test]
    fn summary_coherent() {
        let mut mc = MicrolocalController::new();
        for _ in 0..128 {
            mc.observe(Stratum::NormalFlow, Stratum::NormalFlow, false);
        }
        let summary = mc.summary();
        assert_eq!(summary.total_observations, 128);
        assert_eq!(summary.state, MicrolocalState::Propagating);
    }

    #[test]
    fn recovery_after_calm() {
        let mut mc = MicrolocalController::new();
        // Calibrate.
        for _ in 0..64 {
            mc.observe(Stratum::NormalFlow, Stratum::NormalFlow, false);
        }
        // Trigger adverse regime.
        for _ in 0..200 {
            mc.observe_and_update(Stratum::NormalFlow, Stratum::SignalBoundary, true);
        }
        assert!(matches!(
            mc.state(),
            MicrolocalState::FaultBoundary | MicrolocalState::SingularSupport
        ));
        // Calm down with many normal observations.
        for _ in 0..2000 {
            mc.observe(Stratum::NormalFlow, Stratum::NormalFlow, false);
        }
        assert_eq!(mc.state(), MicrolocalState::Propagating);
    }
}
