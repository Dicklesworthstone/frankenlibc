//! Runtime math kernel for membrane decision control.
//!
//! This module makes the "alien-artifact" stack operational at runtime by
//! compiling advanced methods into tiny online controllers:
//! - conformal-like risk upper bounds (`risk`)
//! - constrained bandit routing of validation depth (`bandit`)
//! - primal-dual budget controller (`control`)
//! - barrier admissibility filter (`barrier`)
//! - incremental overlap-consistency monitor (`cohomology`)
//!
//! The runtime path remains deterministic and low overhead. Heavy synthesis
//! stays offline; online code only executes compact control kernels.

pub mod bandit;
pub mod barrier;
pub mod changepoint;
pub mod clifford;
pub mod cohomology;
pub mod commitment_audit;
pub mod conformal;
pub mod control;
pub mod coupling;
pub mod cvar;
pub mod design;
pub mod eprocess;
pub mod equivariant;
pub mod fusion;
pub mod higher_topos;
pub mod loss_minimizer;
pub mod microlocal;
pub mod pareto;
pub mod risk;
pub mod serre_spectral;
pub mod sparse;

use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use parking_lot::Mutex;

use crate::check_oracle::{CheckContext, CheckOracle, CheckStage};
use crate::config::SafetyLevel;
use crate::heal::HealingAction;
use crate::hji_reachability::{HjiReachabilityController, ReachState};
use crate::large_deviations::{LargeDeviationsMonitor, RateState};
use crate::mean_field_game::{MeanFieldGameController, MfgState};
use crate::padic_valuation::{PadicState, PadicValuationMonitor};
use crate::persistence::{PersistenceDetector, TopologicalState};
use crate::quarantine_controller::{QuarantineController, current_depth, publish_depth};
use crate::risk_engine::{CallFamily, RiskDecision, RiskEngine};
use crate::rough_path::{RoughPathMonitor, SignatureState};
use crate::schrodinger_bridge::{BridgeState, SchrodingerBridgeController};
use crate::spectral_monitor::{PhaseState, SpectralMonitor};
use crate::symplectic_reduction::{ResourceType, SymplecticReductionController, SymplecticState};
use crate::tropical_latency::{PipelinePath, TROPICAL_METRICS, TropicalLatencyCompositor};

use self::bandit::ConstrainedBanditRouter;
use self::barrier::BarrierOracle;
use self::changepoint::{ChangepointController, ChangepointState};
use self::clifford::{AlignmentObservation, AlignmentRegime, CliffordController, CliffordState};
use self::cohomology::CohomologyMonitor;
use self::commitment_audit::{AuditState, CommitmentAuditController};
use self::conformal::{ConformalRiskController, ConformalState};
use self::control::PrimalDualController;
use self::coupling::{CouplingController, CouplingState};
use self::cvar::{DroCvarController, TailState};
use self::design::{OptimalDesignController, Probe, ProbePlan};
use self::eprocess::{AnytimeEProcessMonitor, SequentialState};
use self::equivariant::{EquivariantState, EquivariantTransportController};
use self::fusion::KernelFusionController;
use self::higher_topos::{HigherToposController, ToposState};
use self::loss_minimizer::{LossMinimizationController, LossState};
use self::microlocal::{MicrolocalController, MicrolocalState, Stratum};
use self::pareto::ParetoController;
use self::risk::ConformalRiskEngine;
use self::serre_spectral::{
    InvariantClass, LayerPair, SerreSpectralController, SpectralSequenceState,
};
use self::sparse::{SparseRecoveryController, SparseState};

const FAST_PATH_BUDGET_NS: u64 = 20;
const FULL_PATH_BUDGET_NS: u64 = 200;

/// Runtime API family used for online control decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ApiFamily {
    PointerValidation = 0,
    Allocator = 1,
    StringMemory = 2,
    Stdio = 3,
    Threading = 4,
    Resolver = 5,
    MathFenv = 6,
    Loader = 7,
    Stdlib = 8,
}

impl ApiFamily {
    pub const COUNT: usize = 9;
}

/// Validation profile selected by the runtime controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationProfile {
    Fast,
    Full,
}

impl ValidationProfile {
    /// Returns true if full pipeline checks are required.
    #[must_use]
    pub const fn requires_full(self) -> bool {
        matches!(self, Self::Full)
    }
}

/// Compact runtime context for online policy decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeContext {
    pub family: ApiFamily,
    pub addr_hint: usize,
    pub requested_bytes: usize,
    pub is_write: bool,
    pub contention_hint: u16,
    pub bloom_negative: bool,
}

impl RuntimeContext {
    /// Convenience constructor for pointer-validation flow.
    #[must_use]
    pub const fn pointer_validation(addr_hint: usize, bloom_negative: bool) -> Self {
        Self {
            family: ApiFamily::PointerValidation,
            addr_hint,
            requested_bytes: 0,
            is_write: false,
            contention_hint: 0,
            bloom_negative,
        }
    }
}

/// Runtime membrane action selected by control kernels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembraneAction {
    Allow,
    FullValidate,
    Repair(HealingAction),
    Deny,
}

/// Online decision output consumed by membrane call paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeDecision {
    pub profile: ValidationProfile,
    pub action: MembraneAction,
    pub policy_id: u32,
    pub risk_upper_bound_ppm: u32,
}

impl RuntimeDecision {
    /// Returns true if call path should execute full validation checks.
    #[must_use]
    pub const fn requires_full_validation(self) -> bool {
        self.profile.requires_full()
            || matches!(
                self.action,
                MembraneAction::FullValidate | MembraneAction::Repair(_)
            )
    }
}

/// Runtime state snapshot useful for tests/telemetry export.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RuntimeKernelSnapshot {
    pub decisions: u64,
    pub consistency_faults: u64,
    pub full_validation_trigger_ppm: u32,
    pub repair_trigger_ppm: u32,
    pub sampled_risk_bonus_ppm: u32,
    pub pareto_cumulative_regret_milli: u64,
    pub pareto_cap_enforcements: u64,
    pub pareto_exhausted_families: u32,
    pub quarantine_depth: usize,
    /// Tropical worst-case latency for the full pipeline path (ns).
    pub tropical_full_wcl_ns: u64,
    /// Spectral edge ratio (max_eigenvalue / median_eigenvalue).
    pub spectral_edge_ratio: f64,
    /// Whether a spectral phase transition is active.
    pub spectral_phase_transition: bool,
    /// Rough-path signature anomaly score (0 = normal, >2 = anomalous).
    pub signature_anomaly_score: f64,
    /// Total rough-path anomaly detections.
    pub signature_anomaly_count: u64,
    /// Persistence entropy of the validation cost point cloud.
    pub persistence_entropy: f64,
    /// Total topological anomaly detections.
    pub topo_anomaly_count: u64,
    /// Maximum anytime e-process value across runtime families.
    pub anytime_max_e_value: f64,
    /// Number of families currently in e-process alarm mode.
    pub anytime_alarmed_families: u32,
    /// Maximum robust CVaR latency estimate across families.
    pub cvar_max_robust_ns: u64,
    /// Number of families in CVaR alarm state.
    pub cvar_alarmed_families: u32,
    /// Schrödinger bridge transport distance (W_ε between current policy and equilibrium).
    pub bridge_transport_distance: f64,
    /// Whether a regime transition is detected via optimal transport.
    pub bridge_transitioning: bool,
    /// Number of families with elevated/critical large-deviation rate state.
    pub ld_elevated_families: u32,
    /// Maximum anomaly count across families in the large-deviation monitor.
    pub ld_max_anomaly_count: u64,
    /// HJI reachability value at current discrete state (>0 = safe, ≤0 = breached).
    pub hji_safety_value: f64,
    /// Whether the system state is inside the backward reachable tube.
    pub hji_breached: bool,
    /// Mean-field game empirical contention level (normalized 0..1).
    pub mfg_mean_contention: f64,
    /// Mean-field game congestion collapse detections.
    pub mfg_congestion_count: u64,
    /// p-adic ultrametric distance between current and baseline valuation profiles.
    pub padic_ultrametric_distance: f64,
    /// p-adic regime drift detection count.
    pub padic_drift_count: u64,
    /// Symplectic Hamiltonian energy (deadlock risk indicator, 0..N).
    pub symplectic_energy: f64,
    /// Symplectic admissibility violation count.
    pub symplectic_violation_count: u64,
    /// Higher-topos descent violation rate (EWMA, 0..1).
    pub topos_violation_rate: f64,
    /// Higher-topos descent violation count.
    pub topos_violation_count: u64,
    /// Commitment audit martingale process value.
    pub audit_martingale_value: f64,
    /// Commitment audit replay detection count.
    pub audit_replay_count: u64,
    /// Bayesian change-point posterior short-run-length mass (0..1).
    pub changepoint_posterior_short_mass: f64,
    /// Bayesian change-point detection count.
    pub changepoint_count: u64,
    /// Conformal prediction empirical coverage (0..1).
    pub conformal_empirical_coverage: f64,
    /// Conformal prediction coverage violation count.
    pub conformal_violation_count: u64,
    /// Design-kernel identifiability score (0..1e6).
    pub design_identifiability_ppm: u32,
    /// Number of heavy probes selected in the current budgeted plan.
    pub design_selected_probes: u8,
    /// Probe-budget assigned by mode/controller.
    pub design_budget_ns: u64,
    /// Expected cost of selected probes.
    pub design_expected_cost_ns: u64,
    /// Sparse-recovery latent support size.
    pub sparse_support_size: u8,
    /// Sparse-recovery L1 energy.
    pub sparse_l1_energy: f64,
    /// Sparse-recovery residual EWMA.
    pub sparse_residual_ewma: f64,
    /// Sparse-recovery critical detections.
    pub sparse_critical_count: u64,
    /// Equivariant controller alignment score (higher is more symmetric/stable).
    pub equivariant_alignment_ppm: u32,
    /// Equivariant drift detections.
    pub equivariant_drift_count: u64,
    /// Equivariant fractured-state detections.
    pub equivariant_fractured_count: u64,
    /// Most active runtime orbit class.
    pub equivariant_dominant_orbit: u8,
    /// Robust fusion bonus currently applied to risk.
    pub fusion_bonus_ppm: u32,
    /// Fusion entropy (0..1000) over signal trust weights.
    pub fusion_entropy_milli: u32,
    /// Fusion weight-drift score in ppm.
    pub fusion_drift_ppm: u32,
    /// Dominant fused signal index.
    pub fusion_dominant_signal: u8,
    /// Microlocal wavefront active strata count.
    pub microlocal_active_strata: u8,
    /// Microlocal propagation failure rate (EWMA, 0..1).
    pub microlocal_failure_rate: f64,
    /// Microlocal fault boundary detection count.
    pub microlocal_fault_count: u64,
    /// Serre spectral sequence max differential density.
    pub serre_max_differential: f64,
    /// Serre spectral sequence non-trivial cell count.
    pub serre_nontrivial_cells: u8,
    /// Serre spectral sequence lifting failure count.
    pub serre_lifting_count: u64,
    /// Clifford grade-2 (bivector) energy fraction.
    pub clifford_grade2_energy: f64,
    /// Clifford grade parity imbalance.
    pub clifford_parity_imbalance: f64,
    /// Clifford overlap violation count.
    pub clifford_violation_count: u64,
}

/// Online control kernel for strict/hardened runtime decisions.
pub struct RuntimeMathKernel {
    risk: ConformalRiskEngine,
    router: ConstrainedBanditRouter,
    controller: PrimalDualController,
    barrier: BarrierOracle,
    cohomology: CohomologyMonitor,
    pareto: ParetoController,
    sampled_risk: Mutex<RiskEngine>,
    sampled_oracle: Mutex<CheckOracle>,
    quarantine: Mutex<QuarantineController>,
    tropical: Mutex<TropicalLatencyCompositor>,
    spectral: Mutex<SpectralMonitor>,
    rough_path: Mutex<RoughPathMonitor>,
    persistence: Mutex<PersistenceDetector>,
    anytime: Mutex<AnytimeEProcessMonitor>,
    cvar: Mutex<DroCvarController>,
    bridge: Mutex<SchrodingerBridgeController>,
    large_dev: Mutex<LargeDeviationsMonitor>,
    hji: Mutex<HjiReachabilityController>,
    mfg: Mutex<MeanFieldGameController>,
    padic: Mutex<PadicValuationMonitor>,
    symplectic: Mutex<SymplecticReductionController>,
    design: Mutex<OptimalDesignController>,
    sparse: Mutex<SparseRecoveryController>,
    equivariant: Mutex<EquivariantTransportController>,
    topos: Mutex<HigherToposController>,
    audit: Mutex<CommitmentAuditController>,
    changepoint: Mutex<ChangepointController>,
    conformal: Mutex<ConformalRiskController>,
    loss_minimizer: Mutex<LossMinimizationController>,
    coupling: Mutex<CouplingController>,
    fusion: Mutex<KernelFusionController>,
    microlocal: Mutex<MicrolocalController>,
    serre: Mutex<SerreSpectralController>,
    clifford: Mutex<CliffordController>,
    cached_risk_bonus_ppm: AtomicU64,
    cached_oracle_bias: [AtomicU8; ApiFamily::COUNT],
    cached_spectral_phase: AtomicU8,
    cached_signature_state: AtomicU8,
    cached_topological_state: AtomicU8,
    cached_anytime_state: [AtomicU8; ApiFamily::COUNT],
    cached_cvar_state: [AtomicU8; ApiFamily::COUNT],
    cached_bridge_state: AtomicU8,
    cached_ld_state: [AtomicU8; ApiFamily::COUNT],
    cached_hji_state: AtomicU8,
    cached_mfg_state: AtomicU8,
    cached_padic_state: AtomicU8,
    cached_symplectic_state: AtomicU8,
    cached_probe_mask: AtomicU64,
    cached_design_ident_ppm: AtomicU64,
    cached_design_budget_ns: AtomicU64,
    cached_design_expected_ns: AtomicU64,
    cached_design_selected: AtomicU8,
    cached_sparse_state: AtomicU8,
    cached_equivariant_state: AtomicU8,
    cached_equivariant_alignment_ppm: AtomicU64,
    cached_equivariant_orbit: AtomicU8,
    cached_topos_state: AtomicU8,
    cached_audit_state: AtomicU8,
    cached_changepoint_state: AtomicU8,
    cached_conformal_state: AtomicU8,
    cached_loss_minimizer_state: AtomicU8,
    cached_coupling_state: AtomicU8,
    cached_fusion_bonus_ppm: AtomicU64,
    cached_fusion_entropy_milli: AtomicU64,
    cached_fusion_drift_ppm: AtomicU64,
    cached_fusion_dominant_signal: AtomicU8,
    cached_microlocal_state: AtomicU8,
    cached_serre_state: AtomicU8,
    cached_clifford_state: AtomicU8,
    decisions: AtomicU64,
}

impl RuntimeMathKernel {
    /// Create a new runtime kernel.
    #[must_use]
    pub fn new() -> Self {
        Self {
            risk: ConformalRiskEngine::new(20_000, 3.0),
            router: ConstrainedBanditRouter::new(),
            controller: PrimalDualController::new(),
            barrier: BarrierOracle::new(),
            cohomology: CohomologyMonitor::new(),
            pareto: ParetoController::new(),
            sampled_risk: Mutex::new(RiskEngine::new()),
            sampled_oracle: Mutex::new(CheckOracle::new()),
            quarantine: Mutex::new(QuarantineController::new()),
            tropical: Mutex::new(TropicalLatencyCompositor::new()),
            spectral: Mutex::new(SpectralMonitor::new()),
            rough_path: Mutex::new(RoughPathMonitor::new()),
            persistence: Mutex::new(PersistenceDetector::new()),
            anytime: Mutex::new(AnytimeEProcessMonitor::new()),
            cvar: Mutex::new(DroCvarController::new()),
            bridge: Mutex::new(SchrodingerBridgeController::new()),
            large_dev: Mutex::new(LargeDeviationsMonitor::new()),
            hji: Mutex::new(HjiReachabilityController::new()),
            mfg: Mutex::new(MeanFieldGameController::new()),
            padic: Mutex::new(PadicValuationMonitor::new()),
            symplectic: Mutex::new(SymplecticReductionController::new()),
            design: Mutex::new(OptimalDesignController::new()),
            sparse: Mutex::new(SparseRecoveryController::new()),
            equivariant: Mutex::new(EquivariantTransportController::new()),
            topos: Mutex::new(HigherToposController::new()),
            audit: Mutex::new(CommitmentAuditController::new()),
            changepoint: Mutex::new(ChangepointController::new()),
            conformal: Mutex::new(ConformalRiskController::new()),
            loss_minimizer: Mutex::new(LossMinimizationController::new()),
            coupling: Mutex::new(CouplingController::new()),
            fusion: Mutex::new(KernelFusionController::new()),
            microlocal: Mutex::new(MicrolocalController::new()),
            serre: Mutex::new(SerreSpectralController::new()),
            clifford: Mutex::new(CliffordController::new()),
            cached_risk_bonus_ppm: AtomicU64::new(0),
            cached_oracle_bias: std::array::from_fn(|_| AtomicU8::new(1)),
            cached_spectral_phase: AtomicU8::new(0),
            cached_signature_state: AtomicU8::new(0),
            cached_topological_state: AtomicU8::new(0),
            cached_anytime_state: std::array::from_fn(|_| AtomicU8::new(0)),
            cached_cvar_state: std::array::from_fn(|_| AtomicU8::new(0)),
            cached_bridge_state: AtomicU8::new(0),
            cached_ld_state: std::array::from_fn(|_| AtomicU8::new(0)),
            cached_hji_state: AtomicU8::new(0),
            cached_mfg_state: AtomicU8::new(0),
            cached_padic_state: AtomicU8::new(0),
            cached_symplectic_state: AtomicU8::new(0),
            cached_probe_mask: AtomicU64::new(u64::from(Probe::all_mask())),
            cached_design_ident_ppm: AtomicU64::new(0),
            cached_design_budget_ns: AtomicU64::new(0),
            cached_design_expected_ns: AtomicU64::new(0),
            cached_design_selected: AtomicU8::new(Probe::COUNT as u8),
            cached_sparse_state: AtomicU8::new(0),
            cached_equivariant_state: AtomicU8::new(0),
            cached_equivariant_alignment_ppm: AtomicU64::new(0),
            cached_equivariant_orbit: AtomicU8::new(0),
            cached_topos_state: AtomicU8::new(0),
            cached_audit_state: AtomicU8::new(0),
            cached_changepoint_state: AtomicU8::new(0),
            cached_conformal_state: AtomicU8::new(0),
            cached_loss_minimizer_state: AtomicU8::new(0),
            cached_coupling_state: AtomicU8::new(0),
            cached_fusion_bonus_ppm: AtomicU64::new(0),
            cached_fusion_entropy_milli: AtomicU64::new(0),
            cached_fusion_drift_ppm: AtomicU64::new(0),
            cached_fusion_dominant_signal: AtomicU8::new(0),
            cached_microlocal_state: AtomicU8::new(0),
            cached_serre_state: AtomicU8::new(0),
            cached_clifford_state: AtomicU8::new(0),
            decisions: AtomicU64::new(0),
        }
    }

    /// Decide runtime validation/repair strategy for one call context.
    #[must_use]
    pub fn decide(&self, mode: SafetyLevel, ctx: RuntimeContext) -> RuntimeDecision {
        let sequence = self.decisions.fetch_add(1, Ordering::Relaxed) + 1;
        if sequence.is_multiple_of(64) {
            self.resample_high_order_kernels(mode, ctx);
        }

        let base_risk_ppm = self.risk.upper_bound_ppm(ctx.family);
        let sampled_bonus = self.cached_risk_bonus_ppm.load(Ordering::Relaxed) as u32;
        let consistency_faults = self.cohomology.fault_count();
        let cohomology_bonus = (consistency_faults.min(16) as u32) * 15_000;
        let fast_wcl = TROPICAL_METRICS.fast_wcl_ns.load(Ordering::Relaxed);
        let full_wcl = TROPICAL_METRICS.full_wcl_ns.load(Ordering::Relaxed);
        let fast_over_budget = fast_wcl > FAST_PATH_BUDGET_NS;
        let full_over_budget = full_wcl > FULL_PATH_BUDGET_NS;
        let tropical_bonus = match (fast_over_budget, full_over_budget) {
            (true, true) => 120_000u32,
            (false, true) => 60_000u32,
            _ => 0u32,
        };
        // Spectral phase transition: boost risk by 100k ppm when workload regime changes.
        let spectral_bonus = match self.cached_spectral_phase.load(Ordering::Relaxed) {
            2 => 100_000u32, // NewRegime
            1 => 50_000u32,  // Transitioning
            _ => 0u32,       // Stationary
        };
        // Rough-path signature anomaly: the signature captures ALL moments and
        // temporal ordering — strictly more powerful than spectral (2nd-order only).
        let sig_bonus = match self.cached_signature_state.load(Ordering::Relaxed) {
            2 => 75_000u32, // Anomalous
            _ => 0u32,      // Calibrating/Normal
        };
        // Persistent homology anomaly: detects structural changes in the data
        // shape that are invisible to all statistical methods.
        let topo_bonus = match self.cached_topological_state.load(Ordering::Relaxed) {
            2 => 80_000u32, // Anomalous
            _ => 0u32,      // Calibrating/Normal
        };
        let anytime_bonus = match self.cached_anytime_state[usize::from(ctx.family as u8)]
            .load(Ordering::Relaxed)
        {
            3 => 150_000u32, // Alarm
            2 => 60_000u32,  // Warning
            _ => 0u32,       // Calibrating/Normal
        };
        let cvar_bonus =
            match self.cached_cvar_state[usize::from(ctx.family as u8)].load(Ordering::Relaxed) {
                3 => 130_000u32, // Alarm
                2 => 45_000u32,  // Warning
                _ => 0u32,       // Calibrating/Normal
            };
        // Schrödinger bridge: entropic optimal transport detects regime
        // transitions as the W_ε distance between current and equilibrium policy.
        let bridge_bonus = match self.cached_bridge_state.load(Ordering::Relaxed) {
            2 => 90_000u32, // Transitioning
            _ => 0u32,      // Calibrating/Stable
        };
        // Large-deviations rate function: Cramér bound gives rigorous
        // exponential probability guarantees for catastrophic failure sequences.
        let ld_bonus =
            match self.cached_ld_state[usize::from(ctx.family as u8)].load(Ordering::Relaxed) {
                3 => 140_000u32, // Critical — rate function collapse
                2 => 55_000u32,  // Elevated
                _ => 0u32,       // Calibrating/Normal
            };
        // Hamilton-Jacobi-Isaacs reachability: formal worst-case safety
        // certificate. Breached = adversary has a winning strategy.
        let hji_bonus = match self.cached_hji_state.load(Ordering::Relaxed) {
            3 => 200_000u32, // Breached — inside backward reachable tube
            2 => 70_000u32,  // Approaching — near BRT boundary
            _ => 0u32,       // Calibrating/Safe
        };
        // Mean-field game congestion: Nash equilibrium deviation signals
        // resource coordination failure (tragedy of the commons).
        let mfg_bonus = match self.cached_mfg_state.load(Ordering::Relaxed) {
            3 => 100_000u32, // Collapsed — severe congestion failure
            2 => 40_000u32,  // Congested — above equilibrium
            _ => 0u32,       // Calibrating/Equilibrium
        };
        // p-adic valuation: non-Archimedean regime drift in floating-point
        // exponents. ExceptionalRegime means NaN/Inf/subnormal flood.
        let padic_bonus = match self.cached_padic_state.load(Ordering::Relaxed) {
            3 => 110_000u32, // ExceptionalRegime
            2 => 45_000u32,  // DenormalDrift
            _ => 0u32,       // Calibrating/Normal
        };
        // Symplectic reduction: resource lifecycle admissibility guard.
        // Inadmissible means outside the conservation-law polytope.
        let symplectic_bonus = match self.cached_symplectic_state.load(Ordering::Relaxed) {
            3 => 120_000u32, // Inadmissible — outside polytope
            2 => 50_000u32,  // NearBoundary — approaching capacity
            _ => 0u32,       // Calibrating/Admissible
        };
        // Sparse-recovery root-cause concentration:
        // focused high-energy support indicates a coherent fault source; critical
        // indicates high-residual adversarial or unstable latent dynamics.
        let sparse_bonus = match self.cached_sparse_state.load(Ordering::Relaxed) {
            4 => 150_000u32, // Critical
            3 => 70_000u32,  // Diffuse
            2 => 40_000u32,  // Focused
            _ => 0u32,       // Calibrating/Stable
        };
        let equivariant_bonus = match self.cached_equivariant_state.load(Ordering::Relaxed) {
            3 => 160_000u32, // Fractured cross-family symmetry
            2 => 60_000u32,  // Drift
            _ => 0u32,       // Calibrating/Aligned
        };
        // Higher-topos descent: locale/catalog coherence violation
        // signals i18n fallback chain corruption.
        let topos_bonus = match self.cached_topos_state.load(Ordering::Relaxed) {
            3 => 110_000u32, // Incoherent — sustained descent violation
            2 => 45_000u32,  // DescentViolation
            _ => 0u32,       // Calibrating/Coherent
        };
        // Commitment audit: martingale-based tamper detection for
        // session/accounting traces.
        let audit_bonus = match self.cached_audit_state.load(Ordering::Relaxed) {
            3 => 130_000u32, // TamperDetected — martingale alarm
            2 => 55_000u32,  // Anomalous — martingale warning
            _ => 0u32,       // Calibrating/Consistent
        };
        // Bayesian change-point: posterior mass on short run-lengths
        // signals abrupt shift in adverse-rate regime.
        let changepoint_bonus = match self.cached_changepoint_state.load(Ordering::Relaxed) {
            3 => 140_000u32, // ChangePoint — high posterior short mass
            2 => 50_000u32,  // Drift — moderate posterior shift
            _ => 0u32,       // Calibrating/Stable
        };
        // Conformal prediction: empirical coverage dropping below
        // finite-sample guarantee indicates distribution shift.
        let conformal_bonus = match self.cached_conformal_state.load(Ordering::Relaxed) {
            3 => 120_000u32, // CoverageFailure — severe miscoverage
            2 => 45_000u32,  // Undercoverage — coverage drifting
            _ => 0u32,       // Calibrating/Covered
        };
        // Decision-theoretic loss minimizer: cost explosion across all
        // action categories signals a fundamentally adversarial regime.
        let loss_min_bonus = match self.cached_loss_minimizer_state.load(Ordering::Relaxed) {
            4 => 160_000u32, // CostExplosion — all actions losing
            3 => 50_000u32,  // DenyBiased — deny is cheapest (suspicious)
            2 => 35_000u32,  // RepairBiased — repairs dominating
            _ => 0u32,       // Calibrating/Balanced
        };
        // Probabilistic coupling: strict/hardened divergence beyond
        // Hoeffding concentration bound signals mode inconsistency.
        let coupling_bonus = match self.cached_coupling_state.load(Ordering::Relaxed) {
            4 => 170_000u32, // CertificationFailure — modes incompatible
            3 => 65_000u32,  // Diverged — significant disagreement
            2 => 30_000u32,  // Drifting — mild disagreement
            _ => 0u32,       // Calibrating/Coupled
        };
        let fusion_bonus = self.cached_fusion_bonus_ppm.load(Ordering::Relaxed) as u32;
        // Microlocal sheaf: wavefront set propagation fault-surface control.
        // SingularSupport means dense active microsupport.
        let microlocal_bonus = match self.cached_microlocal_state.load(Ordering::Relaxed) {
            3 => 130_000u32, // SingularSupport — dense fault surface
            2 => 55_000u32,  // FaultBoundary — localized fault
            _ => 0u32,       // Calibrating/Propagating
        };
        // Serre spectral sequence: cross-layer lifting failure detection.
        let serre_bonus = match self.cached_serre_state.load(Ordering::Relaxed) {
            3 => 140_000u32, // Collapsed — diverging spectral sequence
            2 => 50_000u32,  // LiftingFailure — non-trivial differentials
            _ => 0u32,       // Calibrating/Converged
        };
        // Clifford algebra: SIMD alignment/overlap correctness.
        let clifford_bonus = match self.cached_clifford_state.load(Ordering::Relaxed) {
            3 => 120_000u32, // OverlapViolation — Pin parity break
            2 => 45_000u32,  // MisalignmentDrift — bivector energy rising
            _ => 0u32,       // Calibrating/Aligned
        };
        let pre_design_risk_ppm = base_risk_ppm
            .saturating_add(sampled_bonus)
            .saturating_add(cohomology_bonus)
            .saturating_add(tropical_bonus)
            .saturating_add(spectral_bonus)
            .saturating_add(sig_bonus)
            .saturating_add(topo_bonus)
            .saturating_add(anytime_bonus)
            .saturating_add(cvar_bonus)
            .saturating_add(bridge_bonus)
            .saturating_add(ld_bonus)
            .saturating_add(hji_bonus)
            .saturating_add(mfg_bonus)
            .saturating_add(padic_bonus)
            .saturating_add(symplectic_bonus)
            .saturating_add(sparse_bonus)
            .saturating_add(equivariant_bonus)
            .saturating_add(topos_bonus)
            .saturating_add(audit_bonus)
            .saturating_add(changepoint_bonus)
            .saturating_add(conformal_bonus)
            .saturating_add(loss_min_bonus)
            .saturating_add(coupling_bonus)
            .saturating_add(fusion_bonus)
            .saturating_add(microlocal_bonus)
            .saturating_add(serre_bonus)
            .saturating_add(clifford_bonus)
            .min(1_000_000);

        // D-optimal probe scheduling:
        // choose heavy monitors under budget to maximize online identifiability.
        let design_bonus = {
            let adverse_hint = ctx.bloom_negative || (ctx.is_write && ctx.requested_bytes > 4096);
            let mut design = self.design.lock();
            let plan =
                design.choose_plan(mode, pre_design_risk_ppm, adverse_hint, fast_over_budget);
            let ident_ppm = design.identifiability_ppm();
            self.cached_probe_mask
                .store(u64::from(plan.mask), Ordering::Relaxed);
            self.cached_design_ident_ppm
                .store(u64::from(ident_ppm), Ordering::Relaxed);
            self.cached_design_budget_ns
                .store(plan.budget_ns, Ordering::Relaxed);
            self.cached_design_expected_ns
                .store(plan.expected_cost_ns, Ordering::Relaxed);
            self.cached_design_selected
                .store(plan.selected_count(), Ordering::Relaxed);
            if ident_ppm < 150_000 {
                95_000u32
            } else if ident_ppm < 300_000 {
                40_000u32
            } else {
                0u32
            }
        };

        let risk_upper_bound_ppm = pre_design_risk_ppm
            .saturating_add(design_bonus)
            .min(1_000_000);

        let limits = self.controller.limits(mode);
        let mut profile =
            self.router
                .select_profile(ctx.family, mode, risk_upper_bound_ppm, ctx.contention_hint);
        let pareto_profile = self.pareto.recommend_profile(
            mode,
            ctx.family,
            risk_upper_bound_ppm,
            limits.full_validation_trigger_ppm,
            limits.repair_trigger_ppm,
        );
        let pareto_budget_exhausted = self.pareto.is_budget_exhausted(mode, ctx.family);

        let family_idx = usize::from(ctx.family as u8);
        let oracle_bias = self.cached_oracle_bias[family_idx].load(Ordering::Relaxed);
        if oracle_bias == 0 && risk_upper_bound_ppm >= limits.repair_trigger_ppm / 2 {
            profile = ValidationProfile::Full;
        } else if oracle_bias == 2 && risk_upper_bound_ppm <= limits.full_validation_trigger_ppm / 3
        {
            profile = ValidationProfile::Fast;
        }

        // Tropical budget pressure acts as a runtime governor:
        // - if full path is over budget while fast path is healthy and risk is low,
        //   bias toward fast validation;
        // - if both paths are over budget under elevated risk, force full checks.
        if full_over_budget && !fast_over_budget && risk_upper_bound_ppm < limits.repair_trigger_ppm
        {
            profile = ValidationProfile::Fast;
        }
        if fast_over_budget && full_over_budget && risk_upper_bound_ppm >= limits.repair_trigger_ppm
        {
            profile = ValidationProfile::Full;
        }
        if consistency_faults > 0 && mode.heals_enabled() {
            profile = ValidationProfile::Full;
        }
        if self.cached_design_selected.load(Ordering::Relaxed) <= 2
            && risk_upper_bound_ppm >= limits.full_validation_trigger_ppm / 2
        {
            profile = ValidationProfile::Full;
        }
        if self.cached_sparse_state.load(Ordering::Relaxed) >= 4 {
            profile = ValidationProfile::Full;
        }
        if self.cached_equivariant_state.load(Ordering::Relaxed) >= 3 {
            profile = ValidationProfile::Full;
        }

        // Pareto kernel contributes a mode-aware latency/risk tradeoff with
        // explicit regret accounting. Merge conservatively with existing profile.
        if matches!(pareto_profile, ValidationProfile::Full) {
            profile = ValidationProfile::Full;
        }
        // In strict mode, once a family has exhausted its regret budget, lock
        // routing to Pareto's deterministic empirical-optimal arm unless hard
        // risk gates already demand full validation.
        if matches!(mode, SafetyLevel::Strict)
            && pareto_budget_exhausted
            && risk_upper_bound_ppm < limits.full_validation_trigger_ppm
        {
            profile = pareto_profile;
        }

        // Adaptive allocator guard: when quarantine depth is low under elevated
        // risk, force full validation to preserve temporal safety.
        if matches!(ctx.family, ApiFamily::Allocator)
            && mode.heals_enabled()
            && current_depth() < 128
            && risk_upper_bound_ppm >= limits.repair_trigger_ppm / 2
        {
            profile = ValidationProfile::Full;
        }
        if self.cached_cvar_state[usize::from(ctx.family as u8)].load(Ordering::Relaxed) >= 3 {
            profile = ValidationProfile::Full;
        }

        let admissible = self
            .barrier
            .admissible(&ctx, mode, profile, risk_upper_bound_ppm, limits);

        let action = if !admissible {
            if mode.heals_enabled() {
                MembraneAction::Repair(HealingAction::ReturnSafeDefault)
            } else {
                MembraneAction::Deny
            }
        } else if profile.requires_full()
            || risk_upper_bound_ppm >= limits.full_validation_trigger_ppm
        {
            MembraneAction::FullValidate
        } else if mode.heals_enabled() && risk_upper_bound_ppm >= limits.repair_trigger_ppm {
            MembraneAction::Repair(HealingAction::UpgradeToSafeVariant)
        } else {
            MembraneAction::Allow
        };

        RuntimeDecision {
            profile,
            action,
            policy_id: compute_policy_id(mode, ctx.family, profile, action),
            risk_upper_bound_ppm,
        }
    }

    /// Return the current contextual check ordering for a given family/context.
    ///
    /// This is intentionally lightweight and is used by hot validation paths
    /// (notably pointer validation) to execute stage order selected by the
    /// online check oracle.
    #[must_use]
    pub fn check_ordering(
        &self,
        family: ApiFamily,
        aligned: bool,
        recent_page: bool,
    ) -> [CheckStage; 7] {
        let ctx = CheckContext {
            family: family as u8,
            aligned,
            recent_page,
        };
        let oracle = self.sampled_oracle.lock();
        *oracle.get_ordering(&ctx)
    }

    /// Feed exact stage-exit outcomes for the contextual check oracle.
    ///
    /// This closes the loop between runtime-selected ordering and real pipeline
    /// exits so the oracle learns from true hot-path behavior.
    pub fn note_check_order_outcome(
        &self,
        family: ApiFamily,
        aligned: bool,
        recent_page: bool,
        ordering_used: &[CheckStage; 7],
        exit_stage: Option<usize>,
    ) {
        let mode = crate::config::safety_level();
        let ctx = CheckContext {
            family: family as u8,
            aligned,
            recent_page,
        };
        let mut oracle = self.sampled_oracle.lock();
        oracle.report_outcome(&ctx, ordering_used, exit_stage);
        let refreshed = *oracle.get_ordering(&ctx);
        let bias = oracle_bias_from_ordering(&refreshed, mode);
        self.cached_oracle_bias[usize::from(family as u8)].store(bias, Ordering::Relaxed);
    }

    /// Feed observed runtime outcome back into online controllers.
    pub fn observe_validation_result(
        &self,
        family: ApiFamily,
        profile: ValidationProfile,
        estimated_cost_ns: u64,
        adverse: bool,
    ) {
        let mode = crate::config::safety_level();
        let probe_mask = self.cached_probe_mask.load(Ordering::Relaxed) as u32;
        self.risk.observe(family, adverse);
        self.router
            .observe(family, profile, estimated_cost_ns, adverse);
        self.controller.observe(estimated_cost_ns, adverse);
        let risk_bound_ppm = self.risk.upper_bound_ppm(family);
        self.pareto.observe(
            mode,
            family,
            profile,
            estimated_cost_ns,
            adverse,
            risk_bound_ppm,
        );

        let mut spectral_anomaly = None;
        let mut rough_anomaly = None;
        let mut persistence_anomaly = None;
        let mut anytime_anomaly = None;
        let mut cvar_anomaly = None;
        let mut bridge_anomaly = None;
        let mut ld_anomaly = None;
        let mut hji_anomaly = None;
        let mut mfg_anomaly = None;
        let mut padic_anomaly = None;
        let mut symplectic_anomaly = None;
        let mut topos_anomaly = None;
        let mut audit_anomaly = None;
        let mut changepoint_anomaly = None;
        let mut conformal_anomaly = None;
        let mut loss_minimizer_anomaly = None;
        let mut coupling_anomaly = None;

        // Feed tropical latency compositor with per-path observations.
        {
            let path = match profile {
                ValidationProfile::Fast => PipelinePath::FastExit,
                ValidationProfile::Full => PipelinePath::Full,
            };
            let mut tropical = self.tropical.lock();
            tropical.observe_path(path, estimated_cost_ns);
            // Publish metrics every 256 observations.
            if tropical.total_observations().is_multiple_of(256) {
                TROPICAL_METRICS.publish(&tropical);
            }
        }

        // Feed spectral monitor with multi-dimensional observation.
        if ProbePlan::includes_mask(probe_mask, Probe::Spectral) {
            let contention = f64::from(
                self.cached_oracle_bias[usize::from(family as u8)].load(Ordering::Relaxed),
            ) / 2.0;
            let hit_rate = if adverse { 1.0 } else { 0.0 };
            let risk_score = f64::from(risk_bound_ppm) / 1_000_000.0;
            let latency = (estimated_cost_ns as f64).ln_1p();
            let mut spectral = self.spectral.lock();
            spectral.observe(risk_score, latency, contention, hit_rate);
            // Cache the phase state for the hot-path decision.
            let phase = spectral.phase();
            let phase_code = match phase {
                PhaseState::Stationary => 0u8,
                PhaseState::Transitioning => 1u8,
                PhaseState::NewRegime => 2u8,
            };
            self.cached_spectral_phase
                .store(phase_code, Ordering::Relaxed);
            spectral_anomaly = Some(!matches!(phase, PhaseState::Stationary));
        }

        // Feed rough-path/persistence monitors with the same 4D observation vector.
        let run_rough = ProbePlan::includes_mask(probe_mask, Probe::RoughPath);
        let run_persistence = ProbePlan::includes_mask(probe_mask, Probe::Persistence);
        if run_rough || run_persistence {
            let rp_risk = f64::from(risk_bound_ppm) / 1_000_000.0;
            let rp_latency = (estimated_cost_ns as f64).ln_1p();
            let rp_contention = f64::from(
                self.cached_oracle_bias[usize::from(family as u8)].load(Ordering::Relaxed),
            ) / 2.0;
            let rp_hit_rate = if adverse { 1.0 } else { 0.0 };
            let obs = [rp_risk, rp_latency, rp_contention, rp_hit_rate];
            if run_rough {
                let mut rp = self.rough_path.lock();
                rp.observe(obs);
                let state = rp.state();
                let sig_state_code = match state {
                    SignatureState::Calibrating => 0u8,
                    SignatureState::Normal => 1u8,
                    SignatureState::Anomalous => 2u8,
                };
                rough_anomaly = Some(matches!(state, SignatureState::Anomalous));
                self.cached_signature_state
                    .store(sig_state_code, Ordering::Relaxed);
            }
            if run_persistence {
                let mut pd = self.persistence.lock();
                pd.observe(obs);
                let state = pd.state();
                let topo_state_code = match state {
                    TopologicalState::Calibrating => 0u8,
                    TopologicalState::Normal => 1u8,
                    TopologicalState::Anomalous => 2u8,
                };
                persistence_anomaly = Some(matches!(state, TopologicalState::Anomalous));
                self.cached_topological_state
                    .store(topo_state_code, Ordering::Relaxed);
            }
        }

        // Feed anytime-valid sequential detector and cache state for hot path.
        if ProbePlan::includes_mask(probe_mask, Probe::Anytime) {
            let state_code = {
                let mon = self.anytime.lock();
                mon.observe(family, adverse);
                let state = mon.state(family);
                anytime_anomaly = Some(matches!(
                    state,
                    SequentialState::Warning | SequentialState::Alarm
                ));
                match state {
                    SequentialState::Calibrating => 0u8,
                    SequentialState::Normal => 1u8,
                    SequentialState::Warning => 2u8,
                    SequentialState::Alarm => 3u8,
                }
            };
            self.cached_anytime_state[usize::from(family as u8)]
                .store(state_code, Ordering::Relaxed);
        }

        // Feed robust CVaR tail controller and cache family state.
        if ProbePlan::includes_mask(probe_mask, Probe::Cvar) {
            let state_code = {
                let cvar = self.cvar.lock();
                cvar.observe(family, profile, estimated_cost_ns);
                let state = cvar.family_state(mode, family);
                cvar_anomaly = Some(matches!(state, TailState::Warning | TailState::Alarm));
                match state {
                    TailState::Calibrating => 0u8,
                    TailState::Normal => 1u8,
                    TailState::Warning => 2u8,
                    TailState::Alarm => 3u8,
                }
            };
            self.cached_cvar_state[usize::from(family as u8)].store(state_code, Ordering::Relaxed);
        }

        // Feed Schrödinger bridge with inferred action index.
        // Maps (profile, adverse, mode) to the 4-action simplex:
        //   0 = Allow, 1 = FullValidate, 2 = Repair, 3 = Deny.
        if ProbePlan::includes_mask(probe_mask, Probe::Bridge) {
            let action_idx = match (profile, adverse, mode.heals_enabled()) {
                (ValidationProfile::Fast, false, _) => 0, // Allow
                (ValidationProfile::Full, false, _) => 1, // FullValidate
                (_, true, true) => 2,                     // Repair (hardened)
                (_, true, false) => 3,                    // Deny (strict)
            };
            let bridge_code = {
                let mut br = self.bridge.lock();
                br.observe_action(action_idx);
                let state = br.state();
                bridge_anomaly = Some(matches!(state, BridgeState::Transitioning));
                match state {
                    BridgeState::Calibrating => 0u8,
                    BridgeState::Stable => 1u8,
                    BridgeState::Transitioning => 2u8,
                }
            };
            self.cached_bridge_state
                .store(bridge_code, Ordering::Relaxed);
        }

        // Feed large-deviations monitor with per-family adverse indicator.
        // The Cramér rate function tracks how quickly the empirical adverse
        // frequency deviates from its baseline, giving exact exponential bounds.
        if ProbePlan::includes_mask(probe_mask, Probe::LargeDeviations) {
            let fidx = usize::from(family as u8);
            let ld_code = {
                let mut ld = self.large_dev.lock();
                ld.observe(fidx, adverse);
                let state = ld.state(fidx);
                ld_anomaly = Some(matches!(state, RateState::Elevated | RateState::Critical));
                match state {
                    RateState::Calibrating => 0u8,
                    RateState::Normal => 1u8,
                    RateState::Elevated => 2u8,
                    RateState::Critical => 3u8,
                }
            };
            self.cached_ld_state[fidx].store(ld_code, Ordering::Relaxed);
        }

        // Feed HJI reachability controller with (risk, latency, adverse).
        // The pre-computed value function gives O(1) formal safety lookup.
        if ProbePlan::includes_mask(probe_mask, Probe::Hji) {
            let hji_code = {
                let mut hji = self.hji.lock();
                hji.observe(risk_bound_ppm, estimated_cost_ns, adverse);
                let state = hji.state();
                hji_anomaly = Some(matches!(
                    state,
                    ReachState::Approaching | ReachState::Breached
                ));
                match state {
                    ReachState::Calibrating => 0u8,
                    ReachState::Safe => 1u8,
                    ReachState::Approaching => 2u8,
                    ReachState::Breached => 3u8,
                }
            };
            self.cached_hji_state.store(hji_code, Ordering::Relaxed);
        }

        // Feed mean-field game controller with contention proxy.
        // We use estimated_cost_ns as a contention signal: high validation
        // latency indicates resource contention across families.
        if ProbePlan::includes_mask(probe_mask, Probe::MeanField) {
            let contention_hint = estimated_cost_ns.min(65535) as u16;
            let mfg_code = {
                let mut mfg = self.mfg.lock();
                mfg.observe(contention_hint);
                let state = mfg.state();
                mfg_anomaly = Some(matches!(state, MfgState::Congested | MfgState::Collapsed));
                match state {
                    MfgState::Calibrating => 0u8,
                    MfgState::Equilibrium => 1u8,
                    MfgState::Congested => 2u8,
                    MfgState::Collapsed => 3u8,
                }
            };
            self.cached_mfg_state.store(mfg_code, Ordering::Relaxed);
        }

        // Feed p-adic valuation monitor with risk bound as a floating-point
        // value. The 2-adic exponent structure of the risk metric reveals
        // numerical regime transitions invisible to Archimedean analysis.
        if ProbePlan::includes_mask(probe_mask, Probe::Padic) {
            let risk_f64 = risk_bound_ppm as f64;
            let padic_code = {
                let mut padic = self.padic.lock();
                padic.observe_f64(risk_f64);
                let state = padic.state();
                padic_anomaly = Some(matches!(
                    state,
                    PadicState::DenormalDrift | PadicState::ExceptionalRegime
                ));
                match state {
                    PadicState::Calibrating => 0u8,
                    PadicState::Normal => 1u8,
                    PadicState::DenormalDrift => 2u8,
                    PadicState::ExceptionalRegime => 3u8,
                }
            };
            self.cached_padic_state.store(padic_code, Ordering::Relaxed);
        }

        // Feed symplectic reduction controller with resource lifecycle events.
        // Allocator family maps to SharedMemory acquire/release;
        // Threading maps to Semaphore; others map to FileDescriptor.
        if ProbePlan::includes_mask(probe_mask, Probe::Symplectic) {
            let resource = match family {
                ApiFamily::Allocator => ResourceType::SharedMemory,
                ApiFamily::Threading => ResourceType::Semaphore,
                ApiFamily::Resolver => ResourceType::MessageQueue,
                _ => ResourceType::FileDescriptor,
            };
            let sympl_code = {
                let mut sympl = self.symplectic.lock();
                if adverse {
                    sympl.acquire(resource);
                } else {
                    sympl.release(resource);
                }
                let state = sympl.state();
                symplectic_anomaly = Some(matches!(
                    state,
                    SymplecticState::NearBoundary | SymplecticState::Inadmissible
                ));
                match state {
                    SymplecticState::Calibrating => 0u8,
                    SymplecticState::Admissible => 1u8,
                    SymplecticState::NearBoundary => 2u8,
                    SymplecticState::Inadmissible => 3u8,
                }
            };
            self.cached_symplectic_state
                .store(sympl_code, Ordering::Relaxed);
        }

        // Feed higher-topos descent controller with locale-scope proxies.
        // We map (family, adverse) to a scope/result/depth observation:
        // scope_hash from family index, result_hash from risk_bound_ppm,
        // fallback_depth from profile (Full = deeper fallback).
        if ProbePlan::includes_mask(probe_mask, Probe::HigherTopos) {
            let scope_hash = (family as u64).wrapping_mul(0x9e3779b97f4a7c15) ^ estimated_cost_ns;
            let result_hash = u64::from(risk_bound_ppm).wrapping_mul(0x517cc1b727220a95);
            let fallback_depth = if matches!(profile, ValidationProfile::Full) {
                2u8
            } else {
                0u8
            };
            let topos_code = {
                let mut topos = self.topos.lock();
                topos.observe(scope_hash, result_hash, fallback_depth);
                let state = topos.state();
                topos_anomaly = Some(matches!(
                    state,
                    ToposState::DescentViolation | ToposState::Incoherent
                ));
                match state {
                    ToposState::Calibrating => 0u8,
                    ToposState::Coherent => 1u8,
                    ToposState::DescentViolation => 2u8,
                    ToposState::Incoherent => 3u8,
                }
            };
            self.cached_topos_state.store(topos_code, Ordering::Relaxed);
        }

        // Feed commitment audit controller with session state transitions.
        // We encode (family, profile) as state indices and use risk_bound_ppm
        // XOR'd with estimated_cost_ns as a transition fingerprint.
        if ProbePlan::includes_mask(probe_mask, Probe::CommitmentAudit) {
            let from_state = family as u32;
            let to_state = (family as u32).wrapping_mul(3).wrapping_add(profile as u32);
            let transition_hash =
                u64::from(risk_bound_ppm) ^ estimated_cost_ns.wrapping_mul(0x6c62272e07bb0142);
            let audit_code = {
                let mut audit = self.audit.lock();
                audit.observe_transition(from_state, to_state, transition_hash);
                let state = audit.state();
                audit_anomaly = Some(matches!(
                    state,
                    AuditState::Anomalous | AuditState::TamperDetected
                ));
                match state {
                    AuditState::Calibrating => 0u8,
                    AuditState::Consistent => 1u8,
                    AuditState::Anomalous => 2u8,
                    AuditState::TamperDetected => 3u8,
                }
            };
            self.cached_audit_state.store(audit_code, Ordering::Relaxed);
        }

        // Feed Bayesian change-point detector with adverse indicator.
        // The run-length posterior tracks abrupt shifts in failure rates
        // that gradual EWMA smoothers miss entirely.
        if ProbePlan::includes_mask(probe_mask, Probe::Changepoint) {
            let cp_code = {
                let mut cp = self.changepoint.lock();
                cp.observe(adverse);
                let state = cp.state();
                changepoint_anomaly = Some(matches!(
                    state,
                    ChangepointState::Drift | ChangepointState::ChangePoint
                ));
                match state {
                    ChangepointState::Calibrating => 0u8,
                    ChangepointState::Stable => 1u8,
                    ChangepointState::Drift => 2u8,
                    ChangepointState::ChangePoint => 3u8,
                }
            };
            self.cached_changepoint_state
                .store(cp_code, Ordering::Relaxed);
        }

        // Feed conformal risk controller with risk score as nonconformity score.
        // The distribution-free coverage guarantee detects when the runtime
        // risk distribution has shifted beyond finite-sample bounds.
        if ProbePlan::includes_mask(probe_mask, Probe::Conformal) {
            let conf_code = {
                let score = f64::from(risk_bound_ppm) / 1_000_000.0;
                let mut conf = self.conformal.lock();
                conf.observe(score);
                let state = conf.state();
                conformal_anomaly = Some(matches!(
                    state,
                    ConformalState::Undercoverage | ConformalState::CoverageFailure
                ));
                match state {
                    ConformalState::Calibrating => 0u8,
                    ConformalState::Covered => 1u8,
                    ConformalState::Undercoverage => 2u8,
                    ConformalState::CoverageFailure => 3u8,
                }
            };
            self.cached_conformal_state
                .store(conf_code, Ordering::Relaxed);
        }

        // Feed decision-theoretic loss minimizer with action/outcome data.
        // The proper scoring framework learns which membrane action minimizes
        // expected regret across the current operational regime.
        if ProbePlan::includes_mask(probe_mask, Probe::LossMinimizer) {
            let action_code = match (profile, adverse) {
                (ValidationProfile::Fast, false) => 0u8,  // Allow
                (ValidationProfile::Full, false) => 1u8,  // FullValidate
                (_, true) if mode.heals_enabled() => 2u8, // Repair
                (_, true) => 3u8,                         // Deny
            };
            let lm_code = {
                let mut lm = self.loss_minimizer.lock();
                lm.observe(action_code, adverse, estimated_cost_ns);
                let state = lm.state();
                loss_minimizer_anomaly = Some(matches!(
                    state,
                    LossState::DenyBiased | LossState::CostExplosion
                ));
                match state {
                    LossState::Calibrating => 0u8,
                    LossState::Balanced => 1u8,
                    LossState::RepairBiased => 2u8,
                    LossState::DenyBiased => 3u8,
                    LossState::CostExplosion => 4u8,
                }
            };
            self.cached_loss_minimizer_state
                .store(lm_code, Ordering::Relaxed);
        }

        // Feed probabilistic coupling controller with strict/hardened action pair.
        // We infer the "other mode" action from current risk level to simulate
        // what the opposite mode would have chosen.
        if ProbePlan::includes_mask(probe_mask, Probe::Coupling) {
            let strict_action = if risk_bound_ppm >= 500_000 {
                3u8 // Deny
            } else if risk_bound_ppm >= 200_000 {
                1u8 // FullValidate
            } else {
                0u8 // Allow
            };
            let hardened_action = if risk_bound_ppm >= 500_000 {
                2u8 // Repair (hardened heals instead of deny)
            } else if risk_bound_ppm >= 150_000 {
                1u8 // FullValidate (lower threshold)
            } else {
                0u8 // Allow
            };
            let cp_code = {
                let mut cp = self.coupling.lock();
                cp.observe(strict_action, hardened_action, adverse);
                let state = cp.state();
                coupling_anomaly = Some(matches!(
                    state,
                    CouplingState::Diverged | CouplingState::CertificationFailure
                ));
                match state {
                    CouplingState::Calibrating => 0u8,
                    CouplingState::Coupled => 1u8,
                    CouplingState::Drifting => 2u8,
                    CouplingState::Diverged => 3u8,
                    CouplingState::CertificationFailure => 4u8,
                }
            };
            self.cached_coupling_state.store(cp_code, Ordering::Relaxed);
        }

        // Feed microlocal sheaf controller with stratum transition proxy.
        // Signal-heavy families (Threading, Resolver) map to SignalBoundary;
        // StringMemory maps to LongjmpBoundary (longjmp crosses cleanup);
        // others map to NormalFlow.
        {
            let from = Stratum::NormalFlow;
            let to = match family {
                ApiFamily::Threading => Stratum::SignalBoundary,
                ApiFamily::Resolver => Stratum::SignalBoundary,
                ApiFamily::StringMemory if adverse => Stratum::LongjmpBoundary,
                _ => Stratum::NormalFlow,
            };
            let mc_code = {
                let mut mc = self.microlocal.lock();
                mc.observe_and_update(from, to, adverse);
                match mc.state() {
                    MicrolocalState::Calibrating => 0u8,
                    MicrolocalState::Propagating => 1u8,
                    MicrolocalState::FaultBoundary => 2u8,
                    MicrolocalState::SingularSupport => 3u8,
                }
            };
            self.cached_microlocal_state
                .store(mc_code, Ordering::Relaxed);
        }

        // Feed Serre spectral sequence controller with cross-layer lifting proxy.
        // We map (family, adverse) to a layer-pair and invariant-class observation:
        // ABI→Membrane for Allocator/StringMemory; Membrane→Core for others.
        {
            let layer_pair = match family {
                ApiFamily::Allocator | ApiFamily::StringMemory => LayerPair::AbiToMembrane,
                ApiFamily::Threading | ApiFamily::Resolver => LayerPair::AbiToCore,
                _ => LayerPair::MembraneToCore,
            };
            let inv_class = match family {
                ApiFamily::Allocator => InvariantClass::ResourceLifecycle,
                ApiFamily::StringMemory => InvariantClass::ReturnSemantics,
                ApiFamily::Threading => InvariantClass::SideEffectOrder,
                _ => InvariantClass::ErrorRecovery,
            };
            let serre_code = {
                let mut serre = self.serre.lock();
                serre.observe_and_update(layer_pair, inv_class, !adverse);
                match serre.state() {
                    SpectralSequenceState::Calibrating => 0u8,
                    SpectralSequenceState::Converged => 1u8,
                    SpectralSequenceState::LiftingFailure => 2u8,
                    SpectralSequenceState::Collapsed => 3u8,
                }
            };
            self.cached_serre_state.store(serre_code, Ordering::Relaxed);
        }

        // Feed Clifford controller with alignment observation proxy.
        // Source/destination alignment inferred from addr_hint and requested_bytes.
        {
            let obs = AlignmentObservation {
                src_alignment: AlignmentRegime::classify(estimated_cost_ns as usize & 0xFF),
                dst_alignment: AlignmentRegime::classify(risk_bound_ppm as usize & 0xFF),
                overlap_fraction: if adverse { 0.5 } else { 0.0 },
                length_regime: (estimated_cost_ns as f64).clamp(0.0, 200.0) / 200.0,
            };
            let cliff_code = {
                let mut cliff = self.clifford.lock();
                cliff.observe_and_update(obs);
                match cliff.state() {
                    CliffordState::Calibrating => 0u8,
                    CliffordState::Aligned => 1u8,
                    CliffordState::MisalignmentDrift => 2u8,
                    CliffordState::OverlapViolation => 3u8,
                }
            };
            self.cached_clifford_state
                .store(cliff_code, Ordering::Relaxed);
        }

        let mut anomaly_vec = [false; Probe::COUNT];
        if let Some(flag) = spectral_anomaly {
            anomaly_vec[Probe::Spectral as usize] = flag;
        }
        if let Some(flag) = rough_anomaly {
            anomaly_vec[Probe::RoughPath as usize] = flag;
        }
        if let Some(flag) = persistence_anomaly {
            anomaly_vec[Probe::Persistence as usize] = flag;
        }
        if let Some(flag) = anytime_anomaly {
            anomaly_vec[Probe::Anytime as usize] = flag;
        }
        if let Some(flag) = cvar_anomaly {
            anomaly_vec[Probe::Cvar as usize] = flag;
        }
        if let Some(flag) = bridge_anomaly {
            anomaly_vec[Probe::Bridge as usize] = flag;
        }
        if let Some(flag) = ld_anomaly {
            anomaly_vec[Probe::LargeDeviations as usize] = flag;
        }
        if let Some(flag) = hji_anomaly {
            anomaly_vec[Probe::Hji as usize] = flag;
        }
        if let Some(flag) = mfg_anomaly {
            anomaly_vec[Probe::MeanField as usize] = flag;
        }
        if let Some(flag) = padic_anomaly {
            anomaly_vec[Probe::Padic as usize] = flag;
        }
        if let Some(flag) = symplectic_anomaly {
            anomaly_vec[Probe::Symplectic as usize] = flag;
        }
        if let Some(flag) = topos_anomaly {
            anomaly_vec[Probe::HigherTopos as usize] = flag;
        }
        if let Some(flag) = audit_anomaly {
            anomaly_vec[Probe::CommitmentAudit as usize] = flag;
        }
        if let Some(flag) = changepoint_anomaly {
            anomaly_vec[Probe::Changepoint as usize] = flag;
        }
        if let Some(flag) = conformal_anomaly {
            anomaly_vec[Probe::Conformal as usize] = flag;
        }
        if let Some(flag) = loss_minimizer_anomaly {
            anomaly_vec[Probe::LossMinimizer as usize] = flag;
        }
        if let Some(flag) = coupling_anomaly {
            anomaly_vec[Probe::Coupling as usize] = flag;
        }

        // Feed sparse-recovery latent controller with executed-probe anomalies.
        {
            let sparse_code = {
                let mut sparse = self.sparse.lock();
                sparse.observe(probe_mask, anomaly_vec, adverse);
                match sparse.state() {
                    SparseState::Calibrating => 0u8,
                    SparseState::Stable => 1u8,
                    SparseState::Focused => 2u8,
                    SparseState::Diffuse => 3u8,
                    SparseState::Critical => 4u8,
                }
            };
            self.cached_sparse_state
                .store(sparse_code, Ordering::Relaxed);
        }

        // Feed equivariant transport controller (always-on, O(1)):
        // tracks cross-family symmetry breaking under mode/profile actions.
        let equivariant_anomaly = {
            let (eq_code, eq_summary) = {
                let mut eq = self.equivariant.lock();
                eq.observe(
                    family,
                    mode,
                    profile,
                    estimated_cost_ns,
                    adverse,
                    risk_bound_ppm,
                );
                let summary = eq.summary();
                let code = match summary.state {
                    EquivariantState::Calibrating => 0u8,
                    EquivariantState::Aligned => 1u8,
                    EquivariantState::Drift => 2u8,
                    EquivariantState::Fractured => 3u8,
                };
                (code, summary)
            };
            self.cached_equivariant_state
                .store(eq_code, Ordering::Relaxed);
            self.cached_equivariant_alignment_ppm
                .store(u64::from(eq_summary.alignment_ppm), Ordering::Relaxed);
            self.cached_equivariant_orbit
                .store(eq_summary.dominant_orbit, Ordering::Relaxed);
            eq_code >= 2
        };

        // Feed robust fusion controller from current anomaly severity vector.
        {
            let severity = [
                self.cached_spectral_phase.load(Ordering::Relaxed), // 0..2
                self.cached_signature_state.load(Ordering::Relaxed), // 0..2
                self.cached_topological_state.load(Ordering::Relaxed), // 0..2
                self.cached_anytime_state[usize::from(family as u8)].load(Ordering::Relaxed), // 0..3
                self.cached_cvar_state[usize::from(family as u8)].load(Ordering::Relaxed), // 0..3
                self.cached_bridge_state.load(Ordering::Relaxed),                          // 0..2
                self.cached_ld_state[usize::from(family as u8)].load(Ordering::Relaxed),   // 0..3
                self.cached_hji_state.load(Ordering::Relaxed),                             // 0..3
                self.cached_mfg_state.load(Ordering::Relaxed),                             // 0..3
                self.cached_padic_state.load(Ordering::Relaxed),                           // 0..3
                self.cached_symplectic_state.load(Ordering::Relaxed),                      // 0..3
                self.cached_sparse_state.load(Ordering::Relaxed),                          // 0..4
                self.cached_equivariant_state.load(Ordering::Relaxed),                     // 0..3
                self.cached_topos_state.load(Ordering::Relaxed),                           // 0..3
                self.cached_audit_state.load(Ordering::Relaxed),                           // 0..3
                self.cached_changepoint_state.load(Ordering::Relaxed),                     // 0..3
                self.cached_conformal_state.load(Ordering::Relaxed),                       // 0..3
                self.cached_loss_minimizer_state.load(Ordering::Relaxed),                  // 0..4
                self.cached_coupling_state.load(Ordering::Relaxed),                        // 0..4
                self.cached_microlocal_state.load(Ordering::Relaxed),                      // 0..3
                self.cached_serre_state.load(Ordering::Relaxed),                           // 0..3
                self.cached_clifford_state.load(Ordering::Relaxed),                        // 0..3
            ];
            let summary = {
                let mut fusion = self.fusion.lock();
                fusion.observe(severity, adverse, mode)
            };
            self.cached_fusion_bonus_ppm
                .store(u64::from(summary.bonus_ppm), Ordering::Relaxed);
            self.cached_fusion_entropy_milli
                .store(u64::from(summary.entropy_milli), Ordering::Relaxed);
            self.cached_fusion_drift_ppm
                .store(u64::from(summary.drift_ppm), Ordering::Relaxed);
            self.cached_fusion_dominant_signal
                .store(summary.dominant_signal, Ordering::Relaxed);
        }

        // Record executed probes into the design kernel for online information updates.
        {
            let mut design = self.design.lock();
            if let Some(flag) = spectral_anomaly {
                design.record_probe(Probe::Spectral, flag);
            }
            if let Some(flag) = rough_anomaly {
                design.record_probe(Probe::RoughPath, flag);
            }
            if let Some(flag) = persistence_anomaly {
                design.record_probe(Probe::Persistence, flag);
            }
            if let Some(flag) = anytime_anomaly {
                design.record_probe(Probe::Anytime, flag);
            }
            if let Some(flag) = cvar_anomaly {
                design.record_probe(Probe::Cvar, flag);
            }
            if let Some(flag) = bridge_anomaly {
                design.record_probe(Probe::Bridge, flag);
            }
            if let Some(flag) = ld_anomaly {
                design.record_probe(Probe::LargeDeviations, flag);
            }
            if let Some(flag) = hji_anomaly {
                design.record_probe(Probe::Hji, flag);
            }
            if let Some(flag) = mfg_anomaly {
                design.record_probe(Probe::MeanField, flag);
            }
            if let Some(flag) = padic_anomaly {
                design.record_probe(Probe::Padic, flag);
            }
            if let Some(flag) = symplectic_anomaly {
                design.record_probe(Probe::Symplectic, flag);
            }
            if let Some(flag) = topos_anomaly {
                design.record_probe(Probe::HigherTopos, flag);
            }
            if let Some(flag) = audit_anomaly {
                design.record_probe(Probe::CommitmentAudit, flag);
            }
            if let Some(flag) = changepoint_anomaly {
                design.record_probe(Probe::Changepoint, flag);
            }
            if let Some(flag) = conformal_anomaly {
                design.record_probe(Probe::Conformal, flag);
            }
            // Equivariant cohesion currently reuses large-deviation channel
            // for design identifiability updates.
            design.record_probe(Probe::LargeDeviations, equivariant_anomaly);
        }

        // Feed allocator frees into primal-dual quarantine controller.
        if matches!(family, ApiFamily::Allocator) {
            let mut quarantine = self.quarantine.lock();
            let updated = quarantine.record_free(estimated_cost_ns, adverse);
            if updated {
                publish_depth(&quarantine);
            }
        }

        // For non-pointer families we only have coarse stage-exit information.
        // PointerValidation feeds exact stage exits via `note_check_order_outcome`.
        if !matches!(family, ApiFamily::PointerValidation) {
            let ctx = CheckContext {
                family: family as u8,
                aligned: estimated_cost_ns <= 16 && !adverse,
                recent_page: !adverse,
            };
            let exit_stage = if adverse {
                Some(3)
            } else if matches!(profile, ValidationProfile::Fast) {
                Some(1)
            } else {
                None
            };
            let mut oracle = self.sampled_oracle.lock();
            let ordering_used = *oracle.get_ordering(&ctx);
            oracle.report_outcome(&ctx, &ordering_used, exit_stage);
        }
    }

    /// Record overlap information for cross-shard consistency checks.
    ///
    /// Returns true when overlap is consistent, false when a cocycle fault is detected.
    pub fn note_overlap(&self, left_shard: usize, right_shard: usize, witness_hash: u64) -> bool {
        self.cohomology
            .note_overlap(left_shard, right_shard, witness_hash)
    }

    /// Point-in-time kernel snapshot.
    #[must_use]
    pub fn snapshot(&self, mode: SafetyLevel) -> RuntimeKernelSnapshot {
        let limits = self.controller.limits(mode);
        let tropical_full_wcl_ns = self.tropical.lock().worst_case_bound(PipelinePath::Full);
        let spectral_sig = self.spectral.lock().signature();
        let rp_summary = self.rough_path.lock().summary();
        let pd = self.persistence.lock();
        let pd_summary = pd.last_summary();
        let pd_anomaly_count = pd.anomaly_count();
        drop(pd);
        let anytime = self.anytime.lock();
        let anytime_max_e_value = anytime.max_e_value();
        let anytime_alarmed_families = anytime.alarmed_family_count();
        drop(anytime);
        let cvar = self.cvar.lock();
        let cvar_max_robust_ns = cvar.max_family_robust_cvar_ns();
        let cvar_alarmed_families = cvar.alarmed_family_count(mode);
        drop(cvar);
        let bridge_summary = self.bridge.lock().summary();
        let ld = self.large_dev.lock();
        let ld_elevated_families = ld.elevated_family_count();
        let ld_max_anomaly_count = ld.max_anomaly_count();
        drop(ld);
        let hji_summary = self.hji.lock().summary();
        let mfg_summary = self.mfg.lock().summary();
        let padic_summary = self.padic.lock().summary();
        let symplectic_summary = self.symplectic.lock().summary();
        let topos_summary = self.topos.lock().summary();
        let audit_summary = self.audit.lock().summary();
        let changepoint_summary = self.changepoint.lock().summary();
        let conformal_summary = self.conformal.lock().summary();
        let design_summary = self.design.lock().summary();
        let sparse_summary = self.sparse.lock().summary();
        let equivariant_summary = self.equivariant.lock().summary();
        RuntimeKernelSnapshot {
            decisions: self.decisions.load(Ordering::Relaxed),
            consistency_faults: self.cohomology.fault_count(),
            full_validation_trigger_ppm: limits.full_validation_trigger_ppm,
            repair_trigger_ppm: limits.repair_trigger_ppm,
            sampled_risk_bonus_ppm: self.cached_risk_bonus_ppm.load(Ordering::Relaxed) as u32,
            pareto_cumulative_regret_milli: self.pareto.cumulative_regret_milli(),
            pareto_cap_enforcements: self.pareto.cap_enforcement_count(),
            pareto_exhausted_families: self.pareto.exhausted_family_count(mode),
            quarantine_depth: current_depth(),
            tropical_full_wcl_ns,
            spectral_edge_ratio: spectral_sig.edge_ratio,
            spectral_phase_transition: spectral_sig.phase != PhaseState::Stationary,
            signature_anomaly_score: rp_summary.anomaly_score,
            signature_anomaly_count: rp_summary.anomaly_count,
            persistence_entropy: pd_summary.persistence_entropy,
            topo_anomaly_count: pd_anomaly_count,
            anytime_max_e_value,
            anytime_alarmed_families,
            cvar_max_robust_ns,
            cvar_alarmed_families,
            bridge_transport_distance: bridge_summary.transport_distance,
            bridge_transitioning: bridge_summary.state == BridgeState::Transitioning,
            ld_elevated_families,
            ld_max_anomaly_count,
            hji_safety_value: hji_summary.value,
            hji_breached: hji_summary.state == ReachState::Breached,
            mfg_mean_contention: mfg_summary.mean_contention,
            mfg_congestion_count: mfg_summary.congestion_count,
            padic_ultrametric_distance: padic_summary.ultrametric_distance,
            padic_drift_count: padic_summary.drift_count,
            symplectic_energy: symplectic_summary.hamiltonian_energy,
            symplectic_violation_count: symplectic_summary.violation_count,
            topos_violation_rate: topos_summary.violation_rate,
            topos_violation_count: topos_summary.violation_count,
            audit_martingale_value: audit_summary.martingale_value,
            audit_replay_count: audit_summary.replay_count,
            changepoint_posterior_short_mass: changepoint_summary.posterior_short_mass,
            changepoint_count: changepoint_summary.change_point_count,
            conformal_empirical_coverage: conformal_summary.empirical_coverage,
            conformal_violation_count: conformal_summary.violation_count,
            design_identifiability_ppm: design_summary.identifiability_ppm,
            design_selected_probes: design_summary.selected_count,
            design_budget_ns: design_summary.budget_ns,
            design_expected_cost_ns: design_summary.expected_cost_ns,
            sparse_support_size: sparse_summary.support_size,
            sparse_l1_energy: sparse_summary.l1_energy,
            sparse_residual_ewma: sparse_summary.residual_ewma,
            sparse_critical_count: sparse_summary.critical_count,
            equivariant_alignment_ppm: equivariant_summary.alignment_ppm,
            equivariant_drift_count: equivariant_summary.drift_count,
            equivariant_fractured_count: equivariant_summary.fractured_count,
            equivariant_dominant_orbit: self.cached_equivariant_orbit.load(Ordering::Relaxed),
            fusion_bonus_ppm: self.cached_fusion_bonus_ppm.load(Ordering::Relaxed) as u32,
            fusion_entropy_milli: self.cached_fusion_entropy_milli.load(Ordering::Relaxed) as u32,
            fusion_drift_ppm: self.cached_fusion_drift_ppm.load(Ordering::Relaxed) as u32,
            fusion_dominant_signal: self.cached_fusion_dominant_signal.load(Ordering::Relaxed),
            microlocal_active_strata: {
                let mc = self.microlocal.lock();
                mc.wavefront_bits().count_ones() as u8
            },
            microlocal_failure_rate: self.microlocal.lock().summary().propagation_failure_rate,
            microlocal_fault_count: self.microlocal.lock().summary().fault_boundary_count,
            serre_max_differential: self.serre.lock().summary().max_differential,
            serre_nontrivial_cells: self.serre.lock().summary().nontrivial_cells,
            serre_lifting_count: self.serre.lock().summary().lifting_failure_count,
            clifford_grade2_energy: self.clifford.lock().summary().grade2_energy,
            clifford_parity_imbalance: self.clifford.lock().summary().parity_imbalance,
            clifford_violation_count: self.clifford.lock().summary().overlap_violation_count,
        }
    }

    fn resample_high_order_kernels(&self, mode: SafetyLevel, ctx: RuntimeContext) {
        let mut sampled_risk = self.sampled_risk.lock();
        let risk_decision = sampled_risk.evaluate(
            map_family(ctx.family),
            ctx.addr_hint,
            ctx.requested_bytes.max(1),
        );
        drop(sampled_risk);

        let bonus_ppm = match risk_decision {
            RiskDecision::AlarmMode => 500_000_u32,
            RiskDecision::FullCheck => 250_000_u32,
            RiskDecision::NormalCheck => 0_u32,
            RiskDecision::FastPath => 0_u32,
        };
        self.cached_risk_bonus_ppm
            .store(u64::from(bonus_ppm), Ordering::Relaxed);

        let oracle_ctx = CheckContext {
            family: ctx.family as u8,
            aligned: ctx.addr_hint & 0x7 == 0,
            recent_page: !ctx.bloom_negative,
        };
        let mut oracle = self.sampled_oracle.lock();
        let ordering = *oracle.get_ordering(&oracle_ctx);
        let exit_stage = match risk_decision {
            RiskDecision::AlarmMode | RiskDecision::FullCheck => Some(3),
            RiskDecision::FastPath if !ctx.bloom_negative => Some(1),
            _ => None,
        };
        oracle.report_outcome(&oracle_ctx, &ordering, exit_stage);

        let bias = oracle_bias_from_ordering(&ordering, mode);
        self.cached_oracle_bias[usize::from(ctx.family as u8)].store(bias, Ordering::Relaxed);
    }
}

impl Default for RuntimeMathKernel {
    fn default() -> Self {
        Self::new()
    }
}

fn compute_policy_id(
    mode: SafetyLevel,
    family: ApiFamily,
    profile: ValidationProfile,
    action: MembraneAction,
) -> u32 {
    let mode_bits: u32 = match mode {
        SafetyLevel::Strict => 1,
        SafetyLevel::Hardened => 2,
        SafetyLevel::Off => 3,
    };
    let profile_bits: u32 = match profile {
        ValidationProfile::Fast => 1,
        ValidationProfile::Full => 2,
    };
    let action_bits: u32 = match action {
        MembraneAction::Allow => 1,
        MembraneAction::FullValidate => 2,
        MembraneAction::Repair(_) => 3,
        MembraneAction::Deny => 4,
    };

    (mode_bits << 28)
        | ((u32::from(family as u8) & 0xFF) << 16)
        | ((profile_bits & 0xF) << 8)
        | (action_bits & 0xF)
}

fn map_family(family: ApiFamily) -> CallFamily {
    match family {
        ApiFamily::PointerValidation => CallFamily::Memory,
        ApiFamily::Allocator => CallFamily::Alloc,
        ApiFamily::StringMemory => CallFamily::String,
        ApiFamily::Stdio => CallFamily::Stdio,
        ApiFamily::Threading => CallFamily::Thread,
        ApiFamily::Resolver => CallFamily::Socket,
        ApiFamily::MathFenv => CallFamily::Other,
        ApiFamily::Loader => CallFamily::Other,
        ApiFamily::Stdlib => CallFamily::String,
    }
}

/// 0 => full-bias, 1 => neutral, 2 => fast-bias.
fn oracle_bias_from_ordering(ordering: &[CheckStage; 7], mode: SafetyLevel) -> u8 {
    let first = ordering[0];
    let second = ordering[1];

    if matches!(first, CheckStage::Null)
        && matches!(
            second,
            CheckStage::Arena | CheckStage::Fingerprint | CheckStage::Canary
        )
    {
        return 0;
    }
    if matches!(first, CheckStage::Null)
        && matches!(second, CheckStage::TlsCache)
        && !mode.heals_enabled()
    {
        return 2;
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hardened_can_escalate_to_full() {
        let kernel = RuntimeMathKernel::new();
        let decision = kernel.decide(
            SafetyLevel::Hardened,
            RuntimeContext {
                family: ApiFamily::Allocator,
                addr_hint: 0x2000,
                requested_bytes: 8192,
                is_write: true,
                contention_hint: 128,
                bloom_negative: true,
            },
        );
        assert!(decision.requires_full_validation());
    }

    #[test]
    fn strict_decision_is_policy_tagged() {
        let kernel = RuntimeMathKernel::new();
        let decision = kernel.decide(
            SafetyLevel::Strict,
            RuntimeContext::pointer_validation(0x1000, false),
        );
        assert_ne!(decision.policy_id, 0);
    }

    #[test]
    fn observe_updates_snapshot() {
        let kernel = RuntimeMathKernel::new();
        kernel.observe_validation_result(
            ApiFamily::PointerValidation,
            ValidationProfile::Fast,
            7,
            false,
        );
        kernel.observe_validation_result(
            ApiFamily::PointerValidation,
            ValidationProfile::Full,
            45,
            true,
        );
        let snap = kernel.snapshot(SafetyLevel::Hardened);
        assert!(snap.decisions <= 2);
        assert!(snap.full_validation_trigger_ppm > 0);
    }

    #[test]
    fn explicit_oracle_feedback_updates_bias_cache() {
        let kernel = RuntimeMathKernel::new();
        let ordering = kernel.check_ordering(ApiFamily::PointerValidation, true, true);
        kernel.note_check_order_outcome(
            ApiFamily::PointerValidation,
            true,
            true,
            &ordering,
            Some(1),
        );
        let bias = kernel.cached_oracle_bias[usize::from(ApiFamily::PointerValidation as u8)]
            .load(Ordering::Relaxed);
        assert!(bias <= 2);
    }
}
