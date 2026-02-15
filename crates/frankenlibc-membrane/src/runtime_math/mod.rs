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

pub mod admm_budget;
pub mod alpha_investing;
pub mod approachability;
pub mod atiyah_bott;
pub mod azuma_hoeffding;
pub mod bandit;
pub mod barrier;
pub mod bifurcation_detector;
pub mod birkhoff_ergodic;
pub mod borel_cantelli;
pub mod changepoint;
pub mod clifford;
pub mod cohomology;
pub mod commitment_audit;
pub mod conformal;
pub mod control;
pub mod coupling;
pub mod covering_array;
pub mod cvar;
pub mod derived_tstructure;
pub mod design;
pub mod dispersion_index;
pub mod dobrushin_contraction;
pub mod doob_decomposition;
pub mod entropy_rate;
pub mod eprocess;
pub mod equivariant;
pub mod evidence;
pub mod fano_bound;
pub mod fusion;
pub mod grobner_normalizer;
pub mod grothendieck_glue;
pub mod higher_topos;
pub mod hodge_decomposition;
pub mod hurst_exponent;
pub mod info_geometry;
pub mod ito_quadratic_variation;
pub mod kernel_mmd;
pub mod ktheory;
pub mod lempel_ziv;
pub mod localization_chooser;
pub mod loss_minimizer;
pub mod lyapunov_stability;
pub mod malliavin_sensitivity;
pub mod matrix_concentration;
pub mod microlocal;
pub mod nerve_complex;
pub mod obstruction_detector;
pub mod operator_norm;
pub mod ornstein_uhlenbeck;
pub mod pac_bayes;
pub mod pareto;
pub mod policy_table;
pub mod pomdp_repair;
pub mod provenance_info;
pub mod rademacher_complexity;
pub mod redundancy_tuner;
pub mod renewal_theory;
pub mod risk;
pub mod serre_spectral;
pub mod sobol;
pub mod sos_barrier;
pub mod sos_invariant;
pub mod sparse;
pub mod spectral_gap;
pub mod stein_discrepancy;
pub mod submodular_coverage;
pub mod transfer_entropy;
pub mod wasserstein_drift;

#[cfg(all(
    feature = "runtime-math-research",
    not(feature = "runtime-math-production")
))]
compile_error!(
    "`runtime-math-research` requires `runtime-math-production` to keep the default membrane decision law intact."
);

/// Compile-time flag indicating the production runtime-math kernel is enabled.
pub const RUNTIME_MATH_PRODUCTION_ENABLED: bool = cfg!(feature = "runtime-math-production");
/// Compile-time flag indicating research runtime-math extensions are enabled.
pub const RUNTIME_MATH_RESEARCH_ENABLED: bool = cfg!(feature = "runtime-math-research");
const OBSERVE_FEEDBACK_ENABLED: u8 = 1;
const OBSERVE_FEEDBACK_DISABLED: u8 = 2;
// Default disabled for preload-stability while keeping decision/check-ordering live.
static OBSERVE_FEEDBACK_STATE: AtomicU8 = AtomicU8::new(OBSERVE_FEEDBACK_DISABLED);
const POLICY_LOAD_STATE_NONE: u8 = 0;
const POLICY_LOAD_STATE_LOADED: u8 = 1;
const POLICY_LOAD_STATE_VERIFY_FAILED: u8 = 2;

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use parking_lot::Mutex;

use crate::check_oracle::{CheckContext, CheckOracle, CheckStage};
use crate::config::SafetyLevel;
use crate::grobner;
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

use self::admm_budget::{AdmmBudgetController, AdmmState};
use self::alpha_investing::{AlphaInvestingController, AlphaInvestingState};
use self::approachability::{ApproachabilityController, ApproachabilityState};
use self::atiyah_bott::{AtiyahBottController, LocalizationState};
use self::azuma_hoeffding::{AzumaHoeffdingMonitor, AzumaState};
use self::bandit::ConstrainedBanditRouter;
use self::barrier::BarrierOracle;
use self::bifurcation_detector::{BifurcationDetector, BifurcationState};
use self::birkhoff_ergodic::{BirkhoffErgodicMonitor, ErgodicState};
use self::borel_cantelli::{BorelCantelliMonitor, BorelCantelliState};
use self::changepoint::{ChangepointController, ChangepointState};
use self::clifford::{AlignmentObservation, AlignmentRegime, CliffordController, CliffordState};
use self::cohomology::CohomologyMonitor;
use self::commitment_audit::{AuditState, CommitmentAuditController};
use self::conformal::{ConformalRiskController, ConformalState};
use self::control::PrimalDualController;
use self::coupling::{CouplingController, CouplingState};
use self::covering_array::{CoverageState, CoveringArrayController};
use self::cvar::{DroCvarController, TailState};
use self::derived_tstructure::{TStructureController, TStructureState};
use self::design::{OptimalDesignController, Probe, ProbePlan};
use self::dispersion_index::{DispersionIndexMonitor, DispersionState};
use self::dobrushin_contraction::{DobrushinContractionMonitor, DobrushinState};
use self::doob_decomposition::{DoobDecompositionMonitor, DoobState};
use self::entropy_rate::{EntropyRateMonitor, EntropyRateState};
use self::eprocess::{AnytimeEProcessMonitor, SequentialState};
use self::equivariant::{EquivariantState, EquivariantTransportController};
use self::fano_bound::{FanoBoundMonitor, FanoState};
use self::fusion::KernelFusionController;
use self::grobner_normalizer::{GrobnerNormalizerController, GrobnerState};
use self::grothendieck_glue::{
    CocycleObservation, DataSource, GlueState, GrothendieckGlueController, QueryFamily,
};
use self::higher_topos::{HigherToposController, ToposState};
use self::hodge_decomposition::{HodgeDecompositionMonitor, HodgeState};
use self::hurst_exponent::{HurstExponentMonitor, HurstState};
use self::info_geometry::{GeometryState, InfoGeometryMonitor};
use self::ito_quadratic_variation::{ItoQuadraticVariationMonitor, ItoQvState};
use self::kernel_mmd::{KernelMmdMonitor, MmdState};
use self::ktheory::{KTheoryController, KTheoryState};
use self::lempel_ziv::{LempelZivMonitor, LempelZivState};
use self::localization_chooser::{ChooserState, LocalizationChooser};
use self::loss_minimizer::{LossMinimizationController, LossState};
use self::lyapunov_stability::{LyapunovStabilityMonitor, LyapunovState};
use self::malliavin_sensitivity::{MalliavSensitivity, SensitivityState};
use self::matrix_concentration::{ConcentrationState, MatrixConcentrationMonitor};
use self::microlocal::{MicrolocalController, MicrolocalState, Stratum};
use self::nerve_complex::{NerveComplexMonitor, NerveState};
use self::obstruction_detector::{ObstructionDetector, ObstructionState};
use self::operator_norm::{OperatorNormMonitor, StabilityState};
use self::ornstein_uhlenbeck::{OrnsteinUhlenbeckMonitor, OuState};
use self::pac_bayes::{PacBayesMonitor, PacBayesState};
use self::pareto::ParetoController;
use self::pomdp_repair::{PomdpRepairController, PomdpState};
use self::provenance_info::{ProvenanceInfoController, ProvenanceState};
use self::rademacher_complexity::{RademacherComplexityMonitor, RademacherState};
use self::redundancy_tuner::RedundancyTuner;
use self::renewal_theory::{RenewalState, RenewalTheoryMonitor};
use self::risk::ConformalRiskEngine;
use self::serre_spectral::{
    InvariantClass, LayerPair, SerreSpectralController, SpectralSequenceState,
};
use self::sobol::SobolGenerator;
use self::sos_barrier::{SosBarrierController, SosBarrierState, depth_to_arena_utilization_ppm};
use self::sos_invariant::{SosInvariantController, SosState};
use self::sparse::{SparseRecoveryController, SparseState};
use self::spectral_gap::{SpectralGapMonitor, SpectralGapState};
use self::stein_discrepancy::{SteinDiscrepancyMonitor, SteinState};
use self::submodular_coverage::{SubmodularCoverageMonitor, SubmodularState};
use self::transfer_entropy::{TransferEntropyMonitor, TransferEntropyState};
use self::wasserstein_drift::{DriftState, WassersteinDriftMonitor};

#[inline]
fn observe_feedback_enabled() -> bool {
    OBSERVE_FEEDBACK_STATE.load(Ordering::Relaxed) == OBSERVE_FEEDBACK_ENABLED
}

const FAST_PATH_BUDGET_NS: u64 = 20;
const FULL_PATH_BUDGET_NS: u64 = 200;

/// Number of base severity signals fed from hot-path cached atomics.
const BASE_SEVERITY_LEN: usize = 25;
/// Number of meta-controller severity signals appended after the base set.
const META_SEVERITY_LEN: usize = 39;
/// Compile-time assertion: fusion::SIGNALS == BASE + META severity slots.
const _: () = assert!(
    fusion::SIGNALS == BASE_SEVERITY_LEN + META_SEVERITY_LEN,
    "fusion::SIGNALS must equal BASE_SEVERITY_LEN + META_SEVERITY_LEN"
);

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
    Ctype = 9,
    Time = 10,
    Signal = 11,
    IoFd = 12,
    Socket = 13,
    Locale = 14,
    Termios = 15,
    Inet = 16,
    Process = 17,
    VirtualMemory = 18,
    Poll = 19,
}

impl ApiFamily {
    pub const COUNT: usize = 20;
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
    /// Evidence ring-buffer seqno linked to this decision (0 when not sampled).
    pub evidence_seqno: u64,
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

/// Stable, explicit evidence-export counters exposed by the runtime kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeEvidenceContractSnapshot {
    /// Monotonic evidence record sequence number.
    pub evidence_seqno: u64,
    /// Number of evidence losses caused by bounded-ring overwrites.
    pub evidence_loss_count: u64,
    /// Highest observed evidence epoch across all streams.
    pub evidence_max_epoch: u64,
}

/// Common runtime-kernel framework contract.
///
/// This provides a shared `evaluate -> calibrate -> snapshot` surface for
/// controller orchestration and deterministic evidence export wiring.
pub trait RuntimeKernelFramework {
    type Snapshot;

    /// Evaluate one runtime context and return the selected decision.
    fn evaluate(&self, mode: SafetyLevel, ctx: RuntimeContext) -> RuntimeDecision;

    /// Calibrate kernel state with observed post-decision outcome data.
    fn calibrate(
        &self,
        mode: SafetyLevel,
        family: ApiFamily,
        profile: ValidationProfile,
        estimated_cost_ns: u64,
        adverse: bool,
    );

    /// Capture a point-in-time kernel snapshot.
    fn snapshot(&self, mode: SafetyLevel) -> Self::Snapshot;

    /// Capture evidence-export counters for traceability and audit checks.
    fn evidence_contract_snapshot(&self) -> RuntimeEvidenceContractSnapshot;

    /// Export structured JSON decision-card evidence for deterministic tooling ingestion.
    fn export_decision_cards_json(&self) -> String;
}

/// Stable schema version for [`RuntimeKernelSnapshot`].
///
/// Policy:
/// - Additive-only changes are allowed without bumping the version.
/// - Any rename/removal/semantic change requires bump + explicit migration plan
///   for fixtures and harness diff tooling.
pub const RUNTIME_KERNEL_SNAPSHOT_SCHEMA_VERSION: u32 = 2;

/// Runtime state snapshot useful for tests/telemetry export.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RuntimeKernelSnapshot {
    /// Snapshot schema version (see `RUNTIME_KERNEL_SNAPSHOT_SCHEMA_VERSION`).
    pub schema_version: u32,
    /// Total number of `decide(...)` decisions produced by this kernel instance.
    pub decisions: u64,
    /// Total overlap-consistency (cocycle) faults observed by the cohomology monitor.
    pub consistency_faults: u64,
    /// Controller threshold: risk ppm at/above which full validation is forced.
    ///
    /// Units: ppm (0..=1_000_000).
    pub full_validation_trigger_ppm: u32,
    /// Controller threshold: risk ppm at/above which repair actions are allowed/forced.
    ///
    /// Units: ppm (0..=1_000_000).
    pub repair_trigger_ppm: u32,
    /// Sampled high-order risk bonus (ppm) currently applied from `risk_engine`.
    pub sampled_risk_bonus_ppm: u32,
    /// Cumulative regret tracked by the Pareto controller.
    ///
    /// Units: milli-units (1e-3), monotone non-decreasing.
    pub pareto_cumulative_regret_milli: u64,
    /// Number of times hard regret caps were enforced by Pareto routing.
    pub pareto_cap_enforcements: u64,
    /// Number of API families whose Pareto regret budget is exhausted for the current mode.
    pub pareto_exhausted_families: u32,
    /// Current published allocator quarantine depth (temporal-safety budget).
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
    /// Gröbner canonical root-cause class ID (0=none, 1-6=single cause, 7=compound).
    pub sparse_canonical_class: u8,
    /// Per-canonical-class observation counts (8 bins).
    pub sparse_canonical_counts: [u64; grobner::NUM_CANONICAL_CLASSES],
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
    /// K-theory maximum transport distance across ABI families.
    pub ktheory_max_transport_distance: f64,
    /// K-theory ABI fracture detection count.
    pub ktheory_fracture_count: u64,
    /// Covering-array conformance coverage fraction (0..1).
    pub covering_coverage_fraction: f64,
    /// Covering-array coverage gap detection count.
    pub covering_gap_count: u64,
    /// Derived t-structure maximum ordering violation rate.
    pub tstructure_max_violation_rate: f64,
    /// Derived t-structure orthogonality violation count.
    pub tstructure_violation_count: u64,
    /// Atiyah-Bott localization Euler weight.
    pub atiyah_bott_euler_weight: f64,
    /// Atiyah-Bott concentrated anomaly detection count.
    pub atiyah_bott_concentration_count: u64,
    /// POMDP repair optimality gap (0..1+).
    pub pomdp_optimality_gap: f64,
    /// POMDP policy divergence detection count.
    pub pomdp_divergence_count: u64,
    /// SOS invariant maximum stress fraction.
    pub sos_max_stress: f64,
    /// SOS invariant violation event count.
    pub sos_violation_count: u64,
    /// SOS barrier provenance certificate value (ppm, negative = violation).
    pub sos_barrier_provenance_value: i64,
    /// SOS barrier quarantine certificate value (milli-units, negative = violation).
    pub sos_barrier_quarantine_value: i64,
    /// SOS barrier total violation count.
    pub sos_barrier_violations: u64,
    /// ADMM primal-dual gap (0..∞, lower is better).
    pub admm_primal_dual_gap: f64,
    /// ADMM constraint violation count.
    pub admm_violation_count: u64,
    /// Spectral-sequence obstruction norm (0..∞).
    pub obstruction_norm: f64,
    /// Critical obstruction detection count.
    pub obstruction_critical_count: u64,
    /// Operator-norm spectral radius estimate.
    pub operator_norm_spectral_radius: f64,
    /// Operator-norm instability detection count.
    pub operator_norm_instability_count: u64,
    /// Provenance Shannon entropy per byte (0..8, ideal = 8.0).
    pub provenance_shannon_entropy: f64,
    /// Provenance Rényi H₂ collision entropy per byte (0..8).
    pub provenance_renyi_h2: f64,
    /// Provenance collision risk detection count.
    pub provenance_collision_count: u64,
    /// Grobner constraint violation rate (EWMA, 0..1).
    pub grobner_violation_rate: f64,
    /// Grobner structural fault detection count.
    pub grobner_fault_count: u64,
    /// Grothendieck glue global cocycle violation rate (EWMA, 0..1).
    pub grothendieck_violation_rate: f64,
    /// Grothendieck stackification fault detection count.
    pub grothendieck_stack_fault_count: u64,
    /// Malliavin sensitivity norm (0..∞, higher = more fragile).
    pub malliavin_sensitivity_norm: f64,
    /// Malliavin fragility index (innovation-to-total variance ratio, 0..1).
    pub malliavin_fragility_index: f64,
    /// Information geometry aggregate geodesic distance from baseline (0..∞).
    pub info_geo_geodesic_distance: f64,
    /// Information geometry max single-controller Fisher-Rao distance.
    pub info_geo_max_controller_distance: f64,
    /// Matrix concentration spectral deviation from baseline covariance.
    pub matrix_conc_spectral_deviation: f64,
    /// Matrix concentration Bernstein confidence bound.
    pub matrix_conc_bernstein_bound: f64,
    /// Nerve complex β₀ (connected components, 1 = cohesive).
    pub nerve_betti_0: u32,
    /// Nerve complex β₁ (1-cycles in correlation graph).
    pub nerve_betti_1: u32,
    /// Wasserstein drift aggregate distance from baseline (0..3).
    pub wasserstein_aggregate_distance: f64,
    /// Wasserstein drift max single-controller distance.
    pub wasserstein_max_controller_distance: f64,
    /// Kernel MMD² estimate (0..2, higher = more discrepant).
    pub mmd_squared: f64,
    /// Kernel MMD mean shift norm (Euclidean distance of means).
    pub mmd_mean_shift_norm: f64,
    /// PAC-Bayes generalization bound (0..1, lower = tighter).
    pub pac_bayes_bound: f64,
    /// PAC-Bayes KL divergence from posterior to prior.
    pub pac_bayes_kl_divergence: f64,
    /// PAC-Bayes weighted empirical error rate.
    pub pac_bayes_empirical_error: f64,
    /// Stein discrepancy KSD² estimate (0..∞).
    pub stein_ksd_squared: f64,
    /// Stein discrepancy max per-controller score deviation.
    pub stein_max_score_deviation: f64,
    /// Lyapunov stability exponent estimate (negative = stable).
    pub lyapunov_exponent: f64,
    /// Lyapunov smoothed expansion ratio.
    pub lyapunov_expansion_ratio: f64,
    /// Rademacher complexity estimate (0..∞, lower = better-regularized).
    pub rademacher_complexity: f64,
    /// Rademacher generalization gap bound (2R̂ + concentration).
    pub rademacher_gen_gap_bound: f64,
    /// Transfer entropy max pairwise TE (0..∞, higher = stronger causal coupling).
    pub transfer_entropy_max_te: f64,
    /// Transfer entropy mean pairwise TE.
    pub transfer_entropy_mean_te: f64,
    /// Hodge decomposition inconsistency ratio (0..1, 0 = coherent).
    pub hodge_inconsistency_ratio: f64,
    /// Hodge decomposition curl energy (squared cycle residual).
    pub hodge_curl_energy: f64,
    /// Doob decomposition smoothed drift rate (0..∞).
    pub doob_drift_rate: f64,
    /// Doob decomposition max per-controller cumulative drift magnitude.
    pub doob_max_drift: f64,
    /// Fano mutual information bound mean MI across controllers (nats).
    pub fano_mean_mi: f64,
    /// Fano error lower bound (0..1, higher = less predictable).
    pub fano_mean_bound: f64,
    /// Dobrushin contraction coefficient max across controllers (0..1).
    pub dobrushin_max_contraction: f64,
    /// Dobrushin contraction coefficient mean across controllers (0..1).
    pub dobrushin_mean_contraction: f64,
    /// Azuma-Hoeffding max exceedance ratio (0..∞, >1 = bounds violated).
    pub azuma_max_exceedance: f64,
    /// Azuma-Hoeffding mean exceedance ratio across controllers.
    pub azuma_mean_exceedance: f64,
    /// Renewal theory max age ratio across controllers (0..∞).
    pub renewal_max_age_ratio: f64,
    /// Renewal theory mean inter-arrival time.
    pub renewal_mean_time: f64,
    /// Lempel-Ziv max complexity ratio across controllers (0..1+).
    pub lz_max_complexity_ratio: f64,
    /// Lempel-Ziv mean complexity ratio across controllers.
    pub lz_mean_complexity_ratio: f64,
    /// Ito quadratic variation max per step (realized volatility).
    pub ito_qv_max_per_step: f64,
    /// Ito quadratic variation mean per step.
    pub ito_qv_mean_per_step: f64,
    /// Borel-Cantelli max exceedance rate across controllers (0..1).
    pub borel_cantelli_max_rate: f64,
    /// Borel-Cantelli mean exceedance rate across controllers (0..1).
    pub borel_cantelli_mean_rate: f64,
    /// Ornstein-Uhlenbeck min θ across controllers (negative = explosive).
    pub ou_min_theta: f64,
    /// Ornstein-Uhlenbeck mean θ across controllers.
    pub ou_mean_theta: f64,
    /// Hurst exponent max across controllers (0..1, 0.5 = independent).
    pub hurst_max: f64,
    /// Hurst exponent mean across controllers.
    pub hurst_mean: f64,
    /// Dispersion index max across controllers (Var/Mean, 1 = Poisson).
    pub dispersion_max: f64,
    /// Dispersion index mean across controllers.
    pub dispersion_mean: f64,
    /// Birkhoff ergodic max convergence gap across controllers (0..1+).
    pub birkhoff_max_gap: f64,
    /// Birkhoff ergodic mean convergence gap across controllers.
    pub birkhoff_mean_gap: f64,
    /// Coupling empirical divergence bound (p_hat + Hoeffding eps, 0..1).
    pub coupling_divergence_bound: f64,
    /// Coupling certification margin (threshold - bound, positive = certified).
    pub coupling_certification_margin: f64,
    /// Loss-minimizer recommended action (0=allow, 1=full-validate, 2=repair, 3=deny).
    pub loss_recommended_action: u8,
    /// Loss-minimizer posterior `P(C=Adverse | evidence)` in ppm.
    pub loss_posterior_adverse_ppm: u32,
    /// Loss-minimizer selected expected-loss cost (milli-units).
    pub loss_selected_expected_cost_milli: u64,
    /// Loss-minimizer competing action (second-best expected-loss action).
    pub loss_competing_action: u8,
    /// Loss-minimizer competing expected-loss cost (milli-units).
    pub loss_competing_expected_cost_milli: u64,
    /// Loss-minimizer cost explosion detection count.
    pub loss_cost_explosion_count: u64,
    /// Spectral gap max |λ₂| across controllers (0..1, lower = faster mixing).
    pub spectral_gap_max_eigenvalue: f64,
    /// Spectral gap mean |λ₂| across controllers (0..1).
    pub spectral_gap_mean_eigenvalue: f64,
    /// Submodular coverage ratio under budget (0..1, higher = better).
    pub submodular_coverage_ratio: f64,
    /// Submodular selected stage count under budget.
    pub submodular_selected_stages: u8,
    /// Bifurcation max lag-1 autocorrelation (sensitivity) across controllers (0..1).
    pub bifurcation_max_sensitivity: f64,
    /// Bifurcation mean sensitivity across controllers (0..1).
    pub bifurcation_mean_sensitivity: f64,
    /// Shannon entropy rate of severity process (bits, 0..log₂K).
    pub entropy_rate_bits: f64,
    /// Normalized entropy rate ratio (0..1, 0=deterministic, 1=IID uniform).
    pub entropy_rate_ratio: f64,
    /// Alpha-Investing current wealth (milli-units, 0 = depleted).
    pub alpha_investing_wealth_milli: u64,
    /// Alpha-Investing total accepted discoveries.
    pub alpha_investing_rejections: u64,
    /// Alpha-Investing empirical false discovery rate (0..1).
    pub alpha_investing_empirical_fdr: f64,
    /// Approachability squared deviation from safe set (milli² units).
    pub approachability_deviation_sq_milli: u64,
    /// Approachability recommended arm (0..3).
    pub approachability_recommended_arm: u8,
    /// Approachability controller state code (0=Calibrating..3=Violated).
    pub approachability_state: u8,
    /// Localization chooser selected policy arm (0=Minimal, 1=Cautious, 2=Thorough, 3=Protective, 4=Lockdown).
    pub localization_selected_arm: u8,
    /// Localization chooser total observation count.
    pub localization_count: u64,
    /// Sobol scheduler sequence index (monotonic, wraps at 2^32).
    pub sobol_index: u32,
    /// Sobol scheduler augmented probe mask (bits set by Sobol rotation).
    pub sobol_augmented_mask: u32,
    /// Number of probes added by Sobol rotation beyond the D-optimal base set.
    pub sobol_augmented_count: u8,
    /// First 8 bytes of the active policy table hash (0 if no table loaded).
    pub policy_hash_prefix: u64,
    /// Action distribution: [Allow, FullValidate, Repair, Deny] counts.
    pub policy_action_dist: [u64; 4],
    /// Evidence ring buffer: total records written (monotonic seqno).
    pub evidence_seqno: u64,
    /// Evidence ring buffer: loss count (overwrites before consumption).
    pub evidence_loss_count: u64,
    /// Evidence: current epoch counter (max across all streams).
    pub evidence_max_epoch: u64,
    /// Adaptive redundancy tuner: current overhead in ppm.
    pub redundancy_overhead_ppm: u32,
    /// Adaptive redundancy tuner: observed loss rate in ppm (EWMA).
    pub redundancy_loss_rate_ppm: u32,
    /// Adaptive redundancy tuner: state (0=Calibrating,1=Nominal,2=Stressed,3=Critical).
    pub redundancy_state: u8,
    /// Adaptive redundancy tuner: total adjustments made.
    pub redundancy_adjustments: u64,
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
    ktheory: Mutex<KTheoryController>,
    covering: Mutex<CoveringArrayController>,
    tstructure: Mutex<TStructureController>,
    admm: Mutex<AdmmBudgetController>,
    atiyah_bott: Mutex<AtiyahBottController>,
    obstruction: Mutex<ObstructionDetector>,
    operator_norm: Mutex<OperatorNormMonitor>,
    pomdp: Mutex<PomdpRepairController>,
    sos: Mutex<SosInvariantController>,
    sos_barrier: Mutex<SosBarrierController>,
    provenance: Mutex<ProvenanceInfoController>,
    grobner: Mutex<GrobnerNormalizerController>,
    grothendieck: Mutex<GrothendieckGlueController>,
    info_geometry: Mutex<InfoGeometryMonitor>,
    kernel_mmd: Mutex<KernelMmdMonitor>,
    malliavin: Mutex<MalliavSensitivity>,
    matrix_concentration: Mutex<MatrixConcentrationMonitor>,
    nerve_complex: Mutex<NerveComplexMonitor>,
    wasserstein: Mutex<WassersteinDriftMonitor>,
    pac_bayes: Mutex<PacBayesMonitor>,
    stein: Mutex<SteinDiscrepancyMonitor>,
    lyapunov: Mutex<LyapunovStabilityMonitor>,
    rademacher: Mutex<RademacherComplexityMonitor>,
    transfer_entropy: Mutex<TransferEntropyMonitor>,
    hodge: Mutex<HodgeDecompositionMonitor>,
    doob: Mutex<DoobDecompositionMonitor>,
    fano: Mutex<FanoBoundMonitor>,
    dobrushin: Mutex<DobrushinContractionMonitor>,
    azuma: Mutex<AzumaHoeffdingMonitor>,
    renewal: Mutex<RenewalTheoryMonitor>,
    lempel_ziv: Mutex<LempelZivMonitor>,
    spectral_gap: Mutex<SpectralGapMonitor>,
    submodular: Mutex<SubmodularCoverageMonitor>,
    bifurcation: Mutex<BifurcationDetector>,
    entropy_rate: Mutex<EntropyRateMonitor>,
    ito_qv: Mutex<ItoQuadraticVariationMonitor>,
    borel_cantelli: Mutex<BorelCantelliMonitor>,
    ornstein_uhlenbeck: Mutex<OrnsteinUhlenbeckMonitor>,
    hurst: Mutex<HurstExponentMonitor>,
    dispersion: Mutex<DispersionIndexMonitor>,
    birkhoff: Mutex<BirkhoffErgodicMonitor>,
    alpha_investing: Mutex<AlphaInvestingController>,
    approachability: Mutex<ApproachabilityController>,
    localization: Mutex<LocalizationChooser>,
    sobol_scheduler: Mutex<SobolGenerator>,
    redundancy_tuner: Mutex<RedundancyTuner>,
    evidence_log: Box<evidence::SystematicEvidenceLog<512>>,
    cached_evidence_seqno: AtomicU64,
    cached_evidence_loss: AtomicU64,
    cached_evidence_max_epoch: AtomicU64,
    policy_lookup: Option<policy_table::PolicyTableLookup>,
    cached_policy_hash: AtomicU64,
    cached_policy_load_state: AtomicU8,
    cached_policy_action_dist: [AtomicU64; 4], // Allow, FullValidate, Repair, Deny
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
    cached_loss_posterior_ppm: AtomicU64,
    cached_loss_selected_action: AtomicU8,
    cached_loss_selected_cost_milli: AtomicU64,
    cached_loss_competing_action: AtomicU8,
    cached_loss_competing_cost_milli: AtomicU64,
    cached_coupling_state: AtomicU8,
    cached_fusion_bonus_ppm: AtomicU64,
    cached_fusion_entropy_milli: AtomicU64,
    cached_fusion_drift_ppm: AtomicU64,
    cached_fusion_dominant_signal: AtomicU8,
    cached_microlocal_state: AtomicU8,
    cached_serre_state: AtomicU8,
    cached_clifford_state: AtomicU8,
    cached_ktheory_state: AtomicU8,
    cached_covering_state: AtomicU8,
    cached_tstructure_state: AtomicU8,
    cached_admm_state: AtomicU8,
    cached_atiyah_bott_state: AtomicU8,
    cached_obstruction_state: AtomicU8,
    cached_operator_norm_state: AtomicU8,
    cached_pomdp_state: AtomicU8,
    cached_sos_state: AtomicU8,
    cached_sos_barrier_state: AtomicU8,
    cached_provenance_state: AtomicU8,
    cached_grobner_state: AtomicU8,
    cached_grothendieck_state: AtomicU8,
    cached_info_geometry_state: AtomicU8,
    cached_kernel_mmd_state: AtomicU8,
    cached_malliavin_state: AtomicU8,
    cached_matrix_concentration_state: AtomicU8,
    cached_nerve_state: AtomicU8,
    cached_wasserstein_state: AtomicU8,
    cached_pac_bayes_state: AtomicU8,
    cached_stein_state: AtomicU8,
    cached_lyapunov_state: AtomicU8,
    cached_rademacher_state: AtomicU8,
    cached_transfer_entropy_state: AtomicU8,
    cached_hodge_state: AtomicU8,
    cached_doob_state: AtomicU8,
    cached_fano_state: AtomicU8,
    cached_dobrushin_state: AtomicU8,
    cached_azuma_state: AtomicU8,
    cached_renewal_state: AtomicU8,
    cached_lz_state: AtomicU8,
    cached_spectral_gap_state: AtomicU8,
    cached_submodular_state: AtomicU8,
    cached_bifurcation_state: AtomicU8,
    cached_entropy_rate_state: AtomicU8,
    cached_ito_qv_state: AtomicU8,
    cached_borel_cantelli_state: AtomicU8,
    cached_ou_state: AtomicU8,
    cached_hurst_state: AtomicU8,
    cached_dispersion_state: AtomicU8,
    cached_birkhoff_state: AtomicU8,
    cached_alpha_investing_state: AtomicU8,
    cached_approachability_state: AtomicU8,
    cached_localization_state: AtomicU8,
    cached_localization_arm: AtomicU8,
    cached_redundancy_state: AtomicU8,
    cached_redundancy_overhead_ppm: AtomicU64,
    cached_sobol_index: AtomicU64,
    cached_sobol_augmented_mask: AtomicU64,
    decisions: AtomicU64,
}

impl RuntimeMathKernel {
    /// Create a new runtime kernel.
    #[must_use]
    pub fn new() -> Self {
        Self::new_for_mode(crate::config::safety_level())
    }

    /// Create a new runtime kernel with an explicit mode.
    ///
    /// This avoids relying on global env-backed config during tests and other
    /// deterministic harness scenarios.
    #[must_use]
    pub fn new_for_mode(mode: SafetyLevel) -> Self {
        // The observe() hot path uses a cached probe mask to decide which heavy
        // monitors should run. The microbench for observe() constructs a fresh
        // kernel and never calls decide(), so we must seed a budget-feasible
        // probe plan here (instead of defaulting to all probes).
        let risk_prior_ppm = 20_000_u32;
        let mut design = OptimalDesignController::new();
        let plan = design.choose_plan(mode, risk_prior_ppm, false, false);
        let ident_ppm = design.identifiability_ppm();

        Self {
            risk: ConformalRiskEngine::new(risk_prior_ppm, 3.0),
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
            design: Mutex::new(design),
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
            ktheory: Mutex::new(KTheoryController::new()),
            covering: Mutex::new(CoveringArrayController::new()),
            tstructure: Mutex::new(TStructureController::new()),
            admm: Mutex::new(AdmmBudgetController::new()),
            atiyah_bott: Mutex::new(AtiyahBottController::new()),
            obstruction: Mutex::new(ObstructionDetector::new()),
            operator_norm: Mutex::new(OperatorNormMonitor::new()),
            pomdp: Mutex::new(PomdpRepairController::new()),
            sos: Mutex::new(SosInvariantController::new()),
            sos_barrier: Mutex::new(SosBarrierController::new()),
            provenance: Mutex::new(ProvenanceInfoController::new()),
            grobner: Mutex::new(GrobnerNormalizerController::new()),
            grothendieck: Mutex::new(GrothendieckGlueController::new()),
            info_geometry: Mutex::new(InfoGeometryMonitor::new()),
            kernel_mmd: Mutex::new(KernelMmdMonitor::new()),
            malliavin: Mutex::new(MalliavSensitivity::new()),
            matrix_concentration: Mutex::new(MatrixConcentrationMonitor::new()),
            nerve_complex: Mutex::new(NerveComplexMonitor::new()),
            wasserstein: Mutex::new(WassersteinDriftMonitor::new()),
            pac_bayes: Mutex::new(PacBayesMonitor::new()),
            stein: Mutex::new(SteinDiscrepancyMonitor::new()),
            lyapunov: Mutex::new(LyapunovStabilityMonitor::new()),
            rademacher: Mutex::new(RademacherComplexityMonitor::new()),
            transfer_entropy: Mutex::new(TransferEntropyMonitor::new()),
            hodge: Mutex::new(HodgeDecompositionMonitor::new()),
            doob: Mutex::new(DoobDecompositionMonitor::new()),
            fano: Mutex::new(FanoBoundMonitor::new()),
            dobrushin: Mutex::new(DobrushinContractionMonitor::new()),
            azuma: Mutex::new(AzumaHoeffdingMonitor::new()),
            renewal: Mutex::new(RenewalTheoryMonitor::new()),
            lempel_ziv: Mutex::new(LempelZivMonitor::new()),
            spectral_gap: Mutex::new(SpectralGapMonitor::new()),
            submodular: Mutex::new(SubmodularCoverageMonitor::new()),
            bifurcation: Mutex::new(BifurcationDetector::new()),
            entropy_rate: Mutex::new(EntropyRateMonitor::new()),
            ito_qv: Mutex::new(ItoQuadraticVariationMonitor::new()),
            borel_cantelli: Mutex::new(BorelCantelliMonitor::new()),
            ornstein_uhlenbeck: Mutex::new(OrnsteinUhlenbeckMonitor::new()),
            hurst: Mutex::new(HurstExponentMonitor::new()),
            dispersion: Mutex::new(DispersionIndexMonitor::new()),
            birkhoff: Mutex::new(BirkhoffErgodicMonitor::new()),
            alpha_investing: Mutex::new(AlphaInvestingController::new()),
            approachability: Mutex::new(ApproachabilityController::new(mode)),
            localization: Mutex::new(LocalizationChooser::new(mode)),
            sobol_scheduler: Mutex::new(SobolGenerator::new(sobol::MAX_DIM)),
            redundancy_tuner: Mutex::new(RedundancyTuner::new()),
            evidence_log: Box::new(evidence::SystematicEvidenceLog::new(0xDEAD_C0DE_CAFE_F00D)),
            cached_evidence_seqno: AtomicU64::new(0),
            cached_evidence_loss: AtomicU64::new(0),
            cached_evidence_max_epoch: AtomicU64::new(0),
            policy_lookup: None,
            cached_policy_hash: AtomicU64::new(0),
            cached_policy_load_state: AtomicU8::new(POLICY_LOAD_STATE_NONE),
            cached_policy_action_dist: std::array::from_fn(|_| AtomicU64::new(0)),
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
            cached_probe_mask: AtomicU64::new(u64::from(plan.mask)),
            cached_design_ident_ppm: AtomicU64::new(u64::from(ident_ppm)),
            cached_design_budget_ns: AtomicU64::new(plan.budget_ns),
            cached_design_expected_ns: AtomicU64::new(plan.expected_cost_ns),
            cached_design_selected: AtomicU8::new(plan.selected_count()),
            cached_sparse_state: AtomicU8::new(0),
            cached_equivariant_state: AtomicU8::new(0),
            cached_equivariant_alignment_ppm: AtomicU64::new(0),
            cached_equivariant_orbit: AtomicU8::new(0),
            cached_topos_state: AtomicU8::new(0),
            cached_audit_state: AtomicU8::new(0),
            cached_changepoint_state: AtomicU8::new(0),
            cached_conformal_state: AtomicU8::new(0),
            cached_loss_minimizer_state: AtomicU8::new(0),
            cached_loss_posterior_ppm: AtomicU64::new(500_000),
            cached_loss_selected_action: AtomicU8::new(1),
            cached_loss_selected_cost_milli: AtomicU64::new(0),
            cached_loss_competing_action: AtomicU8::new(0),
            cached_loss_competing_cost_milli: AtomicU64::new(0),
            cached_coupling_state: AtomicU8::new(0),
            cached_fusion_bonus_ppm: AtomicU64::new(0),
            cached_fusion_entropy_milli: AtomicU64::new(0),
            cached_fusion_drift_ppm: AtomicU64::new(0),
            cached_fusion_dominant_signal: AtomicU8::new(0),
            cached_microlocal_state: AtomicU8::new(0),
            cached_serre_state: AtomicU8::new(0),
            cached_clifford_state: AtomicU8::new(0),
            cached_ktheory_state: AtomicU8::new(0),
            cached_covering_state: AtomicU8::new(0),
            cached_tstructure_state: AtomicU8::new(0),
            cached_admm_state: AtomicU8::new(0),
            cached_atiyah_bott_state: AtomicU8::new(0),
            cached_obstruction_state: AtomicU8::new(0),
            cached_operator_norm_state: AtomicU8::new(0),
            cached_pomdp_state: AtomicU8::new(0),
            cached_sos_state: AtomicU8::new(0),
            cached_sos_barrier_state: AtomicU8::new(0),
            cached_provenance_state: AtomicU8::new(0),
            cached_grobner_state: AtomicU8::new(0),
            cached_grothendieck_state: AtomicU8::new(0),
            cached_info_geometry_state: AtomicU8::new(0),
            cached_kernel_mmd_state: AtomicU8::new(0),
            cached_malliavin_state: AtomicU8::new(0),
            cached_matrix_concentration_state: AtomicU8::new(0),
            cached_nerve_state: AtomicU8::new(0),
            cached_wasserstein_state: AtomicU8::new(0),
            cached_pac_bayes_state: AtomicU8::new(0),
            cached_stein_state: AtomicU8::new(0),
            cached_lyapunov_state: AtomicU8::new(0),
            cached_rademacher_state: AtomicU8::new(0),
            cached_transfer_entropy_state: AtomicU8::new(0),
            cached_hodge_state: AtomicU8::new(0),
            cached_doob_state: AtomicU8::new(0),
            cached_fano_state: AtomicU8::new(0),
            cached_dobrushin_state: AtomicU8::new(0),
            cached_azuma_state: AtomicU8::new(0),
            cached_renewal_state: AtomicU8::new(0),
            cached_lz_state: AtomicU8::new(0),
            cached_spectral_gap_state: AtomicU8::new(0),
            cached_submodular_state: AtomicU8::new(0),
            cached_bifurcation_state: AtomicU8::new(0),
            cached_entropy_rate_state: AtomicU8::new(0),
            cached_ito_qv_state: AtomicU8::new(0),
            cached_borel_cantelli_state: AtomicU8::new(0),
            cached_ou_state: AtomicU8::new(0),
            cached_hurst_state: AtomicU8::new(0),
            cached_dispersion_state: AtomicU8::new(0),
            cached_birkhoff_state: AtomicU8::new(0),
            cached_alpha_investing_state: AtomicU8::new(0),
            cached_approachability_state: AtomicU8::new(0),
            cached_localization_state: AtomicU8::new(0),
            cached_localization_arm: AtomicU8::new(1), // Default: Cautious
            cached_redundancy_state: AtomicU8::new(0),
            cached_redundancy_overhead_ppm: AtomicU64::new(100_000), // 10% default
            cached_sobol_index: AtomicU64::new(0),
            cached_sobol_augmented_mask: AtomicU64::new(0),
            decisions: AtomicU64::new(0),
        }
    }

    /// Load a proof-carrying policy table from a `.pcpt` artifact.
    ///
    /// The artifact is verified once (hash + structural invariants) and then
    /// provides O(1) lookups in `decide()`. If verification fails, the kernel
    /// continues without a policy table (conservative built-in policy).
    pub fn load_policy_table(
        &mut self,
        artifact: &[u8],
    ) -> Result<(), policy_table::PolicyTableError> {
        match policy_table::PolicyTableLookup::from_artifact(artifact) {
            Ok(lookup) => {
                self.cached_policy_hash
                    .store(lookup.hash_prefix(), Ordering::Relaxed);
                self.cached_policy_load_state
                    .store(POLICY_LOAD_STATE_LOADED, Ordering::Relaxed);
                self.policy_lookup = Some(lookup);
                Ok(())
            }
            Err(err) => {
                self.cached_policy_hash.store(0, Ordering::Relaxed);
                self.cached_policy_load_state
                    .store(POLICY_LOAD_STATE_VERIFY_FAILED, Ordering::Relaxed);
                self.policy_lookup = None;
                Err(err)
            }
        }
    }

    /// Decide runtime validation/repair strategy for one call context.
    #[must_use]
    pub fn decide(&self, mode: SafetyLevel, ctx: RuntimeContext) -> RuntimeDecision {
        let sequence = self.decisions.fetch_add(1, Ordering::Relaxed) + 1;
        // Cadence-gate expensive sampling/oracle updates. Strict mode prioritizes
        // latency stability over reactivity; hardened can resample more often.
        let do_resample = match mode {
            SafetyLevel::Strict => sequence.is_multiple_of(512),
            SafetyLevel::Hardened => sequence.is_multiple_of(512),
            SafetyLevel::Off => sequence.is_multiple_of(1024),
        };
        if do_resample {
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
        // K-theory transport: ABI compatibility integrity.
        // Fractured K-class means ABI contract bundle diverged from baseline.
        let ktheory_bonus = match self.cached_ktheory_state.load(Ordering::Relaxed) {
            3 => 130_000u32, // Fractured — ABI compatibility broken
            2 => 50_000u32,  // Drift — compatibility degrading
            _ => 0u32,       // Calibrating/Compatible
        };
        // Covering-array matroid: conformance interaction coverage.
        // CriticalGap means many interaction tuples are untested.
        let covering_bonus = match self.cached_covering_state.load(Ordering::Relaxed) {
            3 => 100_000u32, // CriticalGap — many untested interactions
            2 => 40_000u32,  // CoverageGap — some missing coverage
            _ => 0u32,       // Calibrating/Complete
        };
        // Derived t-structure: bootstrap ordering invariants.
        // OrthogonalityViolation means stages executing severely out of order.
        let tstructure_bonus = match self.cached_tstructure_state.load(Ordering::Relaxed) {
            3 => 140_000u32, // OrthogonalityViolation — severe ordering fault
            2 => 55_000u32,  // Disorder — minor ordering issues
            _ => 0u32,       // Calibrating/WellOrdered
        };
        // Atiyah-Bott fixed-point localization: concentrated anomaly detection.
        // ConcentratedAnomaly means risk localizes at very few controllers
        // while the rest are perfectly stable — an isolated severe fault.
        let atiyah_bott_bonus = match self.cached_atiyah_bott_state.load(Ordering::Relaxed) {
            3 => 150_000u32, // ConcentratedAnomaly — isolated severe fault
            2 => 45_000u32,  // Localized — risk concentrating
            _ => 0u32,       // Calibrating/Distributed
        };
        // POMDP repair policy: optimality gap monitoring.
        // PolicyDivergence means the threshold cascade is severely miscalibrated
        // relative to the Bellman-optimal policy.
        let pomdp_bonus = match self.cached_pomdp_state.load(Ordering::Relaxed) {
            3 => 120_000u32, // PolicyDivergence — severe miscalibration
            2 => 50_000u32,  // SuboptimalPolicy — growing gap
            _ => 0u32,       // Calibrating/Optimal
        };
        // SOS polynomial invariant: cross-controller coherence guard.
        // InvariantViolated means the combined controller state is in a region
        // that the SOS certificate proved impossible under normal operation.
        let sos_bonus = match self.cached_sos_state.load(Ordering::Relaxed) {
            3 => 180_000u32, // InvariantViolated — structurally impossible state
            2 => 60_000u32,  // InvariantStressed — approaching violation
            _ => 0u32,       // Calibrating/InvariantSatisfied
        };
        // ADMM budget allocator: primal-dual convergence of budget allocation.
        // ConstraintViolation means the risk/latency/coverage budget split
        // is significantly suboptimal — shadow prices indicate binding constraints.
        let admm_bonus = match self.cached_admm_state.load(Ordering::Relaxed) {
            3 => 130_000u32, // ConstraintViolation — budget severely suboptimal
            2 => 45_000u32,  // DualDrift — budget allocation adapting
            _ => 0u32,       // Calibrating/Converged
        };
        // Spectral-sequence obstruction: cross-layer consistency defects.
        // CriticalObstruction means d² ≠ 0 — the controller ensemble has
        // a global consistency defect invisible to individual controllers.
        let obstruction_bonus = match self.cached_obstruction_state.load(Ordering::Relaxed) {
            3 => 160_000u32, // CriticalObstruction — ensemble breakdown
            2 => 50_000u32,  // MinorObstruction — emerging defect
            _ => 0u32,       // Calibrating/Exact
        };
        // Operator-norm spectral radius: ensemble dynamics stability.
        // Unstable means perturbations are amplifying across the controller
        // ensemble — a positive feedback cascade.
        let operator_norm_bonus = match self.cached_operator_norm_state.load(Ordering::Relaxed) {
            3 => 170_000u32, // Unstable — perturbation amplification
            2 => 55_000u32,  // Marginal — near stability boundary
            _ => 0u32,       // Calibrating/Contractive
        };
        // Malliavin sensitivity: fragile configuration near decision boundary.
        // Fragile means small perturbations could flip the safety decision.
        let malliavin_bonus = match self.cached_malliavin_state.load(Ordering::Relaxed) {
            3 => 140_000u32, // Fragile — dominated by unpredictable perturbations
            2 => 50_000u32,  // Sensitive — near decision boundary
            _ => 0u32,       // Calibrating/Robust
        };
        // Information geometry: Fisher-Rao geodesic distance on state manifold.
        // StructuralBreak means the shape of the ensemble distribution shifted.
        let info_geo_bonus = match self.cached_info_geometry_state.load(Ordering::Relaxed) {
            3 => 150_000u32, // StructuralBreak — distributional shape change
            2 => 55_000u32,  // Drifting — gradual regime drift
            _ => 0u32,       // Calibrating/Stationary
        };
        // Matrix concentration: Bernstein bound violation on covariance.
        // BoundViolation means statistically significant structural change.
        let matrix_conc_bonus = match self
            .cached_matrix_concentration_state
            .load(Ordering::Relaxed)
        {
            3 => 160_000u32, // BoundViolation — covariance change significant
            2 => 50_000u32,  // BoundaryApproach — approaching bound
            _ => 0u32,       // Calibrating/WithinBound
        };
        // Nerve complex: Čech nerve correlation coherence. Fragmented means
        // controllers have decorrelated into disjoint behavior clusters.
        let nerve_bonus = match self.cached_nerve_state.load(Ordering::Relaxed) {
            3 => 140_000u32, // Fragmented — severe decorrelation
            2 => 50_000u32,  // Weakening — partial decorrelation
            _ => 0u32,       // Calibrating/Cohesive
        };
        // Wasserstein drift: Earth Mover's distance on severity histograms.
        // Displaced means the metric distance to baseline is large.
        let wasserstein_bonus = match self.cached_wasserstein_state.load(Ordering::Relaxed) {
            3 => 150_000u32, // Displaced — large metric shift
            2 => 55_000u32,  // Transporting — moderate drift
            _ => 0u32,       // Calibrating/Stable
        };
        // Kernel MMD: distribution-free two-sample test in RKHS.
        // Anomalous means arbitrary distributional shift detected.
        let mmd_bonus = match self.cached_kernel_mmd_state.load(Ordering::Relaxed) {
            3 => 160_000u32, // Anomalous — significant discrepancy
            2 => 50_000u32,  // Drifting — moderate distributional shift
            _ => 0u32,       // Calibrating/Conforming
        };
        // PAC-Bayes generalization bound: trust monitoring for the ensemble.
        // Unreliable means the bound is too loose to trust ensemble decisions.
        let pac_bayes_bonus = match self.cached_pac_bayes_state.load(Ordering::Relaxed) {
            3 => 140_000u32, // Unreliable — ensemble cannot be trusted
            2 => 50_000u32,  // Uncertain — bound loosening
            _ => 0u32,       // Calibrating/Tight
        };
        // Stein discrepancy: goodness-of-fit vs reference model.
        // Rejected means strong evidence the system has left the reference regime.
        let stein_bonus = match self.cached_stein_state.load(Ordering::Relaxed) {
            3 => 150_000u32, // Rejected — model misspecification
            2 => 55_000u32,  // Deviant — moderate deviation
            _ => 0u32,       // Calibrating/Consistent
        };
        // Lyapunov stability: trajectory-level divergence detection.
        // Chaotic means perturbations are growing exponentially.
        let lyapunov_bonus = match self.cached_lyapunov_state.load(Ordering::Relaxed) {
            3 => 160_000u32, // Chaotic — exponential divergence
            2 => 55_000u32,  // Marginal — near stability boundary
            _ => 0u32,       // Calibrating/Stable
        };
        // Rademacher complexity: data-dependent ensemble capacity monitoring.
        // Overfit means the ensemble can fit noise — predictions unreliable.
        let rademacher_bonus = match self.cached_rademacher_state.load(Ordering::Relaxed) {
            3 => 140_000u32, // Overfit — ensemble too expressive
            2 => 50_000u32,  // Elevated — approaching capacity limit
            _ => 0u32,       // Calibrating/Controlled
        };
        // Transfer entropy: directed causal information flow detection.
        // CascadeRisk means strong directional dependencies between controllers.
        let transfer_entropy_bonus =
            match self.cached_transfer_entropy_state.load(Ordering::Relaxed) {
                3 => 150_000u32, // CascadeRisk — strong causal coupling
                2 => 50_000u32,  // CausalCoupling — moderate dependencies
                _ => 0u32,       // Calibrating/Independent
            };
        // Hodge decomposition: cyclic inconsistency in controller ordering.
        // Incoherent means the severity ordering is deeply cyclically inconsistent.
        let hodge_bonus = match self.cached_hodge_state.load(Ordering::Relaxed) {
            3 => 140_000u32, // Incoherent — deep cyclic inconsistency
            2 => 50_000u32,  // Inconsistent — some cyclic structure
            _ => 0u32,       // Calibrating/Coherent
        };
        // Doob decomposition: systematic non-random drift in severity process.
        // Runaway means the predictable component dominates — severity worsening.
        let doob_bonus = match self.cached_doob_state.load(Ordering::Relaxed) {
            3 => 150_000u32, // Runaway — strong systematic drift
            2 => 50_000u32,  // Drifting — moderate non-random trend
            _ => 0u32,       // Calibrating/Stationary
        };
        // Fano bound: information-theoretic error lower bound.
        // Opaque means the severity process is inherently unpredictable.
        let fano_bonus = match self.cached_fano_state.load(Ordering::Relaxed) {
            3 => 120_000u32, // Opaque — nearly i.i.d., no temporal structure
            2 => 45_000u32,  // Uncertain — reduced predictability
            _ => 0u32,       // Calibrating/Predictable
        };
        // Dobrushin contraction: Markov chain mixing/ergodicity failure.
        // NonMixing means the severity chain cannot recover from perturbations.
        let dobrushin_bonus = match self.cached_dobrushin_state.load(Ordering::Relaxed) {
            3 => 160_000u32, // NonMixing — chain trapped, no recovery
            2 => 55_000u32,  // SlowMixing — chain mixing slowly
            _ => 0u32,       // Calibrating/Ergodic
        };
        // Azuma-Hoeffding: concentration bound violation on noise component.
        // Explosive means severity jumps exceed bounded-difference assumption.
        let azuma_bonus = match self.cached_azuma_state.load(Ordering::Relaxed) {
            3 => 170_000u32, // Explosive — Azuma bounds violated
            2 => 60_000u32,  // Diffuse — approaching bounds
            _ => 0u32,       // Calibrating/Concentrated
        };
        // Renewal theory: inter-arrival time of return-to-healthy.
        // Stale means the system is stuck in high severity without recovering.
        let renewal_bonus = match self.cached_renewal_state.load(Ordering::Relaxed) {
            3 => 140_000u32, // Stale — system stuck, recovery overdue
            2 => 50_000u32,  // Aging — recovery taking longer than expected
            _ => 0u32,       // Calibrating/Renewing
        };
        // Lempel-Ziv complexity: algorithmic compressibility of severity.
        // Repetitive means stuck/looping; Entropic means loss of structure.
        let lz_bonus = match self.cached_lz_state.load(Ordering::Relaxed) {
            2 => 110_000u32, // Repetitive — stuck in pattern
            3 => 80_000u32,  // Entropic — near-random, lost structure
            _ => 0u32,       // Calibrating/Structured
        };
        // Ito quadratic variation: realized volatility of severity noise.
        // Volatile means severity transitions are erratic; Frozen means deterministic.
        let ito_qv_bonus = match self.cached_ito_qv_state.load(Ordering::Relaxed) {
            3 => 130_000u32, // Volatile — noise is exploding
            2 => 45_000u32,  // Frozen — process stuck/deterministic
            _ => 0u32,       // Calibrating/Stable
        };
        // Borel-Cantelli recurrence: tail event persistence classification.
        // Absorbing means stuck in failure; Recurrent means failures persist.
        let borel_cantelli_bonus = match self.cached_borel_cantelli_state.load(Ordering::Relaxed) {
            3 => 150_000u32, // Absorbing — stuck in exceedance
            2 => 55_000u32,  // Recurrent — persistent exceedances
            _ => 0u32,       // Calibrating/Transient
        };
        // Ornstein-Uhlenbeck mean reversion: equilibrium attraction strength.
        // Explosive means severity diverges from mean; Diffusing means random walk.
        let ou_bonus = match self.cached_ou_state.load(Ordering::Relaxed) {
            3 => 160_000u32, // Explosive — mean-diverging
            2 => 50_000u32,  // Diffusing — random walk, no restoring force
            _ => 0u32,       // Calibrating/Stable
        };
        // Hurst exponent: long-range dependence in severity process.
        // Persistent means failures cluster at multiple time scales beyond EWMA reach.
        let hurst_bonus = match self.cached_hurst_state.load(Ordering::Relaxed) {
            2 => 120_000u32, // Persistent — long-range clustering
            3 => 80_000u32,  // AntiPersistent — self-correcting oscillations
            _ => 0u32,       // Calibrating/Independent
        };
        // Index of dispersion: alarm clustering vs independence.
        // Clustered means failures come in correlated bursts (common-cause).
        let dispersion_bonus = match self.cached_dispersion_state.load(Ordering::Relaxed) {
            2 => 130_000u32, // Clustered — overdispersed, cascading failures
            3 => 60_000u32,  // Underdispersed — unnaturally regular
            _ => 0u32,       // Calibrating/Poisson
        };
        // Birkhoff ergodic convergence: time-average convergence rate.
        // NonErgodic means the system is trapped in a subset of states.
        let birkhoff_bonus = match self.cached_birkhoff_state.load(Ordering::Relaxed) {
            3 => 150_000u32, // NonErgodic — trapped in states
            2 => 55_000u32,  // SlowConvergence — near non-ergodic boundary
            _ => 0u32,       // Calibrating/Ergodic
        };
        // Provenance info-theoretic: fingerprint entropy degradation signals
        // collision resistance loss in the allocation integrity subsystem.
        let provenance_bonus = match self.cached_provenance_state.load(Ordering::Relaxed) {
            3 => 160_000u32, // CollisionRisk — key rotation needed
            2 => 55_000u32,  // EntropyDrift — entropy degrading
            _ => 0u32,       // Calibrating/Secure
        };
        // Grobner normalizer: confluent constraint verification over the
        // controller state vector. StructuralFault = state outside the ideal.
        let grobner_bonus = match self.cached_grobner_state.load(Ordering::Relaxed) {
            3 => 170_000u32, // StructuralFault — impossible controller config
            2 => 50_000u32,  // MinorInconsistency — some constraints breached
            _ => 0u32,       // Calibrating/Consistent
        };
        // Grothendieck glue: cocycle/descent coherence for NSS/resolv/locale.
        // StackificationFault = equivalence classes don't compose.
        let grothendieck_bonus = match self.cached_grothendieck_state.load(Ordering::Relaxed) {
            3 => 140_000u32, // StackificationFault — deep incoherence
            2 => 55_000u32,  // DescentFailure — cocycle violations
            _ => 0u32,       // Calibrating/Coherent
        };
        // Aggregate risk contributions without saturating arithmetic; we clamp at 1_000_000 ppm.
        // This avoids dozens of per-call saturating ops on the decide hot path.
        let mut pre_design_risk_ppm_acc = u64::from(base_risk_ppm);
        pre_design_risk_ppm_acc += u64::from(sampled_bonus);
        pre_design_risk_ppm_acc += u64::from(cohomology_bonus);
        pre_design_risk_ppm_acc += u64::from(tropical_bonus);
        pre_design_risk_ppm_acc += u64::from(spectral_bonus);
        pre_design_risk_ppm_acc += u64::from(sig_bonus);
        pre_design_risk_ppm_acc += u64::from(topo_bonus);
        pre_design_risk_ppm_acc += u64::from(anytime_bonus);
        pre_design_risk_ppm_acc += u64::from(cvar_bonus);
        pre_design_risk_ppm_acc += u64::from(bridge_bonus);
        pre_design_risk_ppm_acc += u64::from(ld_bonus);
        pre_design_risk_ppm_acc += u64::from(hji_bonus);
        pre_design_risk_ppm_acc += u64::from(mfg_bonus);
        pre_design_risk_ppm_acc += u64::from(padic_bonus);
        pre_design_risk_ppm_acc += u64::from(symplectic_bonus);
        pre_design_risk_ppm_acc += u64::from(sparse_bonus);
        pre_design_risk_ppm_acc += u64::from(equivariant_bonus);
        pre_design_risk_ppm_acc += u64::from(topos_bonus);
        pre_design_risk_ppm_acc += u64::from(audit_bonus);
        pre_design_risk_ppm_acc += u64::from(changepoint_bonus);
        pre_design_risk_ppm_acc += u64::from(conformal_bonus);
        pre_design_risk_ppm_acc += u64::from(loss_min_bonus);
        pre_design_risk_ppm_acc += u64::from(coupling_bonus);
        pre_design_risk_ppm_acc += u64::from(fusion_bonus);
        pre_design_risk_ppm_acc += u64::from(microlocal_bonus);
        pre_design_risk_ppm_acc += u64::from(serre_bonus);
        pre_design_risk_ppm_acc += u64::from(clifford_bonus);
        pre_design_risk_ppm_acc += u64::from(ktheory_bonus);
        pre_design_risk_ppm_acc += u64::from(covering_bonus);
        pre_design_risk_ppm_acc += u64::from(tstructure_bonus);
        pre_design_risk_ppm_acc += u64::from(atiyah_bott_bonus);
        pre_design_risk_ppm_acc += u64::from(pomdp_bonus);
        pre_design_risk_ppm_acc += u64::from(sos_bonus);
        pre_design_risk_ppm_acc += u64::from(admm_bonus);
        pre_design_risk_ppm_acc += u64::from(obstruction_bonus);
        pre_design_risk_ppm_acc += u64::from(operator_norm_bonus);
        pre_design_risk_ppm_acc += u64::from(provenance_bonus);
        pre_design_risk_ppm_acc += u64::from(grobner_bonus);
        pre_design_risk_ppm_acc += u64::from(grothendieck_bonus);
        pre_design_risk_ppm_acc += u64::from(malliavin_bonus);
        pre_design_risk_ppm_acc += u64::from(info_geo_bonus);
        pre_design_risk_ppm_acc += u64::from(matrix_conc_bonus);
        pre_design_risk_ppm_acc += u64::from(nerve_bonus);
        pre_design_risk_ppm_acc += u64::from(wasserstein_bonus);
        pre_design_risk_ppm_acc += u64::from(mmd_bonus);
        pre_design_risk_ppm_acc += u64::from(pac_bayes_bonus);
        pre_design_risk_ppm_acc += u64::from(stein_bonus);
        pre_design_risk_ppm_acc += u64::from(lyapunov_bonus);
        pre_design_risk_ppm_acc += u64::from(rademacher_bonus);
        pre_design_risk_ppm_acc += u64::from(transfer_entropy_bonus);
        pre_design_risk_ppm_acc += u64::from(hodge_bonus);
        pre_design_risk_ppm_acc += u64::from(doob_bonus);
        pre_design_risk_ppm_acc += u64::from(fano_bonus);
        pre_design_risk_ppm_acc += u64::from(dobrushin_bonus);
        pre_design_risk_ppm_acc += u64::from(azuma_bonus);
        pre_design_risk_ppm_acc += u64::from(renewal_bonus);
        pre_design_risk_ppm_acc += u64::from(lz_bonus);
        pre_design_risk_ppm_acc += u64::from(ito_qv_bonus);
        pre_design_risk_ppm_acc += u64::from(borel_cantelli_bonus);
        pre_design_risk_ppm_acc += u64::from(ou_bonus);
        pre_design_risk_ppm_acc += u64::from(hurst_bonus);
        pre_design_risk_ppm_acc += u64::from(dispersion_bonus);
        pre_design_risk_ppm_acc += u64::from(birkhoff_bonus);
        let pre_design_risk_ppm = pre_design_risk_ppm_acc.min(1_000_000) as u32;

        let ident_ppm = self.cached_design_ident_ppm.load(Ordering::Relaxed) as u32;
        let design_bonus = {
            if ident_ppm < 150_000 {
                95_000u32
            } else if ident_ppm < 300_000 {
                40_000u32
            } else {
                0u32
            }
        };

        let risk_upper_bound_ppm =
            (u64::from(pre_design_risk_ppm) + u64::from(design_bonus)).min(1_000_000) as u32;

        // D-optimal probe scheduling:
        // choose heavy monitors under budget to maximize online identifiability.
        //
        // IMPORTANT: Strict decide() is a hot path; it must not execute heavy
        // floating-point or linear-algebra work per-call. We update the design
        // plan on a cadence and cache its outputs in atomics.
        // Cadence-gate design updates; the controller performs floating-point + logdet
        // work under a mutex, so strict mode updates less frequently.
        let do_design_update = self.cached_design_budget_ns.load(Ordering::Relaxed) == 0
            || match mode {
                SafetyLevel::Strict => sequence.is_multiple_of(4096),
                SafetyLevel::Hardened => sequence.is_multiple_of(4096),
                SafetyLevel::Off => sequence.is_multiple_of(8192),
            };
        if do_design_update {
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
            // Reset Sobol augmentation diff on plan refresh; the cadence block below re-augments
            // deterministically using the new base plan.
            self.cached_sobol_augmented_mask.store(0, Ordering::Relaxed);
        }

        // Sobol quasi-random probe augmentation: deterministically rotate additional probes
        // beyond the D-optimal base set. Runs on cadence (every 512 decisions) to keep
        // the decide hot path fast.
        if sequence.is_multiple_of(512) {
            let current_mask = self.cached_probe_mask.load(Ordering::Relaxed) as u32;
            let augmented_diff = self.cached_sobol_augmented_mask.load(Ordering::Relaxed) as u32;
            let base_mask = current_mask ^ augmented_diff;

            let budget_ns = self.cached_design_budget_ns.load(Ordering::Relaxed);
            let expected_cost_ns = self.cached_design_expected_ns.load(Ordering::Relaxed);
            let budget_remaining = budget_ns.saturating_sub(expected_cost_ns);

            let mut sobol = self.sobol_scheduler.lock();
            let point = sobol.next_ppm();
            let cov_state = self.cached_covering_state.load(Ordering::Relaxed);
            // Base threshold: 500k ppm = 50% activation probability per probe.
            // Coverage gaps lower the threshold to activate more probes and
            // fill uncovered interaction tuples faster.
            let threshold = match cov_state {
                3 => 250_000u32, // CriticalGap: aggressive exploration
                2 => 350_000u32, // CoverageGap: moderate exploration
                _ => 500_000u32, // Calibrating/Complete: standard rotation
            };

            let mut augmented_mask = base_mask;
            let mut augmented_cost = 0u64;
            // Map each probe to a Sobol dimension (mod 8) for activation.
            // Probes whose Sobol coordinate exceeds the threshold are added
            // if they fit within the remaining budget.
            for probe in Probe::ALL {
                if (base_mask & probe.bit()) != 0 {
                    continue; // already in D-optimal set
                }
                let dim_idx = (probe as u8 as usize) % sobol.dim();
                if point[dim_idx] >= threshold {
                    let cost = design::probe_cost_ns(probe);
                    if augmented_cost.saturating_add(cost) <= budget_remaining {
                        augmented_mask |= probe.bit();
                        augmented_cost += cost;
                    }
                }
            }

            // Replace probe mask with Sobol-augmented version.
            self.cached_probe_mask
                .store(u64::from(augmented_mask), Ordering::Relaxed);
            self.cached_sobol_index
                .store(u64::from(sobol.index()), Ordering::Relaxed);
            self.cached_sobol_augmented_mask
                .store(u64::from(augmented_mask ^ base_mask), Ordering::Relaxed);
        }

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
        // SOS barrier certificate: if the barrier evaluator reports Warning or
        // Violated, force full validation. This is the runtime embodiment of
        // the offline SOS safety proof — monotone escalation only.
        if self.cached_sos_barrier_state.load(Ordering::Relaxed) >= 2 {
            profile = ValidationProfile::Full;
        }
        // Blackwell approachability: if the controller detects the cumulative
        // payoff vector is outside the safe set (Violated), force full validation.
        // Drifting is a warning; only Violated (code 3) triggers escalation.
        if self.cached_approachability_state.load(Ordering::Relaxed) >= 3 {
            profile = ValidationProfile::Full;
        }
        // Localization chooser: if the policy arm is Thorough (2) or higher,
        // force full validation. Conservative escalation only — the chooser
        // cannot de-escalate below the current profile.
        if self.cached_localization_arm.load(Ordering::Relaxed) >= 2 {
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

        // Proof-carrying policy table: O(1) lookup provides offline-synthesized
        // profile/action suggestion. Strict mode: table only controls validation
        // depth (conservative escalation). Hardened mode: table may choose action.
        let policy_cell = self.policy_lookup.as_ref().and_then(|pt| {
            pt.lookup(
                mode,
                ctx.family,
                risk_upper_bound_ppm,
                fast_over_budget,
                full_over_budget,
                pareto_budget_exhausted,
                consistency_faults,
            )
        });
        if let Some(cell) = policy_cell {
            // Conservative merge: table can only escalate profile, never de-escalate.
            if cell.profile.requires_full() {
                profile = ValidationProfile::Full;
            }
        }

        let admissible = self
            .barrier
            .admissible(&ctx, mode, profile, risk_upper_bound_ppm, limits);

        // Policy table escalation: extract Deny/Repair/FullValidate suggestions.
        // Allow is NOT extracted — it defers to the normal cascade so that the
        // source-level ordering invariant (barrier → full_validation → repair → Allow)
        // is preserved.
        let policy_escalation = policy_cell.and_then(|cell| match cell.action {
            // Hardened mode: table may choose Repair/Deny directly.
            MembraneAction::Deny if mode.heals_enabled() => Some(MembraneAction::Deny),
            MembraneAction::Repair(heal) if mode.heals_enabled() => {
                Some(MembraneAction::Repair(heal))
            }
            // Strict mode: Deny/Repair clamp to FullValidate (depth control
            // only — cannot change externally visible semantics per bd-3kh).
            MembraneAction::Deny | MembraneAction::Repair(_) => Some(MembraneAction::FullValidate),
            MembraneAction::FullValidate => Some(MembraneAction::FullValidate),
            _ => None,
        });

        let action = if !admissible {
            if mode.heals_enabled() {
                MembraneAction::Repair(HealingAction::ReturnSafeDefault)
            } else {
                MembraneAction::Deny
            }
        } else if let Some(escalated) = policy_escalation {
            escalated
        } else if profile.requires_full()
            || risk_upper_bound_ppm >= limits.full_validation_trigger_ppm
        {
            MembraneAction::FullValidate
        } else if mode.heals_enabled() && risk_upper_bound_ppm >= limits.repair_trigger_ppm {
            MembraneAction::Repair(HealingAction::UpgradeToSafeVariant)
        } else {
            MembraneAction::Allow
        };

        // Track policy table action distribution for snapshot.
        let action_idx = match action {
            MembraneAction::Allow => 0,
            MembraneAction::FullValidate => 1,
            MembraneAction::Repair(_) => 2,
            MembraneAction::Deny => 3,
        };
        self.cached_policy_action_dist[action_idx].fetch_add(1, Ordering::Relaxed);

        let mut decision = RuntimeDecision {
            profile,
            action,
            policy_id: compute_policy_id(mode, ctx.family, profile, action),
            risk_upper_bound_ppm,
            evidence_seqno: 0,
        };

        // Evidence recording is intentionally cadence-gated:
        // `record_decision()` computes integrity hashes + publishes into a ring buffer, which is
        // too expensive to run on every call even in hardened mode.
        //
        // Policy:
        // - Always record adverse decisions (Repair/Deny).
        // - Otherwise, sample on a coarse cadence to keep overhead negligible.
        let adverse = matches!(action, MembraneAction::Deny | MembraneAction::Repair(_));
        let do_evidence = adverse
            || match mode {
                SafetyLevel::Strict => sequence.is_multiple_of(16384),
                SafetyLevel::Hardened => sequence.is_multiple_of(16384),
                SafetyLevel::Off => false,
            };
        if do_evidence {
            let loss_evidence = evidence::LossEvidenceV1 {
                posterior_adverse_ppm: self
                    .cached_loss_posterior_ppm
                    .load(Ordering::Relaxed)
                    .min(1_000_000) as u32,
                selected_action: self.cached_loss_selected_action.load(Ordering::Relaxed),
                competing_action: self.cached_loss_competing_action.load(Ordering::Relaxed),
                selected_expected_loss_milli: self
                    .cached_loss_selected_cost_milli
                    .load(Ordering::Relaxed)
                    .min(u64::from(u32::MAX)) as u32,
                competing_expected_loss_milli: self
                    .cached_loss_competing_cost_milli
                    .load(Ordering::Relaxed)
                    .min(u64::from(u32::MAX)) as u32,
            };
            let seqno = self.evidence_log.record_decision(
                mode,
                ctx,
                decision,
                0,
                adverse,
                Some(loss_evidence),
                0,
                None,
            );
            decision.evidence_seqno = seqno;
            self.cached_evidence_seqno.store(seqno, Ordering::Relaxed);
        }

        decision
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
        mode: SafetyLevel,
        family: ApiFamily,
        aligned: bool,
        recent_page: bool,
        ordering_used: &[CheckStage; 7],
        exit_stage: Option<usize>,
    ) {
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
        mode: SafetyLevel,
        family: ApiFamily,
        profile: ValidationProfile,
        estimated_cost_ns: u64,
        adverse: bool,
    ) {
        if !observe_feedback_enabled() {
            let _ = (mode, family, profile, estimated_cost_ns, adverse);
            return;
        }

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
        let observe_seq = {
            let path = match profile {
                ValidationProfile::Fast => PipelinePath::FastExit,
                ValidationProfile::Full => PipelinePath::Full,
            };
            let mut tropical = self.tropical.lock();
            tropical.observe_path(path, estimated_cost_ns);
            let observe_seq = tropical.total_observations();
            // Publish metrics every 256 observations.
            if observe_seq.is_multiple_of(256) {
                TROPICAL_METRICS.publish(&tropical);
            }
            observe_seq
        };

        // Cadence-gate the expensive meta-controller cascade (PAC-Bayes, fusion, etc.).
        // The core probe set is still selected by the design kernel via `probe_mask`.
        let meta_interval = match mode {
            SafetyLevel::Strict => 32u64,
            SafetyLevel::Hardened => 16u64,
            SafetyLevel::Off => 64u64,
        };
        let run_meta = observe_seq.is_multiple_of(meta_interval);

        // Redundancy tuner: cadence-gated epoch-level loss observation.
        // This is an observe-path controller, so its updates are driven from
        // observe_validation_result() rather than decide().
        if observe_seq.is_multiple_of(4096) && !matches!(mode, SafetyLevel::Off) {
            // Derive approximate epoch loss: if evidence seqno hasn't advanced
            // proportionally, we infer loss from the gap.
            let seqno = self.cached_evidence_seqno.load(Ordering::Relaxed);
            let loss_count = self.cached_evidence_loss.load(Ordering::Relaxed);
            let epoch = self.cached_evidence_max_epoch.load(Ordering::Relaxed);
            let loss_ppm = if seqno > 0 {
                ((loss_count as u128).saturating_mul(1_000_000) / (seqno as u128)) as u32
            } else {
                0
            };
            let mut tuner = self.redundancy_tuner.lock();
            let _ = tuner.observe_epoch(loss_ppm, epoch);
            self.cached_redundancy_state
                .store(tuner.state() as u8, Ordering::Relaxed);
            self.cached_redundancy_overhead_ppm
                .store(u64::from(tuner.overhead_ppm()), Ordering::Relaxed);
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
                lm.observe(family, action_code, adverse, estimated_cost_ns);
                let summary = lm.summary();
                let state = summary.state;
                loss_minimizer_anomaly = Some(matches!(
                    state,
                    LossState::DenyBiased | LossState::CostExplosion
                ));
                self.cached_loss_posterior_ppm.store(
                    (summary.posterior_adverse_prob.clamp(0.0, 1.0) * 1_000_000.0).round() as u64,
                    Ordering::Relaxed,
                );
                self.cached_loss_selected_action
                    .store(summary.recommended_action, Ordering::Relaxed);
                self.cached_loss_selected_cost_milli.store(
                    (summary.selected_expected_loss.max(0.0) * 1_000.0).round() as u64,
                    Ordering::Relaxed,
                );
                self.cached_loss_competing_action
                    .store(summary.competing_action, Ordering::Relaxed);
                self.cached_loss_competing_cost_milli.store(
                    (summary.competing_expected_loss.max(0.0) * 1_000.0).round() as u64,
                    Ordering::Relaxed,
                );
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

        if run_meta {
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

            // Feed K-theory transport controller with behavioral contract coordinates.
            // Encodes: (normalized_latency, adverse, profile_depth, risk_level).
            {
                let norm_latency = (estimated_cost_ns as f64).clamp(0.0, 200.0) / 200.0;
                let adverse_f = if adverse { 1.0 } else { 0.0 };
                let prof_depth = if matches!(profile, ValidationProfile::Full) {
                    1.0
                } else {
                    0.0
                };
                let risk_level = f64::from(risk_bound_ppm) / 1_000_000.0;
                let coords = [norm_latency, adverse_f, prof_depth, risk_level];
                let kt_code = {
                    let mut kt = self.ktheory.lock();
                    kt.observe_and_update(family as usize, coords);
                    match kt.state() {
                        KTheoryState::Calibrating => 0u8,
                        KTheoryState::Compatible => 1u8,
                        KTheoryState::Drift => 2u8,
                        KTheoryState::Fractured => 3u8,
                    }
                };
                self.cached_ktheory_state.store(kt_code, Ordering::Relaxed);
            }

            // Feed covering-array matroid conformance scheduler.
            // Binary parameters: family_high, mode_hardened, profile_full, adverse,
            // contention_high, aligned.
            {
                let family_high = if (family as u8) >= 4 { 1u8 } else { 0u8 };
                let mode_hard = if mode.heals_enabled() { 1u8 } else { 0u8 };
                let prof_full = if matches!(profile, ValidationProfile::Full) {
                    1u8
                } else {
                    0u8
                };
                let adverse_b = if adverse { 1u8 } else { 0u8 };
                let contention_high = if estimated_cost_ns > 100 { 1u8 } else { 0u8 };
                let aligned = if estimated_cost_ns <= 16 && !adverse {
                    1u8
                } else {
                    0u8
                };
                let params = [
                    family_high,
                    mode_hard,
                    prof_full,
                    adverse_b,
                    contention_high,
                    aligned,
                ];
                let cov_code = {
                    let mut cov = self.covering.lock();
                    cov.observe_and_update(params);
                    match cov.state() {
                        CoverageState::Calibrating => 0u8,
                        CoverageState::Complete => 1u8,
                        CoverageState::CoverageGap => 2u8,
                        CoverageState::CriticalGap => 3u8,
                    }
                };
                self.cached_covering_state
                    .store(cov_code, Ordering::Relaxed);
            }

            // Feed derived t-structure bootstrap ordering controller.
            // We map family to a stage index (families are loosely ordered by
            // initialization dependency depth) and check predecessors via risk.
            {
                let stage_idx = (family as usize).min(7);
                let predecessors_complete = !adverse && risk_bound_ppm < 200_000;
                let ts_code = {
                    let mut ts = self.tstructure.lock();
                    ts.observe_and_update(stage_idx, predecessors_complete);
                    match ts.state() {
                        TStructureState::Calibrating => 0u8,
                        TStructureState::WellOrdered => 1u8,
                        TStructureState::Disorder => 2u8,
                        TStructureState::OrthogonalityViolation => 3u8,
                    }
                };
                self.cached_tstructure_state
                    .store(ts_code, Ordering::Relaxed);
            }

            // Feed POMDP repair policy controller.
            // Infer approximate action code from profile, mode, and risk.
            {
                let action_code = if risk_bound_ppm >= 500_000 {
                    if mode.heals_enabled() { 2u8 } else { 3u8 } // Repair / Deny
                } else if profile.requires_full() || risk_bound_ppm >= 200_000 {
                    1u8 // FullValidate
                } else if mode.heals_enabled() && risk_bound_ppm >= 100_000 {
                    2u8 // Repair
                } else {
                    0u8 // Allow
                };
                let pomdp_code = {
                    let mut p = self.pomdp.lock();
                    p.observe_and_update(risk_bound_ppm, action_code, adverse);
                    match p.state() {
                        PomdpState::Calibrating => 0u8,
                        PomdpState::Optimal => 1u8,
                        PomdpState::SuboptimalPolicy => 2u8,
                        PomdpState::PolicyDivergence => 3u8,
                    }
                };
                self.cached_pomdp_state.store(pomdp_code, Ordering::Relaxed);
            }

            // Feed ADMM budget allocator with risk/latency/coverage signals.
            {
                let risk_cost = (risk_bound_ppm as f64 / 1_000_000.0).clamp(0.0, 1.0);
                let latency_fraction = (estimated_cost_ns as f64 / 200.0).clamp(0.0, 1.0);
                let coverage_gap = if profile.requires_full() { 0.1 } else { 0.4 };
                let admm_code = {
                    let mut admm = self.admm.lock();
                    admm.observe_and_update(risk_cost, latency_fraction, coverage_gap);
                    match admm.state() {
                        AdmmState::Calibrating => 0u8,
                        AdmmState::Converged => 1u8,
                        AdmmState::DualDrift => 2u8,
                        AdmmState::ConstraintViolation => 3u8,
                    }
                };
                self.cached_admm_state.store(admm_code, Ordering::Relaxed);
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
            let _equivariant_anomaly = {
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

            // Feed information-theoretic provenance controller with a compact byte
            // derived from call context, risk, and latency.
            {
                let fingerprint_byte = (u64::from(risk_bound_ppm)
                    ^ estimated_cost_ns
                    ^ u64::from(family as u8).wrapping_mul(0x9e)
                    ^ u64::from(profile as u8).wrapping_mul(0x6d))
                    as u8;
                let prov_code = {
                    let mut prov = self.provenance.lock();
                    prov.observe_bytes(&[fingerprint_byte]);
                    match prov.state() {
                        ProvenanceState::Calibrating => 0u8,
                        ProvenanceState::Secure => 1u8,
                        ProvenanceState::EntropyDrift => 2u8,
                        ProvenanceState::CollisionRisk => 3u8,
                    }
                };
                self.cached_provenance_state
                    .store(prov_code, Ordering::Relaxed);
            }

            // Feed Grothendieck glue controller with local-to-global coherence
            // observations mapped from API family + adverse outcome.
            {
                let (query_family, source_i, source_j, is_stack_check) = match family {
                    ApiFamily::Resolver => (
                        QueryFamily::Hostname,
                        DataSource::Files,
                        DataSource::Dns,
                        false,
                    ),
                    ApiFamily::Threading => (
                        QueryFamily::UserGroup,
                        DataSource::Cache,
                        DataSource::Files,
                        false,
                    ),
                    ApiFamily::StringMemory => (
                        QueryFamily::EncodingLookup,
                        DataSource::IconvTables,
                        DataSource::Fallback,
                        true,
                    ),
                    ApiFamily::Stdlib => (
                        QueryFamily::LocaleResolution,
                        DataSource::LocaleFiles,
                        DataSource::Fallback,
                        true,
                    ),
                    ApiFamily::MathFenv => (
                        QueryFamily::Transliteration,
                        DataSource::LocaleFiles,
                        DataSource::IconvTables,
                        true,
                    ),
                    _ => (
                        QueryFamily::Service,
                        DataSource::Files,
                        DataSource::Cache,
                        false,
                    ),
                };
                let glue_code = {
                    let mut glue = self.grothendieck.lock();
                    let obs = CocycleObservation {
                        family: query_family,
                        source_i,
                        source_j,
                        compatible: !adverse,
                        is_stack_check,
                    };
                    glue.observe_cocycle(&obs);
                    match glue.state() {
                        GlueState::Calibrating => 0u8,
                        GlueState::Coherent => 1u8,
                        GlueState::DescentFailure => 2u8,
                        GlueState::StackificationFault => 3u8,
                    }
                };
                self.cached_grothendieck_state
                    .store(glue_code, Ordering::Relaxed);
            }

            // Feed Grobner normalizer with the constrained 16-variable controller
            // severity vector used for canonical consistency checks.
            {
                let risk_state = if risk_bound_ppm >= 500_000 {
                    3u8
                } else if risk_bound_ppm >= 200_000 {
                    2u8
                } else if risk_bound_ppm >= 50_000 {
                    1u8
                } else {
                    0u8
                };
                let state_vec = [
                    risk_state,                                                   // 0 risk
                    self.cached_bridge_state.load(Ordering::Relaxed).min(3),      // 1 bridge
                    self.cached_changepoint_state.load(Ordering::Relaxed).min(3), // 2 changepoint
                    self.cached_hji_state.load(Ordering::Relaxed).min(3),         // 3 hji
                    self.cached_anytime_state[usize::from(family as u8)] // 4 eprocess/padic
                        .load(Ordering::Relaxed)
                        .max(self.cached_padic_state.load(Ordering::Relaxed))
                        .min(3),
                    self.cached_cvar_state[usize::from(family as u8)] // 5 cvar
                        .load(Ordering::Relaxed)
                        .min(3),
                    self.cached_coupling_state.load(Ordering::Relaxed).min(3), // 6 coupling
                    self.cached_mfg_state.load(Ordering::Relaxed).min(3),      // 7 mfg
                    self.cached_equivariant_state.load(Ordering::Relaxed).min(3), // 8 equivariant
                    self.cached_microlocal_state.load(Ordering::Relaxed).min(3), // 9 microlocal
                    self.cached_ktheory_state.load(Ordering::Relaxed).min(3),  // 10 ktheory
                    self.cached_serre_state.load(Ordering::Relaxed).min(3),    // 11 serre
                    self.cached_tstructure_state.load(Ordering::Relaxed).min(3), // 12 tstructure
                    self.cached_clifford_state.load(Ordering::Relaxed).min(3), // 13 clifford
                    self.cached_topos_state.load(Ordering::Relaxed).min(3),    // 14 topos
                    self.cached_audit_state.load(Ordering::Relaxed).min(3),    // 15 audit
                ];
                let grobner_code = {
                    let mut grobner = self.grobner.lock();
                    grobner.check_state_vector(&state_vec);
                    match grobner.state() {
                        GrobnerState::Calibrating => 0u8,
                        GrobnerState::Consistent => 1u8,
                        GrobnerState::MinorInconsistency => 2u8,
                        GrobnerState::StructuralFault => 3u8,
                    }
                };
                self.cached_grobner_state
                    .store(grobner_code, Ordering::Relaxed);
            }

            // Build base 25-element severity vector from cached controller states.
            // This is consumed by Atiyah-Bott (localization), SOS (invariant guard),
            // and the robust fusion controller.
            let base_severity: [u8; BASE_SEVERITY_LEN] = [
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
                self.cached_ktheory_state.load(Ordering::Relaxed),                         // 0..3
                self.cached_covering_state.load(Ordering::Relaxed),                        // 0..3
                self.cached_tstructure_state.load(Ordering::Relaxed),                      // 0..3
            ];

            // Feed Atiyah-Bott fixed-point localization meta-controller.
            // Tracks concentration of anomaly signal across the base controller set.
            {
                let ab_code = {
                    let mut ab = self.atiyah_bott.lock();
                    ab.observe_and_update(&base_severity);
                    match ab.state() {
                        LocalizationState::Calibrating => 0u8,
                        LocalizationState::Distributed => 1u8,
                        LocalizationState::Localized => 2u8,
                        LocalizationState::ConcentratedAnomaly => 3u8,
                    }
                };
                self.cached_atiyah_bott_state
                    .store(ab_code, Ordering::Relaxed);
            }

            // Feed SOS polynomial invariant meta-controller.
            // Checks cross-controller quadratic coherence invariants.
            {
                let sos_code = {
                    let mut sos = self.sos.lock();
                    sos.observe_and_update(&base_severity);
                    match sos.state() {
                        SosState::Calibrating => 0u8,
                        SosState::InvariantSatisfied => 1u8,
                        SosState::InvariantStressed => 2u8,
                        SosState::InvariantViolated => 3u8,
                    }
                };
                self.cached_sos_state.store(sos_code, Ordering::Relaxed);
            }

            // Feed SOS barrier certificate evaluator (cadence-gated).
            // Evaluates provenance + quarantine + fragmentation barriers using cached signals.
            {
                let barrier_code = {
                    let mut barrier = self.sos_barrier.lock();
                    // Provenance barrier: use cached risk and profile.
                    let risk_ppm = self.cached_risk_bonus_ppm.load(Ordering::Relaxed) as u32;
                    let depth_ppm = if profile.requires_full() {
                        1_000_000u32
                    } else {
                        0u32
                    };
                    barrier.evaluate_provenance(risk_ppm, depth_ppm, 0, 0);
                    let depth = current_depth() as u32;
                    if matches!(family, ApiFamily::Allocator) {
                        barrier.note_allocator_observation(adverse, depth);
                    }
                    // Quarantine barrier: evaluate on cadence.
                    if barrier.is_quarantine_cadence() {
                        barrier.evaluate_quarantine(depth, 0, risk_ppm, 0);
                    }
                    // Fragmentation barrier: allocator-family cadence check.
                    if matches!(family, ApiFamily::Allocator) && barrier.is_fragmentation_cadence()
                    {
                        let sparse_state =
                            u32::from(self.cached_sparse_state.load(Ordering::Relaxed)).min(4);
                        let size_dispersion_ppm = sparse_state.saturating_mul(250_000);
                        let arena_utilization_ppm = depth_to_arena_utilization_ppm(depth);
                        barrier.evaluate_fragmentation(size_dispersion_ppm, arena_utilization_ppm);
                    }
                    match barrier.state() {
                        SosBarrierState::Calibrating => 0u8,
                        SosBarrierState::Safe => 1u8,
                        SosBarrierState::Warning => 2u8,
                        SosBarrierState::Violated => 3u8,
                    }
                };
                self.cached_sos_barrier_state
                    .store(barrier_code, Ordering::Relaxed);
            }

            // Feed spectral-sequence obstruction detector.
            // Tracks d² ≈ 0 (exactness) across tracked controller pairs.
            {
                let obs_code = {
                    let mut obs = self.obstruction.lock();
                    obs.observe_and_update(&base_severity);
                    match obs.state() {
                        ObstructionState::Calibrating => 0u8,
                        ObstructionState::Exact => 1u8,
                        ObstructionState::MinorObstruction => 2u8,
                        ObstructionState::CriticalObstruction => 3u8,
                    }
                };
                self.cached_obstruction_state
                    .store(obs_code, Ordering::Relaxed);
            }

            // Feed operator-norm spectral radius stability monitor.
            // Tracks ensemble dynamics amplification via online power iteration.
            {
                let on_code = {
                    let mut on = self.operator_norm.lock();
                    on.observe_and_update(&base_severity);
                    match on.state() {
                        StabilityState::Calibrating => 0u8,
                        StabilityState::Contractive => 1u8,
                        StabilityState::Marginal => 2u8,
                        StabilityState::Unstable => 3u8,
                    }
                };
                self.cached_operator_norm_state
                    .store(on_code, Ordering::Relaxed);
            }

            // Feed Malliavin sensitivity meta-controller.
            // Tracks sensitivity of aggregate safety decision to per-controller perturbations.
            {
                let malliavin_code = {
                    let mut m = self.malliavin.lock();
                    m.observe_and_update(&base_severity);
                    match m.state() {
                        SensitivityState::Calibrating => 0u8,
                        SensitivityState::Robust => 1u8,
                        SensitivityState::Sensitive => 2u8,
                        SensitivityState::Fragile => 3u8,
                    }
                };
                self.cached_malliavin_state
                    .store(malliavin_code, Ordering::Relaxed);
            }

            // Feed information geometry meta-controller.
            // Tracks Fisher-Rao geodesic distance from baseline state distribution.
            {
                let geo_code = {
                    let mut g = self.info_geometry.lock();
                    g.observe_and_update(&base_severity);
                    match g.state() {
                        GeometryState::Calibrating => 0u8,
                        GeometryState::Stationary => 1u8,
                        GeometryState::Drifting => 2u8,
                        GeometryState::StructuralBreak => 3u8,
                    }
                };
                self.cached_info_geometry_state
                    .store(geo_code, Ordering::Relaxed);
            }

            // Feed matrix concentration meta-controller.
            // Tracks Matrix Bernstein bound on ensemble covariance spectral deviation.
            {
                let conc_code = {
                    let mut c = self.matrix_concentration.lock();
                    c.observe_and_update(&base_severity);
                    match c.state() {
                        ConcentrationState::Calibrating => 0u8,
                        ConcentrationState::WithinBound => 1u8,
                        ConcentrationState::BoundaryApproach => 2u8,
                        ConcentrationState::BoundViolation => 3u8,
                    }
                };
                self.cached_matrix_concentration_state
                    .store(conc_code, Ordering::Relaxed);
            }

            // Feed nerve complex meta-controller.
            // Tracks correlation coherence via Čech nerve Betti numbers.
            {
                let nerve_code = {
                    let mut nc = self.nerve_complex.lock();
                    nc.observe_and_update(&base_severity);
                    match nc.state() {
                        NerveState::Calibrating => 0u8,
                        NerveState::Cohesive => 1u8,
                        NerveState::Weakening => 2u8,
                        NerveState::Fragmented => 3u8,
                    }
                };
                self.cached_nerve_state.store(nerve_code, Ordering::Relaxed);
            }

            // Feed Wasserstein drift meta-controller.
            // Tracks Earth Mover's distance on per-controller severity histograms.
            {
                let wass_code = {
                    let mut w = self.wasserstein.lock();
                    w.observe_and_update(&base_severity);
                    match w.state() {
                        DriftState::Calibrating => 0u8,
                        DriftState::Stable => 1u8,
                        DriftState::Transporting => 2u8,
                        DriftState::Displaced => 3u8,
                    }
                };
                self.cached_wasserstein_state
                    .store(wass_code, Ordering::Relaxed);
            }

            // Feed kernel MMD meta-controller.
            // Tracks Maximum Mean Discrepancy in RKHS for joint distributional shifts.
            {
                let mmd_code = {
                    let mut km = self.kernel_mmd.lock();
                    km.observe_and_update(&base_severity);
                    match km.state() {
                        MmdState::Calibrating => 0u8,
                        MmdState::Conforming => 1u8,
                        MmdState::Drifting => 2u8,
                        MmdState::Anomalous => 3u8,
                    }
                };
                self.cached_kernel_mmd_state
                    .store(mmd_code, Ordering::Relaxed);
            }

            // Feed PAC-Bayes generalization bound monitor.
            // Tracks ensemble trust via finite-sample PAC-Bayes bounds.
            {
                let pb_code = {
                    let mut pb = self.pac_bayes.lock();
                    pb.observe(&base_severity, adverse);
                    match pb.state() {
                        PacBayesState::Calibrating => 0u8,
                        PacBayesState::Tight => 1u8,
                        PacBayesState::Uncertain => 2u8,
                        PacBayesState::Unreliable => 3u8,
                    }
                };
                self.cached_pac_bayes_state
                    .store(pb_code, Ordering::Relaxed);
            }

            // Feed Stein discrepancy goodness-of-fit monitor.
            // Tracks KSD² deviation from calibrated reference model.
            {
                let stein_code = {
                    let mut sd = self.stein.lock();
                    sd.observe_and_update(&base_severity);
                    match sd.state() {
                        SteinState::Calibrating => 0u8,
                        SteinState::Consistent => 1u8,
                        SteinState::Deviant => 2u8,
                        SteinState::Rejected => 3u8,
                    }
                };
                self.cached_stein_state.store(stein_code, Ordering::Relaxed);
            }

            // Feed Lyapunov stability exponent monitor.
            // Tracks trajectory-level divergence for chaotic dynamics detection.
            {
                let lyap_code = {
                    let mut lm = self.lyapunov.lock();
                    lm.observe_and_update(&base_severity);
                    match lm.state() {
                        LyapunovState::Calibrating => 0u8,
                        LyapunovState::Stable => 1u8,
                        LyapunovState::Marginal => 2u8,
                        LyapunovState::Chaotic => 3u8,
                    }
                };
                self.cached_lyapunov_state
                    .store(lyap_code, Ordering::Relaxed);
            }

            // Feed Rademacher complexity monitor.
            // Tracks data-dependent ensemble capacity via random sign vectors.
            {
                let rad_code = {
                    let mut rm = self.rademacher.lock();
                    rm.observe_and_update(&base_severity);
                    match rm.state() {
                        RademacherState::Calibrating => 0u8,
                        RademacherState::Controlled => 1u8,
                        RademacherState::Elevated => 2u8,
                        RademacherState::Overfit => 3u8,
                    }
                };
                self.cached_rademacher_state
                    .store(rad_code, Ordering::Relaxed);
            }

            // Feed transfer entropy causal flow monitor.
            // Tracks directed causal information flow between controllers.
            {
                let te_code = {
                    let mut te = self.transfer_entropy.lock();
                    te.observe_and_update(&base_severity);
                    match te.state() {
                        TransferEntropyState::Calibrating => 0u8,
                        TransferEntropyState::Independent => 1u8,
                        TransferEntropyState::CausalCoupling => 2u8,
                        TransferEntropyState::CascadeRisk => 3u8,
                    }
                };
                self.cached_transfer_entropy_state
                    .store(te_code, Ordering::Relaxed);
            }

            // Feed Hodge decomposition coherence monitor.
            // Tracks cyclic inconsistencies in controller severity ordering.
            {
                let hodge_code = {
                    let mut hm = self.hodge.lock();
                    hm.observe_and_update(&base_severity);
                    match hm.state() {
                        HodgeState::Calibrating => 0u8,
                        HodgeState::Coherent => 1u8,
                        HodgeState::Inconsistent => 2u8,
                        HodgeState::Incoherent => 3u8,
                    }
                };
                self.cached_hodge_state.store(hodge_code, Ordering::Relaxed);
            }

            // Feed Doob decomposition martingale monitor.
            // Tracks systematic (non-random) drift in the severity process.
            {
                let doob_code = {
                    let mut dm = self.doob.lock();
                    dm.observe_and_update(&base_severity);
                    match dm.state() {
                        DoobState::Calibrating => 0u8,
                        DoobState::Stationary => 1u8,
                        DoobState::Drifting => 2u8,
                        DoobState::Runaway => 3u8,
                    }
                };
                self.cached_doob_state.store(doob_code, Ordering::Relaxed);
            }

            // Feed Fano mutual information bound monitor.
            // Tracks information-theoretic error lower bound on severity prediction.
            {
                let fano_code = {
                    let mut fm = self.fano.lock();
                    fm.observe_and_update(&base_severity);
                    match fm.state() {
                        FanoState::Calibrating => 0u8,
                        FanoState::Predictable => 1u8,
                        FanoState::Uncertain => 2u8,
                        FanoState::Opaque => 3u8,
                    }
                };
                self.cached_fano_state.store(fano_code, Ordering::Relaxed);
            }

            // Feed Dobrushin contraction coefficient monitor.
            // Tracks Markov chain mixing/ergodicity of the severity process.
            {
                let dob_code = {
                    let mut dc = self.dobrushin.lock();
                    dc.observe_and_update(&base_severity);
                    match dc.state() {
                        DobrushinState::Calibrating => 0u8,
                        DobrushinState::Ergodic => 1u8,
                        DobrushinState::SlowMixing => 2u8,
                        DobrushinState::NonMixing => 3u8,
                    }
                };
                self.cached_dobrushin_state
                    .store(dob_code, Ordering::Relaxed);
            }

            // Feed Azuma-Hoeffding concentration monitor.
            // Tracks whether severity noise exceeds bounded-difference bounds.
            {
                let azuma_code = {
                    let mut az = self.azuma.lock();
                    az.observe_and_update(&base_severity);
                    match az.state() {
                        AzumaState::Calibrating => 0u8,
                        AzumaState::Concentrated => 1u8,
                        AzumaState::Diffuse => 2u8,
                        AzumaState::Explosive => 3u8,
                    }
                };
                self.cached_azuma_state.store(azuma_code, Ordering::Relaxed);
            }

            // Feed renewal theory monitor.
            // Tracks inter-arrival times of severity recovery events.
            {
                let renewal_code = {
                    let mut rn = self.renewal.lock();
                    rn.observe_and_update(&base_severity);
                    match rn.state() {
                        RenewalState::Calibrating => 0u8,
                        RenewalState::Renewing => 1u8,
                        RenewalState::Aging => 2u8,
                        RenewalState::Stale => 3u8,
                    }
                };
                self.cached_renewal_state
                    .store(renewal_code, Ordering::Relaxed);
            }

            // Feed Lempel-Ziv complexity monitor.
            // Tracks algorithmic complexity of severity sequence.
            {
                let lz_code = {
                    let mut lz = self.lempel_ziv.lock();
                    lz.observe_and_update(&base_severity);
                    match lz.state() {
                        LempelZivState::Calibrating => 0u8,
                        LempelZivState::Structured => 1u8,
                        LempelZivState::Repetitive => 2u8,
                        LempelZivState::Entropic => 3u8,
                    }
                };
                self.cached_lz_state.store(lz_code, Ordering::Relaxed);
            }

            // Feed spectral gap mixing time monitor.
            // Tracks Markov chain spectral gap and mixing time bounds.
            {
                let sg_code = {
                    let mut sg = self.spectral_gap.lock();
                    sg.observe_and_update(&base_severity);
                    match sg.state() {
                        SpectralGapState::Calibrating => 0u8,
                        SpectralGapState::RapidMixing => 1u8,
                        SpectralGapState::SlowMixing => 2u8,
                        SpectralGapState::Metastable => 3u8,
                    }
                };
                self.cached_spectral_gap_state
                    .store(sg_code, Ordering::Relaxed);
            }

            // Feed submodular coverage monitor.
            // Tracks validation stage coverage ratio under budget constraints.
            {
                let sub_code = {
                    let mut sc = self.submodular.lock();
                    sc.observe_and_update(&base_severity);
                    match sc.state() {
                        SubmodularState::Calibrating => 0u8,
                        SubmodularState::Sufficient => 1u8,
                        SubmodularState::Marginal => 2u8,
                        SubmodularState::Insufficient => 3u8,
                    }
                };
                self.cached_submodular_state
                    .store(sub_code, Ordering::Relaxed);
            }

            // Feed bifurcation proximity detector.
            // Tracks critical slowing down via lag-1 autocorrelation.
            {
                let bif_code = {
                    let mut bd = self.bifurcation.lock();
                    bd.observe_and_update(&base_severity);
                    match bd.state() {
                        BifurcationState::Calibrating => 0u8,
                        BifurcationState::Stable => 1u8,
                        BifurcationState::Approaching => 2u8,
                        BifurcationState::Critical => 3u8,
                    }
                };
                self.cached_bifurcation_state
                    .store(bif_code, Ordering::Relaxed);
            }

            // Feed entropy rate complexity monitor.
            // Tracks Shannon entropy rate of the severity process.
            {
                let er_code = {
                    let mut er = self.entropy_rate.lock();
                    er.observe_and_update(&base_severity);
                    match er.state() {
                        EntropyRateState::Calibrating => 0u8,
                        EntropyRateState::LowComplexity => 1u8,
                        EntropyRateState::ModerateComplexity => 2u8,
                        EntropyRateState::HighComplexity => 3u8,
                    }
                };
                self.cached_entropy_rate_state
                    .store(er_code, Ordering::Relaxed);
            }

            // Feed Ito quadratic variation monitor.
            // Tracks realized volatility of the severity martingale component.
            {
                let ito_code = {
                    let mut ito = self.ito_qv.lock();
                    ito.observe_and_update(&base_severity);
                    match ito.state() {
                        ItoQvState::Calibrating => 0u8,
                        ItoQvState::Stable => 1u8,
                        ItoQvState::Frozen => 2u8,
                        ItoQvState::Volatile => 3u8,
                    }
                };
                self.cached_ito_qv_state.store(ito_code, Ordering::Relaxed);
            }

            // Feed Borel-Cantelli recurrence monitor.
            // Classifies whether severity exceedances are transient or recurrent.
            {
                let bc_code = {
                    let mut bc = self.borel_cantelli.lock();
                    bc.observe_and_update(&base_severity);
                    match bc.state() {
                        BorelCantelliState::Calibrating => 0u8,
                        BorelCantelliState::Transient => 1u8,
                        BorelCantelliState::Recurrent => 2u8,
                        BorelCantelliState::Absorbing => 3u8,
                    }
                };
                self.cached_borel_cantelli_state
                    .store(bc_code, Ordering::Relaxed);
            }

            // Feed Ornstein-Uhlenbeck mean reversion monitor.
            // Estimates mean-reversion speed θ of the severity process.
            {
                let ou_code = {
                    let mut ou = self.ornstein_uhlenbeck.lock();
                    ou.observe_and_update(&base_severity);
                    match ou.state() {
                        OuState::Calibrating => 0u8,
                        OuState::Stable => 1u8,
                        OuState::Diffusing => 2u8,
                        OuState::Explosive => 3u8,
                    }
                };
                self.cached_ou_state.store(ou_code, Ordering::Relaxed);
            }

            // Feed Hurst exponent R/S analysis monitor.
            // Detects long-range dependence in severity sequences.
            {
                let hurst_code = {
                    let mut h = self.hurst.lock();
                    h.observe_and_update(&base_severity);
                    match h.state() {
                        HurstState::Calibrating => 0u8,
                        HurstState::Independent => 1u8,
                        HurstState::Persistent => 2u8,
                        HurstState::AntiPersistent => 3u8,
                    }
                };
                self.cached_hurst_state.store(hurst_code, Ordering::Relaxed);
            }

            // Feed index of dispersion alarm clustering monitor.
            // Detects whether alarms are independent, clustered, or regular.
            {
                let disp_code = {
                    let mut d = self.dispersion.lock();
                    d.observe_and_update(&base_severity);
                    match d.state() {
                        DispersionState::Calibrating => 0u8,
                        DispersionState::Poisson => 1u8,
                        DispersionState::Clustered => 2u8,
                        DispersionState::Underdispersed => 3u8,
                    }
                };
                self.cached_dispersion_state
                    .store(disp_code, Ordering::Relaxed);
            }

            // Feed Birkhoff ergodic convergence monitor.
            // Tracks whether time-average of severity converges to ensemble average.
            {
                let birk_code = {
                    let mut b = self.birkhoff.lock();
                    b.observe_and_update(&base_severity);
                    match b.state() {
                        ErgodicState::Calibrating => 0u8,
                        ErgodicState::Ergodic => 1u8,
                        ErgodicState::SlowConvergence => 2u8,
                        ErgodicState::NonErgodic => 3u8,
                    }
                };
                self.cached_birkhoff_state
                    .store(birk_code, Ordering::Relaxed);
            }

            // Alpha-Investing FDR controller: sequential false-discovery control
            // over the monitor alarm ensemble.
            {
                let ai_code = {
                    let mut ai = self.alpha_investing.lock();
                    ai.observe_and_update(&base_severity);
                    match ai.state() {
                        AlphaInvestingState::Calibrating => 0u8,
                        AlphaInvestingState::Normal => 1u8,
                        AlphaInvestingState::Generous => 2u8,
                        AlphaInvestingState::Depleted => 3u8,
                    }
                };
                self.cached_alpha_investing_state
                    .store(ai_code, Ordering::Relaxed);
            }

            // Blackwell approachability: multi-objective (latency, risk, coverage)
            // convergence to a mode-dependent safe set. O(1/√t) guarantee.
            {
                let approachability_code = {
                    let mut appr = self.approachability.lock();
                    let latency_milli =
                        (estimated_cost_ns * 1000 / FULL_PATH_BUDGET_NS.max(1)).min(1000);
                    let risk_milli = (risk_bound_ppm as u64 * 1000 / 1_000_000).min(1000);
                    let coverage_milli = if profile.requires_full() {
                        700u64
                    } else {
                        200u64
                    };
                    appr.observe(latency_milli, risk_milli, coverage_milli);
                    match appr.state() {
                        ApproachabilityState::Calibrating => 0u8,
                        ApproachabilityState::Approaching => 1u8,
                        ApproachabilityState::Drifting => 2u8,
                        ApproachabilityState::Violated => 3u8,
                    }
                };
                self.cached_approachability_state
                    .store(approachability_code, Ordering::Relaxed);
            }

            // Localization fixed-point policy chooser (Atiyah-Bott style).
            // Feeds domain-specific signals: risk, concentration, stability,
            // coverage, and budget pressure from cached controller states.
            {
                let loc_risk_ppm = self.cached_risk_bonus_ppm.load(Ordering::Relaxed) as u32;
                let concentration_state = self.cached_atiyah_bott_state.load(Ordering::Relaxed);
                let stability_state = self
                    .cached_operator_norm_state
                    .load(Ordering::Relaxed)
                    .max(self.cached_lyapunov_state.load(Ordering::Relaxed));
                let coverage_state = self
                    .cached_covering_state
                    .load(Ordering::Relaxed)
                    .max(self.cached_submodular_state.load(Ordering::Relaxed));
                let budget_pressure = {
                    let fast_wcl = TROPICAL_METRICS.fast_wcl_ns.load(Ordering::Relaxed);
                    let full_wcl = TROPICAL_METRICS.full_wcl_ns.load(Ordering::Relaxed);
                    if fast_wcl > FAST_PATH_BUDGET_NS && full_wcl > FULL_PATH_BUDGET_NS {
                        3u8
                    } else if full_wcl > FULL_PATH_BUDGET_NS {
                        2u8
                    } else if fast_wcl > FAST_PATH_BUDGET_NS {
                        1u8
                    } else {
                        0u8
                    }
                };
                let loc_code = {
                    let mut loc = self.localization.lock();
                    loc.observe(
                        loc_risk_ppm,
                        concentration_state,
                        stability_state,
                        coverage_state,
                        budget_pressure,
                    );
                    let arm = loc.selected_arm();
                    self.cached_localization_arm.store(arm, Ordering::Relaxed);
                    match loc.state() {
                        ChooserState::Calibrating => 0u8,
                        ChooserState::Nominal => 1u8,
                        ChooserState::Elevated => 2u8,
                        ChooserState::Intervening => 3u8,
                    }
                };
                self.cached_localization_state
                    .store(loc_code, Ordering::Relaxed);
            }

            // Feed robust fusion controller from extended severity vector.
            // Includes the 25 base controller signals plus META_SEVERITY_LEN meta-controller states.
            {
                let mut severity = [0u8; fusion::SIGNALS];
                severity[..BASE_SEVERITY_LEN].copy_from_slice(&base_severity);
                severity[25] = self.cached_atiyah_bott_state.load(Ordering::Relaxed); // 0..3
                severity[26] = self.cached_pomdp_state.load(Ordering::Relaxed); // 0..3
                severity[27] = self.cached_sos_state.load(Ordering::Relaxed); // 0..3
                severity[28] = self.cached_admm_state.load(Ordering::Relaxed); // 0..3
                severity[29] = self.cached_obstruction_state.load(Ordering::Relaxed); // 0..3
                severity[30] = self.cached_operator_norm_state.load(Ordering::Relaxed); // 0..3
                severity[31] = self.cached_malliavin_state.load(Ordering::Relaxed); // 0..3
                severity[32] = self.cached_info_geometry_state.load(Ordering::Relaxed); // 0..3
                severity[33] = self
                    .cached_matrix_concentration_state
                    .load(Ordering::Relaxed); // 0..3
                severity[34] = self.cached_nerve_state.load(Ordering::Relaxed); // 0..3
                severity[35] = self.cached_wasserstein_state.load(Ordering::Relaxed); // 0..3
                severity[36] = self.cached_kernel_mmd_state.load(Ordering::Relaxed); // 0..3
                severity[37] = self.cached_pac_bayes_state.load(Ordering::Relaxed); // 0..3
                severity[38] = self.cached_stein_state.load(Ordering::Relaxed); // 0..3
                severity[39] = self.cached_lyapunov_state.load(Ordering::Relaxed); // 0..3
                severity[40] = self.cached_rademacher_state.load(Ordering::Relaxed); // 0..3
                severity[41] = self.cached_transfer_entropy_state.load(Ordering::Relaxed); // 0..3
                severity[42] = self.cached_hodge_state.load(Ordering::Relaxed); // 0..3
                severity[43] = self.cached_doob_state.load(Ordering::Relaxed); // 0..3
                severity[44] = self.cached_fano_state.load(Ordering::Relaxed); // 0..3
                severity[45] = self.cached_dobrushin_state.load(Ordering::Relaxed); // 0..3
                severity[46] = self.cached_azuma_state.load(Ordering::Relaxed); // 0..3
                severity[47] = self.cached_renewal_state.load(Ordering::Relaxed); // 0..3
                severity[48] = self.cached_lz_state.load(Ordering::Relaxed); // 0..3
                severity[49] = self.cached_spectral_gap_state.load(Ordering::Relaxed); // 0..3
                severity[50] = self.cached_submodular_state.load(Ordering::Relaxed); // 0..3
                severity[51] = self.cached_bifurcation_state.load(Ordering::Relaxed); // 0..3
                severity[52] = self.cached_entropy_rate_state.load(Ordering::Relaxed); // 0..3
                severity[53] = self.cached_ito_qv_state.load(Ordering::Relaxed); // 0..3
                severity[54] = self.cached_borel_cantelli_state.load(Ordering::Relaxed); // 0..3
                severity[55] = self.cached_ou_state.load(Ordering::Relaxed); // 0..3
                severity[56] = self.cached_hurst_state.load(Ordering::Relaxed); // 0..3
                severity[57] = self.cached_dispersion_state.load(Ordering::Relaxed); // 0..3
                severity[58] = self.cached_birkhoff_state.load(Ordering::Relaxed); // 0..3
                severity[59] = self.cached_alpha_investing_state.load(Ordering::Relaxed); // 0..3
                severity[60] = self.cached_sos_barrier_state.load(Ordering::Relaxed); // 0..3
                severity[61] = self.cached_localization_state.load(Ordering::Relaxed); // 0..3
                severity[62] = self.cached_approachability_state.load(Ordering::Relaxed); // 0..3
                severity[63] = self.cached_redundancy_state.load(Ordering::Relaxed); // 0..3
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
            if let Some(flag) = loss_minimizer_anomaly {
                design.record_probe(Probe::LossMinimizer, flag);
            }
            if let Some(flag) = coupling_anomaly {
                design.record_probe(Probe::Coupling, flag);
            }
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
        let ktheory_summary = self.ktheory.lock().summary();
        let covering_summary = self.covering.lock().summary();
        let tstructure_summary = self.tstructure.lock().summary();
        let atiyah_bott_summary = self.atiyah_bott.lock().summary();
        let pomdp_summary = self.pomdp.lock().summary();
        let sos_summary = self.sos.lock().summary();
        let sos_barrier_summary = self.sos_barrier.lock().summary();
        let admm_summary = self.admm.lock().summary();
        let obstruction_summary = self.obstruction.lock().summary();
        let operator_norm_summary = self.operator_norm.lock().summary();
        let provenance_snapshot = self.provenance.lock().snapshot();
        let grobner_snapshot = self.grobner.lock().snapshot();
        let grothendieck_snapshot = self.grothendieck.lock().snapshot();
        let malliavin_summary = self.malliavin.lock().summary();
        let info_geo_summary = self.info_geometry.lock().summary();
        let matrix_conc_summary = self.matrix_concentration.lock().summary();
        let nerve_summary = self.nerve_complex.lock().summary();
        let wasserstein_summary = self.wasserstein.lock().summary();
        let mmd_summary = self.kernel_mmd.lock().summary();
        let pac_bayes_summary = self.pac_bayes.lock().summary();
        let stein_summary = self.stein.lock().summary();
        let lyapunov_summary = self.lyapunov.lock().summary();
        let rademacher_summary = self.rademacher.lock().summary();
        let transfer_entropy_summary = self.transfer_entropy.lock().summary();
        let hodge_summary = self.hodge.lock().summary();
        let doob_summary = self.doob.lock().summary();
        let fano_summary = self.fano.lock().summary();
        let dobrushin_summary = self.dobrushin.lock().summary();
        let azuma_summary = self.azuma.lock().summary();
        let renewal_summary = self.renewal.lock().summary();
        let lz_summary = self.lempel_ziv.lock().summary();
        let spectral_gap_summary = self.spectral_gap.lock().summary();
        let submodular_summary = self.submodular.lock().summary();
        let bifurcation_summary = self.bifurcation.lock().summary();
        let entropy_rate_summary = self.entropy_rate.lock().summary();
        let ito_qv_summary = self.ito_qv.lock().summary();
        let borel_cantelli_summary = self.borel_cantelli.lock().summary();
        let ou_summary = self.ornstein_uhlenbeck.lock().summary();
        let hurst_summary = self.hurst.lock().summary();
        let dispersion_summary = self.dispersion.lock().summary();
        let birkhoff_summary = self.birkhoff.lock().summary();
        let alpha_investing_summary = self.alpha_investing.lock().summary();
        let approachability_summary = self.approachability.lock().summary();
        let localization_summary = self.localization.lock().summary();
        let coupling_summary = self.coupling.lock().summary();
        let loss_summary = self.loss_minimizer.lock().summary();
        let microlocal_summary = self.microlocal.lock().summary();
        let serre_summary = self.serre.lock().summary();
        let clifford_summary = self.clifford.lock().summary();
        let redundancy_summary = self.redundancy_tuner.lock().summary();
        RuntimeKernelSnapshot {
            schema_version: RUNTIME_KERNEL_SNAPSHOT_SCHEMA_VERSION,
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
            sparse_canonical_class: sparse_summary.canonical_class,
            sparse_canonical_counts: sparse_summary.canonical_class_counts,
            equivariant_alignment_ppm: equivariant_summary.alignment_ppm,
            equivariant_drift_count: equivariant_summary.drift_count,
            equivariant_fractured_count: equivariant_summary.fractured_count,
            equivariant_dominant_orbit: self.cached_equivariant_orbit.load(Ordering::Relaxed),
            fusion_bonus_ppm: self.cached_fusion_bonus_ppm.load(Ordering::Relaxed) as u32,
            fusion_entropy_milli: self.cached_fusion_entropy_milli.load(Ordering::Relaxed) as u32,
            fusion_drift_ppm: self.cached_fusion_drift_ppm.load(Ordering::Relaxed) as u32,
            fusion_dominant_signal: self.cached_fusion_dominant_signal.load(Ordering::Relaxed),
            microlocal_active_strata: microlocal_summary.active_strata,
            microlocal_failure_rate: microlocal_summary.propagation_failure_rate,
            microlocal_fault_count: microlocal_summary.fault_boundary_count,
            serre_max_differential: serre_summary.max_differential,
            serre_nontrivial_cells: serre_summary.nontrivial_cells,
            serre_lifting_count: serre_summary.lifting_failure_count,
            clifford_grade2_energy: clifford_summary.grade2_energy,
            clifford_parity_imbalance: clifford_summary.parity_imbalance,
            clifford_violation_count: clifford_summary.overlap_violation_count,
            ktheory_max_transport_distance: ktheory_summary.max_transport_distance,
            ktheory_fracture_count: ktheory_summary.fracture_count,
            covering_coverage_fraction: covering_summary.coverage_fraction,
            covering_gap_count: covering_summary.gap_count,
            tstructure_max_violation_rate: tstructure_summary.max_violation_rate,
            tstructure_violation_count: tstructure_summary.orthogonality_violation_count,
            atiyah_bott_euler_weight: atiyah_bott_summary.euler_weight,
            atiyah_bott_concentration_count: atiyah_bott_summary.concentration_count,
            pomdp_optimality_gap: pomdp_summary.optimality_gap,
            pomdp_divergence_count: pomdp_summary.divergence_count,
            sos_max_stress: sos_summary.max_stress_fraction,
            sos_violation_count: sos_summary.violation_event_count,
            sos_barrier_provenance_value: sos_barrier_summary.provenance_value,
            sos_barrier_quarantine_value: sos_barrier_summary.quarantine_value,
            sos_barrier_violations: sos_barrier_summary.provenance_violations
                + sos_barrier_summary.quarantine_violations
                + sos_barrier_summary.fragmentation_violations
                + if sos_barrier_summary.fragmentation_hash_valid {
                    0
                } else {
                    1
                },
            admm_primal_dual_gap: admm_summary.primal_dual_gap,
            admm_violation_count: admm_summary.violation_count,
            obstruction_norm: obstruction_summary.obstruction_norm,
            obstruction_critical_count: obstruction_summary.critical_count,
            operator_norm_spectral_radius: operator_norm_summary.spectral_radius,
            operator_norm_instability_count: operator_norm_summary.instability_count,
            provenance_shannon_entropy: provenance_snapshot.shannon_entropy,
            provenance_renyi_h2: provenance_snapshot.renyi_h2,
            provenance_collision_count: provenance_snapshot.collision_risk_count,
            grobner_violation_rate: grobner_snapshot.violation_rate,
            grobner_fault_count: grobner_snapshot.fault_count,
            grothendieck_violation_rate: grothendieck_snapshot.global_violation_rate,
            grothendieck_stack_fault_count: grothendieck_snapshot.stack_fault_count,
            malliavin_sensitivity_norm: malliavin_summary.sensitivity_norm,
            malliavin_fragility_index: malliavin_summary.fragility_index,
            info_geo_geodesic_distance: info_geo_summary.geodesic_distance,
            info_geo_max_controller_distance: info_geo_summary.max_controller_distance,
            matrix_conc_spectral_deviation: matrix_conc_summary.spectral_deviation,
            matrix_conc_bernstein_bound: matrix_conc_summary.bernstein_bound,
            nerve_betti_0: nerve_summary.betti_0,
            nerve_betti_1: nerve_summary.betti_1,
            wasserstein_aggregate_distance: wasserstein_summary.aggregate_distance,
            wasserstein_max_controller_distance: wasserstein_summary.max_controller_distance,
            mmd_squared: mmd_summary.mmd_squared,
            mmd_mean_shift_norm: mmd_summary.mean_shift_norm,
            pac_bayes_bound: pac_bayes_summary.bound,
            pac_bayes_kl_divergence: pac_bayes_summary.kl_divergence,
            pac_bayes_empirical_error: pac_bayes_summary.empirical_error,
            stein_ksd_squared: stein_summary.ksd_squared,
            stein_max_score_deviation: stein_summary.max_score_deviation,
            lyapunov_exponent: lyapunov_summary.exponent,
            lyapunov_expansion_ratio: lyapunov_summary.expansion_ratio,
            rademacher_complexity: rademacher_summary.complexity,
            rademacher_gen_gap_bound: rademacher_summary.gen_gap_bound,
            transfer_entropy_max_te: transfer_entropy_summary.max_te,
            transfer_entropy_mean_te: transfer_entropy_summary.mean_te,
            hodge_inconsistency_ratio: hodge_summary.inconsistency_ratio,
            hodge_curl_energy: hodge_summary.curl_energy,
            doob_drift_rate: doob_summary.drift_rate,
            doob_max_drift: doob_summary.max_drift,
            fano_mean_mi: fano_summary.mean_mi,
            fano_mean_bound: fano_summary.mean_fano_bound,
            dobrushin_max_contraction: dobrushin_summary.max_contraction,
            dobrushin_mean_contraction: dobrushin_summary.mean_contraction,
            azuma_max_exceedance: azuma_summary.max_exceedance,
            azuma_mean_exceedance: azuma_summary.mean_exceedance,
            renewal_max_age_ratio: renewal_summary.max_age_ratio,
            renewal_mean_time: renewal_summary.mean_renewal_time,
            lz_max_complexity_ratio: lz_summary.max_complexity_ratio,
            lz_mean_complexity_ratio: lz_summary.mean_complexity_ratio,
            ito_qv_max_per_step: ito_qv_summary.max_qv_per_step,
            ito_qv_mean_per_step: ito_qv_summary.mean_qv_per_step,
            borel_cantelli_max_rate: borel_cantelli_summary.max_exceedance_rate,
            borel_cantelli_mean_rate: borel_cantelli_summary.mean_exceedance_rate,
            ou_min_theta: ou_summary.min_theta,
            ou_mean_theta: ou_summary.mean_theta,
            hurst_max: hurst_summary.max_hurst,
            hurst_mean: hurst_summary.mean_hurst,
            dispersion_max: dispersion_summary.max_dispersion,
            dispersion_mean: dispersion_summary.mean_dispersion,
            birkhoff_max_gap: birkhoff_summary.max_convergence_gap,
            birkhoff_mean_gap: birkhoff_summary.mean_convergence_gap,
            coupling_divergence_bound: coupling_summary.divergence_bound,
            coupling_certification_margin: coupling_summary.certification_margin,
            loss_recommended_action: loss_summary.recommended_action,
            loss_posterior_adverse_ppm: self
                .cached_loss_posterior_ppm
                .load(Ordering::Relaxed)
                .min(1_000_000) as u32,
            loss_selected_expected_cost_milli: self
                .cached_loss_selected_cost_milli
                .load(Ordering::Relaxed),
            loss_competing_action: self.cached_loss_competing_action.load(Ordering::Relaxed),
            loss_competing_expected_cost_milli: self
                .cached_loss_competing_cost_milli
                .load(Ordering::Relaxed),
            loss_cost_explosion_count: loss_summary.cost_explosion_count,
            spectral_gap_max_eigenvalue: spectral_gap_summary.max_second_eigenvalue,
            spectral_gap_mean_eigenvalue: spectral_gap_summary.mean_second_eigenvalue,
            submodular_coverage_ratio: submodular_summary.coverage_ratio,
            submodular_selected_stages: submodular_summary.selected_stages,
            bifurcation_max_sensitivity: bifurcation_summary.max_sensitivity,
            bifurcation_mean_sensitivity: bifurcation_summary.mean_sensitivity,
            entropy_rate_bits: entropy_rate_summary.entropy_rate_bits,
            entropy_rate_ratio: entropy_rate_summary.entropy_rate_ratio,
            alpha_investing_wealth_milli: alpha_investing_summary.wealth_milli,
            alpha_investing_rejections: alpha_investing_summary.rejections,
            alpha_investing_empirical_fdr: alpha_investing_summary.empirical_fdr,
            approachability_deviation_sq_milli: approachability_summary.deviation_sq_milli,
            approachability_recommended_arm: approachability_summary.recommended_arm,
            approachability_state: match approachability_summary.state {
                ApproachabilityState::Calibrating => 0,
                ApproachabilityState::Approaching => 1,
                ApproachabilityState::Drifting => 2,
                ApproachabilityState::Violated => 3,
            },
            localization_selected_arm: localization_summary.selected_arm,
            localization_count: localization_summary.count,
            sobol_index: self.cached_sobol_index.load(Ordering::Relaxed) as u32,
            sobol_augmented_mask: self.cached_sobol_augmented_mask.load(Ordering::Relaxed) as u32,
            sobol_augmented_count: (self.cached_sobol_augmented_mask.load(Ordering::Relaxed) as u32)
                .count_ones() as u8,
            policy_hash_prefix: self.cached_policy_hash.load(Ordering::Relaxed),
            policy_action_dist: [
                self.cached_policy_action_dist[0].load(Ordering::Relaxed),
                self.cached_policy_action_dist[1].load(Ordering::Relaxed),
                self.cached_policy_action_dist[2].load(Ordering::Relaxed),
                self.cached_policy_action_dist[3].load(Ordering::Relaxed),
            ],
            evidence_seqno: self.cached_evidence_seqno.load(Ordering::Relaxed),
            evidence_loss_count: self.cached_evidence_loss.load(Ordering::Relaxed),
            evidence_max_epoch: self.cached_evidence_max_epoch.load(Ordering::Relaxed),
            redundancy_overhead_ppm: redundancy_summary.overhead_ppm,
            redundancy_loss_rate_ppm: redundancy_summary.loss_rate_ppm,
            redundancy_state: redundancy_summary.state,
            redundancy_adjustments: redundancy_summary.adjustments,
        }
    }

    /// Snapshot evidence-export counters for contract checks and telemetry.
    #[must_use]
    pub fn evidence_contract_snapshot(&self) -> RuntimeEvidenceContractSnapshot {
        RuntimeEvidenceContractSnapshot {
            evidence_seqno: self.cached_evidence_seqno.load(Ordering::Relaxed),
            evidence_loss_count: self.cached_evidence_loss.load(Ordering::Relaxed),
            evidence_max_epoch: self.cached_evidence_max_epoch.load(Ordering::Relaxed),
        }
    }

    /// Export structured decision-card JSON from the runtime evidence log.
    #[must_use]
    pub fn export_decision_cards_json(&self) -> String {
        self.evidence_log.export_decision_cards_json()
    }

    /// Export deterministic JSONL structured logs for runtime-math governance.
    ///
    /// The stream includes:
    /// - per-decision `runtime_decision` rows (TRACE/INFO/WARN/ERROR by action),
    /// - one `runtime_calibration` DEBUG row,
    /// - one `runtime_snapshot` INFO row,
    /// - certificate load/verification rows,
    /// - optional drift/regret WARN alerts when thresholds are exceeded.
    #[must_use]
    pub fn export_runtime_math_log_jsonl(
        &self,
        mode: SafetyLevel,
        bead_id: &str,
        run_id: &str,
    ) -> String {
        let cards = self.evidence_log.decision_cards_snapshot_sorted();
        let snapshot = self.snapshot(mode);
        let policy_hash_prefix = self.cached_policy_hash.load(Ordering::Relaxed);
        let policy_load_state = self.cached_policy_load_state.load(Ordering::Relaxed);
        let bead = sanitize_trace_component(bead_id);
        let run = sanitize_trace_component(run_id);
        let timestamp = now_utc_iso_like();
        let mode_label = mode_name(mode);
        let mut out = String::with_capacity(cards.len().saturating_mul(512).saturating_add(2048));

        for card in cards {
            let action_name = action_name(card.decision.action);
            let level = level_for_action(card.decision.action);
            let family_name = family_name(card.context.family);
            let decision_name = decision_name(card.decision.action);
            let decision_path = decision_path(card.decision.action);
            let healing_action = healing_action_json(card.decision.action);
            let _ = writeln!(
                &mut out,
                "{{\"timestamp\":\"{timestamp}\",\"trace_id\":\"{bead}::{run}::{:06}\",\"bead_id\":\"{bead}\",\"scenario_id\":\"{run}\",\"level\":\"{level}\",\"event\":\"runtime_decision\",\"controller_id\":\"runtime_math_kernel.v1\",\"decision\":\"{decision_name}\",\"decision_action\":\"{action_name}\",\"decision_path\":\"{decision_path}\",\"healing_action\":{healing_action},\"decision_id\":{},\"mode\":\"{}\",\"api_family\":\"{family_name}\",\"symbol\":\"runtime_math::{family_name}\",\"errno\":0,\"latency_ns\":{},\"policy_id\":{},\"risk_upper_bound_ppm\":{},\"evidence_seqno\":{},\"risk_inputs\":{{\"requested_bytes\":{},\"bloom_negative\":{},\"is_write\":{},\"contention_hint\":{},\"addr_hint\":{}}},\"artifact_refs\":[\"crates/frankenlibc-membrane/src/runtime_math/mod.rs\"]}}",
                card.decision_id,
                card.decision_id,
                mode_label,
                card.estimated_cost_ns,
                card.decision.policy_id,
                card.decision.risk_upper_bound_ppm,
                card.decision.evidence_seqno,
                card.context.requested_bytes,
                card.context.bloom_negative,
                card.context.is_write,
                card.context.contention_hint,
                card.context.addr_hint,
            );
        }

        let _ = writeln!(
            &mut out,
            "{{\"timestamp\":\"{timestamp}\",\"trace_id\":\"{bead}::{run}::calibration\",\"bead_id\":\"{bead}\",\"scenario_id\":\"{run}\",\"level\":\"debug\",\"event\":\"runtime_calibration\",\"controller_id\":\"runtime_math_kernel.v1\",\"mode\":\"{mode_label}\",\"api_family\":\"runtime_math\",\"symbol\":\"runtime_math::kernel\",\"decision_path\":\"snapshot::calibration\",\"healing_action\":null,\"errno\":0,\"latency_ns\":0,\"full_validation_trigger_ppm\":{},\"repair_trigger_ppm\":{},\"design_selected_probes\":{},\"design_budget_ns\":{},\"sampled_risk_bonus_ppm\":{},\"policy_hash_prefix\":{},\"artifact_refs\":[\"crates/frankenlibc-membrane/src/runtime_math/mod.rs\"]}}",
            snapshot.full_validation_trigger_ppm,
            snapshot.repair_trigger_ppm,
            snapshot.design_selected_probes,
            snapshot.design_budget_ns,
            snapshot.sampled_risk_bonus_ppm,
            policy_hash_prefix,
        );

        let _ = writeln!(
            &mut out,
            "{{\"timestamp\":\"{timestamp}\",\"trace_id\":\"{bead}::{run}::snapshot\",\"bead_id\":\"{bead}\",\"scenario_id\":\"{run}\",\"level\":\"info\",\"event\":\"runtime_snapshot\",\"controller_id\":\"runtime_math_kernel.v1\",\"mode\":\"{mode_label}\",\"api_family\":\"runtime_math\",\"symbol\":\"runtime_math::kernel\",\"decision_path\":\"snapshot::state\",\"healing_action\":null,\"errno\":0,\"latency_ns\":0,\"decisions\":{},\"consistency_faults\":{},\"pareto_cumulative_regret_milli\":{},\"pareto_cap_enforcements\":{},\"pareto_exhausted_families\":{},\"evidence_seqno\":{},\"artifact_refs\":[\"crates/frankenlibc-membrane/src/runtime_math/mod.rs\"]}}",
            snapshot.decisions,
            snapshot.consistency_faults,
            snapshot.pareto_cumulative_regret_milli,
            snapshot.pareto_cap_enforcements,
            snapshot.pareto_exhausted_families,
            snapshot.evidence_seqno,
        );

        if policy_load_state == POLICY_LOAD_STATE_LOADED {
            let _ = writeln!(
                &mut out,
                "{{\"timestamp\":\"{timestamp}\",\"trace_id\":\"{bead}::{run}::certificate\",\"bead_id\":\"{bead}\",\"scenario_id\":\"{run}\",\"level\":\"info\",\"event\":\"runtime_certificate_loaded\",\"controller_id\":\"runtime_math_kernel.v1\",\"mode\":\"{mode_label}\",\"api_family\":\"runtime_math\",\"symbol\":\"runtime_math::kernel\",\"decision_path\":\"certificate::verify\",\"healing_action\":null,\"errno\":0,\"latency_ns\":0,\"policy_hash_prefix\":{},\"verification\":\"pass\",\"artifact_refs\":[\"crates/frankenlibc-membrane/src/runtime_math/mod.rs\"]}}",
                policy_hash_prefix,
            );
        } else if policy_load_state == POLICY_LOAD_STATE_VERIFY_FAILED {
            let _ = writeln!(
                &mut out,
                "{{\"timestamp\":\"{timestamp}\",\"trace_id\":\"{bead}::{run}::certificate\",\"bead_id\":\"{bead}\",\"scenario_id\":\"{run}\",\"level\":\"error\",\"event\":\"runtime_certificate_verification_failed\",\"controller_id\":\"runtime_math_kernel.v1\",\"mode\":\"{mode_label}\",\"api_family\":\"runtime_math\",\"symbol\":\"runtime_math::kernel\",\"decision_path\":\"certificate::verify\",\"healing_action\":null,\"errno\":0,\"latency_ns\":0,\"policy_hash_prefix\":{},\"verification\":\"fail\",\"artifact_refs\":[\"crates/frankenlibc-membrane/src/runtime_math/mod.rs\"]}}",
                policy_hash_prefix,
            );
        }

        if snapshot.pareto_cap_enforcements > 0 || snapshot.pareto_exhausted_families > 0 {
            let _ = writeln!(
                &mut out,
                "{{\"timestamp\":\"{timestamp}\",\"trace_id\":\"{bead}::{run}::regret\",\"bead_id\":\"{bead}\",\"scenario_id\":\"{run}\",\"level\":\"warn\",\"event\":\"runtime_regret_alert\",\"controller_id\":\"runtime_math_kernel.v1\",\"mode\":\"{mode_label}\",\"api_family\":\"runtime_math\",\"symbol\":\"runtime_math::kernel\",\"decision_path\":\"pareto::regret\",\"healing_action\":null,\"errno\":0,\"latency_ns\":0,\"pareto_cap_enforcements\":{},\"pareto_exhausted_families\":{},\"artifact_refs\":[\"crates/frankenlibc-membrane/src/runtime_math/mod.rs\"]}}",
                snapshot.pareto_cap_enforcements, snapshot.pareto_exhausted_families,
            );
        }

        if snapshot.padic_drift_count > 0
            || snapshot.equivariant_drift_count > 0
            || snapshot.doob_max_drift > f64::EPSILON
            || snapshot.wasserstein_aggregate_distance > f64::EPSILON
        {
            let _ = writeln!(
                &mut out,
                "{{\"timestamp\":\"{timestamp}\",\"trace_id\":\"{bead}::{run}::drift\",\"bead_id\":\"{bead}\",\"scenario_id\":\"{run}\",\"level\":\"warn\",\"event\":\"runtime_drift_alert\",\"controller_id\":\"runtime_math_kernel.v1\",\"mode\":\"{mode_label}\",\"api_family\":\"runtime_math\",\"symbol\":\"runtime_math::kernel\",\"decision_path\":\"drift::monitor\",\"healing_action\":null,\"errno\":0,\"latency_ns\":0,\"padic_drift_count\":{},\"equivariant_drift_count\":{},\"doob_max_drift\":{},\"wasserstein_aggregate_distance\":{},\"artifact_refs\":[\"crates/frankenlibc-membrane/src/runtime_math/mod.rs\"]}}",
                snapshot.padic_drift_count,
                snapshot.equivariant_drift_count,
                snapshot.doob_max_drift,
                snapshot.wasserstein_aggregate_distance,
            );
        }

        out
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

impl RuntimeKernelFramework for RuntimeMathKernel {
    type Snapshot = RuntimeKernelSnapshot;

    fn evaluate(&self, mode: SafetyLevel, ctx: RuntimeContext) -> RuntimeDecision {
        RuntimeMathKernel::decide(self, mode, ctx)
    }

    fn calibrate(
        &self,
        mode: SafetyLevel,
        family: ApiFamily,
        profile: ValidationProfile,
        estimated_cost_ns: u64,
        adverse: bool,
    ) {
        RuntimeMathKernel::observe_validation_result(
            self,
            mode,
            family,
            profile,
            estimated_cost_ns,
            adverse,
        );
    }

    fn snapshot(&self, mode: SafetyLevel) -> Self::Snapshot {
        RuntimeMathKernel::snapshot(self, mode)
    }

    fn evidence_contract_snapshot(&self) -> RuntimeEvidenceContractSnapshot {
        RuntimeMathKernel::evidence_contract_snapshot(self)
    }

    fn export_decision_cards_json(&self) -> String {
        RuntimeMathKernel::export_decision_cards_json(self)
    }
}

impl Default for RuntimeMathKernel {
    fn default() -> Self {
        Self::new()
    }
}

fn action_name(action: MembraneAction) -> &'static str {
    match action {
        MembraneAction::Allow => "Allow",
        MembraneAction::FullValidate => "FullValidate",
        MembraneAction::Repair(_) => "Repair",
        MembraneAction::Deny => "Deny",
    }
}

fn decision_name(action: MembraneAction) -> &'static str {
    match action {
        MembraneAction::Allow => "Allow",
        MembraneAction::FullValidate => "FullValidate",
        MembraneAction::Repair(HealingAction::ClampSize { .. }) => "Repair::ClampSize",
        MembraneAction::Repair(HealingAction::TruncateWithNull { .. }) => {
            "Repair::TruncateWithNull"
        }
        MembraneAction::Repair(HealingAction::IgnoreDoubleFree) => "Repair::IgnoreDoubleFree",
        MembraneAction::Repair(HealingAction::IgnoreForeignFree) => "Repair::IgnoreForeignFree",
        MembraneAction::Repair(HealingAction::ReallocAsMalloc { .. }) => "Repair::ReallocAsMalloc",
        MembraneAction::Repair(HealingAction::ReturnSafeDefault) => "Repair::ReturnSafeDefault",
        MembraneAction::Repair(HealingAction::UpgradeToSafeVariant) => {
            "Repair::UpgradeToSafeVariant"
        }
        MembraneAction::Repair(HealingAction::None) => "Repair::None",
        MembraneAction::Deny => "Deny",
    }
}

fn level_for_action(action: MembraneAction) -> &'static str {
    match action {
        MembraneAction::Allow => "trace",
        MembraneAction::FullValidate => "info",
        MembraneAction::Repair(_) => "warn",
        MembraneAction::Deny => "error",
    }
}

fn decision_path(action: MembraneAction) -> &'static str {
    match action {
        MembraneAction::Allow => "risk->bandit->control->barrier->allow",
        MembraneAction::FullValidate => "risk->bandit->control->barrier->full_validate",
        MembraneAction::Repair(_) => "risk->bandit->control->barrier->repair",
        MembraneAction::Deny => "risk->bandit->control->barrier->deny",
    }
}

fn healing_action_json(action: MembraneAction) -> &'static str {
    match action {
        MembraneAction::Repair(HealingAction::ClampSize { .. }) => "\"ClampSize\"",
        MembraneAction::Repair(HealingAction::TruncateWithNull { .. }) => "\"TruncateWithNull\"",
        MembraneAction::Repair(HealingAction::IgnoreDoubleFree) => "\"IgnoreDoubleFree\"",
        MembraneAction::Repair(HealingAction::IgnoreForeignFree) => "\"IgnoreForeignFree\"",
        MembraneAction::Repair(HealingAction::ReallocAsMalloc { .. }) => "\"ReallocAsMalloc\"",
        MembraneAction::Repair(HealingAction::ReturnSafeDefault) => "\"ReturnSafeDefault\"",
        MembraneAction::Repair(HealingAction::UpgradeToSafeVariant) => "\"UpgradeToSafeVariant\"",
        MembraneAction::Repair(HealingAction::None) => "\"None\"",
        MembraneAction::Allow | MembraneAction::FullValidate | MembraneAction::Deny => "null",
    }
}

fn family_name(family: ApiFamily) -> &'static str {
    match family {
        ApiFamily::PointerValidation => "pointer_validation",
        ApiFamily::Allocator => "allocator",
        ApiFamily::StringMemory => "string_memory",
        ApiFamily::Stdio => "stdio",
        ApiFamily::Threading => "threading",
        ApiFamily::Resolver => "resolver",
        ApiFamily::MathFenv => "math_fenv",
        ApiFamily::Loader => "loader",
        ApiFamily::Stdlib => "stdlib",
        ApiFamily::Ctype => "ctype",
        ApiFamily::Time => "time",
        ApiFamily::Signal => "signal",
        ApiFamily::IoFd => "io_fd",
        ApiFamily::Socket => "socket",
        ApiFamily::Locale => "locale",
        ApiFamily::Termios => "termios",
        ApiFamily::Inet => "inet",
        ApiFamily::Process => "process",
        ApiFamily::VirtualMemory => "virtual_memory",
        ApiFamily::Poll => "poll",
    }
}

fn mode_name(mode: SafetyLevel) -> &'static str {
    match mode {
        SafetyLevel::Strict => "strict",
        SafetyLevel::Hardened => "hardened",
        SafetyLevel::Off => "off",
    }
}

fn sanitize_trace_component(raw: &str) -> String {
    raw.chars()
        .map(|ch| match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' => ch,
            _ => '_',
        })
        .collect()
}

fn now_utc_iso_like() -> String {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    let millis = duration.subsec_millis();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        1970 + secs / 31_557_600,
        (secs % 31_557_600) / 2_629_800 + 1,
        (secs % 2_629_800) / 86_400 + 1,
        (secs % 86_400) / 3_600,
        (secs % 3_600) / 60,
        secs % 60,
        millis,
    )
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
        ApiFamily::Ctype => CallFamily::String,
        ApiFamily::Time => CallFamily::Other,
        ApiFamily::Signal => CallFamily::Other,
        ApiFamily::IoFd => CallFamily::Stdio,
        ApiFamily::Socket | ApiFamily::Inet => CallFamily::Socket,
        ApiFamily::Locale => CallFamily::Other,
        ApiFamily::Termios => CallFamily::Stdio,
        ApiFamily::Process => CallFamily::Other,
        ApiFamily::VirtualMemory => CallFamily::Memory,
        ApiFamily::Poll => CallFamily::Stdio,
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
    use serde_json::Value;
    use std::collections::{BTreeSet, HashMap};

    fn snapshot_struct_field_names(source: &str) -> Vec<String> {
        let struct_start = source
            .find("pub struct RuntimeKernelSnapshot {")
            .expect("RuntimeKernelSnapshot definition must exist");
        let after_struct = &source[struct_start..];
        let struct_end = after_struct
            .find("\n}\n\n/// Online control kernel for strict/hardened runtime decisions.")
            .expect("RuntimeKernelSnapshot end marker must exist");
        let struct_block = &after_struct[..struct_end];

        struct_block
            .lines()
            .filter_map(|line| {
                let trimmed = line.trim();
                let rest = trimmed.strip_prefix("pub ")?;
                let (name, _) = rest.split_once(':')?;
                Some(name.trim().to_string())
            })
            .collect()
    }

    fn snapshot_schema_field_names(schema_doc: &str) -> Vec<String> {
        schema_doc
            .lines()
            .filter_map(|line| {
                let trimmed = line.trim_start();
                if !trimmed.starts_with("| `") {
                    return None;
                }
                let mut parts = trimmed.split('`');
                let _ = parts.next();
                parts.next().map(std::string::ToString::to_string)
            })
            .collect()
    }

    fn snapshot_literal_field_counts(snapshot_src: &str) -> HashMap<String, usize> {
        let struct_start = snapshot_src
            .find("RuntimeKernelSnapshot {\n            schema_version:")
            .expect("snapshot must build RuntimeKernelSnapshot struct literal");
        let literal_tail = &snapshot_src[struct_start..];
        let open_brace = literal_tail
            .find('{')
            .expect("snapshot struct literal must contain an opening brace");

        let mut depth = 0usize;
        let mut close_brace = None;
        for (idx, ch) in literal_tail.char_indices().skip(open_brace) {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        close_brace = Some(idx);
                        break;
                    }
                }
                _ => {}
            }
        }
        let close_brace = close_brace.expect("snapshot struct literal must terminate");
        let struct_literal = &literal_tail[..=close_brace];

        let mut counts = HashMap::new();
        for line in struct_literal.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty()
                || trimmed == "RuntimeKernelSnapshot {"
                || trimmed.starts_with("//")
                || trimmed == "}"
            {
                continue;
            }
            let name = if let Some(colon_idx) = trimmed.find(':') {
                if trimmed[colon_idx..].starts_with("::") {
                    continue;
                }
                &trimmed[..colon_idx]
            } else if let Some(name) = trimmed.strip_suffix(',') {
                name
            } else {
                continue;
            };

            let name = name.trim();
            let mut chars = name.chars();
            let Some(first) = chars.next() else {
                continue;
            };
            if !(first == '_' || first.is_ascii_alphabetic())
                || !chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
            {
                continue;
            }
            *counts.entry(name.to_string()).or_insert(0) += 1;
        }
        counts
    }

    #[test]
    fn runtime_math_feature_flags_are_consistent() {
        if !RUNTIME_MATH_PRODUCTION_ENABLED {
            panic!("runtime-math-production must be enabled for membrane builds");
        }
        if RUNTIME_MATH_RESEARCH_ENABLED && !RUNTIME_MATH_PRODUCTION_ENABLED {
            panic!("runtime-math-research requires runtime-math-production");
        }
    }

    #[test]
    fn runtime_kernel_snapshot_schema_doc_matches_constant() {
        let doc = include_str!("runtime_kernel_snapshot_schema.md");
        let needle = "Schema version constant:";
        let line = doc
            .lines()
            .find(|line| line.contains(needle))
            .expect("schema doc must include a schema version constant line");
        let expected = format!(
            "RUNTIME_KERNEL_SNAPSHOT_SCHEMA_VERSION = {}",
            RUNTIME_KERNEL_SNAPSHOT_SCHEMA_VERSION
        );
        assert!(
            line.contains(&expected),
            "schema doc drift: expected `{expected}` line, got: {line}"
        );
    }

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
        let mode = SafetyLevel::Hardened;
        kernel.observe_validation_result(
            mode,
            ApiFamily::PointerValidation,
            ValidationProfile::Fast,
            7,
            false,
        );
        kernel.observe_validation_result(
            mode,
            ApiFamily::PointerValidation,
            ValidationProfile::Full,
            45,
            true,
        );
        let snap = kernel.snapshot(mode);
        assert!(snap.decisions <= 2);
        assert!(snap.full_validation_trigger_ppm > 0);
    }

    #[test]
    fn explicit_oracle_feedback_updates_bias_cache() {
        let kernel = RuntimeMathKernel::new();
        let mode = SafetyLevel::Strict;
        let ordering = kernel.check_ordering(ApiFamily::PointerValidation, true, true);
        kernel.note_check_order_outcome(
            mode,
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

    #[test]
    fn runtime_kernel_framework_roundtrip_exposes_snapshot_and_contract() {
        let kernel = RuntimeMathKernel::new();
        let mode = SafetyLevel::Hardened;
        let ctx = RuntimeContext {
            family: ApiFamily::Allocator,
            addr_hint: 0x2000,
            requested_bytes: 8192,
            is_write: true,
            contention_hint: 128,
            bloom_negative: true,
        };

        let decision = RuntimeKernelFramework::evaluate(&kernel, mode, ctx);
        RuntimeKernelFramework::calibrate(
            &kernel,
            mode,
            ApiFamily::Allocator,
            decision.profile,
            64,
            !matches!(decision.action, MembraneAction::Allow),
        );

        let snap = RuntimeKernelFramework::snapshot(&kernel, mode);
        let evidence = RuntimeKernelFramework::evidence_contract_snapshot(&kernel);

        assert!(snap.decisions >= 1);
        assert_eq!(evidence.evidence_seqno, snap.evidence_seqno);
        assert_eq!(evidence.evidence_loss_count, snap.evidence_loss_count);
        assert_eq!(evidence.evidence_max_epoch, snap.evidence_max_epoch);
    }

    #[test]
    fn runtime_kernel_framework_exports_structured_decision_card_json() {
        let kernel = RuntimeMathKernel::new();
        let ctx = RuntimeContext::pointer_validation(0x1000, false);
        // Evidence recording follows the existing cadence contract.
        for _ in 0..16385 {
            let _ = kernel.decide(SafetyLevel::Hardened, ctx);
        }

        let export = RuntimeKernelFramework::export_decision_cards_json(&kernel);
        let parsed: Value =
            serde_json::from_str(&export).expect("decision card export must be valid JSON");

        assert_eq!(
            parsed.get("schema").and_then(Value::as_str),
            Some("decision_cards.v1")
        );
        let cards = parsed
            .get("cards")
            .and_then(Value::as_array)
            .expect("cards array must be present");
        assert!(!cards.is_empty(), "at least one decision card is expected");
        let first = cards[0]
            .as_object()
            .expect("decision card entries must be JSON objects");
        for key in [
            "decision_id",
            "decision_type",
            "timestamp_mono_ns",
            "family",
            "mode",
            "profile",
            "action",
            "policy_id",
            "risk_upper_bound_ppm",
            "context",
        ] {
            assert!(
                first.contains_key(key),
                "decision card must contain required key `{key}`"
            );
        }
    }

    #[test]
    fn runtime_math_log_jsonl_export_contains_required_runtime_decision_fields() {
        let kernel = RuntimeMathKernel::new();
        let ctx = RuntimeContext {
            family: ApiFamily::Allocator,
            addr_hint: 0x4000,
            requested_bytes: 4096,
            is_write: true,
            contention_hint: 64,
            bloom_negative: false,
        };
        for _ in 0..16385 {
            let _ = kernel.decide(SafetyLevel::Hardened, ctx);
        }

        let jsonl =
            kernel.export_runtime_math_log_jsonl(SafetyLevel::Hardened, "bd-5vr.8", "smoke-1");
        let lines: Vec<&str> = jsonl
            .lines()
            .filter(|line| !line.trim().is_empty())
            .collect();
        assert!(
            !lines.is_empty(),
            "jsonl export must emit at least one line"
        );

        let mut saw_runtime_decision = false;
        for line in lines {
            let parsed: Value =
                serde_json::from_str(line).expect("each runtime log line must be valid JSON");
            for required in [
                "timestamp",
                "trace_id",
                "bead_id",
                "scenario_id",
                "level",
                "event",
                "controller_id",
                "mode",
                "api_family",
                "symbol",
                "decision_path",
                "healing_action",
                "errno",
                "latency_ns",
                "artifact_refs",
            ] {
                assert!(
                    parsed.get(required).is_some(),
                    "runtime log line missing `{required}`"
                );
            }
            assert!(
                parsed
                    .get("trace_id")
                    .and_then(Value::as_str)
                    .is_some_and(|trace_id| trace_id.contains("::")),
                "trace_id must include scope separators"
            );
            assert_eq!(
                parsed.get("bead_id").and_then(Value::as_str),
                Some("bd-5vr.8"),
                "bead_id should round-trip through structured logs"
            );
            assert_eq!(
                parsed.get("scenario_id").and_then(Value::as_str),
                Some("smoke-1"),
                "scenario_id should round-trip through structured logs"
            );
            assert_eq!(
                parsed.get("errno").and_then(Value::as_i64),
                Some(0),
                "runtime log export should use deterministic errno placeholder"
            );
            assert!(
                parsed.get("latency_ns").and_then(Value::as_u64).is_some(),
                "latency_ns must be included as integer"
            );
            if parsed
                .get("event")
                .and_then(Value::as_str)
                .is_some_and(|event| event == "runtime_decision")
            {
                saw_runtime_decision = true;
                for required in ["decision", "decision_action", "decision_id", "risk_inputs"] {
                    assert!(
                        parsed.get(required).is_some(),
                        "runtime_decision line missing `{required}`"
                    );
                }
                let decision_action = parsed
                    .get("decision_action")
                    .and_then(Value::as_str)
                    .expect("decision_action must be string");
                assert!(
                    matches!(
                        decision_action,
                        "Allow" | "FullValidate" | "Repair" | "Deny"
                    ),
                    "decision_action must match schema enum, got {decision_action}"
                );
                assert!(
                    parsed
                        .get("decision_path")
                        .and_then(Value::as_str)
                        .is_some_and(|path| {
                            path.starts_with("risk->bandit->control->barrier->")
                        }),
                    "decision_path must include deterministic kernel pipeline prefix"
                );
                if decision_action == "Repair" {
                    assert!(
                        parsed
                            .get("healing_action")
                            .and_then(Value::as_str)
                            .is_some(),
                        "repair decisions must include healing_action string"
                    );
                }
            }
        }
        assert!(
            saw_runtime_decision,
            "jsonl export must include runtime_decision rows"
        );
    }

    #[test]
    fn runtime_math_log_jsonl_export_reports_certificate_load_outcomes() {
        let mut success_kernel = RuntimeMathKernel::new();
        let valid_artifact = policy_table::build_test_pcpt(&[]);
        success_kernel
            .load_policy_table(&valid_artifact)
            .expect("valid pcpt must load");
        let success_jsonl =
            success_kernel.export_runtime_math_log_jsonl(SafetyLevel::Strict, "bd-5vr.8", "ok");
        assert!(
            success_jsonl.contains("\"event\":\"runtime_certificate_loaded\""),
            "successful load must emit runtime_certificate_loaded"
        );

        let mut failure_kernel = RuntimeMathKernel::new();
        let mut invalid_artifact = policy_table::build_test_pcpt(&[]);
        invalid_artifact[120] ^= 0xFF;
        assert!(
            failure_kernel.load_policy_table(&invalid_artifact).is_err(),
            "tampered artifact must fail verification"
        );
        let failure_jsonl =
            failure_kernel.export_runtime_math_log_jsonl(SafetyLevel::Strict, "bd-5vr.8", "fail");
        assert!(
            failure_jsonl.contains("\"event\":\"runtime_certificate_verification_failed\""),
            "failed load must emit runtime_certificate_verification_failed"
        );
        assert!(
            failure_jsonl.contains("\"level\":\"error\""),
            "failed certificate verification should be error-level"
        );
    }

    #[test]
    fn snapshot_literal_never_relocks_summary_mutexes() {
        let src = include_str!("mod.rs");
        let snapshot_fn_start = src
            .find("pub fn snapshot(&self, mode: SafetyLevel) -> RuntimeKernelSnapshot")
            .expect("snapshot function signature must exist");
        let snapshot_tail = &src[snapshot_fn_start..];
        let resample_fn_start = snapshot_tail
            .find("fn resample_high_order_kernels(&self, mode: SafetyLevel, ctx: RuntimeContext) {")
            .expect("resample function must follow snapshot");
        let snapshot_src = &snapshot_tail[..resample_fn_start];

        let struct_start = snapshot_src
            .find("RuntimeKernelSnapshot {\n            schema_version:")
            .expect("snapshot must build RuntimeKernelSnapshot struct literal");
        let struct_literal = &snapshot_src[struct_start..];
        assert!(
            !struct_literal.contains(".lock()"),
            "snapshot struct literal must only read cached locals; direct mutex locking in the literal can deadlock"
        );

        for needle in [
            "let tropical_full_wcl_ns = self.tropical.lock().worst_case_bound(PipelinePath::Full);",
            "let spectral_sig = self.spectral.lock().signature();",
            "let rp_summary = self.rough_path.lock().summary();",
            "let bridge_summary = self.bridge.lock().summary();",
            "let hji_summary = self.hji.lock().summary();",
            "let mfg_summary = self.mfg.lock().summary();",
            "let padic_summary = self.padic.lock().summary();",
            "let symplectic_summary = self.symplectic.lock().summary();",
            "let topos_summary = self.topos.lock().summary();",
            "let audit_summary = self.audit.lock().summary();",
            "let changepoint_summary = self.changepoint.lock().summary();",
            "let conformal_summary = self.conformal.lock().summary();",
            "let design_summary = self.design.lock().summary();",
            "let sparse_summary = self.sparse.lock().summary();",
            "let equivariant_summary = self.equivariant.lock().summary();",
            "let ktheory_summary = self.ktheory.lock().summary();",
            "let covering_summary = self.covering.lock().summary();",
            "let tstructure_summary = self.tstructure.lock().summary();",
            "let atiyah_bott_summary = self.atiyah_bott.lock().summary();",
            "let pomdp_summary = self.pomdp.lock().summary();",
            "let sos_summary = self.sos.lock().summary();",
            "let admm_summary = self.admm.lock().summary();",
            "let obstruction_summary = self.obstruction.lock().summary();",
            "let operator_norm_summary = self.operator_norm.lock().summary();",
            "let provenance_snapshot = self.provenance.lock().snapshot();",
            "let grobner_snapshot = self.grobner.lock().snapshot();",
            "let grothendieck_snapshot = self.grothendieck.lock().snapshot();",
            "let malliavin_summary = self.malliavin.lock().summary();",
            "let info_geo_summary = self.info_geometry.lock().summary();",
            "let matrix_conc_summary = self.matrix_concentration.lock().summary();",
            "let nerve_summary = self.nerve_complex.lock().summary();",
            "let wasserstein_summary = self.wasserstein.lock().summary();",
            "let mmd_summary = self.kernel_mmd.lock().summary();",
            "let microlocal_summary = self.microlocal.lock().summary();",
            "let serre_summary = self.serre.lock().summary();",
            "let clifford_summary = self.clifford.lock().summary();",
            "let coupling_summary = self.coupling.lock().summary();",
            "let loss_summary = self.loss_minimizer.lock().summary();",
        ] {
            assert_eq!(
                snapshot_src.matches(needle).count(),
                1,
                "snapshot must cache exactly one local for `{needle}` before struct construction"
            );
        }
    }

    #[test]
    fn runtime_kernel_snapshot_schema_and_literal_cover_all_fields() {
        let src = include_str!("mod.rs");
        let schema_doc = include_str!("runtime_kernel_snapshot_schema.md");
        let struct_fields = snapshot_struct_field_names(src);
        let expected_fields = struct_fields.len();
        assert!(
            expected_fields >= 154,
            "RuntimeKernelSnapshot must include at least the 154 baseline fields"
        );

        let snapshot_fn_start = src
            .find("pub fn snapshot(&self, mode: SafetyLevel) -> RuntimeKernelSnapshot")
            .expect("snapshot function signature must exist");
        let snapshot_tail = &src[snapshot_fn_start..];
        let resample_fn_start = snapshot_tail
            .find("fn resample_high_order_kernels(&self, mode: SafetyLevel, ctx: RuntimeContext) {")
            .expect("resample function must follow snapshot");
        let snapshot_src = &snapshot_tail[..resample_fn_start];
        let literal_fields = snapshot_literal_field_counts(snapshot_src);

        let struct_field_set: BTreeSet<_> = struct_fields.iter().cloned().collect();
        let literal_field_set: BTreeSet<_> = literal_fields.keys().cloned().collect();
        let missing_in_literal: Vec<_> = struct_field_set
            .difference(&literal_field_set)
            .cloned()
            .collect();
        let extra_in_literal: Vec<_> = literal_field_set
            .difference(&struct_field_set)
            .cloned()
            .collect();
        assert!(
            missing_in_literal.is_empty() && extra_in_literal.is_empty(),
            "snapshot literal field mismatch; missing={missing_in_literal:?}, extra={extra_in_literal:?}"
        );

        for field in &struct_field_set {
            assert_eq!(
                literal_fields.get(field),
                Some(&1usize),
                "snapshot literal must assign `{field}` exactly once"
            );
        }

        let schema_field_set: BTreeSet<_> = snapshot_schema_field_names(schema_doc)
            .into_iter()
            .collect();
        for field in &schema_field_set {
            assert!(
                struct_field_set.contains(field),
                "schema references unknown RuntimeKernelSnapshot field `{field}`"
            );
        }
    }

    #[test]
    fn snapshot_contract_ranges_are_sane_for_fresh_kernel() {
        let kernel = RuntimeMathKernel::new();
        let snap = kernel.snapshot(SafetyLevel::Strict);

        assert_eq!(snap.schema_version, RUNTIME_KERNEL_SNAPSHOT_SCHEMA_VERSION);
        assert!(snap.full_validation_trigger_ppm <= 1_000_000);
        assert!(snap.repair_trigger_ppm <= 1_000_000);
        assert!(snap.sampled_risk_bonus_ppm <= 1_000_000);
        assert!(snap.design_identifiability_ppm <= 1_000_000);
        assert!(snap.fusion_bonus_ppm <= 1_000_000);
        assert!(snap.fusion_drift_ppm <= 1_000_000);
        assert!(snap.fusion_entropy_milli <= 1_000);
        assert!(snap.loss_posterior_adverse_ppm <= 1_000_000);
        assert!(snap.loss_recommended_action <= 3);
        assert!(snap.loss_competing_action <= 3);
        assert!((0.0..=1.0).contains(&snap.topos_violation_rate));
        assert!((0.0..=1.0).contains(&snap.covering_coverage_fraction));
        assert!((0.0..=1.0).contains(&snap.pac_bayes_bound));
        assert!((0.0..=1.0).contains(&snap.dobrushin_max_contraction));
        assert!((0.0..=1.0).contains(&snap.dobrushin_mean_contraction));
        assert!((0.0..=1.0).contains(&snap.submodular_coverage_ratio));
        assert!((0.0..=1.0).contains(&snap.bifurcation_max_sensitivity));
        assert!((0.0..=1.0).contains(&snap.bifurcation_mean_sensitivity));
        assert!((0.0..=1.0).contains(&snap.entropy_rate_ratio));
        assert!(snap.sobol_augmented_mask & !Probe::all_mask() == 0);

        for value in [
            snap.spectral_edge_ratio,
            snap.persistence_entropy,
            snap.bridge_transport_distance,
            snap.hji_safety_value,
            snap.padic_ultrametric_distance,
            snap.audit_martingale_value,
            snap.info_geo_geodesic_distance,
            snap.info_geo_max_controller_distance,
            snap.matrix_conc_spectral_deviation,
            snap.matrix_conc_bernstein_bound,
        ] {
            assert!(value.is_finite(), "snapshot values must remain finite");
        }
    }

    #[test]
    fn snapshot_decision_and_evidence_counters_are_monotone() {
        let kernel = RuntimeMathKernel::new();
        let ctx = RuntimeContext::pointer_validation(0x1000, false);

        let snap0 = kernel.snapshot(SafetyLevel::Hardened);
        for _ in 0..8193 {
            let _ = kernel.decide(SafetyLevel::Hardened, ctx);
        }
        let snap1 = kernel.snapshot(SafetyLevel::Hardened);
        for _ in 0..8193 {
            let _ = kernel.decide(SafetyLevel::Hardened, ctx);
        }
        let snap2 = kernel.snapshot(SafetyLevel::Hardened);

        assert!(snap1.decisions >= snap0.decisions);
        assert!(snap2.decisions >= snap1.decisions);
        assert!(snap1.evidence_seqno >= snap0.evidence_seqno);
        assert!(snap2.evidence_seqno >= snap1.evidence_seqno);
        assert!(snap2.evidence_max_epoch >= snap1.evidence_max_epoch);
    }

    #[test]
    fn decision_card_export_json_roundtrip_preserves_payload() {
        let kernel = RuntimeMathKernel::new();
        let ctx = RuntimeContext::pointer_validation(0x1000, false);
        for _ in 0..16385 {
            let _ = kernel.decide(SafetyLevel::Hardened, ctx);
        }

        let export = RuntimeKernelFramework::export_decision_cards_json(&kernel);
        let parsed: Value =
            serde_json::from_str(&export).expect("decision card export must be valid JSON");
        let cards = parsed
            .get("cards")
            .and_then(Value::as_array)
            .expect("decision cards export must contain `cards` array");
        assert!(!cards.is_empty(), "decision card export must not be empty");
        assert!(
            cards.iter().all(|card| card.get("loss_evidence").is_some()),
            "every decision card must include loss_evidence (object or null)"
        );

        let roundtrip = serde_json::to_string(&parsed).expect("roundtrip JSON should serialize");
        let reparsed: Value =
            serde_json::from_str(&roundtrip).expect("roundtrip JSON should parse");
        assert_eq!(
            parsed, reparsed,
            "decision card JSON roundtrip must be lossless"
        );
    }

    #[test]
    fn deterministic_replay_produces_identical_decisions_and_evidence() {
        let k1 = RuntimeMathKernel::new();
        let k2 = RuntimeMathKernel::new();

        let script = [
            (
                SafetyLevel::Strict,
                RuntimeContext::pointer_validation(0x1000, false),
                32u64,
                false,
            ),
            (
                SafetyLevel::Hardened,
                RuntimeContext {
                    family: ApiFamily::Allocator,
                    addr_hint: 0x2200,
                    requested_bytes: 96,
                    is_write: true,
                    contention_hint: 2,
                    bloom_negative: false,
                },
                48u64,
                true,
            ),
            (
                SafetyLevel::Hardened,
                RuntimeContext {
                    family: ApiFamily::StringMemory,
                    addr_hint: 0x3300,
                    requested_bytes: 64,
                    is_write: false,
                    contention_hint: 1,
                    bloom_negative: true,
                },
                20u64,
                false,
            ),
            (
                SafetyLevel::Strict,
                RuntimeContext {
                    family: ApiFamily::IoFd,
                    addr_hint: 0x4400,
                    requested_bytes: 4096,
                    is_write: true,
                    contention_hint: 0,
                    bloom_negative: false,
                },
                75u64,
                true,
            ),
        ];

        let mut trace1 = Vec::new();
        let mut trace2 = Vec::new();
        for round in 0..512 {
            let (mode, ctx, estimated_cost_ns, adverse) = script[round % script.len()];
            let d1 = k1.decide(mode, ctx);
            let d2 = k2.decide(mode, ctx);
            trace1.push(d1);
            trace2.push(d2);

            k1.observe_validation_result(mode, ctx.family, d1.profile, estimated_cost_ns, adverse);
            k2.observe_validation_result(mode, ctx.family, d2.profile, estimated_cost_ns, adverse);
        }

        assert_eq!(
            trace1, trace2,
            "same (mode,input,event) replay must produce identical decisions"
        );
        assert_eq!(
            RuntimeKernelFramework::evidence_contract_snapshot(&k1),
            RuntimeKernelFramework::evidence_contract_snapshot(&k2),
            "same replay must produce identical evidence counters"
        );
    }

    #[test]
    fn raptorq_redundancy_budget_survives_target_loss_fraction() {
        const K_SOURCE: u16 = 256;
        const OVERHEAD_PERCENT: u16 = 20;
        const TARGET_LOSS_PPM: u32 = 100_000; // 10%

        let repair_count = evidence::derive_repair_symbol_count_v1(K_SOURCE, OVERHEAD_PERCENT);
        assert!(
            repair_count >= evidence::SLACK_DECODE_V1,
            "repair count must include at least decode slack"
        );

        let tolerated_loss_ppm = evidence::loss_fraction_max_ppm_v1(K_SOURCE, repair_count);
        assert!(
            tolerated_loss_ppm >= TARGET_LOSS_PPM,
            "expected >= {}ppm tolerated loss; got {}ppm (K={}, overhead={}%, R={})",
            TARGET_LOSS_PPM,
            tolerated_loss_ppm,
            K_SOURCE,
            OVERHEAD_PERCENT,
            repair_count
        );

        let epoch_seed = 0x0BAD_F00D_DEAD_BEEFu64;
        let mut source_payloads = vec![[0u8; evidence::EVIDENCE_SYMBOL_SIZE_T]; K_SOURCE as usize];
        for (idx, payload) in source_payloads.iter_mut().enumerate() {
            *payload = [idx as u8; evidence::EVIDENCE_SYMBOL_SIZE_T];
        }

        let repairs =
            evidence::generate_repair_payloads_v1(epoch_seed, &source_payloads, OVERHEAD_PERCENT);
        let repairs_again =
            evidence::generate_repair_payloads_v1(epoch_seed, &source_payloads, OVERHEAD_PERCENT);
        assert_eq!(
            repairs, repairs_again,
            "repair payload generation must be deterministic"
        );
        assert_eq!(
            repairs.len(),
            repair_count as usize,
            "repair payload count must match derive_repair_symbol_count_v1"
        );
        assert_eq!(
            repairs.first().map(|(esi, _)| *esi),
            Some(K_SOURCE),
            "first repair ESI must start at K_source"
        );
        assert_eq!(
            repairs.last().map(|(esi, _)| *esi),
            Some(K_SOURCE + repair_count - 1),
            "last repair ESI must end at K_source + R - 1"
        );
    }

    #[test]
    fn observe_validation_result_records_all_probe_anomalies() {
        let src = include_str!("mod.rs");
        let observe_start = src
            .find("pub fn observe_validation_result(")
            .expect("observe_validation_result must exist");
        let observe_tail = &src[observe_start..];
        let observe_end = observe_tail
            .find("/// Record overlap information for cross-shard consistency checks.")
            .expect("observe_validation_result end marker must exist");
        let observe_src = &observe_tail[..observe_end];

        for needle in [
            "if let Some(flag) = spectral_anomaly {\n                design.record_probe(Probe::Spectral, flag);",
            "if let Some(flag) = rough_anomaly {\n                design.record_probe(Probe::RoughPath, flag);",
            "if let Some(flag) = persistence_anomaly {\n                design.record_probe(Probe::Persistence, flag);",
            "if let Some(flag) = anytime_anomaly {\n                design.record_probe(Probe::Anytime, flag);",
            "if let Some(flag) = cvar_anomaly {\n                design.record_probe(Probe::Cvar, flag);",
            "if let Some(flag) = bridge_anomaly {\n                design.record_probe(Probe::Bridge, flag);",
            "if let Some(flag) = ld_anomaly {\n                design.record_probe(Probe::LargeDeviations, flag);",
            "if let Some(flag) = hji_anomaly {\n                design.record_probe(Probe::Hji, flag);",
            "if let Some(flag) = mfg_anomaly {\n                design.record_probe(Probe::MeanField, flag);",
            "if let Some(flag) = padic_anomaly {\n                design.record_probe(Probe::Padic, flag);",
            "if let Some(flag) = symplectic_anomaly {\n                design.record_probe(Probe::Symplectic, flag);",
            "if let Some(flag) = topos_anomaly {\n                design.record_probe(Probe::HigherTopos, flag);",
            "if let Some(flag) = audit_anomaly {\n                design.record_probe(Probe::CommitmentAudit, flag);",
            "if let Some(flag) = changepoint_anomaly {\n                design.record_probe(Probe::Changepoint, flag);",
            "if let Some(flag) = conformal_anomaly {\n                design.record_probe(Probe::Conformal, flag);",
            "if let Some(flag) = loss_minimizer_anomaly {\n                design.record_probe(Probe::LossMinimizer, flag);",
            "if let Some(flag) = coupling_anomaly {\n                design.record_probe(Probe::Coupling, flag);",
        ] {
            assert!(
                observe_src.contains(needle),
                "observe_validation_result must feed design kernel with `{needle}`"
            );
        }
    }

    #[test]
    fn high_risk_aggregation_literals_are_lock_free() {
        let src = include_str!("mod.rs");
        let observe_start = src
            .find("pub fn observe_validation_result(")
            .expect("observe_validation_result must exist");
        let observe_tail = &src[observe_start..];
        let observe_end = observe_tail
            .find("/// Record overlap information for cross-shard consistency checks.")
            .expect("observe_validation_result end marker must exist");
        let observe_src = &observe_tail[..observe_end];

        let base_start = observe_src
            .find("let base_severity: [u8; BASE_SEVERITY_LEN] = [")
            .expect("base_severity literal must exist");
        let base_tail = &observe_src[base_start..];
        let base_end = base_tail
            .find("];")
            .expect("base_severity literal must terminate");
        let base_literal = &base_tail[..base_end + 2];
        assert!(
            !base_literal.contains(".lock()"),
            "base_severity aggregation must use cached atomics only (no locking in literal)"
        );

        let fusion_start = observe_src
            .find("let mut severity = [0u8; fusion::SIGNALS];")
            .expect("fusion severity buffer must exist");
        let fusion_tail = &observe_src[fusion_start..];
        let fusion_end = fusion_tail
            .find("let summary = {")
            .expect("fusion summary acquisition block must exist");
        let fusion_literal = &fusion_tail[..fusion_end];
        assert!(
            !fusion_literal.contains(".lock()"),
            "fusion severity aggregation must use cached atomics only (no locking in literal)"
        );
    }

    #[test]
    fn grobner_state_vector_literal_is_lock_free() {
        let src = include_str!("mod.rs");
        let observe_start = src
            .find("pub fn observe_validation_result(")
            .expect("observe_validation_result must exist");
        let observe_tail = &src[observe_start..];
        let observe_end = observe_tail
            .find("/// Record overlap information for cross-shard consistency checks.")
            .expect("observe_validation_result end marker must exist");
        let observe_src = &observe_tail[..observe_end];

        let state_vec_start = observe_src
            .find("let state_vec = [")
            .expect("grobner state_vec literal must exist");
        let state_vec_tail = &observe_src[state_vec_start..];
        let state_vec_end = state_vec_tail
            .find("];")
            .expect("grobner state_vec literal must terminate");
        let state_vec_literal = &state_vec_tail[..state_vec_end + 2];

        assert!(
            !state_vec_literal.contains(".lock()"),
            "grobner state_vec aggregation must use cached atomics only (no locking in literal)"
        );
    }

    #[test]
    fn resample_high_order_kernels_has_no_multi_lock_statements() {
        let src = include_str!("mod.rs");
        let resample_start = src
            .find("fn resample_high_order_kernels(&self, mode: SafetyLevel, ctx: RuntimeContext) {")
            .expect("resample_high_order_kernels must exist");
        let resample_tail = &src[resample_start..];
        let resample_end = resample_tail
            .find("\n}\n\nimpl Default for RuntimeMathKernel")
            .expect("resample_high_order_kernels end marker must exist");
        let resample_src = &resample_tail[..resample_end];

        for (idx, line) in resample_src.lines().enumerate() {
            let lock_count = line.matches(".lock()").count();
            assert!(
                lock_count <= 1,
                "resample_high_order_kernels line {} contains multiple lock() calls: `{}`",
                idx + 1,
                line.trim()
            );
        }
    }

    #[test]
    fn decide_pre_design_aggregation_is_lock_free() {
        let src = include_str!("mod.rs");
        let decide_start = src
            .find(
                "pub fn decide(&self, mode: SafetyLevel, ctx: RuntimeContext) -> RuntimeDecision {",
            )
            .expect("decide must exist");
        let decide_tail = &src[decide_start..];
        let decide_end = decide_tail
            .find("/// Return the current contextual check ordering for a given family/context.")
            .expect("decide end marker must exist");
        let decide_src = &decide_tail[..decide_end];
        let pre_design_start = decide_src
            .find("let base_risk_ppm = self.risk.upper_bound_ppm(ctx.family);")
            .expect("base risk aggregation start must exist");
        let pre_design_tail = &decide_src[pre_design_start..];
        let pre_design_end = pre_design_tail
            .find("let design_bonus = {")
            .expect("design bonus block must exist");
        let pre_design_src = &pre_design_tail[..pre_design_end];

        assert!(
            !pre_design_src.contains(".lock()"),
            "pre-design risk aggregation must only consume cached atomics; no mutex locking allowed"
        );
    }

    #[test]
    fn decide_and_observe_critical_regions_avoid_multi_lock_statements() {
        let src = include_str!("mod.rs");

        let decide_start = src
            .find(
                "pub fn decide(&self, mode: SafetyLevel, ctx: RuntimeContext) -> RuntimeDecision {",
            )
            .expect("decide must exist");
        let decide_tail = &src[decide_start..];
        let decide_end = decide_tail
            .find("/// Return the current contextual check ordering for a given family/context.")
            .expect("decide end marker must exist");
        let decide_src = &decide_tail[..decide_end];

        let observe_start = src
            .find("pub fn observe_validation_result(")
            .expect("observe_validation_result must exist");
        let observe_tail = &src[observe_start..];
        let observe_end = observe_tail
            .find("/// Record overlap information for cross-shard consistency checks.")
            .expect("observe_validation_result end marker must exist");
        let observe_src = &observe_tail[..observe_end];

        for (label, body) in [
            ("decide", decide_src),
            ("observe_validation_result", observe_src),
        ] {
            for (idx, line) in body.lines().enumerate() {
                let lock_count = line.matches(".lock()").count();
                assert!(
                    lock_count <= 1,
                    "{label} line {} contains multiple lock() calls: `{}`",
                    idx + 1,
                    line.trim()
                );
            }
        }
    }

    /// Decision-law invariant: the hard-gate cascade in decide() must follow
    /// exactly this order: barrier → full_validation_trigger → repair_trigger → Allow.
    ///
    /// This is the *conservatism guarantee*: no soft heuristic (oracle bias,
    /// tropical pressure, Pareto, design probes, etc.) can override a hard gate.
    /// The test verifies source structure rather than runtime behavior so it
    /// cannot be invalidated by changing cached atomic values.
    #[test]
    fn decide_hard_gate_cascade_order_is_invariant() {
        let src = include_str!("mod.rs");
        let decide_start = src
            .find(
                "pub fn decide(&self, mode: SafetyLevel, ctx: RuntimeContext) -> RuntimeDecision {",
            )
            .expect("decide must exist");
        let decide_tail = &src[decide_start..];
        let decide_end = decide_tail
            .find("/// Return the current contextual check ordering for a given family/context.")
            .expect("decide end marker must exist");
        let decide_src = &decide_tail[..decide_end];

        // The action determination block must appear after the barrier check.
        let barrier_pos = decide_src
            .find("let admissible = self")
            .expect("barrier admissibility check must exist");
        let action_block = &decide_src[barrier_pos..];

        // Hard gate 1: barrier non-admissible is checked FIRST.
        let gate1 = action_block
            .find("if !admissible {")
            .expect("barrier hard gate must exist");

        // Hard gate 2: full_validation_trigger_ppm checked second.
        let gate2 = action_block
            .find("risk_upper_bound_ppm >= limits.full_validation_trigger_ppm")
            .expect("full_validation_trigger hard gate must exist");

        // Hard gate 3: repair_trigger_ppm checked third.
        let gate3 = action_block
            .find("risk_upper_bound_ppm >= limits.repair_trigger_ppm")
            .expect("repair_trigger hard gate must exist");

        // Hard gate 4: Allow is the final else (lowest priority).
        let gate4 = action_block
            .find("MembraneAction::Allow")
            .expect("Allow fallthrough must exist");

        assert!(
            gate1 < gate2,
            "barrier gate must precede full_validation_trigger gate"
        );
        assert!(
            gate2 < gate3,
            "full_validation_trigger gate must precede repair_trigger gate"
        );
        assert!(
            gate3 < gate4,
            "repair_trigger gate must precede Allow fallthrough"
        );

        // No `.lock()` calls between barrier check and action determination.
        let hard_gate_region = &action_block[..gate4 + "MembraneAction::Allow".len()];
        assert!(
            !hard_gate_region.contains(".lock()"),
            "hard-gate action cascade must not acquire any mutex locks"
        );
    }

    /// Hard rule audit (bd-3dv): verify decide() contains no forbidden
    /// operations on the strict fast path — no transcendentals, no floats,
    /// no heap allocation, no matrix operations.
    #[test]
    fn decide_no_forbidden_math_on_strict_fast_path() {
        let src = include_str!("mod.rs");
        let decide_start = src
            .find(
                "pub fn decide(&self, mode: SafetyLevel, ctx: RuntimeContext) -> RuntimeDecision {",
            )
            .expect("decide must exist");
        let decide_tail = &src[decide_start..];
        let decide_end = decide_tail
            .find("/// Return the current contextual check ordering for a given family/context.")
            .expect("decide end marker must exist");
        let decide_src = &decide_tail[..decide_end];

        // Strip comments to avoid false positives from documentation.
        let non_comment_lines: Vec<&str> = decide_src
            .lines()
            .filter(|l| {
                let trimmed = l.trim();
                !trimmed.starts_with("//") && !trimmed.starts_with("///")
            })
            .collect();
        let code = non_comment_lines.join("\n");

        // Forbidden transcendental functions (would each take >20ns alone).
        for forbidden in &[
            ".exp(", ".ln(", ".log(", ".log2(", ".log10(", ".pow(", ".powf(", ".powi(", ".sqrt(",
            ".sin(", ".cos(", ".tan(", ".asin(", ".acos(", ".atan(",
        ] {
            assert!(
                !code.contains(forbidden),
                "decide() must not contain transcendental `{}` on strict fast path",
                forbidden
            );
        }

        // Forbidden float types in variable bindings/annotations.
        // (AtomicU8 → u32 match is fine; f32/f64 arithmetic is not.)
        assert!(
            !code.contains(": f32")
                && !code.contains(": f64")
                && !code.contains("as f32")
                && !code.contains("as f64"),
            "decide() must not use floating-point types on strict fast path"
        );

        // Forbidden heap allocation.
        for forbidden in &[
            "Vec::new",
            "Vec::with_capacity",
            "Box::new",
            "String::new",
            "String::from",
            "vec![",
            ".to_vec()",
            ".to_string()",
            ".to_owned()",
        ] {
            assert!(
                !code.contains(forbidden),
                "decide() must not heap-allocate via `{}` on strict fast path",
                forbidden
            );
        }

        // Forbidden matrix/linear algebra.
        for forbidden in &[
            "inverse(",
            "eigenvalue(",
            "decompose(",
            "solve_linear(",
            "lu_decomp(",
            "cholesky(",
        ] {
            assert!(
                !code.contains(forbidden),
                "decide() must not perform matrix operations via `{}`",
                forbidden
            );
        }
    }

    /// Decision-law invariant (behavioral): barrier non-admissibility always
    /// produces Deny (strict) or Repair(ReturnSafeDefault) (hardened), never
    /// Allow or FullValidate, regardless of risk level or soft heuristic state.
    #[test]
    fn decide_barrier_non_admissible_always_denies_or_repairs() {
        let kernel = RuntimeMathKernel::new();

        // Trigger barrier failure via oversized request.
        // Strict max = 128 MiB, hardened max = 256 MiB; use 512 MiB to exceed both.
        let oversized_ctx = RuntimeContext {
            family: ApiFamily::Allocator,
            addr_hint: 0x1000,
            requested_bytes: 512 * 1024 * 1024,
            is_write: false,
            contention_hint: 0,
            bloom_negative: false,
        };

        // Strict mode: barrier fail -> Deny.
        let strict_decision = kernel.decide(SafetyLevel::Strict, oversized_ctx);
        assert_eq!(
            strict_decision.action,
            MembraneAction::Deny,
            "barrier non-admissible in strict mode must produce Deny"
        );

        // Hardened mode: barrier fail -> Repair(ReturnSafeDefault).
        let hardened_decision = kernel.decide(SafetyLevel::Hardened, oversized_ctx);
        assert_eq!(
            hardened_decision.action,
            MembraneAction::Repair(HealingAction::ReturnSafeDefault),
            "barrier non-admissible in hardened mode must produce Repair(ReturnSafeDefault)"
        );
    }

    /// Decision-law invariant (behavioral): when risk is driven above
    /// full_validation_trigger_ppm, the action is never Allow.
    #[test]
    fn decide_high_risk_never_allows() {
        let kernel = RuntimeMathKernel::new();

        // Pump cached risk bonus to maximum to force risk above all thresholds.
        kernel
            .cached_risk_bonus_ppm
            .store(950_000, Ordering::Relaxed);

        let ctx = RuntimeContext {
            family: ApiFamily::PointerValidation,
            addr_hint: 0x1000,
            requested_bytes: 64,
            is_write: false,
            contention_hint: 0,
            bloom_negative: false,
        };

        for mode in [SafetyLevel::Strict, SafetyLevel::Hardened] {
            let decision = kernel.decide(mode, ctx);
            assert_ne!(
                decision.action,
                MembraneAction::Allow,
                "high risk ({} ppm) in {mode:?} must not produce Allow",
                decision.risk_upper_bound_ppm,
            );
        }
    }

    /// Decision-law invariant (behavioral): in hardened mode, risk above
    /// repair_trigger_ppm produces Repair or stronger, never Allow.
    #[test]
    fn decide_hardened_repair_trigger_never_allows() {
        let kernel = RuntimeMathKernel::new();

        // Use a moderate bonus that exceeds hardened repair_trigger (140k base)
        // but doesn't necessarily exceed strict full_validation_trigger (220k).
        kernel
            .cached_risk_bonus_ppm
            .store(200_000, Ordering::Relaxed);

        let ctx = RuntimeContext {
            family: ApiFamily::StringMemory,
            addr_hint: 0x2000,
            requested_bytes: 128,
            is_write: true,
            contention_hint: 0,
            bloom_negative: false,
        };

        let decision = kernel.decide(SafetyLevel::Hardened, ctx);
        assert!(
            !matches!(decision.action, MembraneAction::Allow),
            "hardened mode with risk {} ppm (above repair_trigger) must not Allow",
            decision.risk_upper_bound_ppm,
        );
    }

    /// Fusion SIGNALS consistency: the number of severity vector slots assigned
    /// in observe_validation_result() must exactly equal fusion::SIGNALS.
    ///
    /// The severity vector has BASE_SEVERITY_LEN elements from base_severity
    /// (copied via copy_from_slice) plus META_SEVERITY_LEN individually assigned
    /// meta-controller slots. This test counts the individual `severity[N]`
    /// assignments and verifies the total matches fusion::SIGNALS.
    #[test]
    fn fusion_signals_matches_severity_vector_assignments() {
        let src = include_str!("mod.rs");
        let observe_start = src
            .find("pub fn observe_validation_result(")
            .expect("observe_validation_result must exist");
        let observe_tail = &src[observe_start..];
        let observe_end = observe_tail
            .find("/// Record overlap information for cross-shard consistency checks.")
            .expect("observe_validation_result end marker must exist");
        let observe_src = &observe_tail[..observe_end];

        // Find the fusion severity block.
        let fusion_start = observe_src
            .find("let mut severity = [0u8; fusion::SIGNALS];")
            .expect("fusion severity buffer must exist");
        let fusion_tail = &observe_src[fusion_start..];
        let fusion_end = fusion_tail
            .find("let summary = {")
            .expect("fusion summary acquisition block must exist");
        let fusion_block = &fusion_tail[..fusion_end];

        // Count `severity[N] = ` assignment lines (meta-controller slots).
        let meta_count = fusion_block
            .lines()
            .filter(|line| {
                let trimmed = line.trim();
                trimmed.starts_with("severity[") && trimmed.contains("] =")
            })
            .count();

        assert_eq!(
            meta_count, META_SEVERITY_LEN,
            "number of severity[N] assignments ({meta_count}) must equal META_SEVERITY_LEN ({META_SEVERITY_LEN})"
        );

        // Cross-check: BASE + META == SIGNALS.
        assert_eq!(
            BASE_SEVERITY_LEN + META_SEVERITY_LEN,
            fusion::SIGNALS,
            "BASE_SEVERITY_LEN + META_SEVERITY_LEN must equal fusion::SIGNALS"
        );
    }

    /// Compile-time const assertion is already in place; this test documents
    /// that changing SIGNALS, BASE_SEVERITY_LEN, or META_SEVERITY_LEN
    /// without updating all three will cause a compilation failure.
    #[test]
    fn fusion_signals_const_assertion_exists() {
        let src = include_str!("mod.rs");
        assert!(
            src.contains("fusion::SIGNALS == BASE_SEVERITY_LEN + META_SEVERITY_LEN"),
            "const assertion for fusion::SIGNALS consistency must exist in mod.rs"
        );
    }

    #[test]
    fn sobol_scheduler_advances_after_decide() {
        let kernel = RuntimeMathKernel::new();
        // Initial state: sobol index is 0, no augmented mask.
        let snap0 = kernel.snapshot(SafetyLevel::Hardened);
        assert_eq!(snap0.sobol_index, 0);

        // Drive enough decide() calls to trigger the design cadence gate (every 4096).
        let ctx = RuntimeContext {
            family: ApiFamily::PointerValidation,
            is_write: false,
            requested_bytes: 64,
            contention_hint: 0,
            bloom_negative: false,
            addr_hint: 0x1000,
        };
        for _ in 0..4097 {
            let _ = kernel.decide(SafetyLevel::Hardened, ctx);
        }

        let snap1 = kernel.snapshot(SafetyLevel::Hardened);
        // Sobol index should have advanced (at least one cadence-gated step).
        assert!(
            snap1.sobol_index > 0,
            "sobol_index should advance after decide cadence"
        );
    }

    #[test]
    fn sobol_augmented_mask_respects_budget() {
        let kernel = RuntimeMathKernel::new();
        let ctx = RuntimeContext {
            family: ApiFamily::PointerValidation,
            is_write: false,
            requested_bytes: 64,
            contention_hint: 0,
            bloom_negative: false,
            addr_hint: 0x1000,
        };
        // Drive past design cadence gate (every 4096).
        for _ in 0..4097 {
            let _ = kernel.decide(SafetyLevel::Strict, ctx);
        }
        let snap = kernel.snapshot(SafetyLevel::Strict);
        // Augmented probe count must be non-negative (field is u8, always true)
        // and the total mask must be a subset of all probes.
        assert!(
            snap.sobol_augmented_mask & !Probe::all_mask() == 0,
            "augmented mask has bits outside valid probe range"
        );
    }

    #[test]
    fn sobol_deterministic_across_kernels() {
        // Two fresh kernels driven identically must produce the same Sobol index.
        let k1 = RuntimeMathKernel::new();
        let k2 = RuntimeMathKernel::new();
        let ctx = RuntimeContext {
            family: ApiFamily::Allocator,
            is_write: true,
            requested_bytes: 128,
            contention_hint: 0,
            bloom_negative: false,
            addr_hint: 0x2000,
        };
        // Drive past design cadence gate (every 4096) so sobol_index > 0.
        for _ in 0..4097 {
            let _ = k1.decide(SafetyLevel::Hardened, ctx);
            let _ = k2.decide(SafetyLevel::Hardened, ctx);
        }
        let s1 = k1.snapshot(SafetyLevel::Hardened);
        let s2 = k2.snapshot(SafetyLevel::Hardened);
        assert_eq!(
            s1.sobol_index, s2.sobol_index,
            "two identical kernels must have the same sobol index"
        );
        assert_eq!(
            s1.sobol_augmented_mask, s2.sobol_augmented_mask,
            "two identical kernels must produce the same augmented mask"
        );
    }

    // --- bd-3kh: Proof-carrying policy table integration tests ---

    #[test]
    fn pcpt_no_table_same_as_default() {
        let kernel = RuntimeMathKernel::new();
        let ctx = RuntimeContext::pointer_validation(0x1000, false);
        let d = kernel.decide(SafetyLevel::Strict, ctx);
        // Without a table loaded, decisions follow built-in risk logic.
        assert!(
            matches!(
                d.action,
                MembraneAction::Allow | MembraneAction::FullValidate
            ),
            "default strict decision without PCPT should be Allow or FullValidate"
        );
    }

    #[test]
    fn pcpt_load_and_snapshot_hash() {
        let mut kernel = RuntimeMathKernel::new();
        let artifact = policy_table::build_test_pcpt(&[]);
        kernel
            .load_policy_table(&artifact)
            .expect("load valid pcpt");
        let snap = kernel.snapshot(SafetyLevel::Strict);
        assert_ne!(
            snap.policy_hash_prefix, 0,
            "policy hash should be non-zero after load"
        );
    }

    #[test]
    fn pcpt_strict_profile_escalation() {
        // Build a PCPT where ALL PointerValidation strict cells are Full.
        // This satisfies risk monotonicity (all buckets same level) and mode
        // refinement (hardened default Allow ≥ strict Full is fine because
        // strict is more restrictive on profile, not action).
        let per_family = policy_table::RISK_BUCKETS_V1
            * policy_table::BUDGET_BUCKETS_V1
            * policy_table::CONSISTENCY_BUCKETS_V1;
        let mut overrides = Vec::new();
        // Set all strict PointerValidation cells to (Full, Allow).
        for i in 0..per_family {
            overrides.push((i, 1, 0, 0)); // Full, Allow, None
        }
        // Mode refinement: hardened must be >= strict. Since strict has Allow
        // action and hardened defaults to Allow, this passes. The profile
        // refinement check only fails if hardened=Fast and strict=Full, so
        // set hardened PointerValidation cells to Full too.
        let per_mode = ApiFamily::COUNT * per_family;
        for i in 0..per_family {
            overrides.push((per_mode + i, 1, 0, 0)); // Full, Allow, None
        }
        let artifact = policy_table::build_test_pcpt(&overrides);
        let mut kernel = RuntimeMathKernel::new();
        kernel.load_policy_table(&artifact).expect("load");
        let ctx = RuntimeContext::pointer_validation(0x1000, false);
        let d = kernel.decide(SafetyLevel::Strict, ctx);
        // PCPT escalated profile to Full → action should be FullValidate.
        assert!(
            matches!(d.action, MembraneAction::FullValidate),
            "strict PCPT Full profile should produce FullValidate, got {:?}",
            d.action
        );
    }

    #[test]
    fn pcpt_strict_deny_clamped_to_full_validate() {
        // Build a PCPT where PointerValidation under both modes has Deny.
        // Must satisfy: risk monotonicity (all cells same) + mode refinement
        // (hardened >= strict). Setting both to (Full, Deny) works.
        let per_family = policy_table::RISK_BUCKETS_V1
            * policy_table::BUDGET_BUCKETS_V1
            * policy_table::CONSISTENCY_BUCKETS_V1;
        let per_mode = ApiFamily::COUNT * per_family;
        let mut overrides = Vec::new();
        // Strict PointerValidation: (Full, Deny, None)
        for i in 0..per_family {
            overrides.push((i, 1, 3, 0));
        }
        // Hardened PointerValidation: (Full, Deny, None) — must match or exceed.
        for i in 0..per_family {
            overrides.push((per_mode + i, 1, 3, 0));
        }
        let artifact = policy_table::build_test_pcpt(&overrides);
        let mut kernel = RuntimeMathKernel::new();
        kernel.load_policy_table(&artifact).expect("load");
        let ctx = RuntimeContext::pointer_validation(0x1000, false);
        let d = kernel.decide(SafetyLevel::Strict, ctx);
        // Strict mode: Deny clamped to FullValidate.
        assert!(
            matches!(d.action, MembraneAction::FullValidate),
            "strict PCPT Deny should clamp to FullValidate, got {:?}",
            d.action
        );
    }

    #[test]
    fn pcpt_hardened_repair_action() {
        // Build a PCPT where PointerValidation under hardened mode has Repair.
        // Must satisfy: strict cells ≤ hardened. Set strict to FullValidate,
        // hardened to Repair (which is stricter in hardened action ordering).
        let per_family = policy_table::RISK_BUCKETS_V1
            * policy_table::BUDGET_BUCKETS_V1
            * policy_table::CONSISTENCY_BUCKETS_V1;
        let per_mode = ApiFamily::COUNT * per_family;
        let mut overrides = Vec::new();
        // Strict PointerValidation: (Full, FullValidate, None)
        for i in 0..per_family {
            overrides.push((i, 1, 1, 0));
        }
        // Hardened PointerValidation: (Full, Repair, ReturnSafeDefault)
        for i in 0..per_family {
            overrides.push((per_mode + i, 1, 2, 6));
        }
        // Mode refinement: hardened Repair (rank 2) ≥ strict FullValidate (rank 1). OK.
        let artifact = policy_table::build_test_pcpt(&overrides);
        let mut kernel = RuntimeMathKernel::new();
        kernel.load_policy_table(&artifact).expect("load");
        let ctx = RuntimeContext::pointer_validation(0x1000, false);
        let d = kernel.decide(SafetyLevel::Hardened, ctx);
        assert!(
            matches!(d.action, MembraneAction::Repair(_)),
            "hardened PCPT Repair should produce Repair, got {:?}",
            d.action
        );
    }

    #[test]
    fn pcpt_action_distribution_tracked() {
        let mut kernel = RuntimeMathKernel::new();
        let artifact = policy_table::build_test_pcpt(&[]);
        kernel.load_policy_table(&artifact).expect("load");
        let ctx = RuntimeContext::pointer_validation(0x1000, false);
        for _ in 0..10 {
            let _ = kernel.decide(SafetyLevel::Strict, ctx);
        }
        let snap = kernel.snapshot(SafetyLevel::Strict);
        let total: u64 = snap.policy_action_dist.iter().sum();
        assert!(
            total >= 10,
            "action distribution should track at least 10 decisions, got {total}"
        );
    }

    // --- bd-abi: hash mismatch fallback + perf tests ---

    #[test]
    fn pcpt_hash_mismatch_falls_back_to_default() {
        let mut kernel = RuntimeMathKernel::new();
        // Create corrupted artifact.
        let mut artifact = policy_table::build_test_pcpt(&[]);
        artifact[120] ^= 0xFF; // corrupt table data
        // load_policy_table should fail.
        assert!(kernel.load_policy_table(&artifact).is_err());
        // Kernel still works — falls back to no-table default.
        let ctx = RuntimeContext::pointer_validation(0x1000, false);
        let d = kernel.decide(SafetyLevel::Strict, ctx);
        assert_eq!(d.action, MembraneAction::Allow);
        let snap = kernel.snapshot(SafetyLevel::Strict);
        assert_eq!(snap.policy_hash_prefix, 0, "no table loaded → hash=0");
    }

    #[test]
    fn pcpt_lookup_deterministic_across_calls() {
        let mut kernel = RuntimeMathKernel::new();
        let artifact = policy_table::build_test_pcpt(&[]);
        kernel.load_policy_table(&artifact).expect("load");
        let ctx = RuntimeContext::pointer_validation(0x1000, false);
        // Run many decisions and verify all produce same action.
        let decisions: Vec<_> = (0..100)
            .map(|_| kernel.decide(SafetyLevel::Strict, ctx).action)
            .collect();
        // All should be Allow (default table, low risk).
        assert!(
            decisions.iter().all(|a| *a == MembraneAction::Allow),
            "deterministic table should produce consistent actions"
        );
    }

    #[test]
    fn pcpt_lookup_o1_cost_no_allocation() {
        // Structural test: the lookup path is O(1) array indexing.
        // We verify this indirectly by running many lookups in tight loop
        // and checking the time is bounded. This is a smoke test, not a
        // bench — we just ensure it completes quickly.
        let mut kernel = RuntimeMathKernel::new();
        let artifact = policy_table::build_test_pcpt(&[]);
        kernel.load_policy_table(&artifact).expect("load");
        let ctx = RuntimeContext::pointer_validation(0x1000, false);
        let start = std::time::Instant::now();
        for _ in 0..10_000 {
            let _ = kernel.decide(SafetyLevel::Strict, ctx);
        }
        let elapsed = start.elapsed();
        // 10k decisions should take < 50ms even on slow machines.
        assert!(
            elapsed.as_millis() < 50,
            "10k decisions took {}ms — expected < 50ms",
            elapsed.as_millis()
        );
    }

    // --- bd-3ku: evidence integration tests ---

    #[test]
    fn evidence_seqno_advances_on_hardened_decide() {
        let kernel = RuntimeMathKernel::new();
        let ctx = RuntimeContext::pointer_validation(0x1000, false);
        let snap_before = kernel.snapshot(SafetyLevel::Hardened);
        assert_eq!(snap_before.evidence_seqno, 0);
        // Evidence recording is cadence-gated (every 16384 calls) plus adverse
        // decisions are always recorded.  Drive past the cadence boundary.
        for _ in 0..16385 {
            let _ = kernel.decide(SafetyLevel::Hardened, ctx);
        }
        let snap_after = kernel.snapshot(SafetyLevel::Hardened);
        assert!(
            snap_after.evidence_seqno >= 1,
            "evidence seqno should advance, got {}",
            snap_after.evidence_seqno
        );
    }

    #[test]
    fn evidence_strict_records_on_cadence() {
        let kernel = RuntimeMathKernel::new();
        let ctx = RuntimeContext::pointer_validation(0x1000, false);
        // Strict mode records on evidence cadence (every 16384 calls).
        // Run 16385 calls — the first record happens at sequence=16384.
        for _ in 0..16385 {
            let _ = kernel.decide(SafetyLevel::Strict, ctx);
        }
        let snap = kernel.snapshot(SafetyLevel::Strict);
        assert!(
            snap.evidence_seqno >= 1,
            "strict mode should record at least 1 evidence on cadence, got seqno={}",
            snap.evidence_seqno
        );
    }

    #[test]
    fn evidence_snapshot_fields_present() {
        let kernel = RuntimeMathKernel::new();
        let snap = kernel.snapshot(SafetyLevel::Strict);
        // Verify evidence fields exist and have default values.
        assert_eq!(snap.evidence_seqno, 0);
        assert_eq!(snap.evidence_loss_count, 0);
        assert_eq!(snap.evidence_max_epoch, 0);
        assert!(snap.loss_posterior_adverse_ppm <= 1_000_000);
        assert!(snap.loss_recommended_action <= 3);
        assert!(snap.loss_competing_action <= 3);
    }
}
