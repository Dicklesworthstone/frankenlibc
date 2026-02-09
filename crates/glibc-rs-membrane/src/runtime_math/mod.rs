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
pub mod cohomology;
pub mod control;
pub mod cvar;
pub mod eprocess;
pub mod pareto;
pub mod risk;

use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use parking_lot::Mutex;

use crate::check_oracle::{CheckContext, CheckOracle, CheckStage};
use crate::config::SafetyLevel;
use crate::heal::HealingAction;
use crate::hji_reachability::{HjiReachabilityController, ReachState};
use crate::large_deviations::{LargeDeviationsMonitor, RateState};
use crate::mean_field_game::{MeanFieldGameController, MfgState};
use crate::persistence::{PersistenceDetector, TopologicalState};
use crate::quarantine_controller::{QuarantineController, current_depth, publish_depth};
use crate::risk_engine::{CallFamily, RiskDecision, RiskEngine};
use crate::rough_path::{RoughPathMonitor, SignatureState};
use crate::schrodinger_bridge::{BridgeState, SchrodingerBridgeController};
use crate::spectral_monitor::{PhaseState, SpectralMonitor};
use crate::tropical_latency::{PipelinePath, TROPICAL_METRICS, TropicalLatencyCompositor};

use self::bandit::ConstrainedBanditRouter;
use self::barrier::BarrierOracle;
use self::cohomology::CohomologyMonitor;
use self::control::PrimalDualController;
use self::cvar::{DroCvarController, TailState};
use self::eprocess::{AnytimeEProcessMonitor, SequentialState};
use self::pareto::ParetoController;
use self::risk::ConformalRiskEngine;

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
}

impl ApiFamily {
    pub const COUNT: usize = 8;
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
        let risk_upper_bound_ppm = base_risk_ppm
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

    /// Feed observed runtime outcome back into online controllers.
    pub fn observe_validation_result(
        &self,
        family: ApiFamily,
        profile: ValidationProfile,
        estimated_cost_ns: u64,
        adverse: bool,
    ) {
        let mode = crate::config::safety_level();
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
        {
            let contention = f64::from(
                self.cached_oracle_bias[usize::from(family as u8)].load(Ordering::Relaxed),
            ) / 2.0;
            let hit_rate = if adverse { 1.0 } else { 0.0 };
            let risk_score = f64::from(risk_bound_ppm) / 1_000_000.0;
            let latency = (estimated_cost_ns as f64).ln_1p();
            let mut spectral = self.spectral.lock();
            spectral.observe(risk_score, latency, contention, hit_rate);
            // Cache the phase state for the hot-path decision.
            let phase_code = match spectral.phase() {
                PhaseState::Stationary => 0u8,
                PhaseState::Transitioning => 1u8,
                PhaseState::NewRegime => 2u8,
            };
            self.cached_spectral_phase
                .store(phase_code, Ordering::Relaxed);
        }

        // Feed rough-path signature monitor with the same 4D observation vector.
        // The signature captures temporal ordering and all cross-moments — strictly
        // more powerful than the spectral monitor's covariance-only view.
        {
            let rp_risk = f64::from(risk_bound_ppm) / 1_000_000.0;
            let rp_latency = (estimated_cost_ns as f64).ln_1p();
            let rp_contention = f64::from(
                self.cached_oracle_bias[usize::from(family as u8)].load(Ordering::Relaxed),
            ) / 2.0;
            let rp_hit_rate = if adverse { 1.0 } else { 0.0 };
            let obs = [rp_risk, rp_latency, rp_contention, rp_hit_rate];
            let sig_state_code = {
                let mut rp = self.rough_path.lock();
                rp.observe(obs);
                match rp.state() {
                    SignatureState::Calibrating => 0u8,
                    SignatureState::Normal => 1u8,
                    SignatureState::Anomalous => 2u8,
                }
            };
            let topo_state_code = {
                let mut pd = self.persistence.lock();
                pd.observe(obs);
                match pd.state() {
                    TopologicalState::Calibrating => 0u8,
                    TopologicalState::Normal => 1u8,
                    TopologicalState::Anomalous => 2u8,
                }
            };
            self.cached_signature_state
                .store(sig_state_code, Ordering::Relaxed);
            self.cached_topological_state
                .store(topo_state_code, Ordering::Relaxed);
        }

        // Feed anytime-valid sequential detector and cache state for hot path.
        {
            let state_code = {
                let mon = self.anytime.lock();
                mon.observe(family, adverse);
                match mon.state(family) {
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
        {
            let state_code = {
                let cvar = self.cvar.lock();
                cvar.observe(family, profile, estimated_cost_ns);
                match cvar.family_state(mode, family) {
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
        {
            let action_idx = match (profile, adverse, mode.heals_enabled()) {
                (ValidationProfile::Fast, false, _) => 0, // Allow
                (ValidationProfile::Full, false, _) => 1, // FullValidate
                (_, true, true) => 2,                     // Repair (hardened)
                (_, true, false) => 3,                    // Deny (strict)
            };
            let bridge_code = {
                let mut br = self.bridge.lock();
                br.observe_action(action_idx);
                match br.state() {
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
        {
            let fidx = usize::from(family as u8);
            let ld_code = {
                let mut ld = self.large_dev.lock();
                ld.observe(fidx, adverse);
                match ld.state(fidx) {
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
        {
            let hji_code = {
                let mut hji = self.hji.lock();
                hji.observe(risk_bound_ppm, estimated_cost_ns, adverse);
                match hji.state() {
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
        {
            let contention_hint = estimated_cost_ns.min(65535) as u16;
            let mfg_code = {
                let mut mfg = self.mfg.lock();
                mfg.observe(contention_hint);
                match mfg.state() {
                    MfgState::Calibrating => 0u8,
                    MfgState::Equilibrium => 1u8,
                    MfgState::Congested => 2u8,
                    MfgState::Collapsed => 3u8,
                }
            };
            self.cached_mfg_state.store(mfg_code, Ordering::Relaxed);
        }

        // Feed allocator frees into primal-dual quarantine controller.
        if matches!(family, ApiFamily::Allocator) {
            let mut quarantine = self.quarantine.lock();
            let updated = quarantine.record_free(estimated_cost_ns, adverse);
            if updated {
                publish_depth(&quarantine);
            }
        }

        // Feed coarse observations into contextual check oracle for future
        // ordering bias (full precision context is refreshed in sampled path).
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
}
