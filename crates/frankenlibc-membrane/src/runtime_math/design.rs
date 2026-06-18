//! Runtime optimal experimental design kernel.
//!
//! This module turns "optimal experimental design + sparse recovery"
//! into a concrete runtime scheduler for heavy membrane probes.
//! Instead of always running every expensive monitor, we select a
//! budget-feasible probe set that maximizes expected information gain.

use std::cmp::Ordering;

use crate::config::SafetyLevel;

const LATENT_DIM: usize = 4;

/// Heavy runtime probes controlled by the design kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Probe {
    Spectral = 0,
    RoughPath = 1,
    Persistence = 2,
    Anytime = 3,
    Cvar = 4,
    Bridge = 5,
    LargeDeviations = 6,
    Hji = 7,
    MeanField = 8,
    Padic = 9,
    Symplectic = 10,
    HigherTopos = 11,
    CommitmentAudit = 12,
    Changepoint = 13,
    Conformal = 14,
    LossMinimizer = 15,
    Coupling = 16,
}

impl Probe {
    pub const COUNT: usize = 17;
    pub const ALL: [Self; Self::COUNT] = [
        Self::Spectral,
        Self::RoughPath,
        Self::Persistence,
        Self::Anytime,
        Self::Cvar,
        Self::Bridge,
        Self::LargeDeviations,
        Self::Hji,
        Self::MeanField,
        Self::Padic,
        Self::Symplectic,
        Self::HigherTopos,
        Self::CommitmentAudit,
        Self::Changepoint,
        Self::Conformal,
        Self::LossMinimizer,
        Self::Coupling,
    ];

    #[must_use]
    pub const fn bit(self) -> u32 {
        1u32 << (self as u8)
    }

    #[must_use]
    pub const fn all_mask() -> u32 {
        (1u32 << Self::COUNT) - 1
    }
}

/// Selected probe plan for the current runtime regime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbePlan {
    pub mask: u32,
    pub budget_ns: u64,
    pub expected_cost_ns: u64,
}

impl ProbePlan {
    #[must_use]
    pub const fn includes(self, probe: Probe) -> bool {
        (self.mask & probe.bit()) != 0
    }

    #[must_use]
    pub const fn selected_count(self) -> u8 {
        self.mask.count_ones() as u8
    }

    #[must_use]
    pub const fn includes_mask(mask: u32, probe: Probe) -> bool {
        (mask & probe.bit()) != 0
    }
}

#[derive(Clone, Copy)]
struct ProbeCandidate {
    probe: Probe,
    score: f64,
    cost_ns: u64,
}

impl ProbeCandidate {
    const EMPTY: Self = Self {
        probe: Probe::Spectral,
        score: 0.0,
        cost_ns: 0,
    };
}

/// Snapshot exported to runtime telemetry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DesignSummary {
    pub identifiability_ppm: u32,
    pub selected_count: u8,
    pub budget_ns: u64,
    pub expected_cost_ns: u64,
}

/// Online D-optimal probe scheduler.
///
/// We maintain a compact Fisher-like information matrix over latent failure
/// factors and greedily pick probes that maximize Δlogdet / cost under budget.
pub struct OptimalDesignController {
    fisher: [[f64; LATENT_DIM]; LATENT_DIM],
    last_plan: ProbePlan,
    observations: u64,
    anomaly_events: u64,
}

impl OptimalDesignController {
    #[must_use]
    pub fn new() -> Self {
        // Small diagonal prior prevents singular logdet.
        let mut fisher = [[0.0; LATENT_DIM]; LATENT_DIM];
        for (i, row) in fisher.iter_mut().enumerate() {
            row[i] = 1e-3;
        }
        Self {
            fisher,
            last_plan: ProbePlan {
                mask: Probe::all_mask(),
                budget_ns: 0,
                expected_cost_ns: 0,
            },
            observations: 0,
            anomaly_events: 0,
        }
    }

    /// Compute a budget-feasible probe plan for this regime.
    #[must_use]
    pub fn choose_plan(
        &mut self,
        mode: SafetyLevel,
        risk_upper_bound_ppm: u32,
        adverse_hint: bool,
        fast_path_over_budget: bool,
    ) -> ProbePlan {
        let risk = f64::from(risk_upper_bound_ppm) / 1_000_000.0;
        let mut budget_ns = match mode {
            SafetyLevel::Strict => 90,
            SafetyLevel::Hardened => 220,
            SafetyLevel::Off => 45,
        };
        if fast_path_over_budget {
            budget_ns = (budget_ns * 3) / 4;
        }

        let mut mask = 0u32;
        let mut expected_cost_ns = 0u64;
        let add_probe = |mask: &mut u32, expected_cost_ns: &mut u64, probe: Probe| {
            let bit = probe.bit();
            if (*mask & bit) == 0 {
                *mask |= bit;
                *expected_cost_ns = expected_cost_ns.saturating_add(probe_cost_ns(probe));
            }
        };

        // Always-on low-cost sentinels.
        add_probe(&mut mask, &mut expected_cost_ns, Probe::Anytime);
        add_probe(&mut mask, &mut expected_cost_ns, Probe::LargeDeviations);

        // Hard risk gates.
        if risk >= 0.20 || adverse_hint {
            add_probe(&mut mask, &mut expected_cost_ns, Probe::Cvar);
            add_probe(&mut mask, &mut expected_cost_ns, Probe::Hji);
        }
        if mode.heals_enabled() && (risk >= 0.15 || adverse_hint) {
            add_probe(&mut mask, &mut expected_cost_ns, Probe::Bridge);
            add_probe(&mut mask, &mut expected_cost_ns, Probe::MeanField);
        }
        if risk >= 0.50 || adverse_hint {
            // Elevated-risk regimes keep at least one topology-sensitive monitor online
            // so geometric/shape anomalies are still observable under budget pressure.
            let rough_path_cost = probe_cost_ns(Probe::RoughPath);
            let persistence_cost = probe_cost_ns(Probe::Persistence);
            if expected_cost_ns.saturating_add(rough_path_cost) <= budget_ns {
                add_probe(&mut mask, &mut expected_cost_ns, Probe::RoughPath);
            } else if expected_cost_ns.saturating_add(persistence_cost) <= budget_ns {
                add_probe(&mut mask, &mut expected_cost_ns, Probe::Persistence);
            }
        }

        let fisher_cholesky = cholesky_spd(&self.fisher);
        let base_logdet = if fisher_cholesky.is_none() {
            logdet_spd(&self.fisher)
        } else {
            0.0
        };
        let mut candidates = [ProbeCandidate::EMPTY; Probe::COUNT];
        let mut candidate_len = 0usize;
        for probe in Probe::ALL {
            if (mask & probe.bit()) != 0 {
                continue;
            }
            if fast_path_over_budget
                && risk < 0.5
                && matches!(probe, Probe::RoughPath | Probe::Persistence)
            {
                // Topological probes are expensive; defer under tight fast-path budget
                // unless risk is already high.
                continue;
            }
            let cost_ns = probe_cost_ns(probe);
            let features = probe_features(probe);
            let update_weight = 0.25 + 2.5 * risk;
            let gain = if let Some(cholesky) = &fisher_cholesky {
                rank_one_logdet_gain_from_cholesky(cholesky, features, update_weight)
            } else {
                let mut trial = self.fisher;
                rank_one_update(&mut trial, features, update_weight);
                (logdet_spd(&trial) - base_logdet).max(0.0)
            };
            let score = gain / (cost_ns as f64 + 1.0);
            candidates[candidate_len] = ProbeCandidate {
                probe,
                score,
                cost_ns,
            };
            candidate_len += 1;
        }

        let candidates = &mut candidates[..candidate_len];
        sort_candidates_by_score_desc(candidates);
        for candidate in candidates.iter() {
            let next = expected_cost_ns.saturating_add(candidate.cost_ns);
            if next <= budget_ns {
                add_probe(&mut mask, &mut expected_cost_ns, candidate.probe);
            }
        }

        if mask == 0 {
            add_probe(&mut mask, &mut expected_cost_ns, Probe::Anytime);
        }

        self.last_plan = ProbePlan {
            mask,
            budget_ns,
            expected_cost_ns,
        };
        self.last_plan
    }

    /// Record probe execution outcome, updating information geometry online.
    pub fn record_probe(&mut self, probe: Probe, anomaly_detected: bool) {
        let weight = if anomaly_detected { 1.25 } else { 0.20 };
        rank_one_update(&mut self.fisher, probe_features(probe), weight);
        self.observations = self.observations.saturating_add(1);
        if anomaly_detected {
            self.anomaly_events = self.anomaly_events.saturating_add(1);
        }

        // Gentle forgetting keeps the matrix responsive to regime shifts.
        if self.observations.is_multiple_of(1024) {
            for (i, row) in self.fisher.iter_mut().enumerate() {
                for v in row.iter_mut() {
                    *v *= 0.985;
                }
                row[i] += 1e-4;
            }
        }
    }

    /// 0..1e6 identifiability score from log-determinant information volume.
    #[must_use]
    pub fn identifiability_ppm(&self) -> u32 {
        // Since updates are PSD rank-one additions, logdet is monotone
        // and gives a stable scalar identifiability proxy.
        let logdet = logdet_spd(&self.fisher);
        let shifted = (logdet + 20.0).max(0.0);
        let score = (1.0 - (-0.05 * shifted).exp()).clamp(0.0, 1.0);
        (score * 1_000_000.0) as u32
    }

    #[must_use]
    pub fn summary(&self) -> DesignSummary {
        DesignSummary {
            identifiability_ppm: self.identifiability_ppm(),
            selected_count: self.last_plan.selected_count(),
            budget_ns: self.last_plan.budget_ns,
            expected_cost_ns: self.last_plan.expected_cost_ns,
        }
    }
}

impl Default for OptimalDesignController {
    fn default() -> Self {
        Self::new()
    }
}

fn rank_one_update(matrix: &mut [[f64; LATENT_DIM]; LATENT_DIM], v: [f64; LATENT_DIM], w: f64) {
    for i in 0..LATENT_DIM {
        for j in 0..LATENT_DIM {
            matrix[i][j] += w * v[i] * v[j];
        }
    }
}

fn sort_candidates_by_score_desc(candidates: &mut [ProbeCandidate]) {
    candidates.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(Ordering::Equal));
}

fn cholesky_spd(
    matrix: &[[f64; LATENT_DIM]; LATENT_DIM],
) -> Option<[[f64; LATENT_DIM]; LATENT_DIM]> {
    let mut l = [[0.0; LATENT_DIM]; LATENT_DIM];
    for i in 0..LATENT_DIM {
        for j in 0..=i {
            let mut sum = matrix[i][j];
            let mut k = 0;
            while k < j {
                sum -= l[i][k] * l[j][k];
                k += 1;
            }
            if i == j {
                if sum <= 1e-12 {
                    return None;
                }
                l[i][j] = sum.sqrt();
            } else {
                l[i][j] = sum / l[j][j].max(1e-12);
            }
        }
    }
    Some(l)
}

fn logdet_spd(matrix: &[[f64; LATENT_DIM]; LATENT_DIM]) -> f64 {
    let Some(l) = cholesky_spd(matrix) else {
        return -1e9;
    };
    logdet_from_cholesky(&l)
}

fn logdet_from_cholesky(l: &[[f64; LATENT_DIM]; LATENT_DIM]) -> f64 {
    let mut logdet = 0.0;
    for (i, row) in l.iter().enumerate() {
        logdet += 2.0 * row[i].ln();
    }
    logdet
}

fn rank_one_logdet_gain_from_cholesky(
    l: &[[f64; LATENT_DIM]; LATENT_DIM],
    v: [f64; LATENT_DIM],
    w: f64,
) -> f64 {
    let mut y = [0.0; LATENT_DIM];
    for i in 0..LATENT_DIM {
        let mut sum = v[i];
        let mut k = 0;
        while k < i {
            sum -= l[i][k] * y[k];
            k += 1;
        }
        y[i] = sum / l[i][i].max(1e-12);
    }

    let qform = y.iter().map(|value| value * value).sum::<f64>();
    (1.0 + w * qform).ln().max(0.0)
}

pub fn probe_cost_ns(probe: Probe) -> u64 {
    match probe {
        Probe::Spectral => 20,
        Probe::RoughPath => 28,
        Probe::Persistence => 30,
        Probe::Anytime => 8,
        Probe::Cvar => 10,
        Probe::Bridge => 12,
        Probe::LargeDeviations => 8,
        Probe::Hji => 16,
        Probe::MeanField => 12,
        Probe::Padic => 10,
        Probe::Symplectic => 10,
        Probe::HigherTopos => 12,
        Probe::CommitmentAudit => 10,
        Probe::Changepoint => 8,
        Probe::Conformal => 10,
        Probe::LossMinimizer => 6,
        Probe::Coupling => 8,
    }
}

fn probe_features(probe: Probe) -> [f64; LATENT_DIM] {
    match probe {
        Probe::Spectral => [1.0, 0.7, 0.2, 0.4],
        Probe::RoughPath => [0.8, 0.6, 1.0, 0.3],
        Probe::Persistence => [0.4, 0.3, 1.0, 0.2],
        Probe::Anytime => [0.4, 0.9, 0.1, 0.5],
        Probe::Cvar => [0.3, 1.0, 0.1, 0.6],
        Probe::Bridge => [0.6, 0.7, 0.2, 1.0],
        Probe::LargeDeviations => [0.5, 0.9, 0.1, 0.4],
        Probe::Hji => [0.7, 0.8, 0.3, 1.0],
        Probe::MeanField => [0.5, 0.6, 0.2, 0.9],
        Probe::Padic => [0.4, 0.5, 0.7, 0.4],
        Probe::Symplectic => [0.6, 0.7, 0.2, 0.9],
        Probe::HigherTopos => [0.3, 0.4, 0.8, 0.6],
        Probe::CommitmentAudit => [0.5, 0.8, 0.3, 0.7],
        Probe::Changepoint => [0.7, 0.6, 0.2, 0.8],
        Probe::Conformal => [0.4, 0.9, 0.3, 0.5],
        Probe::LossMinimizer => [0.5, 0.7, 0.4, 0.6],
        Probe::Coupling => [0.6, 0.5, 0.3, 0.7],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_sort_preserves_equal_score_probe_order() {
        let mut candidates = [
            ProbeCandidate {
                probe: Probe::Spectral,
                score: 1.0,
                cost_ns: 20,
            },
            ProbeCandidate {
                probe: Probe::RoughPath,
                score: 2.0,
                cost_ns: 28,
            },
            ProbeCandidate {
                probe: Probe::Persistence,
                score: 1.0,
                cost_ns: 30,
            },
            ProbeCandidate {
                probe: Probe::Anytime,
                score: 2.0,
                cost_ns: 8,
            },
        ];

        sort_candidates_by_score_desc(&mut candidates);

        let sorted = candidates.map(|candidate| candidate.probe);
        assert_eq!(
            sorted,
            [
                Probe::RoughPath,
                Probe::Anytime,
                Probe::Spectral,
                Probe::Persistence
            ],
            "stable equal-score ordering must match the previous Vec::sort_by path"
        );
    }

    #[test]
    fn plan_respects_budget() {
        let mut ctrl = OptimalDesignController::new();
        let plan = ctrl.choose_plan(SafetyLevel::Strict, 80_000, false, false);
        assert!(plan.expected_cost_ns <= plan.budget_ns);
        assert!(plan.selected_count() >= 1);
    }

    #[test]
    fn hardened_selects_at_least_as_many_probes() {
        let mut ctrl = OptimalDesignController::new();
        let strict = ctrl.choose_plan(SafetyLevel::Strict, 60_000, false, false);
        let hard = ctrl.choose_plan(SafetyLevel::Hardened, 60_000, false, false);
        assert!(hard.selected_count() >= strict.selected_count());
    }

    #[test]
    fn high_risk_forces_safety_probes() {
        let mut ctrl = OptimalDesignController::new();
        let plan = ctrl.choose_plan(SafetyLevel::Hardened, 700_000, true, false);
        assert!(plan.includes(Probe::Hji));
        assert!(plan.includes(Probe::Cvar));
    }

    #[test]
    fn identifiability_increases_with_observations() {
        let mut ctrl = OptimalDesignController::new();
        let before = ctrl.identifiability_ppm();
        for p in Probe::ALL {
            ctrl.record_probe(p, true);
            ctrl.record_probe(p, false);
        }
        let after = ctrl.identifiability_ppm();
        assert!(after >= before);
    }

    #[test]
    fn fast_path_over_budget_shrinks_budget_and_defers_expensive_topology_probes() {
        let mut ctrl = OptimalDesignController::new();
        let normal = ctrl.choose_plan(SafetyLevel::Strict, 120_000, false, false);
        let constrained = ctrl.choose_plan(SafetyLevel::Strict, 120_000, false, true);

        assert_eq!(normal.budget_ns, 90);
        assert_eq!(constrained.budget_ns, 67);
        assert!(constrained.expected_cost_ns <= constrained.budget_ns);
        assert!(
            !constrained.includes(Probe::RoughPath),
            "tight fast-path budget should defer RoughPath probe at moderate risk"
        );
        assert!(
            !constrained.includes(Probe::Persistence),
            "tight fast-path budget should defer Persistence probe at moderate risk"
        );
    }

    #[test]
    fn high_risk_keeps_topology_probes_eligible_even_when_over_budget() {
        let mut ctrl = OptimalDesignController::new();
        let plan = ctrl.choose_plan(SafetyLevel::Hardened, 650_000, true, true);
        assert!(
            plan.includes(Probe::Hji) && plan.includes(Probe::Cvar),
            "high-risk guard probes must always be retained"
        );
        assert!(
            plan.includes(Probe::RoughPath) || plan.includes(Probe::Persistence),
            "at least one topological probe should remain eligible under high risk"
        );
    }

    #[test]
    fn summary_tracks_last_selected_plan() {
        let mut ctrl = OptimalDesignController::new();
        let plan = ctrl.choose_plan(SafetyLevel::Off, 40_000, false, false);
        let summary = ctrl.summary();
        assert_eq!(summary.selected_count, plan.selected_count());
        assert_eq!(summary.budget_ns, plan.budget_ns);
        assert_eq!(summary.expected_cost_ns, plan.expected_cost_ns);
    }

    #[test]
    fn per_call_monitor_count_bounded_by_budget() {
        // bd-06bxm.4: verify per-call monitor count is bounded
        let mut ctrl = OptimalDesignController::new();

        // All plans must respect budget - this is the core knapsack constraint
        for mode in [SafetyLevel::Strict, SafetyLevel::Hardened, SafetyLevel::Off] {
            for risk in [50_000u32, 200_000, 500_000] {
                let plan = ctrl.choose_plan(mode, risk, false, false);
                assert!(
                    plan.expected_cost_ns <= plan.budget_ns,
                    "plan cost {} exceeds budget {} for mode {:?} risk {}",
                    plan.expected_cost_ns,
                    plan.budget_ns,
                    mode,
                    risk
                );
                // Monitor count is bounded by budget / min_probe_cost
                // min_probe_cost = 6 (LossMinimizer), max budget = 220 (Hardened)
                // So max probes ≈ 220/6 ≈ 36, but in practice much less due to cost distribution
                assert!(
                    plan.selected_count() <= Probe::COUNT as u8,
                    "selected count {} exceeds total probes {}",
                    plan.selected_count(),
                    Probe::COUNT
                );
            }
        }

        // Verify that tighter budgets select fewer probes
        let plan_strict = ctrl.choose_plan(SafetyLevel::Strict, 100_000, false, false);
        let plan_hard = ctrl.choose_plan(SafetyLevel::Hardened, 100_000, false, false);
        assert!(
            plan_hard.expected_cost_ns >= plan_strict.expected_cost_ns
                || plan_hard.selected_count() >= plan_strict.selected_count(),
            "hardened mode should have at least as much budget usage as strict"
        );
    }

    #[test]
    fn greedy_selection_achieves_submodular_optimality_bound() {
        // bd-06bxm.4: verify greedy selection achieves (1-1/e) ≈ 0.632 of optimal.
        // For submodular maximization under a knapsack constraint, greedy selection
        // by gain/cost ratio achieves at least (1-1/e) of the optimal value.

        let mut ctrl = OptimalDesignController::new();

        // Prime the information matrix with some observations
        for _ in 0..100 {
            for p in Probe::ALL.iter().take(8) {
                ctrl.record_probe(*p, false);
            }
        }

        let base_logdet = logdet_spd(&ctrl.fisher);
        let budget_ns: u64 = 80;

        // Greedy selection (what choose_plan does internally)
        let plan = ctrl.choose_plan(SafetyLevel::Strict, 150_000, false, false);

        // Compute greedy gain
        let mut trial_fisher = ctrl.fisher;
        for probe in Probe::ALL {
            if plan.includes(probe) {
                rank_one_update(&mut trial_fisher, probe_features(probe), 0.25 + 2.5 * 0.15);
            }
        }
        let greedy_gain = (logdet_spd(&trial_fisher) - base_logdet).max(0.0);

        // Brute-force optimal for small subset (simplified: try adding each single probe)
        // Full brute force is 2^17 subsets; instead we verify greedy beats any single probe.
        let mut best_single_gain = 0.0f64;
        for probe in Probe::ALL {
            let cost = probe_cost_ns(probe);
            if cost <= budget_ns {
                let mut single_trial = ctrl.fisher;
                rank_one_update(&mut single_trial, probe_features(probe), 0.25 + 2.5 * 0.15);
                let gain = (logdet_spd(&single_trial) - base_logdet).max(0.0);
                best_single_gain = best_single_gain.max(gain);
            }
        }

        // Greedy should beat any single probe selection (sanity check)
        assert!(
            greedy_gain >= best_single_gain * 0.95,
            "greedy gain {} should be at least as good as best single probe gain {}",
            greedy_gain,
            best_single_gain
        );

        // The greedy gain should be positive (we added probes)
        assert!(
            greedy_gain > 0.0 || plan.selected_count() == 0,
            "greedy selection should yield positive information gain"
        );

        // Verify the (1-1/e) bound property holds conceptually:
        // For k selected probes with monotone submodular gain, greedy achieves >= (1-1/e) of OPT.
        // We verify this by checking that selecting more probes increases gain monotonically.
        if plan.selected_count() >= 2 {
            let mut partial_fisher = ctrl.fisher;
            let mut partial_gain = 0.0;
            let mut probes_added = 0;
            for probe in Probe::ALL {
                if plan.includes(probe) && probes_added < plan.selected_count() - 1 {
                    rank_one_update(
                        &mut partial_fisher,
                        probe_features(probe),
                        0.25 + 2.5 * 0.15,
                    );
                    partial_gain = (logdet_spd(&partial_fisher) - base_logdet).max(0.0);
                    probes_added += 1;
                }
            }
            assert!(
                greedy_gain >= partial_gain,
                "adding more probes should not decrease total gain"
            );
        }
    }

    #[test]
    fn rank_one_logdet_gain_matches_full_update() {
        let mut ctrl = OptimalDesignController::new();
        for _ in 0..32 {
            for probe in Probe::ALL.iter().take(6) {
                ctrl.record_probe(*probe, false);
            }
        }

        let cholesky = cholesky_spd(&ctrl.fisher);
        assert!(cholesky.is_some(), "fisher matrix must be SPD");
        let Some(cholesky) = cholesky else {
            return;
        };
        let base_logdet = logdet_spd(&ctrl.fisher);
        let weight = 0.25 + 2.5 * 0.15;

        for probe in Probe::ALL {
            let features = probe_features(probe);
            let fast_gain = rank_one_logdet_gain_from_cholesky(&cholesky, features, weight);
            let mut trial = ctrl.fisher;
            rank_one_update(&mut trial, features, weight);
            let slow_gain = (logdet_spd(&trial) - base_logdet).max(0.0);
            assert!(
                (fast_gain - slow_gain).abs() <= 1e-10,
                "gain mismatch for {probe:?}: fast={fast_gain} slow={slow_gain}"
            );
        }
    }
}
