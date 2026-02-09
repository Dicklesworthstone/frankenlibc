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

        let base_logdet = logdet_spd(&self.fisher);
        let mut candidates: Vec<(Probe, f64, u64)> = Vec::with_capacity(Probe::COUNT);
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
            let mut trial = self.fisher;
            rank_one_update(&mut trial, probe_features(probe), 0.25 + 2.5 * risk);
            let gain = (logdet_spd(&trial) - base_logdet).max(0.0);
            let score = gain / (cost_ns as f64 + 1.0);
            candidates.push((probe, score, cost_ns));
        }

        candidates.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(Ordering::Equal));
        for (probe, _, cost_ns) in candidates {
            let next = expected_cost_ns.saturating_add(cost_ns);
            if next <= budget_ns {
                add_probe(&mut mask, &mut expected_cost_ns, probe);
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

fn logdet_spd(matrix: &[[f64; LATENT_DIM]; LATENT_DIM]) -> f64 {
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
                    return -1e9;
                }
                l[i][j] = sum.sqrt();
            } else {
                l[i][j] = sum / l[j][j].max(1e-12);
            }
        }
    }
    let mut logdet = 0.0;
    for (i, row) in l.iter().enumerate() {
        logdet += 2.0 * row[i].ln();
    }
    logdet
}

fn probe_cost_ns(probe: Probe) -> u64 {
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
}
