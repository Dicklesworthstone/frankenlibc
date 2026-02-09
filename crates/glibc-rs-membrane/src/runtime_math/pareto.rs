//! Latency-risk Pareto controller with online regret accounting.
//!
//! This kernel keeps a lightweight empirical frontier per API family over two
//! arms (`Fast`, `Full`) and selects the profile that minimizes a
//! mode-dependent objective:
//!
//! `L = w_latency(mode) * latency_norm + w_risk(mode) * risk_norm`
//!
//! Regret is tracked online as:
//!
//! `regret_t = max(0, realized_loss(chosen) - estimated_loss(counterfactual))`
//!
//! The counterfactual is estimated from the opposite arm's empirical moments.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::config::SafetyLevel;

use super::{ApiFamily, ValidationProfile};

const ARM_COUNT: usize = 2;
const ARM_FAST: usize = 0;
const ARM_FULL: usize = 1;

const FULL_BUDGET_NS: u64 = 200;
const FAST_LATENCY_PRIOR_NS: u64 = 12;
const FULL_LATENCY_PRIOR_NS: u64 = 70;
const REGRET_HYSTERESIS_MILLI: u64 = 25;

// Per-family max cumulative regret budgets (milli-units).
// These are intentionally tighter in hardened mode.
const STRICT_REGRET_CAP_MILLI: [u64; ApiFamily::COUNT] = [
    240_000, // PointerValidation
    180_000, // Allocator
    220_000, // StringMemory
    220_000, // Stdio
    200_000, // Threading
    200_000, // Resolver
    220_000, // MathFenv
    200_000, // Loader
];
const HARDENED_REGRET_CAP_MILLI: [u64; ApiFamily::COUNT] = [
    140_000, // PointerValidation
    90_000,  // Allocator
    120_000, // StringMemory
    120_000, // Stdio
    110_000, // Threading
    110_000, // Resolver
    120_000, // MathFenv
    110_000, // Loader
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ArmMoments {
    pulls: u64,
    mean_latency_ns: u64,
    adverse_ppm: u32,
}

/// Runtime Pareto policy with explicit regret tracking.
pub struct ParetoController {
    pulls: [AtomicU64; ApiFamily::COUNT * ARM_COUNT],
    latency_sum_ns: [AtomicU64; ApiFamily::COUNT * ARM_COUNT],
    adverse_count: [AtomicU64; ApiFamily::COUNT * ARM_COUNT],
    cumulative_regret_milli: [AtomicU64; ApiFamily::COUNT],
    cap_enforcements: [AtomicU64; ApiFamily::COUNT],
}

impl ParetoController {
    #[must_use]
    pub fn new() -> Self {
        Self {
            pulls: std::array::from_fn(|_| AtomicU64::new(0)),
            latency_sum_ns: std::array::from_fn(|_| AtomicU64::new(0)),
            adverse_count: std::array::from_fn(|_| AtomicU64::new(0)),
            cumulative_regret_milli: std::array::from_fn(|_| AtomicU64::new(0)),
            cap_enforcements: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }

    /// Recommend `Fast` vs `Full` from the current Pareto envelope.
    #[must_use]
    pub fn recommend_profile(
        &self,
        mode: SafetyLevel,
        family: ApiFamily,
        risk_upper_bound_ppm: u32,
        full_validation_trigger_ppm: u32,
        repair_trigger_ppm: u32,
    ) -> ValidationProfile {
        if matches!(mode, SafetyLevel::Off) {
            return ValidationProfile::Fast;
        }
        // Hard safety gates first.
        if risk_upper_bound_ppm >= full_validation_trigger_ppm {
            return ValidationProfile::Full;
        }
        if mode.heals_enabled() && risk_upper_bound_ppm >= repair_trigger_ppm / 2 {
            return ValidationProfile::Full;
        }

        if self.is_budget_exhausted(mode, family) {
            self.cap_enforcements[usize::from(family as u8)].fetch_add(1, Ordering::Relaxed);
            return self.best_empirical_profile(mode, family, risk_upper_bound_ppm);
        }

        let fast = self.estimated_arm(family, ValidationProfile::Fast, risk_upper_bound_ppm);
        let full = self.estimated_arm(family, ValidationProfile::Full, risk_upper_bound_ppm);

        let fast_loss = objective_milli(mode, fast.mean_latency_ns, fast.adverse_ppm);
        let full_loss = objective_milli(mode, full.mean_latency_ns, full.adverse_ppm);

        // Small hysteresis avoids flip-flop near ties.
        if full_loss + REGRET_HYSTERESIS_MILLI < fast_loss {
            ValidationProfile::Full
        } else {
            ValidationProfile::Fast
        }
    }

    /// Observe chosen-arm outcome and update cumulative regret.
    pub fn observe(
        &self,
        mode: SafetyLevel,
        family: ApiFamily,
        chosen: ValidationProfile,
        latency_ns: u64,
        adverse: bool,
        risk_upper_bound_ppm: u32,
    ) {
        let family_idx = usize::from(family as u8);
        let chosen_slot = slot(family_idx, arm(chosen));
        let other_profile = other_profile(chosen);

        // Counterfactual estimate before updating chosen arm.
        let counter = self.estimated_arm(family, other_profile, risk_upper_bound_ppm);
        let counter_loss = objective_milli(mode, counter.mean_latency_ns, counter.adverse_ppm);

        self.pulls[chosen_slot].fetch_add(1, Ordering::Relaxed);
        self.latency_sum_ns[chosen_slot].fetch_add(latency_ns, Ordering::Relaxed);
        if adverse {
            self.adverse_count[chosen_slot].fetch_add(1, Ordering::Relaxed);
        }

        let realized_risk_ppm = if adverse { 1_000_000 } else { 0 };
        let realized_loss = objective_milli(mode, latency_ns, realized_risk_ppm);
        let regret = realized_loss.saturating_sub(counter_loss);

        let cap = regret_cap_milli(mode, family);
        let prev = self.cumulative_regret_milli[family_idx].load(Ordering::Relaxed);
        let residual = cap.saturating_sub(prev);
        let charged = regret.min(residual);
        self.cumulative_regret_milli[family_idx].fetch_add(charged, Ordering::Relaxed);

        if charged < regret {
            self.cap_enforcements[family_idx].fetch_add(1, Ordering::Relaxed);
        }
    }

    #[must_use]
    pub fn cumulative_regret_milli(&self) -> u64 {
        let mut total = 0u64;
        for r in &self.cumulative_regret_milli {
            total = total.saturating_add(r.load(Ordering::Relaxed));
        }
        total
    }

    #[must_use]
    pub fn cap_enforcement_count(&self) -> u64 {
        let mut total = 0u64;
        for c in &self.cap_enforcements {
            total = total.saturating_add(c.load(Ordering::Relaxed));
        }
        total
    }

    #[must_use]
    pub fn exhausted_family_count(&self, mode: SafetyLevel) -> u32 {
        let mut exhausted = 0u32;
        for idx in 0..ApiFamily::COUNT {
            let family = family_from_index(idx);
            let cap = regret_cap_milli(mode, family);
            let current = self.cumulative_regret_milli[idx].load(Ordering::Relaxed);
            if current >= cap {
                exhausted += 1;
            }
        }
        exhausted
    }

    #[must_use]
    pub fn is_budget_exhausted(&self, mode: SafetyLevel, family: ApiFamily) -> bool {
        let idx = usize::from(family as u8);
        self.cumulative_regret_milli[idx].load(Ordering::Relaxed) >= regret_cap_milli(mode, family)
    }

    fn estimated_arm(
        &self,
        family: ApiFamily,
        profile: ValidationProfile,
        risk_upper_bound_ppm: u32,
    ) -> ArmMoments {
        let family_idx = usize::from(family as u8);
        let slot = slot(family_idx, arm(profile));
        let pulls = self.pulls[slot].load(Ordering::Relaxed);

        if pulls == 0 {
            return ArmMoments {
                pulls,
                mean_latency_ns: match profile {
                    ValidationProfile::Fast => FAST_LATENCY_PRIOR_NS,
                    ValidationProfile::Full => FULL_LATENCY_PRIOR_NS,
                },
                adverse_ppm: match profile {
                    ValidationProfile::Fast => risk_upper_bound_ppm,
                    ValidationProfile::Full => risk_upper_bound_ppm / 2,
                },
            };
        }

        let latency_sum = self.latency_sum_ns[slot].load(Ordering::Relaxed);
        let adverse = self.adverse_count[slot].load(Ordering::Relaxed);
        let mean_latency_ns = latency_sum / pulls.max(1);
        let empirical_ppm = adverse
            .saturating_mul(1_000_000)
            .saturating_div(pulls.max(1))
            .min(1_000_000) as u32;

        // Blend empirical risk with global risk envelope to avoid stale local
        // arm estimates in nonstationary bursts.
        let prior_ppm = match profile {
            ValidationProfile::Fast => risk_upper_bound_ppm,
            ValidationProfile::Full => risk_upper_bound_ppm / 2,
        };
        let adverse_ppm = ((empirical_ppm as u64 * 3 + prior_ppm as u64) / 4) as u32;

        ArmMoments {
            pulls,
            mean_latency_ns,
            adverse_ppm,
        }
    }

    fn best_empirical_profile(
        &self,
        mode: SafetyLevel,
        family: ApiFamily,
        risk_upper_bound_ppm: u32,
    ) -> ValidationProfile {
        let fast = self.estimated_arm(family, ValidationProfile::Fast, risk_upper_bound_ppm);
        let full = self.estimated_arm(family, ValidationProfile::Full, risk_upper_bound_ppm);
        let fast_loss = objective_milli(mode, fast.mean_latency_ns, fast.adverse_ppm);
        let full_loss = objective_milli(mode, full.mean_latency_ns, full.adverse_ppm);
        if full_loss <= fast_loss {
            ValidationProfile::Full
        } else {
            ValidationProfile::Fast
        }
    }
}

impl Default for ParetoController {
    fn default() -> Self {
        Self::new()
    }
}

#[inline]
const fn arm(profile: ValidationProfile) -> usize {
    match profile {
        ValidationProfile::Fast => ARM_FAST,
        ValidationProfile::Full => ARM_FULL,
    }
}

#[inline]
const fn other_profile(profile: ValidationProfile) -> ValidationProfile {
    match profile {
        ValidationProfile::Fast => ValidationProfile::Full,
        ValidationProfile::Full => ValidationProfile::Fast,
    }
}

#[inline]
const fn slot(family_idx: usize, arm: usize) -> usize {
    family_idx * ARM_COUNT + arm
}

#[inline]
fn objective_milli(mode: SafetyLevel, latency_ns: u64, adverse_ppm: u32) -> u64 {
    let (w_latency, w_risk) = match mode {
        // Strict prioritizes ABI-compatible low overhead while still accounting
        // for risk.
        SafetyLevel::Strict => (750u64, 250u64),
        // Hardened prioritizes risk suppression.
        SafetyLevel::Hardened => (250u64, 750u64),
        SafetyLevel::Off => (1000u64, 0u64),
    };

    let latency_norm_ppm = latency_ns
        .saturating_mul(1_000_000)
        .saturating_div(FULL_BUDGET_NS)
        .min(2_000_000);
    let risk_norm_ppm = u64::from(adverse_ppm.min(1_000_000));

    // Weighted ppm, then convert to milli-units for compact regret accounting.
    let weighted_ppm =
        (w_latency.saturating_mul(latency_norm_ppm) + w_risk.saturating_mul(risk_norm_ppm)) / 1000;
    weighted_ppm / 1000
}

#[inline]
const fn regret_cap_milli(mode: SafetyLevel, family: ApiFamily) -> u64 {
    let idx = family as usize;
    match mode {
        SafetyLevel::Strict => STRICT_REGRET_CAP_MILLI[idx],
        SafetyLevel::Hardened => HARDENED_REGRET_CAP_MILLI[idx],
        SafetyLevel::Off => u64::MAX,
    }
}

const fn family_from_index(index: usize) -> ApiFamily {
    match index {
        0 => ApiFamily::PointerValidation,
        1 => ApiFamily::Allocator,
        2 => ApiFamily::StringMemory,
        3 => ApiFamily::Stdio,
        4 => ApiFamily::Threading,
        5 => ApiFamily::Resolver,
        6 => ApiFamily::MathFenv,
        _ => ApiFamily::Loader,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_prefers_fast_on_low_risk_low_latency_history() {
        let pareto = ParetoController::new();
        for _ in 0..64 {
            pareto.observe(
                SafetyLevel::Strict,
                ApiFamily::PointerValidation,
                ValidationProfile::Fast,
                8,
                false,
                20_000,
            );
            pareto.observe(
                SafetyLevel::Strict,
                ApiFamily::PointerValidation,
                ValidationProfile::Full,
                85,
                false,
                20_000,
            );
        }
        let p = pareto.recommend_profile(
            SafetyLevel::Strict,
            ApiFamily::PointerValidation,
            20_000,
            220_000,
            1_000_000,
        );
        assert_eq!(p, ValidationProfile::Fast);
    }

    #[test]
    fn hardened_prefers_full_on_elevated_risk() {
        let pareto = ParetoController::new();
        let p = pareto.recommend_profile(
            SafetyLevel::Hardened,
            ApiFamily::Allocator,
            200_000,
            120_000,
            140_000,
        );
        assert_eq!(p, ValidationProfile::Full);
    }

    #[test]
    fn regret_accumulates_for_bad_choice() {
        let pareto = ParetoController::new();
        pareto.observe(
            SafetyLevel::Strict,
            ApiFamily::StringMemory,
            ValidationProfile::Fast,
            500,
            true,
            40_000,
        );
        assert!(pareto.cumulative_regret_milli() > 0);
    }

    #[test]
    fn regret_saturates_at_cap() {
        let pareto = ParetoController::new();
        let family = ApiFamily::Allocator;
        let cap = regret_cap_milli(SafetyLevel::Strict, family);
        for _ in 0..10_000 {
            pareto.observe(
                SafetyLevel::Strict,
                family,
                ValidationProfile::Fast,
                10_000,
                true,
                20_000,
            );
        }
        assert!(pareto.cumulative_regret_milli() >= cap);
        assert!(pareto.is_budget_exhausted(SafetyLevel::Strict, family));
    }

    #[test]
    fn budget_enforcement_count_increases_when_saturated() {
        let pareto = ParetoController::new();
        let family = ApiFamily::Threading;
        for _ in 0..20_000 {
            pareto.observe(
                SafetyLevel::Hardened,
                family,
                ValidationProfile::Fast,
                20_000,
                true,
                100_000,
            );
        }
        assert!(pareto.cap_enforcement_count() > 0);
        assert!(pareto.exhausted_family_count(SafetyLevel::Hardened) >= 1);
    }
}
