//! Distributionally-robust CVaR tail controller.
//!
//! This kernel tracks latency tail behavior per API family and profile arm,
//! then computes a conservative CVaR-style envelope with a finite-sample
//! uncertainty radius. The runtime controller uses it to guard against
//! heavy-tail latency explosions while preserving low-overhead fast paths.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::config::SafetyLevel;

use super::{ApiFamily, ValidationProfile};

const ARM_COUNT: usize = 2;
const ARM_FAST: usize = 0;
const ARM_FULL: usize = 1;

const FAST_BUDGET_NS: u64 = 20;
const FULL_BUDGET_NS: u64 = 200;

const DELTA_CONFIDENCE: f64 = 0.01;
const WARMUP_CALLS: u64 = 64;

// sqrt(ln(2/delta)/2) with delta=0.01.
const RADIUS_COEFF: f64 = 1.62762363071873;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TailState {
    Calibrating,
    Normal,
    Warning,
    Alarm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TailStats {
    pulls: u64,
    tail_count: u64,
    tail_sum_ns: u64,
}

/// Runtime CVaR tail controller.
pub struct DroCvarController {
    pulls: [AtomicU64; ApiFamily::COUNT * ARM_COUNT],
    tail_count: [AtomicU64; ApiFamily::COUNT * ARM_COUNT],
    tail_sum_ns: [AtomicU64; ApiFamily::COUNT * ARM_COUNT],
}

impl DroCvarController {
    #[must_use]
    pub fn new() -> Self {
        Self {
            pulls: std::array::from_fn(|_| AtomicU64::new(0)),
            tail_count: std::array::from_fn(|_| AtomicU64::new(0)),
            tail_sum_ns: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }

    pub fn observe(&self, family: ApiFamily, profile: ValidationProfile, latency_ns: u64) {
        let idx = usize::from(family as u8);
        let slot = slot(idx, arm(profile));
        self.pulls[slot].fetch_add(1, Ordering::Relaxed);

        let threshold = profile_threshold_ns(profile);
        if latency_ns > threshold {
            self.tail_count[slot].fetch_add(1, Ordering::Relaxed);
            self.tail_sum_ns[slot].fetch_add(latency_ns, Ordering::Relaxed);
        }
    }

    #[must_use]
    pub fn family_state(&self, mode: SafetyLevel, family: ApiFamily) -> TailState {
        let idx = usize::from(family as u8);
        let fast = self.robust_cvar_stats(slot(idx, ARM_FAST), FAST_BUDGET_NS);
        let full = self.robust_cvar_stats(slot(idx, ARM_FULL), FULL_BUDGET_NS);

        let pulls = fast.pulls.saturating_add(full.pulls);
        if pulls < WARMUP_CALLS {
            return TailState::Calibrating;
        }

        let worst_ratio_permille = fast
            .ratio_permille
            .max(full.ratio_permille)
            .max(self.family_aggregate_ratio_permille(idx));

        let (warning, alarm) = match mode {
            SafetyLevel::Strict => (1_700u64, 2_600u64),
            SafetyLevel::Hardened => (1_400u64, 2_200u64),
            SafetyLevel::Off => (u64::MAX, u64::MAX),
        };

        if worst_ratio_permille >= alarm {
            TailState::Alarm
        } else if worst_ratio_permille >= warning {
            TailState::Warning
        } else {
            TailState::Normal
        }
    }

    #[must_use]
    pub fn family_robust_cvar_ns(&self, family: ApiFamily) -> u64 {
        let idx = usize::from(family as u8);
        let fast = self.robust_cvar_stats(slot(idx, ARM_FAST), FAST_BUDGET_NS);
        let full = self.robust_cvar_stats(slot(idx, ARM_FULL), FULL_BUDGET_NS);
        fast.robust_cvar_ns.max(full.robust_cvar_ns)
    }

    #[must_use]
    pub fn max_family_robust_cvar_ns(&self) -> u64 {
        let mut max_v = 0u64;
        for idx in 0..ApiFamily::COUNT {
            let fam = family_from_index(idx);
            max_v = max_v.max(self.family_robust_cvar_ns(fam));
        }
        max_v
    }

    #[must_use]
    pub fn alarmed_family_count(&self, mode: SafetyLevel) -> u32 {
        let mut count = 0u32;
        for idx in 0..ApiFamily::COUNT {
            let fam = family_from_index(idx);
            if matches!(self.family_state(mode, fam), TailState::Alarm) {
                count += 1;
            }
        }
        count
    }

    fn family_aggregate_ratio_permille(&self, family_idx: usize) -> u64 {
        let fast = self.load_stats(slot(family_idx, ARM_FAST));
        let full = self.load_stats(slot(family_idx, ARM_FULL));
        let pulls = fast.pulls.saturating_add(full.pulls);
        if pulls == 0 {
            return 1_000;
        }

        let weighted_budget = FAST_BUDGET_NS
            .saturating_mul(fast.pulls)
            .saturating_add(FULL_BUDGET_NS.saturating_mul(full.pulls))
            / pulls.max(1);

        let tail_count = fast.tail_count.saturating_add(full.tail_count);
        let tail_sum = fast.tail_sum_ns.saturating_add(full.tail_sum_ns);
        let empirical = if tail_count > 0 {
            tail_sum / tail_count.max(1)
        } else {
            weighted_budget
        };

        let radius = uncertainty_radius_ns(pulls, weighted_budget);
        let robust = empirical.saturating_add(radius);
        robust
            .saturating_mul(1_000)
            .saturating_div(weighted_budget.max(1))
    }

    fn robust_cvar_stats(&self, slot: usize, threshold_ns: u64) -> RobustTail {
        let stats = self.load_stats(slot);
        let empirical = if stats.tail_count > 0 {
            stats.tail_sum_ns / stats.tail_count.max(1)
        } else {
            threshold_ns
        };

        let radius = uncertainty_radius_ns(stats.pulls, threshold_ns);
        let robust_cvar_ns = empirical.saturating_add(radius);
        let ratio_permille = robust_cvar_ns
            .saturating_mul(1_000)
            .saturating_div(threshold_ns.max(1));

        RobustTail {
            pulls: stats.pulls,
            robust_cvar_ns,
            ratio_permille,
        }
    }

    fn load_stats(&self, slot: usize) -> TailStats {
        TailStats {
            pulls: self.pulls[slot].load(Ordering::Relaxed),
            tail_count: self.tail_count[slot].load(Ordering::Relaxed),
            tail_sum_ns: self.tail_sum_ns[slot].load(Ordering::Relaxed),
        }
    }
}

impl Default for DroCvarController {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RobustTail {
    pulls: u64,
    robust_cvar_ns: u64,
    ratio_permille: u64,
}

fn uncertainty_radius_ns(n: u64, threshold_ns: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    let eps = (RADIUS_COEFF / (n as f64).sqrt()).max(0.0);
    let inflation = 1.0 + eps;
    let radius = ((inflation - 1.0) * threshold_ns as f64).ceil();
    radius.max(0.0) as u64
}

const fn profile_threshold_ns(profile: ValidationProfile) -> u64 {
    match profile {
        ValidationProfile::Fast => FAST_BUDGET_NS,
        ValidationProfile::Full => FULL_BUDGET_NS,
    }
}

const fn arm(profile: ValidationProfile) -> usize {
    match profile {
        ValidationProfile::Fast => ARM_FAST,
        ValidationProfile::Full => ARM_FULL,
    }
}

const fn slot(family_idx: usize, arm_idx: usize) -> usize {
    family_idx * ARM_COUNT + arm_idx
}

fn family_from_index(idx: usize) -> ApiFamily {
    match idx {
        0 => ApiFamily::PointerValidation,
        1 => ApiFamily::Allocator,
        2 => ApiFamily::StringMemory,
        3 => ApiFamily::Stdio,
        4 => ApiFamily::Threading,
        5 => ApiFamily::Resolver,
        6 => ApiFamily::MathFenv,
        7 => ApiFamily::Loader,
        8 => ApiFamily::Stdlib,
        9 => ApiFamily::Ctype,
        10 => ApiFamily::Time,
        11 => ApiFamily::Signal,
        12 => ApiFamily::IoFd,
        13 => ApiFamily::Socket,
        14 => ApiFamily::Locale,
        15 => ApiFamily::Termios,
        16 => ApiFamily::Inet,
        17 => ApiFamily::Process,
        18 => ApiFamily::VirtualMemory,
        _ => ApiFamily::Poll,
    }
}

#[allow(clippy::assertions_on_constants)]
const _: () = {
    assert!(DELTA_CONFIDENCE > 0.0);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_calibrating() {
        let c = DroCvarController::new();
        assert_eq!(
            c.family_state(SafetyLevel::Hardened, ApiFamily::PointerValidation),
            TailState::Calibrating
        );
    }

    #[test]
    fn stable_low_latency_is_normal() {
        let c = DroCvarController::new();
        for _ in 0..512 {
            c.observe(ApiFamily::StringMemory, ValidationProfile::Fast, 12);
        }
        assert_eq!(
            c.family_state(SafetyLevel::Hardened, ApiFamily::StringMemory),
            TailState::Normal
        );
    }

    #[test]
    fn heavy_tail_triggers_alarm_in_hardened() {
        let c = DroCvarController::new();
        for i in 0..1024 {
            let latency = if i % 5 == 0 { 450 } else { 16 };
            c.observe(ApiFamily::Allocator, ValidationProfile::Fast, latency);
        }
        let state = c.family_state(SafetyLevel::Hardened, ApiFamily::Allocator);
        assert!(matches!(state, TailState::Warning | TailState::Alarm));
        assert!(c.family_robust_cvar_ns(ApiFamily::Allocator) >= FAST_BUDGET_NS);
    }

    #[test]
    fn reports_aggregate_max() {
        let c = DroCvarController::new();
        for _ in 0..256 {
            c.observe(ApiFamily::Resolver, ValidationProfile::Full, 350);
        }
        assert!(c.max_family_robust_cvar_ns() >= FULL_BUDGET_NS);
    }

    #[test]
    fn high_index_families_are_counted_independently() {
        let c = DroCvarController::new();
        for _ in 0..256 {
            c.observe(ApiFamily::Loader, ValidationProfile::Fast, 12);
            c.observe(ApiFamily::Poll, ValidationProfile::Fast, 480);
        }

        assert_eq!(
            c.family_state(SafetyLevel::Hardened, ApiFamily::Loader),
            TailState::Normal
        );
        assert!(matches!(
            c.family_state(SafetyLevel::Hardened, ApiFamily::Poll),
            TailState::Warning | TailState::Alarm
        ));
        assert!(
            c.alarmed_family_count(SafetyLevel::Hardened) >= 1,
            "poll alarm should be counted independently from loader"
        );
        assert!(
            c.max_family_robust_cvar_ns() >= c.family_robust_cvar_ns(ApiFamily::Poll),
            "max aggregation should include high-index families"
        );
    }
}
