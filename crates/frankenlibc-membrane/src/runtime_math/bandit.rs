//! Constrained bandit router for validation depth selection.

use std::sync::atomic::{AtomicI64, AtomicU8, AtomicU64, Ordering};

use crate::config::SafetyLevel;

use super::{ApiFamily, ValidationProfile};

const ARM_COUNT: usize = 2;
const ARM_FAST: usize = 0;
const ARM_FULL: usize = 1;

/// Cadence at which UCB scores are recomputed per family.
/// Every 64 observations per family, the expensive ln+sqrt computation
/// runs once and the preferred profile is cached for the hot path.
const UCB_RECOMPUTE_CADENCE: u64 = 64;

/// Online router selecting `Fast` vs `Full` validation profiles.
///
/// **Hot-path discipline:** `select_profile()` reads only from a per-family
/// atomic cache (single load, ~1-2ns) after hard safety gates. The expensive
/// UCB computation (ln + 2×sqrt + 2×f64 divisions) runs on cadence inside
/// `observe()` every 64 calls per family.
pub struct ConstrainedBanditRouter {
    pulls: [AtomicU64; ApiFamily::COUNT * ARM_COUNT],
    utility_milli: [AtomicI64; ApiFamily::COUNT * ARM_COUNT],
    /// Total pulls per family (sum of fast + full), for cadenced recomputation.
    family_pulls: [AtomicU64; ApiFamily::COUNT],
    /// Cached UCB-preferred profile per family: 0 = Fast, 1 = Full.
    /// Updated on cadence in `observe()`.
    cached_ucb_profile: [AtomicU8; ApiFamily::COUNT],
}

impl ConstrainedBanditRouter {
    #[must_use]
    pub fn new() -> Self {
        Self {
            pulls: std::array::from_fn(|_| AtomicU64::new(0)),
            utility_milli: std::array::from_fn(|_| AtomicI64::new(0)),
            family_pulls: std::array::from_fn(|_| AtomicU64::new(0)),
            // Default to Full until we have enough data (conservative).
            cached_ucb_profile: std::array::from_fn(|_| AtomicU8::new(1)),
        }
    }

    /// Select a validation profile using cached UCB with hard safety constraints.
    ///
    /// **Hot-path safe:** hard safety gates are integer comparisons; UCB
    /// preference is a single atomic load (~1-2ns). The expensive ln+sqrt
    /// computation is amortized in `observe()`.
    #[must_use]
    pub fn select_profile(
        &self,
        family: ApiFamily,
        mode: SafetyLevel,
        risk_upper_bound_ppm: u32,
        contention_hint: u16,
    ) -> ValidationProfile {
        // Hard safety/robustness gates first.
        if mode.heals_enabled() && (risk_upper_bound_ppm >= 100_000 || contention_hint >= 96) {
            return ValidationProfile::Full;
        }
        if risk_upper_bound_ppm >= 300_000 {
            return ValidationProfile::Full;
        }

        let family_idx = usize::from(family as u8);
        // Ensure initial exploration of both arms without running the expensive
        // ln+sqrt UCB computation on the hot path.
        let fast_pulls = self.pulls[idx(family_idx, ARM_FAST)].load(Ordering::Relaxed);
        if fast_pulls == 0 {
            return ValidationProfile::Fast;
        }
        let full_pulls = self.pulls[idx(family_idx, ARM_FULL)].load(Ordering::Relaxed);
        if full_pulls == 0 {
            return ValidationProfile::Full;
        }
        match self.cached_ucb_profile[family_idx].load(Ordering::Relaxed) {
            0 => ValidationProfile::Fast,
            _ => ValidationProfile::Full,
        }
    }

    /// Record realized utility for the selected profile.
    ///
    /// Utility is higher for lower latency and no adverse outcome.
    /// On cadence (every 64 calls per family), recomputes UCB scores
    /// and caches the preferred profile for the hot path.
    pub fn observe(
        &self,
        family: ApiFamily,
        profile: ValidationProfile,
        estimated_cost_ns: u64,
        adverse: bool,
    ) {
        let family_idx = usize::from(family as u8);
        let arm = match profile {
            ValidationProfile::Fast => ARM_FAST,
            ValidationProfile::Full => ARM_FULL,
        };
        let slot = idx(family_idx, arm);

        self.pulls[slot].fetch_add(1, Ordering::Relaxed);
        let total = self.family_pulls[family_idx].fetch_add(1, Ordering::Relaxed) + 1;

        // Utility model:
        // - latency penalty in milli-units
        // - heavy penalty for adverse outcomes
        let latency_penalty = (estimated_cost_ns as i64).saturating_mul(8);
        let adverse_penalty = if adverse { 20_000 } else { 0 };
        let utility = 100_000 - latency_penalty - adverse_penalty;
        self.utility_milli[slot].fetch_add(utility, Ordering::Relaxed);

        // Cadenced UCB recomputation.
        if total >= 2 && total.is_multiple_of(UCB_RECOMPUTE_CADENCE) {
            let ucb_profile = self.compute_ucb_profile(family_idx);
            self.cached_ucb_profile[family_idx].store(ucb_profile, Ordering::Relaxed);
        }
    }

    /// Expensive UCB computation (ln + 2×sqrt + 2×f64 divisions).
    /// Called only on cadence from `observe()`, never on the hot path.
    fn compute_ucb_profile(&self, family_idx: usize) -> u8 {
        let fast_idx = idx(family_idx, ARM_FAST);
        let full_idx = idx(family_idx, ARM_FULL);

        let fast_pulls = self.pulls[fast_idx].load(Ordering::Relaxed);
        let full_pulls = self.pulls[full_idx].load(Ordering::Relaxed);

        if fast_pulls == 0 || full_pulls == 0 {
            // Still exploring: default to Full (conservative).
            return 1;
        }

        let total = (fast_pulls + full_pulls) as f64;
        let log_total = total.ln().max(1.0);
        let mode = crate::config::safety_level();
        // Utility values are around 100,000, so scale c accordingly.
        let c = if mode.heals_enabled() {
            55_000.0
        } else {
            35_000.0
        };

        let fast_mean =
            self.utility_milli[fast_idx].load(Ordering::Relaxed) as f64 / fast_pulls as f64;
        let full_mean =
            self.utility_milli[full_idx].load(Ordering::Relaxed) as f64 / full_pulls as f64;

        let fast_ucb = fast_mean + c * (2.0 * log_total / fast_pulls as f64).sqrt();
        let full_ucb = full_mean + c * (2.0 * log_total / full_pulls as f64).sqrt();

        if full_ucb > fast_ucb { 1 } else { 0 }
    }
}

impl Default for ConstrainedBanditRouter {
    fn default() -> Self {
        Self::new()
    }
}

#[inline]
const fn idx(family_idx: usize, arm: usize) -> usize {
    family_idx * ARM_COUNT + arm
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn high_risk_prefers_full() {
        let router = ConstrainedBanditRouter::new();
        let profile =
            router.select_profile(ApiFamily::Allocator, SafetyLevel::Hardened, 350_000, 0);
        assert_eq!(profile, ValidationProfile::Full);
    }

    #[test]
    fn observes_utilities() {
        let router = ConstrainedBanditRouter::new();
        router.observe(ApiFamily::StringMemory, ValidationProfile::Fast, 9, false);
        router.observe(ApiFamily::StringMemory, ValidationProfile::Full, 45, true);
        // Should not panic and should still return a valid profile.
        let _ = router.select_profile(ApiFamily::StringMemory, SafetyLevel::Hardened, 50_000, 8);
    }

    #[test]
    fn explores_both_arms_before_cached_ucb_takes_over() {
        let router = ConstrainedBanditRouter::new();

        // First selection: explore Fast arm.
        let p1 = router.select_profile(ApiFamily::Allocator, SafetyLevel::Strict, 10_000, 0);
        assert_eq!(p1, ValidationProfile::Fast);
        router.observe(ApiFamily::Allocator, p1, 10, false);

        // Second selection: explore Full arm.
        let p2 = router.select_profile(ApiFamily::Allocator, SafetyLevel::Strict, 10_000, 0);
        assert_eq!(p2, ValidationProfile::Full);
        router.observe(ApiFamily::Allocator, p2, 120, false);

        // After both arms observed at least once, selection should be based on the cached value
        // (default Full until cadence recompute).
        let p3 = router.select_profile(ApiFamily::Allocator, SafetyLevel::Strict, 10_000, 0);
        assert_eq!(p3, ValidationProfile::Full);
    }
}
