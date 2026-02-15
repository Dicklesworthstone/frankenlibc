//! Runtime risk upper-bound estimator (conformal-style envelope).

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use super::ApiFamily;

/// Cadence at which cached upper-bound values are recomputed.
/// Every 64 observations per family, the expensive sqrt+division computation
/// runs once and results are cached in atomics for the hot path.
const RECOMPUTE_CADENCE: u64 = 64;

/// Conformal-style online risk envelope.
///
/// This tracks adverse outcomes per family and exposes a conservative upper
/// bound in ppm. It is intentionally lightweight for hot runtime use.
///
/// **Hot-path discipline:** `upper_bound_ppm()` reads only from a per-family
/// atomic cache (single load, ~1-2ns). The expensive sqrt + f64 division
/// computation runs on cadence inside `observe()` every 64 calls per family.
pub struct ConformalRiskEngine {
    calls: [AtomicU64; ApiFamily::COUNT],
    adverse: [AtomicU64; ApiFamily::COUNT],
    /// Cached upper-bound ppm per family. Updated on cadence in `observe()`.
    cached_ub_ppm: [AtomicU32; ApiFamily::COUNT],
    z_score: f64,
}

impl ConformalRiskEngine {
    /// Create a new engine.
    ///
    /// `prior_ppm` controls startup conservatism before enough calls are observed.
    /// `z_score` controls confidence width (e.g., 3.0 ~ highly conservative).
    #[must_use]
    pub fn new(prior_ppm: u32, z_score: f64) -> Self {
        Self {
            calls: std::array::from_fn(|_| AtomicU64::new(0)),
            adverse: std::array::from_fn(|_| AtomicU64::new(0)),
            cached_ub_ppm: std::array::from_fn(|_| AtomicU32::new(prior_ppm)),
            z_score,
        }
    }

    /// Record one runtime outcome for a family.
    ///
    /// On cadence (every 64 calls per family), recomputes the upper-bound ppm
    /// using the expensive smoothed binomial + sqrt envelope and caches the
    /// result in an atomic for the hot path.
    pub fn observe(&self, family: ApiFamily, adverse: bool) {
        let idx = usize::from(family as u8);
        let new_calls = self.calls[idx].fetch_add(1, Ordering::Relaxed) + 1;
        if adverse {
            self.adverse[idx].fetch_add(1, Ordering::Relaxed);
        }
        // Cadenced recomputation: amortize the expensive sqrt+division over
        // RECOMPUTE_CADENCE observations so the hot path is a single atomic load.
        if new_calls >= 32 && new_calls.is_multiple_of(RECOMPUTE_CADENCE) {
            let ub = self.compute_upper_bound(idx, new_calls);
            self.cached_ub_ppm[idx].store(ub, Ordering::Relaxed);
        }
    }

    /// Conservative upper bound on adverse probability in ppm.
    ///
    /// **Hot-path safe:** single atomic load (~1-2ns). The expensive computation
    /// is amortized in `observe()` on cadence.
    #[must_use]
    pub fn upper_bound_ppm(&self, family: ApiFamily) -> u32 {
        let idx = usize::from(family as u8);
        self.cached_ub_ppm[idx].load(Ordering::Relaxed)
    }

    /// Expensive upper-bound computation (sqrt + f64 divisions).
    /// Called only on cadence from `observe()`, never on the hot path.
    fn compute_upper_bound(&self, idx: usize, calls: u64) -> u32 {
        let adverse = self.adverse[idx].load(Ordering::Relaxed);
        let n = calls as f64;
        let p_hat = (adverse as f64 + 1.0) / (n + 2.0);
        let var = (p_hat * (1.0 - p_hat) / (n + 3.0)).max(0.0);
        let ub = (p_hat + self.z_score * var.sqrt()).clamp(0.0, 1.0);
        (ub * 1_000_000.0).round() as u32
    }
}

impl Default for ConformalRiskEngine {
    fn default() -> Self {
        Self::new(20_000, 3.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_with_prior() {
        let risk = ConformalRiskEngine::new(12_345, 3.0);
        assert_eq!(risk.upper_bound_ppm(ApiFamily::Allocator), 12_345);
    }

    #[test]
    fn recomputes_on_cadence_boundary() {
        let risk = ConformalRiskEngine::new(1, 3.0);
        for _ in 0..63 {
            risk.observe(ApiFamily::Allocator, false);
        }
        assert_eq!(risk.upper_bound_ppm(ApiFamily::Allocator), 1);

        risk.observe(ApiFamily::Allocator, false);
        let ub = risk.upper_bound_ppm(ApiFamily::Allocator);
        assert!(ub > 1);
        assert!(ub <= 1_000_000);
    }

    #[test]
    fn adverse_outcomes_increase_upper_bound() {
        let risk = ConformalRiskEngine::default();
        for _ in 0..128 {
            risk.observe(ApiFamily::StringMemory, true);
        }
        let ub = risk.upper_bound_ppm(ApiFamily::StringMemory);
        assert!(ub > 500_000);
    }

    #[test]
    fn mostly_clean_traffic_reduces_upper_bound() {
        let risk = ConformalRiskEngine::new(50_000, 2.0);
        for i in 0..512 {
            risk.observe(ApiFamily::PointerValidation, i % 200 == 0);
        }
        let ub = risk.upper_bound_ppm(ApiFamily::PointerValidation);
        assert!(ub < 50_000);
    }

    #[test]
    fn upper_bound_is_always_valid_ppm() {
        let risk = ConformalRiskEngine::new(25_000, 3.5);
        for i in 0..4096 {
            risk.observe(ApiFamily::Resolver, i % 17 == 0 || i % 97 == 0);
        }
        let ub = risk.upper_bound_ppm(ApiFamily::Resolver);
        assert!(ub <= 1_000_000);
    }

    #[test]
    fn family_counters_are_isolated() {
        let risk = ConformalRiskEngine::new(10_000, 3.0);

        for _ in 0..256 {
            risk.observe(ApiFamily::Allocator, true);
            risk.observe(ApiFamily::PointerValidation, false);
        }

        let allocator = risk.upper_bound_ppm(ApiFamily::Allocator);
        let pointer = risk.upper_bound_ppm(ApiFamily::PointerValidation);
        assert!(allocator > pointer);
    }

    #[test]
    fn higher_adverse_rate_yields_higher_bound_for_same_volume() {
        let risk = ConformalRiskEngine::new(1_000, 3.0);

        for i in 0..512 {
            risk.observe(ApiFamily::Allocator, i % 2 == 0);
            risk.observe(ApiFamily::Resolver, i % 64 == 0);
        }

        let high_rate = risk.upper_bound_ppm(ApiFamily::Allocator);
        let low_rate = risk.upper_bound_ppm(ApiFamily::Resolver);
        assert!(high_rate > low_rate);
        assert!(high_rate <= 1_000_000);
        assert!(low_rate <= 1_000_000);
    }

    #[test]
    fn high_index_family_isolated_from_loader() {
        let risk = ConformalRiskEngine::new(5_000, 3.0);

        for i in 0..512 {
            risk.observe(ApiFamily::Poll, i % 2 == 0);
            risk.observe(ApiFamily::Loader, false);
        }

        let poll = risk.upper_bound_ppm(ApiFamily::Poll);
        let loader = risk.upper_bound_ppm(ApiFamily::Loader);
        assert!(
            poll > loader,
            "high-index family updates should not collapse into loader accounting"
        );
    }
}
