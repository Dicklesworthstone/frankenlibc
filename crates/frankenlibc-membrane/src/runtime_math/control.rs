//! Primal-dual runtime controller for latency/safety budgets.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

use crate::config::SafetyLevel;

/// Runtime control limits derived from current controller state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlLimits {
    pub full_validation_trigger_ppm: u32,
    pub repair_trigger_ppm: u32,
    pub max_request_bytes: usize,
}

/// Lightweight primal-dual controller.
///
/// The controller adjusts runtime thresholds based on observed latency and
/// adverse-rate pressure while keeping decisions deterministic.
pub struct PrimalDualController {
    observed_calls: AtomicU64,
    total_cost_ns: AtomicU64,
    adverse_events: AtomicU64,
    lambda_latency: AtomicI64,
    lambda_risk: AtomicI64,
}

impl PrimalDualController {
    #[must_use]
    pub fn new() -> Self {
        Self {
            observed_calls: AtomicU64::new(0),
            total_cost_ns: AtomicU64::new(0),
            adverse_events: AtomicU64::new(0),
            lambda_latency: AtomicI64::new(0),
            lambda_risk: AtomicI64::new(0),
        }
    }

    /// Observe one routed call.
    pub fn observe(&self, estimated_cost_ns: u64, adverse: bool) {
        let calls = self.observed_calls.fetch_add(1, Ordering::Relaxed) + 1;
        self.total_cost_ns
            .fetch_add(estimated_cost_ns, Ordering::Relaxed);
        if adverse {
            self.adverse_events.fetch_add(1, Ordering::Relaxed);
        }

        // Update multipliers every 128 samples.
        if calls.is_multiple_of(128) {
            let total_cost = self.total_cost_ns.load(Ordering::Relaxed);
            let bad = self.adverse_events.load(Ordering::Relaxed);
            let avg_cost = total_cost / calls.max(1);
            let adverse_ppm = ((bad as u128 * 1_000_000) / (calls.max(1) as u128)) as i64;

            let latency_target_ns = 60_i64;
            let risk_target_ppm = 8_000_i64;

            let latency_err = avg_cost as i64 - latency_target_ns;
            let risk_err = adverse_ppm - risk_target_ppm;

            let _ = self.lambda_latency.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |x| {
                Some(x.saturating_add((latency_err / 4).clamp(-64, 64)).clamp(-2_000_000, 2_000_000))
            });
            let _ = self.lambda_risk.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |x| {
                Some(x.saturating_add((risk_err / 256).clamp(-128, 128)).clamp(-2_000_000, 2_000_000))
            });
        }
    }

    /// Produce current limits for a given mode.
    #[must_use]
    pub fn limits(&self, mode: SafetyLevel) -> ControlLimits {
        let lambda_l = self.lambda_latency.load(Ordering::Relaxed);
        let lambda_r = self.lambda_risk.load(Ordering::Relaxed);

        let base_full = match mode {
            SafetyLevel::Strict => 220_000_i64,
            SafetyLevel::Hardened => 80_000_i64,
            SafetyLevel::Off => 1_000_000_i64,
        };
        let base_repair = match mode {
            SafetyLevel::Strict => 1_000_000_i64,
            SafetyLevel::Hardened => 140_000_i64,
            SafetyLevel::Off => 1_000_000_i64,
        };

        let full_validation_trigger_ppm =
            (base_full - lambda_r + lambda_l).clamp(5_000, 900_000) as u32;
        let repair_trigger_ppm =
            (base_repair - lambda_r / 2 + lambda_l / 2).clamp(10_000, 980_000) as u32;

        // Keep size bound conservative but mode-aware.
        let max_request_bytes = match mode {
            SafetyLevel::Strict => 128 * 1024 * 1024,
            SafetyLevel::Hardened => 256 * 1024 * 1024,
            SafetyLevel::Off => usize::MAX / 4,
        };

        ControlLimits {
            full_validation_trigger_ppm,
            repair_trigger_ppm,
            max_request_bytes,
        }
    }
}

impl Default for PrimalDualController {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_are_mode_aware() {
        let ctl = PrimalDualController::new();
        let strict = ctl.limits(SafetyLevel::Strict);
        let hardened = ctl.limits(SafetyLevel::Hardened);
        assert!(hardened.full_validation_trigger_ppm <= strict.full_validation_trigger_ppm);
        assert!(hardened.repair_trigger_ppm <= strict.repair_trigger_ppm);
    }

    #[test]
    fn observe_does_not_panic() {
        let ctl = PrimalDualController::new();
        for i in 0..300 {
            ctl.observe(50 + (i % 7), i % 19 == 0);
        }
        let _ = ctl.limits(SafetyLevel::Hardened);
    }

    #[test]
    fn limits_shift_after_cadence_update() {
        let ctl = PrimalDualController::new();
        let strict0 = ctl.limits(SafetyLevel::Strict);

        for _ in 0..128 {
            ctl.observe(200, true);
        }

        let strict1 = ctl.limits(SafetyLevel::Strict);
        assert!(strict1.full_validation_trigger_ppm < strict0.full_validation_trigger_ppm);
        assert!(strict1.repair_trigger_ppm <= strict0.repair_trigger_ppm);
        assert_eq!(strict1.max_request_bytes, strict0.max_request_bytes);
    }

    #[test]
    fn off_mode_limits_are_high_and_bounded() {
        let ctl = PrimalDualController::new();
        let off = ctl.limits(SafetyLevel::Off);
        assert_eq!(off.full_validation_trigger_ppm, 900_000);
        assert_eq!(off.repair_trigger_ppm, 980_000);
        assert_eq!(off.max_request_bytes, usize::MAX / 4);
    }

    #[test]
    fn limits_remain_bounded_under_long_trace() {
        let ctl = PrimalDualController::new();

        for i in 0..4096_u64 {
            let cost = 20 + (i % 500);
            let adverse = i % 11 == 0 || i % 257 == 0;
            ctl.observe(cost, adverse);

            let strict = ctl.limits(SafetyLevel::Strict);
            let hardened = ctl.limits(SafetyLevel::Hardened);
            let off = ctl.limits(SafetyLevel::Off);

            assert!((5_000..=900_000).contains(&strict.full_validation_trigger_ppm));
            assert!((10_000..=980_000).contains(&strict.repair_trigger_ppm));
            assert!((5_000..=900_000).contains(&hardened.full_validation_trigger_ppm));
            assert!((10_000..=980_000).contains(&hardened.repair_trigger_ppm));
            assert_eq!(off.full_validation_trigger_ppm, 900_000);
            assert_eq!(off.repair_trigger_ppm, 980_000);
            assert!(hardened.full_validation_trigger_ppm <= strict.full_validation_trigger_ppm);
            assert!(hardened.repair_trigger_ppm <= strict.repair_trigger_ppm);
        }
    }

    #[test]
    fn higher_adverse_pressure_tightens_thresholds() {
        let calm = PrimalDualController::new();
        let noisy = PrimalDualController::new();

        for i in 0..1024_u64 {
            calm.observe(60, false);
            noisy.observe(60, i % 3 == 0);
        }

        let calm_strict = calm.limits(SafetyLevel::Strict);
        let noisy_strict = noisy.limits(SafetyLevel::Strict);
        let calm_hardened = calm.limits(SafetyLevel::Hardened);
        let noisy_hardened = noisy.limits(SafetyLevel::Hardened);

        assert!(
            noisy_strict.full_validation_trigger_ppm <= calm_strict.full_validation_trigger_ppm
        );
        assert!(noisy_strict.repair_trigger_ppm <= calm_strict.repair_trigger_ppm);
        assert!(
            noisy_hardened.full_validation_trigger_ppm <= calm_hardened.full_validation_trigger_ppm
        );
        assert!(noisy_hardened.repair_trigger_ppm <= calm_hardened.repair_trigger_ppm);
    }
}
