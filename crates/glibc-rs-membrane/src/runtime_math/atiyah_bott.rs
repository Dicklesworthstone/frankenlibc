//! # Atiyah-Bott Fixed-Point Localization Controller
//!
//! Implements Atiyah-Bott localization methods for fixed-point compression
//! of the runtime bonus-evaluation hot path (math item #35).
//!
//! ## Mathematical Foundation
//!
//! The **Atiyah-Bott fixed-point theorem** (1967) states that for a compact
//! Lie group G acting on a compact manifold M with isolated fixed points,
//! the integral of an equivariant cohomology class ω localizes:
//!
//! ```text
//! ∫_M ω = Σ_{p ∈ M^G} ω(p) / e_G(T_p M)
//! ```
//!
//! where the sum runs over the **fixed points** p of the G-action, and
//! e_G(T_p M) is the equivariant Euler class of the tangent space at p.
//!
//! The key insight: a global integral over the entire manifold can be
//! computed *exactly* from data at the fixed points alone. The non-fixed
//! regions contribute nothing — they "localize away."
//!
//! ## Runtime Application
//!
//! The runtime math kernel aggregates bonuses from N ≈ 28 controllers.
//! Most controllers spend the majority of their time in stable/nominal
//! "fixed-point" states (Calibrating, Aligned, Compatible, Coherent, etc.).
//!
//! The **localization principle** says: when most controllers are at their
//! fixed points, the *total risk integral* is determined entirely by the
//! few **non-fixed** (anomalous) controllers. The contribution from stable
//! controllers is exactly zero — they localize away.
//!
//! This controller tracks:
//!
//! 1. **Fixed-point fraction** f ∈ [0,1]: fraction of controllers at
//!    their stable fixed point (state ≤ 1 in the 0..3 encoding).
//!
//! 2. **Localization index** L: when f is high (most stable), the few
//!    non-fixed controllers carry *concentrated* anomaly signal. L
//!    measures this concentration via an inverse-participation ratio:
//!
//!    ```text
//!    L = (Σ_i s_i²) / (Σ_i s_i)²
//!    ```
//!
//!    where s_i are the severity levels of non-fixed controllers.
//!    L → 1 means one controller dominates (highly concentrated).
//!    L → 1/k means k controllers share equally.
//!
//! 3. **Euler weight** w: the localization weight amplifies concentrated
//!    anomalies when the fixed-point fraction is high:
//!
//!    ```text
//!    w = L × f^α   (α = 2, quadratic amplification of concentration)
//!    ```
//!
//!    High w means "a few things are very wrong while everything else is
//!    perfectly stable" — a clear, localized fault that merits escalation.
//!
//! ## State Machine
//!
//! - **Calibrating**: fewer than CALIBRATION_THRESHOLD observations.
//! - **Distributed**: non-fixed controllers are spread out (L < 0.35).
//!   Risk is diffuse — many things are slightly off.
//! - **Localized**: risk concentrates at few controllers (L ≥ 0.35).
//!   Fixed-point fraction is moderate to high. Targeted investigation.
//! - **ConcentratedAnomaly**: high localization AND high fixed-point
//!   fraction (w ≥ 0.50). A clear, isolated fault signal.

/// Number of base controller signals tracked for localization.
/// Must match the base severity array size in mod.rs (25 base controllers).
const NUM_SIGNALS: usize = 25;

/// Observations before leaving calibration.
const CALIBRATION_THRESHOLD: u64 = 128;

/// EWMA smoothing parameter for localization index tracking.
const EWMA_ALPHA: f64 = 0.05;

/// Fixed-point state threshold: state codes ≤ this value are "fixed points."
/// 0 = Calibrating, 1 = nominal/stable. Both count as fixed.
const FIXED_POINT_THRESHOLD: u8 = 1;

/// Localization index threshold for Distributed → Localized transition.
const LOCALIZATION_THRESHOLD: f64 = 0.35;

/// Euler weight threshold for Localized → ConcentratedAnomaly.
const CONCENTRATION_THRESHOLD: f64 = 0.50;

/// Exponent for fixed-point fraction amplification.
const FP_EXPONENT: f64 = 2.0;

/// Controller states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalizationState {
    /// Insufficient observations.
    Calibrating,
    /// Anomaly signal distributed across many controllers.
    Distributed,
    /// Anomaly signal localizing at few controllers.
    Localized,
    /// Concentrated anomaly at very few controllers with high stability elsewhere.
    ConcentratedAnomaly,
}

/// Summary snapshot for telemetry.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LocalizationSummary {
    pub state: LocalizationState,
    /// Fraction of controllers at their fixed-point (stable) state.
    pub fixed_point_fraction: f64,
    /// Inverse-participation ratio of non-fixed severity levels.
    pub localization_index: f64,
    /// Euler weight: L × f^α.
    pub euler_weight: f64,
    /// Number of non-fixed controllers in the last observation.
    pub non_fixed_count: u8,
    /// Total observations processed.
    pub total_observations: u64,
    /// Number of ConcentratedAnomaly detections.
    pub concentration_count: u64,
}

/// Atiyah-Bott fixed-point localization controller.
pub struct AtiyahBottController {
    /// EWMA-smoothed localization index.
    smoothed_localization: f64,
    /// EWMA-smoothed fixed-point fraction.
    smoothed_fp_fraction: f64,
    /// Total observations.
    observations: u64,
    /// ConcentratedAnomaly detection counter.
    concentration_count: u64,
    /// Last raw localization index (for snapshot).
    last_raw_localization: f64,
    /// Last non-fixed count.
    last_non_fixed: u8,
}

impl Default for AtiyahBottController {
    fn default() -> Self {
        Self::new()
    }
}

impl AtiyahBottController {
    pub fn new() -> Self {
        Self {
            smoothed_localization: 0.0,
            smoothed_fp_fraction: 1.0,
            observations: 0,
            concentration_count: 0,
            last_raw_localization: 0.0,
            last_non_fixed: 0,
        }
    }

    /// Feed a severity vector (one entry per controller signal) and update.
    ///
    /// Each entry is a state code (0..=3 typically) from a cached AtomicU8.
    pub fn observe_and_update(&mut self, severity: &[u8; NUM_SIGNALS]) {
        self.observations += 1;

        // Partition into fixed-point and non-fixed controllers.
        let mut fixed_count: u32 = 0;
        let mut non_fixed_severities = [0u8; NUM_SIGNALS];
        let mut non_fixed_n: usize = 0;

        for &s in severity.iter() {
            if s <= FIXED_POINT_THRESHOLD {
                fixed_count += 1;
            } else {
                non_fixed_severities[non_fixed_n] = s;
                non_fixed_n += 1;
            }
        }

        let fp_fraction = f64::from(fixed_count) / NUM_SIGNALS as f64;

        // Compute inverse-participation ratio (localization index) over
        // non-fixed severity levels.
        let localization = if non_fixed_n == 0 {
            0.0 // all fixed → no anomaly to localize
        } else {
            let mut sum_s: f64 = 0.0;
            let mut sum_s2: f64 = 0.0;
            for &sev in &non_fixed_severities[..non_fixed_n] {
                let s = f64::from(sev);
                sum_s += s;
                sum_s2 += s * s;
            }
            if sum_s > 0.0 {
                sum_s2 / (sum_s * sum_s)
            } else {
                0.0
            }
        };

        self.last_raw_localization = localization;
        self.last_non_fixed = non_fixed_n as u8;

        // EWMA update.
        if self.observations == 1 {
            self.smoothed_localization = localization;
            self.smoothed_fp_fraction = fp_fraction;
        } else {
            self.smoothed_localization += EWMA_ALPHA * (localization - self.smoothed_localization);
            self.smoothed_fp_fraction += EWMA_ALPHA * (fp_fraction - self.smoothed_fp_fraction);
        }

        // Count observations spent in ConcentratedAnomaly (post-calibration).
        if self.observations > CALIBRATION_THRESHOLD
            && self.state() == LocalizationState::ConcentratedAnomaly
        {
            self.concentration_count += 1;
        }
    }

    /// Compute the Euler weight: L × f^α.
    fn euler_weight(&self) -> f64 {
        self.smoothed_localization * self.smoothed_fp_fraction.powf(FP_EXPONENT)
    }

    /// Current state.
    pub fn state(&self) -> LocalizationState {
        if self.observations < CALIBRATION_THRESHOLD {
            return LocalizationState::Calibrating;
        }

        let w = self.euler_weight();

        if w >= CONCENTRATION_THRESHOLD {
            LocalizationState::ConcentratedAnomaly
        } else if self.smoothed_localization >= LOCALIZATION_THRESHOLD {
            LocalizationState::Localized
        } else {
            LocalizationState::Distributed
        }
    }

    /// Summary snapshot.
    pub fn summary(&self) -> LocalizationSummary {
        LocalizationSummary {
            state: self.state(),
            fixed_point_fraction: self.smoothed_fp_fraction,
            localization_index: self.smoothed_localization,
            euler_weight: self.euler_weight(),
            non_fixed_count: self.last_non_fixed,
            total_observations: self.observations,
            concentration_count: self.concentration_count,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_stable() -> [u8; NUM_SIGNALS] {
        [0; NUM_SIGNALS] // all at fixed-point state 0 (Calibrating)
    }

    fn one_anomalous(idx: usize, severity: u8) -> [u8; NUM_SIGNALS] {
        let mut v = [1; NUM_SIGNALS]; // all nominal (fixed point)
        v[idx] = severity;
        v
    }

    fn many_anomalous(count: usize, severity: u8) -> [u8; NUM_SIGNALS] {
        let mut v = [1; NUM_SIGNALS];
        for slot in v.iter_mut().take(count.min(NUM_SIGNALS)) {
            *slot = severity;
        }
        v
    }

    #[test]
    fn calibration_phase() {
        let mut ctrl = AtiyahBottController::new();
        for _ in 0..CALIBRATION_THRESHOLD - 1 {
            ctrl.observe_and_update(&all_stable());
        }
        assert_eq!(ctrl.state(), LocalizationState::Calibrating);
    }

    #[test]
    fn all_stable_is_distributed() {
        let mut ctrl = AtiyahBottController::new();
        // When everything is stable, localization index is 0 (no non-fixed
        // controllers), so we stay in Distributed.
        for _ in 0..256 {
            ctrl.observe_and_update(&all_stable());
        }
        assert_eq!(ctrl.state(), LocalizationState::Distributed);
        let s = ctrl.summary();
        assert!(s.fixed_point_fraction > 0.99);
        assert!(s.localization_index < 0.01);
    }

    #[test]
    fn single_severe_anomaly_concentrates() {
        let mut ctrl = AtiyahBottController::new();
        // Calibrate with stable traffic.
        for _ in 0..CALIBRATION_THRESHOLD {
            ctrl.observe_and_update(&all_stable());
        }
        // Now inject a single severe anomaly (state=3) while rest are stable.
        let pattern = one_anomalous(5, 3);
        for _ in 0..2000 {
            ctrl.observe_and_update(&pattern);
        }
        let s = ctrl.summary();
        // With only 1 non-fixed controller, IPR = s²/(s)² = 1.0.
        // fp_fraction = 24/25 = 0.96. Euler weight = 1.0 × 0.96² = 0.922.
        assert_eq!(s.state, LocalizationState::ConcentratedAnomaly);
        assert!(s.euler_weight > 0.5);
        assert!(s.non_fixed_count <= 2); // EWMA might lag slightly
    }

    #[test]
    fn diffuse_anomalies_stay_distributed() {
        let mut ctrl = AtiyahBottController::new();
        // Many controllers anomalous at moderate severity.
        let pattern = many_anomalous(15, 2);
        for _ in 0..2000 {
            ctrl.observe_and_update(&pattern);
        }
        let s = ctrl.summary();
        // 15 non-fixed with equal severity: IPR = 15×4 / (15×2)² = 60/900 = 0.067
        // fp_fraction = 10/25 = 0.40, so w = 0.067 × 0.16 = 0.011
        assert_ne!(s.state, LocalizationState::ConcentratedAnomaly);
        assert!(s.localization_index < LOCALIZATION_THRESHOLD);
    }

    #[test]
    fn two_anomalies_localizes() {
        let mut ctrl = AtiyahBottController::new();
        // Two non-fixed controllers with high severity, rest stable.
        let mut pattern = [1u8; NUM_SIGNALS];
        pattern[3] = 3;
        pattern[7] = 3;
        for _ in 0..2000 {
            ctrl.observe_and_update(&pattern);
        }
        let s = ctrl.summary();
        // 2 non-fixed with severity 3: IPR = 2×9/(6²) = 18/36 = 0.5
        // fp_fraction = 23/25 = 0.92, w = 0.5 × 0.846 = 0.423
        assert!(
            s.state == LocalizationState::Localized
                || s.state == LocalizationState::ConcentratedAnomaly,
            "Expected Localized or ConcentratedAnomaly, got {:?}",
            s.state
        );
    }

    #[test]
    fn mixed_severity_concentration() {
        let mut ctrl = AtiyahBottController::new();
        // One at severity 3, two at severity 2, rest stable.
        let mut pattern = [1u8; NUM_SIGNALS];
        pattern[0] = 3;
        pattern[1] = 2;
        pattern[2] = 2;
        for _ in 0..2000 {
            ctrl.observe_and_update(&pattern);
        }
        let s = ctrl.summary();
        // IPR = (9+4+4)/(3+2+2)² = 17/49 ≈ 0.347
        // fp_fraction = 22/25 = 0.88, w ≈ 0.347 × 0.774 ≈ 0.269
        assert!(s.localization_index > 0.30);
        assert!(s.fixed_point_fraction > 0.85);
    }

    #[test]
    fn recovery_from_concentration() {
        let mut ctrl = AtiyahBottController::new();
        // Drive into ConcentratedAnomaly.
        let anomalous = one_anomalous(10, 3);
        for _ in 0..2000 {
            ctrl.observe_and_update(&anomalous);
        }
        assert_eq!(ctrl.state(), LocalizationState::ConcentratedAnomaly);

        // Recover with all-stable traffic.
        for _ in 0..10_000 {
            ctrl.observe_and_update(&all_stable());
        }
        // Should return to Distributed (localization index drops to 0).
        assert_eq!(ctrl.state(), LocalizationState::Distributed);
    }
}
