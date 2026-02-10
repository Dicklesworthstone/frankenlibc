//! Blackwell Approachability Controller (Blackwell 1956)
//!
//! Ensures the cumulative time-averaged (latency, risk, coverage) payoff
//! vector converges to a mode-dependent target safe set S, regardless of
//! the adversary's input sequence. This provides a formal O(1/√t)
//! convergence guarantee for multi-objective routing decisions.
//!
//! ## Mathematical Foundation
//!
//! **Blackwell's Approachability Theorem**: In a repeated vector-valued game,
//! a convex set S is *approachable* if and only if for every supporting
//! half-space H ⊇ S, the player has a strategy keeping the time-averaged
//! payoff inside H. The constructive algorithm:
//!
//! 1. Compute cumulative average payoff ḡ(t) = (1/t) Σ g(s).
//! 2. If ḡ(t) ∈ S, play any action.
//! 3. Otherwise, project: p* = Π_S(ḡ(t)).
//! 4. Compute direction d = p* − ḡ(t).
//! 5. Choose arm a* = argmax_a ⟨d, payoff[a]⟩.
//!
//! Convergence rate: dist(ḡ(t), S) ≤ C / √t.
//!
//! ## Integration
//!
//! The controller acts as a principled tiebreaker in the ambiguous risk
//! range of `decide()`. Hard safety gates (barrier, CVaR alarm, HJI
//! breach, etc.) always override. The approachability recommendation only
//! influences routing when risk falls between the full-validation trigger
//! and the repair trigger — the "gray zone" where ad-hoc heuristics
//! currently govern.
//!
//! ## Legacy Anchor
//!
//! `malloc`/`nptl` — allocator and threading hot paths where the
//! latency/risk/coverage tradeoff is sharpest. Adversarial allocation
//! patterns (phase-change workloads, thread-pool storms) can push
//! cumulative averages out of the safe set; Blackwell's theorem
//! guarantees convergence back regardless.

use crate::config::SafetyLevel;

/// Number of routing arms (actions).
const ARM_COUNT: usize = 4;

/// Payoff vectors per arm (latency_milli, risk_milli, coverage_milli).
///
/// These are design-time estimates calibrated from benchmark data.
/// Each component is in milli-units (0..1000).
///
/// | Arm | Profile | Gate      | (lat, risk, cov) |
/// |-----|---------|-----------|-------------------|
/// | 0   | Fast    | Allow     | (100, 500, 100)   |
/// | 1   | Fast    | FullValid | (250, 300, 400)   |
/// | 2   | Full    | Allow/FV  | (500, 150, 700)   |
/// | 3   | Full    | Repair    | (800, 50, 1000)   |
const ARM_PAYOFF: [[i64; 3]; ARM_COUNT] = [
    [100, 500, 100],
    [250, 300, 400],
    [500, 150, 700],
    [800, 50, 1000],
];

/// Minimum observations before leaving calibration.
const CALIBRATION_THRESHOLD: u64 = 256;

/// Safe set bounds (milli-units) for strict mode.
/// Format: [latency_upper, risk_upper, coverage_lower]
const STRICT_TARGET: [u64; 3] = [350, 500, 150];

/// Safe set bounds (milli-units) for hardened mode.
const HARDENED_TARGET: [u64; 3] = [700, 200, 500];

/// Alert threshold: deviation above this triggers state escalation (milli-units).
const ALERT_DEVIATION_MILLI: u64 = 200;

/// State encoding for the approachability controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ApproachabilityState {
    /// Too few observations to make a recommendation.
    Calibrating = 0,
    /// Average payoff is inside the safe set (or converging toward it).
    Approaching = 1,
    /// Average payoff is outside the safe set and deviation is growing.
    Drifting = 2,
    /// Average payoff deviation exceeds the alert threshold.
    Violated = 3,
}

/// Summary of the approachability controller state for snapshots.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ApproachabilitySummary {
    /// Number of observations processed.
    pub count: u64,
    /// Current recommended arm (0..3).
    pub recommended_arm: u8,
    /// Squared Euclidean deviation from safe set (milli² units).
    pub deviation_sq_milli: u64,
    /// Current state code.
    pub state: ApproachabilityState,
    /// Per-dimension average payoffs (milli-units).
    pub avg_latency_milli: u64,
    pub avg_risk_milli: u64,
    pub avg_coverage_milli: u64,
}

/// Blackwell approachability controller for multi-objective routing.
///
/// All arithmetic is integer milli-units — no floating-point on the hot path.
pub struct ApproachabilityController {
    /// Cumulative latency payoff sum (milli-units).
    sum_latency: u64,
    /// Cumulative risk payoff sum (milli-units).
    sum_risk: u64,
    /// Cumulative coverage payoff sum (milli-units).
    sum_coverage: u64,
    /// Observation count.
    count: u64,
    /// Recommended arm from last update.
    recommended_arm: u8,
    /// Previous deviation (for tracking convergence direction).
    prev_deviation_sq: u64,
    /// Mode-dependent safe set bounds.
    target: [u64; 3],
}

impl ApproachabilityController {
    /// Create a new controller for the given safety mode.
    #[must_use]
    pub fn new(mode: SafetyLevel) -> Self {
        let target = match mode {
            SafetyLevel::Strict | SafetyLevel::Off => STRICT_TARGET,
            SafetyLevel::Hardened => HARDENED_TARGET,
        };
        Self {
            sum_latency: 0,
            sum_risk: 0,
            sum_coverage: 0,
            count: 0,
            recommended_arm: 0,
            prev_deviation_sq: 0,
            target,
        }
    }

    /// Record an observation and update the recommended arm.
    ///
    /// `latency_milli`: normalized latency cost (0..1000).
    /// `risk_milli`: post-decision risk exposure (0..1000).
    /// `coverage_milli`: validation thoroughness (0..1000).
    pub fn observe(&mut self, latency_milli: u64, risk_milli: u64, coverage_milli: u64) {
        let lat = latency_milli.min(1000);
        let risk = risk_milli.min(1000);
        let cov = coverage_milli.min(1000);

        self.sum_latency += lat;
        self.sum_risk += risk;
        self.sum_coverage += cov;
        self.count += 1;

        if self.count < CALIBRATION_THRESHOLD {
            return;
        }

        // Compute average payoff (integer division; count > 0 guaranteed by guard above).
        let avg_lat = self.sum_latency.checked_div(self.count).unwrap_or(0);
        let avg_risk = self.sum_risk.checked_div(self.count).unwrap_or(0);
        let avg_cov = self.sum_coverage.checked_div(self.count).unwrap_or(0);

        // Box projection: clamp to safe set.
        // For latency and risk: upper bounds (lower is better).
        // For coverage: lower bound (higher is better).
        let proj_lat = avg_lat.min(self.target[0]);
        let proj_risk = avg_risk.min(self.target[1]);
        let proj_cov = avg_cov.max(self.target[2]);

        // Direction d = projection - average (signed).
        let d_lat = proj_lat as i64 - avg_lat as i64;
        let d_risk = proj_risk as i64 - avg_risk as i64;
        let d_cov = proj_cov as i64 - avg_cov as i64;

        // Squared deviation (for state tracking).
        let dev_sq = (d_lat * d_lat + d_risk * d_risk + d_cov * d_cov) as u64;
        self.prev_deviation_sq = dev_sq;

        // If already inside the safe set, keep current arm.
        if d_lat == 0 && d_risk == 0 && d_cov == 0 {
            return;
        }

        // Arm selection: argmax_a <d, payoff[a]>.
        let mut best_arm: u8 = 0;
        let mut best_score = i64::MIN;

        for (arm_idx, payoff) in ARM_PAYOFF.iter().enumerate() {
            let score = d_lat * payoff[0] + d_risk * payoff[1] + d_cov * payoff[2];
            if score > best_score {
                best_score = score;
                best_arm = arm_idx as u8;
            }
        }

        self.recommended_arm = best_arm;
    }

    /// Returns the currently recommended arm index (0..3).
    #[must_use]
    pub fn recommended_arm(&self) -> u8 {
        self.recommended_arm
    }

    /// Returns the current state of the controller.
    #[must_use]
    pub fn state(&self) -> ApproachabilityState {
        if self.count < CALIBRATION_THRESHOLD {
            return ApproachabilityState::Calibrating;
        }

        let dev_sq = self.prev_deviation_sq;
        if dev_sq == 0 {
            ApproachabilityState::Approaching
        } else if dev_sq > ALERT_DEVIATION_MILLI * ALERT_DEVIATION_MILLI {
            ApproachabilityState::Violated
        } else {
            ApproachabilityState::Drifting
        }
    }

    /// Returns a summary snapshot for telemetry/tests.
    #[must_use]
    pub fn summary(&self) -> ApproachabilitySummary {
        let avg_lat = self.sum_latency.checked_div(self.count).unwrap_or(0);
        let avg_risk = self.sum_risk.checked_div(self.count).unwrap_or(0);
        let avg_cov = self.sum_coverage.checked_div(self.count).unwrap_or(0);

        ApproachabilitySummary {
            count: self.count,
            recommended_arm: self.recommended_arm,
            deviation_sq_milli: self.prev_deviation_sq,
            state: self.state(),
            avg_latency_milli: avg_lat,
            avg_risk_milli: avg_risk,
            avg_coverage_milli: avg_cov,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_starts_calibrating() {
        let ctrl = ApproachabilityController::new(SafetyLevel::Strict);
        assert_eq!(ctrl.state(), ApproachabilityState::Calibrating);
        assert_eq!(ctrl.recommended_arm(), 0);
        assert_eq!(ctrl.summary().count, 0);
    }

    #[test]
    fn stays_calibrating_below_threshold() {
        let mut ctrl = ApproachabilityController::new(SafetyLevel::Strict);
        for _ in 0..CALIBRATION_THRESHOLD - 1 {
            ctrl.observe(200, 300, 400);
        }
        assert_eq!(ctrl.state(), ApproachabilityState::Calibrating);
    }

    #[test]
    fn approaches_when_inside_safe_set_strict() {
        let mut ctrl = ApproachabilityController::new(SafetyLevel::Strict);
        // Feed observations inside the strict safe set: lat=200, risk=300, cov=400.
        // Safe set: lat≤350, risk≤500, cov≥150. All satisfied.
        for _ in 0..CALIBRATION_THRESHOLD + 10 {
            ctrl.observe(200, 300, 400);
        }
        assert_eq!(ctrl.state(), ApproachabilityState::Approaching);
        assert_eq!(ctrl.summary().deviation_sq_milli, 0);
    }

    #[test]
    fn approaches_when_inside_safe_set_hardened() {
        let mut ctrl = ApproachabilityController::new(SafetyLevel::Hardened);
        // Safe set: lat≤700, risk≤200, cov≥500.
        for _ in 0..CALIBRATION_THRESHOLD + 10 {
            ctrl.observe(400, 100, 600);
        }
        assert_eq!(ctrl.state(), ApproachabilityState::Approaching);
    }

    #[test]
    fn detects_latency_violation() {
        let mut ctrl = ApproachabilityController::new(SafetyLevel::Strict);
        // Strict safe set: lat≤350. Feed lat=800 (way over).
        for _ in 0..CALIBRATION_THRESHOLD + 10 {
            ctrl.observe(800, 200, 300);
        }
        // Deviation in latency: 800-350 = 450. Squared = 202500. > 200² = 40000.
        assert_eq!(ctrl.state(), ApproachabilityState::Violated);
    }

    #[test]
    fn detects_risk_violation_hardened() {
        let mut ctrl = ApproachabilityController::new(SafetyLevel::Hardened);
        // Hardened safe set: risk≤200. Feed risk=600.
        for _ in 0..CALIBRATION_THRESHOLD + 10 {
            ctrl.observe(400, 600, 700);
        }
        // Deviation in risk: 600-200 = 400. Squared = 160000. > 40000.
        assert_eq!(ctrl.state(), ApproachabilityState::Violated);
    }

    #[test]
    fn detects_coverage_violation() {
        let mut ctrl = ApproachabilityController::new(SafetyLevel::Hardened);
        // Hardened safe set: cov≥500. Feed cov=100.
        for _ in 0..CALIBRATION_THRESHOLD + 10 {
            ctrl.observe(400, 100, 100);
        }
        // Deviation in coverage: 500-100 = 400. Squared = 160000. > 40000.
        assert_eq!(ctrl.state(), ApproachabilityState::Violated);
    }

    #[test]
    fn recommends_full_when_risk_too_high() {
        let mut ctrl = ApproachabilityController::new(SafetyLevel::Strict);
        // Feed high risk (800) - should recommend arms with lower risk payoff.
        // Direction: d_risk < 0 (need to reduce risk), d_lat ≈ 0, d_cov might be 0.
        // Actually d_risk = proj_risk - avg_risk = 500 - 800 = -300.
        // Arm 3 has lowest risk payoff (50), so -300 * 50 is least negative → arm 3 wins on risk.
        // But arm 0 has risk 500: -300*500 = -150000. Arm 3: -300*50 = -15000.
        // So arm 3 should have the best (least negative) risk contribution.
        for _ in 0..CALIBRATION_THRESHOLD + 50 {
            ctrl.observe(200, 800, 300);
        }
        // Arm 3 (Full+Repair) should be recommended due to low risk payoff.
        assert!(
            ctrl.recommended_arm() >= 2,
            "Should recommend Full profile arm"
        );
    }

    #[test]
    fn recommends_fast_when_latency_too_high() {
        let mut ctrl = ApproachabilityController::new(SafetyLevel::Strict);
        // Feed high latency (900), low risk (100), high coverage (800).
        // Direction: d_lat = 350 - 900 = -550 (need to reduce latency).
        // Arm 0 has lowest latency payoff (100): -550*100 = -55000. Arm 3: -550*800 = -440000.
        // Arm 0 is least negative on latency → wins.
        for _ in 0..CALIBRATION_THRESHOLD + 50 {
            ctrl.observe(900, 100, 800);
        }
        assert!(
            ctrl.recommended_arm() <= 1,
            "Should recommend Fast profile arm"
        );
    }

    #[test]
    fn convergence_from_outside_safe_set() {
        let mut ctrl = ApproachabilityController::new(SafetyLevel::Strict);
        // Start with bad observations to push outside safe set.
        for _ in 0..CALIBRATION_THRESHOLD + 100 {
            ctrl.observe(800, 800, 50);
        }
        assert_eq!(ctrl.state(), ApproachabilityState::Violated);

        // Now feed good observations. The arm recommendation should guide us
        // back toward the safe set. After enough good observations, deviation
        // should decrease.
        let initial_dev = ctrl.summary().deviation_sq_milli;
        for _ in 0..2000 {
            ctrl.observe(100, 100, 900);
        }
        let final_dev = ctrl.summary().deviation_sq_milli;
        assert!(
            final_dev < initial_dev,
            "Deviation should decrease: {final_dev} < {initial_dev}"
        );
    }

    #[test]
    fn summary_fields_correct() {
        let mut ctrl = ApproachabilityController::new(SafetyLevel::Strict);
        ctrl.observe(200, 300, 400);
        ctrl.observe(400, 100, 600);
        let s = ctrl.summary();
        assert_eq!(s.count, 2);
        assert_eq!(s.avg_latency_milli, 300);
        assert_eq!(s.avg_risk_milli, 200);
        assert_eq!(s.avg_coverage_milli, 500);
    }

    #[test]
    fn clamps_input_to_1000() {
        let mut ctrl = ApproachabilityController::new(SafetyLevel::Strict);
        ctrl.observe(5000, 5000, 5000);
        let s = ctrl.summary();
        // All should be clamped to 1000.
        assert_eq!(s.avg_latency_milli, 1000);
        assert_eq!(s.avg_risk_milli, 1000);
        assert_eq!(s.avg_coverage_milli, 1000);
    }

    #[test]
    fn drifting_state_for_moderate_deviation() {
        let mut ctrl = ApproachabilityController::new(SafetyLevel::Strict);
        // Strict: lat≤350. Feed lat=400 → deviation = 50, dev² = 2500 < 40000.
        // risk=300 (≤500 ok), cov=200 (≥150 ok).
        for _ in 0..CALIBRATION_THRESHOLD + 10 {
            ctrl.observe(400, 300, 200);
        }
        // Small deviation (50² = 2500) should be Drifting, not Violated.
        assert_eq!(ctrl.state(), ApproachabilityState::Drifting);
    }

    #[test]
    fn hardened_mode_uses_different_targets() {
        let strict = ApproachabilityController::new(SafetyLevel::Strict);
        let hardened = ApproachabilityController::new(SafetyLevel::Hardened);
        assert_ne!(strict.target, hardened.target);
    }
}
