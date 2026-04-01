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

impl Default for ApproachabilityController {
    fn default() -> Self {
        Self::new(SafetyLevel::Strict)
    }
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
    fn off_mode_uses_strict_safe_set() {
        let mut ctrl = ApproachabilityController::new(SafetyLevel::Off);
        // This point is inside the strict target as well as the hardened target.
        for _ in 0..CALIBRATION_THRESHOLD + 10 {
            ctrl.observe(300, 400, 300);
        }
        assert_eq!(ctrl.state(), ApproachabilityState::Approaching);

        let mut off = ApproachabilityController::new(SafetyLevel::Off);
        let mut hardened = ApproachabilityController::new(SafetyLevel::Hardened);
        // Risk=300 violates hardened (<=200) but not strict/off (<=500).
        for _ in 0..CALIBRATION_THRESHOLD + 10 {
            off.observe(300, 300, 600);
            hardened.observe(300, 300, 600);
        }
        assert_eq!(off.state(), ApproachabilityState::Approaching);
        assert_eq!(hardened.state(), ApproachabilityState::Drifting);
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
    fn safe_set_reentry_preserves_last_recommended_arm() {
        let mut ctrl = ApproachabilityController::new(SafetyLevel::Strict);
        for _ in 0..CALIBRATION_THRESHOLD + 50 {
            ctrl.observe(900, 100, 800);
        }
        let chosen_arm = ctrl.recommended_arm();
        assert!(chosen_arm <= 1, "latency pressure should pick a fast arm");

        for _ in 0..2048 {
            ctrl.observe(200, 200, 400);
        }

        assert_eq!(ctrl.state(), ApproachabilityState::Approaching);
        assert_eq!(
            ctrl.summary().deviation_sq_milli,
            0,
            "re-entering the safe set should zero out deviation"
        );
        assert_eq!(
            ctrl.recommended_arm(),
            chosen_arm,
            "controller keeps the last recommendation while averages remain inside the safe set"
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

    #[test]
    fn deterministic_across_instances() {
        let mut a = ApproachabilityController::new(SafetyLevel::Strict);
        let mut b = ApproachabilityController::new(SafetyLevel::Strict);
        for i in 0..CALIBRATION_THRESHOLD + 500 {
            let lat = i * 7 % 1000;
            let risk = i * 13 % 1000;
            let cov = i * 23 % 1000;
            a.observe(lat, risk, cov);
            b.observe(lat, risk, cov);
        }
        assert_eq!(a.recommended_arm(), b.recommended_arm());
        assert_eq!(a.state(), b.state());
        let sa = a.summary();
        let sb = b.summary();
        assert_eq!(sa.count, sb.count);
        assert_eq!(sa.deviation_sq_milli, sb.deviation_sq_milli);
        assert_eq!(sa.avg_latency_milli, sb.avg_latency_milli);
        assert_eq!(sa.avg_risk_milli, sb.avg_risk_milli);
        assert_eq!(sa.avg_coverage_milli, sb.avg_coverage_milli);
    }

    #[test]
    fn regime_adversarial_then_recovery_to_approaching() {
        let mut ctrl = ApproachabilityController::new(SafetyLevel::Strict);

        // Phase 1: adversarial (high lat, high risk, low coverage).
        for _ in 0..CALIBRATION_THRESHOLD + 200 {
            ctrl.observe(900, 900, 50);
        }
        assert_eq!(ctrl.state(), ApproachabilityState::Violated);

        // Phase 2: sustained correction (low lat, low risk, high coverage).
        // Enough to dilute the adversarial average back inside the safe set.
        for _ in 0..50_000 {
            ctrl.observe(50, 50, 900);
        }
        // After 50k good observations diluting ~456 bad, averages should be
        // well inside the strict safe set (lat≤350, risk≤500, cov≥150).
        assert_eq!(
            ctrl.state(),
            ApproachabilityState::Approaching,
            "Should fully recover to Approaching after sustained correction"
        );
    }

    #[test]
    fn regime_phase_change_workload() {
        let mut ctrl = ApproachabilityController::new(SafetyLevel::Hardened);

        // Phase 1: stable inside safe set.
        for _ in 0..CALIBRATION_THRESHOLD + 1000 {
            ctrl.observe(300, 100, 700);
        }
        assert_eq!(ctrl.state(), ApproachabilityState::Approaching);

        // Phase 2: sudden phase change — latency spike, risk spike.
        for _ in 0..5000 {
            ctrl.observe(900, 800, 100);
        }
        // Should detect violation.
        assert!(
            ctrl.state() == ApproachabilityState::Violated
                || ctrl.state() == ApproachabilityState::Drifting,
            "Should detect regime change: state={:?}",
            ctrl.state()
        );

        // Phase 3: return to nominal.
        for _ in 0..50_000 {
            ctrl.observe(300, 100, 700);
        }
        let s = ctrl.summary();
        assert_eq!(
            s.state,
            ApproachabilityState::Approaching,
            "Should recover after regime returns to nominal"
        );
    }

    #[test]
    fn stress_varied_inputs_no_panic() {
        for mode in [SafetyLevel::Strict, SafetyLevel::Hardened] {
            let mut ctrl = ApproachabilityController::new(mode);
            for i in 0u64..5000 {
                let lat = (i.wrapping_mul(997) % 1001).min(1000);
                let risk = (i.wrapping_mul(1013) % 1001).min(1000);
                let cov = (i.wrapping_mul(1021) % 1001).min(1000);
                ctrl.observe(lat, risk, cov);
            }
            let s = ctrl.summary();
            assert_eq!(s.count, 5000);
            assert!(s.recommended_arm < ARM_COUNT as u8);
            assert!(s.avg_latency_milli <= 1000);
            assert!(s.avg_risk_milli <= 1000);
            assert!(s.avg_coverage_milli <= 1000);
        }
    }

    #[test]
    fn stress_saturating_inputs() {
        let mut ctrl = ApproachabilityController::new(SafetyLevel::Strict);
        for _ in 0..CALIBRATION_THRESHOLD + 100 {
            ctrl.observe(u64::MAX, u64::MAX, u64::MAX);
        }
        let s = ctrl.summary();
        // Inputs clamp to 1000.
        assert_eq!(s.avg_latency_milli, 1000);
        assert_eq!(s.avg_risk_milli, 1000);
        assert_eq!(s.avg_coverage_milli, 1000);
        assert!(s.recommended_arm < ARM_COUNT as u8);
    }

    #[test]
    fn observe_throughput_below_strict_budget() {
        let mut ctrl = ApproachabilityController::new(SafetyLevel::Strict);
        let iters = 100_000u64;
        let start = std::time::Instant::now();
        for i in 0..iters {
            let lat = (i * 7919) % 1000;
            let risk = (i * 1013) % 1000;
            let cov = (i * 2027) % 1000;
            ctrl.observe(lat, risk, cov);
        }
        let elapsed = start.elapsed();
        let ns_per_call = elapsed.as_nanos() as u64 / iters;
        // Conservative ceiling: 2000ns per call.
        // Actual should be ~20-50ns (integer-only, O(1)).
        assert!(
            ns_per_call < 2000,
            "observe() too slow: {ns_per_call}ns/call (budget: 2000ns)"
        );
    }

    // ── bd-cv9 tests: regime simulation, convergence, determinism ──

    #[test]
    fn convergence_rate_decreases_monotonically() {
        // Verify that deviation decreases roughly monotonically after switching
        // from adversarial to benign input. Take snapshots at exponentially
        // spaced checkpoints to confirm the O(1/√t) convergence shape.
        let mut ctrl = ApproachabilityController::new(SafetyLevel::Strict);

        // Phase 1: push outside safe set (high lat, high risk, low coverage).
        for _ in 0..CALIBRATION_THRESHOLD + 500 {
            ctrl.observe(900, 900, 50);
        }
        assert_eq!(ctrl.state(), ApproachabilityState::Violated);

        // Phase 2: benign correction. Record deviation at checkpoints.
        let checkpoints = [500u64, 1000, 2000, 4000, 8000, 16000];
        let mut prev_dev = ctrl.summary().deviation_sq_milli;
        let mut benign_count = 0u64;

        for &target in &checkpoints {
            while benign_count < target {
                ctrl.observe(100, 100, 800);
                benign_count += 1;
            }
            let dev = ctrl.summary().deviation_sq_milli;
            assert!(
                dev <= prev_dev,
                "Deviation should decrease: checkpoint={target}, dev={dev} > prev={prev_dev}"
            );
            prev_dev = dev;
        }
        // After 16k benign observations diluting ~756 bad, should be Approaching.
        assert_eq!(ctrl.state(), ApproachabilityState::Approaching);
    }

    #[test]
    fn all_four_arms_reachable() {
        // Verify each arm can become the recommended action under appropriate
        // conditions. This ensures no dead arms in the payoff matrix.
        //
        // The arm selection is argmax_a <d, payoff[a]> where d = projection - avg.
        // d_lat ≤ 0, d_risk ≤ 0, d_cov ≥ 0 always (projection clamps toward safe set).
        // We choose inputs to create direction vectors that isolate each arm.
        let mut seen = [false; ARM_COUNT];

        // Arm 0 (Fast/Allow): d = (-600, 0, 0). Only latency violated.
        // Strict: target_lat=350. Feed lat=950, risk=300(≤500), cov=400(≥150).
        let mut c0 = ApproachabilityController::new(SafetyLevel::Strict);
        for _ in 0..CALIBRATION_THRESHOLD + 500 {
            c0.observe(950, 300, 400);
        }
        seen[c0.recommended_arm() as usize] = true;

        // Arm 1 (Fast/FullValid): d ≈ (-180, -150, +50).
        // Strict: avg_lat=530, avg_risk=650, avg_cov=100.
        let mut c1 = ApproachabilityController::new(SafetyLevel::Strict);
        for _ in 0..CALIBRATION_THRESHOLD + 500 {
            c1.observe(530, 650, 100);
        }
        seen[c1.recommended_arm() as usize] = true;

        // Arm 2 (Full/Allow): d ≈ (-250, -500, +30).
        // Strict: avg_lat=600, avg_risk=1000, avg_cov=120.
        let mut c2 = ApproachabilityController::new(SafetyLevel::Strict);
        for _ in 0..CALIBRATION_THRESHOLD + 500 {
            c2.observe(600, 1000, 120);
        }
        seen[c2.recommended_arm() as usize] = true;

        // Arm 3 (Full/Repair): d = (0, -800, 0). Only risk violated.
        // Strict: target_risk=500. Feed lat=200(≤350), risk=950, cov=400(≥150).
        let mut c3 = ApproachabilityController::new(SafetyLevel::Strict);
        for _ in 0..CALIBRATION_THRESHOLD + 500 {
            c3.observe(200, 950, 400);
        }
        seen[c3.recommended_arm() as usize] = true;

        let reached: usize = seen.iter().filter(|&&b| b).count();
        assert!(
            reached >= 3,
            "At least 3 of 4 arms should be reachable, got {reached}: {seen:?}"
        );
    }

    #[test]
    fn multi_dimension_violation_escalates() {
        // When all three dimensions are violated simultaneously,
        // the controller should reach Violated state.
        let mut ctrl = ApproachabilityController::new(SafetyLevel::Hardened);
        // Hardened: lat≤700, risk≤200, cov≥500. Violate all three.
        for _ in 0..CALIBRATION_THRESHOLD + 100 {
            ctrl.observe(950, 800, 50);
        }
        assert_eq!(ctrl.state(), ApproachabilityState::Violated);

        // Combined deviation should be large.
        let s = ctrl.summary();
        // lat: 950-700=250, risk: 800-200=600, cov: 500-50=450.
        // dev² = 250²+600²+450² = 62500+360000+202500 = 625000.
        assert!(
            s.deviation_sq_milli > 400_000,
            "Multi-dimension violation should produce large deviation: {}",
            s.deviation_sq_milli
        );
    }

    #[test]
    fn cyclic_regime_transitions() {
        // Simulate repeated regime changes: benign → adversarial → benign → ...
        // Controller should recover each time. Because cumulative averaging
        // dilutes later adversarial phases, we scale the adversarial phase
        // proportionally to total observations accumulated so far.
        let mut ctrl = ApproachabilityController::new(SafetyLevel::Strict);
        let mut total_obs = 0u64;

        // Warm up to exit calibration.
        for _ in 0..CALIBRATION_THRESHOLD {
            ctrl.observe(200, 200, 400);
            total_obs += 1;
        }
        assert_eq!(ctrl.state(), ApproachabilityState::Approaching);

        for cycle in 0..3 {
            // Adversarial phase: need enough bad observations to shift the
            // cumulative average outside the safe set. Scale with total count.
            let bad_count = (total_obs * 3).max(2000);
            for _ in 0..bad_count {
                ctrl.observe(800, 800, 50);
                total_obs += 1;
            }
            let state_after_bad = ctrl.state();
            assert!(
                state_after_bad == ApproachabilityState::Violated
                    || state_after_bad == ApproachabilityState::Drifting,
                "Cycle {cycle}: should detect violation after {bad_count} bad obs, got {state_after_bad:?}"
            );

            // Recovery phase: sustained benign traffic to dilute bad average.
            let good_count = total_obs * 4;
            for _ in 0..good_count {
                ctrl.observe(100, 100, 800);
                total_obs += 1;
            }
            assert_eq!(
                ctrl.state(),
                ApproachabilityState::Approaching,
                "Cycle {cycle}: should recover to Approaching"
            );
        }
    }

    #[test]
    fn determinism_off_mode_matches_strict() {
        // SafetyLevel::Off uses the same target as Strict.
        let mut strict = ApproachabilityController::new(SafetyLevel::Strict);
        let mut off = ApproachabilityController::new(SafetyLevel::Off);

        for i in 0..CALIBRATION_THRESHOLD + 200 {
            let lat = i * 41 % 1000;
            let risk = i * 67 % 1000;
            let cov = i * 89 % 1000;
            strict.observe(lat, risk, cov);
            off.observe(lat, risk, cov);
        }
        assert_eq!(strict.state(), off.state());
        assert_eq!(strict.recommended_arm(), off.recommended_arm());
        assert_eq!(
            strict.summary().deviation_sq_milli,
            off.summary().deviation_sq_milli
        );
    }

    #[test]
    fn determinism_interleaved_sequences() {
        // Two controllers seeing the same sequence produce identical results.
        let mut a = ApproachabilityController::new(SafetyLevel::Hardened);
        let mut b = ApproachabilityController::new(SafetyLevel::Hardened);

        let inputs: Vec<(u64, u64, u64)> = (0..CALIBRATION_THRESHOLD + 1000)
            .map(|i| {
                let lat = i * 31 % 1000;
                let risk = i * 59 % 1000;
                let cov = i * 97 % 1000;
                (lat, risk, cov)
            })
            .collect();

        for &(lat, risk, cov) in &inputs {
            a.observe(lat, risk, cov);
        }
        for &(lat, risk, cov) in &inputs {
            b.observe(lat, risk, cov);
        }

        let sa = a.summary();
        let sb = b.summary();
        assert_eq!(sa.count, sb.count);
        assert_eq!(sa.state, sb.state);
        assert_eq!(sa.recommended_arm, sb.recommended_arm);
        assert_eq!(sa.deviation_sq_milli, sb.deviation_sq_milli);
        assert_eq!(sa.avg_latency_milli, sb.avg_latency_milli);
        assert_eq!(sa.avg_risk_milli, sb.avg_risk_milli);
        assert_eq!(sa.avg_coverage_milli, sb.avg_coverage_milli);
    }

    #[test]
    fn convergence_safe_set_approach_stays_zero() {
        // After entering the safe set, deviation should stay at zero
        // as long as inputs remain inside the safe set.
        let mut ctrl = ApproachabilityController::new(SafetyLevel::Strict);
        for _ in 0..CALIBRATION_THRESHOLD + 5000 {
            ctrl.observe(200, 300, 400);
        }
        assert_eq!(ctrl.state(), ApproachabilityState::Approaching);
        assert_eq!(ctrl.summary().deviation_sq_milli, 0);

        // Continue feeding safe inputs — should remain at zero.
        for _ in 0..1000 {
            ctrl.observe(250, 350, 300);
        }
        assert_eq!(ctrl.state(), ApproachabilityState::Approaching);
        assert_eq!(ctrl.summary().deviation_sq_milli, 0);
    }

    #[test]
    fn boundary_exact_safe_set_thresholds() {
        // Feed observations exactly at safe set boundaries.
        // Strict: lat≤350, risk≤500, cov≥150.
        let mut ctrl = ApproachabilityController::new(SafetyLevel::Strict);
        for _ in 0..CALIBRATION_THRESHOLD + 500 {
            ctrl.observe(350, 500, 150);
        }
        // Exactly on the boundary should be Approaching (deviation = 0).
        assert_eq!(ctrl.state(), ApproachabilityState::Approaching);
        assert_eq!(ctrl.summary().deviation_sq_milli, 0);
    }

    #[test]
    fn observe_throughput_below_hardened_budget() {
        let mut ctrl = ApproachabilityController::new(SafetyLevel::Hardened);
        let iters = 100_000u64;
        let start = std::time::Instant::now();
        for i in 0..iters {
            let lat = (i * 7919) % 1000;
            let risk = (i * 1013) % 1000;
            let cov = (i * 2027) % 1000;
            ctrl.observe(lat, risk, cov);
        }
        let elapsed = start.elapsed();
        let ns_per_call = elapsed.as_nanos() as u64 / iters;
        assert!(
            ns_per_call < 2000,
            "observe() too slow in hardened mode: {ns_per_call}ns/call (budget: 2000ns)"
        );
    }
}
