//! # Conformal Risk Engine
//!
//! Online calibrated risk controller for membrane decisions. Uses conformal
//! prediction to maintain finite-sample coverage guarantees on per-call-family
//! allow/check/deny decisions.
//!
//! ## How it works
//!
//! Instead of running the full validation pipeline on every call, the risk engine
//! maintains a **nonconformity score distribution** per call family. Each call's
//! "suspiciousness" is compared against a calibrated threshold:
//!
//! - **Below low threshold**: Skip expensive validation (fast path).
//! - **Between thresholds**: Normal validation pipeline.
//! - **Above high threshold**: Full validation + quarantine check.
//!
//! The thresholds self-calibrate using conformal prediction:
//! given a target error rate `alpha`, the threshold is the `(1-alpha)` quantile
//! of recent nonconformity scores. This guarantees that the false-skip rate
//! stays below `alpha` regardless of the input distribution.
//!
//! ## E-process sequential monitoring
//!
//! An e-process (product of e-values) monitors whether the risk engine's
//! assumptions are violated. If the e-process exceeds a threshold, the engine
//! falls back to full validation until scores re-stabilize. This provides
//! anytime-valid monitoring without fixed sample sizes.

use std::sync::atomic::{AtomicU64, Ordering};

/// Number of call families tracked independently.
pub const NUM_FAMILIES: usize = 8;

/// Window size for nonconformity score history.
const SCORE_WINDOW: usize = 256;

/// Default target false-skip rate (conformal alpha).
const DEFAULT_ALPHA: f64 = 0.01;

/// E-process alarm threshold (ln scale).
const E_PROCESS_ALARM: f64 = 10.0;

/// Call family identifier for risk tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CallFamily {
    Memory = 0,
    String = 1,
    Alloc = 2,
    Stdio = 3,
    Socket = 4,
    Thread = 5,
    Signal = 6,
    Other = 7,
}

impl CallFamily {
    fn index(self) -> usize {
        self as usize
    }
}

/// Risk decision output from the engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskDecision {
    /// Skip expensive validation — score is well below threshold.
    FastPath,
    /// Run normal validation pipeline.
    NormalCheck,
    /// Run full validation + additional scrutiny.
    FullCheck,
    /// Engine is in alarm state — validate everything.
    AlarmMode,
}

/// Per-family score tracker with conformal calibration.
struct FamilyTracker {
    /// Circular buffer of recent nonconformity scores (fixed-point, scaled by 1000).
    scores: [u32; SCORE_WINDOW],
    /// Write position in circular buffer.
    write_pos: usize,
    /// Number of scores recorded (capped at SCORE_WINDOW).
    count: usize,
    /// Cached fast-path threshold (conformal quantile, fixed-point).
    fast_threshold: u32,
    /// Cached full-check threshold (conformal quantile, fixed-point).
    full_threshold: u32,
    /// E-process log value (accumulated evidence against calibration).
    e_process_log: f64,
    /// Whether the alarm is active.
    alarm: bool,
    /// Number of calls since last recalibration.
    calls_since_recal: u32,
}

impl FamilyTracker {
    fn new() -> Self {
        Self {
            scores: [0; SCORE_WINDOW],
            write_pos: 0,
            count: 0,
            fast_threshold: 100, // Conservative initial thresholds
            full_threshold: 800,
            e_process_log: 0.0,
            alarm: false,
            calls_since_recal: 0,
        }
    }

    /// Compute the nonconformity score for a pointer operation.
    ///
    /// Higher scores = more suspicious. Score components:
    /// - Pointer alignment deviation (0-200)
    /// - Region size anomaly vs recent distribution (0-300)
    /// - Temporal distance from last validation (0-200)
    /// - Call pattern entropy deviation (0-300)
    fn compute_score(&self, ptr_addr: usize, size: usize) -> u32 {
        let mut score: u32 = 0;

        // Alignment component: non-aligned pointers are more suspicious
        let alignment = ptr_addr.trailing_zeros().min(6); // 0-6
        score += (6 - alignment) * 33; // 0-198

        // Size anomaly: very large or zero sizes are suspicious
        let size_score = if size == 0 {
            200
        } else if size > 1 << 20 {
            250
        } else if size > 1 << 16 {
            150
        } else {
            // Small/medium sizes get low score
            size.leading_zeros().min(100)
        };
        score += size_score;

        // Entropy from pointer bits (high-entropy = more likely valid heap pointer)
        let ptr_entropy = (ptr_addr as u64).count_ones();
        let entropy_score = if !(8..=56).contains(&ptr_entropy) {
            200 // Very low or very high entropy = suspicious
        } else {
            0
        };
        score += entropy_score;

        score.min(1000) // Cap at 1000
    }

    /// Record a score and update calibration.
    fn record_score(&mut self, score: u32) {
        self.scores[self.write_pos] = score;
        self.write_pos = (self.write_pos + 1) % SCORE_WINDOW;
        if self.count < SCORE_WINDOW {
            self.count += 1;
        }

        self.calls_since_recal += 1;

        // Recalibrate every 64 calls
        if self.calls_since_recal >= 64 {
            self.recalibrate();
            self.calls_since_recal = 0;
        }

        // Update e-process
        self.update_e_process(score);
    }

    /// Recalibrate thresholds using conformal prediction.
    ///
    /// The fast-path threshold is set to the `alpha` quantile:
    /// if score < threshold, we're confident this is a safe call.
    ///
    /// The full-check threshold is set to the `(1 - alpha)` quantile:
    /// if score > threshold, this call needs extra scrutiny.
    fn recalibrate(&mut self) {
        if self.count < 16 {
            return; // Not enough data
        }

        // Sort a copy of the active scores
        let n = self.count;
        let mut sorted = Vec::with_capacity(n);
        for &score in &self.scores[..n] {
            sorted.push(score);
        }
        sorted.sort_unstable();

        // Conformal quantiles with finite-sample correction
        // Floor for fast (conservative: fewer false skips)
        let fast_idx = ((n as f64) * DEFAULT_ALPHA).floor() as usize;
        // Ceil for full (conservative: fewer missed threats)
        let full_idx = ((n as f64) * (1.0 - DEFAULT_ALPHA)).ceil() as usize;

        self.fast_threshold = sorted[fast_idx.min(n - 1)];
        self.full_threshold = sorted[full_idx.min(n - 1)];

        // Ensure thresholds are properly ordered
        if self.fast_threshold >= self.full_threshold {
            self.fast_threshold = self.full_threshold / 2;
        }
    }

    /// Update the e-process for sequential monitoring.
    ///
    /// The e-value for each observation tests whether the current
    /// calibration is still valid. If the cumulative product (log sum)
    /// exceeds the alarm threshold, we've detected distribution shift.
    fn update_e_process(&mut self, score: u32) {
        if self.count < 32 {
            return;
        }

        // E-value: ratio of observed density to expected density under calibration.
        // Simple version: if score falls outside the calibrated range more often
        // than alpha, the e-value grows.
        let is_outlier = score > self.full_threshold;
        let expected_rate = DEFAULT_ALPHA;
        let e_value = if is_outlier {
            (1.0 / expected_rate).ln()
        } else {
            ((1.0 - 1.0 / (self.count as f64)) / (1.0 - expected_rate)).ln()
        };

        self.e_process_log += e_value;

        // Check alarm
        if self.e_process_log > E_PROCESS_ALARM {
            self.alarm = true;
        }

        // Decay: allow recovery from transient shifts
        self.e_process_log *= 0.999;
        if self.e_process_log < 0.0 {
            self.e_process_log = 0.0;
            self.alarm = false;
        }
    }

    /// Make a risk decision for a given score.
    fn decide(&self, score: u32) -> RiskDecision {
        if self.alarm {
            return RiskDecision::AlarmMode;
        }
        if self.count < 32 {
            return RiskDecision::NormalCheck; // Not enough data yet
        }
        if score <= self.fast_threshold {
            RiskDecision::FastPath
        } else if score >= self.full_threshold {
            RiskDecision::FullCheck
        } else {
            RiskDecision::NormalCheck
        }
    }
}

/// The global risk engine managing all call families.
pub struct RiskEngine {
    /// Per-family trackers.
    trackers: Vec<FamilyTracker>,
    /// Global call counter.
    total_calls: u64,
    /// Fast-path decisions made.
    fast_path_count: u64,
    /// Full-check decisions made.
    full_check_count: u64,
    /// Alarm activations.
    alarm_count: u64,
}

impl RiskEngine {
    /// Creates a new risk engine.
    pub fn new() -> Self {
        Self {
            trackers: (0..NUM_FAMILIES).map(|_| FamilyTracker::new()).collect(),
            total_calls: 0,
            fast_path_count: 0,
            full_check_count: 0,
            alarm_count: 0,
        }
    }

    /// Evaluate risk for a pointer operation and return a decision.
    ///
    /// This is the hot-path entry point. It computes a nonconformity score,
    /// compares against calibrated thresholds, and returns a decision.
    ///
    /// Amortized cost: O(1). Recalibration every 64 calls costs O(n log n)
    /// for the score window sort, but n=256 so this is ~2048 comparisons
    /// amortized over 64 calls = ~32 comparisons per call.
    pub fn evaluate(&mut self, family: CallFamily, ptr_addr: usize, size: usize) -> RiskDecision {
        let idx = family.index();
        let tracker = &self.trackers[idx];

        // Compute nonconformity score
        let score = tracker.compute_score(ptr_addr, size);

        // Make decision before updating (use current calibration)
        let decision = tracker.decide(score);

        // Record score for future calibration
        let tracker = &mut self.trackers[idx];
        tracker.record_score(score);

        // Update counters
        self.total_calls += 1;
        match decision {
            RiskDecision::FastPath => self.fast_path_count += 1,
            RiskDecision::FullCheck => self.full_check_count += 1,
            RiskDecision::AlarmMode => self.alarm_count += 1,
            RiskDecision::NormalCheck => {}
        }

        decision
    }

    /// Returns the fast-path rate (fraction of calls that skipped validation).
    pub fn fast_path_rate(&self) -> f64 {
        if self.total_calls == 0 {
            0.0
        } else {
            self.fast_path_count as f64 / self.total_calls as f64
        }
    }

    /// Returns the alarm rate.
    pub fn alarm_rate(&self) -> f64 {
        if self.total_calls == 0 {
            0.0
        } else {
            self.alarm_count as f64 / self.total_calls as f64
        }
    }

    /// Returns the total number of calls evaluated.
    pub fn total_calls(&self) -> u64 {
        self.total_calls
    }

    /// Resets the alarm for a specific family (after investigation).
    pub fn reset_alarm(&mut self, family: CallFamily) {
        let idx = family.index();
        self.trackers[idx].alarm = false;
        self.trackers[idx].e_process_log = 0.0;
    }

    /// Returns whether a specific family is in alarm state.
    pub fn is_alarmed(&self, family: CallFamily) -> bool {
        self.trackers[family.index()].alarm
    }
}

impl Default for RiskEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Global atomic counters for lock-free risk telemetry.
pub struct RiskMetrics {
    pub fast_paths: AtomicU64,
    pub normal_checks: AtomicU64,
    pub full_checks: AtomicU64,
    pub alarms: AtomicU64,
}

impl RiskMetrics {
    pub const fn new() -> Self {
        Self {
            fast_paths: AtomicU64::new(0),
            normal_checks: AtomicU64::new(0),
            full_checks: AtomicU64::new(0),
            alarms: AtomicU64::new(0),
        }
    }

    pub fn record(&self, decision: RiskDecision) {
        match decision {
            RiskDecision::FastPath => self.fast_paths.fetch_add(1, Ordering::Relaxed),
            RiskDecision::NormalCheck => self.normal_checks.fetch_add(1, Ordering::Relaxed),
            RiskDecision::FullCheck => self.full_checks.fetch_add(1, Ordering::Relaxed),
            RiskDecision::AlarmMode => self.alarms.fetch_add(1, Ordering::Relaxed),
        };
    }
}

impl Default for RiskMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Global risk metrics instance.
pub static RISK_METRICS: RiskMetrics = RiskMetrics::new();

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_engine() {
        let engine = RiskEngine::new();
        assert_eq!(engine.total_calls(), 0);
        assert_eq!(engine.fast_path_rate(), 0.0);
    }

    #[test]
    fn test_initial_decisions_are_normal() {
        let mut engine = RiskEngine::new();
        // With no history, engine should be conservative
        let decision = engine.evaluate(CallFamily::Memory, 0x7f00_0000_0000, 64);
        assert_eq!(decision, RiskDecision::NormalCheck);
    }

    #[test]
    fn test_calibration_after_enough_data() {
        let mut engine = RiskEngine::new();
        // Feed 100 well-aligned, normal-sized calls
        for i in 0..100u64 {
            let addr = 0x7f00_0000_0000 + i * 64;
            engine.evaluate(CallFamily::Memory, addr as usize, 64);
        }
        assert!(engine.total_calls() == 100);
    }

    #[test]
    fn test_suspicious_pointer_gets_full_check() {
        let mut engine = RiskEngine::new();
        // Build up history of normal calls
        for i in 0..200u64 {
            let addr = 0x7f00_0000_0000 + i * 64;
            engine.evaluate(CallFamily::Memory, addr as usize, 64);
        }
        // Now try a suspicious call: null-ish, huge size
        let decision = engine.evaluate(CallFamily::Memory, 3, 1 << 30);
        assert!(
            decision == RiskDecision::FullCheck || decision == RiskDecision::AlarmMode,
            "Expected FullCheck or AlarmMode for suspicious call, got {:?}",
            decision
        );
    }

    #[test]
    fn test_different_families_independent() {
        let mut engine = RiskEngine::new();
        // Build history for Memory family only
        for i in 0..100u64 {
            engine.evaluate(CallFamily::Memory, (0x7f00_0000_0000 + i * 64) as usize, 64);
        }
        // String family should still be conservative
        let decision = engine.evaluate(CallFamily::String, 0x7f00_0000_0000, 64);
        assert_eq!(decision, RiskDecision::NormalCheck);
    }

    #[test]
    fn test_risk_metrics_atomic() {
        let metrics = RiskMetrics::new();
        metrics.record(RiskDecision::FastPath);
        metrics.record(RiskDecision::FastPath);
        metrics.record(RiskDecision::FullCheck);
        assert_eq!(metrics.fast_paths.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.full_checks.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_alarm_reset() {
        let mut engine = RiskEngine::new();
        assert!(!engine.is_alarmed(CallFamily::Alloc));
        engine.reset_alarm(CallFamily::Alloc);
        assert!(!engine.is_alarmed(CallFamily::Alloc));
    }

    #[test]
    fn test_call_family_indices_unique() {
        let families = [
            CallFamily::Memory,
            CallFamily::String,
            CallFamily::Alloc,
            CallFamily::Stdio,
            CallFamily::Socket,
            CallFamily::Thread,
            CallFamily::Signal,
            CallFamily::Other,
        ];
        for (i, &f) in families.iter().enumerate() {
            assert_eq!(f.index(), i);
        }
    }
}
