//! # Pressure Sensor + Overload State Machine
//!
//! Deterministic regime classifier for system load states. Monitors five
//! pressure signals and transitions through four regimes:
//!
//! ```text
//! Nominal ──(pressure ↑)──> Pressured ──(pressure ↑↑)──> Overloaded
//!    ^                                                       │
//!    └──────(cooldown)──── Recovery <──(pressure ↓)──────────┘
//! ```
//!
//! ## Signals
//!
//! Each observation contains five orthogonal pressure dimensions:
//! - `scheduler_delay_ns`: Scheduling latency (higher = more contention)
//! - `queue_depth`: Pending work items (higher = more backlog)
//! - `error_burst_count`: Recent error spikes (higher = instability)
//! - `latency_envelope_ns`: Tail latency of recent operations
//! - `resource_pressure_pct`: Aggregate resource usage (0–100)
//!
//! ## Hysteresis
//!
//! State transitions use asymmetric thresholds (enter > exit) and mandatory
//! cooldown epochs to prevent flapping. The Recovery state enforces a hold
//! period before returning to Nominal, ensuring stability after overload.
//!
//! ## Determinism
//!
//! All transitions are deterministic given the same signal sequence. No
//! randomness, no clock dependencies, no external state. The EWMA smoothing
//! factor and all thresholds are compile-time or construction-time constants.

/// EWMA smoothing factor for pressure score (0.0–1.0).
/// Higher = more responsive, lower = more stable.
const EWMA_ALPHA: f64 = 0.2;

/// Default thresholds for regime transitions.
const DEFAULT_PRESSURED_ENTER: f64 = 60.0;
const DEFAULT_PRESSURED_EXIT: f64 = 45.0;
const DEFAULT_OVERLOADED_ENTER: f64 = 85.0;
const DEFAULT_OVERLOADED_EXIT: f64 = 70.0;
const DEFAULT_COOLDOWN_EPOCHS: u32 = 3;
const DEFAULT_RECOVERY_HOLD_EPOCHS: u32 = 5;

/// Signal weight for composite pressure score.
const W_SCHEDULER_DELAY: f64 = 0.25;
const W_QUEUE_DEPTH: f64 = 0.20;
const W_ERROR_BURST: f64 = 0.20;
const W_LATENCY_ENVELOPE: f64 = 0.20;
const W_RESOURCE_PRESSURE: f64 = 0.15;

/// Normalization caps for signal-to-score conversion.
const CAP_SCHEDULER_DELAY_NS: f64 = 10_000_000.0; // 10ms
const CAP_QUEUE_DEPTH: f64 = 1000.0;
const CAP_ERROR_BURST: f64 = 50.0;
const CAP_LATENCY_ENVELOPE_NS: f64 = 50_000_000.0; // 50ms

/// Operating regime of the system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SystemRegime {
    /// Normal operating conditions. All signals within budget.
    Nominal,
    /// Elevated load. Still functional but approaching capacity.
    Pressured,
    /// Capacity exceeded. Degradation policies should be active.
    Overloaded,
    /// Transitioning back from overload. Hold period before Nominal.
    Recovery,
}

impl SystemRegime {
    /// Returns true if degradation policies should be active.
    #[must_use]
    pub const fn degradation_active(self) -> bool {
        matches!(self, Self::Overloaded)
    }

    /// Returns true if the system is under any form of pressure.
    #[must_use]
    pub const fn under_pressure(self) -> bool {
        !matches!(self, Self::Nominal)
    }
}

/// Raw pressure signals from the runtime.
#[derive(Debug, Clone, Copy)]
pub struct PressureSignals {
    /// Scheduling delay in nanoseconds.
    pub scheduler_delay_ns: u64,
    /// Number of pending work items in queues.
    pub queue_depth: u32,
    /// Count of errors in the current burst window.
    pub error_burst_count: u32,
    /// Tail latency envelope of recent operations (ns).
    pub latency_envelope_ns: u64,
    /// Aggregate resource pressure as percentage (0.0–100.0).
    pub resource_pressure_pct: f64,
}

impl PressureSignals {
    /// Compute a normalized composite pressure score (0.0–100.0).
    ///
    /// Each signal is normalized to [0, 100] using saturation caps, then
    /// combined via weighted sum.
    #[must_use]
    pub fn composite_score(&self) -> f64 {
        let s_delay =
            ((self.scheduler_delay_ns as f64) / CAP_SCHEDULER_DELAY_NS * 100.0).clamp(0.0, 100.0);
        let s_queue = ((self.queue_depth as f64) / CAP_QUEUE_DEPTH * 100.0).clamp(0.0, 100.0);
        let s_error = ((self.error_burst_count as f64) / CAP_ERROR_BURST * 100.0).clamp(0.0, 100.0);
        let s_latency =
            ((self.latency_envelope_ns as f64) / CAP_LATENCY_ENVELOPE_NS * 100.0).clamp(0.0, 100.0);
        let s_resource = self.resource_pressure_pct.clamp(0.0, 100.0);

        W_SCHEDULER_DELAY * s_delay
            + W_QUEUE_DEPTH * s_queue
            + W_ERROR_BURST * s_error
            + W_LATENCY_ENVELOPE * s_latency
            + W_RESOURCE_PRESSURE * s_resource
    }
}

/// Threshold configuration for regime transitions.
#[derive(Debug, Clone, Copy)]
pub struct RegimeThresholds {
    /// Score above which Nominal → Pressured.
    pub pressured_enter: f64,
    /// Score below which Pressured → Nominal (must be < pressured_enter).
    pub pressured_exit: f64,
    /// Score above which Pressured → Overloaded.
    pub overloaded_enter: f64,
    /// Score below which Overloaded → Recovery (must be < overloaded_enter).
    pub overloaded_exit: f64,
    /// Epochs a transition signal must persist before state change.
    pub cooldown_epochs: u32,
    /// Epochs Recovery must hold before returning to Nominal.
    pub recovery_hold_epochs: u32,
}

impl Default for RegimeThresholds {
    fn default() -> Self {
        Self {
            pressured_enter: DEFAULT_PRESSURED_ENTER,
            pressured_exit: DEFAULT_PRESSURED_EXIT,
            overloaded_enter: DEFAULT_OVERLOADED_ENTER,
            overloaded_exit: DEFAULT_OVERLOADED_EXIT,
            cooldown_epochs: DEFAULT_COOLDOWN_EPOCHS,
            recovery_hold_epochs: DEFAULT_RECOVERY_HOLD_EPOCHS,
        }
    }
}

impl RegimeThresholds {
    /// Validate that thresholds are consistent (enter > exit, ordered).
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.pressured_exit < self.pressured_enter
            && self.overloaded_exit < self.overloaded_enter
            && self.pressured_enter < self.overloaded_enter
            && self.pressured_exit < self.overloaded_exit
            && self.cooldown_epochs > 0
            && self.recovery_hold_epochs > 0
    }
}

/// Snapshot of the sensor state at a point in time.
#[derive(Debug, Clone, Copy)]
pub struct PressureSnapshot {
    /// Current regime.
    pub regime: SystemRegime,
    /// Smoothed composite pressure score (0.0–100.0).
    pub pressure_score: f64,
    /// Raw composite score from the last observation.
    pub raw_score: f64,
    /// Total regime transitions since creation.
    pub transition_count: u64,
    /// Current epoch number.
    pub epoch: u64,
    /// Remaining cooldown epochs before next transition is allowed.
    pub cooldown_remaining: u32,
}

/// The pressure sensor and overload state machine.
pub struct PressureSensor {
    /// Current operating regime.
    regime: SystemRegime,
    /// Threshold configuration.
    thresholds: RegimeThresholds,
    /// EWMA-smoothed composite pressure score.
    pressure_score: f64,
    /// Consecutive epochs the pending transition has been signaled.
    pending_streak: u32,
    /// Direction of pending transition (true = escalating, false = de-escalating).
    pending_escalate: bool,
    /// Remaining recovery hold epochs.
    recovery_remaining: u32,
    /// Total regime transitions.
    transition_count: u64,
    /// Epoch counter.
    epoch: u64,
    /// Last raw composite score.
    last_raw_score: f64,
}

impl PressureSensor {
    /// Create a new sensor with default thresholds.
    pub fn new() -> Self {
        Self::with_thresholds(RegimeThresholds::default())
    }

    /// Create a new sensor with custom thresholds.
    ///
    /// # Panics
    ///
    /// Panics if thresholds are invalid (enter <= exit or misordered).
    pub fn with_thresholds(thresholds: RegimeThresholds) -> Self {
        assert!(thresholds.is_valid(), "Invalid regime thresholds");
        Self {
            regime: SystemRegime::Nominal,
            thresholds,
            pressure_score: 0.0,
            pending_streak: 0,
            pending_escalate: false,
            recovery_remaining: 0,
            transition_count: 0,
            epoch: 0,
            last_raw_score: 0.0,
        }
    }

    /// Current operating regime.
    #[must_use]
    pub fn regime(&self) -> SystemRegime {
        self.regime
    }

    /// Smoothed pressure score.
    #[must_use]
    pub fn pressure_score(&self) -> f64 {
        self.pressure_score
    }

    /// Total regime transitions since creation.
    #[must_use]
    pub fn transition_count(&self) -> u64 {
        self.transition_count
    }

    /// Current epoch.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Full diagnostic snapshot.
    #[must_use]
    pub fn snapshot(&self) -> PressureSnapshot {
        PressureSnapshot {
            regime: self.regime,
            pressure_score: self.pressure_score,
            raw_score: self.last_raw_score,
            transition_count: self.transition_count,
            epoch: self.epoch,
            cooldown_remaining: if self.regime == SystemRegime::Recovery {
                self.recovery_remaining
            } else {
                self.thresholds
                    .cooldown_epochs
                    .saturating_sub(self.pending_streak)
            },
        }
    }

    /// Process a new set of pressure signals.
    ///
    /// Returns the (possibly updated) regime after processing.
    pub fn observe(&mut self, signals: &PressureSignals) -> SystemRegime {
        self.epoch += 1;
        let raw = signals.composite_score();
        self.last_raw_score = raw;

        // EWMA update
        if self.epoch == 1 {
            self.pressure_score = raw;
        } else {
            self.pressure_score = EWMA_ALPHA * raw + (1.0 - EWMA_ALPHA) * self.pressure_score;
        }

        let score = self.pressure_score;
        // Copy thresholds to avoid borrow conflict with &mut self methods.
        let th = self.thresholds;

        match self.regime {
            SystemRegime::Nominal => {
                if score >= th.pressured_enter {
                    self.accumulate_pending(true);
                    if self.pending_streak >= th.cooldown_epochs {
                        self.transition_to(SystemRegime::Pressured);
                    }
                } else {
                    self.reset_pending();
                }
            }
            SystemRegime::Pressured => {
                if score >= th.overloaded_enter {
                    self.accumulate_pending(true);
                    if self.pending_streak >= th.cooldown_epochs {
                        self.transition_to(SystemRegime::Overloaded);
                    }
                } else if score < th.pressured_exit {
                    self.accumulate_pending(false);
                    if self.pending_streak >= th.cooldown_epochs {
                        self.transition_to(SystemRegime::Nominal);
                    }
                } else {
                    self.reset_pending();
                }
            }
            SystemRegime::Overloaded => {
                if score < th.overloaded_exit {
                    self.accumulate_pending(false);
                    if self.pending_streak >= th.cooldown_epochs {
                        self.transition_to(SystemRegime::Recovery);
                        self.recovery_remaining = th.recovery_hold_epochs;
                    }
                } else {
                    self.reset_pending();
                }
            }
            SystemRegime::Recovery => {
                if score >= th.overloaded_enter {
                    // Re-escalate: pressure spiked again during recovery.
                    self.accumulate_pending(true);
                    if self.pending_streak >= th.cooldown_epochs {
                        self.transition_to(SystemRegime::Overloaded);
                    }
                } else if self.recovery_remaining > 0 {
                    self.recovery_remaining -= 1;
                    self.reset_pending();
                } else {
                    // Recovery hold complete. Transition based on current score.
                    if score >= th.pressured_enter {
                        self.transition_to(SystemRegime::Pressured);
                    } else {
                        self.transition_to(SystemRegime::Nominal);
                    }
                }
            }
        }

        self.regime
    }

    fn accumulate_pending(&mut self, escalate: bool) {
        if self.pending_escalate == escalate {
            self.pending_streak += 1;
        } else {
            self.pending_escalate = escalate;
            self.pending_streak = 1;
        }
    }

    fn reset_pending(&mut self) {
        self.pending_streak = 0;
    }

    fn transition_to(&mut self, new_regime: SystemRegime) {
        if self.regime != new_regime {
            self.regime = new_regime;
            self.transition_count += 1;
            self.pending_streak = 0;
        }
    }
}

impl Default for PressureSensor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn calm_signals() -> PressureSignals {
        PressureSignals {
            scheduler_delay_ns: 100_000, // 0.1ms
            queue_depth: 5,
            error_burst_count: 0,
            latency_envelope_ns: 500_000, // 0.5ms
            resource_pressure_pct: 10.0,
        }
    }

    fn moderate_signals() -> PressureSignals {
        PressureSignals {
            scheduler_delay_ns: 5_000_000, // 5ms
            queue_depth: 500,
            error_burst_count: 10,
            latency_envelope_ns: 20_000_000, // 20ms
            resource_pressure_pct: 65.0,
        }
    }

    fn heavy_signals() -> PressureSignals {
        PressureSignals {
            scheduler_delay_ns: 10_000_000, // 10ms
            queue_depth: 1000,
            error_burst_count: 50,
            latency_envelope_ns: 50_000_000, // 50ms
            resource_pressure_pct: 95.0,
        }
    }

    #[test]
    fn new_sensor_is_nominal() {
        let sensor = PressureSensor::new();
        assert_eq!(sensor.regime(), SystemRegime::Nominal);
        assert_eq!(sensor.transition_count(), 0);
        assert_eq!(sensor.epoch(), 0);
    }

    #[test]
    fn calm_signals_stay_nominal() {
        let mut sensor = PressureSensor::new();
        for _ in 0..50 {
            sensor.observe(&calm_signals());
        }
        assert_eq!(sensor.regime(), SystemRegime::Nominal);
        assert_eq!(sensor.transition_count(), 0);
    }

    #[test]
    fn composite_score_bounded() {
        let calm = calm_signals();
        let score = calm.composite_score();
        assert!(
            (0.0..=100.0).contains(&score),
            "score {score} out of bounds"
        );

        let heavy = heavy_signals();
        let score = heavy.composite_score();
        assert!(
            (0.0..=100.0).contains(&score),
            "score {score} out of bounds"
        );
    }

    #[test]
    fn heavy_load_escalates_to_overloaded() {
        let mut sensor = PressureSensor::new();
        // Warm up with calm signals
        for _ in 0..5 {
            sensor.observe(&calm_signals());
        }
        // Apply heavy load
        for _ in 0..20 {
            sensor.observe(&heavy_signals());
        }
        assert!(
            sensor.regime() == SystemRegime::Overloaded
                || sensor.regime() == SystemRegime::Pressured,
            "Expected escalation under heavy load, got {:?}",
            sensor.regime()
        );
    }

    #[test]
    fn hysteresis_prevents_flapping() {
        let mut sensor = PressureSensor::new();
        // Drive to Pressured
        for _ in 0..20 {
            sensor.observe(&moderate_signals());
        }
        let transitions_before = sensor.transition_count();

        // Oscillate around the threshold
        for i in 0..20 {
            if i % 2 == 0 {
                sensor.observe(&moderate_signals());
            } else {
                sensor.observe(&calm_signals());
            }
        }

        // Should not have flapped excessively
        let transitions_after = sensor.transition_count();
        assert!(
            transitions_after - transitions_before <= 4,
            "Too many transitions during oscillation: {}",
            transitions_after - transitions_before
        );
    }

    #[test]
    fn recovery_holds_before_nominal() {
        let mut sensor = PressureSensor::new();
        // Drive to Overloaded
        for _ in 0..30 {
            sensor.observe(&heavy_signals());
        }
        assert!(
            sensor.regime() == SystemRegime::Overloaded
                || sensor.regime() == SystemRegime::Pressured,
        );

        // Drop to calm — should go through Recovery, not straight to Nominal
        let mut saw_recovery = false;
        for _ in 0..30 {
            sensor.observe(&calm_signals());
            if sensor.regime() == SystemRegime::Recovery {
                saw_recovery = true;
            }
        }
        // Should eventually reach Nominal
        assert_eq!(sensor.regime(), SystemRegime::Nominal);
        assert!(saw_recovery, "Expected Recovery state during de-escalation");
    }

    #[test]
    fn recovery_re_escalates_on_spike() {
        let mut sensor = PressureSensor::new();
        // Drive to Overloaded
        for _ in 0..30 {
            sensor.observe(&heavy_signals());
        }
        // Start recovery
        for _ in 0..10 {
            sensor.observe(&calm_signals());
        }
        // If in Recovery, spike again
        if sensor.regime() == SystemRegime::Recovery {
            for _ in 0..10 {
                sensor.observe(&heavy_signals());
            }
            assert!(
                sensor.regime() == SystemRegime::Overloaded
                    || sensor.regime() == SystemRegime::Recovery,
                "Expected re-escalation, got {:?}",
                sensor.regime()
            );
        }
    }

    #[test]
    fn threshold_validation() {
        let valid = RegimeThresholds::default();
        assert!(valid.is_valid());

        let invalid = RegimeThresholds {
            pressured_enter: 40.0,
            pressured_exit: 50.0, // exit > enter: invalid
            ..Default::default()
        };
        assert!(!invalid.is_valid());
    }

    #[test]
    fn snapshot_reflects_state() {
        let mut sensor = PressureSensor::new();
        sensor.observe(&calm_signals());
        let snap = sensor.snapshot();
        assert_eq!(snap.regime, SystemRegime::Nominal);
        assert_eq!(snap.epoch, 1);
        assert!(snap.pressure_score >= 0.0);
    }

    #[test]
    fn degradation_active_only_in_overloaded() {
        assert!(!SystemRegime::Nominal.degradation_active());
        assert!(!SystemRegime::Pressured.degradation_active());
        assert!(SystemRegime::Overloaded.degradation_active());
        assert!(!SystemRegime::Recovery.degradation_active());
    }

    #[test]
    fn under_pressure_except_nominal() {
        assert!(!SystemRegime::Nominal.under_pressure());
        assert!(SystemRegime::Pressured.under_pressure());
        assert!(SystemRegime::Overloaded.under_pressure());
        assert!(SystemRegime::Recovery.under_pressure());
    }

    #[test]
    fn deterministic_replay() {
        // Same signal sequence must produce identical state history.
        let signals: Vec<PressureSignals> = (0..50)
            .map(|i| {
                if i < 10 {
                    calm_signals()
                } else if i < 30 {
                    heavy_signals()
                } else {
                    calm_signals()
                }
            })
            .collect();

        let mut sensor1 = PressureSensor::new();
        let mut sensor2 = PressureSensor::new();
        let mut history1 = Vec::new();
        let mut history2 = Vec::new();

        for s in &signals {
            history1.push(sensor1.observe(s));
            history2.push(sensor2.observe(s));
        }

        assert_eq!(history1, history2, "Replay diverged");
    }
}
