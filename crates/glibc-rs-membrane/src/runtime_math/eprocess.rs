//! Anytime-valid e-process monitor for online drift alarms.
//!
//! This kernel runs directly on the runtime path as a compact sequential test:
//! for each API family it maintains a likelihood-ratio-style e-process under
//! a null adverse-rate budget `p0`. When evidence accumulates that adverse
//! outcomes exceed the budget, it raises a warning/alarm state used by the
//! decision controller.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

use super::ApiFamily;

const SCALE: f64 = 1_000_000.0;
const LOG_E_FLOOR: i64 = (-20.0 * SCALE) as i64;
const LOG_E_CAP: i64 = (50.0 * SCALE) as i64;

/// Sequential alert state for one API family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SequentialState {
    Calibrating,
    Normal,
    Warning,
    Alarm,
}

/// Point-in-time summary for one family.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FamilyEProcessSummary {
    pub calls: u64,
    pub adverse: u64,
    pub e_value: f64,
    pub state: SequentialState,
}

/// Lightweight anytime-valid monitor.
///
/// Internally stores `log(e)` in fixed-point for lock-free updates.
pub struct AnytimeEProcessMonitor {
    calls: [AtomicU64; ApiFamily::COUNT],
    adverse: [AtomicU64; ApiFamily::COUNT],
    log_e_scaled: [AtomicI64; ApiFamily::COUNT],
    warmup_calls: u64,
    warning_log_e_scaled: i64,
    alarm_log_e_scaled: i64,
    adverse_delta_scaled: i64,
    clean_delta_scaled: i64,
}

impl AnytimeEProcessMonitor {
    /// Construct with pragmatic defaults tuned for membrane telemetry.
    #[must_use]
    pub fn new() -> Self {
        // Null budget p0: expected adverse rate <= 2%.
        // Alternative q1: elevated adverse regime around 20%.
        Self::new_with_params(0.02, 0.20, 64, 100.0, 10_000.0)
    }

    /// Construct with explicit parameters.
    #[must_use]
    pub fn new_with_params(
        p0: f64,
        q1: f64,
        warmup_calls: u64,
        warning_e: f64,
        alarm_e: f64,
    ) -> Self {
        let p0 = p0.clamp(1e-6, 1.0 - 1e-6);
        let q1 = q1.clamp(p0 + 1e-6, 1.0 - 1e-6);
        let warning_e = warning_e.max(1.0);
        let alarm_e = alarm_e.max(warning_e);

        let adverse_delta = (q1 / p0).ln();
        let clean_delta = ((1.0 - q1) / (1.0 - p0)).ln();

        Self {
            calls: std::array::from_fn(|_| AtomicU64::new(0)),
            adverse: std::array::from_fn(|_| AtomicU64::new(0)),
            log_e_scaled: std::array::from_fn(|_| AtomicI64::new(0)),
            warmup_calls,
            warning_log_e_scaled: (warning_e.ln() * SCALE).round() as i64,
            alarm_log_e_scaled: (alarm_e.ln() * SCALE).round() as i64,
            adverse_delta_scaled: (adverse_delta * SCALE).round() as i64,
            clean_delta_scaled: (clean_delta * SCALE).round() as i64,
        }
    }

    /// Observe one runtime outcome.
    pub fn observe(&self, family: ApiFamily, adverse: bool) {
        let idx = usize::from(family as u8);
        self.calls[idx].fetch_add(1, Ordering::Relaxed);
        if adverse {
            self.adverse[idx].fetch_add(1, Ordering::Relaxed);
        }

        let delta = if adverse {
            self.adverse_delta_scaled
        } else {
            self.clean_delta_scaled
        };

        let slot = &self.log_e_scaled[idx];
        let mut current = slot.load(Ordering::Relaxed);
        loop {
            let next = current.saturating_add(delta).clamp(LOG_E_FLOOR, LOG_E_CAP);
            match slot.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
    }

    /// Current sequential state for a family.
    #[must_use]
    pub fn state(&self, family: ApiFamily) -> SequentialState {
        let idx = usize::from(family as u8);
        let calls = self.calls[idx].load(Ordering::Relaxed);
        if calls < self.warmup_calls {
            return SequentialState::Calibrating;
        }

        let log_e = self.log_e_scaled[idx].load(Ordering::Relaxed);
        if log_e >= self.alarm_log_e_scaled {
            SequentialState::Alarm
        } else if log_e >= self.warning_log_e_scaled {
            SequentialState::Warning
        } else {
            SequentialState::Normal
        }
    }

    /// Current e-value for a family.
    #[must_use]
    pub fn e_value(&self, family: ApiFamily) -> f64 {
        let idx = usize::from(family as u8);
        let log_e = self.log_e_scaled[idx].load(Ordering::Relaxed) as f64 / SCALE;
        log_e.exp()
    }

    /// Family summary.
    #[must_use]
    pub fn summary(&self, family: ApiFamily) -> FamilyEProcessSummary {
        let idx = usize::from(family as u8);
        FamilyEProcessSummary {
            calls: self.calls[idx].load(Ordering::Relaxed),
            adverse: self.adverse[idx].load(Ordering::Relaxed),
            e_value: self.e_value(family),
            state: self.state(family),
        }
    }

    /// Max e-value across all families.
    #[must_use]
    pub fn max_e_value(&self) -> f64 {
        let mut max_e = 1.0_f64;
        for family in all_families() {
            max_e = max_e.max(self.e_value(family));
        }
        max_e
    }

    /// Number of families in alarm state.
    #[must_use]
    pub fn alarmed_family_count(&self) -> u32 {
        let mut count = 0u32;
        for family in all_families() {
            if matches!(self.state(family), SequentialState::Alarm) {
                count += 1;
            }
        }
        count
    }
}

impl Default for AnytimeEProcessMonitor {
    fn default() -> Self {
        Self::new()
    }
}

fn all_families() -> [ApiFamily; ApiFamily::COUNT] {
    [
        ApiFamily::PointerValidation,
        ApiFamily::Allocator,
        ApiFamily::StringMemory,
        ApiFamily::Stdio,
        ApiFamily::Threading,
        ApiFamily::Resolver,
        ApiFamily::MathFenv,
        ApiFamily::Loader,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_calibrating() {
        let mon = AnytimeEProcessMonitor::new();
        assert_eq!(
            mon.state(ApiFamily::PointerValidation),
            SequentialState::Calibrating
        );
    }

    #[test]
    fn adverse_streak_triggers_alarm() {
        let mon = AnytimeEProcessMonitor::new_with_params(0.02, 0.25, 16, 10.0, 100.0);
        for _ in 0..128 {
            mon.observe(ApiFamily::Allocator, true);
        }
        assert_eq!(mon.state(ApiFamily::Allocator), SequentialState::Alarm);
        assert!(mon.e_value(ApiFamily::Allocator) > 100.0);
    }

    #[test]
    fn clean_traffic_stays_normal_after_warmup() {
        let mon = AnytimeEProcessMonitor::new_with_params(0.02, 0.2, 16, 10.0, 100.0);
        for _ in 0..256 {
            mon.observe(ApiFamily::StringMemory, false);
        }
        assert_eq!(mon.state(ApiFamily::StringMemory), SequentialState::Normal);
        assert!(mon.e_value(ApiFamily::StringMemory) <= 1.0);
    }

    #[test]
    fn summary_reports_counts() {
        let mon = AnytimeEProcessMonitor::new_with_params(0.02, 0.2, 4, 10.0, 100.0);
        for i in 0..10 {
            mon.observe(ApiFamily::Resolver, i % 3 == 0);
        }
        let s = mon.summary(ApiFamily::Resolver);
        assert_eq!(s.calls, 10);
        assert_eq!(s.adverse, 4);
        assert!(s.e_value.is_finite());
    }
}
