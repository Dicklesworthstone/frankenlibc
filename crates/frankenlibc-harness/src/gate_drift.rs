//! Gate drift monitor backed by the runtime changepoint controller.

use std::collections::BTreeMap;

use frankenlibc_membrane::runtime_math::changepoint::{ChangepointController, ChangepointState};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GateObservation {
    pub gate: String,
    pub passed: bool,
    pub expected_passed: bool,
    pub code_delta: bool,
}

impl GateObservation {
    #[must_use]
    pub fn uncorrelated_outcome_shift(&self) -> bool {
        self.passed != self.expected_passed && !self.code_delta
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GateDriftConfig {
    pub min_observations: u64,
    pub flag_drift_state: bool,
}

impl Default for GateDriftConfig {
    fn default() -> Self {
        Self {
            min_observations: 32,
            flag_drift_state: true,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct GateDriftGateSummary {
    pub gate: String,
    pub observations: u64,
    pub uncorrelated_shifts: u64,
    pub state: ChangepointState,
    pub posterior_short_mass: f64,
    pub max_posterior_short_mass: f64,
    pub change_point_count: u64,
    pub flagged: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct GateDriftSummary {
    pub gates: Vec<GateDriftGateSummary>,
    pub flagged_gates: usize,
}

#[must_use]
pub fn evaluate_gate_drift<I>(config: GateDriftConfig, observations: I) -> GateDriftSummary
where
    I: IntoIterator<Item = GateObservation>,
{
    let mut gates: BTreeMap<String, GateTracker> = BTreeMap::new();
    for observation in observations {
        let adverse = observation.uncorrelated_outcome_shift();
        let tracker = gates
            .entry(observation.gate)
            .or_insert_with(|| GateTracker::new(config));
        tracker.observe(adverse);
    }

    let mut flagged_gates = 0;
    let gates = gates
        .into_iter()
        .map(|(gate, tracker)| {
            let summary = tracker.controller.summary();
            if tracker.flagged {
                flagged_gates += 1;
            }
            GateDriftGateSummary {
                gate,
                observations: summary.total_observations,
                uncorrelated_shifts: tracker.uncorrelated_shifts,
                state: summary.state,
                posterior_short_mass: summary.posterior_short_mass,
                max_posterior_short_mass: tracker.max_posterior_short_mass,
                change_point_count: summary.change_point_count,
                flagged: tracker.flagged,
            }
        })
        .collect();

    GateDriftSummary {
        gates,
        flagged_gates,
    }
}

struct GateTracker {
    controller: ChangepointController,
    config: GateDriftConfig,
    uncorrelated_shifts: u64,
    max_posterior_short_mass: f64,
    flagged: bool,
}

impl GateTracker {
    fn new(config: GateDriftConfig) -> Self {
        Self {
            controller: ChangepointController::new(),
            config,
            uncorrelated_shifts: 0,
            max_posterior_short_mass: 0.0,
            flagged: false,
        }
    }

    fn observe(&mut self, adverse: bool) {
        self.controller.observe(adverse);
        if adverse {
            self.uncorrelated_shifts += 1;
        }
        let summary = self.controller.summary();
        self.max_posterior_short_mass = self
            .max_posterior_short_mass
            .max(summary.posterior_short_mass);
        let state_flagged = matches!(summary.state, ChangepointState::ChangePoint)
            || (self.config.flag_drift_state && matches!(summary.state, ChangepointState::Drift));
        if summary.total_observations >= self.config.min_observations && state_flagged {
            self.flagged = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation(
        gate: &str,
        passed: bool,
        expected_passed: bool,
        code_delta: bool,
    ) -> GateObservation {
        GateObservation {
            gate: gate.to_string(),
            passed,
            expected_passed,
            code_delta,
        }
    }

    #[test]
    fn stable_gate_stays_unflagged() {
        let observations = (0..80).map(|_| observation("smoke", true, true, false));
        let summary = evaluate_gate_drift(GateDriftConfig::default(), observations);
        assert_eq!(summary.flagged_gates, 0);
        assert_eq!(summary.gates[0].state, ChangepointState::Stable);
        assert_eq!(summary.gates[0].uncorrelated_shifts, 0);
    }

    #[test]
    fn uncorrelated_pass_rate_jump_flags_gate() {
        let stable = (0..200).map(|_| observation("smoke", false, false, false));
        let suspicious = (0..100).map(|_| observation("smoke", true, false, false));
        let summary = evaluate_gate_drift(GateDriftConfig::default(), stable.chain(suspicious));
        assert_eq!(summary.flagged_gates, 1);
        assert!(summary.gates[0].flagged);
        assert!(summary.gates[0].uncorrelated_shifts > 0);
    }

    #[test]
    fn code_correlated_change_is_not_adverse() {
        let stable = (0..200).map(|_| observation("smoke", false, false, false));
        let real_change = (0..100).map(|_| observation("smoke", true, false, true));
        let summary = evaluate_gate_drift(GateDriftConfig::default(), stable.chain(real_change));
        assert_eq!(summary.flagged_gates, 0);
        assert_eq!(summary.gates[0].uncorrelated_shifts, 0);
    }
}
