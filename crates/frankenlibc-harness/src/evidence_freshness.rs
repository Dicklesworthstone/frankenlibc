//! Evidence freshness monitor backed by the runtime e-process kernel.

use frankenlibc_membrane::runtime_math::ApiFamily;
use frankenlibc_membrane::runtime_math::eprocess::{
    AnytimeEProcessMonitor, FamilyEProcessSummary, SequentialState,
};

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct EvidenceFreshnessConfig {
    pub null_divergence_rate: f64,
    pub alarm_divergence_rate: f64,
    pub warmup_observations: u64,
    pub warning_e_value: f64,
    pub alarm_e_value: f64,
}

impl EvidenceFreshnessConfig {
    #[must_use]
    pub fn false_alarm_alpha(self) -> f64 {
        1.0 / self.alarm_e_value
    }
}

impl Default for EvidenceFreshnessConfig {
    fn default() -> Self {
        Self {
            null_divergence_rate: 0.05,
            alarm_divergence_rate: 0.80,
            warmup_observations: 1,
            warning_e_value: 4.0,
            alarm_e_value: 10.0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct EvidenceFreshnessSummary {
    pub observations: u64,
    pub divergences: u64,
    pub e_value: f64,
    pub state: SequentialState,
    pub false_alarm_alpha: f64,
}

#[must_use]
pub fn evaluate_evidence_freshness<I>(
    config: EvidenceFreshnessConfig,
    divergences: I,
) -> EvidenceFreshnessSummary
where
    I: IntoIterator<Item = bool>,
{
    let monitor = AnytimeEProcessMonitor::new_with_params(
        config.null_divergence_rate,
        config.alarm_divergence_rate,
        config.warmup_observations,
        config.warning_e_value,
        config.alarm_e_value,
    );
    for diverged in divergences {
        monitor.observe(ApiFamily::IoFd, diverged);
    }
    summarize(config, monitor.summary(ApiFamily::IoFd))
}

fn summarize(
    config: EvidenceFreshnessConfig,
    summary: FamilyEProcessSummary,
) -> EvidenceFreshnessSummary {
    EvidenceFreshnessSummary {
        observations: summary.calls,
        divergences: summary.adverse,
        e_value: summary.e_value,
        state: summary.state,
        false_alarm_alpha: config.false_alarm_alpha(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_artifacts_stay_normal_after_warmup() {
        let summary = evaluate_evidence_freshness(EvidenceFreshnessConfig::default(), [false]);
        assert_eq!(summary.observations, 1);
        assert_eq!(summary.divergences, 0);
        assert_eq!(summary.state, SequentialState::Normal);
        assert!(summary.e_value < 1.0);
        assert_eq!(summary.false_alarm_alpha, 0.1);
    }

    #[test]
    fn divergent_artifact_crosses_alarm_threshold() {
        let summary = evaluate_evidence_freshness(EvidenceFreshnessConfig::default(), [true]);
        assert_eq!(summary.observations, 1);
        assert_eq!(summary.divergences, 1);
        assert_eq!(summary.state, SequentialState::Alarm);
        assert!(summary.e_value >= EvidenceFreshnessConfig::default().alarm_e_value);
    }
}
