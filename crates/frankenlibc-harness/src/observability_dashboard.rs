//! Operator-facing observability dashboard aggregation for metrics JSONL streams.
//!
//! Bead: `bd-282v`
//!
//! This module ingests the existing membrane/healing/runtime JSONL exports and
//! produces a compact dashboard bundle in four formats:
//! - machine-readable JSON summary,
//! - Prometheus exposition text,
//! - StatsD lines,
//! - a Grafana dashboard template targeting the Prometheus names above.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const OBSERVABILITY_BEAD_ID: &str = "bd-282v";
const LATENCY_HISTOGRAM_BUCKETS_NS: [u64; 8] =
    [100, 500, 1_000, 5_000, 10_000, 50_000, 100_000, 500_000];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ObservabilityDashboardReport {
    pub schema_version: String,
    pub bead: String,
    pub generated_at_utc: String,
    pub input_files: Vec<String>,
    pub summary: DashboardSummary,
    pub validation: ValidationDashboard,
    pub healing: HealingDashboard,
    pub cache: CacheDashboard,
    pub allocator: AllocatorDashboard,
    pub runtime_math: RuntimeMathDashboard,
    pub artifact_refs: Vec<String>,
    pub alerts: Vec<DashboardAlert>,
    pub alert_rules: Vec<DashboardAlertRule>,
}

impl ObservabilityDashboardReport {
    #[must_use]
    pub fn to_json_pretty(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|err| format!("{{\"error\":\"{err}\"}}"))
    }

    #[must_use]
    pub fn to_prometheus_text(&self) -> String {
        let mut out = String::new();
        out.push_str("# HELP frankenlibc_observability_input_rows_total Total non-empty JSONL rows seen by the observability dashboard.\n");
        out.push_str("# TYPE frankenlibc_observability_input_rows_total counter\n");
        let _ = writeln!(
            &mut out,
            "frankenlibc_observability_input_rows_total {}",
            self.summary.total_rows
        );
        let _ = writeln!(
            &mut out,
            "frankenlibc_observability_parsed_rows_total {}",
            self.summary.parsed_rows
        );
        let _ = writeln!(
            &mut out,
            "frankenlibc_observability_invalid_rows_total {}",
            self.summary.invalid_rows
        );

        out.push_str("# HELP frankenlibc_validations_total Total membrane validations from the latest snapshot or observed events.\n");
        out.push_str("# TYPE frankenlibc_validations_total gauge\n");
        let _ = writeln!(
            &mut out,
            "frankenlibc_validations_total {}",
            self.validation.validations_total
        );
        let _ = writeln!(
            &mut out,
            "frankenlibc_validation_events_total {}",
            self.validation.events_observed
        );
        for (outcome, count) in &self.validation.by_outcome {
            write_prometheus_sample(
                &mut out,
                "frankenlibc_validation_outcomes_total",
                &[("outcome", outcome.as_str())],
                &count.to_string(),
            );
        }
        for (stage, count) in &self.validation.by_stage {
            write_prometheus_sample(
                &mut out,
                "frankenlibc_validation_stage_events_total",
                &[("stage", stage.as_str())],
                &count.to_string(),
            );
        }
        out.push_str("# HELP frankenlibc_validation_latency_ns Membrane validation latency histogram in nanoseconds.\n");
        out.push_str("# TYPE frankenlibc_validation_latency_ns histogram\n");
        for bucket in &self.validation.latency_histogram {
            let bound = bucket
                .le
                .map_or_else(|| String::from("+Inf"), |value| value.to_string());
            write_prometheus_sample(
                &mut out,
                "frankenlibc_validation_latency_ns_bucket",
                &[("le", bound.as_str())],
                &bucket.cumulative_count.to_string(),
            );
        }
        let latency_sum = self
            .validation
            .latency_ns
            .mean
            .map(|mean| mean * self.validation.latency_ns.count as f64)
            .unwrap_or(0.0);
        let _ = writeln!(
            &mut out,
            "frankenlibc_validation_latency_ns_sum {}",
            latency_sum
        );
        let _ = writeln!(
            &mut out,
            "frankenlibc_validation_latency_ns_count {}",
            self.validation.latency_ns.count
        );

        out.push_str("# HELP frankenlibc_heals_total Total heals observed across membrane-heal rows and snapshots.\n");
        out.push_str("# TYPE frankenlibc_heals_total gauge\n");
        let _ = writeln!(
            &mut out,
            "frankenlibc_heals_total {}",
            self.healing.heals_total
        );
        let _ = writeln!(
            &mut out,
            "frankenlibc_healing_escalated_total {}",
            self.healing.escalated_total
        );
        for (action, count) in &self.healing.by_action {
            write_prometheus_sample(
                &mut out,
                "frankenlibc_healing_actions_total",
                &[("action", action.as_str())],
                &count.to_string(),
            );
        }
        for (api_family, count) in &self.healing.by_api_family {
            write_prometheus_sample(
                &mut out,
                "frankenlibc_healing_api_family_total",
                &[("api_family", api_family.as_str())],
                &count.to_string(),
            );
        }

        if let Some(value) = self.cache.tls_cache_hits {
            let _ = writeln!(&mut out, "frankenlibc_tls_cache_hits_total {}", value);
        }
        if let Some(value) = self.cache.tls_cache_misses {
            let _ = writeln!(&mut out, "frankenlibc_tls_cache_misses_total {}", value);
        }
        if let Some(value) = self.cache.tls_cache_hit_rate {
            let _ = writeln!(&mut out, "frankenlibc_tls_cache_hit_rate {}", value);
        }
        if let Some(value) = self.cache.bloom_hits {
            let _ = writeln!(&mut out, "frankenlibc_bloom_hits_total {}", value);
        }
        if let Some(value) = self.cache.bloom_misses {
            let _ = writeln!(&mut out, "frankenlibc_bloom_misses_total {}", value);
        }
        if let Some(value) = self.cache.bloom_hit_rate {
            let _ = writeln!(&mut out, "frankenlibc_bloom_hit_rate {}", value);
        }

        if let Some(value) = self.allocator.allocations_total {
            let _ = writeln!(
                &mut out,
                "frankenlibc_allocator_allocations_total {}",
                value
            );
        }
        if let Some(value) = self.allocator.frees_total {
            let _ = writeln!(&mut out, "frankenlibc_allocator_frees_total {}", value);
        }
        if let Some(value) = self.allocator.active_allocations {
            let _ = writeln!(
                &mut out,
                "frankenlibc_allocator_active_allocations {}",
                value
            );
        }
        if let Some(value) = self.allocator.bytes_allocated {
            let _ = writeln!(&mut out, "frankenlibc_allocator_bytes_allocated {}", value);
        }
        if let Some(value) = self.allocator.quarantine_depth {
            let _ = writeln!(&mut out, "frankenlibc_allocator_quarantine_depth {}", value);
        }
        if let Some(value) = self.allocator.arena_utilization_ppm {
            let _ = writeln!(
                &mut out,
                "frankenlibc_allocator_arena_utilization_ppm {}",
                value
            );
        }
        if let Some(value) = self.allocator.thread_cache_hits {
            let _ = writeln!(
                &mut out,
                "frankenlibc_allocator_thread_cache_hits_total {}",
                value
            );
        }
        if let Some(value) = self.allocator.thread_cache_misses {
            let _ = writeln!(
                &mut out,
                "frankenlibc_allocator_thread_cache_misses_total {}",
                value
            );
        }
        if let Some(value) = self.allocator.thread_cache_hit_rate {
            let _ = writeln!(
                &mut out,
                "frankenlibc_allocator_thread_cache_hit_rate {}",
                value
            );
        }
        if let Some(value) = self.allocator.central_bin_hits {
            let _ = writeln!(
                &mut out,
                "frankenlibc_allocator_central_bin_hits_total {}",
                value
            );
        }
        if let Some(value) = self.allocator.spills_to_central {
            let _ = writeln!(
                &mut out,
                "frankenlibc_allocator_spills_to_central_total {}",
                value
            );
        }

        out.push_str(
            "# HELP frankenlibc_runtime_decisions_total Total runtime decision rows seen.\n",
        );
        out.push_str("# TYPE frankenlibc_runtime_decisions_total counter\n");
        let _ = writeln!(
            &mut out,
            "frankenlibc_runtime_decisions_total {}",
            self.runtime_math.decision_total
        );
        for (decision, count) in &self.runtime_math.by_decision {
            write_prometheus_sample(
                &mut out,
                "frankenlibc_runtime_decisions_by_decision_total",
                &[("decision", decision.as_str())],
                &count.to_string(),
            );
        }
        for (action, count) in &self.runtime_math.by_action {
            write_prometheus_sample(
                &mut out,
                "frankenlibc_runtime_decisions_by_action_total",
                &[("action", action.as_str())],
                &count.to_string(),
            );
        }
        for (policy, count) in &self.runtime_math.overload_policies {
            write_prometheus_sample(
                &mut out,
                "frankenlibc_runtime_overload_policy_total",
                &[("policy", policy.as_str())],
                &count.to_string(),
            );
        }
        write_optional_summary_gauge(
            &mut out,
            "frankenlibc_runtime_risk_upper_bound_ppm",
            &self.runtime_math.risk_upper_bound_ppm,
        );
        if let Some(value) = self.runtime_math.snapshot_decisions {
            let _ = writeln!(
                &mut out,
                "frankenlibc_runtime_snapshot_decisions_total {}",
                value
            );
        }
        if let Some(value) = self.runtime_math.snapshot_consistency_faults {
            let _ = writeln!(
                &mut out,
                "frankenlibc_runtime_snapshot_consistency_faults {}",
                value
            );
        }
        if let Some(value) = self.runtime_math.snapshot_regret_milli {
            let _ = writeln!(
                &mut out,
                "frankenlibc_runtime_snapshot_regret_milli {}",
                value
            );
        }
        let _ = writeln!(
            &mut out,
            "frankenlibc_runtime_snapshot_field_out_of_range_total {}",
            self.runtime_math.snapshot_field_out_of_range_total
        );

        let _ = writeln!(
            &mut out,
            "frankenlibc_observability_alerts_total {}",
            self.alerts.len()
        );
        for alert in &self.alerts {
            write_prometheus_sample(
                &mut out,
                "frankenlibc_observability_alert_active",
                &[
                    ("name", alert.name.as_str()),
                    ("severity", alert.severity.as_str()),
                ],
                "1",
            );
        }

        out
    }

    #[must_use]
    pub fn to_alert_rules_yaml(&self) -> String {
        #[derive(Serialize)]
        struct RuleLabels<'a> {
            severity: &'a str,
        }

        #[derive(Serialize)]
        struct RuleAnnotations<'a> {
            summary: &'a str,
        }

        #[derive(Serialize)]
        struct Rule<'a> {
            alert: &'a str,
            expr: &'a str,
            #[serde(rename = "for")]
            for_window: &'a str,
            labels: RuleLabels<'a>,
            annotations: RuleAnnotations<'a>,
        }

        #[derive(Serialize)]
        struct RuleGroup<'a> {
            name: &'a str,
            rules: Vec<Rule<'a>>,
        }

        #[derive(Serialize)]
        struct RuleFile<'a> {
            groups: Vec<RuleGroup<'a>>,
        }

        let rules = self
            .alert_rules
            .iter()
            .map(|rule| Rule {
                alert: rule.alert.as_str(),
                expr: rule.expr.as_str(),
                for_window: rule.for_window.as_str(),
                labels: RuleLabels {
                    severity: rule.severity.as_str(),
                },
                annotations: RuleAnnotations {
                    summary: rule.summary.as_str(),
                },
            })
            .collect();
        serde_yaml::to_string(&RuleFile {
            groups: vec![RuleGroup {
                name: "frankenlibc-observability",
                rules,
            }],
        })
        .unwrap_or_else(|err| format!("error: {err}\n"))
    }

    #[must_use]
    pub fn to_statsd_text(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(
            &mut out,
            "frankenlibc.observability.input_rows_total:{}|c",
            self.summary.total_rows
        );
        let _ = writeln!(
            &mut out,
            "frankenlibc.observability.invalid_rows_total:{}|c",
            self.summary.invalid_rows
        );
        let _ = writeln!(
            &mut out,
            "frankenlibc.validation.validations_total:{}|g",
            self.validation.validations_total
        );
        let _ = writeln!(
            &mut out,
            "frankenlibc.validation.events_total:{}|c",
            self.validation.events_observed
        );
        for (outcome, count) in &self.validation.by_outcome {
            let key = sanitize_metric_component(outcome);
            let _ = writeln!(
                &mut out,
                "frankenlibc.validation.outcome.{}:{}|c",
                key, count
            );
        }
        for (stage, count) in &self.validation.by_stage {
            let key = sanitize_metric_component(stage);
            let _ = writeln!(&mut out, "frankenlibc.validation.stage.{}:{}|c", key, count);
        }
        write_statsd_summary(
            &mut out,
            "frankenlibc.validation.latency_ns",
            &self.validation.latency_ns,
        );

        let _ = writeln!(
            &mut out,
            "frankenlibc.healing.total:{}|g",
            self.healing.heals_total
        );
        let _ = writeln!(
            &mut out,
            "frankenlibc.healing.escalated_total:{}|g",
            self.healing.escalated_total
        );
        for (action, count) in &self.healing.by_action {
            let key = sanitize_metric_component(action);
            let _ = writeln!(&mut out, "frankenlibc.healing.action.{}:{}|c", key, count);
        }
        for (family, count) in &self.healing.by_api_family {
            let key = sanitize_metric_component(family);
            let _ = writeln!(&mut out, "frankenlibc.healing.family.{}:{}|c", key, count);
        }

        if let Some(value) = self.cache.tls_cache_hits {
            let _ = writeln!(&mut out, "frankenlibc.cache.tls_hits:{}|g", value);
        }
        if let Some(value) = self.cache.tls_cache_misses {
            let _ = writeln!(&mut out, "frankenlibc.cache.tls_misses:{}|g", value);
        }
        if let Some(value) = self.cache.tls_cache_hit_rate {
            let _ = writeln!(&mut out, "frankenlibc.cache.tls_hit_rate:{}|g", value);
        }
        if let Some(value) = self.cache.bloom_hits {
            let _ = writeln!(&mut out, "frankenlibc.cache.bloom_hits:{}|g", value);
        }
        if let Some(value) = self.cache.bloom_misses {
            let _ = writeln!(&mut out, "frankenlibc.cache.bloom_misses:{}|g", value);
        }
        if let Some(value) = self.cache.bloom_hit_rate {
            let _ = writeln!(&mut out, "frankenlibc.cache.bloom_hit_rate:{}|g", value);
        }

        if let Some(value) = self.allocator.allocations_total {
            let _ = writeln!(
                &mut out,
                "frankenlibc.allocator.allocations_total:{}|g",
                value
            );
        }
        if let Some(value) = self.allocator.frees_total {
            let _ = writeln!(&mut out, "frankenlibc.allocator.frees_total:{}|g", value);
        }
        if let Some(value) = self.allocator.active_allocations {
            let _ = writeln!(
                &mut out,
                "frankenlibc.allocator.active_allocations:{}|g",
                value
            );
        }
        if let Some(value) = self.allocator.bytes_allocated {
            let _ = writeln!(
                &mut out,
                "frankenlibc.allocator.bytes_allocated:{}|g",
                value
            );
        }
        if let Some(value) = self.allocator.quarantine_depth {
            let _ = writeln!(
                &mut out,
                "frankenlibc.allocator.quarantine_depth:{}|g",
                value
            );
        }
        if let Some(value) = self.allocator.arena_utilization_ppm {
            let _ = writeln!(
                &mut out,
                "frankenlibc.allocator.arena_utilization_ppm:{}|g",
                value
            );
        }
        if let Some(value) = self.allocator.thread_cache_hits {
            let _ = writeln!(
                &mut out,
                "frankenlibc.allocator.thread_cache_hits:{}|g",
                value
            );
        }
        if let Some(value) = self.allocator.thread_cache_misses {
            let _ = writeln!(
                &mut out,
                "frankenlibc.allocator.thread_cache_misses:{}|g",
                value
            );
        }
        if let Some(value) = self.allocator.thread_cache_hit_rate {
            let _ = writeln!(
                &mut out,
                "frankenlibc.allocator.thread_cache_hit_rate:{}|g",
                value
            );
        }
        if let Some(value) = self.allocator.central_bin_hits {
            let _ = writeln!(
                &mut out,
                "frankenlibc.allocator.central_bin_hits:{}|g",
                value
            );
        }
        if let Some(value) = self.allocator.spills_to_central {
            let _ = writeln!(
                &mut out,
                "frankenlibc.allocator.spills_to_central:{}|g",
                value
            );
        }

        let _ = writeln!(
            &mut out,
            "frankenlibc.runtime.decisions_total:{}|c",
            self.runtime_math.decision_total
        );
        for (decision, count) in &self.runtime_math.by_decision {
            let key = sanitize_metric_component(decision);
            let _ = writeln!(&mut out, "frankenlibc.runtime.decision.{}:{}|c", key, count);
        }
        for (action, count) in &self.runtime_math.by_action {
            let key = sanitize_metric_component(action);
            let _ = writeln!(&mut out, "frankenlibc.runtime.action.{}:{}|c", key, count);
        }
        for (policy, count) in &self.runtime_math.overload_policies {
            let key = sanitize_metric_component(policy);
            let _ = writeln!(
                &mut out,
                "frankenlibc.runtime.overload_policy.{}:{}|c",
                key, count
            );
        }
        write_statsd_summary(
            &mut out,
            "frankenlibc.runtime.risk_upper_bound_ppm",
            &self.runtime_math.risk_upper_bound_ppm,
        );

        out
    }

    #[must_use]
    pub fn to_grafana_dashboard_json(&self) -> String {
        let dashboard = json!({
            "schemaVersion": 39,
            "title": "FrankenLibC Observability Dashboard",
            "uid": "frankenlibc-observability",
            "tags": ["frankenlibc", "observability", OBSERVABILITY_BEAD_ID],
            "timezone": "utc",
            "time": {"from": "now-6h", "to": "now"},
            "templating": {"list": []},
            "panels": [
                grafana_stat_panel(
                    1,
                    "Validations",
                    "frankenlibc_validations_total",
                    "count"
                ),
                grafana_stat_panel(
                    2,
                    "Heals",
                    "frankenlibc_heals_total",
                    "count"
                ),
                grafana_stat_panel(
                    3,
                    "TLS Cache Hit Rate",
                    "frankenlibc_tls_cache_hit_rate",
                    "percentunit"
                ),
                grafana_stat_panel(
                    7,
                    "Allocator Live Bytes",
                    "frankenlibc_allocator_bytes_allocated",
                    "bytes"
                ),
                grafana_stat_panel(
                    8,
                    "Allocator Quarantine Depth",
                    "frankenlibc_allocator_quarantine_depth",
                    "short"
                ),
                grafana_stat_panel(
                    9,
                    "Arena Utilization",
                    "frankenlibc_allocator_arena_utilization_ppm / 1000000",
                    "percentunit"
                ),
                grafana_timeseries_panel(
                    4,
                    "Validation Outcomes",
                    "sum by (outcome) (frankenlibc_validation_outcomes_total)"
                ),
                grafana_timeseries_panel(
                    5,
                    "Runtime Decisions",
                    "sum by (decision) (frankenlibc_runtime_decisions_by_decision_total)"
                ),
                grafana_timeseries_panel(
                    6,
                    "Runtime Risk Upper Bound",
                    "frankenlibc_runtime_risk_upper_bound_ppm{stat=\"p95\"}"
                ),
                grafana_timeseries_panel(
                    10,
                    "Active Allocations",
                    "frankenlibc_allocator_active_allocations"
                ),
                grafana_timeseries_panel(
                    11,
                    "Allocator Cache Efficiency",
                    "frankenlibc_allocator_thread_cache_hit_rate"
                )
            ],
            "annotations": {"list": []},
            "links": [],
            "fiscalYearStartMonth": 0,
            "description": format!(
                "Generated from {} input file(s); available sections: {}",
                self.input_files.len(),
                self.summary.available_sections.join(", ")
            ),
            "meta": {
                "bead": self.bead,
                "generated_at_utc": self.generated_at_utc,
                "alerts": self.alerts,
            }
        });
        serde_json::to_string_pretty(&dashboard)
            .unwrap_or_else(|err| format!("{{\"error\":\"{err}\"}}"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DashboardSummary {
    pub total_rows: u64,
    pub parsed_rows: u64,
    pub invalid_rows: u64,
    pub controllers_seen: Vec<String>,
    pub modes_seen: Vec<String>,
    pub api_families_seen: Vec<String>,
    pub available_sections: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ValidationDashboard {
    pub validations_total: u64,
    pub events_observed: u64,
    pub by_outcome: BTreeMap<String, u64>,
    pub by_stage: BTreeMap<String, u64>,
    pub latency_ns: ScalarSummary,
    pub latency_histogram: Vec<HistogramBucket>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HealingDashboard {
    pub heals_total: u64,
    pub escalated_total: u64,
    pub by_action: BTreeMap<String, u64>,
    pub by_api_family: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CacheDashboard {
    pub tls_cache_hits: Option<u64>,
    pub tls_cache_misses: Option<u64>,
    pub tls_cache_hit_rate: Option<f64>,
    pub bloom_hits: Option<u64>,
    pub bloom_misses: Option<u64>,
    pub bloom_hit_rate: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AllocatorDashboard {
    pub available: bool,
    pub allocations_total: Option<u64>,
    pub frees_total: Option<u64>,
    pub active_allocations: Option<u64>,
    pub bytes_allocated: Option<u64>,
    pub quarantine_depth: Option<u64>,
    pub arena_utilization_ppm: Option<u64>,
    pub thread_cache_hits: Option<u64>,
    pub thread_cache_misses: Option<u64>,
    pub thread_cache_hit_rate: Option<f64>,
    pub central_bin_hits: Option<u64>,
    pub spills_to_central: Option<u64>,
    pub source_note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuntimeMathDashboard {
    pub decision_total: u64,
    pub by_decision: BTreeMap<String, u64>,
    pub by_action: BTreeMap<String, u64>,
    pub overload_policies: BTreeMap<String, u64>,
    pub risk_upper_bound_ppm: ScalarSummary,
    pub snapshot_decisions: Option<u64>,
    pub snapshot_consistency_faults: Option<u64>,
    pub snapshot_regret_milli: Option<u64>,
    pub snapshot_cap_enforcements: Option<u64>,
    pub snapshot_exhausted_families: Option<u64>,
    pub snapshot_field_out_of_range_total: u64,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq)]
pub struct ScalarSummary {
    pub count: u64,
    pub min: Option<u64>,
    pub p50: Option<u64>,
    pub p95: Option<u64>,
    pub p99: Option<u64>,
    pub max: Option<u64>,
    pub mean: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HistogramBucket {
    pub le: Option<u64>,
    pub cumulative_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DashboardAlert {
    pub name: String,
    pub severity: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DashboardAlertRule {
    pub alert: String,
    pub expr: String,
    #[serde(rename = "for")]
    pub for_window: String,
    pub severity: String,
    pub summary: String,
}

#[derive(Debug, Clone, Copy, Default)]
struct SnapshotMetrics {
    validations: u64,
    heals: u64,
    tls_cache_hits: u64,
    tls_cache_misses: u64,
    bloom_hits: u64,
    bloom_misses: u64,
}

#[derive(Debug, Clone, Copy, Default)]
struct AllocatorSnapshotMetrics {
    allocations_total: u64,
    frees_total: u64,
    active_allocations: u64,
    bytes_allocated: u64,
    thread_cache_hits: u64,
    thread_cache_misses: u64,
    central_bin_hits: u64,
    spills_to_central: u64,
}

#[derive(Debug, Default)]
struct AggregationState {
    total_rows: u64,
    parsed_rows: u64,
    invalid_rows: u64,
    controllers_seen: BTreeSet<String>,
    modes_seen: BTreeSet<String>,
    api_families_seen: BTreeSet<String>,
    artifact_refs: BTreeSet<String>,
    validation_events: u64,
    validation_by_outcome: BTreeMap<String, u64>,
    validation_by_stage: BTreeMap<String, u64>,
    validation_latencies_ns: Vec<u64>,
    healing_total: u64,
    healing_escalated_total: u64,
    healing_by_action: BTreeMap<String, u64>,
    healing_by_api_family: BTreeMap<String, u64>,
    latest_snapshot_metrics: Option<SnapshotMetrics>,
    latest_allocator_snapshot: Option<AllocatorSnapshotMetrics>,
    runtime_decision_total: u64,
    runtime_by_decision: BTreeMap<String, u64>,
    runtime_by_action: BTreeMap<String, u64>,
    runtime_overload_policies: BTreeMap<String, u64>,
    runtime_risk_upper_bound_ppm: Vec<u64>,
    runtime_snapshot_decisions: Option<u64>,
    runtime_snapshot_consistency_faults: Option<u64>,
    runtime_snapshot_regret_milli: Option<u64>,
    runtime_snapshot_cap_enforcements: Option<u64>,
    runtime_snapshot_exhausted_families: Option<u64>,
    runtime_snapshot_quarantine_depth: Option<u64>,
    runtime_snapshot_arena_utilization_ppm: Option<u64>,
    runtime_snapshot_field_out_of_range_total: u64,
}

pub fn build_from_paths(paths: &[PathBuf]) -> Result<ObservabilityDashboardReport, String> {
    if paths.is_empty() {
        return Err("observability dashboard requires at least one --input path".to_string());
    }

    let mut state = AggregationState::default();
    for path in paths {
        let content = std::fs::read_to_string(path)
            .map_err(|err| format!("failed reading '{}': {err}", path.display()))?;
        for raw_line in content.lines() {
            let line = raw_line.trim();
            if line.is_empty() {
                continue;
            }
            state.total_rows += 1;

            let value: Value = match serde_json::from_str(line) {
                Ok(value) => value,
                Err(_) => {
                    state.invalid_rows += 1;
                    continue;
                }
            };
            let Some(obj) = value.as_object() else {
                state.invalid_rows += 1;
                continue;
            };
            state.parsed_rows += 1;
            state.ingest_object(obj);
        }
    }

    Ok(state.finalize(paths))
}

pub fn write_bundle(
    inputs: &[PathBuf],
    output: &Path,
    prometheus_output: &Path,
    statsd_output: &Path,
    grafana_output: &Path,
    alerts_output: &Path,
) -> Result<ObservabilityDashboardReport, String> {
    let report = build_from_paths(inputs)?;
    write_text_file(output, &report.to_json_pretty())?;
    write_text_file(prometheus_output, &report.to_prometheus_text())?;
    write_text_file(statsd_output, &report.to_statsd_text())?;
    write_text_file(grafana_output, &report.to_grafana_dashboard_json())?;
    write_text_file(alerts_output, &report.to_alert_rules_yaml())?;
    Ok(report)
}

impl AggregationState {
    fn ingest_object(&mut self, obj: &serde_json::Map<String, Value>) {
        if let Some(controller) = obj.get("controller_id").and_then(Value::as_str) {
            self.controllers_seen.insert(controller.to_string());
        }
        if let Some(mode) = extract_mode(obj) {
            self.modes_seen.insert(mode.to_string());
        }
        if let Some(api_family) = obj.get("api_family").and_then(Value::as_str) {
            self.api_families_seen.insert(api_family.to_string());
        }
        if let Some(artifact_refs) = obj.get("artifact_refs").and_then(Value::as_array) {
            for artifact_ref in artifact_refs.iter().filter_map(Value::as_str) {
                self.artifact_refs.insert(artifact_ref.to_string());
            }
        }

        if is_membrane_snapshot(obj) {
            self.ingest_membrane_snapshot(obj);
        }
        if is_allocator_snapshot(obj) {
            self.ingest_allocator_snapshot(obj);
        }
        if is_validation_row(obj) {
            self.ingest_validation(obj);
        }
        if is_healing_row(obj) {
            self.ingest_healing(obj);
        }
        if obj.get("event").and_then(Value::as_str) == Some("runtime_decision") {
            self.ingest_runtime_decision(obj);
        }
        if obj.get("event").and_then(Value::as_str) == Some("runtime_snapshot") {
            self.ingest_runtime_snapshot(obj);
        }
        if obj.get("event").and_then(Value::as_str) == Some("runtime_snapshot_field_out_of_range") {
            self.runtime_snapshot_field_out_of_range_total += 1;
        }
    }

    fn ingest_membrane_snapshot(&mut self, obj: &serde_json::Map<String, Value>) {
        let Some(metrics) = obj.get("metrics").and_then(Value::as_object) else {
            return;
        };
        self.latest_snapshot_metrics = Some(SnapshotMetrics {
            validations: metrics
                .get("validations")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            heals: metrics.get("heals").and_then(Value::as_u64).unwrap_or(0),
            tls_cache_hits: metrics
                .get("tls_cache_hits")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            tls_cache_misses: metrics
                .get("tls_cache_misses")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            bloom_hits: metrics
                .get("bloom_hits")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            bloom_misses: metrics
                .get("bloom_misses")
                .and_then(Value::as_u64)
                .unwrap_or(0),
        });
    }

    fn ingest_allocator_snapshot(&mut self, obj: &serde_json::Map<String, Value>) {
        self.latest_allocator_snapshot = Some(AllocatorSnapshotMetrics {
            allocations_total: obj
                .get("allocations_total")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            frees_total: obj.get("frees_total").and_then(Value::as_u64).unwrap_or(0),
            active_allocations: obj
                .get("active_allocations")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            bytes_allocated: obj
                .get("bytes_allocated")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            thread_cache_hits: obj
                .get("thread_cache_hits")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            thread_cache_misses: obj
                .get("thread_cache_misses")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            central_bin_hits: obj
                .get("central_bin_hits")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            spills_to_central: obj
                .get("spills_to_central")
                .and_then(Value::as_u64)
                .unwrap_or(0),
        });
    }

    fn ingest_validation(&mut self, obj: &serde_json::Map<String, Value>) {
        self.validation_events += 1;
        if let Some(outcome) = obj.get("outcome").and_then(Value::as_str) {
            increment_counter(&mut self.validation_by_outcome, outcome);
        }
        if let Some(stage) = obj.get("stage").and_then(Value::as_str) {
            increment_counter(&mut self.validation_by_stage, stage);
        }
        if let Some(latency_ns) = obj.get("latency_ns").and_then(Value::as_u64) {
            self.validation_latencies_ns.push(latency_ns);
        }
    }

    fn ingest_healing(&mut self, obj: &serde_json::Map<String, Value>) {
        self.healing_total += 1;
        if obj
            .get("escalated")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            self.healing_escalated_total += 1;
        }
        if let Some(action) = obj.get("healing_action").and_then(Value::as_str) {
            increment_counter(&mut self.healing_by_action, action);
        }
        if let Some(api_family) = obj.get("api_family").and_then(Value::as_str) {
            increment_counter(&mut self.healing_by_api_family, api_family);
        }
    }

    fn ingest_runtime_decision(&mut self, obj: &serde_json::Map<String, Value>) {
        self.runtime_decision_total += 1;
        if let Some(decision) = obj.get("decision").and_then(Value::as_str) {
            increment_counter(&mut self.runtime_by_decision, decision);
        }
        if let Some(action) = obj.get("decision_action").and_then(Value::as_str) {
            increment_counter(&mut self.runtime_by_action, action);
        }
        if let Some(policy) = obj.get("overload_policy").and_then(Value::as_str) {
            increment_counter(&mut self.runtime_overload_policies, policy);
        }
        if let Some(risk) = obj.get("risk_upper_bound_ppm").and_then(Value::as_u64) {
            self.runtime_risk_upper_bound_ppm.push(risk);
        }
    }

    fn ingest_runtime_snapshot(&mut self, obj: &serde_json::Map<String, Value>) {
        self.runtime_snapshot_decisions = obj.get("decisions").and_then(Value::as_u64);
        self.runtime_snapshot_consistency_faults =
            obj.get("consistency_faults").and_then(Value::as_u64);
        self.runtime_snapshot_regret_milli = obj
            .get("pareto_cumulative_regret_milli")
            .and_then(Value::as_u64);
        self.runtime_snapshot_cap_enforcements =
            obj.get("pareto_cap_enforcements").and_then(Value::as_u64);
        self.runtime_snapshot_exhausted_families =
            obj.get("pareto_exhausted_families").and_then(Value::as_u64);
        self.runtime_snapshot_quarantine_depth =
            obj.get("quarantine_depth").and_then(Value::as_u64);
        self.runtime_snapshot_arena_utilization_ppm =
            obj.get("arena_utilization_ppm").and_then(Value::as_u64);
    }

    fn finalize(self, paths: &[PathBuf]) -> ObservabilityDashboardReport {
        let validation_summary = summarize_u64s(&self.validation_latencies_ns);
        let validation_histogram = build_cumulative_histogram(
            &self.validation_latencies_ns,
            &LATENCY_HISTOGRAM_BUCKETS_NS,
        );
        let runtime_risk_summary = summarize_u64s(&self.runtime_risk_upper_bound_ppm);
        let snapshot_metrics = self.latest_snapshot_metrics.unwrap_or_default();
        let allocator_snapshot = self.latest_allocator_snapshot.unwrap_or_default();

        let validation_total = if snapshot_metrics.validations > 0 {
            snapshot_metrics.validations
        } else {
            self.validation_events
        };
        let healing_total = if snapshot_metrics.heals > 0 {
            snapshot_metrics.heals.max(self.healing_total)
        } else {
            self.healing_total
        };

        let cache = if snapshot_metrics.tls_cache_hits > 0
            || snapshot_metrics.tls_cache_misses > 0
            || snapshot_metrics.bloom_hits > 0
            || snapshot_metrics.bloom_misses > 0
        {
            let tls_total = snapshot_metrics.tls_cache_hits + snapshot_metrics.tls_cache_misses;
            let bloom_total = snapshot_metrics.bloom_hits + snapshot_metrics.bloom_misses;
            CacheDashboard {
                tls_cache_hits: Some(snapshot_metrics.tls_cache_hits),
                tls_cache_misses: Some(snapshot_metrics.tls_cache_misses),
                tls_cache_hit_rate: (tls_total > 0)
                    .then_some(snapshot_metrics.tls_cache_hits as f64 / tls_total as f64),
                bloom_hits: Some(snapshot_metrics.bloom_hits),
                bloom_misses: Some(snapshot_metrics.bloom_misses),
                bloom_hit_rate: (bloom_total > 0)
                    .then_some(snapshot_metrics.bloom_hits as f64 / bloom_total as f64),
            }
        } else {
            CacheDashboard {
                tls_cache_hits: None,
                tls_cache_misses: None,
                tls_cache_hit_rate: None,
                bloom_hits: None,
                bloom_misses: None,
                bloom_hit_rate: None,
            }
        };

        let validation = ValidationDashboard {
            validations_total: validation_total,
            events_observed: self.validation_events,
            by_outcome: self.validation_by_outcome,
            by_stage: self.validation_by_stage,
            latency_ns: validation_summary,
            latency_histogram: validation_histogram,
        };
        let healing = HealingDashboard {
            heals_total: healing_total,
            escalated_total: self.healing_escalated_total,
            by_action: self.healing_by_action,
            by_api_family: self.healing_by_api_family,
        };
        let runtime_math = RuntimeMathDashboard {
            decision_total: self.runtime_decision_total,
            by_decision: self.runtime_by_decision,
            by_action: self.runtime_by_action,
            overload_policies: self.runtime_overload_policies,
            risk_upper_bound_ppm: runtime_risk_summary,
            snapshot_decisions: self.runtime_snapshot_decisions,
            snapshot_consistency_faults: self.runtime_snapshot_consistency_faults,
            snapshot_regret_milli: self.runtime_snapshot_regret_milli,
            snapshot_cap_enforcements: self.runtime_snapshot_cap_enforcements,
            snapshot_exhausted_families: self.runtime_snapshot_exhausted_families,
            snapshot_field_out_of_range_total: self.runtime_snapshot_field_out_of_range_total,
        };

        let allocator_thread_cache_total =
            allocator_snapshot.thread_cache_hits + allocator_snapshot.thread_cache_misses;
        let allocator = if allocator_snapshot.allocations_total > 0
            || allocator_snapshot.frees_total > 0
            || allocator_snapshot.active_allocations > 0
            || allocator_snapshot.bytes_allocated > 0
            || self.runtime_snapshot_quarantine_depth.is_some()
            || self.runtime_snapshot_arena_utilization_ppm.is_some()
        {
            AllocatorDashboard {
                available: true,
                allocations_total: (allocator_snapshot.allocations_total > 0)
                    .then_some(allocator_snapshot.allocations_total),
                frees_total: (allocator_snapshot.frees_total > 0)
                    .then_some(allocator_snapshot.frees_total),
                active_allocations: (allocator_snapshot.active_allocations > 0)
                    .then_some(allocator_snapshot.active_allocations),
                bytes_allocated: (allocator_snapshot.bytes_allocated > 0)
                    .then_some(allocator_snapshot.bytes_allocated),
                quarantine_depth: self.runtime_snapshot_quarantine_depth,
                arena_utilization_ppm: self.runtime_snapshot_arena_utilization_ppm.or_else(|| {
                    self.runtime_snapshot_quarantine_depth
                        .map(quarantine_depth_to_utilization_ppm)
                }),
                thread_cache_hits: (allocator_snapshot.thread_cache_hits > 0)
                    .then_some(allocator_snapshot.thread_cache_hits),
                thread_cache_misses: (allocator_snapshot.thread_cache_misses > 0)
                    .then_some(allocator_snapshot.thread_cache_misses),
                thread_cache_hit_rate: (allocator_thread_cache_total > 0).then_some(
                    allocator_snapshot.thread_cache_hits as f64
                        / allocator_thread_cache_total as f64,
                ),
                central_bin_hits: (allocator_snapshot.central_bin_hits > 0)
                    .then_some(allocator_snapshot.central_bin_hits),
                spills_to_central: (allocator_snapshot.spills_to_central > 0)
                    .then_some(allocator_snapshot.spills_to_central),
                source_note: "Allocator KPIs are sourced from allocator_metrics_snapshot rows and runtime_snapshot pressure fields.".to_string(),
            }
        } else {
            AllocatorDashboard {
                available: false,
                allocations_total: None,
                frees_total: None,
                active_allocations: None,
                bytes_allocated: None,
                quarantine_depth: None,
                arena_utilization_ppm: None,
                thread_cache_hits: None,
                thread_cache_misses: None,
                thread_cache_hit_rate: None,
                central_bin_hits: None,
                spills_to_central: None,
                source_note: "Allocator counters are not emitted by the currently ingested JSONL streams; only runtime/healing/cache data is currently exported.".to_string(),
            }
        };

        let mut available_sections = Vec::new();
        if validation.validations_total > 0 || validation.events_observed > 0 {
            available_sections.push("validation".to_string());
        }
        if healing.heals_total > 0 {
            available_sections.push("healing".to_string());
        }
        if cache.tls_cache_hits.is_some() || cache.bloom_hits.is_some() {
            available_sections.push("cache".to_string());
        }
        if allocator.available {
            available_sections.push("allocator".to_string());
        }
        if runtime_math.decision_total > 0
            || runtime_math.snapshot_decisions.is_some()
            || runtime_math.snapshot_field_out_of_range_total > 0
        {
            available_sections.push("runtime_math".to_string());
        }

        let mut alerts = Vec::new();
        if self.invalid_rows > 0 {
            alerts.push(DashboardAlert {
                name: "invalid_rows_present".to_string(),
                severity: "warn".to_string(),
                message: format!(
                    "{} input row(s) failed JSON parsing or were not objects",
                    self.invalid_rows
                ),
            });
        }
        if healing.escalated_total > 0 {
            alerts.push(DashboardAlert {
                name: "escalated_healing_actions".to_string(),
                severity: "warn".to_string(),
                message: format!(
                    "{} escalated healing action(s) observed",
                    healing.escalated_total
                ),
            });
        }
        if runtime_math.snapshot_field_out_of_range_total > 0 {
            alerts.push(DashboardAlert {
                name: "runtime_snapshot_contract_drift".to_string(),
                severity: "error".to_string(),
                message: format!(
                    "{} runtime snapshot field(s) were out of contract range",
                    runtime_math.snapshot_field_out_of_range_total
                ),
            });
        }
        if validation.latency_ns.p95.is_some_and(|p95| p95 > 5_000) {
            alerts.push(DashboardAlert {
                name: "validation_latency_p95_budget".to_string(),
                severity: "warn".to_string(),
                message: format!(
                    "validation latency p95={}ns exceeds 5000ns dashboard warning budget",
                    validation.latency_ns.p95.unwrap_or_default()
                ),
            });
        }
        if allocator
            .arena_utilization_ppm
            .is_some_and(|utilization| utilization >= 850_000)
        {
            alerts.push(DashboardAlert {
                name: "allocator_arena_pressure".to_string(),
                severity: "warn".to_string(),
                message: format!(
                    "allocator arena utilization {}ppm exceeds 850000ppm warning budget",
                    allocator.arena_utilization_ppm.unwrap_or_default()
                ),
            });
        }
        if allocator
            .thread_cache_hit_rate
            .is_some_and(|hit_rate| hit_rate < 0.60)
        {
            alerts.push(DashboardAlert {
                name: "allocator_thread_cache_efficiency".to_string(),
                severity: "warn".to_string(),
                message: format!(
                    "allocator thread-cache hit rate {:.3} is below 0.600 warning floor",
                    allocator.thread_cache_hit_rate.unwrap_or_default()
                ),
            });
        }

        ObservabilityDashboardReport {
            schema_version: "v1".to_string(),
            bead: OBSERVABILITY_BEAD_ID.to_string(),
            generated_at_utc: approx_now_utc(),
            input_files: paths
                .iter()
                .map(|path| path.display().to_string())
                .collect(),
            summary: DashboardSummary {
                total_rows: self.total_rows,
                parsed_rows: self.parsed_rows,
                invalid_rows: self.invalid_rows,
                controllers_seen: self.controllers_seen.into_iter().collect(),
                modes_seen: self.modes_seen.into_iter().collect(),
                api_families_seen: self.api_families_seen.into_iter().collect(),
                available_sections,
            },
            validation,
            healing,
            cache,
            allocator,
            runtime_math,
            artifact_refs: self.artifact_refs.into_iter().collect(),
            alerts,
            alert_rules: default_alert_rules(),
        }
    }
}

fn is_membrane_snapshot(obj: &serde_json::Map<String, Value>) -> bool {
    obj.get("event").and_then(Value::as_str) == Some("membrane_metrics_snapshot")
        && obj.get("metrics").is_some()
}

fn is_allocator_snapshot(obj: &serde_json::Map<String, Value>) -> bool {
    obj.get("event").and_then(Value::as_str) == Some("allocator_metrics_snapshot")
        && obj.get("api_family").and_then(Value::as_str) == Some("allocator")
}

fn is_validation_row(obj: &serde_json::Map<String, Value>) -> bool {
    obj.get("api_family").and_then(Value::as_str) == Some("pointer_validation")
        || obj
            .get("event")
            .and_then(Value::as_str)
            .is_some_and(|event| event.starts_with("validation_"))
}

fn is_healing_row(obj: &serde_json::Map<String, Value>) -> bool {
    let is_membrane_heal = obj.get("api_family").and_then(Value::as_str) == Some("membrane-heal")
        || obj
            .get("trace_id")
            .and_then(Value::as_str)
            .is_some_and(|trace_id| trace_id.starts_with("membrane::heal"));
    is_membrane_heal
        && obj.get("outcome").and_then(Value::as_str) == Some("repair")
        && obj.get("healing_action").and_then(Value::as_str).is_some()
}

fn extract_mode<'a>(obj: &'a serde_json::Map<String, Value>) -> Option<&'a str> {
    obj.get("mode")
        .and_then(Value::as_str)
        .or_else(|| obj.get("runtime_mode").and_then(Value::as_str))
}

fn increment_counter(map: &mut BTreeMap<String, u64>, key: &str) {
    *map.entry(key.to_string()).or_default() += 1;
}

fn summarize_u64s(values: &[u64]) -> ScalarSummary {
    if values.is_empty() {
        return ScalarSummary::default();
    }

    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let count = u64::try_from(sorted.len()).unwrap_or(u64::MAX);
    let sum = sorted
        .iter()
        .fold(0u128, |acc, value| acc + u128::from(*value));

    ScalarSummary {
        count,
        min: sorted.first().copied(),
        p50: percentile(&sorted, 50, 100),
        p95: percentile(&sorted, 95, 100),
        p99: percentile(&sorted, 99, 100),
        max: sorted.last().copied(),
        mean: Some(sum as f64 / count as f64),
    }
}

fn percentile(sorted: &[u64], numer: u64, denom: u64) -> Option<u64> {
    if sorted.is_empty() || denom == 0 {
        return None;
    }
    let last_index = u128::try_from(sorted.len().saturating_sub(1)).ok()?;
    let idx = (last_index * u128::from(numer)).div_ceil(u128::from(denom));
    sorted.get(usize::try_from(idx).ok()?).copied()
}

fn build_cumulative_histogram(values: &[u64], buckets: &[u64]) -> Vec<HistogramBucket> {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();

    let mut histogram = Vec::with_capacity(buckets.len() + 1);
    for bucket in buckets {
        let count = sorted.partition_point(|value| *value <= *bucket);
        histogram.push(HistogramBucket {
            le: Some(*bucket),
            cumulative_count: u64::try_from(count).unwrap_or(u64::MAX),
        });
    }
    histogram.push(HistogramBucket {
        le: None,
        cumulative_count: u64::try_from(sorted.len()).unwrap_or(u64::MAX),
    });
    histogram
}

fn quarantine_depth_to_utilization_ppm(depth: u64) -> u64 {
    if depth <= 64 {
        0
    } else if depth >= 65_536 {
        1_000_000
    } else {
        ((depth - 64) * 1_000_000) / (65_536 - 64)
    }
}

fn default_alert_rules() -> Vec<DashboardAlertRule> {
    vec![
        DashboardAlertRule {
            alert: "FrankenLibCInvalidObservabilityRows".to_string(),
            expr: "increase(frankenlibc_observability_invalid_rows_total[5m]) > 0".to_string(),
            for_window: "2m".to_string(),
            severity: "warning".to_string(),
            summary: "Observability ingestion is receiving malformed JSONL rows.".to_string(),
        },
        DashboardAlertRule {
            alert: "FrankenLibCValidationLatencyBudget".to_string(),
            expr: "frankenlibc_validation_latency_ns{stat=\"p95\"} > 5000".to_string(),
            for_window: "10m".to_string(),
            severity: "warning".to_string(),
            summary: "Membrane validation latency p95 is above the operator budget.".to_string(),
        },
        DashboardAlertRule {
            alert: "FrankenLibCEscalatedHealing".to_string(),
            expr: "frankenlibc_healing_escalated_total > 0".to_string(),
            for_window: "1m".to_string(),
            severity: "warning".to_string(),
            summary: "Escalated healing actions were observed in the membrane.".to_string(),
        },
        DashboardAlertRule {
            alert: "FrankenLibCRuntimeSnapshotContractDrift".to_string(),
            expr: "frankenlibc_runtime_snapshot_field_out_of_range_total > 0".to_string(),
            for_window: "1m".to_string(),
            severity: "critical".to_string(),
            summary: "Runtime snapshot fields drifted outside their proof-carrying contract."
                .to_string(),
        },
        DashboardAlertRule {
            alert: "FrankenLibCAllocatorArenaPressure".to_string(),
            expr: "frankenlibc_allocator_arena_utilization_ppm > 850000".to_string(),
            for_window: "10m".to_string(),
            severity: "warning".to_string(),
            summary: "Allocator arena utilization is approaching the fragmentation budget."
                .to_string(),
        },
        DashboardAlertRule {
            alert: "FrankenLibCAllocatorThreadCacheHitRateLow".to_string(),
            expr: "frankenlibc_allocator_thread_cache_hit_rate < 0.60".to_string(),
            for_window: "15m".to_string(),
            severity: "warning".to_string(),
            summary: "Allocator thread-cache hit rate is persistently low.".to_string(),
        },
        DashboardAlertRule {
            alert: "FrankenLibCRuntimeRiskUpperBoundHigh".to_string(),
            expr: "frankenlibc_runtime_risk_upper_bound_ppm{stat=\"p95\"} > 250000".to_string(),
            for_window: "10m".to_string(),
            severity: "warning".to_string(),
            summary: "Runtime risk upper-bound p95 has breached the hardened budget.".to_string(),
        },
    ]
}

fn write_text_file(path: &Path, body: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|err| format!("failed creating '{}': {err}", parent.display()))?;
    }
    std::fs::write(path, body).map_err(|err| format!("failed writing '{}': {err}", path.display()))
}

fn write_prometheus_sample(out: &mut String, name: &str, labels: &[(&str, &str)], value: &str) {
    if labels.is_empty() {
        let _ = writeln!(out, "{name} {value}");
        return;
    }

    out.push_str(name);
    out.push('{');
    for (idx, (key, label_value)) in labels.iter().enumerate() {
        if idx != 0 {
            out.push(',');
        }
        let _ = write!(
            out,
            r#"{key}="{}""#,
            escape_prometheus_label_value(label_value)
        );
    }
    let _ = writeln!(out, "}} {value}");
}

fn write_optional_summary_gauge(out: &mut String, name: &str, summary: &ScalarSummary) {
    for (stat, value) in [
        ("min", summary.min.map(|value| value.to_string())),
        ("p50", summary.p50.map(|value| value.to_string())),
        ("p95", summary.p95.map(|value| value.to_string())),
        ("p99", summary.p99.map(|value| value.to_string())),
        ("max", summary.max.map(|value| value.to_string())),
        ("mean", summary.mean.map(|value| value.to_string())),
    ] {
        if let Some(value) = value {
            write_prometheus_sample(out, name, &[("stat", stat)], &value);
        }
    }
}

fn escape_prometheus_label_value(value: &str) -> String {
    value
        .chars()
        .flat_map(|ch| match ch {
            '\\' => ['\\', '\\'].into_iter().collect::<Vec<_>>(),
            '"' => ['\\', '"'].into_iter().collect::<Vec<_>>(),
            '\n' => ['\\', 'n'].into_iter().collect::<Vec<_>>(),
            other => vec![other],
        })
        .collect()
}

fn write_statsd_summary(out: &mut String, prefix: &str, summary: &ScalarSummary) {
    let _ = writeln!(out, "{prefix}.count:{}|g", summary.count);
    if let Some(value) = summary.min {
        let _ = writeln!(out, "{prefix}.min:{}|g", value);
    }
    if let Some(value) = summary.p50 {
        let _ = writeln!(out, "{prefix}.p50:{}|g", value);
    }
    if let Some(value) = summary.p95 {
        let _ = writeln!(out, "{prefix}.p95:{}|g", value);
    }
    if let Some(value) = summary.p99 {
        let _ = writeln!(out, "{prefix}.p99:{}|g", value);
    }
    if let Some(value) = summary.max {
        let _ = writeln!(out, "{prefix}.max:{}|g", value);
    }
    if let Some(value) = summary.mean {
        let _ = writeln!(out, "{prefix}.mean:{}|g", value);
    }
}

fn sanitize_metric_component(component: &str) -> String {
    let sanitized: String = component
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect();
    sanitized.trim_matches('_').to_string()
}

fn approx_now_utc() -> String {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    let millis = duration.subsec_millis();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        1970 + secs / 31_557_600,
        (secs % 31_557_600) / 2_629_800 + 1,
        (secs % 2_629_800) / 86400 + 1,
        (secs % 86400) / 3600,
        (secs % 3600) / 60,
        secs % 60,
        millis,
    )
}

fn grafana_stat_panel(id: u64, title: &str, expr: &str, unit: &str) -> Value {
    let row = (id - 1) / 3;
    json!({
        "id": id,
        "type": "stat",
        "title": title,
        "datasource": {"type": "prometheus", "uid": "prometheus"},
        "gridPos": {"h": 8, "w": 8, "x": ((id - 1) % 3) * 8, "y": row * 8},
        "targets": [{"refId": "A", "expr": expr}],
        "fieldConfig": {"defaults": {"unit": unit}}
    })
}

fn grafana_timeseries_panel(id: u64, title: &str, expr: &str) -> Value {
    json!({
        "id": id,
        "type": "timeseries",
        "title": title,
        "datasource": {"type": "prometheus", "uid": "prometheus"},
        "gridPos": {"h": 9, "w": 12, "x": if id.is_multiple_of(2) { 12 } else { 0 }, "y": 8 + (((id - 4) / 2) * 9)},
        "targets": [{"refId": "A", "expr": expr}],
        "fieldConfig": {"defaults": {"unit": "short"}}
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_rows() -> String {
        let rows = vec![
            json!({
                "timestamp": "2026-04-06T00:00:00.000Z",
                "trace_id": "membrane::metrics::bd-282v::smoke",
                "decision_id": 1,
                "schema_version": "1.0",
                "level": "info",
                "event": "membrane_metrics_snapshot",
                "controller_id": "membrane_metrics.v1",
                "mode": "strict",
                "api_family": "pointer_validation",
                "symbol": "membrane::ptr_validator::validate",
                "decision_path": "tsm::metrics::snapshot",
                "decision_action": "observe",
                "outcome": "snapshot",
                "healing_action": Value::Null,
                "errno": 0,
                "latency_ns": 0,
                "metrics": {
                    "validations": 12,
                    "tls_cache_hits": 9,
                    "tls_cache_misses": 3,
                    "tls_cache_hit_rate": 0.75,
                    "bloom_hits": 6,
                    "bloom_misses": 2,
                    "bloom_hit_rate": 0.75,
                    "arena_lookups": 4,
                    "fingerprint_passes": 4,
                    "fingerprint_failures": 1,
                    "canary_passes": 4,
                    "canary_failures": 0,
                    "heals": 2,
                    "double_frees_healed": 1,
                    "foreign_frees_healed": 0,
                    "size_clamps": 1
                },
                "artifact_refs": ["crates/frankenlibc-membrane/src/metrics.rs"]
            }),
            json!({
                "timestamp": "2026-04-06T00:00:01.000Z",
                "trace_id": "tsm::pointer_validation::decision::0001",
                "span_id": "validation::stage::1",
                "parent_span_id": "validation::entry::1",
                "decision_id": 1,
                "schema_version": "1.0",
                "level": "info",
                "event": "validation_stage",
                "controller_id": "tsm_validation_pipeline.v1",
                "decision_path": "null_check",
                "decision_action": "Allow",
                "outcome": "allow",
                "mode": "strict",
                "api_family": "pointer_validation",
                "symbol": "membrane::ptr_validator::validate",
                "stage": "null_check",
                "latency_ns": 500,
                "policy_id": 7,
                "risk_upper_bound_ppm": 1200,
                "evidence_seqno": 1,
                "artifact_refs": ["crates/frankenlibc-membrane/src/ptr_validator.rs"]
            }),
            json!({
                "trace_id": "membrane::heal::0001",
                "decision_id": 2,
                "schema_version": "1.0",
                "bead_id": OBSERVABILITY_BEAD_ID,
                "runtime_mode": "hardened",
                "level": "warn",
                "api_family": "membrane-heal",
                "decision_path": "record",
                "outcome": "repair",
                "healing_action": "ClampSize",
                "escalated": false,
                "details": {"requested": 64, "clamped": 32}
            }),
            json!({
                "timestamp": "2026-04-06T00:00:02.000Z",
                "trace_id": "allocator::metrics::bd-282v::smoke",
                "bead_id": OBSERVABILITY_BEAD_ID,
                "scenario_id": "smoke",
                "decision_id": 0,
                "schema_version": "1.0",
                "level": "info",
                "event": "allocator_metrics_snapshot",
                "controller_id": "malloc_stats.v1",
                "mode": "hardened",
                "api_family": "allocator",
                "symbol": "malloc::stats",
                "decision_path": "allocator::stats::snapshot",
                "decision_action": "observe",
                "outcome": "snapshot",
                "healing_action": Value::Null,
                "errno": 0,
                "latency_ns": 0,
                "allocations_total": 17,
                "frees_total": 11,
                "active_allocations": 6,
                "bytes_allocated": 8192,
                "thread_cache_hits": 14,
                "thread_cache_misses": 6,
                "central_bin_hits": 3,
                "spills_to_central": 1,
                "artifact_refs": ["crates/frankenlibc-abi/src/malloc_abi.rs"]
            }),
            json!({
                "timestamp": "2026-04-06T00:00:03.000Z",
                "trace_id": "runtime_math::decision::0001",
                "bead_id": OBSERVABILITY_BEAD_ID,
                "scenario_id": "smoke",
                "level": "warn",
                "event": "runtime_decision",
                "controller_id": "runtime_math_kernel.v1",
                "decision": "Repair",
                "decision_action": "Repair",
                "decision_path": "runtime_math::repair",
                "healing_action": "ClampSize",
                "decision_id": 3,
                "schema_version": "1.0",
                "mode": "hardened",
                "api_family": "allocator",
                "symbol": "runtime_math::allocator",
                "errno": 0,
                "latency_ns": 250,
                "policy_id": 7,
                "risk_upper_bound_ppm": 420000,
                "evidence_seqno": 1,
                "overload_state": "nominal",
                "degradation_active": false,
                "overload_policy": "pressured-fast",
                "overload_policy_count": 2,
                "pressure_score_milli": 1200,
                "pressure_raw_score_milli": 1200,
                "risk_inputs": {
                    "requested_bytes": 128,
                    "bloom_negative": false,
                    "is_write": true,
                    "contention_hint": 4,
                    "addr_hint": 0,
                    "pressure_epoch": 1,
                    "pressure_transition_count": 1
                },
                "artifact_refs": ["crates/frankenlibc-membrane/src/runtime_math/mod.rs"]
            }),
            json!({
                "timestamp": "2026-04-06T00:00:04.000Z",
                "trace_id": "runtime_math::snapshot::bd-282v::smoke",
                "bead_id": OBSERVABILITY_BEAD_ID,
                "scenario_id": "smoke",
                "decision_id": 0,
                "schema_version": "1.0",
                "level": "info",
                "event": "runtime_snapshot",
                "controller_id": "runtime_math_kernel.v1",
                "mode": "hardened",
                "api_family": "runtime_math",
                "symbol": "runtime_math::kernel",
                "decision_path": "snapshot::state",
                "healing_action": Value::Null,
                "errno": 0,
                "latency_ns": 0,
                "decisions": 5,
                "consistency_faults": 1,
                "pareto_cumulative_regret_milli": 50,
                "pareto_cap_enforcements": 0,
                "pareto_exhausted_families": 0,
                "quarantine_depth": 4096,
                "arena_utilization_ppm": 62451,
                "evidence_seqno": 2,
                "artifact_refs": ["crates/frankenlibc-membrane/src/runtime_math/mod.rs"]
            }),
        ];
        rows.into_iter()
            .map(|row| serde_json::to_string(&row).expect("row must serialize"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn write_test_input(name: &str, contents: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "frankenlibc_observability_dashboard_{}_{}",
            name,
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let path = dir.join("input.jsonl");
        std::fs::write(&path, contents).expect("write temp input");
        path
    }

    #[test]
    fn scalar_summary_percentiles_are_deterministic() {
        let summary = summarize_u64s(&[5, 10, 15, 20, 25]);
        assert_eq!(summary.count, 5);
        assert_eq!(summary.min, Some(5));
        assert_eq!(summary.p50, Some(15));
        assert_eq!(summary.p95, Some(25));
        assert_eq!(summary.max, Some(25));
        assert!(summary.mean.is_some_and(|mean| mean > 14.0 && mean < 16.0));
    }

    #[test]
    fn dashboard_aggregates_mixed_streams() {
        let path = write_test_input("aggregate", &format!("{}\nnot-json", test_rows()));
        let report = build_from_paths(&[path]).expect("dashboard should build");

        assert_eq!(report.schema_version, "v1");
        assert_eq!(report.bead, OBSERVABILITY_BEAD_ID);
        assert_eq!(report.summary.total_rows, 7);
        assert_eq!(report.summary.invalid_rows, 1);
        assert_eq!(report.validation.validations_total, 12);
        assert_eq!(report.validation.events_observed, 2);
        assert_eq!(report.validation.by_stage.get("null_check"), Some(&1));
        assert_eq!(report.healing.heals_total, 2);
        assert_eq!(report.healing.by_action.get("ClampSize"), Some(&1));
        assert!(report.allocator.available);
        assert_eq!(report.allocator.allocations_total, Some(17));
        assert_eq!(report.allocator.frees_total, Some(11));
        assert_eq!(report.allocator.active_allocations, Some(6));
        assert_eq!(report.allocator.bytes_allocated, Some(8192));
        assert_eq!(report.allocator.quarantine_depth, Some(4096));
        assert_eq!(report.allocator.arena_utilization_ppm, Some(62451));
        assert_eq!(report.runtime_math.decision_total, 1);
        assert_eq!(report.runtime_math.by_decision.get("Repair"), Some(&1));
        assert_eq!(report.runtime_math.snapshot_decisions, Some(5));
        assert_eq!(report.cache.tls_cache_hits, Some(9));
        assert!(
            report
                .summary
                .available_sections
                .contains(&"allocator".to_string())
        );
        assert!(
            report
                .summary
                .available_sections
                .contains(&"runtime_math".to_string())
        );
        assert!(
            !report.alerts.is_empty(),
            "invalid row should emit an alert"
        );
        assert!(
            report
                .alert_rules
                .iter()
                .any(|rule| rule.alert == "FrankenLibCAllocatorArenaPressure"),
            "alert-rules contract must include allocator pressure"
        );

        let prometheus = report.to_prometheus_text();
        assert!(
            prometheus.contains("frankenlibc_validations_total 12"),
            "prometheus output should include validation gauge"
        );
        assert!(
            prometheus
                .contains("frankenlibc_runtime_decisions_by_decision_total{decision=\"Repair\"} 1"),
            "prometheus output should include runtime decision labels"
        );
        assert!(
            prometheus.contains("frankenlibc_allocator_bytes_allocated 8192"),
            "prometheus output should include allocator byte gauge"
        );

        let statsd = report.to_statsd_text();
        assert!(
            statsd.contains("frankenlibc.healing.action.clampsize:1|c"),
            "statsd output should include healing action counter"
        );
        assert!(
            statsd.contains("frankenlibc.allocator.allocations_total:17|g"),
            "statsd output should include allocator totals"
        );

        let grafana: Value = serde_json::from_str(&report.to_grafana_dashboard_json())
            .expect("grafana template must be valid json");
        assert_eq!(
            grafana["title"].as_str(),
            Some("FrankenLibC Observability Dashboard")
        );
        assert!(
            grafana["panels"]
                .as_array()
                .is_some_and(|panels| panels.len() >= 10),
            "grafana template should contain panel definitions"
        );

        let alert_rules = report.to_alert_rules_yaml();
        assert!(
            alert_rules.contains("FrankenLibCAllocatorArenaPressure"),
            "alert rules yaml should include allocator pressure rule"
        );
    }
}
