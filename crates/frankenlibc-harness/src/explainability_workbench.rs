//! Deterministic trace-to-decision drilldown for structured log bundles.
//!
//! Bead: `bd-26xb.4`
//!
//! This module turns the existing structured-log + artifact-index evidence into
//! a one-command explainability workbench. It focuses on the operator questions
//! that are hardest to answer from raw JSONL alone:
//! - what happened first and last,
//! - which validator stages fired,
//! - where strict vs hardened diverged,
//! - which artifacts are relevant for root-cause drilldown.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;

use serde::Serialize;
use thiserror::Error;

use crate::structured_log::{ArtifactIndex, LogEntry, validate_log_line};

const WORKBENCH_BEAD_ID: &str = "bd-26xb.4";

#[derive(Debug, Error)]
pub enum ExplainabilityWorkbenchError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid log line {line_number}: {message}")]
    InvalidLog { line_number: usize, message: String },
    #[error("artifact index parse failed: {0}")]
    InvalidArtifactIndex(#[from] serde_json::Error),
    #[error("no matching traces found")]
    NoMatchingTraces,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExplainabilityWorkbenchReport {
    pub schema_version: String,
    pub bead: String,
    pub source_log: String,
    pub source_artifact_index: Option<String>,
    pub trace_filter: Option<String>,
    pub scenario_filter: Option<String>,
    pub tooling_contract: ToolingContract,
    pub scenarios: Vec<ScenarioWorkbench>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ToolingContract {
    pub has_asupersync_dependency: bool,
    pub asupersync_feature_present: bool,
    pub default_enables_asupersync_tooling: bool,
    pub asupersync_tooling_enabled: bool,
    pub frankentui_feature_present: bool,
    pub frankentui_dependency_set_complete: bool,
    pub frankentui_ui_enabled: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScenarioWorkbench {
    pub scenario_id: String,
    pub trace_count: usize,
    pub modes: Vec<String>,
    pub root_cause: RootCauseSummary,
    pub mode_divergence: Vec<ModeDivergence>,
    pub artifact_links: Vec<ArtifactLink>,
    pub traces: Vec<TraceWorkbench>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RootCauseSummary {
    pub rationale: String,
    pub controllers: Vec<String>,
    pub healing_actions: Vec<String>,
    pub failure_signatures: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ModeDivergence {
    pub left_mode: String,
    pub right_mode: String,
    pub differs: bool,
    pub differing_fields: Vec<String>,
    pub left: ModeSignature,
    pub right: ModeSignature,
}

#[derive(Debug, Clone, Serialize)]
pub struct ModeSignature {
    pub mode: String,
    pub outcome: Option<String>,
    pub decision_action: Option<String>,
    pub healing_action: Option<String>,
    pub decision_path: Option<String>,
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TraceWorkbench {
    pub trace_id: String,
    pub bead_id: Option<String>,
    pub scenario_id: String,
    pub mode: String,
    pub api_families: Vec<String>,
    pub symbols: Vec<String>,
    pub summary: TraceSummary,
    pub validator_stages: Vec<ValidatorStageSummary>,
    pub artifact_links: Vec<ArtifactLink>,
    pub timeline: Vec<TimelineEvent>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TraceSummary {
    pub entry_count: usize,
    pub first_timestamp: String,
    pub last_timestamp: String,
    pub controllers: Vec<String>,
    pub decision_actions: Vec<String>,
    pub healing_actions: Vec<String>,
    pub outcomes: Vec<String>,
    pub failure_signatures: Vec<String>,
    pub primary_rationale: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ValidatorStageSummary {
    pub stage: String,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArtifactLink {
    pub path: String,
    pub kind: Option<String>,
    pub sha256: Option<String>,
    pub description: Option<String>,
    pub sources: Vec<String>,
    pub join_match: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TimelineEvent {
    pub line_number: usize,
    pub timestamp: String,
    pub level: String,
    pub event: String,
    pub mode: Option<String>,
    pub api_family: Option<String>,
    pub symbol: Option<String>,
    pub decision_path: Option<String>,
    pub stage_chain: Vec<String>,
    pub controller_id: Option<String>,
    pub decision_action: Option<String>,
    pub healing_action: Option<String>,
    pub outcome: Option<String>,
    pub errno: Option<i32>,
    pub latency_ns: Option<u64>,
    pub span_id: Option<String>,
    pub parent_span_id: Option<String>,
    pub decision_id: Option<u64>,
    pub policy_id: Option<u32>,
    pub evidence_seqno: Option<u64>,
    pub artifact_refs: Vec<String>,
    pub detail_excerpt: Option<String>,
}

#[derive(Debug, Clone)]
struct IndexedEntry {
    line_number: usize,
    entry: LogEntry,
}

#[derive(Debug, Default)]
struct TraceJoinKeys {
    trace_ids: BTreeSet<String>,
    span_ids: BTreeSet<String>,
    decision_ids: BTreeSet<u64>,
    policy_ids: BTreeSet<u32>,
    evidence_seqnos: BTreeSet<u64>,
}

#[must_use]
pub fn tooling_contract() -> ToolingContract {
    ToolingContract {
        has_asupersync_dependency: true,
        asupersync_feature_present: true,
        default_enables_asupersync_tooling: true,
        asupersync_tooling_enabled: cfg!(feature = "asupersync-tooling"),
        frankentui_feature_present: true,
        frankentui_dependency_set_complete: true,
        frankentui_ui_enabled: cfg!(feature = "frankentui-ui"),
    }
}

pub fn build_report(
    log_path: &Path,
    artifact_index_path: Option<&Path>,
    trace_filter: Option<&str>,
    scenario_filter: Option<&str>,
) -> Result<ExplainabilityWorkbenchReport, ExplainabilityWorkbenchError> {
    let entries = read_log_entries(log_path)?;
    let artifact_index = read_artifact_index(artifact_index_path)?;

    let mut by_trace: BTreeMap<String, Vec<IndexedEntry>> = BTreeMap::new();
    for entry in entries {
        if trace_filter.is_some_and(|needle| needle != entry.entry.trace_id) {
            continue;
        }
        by_trace
            .entry(entry.entry.trace_id.clone())
            .or_default()
            .push(entry);
    }

    let mut scenarios = BTreeMap::<String, Vec<TraceWorkbench>>::new();
    for (trace_id, mut trace_entries) in by_trace {
        trace_entries.sort_by(|left, right| {
            left.entry
                .timestamp
                .cmp(&right.entry.timestamp)
                .then_with(|| left.line_number.cmp(&right.line_number))
        });

        let trace = build_trace(trace_id, &trace_entries, artifact_index.as_ref());
        let scenario_id = trace.scenario_id.clone();
        if scenario_filter.is_some_and(|needle| needle != scenario_id) {
            continue;
        }
        scenarios.entry(scenario_id).or_default().push(trace);
    }

    let mut report_scenarios = Vec::new();
    for (scenario_id, mut traces) in scenarios {
        traces.sort_by(|left, right| {
            left.mode
                .cmp(&right.mode)
                .then_with(|| left.trace_id.cmp(&right.trace_id))
        });
        report_scenarios.push(build_scenario(scenario_id, traces));
    }

    if report_scenarios.is_empty() {
        return Err(ExplainabilityWorkbenchError::NoMatchingTraces);
    }

    Ok(ExplainabilityWorkbenchReport {
        schema_version: String::from("v1"),
        bead: String::from(WORKBENCH_BEAD_ID),
        source_log: log_path.display().to_string(),
        source_artifact_index: artifact_index_path.map(|path| path.display().to_string()),
        trace_filter: trace_filter.map(ToOwned::to_owned),
        scenario_filter: scenario_filter.map(ToOwned::to_owned),
        tooling_contract: tooling_contract(),
        scenarios: report_scenarios,
    })
}

fn read_log_entries(log_path: &Path) -> Result<Vec<IndexedEntry>, ExplainabilityWorkbenchError> {
    let content = std::fs::read_to_string(log_path)?;
    let mut entries = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let entry = validate_log_line(trimmed, idx + 1).map_err(|errors| {
            ExplainabilityWorkbenchError::InvalidLog {
                line_number: idx + 1,
                message: errors
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("; "),
            }
        })?;
        entries.push(IndexedEntry {
            line_number: idx + 1,
            entry,
        });
    }
    Ok(entries)
}

fn read_artifact_index(
    artifact_index_path: Option<&Path>,
) -> Result<Option<ArtifactIndex>, ExplainabilityWorkbenchError> {
    let Some(path) = artifact_index_path else {
        return Ok(None);
    };
    let body = std::fs::read_to_string(path)?;
    let mut index: ArtifactIndex = serde_json::from_str(&body)?;
    let _ = index.normalize_legacy_defaults();
    Ok(Some(index))
}

fn build_trace(
    trace_id: String,
    entries: &[IndexedEntry],
    artifact_index: Option<&ArtifactIndex>,
) -> TraceWorkbench {
    let scenario_id = entries
        .iter()
        .find_map(|row| row.entry.scenario_id.clone())
        .unwrap_or_else(|| trace_id.clone());
    let mode = entries
        .iter()
        .find_map(|row| row.entry.mode.clone())
        .unwrap_or_else(|| String::from("unknown"));
    let bead_id = entries.iter().find_map(|row| row.entry.bead_id.clone());

    let mut api_families = BTreeSet::new();
    let mut symbols = BTreeSet::new();
    let mut stage_counts = BTreeMap::<String, usize>::new();
    let mut controllers = BTreeSet::new();
    let mut decision_actions = BTreeSet::new();
    let mut healing_actions = BTreeSet::new();
    let mut outcomes = BTreeSet::new();
    let mut failure_signatures = BTreeSet::new();
    let mut timeline = Vec::new();

    for row in entries {
        let stage_chain = row
            .entry
            .decision_path
            .as_deref()
            .map(split_stages)
            .unwrap_or_default();
        for stage in &stage_chain {
            *stage_counts.entry(stage.clone()).or_default() += 1;
        }

        if let Some(api_family) = row.entry.api_family.clone() {
            api_families.insert(api_family);
        }
        if let Some(symbol) = row.entry.symbol.clone() {
            symbols.insert(symbol);
        }
        if let Some(controller) = row.entry.controller_id.clone() {
            controllers.insert(controller);
        }
        if let Some(action) = row.entry.decision_action.clone() {
            decision_actions.insert(action);
        }
        if let Some(action) = row.entry.healing_action.clone()
            && !is_none_like(&action)
        {
            healing_actions.insert(action);
        }
        if let Some(outcome) = row.entry.outcome {
            outcomes.insert(outcome_label(outcome).to_string());
        }
        if let Some(signature) = failure_signature(&row.entry) {
            failure_signatures.insert(signature);
        }

        timeline.push(TimelineEvent {
            line_number: row.line_number,
            timestamp: row.entry.timestamp.clone(),
            level: level_label(row.entry.level).to_string(),
            event: row.entry.event.clone(),
            mode: row.entry.mode.clone(),
            api_family: row.entry.api_family.clone(),
            symbol: row.entry.symbol.clone(),
            decision_path: row.entry.decision_path.clone(),
            stage_chain,
            controller_id: row.entry.controller_id.clone(),
            decision_action: row.entry.decision_action.clone(),
            healing_action: row.entry.healing_action.clone(),
            outcome: row
                .entry
                .outcome
                .map(|outcome| outcome_label(outcome).to_string()),
            errno: row.entry.errno,
            latency_ns: row.entry.latency_ns,
            span_id: row.entry.span_id.clone(),
            parent_span_id: row.entry.parent_span_id.clone(),
            decision_id: row.entry.decision_id,
            policy_id: row.entry.policy_id,
            evidence_seqno: row.entry.evidence_seqno,
            artifact_refs: row.entry.artifact_refs.clone().unwrap_or_default(),
            detail_excerpt: detail_excerpt(&row.entry),
        });
    }

    let validator_stages = stage_counts
        .into_iter()
        .map(|(stage, count)| ValidatorStageSummary { stage, count })
        .collect::<Vec<_>>();

    let artifact_links = collect_artifact_links(&trace_id, &timeline, artifact_index);
    let primary_rationale = primary_rationale(
        &failure_signatures,
        &healing_actions,
        &decision_actions,
        &timeline,
    );

    let summary = TraceSummary {
        entry_count: timeline.len(),
        first_timestamp: timeline
            .first()
            .map(|entry| entry.timestamp.clone())
            .unwrap_or_default(),
        last_timestamp: timeline
            .last()
            .map(|entry| entry.timestamp.clone())
            .unwrap_or_default(),
        controllers: controllers.into_iter().collect(),
        decision_actions: decision_actions.into_iter().collect(),
        healing_actions: healing_actions.into_iter().collect(),
        outcomes: outcomes.into_iter().collect(),
        failure_signatures: failure_signatures.into_iter().collect(),
        primary_rationale,
    };

    TraceWorkbench {
        trace_id,
        bead_id,
        scenario_id,
        mode,
        api_families: api_families.into_iter().collect(),
        symbols: symbols.into_iter().collect(),
        summary,
        validator_stages,
        artifact_links,
        timeline,
    }
}

fn collect_artifact_links(
    trace_id: &str,
    timeline: &[TimelineEvent],
    artifact_index: Option<&ArtifactIndex>,
) -> Vec<ArtifactLink> {
    let mut links = BTreeMap::<String, ArtifactLink>::new();

    for event in timeline {
        for path in &event.artifact_refs {
            let entry = links.entry(path.clone()).or_insert_with(|| ArtifactLink {
                path: path.clone(),
                kind: None,
                sha256: None,
                description: None,
                sources: vec![String::from("log_ref")],
                join_match: Vec::new(),
            });
            push_unique(&mut entry.sources, String::from("log_ref"));
        }
    }

    let Some(index) = artifact_index else {
        return links.into_values().collect();
    };

    let join_keys = collect_trace_join_keys(trace_id, timeline);
    for artifact in &index.artifacts {
        let mut match_reasons = Vec::new();
        if links.contains_key(&artifact.path) {
            match_reasons.push(String::from("path_ref"));
        }
        if let Some(artifact_keys) = artifact.join_keys.as_ref() {
            match_reasons.extend(join_reasons(&join_keys, artifact_keys));
        }
        if match_reasons.is_empty() {
            continue;
        }

        let entry = links
            .entry(artifact.path.clone())
            .or_insert_with(|| ArtifactLink {
                path: artifact.path.clone(),
                kind: None,
                sha256: None,
                description: None,
                sources: Vec::new(),
                join_match: Vec::new(),
            });
        entry.kind = Some(artifact.kind.clone());
        entry.sha256 = Some(artifact.sha256.clone());
        entry.description = artifact.description.clone();
        push_unique(&mut entry.sources, String::from("artifact_index"));
        for reason in match_reasons {
            push_unique(&mut entry.join_match, reason);
        }
    }

    links.into_values().collect()
}

fn collect_trace_join_keys(trace_id: &str, timeline: &[TimelineEvent]) -> TraceJoinKeys {
    let mut join_keys = TraceJoinKeys::default();
    join_keys.trace_ids.insert(trace_id.to_string());
    for event in timeline {
        if let Some(span_id) = event.span_id.clone() {
            join_keys.span_ids.insert(span_id);
        }
        if let Some(decision_id) = event.decision_id {
            join_keys.decision_ids.insert(decision_id);
        }
        if let Some(policy_id) = event.policy_id {
            join_keys.policy_ids.insert(policy_id);
        }
        if let Some(evidence_seqno) = event.evidence_seqno {
            join_keys.evidence_seqnos.insert(evidence_seqno);
        }
    }
    join_keys
}

fn join_reasons(
    trace_keys: &TraceJoinKeys,
    artifact_keys: &crate::structured_log::ArtifactJoinKeys,
) -> Vec<String> {
    let mut reasons = Vec::new();
    if artifact_keys
        .trace_ids
        .iter()
        .any(|trace_id| trace_keys.trace_ids.contains(trace_id))
    {
        reasons.push(String::from("trace_id"));
    }
    if artifact_keys
        .span_ids
        .iter()
        .any(|span_id| trace_keys.span_ids.contains(span_id))
    {
        reasons.push(String::from("span_id"));
    }
    if artifact_keys
        .decision_ids
        .iter()
        .any(|decision_id| trace_keys.decision_ids.contains(decision_id))
    {
        reasons.push(String::from("decision_id"));
    }
    if artifact_keys
        .policy_ids
        .iter()
        .any(|policy_id| trace_keys.policy_ids.contains(policy_id))
    {
        reasons.push(String::from("policy_id"));
    }
    if artifact_keys
        .evidence_seqnos
        .iter()
        .any(|evidence_seqno| trace_keys.evidence_seqnos.contains(evidence_seqno))
    {
        reasons.push(String::from("evidence_seqno"));
    }
    reasons
}

fn build_scenario(scenario_id: String, traces: Vec<TraceWorkbench>) -> ScenarioWorkbench {
    let mut modes = BTreeSet::new();
    let mut controllers = BTreeSet::new();
    let mut healing_actions = BTreeSet::new();
    let mut failure_signatures = BTreeSet::new();
    let mut artifact_links = BTreeMap::<String, ArtifactLink>::new();

    for trace in &traces {
        modes.insert(trace.mode.clone());
        controllers.extend(trace.summary.controllers.iter().cloned());
        healing_actions.extend(trace.summary.healing_actions.iter().cloned());
        failure_signatures.extend(trace.summary.failure_signatures.iter().cloned());
        for artifact in &trace.artifact_links {
            let entry = artifact_links
                .entry(artifact.path.clone())
                .or_insert_with(|| artifact.clone());
            if entry.kind.is_none() {
                entry.kind = artifact.kind.clone();
            }
            if entry.sha256.is_none() {
                entry.sha256 = artifact.sha256.clone();
            }
            if entry.description.is_none() {
                entry.description = artifact.description.clone();
            }
            for source in &artifact.sources {
                push_unique(&mut entry.sources, source.clone());
            }
            for reason in &artifact.join_match {
                push_unique(&mut entry.join_match, reason.clone());
            }
        }
    }

    let rationale = traces
        .iter()
        .find(|trace| !trace.summary.failure_signatures.is_empty())
        .or_else(|| traces.first())
        .map(|trace| trace.summary.primary_rationale.clone())
        .unwrap_or_else(|| String::from("timeline_only"));

    let root_cause = RootCauseSummary {
        rationale,
        controllers: controllers.into_iter().collect(),
        healing_actions: healing_actions.into_iter().collect(),
        failure_signatures: failure_signatures.into_iter().collect(),
    };

    let mode_divergence = build_mode_divergence(&traces);

    ScenarioWorkbench {
        scenario_id,
        trace_count: traces.len(),
        modes: modes.into_iter().collect(),
        root_cause,
        mode_divergence,
        artifact_links: artifact_links.into_values().collect(),
        traces,
    }
}

fn build_mode_divergence(traces: &[TraceWorkbench]) -> Vec<ModeDivergence> {
    let mut by_mode = BTreeMap::<String, ModeSignature>::new();
    for trace in traces {
        if trace.mode == "unknown" {
            continue;
        }
        by_mode.insert(trace.mode.clone(), signature_for_trace(trace));
    }

    let mut modes = by_mode.keys().cloned().collect::<Vec<_>>();
    modes.sort_by(|left, right| mode_sort_key(left).cmp(&mode_sort_key(right)));
    let mut divergence = Vec::new();
    for left_idx in 0..modes.len() {
        for right_idx in (left_idx + 1)..modes.len() {
            let left = by_mode
                .get(&modes[left_idx])
                .expect("mode signature must exist")
                .clone();
            let right = by_mode
                .get(&modes[right_idx])
                .expect("mode signature must exist")
                .clone();
            let mut differing_fields = Vec::new();
            if left.outcome != right.outcome {
                differing_fields.push(String::from("outcome"));
            }
            if left.decision_action != right.decision_action {
                differing_fields.push(String::from("decision_action"));
            }
            if left.healing_action != right.healing_action {
                differing_fields.push(String::from("healing_action"));
            }
            if left.decision_path != right.decision_path {
                differing_fields.push(String::from("decision_path"));
            }

            divergence.push(ModeDivergence {
                left_mode: left.mode.clone(),
                right_mode: right.mode.clone(),
                differs: !differing_fields.is_empty(),
                differing_fields,
                left,
                right,
            });
        }
    }

    divergence
}

fn mode_sort_key(mode: &str) -> (u8, &str) {
    match mode {
        "strict" => (0, mode),
        "hardened" => (1, mode),
        _ => (2, mode),
    }
}

fn signature_for_trace(trace: &TraceWorkbench) -> ModeSignature {
    let outcome = trace
        .timeline
        .iter()
        .rev()
        .find_map(|entry| entry.outcome.clone());
    let decision_action = trace
        .timeline
        .iter()
        .rev()
        .find_map(|entry| entry.decision_action.clone());
    let healing_action = trace
        .timeline
        .iter()
        .rev()
        .find_map(|entry| entry.healing_action.clone())
        .filter(|action| !is_none_like(action));
    let decision_path = trace
        .timeline
        .iter()
        .rev()
        .find_map(|entry| entry.decision_path.clone());

    ModeSignature {
        mode: trace.mode.clone(),
        outcome,
        decision_action,
        healing_action,
        decision_path,
        rationale: trace.summary.primary_rationale.clone(),
    }
}

fn primary_rationale(
    failure_signatures: &BTreeSet<String>,
    healing_actions: &BTreeSet<String>,
    decision_actions: &BTreeSet<String>,
    timeline: &[TimelineEvent],
) -> String {
    if let Some(signature) = failure_signatures.iter().next() {
        return format!("failure_signature:{signature}");
    }
    if let Some(action) = healing_actions.iter().next() {
        return format!("healing_action:{action}");
    }
    if let Some(action) = decision_actions.iter().next() {
        return format!("decision_action:{action}");
    }
    if let Some(path) = timeline
        .iter()
        .find_map(|entry| entry.decision_path.clone())
    {
        return format!("decision_path:{path}");
    }
    String::from("timeline_only")
}

fn split_stages(raw: &str) -> Vec<String> {
    let mut normalized = raw.to_string();
    for separator in ["->", "::", ">", "+", "|", "/"] {
        normalized = normalized.replace(separator, " ");
    }
    normalized
        .split_whitespace()
        .map(|token| {
            token
                .trim_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_' && ch != '-')
                .to_string()
        })
        .filter(|token| !token.is_empty())
        .collect()
}

fn detail_excerpt(entry: &LogEntry) -> Option<String> {
    let details = entry.details.as_ref()?;
    if let Some(signature) = details
        .get("failure_signature")
        .and_then(serde_json::Value::as_str)
    {
        return Some(signature.to_string());
    }
    if let Some(reason) = details
        .get("exclusion_reason")
        .and_then(serde_json::Value::as_str)
    {
        return Some(reason.to_string());
    }
    if let Some(reason) = details.get("reason").and_then(serde_json::Value::as_str) {
        return Some(reason.to_string());
    }
    let rendered = serde_json::to_string(details).ok()?;
    Some(truncate(&rendered, 80))
}

fn failure_signature(entry: &LogEntry) -> Option<String> {
    entry
        .details
        .as_ref()
        .and_then(|details| details.get("failure_signature"))
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned)
}

fn is_none_like(value: &str) -> bool {
    matches!(value, "none" | "None" | "null" | "Null")
}

fn push_unique(values: &mut Vec<String>, value: String) {
    if !values.contains(&value) {
        values.push(value);
    }
}

fn level_label(level: crate::structured_log::LogLevel) -> &'static str {
    match level {
        crate::structured_log::LogLevel::Trace => "trace",
        crate::structured_log::LogLevel::Debug => "debug",
        crate::structured_log::LogLevel::Info => "info",
        crate::structured_log::LogLevel::Warn => "warn",
        crate::structured_log::LogLevel::Error => "error",
        crate::structured_log::LogLevel::Fatal => "fatal",
    }
}

fn outcome_label(outcome: crate::structured_log::Outcome) -> &'static str {
    match outcome {
        crate::structured_log::Outcome::Pass => "pass",
        crate::structured_log::Outcome::Fail => "fail",
        crate::structured_log::Outcome::Skip => "skip",
        crate::structured_log::Outcome::Error => "error",
        crate::structured_log::Outcome::Timeout => "timeout",
    }
}

#[must_use]
pub fn render_plain(report: &ExplainabilityWorkbenchReport) -> String {
    let mut out = String::new();

    let _ = writeln!(
        out,
        "explainability workbench (scenarios={}, log={})",
        report.scenarios.len(),
        report.source_log
    );
    if let Some(path) = &report.source_artifact_index {
        let _ = writeln!(out, "artifact index: {path}");
    }
    if let Some(trace_filter) = &report.trace_filter {
        let _ = writeln!(out, "trace filter: {trace_filter}");
    }
    if let Some(scenario_filter) = &report.scenario_filter {
        let _ = writeln!(out, "scenario filter: {scenario_filter}");
    }
    let _ = writeln!(
        out,
        "tooling: asupersync_enabled={} frankentui_enabled={}",
        report.tooling_contract.asupersync_tooling_enabled,
        report.tooling_contract.frankentui_ui_enabled
    );

    for scenario in &report.scenarios {
        let _ = writeln!(
            out,
            "\nscenario {} modes={} traces={}",
            scenario.scenario_id,
            scenario.modes.join(","),
            scenario.trace_count
        );
        let _ = writeln!(out, "root cause: {}", scenario.root_cause.rationale);
        if scenario.mode_divergence.is_empty() {
            let _ = writeln!(out, "mode divergence: none");
        } else {
            for divergence in &scenario.mode_divergence {
                let fields = if divergence.differing_fields.is_empty() {
                    String::from("none")
                } else {
                    divergence.differing_fields.join(",")
                };
                let _ = writeln!(
                    out,
                    "mode divergence {} vs {}: {}",
                    divergence.left_mode, divergence.right_mode, fields
                );
            }
        }
        let _ = writeln!(out, "artifact links: {}", scenario.artifact_links.len());

        for trace in &scenario.traces {
            let _ = writeln!(
                out,
                "\n  trace {} mode={} entries={} rationale={}",
                trace.trace_id,
                trace.mode,
                trace.summary.entry_count,
                trace.summary.primary_rationale
            );
            let stage_line = if trace.validator_stages.is_empty() {
                String::from("none")
            } else {
                trace
                    .validator_stages
                    .iter()
                    .map(|stage| format!("{}({})", stage.stage, stage.count))
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            let _ = writeln!(out, "  stages: {stage_line}");
            if !trace.artifact_links.is_empty() {
                let artifact_line = trace
                    .artifact_links
                    .iter()
                    .map(|artifact| artifact.path.clone())
                    .collect::<Vec<_>>()
                    .join(", ");
                let _ = writeln!(out, "  artifacts: {artifact_line}");
            }
            let _ = writeln!(
                out,
                "  {:<24} {:<6} {:<18} {:<28} {:<12} {:<12} {:<8} detail",
                "timestamp", "level", "event", "decision_path", "action", "healing", "outcome"
            );
            let _ = writeln!(out, "  {}", "-".repeat(132));
            for event in &trace.timeline {
                let _ = writeln!(
                    out,
                    "  {:<24} {:<6} {:<18} {:<28} {:<12} {:<12} {:<8} {}",
                    truncate(&event.timestamp, 24),
                    truncate(&event.level, 6),
                    truncate(&event.event, 18),
                    truncate(event.decision_path.as_deref().unwrap_or(""), 28),
                    truncate(event.decision_action.as_deref().unwrap_or(""), 12),
                    truncate(event.healing_action.as_deref().unwrap_or(""), 12),
                    truncate(event.outcome.as_deref().unwrap_or(""), 8),
                    truncate(event.detail_excerpt.as_deref().unwrap_or(""), 40),
                );
            }
        }
    }

    out
}

fn truncate(raw: &str, width: usize) -> String {
    if raw.len() <= width {
        return raw.to_string();
    }
    if width <= 3 {
        return raw[..width].to_string();
    }
    format!("{}...", &raw[..(width - 3)])
}

#[cfg(feature = "frankentui-ui")]
#[must_use]
pub fn render_ftui(report: &ExplainabilityWorkbenchReport, ansi: bool, width: u16) -> String {
    use ftui_core::geometry::Rect;
    use ftui_layout::Constraint;
    use ftui_render::cell::PackedRgba;
    use ftui_render::frame::Frame;
    use ftui_render::grapheme_pool::GraphemePool;
    use ftui_style::Style;
    use ftui_widgets::Widget;
    use ftui_widgets::block::Block;
    use ftui_widgets::borders::{BorderType, Borders};
    use ftui_widgets::table::{Row, Table};

    let rows = report
        .scenarios
        .iter()
        .flat_map(|scenario| {
            scenario.traces.iter().flat_map(move |trace| {
                trace.timeline.iter().map(move |event| {
                    let status = event.outcome.clone().unwrap_or_default();
                    let style = match status.as_str() {
                        "fail" | "error" | "timeout" => Style::new().fg(PackedRgba::RED).bold(),
                        "pass" => Style::new().fg(PackedRgba::rgb(0, 255, 0)),
                        _ => Style::new(),
                    };
                    Row::new([
                        scenario.scenario_id.as_str(),
                        trace.mode.as_str(),
                        event.event.as_str(),
                        event.decision_path.as_deref().unwrap_or(""),
                        event.decision_action.as_deref().unwrap_or(""),
                        status.as_str(),
                    ])
                    .style(style)
                })
            })
        })
        .collect::<Vec<_>>();

    let height = (rows.len() as u16).saturating_add(4).max(6);
    let mut pool = GraphemePool::new();
    let mut frame = Frame::new(width, height, &mut pool);
    let header = Row::new([
        "scenario",
        "mode",
        "event",
        "decision_path",
        "action",
        "outcome",
    ])
    .style(Style::new().bold());
    let table = Table::new(
        rows,
        [
            Constraint::Fixed(18),
            Constraint::Fixed(10),
            Constraint::Fixed(18),
            Constraint::Fixed(36),
            Constraint::Fixed(12),
            Constraint::Fixed(10),
        ],
    )
    .header(header)
    .block(
        Block::new()
            .title(" explainability workbench ")
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded),
    )
    .column_spacing(1);

    let area = Rect::from_size(width, height);
    table.render(area, &mut frame);
    if ansi {
        ftui_harness::buffer_to_ansi(&frame.buffer)
    } else {
        ftui_harness::buffer_to_text(&frame.buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::structured_log::{ArtifactIndex, ArtifactJoinKeys, LogEntry, LogLevel, Outcome};

    fn temp_path(name: &str, suffix: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "frankenlibc_explainability_workbench_{name}_{}_{}",
            std::process::id(),
            suffix
        ))
    }

    struct SampleEntrySpec<'a> {
        trace_id: &'a str,
        scenario_id: &'a str,
        mode: &'a str,
        outcome: Outcome,
        action: &'a str,
        healing_action: &'a str,
        decision_id: u64,
        artifact_ref: &'a str,
    }

    fn sample_entry(spec: SampleEntrySpec<'_>) -> LogEntry {
        LogEntry::new(spec.trace_id, LogLevel::Info, "case_result")
            .with_bead(WORKBENCH_BEAD_ID)
            .with_scenario_id(spec.scenario_id)
            .with_mode(spec.mode)
            .with_api("malloc", "allocator_elimination")
            .with_decision_path("validator->fingerprint->repair")
            .with_controller_id("runtime_math_kernel.v1")
            .with_decision_action(spec.action)
            .with_healing_action(spec.healing_action)
            .with_decision_id(spec.decision_id)
            .with_policy_id(7)
            .with_outcome(spec.outcome)
            .with_artifacts(vec![spec.artifact_ref.to_string()])
            .with_details(serde_json::json!({
                "failure_signature": format!("{}_signature", spec.mode),
            }))
    }

    #[test]
    fn build_report_detects_mode_divergence_and_stage_chain() {
        let log_path = temp_path("mode_divergence", "log.jsonl");
        let strict = sample_entry(SampleEntrySpec {
            trace_id: "bd-26xb.4::demo::001",
            scenario_id: "demo",
            mode: "strict",
            outcome: Outcome::Fail,
            action: "Repair",
            healing_action: "ClampSize",
            decision_id: 41,
            artifact_ref: "artifacts/strict.log",
        });
        let hardened = sample_entry(SampleEntrySpec {
            trace_id: "bd-26xb.4::demo::002",
            scenario_id: "demo",
            mode: "hardened",
            outcome: Outcome::Pass,
            action: "Allow",
            healing_action: "None",
            decision_id: 42,
            artifact_ref: "artifacts/hardened.log",
        });
        std::fs::write(
            &log_path,
            format!(
                "{}\n{}\n",
                strict.to_jsonl().expect("strict jsonl"),
                hardened.to_jsonl().expect("hardened jsonl")
            ),
        )
        .expect("write log");

        let report = build_report(&log_path, None, None, Some("demo")).expect("report");
        assert_eq!(report.scenarios.len(), 1);
        let scenario = &report.scenarios[0];
        assert_eq!(scenario.trace_count, 2);
        assert_eq!(scenario.mode_divergence.len(), 1);
        assert!(scenario.mode_divergence[0].differs);
        assert!(
            scenario.mode_divergence[0]
                .differing_fields
                .contains(&String::from("outcome"))
        );
        assert_eq!(scenario.traces[0].validator_stages[0].stage, "fingerprint");
        assert_eq!(
            scenario.root_cause.rationale,
            "failure_signature:hardened_signature"
        );
    }

    #[test]
    fn artifact_index_entries_join_via_decision_id() {
        let log_path = temp_path("artifact_join", "log.jsonl");
        let index_path = temp_path("artifact_join", "index.json");
        let strict = sample_entry(SampleEntrySpec {
            trace_id: "bd-26xb.4::demo::010",
            scenario_id: "demo",
            mode: "strict",
            outcome: Outcome::Fail,
            action: "Repair",
            healing_action: "ClampSize",
            decision_id: 77,
            artifact_ref: "artifacts/strict.log",
        });
        std::fs::write(
            &log_path,
            format!("{}\n", strict.to_jsonl().expect("jsonl")),
        )
        .expect("write log");

        let mut index = ArtifactIndex::new("demo", WORKBENCH_BEAD_ID);
        index.add_with_join_keys(
            "reports/root-cause.json",
            "report",
            "abc123",
            ArtifactJoinKeys {
                decision_ids: vec![77],
                ..ArtifactJoinKeys::default()
            },
        );
        std::fs::write(&index_path, index.to_json().expect("index json")).expect("write index");

        let report = build_report(&log_path, Some(&index_path), None, None).expect("report");
        let trace = &report.scenarios[0].traces[0];
        assert!(
            trace
                .artifact_links
                .iter()
                .any(|artifact| artifact.path == "reports/root-cause.json"
                    && artifact.join_match.contains(&String::from("decision_id")))
        );
    }

    #[test]
    fn plain_render_mentions_divergence_and_artifacts() {
        let log_path = temp_path("plain_render", "log.jsonl");
        let strict = sample_entry(SampleEntrySpec {
            trace_id: "bd-26xb.4::demo::021",
            scenario_id: "demo",
            mode: "strict",
            outcome: Outcome::Fail,
            action: "Repair",
            healing_action: "ClampSize",
            decision_id: 101,
            artifact_ref: "artifacts/strict.log",
        });
        let hardened = sample_entry(SampleEntrySpec {
            trace_id: "bd-26xb.4::demo::022",
            scenario_id: "demo",
            mode: "hardened",
            outcome: Outcome::Pass,
            action: "Allow",
            healing_action: "None",
            decision_id: 102,
            artifact_ref: "artifacts/hardened.log",
        });
        std::fs::write(
            &log_path,
            format!(
                "{}\n{}\n",
                strict.to_jsonl().expect("strict jsonl"),
                hardened.to_jsonl().expect("hardened jsonl")
            ),
        )
        .expect("write log");

        let report = build_report(&log_path, None, None, None).expect("report");
        let rendered = render_plain(&report);
        assert!(rendered.contains("mode divergence strict vs hardened: outcome"));
        assert!(rendered.contains("artifacts/strict.log"));
    }

    #[cfg(feature = "frankentui-ui")]
    #[test]
    fn ftui_render_mentions_title_and_scenario() {
        let log_path = temp_path("ftui_render", "log.jsonl");
        let strict = sample_entry(SampleEntrySpec {
            trace_id: "bd-26xb.4::demo::031",
            scenario_id: "demo",
            mode: "strict",
            outcome: Outcome::Fail,
            action: "Repair",
            healing_action: "ClampSize",
            decision_id: 301,
            artifact_ref: "artifacts/strict.log",
        });
        std::fs::write(
            &log_path,
            format!("{}\n", strict.to_jsonl().expect("strict jsonl")),
        )
        .expect("write log");

        let report = build_report(&log_path, None, None, None).expect("report");
        let rendered = render_ftui(&report, false, 120);
        assert!(rendered.contains("explainability workbench"));
        assert!(rendered.contains("demo"));
        assert!(rendered.contains("strict"));
    }
}
