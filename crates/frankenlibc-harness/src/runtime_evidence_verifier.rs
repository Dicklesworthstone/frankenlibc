//! Runtime evidence JSONL verifier for membrane decision replay gates.
//!
//! The verifier consumes `runtime_evidence.decision.v1` rows emitted by the
//! membrane evidence log, applies the membrane-owned row schema, then enforces
//! replay-specific invariants such as freshness, monotone timestamps, valid
//! decision transitions, repair evidence, and gate expectations.

use std::collections::BTreeSet;

use frankenlibc_membrane::runtime_math::evidence::{
    RuntimeEvidenceRowValidationError, validate_runtime_evidence_row_v1,
};
use serde::Serialize;
use serde_json::Value;

const REPORT_SCHEMA: &str = "runtime_evidence_verifier.v1";
const STATUS_PASS: &str = "pass";
const STATUS_FAIL: &str = "fail";

const DECISION_ALLOW: &str = "Allow";
const DECISION_FULL_VALIDATE: &str = "FullValidate";
const DECISION_REPAIR: &str = "Repair";
const DECISION_DENY: &str = "Deny";

const KNOWN_HEALING_ACTIONS: &[&str] = &[
    "ClampSize",
    "TruncateWithNull",
    "IgnoreDoubleFree",
    "IgnoreForeignFree",
    "ReallocAsMalloc",
    "ReturnSafeDefault",
    "UpgradeToSafeVariant",
    "None",
];

/// Gate-level expectation for one runtime evidence row family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeEvidenceExpectation {
    pub symbol: String,
    pub runtime_mode: String,
    pub decision_action: String,
    pub denied: bool,
}

impl RuntimeEvidenceExpectation {
    #[must_use]
    pub fn new(
        symbol: impl Into<String>,
        runtime_mode: impl Into<String>,
        decision_action: impl Into<String>,
        denied: bool,
    ) -> Self {
        Self {
            symbol: symbol.into(),
            runtime_mode: runtime_mode.into(),
            decision_action: decision_action.into(),
            denied,
        }
    }

    fn key(&self) -> String {
        expectation_key(&self.symbol, &self.runtime_mode)
    }
}

/// Runtime evidence verifier configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeEvidenceVerifierConfig {
    pub expected_source_commit: String,
    pub expectations: Vec<RuntimeEvidenceExpectation>,
    pub allow_unexpected_denials: bool,
}

impl RuntimeEvidenceVerifierConfig {
    #[must_use]
    pub fn new(expected_source_commit: impl Into<String>) -> Self {
        Self {
            expected_source_commit: expected_source_commit.into(),
            expectations: Vec::new(),
            allow_unexpected_denials: true,
        }
    }

    #[must_use]
    pub fn with_expectation(mut self, expectation: RuntimeEvidenceExpectation) -> Self {
        self.expectations.push(expectation);
        self
    }

    #[must_use]
    pub fn deny_unexpected_denials(mut self) -> Self {
        self.allow_unexpected_denials = false;
        self
    }
}

/// One verifier failure with a deterministic signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuntimeEvidenceFailure {
    pub line: usize,
    pub trace_id: Option<String>,
    pub failure_signature: String,
    pub message: String,
}

/// Structured verifier report for harness and checker output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuntimeEvidenceVerificationReport {
    pub schema: &'static str,
    pub status: &'static str,
    pub expected_source_commit: String,
    pub total_rows: usize,
    pub failure_count: usize,
    pub observed_expectations: Vec<String>,
    pub failures: Vec<RuntimeEvidenceFailure>,
}

impl RuntimeEvidenceVerificationReport {
    #[must_use]
    pub fn passed(&self) -> bool {
        self.failure_count == 0
    }

    #[must_use]
    pub fn has_failure_signature(&self, signature: &str) -> bool {
        self.failures
            .iter()
            .any(|failure| failure.failure_signature == signature)
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

/// Verify runtime evidence JSONL against schema, ordering, freshness, and expectations.
#[must_use]
pub fn verify_runtime_evidence_jsonl(
    jsonl: &str,
    config: &RuntimeEvidenceVerifierConfig,
) -> RuntimeEvidenceVerificationReport {
    let mut failures = Vec::new();
    let mut total_rows = 0usize;
    let mut last_timestamp_mono_ns = None;
    let mut observed_expectations = BTreeSet::new();

    for (zero_based_line, raw_line) in jsonl.lines().enumerate() {
        let line_no = zero_based_line + 1;
        if raw_line.trim().is_empty() {
            continue;
        }
        total_rows = total_rows.saturating_add(1);

        let row: Value = match serde_json::from_str(raw_line) {
            Ok(row) => row,
            Err(err) => {
                push_failure(
                    &mut failures,
                    line_no,
                    None,
                    "runtime_evidence_corrupt_jsonl",
                    format!("line {line_no} is not valid JSON: {err}"),
                );
                continue;
            }
        };
        let trace_id = string_field(&row, "trace_id").map(str::to_owned);

        if let Err(err) = validate_runtime_evidence_row_v1(&row) {
            let signature = schema_error_signature(err);
            push_failure(
                &mut failures,
                line_no,
                trace_id.clone(),
                signature,
                format!("schema validation failed: {err:?}"),
            );
            continue;
        }

        let source_commit = string_field(&row, "source_commit").unwrap_or_default();
        if !config.expected_source_commit.is_empty()
            && source_commit != config.expected_source_commit
        {
            push_failure(
                &mut failures,
                line_no,
                trace_id.clone(),
                "runtime_evidence_stale_source_commit",
                format!(
                    "source_commit {source_commit} does not match expected {}",
                    config.expected_source_commit
                ),
            );
        }

        match row.get("timestamp_mono_ns").and_then(Value::as_u64) {
            Some(timestamp) => {
                if last_timestamp_mono_ns.is_some_and(|last| timestamp < last) {
                    push_failure(
                        &mut failures,
                        line_no,
                        trace_id.clone(),
                        "runtime_evidence_out_of_order_timestamp",
                        "timestamp_mono_ns moved backward".to_string(),
                    );
                }
                last_timestamp_mono_ns = Some(timestamp);
            }
            None => push_failure(
                &mut failures,
                line_no,
                trace_id.clone(),
                "runtime_evidence_missing_timestamp_mono_ns",
                "timestamp_mono_ns is required for replay ordering".to_string(),
            ),
        }

        let runtime_mode = string_field(&row, "runtime_mode").unwrap_or_default();
        let symbol = string_field(&row, "symbol").unwrap_or_default();
        let action = string_field(&row, "decision_action").unwrap_or_default();
        let denied = row.get("denied").and_then(Value::as_bool).unwrap_or(false);
        let decision_path = string_field(&row, "decision_path").unwrap_or_default();
        let healing_action = row.get("healing_action");

        validate_decision_transition(
            &mut failures,
            DecisionTransitionRow {
                line: line_no,
                trace_id: trace_id.clone(),
                action,
                denied,
                decision_path,
                healing_action,
                allow_unexpected_denials: config.allow_unexpected_denials,
            },
        );

        let key = expectation_key(symbol, runtime_mode);
        for expectation in config
            .expectations
            .iter()
            .filter(|expectation| expectation.key() == key)
        {
            observed_expectations.insert(key.clone());
            if expectation.decision_action != action {
                push_failure(
                    &mut failures,
                    line_no,
                    trace_id.clone(),
                    "runtime_evidence_expectation_mismatch",
                    format!(
                        "{} {} expected decision {}, got {action}",
                        expectation.runtime_mode, expectation.symbol, expectation.decision_action
                    ),
                );
            }
            if expectation.denied != denied {
                let signature = if denied {
                    "runtime_evidence_unexpected_denial"
                } else {
                    "runtime_evidence_expectation_mismatch"
                };
                push_failure(
                    &mut failures,
                    line_no,
                    trace_id.clone(),
                    signature,
                    format!(
                        "{} {} expected denied={}, got {denied}",
                        expectation.runtime_mode, expectation.symbol, expectation.denied
                    ),
                );
            }
        }
    }

    for expectation in &config.expectations {
        let key = expectation.key();
        if !observed_expectations.contains(&key) {
            push_failure(
                &mut failures,
                0,
                None,
                "runtime_evidence_expectation_missing",
                format!(
                    "missing expected row for {} {}",
                    expectation.runtime_mode, expectation.symbol
                ),
            );
        }
    }

    let failure_count = failures.len();
    let status = if failure_count == 0 {
        STATUS_PASS
    } else {
        STATUS_FAIL
    };
    RuntimeEvidenceVerificationReport {
        schema: REPORT_SCHEMA,
        status,
        expected_source_commit: config.expected_source_commit.clone(),
        total_rows,
        failure_count,
        observed_expectations: observed_expectations.into_iter().collect(),
        failures,
    }
}

struct DecisionTransitionRow<'a> {
    line: usize,
    trace_id: Option<String>,
    action: &'a str,
    denied: bool,
    decision_path: &'a str,
    healing_action: Option<&'a Value>,
    allow_unexpected_denials: bool,
}

fn validate_decision_transition(
    failures: &mut Vec<RuntimeEvidenceFailure>,
    row: DecisionTransitionRow<'_>,
) {
    let Some(expected_terminal) = decision_path_terminal(row.action) else {
        push_failure(
            failures,
            row.line,
            row.trace_id,
            "runtime_evidence_impossible_transition",
            format!("decision_action {} is not known", row.action),
        );
        return;
    };

    let actual_terminal = row
        .decision_path
        .rsplit("->")
        .next()
        .unwrap_or_default()
        .replace('-', "_")
        .to_ascii_lowercase();
    if actual_terminal != expected_terminal {
        push_failure(
            failures,
            row.line,
            row.trace_id.clone(),
            "runtime_evidence_impossible_transition",
            format!(
                "decision_path terminal {actual_terminal} does not match {}",
                row.action
            ),
        );
    }

    match row.action {
        DECISION_REPAIR => {
            let action_name = row
                .healing_action
                .and_then(Value::as_str)
                .unwrap_or_default();
            if action_name.is_empty() || action_name == "None" {
                push_failure(
                    failures,
                    row.line,
                    row.trace_id.clone(),
                    "runtime_evidence_missing_healing_action",
                    "Repair decision must carry a non-empty healing_action".to_string(),
                );
            } else if !KNOWN_HEALING_ACTIONS.contains(&action_name) {
                push_failure(
                    failures,
                    row.line,
                    row.trace_id.clone(),
                    "runtime_evidence_unknown_healing_action",
                    format!("unknown healing_action {action_name}"),
                );
            }
            if row.denied {
                push_failure(
                    failures,
                    row.line,
                    row.trace_id.clone(),
                    "runtime_evidence_impossible_transition",
                    "Repair decision cannot also be denied=true".to_string(),
                );
            }
        }
        DECISION_DENY => {
            if !row.denied || !row.allow_unexpected_denials {
                push_failure(
                    failures,
                    row.line,
                    row.trace_id.clone(),
                    "runtime_evidence_unexpected_denial",
                    "Deny decision was not allowed by gate expectations".to_string(),
                );
            }
        }
        _ => {
            if row.denied {
                push_failure(
                    failures,
                    row.line,
                    row.trace_id.clone(),
                    "runtime_evidence_unexpected_denial",
                    format!("{} decision cannot carry denied=true", row.action),
                );
            }
            if row.healing_action.is_some_and(|value| !value.is_null()) {
                push_failure(
                    failures,
                    row.line,
                    row.trace_id,
                    "runtime_evidence_impossible_transition",
                    format!("{} decision cannot carry healing_action", row.action),
                );
            }
        }
    }
}

fn decision_path_terminal(action: &str) -> Option<&'static str> {
    match action {
        DECISION_ALLOW => Some("allow"),
        DECISION_FULL_VALIDATE => Some("full_validate"),
        DECISION_REPAIR => Some("repair"),
        DECISION_DENY => Some("deny"),
        _ => None,
    }
}

fn schema_error_signature(err: RuntimeEvidenceRowValidationError) -> &'static str {
    match err {
        RuntimeEvidenceRowValidationError::UnexpectedValue("mode" | "runtime_mode") => {
            "runtime_evidence_invalid_mode"
        }
        RuntimeEvidenceRowValidationError::UnexpectedValue("validation_profile") => {
            "runtime_evidence_invalid_profile"
        }
        RuntimeEvidenceRowValidationError::WrongType("latency_ns") => {
            "runtime_evidence_invalid_latency"
        }
        RuntimeEvidenceRowValidationError::MissingRequiredField("healing_action") => {
            "runtime_evidence_missing_healing_action"
        }
        RuntimeEvidenceRowValidationError::MissingRequiredField("source_commit") => {
            "runtime_evidence_stale_source_commit"
        }
        _ => "runtime_evidence_schema_invalid",
    }
}

fn expectation_key(symbol: &str, runtime_mode: &str) -> String {
    format!("{runtime_mode}::{symbol}")
}

fn string_field<'a>(row: &'a Value, field: &str) -> Option<&'a str> {
    row.get(field).and_then(Value::as_str)
}

fn push_failure(
    failures: &mut Vec<RuntimeEvidenceFailure>,
    line: usize,
    trace_id: Option<String>,
    signature: &'static str,
    message: String,
) {
    failures.push(RuntimeEvidenceFailure {
        line,
        trace_id,
        failure_signature: signature.to_string(),
        message,
    });
}
