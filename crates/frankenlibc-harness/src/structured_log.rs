//! Structured logging contract for frankenlibc test/e2e/perf workflows.
//!
//! Bead: `bd-144`
//!
//! Provides:
//! - [`LogEntry`]: canonical JSONL log record with required + optional fields.
//! - [`ArtifactIndex`]: links logs to verification artifacts with SHA-256 integrity.
//! - [`LogEmitter`]: writes JSONL lines to a file or stdout.
//! - [`validate_log_line`]: validates a single JSONL line against the schema.
//! - [`validate_log_file`]: validates an entire JSONL file.

use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::Path;

// ---------------------------------------------------------------------------
// Log entry
// ---------------------------------------------------------------------------

/// Severity level for log entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Fatal,
}

/// TSM pipeline decision (for membrane events).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    Allow,
    FullValidate,
    Repair,
    Deny,
}

/// Test/verification outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Pass,
    Fail,
    Skip,
    Error,
    Timeout,
}

/// Evidence stream / workflow domain.
///
/// This helps unify log aggregation across unit, conformance, e2e, perf, and release workflows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StreamKind {
    Unit,
    Conformance,
    E2e,
    Perf,
    Release,
}

/// Membrane validation profile (depth) selected by runtime policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidationProfile {
    Fast,
    Full,
}

/// Canonical structured log entry.
///
/// Required fields: `timestamp`, `trace_id`, `level`, `event`.
/// Optional fields provide context for test/e2e/perf workflows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    // Required
    pub timestamp: String,
    pub trace_id: String,
    pub level: LogLevel,
    pub event: String,

    // Optional
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bead_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<StreamKind>,
    /// Pipeline step / gate name (e.g. `ci`, `e2e_suite`, `perf_gate`, `closure_gate`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gate: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_family: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    /// Optional span id for multi-component traces under one `trace_id`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub span_id: Option<String>,
    /// Optional parent span id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_span_id: Option<String>,
    /// Validation profile selected by runtime policy (when applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<ValidationProfile>,
    /// Healing action applied (hardened mode) when applicable. Keep this as a string so new
    /// actions do not require schema churn; stable families should still use a bounded vocab.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub healing_action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<Decision>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<Outcome>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errno: Option<i32>,
    /// Exit code for external processes/scripts when relevant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ns: Option<u64>,
    /// Wall-clock duration for a higher-level gate step (milliseconds).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_refs: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl LogEntry {
    /// Create a new log entry with required fields only.
    #[must_use]
    pub fn new(trace_id: impl Into<String>, level: LogLevel, event: impl Into<String>) -> Self {
        Self {
            timestamp: now_utc(),
            trace_id: trace_id.into(),
            level,
            event: event.into(),
            bead_id: None,
            stream: None,
            gate: None,
            mode: None,
            api_family: None,
            symbol: None,
            span_id: None,
            parent_span_id: None,
            profile: None,
            healing_action: None,
            decision: None,
            outcome: None,
            errno: None,
            exit_code: None,
            latency_ns: None,
            duration_ms: None,
            artifact_refs: None,
            details: None,
        }
    }

    /// Set the bead ID.
    #[must_use]
    pub fn with_bead(mut self, bead_id: impl Into<String>) -> Self {
        self.bead_id = Some(bead_id.into());
        self
    }

    /// Set the evidence stream kind.
    #[must_use]
    pub fn with_stream(mut self, stream: StreamKind) -> Self {
        self.stream = Some(stream);
        self
    }

    /// Set the pipeline step / gate name.
    #[must_use]
    pub fn with_gate(mut self, gate: impl Into<String>) -> Self {
        self.gate = Some(gate.into());
        self
    }

    /// Set the runtime mode.
    #[must_use]
    pub fn with_mode(mut self, mode: impl Into<String>) -> Self {
        self.mode = Some(mode.into());
        self
    }

    /// Set the API family and symbol.
    #[must_use]
    pub fn with_api(mut self, family: impl Into<String>, symbol: impl Into<String>) -> Self {
        self.api_family = Some(family.into());
        self.symbol = Some(symbol.into());
        self
    }

    /// Set span identifiers (optional).
    #[must_use]
    pub fn with_span(mut self, span_id: impl Into<String>, parent_span_id: Option<String>) -> Self {
        self.span_id = Some(span_id.into());
        self.parent_span_id = parent_span_id;
        self
    }

    /// Set validation profile.
    #[must_use]
    pub fn with_profile(mut self, profile: ValidationProfile) -> Self {
        self.profile = Some(profile);
        self
    }

    /// Set healing action.
    #[must_use]
    pub fn with_healing_action(mut self, action: impl Into<String>) -> Self {
        self.healing_action = Some(action.into());
        self
    }

    /// Set the outcome.
    #[must_use]
    pub fn with_outcome(mut self, outcome: Outcome) -> Self {
        self.outcome = Some(outcome);
        self
    }

    /// Set the membrane decision.
    #[must_use]
    pub fn with_decision(mut self, decision: Decision) -> Self {
        self.decision = Some(decision);
        self
    }

    /// Set errno.
    #[must_use]
    pub fn with_errno(mut self, errno: i32) -> Self {
        self.errno = Some(errno);
        self
    }

    /// Set exit code.
    #[must_use]
    pub fn with_exit_code(mut self, exit_code: i32) -> Self {
        self.exit_code = Some(exit_code);
        self
    }

    /// Set latency in nanoseconds.
    #[must_use]
    pub fn with_latency_ns(mut self, ns: u64) -> Self {
        self.latency_ns = Some(ns);
        self
    }

    /// Set duration in milliseconds.
    #[must_use]
    pub fn with_duration_ms(mut self, ms: u64) -> Self {
        self.duration_ms = Some(ms);
        self
    }

    /// Add artifact references.
    #[must_use]
    pub fn with_artifacts(mut self, refs: Vec<String>) -> Self {
        self.artifact_refs = Some(refs);
        self
    }

    /// Set free-form details.
    #[must_use]
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }

    /// Serialize to a single JSONL line (no trailing newline).
    pub fn to_jsonl(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

// ---------------------------------------------------------------------------
// Artifact index
// ---------------------------------------------------------------------------

/// A single artifact entry in the index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactEntry {
    pub path: String,
    pub kind: String,
    pub sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Artifact index linking logs to verification artifacts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactIndex {
    pub index_version: u32,
    pub run_id: String,
    pub bead_id: String,
    pub generated_utc: String,
    pub artifacts: Vec<ArtifactEntry>,
}

impl ArtifactIndex {
    /// Create a new artifact index.
    #[must_use]
    pub fn new(run_id: impl Into<String>, bead_id: impl Into<String>) -> Self {
        Self {
            index_version: 1,
            run_id: run_id.into(),
            bead_id: bead_id.into(),
            generated_utc: now_utc(),
            artifacts: Vec::new(),
        }
    }

    /// Add an artifact entry.
    pub fn add(
        &mut self,
        path: impl Into<String>,
        kind: impl Into<String>,
        sha256: impl Into<String>,
    ) -> &mut Self {
        self.artifacts.push(ArtifactEntry {
            path: path.into(),
            kind: kind.into(),
            sha256: sha256.into(),
            size_bytes: None,
            description: None,
        });
        self
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

// ---------------------------------------------------------------------------
// Log emitter
// ---------------------------------------------------------------------------

/// Writes structured JSONL log entries to a file or stdout.
pub struct LogEmitter {
    writer: Box<dyn Write>,
    seq: u64,
    bead_id: String,
    run_id: String,
}

impl LogEmitter {
    /// Create an emitter that writes to a file.
    pub fn to_file(path: &Path, bead_id: &str, run_id: &str) -> std::io::Result<Self> {
        let file = std::fs::File::create(path)?;
        Ok(Self {
            writer: Box::new(std::io::BufWriter::new(file)),
            seq: 0,
            bead_id: bead_id.to_string(),
            run_id: run_id.to_string(),
        })
    }

    /// Create an emitter that writes to a Vec<u8> buffer (for testing).
    #[must_use]
    pub fn to_buffer(bead_id: &str, run_id: &str) -> Self {
        Self {
            writer: Box::new(Vec::new()),
            seq: 0,
            bead_id: bead_id.to_string(),
            run_id: run_id.to_string(),
        }
    }

    /// Generate the next trace ID.
    fn next_trace_id(&mut self) -> String {
        self.seq += 1;
        format!("{}::{}::{:03}", self.bead_id, self.run_id, self.seq)
    }

    /// Emit a log entry with auto-generated trace_id and bead_id.
    pub fn emit(&mut self, level: LogLevel, event: &str) -> std::io::Result<LogEntry> {
        let trace_id = self.next_trace_id();
        let entry = LogEntry::new(&trace_id, level, event).with_bead(&self.bead_id);
        let line = serde_json::to_string(&entry).map_err(std::io::Error::other)?;
        writeln!(self.writer, "{line}")?;
        Ok(entry)
    }

    /// Emit a fully-populated log entry.
    pub fn emit_entry(&mut self, mut entry: LogEntry) -> std::io::Result<()> {
        if entry.trace_id.is_empty() {
            entry.trace_id = self.next_trace_id();
        }
        if entry.bead_id.is_none() {
            entry.bead_id = Some(self.bead_id.clone());
        }
        let line = serde_json::to_string(&entry).map_err(std::io::Error::other)?;
        writeln!(self.writer, "{line}")
    }

    /// Flush the underlying writer.
    pub fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validation error for a log line.
#[derive(Debug)]
pub struct LogValidationError {
    pub line_number: usize,
    pub field: String,
    pub message: String,
}

impl std::fmt::Display for LogValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "line {}: field '{}': {}",
            self.line_number, self.field, self.message
        )
    }
}

/// Validate a single JSONL line against the schema.
///
/// Returns `Ok(())` if valid, or a list of validation errors.
pub fn validate_log_line(
    line: &str,
    line_number: usize,
) -> Result<LogEntry, Vec<LogValidationError>> {
    let mut errors = Vec::new();

    let value: serde_json::Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => {
            errors.push(LogValidationError {
                line_number,
                field: "<json>".to_string(),
                message: format!("invalid JSON: {e}"),
            });
            return Err(errors);
        }
    };

    let obj = match value.as_object() {
        Some(o) => o,
        None => {
            errors.push(LogValidationError {
                line_number,
                field: "<root>".to_string(),
                message: "expected JSON object".to_string(),
            });
            return Err(errors);
        }
    };

    // Required fields
    for field in ["timestamp", "trace_id", "level", "event"] {
        if !obj.contains_key(field) {
            errors.push(LogValidationError {
                line_number,
                field: field.to_string(),
                message: "required field missing".to_string(),
            });
        }
    }

    // Validate level enum
    if let Some(level) = obj.get("level").and_then(|v| v.as_str())
        && !["trace", "debug", "info", "warn", "error", "fatal"].contains(&level)
    {
        errors.push(LogValidationError {
            line_number,
            field: "level".to_string(),
            message: format!("invalid level: '{level}'"),
        });
    }

    // Validate mode enum if present
    if let Some(mode) = obj.get("mode").and_then(|v| v.as_str())
        && !["strict", "hardened"].contains(&mode)
    {
        errors.push(LogValidationError {
            line_number,
            field: "mode".to_string(),
            message: format!("invalid mode: '{mode}'"),
        });
    }

    // Validate outcome enum if present
    if let Some(outcome) = obj.get("outcome").and_then(|v| v.as_str())
        && !["pass", "fail", "skip", "error", "timeout"].contains(&outcome)
    {
        errors.push(LogValidationError {
            line_number,
            field: "outcome".to_string(),
            message: format!("invalid outcome: '{outcome}'"),
        });
    }

    // Validate decision enum if present
    if let Some(decision) = obj.get("decision").and_then(|v| v.as_str())
        && !["Allow", "FullValidate", "Repair", "Deny"].contains(&decision)
    {
        errors.push(LogValidationError {
            line_number,
            field: "decision".to_string(),
            message: format!("invalid decision: '{decision}'"),
        });
    }

    // Validate stream enum if present
    if let Some(stream) = obj.get("stream").and_then(|v| v.as_str())
        && !["unit", "conformance", "e2e", "perf", "release"].contains(&stream)
    {
        errors.push(LogValidationError {
            line_number,
            field: "stream".to_string(),
            message: format!("invalid stream: '{stream}'"),
        });
    }

    // Validate profile enum if present
    if let Some(profile) = obj.get("profile").and_then(|v| v.as_str())
        && !["Fast", "Full"].contains(&profile)
    {
        errors.push(LogValidationError {
            line_number,
            field: "profile".to_string(),
            message: format!("invalid profile: '{profile}'"),
        });
    }

    // Validate trace_id format: should contain ::
    if let Some(trace_id) = obj.get("trace_id").and_then(|v| v.as_str())
        && !trace_id.contains("::")
    {
        errors.push(LogValidationError {
            line_number,
            field: "trace_id".to_string(),
            message: format!(
                "trace_id should follow <bead_id>::<run_id>::<seq> format, got: '{trace_id}'"
            ),
        });
    }

    if !errors.is_empty() {
        return Err(errors);
    }

    // If validation passed, try full deserialization
    match serde_json::from_value::<LogEntry>(value) {
        Ok(entry) => Ok(entry),
        Err(e) => {
            errors.push(LogValidationError {
                line_number,
                field: "<deserialization>".to_string(),
                message: format!("failed to deserialize: {e}"),
            });
            Err(errors)
        }
    }
}

/// Validate an entire JSONL file.
///
/// Returns the total line count and any validation errors found.
pub fn validate_log_file(path: &Path) -> Result<(usize, Vec<LogValidationError>), std::io::Error> {
    let content = std::fs::read_to_string(path)?;
    let mut all_errors = Vec::new();
    let mut line_count = 0;

    for (i, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        line_count += 1;
        if let Err(errs) = validate_log_line(line, i + 1) {
            all_errors.extend(errs);
        }
    }

    Ok((line_count, all_errors))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn now_utc() -> String {
    // Use a simple format without external chrono dependency
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    let millis = duration.subsec_millis();
    // Approximate UTC formatting (good enough for structured logs)
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        1970 + secs / 31_557_600,            // approximate year
        (secs % 31_557_600) / 2_629_800 + 1, // approximate month
        (secs % 2_629_800) / 86400 + 1,      // approximate day
        (secs % 86400) / 3600,
        (secs % 3600) / 60,
        secs % 60,
        millis,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_entry_serializes_required_fields() {
        let entry = LogEntry::new("bd-test::run-1::001", LogLevel::Info, "test_start");
        let json = entry.to_jsonl().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed["timestamp"].is_string());
        assert_eq!(parsed["trace_id"], "bd-test::run-1::001");
        assert_eq!(parsed["level"], "info");
        assert_eq!(parsed["event"], "test_start");
        // Optional fields should be absent
        assert!(parsed.get("bead_id").is_none());
        assert!(parsed.get("stream").is_none());
        assert!(parsed.get("gate").is_none());
        assert!(parsed.get("mode").is_none());
    }

    #[test]
    fn log_entry_with_all_optional_fields() {
        let entry = LogEntry::new("bd-test::run-1::002", LogLevel::Error, "test_failure")
            .with_bead("bd-144")
            .with_stream(StreamKind::E2e)
            .with_gate("e2e_suite")
            .with_mode("hardened")
            .with_api("malloc", "realloc")
            .with_span("span-1", None)
            .with_profile(ValidationProfile::Full)
            .with_healing_action("ClampSize")
            .with_outcome(Outcome::Fail)
            .with_decision(Decision::Deny)
            .with_errno(12)
            .with_exit_code(1)
            .with_latency_ns(150)
            .with_duration_ms(2)
            .with_artifacts(vec!["path/to/backtrace".to_string()])
            .with_details(serde_json::json!({"expected": "non-null"}));

        let json = entry.to_jsonl().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["bead_id"], "bd-144");
        assert_eq!(parsed["stream"], "e2e");
        assert_eq!(parsed["gate"], "e2e_suite");
        assert_eq!(parsed["mode"], "hardened");
        assert_eq!(parsed["api_family"], "malloc");
        assert_eq!(parsed["symbol"], "realloc");
        assert_eq!(parsed["span_id"], "span-1");
        assert_eq!(parsed["profile"], "Full");
        assert_eq!(parsed["healing_action"], "ClampSize");
        assert_eq!(parsed["outcome"], "fail");
        assert_eq!(parsed["decision"], "Deny");
        assert_eq!(parsed["errno"], 12);
        assert_eq!(parsed["exit_code"], 1);
        assert_eq!(parsed["latency_ns"], 150);
        assert_eq!(parsed["duration_ms"], 2);
        assert!(parsed["artifact_refs"].is_array());
        assert!(parsed["details"].is_object());
    }

    #[test]
    fn validate_valid_line() {
        let entry = LogEntry::new("bd-test::run-1::001", LogLevel::Info, "test_start");
        let json = entry.to_jsonl().unwrap();
        let result = validate_log_line(&json, 1);
        assert!(result.is_ok(), "Valid line should pass: {result:?}");
    }

    #[test]
    fn validate_missing_required_field() {
        let json = r#"{"timestamp":"2026-01-01T00:00:00Z","level":"info","event":"test"}"#;
        let result = validate_log_line(json, 1);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(
            errors.iter().any(|e| e.field == "trace_id"),
            "Should report missing trace_id"
        );
    }

    #[test]
    fn validate_invalid_level() {
        let json = r#"{"timestamp":"2026-01-01T00:00:00Z","trace_id":"a::b::c","level":"critical","event":"test"}"#;
        let result = validate_log_line(json, 1);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.field == "level"));
    }

    #[test]
    fn validate_invalid_json() {
        let result = validate_log_line("not json at all", 1);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.field == "<json>"));
    }

    #[test]
    fn validate_bad_trace_id_format() {
        let json = r#"{"timestamp":"2026-01-01T00:00:00Z","trace_id":"no-separator","level":"info","event":"test"}"#;
        let result = validate_log_line(json, 1);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.field == "trace_id"));
    }

    #[test]
    fn artifact_index_serializes() {
        let mut idx = ArtifactIndex::new("run-001", "bd-144");
        idx.add("path/to/log.jsonl", "log", "abc123");
        let json = idx.to_json().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["index_version"], 1);
        assert_eq!(parsed["run_id"], "run-001");
        assert_eq!(parsed["bead_id"], "bd-144");
        assert_eq!(parsed["artifacts"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn emitter_generates_sequential_trace_ids() {
        let mut emitter = LogEmitter::to_buffer("bd-test", "run-42");
        let e1 = emitter.emit(LogLevel::Info, "start").unwrap();
        let e2 = emitter.emit(LogLevel::Info, "end").unwrap();
        assert!(e1.trace_id.ends_with("::001"));
        assert!(e2.trace_id.ends_with("::002"));
        assert!(e1.trace_id.starts_with("bd-test::run-42::"));
    }

    #[test]
    fn roundtrip_deserialization() {
        let entry = LogEntry::new("bd-test::run-1::001", LogLevel::Warn, "slow_op")
            .with_mode("strict")
            .with_latency_ns(25000);
        let json = entry.to_jsonl().unwrap();
        let restored: LogEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.trace_id, "bd-test::run-1::001");
        assert_eq!(restored.level, LogLevel::Warn);
        assert_eq!(restored.event, "slow_op");
        assert_eq!(restored.mode.as_deref(), Some("strict"));
        assert_eq!(restored.latency_ns, Some(25000));
    }
}
