//! Unified evidence ledger for the Transparent Safety Membrane.
//!
//! Collects all TSM evidence streams (metrics snapshots, healing actions,
//! validation decisions, conformance results) into a single append-only
//! ledger with cross-stream correlation via `trace_id`, `decision_id`,
//! `policy_id`, and `evidence_seqno`.
//!
//! Supports:
//! - **JSONL export** for offline replay and deterministic analysis
//! - **OTLP-shaped JSON export** for live dashboard integration
//! - **Privacy/redaction policy** to prevent PII leakage in trace data
//!
//! # Design invariants
//!
//! - Evidence records are append-only; the ledger never mutates past entries
//! - Sequence numbers are monotonically increasing per ledger instance
//! - Redaction is applied at emission time, not at ingestion
//! - The ledger is bounded (ring buffer) to prevent unbounded memory growth

use crate::config::SafetyLevel;
use crate::heal::HealingAction;
use crate::ids::{DecisionId, MEMBRANE_SCHEMA_VERSION, PolicyId, TraceId};
use crate::metrics::MetricsSnapshot;
use crate::util::NoPoisonMutex as Mutex;
use std::collections::VecDeque;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};

/// Maximum records retained in the ring buffer before oldest are evicted.
const DEFAULT_LEDGER_CAPACITY: usize = 4096;

/// Evidence record categories for cross-stream correlation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EvidenceCategory {
    /// Periodic metrics snapshot from the membrane.
    MetricsSnapshot,
    /// Healing action applied in hardened mode.
    HealingAction,
    /// Validation pipeline decision (allow/deny/repair).
    ValidationDecision,
    /// Conformance test result from the harness.
    ConformanceResult,
    /// Runtime math kernel decision card.
    RuntimeMathDecision,
}

impl EvidenceCategory {
    /// Canonical string label for JSONL emission.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MetricsSnapshot => "metrics_snapshot",
            Self::HealingAction => "healing_action",
            Self::ValidationDecision => "validation_decision",
            Self::ConformanceResult => "conformance_result",
            Self::RuntimeMathDecision => "runtime_math_decision",
        }
    }
}

/// Severity level for evidence records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EvidenceLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl EvidenceLevel {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
}

/// Privacy redaction policy for evidence emission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RedactionPolicy {
    /// No redaction — full evidence including pointer addresses.
    None,
    /// Redact raw pointer addresses (replace with deterministic hashes).
    RedactPointers,
    /// Redact all potentially identifying information.
    Full,
}

impl RedactionPolicy {
    /// Parse from environment or string.
    #[must_use]
    pub fn from_str_loose(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "none" | "off" | "disabled" | "0" => Self::None,
            "pointers" | "ptrs" | "addresses" => Self::RedactPointers,
            "full" | "all" | "strict" | "1" => Self::Full,
            _ => Self::RedactPointers, // safe default
        }
    }
}

/// A single evidence record in the unified ledger.
#[derive(Debug, Clone)]
pub struct EvidenceRecord {
    /// Monotonically increasing sequence number within this ledger.
    pub seqno: u64,
    /// Timestamp (seconds since UNIX epoch + nanosecond fraction).
    pub timestamp_secs: u64,
    pub timestamp_nanos: u32,
    /// Cross-stream correlation identifiers.
    pub trace_id: TraceId,
    pub decision_id: DecisionId,
    pub policy_id: PolicyId,
    /// Evidence category.
    pub category: EvidenceCategory,
    /// Severity level.
    pub level: EvidenceLevel,
    /// Runtime mode at time of recording.
    pub mode: SafetyLevel,
    /// API family (e.g., "allocator", "string_memory").
    pub api_family: String,
    /// Symbol name (e.g., "malloc", "memcpy").
    pub symbol: String,
    /// Decision path through the TSM pipeline.
    pub decision_path: String,
    /// Outcome label (e.g., "allow", "repair", "deny", "snapshot").
    pub outcome: String,
    /// Healing action applied (if any).
    pub healing_action: Option<HealingAction>,
    /// Errno set by the operation.
    pub errno_val: i32,
    /// Latency of the operation in nanoseconds.
    pub latency_ns: u64,
    /// Free-form details as a pre-serialized JSON string.
    pub details_json: String,
    /// References to related artifact files.
    pub artifact_refs: Vec<String>,
}

/// Grouped parameters for recording a validation decision.
pub struct ValidationEvidence {
    /// Cross-stream trace identifier.
    pub trace_id: TraceId,
    /// Decision identifier for this validation.
    pub decision_id: DecisionId,
    /// Policy that governed this decision.
    pub policy_id: PolicyId,
    /// API family (e.g., "allocator", "string_memory").
    pub api_family: String,
    /// Symbol name (e.g., "malloc", "memcpy").
    pub symbol: String,
    /// Decision path through the TSM pipeline.
    pub decision_path: String,
    /// Outcome label (e.g., "allow", "repair", "deny").
    pub outcome: String,
    /// Errno set by the operation.
    pub errno_val: i32,
    /// Latency of the operation in nanoseconds.
    pub latency_ns: u64,
    /// Free-form details as a pre-serialized JSON string.
    pub details_json: String,
}

/// Unified evidence ledger collecting all TSM evidence streams.
///
/// Thread-safe, bounded ring buffer with monotonic sequencing.
pub struct EvidenceLedger {
    /// Monotonic sequence counter for evidence records.
    seqno: AtomicU64,
    /// Bounded ring buffer of evidence records.
    records: Mutex<VecDeque<EvidenceRecord>>,
    /// Maximum capacity before oldest records are evicted.
    capacity: usize,
    /// Active redaction policy.
    redaction_policy: RedactionPolicy,
}

impl EvidenceLedger {
    /// Create a new ledger with default capacity and redaction from environment.
    #[must_use]
    pub fn new() -> Self {
        let redaction = std::env::var("FRANKENLIBC_EVIDENCE_REDACTION")
            .map(|v| RedactionPolicy::from_str_loose(&v))
            .unwrap_or(RedactionPolicy::RedactPointers);
        Self {
            seqno: AtomicU64::new(0),
            records: Mutex::new(VecDeque::with_capacity(DEFAULT_LEDGER_CAPACITY)),
            capacity: DEFAULT_LEDGER_CAPACITY,
            redaction_policy: redaction,
        }
    }

    /// Create a ledger with custom capacity and redaction policy.
    #[must_use]
    pub fn with_config(capacity: usize, redaction_policy: RedactionPolicy) -> Self {
        let cap = capacity.max(16); // minimum 16 records
        Self {
            seqno: AtomicU64::new(0),
            records: Mutex::new(VecDeque::with_capacity(cap)),
            capacity: cap,
            redaction_policy,
        }
    }

    /// Append an evidence record. Assigns a monotonic seqno and timestamp.
    pub fn append(&self, mut record: EvidenceRecord) {
        record.seqno = self.seqno.fetch_add(1, Ordering::Relaxed) + 1;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        record.timestamp_secs = now.as_secs();
        record.timestamp_nanos = now.subsec_nanos();

        let mut records = self.records.lock();
        while records.len() >= self.capacity {
            let _ = records.pop_front();
        }
        records.push_back(record);
    }

    /// Record a metrics snapshot as evidence.
    pub fn record_metrics_snapshot(
        &self,
        snapshot: &MetricsSnapshot,
        trace_id: TraceId,
        api_family: &str,
    ) {
        let details = format!(
            "{{\"validations\":{},\"tls_cache_hits\":{},\"tls_cache_misses\":{},\
\"bloom_hits\":{},\"bloom_misses\":{},\"arena_lookups\":{},\
\"fingerprint_passes\":{},\"fingerprint_failures\":{},\
\"canary_passes\":{},\"canary_failures\":{},\
\"heals\":{},\"double_frees_healed\":{},\"foreign_frees_healed\":{},\
\"size_clamps\":{},\"tls_cache_hit_rate\":{},\"bloom_hit_rate\":{}}}",
            snapshot.validations,
            snapshot.tls_cache_hits,
            snapshot.tls_cache_misses,
            snapshot.bloom_hits,
            snapshot.bloom_misses,
            snapshot.arena_lookups,
            snapshot.fingerprint_passes,
            snapshot.fingerprint_failures,
            snapshot.canary_passes,
            snapshot.canary_failures,
            snapshot.heals,
            snapshot.double_frees_healed,
            snapshot.foreign_frees_healed,
            snapshot.size_clamps,
            snapshot.tls_cache_hit_rate(),
            snapshot.bloom_hit_rate(),
        );
        self.append(EvidenceRecord {
            seqno: 0, // assigned by append
            timestamp_secs: 0,
            timestamp_nanos: 0,
            trace_id,
            decision_id: DecisionId::default(),
            policy_id: PolicyId::default(),
            category: EvidenceCategory::MetricsSnapshot,
            level: EvidenceLevel::Info,
            mode: crate::config::safety_level(),
            api_family: api_family.to_string(),
            symbol: String::new(),
            decision_path: "tsm::metrics::snapshot".to_string(),
            outcome: "snapshot".to_string(),
            healing_action: None,
            errno_val: 0,
            latency_ns: 0,
            details_json: details,
            artifact_refs: vec!["crates/frankenlibc-membrane/src/metrics.rs".to_string()],
        });
    }

    /// Record a healing action as evidence.
    pub fn record_healing(
        &self,
        action: &HealingAction,
        trace_id: TraceId,
        decision_id: DecisionId,
        api_family: &str,
        symbol: &str,
    ) {
        if !action.is_heal() {
            return;
        }
        let level = if is_escalated_healing(action) {
            EvidenceLevel::Warn
        } else {
            EvidenceLevel::Info
        };
        self.append(EvidenceRecord {
            seqno: 0,
            timestamp_secs: 0,
            timestamp_nanos: 0,
            trace_id,
            decision_id,
            policy_id: PolicyId::default(),
            category: EvidenceCategory::HealingAction,
            level,
            mode: crate::config::safety_level(),
            api_family: api_family.to_string(),
            symbol: symbol.to_string(),
            decision_path: "tsm::heal::record".to_string(),
            outcome: "repair".to_string(),
            healing_action: Some(*action),
            errno_val: 0,
            latency_ns: 0,
            details_json: healing_action_to_json(action),
            artifact_refs: vec![],
        });
    }

    /// Record a validation decision as evidence.
    pub fn record_validation(&self, evidence: ValidationEvidence) {
        let level = if evidence.outcome == "deny" {
            EvidenceLevel::Warn
        } else {
            EvidenceLevel::Info
        };
        self.append(EvidenceRecord {
            seqno: 0,
            timestamp_secs: 0,
            timestamp_nanos: 0,
            trace_id: evidence.trace_id,
            decision_id: evidence.decision_id,
            policy_id: evidence.policy_id,
            category: EvidenceCategory::ValidationDecision,
            level,
            mode: crate::config::safety_level(),
            api_family: evidence.api_family,
            symbol: evidence.symbol,
            decision_path: evidence.decision_path,
            outcome: evidence.outcome,
            healing_action: None,
            errno_val: evidence.errno_val,
            latency_ns: evidence.latency_ns,
            details_json: evidence.details_json,
            artifact_refs: vec![],
        });
    }

    /// Total number of records appended (including evicted ones).
    #[must_use]
    pub fn total_appended(&self) -> u64 {
        self.seqno.load(Ordering::Relaxed)
    }

    /// Number of records currently retained in the ring buffer.
    #[must_use]
    pub fn retained_count(&self) -> usize {
        self.records.lock().len()
    }

    /// Export all retained records as JSONL with redaction applied.
    #[must_use]
    pub fn export_jsonl(&self) -> String {
        let records = self.records.lock();
        let mut out = String::with_capacity(records.len() * 512);
        for record in records.iter() {
            let line = self.record_to_jsonl(record);
            out.push_str(&line);
            out.push('\n');
        }
        out
    }

    /// Export records matching a specific category as JSONL.
    #[must_use]
    pub fn export_jsonl_filtered(&self, category: EvidenceCategory) -> String {
        let records = self.records.lock();
        let mut out = String::new();
        for record in records.iter() {
            if record.category == category {
                let line = self.record_to_jsonl(record);
                out.push_str(&line);
                out.push('\n');
            }
        }
        out
    }

    /// Clear all retained records (does not reset sequence counter).
    pub fn clear(&self) {
        self.records.lock().clear();
    }

    /// Drain all records from the ledger, returning them as a Vec.
    pub fn drain(&self) -> Vec<EvidenceRecord> {
        let mut records = self.records.lock();
        records.drain(..).collect()
    }

    /// Build a cross-stream correlation index of all retained records.
    ///
    /// Returns a mapping of trace_id -> list of (seqno, category) pairs
    /// for records that share the same trace_id.
    #[must_use]
    pub fn correlation_index(&self) -> Vec<(String, Vec<(u64, EvidenceCategory)>)> {
        let records = self.records.lock();
        let mut index: crate::util::ArtifactHashMap<String, Vec<(u64, EvidenceCategory)>> =
            crate::util::artifact_hash_map();
        for record in records.iter() {
            if !record.trace_id.is_empty() {
                index
                    .entry(record.trace_id.as_str().to_string())
                    .or_default()
                    .push((record.seqno, record.category));
            }
        }
        let mut result: Vec<_> = index.into_iter().collect();
        result.sort_by(|a, b| a.0.cmp(&b.0));
        result
    }

    /// Export retained records as deterministic OTLP-shaped JSON log records.
    ///
    /// The export intentionally stays dependency-light and serializes to the
    /// OpenTelemetry Logs JSON shape expected by dashboards: resource logs,
    /// scope logs, and one log record per retained evidence entry.
    #[must_use]
    pub fn otlp_export(&self) -> OtlpExport {
        let records = self.records.lock();
        let mut category_counts = [0u64; 5];
        let mut level_counts = [0u64; 5];
        let mut log_records = Vec::with_capacity(records.len());
        for record in records.iter() {
            increment_count(&mut category_counts, category_index(record.category));
            increment_count(&mut level_counts, level_index(record.level));
            log_records.push(self.record_to_otlp_log(record));
        }
        OtlpExport {
            total_records: u64::try_from(records.len()).unwrap_or(u64::MAX),
            total_appended: self.seqno.load(Ordering::Relaxed),
            category_counts,
            level_counts,
            redaction_policy: self.redaction_policy,
            log_records,
        }
    }

    fn record_to_jsonl(&self, record: &EvidenceRecord) -> String {
        let mut out = String::with_capacity(512);
        let timestamp = format!("{}.{:09}Z", record.timestamp_secs, record.timestamp_nanos);
        let mode_str = match record.mode {
            SafetyLevel::Strict => "strict",
            SafetyLevel::Hardened => "hardened",
            SafetyLevel::Off => "off",
        };
        let trace_id_str = self.redact_trace_id(record.trace_id.as_str());
        let healing_json = match &record.healing_action {
            Some(action) => format!("\"{}\"", healing_action_name(action)),
            None => "null".to_string(),
        };
        let symbol_str = self.redact_symbol(&record.symbol);
        let api_family_str = sanitize_json_string(&record.api_family);
        let decision_path_str = sanitize_json_string(&record.decision_path);
        let outcome_str = sanitize_json_string(&record.outcome);

        let _ = write!(
            &mut out,
            "{{\"timestamp\":\"{timestamp}\",\
\"evidence_seqno\":{},\
\"trace_id\":\"{trace_id_str}\",\
\"decision_id\":{},\
\"policy_id\":{},\
\"schema_version\":\"{}\",\
\"category\":\"{}\",\
\"level\":\"{}\",\
\"mode\":\"{mode_str}\",\
\"api_family\":\"{api_family_str}\",\
\"symbol\":\"{symbol_str}\",\
\"decision_path\":\"{decision_path_str}\",\
\"outcome\":\"{outcome_str}\",\
\"healing_action\":{healing_json},\
\"errno\":{},\
\"latency_ns\":{},\
\"details\":{},\
\"artifact_refs\":{},\
\"redaction_policy\":\"{}\"}}",
            record.seqno,
            record.decision_id.as_u64(),
            record.policy_id.as_u32(),
            MEMBRANE_SCHEMA_VERSION,
            record.category.as_str(),
            record.level.as_str(),
            record.errno_val,
            record.latency_ns,
            if record.details_json.is_empty() {
                "null"
            } else {
                &record.details_json
            },
            artifact_refs_json(&record.artifact_refs),
            redaction_policy_str(self.redaction_policy),
        );
        out
    }

    fn record_to_otlp_log(&self, record: &EvidenceRecord) -> serde_json::Value {
        let mode_str = match record.mode {
            SafetyLevel::Strict => "strict",
            SafetyLevel::Hardened => "hardened",
            SafetyLevel::Off => "off",
        };
        let trace_id_str = self.redact_trace_id(record.trace_id.as_str());
        let symbol_str = self.redact_symbol(&record.symbol);
        let healing_value = record
            .healing_action
            .as_ref()
            .map_or(serde_json::Value::Null, |action| {
                serde_json::Value::String(healing_action_name(action).to_string())
            });
        let details_value = if record.details_json.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_str(&record.details_json)
                .unwrap_or_else(|_| serde_json::Value::String(record.details_json.clone()))
        };
        let time_unix_nano =
            (record.timestamp_secs as u128 * 1_000_000_000) + record.timestamp_nanos as u128;

        serde_json::json!({
            "timeUnixNano": time_unix_nano.to_string(),
            "observedTimeUnixNano": time_unix_nano.to_string(),
            "severityNumber": otlp_severity_number(record.level),
            "severityText": otlp_severity_text(record.level),
            "body": {
                "stringValue": &record.outcome,
            },
            "attributes": [
                otlp_string_attr("frankenlibc.trace_id", trace_id_str),
                otlp_int_attr("frankenlibc.evidence_seqno", record.seqno),
                otlp_int_attr("frankenlibc.decision_id", record.decision_id.as_u64()),
                otlp_int_attr("frankenlibc.policy_id", record.policy_id.as_u32()),
                otlp_string_attr("frankenlibc.schema_version", MEMBRANE_SCHEMA_VERSION.to_string()),
                otlp_string_attr("frankenlibc.category", record.category.as_str()),
                otlp_string_attr("frankenlibc.level", record.level.as_str()),
                otlp_string_attr("frankenlibc.mode", mode_str),
                otlp_string_attr("frankenlibc.api_family", &record.api_family),
                otlp_string_attr("frankenlibc.symbol", symbol_str),
                otlp_string_attr("frankenlibc.decision_path", &record.decision_path),
                otlp_string_attr("frankenlibc.outcome", &record.outcome),
                otlp_json_attr("frankenlibc.healing_action", healing_value),
                otlp_int_attr("frankenlibc.errno", record.errno_val),
                otlp_int_attr("frankenlibc.latency_ns", record.latency_ns),
                otlp_json_attr("frankenlibc.details", details_value),
                otlp_json_attr("frankenlibc.artifact_refs", serde_json::json!(&record.artifact_refs)),
                otlp_string_attr("frankenlibc.redaction_policy", redaction_policy_str(self.redaction_policy)),
            ],
        })
    }

    fn redact_trace_id(&self, trace_id: &str) -> String {
        match self.redaction_policy {
            RedactionPolicy::None => sanitize_json_string(trace_id),
            RedactionPolicy::RedactPointers | RedactionPolicy::Full => {
                // Redact hex pointer addresses in trace IDs (patterns like 0x7fff...)
                redact_hex_addresses(trace_id)
            }
        }
    }

    fn redact_symbol(&self, symbol: &str) -> String {
        match self.redaction_policy {
            RedactionPolicy::None | RedactionPolicy::RedactPointers => sanitize_json_string(symbol),
            RedactionPolicy::Full => {
                // In full redaction, hash the symbol name
                if symbol.is_empty() {
                    String::new()
                } else {
                    format!("redacted_{:016x}", simple_hash(symbol.as_bytes()))
                }
            }
        }
    }
}

impl Default for EvidenceLedger {
    fn default() -> Self {
        Self::new()
    }
}

/// Deterministic OTLP-shaped export of retained evidence records.
#[derive(Debug, Clone)]
pub struct OtlpExport {
    /// Records currently in the ring buffer.
    pub total_records: u64,
    /// Total records ever appended (including evicted).
    pub total_appended: u64,
    /// Counts per category: [MetricsSnapshot, HealingAction, ValidationDecision,
    /// ConformanceResult, RuntimeMathDecision].
    pub category_counts: [u64; 5],
    /// Counts per level: [Trace, Debug, Info, Warn, Error].
    pub level_counts: [u64; 5],
    /// Active redaction policy.
    pub redaction_policy: RedactionPolicy,
    /// OTLP log records in the same order as the retained ring buffer.
    log_records: Vec<serde_json::Value>,
}

impl OtlpExport {
    /// Number of OTLP log records emitted by this export.
    #[must_use]
    pub fn log_record_count(&self) -> usize {
        self.log_records.len()
    }

    /// Serialize the export as an OTLP-shaped JSON string.
    #[must_use]
    pub fn to_json(&self) -> String {
        let [
            metrics_snapshot_count,
            healing_action_count,
            validation_decision_count,
            conformance_result_count,
            runtime_math_decision_count,
        ] = self.category_counts;
        let [
            trace_count,
            debug_count,
            info_count,
            warn_count,
            error_count,
        ] = self.level_counts;
        let export = serde_json::json!({
            "otlp_schema": "logs/v1",
            "total_records": self.total_records,
            "total_appended": self.total_appended,
            "record_count": self.log_records.len(),
            "category_counts": {
                "metrics_snapshot": metrics_snapshot_count,
                "healing_action": healing_action_count,
                "validation_decision": validation_decision_count,
                "conformance_result": conformance_result_count,
                "runtime_math_decision": runtime_math_decision_count,
            },
            "level_counts": {
                "trace": trace_count,
                "debug": debug_count,
                "info": info_count,
                "warn": warn_count,
                "error": error_count,
            },
            "redaction_policy": redaction_policy_str(self.redaction_policy),
            "resourceLogs": [
                {
                    "resource": {
                        "attributes": [
                            otlp_string_attr("service.name", "frankenlibc"),
                            otlp_string_attr("telemetry.sdk.name", "frankenlibc-membrane"),
                            otlp_string_attr(
                                "frankenlibc.schema_version",
                                MEMBRANE_SCHEMA_VERSION.to_string(),
                            ),
                            otlp_string_attr(
                                "frankenlibc.redaction_policy",
                                redaction_policy_str(self.redaction_policy),
                            ),
                        ],
                    },
                    "scopeLogs": [
                        {
                            "scope": {
                                "name": "frankenlibc.evidence_ledger",
                                "version": MEMBRANE_SCHEMA_VERSION.to_string(),
                            },
                            "logRecords": self.log_records.clone(),
                        },
                    ],
                },
            ],
        });
        serde_json::to_string(&export).unwrap_or_else(|_| {
            "{\"otlp_schema\":\"logs/v1\",\"serialization_error\":true}".to_string()
        })
    }
}

/// Global evidence ledger singleton.
///
/// Uses a fixed default (RedactPointers) instead of reading
/// `FRANKENLIBC_EVIDENCE_REDACTION` from the environment. This avoids
/// a reentrancy hazard: under LD_PRELOAD, `std::env::var()` can call
/// our exported `strlen`, which could trigger a healing action, which
/// would call `global_evidence_ledger()` while the LazyLock is still
/// initializing — causing a deadlock. This is the same class of bug
/// that `config.rs` guards against with its atomic state machine.
///
/// Users who need custom redaction should construct their own ledger
/// via `EvidenceLedger::new()` or `EvidenceLedger::with_config()`.
static GLOBAL_LEDGER: std::sync::LazyLock<EvidenceLedger> = std::sync::LazyLock::new(|| {
    EvidenceLedger::with_config(DEFAULT_LEDGER_CAPACITY, RedactionPolicy::RedactPointers)
});

/// Access the global evidence ledger singleton.
#[must_use]
pub fn global_evidence_ledger() -> &'static EvidenceLedger {
    &GLOBAL_LEDGER
}

// ─── helpers ────────────────────────────────────────────────────────────

fn is_escalated_healing(action: &HealingAction) -> bool {
    matches!(
        action,
        HealingAction::ReturnSafeDefault | HealingAction::UpgradeToSafeVariant
    )
}

fn healing_action_name(action: &HealingAction) -> &'static str {
    match action {
        HealingAction::ClampSize { .. } => "ClampSize",
        HealingAction::TruncateWithNull { .. } => "TruncateWithNull",
        HealingAction::IgnoreDoubleFree => "IgnoreDoubleFree",
        HealingAction::IgnoreForeignFree => "IgnoreForeignFree",
        HealingAction::ReallocAsMalloc { .. } => "ReallocAsMalloc",
        HealingAction::ReturnSafeDefault => "ReturnSafeDefault",
        HealingAction::UpgradeToSafeVariant => "UpgradeToSafeVariant",
        HealingAction::None => "None",
    }
}

fn healing_action_to_json(action: &HealingAction) -> String {
    match action {
        HealingAction::ClampSize { requested, clamped } => {
            format!("{{\"action\":\"ClampSize\",\"requested\":{requested},\"clamped\":{clamped}}}")
        }
        HealingAction::TruncateWithNull {
            requested,
            truncated,
        } => {
            format!(
                "{{\"action\":\"TruncateWithNull\",\"requested\":{requested},\"truncated\":{truncated}}}"
            )
        }
        HealingAction::ReallocAsMalloc { size } => {
            format!("{{\"action\":\"ReallocAsMalloc\",\"size\":{size}}}")
        }
        HealingAction::IgnoreDoubleFree => "{\"action\":\"IgnoreDoubleFree\"}".to_string(),
        HealingAction::IgnoreForeignFree => "{\"action\":\"IgnoreForeignFree\"}".to_string(),
        HealingAction::ReturnSafeDefault => "{\"action\":\"ReturnSafeDefault\"}".to_string(),
        HealingAction::UpgradeToSafeVariant => "{\"action\":\"UpgradeToSafeVariant\"}".to_string(),
        HealingAction::None => "{\"action\":\"None\"}".to_string(),
    }
}

fn category_index(category: EvidenceCategory) -> usize {
    match category {
        EvidenceCategory::MetricsSnapshot => 0,
        EvidenceCategory::HealingAction => 1,
        EvidenceCategory::ValidationDecision => 2,
        EvidenceCategory::ConformanceResult => 3,
        EvidenceCategory::RuntimeMathDecision => 4,
    }
}

fn level_index(level: EvidenceLevel) -> usize {
    match level {
        EvidenceLevel::Trace => 0,
        EvidenceLevel::Debug => 1,
        EvidenceLevel::Info => 2,
        EvidenceLevel::Warn => 3,
        EvidenceLevel::Error => 4,
    }
}

fn increment_count(counts: &mut [u64; 5], index: usize) {
    if let Some(count) = counts.get_mut(index) {
        *count = count.saturating_add(1);
    }
}

fn otlp_severity_text(level: EvidenceLevel) -> &'static str {
    match level {
        EvidenceLevel::Trace => "TRACE",
        EvidenceLevel::Debug => "DEBUG",
        EvidenceLevel::Info => "INFO",
        EvidenceLevel::Warn => "WARN",
        EvidenceLevel::Error => "ERROR",
    }
}

fn otlp_severity_number(level: EvidenceLevel) -> u8 {
    match level {
        EvidenceLevel::Trace => 1,
        EvidenceLevel::Debug => 5,
        EvidenceLevel::Info => 9,
        EvidenceLevel::Warn => 13,
        EvidenceLevel::Error => 17,
    }
}

fn otlp_string_attr(key: &str, value: impl AsRef<str>) -> serde_json::Value {
    serde_json::json!({
        "key": key,
        "value": {
            "stringValue": value.as_ref(),
        },
    })
}

fn otlp_int_attr(key: &str, value: impl ToString) -> serde_json::Value {
    serde_json::json!({
        "key": key,
        "value": {
            "intValue": value.to_string(),
        },
    })
}

fn otlp_json_attr(key: &str, value: serde_json::Value) -> serde_json::Value {
    let string_value = serde_json::to_string(&value).unwrap_or_else(|_| "null".to_string());
    serde_json::json!({
        "key": key,
        "value": {
            "stringValue": string_value,
        },
    })
}

fn sanitize_json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

fn artifact_refs_json(refs: &[String]) -> String {
    if refs.is_empty() {
        return "[]".to_string();
    }
    let mut out = String::from("[");
    for (i, r) in refs.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('"');
        out.push_str(&sanitize_json_string(r));
        out.push('"');
    }
    out.push(']');
    out
}

fn redaction_policy_str(policy: RedactionPolicy) -> &'static str {
    match policy {
        RedactionPolicy::None => "none",
        RedactionPolicy::RedactPointers => "redact_pointers",
        RedactionPolicy::Full => "full",
    }
}

/// Replace hex address patterns (0x followed by 8+ hex digits) with [REDACTED].
fn redact_hex_addresses(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.char_indices().peekable();
    while let Some((i, ch)) = chars.next() {
        if ch == '0' {
            // Check if next char is 'x' forming a "0x" prefix.
            if let Some(&(_, 'x')) = chars.peek() {
                chars.next(); // consume the 'x'
                let hex_start = chars.peek().map_or(s.len(), |&(idx, _)| idx);
                let mut hex_end = hex_start;
                while let Some(&(idx, hch)) = chars.peek() {
                    if hch.is_ascii_hexdigit() {
                        hex_end = idx + hch.len_utf8();
                        chars.next();
                    } else {
                        break;
                    }
                }
                let hex_len = hex_end - hex_start;
                if hex_len >= 8 {
                    result.push_str("[REDACTED]");
                } else {
                    // Short hex — not an address, keep as-is
                    result.push_str(&s[i..hex_end]);
                }
                continue;
            }
        }
        result.push(ch);
    }
    result
}

/// Simple non-cryptographic hash for redaction (FNV-1a).
fn simple_hash(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_ledger() -> EvidenceLedger {
        EvidenceLedger::with_config(64, RedactionPolicy::None)
    }

    fn make_record(category: EvidenceCategory, trace_id: &str) -> EvidenceRecord {
        EvidenceRecord {
            seqno: 0,
            timestamp_secs: 0,
            timestamp_nanos: 0,
            trace_id: TraceId::new(trace_id.to_string()),
            decision_id: DecisionId::from_raw(42),
            policy_id: PolicyId::from_raw(7),
            category,
            level: EvidenceLevel::Info,
            mode: SafetyLevel::Strict,
            api_family: "allocator".to_string(),
            symbol: "malloc".to_string(),
            decision_path: "tsm::validate::full".to_string(),
            outcome: "allow".to_string(),
            healing_action: None,
            errno_val: 0,
            latency_ns: 150,
            details_json: "{\"size\":1024}".to_string(),
            artifact_refs: vec![],
        }
    }

    fn find_otlp_string_attr<'a>(attrs: &'a [serde_json::Value], key: &str) -> Option<&'a str> {
        attrs
            .iter()
            .find(|attr| attr["key"] == key)
            .and_then(|attr| attr["value"]["stringValue"].as_str())
    }

    fn workspace_root() -> std::path::PathBuf {
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        manifest
            .parent()
            .and_then(std::path::Path::parent)
            .expect("membrane crate should live under workspace/crates")
            .to_path_buf()
    }

    fn evidence_ledger_contract_path(root: &std::path::Path) -> std::path::PathBuf {
        root.join("tests/conformance/evidence_ledger_contract.v1.json")
    }

    fn load_json(path: &std::path::Path) -> serde_json::Value {
        serde_json::from_str(&std::fs::read_to_string(path).expect("JSON file should be readable"))
            .expect("JSON file should parse")
    }

    fn write_json(path: &std::path::Path, value: &serde_json::Value) {
        let content = serde_json::to_string_pretty(value).expect("JSON should serialize");
        std::fs::write(path, format!("{content}\n")).expect("JSON fixture should be writable");
    }

    fn unique_contract_dir(root: &std::path::Path, label: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock should be after Unix epoch")
            .as_nanos();
        let dir = root
            .join("target/conformance/evidence-ledger-contract")
            .join(format!("{label}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("test output dir should be created");
        dir
    }

    fn run_contract_checker(
        root: &std::path::Path,
        dir: &std::path::Path,
        contract_override: Option<&std::path::Path>,
    ) -> std::process::Output {
        let mut command = std::process::Command::new("bash");
        command
            .arg(root.join("scripts/check_evidence_ledger_contract.sh"))
            .current_dir(root)
            .env(
                "FRANKENLIBC_EVIDENCE_LEDGER_REPORT",
                dir.join("report.json"),
            )
            .env("FRANKENLIBC_EVIDENCE_LEDGER_LOG", dir.join("log.jsonl"));
        if let Some(path) = contract_override {
            command.env("FRANKENLIBC_EVIDENCE_LEDGER_CONTRACT", path);
        }
        command.output().expect("checker should run")
    }

    fn string_set(value: &serde_json::Value, key: &str) -> std::collections::BTreeSet<String> {
        value[key]
            .as_array()
            .expect("field should be an array")
            .iter()
            .map(|item| {
                item.as_str()
                    .expect("array item should be a string")
                    .to_string()
            })
            .collect()
    }

    fn assert_contract_file_line_ref(root: &std::path::Path, value: &serde_json::Value) {
        let reference = value.as_str().expect("file line ref should be string");
        let (path, line) = reference
            .rsplit_once(':')
            .expect("reference should have file:line shape");
        let line: usize = line.parse().expect("line should parse");
        let content = std::fs::read_to_string(root.join(path)).expect("referenced file exists");
        let source_line = content
            .lines()
            .nth(line.saturating_sub(1))
            .expect("line should exist");
        assert!(
            !source_line.trim().is_empty(),
            "{reference} should not point at a blank line"
        );
    }

    fn assert_required_tests_exist(completion: &serde_json::Value, section: &str, source: &str) {
        let required = completion[section]["required_test_names"]
            .as_array()
            .expect("required_test_names should be an array");
        assert!(!required.is_empty(), "{section} should list tests");
        for test_name in required {
            let test_name = test_name.as_str().expect("test name should be string");
            assert!(
                source.contains(&format!("fn {test_name}(")),
                "{section} references missing test {test_name}"
            );
        }
    }

    #[test]
    fn empty_ledger_has_zero_counts() {
        let ledger = make_test_ledger();
        assert_eq!(ledger.total_appended(), 0);
        assert_eq!(ledger.retained_count(), 0);
    }

    #[test]
    fn append_assigns_monotonic_seqno() {
        let ledger = make_test_ledger();
        ledger.append(make_record(EvidenceCategory::ValidationDecision, "t1"));
        ledger.append(make_record(EvidenceCategory::HealingAction, "t2"));
        ledger.append(make_record(EvidenceCategory::MetricsSnapshot, "t3"));

        assert_eq!(ledger.total_appended(), 3);
        assert_eq!(ledger.retained_count(), 3);

        let drained = ledger.drain();
        assert_eq!(drained[0].seqno, 1);
        assert_eq!(drained[1].seqno, 2);
        assert_eq!(drained[2].seqno, 3);
    }

    #[test]
    fn ring_buffer_evicts_oldest_on_overflow() {
        let ledger = EvidenceLedger::with_config(16, RedactionPolicy::None);
        for i in 0..32 {
            ledger.append(make_record(
                EvidenceCategory::ValidationDecision,
                &format!("trace-{i}"),
            ));
        }
        assert_eq!(ledger.total_appended(), 32);
        assert_eq!(ledger.retained_count(), 16);

        let drained = ledger.drain();
        // Oldest retained should be seqno 17
        assert_eq!(drained[0].seqno, 17);
        assert_eq!(drained[15].seqno, 32);
    }

    #[test]
    fn export_jsonl_produces_valid_json_lines() {
        let ledger = make_test_ledger();
        ledger.append(make_record(EvidenceCategory::ValidationDecision, "t1"));
        ledger.append(make_record(EvidenceCategory::HealingAction, "t2"));

        let jsonl = ledger.export_jsonl();
        let lines: Vec<&str> = jsonl.trim().split('\n').collect();
        assert_eq!(lines.len(), 2);

        for line in &lines {
            let parsed: serde_json::Value =
                serde_json::from_str(line).expect("each JSONL line should be valid JSON");
            assert!(parsed["evidence_seqno"].is_number());
            assert!(parsed["trace_id"].is_string());
            assert!(parsed["decision_id"].is_number());
            assert!(parsed["schema_version"].is_string());
            assert!(parsed["category"].is_string());
            assert!(parsed["level"].is_string());
            assert!(parsed["mode"].is_string());
        }
    }

    #[test]
    fn export_jsonl_filtered_only_returns_matching_category() {
        let ledger = make_test_ledger();
        ledger.append(make_record(EvidenceCategory::ValidationDecision, "t1"));
        ledger.append(make_record(EvidenceCategory::HealingAction, "t2"));
        ledger.append(make_record(EvidenceCategory::ValidationDecision, "t3"));

        let filtered = ledger.export_jsonl_filtered(EvidenceCategory::ValidationDecision);
        let lines: Vec<&str> = filtered.trim().split('\n').collect();
        assert_eq!(lines.len(), 2);
    }

    #[test]
    fn record_metrics_snapshot_creates_evidence() {
        let ledger = make_test_ledger();
        let snapshot = MetricsSnapshot {
            validations: 100,
            tls_cache_hits: 80,
            tls_cache_misses: 20,
            bloom_hits: 60,
            bloom_misses: 40,
            arena_lookups: 50,
            fingerprint_passes: 45,
            fingerprint_failures: 5,
            canary_passes: 48,
            canary_failures: 2,
            heals: 10,
            double_frees_healed: 3,
            foreign_frees_healed: 2,
            size_clamps: 5,
        };
        ledger.record_metrics_snapshot(
            &snapshot,
            TraceId::new("snapshot-trace".to_string()),
            "membrane",
        );

        assert_eq!(ledger.retained_count(), 1);
        let drained = ledger.drain();
        assert_eq!(drained[0].category, EvidenceCategory::MetricsSnapshot);
        assert!(drained[0].details_json.contains("\"validations\":100"));
    }

    #[test]
    fn record_healing_skips_none_action() {
        let ledger = make_test_ledger();
        ledger.record_healing(
            &HealingAction::None,
            TraceId::new("heal-trace".to_string()),
            DecisionId::from_raw(1),
            "allocator",
            "free",
        );
        assert_eq!(ledger.retained_count(), 0);
    }

    #[test]
    fn record_healing_creates_evidence_for_real_actions() {
        let ledger = make_test_ledger();
        ledger.record_healing(
            &HealingAction::IgnoreDoubleFree,
            TraceId::new("heal-trace".to_string()),
            DecisionId::from_raw(1),
            "allocator",
            "free",
        );
        assert_eq!(ledger.retained_count(), 1);
        let drained = ledger.drain();
        assert_eq!(drained[0].category, EvidenceCategory::HealingAction);
        assert_eq!(drained[0].level, EvidenceLevel::Info);
        assert!(drained[0].details_json.contains("IgnoreDoubleFree"));
    }

    #[test]
    fn escalated_healing_sets_warn_level() {
        let ledger = make_test_ledger();
        ledger.record_healing(
            &HealingAction::ReturnSafeDefault,
            TraceId::new("esc-trace".to_string()),
            DecisionId::from_raw(2),
            "string",
            "strcpy",
        );
        let drained = ledger.drain();
        assert_eq!(drained[0].level, EvidenceLevel::Warn);
    }

    #[test]
    fn record_validation_with_deny_sets_warn_level() {
        let ledger = make_test_ledger();
        ledger.record_validation(ValidationEvidence {
            trace_id: TraceId::new("val-trace".to_string()),
            decision_id: DecisionId::from_raw(3),
            policy_id: PolicyId::from_raw(1),
            api_family: "allocator".to_string(),
            symbol: "malloc".to_string(),
            decision_path: "tsm::validate::full".to_string(),
            outcome: "deny".to_string(),
            errno_val: 22, // EINVAL
            latency_ns: 500,
            details_json: "{\"reason\":\"null_ptr\"}".to_string(),
        });
        let drained = ledger.drain();
        assert_eq!(drained[0].level, EvidenceLevel::Warn);
        assert_eq!(drained[0].outcome, "deny");
        assert_eq!(drained[0].errno_val, 22);
    }

    #[test]
    fn correlation_index_groups_by_trace_id() {
        let ledger = make_test_ledger();
        ledger.append(make_record(
            EvidenceCategory::ValidationDecision,
            "shared-trace",
        ));
        ledger.append(make_record(EvidenceCategory::HealingAction, "shared-trace"));
        ledger.append(make_record(
            EvidenceCategory::MetricsSnapshot,
            "other-trace",
        ));

        let index = ledger.correlation_index();
        let shared = index.iter().find(|(k, _)| k == "shared-trace");
        assert!(shared.is_some());
        assert_eq!(shared.unwrap().1.len(), 2);
    }

    #[test]
    fn otlp_export_emits_log_records_and_counts() {
        let ledger = make_test_ledger();
        let mut first = make_record(EvidenceCategory::ValidationDecision, "t1");
        first.artifact_refs = vec!["artifacts/proof.json".to_string()];
        ledger.append(first);
        ledger.append(make_record(EvidenceCategory::ValidationDecision, "t2"));
        ledger.append(make_record(EvidenceCategory::HealingAction, "t3"));

        let export = ledger.otlp_export();
        assert_eq!(export.total_records, 3);
        assert_eq!(export.log_record_count(), 3);
        assert_eq!(export.category_counts[2], 2); // ValidationDecision
        assert_eq!(export.category_counts[1], 1); // HealingAction

        let json = export.to_json();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.get("otlp_status").is_none());
        assert_eq!(parsed["otlp_schema"], "logs/v1");
        assert_eq!(parsed["record_count"], 3);

        let log_records = parsed["resourceLogs"][0]["scopeLogs"][0]["logRecords"]
            .as_array()
            .expect("OTLP export must include log records");
        assert_eq!(log_records.len(), 3);
        assert_eq!(log_records[0]["body"]["stringValue"], "allow");
        assert_eq!(log_records[0]["severityText"], "INFO");

        let attrs = log_records[0]["attributes"]
            .as_array()
            .expect("OTLP log record must include attributes");
        assert_eq!(
            find_otlp_string_attr(attrs, "frankenlibc.category"),
            Some("validation_decision")
        );
        assert_eq!(
            find_otlp_string_attr(attrs, "frankenlibc.details"),
            Some("{\"size\":1024}")
        );
        assert_eq!(
            find_otlp_string_attr(attrs, "frankenlibc.artifact_refs"),
            Some("[\"artifacts/proof.json\"]")
        );
    }

    #[test]
    fn otlp_export_applies_pointer_redaction() {
        let ledger = EvidenceLedger::with_config(16, RedactionPolicy::RedactPointers);
        ledger.append(make_record(
            EvidenceCategory::ValidationDecision,
            "ptr::0x7fffffffe000",
        ));

        let json = ledger.otlp_export().to_json();
        assert!(
            !json.contains("0x7fffffffe000"),
            "OTLP export should redact pointer-like trace data: {json}"
        );
        assert!(
            json.contains("[REDACTED]"),
            "OTLP export should preserve redaction marker: {json}"
        );
    }

    #[test]
    fn redaction_policy_redacts_hex_addresses() {
        let result = redact_hex_addresses("ptr=0x7fffffffe000 val=0x1a");
        assert_eq!(result, "ptr=[REDACTED] val=0x1a");
    }

    #[test]
    fn redaction_policy_keeps_short_hex() {
        let result = redact_hex_addresses("code=0xbeef");
        assert_eq!(result, "code=0xbeef");
    }

    #[test]
    fn redaction_handles_trailing_0x_prefix() {
        // "0x" at end of string with no hex digits
        let result = redact_hex_addresses("end0x");
        assert_eq!(result, "end0x");
    }

    #[test]
    fn redaction_handles_bare_0x() {
        let result = redact_hex_addresses("0x");
        assert_eq!(result, "0x");
    }

    #[test]
    fn redaction_handles_exactly_8_hex_digits() {
        let result = redact_hex_addresses("addr=0xdeadbeef rest");
        assert_eq!(result, "addr=[REDACTED] rest");
    }

    #[test]
    fn redaction_preserves_non_ascii() {
        // Ensure non-ASCII characters pass through without corruption
        let result = redact_hex_addresses("café=0x7fffffffe000");
        assert_eq!(result, "café=[REDACTED]");
    }

    #[test]
    fn global_evidence_ledger_is_accessible() {
        // Verify the global singleton can be accessed without deadlock.
        // This implicitly tests that the reentrancy-safe constructor works.
        let ledger = global_evidence_ledger();
        assert_eq!(ledger.retained_count(), ledger.retained_count());
    }

    #[test]
    fn redacted_ledger_masks_pointers_in_jsonl() {
        let ledger = EvidenceLedger::with_config(16, RedactionPolicy::RedactPointers);
        let mut record = make_record(EvidenceCategory::ValidationDecision, "ptr::0x7fffffffe000");
        record.details_json = "{\"addr\":\"raw\"}".to_string();
        ledger.append(record);

        let jsonl = ledger.export_jsonl();
        let parsed: serde_json::Value =
            serde_json::from_str(jsonl.trim()).expect("redacted JSONL parses");
        let trace = parsed["trace_id"].as_str().unwrap();
        assert!(
            trace.contains("[REDACTED]"),
            "trace_id should be redacted: {trace}"
        );
    }

    #[test]
    fn full_redaction_hashes_symbols() {
        let ledger = EvidenceLedger::with_config(16, RedactionPolicy::Full);
        ledger.append(make_record(EvidenceCategory::ValidationDecision, "t1"));

        let jsonl = ledger.export_jsonl();
        let parsed: serde_json::Value =
            serde_json::from_str(jsonl.trim()).expect("full-redacted JSONL parses");
        let symbol = parsed["symbol"].as_str().unwrap();
        assert!(
            symbol.starts_with("redacted_"),
            "symbol should be hashed: {symbol}"
        );
    }

    #[test]
    fn sanitize_json_string_escapes_control_chars() {
        let s = "hello\n\"world\"\t\\end";
        let sanitized = sanitize_json_string(s);
        assert_eq!(sanitized, "hello\\n\\\"world\\\"\\t\\\\end");
    }

    #[test]
    fn clear_empties_buffer_but_preserves_seqno() {
        let ledger = make_test_ledger();
        ledger.append(make_record(EvidenceCategory::ValidationDecision, "t1"));
        ledger.append(make_record(EvidenceCategory::HealingAction, "t2"));
        assert_eq!(ledger.total_appended(), 2);

        ledger.clear();
        assert_eq!(ledger.retained_count(), 0);
        assert_eq!(ledger.total_appended(), 2);

        // New records continue the sequence
        ledger.append(make_record(EvidenceCategory::MetricsSnapshot, "t3"));
        let drained = ledger.drain();
        assert_eq!(drained[0].seqno, 3);
    }

    #[test]
    fn jsonl_includes_all_required_schema_fields() {
        let ledger = make_test_ledger();
        ledger.record_validation(ValidationEvidence {
            trace_id: TraceId::new("schema-test".to_string()),
            decision_id: DecisionId::from_raw(99),
            policy_id: PolicyId::from_raw(5),
            api_family: "string_memory".to_string(),
            symbol: "memcpy".to_string(),
            decision_path: "tsm::validate::bounds".to_string(),
            outcome: "allow".to_string(),
            errno_val: 0,
            latency_ns: 42,
            details_json: "{\"src_ok\":true}".to_string(),
        });

        let jsonl = ledger.export_jsonl();
        let parsed: serde_json::Value =
            serde_json::from_str(jsonl.trim()).expect("schema test JSONL parses");

        // All mandatory fields from the structured log contract
        assert!(parsed["timestamp"].is_string());
        assert!(parsed["evidence_seqno"].is_number());
        assert!(parsed["trace_id"].is_string());
        assert!(parsed["decision_id"].is_number());
        assert!(parsed["policy_id"].is_number());
        assert!(parsed["schema_version"].is_string());
        assert!(parsed["category"].is_string());
        assert!(parsed["level"].is_string());
        assert!(parsed["mode"].is_string());
        assert!(parsed["api_family"].is_string());
        assert!(parsed["symbol"].is_string());
        assert!(parsed["decision_path"].is_string());
        assert!(parsed["outcome"].is_string());
        assert!(parsed["errno"].is_number());
        assert!(parsed["latency_ns"].is_number());
        assert!(parsed["redaction_policy"].is_string());

        // Verify specific values
        assert_eq!(parsed["decision_id"], 99);
        assert_eq!(parsed["policy_id"], 5);
        assert_eq!(parsed["api_family"], "string_memory");
        assert_eq!(parsed["symbol"], "memcpy");
        assert_eq!(parsed["outcome"], "allow");
        assert_eq!(parsed["latency_ns"], 42);
    }

    #[test]
    fn evidence_ledger_contract_binds_completion_debt_items() {
        let root = workspace_root();
        let contract = load_json(&evidence_ledger_contract_path(&root));
        assert_eq!(contract["schema_version"], "evidence_ledger_contract.v1");
        assert_eq!(contract["bead"], "bd-28tf");

        let completion = &contract["completion_debt_evidence"];
        assert_eq!(completion["bead"], "bd-28tf.1");
        assert_eq!(completion["original_bead"], "bd-28tf");
        assert_eq!(completion["original_audit_score"], 470);
        assert!(
            completion["next_audit_score_threshold"]
                .as_u64()
                .is_some_and(|score| score >= 800)
        );

        let source_path = root.join(
            completion["test_source"]
                .as_str()
                .expect("test_source should be string"),
        );
        let source = std::fs::read_to_string(source_path).expect("test source should be readable");
        for reference in completion["implementation_refs"]
            .as_array()
            .expect("implementation refs should be array")
        {
            assert_contract_file_line_ref(&root, reference);
        }
        for (section, missing_item) in [
            ("unit_primary", "tests.unit.primary"),
            ("e2e_primary", "tests.e2e.primary"),
            ("conformance_primary", "tests.conformance.primary"),
            ("telemetry_primary", "telemetry.primary"),
        ] {
            assert_eq!(completion[section]["missing_item_id"], missing_item);
            assert!(
                completion[section]["next_audit_score_threshold"]
                    .as_u64()
                    .is_some_and(|score| score >= 800)
            );
            assert_required_tests_exist(completion, section, &source);
        }
    }

    #[test]
    fn jsonl_and_otlp_exports_cover_completion_contract_fields() {
        let root = workspace_root();
        let contract = load_json(&evidence_ledger_contract_path(&root));
        let ledger = make_test_ledger();
        ledger.record_validation(ValidationEvidence {
            trace_id: TraceId::new("contract::validation::0x7fffffffe000".to_string()),
            decision_id: DecisionId::from_raw(101),
            policy_id: PolicyId::from_raw(9),
            api_family: "allocator".to_string(),
            symbol: "malloc".to_string(),
            decision_path: "tsm::validate::full".to_string(),
            outcome: "deny".to_string(),
            errno_val: 22,
            latency_ns: 777,
            details_json: "{\"reason\":\"contract_probe\"}".to_string(),
        });

        let jsonl_line = ledger.export_jsonl();
        let jsonl: serde_json::Value =
            serde_json::from_str(jsonl_line.trim()).expect("JSONL export should parse");
        for field in string_set(&contract["jsonl_contract"], "required_fields") {
            assert!(jsonl.get(&field).is_some(), "JSONL missing {field}");
        }

        let otlp: serde_json::Value =
            serde_json::from_str(&ledger.otlp_export().to_json()).expect("OTLP export parses");
        assert_eq!(otlp["otlp_schema"], "logs/v1");
        let resource_attrs = otlp["resourceLogs"][0]["resource"]["attributes"]
            .as_array()
            .expect("resource attributes should be present");
        let resource_attr_keys: std::collections::BTreeSet<_> = resource_attrs
            .iter()
            .filter_map(|attr| attr["key"].as_str())
            .collect();
        for key in string_set(&contract["otlp_contract"], "required_resource_attributes") {
            assert!(
                resource_attr_keys.contains(key.as_str()),
                "resource attrs missing {key}"
            );
        }
        let log_attrs = otlp["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["attributes"]
            .as_array()
            .expect("log attributes should be present");
        let log_attr_keys: std::collections::BTreeSet<_> = log_attrs
            .iter()
            .filter_map(|attr| attr["key"].as_str())
            .collect();
        for key in string_set(&contract["otlp_contract"], "required_log_attributes") {
            assert!(
                log_attr_keys.contains(key.as_str()),
                "log attrs missing {key}"
            );
        }
    }

    #[test]
    fn evidence_ledger_contract_checker_accepts_contract() {
        let root = workspace_root();
        let dir = unique_contract_dir(&root, "accepts-contract");
        let output = run_contract_checker(&root, &dir, None);
        assert!(
            output.status.success(),
            "checker should pass\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let report = load_json(&dir.join("report.json"));
        assert_eq!(report["status"], "pass");
        assert_eq!(report["completion_debt_bead"], "bd-28tf.1");
        let log_text = std::fs::read_to_string(dir.join("log.jsonl")).expect("log is readable");
        let log_row: serde_json::Value =
            serde_json::from_str(log_text.trim()).expect("log row parses");
        assert_eq!(log_row["event"], "evidence_ledger_contract_validated");
        assert_eq!(log_row["completion_debt_bead"], "bd-28tf.1");
    }

    #[test]
    fn evidence_ledger_contract_checker_rejects_stale_test_binding() {
        let root = workspace_root();
        let dir = unique_contract_dir(&root, "rejects-stale-binding");
        let mut contract = load_json(&evidence_ledger_contract_path(&root));
        contract["completion_debt_evidence"]["unit_primary"]["required_test_names"] =
            serde_json::json!(["missing_evidence_ledger_contract_test"]);
        let stale_contract = dir.join("stale-contract.json");
        write_json(&stale_contract, &contract);

        let output = run_contract_checker(&root, &dir, Some(&stale_contract));
        assert!(!output.status.success(), "stale test binding should fail");
        let report = load_json(&dir.join("report.json"));
        assert_eq!(report["status"], "fail");
        let errors = report["errors"]
            .as_array()
            .expect("errors should be an array");
        assert!(errors.iter().any(|error| {
            error
                .as_str()
                .is_some_and(|text| text.contains("missing_evidence_ledger_contract_test"))
        }));
    }

    #[test]
    fn healing_action_json_round_trip() {
        let actions = vec![
            HealingAction::ClampSize {
                requested: 1024,
                clamped: 512,
            },
            HealingAction::TruncateWithNull {
                requested: 256,
                truncated: 128,
            },
            HealingAction::IgnoreDoubleFree,
            HealingAction::IgnoreForeignFree,
            HealingAction::ReallocAsMalloc { size: 64 },
            HealingAction::ReturnSafeDefault,
            HealingAction::UpgradeToSafeVariant,
        ];

        for action in &actions {
            let json = healing_action_to_json(action);
            let parsed: serde_json::Value =
                serde_json::from_str(&json).expect("healing action JSON should parse");
            assert!(parsed["action"].is_string());
        }
    }
}
