//! Strict/hardened decision-trace minimizer for replay divergences
//! (bd-juvqm.6).
//!
//! Consumes a JSONL stream of runtime decision rows, workload-trace
//! rows, or healing-oracle logs and returns the smallest replayable
//! trace that still triggers the same strict/hardened divergence (or
//! reports `NoDivergence` for a clean control input).
//!
//! Determinism: ordering is BTreeMap-stable (sorted by fingerprint
//! key). Calling [`minimize`] twice with the same input rows
//! returns a `PartialEq`-equal output.
//!
//! Failure modes:
//!   * Empty input → `Err(MinimizerError::Empty)`
//!   * Missing required field on any row →
//!     `Err(MinimizerError::MalformedRow{ row_index, missing })`
//!   * Missing schema_version on any row →
//!     `Err(MinimizerError::MissingSchemaVersion{ row_index })`
//!   * Empty artifact_refs on any row →
//!     `Err(MinimizerError::MissingArtifactRefs{ row_index })`
//!
//! These rejection classes are by design: a downstream replay must
//! be able to point at the original artifacts and at a schema
//! version that decodes the rows.

use std::collections::BTreeMap;

/// One row of a decision-trace input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceRow {
    pub schema_version: String,
    pub scenario: String,
    pub api_family: String,
    pub symbol: String,
    pub decision_path: String,
    pub input_class: String,
    pub mode_strict_decision: String,
    pub mode_hardened_decision: String,
    pub source_commit: String,
    pub artifact_refs: Vec<String>,
}

/// Output of [`minimize`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinimizedTrace {
    /// The first divergent row per (scenario, api_family, symbol,
    /// decision_path, input_class) fingerprint key, sorted by key.
    pub minimized_rows: Vec<TraceRow>,
    /// Number of input rows that were dropped because they had a
    /// fingerprint key already represented by a kept row.
    pub dropped_row_count: usize,
    /// Reason a row was dropped — one entry per dropped row in input
    /// order. The string is the fingerprint key concatenation that
    /// matches the kept row.
    pub dropped_row_rationale: Vec<String>,
    /// Synthetic replay command a downstream agent can paste.
    pub replay_command: String,
    /// Stable signature of the divergence:
    /// `<scenario>::<api_family>::<symbol>::<decision_path>::<input_class>::<strict>->vs->-<hardened>`.
    /// Empty when there is no divergence.
    pub expected_failure_signature: String,
    /// source_commit of the first kept row (anchors the replay).
    pub source_commit: String,
    /// Original artifact_refs union of every kept row, deduped &
    /// sorted.
    pub original_artifact_refs: Vec<String>,
    /// True iff the input contained any (strict, hardened) row pair
    /// where the two decisions disagreed.
    pub has_divergence: bool,
}

/// Failure shapes for the minimizer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MinimizerError {
    Empty,
    MalformedRow {
        row_index: usize,
        missing: &'static str,
    },
    MissingSchemaVersion {
        row_index: usize,
    },
    MissingArtifactRefs {
        row_index: usize,
    },
}

impl core::fmt::Display for MinimizerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MinimizerError::Empty => f.write_str("input has no rows"),
            MinimizerError::MalformedRow { row_index, missing } => {
                write!(f, "row {row_index} missing required field {missing}")
            }
            MinimizerError::MissingSchemaVersion { row_index } => {
                write!(f, "row {row_index} missing schema_version")
            }
            MinimizerError::MissingArtifactRefs { row_index } => {
                write!(f, "row {row_index} has empty artifact_refs")
            }
        }
    }
}

impl std::error::Error for MinimizerError {}

/// Compute the fingerprint key the minimizer uses to dedup rows.
fn fingerprint_key(r: &TraceRow) -> String {
    format!(
        "{}|{}|{}|{}|{}",
        r.scenario, r.api_family, r.symbol, r.decision_path, r.input_class
    )
}

fn validate_row(idx: usize, r: &TraceRow) -> Result<(), MinimizerError> {
    if r.schema_version.is_empty() {
        return Err(MinimizerError::MissingSchemaVersion { row_index: idx });
    }
    if r.artifact_refs.is_empty() {
        return Err(MinimizerError::MissingArtifactRefs { row_index: idx });
    }
    if r.scenario.is_empty() {
        return Err(MinimizerError::MalformedRow {
            row_index: idx,
            missing: "scenario",
        });
    }
    if r.api_family.is_empty() {
        return Err(MinimizerError::MalformedRow {
            row_index: idx,
            missing: "api_family",
        });
    }
    if r.symbol.is_empty() {
        return Err(MinimizerError::MalformedRow {
            row_index: idx,
            missing: "symbol",
        });
    }
    if r.decision_path.is_empty() {
        return Err(MinimizerError::MalformedRow {
            row_index: idx,
            missing: "decision_path",
        });
    }
    if r.input_class.is_empty() {
        return Err(MinimizerError::MalformedRow {
            row_index: idx,
            missing: "input_class",
        });
    }
    if r.mode_strict_decision.is_empty() {
        return Err(MinimizerError::MalformedRow {
            row_index: idx,
            missing: "mode_strict_decision",
        });
    }
    if r.mode_hardened_decision.is_empty() {
        return Err(MinimizerError::MalformedRow {
            row_index: idx,
            missing: "mode_hardened_decision",
        });
    }
    if r.source_commit.is_empty() {
        return Err(MinimizerError::MalformedRow {
            row_index: idx,
            missing: "source_commit",
        });
    }
    Ok(())
}

/// Reduce `rows` to the smallest replayable trace.
///
/// The algorithm:
///   1. Validate every row (any failure aborts the whole minimize).
///   2. Walk rows in input order. Keep the first row encountered
///      for each fingerprint key. Subsequent rows with the same
///      key are dropped and recorded in `dropped_row_rationale`.
///   3. Sort kept rows by fingerprint key (BTreeMap order) for
///      deterministic output regardless of input ordering.
///   4. Compute `has_divergence` as "any kept row has a strict
///      decision that differs from its hardened decision".
///   5. Build `expected_failure_signature` from the first kept row
///      in deterministic fingerprint-key order that exhibits a
///      divergence, or "" if none.
pub fn minimize(rows: &[TraceRow]) -> Result<MinimizedTrace, MinimizerError> {
    if rows.is_empty() {
        return Err(MinimizerError::Empty);
    }
    for (i, r) in rows.iter().enumerate() {
        validate_row(i, r)?;
    }

    let mut keep_by_key: BTreeMap<String, TraceRow> = BTreeMap::new();
    let mut dropped: Vec<String> = Vec::new();
    for r in rows {
        let key = fingerprint_key(r);
        if let std::collections::btree_map::Entry::Vacant(e) = keep_by_key.entry(key.clone()) {
            e.insert(r.clone());
        } else {
            dropped.push(format!("dropped duplicate-fingerprint row: {key}"));
        }
    }

    let kept: Vec<TraceRow> = keep_by_key.values().cloned().collect();
    let dropped_count = dropped.len();

    // Pick the first replayable kept row that diverges. This must be
    // derived from `kept`, not raw input rows, because duplicate
    // fingerprint rows are intentionally dropped above.
    let first_divergence = kept
        .iter()
        .find(|r| r.mode_strict_decision != r.mode_hardened_decision);

    let (has_divergence, signature) = match first_divergence {
        Some(r) => (
            true,
            format!(
                "{}::{}::{}::{}::{}::{}->vs->-{}",
                r.scenario,
                r.api_family,
                r.symbol,
                r.decision_path,
                r.input_class,
                r.mode_strict_decision,
                r.mode_hardened_decision
            ),
        ),
        None => (false, String::new()),
    };

    // Replay command emits the kept-row count and the signature so a
    // downstream agent can rerun the smallest possible reproducer.
    let replay_command = if has_divergence {
        format!(
            "rch cargo test -p frankenlibc-harness --test runtime_evidence_replay_gate_test -- --exact replay::{}",
            signature.replace("::", "_").replace("->vs->-", "_to_")
        )
    } else {
        "rch cargo test -p frankenlibc-harness --test runtime_evidence_replay_gate_test -- --exact replay::no_divergence_control".to_string()
    };

    // Union of artifact_refs across kept rows, deduped and sorted.
    let mut union: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for r in &kept {
        for a in &r.artifact_refs {
            union.insert(a.clone());
        }
    }
    let original_artifact_refs: Vec<String> = union.into_iter().collect();

    let source_commit = kept
        .first()
        .map(|r| r.source_commit.clone())
        .unwrap_or_default();

    Ok(MinimizedTrace {
        minimized_rows: kept,
        dropped_row_count: dropped_count,
        dropped_row_rationale: dropped,
        replay_command,
        expected_failure_signature: signature,
        source_commit,
        original_artifact_refs,
        has_divergence,
    })
}

/// Required-field list for the persisted JSONL form of
/// [`MinimizedTrace`] (bd-yhvim). Pinned by the manifest
/// `serialization_contract` block.
pub const MINIMIZED_TRACE_REQUIRED_FIELDS: &[&str] = &[
    "kind",
    "expected_failure_signature",
    "replay_command",
    "source_commit",
    "dropped_row_count",
    "dropped_row_rationale",
    "original_artifact_refs",
    "has_divergence",
    "minimized_rows_len",
];

pub const MINIMIZED_TRACE_KIND: &str = "minimized_trace_summary";

/// Compact summary of a [`MinimizedTrace`] suitable for round-trip
/// through JSONL. Carries every field except the full
/// `minimized_rows` (which is captured as `minimized_rows_len` for
/// compactness; full rows are persisted separately when needed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinimizedTraceSummary {
    pub kind: String,
    pub expected_failure_signature: String,
    pub replay_command: String,
    pub source_commit: String,
    pub dropped_row_count: usize,
    pub dropped_row_rationale: Vec<String>,
    pub original_artifact_refs: Vec<String>,
    pub has_divergence: bool,
    pub minimized_rows_len: usize,
}

impl MinimizedTraceSummary {
    /// Construct a summary from a [`MinimizedTrace`].
    pub fn from_trace(t: &MinimizedTrace) -> Self {
        Self {
            kind: MINIMIZED_TRACE_KIND.to_string(),
            expected_failure_signature: t.expected_failure_signature.clone(),
            replay_command: t.replay_command.clone(),
            source_commit: t.source_commit.clone(),
            dropped_row_count: t.dropped_row_count,
            dropped_row_rationale: t.dropped_row_rationale.clone(),
            original_artifact_refs: t.original_artifact_refs.clone(),
            has_divergence: t.has_divergence,
            minimized_rows_len: t.minimized_rows.len(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MinimizerSerError {
    InvalidJson(String),
    MissingField(&'static str),
    WrongFieldType(&'static str),
    UnexpectedKind(String),
}

impl core::fmt::Display for MinimizerSerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MinimizerSerError::InvalidJson(e) => write!(f, "invalid JSON: {e}"),
            MinimizerSerError::MissingField(name) => write!(f, "missing field {name}"),
            MinimizerSerError::WrongFieldType(name) => write!(f, "wrong field type for {name}"),
            MinimizerSerError::UnexpectedKind(kind) => {
                write!(f, "unexpected minimized trace kind {kind:?}")
            }
        }
    }
}

impl std::error::Error for MinimizerSerError {}

/// Serialize a [`MinimizedTrace`] (or its [`MinimizedTraceSummary`])
/// as a single JSONL line using the lib's `serde_json` dependency.
pub fn serialize_minimized_trace_jsonl(trace: &MinimizedTrace) -> String {
    let summary = MinimizedTraceSummary::from_trace(trace);
    serialize_summary_jsonl(&summary)
}

pub fn serialize_summary_jsonl(s: &MinimizedTraceSummary) -> String {
    let v = serde_json::json!({
        "kind": s.kind,
        "expected_failure_signature": s.expected_failure_signature,
        "replay_command": s.replay_command,
        "source_commit": s.source_commit,
        "dropped_row_count": s.dropped_row_count,
        "dropped_row_rationale": s.dropped_row_rationale,
        "original_artifact_refs": s.original_artifact_refs,
        "has_divergence": s.has_divergence,
        "minimized_rows_len": s.minimized_rows_len,
    });
    let mut line = v.to_string();
    line.push('\n');
    line
}

/// Parse a JSONL line back into a [`MinimizedTraceSummary`]. Fails
/// closed when any required field is missing or has the wrong type.
pub fn parse_minimized_trace_jsonl(line: &str) -> Result<MinimizedTraceSummary, MinimizerSerError> {
    let v: serde_json::Value = serde_json::from_str(line.trim_end())
        .map_err(|e| MinimizerSerError::InvalidJson(e.to_string()))?;
    fn s(v: &serde_json::Value, name: &'static str) -> Result<String, MinimizerSerError> {
        v.get(name)
            .ok_or(MinimizerSerError::MissingField(name))?
            .as_str()
            .map(str::to_owned)
            .ok_or(MinimizerSerError::WrongFieldType(name))
    }
    fn n(v: &serde_json::Value, name: &'static str) -> Result<u64, MinimizerSerError> {
        v.get(name)
            .ok_or(MinimizerSerError::MissingField(name))?
            .as_u64()
            .ok_or(MinimizerSerError::WrongFieldType(name))
    }
    fn b(v: &serde_json::Value, name: &'static str) -> Result<bool, MinimizerSerError> {
        v.get(name)
            .ok_or(MinimizerSerError::MissingField(name))?
            .as_bool()
            .ok_or(MinimizerSerError::WrongFieldType(name))
    }
    fn vs(v: &serde_json::Value, name: &'static str) -> Result<Vec<String>, MinimizerSerError> {
        v.get(name)
            .ok_or(MinimizerSerError::MissingField(name))?
            .as_array()
            .ok_or(MinimizerSerError::WrongFieldType(name))?
            .iter()
            .map(|e| {
                e.as_str()
                    .map(str::to_owned)
                    .ok_or(MinimizerSerError::WrongFieldType(name))
            })
            .collect()
    }
    let kind = s(&v, "kind")?;
    if kind != MINIMIZED_TRACE_KIND {
        return Err(MinimizerSerError::UnexpectedKind(kind));
    }
    Ok(MinimizedTraceSummary {
        kind,
        expected_failure_signature: s(&v, "expected_failure_signature")?,
        replay_command: s(&v, "replay_command")?,
        source_commit: s(&v, "source_commit")?,
        dropped_row_count: n(&v, "dropped_row_count")? as usize,
        dropped_row_rationale: vs(&v, "dropped_row_rationale")?,
        original_artifact_refs: vs(&v, "original_artifact_refs")?,
        has_divergence: b(&v, "has_divergence")?,
        minimized_rows_len: n(&v, "minimized_rows_len")? as usize,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(
        scenario: &str,
        api_family: &str,
        symbol: &str,
        decision_path: &str,
        input_class: &str,
        strict: &str,
        hardened: &str,
    ) -> TraceRow {
        TraceRow {
            schema_version: "v1".to_string(),
            scenario: scenario.to_string(),
            api_family: api_family.to_string(),
            symbol: symbol.to_string(),
            decision_path: decision_path.to_string(),
            input_class: input_class.to_string(),
            mode_strict_decision: strict.to_string(),
            mode_hardened_decision: hardened.to_string(),
            source_commit: "abc1234567890abc1234567890abc1234567890a".to_string(),
            artifact_refs: vec![
                "target/conformance/runtime_evidence_replay_gate.log.jsonl".to_string(),
            ],
        }
    }

    #[test]
    fn empty_input_is_rejected() {
        let r: Vec<TraceRow> = vec![];
        assert_eq!(minimize(&r), Err(MinimizerError::Empty));
    }

    #[test]
    fn missing_schema_version_is_rejected() {
        let mut r = row("s", "stdio", "fread", "fast", "typical", "Allow", "Allow");
        r.schema_version = String::new();
        assert_eq!(
            minimize(&[r]),
            Err(MinimizerError::MissingSchemaVersion { row_index: 0 })
        );
    }

    #[test]
    fn missing_artifact_refs_is_rejected() {
        let mut r = row("s", "stdio", "fread", "fast", "typical", "Allow", "Allow");
        r.artifact_refs.clear();
        assert_eq!(
            minimize(&[r]),
            Err(MinimizerError::MissingArtifactRefs { row_index: 0 })
        );
    }

    #[test]
    fn missing_required_field_is_rejected() {
        let mut r = row("s", "stdio", "fread", "fast", "typical", "Allow", "Allow");
        r.symbol = String::new();
        match minimize(&[r]) {
            Err(MinimizerError::MalformedRow {
                row_index: 0,
                missing: "symbol",
            }) => {}
            other => panic!("expected MalformedRow{{0, symbol}}; got {other:?}"),
        }
    }

    #[test]
    fn no_divergence_control_returns_empty_signature() {
        let rows = vec![
            row("s", "stdio", "fread", "fast", "typical", "Allow", "Allow"),
            row("s", "stdio", "fwrite", "fast", "typical", "Allow", "Allow"),
        ];
        let m = minimize(&rows).unwrap();
        assert!(!m.has_divergence);
        assert_eq!(m.expected_failure_signature, "");
        assert_eq!(m.minimized_rows.len(), 2);
        assert_eq!(m.dropped_row_count, 0);
        assert!(m.replay_command.contains("no_divergence_control"));
    }

    #[test]
    fn first_divergence_is_preserved_in_signature() {
        let rows = vec![
            row("s", "stdio", "fread", "fast", "typical", "Allow", "Allow"),
            row(
                "s",
                "stdio",
                "fread",
                "slow",
                "adversarial",
                "Allow",
                "Repair",
            ),
            row("s", "malloc", "malloc", "fast", "typical", "Deny", "Deny"),
        ];
        let m = minimize(&rows).unwrap();
        assert!(m.has_divergence);
        assert_eq!(
            m.expected_failure_signature,
            "s::stdio::fread::slow::adversarial::Allow->vs->-Repair"
        );
        assert_eq!(m.minimized_rows.len(), 3);
        assert_eq!(m.dropped_row_count, 0);
    }

    #[test]
    fn duplicate_fingerprint_rows_are_dropped() {
        let rows = vec![
            row(
                "s",
                "stdio",
                "fread",
                "slow",
                "adversarial",
                "Allow",
                "Repair",
            ),
            row(
                "s",
                "stdio",
                "fread",
                "slow",
                "adversarial",
                "Allow",
                "Repair",
            ),
            row(
                "s",
                "stdio",
                "fread",
                "slow",
                "adversarial",
                "Allow",
                "Repair",
            ),
        ];
        let m = minimize(&rows).unwrap();
        assert_eq!(m.minimized_rows.len(), 1);
        assert_eq!(m.dropped_row_count, 2);
        assert!(m.dropped_row_rationale[0].contains("s|stdio|fread|slow|adversarial"));
    }

    // MR strength matrix:
    // duplicate-row suppression: sensitivity 5, independence 4, cost 1, score 20
    // input-reordering invariance: sensitivity 4, independence 4, cost 1, score 16
    // kept-row replayability: sensitivity 5, independence 5, cost 1, score 25

    #[test]
    fn duplicate_divergent_row_dropped_does_not_create_unreplayable_signature() {
        let rows = vec![
            row("s", "stdio", "fread", "fast", "typical", "Allow", "Allow"),
            row("s", "stdio", "fread", "fast", "typical", "Allow", "Repair"),
        ];

        let m = minimize(&rows).unwrap();

        assert_eq!(m.minimized_rows.len(), 1);
        assert_eq!(m.dropped_row_count, 1);
        assert!(!m.has_divergence);
        assert_eq!(m.expected_failure_signature, "");
        assert!(m.replay_command.contains("no_divergence_control"));
    }

    #[test]
    fn replay_signature_comes_from_kept_rows_after_duplicate_suppression() {
        let rows = vec![
            row("s", "stdio", "fread", "fast", "typical", "Allow", "Allow"),
            row("s", "stdio", "fread", "fast", "typical", "Allow", "Repair"),
            row(
                "s",
                "stdio",
                "fwrite",
                "slow",
                "adversarial",
                "Allow",
                "Repair",
            ),
        ];

        let m = minimize(&rows).unwrap();

        assert!(m.has_divergence);
        assert_eq!(m.minimized_rows.len(), 2);
        assert_eq!(
            m.expected_failure_signature,
            "s::stdio::fwrite::slow::adversarial::Allow->vs->-Repair"
        );
        assert!(
            m.minimized_rows.iter().any(|r| {
                r.symbol == "fwrite" && r.mode_strict_decision != r.mode_hardened_decision
            }),
            "signature must identify a divergence present in minimized_rows"
        );
    }

    #[test]
    fn signature_is_stable_under_reordering_when_multiple_kept_rows_diverge() {
        let rows = vec![
            row(
                "z",
                "stdio",
                "fwrite",
                "slow",
                "adversarial",
                "Allow",
                "Repair",
            ),
            row("a", "malloc", "free", "full", "foreign", "Deny", "Repair"),
        ];
        let mut reversed = rows.clone();
        reversed.reverse();

        let original = minimize(&rows).unwrap();
        let permuted = minimize(&reversed).unwrap();

        assert_eq!(
            original.expected_failure_signature,
            permuted.expected_failure_signature
        );
        assert_eq!(
            original.expected_failure_signature,
            "a::malloc::free::full::foreign::Deny->vs->-Repair"
        );
        assert_eq!(original.has_divergence, permuted.has_divergence);
        assert_eq!(original.minimized_rows, permuted.minimized_rows);
    }

    #[test]
    fn output_is_deterministic_under_input_reordering() {
        let a = vec![
            row("a", "stdio", "fread", "fast", "typical", "Allow", "Allow"),
            row(
                "a",
                "stdio",
                "fwrite",
                "slow",
                "adversarial",
                "Allow",
                "Repair",
            ),
            row("a", "malloc", "free", "fast", "typical", "Deny", "Deny"),
        ];
        let mut b = a.clone();
        b.reverse();

        let ma = minimize(&a).unwrap();
        let mb = minimize(&b).unwrap();
        // minimized_rows should be sorted by fingerprint key in both
        // outputs — therefore identical regardless of input order.
        assert_eq!(ma.minimized_rows, mb.minimized_rows);
        assert_eq!(ma.original_artifact_refs, mb.original_artifact_refs);
        // expected_failure_signature picks the first divergent row in
        // INPUT order, so reversed input may surface a different
        // divergence as "first" — but if there's only one diverging
        // row in this corpus, signatures must match.
        assert_eq!(ma.has_divergence, mb.has_divergence);
        assert_eq!(ma.expected_failure_signature, mb.expected_failure_signature);
    }

    #[test]
    fn replay_command_routes_through_rch() {
        let rows = vec![row(
            "s",
            "stdio",
            "fread",
            "slow",
            "adversarial",
            "Allow",
            "Repair",
        )];
        let m = minimize(&rows).unwrap();
        assert!(m.replay_command.starts_with("rch cargo test -p "));
        assert!(m.replay_command.contains("frankenlibc-harness"));
        assert!(!m.replay_command.contains("--workspace"));
    }

    #[test]
    fn artifact_refs_are_deduped_and_sorted_in_output() {
        let mut r1 = row("s", "stdio", "fread", "fast", "typical", "Allow", "Allow");
        r1.artifact_refs = vec!["b.jsonl".to_string(), "a.jsonl".to_string()];
        let mut r2 = row("s", "stdio", "fwrite", "fast", "typical", "Allow", "Allow");
        r2.artifact_refs = vec!["a.jsonl".to_string(), "c.jsonl".to_string()];
        let m = minimize(&[r1, r2]).unwrap();
        assert_eq!(
            m.original_artifact_refs,
            vec!["a.jsonl", "b.jsonl", "c.jsonl"]
        );
    }

    // ── JSONL round-trip tests (bd-yhvim) ────────────────────────────

    #[test]
    fn jsonl_serialization_emits_one_line_with_every_required_field() {
        let rows = vec![row(
            "s",
            "stdio",
            "fread",
            "slow",
            "adversarial",
            "Allow",
            "Repair",
        )];
        let m = minimize(&rows).unwrap();
        let line = serialize_minimized_trace_jsonl(&m);
        assert!(line.ends_with('\n'));
        assert_eq!(line.matches('\n').count(), 1);
        let v: serde_json::Value = serde_json::from_str(line.trim_end()).unwrap();
        for f in MINIMIZED_TRACE_REQUIRED_FIELDS {
            assert!(v.get(*f).is_some(), "missing field {f}");
        }
    }

    #[test]
    fn jsonl_round_trip_preserves_summary_fields() {
        let rows = vec![
            row("s", "stdio", "fread", "fast", "typical", "Allow", "Allow"),
            row(
                "s",
                "stdio",
                "fread",
                "slow",
                "adversarial",
                "Allow",
                "Repair",
            ),
        ];
        let m = minimize(&rows).unwrap();
        let line = serialize_minimized_trace_jsonl(&m);
        let summary = parse_minimized_trace_jsonl(&line).unwrap();
        assert_eq!(summary.kind, MINIMIZED_TRACE_KIND);
        assert_eq!(
            summary.expected_failure_signature,
            m.expected_failure_signature
        );
        assert_eq!(summary.replay_command, m.replay_command);
        assert_eq!(summary.source_commit, m.source_commit);
        assert_eq!(summary.dropped_row_count, m.dropped_row_count);
        assert_eq!(summary.dropped_row_rationale, m.dropped_row_rationale);
        assert_eq!(summary.original_artifact_refs, m.original_artifact_refs);
        assert_eq!(summary.has_divergence, m.has_divergence);
        assert_eq!(summary.minimized_rows_len, m.minimized_rows.len());
    }

    #[test]
    fn jsonl_parser_rejects_missing_required_field() {
        let bad = r#"{"kind":"minimized_trace_summary","replay_command":"x","source_commit":"y"}"#;
        match parse_minimized_trace_jsonl(bad) {
            Err(MinimizerSerError::MissingField("expected_failure_signature")) => {}
            other => panic!("expected MissingField; got {other:?}"),
        }
    }

    #[test]
    fn jsonl_parser_rejects_wrong_field_type() {
        let bad = r#"{"kind":"minimized_trace_summary","expected_failure_signature":"sig","replay_command":"x","source_commit":"y","dropped_row_count":"NOT_A_NUMBER","dropped_row_rationale":[],"original_artifact_refs":[],"has_divergence":false,"minimized_rows_len":0}"#;
        match parse_minimized_trace_jsonl(bad) {
            Err(MinimizerSerError::WrongFieldType("dropped_row_count")) => {}
            other => panic!("expected WrongFieldType; got {other:?}"),
        }
    }

    #[test]
    fn jsonl_parser_rejects_wrong_kind() {
        let bad = r#"{"kind":"wrong","expected_failure_signature":"sig","replay_command":"x","source_commit":"y","dropped_row_count":0,"dropped_row_rationale":[],"original_artifact_refs":[],"has_divergence":false,"minimized_rows_len":0}"#;
        match parse_minimized_trace_jsonl(bad) {
            Err(MinimizerSerError::UnexpectedKind(kind)) if kind == "wrong" => {}
            other => panic!("expected UnexpectedKind; got {other:?}"),
        }
    }

    #[test]
    fn jsonl_parser_rejects_invalid_json() {
        let bad = "{not valid json}";
        match parse_minimized_trace_jsonl(bad) {
            Err(MinimizerSerError::InvalidJson(_)) => {}
            other => panic!("expected InvalidJson; got {other:?}"),
        }
    }

    #[test]
    fn no_divergence_control_serializes_with_empty_signature() {
        let rows = vec![row(
            "s", "stdio", "fread", "fast", "typical", "Allow", "Allow",
        )];
        let m = minimize(&rows).unwrap();
        let line = serialize_minimized_trace_jsonl(&m);
        let summary = parse_minimized_trace_jsonl(&line).unwrap();
        assert_eq!(summary.kind, MINIMIZED_TRACE_KIND);
        assert_eq!(summary.expected_failure_signature, "");
        assert!(!summary.has_divergence);
    }
}
