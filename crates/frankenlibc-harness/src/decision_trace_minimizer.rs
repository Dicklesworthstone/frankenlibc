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
///   5. Build `expected_failure_signature` from the *first* kept
///      row that exhibits a divergence, or "" if none.
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

    // Pick the first kept row in INPUT order that diverges, for the
    // expected_failure_signature.
    let mut first_divergence: Option<&TraceRow> = None;
    for r in rows {
        if r.mode_strict_decision != r.mode_hardened_decision {
            first_divergence = Some(r);
            break;
        }
    }

    let signature = if let Some(r) = first_divergence {
        format!(
            "{}::{}::{}::{}::{}::{}->vs->-{}",
            r.scenario,
            r.api_family,
            r.symbol,
            r.decision_path,
            r.input_class,
            r.mode_strict_decision,
            r.mode_hardened_decision
        )
    } else {
        String::new()
    };

    // Replay command emits the kept-row count and the signature so a
    // downstream agent can rerun the smallest possible reproducer.
    let replay_command = if first_divergence.is_some() {
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
        has_divergence: first_divergence.is_some(),
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
}
