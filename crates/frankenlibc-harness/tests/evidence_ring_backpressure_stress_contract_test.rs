//! Conformance gate for the evidence-ring backpressure stress contract
//! (bd-juvqm.7).
//!
//! Validates the schema and policy of
//! `tests/conformance/evidence_ring_backpressure_stress_contract.v1.json`,
//! plus exercises the model ring + stress driver from
//! `frankenlibc_harness::evidence_ring_backpressure` so the contract is
//! testable today without a live runtime evidence emission run.
//!
//! The contract requires the following ring-path rows to be present:
//!   * runtime_math.decision_card_ring
//!   * runtime_math.evidence_symbol_ring
//!   * structured_log.event_ring
//!   * stdio.evidence_row_ring
//!   * membrane.validation_log_ring

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use frankenlibc_harness::evidence_ring_backpressure::{
    ModelRing, StressDriver, validate_stress_report,
};
use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

fn manifest_path(root: &Path) -> PathBuf {
    root.join("tests")
        .join("conformance")
        .join("evidence_ring_backpressure_stress_contract.v1.json")
}

fn load_manifest() -> TestResult<Value> {
    let root = workspace_root()?;
    let path = manifest_path(&root);
    let content = std::fs::read_to_string(&path).map_err(|err| format!("read {path:?}: {err}"))?;
    serde_json::from_str(&content).map_err(|err| format!("parse {path:?}: {err}"))
}

fn require(condition: bool, message: impl Into<String>) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn json_field<'a>(value: &'a Value, field: &str) -> TestResult<&'a Value> {
    value
        .get(field)
        .ok_or_else(|| format!("missing field `{field}`"))
}

fn json_array<'a>(value: &'a Value, field: &str) -> TestResult<&'a Vec<Value>> {
    json_field(value, field)?
        .as_array()
        .ok_or_else(|| format!("`{field}` must be an array"))
}

fn json_string<'a>(value: &'a Value, field: &str) -> TestResult<&'a str> {
    json_field(value, field)?
        .as_str()
        .ok_or_else(|| format!("`{field}` must be a string"))
}

fn json_bool(value: &Value, field: &str) -> TestResult<bool> {
    json_field(value, field)?
        .as_bool()
        .ok_or_else(|| format!("`{field}` must be a bool"))
}

#[test]
fn manifest_anchors_to_juvqm7() -> TestResult {
    let m = load_manifest()?;
    require(
        json_string(&m, "manifest_id")? == "evidence-ring-backpressure-stress-contract",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-juvqm.7", "bead")?;
    require(
        json_string(&m, "anchored_baseline_manifest")?
            == "tests/conformance/high_core_tail_baseline.v1.json",
        "anchored baseline",
    )?;
    require(
        json_string(&m, "tail_statistics_contract_owner")? == "bd-juvqm.11",
        "tail stats contract owner",
    )
}

#[test]
fn five_required_ring_paths_are_present_with_required_fields() -> TestResult {
    let m = load_manifest()?;
    let required: BTreeSet<&str> = json_array(&m, "required_ring_path_fields")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let needed: [&str; 10] = [
        "ring_id",
        "owner_subsystem",
        "capacity",
        "expected_loss_semantics",
        "monotone_seqno_required",
        "evidence_loss_count_field",
        "max_epoch_field",
        "redaction_cardinality_limit",
        "deterministic_serialization_after_overwrite",
        "downstream_replay_treatment",
    ];
    for f in needed {
        require(
            required.contains(f),
            format!("required_ring_path_fields must include {f}"),
        )?;
    }

    let ring_paths = json_array(&m, "ring_paths")?;
    require(ring_paths.len() == 5, "must have 5 ring paths")?;

    let expected_ring_ids: BTreeSet<&str> = [
        "runtime_math.decision_card_ring",
        "runtime_math.evidence_symbol_ring",
        "structured_log.event_ring",
        "stdio.evidence_row_ring",
        "membrane.validation_log_ring",
    ]
    .into_iter()
    .collect();
    let observed_ring_ids: BTreeSet<&str> = ring_paths
        .iter()
        .filter_map(|r| r.get("ring_id").and_then(Value::as_str))
        .collect();
    require(
        observed_ring_ids == expected_ring_ids,
        format!(
            "ring_id set must match contract; expected {expected_ring_ids:?}, got {observed_ring_ids:?}"
        ),
    )?;

    // Every row must populate every required field.
    for row in ring_paths {
        for f in needed {
            require(
                row.get(f).is_some(),
                format!(
                    "ring path {:?} missing required field {f}",
                    row.get("ring_id")
                ),
            )?;
        }
        require(
            json_bool(row, "monotone_seqno_required")?,
            "monotone_seqno_required must be true on every row",
        )?;
        require(
            json_bool(row, "deterministic_serialization_after_overwrite")?,
            "deterministic_serialization_after_overwrite must be true on every row",
        )?;
        require(
            json_string(row, "expected_loss_semantics")? == "overwrite_oldest",
            "expected_loss_semantics must be overwrite_oldest",
        )?;
    }
    Ok(())
}

#[test]
fn policy_fails_closed_on_required_kinds() -> TestResult {
    let m = load_manifest()?;
    let policy = json_field(&m, "policy")?;
    for f in [
        "fail_closed_when_ring_path_unaccounted",
        "fail_closed_when_seqno_non_monotone",
        "fail_closed_when_loss_count_field_missing",
        "fail_closed_when_max_epoch_field_missing",
        "fail_closed_when_redaction_cardinality_unbounded",
        "fail_closed_when_serialization_non_deterministic_post_overwrite",
        "fail_closed_when_loss_evidence_kind_undocumented",
        "fail_closed_when_source_commit_stale",
    ] {
        require(json_bool(policy, f)?, format!("{f} must be true"))?;
    }

    let rejected: BTreeSet<&str> = json_array(policy, "rejected_evidence_kinds")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for kind in [
        "missing_ring_path_row",
        "non_monotone_seqno",
        "missing_loss_count_field",
        "missing_max_epoch_field",
        "unbounded_redaction_cardinality",
        "non_deterministic_post_overwrite",
        "undocumented_loss_evidence_kind",
        "stale_source_commit",
    ] {
        require(
            rejected.contains(kind),
            format!("rejected_evidence_kinds must include {kind}"),
        )?;
    }
    Ok(())
}

#[test]
fn loss_evidence_kinds_split_pass_and_fail_closed() -> TestResult {
    let m = load_manifest()?;
    let kinds = json_array(&m, "loss_evidence_kinds")?;
    let mut pass_count = 0;
    let mut fail_count = 0;
    for k in kinds {
        let kind = json_string(k, "kind")?;
        let fail_closed = json_bool(k, "fail_closed")?;
        // Only one kind is fail_closed=false: expected_overwrite_loss.
        if fail_closed {
            fail_count += 1;
        } else {
            require(
                kind == "expected_overwrite_loss",
                format!("only `expected_overwrite_loss` may be fail_closed=false, saw {kind}"),
            )?;
            pass_count += 1;
        }
    }
    require(
        pass_count == 1,
        format!("exactly one pass-through loss kind required, saw {pass_count}"),
    )?;
    require(
        fail_count == 4,
        format!("expected 4 fail-closed loss kinds, saw {fail_count}"),
    )?;
    Ok(())
}

#[test]
fn stress_drive_exercises_overwrite_semantics_and_passes_validator() -> TestResult {
    let mut ring = ModelRing::new(64, 128);
    let driver = StressDriver::new(0xc0ffee_u64, 4);
    let report = driver.run(&mut ring);
    require(report.snapshot_size == 64, "snapshot_size must equal cap")?;
    require(
        report.evidence_loss_count == report.observed_seqno_gap,
        format!(
            "evidence_loss_count {} must equal observed_seqno_gap {}",
            report.evidence_loss_count, report.observed_seqno_gap
        ),
    )?;
    require(
        report.max_epoch >= 3,
        format!(
            "drive=4 must produce max_epoch >= 3, got {}",
            report.max_epoch
        ),
    )?;
    let rej = validate_stress_report(&report);
    require(
        rej.is_empty(),
        format!("clean stress report must validate cleanly; got {rej:?}"),
    )
}

#[test]
fn stress_drive_serialization_is_deterministic_under_same_seed() -> TestResult {
    let mut a = ModelRing::new(64, 128);
    let mut b = ModelRing::new(64, 128);
    let driver = StressDriver::new(0xdeadbeef_u64, 4);
    let ra = driver.run(&mut a);
    let rb = driver.run(&mut b);
    require(
        ra.snapshot_serialization == rb.snapshot_serialization,
        "snapshot_serialization must be byte-identical under same seed",
    )?;
    require(
        ra.evidence_loss_count == rb.evidence_loss_count,
        "loss_count",
    )?;
    require(ra.max_epoch == rb.max_epoch, "max_epoch")?;
    Ok(())
}

#[test]
fn validator_rejects_loss_count_underreporting_gap() -> TestResult {
    let mut ring = ModelRing::new(64, 128);
    let driver = StressDriver::new(7, 4);
    let mut report = driver.run(&mut ring);
    // Underreport the loss_count by 1.
    report.evidence_loss_count -= 1;
    let rej = validate_stress_report(&report);
    require(
        rej.contains(&"loss_count_underreports_gap".to_string()),
        format!("validator must reject loss_count underreporting; got {rej:?}"),
    )
}

#[test]
fn validator_rejects_unbounded_redaction_cardinality() -> TestResult {
    let mut ring = ModelRing::new(64, 128);
    let driver = StressDriver::new(7, 4);
    let mut report = driver.run(&mut ring);
    report.redaction_cardinality_limit = 0;
    let rej = validate_stress_report(&report);
    require(
        rej.contains(&"unbounded_redaction_cardinality".to_string()),
        format!("validator must reject unbounded redaction cardinality; got {rej:?}"),
    )
}

#[test]
fn real_runtime_evidence_ring_overwrites_and_seqno_is_monotone() -> TestResult {
    use frankenlibc_membrane::SafetyLevel;
    use frankenlibc_membrane::runtime_math::evidence::{
        EVIDENCE_SYMBOL_SIZE_T, EvidenceRingBuffer, EvidenceSymbolRecord, FLAG_SYSTEMATIC,
    };
    use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction, ValidationProfile};

    const CAP: usize = 16;
    let ring: EvidenceRingBuffer<CAP> = EvidenceRingBuffer::new();
    let total = (CAP * 4) as u64;
    for i in 0..total {
        let seq = ring.allocate_seqno();
        let payload = [i as u8; EVIDENCE_SYMBOL_SIZE_T];
        let rec = EvidenceSymbolRecord::build_v1(
            1,
            seq,
            2,
            ApiFamily::Allocator,
            SafetyLevel::Strict,
            MembraneAction::Allow,
            ValidationProfile::Fast,
            FLAG_SYSTEMATIC,
            0,
            256,
            0,
            0,
            &payload,
            None,
        );
        ring.publish(seq, rec);
    }
    let snap = ring.snapshot_sorted();
    require(
        snap.len() <= CAP,
        format!(
            "real ring snapshot {} must not exceed CAP={CAP}",
            snap.len()
        ),
    )?;
    require(
        snap.last().unwrap().seqno() == total,
        format!(
            "real ring last seqno must be {total}, saw {}",
            snap.last().unwrap().seqno()
        ),
    )?;
    let mut last_seqno = 0;
    for r in &snap {
        require(
            r.seqno() > last_seqno,
            format!(
                "real ring seqno must be monotone; {} <= {last_seqno}",
                r.seqno()
            ),
        )?;
        last_seqno = r.seqno();
    }
    // Real ring does NOT export evidence_loss_count directly; derived
    // loss = total - snap.len() must be >= total - CAP.
    let derived_loss = total - snap.len() as u64;
    require(
        derived_loss >= total - CAP as u64,
        format!(
            "real ring derived loss {derived_loss} must >= {} (drive past capacity)",
            total - CAP as u64
        ),
    )
}
