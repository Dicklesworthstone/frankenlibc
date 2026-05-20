//! Conformance gate for the membrane concurrency bounded model check
//! (bd-juvqm.8).
//!
//! Validates the manifest schema + runs the seqlock model checker via
//! `frankenlibc_harness::concurrency_model_check::check_seqlock` and
//! asserts:
//!   * Schedules-explored count matches the manifest's stated bound.
//!   * No invariant violations on the canonical seqlock model.
//!   * Failure output (when synthesized) carries a schedule label
//!     identifying the violated invariant + step interleaving.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use frankenlibc_harness::concurrency_model_check::{InvariantViolation, check_seqlock};
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
        .join("membrane_concurrency_bounded_model_check.v1.json")
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
    value.get(field).ok_or_else(|| format!("missing `{field}`"))
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

fn json_u64(value: &Value, field: &str) -> TestResult<u64> {
    json_field(value, field)?
        .as_u64()
        .ok_or_else(|| format!("`{field}` must be a u64"))
}

fn git_stdout(root: &Path, args: &[&str]) -> TestResult<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .map_err(|err| format!("run git {args:?}: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    String::from_utf8(output.stdout)
        .map_err(|err| format!("git {args:?} emitted non-utf8 stdout: {err}"))
}

fn is_hex_commit(value: &str) -> bool {
    value.len() == 40 && value.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn validate_manifest_source_commit_freshness(manifest: &Value) -> TestResult {
    let source_commit = json_string(manifest, "source_commit")?;
    require(
        is_hex_commit(source_commit),
        "source_commit must be a 40-character git commit",
    )?;

    let policy = json_field(manifest, "policy")?;
    require(
        json_bool(policy, "fail_closed_when_source_commit_stale")?,
        "policy.fail_closed_when_source_commit_stale must be true",
    )?;
    require(
        json_string(policy, "stale_source_commit_freshness_target")? == "current git HEAD",
        "policy.stale_source_commit_freshness_target must be current git HEAD",
    )?;

    let freshness = json_field(manifest, "source_commit_freshness")?;
    require(
        json_bool(
            freshness,
            "require_no_tracked_source_changes_since_source_commit",
        )?,
        "source_commit_freshness must require no tracked source changes",
    )?;
    let roots = json_array(freshness, "tracked_source_roots")?;
    require(!roots.is_empty(), "tracked_source_roots must not be empty")?;
    let root_strings: Vec<&str> = roots
        .iter()
        .map(|root| {
            root.as_str()
                .ok_or_else(|| "tracked_source_roots entries must be strings".to_string())
        })
        .collect::<Result<_, _>>()?;

    let repo = workspace_root()?;
    git_stdout(
        &repo,
        &["cat-file", "-e", &format!("{source_commit}^{{commit}}")],
    )?;
    let commit_range = format!("{source_commit}..HEAD");
    let mut args = vec!["diff", "--name-only", commit_range.as_str(), "--"];
    args.extend(root_strings);
    let changed = git_stdout(&repo, &args)?;
    let changed_paths: Vec<&str> = changed.lines().filter(|line| !line.is_empty()).collect();
    require(
        changed_paths.is_empty(),
        format!(
            "source_commit {source_commit} is stale for membrane concurrency model roots: {changed_paths:?}"
        ),
    )
}

#[test]
fn manifest_anchors_to_juvqm8_with_seqlock_primitive() -> TestResult {
    let m = load_manifest()?;
    require(
        json_string(&m, "manifest_id")? == "membrane-concurrency-bounded-model-check",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-juvqm.8", "bead")?;
    let pr = json_field(&m, "primitive_under_check")?;
    require(
        json_string(pr, "name")? == "SeqlockCounter",
        "primitive name",
    )?;
    require(json_u64(pr, "writer_step_count")? == 3, "writer step count")?;
    require(json_u64(pr, "reader_step_count")? == 4, "reader step count")
}

#[test]
fn model_bounds_match_combinatorial_count() -> TestResult {
    let m = load_manifest()?;
    let bounds = json_field(&m, "model_bounds")?;
    require(json_u64(bounds, "writers_modeled")? == 1, "writers_modeled")?;
    require(json_u64(bounds, "readers_modeled")? == 1, "readers_modeled")?;
    require(
        json_u64(bounds, "expected_schedule_count_for_one_write")? == 35,
        "1-write schedule count = 7!/(3!4!) = 35",
    )?;
    require(
        json_u64(bounds, "expected_schedule_count_for_two_writes")? == 210,
        "2-write schedule count = 10!/(6!4!) = 210",
    )
}

#[test]
fn invariants_proved_set_is_complete() -> TestResult {
    let m = load_manifest()?;
    let proved: BTreeSet<&str> = json_array(&m, "invariants_proved")?
        .iter()
        .filter_map(|i| i.get("invariant_id").and_then(Value::as_str))
        .collect();
    for id in [
        "no_torn_read_accepted",
        "no_stable_read_at_odd_version",
        "no_missed_writer_publication",
        "monotone_retry_diagnostic",
    ] {
        require(
            proved.contains(id),
            format!("invariants_proved must contain {id}"),
        )?;
    }
    Ok(())
}

#[test]
fn invariants_outside_bound_documented_honestly() -> TestResult {
    let m = load_manifest()?;
    let outside: BTreeSet<&str> = json_array(&m, "invariants_outside_bound")?
        .iter()
        .filter_map(|i| i.get("invariant_id").and_then(Value::as_str))
        .collect();
    for id in [
        "memory_model_relaxed_orderings",
        "multi_writer_interleavings",
        "schedule_count_above_two_writes",
    ] {
        require(
            outside.contains(id),
            format!("invariants_outside_bound must contain {id}"),
        )?;
    }
    Ok(())
}

#[test]
fn policy_fails_closed_on_required_kinds() -> TestResult {
    let m = load_manifest()?;
    let policy = json_field(&m, "policy")?;
    for f in [
        "fail_closed_when_invariant_violation_present",
        "fail_closed_when_schedules_explored_below_expected",
        "fail_closed_when_source_commit_stale",
        "fail_closed_when_failure_output_missing_schedule_label",
    ] {
        require(json_bool(policy, f)?, format!("{f} must be true"))?;
    }
    let rejected: BTreeSet<&str> = json_array(policy, "rejected_evidence_kinds")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for k in [
        "invariant_violation_present",
        "incomplete_schedule_enumeration",
        "stale_source_commit",
        "missing_schedule_label_on_violation",
        "primitive_under_check_drift",
    ] {
        require(
            rejected.contains(k),
            format!("rejected_evidence_kinds must include {k}"),
        )?;
    }
    Ok(())
}

#[test]
fn manifest_source_commit_is_fresh_for_model_roots() -> TestResult {
    let m = load_manifest()?;
    validate_manifest_source_commit_freshness(&m)
}

#[test]
fn fixture_invalid_manifest_source_commit_is_rejected() -> TestResult {
    let mut m = load_manifest()?;
    m["source_commit"] = Value::String("0000000000000000000000000000000000000000".to_string());
    let err = validate_manifest_source_commit_freshness(&m)
        .expect_err("invalid manifest source_commit must be rejected");
    require(
        err.contains("git") || err.contains("source_commit"),
        format!("unexpected invalid source_commit error: {err}"),
    )
}

#[test]
fn fixture_stale_manifest_source_commit_is_rejected() -> TestResult {
    let mut m = load_manifest()?;
    m["source_commit"] = Value::String("7fae3d3d05b50e71aafbf232771d447cfd74f67b".to_string());
    let err = validate_manifest_source_commit_freshness(&m)
        .expect_err("stale manifest source_commit must be rejected");
    require(
        err.contains("stale") || err.contains("git"),
        format!("unexpected stale source_commit error: {err}"),
    )
}

#[test]
fn live_model_check_one_write_explores_thirty_five_schedules_with_no_violations() -> TestResult {
    let report = check_seqlock(1);
    require(
        report.schedules_explored == 35,
        format!("expected 35 schedules; got {}", report.schedules_explored),
    )?;
    require(
        report.invariant_violations.is_empty(),
        format!(
            "no invariant violations expected; got {:?}",
            report.invariant_violations
        ),
    )?;
    require(
        report.stable_outcomes > 0 && report.retry_outcomes > 0,
        "exhaustive enumeration must produce both Stable and Retry outcomes",
    )
}

#[test]
fn live_model_check_two_writes_explores_two_hundred_ten_schedules_with_no_violations() -> TestResult
{
    let report = check_seqlock(2);
    require(
        report.schedules_explored == 210,
        format!("expected 210 schedules; got {}", report.schedules_explored),
    )?;
    require(
        report.invariant_violations.is_empty(),
        format!(
            "no invariant violations expected; got {:?}",
            report.invariant_violations
        ),
    )
}

#[test]
fn invariant_violation_carries_named_kind_and_schedule_steps() -> TestResult {
    // Synthesize a violation and prove the failure output carries
    // both the violation kind AND the minimal schedule.
    let v = InvariantViolation::StaleReadAccepted {
        read_val: 99,
        published: vec![1, 2],
        schedule: vec![
            "R:load_ver_before".into(),
            "W:ver_odd".into(),
            "R:load_val".into(),
            "W:set_val".into(),
            "R:load_ver_after".into(),
            "W:ver_even".into(),
            "R:decide".into(),
        ],
    };
    match v {
        InvariantViolation::StaleReadAccepted { schedule, .. } => {
            require(
                schedule.iter().any(|s| s.starts_with("R:")),
                "schedule must contain reader steps",
            )?;
            require(
                schedule.iter().any(|s| s.starts_with("W:")),
                "schedule must contain writer steps",
            )?;
            require(
                schedule.len() == 7,
                "schedule must list every step (3 W + 4 R = 7)",
            )?;
        }
        _ => return Err("unexpected violation kind".into()),
    }
    Ok(())
}

#[test]
fn summary_anchors_to_explored_schedule_count() -> TestResult {
    let m = load_manifest()?;
    let summary = json_field(&m, "summary")?;
    // 35 (1-write) + 210 (2-write) = 245 total schedules across the
    // two probe runs.
    require(
        json_u64(summary, "schedule_count_explored")? == 245,
        "summary schedule_count_explored",
    )?;
    require(
        json_u64(summary, "invariant_count_proved")? == 4,
        "summary invariant_count_proved",
    )?;
    require(
        json_u64(summary, "invariant_count_outside_bound")? == 3,
        "summary invariant_count_outside_bound",
    )?;
    require(
        json_string(summary, "claim_status")? == "bounded_model_clean",
        "summary claim_status",
    )
}
