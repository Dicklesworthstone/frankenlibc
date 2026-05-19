//! Integration coverage for the standalone blocker dependency explainer.
//!
//! The explainer is the guard that keeps `bd-c51oi` open while the default
//! standalone forge remains claim-blocked, even after report-only burndown
//! experiments prove narrower future lanes.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

const CONTRACT_REL: &str = "tests/conformance/standalone_blocker_dependency_explainer.v1.json";
const CHECKER_REL: &str = "scripts/check_standalone_blocker_dependency_explainer.sh";
const TRACKER_REL: &str = ".beads/issues.jsonl";
const ROLLUP_REL: &str = "tests/conformance/standalone_blocker_burndown_progress_rollup.v1.json";

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

fn load_json(path: &Path) -> TestResult<Value> {
    let content =
        std::fs::read_to_string(path).map_err(|err| format!("{}: {err}", path.display()))?;
    serde_json::from_str(&content).map_err(|err| format!("{}: {err}", path.display()))
}

fn json_field<'a>(value: &'a Value, field: &str) -> TestResult<&'a Value> {
    value
        .get(field)
        .ok_or_else(|| format!("{field} must be present"))
}

fn json_string<'a>(value: &'a Value, field: &str) -> TestResult<&'a str> {
    json_field(value, field)?
        .as_str()
        .ok_or_else(|| format!("{field} must be a string"))
}

fn json_array<'a>(value: &'a Value, field: &str) -> TestResult<&'a Vec<Value>> {
    json_field(value, field)?
        .as_array()
        .ok_or_else(|| format!("{field} must be an array"))
}

fn string_set(value: &Value, field: &str) -> TestResult<HashSet<String>> {
    json_array(value, field)?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("{field} entries must be strings"))
        })
        .collect()
}

fn require(condition: bool, message: impl Into<String>) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn unique_label(prefix: &str) -> TestResult<String> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| format!("system time before UNIX_EPOCH: {err}"))?
        .as_nanos();
    Ok(format!("{prefix}-{}-{nanos}", std::process::id()))
}

fn format_output(output: &Output) -> String {
    format!(
        "status={}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[derive(Default)]
struct CheckerInputs {
    tracker: Option<PathBuf>,
    rollup: Option<PathBuf>,
}

fn run_checker(root: &Path, label: &str, inputs: CheckerInputs) -> TestResult<(Output, PathBuf)> {
    let report = root.join("target/conformance").join(format!(
        "standalone_blocker_dependency_explainer.{label}.report.json"
    ));
    let rollup_report = root.join("target/conformance").join(format!(
        "standalone_blocker_dependency_explainer.{label}.rollup.report.json"
    ));
    let mut command = Command::new("bash");
    command
        .arg(root.join(CHECKER_REL))
        .env("FRANKENLIBC_STANDALONE_BLOCKER_EXPLAINER_REPORT", &report)
        .env(
            "FRANKENLIBC_STANDALONE_BLOCKER_ROLLUP_REPORT",
            &rollup_report,
        )
        .current_dir(root);
    if let Some(tracker) = inputs.tracker {
        command.env("FRANKENLIBC_TRACKER_JSONL", tracker);
    }
    if let Some(rollup) = inputs.rollup {
        command.env("FRANKENLIBC_STANDALONE_BLOCKER_ROLLUP", rollup);
    }
    let output = command
        .output()
        .map_err(|err| format!("failed to run dependency explainer checker: {err}"))?;
    Ok((output, report))
}

fn expect_checker_failure(
    root: &Path,
    label: &str,
    inputs: CheckerInputs,
    expected_error: &str,
) -> TestResult {
    let (output, report) = run_checker(root, label, inputs)?;
    require(
        !output.status.success(),
        format!("checker unexpectedly passed\n{}", format_output(&output)),
    )?;
    let report_json = load_json(&report)?;
    let errors = json_array(&report_json, "errors")?;
    require(
        errors
            .iter()
            .filter_map(Value::as_str)
            .any(|error| error.contains(expected_error)),
        format!("expected error {expected_error:?}; report={report_json:?}"),
    )
}

fn mutation_dir(root: &Path) -> TestResult<PathBuf> {
    let dir = root.join("target/conformance/mutated-standalone-blocker-dependency-explainer");
    std::fs::create_dir_all(&dir).map_err(|err| format!("{}: {err}", dir.display()))?;
    Ok(dir)
}

fn write_mutated_tracker(
    root: &Path,
    label: &str,
    mutate: impl Fn(&mut Value) -> TestResult,
) -> TestResult<PathBuf> {
    let source = root.join(TRACKER_REL);
    let content =
        std::fs::read_to_string(&source).map_err(|err| format!("{}: {err}", source.display()))?;
    let mut found = false;
    let mut lines = Vec::new();
    for line in content.lines() {
        let mut row: Value =
            serde_json::from_str(line).map_err(|err| format!("{}: {err}", source.display()))?;
        if row.get("id").and_then(Value::as_str) == Some("bd-c51oi") {
            mutate(&mut row)?;
            found = true;
        }
        lines.push(
            serde_json::to_string(&row)
                .map_err(|err| format!("failed to serialize tracker row: {err}"))?,
        );
    }
    require(found, "mutated tracker must contain bd-c51oi")?;
    let path = mutation_dir(root)?.join(format!("{}.issues.jsonl", unique_label(label)?));
    std::fs::write(&path, format!("{}\n", lines.join("\n")))
        .map_err(|err| format!("{}: {err}", path.display()))?;
    Ok(path)
}

fn write_tracker_with_blocker_mutation(
    root: &Path,
    label: &str,
    mutate: impl Fn(&mut Value) -> TestResult,
) -> TestResult<PathBuf> {
    let source = root.join(TRACKER_REL);
    let content =
        std::fs::read_to_string(&source).map_err(|err| format!("{}: {err}", source.display()))?;
    let mut found = false;
    let mut lines = Vec::new();
    for line in content.lines() {
        let mut row: Value =
            serde_json::from_str(line).map_err(|err| format!("{}: {err}", source.display()))?;
        if row.get("id").and_then(Value::as_str) == Some("bd-716tv") {
            mutate(&mut row)?;
            found = true;
        }
        lines.push(
            serde_json::to_string(&row)
                .map_err(|err| format!("failed to serialize tracker row: {err}"))?,
        );
    }
    require(found, "mutated tracker must contain bd-716tv")?;
    let path = mutation_dir(root)?.join(format!("{}.issues.jsonl", unique_label(label)?));
    std::fs::write(&path, format!("{}\n", lines.join("\n")))
        .map_err(|err| format!("{}: {err}", path.display()))?;
    Ok(path)
}

fn write_mutated_rollup(
    root: &Path,
    label: &str,
    mutate: impl FnOnce(&mut Value) -> TestResult,
) -> TestResult<PathBuf> {
    let mut rollup = load_json(&root.join(ROLLUP_REL))?;
    mutate(&mut rollup)?;
    let path = mutation_dir(root)?.join(format!("{}.rollup.json", unique_label(label)?));
    let content = serde_json::to_string_pretty(&rollup)
        .map_err(|err| format!("failed to serialize mutated rollup: {err}"))?;
    std::fs::write(&path, format!("{content}\n"))
        .map_err(|err| format!("{}: {err}", path.display()))?;
    Ok(path)
}

#[test]
fn contract_names_the_claim_and_negative_controls() -> TestResult {
    let root = workspace_root()?;
    let contract = load_json(&root.join(CONTRACT_REL))?;
    require(
        json_string(&contract, "manifest_id")? == "standalone_blocker_dependency_explainer",
        "manifest id",
    )?;
    require(json_string(&contract, "bead")? == "bd-i1fwe", "bead")?;
    require(
        json_string(&contract, "refresh_bead")? == "bd-kh0jc",
        "refresh bead",
    )?;
    let target = json_field(&contract, "target_issue_contract")?;
    require(
        json_string(target, "target_issue_id")? == "bd-c51oi",
        "target issue id",
    )?;
    require(
        json_string(target, "target_issue_must_remain_status")? == "in_progress",
        "target issue status",
    )?;
    require(
        json_string(target, "retired_blocker_issue_id")? == "bd-716tv",
        "retired blocker id",
    )?;

    let claim = json_field(&contract, "standalone_claim_contract")?;
    require(
        json_string(claim, "rollup_claim_status")? == "claim_blocked",
        "rollup claim status",
    )?;
    require(
        json_field(claim, "promotion_allowed")?.as_bool() == Some(false),
        "claim contract must forbid promotion",
    )?;
    let required_experiments = string_set(claim, "required_partial_experiments")?;
    require(
        required_experiments.contains("owned-unwind-stub-experiment"),
        "owned-unwind report-only experiment must be required",
    )?;
    require(
        required_experiments.contains("owned-tls-cache-source-surface-experiment"),
        "owned-TLS report-only experiment must be required",
    )?;

    let controls: HashSet<_> = json_array(&contract, "negative_controls")?
        .iter()
        .map(|row| json_string(row, "expected_error").map(str::to_owned))
        .collect::<TestResult<_>>()?;
    for expected in [
        "target_has_retired_dependency",
        "target_status_not_in_progress",
        "retired_blocker_status_not_closed",
        "partial_experiment_allows_promotion",
    ] {
        require(
            controls.contains(expected),
            format!("missing negative control for {expected}"),
        )?;
    }
    Ok(())
}

#[test]
fn checker_materializes_claim_blockers_and_report_only_experiments() -> TestResult {
    let root = workspace_root()?;
    let (output, report) = run_checker(&root, "canonical", CheckerInputs::default())?;
    require(
        output.status.success(),
        format!("canonical checker failed\n{}", format_output(&output)),
    )?;
    let report_json = load_json(&report)?;
    require(
        json_string(&report_json, "status")? == "pass",
        "canonical report status",
    )?;
    let target = json_field(&report_json, "target_issue")?;
    require(json_string(target, "id")? == "bd-c51oi", "target issue")?;
    require(
        json_string(target, "status")? == "in_progress",
        "target stays in progress",
    )?;
    let blocker = json_field(&report_json, "blocker_dependency")?;
    require(
        json_string(blocker, "relationship")? == "retired",
        "blocker relationship",
    )?;
    require(
        json_field(blocker, "edge_present")?.as_bool() == Some(false),
        "retired dependency edge must stay absent",
    )?;
    let claim = json_field(&report_json, "standalone_claim_state")?;
    require(
        json_string(claim, "claim_status")? == "claim_blocked",
        "standalone claim stays blocked",
    )?;
    let summary = json_field(claim, "summary")?;
    require(
        json_field(summary, "promotion_allowed")?.as_bool() == Some(false),
        "rollup summary forbids promotion",
    )?;
    require(
        json_field(summary, "current_blocking_reason_count")?.as_u64() == Some(10),
        "current blocking reason count",
    )?;
    require(
        json_field(summary, "blocked_progress_category_count")?.as_u64() == Some(8),
        "blocked progress category count",
    )?;

    let experiments = json_array(&report_json, "partial_burndown_experiments")?;
    require(experiments.len() == 2, "two partial experiments")?;
    for experiment in experiments {
        let experiment_id = json_string(experiment, "experiment_id")?;
        require(
            json_field(experiment, "report_only")?.as_bool() == Some(true),
            format!("{experiment_id}: must stay report-only"),
        )?;
        require(
            json_field(experiment, "default_forge_path_unchanged")?.as_bool() == Some(true),
            format!("{experiment_id}: must leave default forge unchanged"),
        )?;
        require(
            json_field(experiment, "promotion_allowed")?.as_bool() == Some(false),
            format!("{experiment_id}: must not allow promotion"),
        )?;
    }
    let negative_controls = json_array(&report_json, "negative_controls")?;
    require(negative_controls.len() == 4, "four negative controls")?;
    for control in negative_controls {
        require(
            json_string(control, "status")? == "pass",
            format!("negative control {:?} must pass", control.get("control_id")),
        )?;
    }
    Ok(())
}

#[test]
fn checker_rejects_retired_dependency_reintroduction() -> TestResult {
    let root = workspace_root()?;
    let tracker = write_mutated_tracker(&root, "retired-dependency", |row| {
        let deps = row
            .as_object_mut()
            .ok_or_else(|| "bd-c51oi row must be object".to_string())?
            .entry("dependencies")
            .or_insert_with(|| Value::Array(Vec::new()));
        let deps = deps
            .as_array_mut()
            .ok_or_else(|| "bd-c51oi dependencies must be array".to_string())?;
        deps.push(serde_json::json!({
            "issue_id": "bd-c51oi",
            "depends_on_id": "bd-716tv",
            "type": "blocks"
        }));
        Ok(())
    })?;
    expect_checker_failure(
        &root,
        "retired-dependency",
        CheckerInputs {
            tracker: Some(tracker),
            rollup: None,
        },
        "target_has_retired_dependency",
    )
}

#[test]
fn checker_rejects_premature_parent_closure() -> TestResult {
    let root = workspace_root()?;
    let tracker = write_mutated_tracker(&root, "premature-closure", |row| {
        row.as_object_mut()
            .ok_or_else(|| "bd-c51oi row must be object".to_string())?
            .insert("status".to_owned(), Value::String("closed".to_owned()));
        Ok(())
    })?;
    expect_checker_failure(
        &root,
        "premature-closure",
        CheckerInputs {
            tracker: Some(tracker),
            rollup: None,
        },
        "target_status_not_in_progress",
    )
}

#[test]
fn checker_rejects_retired_blocker_reopening() -> TestResult {
    let root = workspace_root()?;
    let tracker = write_tracker_with_blocker_mutation(&root, "blocker-reopened", |row| {
        row.as_object_mut()
            .ok_or_else(|| "bd-716tv row must be object".to_string())?
            .insert("status".to_owned(), Value::String("in_progress".to_owned()));
        Ok(())
    })?;
    expect_checker_failure(
        &root,
        "blocker-reopened",
        CheckerInputs {
            tracker: Some(tracker),
            rollup: None,
        },
        "retired_blocker_status_not_closed",
    )
}

#[test]
fn checker_rejects_report_only_experiment_promotion() -> TestResult {
    let root = workspace_root()?;
    let rollup = write_mutated_rollup(&root, "experiment-promotion", |rollup| {
        let experiments = rollup
            .get_mut("partial_burndown_experiments")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| "partial_burndown_experiments must be array".to_string())?;
        let first = experiments
            .first_mut()
            .ok_or_else(|| "partial_burndown_experiments must not be empty".to_string())?;
        first
            .as_object_mut()
            .ok_or_else(|| "partial experiment row must be object".to_string())?
            .insert("promotion_allowed".to_owned(), Value::Bool(true));
        Ok(())
    })?;
    expect_checker_failure(
        &root,
        "experiment-promotion",
        CheckerInputs {
            tracker: None,
            rollup: Some(rollup),
        },
        "partial_experiment_allows_promotion",
    )
}
