//! Integration test: targeted closure beads for feature-parity owner-family rows (bd-bp8fl.3.3)
//!
//! The gate proves that each owner-family row in
//! `feature_parity_gap_owner_family_groups.v1.md` has a concrete follow-up
//! bead, a current tracker row, replay obligations, and structured failure
//! logs. Duplicate or stale mappings fail closed before a closure claim can
//! hide uncovered feature-parity gaps.

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const EXPECTED_ROWS: &[(&str, &str, u64)] = &[
    ("fpg-claim-control", "bd-bp8fl.3.5", 8),
    ("fpg-reverse-runtime-core", "bd-bp8fl.3.6", 10),
    ("fpg-reverse-loader-process-abi", "bd-bp8fl.3.7", 10),
    ("fpg-proof-core-safety", "bd-bp8fl.3.8", 7),
    ("fpg-proof-online-control", "bd-bp8fl.3.9", 13),
    ("fpg-proof-coverage-interaction", "bd-bp8fl.3.10", 10),
    ("fpg-proof-algebraic-topological", "bd-bp8fl.3.11", 15),
    ("fpg-gap-summary-evidence-foundation", "bd-bp8fl.3.12", 7),
    (
        "fpg-gap-summary-ported-surface-evidence",
        "bd-bp8fl.3.13",
        10,
    ),
    (
        "fpg-gap-summary-runtime-monitor-evidence",
        "bd-bp8fl.3.14",
        21,
    ),
];

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "source_row_id",
    "created_issue_id",
    "missing_evidence_type",
    "expected",
    "actual",
    "artifact_refs",
    "failure_signature",
];

fn test_error(message: impl Into<String>) -> Box<dyn Error> {
    std::io::Error::other(message.into()).into()
}

fn ensure(condition: bool, message: impl Into<String>) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(test_error(message))
    }
}

fn ensure_eq<T>(actual: T, expected: T, context: impl Into<String>) -> TestResult
where
    T: std::fmt::Debug + PartialEq,
{
    if actual == expected {
        Ok(())
    } else {
        Err(test_error(format!(
            "{}: expected {:?}, got {:?}",
            context.into(),
            expected,
            actual
        )))
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn artifact_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/feature_parity_targeted_closure_beads.v1.json")
}

fn group_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/feature_parity_gap_groups.v1.json")
}

fn owner_family_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/feature_parity_gap_owner_family_groups.v1.md")
}

fn script_path(root: &Path) -> PathBuf {
    root.join("scripts/check_feature_parity_targeted_closure_beads.sh")
}

fn load_json(path: &Path) -> TestResult<Value> {
    let content = std::fs::read_to_string(path)
        .map_err(|err| test_error(format!("{} should be readable: {err}", path.display())))?;
    serde_json::from_str(&content)
        .map_err(|err| test_error(format!("{} should parse as JSON: {err}", path.display())))
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    let content = serde_json::to_string_pretty(value)
        .map_err(|err| test_error(format!("{} serialization failed: {err}", path.display())))?;
    std::fs::write(path, format!("{content}\n"))
        .map_err(|err| test_error(format!("{} write failed: {err}", path.display())))
}

fn read_text(path: &Path) -> TestResult<String> {
    std::fs::read_to_string(path)
        .map_err(|err| test_error(format!("{} should be readable: {err}", path.display())))
}

fn as_array<'a>(value: &'a Value, context: &str) -> TestResult<&'a Vec<Value>> {
    value
        .as_array()
        .ok_or_else(|| test_error(format!("{context} must be an array")))
}

fn as_str<'a>(value: &'a Value, context: &str) -> TestResult<&'a str> {
    value
        .as_str()
        .ok_or_else(|| test_error(format!("{context} must be a string")))
}

fn unique_temp_dir(prefix: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| test_error(format!("system clock should be after Unix epoch: {err}")))?
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir)
        .map_err(|err| test_error(format!("{} mkdir failed: {err}", dir.display())))?;
    Ok(dir)
}

fn repo_path(root: &Path, rel: &str, context: &str) -> TestResult<PathBuf> {
    let path = Path::new(rel);
    ensure(
        !path.is_absolute(),
        format!("{context} must be repo-relative, got {rel}"),
    )?;
    ensure(
        path.components()
            .all(|component| !matches!(component, Component::ParentDir | Component::RootDir)),
        format!("{context} must not escape the workspace, got {rel}"),
    )?;
    Ok(root.join(path))
}

fn parse_issues(path: &Path) -> TestResult<BTreeMap<String, Value>> {
    let mut issues = BTreeMap::new();
    for (idx, line) in read_text(path)?.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let issue: Value = serde_json::from_str(line)
            .map_err(|err| test_error(format!("issues line {} should parse: {err}", idx + 1)))?;
        let id = as_str(&issue["id"], "issue.id")?.to_owned();
        issues.insert(id, issue);
    }
    Ok(issues)
}

fn write_tracker_fixture(path: &Path, artifact: &Value) -> TestResult {
    let mut content = String::new();
    for row in as_array(&artifact["closure_rows"], "closure_rows")? {
        let issue = serde_json::json!({
            "id": as_str(&row["created_issue_id"], "row.created_issue_id")?,
            "status": "open",
            "dependencies": [
                {
                    "depends_on_id": as_str(&row["parent_issue_id"], "row.parent_issue_id")?,
                    "type": "parent-child"
                }
            ]
        });
        content.push_str(
            &serde_json::to_string(&issue).map_err(|err| {
                test_error(format!("tracker fixture serialization failed: {err}"))
            })?,
        );
        content.push('\n');
    }
    std::fs::write(path, content)
        .map_err(|err| test_error(format!("{} write failed: {err}", path.display())))
}

fn tracker_fixture(artifact: &Value, prefix: &str) -> TestResult<(PathBuf, PathBuf)> {
    let out_dir = unique_temp_dir(prefix)?;
    let issues = out_dir.join("issues.jsonl");
    write_tracker_fixture(&issues, artifact)?;
    Ok((out_dir, issues))
}

fn command_output_message(output: &std::process::Output) -> String {
    format!(
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn artifact_defines_complete_targeted_closure_contract() -> TestResult {
    let root = workspace_root();
    let artifact = load_json(&artifact_path(&root))?;
    ensure_eq(
        artifact["schema_version"].as_str(),
        Some("v1"),
        "schema_version",
    )?;
    ensure_eq(artifact["bead"].as_str(), Some("bd-bp8fl.3.3"), "bead")?;
    ensure(
        artifact["purpose"]
            .as_str()
            .is_some_and(|purpose| purpose.contains("feature-parity gap")),
        "purpose must describe the feature-parity gap closure contract",
    )?;

    let log_fields = as_array(&artifact["required_log_fields"], "required_log_fields")?
        .iter()
        .map(|value| value.as_str().unwrap_or_default())
        .collect::<Vec<_>>();
    ensure_eq(
        log_fields,
        REQUIRED_LOG_FIELDS.to_vec(),
        "required_log_fields",
    )?;

    let inputs = artifact["inputs"]
        .as_object()
        .ok_or_else(|| test_error("inputs must be an object"))?;
    for key in [
        "feature_parity_gap_groups",
        "feature_parity_gap_owner_family_groups",
        "feature_parity_gap_ledger",
        "issues_jsonl",
    ] {
        let rel = inputs
            .get(key)
            .and_then(Value::as_str)
            .ok_or_else(|| test_error(format!("inputs.{key} must be a path string")))?;
        let resolved = repo_path(&root, rel, &format!("inputs.{key}"))?;
        ensure(
            resolved.exists(),
            format!("inputs.{key} points at missing artifact {rel}"),
        )?;
    }

    let policy = &artifact["claim_policy"];
    ensure_eq(
        policy["missing_or_duplicate_source_row"].as_str(),
        Some("fail_closed"),
        "claim_policy.missing_or_duplicate_source_row",
    )?;
    ensure_eq(
        policy["closed_tracker_without_current_gate"].as_str(),
        Some("claim_blocked"),
        "claim_policy.closed_tracker_without_current_gate",
    )?;

    let summary = &artifact["summary"];
    ensure_eq(
        summary["expected_source_rows"].as_u64(),
        Some(EXPECTED_ROWS.len() as u64),
        "summary.expected_source_rows",
    )?;
    ensure_eq(
        summary["expected_gap_count"].as_u64(),
        Some(111),
        "summary.expected_gap_count",
    )?;
    ensure_eq(
        summary["created_issue_count"].as_u64(),
        Some(EXPECTED_ROWS.len() as u64),
        "summary.created_issue_count",
    )
}

#[test]
fn closure_rows_match_owner_groups_and_tracker_dependencies() -> TestResult {
    let root = workspace_root();
    let artifact = load_json(&artifact_path(&root))?;
    let groups = load_json(&group_path(&root))?;
    let owner_md = read_text(&owner_family_path(&root))?;
    let (_out_dir, issues_fixture) =
        tracker_fixture(&artifact, "feature-parity-targeted-closure-tracker")?;
    let issues = parse_issues(&issues_fixture)?;

    let group_by_id = as_array(&groups["batches"], "groups.batches")?
        .iter()
        .map(|group| {
            Ok((
                as_str(&group["batch_id"], "group.batch_id")?.to_owned(),
                group,
            ))
        })
        .collect::<TestResult<BTreeMap<_, _>>>()?;
    let rows = as_array(&artifact["closure_rows"], "closure_rows")?;
    ensure_eq(rows.len(), EXPECTED_ROWS.len(), "closure row count")?;

    let expected_source_ids = EXPECTED_ROWS
        .iter()
        .map(|(source_id, _, _)| *source_id)
        .collect::<BTreeSet<_>>();
    let expected_issue_ids = EXPECTED_ROWS
        .iter()
        .map(|(_, issue_id, _)| *issue_id)
        .collect::<BTreeSet<_>>();
    let mut actual_source_ids = BTreeSet::new();
    let mut actual_issue_ids = BTreeSet::new();
    let mut total_gap_count = 0_u64;

    for row in rows {
        let source_id = as_str(&row["source_row_id"], "row.source_row_id")?;
        let issue_id = as_str(&row["created_issue_id"], "row.created_issue_id")?;
        actual_source_ids.insert(source_id);
        actual_issue_ids.insert(issue_id);

        let group = group_by_id
            .get(source_id)
            .ok_or_else(|| test_error(format!("missing source group {source_id}")))?;
        let issue = issues
            .get(issue_id)
            .ok_or_else(|| test_error(format!("missing tracker issue {issue_id}")))?;

        let gap_count = as_array(&group["gap_ids"], "group.gap_ids")?.len() as u64;
        let expected_gap_count = EXPECTED_ROWS
            .iter()
            .find_map(|(expected_source, _, count)| {
                (*expected_source == source_id).then_some(*count)
            })
            .ok_or_else(|| test_error(format!("unexpected source row {source_id}")))?;
        ensure_eq(
            gap_count,
            expected_gap_count,
            format!("{source_id} gap count"),
        )?;
        total_gap_count += gap_count;

        ensure_eq(
            as_str(&row["missing_evidence_type"], "row.missing_evidence_type")?,
            as_str(&group["oracle_kind"], "group.oracle_kind")?,
            format!("{source_id} oracle kind"),
        )?;
        ensure(
            owner_md.contains(source_id) && owner_md.contains(issue_id),
            format!("owner-family markdown must cite {source_id} and {issue_id}"),
        )?;

        let parent = as_str(&row["parent_issue_id"], "row.parent_issue_id")?;
        let dependency_ids = as_array(&issue["dependencies"], "issue.dependencies")?
            .iter()
            .filter_map(|dep| dep["depends_on_id"].as_str())
            .collect::<BTreeSet<_>>();
        ensure(
            dependency_ids.contains(parent),
            format!("{issue_id} must depend on parent {parent}"),
        )?;

        for key in [
            "required_unit_tests",
            "required_e2e_scripts",
            "claim_surfaces",
            "br_commands",
        ] {
            ensure(
                !as_array(&row[key], key)?.is_empty(),
                format!("{source_id}.{key} must be non-empty"),
            )?;
        }
        for test_path in as_array(&row["required_unit_tests"], "required_unit_tests")? {
            let rel = as_str(test_path, "required_unit_tests[]")?;
            let resolved = repo_path(&root, rel, "required_unit_tests[]")?;
            ensure(
                resolved.exists(),
                format!("{source_id} required unit test is missing: {rel}"),
            )?;
        }
        for script in as_array(&row["required_e2e_scripts"], "required_e2e_scripts")? {
            let command = as_str(script, "required_e2e_scripts[]")?;
            let rel = command
                .split_whitespace()
                .next()
                .ok_or_else(|| test_error("required_e2e_scripts[] must name a script"))?;
            let resolved = repo_path(&root, rel, "required_e2e_scripts[]")?;
            ensure(
                resolved.exists(),
                format!("{source_id} required e2e script is missing: {rel}"),
            )?;
        }
        for command in as_array(&row["br_commands"], "br_commands")? {
            ensure(
                as_str(command, "br_commands[]")?.contains(issue_id),
                format!("{source_id} br command must cite {issue_id}"),
            )?;
        }
    }

    ensure_eq(actual_source_ids, expected_source_ids, "source row ids")?;
    ensure_eq(actual_issue_ids, expected_issue_ids, "created issue ids")?;
    ensure_eq(total_gap_count, 111, "total mapped gap count")
}

#[test]
fn gate_script_passes_and_emits_structured_artifacts() -> TestResult {
    let root = workspace_root();
    let artifact = load_json(&artifact_path(&root))?;
    let script = script_path(&root);
    ensure(script.exists(), format!("missing {}", script.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&script)
            .map_err(|err| test_error(format!("{} metadata failed: {err}", script.display())))?
            .permissions()
            .mode();
        ensure(
            mode & 0o111 != 0,
            "check_feature_parity_targeted_closure_beads.sh must be executable",
        )?;
    }

    let (out_dir, issues_fixture) = tracker_fixture(&artifact, "feature-parity-targeted-closure")?;
    let report_path = out_dir.join("report.json");
    let log_path = out_dir.join("log.jsonl");
    let output = Command::new(&script)
        .current_dir(&root)
        .env("FRANKENLIBC_TARGETED_CLOSURE_OUT_DIR", &out_dir)
        .env("FRANKENLIBC_TARGETED_CLOSURE_REPORT", &report_path)
        .env("FRANKENLIBC_TARGETED_CLOSURE_LOG", &log_path)
        .env("FRANKENLIBC_BEADS_JSONL", &issues_fixture)
        .output()
        .map_err(|err| test_error(format!("failed to run targeted-closure gate: {err}")))?;
    ensure(
        output.status.success(),
        format!(
            "targeted-closure gate failed\n{}",
            command_output_message(&output)
        ),
    )?;

    let report = load_json(&report_path)?;
    ensure_eq(report["status"].as_str(), Some("pass"), "report status")?;
    ensure_eq(
        report["summary"]["source_rows"].as_u64(),
        Some(EXPECTED_ROWS.len() as u64),
        "report summary.source_rows",
    )?;
    ensure_eq(
        report["summary"]["gap_count"].as_u64(),
        Some(111),
        "report summary.gap_count",
    )?;
    ensure(
        as_array(&report["errors"], "report.errors")?.is_empty(),
        "report.errors must be empty on pass",
    )?;

    let log_content = read_text(&log_path)?;
    let logs = log_content
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).map_err(|err| test_error(err.to_string())))
        .collect::<TestResult<Vec<_>>>()?;
    ensure_eq(logs.len(), EXPECTED_ROWS.len(), "log row count")?;
    for log in logs {
        for field in REQUIRED_LOG_FIELDS {
            ensure(
                log.get(*field).is_some(),
                format!("missing log field {field}"),
            )?;
        }
        ensure_eq(log["bead_id"].as_str(), Some("bd-bp8fl.3.3"), "log bead_id")?;
        ensure_eq(
            log["failure_signature"].as_str(),
            Some("none"),
            "log failure_signature",
        )?;
    }
    Ok(())
}

#[test]
fn gate_script_fails_closed_for_duplicate_source_row() -> TestResult {
    let root = workspace_root();
    let mut artifact = load_json(&artifact_path(&root))?;
    let rows = artifact["closure_rows"]
        .as_array_mut()
        .ok_or_else(|| test_error("closure_rows must be mutable array"))?;
    let duplicate_source = rows
        .first()
        .and_then(|row| row["source_row_id"].as_str())
        .ok_or_else(|| test_error("first closure row must have source_row_id"))?
        .to_owned();
    let second = rows
        .get_mut(1)
        .ok_or_else(|| test_error("closure_rows must have a second row"))?;
    second["source_row_id"] = Value::String(duplicate_source);

    let out_dir = unique_temp_dir("feature-parity-targeted-closure-negative")?;
    let fixture = out_dir.join("duplicate-source.fixture.json");
    let report_path = out_dir.join("duplicate-source.report.json");
    let log_path = out_dir.join("duplicate-source.log.jsonl");
    write_json(&fixture, &artifact)?;
    let issues_fixture = out_dir.join("issues.jsonl");
    write_tracker_fixture(&issues_fixture, &artifact)?;

    let script = script_path(&root);
    let output = Command::new(&script)
        .current_dir(&root)
        .env("FRANKENLIBC_TARGETED_CLOSURE_BEADS", &fixture)
        .env("FRANKENLIBC_TARGETED_CLOSURE_REPORT", &report_path)
        .env("FRANKENLIBC_TARGETED_CLOSURE_LOG", &log_path)
        .env("FRANKENLIBC_BEADS_JSONL", &issues_fixture)
        .output()
        .map_err(|err| {
            test_error(format!(
                "failed to run negative targeted-closure gate: {err}"
            ))
        })?;
    ensure(
        !output.status.success(),
        "duplicate source row must fail the gate",
    )?;

    let report = load_json(&report_path)?;
    ensure_eq(report["status"].as_str(), Some("fail"), "negative status")?;
    let errors = as_array(&report["errors"], "report.errors")?
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .join("\n");
    ensure(
        errors.contains("duplicate source_row_id"),
        format!("negative report should name duplicate source rows, got {errors:?}"),
    )
}
