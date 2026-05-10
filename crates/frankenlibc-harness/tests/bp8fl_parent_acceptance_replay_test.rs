//! Integration test: bd-bp8fl parent acceptance replay gate (bd-aixvz.1).
//!
//! The gate turns the tracker-only bd-aixvz closure into a replayable,
//! read-only proof with report and JSONL telemetry.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const TARGET_PARENT_IDS: &[&str] = &[
    "bd-bp8fl",
    "bd-bp8fl.1",
    "bd-bp8fl.2",
    "bd-bp8fl.3",
    "bd-bp8fl.4",
    "bd-bp8fl.5",
    "bd-bp8fl.6",
    "bd-bp8fl.7",
    "bd-bp8fl.8",
    "bd-bp8fl.9",
    "bd-bp8fl.10",
];

const REQUIRED_REPORT_FIELDS: &[&str] = &[
    "schema_version",
    "bead",
    "parent_bead",
    "generated_at_utc",
    "trace_id",
    "source_commit",
    "mode",
    "status",
    "tracker_state",
    "parent_count",
    "jsonl_count",
    "db_count",
    "missing_parent_ids",
    "duplicate_parent_ids",
    "failed_terms",
    "tool_probes",
    "summary",
    "artifact_refs",
];

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "parent_epic_id",
    "command",
    "exit_status",
    "expected",
    "actual",
    "db_count",
    "jsonl_count",
    "artifact_refs",
    "source_commit",
    "failure_signature",
];

fn test_error(message: impl Into<String>) -> Box<dyn std::error::Error> {
    Box::new(std::io::Error::other(message.into()))
}

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Ok(Path::new(manifest)
        .parent()
        .ok_or_else(|| test_error("crate manifest should have a crates/ parent"))?
        .parent()
        .ok_or_else(|| test_error("crates directory should have a workspace parent"))?
        .to_path_buf())
}

fn load_json(path: &Path) -> TestResult<Value> {
    let content = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&content)?)
}

fn artifact_path(root: &Path) -> PathBuf {
    root.join("tests")
        .join("conformance")
        .join("bp8fl_parent_acceptance_replay.v1.json")
}

fn unique_temp_dir(prefix: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| test_error(format!("system clock should be after Unix epoch: {err}")))?
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn array_strings<'a>(value: &'a Value, field: &str) -> TestResult<Vec<&'a str>> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| test_error(format!("{field} should be array")))?
        .iter()
        .map(|item| {
            item.as_str()
                .ok_or_else(|| test_error(format!("{field} entry should be string")))
        })
        .collect()
}

fn object_array<'a>(value: &'a Value, field: &str) -> TestResult<&'a Vec<Value>> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| test_error(format!("{field} should be array")))
}

fn run_checker(mode: &str, temp: &Path) -> TestResult<(std::process::Output, PathBuf, PathBuf)> {
    run_checker_with_issues(mode, temp, None)
}

fn run_checker_with_issues(
    mode: &str,
    temp: &Path,
    issues: Option<&Path>,
) -> TestResult<(std::process::Output, PathBuf, PathBuf)> {
    let root = workspace_root()?;
    let report = temp.join("bp8fl_parent_acceptance_replay.report.json");
    let log = temp.join("bp8fl_parent_acceptance_replay.log.jsonl");
    let mut command = Command::new(root.join("scripts/check_bp8fl_parent_acceptance_replay.sh"));
    command
        .arg(mode)
        .current_dir(&root)
        .env("FRANKENLIBC_BP8FL_PARENT_ACCEPTANCE_TARGET_DIR", temp)
        .env("FRANKENLIBC_BP8FL_PARENT_ACCEPTANCE_REPORT", &report)
        .env("FRANKENLIBC_BP8FL_PARENT_ACCEPTANCE_LOG", &log)
        .env("FRANKENLIBC_BP8FL_PARENT_ACCEPTANCE_PROBE_TOOLS", "0");
    if let Some(issues) = issues {
        command.env("FRANKENLIBC_BP8FL_PARENT_ACCEPTANCE_ISSUES", issues);
    }
    let output = command.output()?;
    Ok((output, report, log))
}

fn assert_success(output: &std::process::Output) -> TestResult {
    if output.status.success() {
        Ok(())
    } else {
        Err(test_error(format!(
            "checker failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )))
    }
}

fn log_rows(path: &Path) -> TestResult<Vec<Value>> {
    let content = std::fs::read_to_string(path)?;
    Ok(content
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?)
}

#[test]
fn artifact_defines_aixvz_completion_debt_contract() -> TestResult {
    let root = workspace_root()?;
    let artifact = load_json(&artifact_path(&root))?;
    assert_eq!(artifact["schema_version"].as_str(), Some("v1"));
    assert_eq!(artifact["bead"].as_str(), Some("bd-aixvz.1"));
    assert_eq!(artifact["parent_bead"].as_str(), Some("bd-aixvz"));
    assert_eq!(
        artifact["audit_reference"]["missing_items"]
            .as_array()
            .ok_or_else(|| test_error("missing_items should be array"))?
            .len(),
        3
    );

    let target_ids = array_strings(&artifact, "target_parent_ids")?;
    assert_eq!(target_ids, TARGET_PARENT_IDS);

    let report_fields = array_strings(&artifact, "required_report_fields")?;
    assert_eq!(report_fields, REQUIRED_REPORT_FIELDS);

    let log_fields = array_strings(&artifact, "required_log_fields")?;
    assert_eq!(log_fields, REQUIRED_LOG_FIELDS);

    let terms = object_array(&artifact, "required_acceptance_terms")?;
    let term_ids: HashSet<_> = terms
        .iter()
        .map(|term| {
            term.get("term_id")
                .and_then(Value::as_str)
                .ok_or_else(|| test_error("term_id should be string"))
        })
        .collect::<TestResult<_>>()?;
    for term in [
        "parent_specific_header",
        "required_unit_tests",
        "deterministic_e2e",
        "structured_telemetry",
        "source_of_truth_freshness",
        "claim_gate_cases",
        "closure_commands",
        "no_feature_loss",
    ] {
        assert!(term_ids.contains(term), "missing acceptance term {term}");
    }
    Ok(())
}

#[test]
fn fixture_replay_proves_missing_duplicate_and_weak_rows_fail_closed() -> TestResult {
    let temp = unique_temp_dir("bp8fl-parent-acceptance-fixture")?;
    let (output, report_path, log_path) = run_checker("--fixture-replay", &temp)?;
    assert_success(&output)?;

    let report = load_json(&report_path)?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(
        report["tracker_state"].as_str(),
        Some("fixture_failure_detected")
    );

    let signatures: HashSet<_> = array_strings(&report, "failure_signatures")?
        .into_iter()
        .collect();
    for expected in [
        "missing_parent_rows",
        "duplicate_parent_rows",
        "missing_structured_telemetry",
    ] {
        assert!(
            signatures.contains(expected),
            "fixture did not detect {expected}"
        );
    }

    let rows = log_rows(&log_path)?;
    assert!(
        !rows.is_empty(),
        "fixture replay should emit telemetry rows"
    );
    for row in rows {
        for field in REQUIRED_LOG_FIELDS {
            assert!(row.get(*field).is_some(), "missing log field {field}");
        }
    }
    Ok(())
}

#[test]
fn valid_parent_fixture_rows_pass_acceptance_replay() -> TestResult {
    let temp = unique_temp_dir("bp8fl-parent-acceptance-valid")?;
    let issues = temp.join("issues.jsonl");
    let valid_criteria = "Parent-specific acceptance criteria: Preserve fixture scope. \
Closure requires child workstreams for bd-bp8fl. Required unit tests include parser tests. \
Required deterministic e2e scripts replay tracker rows. Structured logs must include \
trace_id, source_commit, and failure_signature. Source-of-truth freshness checks record \
DB and JSONL counts. Claim gates include positive and negative cases. Closure must list \
exact commands and a no-feature-loss note.";
    let content = TARGET_PARENT_IDS
        .iter()
        .map(|id| {
            format!(
                "{{\"id\":\"{id}\",\"status\":\"closed\",\"priority\":0,\"issue_type\":\"epic\",\"acceptance_criteria\":\"{valid_criteria}\"}}\n"
            )
        })
        .collect::<String>();
    std::fs::write(&issues, content)?;

    let (output, report_path, log_path) =
        run_checker_with_issues("--validate-current", &temp, Some(&issues))?;
    assert_success(&output)?;

    let report = load_json(&report_path)?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["mode"].as_str(), Some("--validate-current"));
    assert_eq!(
        report["parent_count"].as_u64(),
        Some(TARGET_PARENT_IDS.len() as u64)
    );
    assert_eq!(
        report["missing_parent_ids"].as_array().map(Vec::len),
        Some(0)
    );
    assert_eq!(
        report["duplicate_parent_ids"].as_array().map(Vec::len),
        Some(0)
    );
    assert_eq!(report["failed_terms"].as_array().map(Vec::len), Some(0));

    for field in REQUIRED_REPORT_FIELDS {
        assert!(report.get(*field).is_some(), "missing report field {field}");
    }

    let rows = log_rows(&log_path)?;
    assert!(
        rows.len() >= TARGET_PARENT_IDS.len(),
        "current validation should emit per-parent telemetry"
    );
    for row in rows {
        for field in REQUIRED_LOG_FIELDS {
            assert!(row.get(*field).is_some(), "missing log field {field}");
        }
    }
    Ok(())
}

#[test]
fn checker_script_is_read_only_and_names_tool_probe_contract() -> TestResult {
    let root = workspace_root()?;
    let script =
        std::fs::read_to_string(root.join("scripts/check_bp8fl_parent_acceptance_replay.sh"))?;
    for forbidden in [
        "br update",
        "br close",
        "br create",
        "git add",
        "git commit",
    ] {
        assert!(
            !script.contains(forbidden),
            "checker must stay read-only; found {forbidden}"
        );
    }
    assert!(script.contains("br show"));
    assert!(script.contains("br dep"));
    assert!(script.contains("FRANKENLIBC_BP8FL_PARENT_ACCEPTANCE_PROBE_TOOLS"));
    Ok(())
}
