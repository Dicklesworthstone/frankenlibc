//! Integration test: ambition graph readiness lint (bd-bp8fl.2.6)
//!
//! The lint turns weak or malformed tracker graph rows into structured
//! findings without auto-closing, deleting, or narrowing any bead.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const REQUIRED_REPORT_FIELDS: &[&str] = &[
    "schema_version",
    "bead",
    "generated_at_utc",
    "trace_id",
    "source_commit",
    "status",
    "mode",
    "tracker_state",
    "issue_count",
    "finding_count",
    "severity_counts",
    "findings_by_rule",
    "next_safe_actions",
    "summary",
    "artifact_refs",
];

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "lint_run_id",
    "bead_id",
    "rule_id",
    "severity",
    "expected",
    "actual",
    "dependency_state",
    "tracker_state",
    "evidence_refs",
    "source_commit",
    "failure_signature",
];

const REQUIRED_RULES: &[&str] = &[
    "label_syntax",
    "acceptance_contract",
    "dependency_sanity",
    "tracker_state",
    "already_shipped_but_open",
    "scope_specificity",
];

fn test_error(message: impl Into<String>) -> Box<dyn std::error::Error> {
    Box::new(std::io::Error::other(message.into()))
}

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let root = Path::new(manifest)
        .parent()
        .ok_or_else(|| test_error("crate manifest should have a crates/ parent"))?
        .parent()
        .ok_or_else(|| test_error("crates directory should have a workspace parent"))?
        .to_path_buf();
    Ok(root)
}

fn load_json(path: &Path) -> TestResult<serde_json::Value> {
    let content = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&content)?)
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

fn load_artifact() -> TestResult<serde_json::Value> {
    load_json(&workspace_root()?.join("tests/conformance/ambition_graph_readiness_lint.v1.json"))
}

fn run_lint(mode: &str, temp: &Path) -> TestResult<(std::process::Output, PathBuf, PathBuf)> {
    run_lint_with_issues(mode, temp, None)
}

fn run_lint_with_issues(
    mode: &str,
    temp: &Path,
    issues: Option<&Path>,
) -> TestResult<(std::process::Output, PathBuf, PathBuf)> {
    let root = workspace_root()?;
    let report = temp.join("ambition_graph_readiness_lint.report.json");
    let log = temp.join("ambition_graph_readiness_lint.log.jsonl");
    let mut command = Command::new(root.join("scripts/check_ambition_graph_readiness_lint.sh"));
    command
        .arg(mode)
        .current_dir(&root)
        .env("FRANKENLIBC_AMBITION_GRAPH_LINT_TARGET_DIR", temp)
        .env("FRANKENLIBC_AMBITION_GRAPH_LINT_REPORT", &report)
        .env("FRANKENLIBC_AMBITION_GRAPH_LINT_LOG", &log);
    if let Some(issues) = issues {
        command.env("FRANKENLIBC_AMBITION_GRAPH_LINT_ISSUES", issues);
    }
    let output = command.output()?;
    Ok((output, report, log))
}

fn assert_success(output: &std::process::Output) {
    assert!(
        output.status.success(),
        "lint failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn log_rows(path: &Path) -> TestResult<Vec<serde_json::Value>> {
    let content = std::fs::read_to_string(path)?;
    Ok(content
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?)
}

#[test]
fn artifact_defines_graph_readiness_contract() -> TestResult {
    let artifact = load_artifact()?;
    assert_eq!(artifact["schema_version"].as_str(), Some("v1"));
    assert_eq!(artifact["bead"].as_str(), Some("bd-bp8fl.2.6"));
    assert!(artifact["source_of_truth_policy"].is_object());
    assert!(artifact["fixture_graph"]["issues"].is_array());

    let report_fields: Vec<_> = artifact["required_report_fields"]
        .as_array()
        .ok_or_else(|| test_error("required_report_fields should be array"))?
        .iter()
        .map(|field| {
            field
                .as_str()
                .ok_or_else(|| test_error("report field should be string"))
        })
        .collect::<TestResult<Vec<_>>>()?;
    assert_eq!(report_fields, REQUIRED_REPORT_FIELDS);

    let log_fields: Vec<_> = artifact["required_log_fields"]
        .as_array()
        .ok_or_else(|| test_error("required_log_fields should be array"))?
        .iter()
        .map(|field| {
            field
                .as_str()
                .ok_or_else(|| test_error("log field should be string"))
        })
        .collect::<TestResult<Vec<_>>>()?;
    assert_eq!(log_fields, REQUIRED_LOG_FIELDS);

    let rules: HashSet<_> = artifact["rule_catalog"]
        .as_array()
        .ok_or_else(|| test_error("rule_catalog should be array"))?
        .iter()
        .map(|rule| {
            rule["rule_id"]
                .as_str()
                .ok_or_else(|| test_error("rule_id should be string"))
        })
        .collect::<TestResult<HashSet<_>>>()?;
    for rule in REQUIRED_RULES {
        assert!(rules.contains(rule), "missing rule {rule}");
    }
    Ok(())
}

#[test]
fn fixture_replay_emits_actionable_findings() -> TestResult {
    let temp = unique_temp_dir("ambition-graph-lint-fixture")?;
    let (output, report_path, log_path) = run_lint("--fixture-replay", &temp)?;
    assert_success(&output);

    let report = load_json(&report_path)?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["bead"].as_str(), Some("bd-bp8fl.2.6"));
    assert_eq!(report["mode"].as_str(), Some("--fixture-replay"));
    assert_eq!(report["tracker_state"].as_str(), Some("graph_failure"));
    assert!(
        report["finding_count"].as_u64().unwrap_or_default() >= REQUIRED_RULES.len() as u64,
        "fixture should exercise every required rule"
    );

    for field in REQUIRED_REPORT_FIELDS {
        assert!(report.get(*field).is_some(), "missing report field {field}");
    }

    let findings_by_rule = report["findings_by_rule"]
        .as_object()
        .ok_or_else(|| test_error("findings_by_rule should be object"))?;
    for rule in REQUIRED_RULES {
        assert!(
            findings_by_rule.contains_key(*rule),
            "fixture missing finding for rule {rule}"
        );
    }
    assert_eq!(
        report["summary"]["actionable_without_blocking_unrelated_beads"].as_bool(),
        Some(true)
    );

    let rows = log_rows(&log_path)?;
    assert!(!rows.is_empty(), "fixture should emit lint findings");
    for row in rows {
        for field in REQUIRED_LOG_FIELDS {
            assert!(row.get(*field).is_some(), "missing log field {field}");
        }
        assert!(
            !row["actual"].as_str().unwrap_or_default().is_empty(),
            "findings must include diagnostics"
        );
    }
    Ok(())
}

#[test]
fn clean_tracker_fixture_validation_has_clean_hard_graph_rules() -> TestResult {
    let temp = unique_temp_dir("ambition-graph-lint-current")?;
    let issues = temp.join("issues.jsonl");
    std::fs::write(
        &issues,
        "{\"id\":\"bd-clean-parent\",\"title\":\"Clean fixture parent\",\"description\":\"Parent fixture for a clean graph-quality validation run.\",\"status\":\"open\",\"priority\":0,\"issue_type\":\"epic\",\"labels\":[\"fixture\",\"graph-quality\"],\"acceptance_criteria\":\"Preserve fixture intent; include unit tests, deterministic e2e harness replay, structured JSONL logs with trace_id and failure_signature, artifact paths, closure commands, and explicit limitations.\"}\n{\"id\":\"bd-clean-task\",\"title\":\"Add clean graph readiness fixture\",\"description\":\"Conformance evidence fixture proving valid labels and dependency edges do not produce hard graph lint failures for implementation handoffs.\",\"status\":\"open\",\"priority\":1,\"issue_type\":\"task\",\"labels\":[\"fixture\",\"readiness\"],\"acceptance_criteria\":\"Preserve existing graph ambition; include unit tests, deterministic e2e harness replay, structured JSONL logs with trace_id and failure_signature, artifact paths, closure commands, and explicit limitations.\",\"dependencies\":[{\"issue_id\":\"bd-clean-task\",\"depends_on_id\":\"bd-clean-parent\",\"type\":\"parent-child\"}]}\n",
    )?;
    let (output, report_path, log_path) =
        run_lint_with_issues("--validate-current", &temp, Some(&issues))?;
    assert_success(&output);

    let report = load_json(&report_path)?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(
        report["summary"]["label_syntax_clean"].as_bool(),
        Some(true),
        "current .beads labels must stay parseable by br --no-db"
    );
    assert_eq!(
        report["summary"]["dependency_graph_clean"].as_bool(),
        Some(true),
        "current graph must not contain hard dependency failures"
    );

    let rows = log_rows(&log_path)?;
    for row in rows {
        for field in REQUIRED_LOG_FIELDS {
            assert!(row.get(*field).is_some(), "missing log field {field}");
        }
        assert_ne!(row["rule_id"].as_str(), Some("label_syntax"));
        assert_ne!(row["rule_id"].as_str(), Some("dependency_sanity"));
    }
    Ok(())
}

#[test]
fn current_tracker_validation_fails_closed_on_invalid_label() -> TestResult {
    let root = workspace_root()?;
    let temp = unique_temp_dir("ambition-graph-lint-invalid-label")?;
    let issues = temp.join("issues.jsonl");
    let report = temp.join("ambition_graph_readiness_lint.report.json");
    let log = temp.join("ambition_graph_readiness_lint.log.jsonl");
    std::fs::write(
        &issues,
        "{\"id\":\"bd-invalid-label\",\"title\":\"Invalid label fixture\",\"description\":\"Closed row should still be label-parseable.\",\"status\":\"closed\",\"priority\":1,\"issue_type\":\"task\",\"labels\":[\"sys/stat\"]}\n",
    )?;

    let output = Command::new(root.join("scripts/check_ambition_graph_readiness_lint.sh"))
        .arg("--validate-current")
        .current_dir(&root)
        .env("FRANKENLIBC_AMBITION_GRAPH_LINT_ISSUES", &issues)
        .env("FRANKENLIBC_AMBITION_GRAPH_LINT_TARGET_DIR", &temp)
        .env("FRANKENLIBC_AMBITION_GRAPH_LINT_REPORT", &report)
        .env("FRANKENLIBC_AMBITION_GRAPH_LINT_LOG", &log)
        .output()?;

    assert!(
        !output.status.success(),
        "invalid current label should fail closed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report_json = load_json(&report)?;
    assert_eq!(report_json["status"].as_str(), Some("fail"));
    assert_eq!(
        report_json["findings_by_rule"]["label_syntax"].as_u64(),
        Some(1)
    );
    Ok(())
}
