//! Integration test: workload failure minimizer/dashboard (bd-b92jd.3.3).
//!
//! The dashboard consumes bd-b92jd.3.2 replay traces and proves skipped or
//! blocked workload rows stay visible as structured failure evidence.

use serde_json::{Value, json};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const REQUIRED_CLASSES: &[&str] = &[
    "startup_timeout",
    "startup_segv",
    "symbol_lookup",
    "loader_missing_library",
    "parity_mismatch",
    "perf_regression",
    "optional_skip",
    "environment_error",
];

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "event",
    "status",
    "failure_class",
    "failure_signature",
    "count",
    "representative_workload_id",
    "representative_mode",
    "artifact_refs",
    "source_commit",
    "target_dir",
];

fn test_error(message: impl Into<String>) -> Box<dyn std::error::Error> {
    Box::new(std::io::Error::other(message.into()))
}

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Ok(Path::new(manifest)
        .parent()
        .ok_or_else(|| test_error("crate manifest should have crates parent"))?
        .parent()
        .ok_or_else(|| test_error("crates directory should have workspace parent"))?
        .to_path_buf())
}

fn load_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn json_field<'a>(value: &'a Value, key: &str) -> TestResult<&'a Value> {
    value
        .get(key)
        .ok_or_else(|| test_error(format!("missing JSON field {key}")))
}

fn unique_output_dir(root: &Path, prefix: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| test_error(format!("system clock should be after Unix epoch: {err}")))?
        .as_nanos();
    let dir = root
        .join("target/conformance")
        .join(format!("{prefix}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn trace_row(workload_id: &str, mode: &str, status: &str, failure_signature: &str) -> Value {
    json!({
        "trace_id": format!("fixture::{workload_id}::{mode}"),
        "bead_id": "bd-b92jd.3.2",
        "workload_id": workload_id,
        "mode": mode,
        "status": status,
        "failure_signature": failure_signature,
        "source_commit": "0123456789abcdef0123456789abcdef01234567",
        "target_dir": "target/conformance/workload_failure_fixture",
        "artifact_refs": [
            "tests/conformance/user_workload_replay_manifest.v1.json"
        ]
    })
}

fn write_fixture_inputs(dir: &Path, rows: &[Value]) -> TestResult<(PathBuf, PathBuf)> {
    let report = dir.join("trace.report.json");
    let log = dir.join("trace.log.jsonl");
    let report_json = json!({
        "schema_version": "v1",
        "bead": "bd-b92jd.3.2",
        "status": "pass",
        "trace_row_count": rows.len(),
        "artifact_refs": ["fixture"]
    });
    std::fs::write(&report, serde_json::to_string_pretty(&report_json)? + "\n")?;
    let mut log_content = String::new();
    for row in rows {
        log_content.push_str(&serde_json::to_string(row)?);
        log_content.push('\n');
    }
    std::fs::write(&log, log_content)?;
    Ok((report, log))
}

fn run_dashboard(root: &Path, dir: &Path, rows: &[Value]) -> TestResult<std::process::Output> {
    let (trace_report, trace_log) = write_fixture_inputs(dir, rows)?;
    let output = Command::new(root.join("scripts/check_workload_failure_dashboard.sh"))
        .current_dir(root)
        .env("FRANKENLIBC_WORKLOAD_FAILURE_AUTORUN_TRACE", "0")
        .env("FRANKENLIBC_WORKLOAD_FAILURE_TRACE_REPORT", &trace_report)
        .env("FRANKENLIBC_WORKLOAD_FAILURE_TRACE_LOG", &trace_log)
        .env("FRANKENLIBC_WORKLOAD_FAILURE_OUT_DIR", dir)
        .env(
            "FRANKENLIBC_WORKLOAD_FAILURE_REPORT",
            dir.join("dashboard.report.json"),
        )
        .env(
            "FRANKENLIBC_WORKLOAD_FAILURE_MARKDOWN",
            dir.join("dashboard.md"),
        )
        .env(
            "FRANKENLIBC_WORKLOAD_FAILURE_LOG",
            dir.join("dashboard.log.jsonl"),
        )
        .output()?;
    Ok(output)
}

fn valid_rows_covering_classes() -> Vec<Value> {
    vec![
        trace_row("coreutils_echo_stdout", "baseline", "pass", "none"),
        trace_row(
            "coreutils_echo_stdout",
            "strict",
            "claim_blocked",
            "interpose_artifact_missing",
        ),
        trace_row(
            "optional_sqlite_version_probe",
            "baseline",
            "skipped",
            "optional_tool_missing:sqlite3",
        ),
        trace_row(
            "shell_pipeline_count_lines",
            "hardened",
            "fail",
            "stdout_digest_mismatch",
        ),
        trace_row(
            "slow_startup_fixture",
            "strict",
            "timeout",
            "startup_timeout",
        ),
        trace_row("segv_fixture", "strict", "fail", "startup_segv"),
        trace_row("lookup_fixture", "strict", "fail", "symbol_lookup"),
        trace_row("perf_fixture", "hardened", "fail", "perf_regression"),
        trace_row("env_fixture", "baseline", "fail", "command_unavailable"),
    ]
}

#[test]
fn artifact_declares_failure_dashboard_contract() -> TestResult {
    let root = workspace_root()?;
    let artifact = load_json(&root.join("tests/conformance/workload_failure_dashboard.v1.json"))?;
    assert_eq!(artifact["schema_version"].as_str(), Some("v1"));
    assert_eq!(artifact["bead"].as_str(), Some("bd-b92jd.3.3"));
    assert_eq!(artifact["source_bead"].as_str(), Some("bd-b92jd.3.2"));
    assert_eq!(
        artifact["trace_id"].as_str(),
        Some("bd-b92jd-3-3-workload-failure-dashboard-v1")
    );

    let classes: HashSet<_> = json_field(&artifact, "required_failure_classes")?
        .as_array()
        .ok_or_else(|| test_error("required_failure_classes should be array"))?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for class in REQUIRED_CLASSES {
        assert!(classes.contains(class), "missing class {class}");
    }
    let classification = json_field(&artifact, "signature_classification")?;
    assert!(json_field(classification, "exact")?.is_object());
    assert!(json_field(classification, "prefixes")?.is_object());
    Ok(())
}

#[test]
fn gate_script_is_executable() -> TestResult {
    let root = workspace_root()?;
    let script = root.join("scripts/check_workload_failure_dashboard.sh");
    assert!(script.exists(), "missing {}", script.display());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script)?.permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_workload_failure_dashboard.sh must be executable"
        );
    }
    Ok(())
}

#[test]
fn dashboard_groups_failures_and_emits_markdown_jsonl() -> TestResult {
    let root = workspace_root()?;
    let dir = unique_output_dir(&root, "workload-failure-dashboard-pass")?;
    let output = run_dashboard(&root, &dir, &valid_rows_covering_classes())?;
    assert!(
        output.status.success(),
        "dashboard gate failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = load_json(&dir.join("dashboard.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["summary"]["trace_row_count"].as_u64(), Some(9));
    assert_eq!(report["summary"]["hidden_skip_count"].as_u64(), Some(0));
    assert_eq!(
        report["summary"]["unknown_signature_count"].as_u64(),
        Some(0)
    );
    for class in REQUIRED_CLASSES {
        assert!(
            report["summary"]["class_counts"][class]
                .as_u64()
                .unwrap_or(0)
                >= 1,
            "expected class count for {class}"
        );
    }

    let groups = json_field(&report, "failure_groups")?
        .as_array()
        .ok_or_else(|| test_error("failure_groups should be array"))?;
    let group_classes: HashSet<_> = groups
        .iter()
        .filter_map(|group| group.get("failure_class").and_then(Value::as_str))
        .collect();
    for class in REQUIRED_CLASSES {
        assert!(group_classes.contains(class), "missing group class {class}");
    }
    assert!(
        report["next_beads"]
            .as_array()
            .ok_or_else(|| test_error("next_beads should be array"))?
            .iter()
            .any(|item| item["failure_class"].as_str() == Some("parity_mismatch")),
        "real regression classes should produce next bead suggestions"
    );

    let markdown = std::fs::read_to_string(dir.join("dashboard.md"))?;
    assert!(markdown.contains("# Workload Failure Dashboard"));
    assert!(markdown.contains("`loader_missing_library`"));
    assert!(markdown.contains("`optional_skip`"));

    let log_content = std::fs::read_to_string(dir.join("dashboard.log.jsonl"))?;
    let log_rows: Vec<Value> = log_content
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    assert!(
        log_rows
            .iter()
            .any(|row| row["failure_class"].as_str() == Some("loader_missing_library"))
    );
    for row in log_rows {
        for field in REQUIRED_LOG_FIELDS {
            assert!(row.get(*field).is_some(), "structured log missing {field}");
        }
    }
    Ok(())
}

#[test]
fn hidden_skip_rows_fail_closed() -> TestResult {
    let root = workspace_root()?;
    let dir = unique_output_dir(&root, "workload-failure-dashboard-hidden-skip")?;
    let rows = vec![
        trace_row("coreutils_echo_stdout", "baseline", "pass", "none"),
        trace_row("optional_sqlite_version_probe", "strict", "skipped", "none"),
    ];
    let output = run_dashboard(&root, &dir, &rows)?;
    assert!(!output.status.success(), "hidden skip should fail closed");
    let report = load_json(&dir.join("dashboard.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert_eq!(report["summary"]["hidden_skip_count"].as_u64(), Some(1));
    let errors = json_field(&report, "errors")?
        .as_array()
        .ok_or_else(|| test_error("errors should be array"))?;
    assert!(
        errors.iter().any(|error| error
            .as_str()
            .is_some_and(|text| text.contains("hidden non-pass"))),
        "hidden skip diagnostic should be present"
    );
    Ok(())
}

#[test]
fn unknown_failure_signatures_fail_closed() -> TestResult {
    let root = workspace_root()?;
    let dir = unique_output_dir(&root, "workload-failure-dashboard-unknown")?;
    let rows = vec![
        trace_row("coreutils_echo_stdout", "baseline", "pass", "none"),
        trace_row("mystery_workload", "strict", "fail", "mystery_failure"),
    ];
    let output = run_dashboard(&root, &dir, &rows)?;
    assert!(
        !output.status.success(),
        "unknown signatures should fail closed"
    );
    let report = load_json(&dir.join("dashboard.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert_eq!(
        report["summary"]["unknown_signature_count"].as_u64(),
        Some(1)
    );
    assert!(
        json_field(&report, "errors")?
            .as_array()
            .ok_or_else(|| test_error("errors should be array"))?
            .iter()
            .any(|error| error
                .as_str()
                .is_some_and(|text| text.contains("unknown failure signature")))
    );
    Ok(())
}
