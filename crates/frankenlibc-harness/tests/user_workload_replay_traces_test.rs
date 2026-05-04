//! Integration test: user workload replay trace runner (bd-b92jd.3.2).
//!
//! Verifies that the runner consumes the bd-b92jd.3.1 manifest, records
//! baseline/strict/hardened trace rows, fails closed on missing preload
//! artifacts, keeps optional probes skip-clean, and emits required JSONL fields.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const REQUIRED_TRACE_FIELDS: &[&str] = &[
    "trace_id",
    "workload_id",
    "mode",
    "command",
    "env",
    "baseline_exit",
    "preload_exit",
    "expected_stdout_digest",
    "actual_stdout_digest",
    "stderr_signature",
    "latency_ns",
    "failure_signature",
    "source_commit",
    "target_dir",
    "artifact_refs",
];

fn workspace_root() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn load_json(path: &Path) -> serde_json::Value {
    let content = std::fs::read_to_string(path).expect("json file should be readable");
    serde_json::from_str(&content).expect("json should parse")
}

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after Unix epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn run_trace_runner(
    prefix: &str,
    extra_env: &[(&str, &str)],
) -> (PathBuf, PathBuf, std::process::Output) {
    let root = workspace_root();
    let temp = unique_temp_dir(prefix);
    let report = temp.join("user_workload_replay_traces.report.json");
    let log = temp.join("user_workload_replay_traces.log.jsonl");
    let target = temp.join("traces");
    let mut command = Command::new(root.join("scripts/run_user_workload_replay_traces.sh"));
    command
        .arg("--run")
        .env(
            "USER_WORKLOAD_REPLAY_MANIFEST",
            root.join("tests/conformance/user_workload_replay_manifest.v1.json"),
        )
        .env("USER_WORKLOAD_REPLAY_RUN_ID", prefix)
        .env("USER_WORKLOAD_REPLAY_TARGET_DIR", &target)
        .env("USER_WORKLOAD_REPLAY_TRACE_REPORT", &report)
        .env("USER_WORKLOAD_REPLAY_TRACE_LOG", &log)
        .env("USER_WORKLOAD_REPLAY_FORCE_MISSING_TOOLS", "sqlite3")
        .current_dir(&root);
    for (key, value) in extra_env {
        command.env(key, value);
    }
    let output = command.output().expect("trace runner should execute");
    (report, log, output)
}

fn parse_jsonl(path: &Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(path)
        .expect("jsonl should be readable")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("jsonl row should parse"))
        .collect()
}

#[test]
fn trace_runner_script_exists_and_is_executable() {
    let root = workspace_root();
    let script = root.join("scripts/run_user_workload_replay_traces.sh");
    assert!(script.exists(), "trace runner script must exist");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "run_user_workload_replay_traces.sh must be executable"
        );
    }
}

#[test]
fn runner_emits_required_report_and_trace_rows() {
    let (report_path, log_path, output) = run_trace_runner("workload-trace-pass", &[]);
    assert!(
        output.status.success(),
        "trace runner failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = load_json(&report_path);
    assert_eq!(report["schema_version"].as_str(), Some("v1"));
    assert_eq!(report["bead"].as_str(), Some("bd-b92jd.3.2"));
    assert_eq!(report["source_bead"].as_str(), Some("bd-b92jd.3.1"));
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["trace_row_count"].as_u64(), Some(15));
    assert_eq!(report["workload_count"].as_u64(), Some(5));
    assert_eq!(report["mode_counts"]["baseline"].as_u64(), Some(5));
    assert_eq!(report["mode_counts"]["strict"].as_u64(), Some(5));
    assert_eq!(report["mode_counts"]["hardened"].as_u64(), Some(5));
    assert_eq!(report["baseline_failure_count"].as_u64(), Some(0));

    let rows = parse_jsonl(&log_path);
    assert_eq!(rows.len(), 15, "one row per workload x mode");
    for row in &rows {
        for field in REQUIRED_TRACE_FIELDS {
            assert!(row.get(*field).is_some(), "trace row missing {field}");
        }
        assert_eq!(row["bead_id"].as_str(), Some("bd-b92jd.3.2"));
        assert!(
            row["source_commit"]
                .as_str()
                .is_some_and(|value| value.len() == 40),
            "source_commit must be a git SHA"
        );
        assert!(
            row["latency_ns"].as_i64().is_some_and(|value| value >= 0),
            "latency_ns must be non-negative"
        );
    }

    let baseline = rows
        .iter()
        .find(|row| {
            row["workload_id"].as_str() == Some("coreutils_echo_stdout")
                && row["mode"].as_str() == Some("baseline")
        })
        .expect("coreutils baseline row");
    assert_eq!(baseline["baseline_exit"].as_i64(), Some(0));
    assert_eq!(baseline["preload_exit"], serde_json::Value::Null);
    assert_eq!(baseline["failure_signature"].as_str(), Some("none"));
}

#[test]
fn missing_preload_artifact_blocks_strict_and_hardened_without_failing_gate() {
    let (report_path, log_path, output) = run_trace_runner("workload-trace-missing-artifact", &[]);
    assert!(
        output.status.success(),
        "missing preload artifact should be fail-closed evidence, not script failure"
    );
    let report = load_json(&report_path);
    assert_eq!(
        report["preload_artifact"]["failure_signature"].as_str(),
        Some("interpose_artifact_missing")
    );
    let rows = parse_jsonl(&log_path);
    let blocked = rows
        .iter()
        .filter(|row| {
            matches!(row["mode"].as_str(), Some("strict" | "hardened"))
                && row["status"].as_str() == Some("claim_blocked")
                && row["failure_signature"].as_str() == Some("interpose_artifact_missing")
        })
        .count();
    assert_eq!(
        blocked, 8,
        "four non-optional workloads x two preload modes"
    );
}

#[test]
fn optional_tool_rows_skip_cleanly() {
    let (_report_path, log_path, output) = run_trace_runner("workload-trace-optional-skip", &[]);
    assert!(output.status.success(), "optional skip run should pass");
    let rows = parse_jsonl(&log_path);
    let optional_rows: Vec<_> = rows
        .iter()
        .filter(|row| row["workload_id"].as_str() == Some("optional_sqlite_version_probe"))
        .collect();
    assert_eq!(optional_rows.len(), 3);
    for row in optional_rows {
        assert_eq!(row["status"].as_str(), Some("skipped"));
        assert_eq!(
            row["failure_signature"].as_str(),
            Some("optional_tool_missing:sqlite3")
        );
        assert_eq!(row["baseline_exit"], serde_json::Value::Null);
        assert_eq!(row["preload_exit"], serde_json::Value::Null);
    }
}

#[test]
fn trace_artifact_refs_point_to_materialized_files() {
    let (_report_path, log_path, output) = run_trace_runner("workload-trace-artifacts", &[]);
    assert!(output.status.success(), "trace run should pass");
    let root = workspace_root();
    let rows = parse_jsonl(&log_path);
    for row in rows {
        let artifact_refs = row["artifact_refs"].as_array().unwrap();
        assert!(
            artifact_refs.iter().any(|value| value
                .as_str()
                .is_some_and(|path| path.ends_with("trace.json"))),
            "row should include per-row trace.json artifact"
        );
        for artifact_ref in artifact_refs {
            let artifact_ref = artifact_ref.as_str().unwrap();
            if artifact_ref.starts_with("target/") || artifact_ref.contains("/traces/") {
                assert!(
                    root.join(artifact_ref).exists() || Path::new(artifact_ref).exists(),
                    "trace artifact should exist: {artifact_ref}"
                );
            }
        }
    }
}

#[test]
fn validate_only_checks_shape_without_running_workloads() {
    let root = workspace_root();
    let temp = unique_temp_dir("workload-trace-validate-only");
    let report = temp.join("report.json");
    let log = temp.join("log.jsonl");
    let output = Command::new(root.join("scripts/run_user_workload_replay_traces.sh"))
        .arg("--validate-only")
        .env(
            "USER_WORKLOAD_REPLAY_MANIFEST",
            root.join("tests/conformance/user_workload_replay_manifest.v1.json"),
        )
        .env("USER_WORKLOAD_REPLAY_TARGET_DIR", temp.join("traces"))
        .env("USER_WORKLOAD_REPLAY_TRACE_REPORT", &report)
        .env("USER_WORKLOAD_REPLAY_TRACE_LOG", &log)
        .current_dir(&root)
        .output()
        .expect("validate-only should execute");
    assert!(
        output.status.success(),
        "validate-only failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report_json = load_json(&report);
    assert_eq!(report_json["status"].as_str(), Some("pass"));
    assert_eq!(report_json["trace_row_count"].as_u64(), Some(0));
}
