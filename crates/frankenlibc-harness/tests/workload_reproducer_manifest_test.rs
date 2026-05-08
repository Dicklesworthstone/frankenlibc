//! Integration test: workload reproducer manifest gate (bd-fp4tm.3).
//!
//! Verifies that workload replay and LD_PRELOAD smoke failure rows become
//! compact reproducers and that rows without command/env/mode fail closed.

use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const REQUIRED_FAILURE_SIGNATURES: &[&str] = &[
    "startup_timeout",
    "startup_segv",
    "startup_symbol_lookup_error",
    "startup_strict_parity_mismatch",
    "startup_perf_regression",
    "unsupported_workload",
    "missing_binary",
];

const REQUIRED_REPRODUCER_FIELDS: &[&str] = &[
    "reproducer_id",
    "source_trace_id",
    "source_kind",
    "workload_id",
    "mode",
    "command",
    "env",
    "input_files",
    "timeout_ms",
    "exit_status",
    "stdout_excerpt",
    "stderr_excerpt",
    "failure_signature",
    "failure_class",
    "artifact_refs",
    "triage_owner_family",
    "reproduction_command",
    "next_safe_action",
    "minimization_state",
    "source_commit",
];

fn test_error(message: impl Into<String>) -> Box<dyn std::error::Error> {
    Box::new(std::io::Error::other(message.into()))
}

fn workspace_root() -> TestResult<PathBuf> {
    Ok(Path::new(env!("CARGO_MANIFEST_DIR"))
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

fn failure_row(workload_id: &str, mode: &str, signature: &str) -> Value {
    json!({
        "trace_id": format!("fixture::{workload_id}::{mode}"),
        "bead_id": "bd-b92jd.3.2",
        "workload_id": workload_id,
        "mode": mode,
        "command": ["/bin/echo", workload_id],
        "env": {
            "FRANKENLIBC_MODE": mode,
            "LD_PRELOAD": "target/release/libfrankenlibc_abi.so"
        },
        "input_files": [
            "tests/conformance/user_workload_replay_manifest.v1.json"
        ],
        "timeout_ms": 5000,
        "preload_exit": 1,
        "stdout": "",
        "stderr": format!("synthetic failure: {signature}"),
        "status": "fail",
        "failure_signature": signature,
        "artifact_refs": [
            "tests/conformance/user_workload_replay_manifest.v1.json"
        ],
        "source_commit": "0123456789abcdef0123456789abcdef01234567"
    })
}

fn smoke_failure_row(workload_id: &str, signature: &str) -> Value {
    json!({
        "trace_id": format!("ld-smoke::{workload_id}"),
        "bead_id": "bd-1ah8",
        "event": "ld_preload_failure",
        "case": workload_id,
        "mode": "strict",
        "command": ["/usr/bin/python3", "-c", "print('smoke')"],
        "env": {
            "FRANKENLIBC_MODE": "strict",
            "LD_PRELOAD": "target/release/libfrankenlibc_abi.so"
        },
        "timeout_seconds": 10,
        "preload_rc": 127,
        "stdout": "",
        "stderr": "symbol lookup error: missing_symbol",
        "status": "fail",
        "failure_signature": signature,
        "artifact_refs": [
            "tests/conformance/ld_preload_smoke_summary.v1.json"
        ],
        "source_commit": "0123456789abcdef0123456789abcdef01234567"
    })
}

fn fixture_rows() -> Vec<Value> {
    vec![
        failure_row("timeout_fixture", "strict", "startup_timeout"),
        failure_row("segv_fixture", "hardened", "startup_segv"),
        smoke_failure_row("symbol_lookup_fixture", "startup_symbol_lookup_error"),
        failure_row("parity_fixture", "strict", "startup_strict_parity_mismatch"),
        failure_row("perf_fixture", "hardened", "startup_perf_regression"),
        failure_row("unsupported_fixture", "strict", "unsupported_workload"),
        failure_row("missing_binary_fixture", "strict", "missing_binary"),
        json!({
            "trace_id": "fixture::passing::baseline",
            "bead_id": "bd-b92jd.3.2",
            "workload_id": "passing",
            "mode": "baseline",
            "command": ["/bin/true"],
            "env": {},
            "status": "pass",
            "failure_signature": "none",
            "artifact_refs": []
        }),
    ]
}

fn write_jsonl(dir: &Path, rows: &[Value]) -> TestResult<PathBuf> {
    let log = dir.join("trace.log.jsonl");
    let mut content = String::new();
    for row in rows {
        content.push_str(&serde_json::to_string(row)?);
        content.push('\n');
    }
    std::fs::write(&log, content)?;
    Ok(log)
}

fn run_gate(root: &Path, dir: &Path, rows: &[Value]) -> TestResult<std::process::Output> {
    let input = write_jsonl(dir, rows)?;
    let output = Command::new("bash")
        .arg(root.join("scripts/check_workload_reproducer_manifest.sh"))
        .current_dir(root)
        .env("FRANKENLIBC_WORKLOAD_REPRODUCER_INPUTS", &input)
        .env("FRANKENLIBC_WORKLOAD_REPRODUCER_OUT_DIR", dir)
        .env(
            "FRANKENLIBC_WORKLOAD_REPRODUCER_REPORT",
            dir.join("reproducer.report.json"),
        )
        .env(
            "FRANKENLIBC_WORKLOAD_REPRODUCER_MANIFEST",
            dir.join("reproducer.manifest.json"),
        )
        .env(
            "FRANKENLIBC_WORKLOAD_REPRODUCER_LOG",
            dir.join("reproducer.log.jsonl"),
        )
        .output()?;
    Ok(output)
}

#[test]
fn contract_declares_reproducer_schema_and_failure_classes() -> TestResult {
    let root = workspace_root()?;
    let contract = load_json(&root.join("tests/conformance/workload_reproducer_manifest.v1.json"))?;
    assert_eq!(contract["schema_version"].as_str(), Some("v1"));
    assert_eq!(contract["bead"].as_str(), Some("bd-fp4tm.3"));

    let signatures: BTreeSet<_> = json_field(&contract, "required_failure_signatures")?
        .as_array()
        .ok_or_else(|| test_error("required_failure_signatures should be array"))?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for signature in REQUIRED_FAILURE_SIGNATURES {
        assert!(
            signatures.contains(signature),
            "missing failure signature {signature}"
        );
        let entry = &contract["failure_signature_schema"][signature];
        assert!(entry["failure_class"].as_str().is_some());
        assert!(entry["triage_owner_family"].as_str().is_some());
        assert!(entry["next_safe_action"].as_str().is_some());
    }

    let fields: BTreeSet<_> = json_field(&contract, "required_reproducer_fields")?
        .as_array()
        .ok_or_else(|| test_error("required_reproducer_fields should be array"))?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for field in REQUIRED_REPRODUCER_FIELDS {
        assert!(fields.contains(field), "missing reproducer field {field}");
    }
    Ok(())
}

#[test]
fn gate_script_is_executable() -> TestResult {
    let root = workspace_root()?;
    let script = root.join("scripts/check_workload_reproducer_manifest.sh");
    assert!(script.exists(), "missing {}", script.display());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script)?.permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_workload_reproducer_manifest.sh must be executable"
        );
    }
    Ok(())
}

#[test]
fn gate_emits_compact_reproducer_manifest_and_jsonl_log() -> TestResult {
    let root = workspace_root()?;
    let dir = unique_output_dir(&root, "workload-reproducer-pass")?;
    let output = run_gate(&root, &dir, &fixture_rows())?;
    assert!(
        output.status.success(),
        "reproducer gate failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = load_json(&dir.join("reproducer.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["summary"]["input_row_count"].as_u64(), Some(8));
    assert_eq!(report["summary"]["failure_row_count"].as_u64(), Some(7));
    assert_eq!(report["summary"]["reproducer_count"].as_u64(), Some(7));

    let manifest = load_json(&dir.join("reproducer.manifest.json"))?;
    assert_eq!(manifest["status"].as_str(), Some("pass"));
    let reproducers = json_field(&manifest, "reproducers")?
        .as_array()
        .ok_or_else(|| test_error("reproducers should be array"))?;
    assert_eq!(reproducers.len(), 7);

    let mut signatures = BTreeSet::new();
    let mut source_kinds = BTreeSet::new();
    for item in reproducers {
        for field in REQUIRED_REPRODUCER_FIELDS {
            assert!(item.get(*field).is_some(), "reproducer missing {field}");
        }
        signatures.insert(
            item["failure_signature"]
                .as_str()
                .ok_or_else(|| test_error("failure_signature should be string"))?,
        );
        source_kinds.insert(
            item["source_kind"]
                .as_str()
                .ok_or_else(|| test_error("source_kind should be string"))?,
        );
        assert!(
            item["reproduction_command"]
                .as_str()
                .is_some_and(|text| text.contains("FRANKENLIBC_MODE")),
            "reproduction command should include captured env"
        );
    }
    for signature in REQUIRED_FAILURE_SIGNATURES {
        assert!(signatures.contains(signature), "missing {signature}");
    }
    assert!(source_kinds.contains("workload_replay"));
    assert!(source_kinds.contains("ld_preload_smoke"));

    let log_text = std::fs::read_to_string(dir.join("reproducer.log.jsonl"))?;
    let log_rows: Vec<Value> = log_text
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    assert_eq!(log_rows.len(), 7);
    for row in log_rows {
        assert_eq!(row["bead_id"].as_str(), Some("bd-fp4tm.3"));
        assert_eq!(
            row["event"].as_str(),
            Some("workload_reproducer_manifest_row")
        );
        assert_eq!(row["status"].as_str(), Some("pass"));
    }
    Ok(())
}

#[test]
fn failure_rows_missing_command_fail_closed() -> TestResult {
    let root = workspace_root()?;
    let dir = unique_output_dir(&root, "workload-reproducer-missing-command")?;
    let mut rows = vec![failure_row("missing_command", "strict", "startup_timeout")];
    rows[0]
        .as_object_mut()
        .ok_or_else(|| test_error("row should be object"))?
        .remove("command");
    let output = run_gate(&root, &dir, &rows)?;
    assert!(!output.status.success(), "missing command should fail");
    let report = load_json(&dir.join("reproducer.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["failure_signatures"]
            .as_array()
            .ok_or_else(|| test_error("failure_signatures should be array"))?
            .iter()
            .any(|item| item.as_str() == Some("reproducer_missing_command"))
    );
    Ok(())
}

#[test]
fn failure_rows_missing_env_fail_closed() -> TestResult {
    let root = workspace_root()?;
    let dir = unique_output_dir(&root, "workload-reproducer-missing-env")?;
    let mut rows = vec![failure_row("missing_env", "strict", "startup_segv")];
    rows[0]
        .as_object_mut()
        .ok_or_else(|| test_error("row should be object"))?
        .remove("env");
    let output = run_gate(&root, &dir, &rows)?;
    assert!(!output.status.success(), "missing env should fail");
    let report = load_json(&dir.join("reproducer.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["failure_signatures"]
            .as_array()
            .ok_or_else(|| test_error("failure_signatures should be array"))?
            .iter()
            .any(|item| item.as_str() == Some("reproducer_missing_env"))
    );
    Ok(())
}

#[test]
fn failure_rows_missing_mode_fail_closed() -> TestResult {
    let root = workspace_root()?;
    let dir = unique_output_dir(&root, "workload-reproducer-missing-mode")?;
    let mut rows = vec![failure_row("missing_mode", "strict", "missing_binary")];
    rows[0]
        .as_object_mut()
        .ok_or_else(|| test_error("row should be object"))?
        .remove("mode");
    let output = run_gate(&root, &dir, &rows)?;
    assert!(!output.status.success(), "missing mode should fail");
    let report = load_json(&dir.join("reproducer.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["failure_signatures"]
            .as_array()
            .ok_or_else(|| test_error("failure_signatures should be array"))?
            .iter()
            .any(|item| item.as_str() == Some("reproducer_missing_mode"))
    );
    Ok(())
}
