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

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "event",
    "status",
    "reproducer_id",
    "workload_id",
    "mode",
    "failure_signature",
    "failure_class",
    "triage_owner_family",
    "artifact_refs",
    "source_commit",
    "next_safe_action",
];

const COMPLETION_DEBT_SECTIONS: &[(&str, &str)] = &[
    ("unit_primary", "tests.unit.primary"),
    ("e2e_primary", "tests.e2e.primary"),
    ("fuzz_primary", "tests.fuzz.primary"),
    ("conformance_primary", "tests.conformance.primary"),
    ("telemetry_primary", "telemetry.primary"),
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

fn write_json(path: &Path, value: &Value) -> TestResult {
    let content = serde_json::to_string_pretty(value)?;
    std::fs::write(path, format!("{content}\n"))?;
    Ok(())
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
    run_gate_with_contract(root, dir, rows, None)
}

fn run_gate_with_contract(
    root: &Path,
    dir: &Path,
    rows: &[Value],
    contract: Option<&Path>,
) -> TestResult<std::process::Output> {
    let input = write_jsonl(dir, rows)?;
    let mut command = Command::new("bash");
    command
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
        );
    if let Some(contract) = contract {
        command.env("FRANKENLIBC_WORKLOAD_REPRODUCER_CONTRACT", contract);
    }
    let output = command.output()?;
    Ok(output)
}

fn assert_file_line_ref(root: &Path, value: &Value) -> TestResult {
    let reference = value
        .as_str()
        .ok_or_else(|| test_error("file line ref should be string"))?;
    let (path, line) = reference
        .rsplit_once(':')
        .ok_or_else(|| test_error(format!("{reference} should be file:line")))?;
    let line: usize = line.parse()?;
    let content = std::fs::read_to_string(root.join(path))?;
    let source_line = content
        .lines()
        .nth(line.saturating_sub(1))
        .ok_or_else(|| test_error(format!("{reference} points past EOF")))?;
    assert!(
        !source_line.trim().is_empty(),
        "{reference} should not point at a blank line"
    );
    Ok(())
}

fn assert_required_tests_are_declared(evidence: &Value, section: &str, source: &str) -> TestResult {
    let tests = evidence[section]["required_test_names"]
        .as_array()
        .ok_or_else(|| test_error(format!("{section}.required_test_names should be array")))?;
    assert!(
        !tests.is_empty(),
        "{section}.required_test_names should be non-empty"
    );
    for test_name in tests {
        let test_name = test_name
            .as_str()
            .ok_or_else(|| test_error("required test name should be string"))?;
        assert!(
            source.contains(&format!("fn {test_name}(")),
            "{section} references missing test {test_name}"
        );
    }
    Ok(())
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
fn completion_debt_evidence_binds_all_missing_items() -> TestResult {
    let root = workspace_root()?;
    let contract = load_json(&root.join("tests/conformance/workload_reproducer_manifest.v1.json"))?;
    let evidence = json_field(&contract, "completion_debt_evidence")?;

    assert_eq!(evidence["bead"].as_str(), Some("bd-26xb.1.1"));
    assert_eq!(evidence["original_bead"].as_str(), Some("bd-26xb.1"));
    assert_eq!(evidence["original_audit_score"].as_u64(), Some(470));
    assert!(
        evidence["next_audit_score_threshold"]
            .as_u64()
            .is_some_and(|score| score >= 800)
    );

    let test_source = evidence["test_source"]
        .as_str()
        .ok_or_else(|| test_error("completion debt test_source should be string"))?;
    let test_source_text = std::fs::read_to_string(root.join(test_source))?;

    let implementation_refs = evidence["implementation_refs"]
        .as_array()
        .ok_or_else(|| test_error("implementation_refs should be array"))?;
    assert!(
        implementation_refs.len() >= 4,
        "completion debt evidence should cite concrete implementation refs"
    );
    for reference in implementation_refs {
        assert_file_line_ref(&root, reference)?;
    }

    for (section, missing_item) in COMPLETION_DEBT_SECTIONS {
        assert_eq!(
            evidence[*section]["missing_item_id"].as_str(),
            Some(*missing_item),
            "{section}.missing_item_id"
        );
        assert!(
            evidence[*section]["next_audit_score_threshold"]
                .as_u64()
                .is_some_and(|score| score >= 800),
            "{section}.next_audit_score_threshold"
        );
        assert_required_tests_are_declared(evidence, section, &test_source_text)?;
    }

    let axes: BTreeSet<_> = evidence["fuzz_primary"]["deterministic_mutation_axes"]
        .as_array()
        .ok_or_else(|| test_error("fuzz mutation axes should be array"))?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for axis in [
        "failure_signature",
        "source_kind",
        "mode",
        "required_field_omission",
    ] {
        assert!(axes.contains(axis), "missing fuzz mutation axis {axis}");
    }

    let telemetry_fields: BTreeSet<_> = evidence["telemetry_primary"]["required_log_fields"]
        .as_array()
        .ok_or_else(|| test_error("telemetry required_log_fields should be array"))?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for field in REQUIRED_LOG_FIELDS {
        assert!(
            telemetry_fields.contains(field),
            "telemetry evidence missing log field {field}"
        );
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
    assert_eq!(
        report["completion_debt_evidence"]["bead"].as_str(),
        Some("bd-26xb.1.1")
    );
    assert_eq!(
        report["summary"]["completion_debt_bead"].as_str(),
        Some("bd-26xb.1.1")
    );

    let manifest = load_json(&dir.join("reproducer.manifest.json"))?;
    assert_eq!(manifest["status"].as_str(), Some("pass"));
    assert_eq!(
        manifest["completion_debt_evidence"]["original_bead"].as_str(),
        Some("bd-26xb.1")
    );
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
        assert_eq!(row["completion_debt_bead"].as_str(), Some("bd-26xb.1.1"));
        assert_eq!(
            row["completion_debt_original_bead"].as_str(),
            Some("bd-26xb.1")
        );
    }
    Ok(())
}

#[test]
fn gate_rejects_stale_completion_debt_test_binding() -> TestResult {
    let root = workspace_root()?;
    let dir = unique_output_dir(&root, "workload-reproducer-stale-completion")?;
    let mut contract =
        load_json(&root.join("tests/conformance/workload_reproducer_manifest.v1.json"))?;
    contract["completion_debt_evidence"]["unit_primary"]["required_test_names"] =
        json!(["missing_completion_debt_test_binding"]);
    let contract_path = dir.join("broken-contract.json");
    write_json(&contract_path, &contract)?;

    let output = run_gate_with_contract(&root, &dir, &fixture_rows(), Some(&contract_path))?;
    assert!(
        !output.status.success(),
        "stale completion debt binding should fail"
    );
    let report = load_json(&dir.join("reproducer.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    let errors = report["errors"]
        .as_array()
        .ok_or_else(|| test_error("report.errors should be array"))?;
    assert!(
        errors.iter().any(|error| error
            .as_str()
            .is_some_and(|text| text.contains("missing_completion_debt_test_binding"))),
        "report should include stale completion debt test binding error"
    );
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
