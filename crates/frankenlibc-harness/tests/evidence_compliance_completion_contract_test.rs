//! Completion-debt contract tests for bd-33p.3 / bd-33p.3.1.

use frankenlibc_harness::structured_log::validate_log_line;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let crates_dir = manifest
        .parent()
        .ok_or_else(|| io::Error::other("frankenlibc-harness manifest must have a parent"))?;
    let root = crates_dir.parent().ok_or_else(|| {
        io::Error::other("frankenlibc-harness manifest must live below workspace root")
    })?;
    Ok(root.to_path_buf())
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/evidence_compliance_gate_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_evidence_compliance_completion_contract.sh")
}

fn evidence_gate_path(root: &Path) -> PathBuf {
    root.join("scripts/check_evidence_compliance.sh")
}

fn load_json(path: &Path) -> TestResult<Value> {
    let text = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&text)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let out = root.join("target/conformance").join(format!(
        "evidence_compliance_completion_contract_{label}_{}_{}",
        std::process::id(),
        stamp
    ));
    std::fs::create_dir_all(&out)?;
    Ok(out)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env(
            "FRANKENLIBC_EVIDENCE_COMPLIANCE_COMPLETION_CONTRACT",
            contract,
        )
        .env(
            "FRANKENLIBC_EVIDENCE_COMPLIANCE_COMPLETION_REPORT",
            out_dir.join("evidence_compliance_gate_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_EVIDENCE_COMPLIANCE_COMPLETION_LOG",
            out_dir.join("evidence_compliance_gate_completion_contract.log.jsonl"),
        )
        .output()?)
}

fn output_text(output: &Output) -> String {
    format!(
        "status={}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn strings(value: &Value) -> TestResult<BTreeSet<String>> {
    value
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "expected array"))?
        .iter()
        .map(|item| {
            item.as_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "expected string").into())
                .map(str::to_owned)
        })
        .collect()
}

fn assert_file_line_ref_exists(root: &Path, file_line_ref: &str) -> TestResult {
    let (path, line) = file_line_ref.rsplit_once(':').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "file-line ref should contain ':'",
        )
    })?;
    let line_no: usize = line.parse()?;
    assert!(line_no > 0, "file-line ref line must be positive");
    let full_path = root.join(path);
    assert!(
        full_path.exists(),
        "file-line ref path should exist: {file_line_ref}"
    );
    let line_count = std::fs::read_to_string(&full_path)?.lines().count();
    assert!(
        line_no <= line_count,
        "file-line ref outside file: {file_line_ref}"
    );
    Ok(())
}

#[test]
fn evidence_compliance_gate_script_locks_rch_execution_contract() -> TestResult {
    let root = workspace_root()?;
    let script = evidence_gate_path(&root);
    let text = std::fs::read_to_string(&script)?;

    for required in [
        "RUN_MODE=\"rch\"",
        "--rch",
        "--local",
        "RCH_REQUIRE_REMOTE=1",
        "rch exec --",
        "run_cargo cargo build -p frankenlibc-harness --bin harness",
        "run_cargo cargo test -p frankenlibc-harness --test evidence_compliance_test -- --nocapture",
        "cargo build -p frankenlibc-harness --bin harness",
        "cargo test -p frankenlibc-harness --test evidence_compliance_test -- --nocapture",
        "check_evidence_compliance: PASS",
    ] {
        assert!(
            text.contains(required),
            "evidence compliance gate script should contain contract fragment {required:?}"
        );
    }

    let help = Command::new(&script)
        .arg("--help")
        .current_dir(&root)
        .output()?;
    assert!(
        help.status.success(),
        "evidence compliance gate --help failed:\n{}",
        output_text(&help)
    );
    let help_text = String::from_utf8_lossy(&help.stdout);
    assert!(help_text.contains("--rch"));
    assert!(help_text.contains("--local"));
    assert!(help_text.contains("default"));

    Ok(())
}

#[test]
fn manifest_binds_evidence_compliance_completion_debt() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&contract_path(&root))?;
    let evidence = &manifest["completion_debt_evidence"];

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("evidence_compliance_gate_completion_contract.v1")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-33p.3"));
    assert_eq!(evidence["bead"].as_str(), Some("bd-33p.3.1"));
    assert_eq!(evidence["original_bead"].as_str(), Some("bd-33p.3"));

    for source in manifest["source_modules"]
        .as_array()
        .ok_or("source_modules must be array")?
    {
        let source = source.as_str().ok_or("source path string")?;
        assert!(
            root.join(source).exists(),
            "source module should exist: {source}"
        );
    }

    let sources = evidence["test_sources"]
        .as_object()
        .ok_or("test_sources should be object")?;
    let mut source_texts = std::collections::BTreeMap::new();
    for (key, path) in sources {
        let path = path.as_str().ok_or("test source path string")?;
        source_texts.insert(key.as_str(), std::fs::read_to_string(root.join(path))?);
    }

    for (section, missing_item_id) in [
        ("unit_primary", "tests.unit.primary"),
        ("e2e_primary", "tests.e2e.primary"),
        ("conformance_primary", "tests.conformance.primary"),
    ] {
        let section_value = &evidence[section];
        assert_eq!(
            section_value["missing_item_id"].as_str(),
            Some(missing_item_id),
            "{section} should bind its audit missing item"
        );
        let refs = section_value["required_test_refs"]
            .as_array()
            .ok_or("required_test_refs should be array")?;
        assert!(!refs.is_empty(), "{section} should name required tests");
        for test_ref in refs {
            let source = test_ref["source"].as_str().ok_or("source string")?;
            let name = test_ref["name"].as_str().ok_or("name string")?;
            let text = source_texts.get(source).ok_or("declared test source")?;
            assert!(
                text.contains(&format!("fn {name}")),
                "{section} references missing test {source}::{name}"
            );
        }
    }

    let refs = evidence["implementation_refs"]
        .as_array()
        .ok_or("implementation refs missing")?;
    assert!(
        refs.len() >= 15,
        "implementation refs should cover validator, CLI, tests, scripts, and contract surfaces"
    );
    for file_line_ref in refs {
        assert_file_line_ref_exists(&root, file_line_ref.as_str().ok_or("ref string")?)?;
    }

    let contract = &evidence["compliance_contract"];
    let violation_codes = strings(&contract["required_violation_codes"])?;
    for code in [
        "log.schema_violation",
        "failure_event.missing_artifact_refs",
        "failure_artifact_ref.not_indexed",
        "artifact_index.sha_mismatch",
    ] {
        assert!(
            violation_codes.contains(code),
            "contract should require violation code {code}"
        );
    }
    let triage_fields = strings(&contract["required_triage_fields"])?;
    for field in [
        "violation_code",
        "offending_event",
        "expected_fields",
        "remediation_hint",
        "artifact_pointer",
    ] {
        assert!(
            triage_fields.contains(field),
            "contract should require triage field {field}"
        );
    }

    Ok(())
}

#[test]
fn checker_emits_report_and_structured_log_row() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_out_dir(&root, "pass")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report =
        load_json(&out_dir.join("evidence_compliance_gate_completion_contract.report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("evidence_compliance_gate_completion_contract.report.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-33p.3.1"));
    assert_eq!(report["original_bead"].as_str(), Some("bd-33p.3"));
    assert_eq!(report["violation_codes"].as_array().map(Vec::len), Some(15));
    assert_eq!(report["triage_fields"].as_array().map(Vec::len), Some(7));

    let log_path = out_dir.join("evidence_compliance_gate_completion_contract.log.jsonl");
    let log_text = std::fs::read_to_string(&log_path)?;
    let row: Value = serde_json::from_str(log_text.trim())?;
    assert_eq!(
        row["event"].as_str(),
        Some("evidence_compliance_gate_completion_contract_validated")
    );
    assert_eq!(row["outcome"].as_str(), Some("pass"));
    assert_eq!(row["failure_signature"].as_str(), Some("none"));
    assert_eq!(row["stream"].as_str(), Some("conformance"));
    assert_eq!(
        row["gate"].as_str(),
        Some("evidence_compliance_gate_completion_contract")
    );
    assert_eq!(row["violation_code_count"].as_u64(), Some(15));
    for field in [
        "timestamp",
        "trace_id",
        "level",
        "event",
        "artifact_refs",
        "bead_id",
        "source_commit",
        "failure_signature",
    ] {
        assert!(row.get(field).is_some(), "log row missing {field}");
    }
    validate_log_line(&serde_json::to_string(&row)?, 1)
        .map_err(|errors| io::Error::other(format!("structured log rejected: {errors:?}")))?;

    Ok(())
}

#[test]
fn checker_rejects_removed_violation_code() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_out_dir(&root, "missing_code")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["compliance_contract"]["required_violation_codes"] =
        json!([
            "artifact_index.join_keys.empty",
            "artifact_index.join_keys.bad_trace_id",
            "artifact_index.join_keys.bad_decision_id",
            "artifact_index.join_keys.bad_policy_id",
            "artifact_index.missing",
            "artifact_index.invalid_json",
            "artifact_index.bad_version",
            "artifact_index.artifact_missing",
            "artifact_index.sha_error",
            "log.schema_violation",
            "log.missing",
            "failure_event.missing_artifact_refs",
            "failure_artifact_ref.missing",
            "failure_artifact_ref.not_indexed"
        ]);
    let bad_contract = out_dir.join("missing_sha_mismatch.json");
    write_json(&bad_contract, &manifest)?;

    let output = run_checker(&root, &bad_contract, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing required violation code"
    );

    let report =
        load_json(&out_dir.join("evidence_compliance_gate_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    let errors = report["errors"].as_array().ok_or("errors array")?;
    assert!(
        errors.iter().filter_map(Value::as_str).any(|message| {
            message.contains("required_violation_codes missing")
                && message.contains("artifact_index.sha_mismatch")
        }),
        "failure report should mention removed violation code"
    );

    let log_text = std::fs::read_to_string(
        out_dir.join("evidence_compliance_gate_completion_contract.log.jsonl"),
    )?;
    let row: Value = serde_json::from_str(log_text.trim())?;
    assert_eq!(
        row["event"].as_str(),
        Some("evidence_compliance_gate_completion_contract_failed")
    );
    assert!(
        row["failure_signature"]
            .as_str()
            .is_some_and(|value| value.contains("artifact_index.sha_mismatch")),
        "failure log should include removed violation code"
    );

    Ok(())
}
