use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn repo_root() -> TestResult<PathBuf> {
    Ok(Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| invalid_data("crate directory has workspace parent"))?
        .parent()
        .ok_or_else(|| invalid_data("workspace parent has repo root"))?
        .to_path_buf())
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/verification_matrix_schema_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_verification_matrix_schema_completion_contract.sh")
}

fn read_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn read_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    std::fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let path = root.join("target/conformance").join(format!(
        "verification-matrix-schema-completion-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<Output> {
    let beads_fixture = out_dir.join("verification_matrix_schema_empty_beads.jsonl");
    std::fs::write(&beads_fixture, "")?;
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_VERIFY_MATRIX_SCHEMA_CONTRACT", contract)
        .env("FRANKENLIBC_VERIFY_MATRIX_SCHEMA_OUT_DIR", out_dir)
        .env("FRANKENLIBC_VERIFY_MATRIX_SCHEMA_BEADS", beads_fixture)
        .env(
            "FRANKENLIBC_VERIFY_MATRIX_SCHEMA_REPORT",
            out_dir.join("verification_matrix_schema_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_VERIFY_MATRIX_SCHEMA_LOG",
            out_dir.join("verification_matrix_schema_completion_contract.log.jsonl"),
        )
        .env(
            "FRANKENLIBC_VERIFY_MATRIX_SCHEMA_GATE_TRANSCRIPT",
            out_dir.join("verification_matrix_schema_completion_contract.gate.txt"),
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

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn json_array<'a>(value: &'a Value, name: &str) -> TestResult<&'a [Value]> {
    value
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| invalid_data(format!("{name} must be array")).into())
}

fn json_array_mut<'a>(value: &'a mut Value, name: &str) -> TestResult<&'a mut Vec<Value>> {
    value
        .as_array_mut()
        .ok_or_else(|| invalid_data(format!("{name} must be array")).into())
}

fn json_str<'a>(value: &'a Value, name: &str) -> TestResult<&'a str> {
    value
        .as_str()
        .ok_or_else(|| invalid_data(format!("{name} must be string")).into())
}

fn string_set(value: &Value) -> TestResult<BTreeSet<String>> {
    let mut items = BTreeSet::new();
    for item in json_array(value, "expected array")? {
        items.insert(json_str(item, "expected string")?.to_owned());
    }
    Ok(items)
}

fn assert_checker_failed(output: &Output) {
    assert!(
        !output.status.success(),
        "checker unexpectedly passed:\n{}",
        output_text(output)
    );
}

#[test]
fn manifest_binds_verification_matrix_schema_evidence() -> TestResult {
    let root = repo_root()?;
    let manifest = read_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("verification_matrix_schema_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-1s7"));
    assert_eq!(manifest["completion_debt_bead"].as_str(), Some("bd-1s7.1"));
    assert_eq!(
        string_set(&manifest["completion_debt_evidence"]["missing_items_closed"])?,
        BTreeSet::from([
            "tests.e2e.primary".to_string(),
            "tests.conformance.primary".to_string()
        ])
    );

    let artifacts = manifest["source_artifacts"]
        .as_object()
        .ok_or_else(|| invalid_data("source_artifacts must be object"))?;
    for key in [
        "verification_matrix",
        "verification_matrix_gate",
        "verification_matrix_harness",
        "completion_checker",
        "completion_harness",
    ] {
        assert!(artifacts.contains_key(key), "missing artifact {key}");
        let artifact = artifacts
            .get(key)
            .ok_or_else(|| invalid_data(format!("missing artifact {key}")))?;
        let path = json_str(artifact, "artifact path")?;
        assert!(root.join(path).exists(), "artifact should exist: {path}");
    }

    let contract = &manifest["required_schema_contract"];
    assert_eq!(contract["matrix_version"].as_u64(), Some(1));
    assert_eq!(contract["row_schema_version"].as_str(), Some("v1"));
    assert_eq!(
        string_set(&contract["required_stream_examples"])?,
        BTreeSet::from([
            "docs".to_string(),
            "e2e".to_string(),
            "syscall".to_string(),
            "stubs".to_string(),
            "math".to_string(),
            "perf".to_string()
        ])
    );

    let e2e_refs = json_array(
        &manifest["completion_debt_evidence"]["e2e_primary"]["required_test_refs"],
        "e2e refs",
    )?;
    assert!(e2e_refs.len() >= 7, "expected e2e refs: {e2e_refs:?}");
    let conformance_refs = json_array(
        &manifest["completion_debt_evidence"]["conformance_primary"]["required_test_refs"],
        "conformance refs",
    )?;
    assert!(
        conformance_refs.len() >= 8,
        "expected conformance refs: {conformance_refs:?}"
    );

    Ok(())
}

#[test]
fn checker_validates_schema_contract_and_emits_report_log() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "pass")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report_path = out_dir.join("verification_matrix_schema_completion_contract.report.json");
    let log_path = out_dir.join("verification_matrix_schema_completion_contract.log.jsonl");
    let report = read_json(&report_path)?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(
        report["schema_summary"]["row_schema_version"].as_str(),
        Some("v1")
    );
    assert_eq!(
        string_set(&report["schema_summary"]["stream_examples"])?,
        BTreeSet::from([
            "docs".to_string(),
            "e2e".to_string(),
            "syscall".to_string(),
            "stubs".to_string(),
            "math".to_string(),
            "perf".to_string()
        ])
    );
    assert_eq!(
        json_array(&report["e2e_bindings"], "e2e_bindings")?.len(),
        7
    );
    assert_eq!(
        json_array(&report["conformance_bindings"], "conformance_bindings")?.len(),
        8
    );
    let errors = json_array(&report["errors"], "errors")?;
    assert!(errors.is_empty());

    let events = read_jsonl(&log_path)?;
    let event_names: BTreeSet<String> = events
        .iter()
        .filter_map(|event| event["event"].as_str().map(ToOwned::to_owned))
        .collect();
    assert_eq!(
        event_names,
        BTreeSet::from([
            "verification_matrix_schema_e2e_bindings_verified".to_string(),
            "verification_matrix_schema_conformance_bindings_verified".to_string(),
            "verification_matrix_schema_gate_replayed".to_string(),
            "verification_matrix_schema_contract_verified".to_string(),
            "verification_matrix_schema_completion_contract_pass".to_string()
        ])
    );
    for event in events {
        for field in [
            "timestamp",
            "trace_id",
            "event",
            "bead_id",
            "source_bead",
            "completion_debt_bead",
            "source_commit",
            "status",
            "outcome",
            "artifact_refs",
            "failure_signature",
            "details",
        ] {
            assert!(event.get(field).is_some(), "event missing {field}: {event}");
        }
    }

    Ok(())
}

#[test]
fn checker_replays_verification_matrix_schema_gate() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "gate")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let gate_text = std::fs::read_to_string(
        out_dir.join("verification_matrix_schema_completion_contract.gate.txt"),
    )?;
    assert!(gate_text.contains("PASS: Schema structure is valid"));
    assert!(gate_text.contains("PASS: All open/in_progress critique beads have verification rows"));
    assert!(gate_text.contains("check_verification_matrix: PASS"));

    Ok(())
}

#[test]
fn checker_rejects_missing_stream_example() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing-stream")?;
    let mut manifest = read_json(&contract_path(&root))?;
    json_array_mut(
        &mut manifest["required_schema_contract"]["required_stream_examples"],
        "required_stream_examples",
    )?
    .push(json!("impossible_stream"));
    let mutated = out_dir.join("verification_matrix_schema_missing_stream.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report =
        read_json(&out_dir.join("verification_matrix_schema_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .to_string()
            .contains("missing required streams"),
        "report should cite missing stream: {report}"
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_gate_token() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing-token")?;
    let mut manifest = read_json(&contract_path(&root))?;
    json_array_mut(
        &mut manifest["required_schema_contract"]["required_source_text"]["verification_matrix_gate"],
        "verification_matrix_gate needles",
    )?
    .push(json!(
        "verification matrix gate must emit this intentionally missing schema token"
    ));
    let mutated = out_dir.join("verification_matrix_schema_missing_token.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report =
        read_json(&out_dir.join("verification_matrix_schema_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .to_string()
            .contains("verification_matrix_gate"),
        "report should cite missing gate token: {report}"
    );

    Ok(())
}

#[test]
fn checker_rejects_local_cargo_command() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "local-cargo")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["e2e_primary"]["required_commands"] =
        json!(["cargo test -p frankenlibc-harness --test verification_matrix_test"]);
    let mutated = out_dir.join("verification_matrix_schema_local_cargo.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report =
        read_json(&out_dir.join("verification_matrix_schema_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"].to_string().contains("rch-backed"),
        "report should cite local cargo command: {report}"
    );

    Ok(())
}
