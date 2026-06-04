use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn repo_root() -> TestResult<PathBuf> {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("crate directory should have workspace parent")?;
    let root = crate_dir
        .parent()
        .ok_or("workspace parent should have repo parent")?;
    Ok(root.to_path_buf())
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/golden_fixture_protocol_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_golden_fixture_protocol_completion_contract.sh")
}

fn load_json(path: &Path) -> TestResult<Value> {
    let text = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&text)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let out = root.join("target/conformance").join(format!(
        "golden_fixture_protocol_completion_contract_{label}_{}_{}",
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
        .env("FRANKENLIBC_GOLDEN_FIXTURE_COMPLETION_CONTRACT", contract)
        .env("FRANKENLIBC_GOLDEN_FIXTURE_COMPLETION_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_GOLDEN_FIXTURE_COMPLETION_REPORT",
            out_dir.join("golden_fixture_protocol_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_GOLDEN_FIXTURE_COMPLETION_LOG",
            out_dir.join("golden_fixture_protocol_completion_contract.log.jsonl"),
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

fn read_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    std::fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| Ok(serde_json::from_str::<Value>(line)?))
        .collect()
}

fn string_values(value: &Value) -> TestResult<Vec<String>> {
    let array = value.as_array().ok_or("expected array")?;
    let mut values = Vec::with_capacity(array.len());
    for item in array {
        values.push(item.as_str().ok_or("expected string item")?.to_string());
    }
    Ok(values)
}

#[test]
fn manifest_binds_all_completion_debt_evidence_classes() -> TestResult {
    let root = repo_root()?;
    let manifest = load_json(&contract_path(&root))?;
    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("golden_fixture_protocol_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-15n.3"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-15n.3.1")
    );

    let source_artifacts = manifest["source_artifacts"]
        .as_object()
        .ok_or("source_artifacts object")?;
    for required in [
        "golden_fixture_protocol",
        "conformance_coverage_gate",
        "conformance_coverage_wrapper",
        "conformance_coverage_harness_test",
        "coverage_baseline",
        "coverage_snapshot",
        "golden_gate",
        "golden_update_script",
        "golden_sha256s",
        "golden_markdown",
        "golden_json",
        "golden_suite_json",
        "completion_checker",
        "completion_harness_test",
    ] {
        let path = source_artifacts[required].as_str().ok_or("source path")?;
        assert!(root.join(path).exists(), "source artifact missing: {path}");
    }

    let binding_ids: Vec<_> = manifest["missing_item_bindings"]
        .as_array()
        .ok_or("missing_item_bindings array")?
        .iter()
        .filter_map(|item| item["id"].as_str())
        .collect();
    for required in [
        "tests.unit.primary",
        "tests.e2e.primary",
        "tests.golden.primary",
        "tests.conformance.primary",
    ] {
        assert!(
            binding_ids.contains(&required),
            "missing binding {required}"
        );
    }

    let protocol = load_json(&root.join("tests/conformance/golden_fixture_protocol.v1.json"))?;
    assert_eq!(protocol["bead"].as_str(), Some("bd-15n.3"));
    assert_eq!(
        protocol["protocol"]["capture"]["fixed_timestamp"].as_str(),
        Some("1970-01-01T00:00:00Z")
    );
    assert_eq!(
        protocol["protocol"]["coverage_regression"]["baseline"].as_str(),
        Some("tests/conformance/conformance_coverage_baseline.v1.json")
    );

    Ok(())
}

#[test]
fn checker_validates_golden_fixture_protocol_contract() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "validates")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report =
        load_json(&out_dir.join("golden_fixture_protocol_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["source_bead"].as_str(), Some("bd-15n.3"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-15n.3.1"));
    assert_eq!(report["summary"]["required_outputs"].as_u64(), Some(4));
    let baseline =
        load_json(&root.join("tests/conformance/conformance_coverage_baseline.v1.json"))?;
    let snapshot =
        load_json(&root.join("tests/conformance/conformance_coverage_snapshot.v1.json"))?;
    assert_eq!(
        report["summary"]["coverage_baseline_cases"].as_u64(),
        baseline["summary"]["total_fixture_cases"].as_u64()
    );
    assert_eq!(
        report["summary"]["coverage_snapshot_cases"].as_u64(),
        snapshot["summary"]["total_fixture_cases"].as_u64()
    );

    Ok(())
}

#[test]
fn checker_emits_completion_report_and_jsonl() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "jsonl")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report =
        load_json(&out_dir.join("golden_fixture_protocol_completion_contract.report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("golden_fixture_protocol_completion_contract.report.v1")
    );
    let events = string_values(&report["events"])?;
    for event in [
        "golden_fixture_protocol_completion_summary",
        "golden_fixture_protocol_source_bindings",
        "golden_fixture_protocol_test_bindings",
        "golden_fixture_protocol_completion_contract_pass",
    ] {
        assert!(events.iter().any(|value| value == event), "missing {event}");
    }

    let rows = read_jsonl(&out_dir.join("golden_fixture_protocol_completion_contract.log.jsonl"))?;
    assert_eq!(rows.len(), 4, "checker should emit four telemetry rows");
    for row in rows {
        for field in [
            "timestamp",
            "event",
            "bead_id",
            "source_bead",
            "completion_debt_bead",
            "status",
            "outcome",
            "source_commit",
            "schema_version",
            "artifact_refs",
            "test_refs",
            "failure_signature",
        ] {
            assert!(!row[field].is_null(), "log row missing {field}: {row}");
        }
        assert_eq!(row["status"].as_str(), Some("pass"));
        assert_eq!(row["failure_signature"].as_str(), Some("none"));
    }

    Ok(())
}

#[test]
fn checker_rejects_missing_golden_artifact_binding() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing_golden")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["source_artifacts"]
        .as_object_mut()
        .ok_or("source_artifacts object")?
        .remove("golden_json");
    let mutated = out_dir.join("missing_golden_contract.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing golden artifact binding:\n{}",
        output_text(&output)
    );
    let report =
        load_json(&out_dir.join("golden_fixture_protocol_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .ok_or("errors array")?
            .iter()
            .any(|error| error.as_str().unwrap_or("").contains("golden_json")),
        "report should name missing golden_json binding: {report}"
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_source_test_ref() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing_test_ref")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["test_sources"]["source_harness_test"]
        ["required_test_refs"]
        .as_array_mut()
        .ok_or("required_test_refs array")?
        .push(json!("missing_golden_fixture_protocol_test_ref"));
    let mutated = out_dir.join("missing_test_ref_contract.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing test ref:\n{}",
        output_text(&output)
    );
    let report =
        load_json(&out_dir.join("golden_fixture_protocol_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .ok_or("errors array")?
            .iter()
            .any(|error| error
                .as_str()
                .unwrap_or("")
                .contains("missing_golden_fixture_protocol_test_ref")),
        "report should name missing test ref: {report}"
    );

    Ok(())
}

#[test]
fn checker_rejects_unimplemented_telemetry_event() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing_event")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["telemetry_contract"]["required_events"]
        .as_array_mut()
        .ok_or("required_events array")?
        .push(json!("missing_golden_fixture_protocol_completion_event"));
    let mutated = out_dir.join("missing_event_contract.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing event:\n{}",
        output_text(&output)
    );
    let report =
        load_json(&out_dir.join("golden_fixture_protocol_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .ok_or("errors array")?
            .iter()
            .any(|error| error
                .as_str()
                .unwrap_or("")
                .contains("missing_golden_fixture_protocol_completion_event")),
        "report should name missing event: {report}"
    );

    Ok(())
}
