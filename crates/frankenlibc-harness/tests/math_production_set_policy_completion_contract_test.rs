use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

static CHECKER_LOCK: Mutex<()> = Mutex::new(());

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate directory has workspace parent")
        .parent()
        .expect("workspace parent has repo parent")
        .to_path_buf()
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/math_production_set_policy_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_math_production_set_policy_completion_contract.sh")
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
        "math_production_set_policy_completion_contract_{label}_{}_{}",
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
            "FRANKENLIBC_MATH_PRODUCTION_POLICY_COMPLETION_CONTRACT",
            contract,
        )
        .env(
            "FRANKENLIBC_MATH_PRODUCTION_POLICY_COMPLETION_OUT_DIR",
            out_dir,
        )
        .env(
            "FRANKENLIBC_MATH_PRODUCTION_POLICY_COMPLETION_REPORT",
            out_dir.join("math_production_set_policy_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_MATH_PRODUCTION_POLICY_COMPLETION_LOG",
            out_dir.join("math_production_set_policy_completion_contract.log.jsonl"),
        )
        .output()?)
}

fn run_checker_serial(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<Output> {
    let _guard = CHECKER_LOCK.lock().map_err(|_| "checker lock poisoned")?;
    run_checker(root, contract, out_dir)
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
fn manifest_binds_unit_completion_evidence() -> TestResult {
    let root = repo_root();
    let manifest = load_json(&contract_path(&root))?;
    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("math_production_set_policy_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-25pf"));
    assert_eq!(manifest["completion_debt_bead"].as_str(), Some("bd-25pf.1"));

    let source_artifacts = manifest["source_artifacts"]
        .as_object()
        .ok_or("source_artifacts object")?;
    for required in [
        "production_set_policy",
        "production_set_policy_gate",
        "source_harness_test",
        "production_manifest",
        "governance",
        "linkage",
        "value_proof",
        "retirement_policy",
        "admission_report",
        "completion_checker",
        "completion_harness_test",
    ] {
        let path = source_artifacts[required].as_str().ok_or("source path")?;
        assert!(root.join(path).exists(), "source artifact missing: {path}");
    }

    let bindings = manifest["missing_item_bindings"]
        .as_array()
        .ok_or("missing_item_bindings array")?;
    let unit = bindings
        .iter()
        .find(|item| item["id"].as_str() == Some("tests.unit.primary"))
        .ok_or("tests.unit.primary binding")?;
    assert_eq!(unit["kind"].as_str(), Some("unit"));
    let required_tests: Vec<_> = unit["required_test_refs"]
        .as_array()
        .ok_or("required_test_refs array")?
        .iter()
        .filter_map(|item| item.as_str())
        .collect();
    for required in [
        "policy_exists_and_basic_fields_are_valid",
        "policy_summary_matches_current_artifacts",
        "gate_script_exists_and_executable",
        "gate_script_emits_logs_and_report",
        "manifest_binds_unit_completion_evidence",
        "checker_validates_math_production_set_policy_contract",
    ] {
        assert!(required_tests.contains(&required), "missing {required}");
    }

    let policy = load_json(&root.join("tests/conformance/math_production_set_policy.v1.json"))?;
    assert_eq!(policy["bead"].as_str(), Some("bd-25pf"));
    assert_eq!(
        policy["summary"]["total_production_modules"].as_u64(),
        Some(25)
    );
    assert_eq!(policy["summary"]["missing_value_proof"].as_u64(), Some(0));

    Ok(())
}

#[test]
fn checker_validates_math_production_set_policy_contract() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "validates")?;
    let output = run_checker_serial(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report =
        load_json(&out_dir.join("math_production_set_policy_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["source_bead"].as_str(), Some("bd-25pf"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-25pf.1"));
    assert_eq!(report["summary"]["production_modules"].as_u64(), Some(25));
    assert_eq!(report["summary"]["source_gate_rows"].as_u64(), Some(25));
    assert_eq!(
        report["summary"]["source_gate_failure_count"].as_u64(),
        Some(0)
    );

    Ok(())
}

#[test]
fn checker_emits_completion_report_and_jsonl() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "jsonl")?;
    let output = run_checker_serial(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report =
        load_json(&out_dir.join("math_production_set_policy_completion_contract.report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("math_production_set_policy_completion_contract.report.v1")
    );
    let events = string_values(&report["events"])?;
    for event in [
        "math_production_set_policy_completion_summary",
        "math_production_set_policy_source_bindings",
        "math_production_set_policy_test_bindings",
        "math_production_set_policy_completion_contract_pass",
    ] {
        assert!(events.iter().any(|value| value == event), "missing {event}");
    }

    let rows =
        read_jsonl(&out_dir.join("math_production_set_policy_completion_contract.log.jsonl"))?;
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
fn checker_rejects_missing_policy_source_binding() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "missing_source")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["source_artifacts"]
        .as_object_mut()
        .ok_or("source_artifacts object")?
        .remove("value_proof");
    let mutated = out_dir.join("missing_source_contract.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker_serial(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing source binding:\n{}",
        output_text(&output)
    );
    let report =
        load_json(&out_dir.join("math_production_set_policy_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .ok_or("errors array")?
            .iter()
            .any(|error| error.as_str().unwrap_or("").contains("value_proof")),
        "report should name missing value_proof binding: {report}"
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_source_test_ref() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "missing_test_ref")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["test_sources"]["source_harness_test"]
        ["required_test_refs"]
        .as_array_mut()
        .ok_or("required_test_refs array")?
        .push(json!("missing_math_production_set_policy_test_ref"));
    let mutated = out_dir.join("missing_test_ref_contract.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker_serial(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing test ref:\n{}",
        output_text(&output)
    );
    let report =
        load_json(&out_dir.join("math_production_set_policy_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .ok_or("errors array")?
            .iter()
            .any(|error| error
                .as_str()
                .unwrap_or("")
                .contains("missing_math_production_set_policy_test_ref")),
        "report should name missing test ref: {report}"
    );

    Ok(())
}

#[test]
fn checker_rejects_unimplemented_telemetry_event() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "missing_event")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["telemetry_contract"]["required_events"]
        .as_array_mut()
        .ok_or("required_events array")?
        .push(json!("missing_math_production_set_policy_completion_event"));
    let mutated = out_dir.join("missing_event_contract.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker_serial(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing event:\n{}",
        output_text(&output)
    );
    let report =
        load_json(&out_dir.join("math_production_set_policy_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .ok_or("errors array")?
            .iter()
            .any(|error| error
                .as_str()
                .unwrap_or("")
                .contains("missing_math_production_set_policy_completion_event")),
        "report should name missing event: {report}"
    );

    Ok(())
}
