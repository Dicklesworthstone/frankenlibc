use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate directory has workspace parent")
        .parent()
        .expect("workspace parent has repo parent")
        .to_path_buf()
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/universal_evidence_schema_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_universal_evidence_schema_completion_contract.sh")
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
        "universal_evidence_schema_completion_contract_{label}_{}_{}",
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
            "FRANKENLIBC_UNIVERSAL_EVIDENCE_SCHEMA_COMPLETION_CONTRACT",
            contract,
        )
        .env(
            "FRANKENLIBC_UNIVERSAL_EVIDENCE_SCHEMA_COMPLETION_OUT_DIR",
            out_dir,
        )
        .env(
            "FRANKENLIBC_UNIVERSAL_EVIDENCE_SCHEMA_COMPLETION_REPORT",
            out_dir.join("universal_evidence_schema_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_UNIVERSAL_EVIDENCE_SCHEMA_COMPLETION_LOG",
            out_dir.join("universal_evidence_schema_completion_contract.log.jsonl"),
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

fn source_text(root: &Path, manifest: &Value, source_id: &str) -> TestResult<String> {
    let path = manifest["source_artifacts"][source_id]
        .as_str()
        .ok_or("source path must be string")?;
    Ok(std::fs::read_to_string(root.join(path))?)
}

#[test]
fn manifest_binds_unit_e2e_conformance_and_telemetry_evidence() -> TestResult {
    let root = repo_root();
    let manifest = load_json(&contract_path(&root))?;
    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("universal_evidence_schema_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-bp8fl.7.5"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-bp8fl.7.5.1")
    );

    let source_artifacts = manifest["source_artifacts"]
        .as_object()
        .ok_or("source_artifacts must be object")?;
    for (source_id, path) in source_artifacts {
        let path = path.as_str().ok_or("source artifact path must be string")?;
        assert!(
            root.join(path).exists(),
            "source artifact {source_id} missing at {path}"
        );
    }

    let required_fields =
        string_values(&manifest["completion_debt_evidence"]["required_universal_fields"])?;
    for field in [
        "runtime_mode",
        "replacement_level",
        "oracle_kind",
        "failure_signature",
        "artifact_refs",
    ] {
        assert!(
            required_fields.iter().any(|value| value == field),
            "required field binding missing {field}"
        );
    }

    let log_schema: Value = serde_json::from_str(&std::fs::read_to_string(
        root.join("tests/conformance/log_schema.json"),
    )?)?;
    for field in required_fields {
        assert!(
            log_schema["optional_fields"].get(&field).is_some(),
            "log_schema optional fields missing {field}"
        );
    }
    for example in ["ambition_evidence", "artifact_index", "test_failure"] {
        assert!(
            log_schema["examples"].get(example).is_some(),
            "log schema missing example {example}"
        );
    }

    let binding_ids: Vec<&str> = manifest["missing_item_bindings"]
        .as_array()
        .ok_or("missing_item_bindings must be array")?
        .iter()
        .filter_map(|item| item["id"].as_str())
        .collect();
    for missing_item in [
        "tests.unit.primary",
        "tests.e2e.primary",
        "tests.conformance.primary",
        "telemetry.primary",
    ] {
        assert!(
            binding_ids.contains(&missing_item),
            "missing item binding {missing_item}"
        );
    }

    for implementation_ref in manifest["completion_debt_evidence"]["implementation_refs"]
        .as_array()
        .ok_or("implementation refs must be array")?
    {
        let path = implementation_ref["path"]
            .as_str()
            .ok_or("implementation path must be string")?;
        let text = std::fs::read_to_string(root.join(path))?;
        for needle in implementation_ref["required_text"]
            .as_array()
            .ok_or("required_text must be array")?
        {
            let needle = needle.as_str().ok_or("needle must be string")?;
            assert!(text.contains(needle), "{path} missing {needle}");
        }
    }

    let test_sources = manifest["completion_debt_evidence"]["test_sources"]
        .as_object()
        .ok_or("test_sources must be object")?;
    for (source_id, spec) in test_sources {
        let path = spec["path"].as_str().ok_or("test source path string")?;
        let text = std::fs::read_to_string(root.join(path))?;
        for test_ref in spec["required_test_refs"]
            .as_array()
            .ok_or("required_test_refs must be array")?
        {
            let name = test_ref.as_str().ok_or("test ref string")?;
            assert!(
                text.contains(&format!("fn {name}")),
                "test source {source_id} missing fn {name}"
            );
        }
    }

    Ok(())
}

#[test]
fn checker_validates_universal_schema_source_contract() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "validates")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report =
        load_json(&out_dir.join("universal_evidence_schema_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["source_bead"].as_str(), Some("bd-bp8fl.7.5"));
    assert_eq!(
        report["completion_debt_bead"].as_str(),
        Some("bd-bp8fl.7.5.1")
    );
    assert_eq!(
        report["summary"]["required_universal_fields"].as_u64(),
        Some(18)
    );
    assert!(
        report["test_refs"].as_array().map(Vec::len).unwrap_or(0) >= 19,
        "report should bind all source and completion tests"
    );

    Ok(())
}

#[test]
fn checker_emits_report_and_jsonl_with_audit_fields() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "jsonl")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report =
        load_json(&out_dir.join("universal_evidence_schema_completion_contract.report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("universal_evidence_schema_completion_contract.report.v1")
    );
    let events = string_values(&report["events"])?;
    for event in [
        "universal_evidence_schema_completion_summary",
        "universal_evidence_schema_source_bindings",
        "universal_evidence_schema_compliance_bindings",
        "universal_evidence_schema_completion_contract_pass",
    ] {
        assert!(events.iter().any(|value| value == event), "missing {event}");
    }

    let rows =
        read_jsonl(&out_dir.join("universal_evidence_schema_completion_contract.log.jsonl"))?;
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
            "required_universal_fields",
            "test_refs",
            "artifact_refs",
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
fn checker_rejects_missing_runtime_mode_binding() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "missing_runtime_mode")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["required_universal_fields"] = json!([
        "bead_id",
        "scenario_id",
        "mode",
        "replacement_level",
        "api_family",
        "symbol",
        "oracle_kind",
        "expected",
        "actual",
        "errno",
        "decision_path",
        "healing_action",
        "latency_ns",
        "source_commit",
        "target_dir",
        "failure_signature",
        "artifact_refs"
    ]);
    let mutated = out_dir.join("missing_runtime_mode_contract.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing runtime_mode:\n{}",
        output_text(&output)
    );
    let report =
        load_json(&out_dir.join("universal_evidence_schema_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .ok_or("errors must be array")?
            .iter()
            .any(|error| error.as_str().unwrap_or("").contains("runtime_mode")),
        "report should name runtime_mode failure: {report}"
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_required_test_ref() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "missing_test_ref")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["test_sources"]["evidence_compliance_tests"]
        ["required_test_refs"]
        .as_array_mut()
        .ok_or("required_test_refs array")?
        .push(json!("missing_universal_evidence_schema_test_ref"));
    let mutated = out_dir.join("missing_test_ref_contract.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing test ref:\n{}",
        output_text(&output)
    );
    let report =
        load_json(&out_dir.join("universal_evidence_schema_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .ok_or("errors must be array")?
            .iter()
            .any(|error| error
                .as_str()
                .unwrap_or("")
                .contains("missing_universal_evidence_schema_test_ref")),
        "report should name missing test ref: {report}"
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_telemetry_event() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "missing_event")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["telemetry_contract"]["required_events"]
        .as_array_mut()
        .ok_or("required_events array")?
        .push(json!("missing_universal_evidence_schema_completion_event"));
    let mutated = out_dir.join("missing_event_contract.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing event:\n{}",
        output_text(&output)
    );
    let report =
        load_json(&out_dir.join("universal_evidence_schema_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .ok_or("errors must be array")?
            .iter()
            .any(|error| error
                .as_str()
                .unwrap_or("")
                .contains("missing_universal_evidence_schema_completion_event")),
        "report should name missing event: {report}"
    );

    Ok(())
}

#[test]
fn completion_manifest_points_at_live_source_files() -> TestResult {
    let root = repo_root();
    let manifest = load_json(&contract_path(&root))?;
    let structured_log = source_text(&root, &manifest, "structured_log_source")?;
    assert!(
        structured_log.contains("ambition_evidence events must include"),
        "structured log validator should carry ambition evidence contract"
    );
    let compliance = source_text(&root, &manifest, "evidence_compliance_source")?;
    assert!(
        compliance.contains("failure_event.missing_artifact_refs"),
        "evidence compliance gate should fail closed on missing failure artifacts"
    );
    let checker = source_text(&root, &manifest, "completion_checker")?;
    assert!(
        checker.contains("universal_evidence_schema_completion_contract.v1"),
        "completion checker should bind its schema version"
    );
    Ok(())
}
