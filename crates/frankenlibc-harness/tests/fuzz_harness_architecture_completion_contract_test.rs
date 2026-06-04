use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn repo_root() -> TestResult<PathBuf> {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace = crate_dir
        .parent()
        .ok_or("crate directory has workspace parent")?;
    let root = workspace
        .parent()
        .ok_or("workspace parent has repo parent")?;
    Ok(root.to_path_buf())
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/fuzz_harness_architecture_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_fuzz_harness_architecture_completion_contract.sh")
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
        "fuzz_harness_architecture_completion_contract_{label}_{}_{}",
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
        .env("FRANKENLIBC_FUZZ_HARNESS_COMPLETION_CONTRACT", contract)
        .env("FRANKENLIBC_FUZZ_HARNESS_COMPLETION_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_FUZZ_HARNESS_COMPLETION_REPORT",
            out_dir.join("fuzz_harness_architecture_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_FUZZ_HARNESS_COMPLETION_LOG",
            out_dir.join("fuzz_harness_architecture_completion_contract.log.jsonl"),
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
fn manifest_binds_unit_e2e_and_fuzz_completion_evidence() -> TestResult {
    let root = repo_root()?;
    let manifest = load_json(&contract_path(&root))?;
    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("fuzz_harness_architecture_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-1oz.5"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-1oz.5.1")
    );

    let source_artifacts = manifest["source_artifacts"]
        .as_object()
        .ok_or("source_artifacts object")?;
    for required in [
        "fuzz_harness_architecture_report",
        "fuzz_harness_architecture_generator",
        "fuzz_harness_architecture_gate",
        "fuzz_harness_architecture_harness_test",
        "fuzz_cargo_manifest",
        "fuzz_ci_gate",
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
        "tests.fuzz.primary",
    ] {
        assert!(
            binding_ids.contains(&required),
            "missing binding {required}"
        );
    }

    let source_report =
        load_json(&root.join("tests/conformance/fuzz_harness_architecture.v1.json"))?;
    assert_eq!(source_report["bead"].as_str(), Some("bd-1oz.5"));
    assert_eq!(source_report["summary"]["total_targets"].as_u64(), Some(66));
    assert_eq!(
        source_report["summary"]["functional_targets"].as_u64(),
        Some(66)
    );
    assert_eq!(source_report["summary"]["stub_targets"].as_u64(), Some(0));
    assert_eq!(
        source_report["summary"]["checks_passed"].as_u64(),
        Some(330)
    );
    assert_eq!(source_report["summary"]["checks_total"].as_u64(), Some(330));
    assert!(
        source_report["corpus_strategy"]["manifests"]
            .as_array()
            .ok_or("corpus manifests")?
            .iter()
            .all(|manifest| manifest["count"].as_u64().unwrap_or(0) > 0
                && manifest["reproducible"].as_bool() == Some(true))
    );

    Ok(())
}

#[test]
fn checker_validates_fuzz_harness_architecture_contract() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "validates")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report =
        load_json(&out_dir.join("fuzz_harness_architecture_completion_contract.report.json"))?;
    let source_report =
        load_json(&root.join("tests/conformance/fuzz_harness_architecture.v1.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["source_bead"].as_str(), Some("bd-1oz.5"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-1oz.5.1"));
    assert_eq!(report["summary"]["total_targets"].as_u64(), Some(66));
    assert_eq!(report["summary"]["functional_targets"].as_u64(), Some(66));
    assert_eq!(report["summary"]["checks_passed"].as_u64(), Some(330));
    assert_eq!(
        report["summary"]["seed_corpus"].as_u64(),
        source_report["summary"]["total_seed_corpus"].as_u64()
    );
    assert_eq!(report["summary"]["unique_cwes"].as_u64(), Some(17));

    Ok(())
}

#[test]
fn checker_emits_completion_report_and_jsonl() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "jsonl")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report =
        load_json(&out_dir.join("fuzz_harness_architecture_completion_contract.report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("fuzz_harness_architecture_completion_contract.report.v1")
    );
    let events = string_values(&report["events"])?;
    for event in [
        "fuzz_harness_architecture_completion_summary",
        "fuzz_harness_architecture_source_bindings",
        "fuzz_harness_architecture_test_bindings",
        "fuzz_harness_architecture_completion_contract_pass",
    ] {
        assert!(events.iter().any(|value| value == event), "missing {event}");
    }

    let rows =
        read_jsonl(&out_dir.join("fuzz_harness_architecture_completion_contract.log.jsonl"))?;
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
fn checker_rejects_missing_fuzz_target_binding() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing_target")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["required_architecture_contract"]["required_targets"]
        .as_array_mut()
        .ok_or("required_targets array")?
        .push(json!("fuzz_missing_completion_target"));
    let mutated = out_dir.join("missing_fuzz_target_contract.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing fuzz target:\n{}",
        output_text(&output)
    );
    let report =
        load_json(&out_dir.join("fuzz_harness_architecture_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .ok_or("errors array")?
            .iter()
            .any(|error| error
                .as_str()
                .unwrap_or("")
                .contains("fuzz_missing_completion_target")),
        "report should name missing fuzz target: {report}"
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
        .push(json!("missing_fuzz_harness_architecture_test_ref"));
    let mutated = out_dir.join("missing_test_ref_contract.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing test ref:\n{}",
        output_text(&output)
    );
    let report =
        load_json(&out_dir.join("fuzz_harness_architecture_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .ok_or("errors array")?
            .iter()
            .any(|error| error
                .as_str()
                .unwrap_or("")
                .contains("missing_fuzz_harness_architecture_test_ref")),
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
        .push(json!("missing_fuzz_harness_architecture_completion_event"));
    let mutated = out_dir.join("missing_event_contract.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing event:\n{}",
        output_text(&output)
    );
    let report =
        load_json(&out_dir.join("fuzz_harness_architecture_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .ok_or("errors array")?
            .iter()
            .any(|error| error
                .as_str()
                .unwrap_or("")
                .contains("missing_fuzz_harness_architecture_completion_event")),
        "report should name missing event: {report}"
    );

    Ok(())
}
