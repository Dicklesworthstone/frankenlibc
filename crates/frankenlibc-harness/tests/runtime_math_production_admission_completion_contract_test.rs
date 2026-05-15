use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::error::Error;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

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
    root.join("tests/conformance/runtime_math_production_admission_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_runtime_math_production_admission_completion_contract.sh")
}

fn load_json(path: &Path) -> TestResult<Value> {
    let text = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&text)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn workspace_relative_path(root: &Path, path: &str) -> TestResult<PathBuf> {
    let relative = Path::new(path);
    let has_escape = relative.is_absolute()
        || relative
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::Prefix(_)));
    if has_escape {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("path should stay under workspace root: {path}"),
        )
        .into());
    }
    Ok(root.join(relative))
}

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let out = root.join("target/conformance").join(format!(
        "runtime_math_production_admission_completion_contract_{label}_{}_{}",
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
            "FRANKENLIBC_RUNTIME_MATH_PRODUCTION_ADMISSION_CONTRACT",
            contract,
        )
        .env(
            "FRANKENLIBC_RUNTIME_MATH_PRODUCTION_ADMISSION_REPORT",
            out_dir.join("runtime_math_production_admission_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_RUNTIME_MATH_PRODUCTION_ADMISSION_LOG",
            out_dir.join("runtime_math_production_admission_completion_contract.log.jsonl"),
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

fn string_set(value: &Value) -> TestResult<BTreeSet<String>> {
    let array = value
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "expected string array"))?;
    let mut set = BTreeSet::new();
    for item in array {
        set.insert(
            item.as_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "expected string"))?
                .to_string(),
        );
    }
    Ok(set)
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
    let full_path = workspace_relative_path(root, path)?;
    assert!(
        full_path.is_file(),
        "file-line ref path should exist: {file_line_ref}"
    );
    let contents = std::fs::read_to_string(full_path)?;
    let lines: Vec<_> = contents.lines().collect();
    assert!(
        line_no <= lines.len() && !lines[line_no - 1].trim().is_empty(),
        "file-line ref should point to a non-empty line: {file_line_ref}"
    );
    Ok(())
}

fn assert_test_ref_exists(root: &Path, manifest: &Value, test_ref: &Value) -> TestResult {
    let source = test_ref["source"]
        .as_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "test ref source"))?;
    let name = test_ref["name"]
        .as_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "test ref name"))?;
    let source_path = manifest["completion_debt_evidence"]["test_sources"][source]
        .as_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "test source path"))?;
    let text = std::fs::read_to_string(workspace_relative_path(root, source_path)?)?;
    assert!(
        text.contains(&format!("fn {name}")),
        "{source} should contain test function {name}"
    );
    Ok(())
}

fn log_records(path: &Path) -> TestResult<Vec<Value>> {
    std::fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| Ok(serde_json::from_str::<Value>(line)?))
        .collect()
}

#[test]
fn manifest_binds_all_bd3ot4_missing_items() -> TestResult {
    let root = repo_root()?;
    let manifest = load_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("runtime_math_production_admission_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-3ot"));
    assert_eq!(manifest["completion_debt_bead"].as_str(), Some("bd-3ot.4"));
    assert_eq!(
        string_set(&manifest["completion_debt_evidence"]["missing_items"])?,
        BTreeSet::from([
            "telemetry.primary".to_string(),
            "tests.conformance.primary".to_string(),
            "tests.e2e.primary".to_string(),
            "tests.fuzz.primary".to_string(),
            "tests.unit.primary".to_string(),
        ])
    );

    let artifacts = manifest["source_artifacts"]
        .as_object()
        .ok_or("source_artifacts must be object")?;
    for (artifact_id, path) in artifacts {
        let path = path.as_str().ok_or("artifact path must be string")?;
        assert!(
            root.join(path).is_file(),
            "source artifact {artifact_id} missing at {path}"
        );
    }

    for file_line_ref in manifest["completion_debt_evidence"]["implementation_refs"]
        .as_array()
        .ok_or("implementation refs must be array")?
    {
        assert_file_line_ref_exists(
            &root,
            file_line_ref
                .as_str()
                .ok_or("implementation ref must be string")?,
        )?;
    }

    let child_contracts = manifest["completion_debt_evidence"]["child_contracts"]
        .as_array()
        .ok_or("child contracts must be array")?;
    assert_eq!(child_contracts.len(), 9);
    let child_ids = child_contracts
        .iter()
        .filter_map(|row| row["id"].as_str())
        .collect::<BTreeSet<_>>();
    assert!(child_ids.contains("admission_ci"));
    assert!(child_ids.contains("admission_retirement"));
    assert!(child_ids.contains("fuzz_phase2"));
    assert!(child_ids.contains("runtime_math_logging"));

    let evidence = &manifest["completion_debt_evidence"];
    for section_name in ["unit_primary", "e2e_primary"] {
        let section = &evidence[section_name];
        for command in section["required_commands"]
            .as_array()
            .ok_or("required commands must be array")?
        {
            let command = command.as_str().ok_or("command must be string")?;
            if command.contains("cargo ") {
                assert!(
                    command.starts_with("rch exec -- "),
                    "cargo validation command must use rch: {command}"
                );
            }
        }
        for test_ref in section["required_test_refs"]
            .as_array()
            .ok_or("required test refs must be array")?
        {
            assert_test_ref_exists(&root, &manifest, test_ref)?;
        }
    }
    for test_ref in evidence["telemetry_primary"]["required_test_refs"]
        .as_array()
        .ok_or("telemetry refs must be array")?
    {
        assert_test_ref_exists(&root, &manifest, test_ref)?;
    }

    assert_eq!(
        string_set(&evidence["fuzz_primary"]["required_targets"])?,
        BTreeSet::from(["fuzz_runtime_math".to_string()])
    );
    assert!(evidence["fuzz_primary"]["required_cargo_fuzz_command"]
        .as_str()
        .is_some_and(|command| command.starts_with("rch exec -- ")
            && command.contains("cargo fuzz run")
            && command.contains("fuzz_runtime_math")));
    Ok(())
}

#[test]
fn checker_validates_runtime_math_production_admission_contract() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "validates")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report = load_json(
        &out_dir.join("runtime_math_production_admission_completion_contract.report.json"),
    )?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["source_bead"].as_str(), Some("bd-3ot"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-3ot.4"));
    assert_eq!(
        report["source_summary"]["admission_modules"].as_u64(),
        Some(69)
    );
    assert_eq!(report["source_summary"]["admitted"].as_u64(), Some(25));
    assert_eq!(report["source_summary"]["retired"].as_u64(), Some(44));
    assert_eq!(
        report["child_summary"]["child_contract_count"].as_u64(),
        Some(9)
    );
    assert_eq!(
        report["item_summary"]["missing_item_count"].as_u64(),
        Some(5)
    );
    assert_eq!(
        report["item_summary"]["fuzz_target_count"].as_u64(),
        Some(1)
    );
    assert_eq!(
        report["item_summary"]["telemetry_event_count"].as_u64(),
        Some(5)
    );
    Ok(())
}

#[test]
fn checker_emits_report_and_jsonl() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "jsonl")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report = load_json(
        &out_dir.join("runtime_math_production_admission_completion_contract.report.json"),
    )?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("runtime_math_production_admission_completion_contract.report.v1")
    );
    assert_eq!(report["events"].as_array().map(Vec::len), Some(5));

    let records = log_records(
        &out_dir.join("runtime_math_production_admission_completion_contract.log.jsonl"),
    )?;
    assert_eq!(records.len(), 5);
    let events = records
        .iter()
        .filter_map(|record| record["event"].as_str())
        .collect::<BTreeSet<_>>();
    for event in [
        "runtime_math_production_admission_units_validated",
        "runtime_math_production_admission_e2e_validated",
        "runtime_math_production_admission_fuzz_validated",
        "runtime_math_production_admission_conformance_validated",
        "runtime_math_production_admission_telemetry_validated",
    ] {
        assert!(events.contains(event), "missing event {event}");
    }

    let required_fields = string_set(&report["required_fields"])?;
    for record in records {
        for field in &required_fields {
            assert!(
                record.get(field).is_some(),
                "log record missing field {field}: {record}"
            );
        }
        assert_eq!(record["status"].as_str(), Some("pass"));
        assert_eq!(record["completion_debt_bead"].as_str(), Some("bd-3ot.4"));
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_child_contract() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing_child")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["child_contracts"][0]["path"] =
        json!("tests/conformance/definitely_missing_runtime_math_child_contract.json");
    let mutated = out_dir.join("contract_missing_child.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing child contract:\n{}",
        output_text(&output)
    );
    assert!(
        output_text(&output).contains("child contract missing"),
        "failure should identify missing child contract"
    );
    Ok(())
}

#[test]
fn checker_rejects_non_rch_cargo_validation_command() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "non_rch")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["unit_primary"]["required_commands"][0] = json!(
        "cargo test -p frankenlibc-harness --test runtime_math_production_admission_completion_contract_test -- --nocapture"
    );
    let mutated = out_dir.join("contract_non_rch.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject non-rch cargo command:\n{}",
        output_text(&output)
    );
    assert!(
        output_text(&output).contains("cargo validation command must use rch"),
        "failure should identify rch validation requirement"
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_telemetry_event() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing_event")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["telemetry_primary"]["required_events"]
        .as_array_mut()
        .ok_or("required_events must be array")?
        .retain(|event| event.as_str() != Some("runtime_math_production_admission_fuzz_validated"));
    let mutated = out_dir.join("contract_missing_event.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing telemetry event:\n{}",
        output_text(&output)
    );
    assert!(
        output_text(&output).contains("telemetry required_events mismatch"),
        "failure should identify telemetry event drift"
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_fuzz_runtime_math_target() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing_fuzz_target")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["fuzz_primary"]["required_targets"]
        .as_array_mut()
        .ok_or("required_targets must be array")?
        .retain(|target| target.as_str() != Some("fuzz_runtime_math"));
    let mutated = out_dir.join("contract_missing_fuzz_target.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing fuzz target:\n{}",
        output_text(&output)
    );
    assert!(
        output_text(&output).contains("fuzz_runtime_math target missing"),
        "failure should identify missing runtime-math fuzz target"
    );
    Ok(())
}
