use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::error::Error;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate directory has workspace parent")
        .parent()
        .expect("workspace parent has repo parent")
        .to_path_buf()
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/math_kernel_rebuild_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_math_kernel_rebuild_completion_contract.sh")
}

fn load_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
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
        "math_kernel_rebuild_completion_contract_{label}_{}_{}",
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
        .env("FRANKENLIBC_MATH_KERNEL_REBUILD_CONTRACT", contract)
        .env(
            "FRANKENLIBC_MATH_KERNEL_REBUILD_REPORT",
            out_dir.join("math_kernel_rebuild_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_MATH_KERNEL_REBUILD_LOG",
            out_dir.join("math_kernel_rebuild_completion_contract.log.jsonl"),
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
    let lines = std::fs::read_to_string(full_path)?
        .lines()
        .map(str::to_owned)
        .collect::<Vec<_>>();
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
fn manifest_binds_math_kernel_rebuild_evidence() -> TestResult {
    let root = repo_root();
    let manifest = load_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("math_kernel_rebuild_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-kan"));
    assert_eq!(manifest["completion_debt_bead"].as_str(), Some("bd-kan.1"));
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

    let parent = load_json(
        &root.join(
            manifest["source_artifacts"]["production_admission_contract"]
                .as_str()
                .ok_or("production admission path must be string")?,
        ),
    )?;
    assert_eq!(parent["completion_debt_bead"].as_str(), Some("bd-3ot.4"));
    assert_eq!(
        parent["completion_debt_evidence"]["child_contracts"]
            .as_array()
            .map(Vec::len),
        Some(9)
    );

    let production = load_json(
        &root.join(
            manifest["source_artifacts"]["production_manifest"]
                .as_str()
                .ok_or("production manifest path must be string")?,
        ),
    )?;
    assert_eq!(
        production["production_modules"].as_array().map(Vec::len),
        Some(25)
    );
    assert_eq!(
        production["research_only_modules"].as_array().map(Vec::len),
        Some(44)
    );
    assert!(
        production["default_feature_set"]
            .as_array()
            .is_some_and(|features| features
                .iter()
                .any(|feature| feature.as_str() == Some("runtime-math-production")))
    );
    assert!(
        production["optional_feature_set"]
            .as_array()
            .is_some_and(|features| features
                .iter()
                .any(|feature| feature.as_str() == Some("runtime-math-research")))
    );

    let evidence = &manifest["completion_debt_evidence"];
    for section_name in [
        "unit_primary",
        "e2e_primary",
        "fuzz_primary",
        "conformance_primary",
        "telemetry_primary",
    ] {
        let section = &evidence[section_name];
        for command in section["required_commands"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            if command.contains("cargo ") {
                assert!(
                    command.starts_with("rch exec -- "),
                    "cargo validation command must use rch: {command}"
                );
            }
        }
        for test_ref in section["required_test_refs"]
            .as_array()
            .into_iter()
            .flatten()
        {
            assert_test_ref_exists(&root, &manifest, test_ref)?;
        }
    }
    Ok(())
}

#[test]
fn checker_validates_math_kernel_rebuild_contract() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "validates")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report = load_json(&out_dir.join("math_kernel_rebuild_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["source_bead"].as_str(), Some("bd-kan"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-kan.1"));
    assert_eq!(
        report["source_summary"]["production_module_count"].as_u64(),
        Some(25)
    );
    assert_eq!(
        report["source_summary"]["research_module_count"].as_u64(),
        Some(44)
    );
    assert_eq!(
        report["source_summary"]["child_contract_count"].as_u64(),
        Some(9)
    );
    assert_eq!(
        report["item_summary"]["missing_item_count"].as_u64(),
        Some(5)
    );
    assert_eq!(
        report["item_summary"]["telemetry_event_count"].as_u64(),
        Some(5)
    );
    Ok(())
}

#[test]
fn checker_emits_report_and_jsonl() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "jsonl")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report = load_json(&out_dir.join("math_kernel_rebuild_completion_contract.report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("math_kernel_rebuild_completion_contract.report.v1")
    );
    assert_eq!(report["events"].as_array().map(Vec::len), Some(5));

    let rows = log_records(&out_dir.join("math_kernel_rebuild_completion_contract.log.jsonl"))?;
    assert_eq!(rows.len(), 5);
    let events = rows
        .iter()
        .filter_map(|row| row["event"].as_str())
        .collect::<BTreeSet<_>>();
    for event in [
        "math_kernel_rebuild_units_validated",
        "math_kernel_rebuild_e2e_validated",
        "math_kernel_rebuild_fuzz_validated",
        "math_kernel_rebuild_conformance_validated",
        "math_kernel_rebuild_telemetry_validated",
    ] {
        assert!(events.contains(event), "missing event {event}");
    }

    let required_fields = string_set(&report["required_fields"])?;
    for row in rows {
        for field in &required_fields {
            assert!(row.get(field).is_some(), "missing field {field}: {row}");
        }
        assert_eq!(row["completion_debt_bead"].as_str(), Some("bd-kan.1"));
        assert_eq!(row["status"].as_str(), Some("pass"));
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_production_admission_contract() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "missing_parent")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["source_artifacts"]["production_admission_contract"] =
        json!("tests/conformance/definitely_missing_production_admission_contract.json");
    let mutated = out_dir.join("contract_missing_parent.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing production admission contract:\n{}",
        output_text(&output)
    );
    assert!(
        output_text(&output).contains("source artifact missing: production_admission_contract"),
        "failure should identify missing parent proof"
    );
    Ok(())
}

#[test]
fn checker_rejects_non_rch_cargo_validation_command() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "non_rch")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["unit_primary"]["required_commands"][0] = json!(
        "cargo test -p frankenlibc-harness --test math_kernel_rebuild_completion_contract_test -- --nocapture"
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
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "missing_event")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["telemetry_primary"]["required_events"]
        .as_array_mut()
        .ok_or("required_events must be array")?
        .retain(|event| event.as_str() != Some("math_kernel_rebuild_fuzz_validated"));
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
        "failure should identify telemetry drift"
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_runtime_math_fuzz_target() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "missing_fuzz")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["fuzz_primary"]["required_targets"]
        .as_array_mut()
        .ok_or("required_targets must be array")?
        .retain(|target| target.as_str() != Some("fuzz_runtime_math"));
    let mutated = out_dir.join("contract_missing_fuzz.json");
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
