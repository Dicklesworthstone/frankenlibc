//! Contract tests for bd-3ot.1.1 runtime-math controller manifest completion evidence.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let crates_dir = manifest
        .parent()
        .ok_or_else(|| io::Error::other("frankenlibc-harness manifest should have a parent"))?;
    let root = crates_dir.parent().ok_or_else(|| {
        io::Error::other("frankenlibc-harness manifest should live below workspace root")
    })?;
    Ok(root.to_path_buf())
}

fn read_manifest(root: &Path) -> TestResult<serde_json::Value> {
    let path =
        root.join("tests/conformance/runtime_math_controller_manifest_completion_contract.v1.json");
    let text = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&text)?)
}

fn write_json(path: &Path, value: &serde_json::Value) -> TestResult {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn unique_output_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let path = root.join("target/conformance").join(format!(
        "runtime-math-controller-manifest-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<std::process::Output> {
    Ok(Command::new("bash")
        .arg(root.join("scripts/check_runtime_math_controller_manifest_completion_contract.sh"))
        .current_dir(root)
        .env("FRANKENLIBC_RUNTIME_MATH_CONTROLLER_CONTRACT", contract)
        .env(
            "FRANKENLIBC_RUNTIME_MATH_CONTROLLER_REPORT",
            out_dir.join("runtime_math_controller_manifest_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_RUNTIME_MATH_CONTROLLER_LOG",
            out_dir.join("runtime_math_controller_manifest_completion_contract.log.jsonl"),
        )
        .output()?)
}

fn read_json(path: &Path) -> TestResult<serde_json::Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn read_jsonl(path: &Path) -> TestResult<Vec<serde_json::Value>> {
    std::fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}

fn string_set(value: &serde_json::Value) -> TestResult<BTreeSet<String>> {
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

fn json_str_field_is(row: &serde_json::Value, field: &str, expected: &str) -> bool {
    row.get(field)
        .and_then(serde_json::Value::as_str)
        .is_some_and(|value| value.eq(expected))
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
        full_path.is_file(),
        "file-line ref path should exist: {file_line_ref}"
    );
    let line_count = std::fs::read_to_string(full_path)?.lines().count();
    assert!(
        line_no <= line_count,
        "file-line ref outside file: {file_line_ref}"
    );
    Ok(())
}

fn source_texts(root: &Path, manifest: &serde_json::Value) -> TestResult<BTreeMap<String, String>> {
    let sources = manifest["completion_debt_evidence"]["test_sources"]
        .as_object()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "test_sources object"))?;
    let mut texts = BTreeMap::new();
    for (key, path) in sources {
        let path = path
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "source path string"))?;
        texts.insert(key.clone(), std::fs::read_to_string(root.join(path))?);
    }
    Ok(texts)
}

#[test]
fn manifest_binds_unit_e2e_fuzz_conformance_and_telemetry_evidence() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_manifest(&root)?;
    assert_eq!(manifest["bead"].as_str(), Some("bd-3ot.1"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-3ot.1.1")
    );

    let evidence = &manifest["completion_debt_evidence"];
    assert_eq!(evidence["bead"].as_str(), Some("bd-3ot.1.1"));
    assert_eq!(evidence["original_bead"].as_str(), Some("bd-3ot.1"));
    assert!(
        evidence["next_audit_score_threshold"].as_u64().unwrap_or(0) >= 800,
        "completion evidence should target a passing next audit score"
    );

    for file_line_ref in evidence["implementation_refs"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "refs array"))?
    {
        assert_file_line_ref_exists(
            &root,
            file_line_ref
                .as_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "ref string"))?,
        )?;
    }

    let artifacts = evidence["artifacts"]
        .as_object()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "artifacts object"))?;
    for path in artifacts.values() {
        let path = path
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "artifact path string"))?;
        assert!(root.join(path).is_file(), "artifact should exist: {path}");
    }

    let controller_manifest_path = artifacts["controller_manifest"]
        .as_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "controller manifest path"))?;
    let controller_manifest: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(
        root.join(controller_manifest_path),
    )?)?;
    assert_eq!(controller_manifest["schema_version"].as_str(), Some("v1"));
    assert!(
        controller_manifest["controllers"]
            .as_array()
            .is_some_and(|controllers| !controllers.is_empty()),
        "controller manifest should contain controller rows"
    );
    for field in [
        "missing_decision_hook",
        "missing_invariant",
        "missing_fallback",
        "missing_benefit_target",
    ] {
        assert_eq!(
            controller_manifest["summary"][field].as_u64(),
            Some(0),
            "controller manifest summary should close {field}"
        );
    }

    let required_policies =
        string_set(&evidence["controller_manifest_contract"]["required_policies"])?;
    for policy in [
        "controller_manifest: decision_target_required",
        "controller_manifest: invariant_required",
        "controller_manifest: fallback_when_data_missing_required",
        "controller_manifest: value_target_required",
    ] {
        assert!(
            required_policies.contains(policy),
            "missing policy {policy}"
        );
    }

    let source_texts = source_texts(&root, &manifest)?;
    for (section, missing_item) in [
        ("unit_primary", "tests.unit.primary"),
        ("e2e_primary", "tests.e2e.primary"),
        ("fuzz_primary", "tests.fuzz.primary"),
        ("conformance_primary", "tests.conformance.primary"),
        ("telemetry_primary", "telemetry.primary"),
    ] {
        let section_value = &evidence[section];
        assert_eq!(
            section_value["missing_item_id"].as_str(),
            Some(missing_item)
        );
        let refs = section_value["required_test_refs"]
            .as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "test refs array"))?;
        assert!(!refs.is_empty(), "{section} should name test refs");
        for test_ref in refs {
            let source = test_ref["source"]
                .as_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "source string"))?;
            let name = test_ref["name"]
                .as_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "test name string"))?;
            let text = source_texts.get(source).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "source should be declared")
            })?;
            assert!(
                text.contains(&format!("fn {name}")),
                "{section} references missing test {source}::{name}"
            );
        }
    }

    Ok(())
}

#[test]
fn checker_emits_report_and_jsonl() -> TestResult {
    let root = workspace_root()?;
    let contract =
        root.join("tests/conformance/runtime_math_controller_manifest_completion_contract.v1.json");
    let out_dir = unique_output_dir(&root, "pass")?;
    let output = run_checker(&root, &contract, &out_dir)?;
    assert!(
        output.status.success(),
        "checker failed stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = read_json(
        &out_dir.join("runtime_math_controller_manifest_completion_contract.report.json"),
    )?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-3ot.1.1"));
    assert_eq!(report["original_bead"].as_str(), Some("bd-3ot.1"));
    assert!(
        report["controller_count"].as_u64().unwrap_or(0) > 0,
        "report should include controller count"
    );
    assert!(
        string_set(&report["required_policies"])?
            .contains("controller_manifest: decision_target_required"),
        "report should include decision target policy"
    );

    let rows = read_jsonl(
        &out_dir.join("runtime_math_controller_manifest_completion_contract.log.jsonl"),
    )?;
    assert_eq!(rows.len(), 1, "checker should emit one telemetry row");
    let row = &rows[0];
    assert!(json_str_field_is(
        row,
        "event",
        "runtime_math_controller_manifest_completion_contract_validated"
    ));
    assert!(json_str_field_is(row, "completion_debt_bead", "bd-3ot.1.1"));
    assert!(json_str_field_is(row, "status", "pass"));
    assert!(json_str_field_is(row, "failure_signature", "none"));

    let policies = string_set(&row["required_policies"])?;
    assert!(policies.contains("controller_manifest: invariant_required"));
    assert!(policies.contains("tooling_contract: asupersync_dependency_required"));

    Ok(())
}

#[test]
fn checker_rejects_missing_decision_hook_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "stale")?;
    let mut manifest = read_manifest(&root)?;
    manifest["completion_debt_evidence"]["controller_manifest_contract"]["required_controller_fields"] =
        serde_json::json!([
            "module",
            "tier",
            "invariant",
            "fallback_when_data_missing",
            "runtime_cost_target",
            "benefit_target"
        ]);
    let stale_contract = out_dir.join("stale_runtime_math_controller_manifest_contract.v1.json");
    write_json(&stale_contract, &manifest)?;

    let output = run_checker(&root, &stale_contract, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing decision-hook binding"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains(
            "controller_manifest_contract.required_controller_fields missing decision_hook"
        ),
        "checker output should name missing decision_hook: {combined}"
    );

    let report = read_json(
        &out_dir.join("runtime_math_controller_manifest_completion_contract.report.json"),
    )?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "errors array"))?
            .iter()
            .any(|item| item
                .as_str()
                .unwrap_or("")
                .contains("required_controller_fields missing decision_hook")),
        "report should retain missing decision-hook error"
    );

    let rows = read_jsonl(
        &out_dir.join("runtime_math_controller_manifest_completion_contract.log.jsonl"),
    )?;
    assert_eq!(rows.len(), 1);
    assert!(json_str_field_is(
        &rows[0],
        "event",
        "runtime_math_controller_manifest_completion_contract_failed"
    ));

    Ok(())
}
