//! Gentoo unit-test completion-debt contract (bd-2icq.13 / bd-2icq.13.1).

use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const REQUIRED_COMPONENTS: &[&str] = &[
    "build_runner",
    "test_runner",
    "docker_integration",
    "log_parser",
    "cache_manager",
    "regression_detector",
    "flaky_detector",
    "progress_reporter",
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

fn manifest_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/gentoo_unit_test_contract.v1.json")
}

fn load_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn load_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    let mut rows = Vec::new();
    for line in std::fs::read_to_string(path)?.lines() {
        if line.trim().is_empty() {
            continue;
        }
        rows.push(serde_json::from_str(line)?);
    }
    Ok(rows)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    std::fs::write(path, format!("{}\n", serde_json::to_string_pretty(value)?))?;
    Ok(())
}

fn unique_output_dir(root: &Path, prefix: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| test_error(format!("system clock should be after Unix epoch: {err}")))?
        .as_nanos();
    let path = root
        .join("target/conformance")
        .join(format!("{prefix}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn string_field<'a>(value: &'a Value, field: &str) -> TestResult<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| test_error(format!("missing string field {field}")))
}

fn array_field<'a>(value: &'a Value, field: &str) -> TestResult<&'a Vec<Value>> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| test_error(format!("missing array field {field}")))
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<std::process::Output> {
    Ok(Command::new("bash")
        .arg(root.join("scripts/check_gentoo_unit_test_contract.sh"))
        .current_dir(root)
        .env("FRANKENLIBC_GENTOO_UNIT_CONTRACT", contract)
        .env("FRANKENLIBC_GENTOO_UNIT_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_GENTOO_UNIT_REPORT",
            out_dir.join("gentoo_unit_test_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_GENTOO_UNIT_LOG",
            out_dir.join("gentoo_unit_test_contract.log.jsonl"),
        )
        .output()?)
}

#[test]
fn manifest_anchors_completion_debt() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    assert_eq!(string_field(&manifest, "schema_version")?, "v1");
    assert_eq!(
        string_field(&manifest, "manifest_id")?,
        "gentoo-unit-test-contract"
    );
    assert_eq!(string_field(&manifest, "bead")?, "bd-2icq.13");
    assert_eq!(
        string_field(&manifest, "completion_debt_bead")?,
        "bd-2icq.13.1"
    );

    let evidence = manifest
        .get("completion_debt_evidence")
        .ok_or_else(|| test_error("missing completion_debt_evidence"))?;
    assert_eq!(string_field(evidence, "bead")?, "bd-2icq.13.1");
    assert_eq!(string_field(evidence, "original_bead")?, "bd-2icq.13");
    assert_eq!(
        string_field(evidence, "test_source")?,
        "crates/frankenlibc-harness/tests/gentoo_unit_test_contract_test.rs"
    );
    Ok(())
}

#[test]
fn unit_components_cover_parent_required_modules() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let components = array_field(&manifest, "required_components")?;
    let ids: BTreeSet<_> = components
        .iter()
        .filter_map(|component| component.get("component_id").and_then(Value::as_str))
        .collect();

    for required in REQUIRED_COMPONENTS {
        assert!(
            ids.contains(required),
            "missing required Gentoo component {required}"
        );
    }

    for component in components {
        let implementation = root.join(string_field(component, "implementation")?);
        let test_file = root.join(string_field(component, "test_file")?);
        assert!(
            implementation.is_file(),
            "{} missing",
            implementation.display()
        );
        assert!(test_file.is_file(), "{} missing", test_file.display());
        assert!(
            !array_field(component, "coverage_categories")?.is_empty(),
            "coverage categories should be explicit"
        );
        assert!(
            !array_field(component, "required_tests")?.is_empty(),
            "required tests should be explicit"
        );
    }
    Ok(())
}

#[test]
fn required_python_tests_exist_in_source() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    for component in array_field(&manifest, "required_components")? {
        let test_file = root.join(string_field(component, "test_file")?);
        let source = std::fs::read_to_string(&test_file)?;
        for required in array_field(component, "required_tests")? {
            let class_name = string_field(required, "class")?;
            let test_name = string_field(required, "test")?;
            assert!(
                source.contains(&format!("class {class_name}")),
                "{} missing class {class_name}",
                test_file.display()
            );
            assert!(
                source.contains(&format!("def {test_name}(")),
                "{} missing test {test_name}",
                test_file.display()
            );
        }
    }
    Ok(())
}

#[test]
fn fixture_contract_pins_malformed_and_valid_inputs() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let fixtures = manifest
        .get("fixture_contract")
        .and_then(|contract| contract.get("required_files"))
        .and_then(Value::as_array)
        .ok_or_else(|| test_error("missing fixture_contract.required_files"))?;

    let paths: BTreeSet<_> = fixtures
        .iter()
        .filter_map(|fixture| fixture.get("path").and_then(Value::as_str))
        .collect();
    for required in [
        "tests/gentoo/fixtures/sample_logs/valid_runtime.jsonl",
        "tests/gentoo/fixtures/sample_logs/valid_hook.jsonl",
        "tests/gentoo/fixtures/sample_logs/invalid_json.jsonl",
        "tests/gentoo/fixtures/sample_logs/invalid_missing_field.jsonl",
    ] {
        assert!(paths.contains(required), "missing fixture {required}");
        assert!(
            root.join(required).is_file(),
            "fixture file missing {required}"
        );
    }
    Ok(())
}

#[test]
fn integration_contract_pins_docker_and_telemetry_probe() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let integration = manifest
        .get("integration_contract")
        .ok_or_else(|| test_error("missing integration_contract"))?;
    let script = root.join(string_field(integration, "script")?);
    let script_source = std::fs::read_to_string(&script)?;
    for needle in array_field(integration, "required_script_needles")? {
        let needle = needle
            .as_str()
            .ok_or_else(|| test_error("integration needle should be string"))?;
        assert!(
            script_source.contains(needle),
            "{} missing needle {needle}",
            script.display()
        );
    }

    for required in array_field(integration, "required_tests")? {
        let test_file = root.join(string_field(required, "file")?);
        let source = std::fs::read_to_string(&test_file)?;
        assert!(source.contains(&format!("class {}", string_field(required, "class")?)));
        assert!(source.contains(&format!("def {}(", string_field(required, "test")?)));
    }
    Ok(())
}

#[test]
fn checker_accepts_manifest_and_emits_telemetry() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "gentoo-unit-contract-ok")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    assert!(
        output.status.success(),
        "checker failed stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = load_json(&out_dir.join("gentoo_unit_test_contract.report.json"))?;
    assert_eq!(string_field(&report, "status")?, "pass");
    assert_eq!(
        report.get("component_count").and_then(Value::as_u64),
        Some(REQUIRED_COMPONENTS.len() as u64)
    );
    assert!(
        report
            .get("total_unit_tests_indexed")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            >= 100,
        "expected broad unit-test inventory"
    );

    let rows = load_jsonl(&out_dir.join("gentoo_unit_test_contract.log.jsonl"))?;
    assert_eq!(rows.len(), REQUIRED_COMPONENTS.len() + 1);
    assert!(rows.iter().any(|row| {
        row["event"].as_str() == Some("gentoo_unit_contract_summary")
            && row["status"].as_str() == Some("pass")
    }));
    for component in REQUIRED_COMPONENTS {
        assert!(
            rows.iter()
                .any(|row| row["event"].as_str() == Some("gentoo_unit_component")
                    && row["component_id"].as_str() == Some(component)
                    && row["failure_signature"].as_str() == Some("none")),
            "missing passing telemetry row for {component}"
        );
    }
    Ok(())
}

#[test]
fn checker_rejects_stale_required_test_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "gentoo-unit-contract-fail")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let components = manifest["required_components"]
        .as_array_mut()
        .ok_or_else(|| test_error("required_components should be array"))?;
    let required_tests = components[0]["required_tests"]
        .as_array_mut()
        .ok_or_else(|| test_error("required_tests should be array"))?;
    required_tests.push(json!({
        "class": "BuildRunnerTests",
        "test": "test_missing_completion_debt_binding",
        "line_ref": "tests/gentoo/test-build-runner.py:1"
    }));
    let bad_manifest = out_dir.join("bad_contract.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject stale test binding"
    );
    let report = load_json(&out_dir.join("gentoo_unit_test_contract.report.json"))?;
    let errors = array_field(&report, "errors")?;
    assert!(
        errors.iter().any(|error| error
            .as_str()
            .is_some_and(|text| text.contains("test_missing_completion_debt_binding"))),
        "report should name stale binding: {errors:?}"
    );
    Ok(())
}
