//! Gentoo regression detector completion-debt contract (bd-2icq.12 / bd-2icq.12.1).

use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

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
    root.join("tests/conformance/gentoo_regression_detector_completion_contract.v1.json")
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

fn optional_string_field<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value.get(field).and_then(Value::as_str)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<std::process::Output> {
    Ok(Command::new("bash")
        .arg(root.join("scripts/check_gentoo_regression_detector_completion_contract.sh"))
        .current_dir(root)
        .env("FRANKENLIBC_GENTOO_REGRESSION_CONTRACT", contract)
        .env("FRANKENLIBC_GENTOO_REGRESSION_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_GENTOO_REGRESSION_REPORT",
            out_dir.join("gentoo_regression_detector_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_GENTOO_REGRESSION_LOG",
            out_dir.join("gentoo_regression_detector_completion_contract.log.jsonl"),
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
        "gentoo-regression-detector-completion-contract"
    );
    assert_eq!(string_field(&manifest, "bead")?, "bd-2icq.12");
    assert_eq!(
        string_field(&manifest, "completion_debt_bead")?,
        "bd-2icq.12.1"
    );

    let evidence = manifest
        .get("completion_debt_evidence")
        .ok_or_else(|| test_error("missing completion_debt_evidence"))?;
    assert_eq!(string_field(evidence, "bead")?, "bd-2icq.12.1");
    assert_eq!(string_field(evidence, "original_bead")?, "bd-2icq.12");
    assert_eq!(
        string_field(evidence, "test_source")?,
        "crates/frankenlibc-harness/tests/gentoo_regression_detector_completion_contract_test.rs"
    );
    Ok(())
}

#[test]
fn manifest_binds_unit_e2e_and_telemetry_missing_items() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let evidence = manifest
        .get("completion_debt_evidence")
        .ok_or_else(|| test_error("missing completion_debt_evidence"))?;
    let expected = [
        ("unit_primary", "tests.unit.primary"),
        ("e2e_primary", "tests.e2e.primary"),
        ("telemetry_primary", "telemetry.primary"),
    ];
    for (section, missing_item) in expected {
        let section_value = evidence
            .get(section)
            .ok_or_else(|| test_error(format!("missing {section}")))?;
        assert_eq!(
            string_field(section_value, "missing_item_id")?,
            missing_item
        );
        assert!(
            !array_field(section_value, "required_test_names")?.is_empty(),
            "{section} should bind Rust tests"
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
fn baseline_and_release_gate_contracts_are_file_backed() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;

    let baseline_contract = manifest
        .get("baseline_contract")
        .ok_or_else(|| test_error("missing baseline_contract"))?;
    let baseline_path = root.join(string_field(baseline_contract, "baseline_file")?);
    let baseline = load_json(&baseline_path)?;
    assert_eq!(string_field(&baseline, "schema_version")?, "v1");
    assert_eq!(string_field(&baseline, "bead")?, "bd-2icq.12");
    assert!(
        array_field(&baseline, "packages")?.len() >= 5,
        "baseline should pin enough package examples"
    );

    let release_gate = manifest
        .get("release_gate_contract")
        .ok_or_else(|| test_error("missing release_gate_contract"))?;
    let release_config = load_json(&root.join(string_field(release_gate, "config")?))?;
    let gates = release_config
        .get("gates")
        .and_then(Value::as_object)
        .ok_or_else(|| test_error("missing release gates"))?;
    for tier in ["tier1", "top20", "top100"] {
        let thresholds = gates
            .get(tier)
            .and_then(|gate| gate.get("thresholds"))
            .and_then(Value::as_object)
            .ok_or_else(|| test_error(format!("missing thresholds for {tier}")))?;
        for threshold in [
            "build_success_rate_pct",
            "test_pass_rate_pct",
            "max_new_regressions",
            "max_overhead_pct",
        ] {
            assert!(
                thresholds.contains_key(threshold),
                "{tier} missing {threshold}"
            );
        }
    }
    Ok(())
}

#[test]
fn e2e_contract_pins_clean_blocking_and_gate_scenarios() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let e2e = manifest
        .get("e2e_primary")
        .ok_or_else(|| test_error("missing e2e_primary"))?;
    let ids: BTreeSet<_> = array_field(e2e, "scenarios")?
        .iter()
        .filter_map(|scenario| scenario.get("scenario_id").and_then(Value::as_str))
        .collect();

    for scenario in [
        "clean_current_matches_baseline",
        "blocking_current_fails_gate",
        "ci_gate_runs_all_detector_checks",
    ] {
        assert!(ids.contains(scenario), "missing e2e scenario {scenario}");
    }
    Ok(())
}

#[test]
fn checker_accepts_manifest_and_runs_detector_gate() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "gentoo-regression-contract-ok")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    assert!(
        output.status.success(),
        "checker failed stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report =
        load_json(&out_dir.join("gentoo_regression_detector_completion_contract.report.json"))?;
    assert_eq!(string_field(&report, "status")?, "pass");
    assert_eq!(
        report.get("component_count").and_then(Value::as_u64),
        Some(2)
    );
    assert_eq!(
        report.get("e2e_scenario_count").and_then(Value::as_u64),
        Some(3)
    );
    assert!(
        report
            .get("total_unit_tests_indexed")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            >= 24,
        "expected detector and baseline unit-test inventory"
    );

    let rows =
        load_jsonl(&out_dir.join("gentoo_regression_detector_completion_contract.log.jsonl"))?;
    let events: BTreeSet<_> = rows
        .iter()
        .filter_map(|row| optional_string_field(row, "event"))
        .collect();
    for event in [
        "gentoo_regression_detector_component",
        "gentoo_regression_detector_e2e",
        "gentoo_regression_detector_summary",
    ] {
        assert!(events.contains(event), "missing telemetry event {event}");
    }
    let blocking_row = rows
        .iter()
        .find(|row| {
            optional_string_field(row, "event") == Some("gentoo_regression_detector_e2e")
                && optional_string_field(row, "scenario_id") == Some("blocking_current_fails_gate")
                && optional_string_field(row, "status") == Some("pass")
        })
        .ok_or_else(|| test_error("missing passing blocking e2e row"))?;
    assert_eq!(string_field(blocking_row, "failure_signature")?, "none");
    assert!(rows.iter().any(|row| {
        optional_string_field(row, "event") == Some("gentoo_regression_detector_summary")
            && optional_string_field(row, "status") == Some("pass")
    }));
    Ok(())
}

#[test]
fn checker_rejects_stale_required_test_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "gentoo-regression-contract-fail-test")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let components = manifest["required_components"]
        .as_array_mut()
        .ok_or_else(|| test_error("required_components should be array"))?;
    let required_tests = components[0]["required_tests"]
        .as_array_mut()
        .ok_or_else(|| test_error("required_tests should be array"))?;
    required_tests.push(json!({
        "class": "TestRegressionDetection",
        "test": "test_missing_completion_debt_binding",
        "line_ref": "tests/gentoo/test_regression_detector.py:1"
    }));
    let bad_manifest = out_dir.join("bad_contract.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject stale test binding"
    );
    let report =
        load_json(&out_dir.join("gentoo_regression_detector_completion_contract.report.json"))?;
    let errors = array_field(&report, "errors")?;
    assert!(
        errors.iter().any(|error| error
            .as_str()
            .is_some_and(|text| text.contains("test_missing_completion_debt_binding"))),
        "report should name stale binding: {errors:?}"
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_e2e_scenario_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "gentoo-regression-contract-fail-e2e")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let scenarios = manifest["e2e_primary"]["scenarios"]
        .as_array_mut()
        .ok_or_else(|| test_error("e2e scenarios should be array"))?;
    scenarios
        .retain(|scenario| scenario["scenario_id"].as_str() != Some("blocking_current_fails_gate"));
    let bad_manifest = out_dir.join("bad_contract.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing e2e scenario"
    );
    let report =
        load_json(&out_dir.join("gentoo_regression_detector_completion_contract.report.json"))?;
    let errors = array_field(&report, "errors")?;
    assert!(
        errors.iter().any(|error| error
            .as_str()
            .is_some_and(|text| text.contains("blocking_current_fails_gate"))),
        "report should name missing e2e scenario: {errors:?}"
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_telemetry_event_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "gentoo-regression-contract-fail-telemetry")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let events = manifest["telemetry_contract"]["required_log_events"]
        .as_array_mut()
        .ok_or_else(|| test_error("required_log_events should be array"))?;
    events.retain(|event| event.as_str() != Some("gentoo_regression_detector_e2e"));
    let bad_manifest = out_dir.join("bad_contract.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing telemetry event"
    );
    let report =
        load_json(&out_dir.join("gentoo_regression_detector_completion_contract.report.json"))?;
    let errors = array_field(&report, "errors")?;
    assert!(
        errors.iter().any(|error| error
            .as_str()
            .is_some_and(|text| text.contains("required_log_events drifted"))),
        "report should name telemetry drift: {errors:?}"
    );
    Ok(())
}
