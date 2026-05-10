//! Optimization proof ledger completion-debt contract (bd-30o.2 / bd-30o.2.1).

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
    root.join("tests/conformance/optimization_proof_ledger_completion_contract.v1.json")
}

fn load_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
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

fn object_field<'a>(
    value: &'a Value,
    field: &str,
) -> TestResult<&'a serde_json::Map<String, Value>> {
    value
        .get(field)
        .and_then(Value::as_object)
        .ok_or_else(|| test_error(format!("missing object field {field}")))
}

fn source_artifact_path(manifest: &Value, artifact_id: &str) -> TestResult<String> {
    let artifacts = object_field(manifest, "source_artifacts")?;
    artifacts
        .get(artifact_id)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| test_error(format!("missing source_artifacts.{artifact_id}")))
}

fn string_set(values: &[Value]) -> TestResult<BTreeSet<String>> {
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| test_error("array entry should be string"))
        })
        .collect()
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<std::process::Output> {
    Ok(Command::new("bash")
        .arg(root.join("scripts/check_optimization_proof_ledger_completion_contract.sh"))
        .current_dir(root)
        .env("OPTIMIZATION_PROOF_LEDGER_COMPLETION_CONTRACT", contract)
        .env("OPTIMIZATION_PROOF_LEDGER_COMPLETION_OUT_DIR", out_dir)
        .env(
            "OPTIMIZATION_PROOF_LEDGER_COMPLETION_REPORT",
            out_dir.join("optimization_proof_ledger_completion_contract.report.json"),
        )
        .env(
            "OPTIMIZATION_PROOF_LEDGER_COMPLETION_LOG",
            out_dir.join("optimization_proof_ledger_completion_contract.log.jsonl"),
        )
        .output()?)
}

fn run_bad_manifest(root: &Path, manifest: &Value, out_dir: &Path) -> TestResult<Value> {
    let bad_manifest = out_dir.join("bad_contract.json");
    write_json(&bad_manifest, manifest)?;
    let output = run_checker(root, &bad_manifest, out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject bad manifest stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    load_json(&out_dir.join("optimization_proof_ledger_completion_contract.report.json"))
}

#[test]
fn manifest_anchors_completion_debt() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    assert_eq!(string_field(&manifest, "schema_version")?, "v1");
    assert_eq!(
        string_field(&manifest, "manifest_id")?,
        "optimization-proof-ledger-completion-contract"
    );
    assert_eq!(string_field(&manifest, "bead")?, "bd-30o.2");
    assert_eq!(
        string_field(&manifest, "completion_debt_bead")?,
        "bd-30o.2.1"
    );
    Ok(())
}

#[test]
fn source_artifacts_are_file_backed() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    for (artifact_id, path_value) in object_field(&manifest, "source_artifacts")? {
        let path = path_value
            .as_str()
            .ok_or_else(|| test_error(format!("{artifact_id} path must be string")))?;
        assert!(root.join(path).is_file(), "{artifact_id} missing {path}");
    }
    Ok(())
}

#[test]
fn ledger_contract_binds_checked_in_ledger() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let ledger = load_json(&root.join(source_artifact_path(&manifest, "ledger")?))?;
    let contract = manifest
        .get("ledger_contract")
        .ok_or_else(|| test_error("missing ledger_contract"))?;
    assert_eq!(
        ledger.get("schema_version").and_then(Value::as_u64),
        contract.get("schema_version").and_then(Value::as_u64)
    );
    assert_eq!(ledger.get("bead"), contract.get("bead"));

    let actual_ids: BTreeSet<_> = array_field(&ledger, "candidates")?
        .iter()
        .filter_map(|candidate| candidate.get("candidate_id").and_then(Value::as_str))
        .map(ToOwned::to_owned)
        .collect();
    let expected_ids = string_set(array_field(contract, "expected_candidate_ids")?)?;
    assert_eq!(actual_ids, expected_ids);

    let template_classes = string_set(array_field(
        &ledger["proof_template"],
        "minimum_input_class_coverage",
    )?)?;
    for required in string_set(array_field(contract, "required_input_classes")?)? {
        assert!(
            template_classes.contains(&required),
            "missing input class {required}"
        );
    }

    let expected_summary = object_field(contract, "summary")?;
    for (key, expected) in expected_summary {
        assert_eq!(
            ledger["summary"].get(key),
            Some(expected),
            "summary mismatch for {key}"
        );
    }
    Ok(())
}

#[test]
fn checker_contract_binds_original_gate_script() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let checker = manifest
        .get("checker_contract")
        .ok_or_else(|| test_error("missing checker_contract"))?;
    let script = string_field(checker, "script")?;
    let source = std::fs::read_to_string(root.join(script))?;
    for needle in array_field(checker, "required_script_needles")? {
        let needle = needle
            .as_str()
            .ok_or_else(|| test_error("script needle must be string"))?;
        assert!(source.contains(needle), "missing checker needle {needle}");
    }
    Ok(())
}

#[test]
fn unit_primary_binds_original_unit_tests() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let unit = manifest
        .get("unit_primary")
        .ok_or_else(|| test_error("missing unit_primary"))?;
    assert_eq!(string_field(unit, "missing_item_id")?, "tests.unit.primary");
    let source = std::fs::read_to_string(root.join(string_field(unit, "test_file")?))?;
    for name in array_field(unit, "required_test_names")? {
        let name = name
            .as_str()
            .ok_or_else(|| test_error("test name must be string"))?;
        assert!(source.contains(&format!("fn {name}(")), "missing {name}");
    }
    Ok(())
}

#[test]
fn e2e_primary_scenarios_are_explicit_and_rch_safe() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let e2e = manifest
        .get("e2e_primary")
        .ok_or_else(|| test_error("missing e2e_primary"))?;
    assert_eq!(string_field(e2e, "missing_item_id")?, "tests.e2e.primary");
    let ids: BTreeSet<_> = array_field(e2e, "scenarios")?
        .iter()
        .filter_map(|scenario| scenario.get("scenario_id").and_then(Value::as_str))
        .collect();
    for scenario in [
        "optimization_proof_ledger_gate_passes",
        "completion_checker_replays_ledger_gate",
        "rust_completion_contract_exercises_positive_and_negative_paths",
    ] {
        assert!(ids.contains(scenario), "missing scenario {scenario}");
    }
    for scenario in array_field(e2e, "scenarios")? {
        let command = string_field(scenario, "command")?;
        if command.contains("cargo ") {
            assert!(
                command.starts_with("rch cargo "),
                "cargo scenario must use rch: {command}"
            );
        }
        assert!(
            command.starts_with("bash scripts/") || command.starts_with("rch cargo "),
            "unsupported scenario launcher: {command}"
        );
        assert_eq!(
            scenario.get("expected_exit").and_then(Value::as_u64),
            Some(0)
        );
    }
    Ok(())
}

#[test]
fn completion_evidence_names_this_test_suite() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let evidence = manifest
        .get("completion_debt_evidence")
        .ok_or_else(|| test_error("missing completion_debt_evidence"))?;
    assert_eq!(string_field(evidence, "bead")?, "bd-30o.2.1");
    assert_eq!(string_field(evidence, "original_bead")?, "bd-30o.2");
    let source = std::fs::read_to_string(root.join(string_field(evidence, "test_source")?))?;
    for name in array_field(evidence, "required_test_names")? {
        let name = name
            .as_str()
            .ok_or_else(|| test_error("completion test name must be string"))?;
        assert!(source.contains(&format!("fn {name}(")), "missing {name}");
    }
    Ok(())
}

#[test]
fn checker_accepts_manifest_and_emits_report() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "optimization-ledger-ok")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    assert!(
        output.status.success(),
        "checker failed stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report =
        load_json(&out_dir.join("optimization_proof_ledger_completion_contract.report.json"))?;
    assert_eq!(string_field(&report, "status")?, "pass");
    assert_eq!(
        string_field(&report, "schema_version")?,
        "optimization_proof_ledger_completion_contract.report.v1"
    );
    assert_eq!(
        report.get("candidate_count").and_then(Value::as_u64),
        Some(3)
    );
    assert_eq!(
        report
            .get("expected_candidate_count")
            .and_then(Value::as_u64),
        Some(3)
    );
    assert_eq!(
        report
            .get("unit_required_test_count")
            .and_then(Value::as_u64),
        Some(10)
    );
    assert_eq!(
        report.get("e2e_scenario_count").and_then(Value::as_u64),
        Some(3)
    );
    assert_eq!(
        report.get("original_gate_status").and_then(Value::as_str),
        Some("pass")
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_unit_test_anchor() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "optimization-ledger-fail-unit")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["unit_primary"]["required_test_names"][0] =
        json!("missing_optimization_ledger_unit_test");
    let report = run_bad_manifest(&root, &manifest, &out_dir)?;
    let errors = array_field(&report, "errors")?;
    assert!(
        errors.iter().any(|error| error
            .as_str()
            .is_some_and(|text| text.contains("unit_primary references missing ledger unit test"))),
        "report should name missing unit test: {errors:?}"
    );
    Ok(())
}

#[test]
fn checker_rejects_stale_summary_count() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "optimization-ledger-fail-summary")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["ledger_contract"]["summary"]["total_candidates"] = json!(4);
    let report = run_bad_manifest(&root, &manifest, &out_dir)?;
    let errors = array_field(&report, "errors")?;
    assert!(
        errors.iter().any(|error| {
            error
                .as_str()
                .is_some_and(|text| text.contains("ledger summary total_candidates mismatch"))
        }),
        "report should name stale summary count: {errors:?}"
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_candidate_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "optimization-ledger-fail-candidate")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["ledger_contract"]["expected_candidate_ids"]
        .as_array_mut()
        .ok_or_else(|| test_error("expected_candidate_ids should be array"))?
        .pop();
    let report = run_bad_manifest(&root, &manifest, &out_dir)?;
    let errors = array_field(&report, "errors")?;
    assert!(
        errors.iter().any(|error| error
            .as_str()
            .is_some_and(|text| text.contains("expected_candidate_ids mismatch"))),
        "report should name missing candidate binding: {errors:?}"
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_completion_test_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "optimization-ledger-fail-completion-test")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["completion_debt_evidence"]["required_test_names"][0] =
        json!("missing_optimization_ledger_completion_contract_test");
    let report = run_bad_manifest(&root, &manifest, &out_dir)?;
    let errors = array_field(&report, "errors")?;
    assert!(
        errors.iter().any(|error| error.as_str().is_some_and(
            |text| text.contains("completion_debt_evidence references missing Rust test")
        )),
        "report should name missing completion test binding: {errors:?}"
    );
    Ok(())
}
