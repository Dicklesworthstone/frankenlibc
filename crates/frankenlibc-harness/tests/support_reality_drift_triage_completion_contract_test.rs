//! Support/reality drift triage completion-debt contract (bd-0agsk.4 / bd-0agsk.4.1).

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
    root.join("tests/conformance/support_reality_drift_triage_completion_contract.v1.json")
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
        .arg(root.join("scripts/check_support_reality_drift_triage_completion_contract.sh"))
        .current_dir(root)
        .env("SUPPORT_REALITY_DRIFT_COMPLETION_CONTRACT", contract)
        .env("SUPPORT_REALITY_DRIFT_COMPLETION_OUT_DIR", out_dir)
        .env(
            "SUPPORT_REALITY_DRIFT_COMPLETION_REPORT",
            out_dir.join("support_reality_drift_triage_completion_contract.report.json"),
        )
        .env(
            "SUPPORT_REALITY_DRIFT_COMPLETION_LOG",
            out_dir.join("support_reality_drift_triage_completion_contract.log.jsonl"),
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
        "support-reality-drift-triage-completion-contract"
    );
    assert_eq!(string_field(&manifest, "bead")?, "bd-0agsk.4");
    assert_eq!(
        string_field(&manifest, "completion_debt_bead")?,
        "bd-0agsk.4.1"
    );
    let evidence = manifest
        .get("completion_debt_evidence")
        .ok_or_else(|| test_error("missing completion_debt_evidence"))?;
    assert_eq!(string_field(evidence, "bead")?, "bd-0agsk.4.1");
    assert_eq!(string_field(evidence, "original_bead")?, "bd-0agsk.4");
    Ok(())
}

#[test]
fn source_artifacts_are_file_backed() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let artifacts = manifest
        .get("source_artifacts")
        .and_then(Value::as_object)
        .ok_or_else(|| test_error("missing source_artifacts"))?;
    for (artifact_id, path_value) in artifacts {
        let path = path_value
            .as_str()
            .ok_or_else(|| test_error(format!("{artifact_id} path must be string")))?;
        assert!(root.join(path).is_file(), "{artifact_id} missing {path}");
    }
    Ok(())
}

#[test]
fn triage_invariants_bind_delta_buckets() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let triage = load_json(&root.join("tests/conformance/support_reality_drift_triage.v1.json"))?;
    let invariants = manifest
        .get("triage_invariants")
        .ok_or_else(|| test_error("missing triage_invariants"))?;
    assert_eq!(
        string_field(&triage, "schema_version")?,
        string_field(invariants, "schema_version")?
    );
    assert_eq!(string_field(&triage, "generated_by_bead")?, "bd-0agsk.4");
    assert_eq!(
        string_field(&triage, "claim_status")?,
        string_field(invariants, "claim_status")?
    );

    let buckets: BTreeSet<_> = array_field(&triage, "delta_buckets")?
        .iter()
        .filter_map(|bucket| bucket.get("id").and_then(Value::as_str))
        .collect();
    for required in array_field(invariants, "required_delta_buckets")? {
        assert!(
            buckets.contains(string_field(required, "id")?),
            "missing delta bucket {}",
            string_field(required, "id")?
        );
    }
    Ok(())
}

#[test]
fn original_rust_conformance_tests_are_bound() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let rust = manifest
        .get("rust_conformance_contract")
        .ok_or_else(|| test_error("missing rust_conformance_contract"))?;
    let source = std::fs::read_to_string(root.join(string_field(rust, "test_file")?))?;
    for required in array_field(rust, "required_tests")? {
        let name = string_field(required, "test")?;
        assert!(source.contains(&format!("fn {name}(")), "missing {name}");
    }
    Ok(())
}

#[test]
fn conformance_primary_scenarios_are_explicit() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let conformance = manifest
        .get("conformance_primary")
        .ok_or_else(|| test_error("missing conformance_primary"))?;
    assert_eq!(
        string_field(conformance, "missing_item_id")?,
        "tests.conformance.primary"
    );
    let ids: BTreeSet<_> = array_field(conformance, "scenarios")?
        .iter()
        .filter_map(|scenario| scenario.get("scenario_id").and_then(Value::as_str))
        .collect();
    for scenario in [
        "triage_checker_passes_live_inputs",
        "rust_conformance_binds_positive_and_negative_cases",
        "fail_closed_contract_mutations_are_rejected",
    ] {
        assert!(ids.contains(scenario), "missing scenario {scenario}");
    }
    Ok(())
}

#[test]
fn checker_accepts_manifest_and_runs_original_gate() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "support-reality-drift-completion-ok")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    assert!(
        output.status.success(),
        "checker failed stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report =
        load_json(&out_dir.join("support_reality_drift_triage_completion_contract.report.json"))?;
    assert_eq!(string_field(&report, "status")?, "pass");
    assert!(
        report
            .get("source_artifact_count")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            >= 7
    );
    assert_eq!(
        report
            .get("conformance_scenario_count")
            .and_then(Value::as_u64),
        Some(1)
    );

    let rows =
        load_jsonl(&out_dir.join("support_reality_drift_triage_completion_contract.log.jsonl"))?;
    let events: BTreeSet<_> = rows
        .iter()
        .filter_map(|row| optional_string_field(row, "event"))
        .collect();
    for event in [
        "support_reality_drift_completion_source",
        "support_reality_drift_completion_conformance",
        "support_reality_drift_completion_summary",
    ] {
        assert!(events.contains(event), "missing telemetry event {event}");
    }
    assert!(rows.iter().any(|row| {
        optional_string_field(row, "event") == Some("support_reality_drift_completion_conformance")
            && optional_string_field(row, "scenario_id")
                == Some("triage_checker_passes_live_inputs")
            && optional_string_field(row, "status") == Some("pass")
    }));
    Ok(())
}

#[test]
fn checker_rejects_missing_required_test_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "support-reality-drift-fail-test")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let tests = manifest["rust_conformance_contract"]["required_tests"]
        .as_array_mut()
        .ok_or_else(|| test_error("required_tests should be array"))?;
    tests.push(json!({
        "test": "missing_support_reality_drift_completion_test",
        "line_ref": "crates/frankenlibc-harness/tests/support_reality_drift_triage_test.rs:1"
    }));
    let bad_manifest = out_dir.join("bad_contract.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject stale required test"
    );
    let report =
        load_json(&out_dir.join("support_reality_drift_triage_completion_contract.report.json"))?;
    let errors = array_field(&report, "errors")?;
    assert!(
        errors.iter().any(|error| error
            .as_str()
            .is_some_and(|text| text.contains("missing required Rust conformance test"))),
        "report should name missing test binding: {errors:?}"
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_delta_bucket_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "support-reality-drift-fail-bucket")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let buckets = manifest["triage_invariants"]["required_delta_buckets"]
        .as_array_mut()
        .ok_or_else(|| test_error("required_delta_buckets should be array"))?;
    buckets.push(json!({
        "id": "missing_completion_contract_bucket",
        "classification": "missing_export",
        "min_symbol_count": 1,
        "required_symbols": ["missing_symbol"]
    }));
    let bad_manifest = out_dir.join("bad_contract.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing delta bucket"
    );
    let report =
        load_json(&out_dir.join("support_reality_drift_triage_completion_contract.report.json"))?;
    let errors = array_field(&report, "errors")?;
    assert!(
        errors.iter().any(|error| error
            .as_str()
            .is_some_and(|text| text.contains("missing required triage delta bucket"))),
        "report should name missing bucket: {errors:?}"
    );
    Ok(())
}

#[test]
fn checker_rejects_stale_summary_count() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "support-reality-drift-fail-summary")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["triage_invariants"]["summary"]["delta_symbol_count"] = json!(74);
    let bad_manifest = out_dir.join("bad_contract.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject stale summary count"
    );
    let report =
        load_json(&out_dir.join("support_reality_drift_triage_completion_contract.report.json"))?;
    let errors = array_field(&report, "errors")?;
    assert!(
        errors.iter().any(|error| error
            .as_str()
            .is_some_and(|text| text.contains("triage summary count mismatch"))),
        "report should name stale summary count: {errors:?}"
    );
    Ok(())
}
