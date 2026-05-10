//! Cross-report consistency completion-debt contract (bd-2vv.11 / bd-2vv.11.1).

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
    root.join("tests/conformance/cross_report_consistency_completion_contract.v1.json")
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
        .arg(root.join("scripts/check_cross_report_consistency_completion_contract.sh"))
        .current_dir(root)
        .env("CROSS_REPORT_COMPLETION_CONTRACT", contract)
        .env("CROSS_REPORT_COMPLETION_OUT_DIR", out_dir)
        .env(
            "CROSS_REPORT_COMPLETION_REPORT",
            out_dir.join("cross_report_consistency_completion_contract.report.json"),
        )
        .env(
            "CROSS_REPORT_COMPLETION_LOG",
            out_dir.join("cross_report_consistency_completion_contract.log.jsonl"),
        )
        .env(
            "CROSS_REPORT_COMPLETION_GENERATED",
            out_dir.join("cross_report_consistency_completion_contract.generated.json"),
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
        "cross-report-consistency-completion-contract"
    );
    assert_eq!(string_field(&manifest, "bead")?, "bd-2vv.11");
    assert_eq!(
        string_field(&manifest, "completion_debt_bead")?,
        "bd-2vv.11.1"
    );
    let evidence = manifest
        .get("completion_debt_evidence")
        .ok_or_else(|| test_error("missing completion_debt_evidence"))?;
    assert_eq!(string_field(evidence, "bead")?, "bd-2vv.11.1");
    assert_eq!(string_field(evidence, "original_bead")?, "bd-2vv.11");
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
fn consistency_invariants_bind_checked_in_report() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let report = load_json(&root.join("tests/conformance/cross_report_consistency.v1.json"))?;
    let invariants = manifest
        .get("consistency_invariants")
        .ok_or_else(|| test_error("missing consistency_invariants"))?;
    assert_eq!(
        string_field(&report, "schema_version")?,
        string_field(invariants, "schema_version")?
    );
    assert_eq!(string_field(&report, "bead")?, "bd-2vv.11");
    assert_eq!(
        string_field(&report, "consistency_hash")?,
        string_field(invariants, "consistency_hash")?
    );

    let summary = report
        .get("summary")
        .ok_or_else(|| test_error("missing report summary"))?;
    let expected = invariants
        .get("summary")
        .ok_or_else(|| test_error("missing invariant summary"))?;
    assert_eq!(
        string_field(summary, "overall_verdict")?,
        string_field(expected, "overall_verdict")?
    );
    assert_eq!(
        summary.get("total_findings").and_then(Value::as_u64),
        expected.get("total_findings").and_then(Value::as_u64)
    );
    assert_eq!(summary["by_severity"]["critical"], expected["critical"]);
    assert_eq!(summary["by_severity"]["error"], expected["error"]);
    assert_eq!(summary["by_severity"]["warning"], expected["warning"]);
    assert_eq!(
        summary["by_verdict"]["inconsistent"].as_u64().unwrap_or(0),
        expected["inconsistent"].as_u64().unwrap_or(0)
    );

    let findings = array_field(&report, "findings")?;
    for required in array_field(invariants, "required_findings")? {
        let required_symbol = required.get("required_symbol").and_then(Value::as_str);
        let found = findings.iter().any(|finding| {
            finding.get("rule") == required.get("rule")
                && finding.get("verdict") == required.get("verdict")
                && finding.get("severity") == required.get("severity")
                && required_symbol.is_none_or(|symbol| {
                    finding
                        .get("affected_symbols")
                        .and_then(Value::as_array)
                        .is_some_and(|symbols| {
                            symbols.iter().any(|item| item.as_str() == Some(symbol))
                        })
                })
        });
        assert!(found, "missing required finding {required:?}");
    }
    Ok(())
}

#[test]
fn unit_primary_binds_original_rust_tests() -> TestResult {
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
            .ok_or_else(|| test_error("required test name must be string"))?;
        assert!(source.contains(&format!("fn {name}(")), "missing {name}");
    }
    Ok(())
}

#[test]
fn e2e_primary_scenarios_are_explicit() -> TestResult {
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
        "completion_checker_replays_current_generator",
        "generator_emits_cross_report_snapshot",
        "rust_completion_contract_exercises_positive_and_negative_paths",
    ] {
        assert!(ids.contains(scenario), "missing scenario {scenario}");
    }
    Ok(())
}

#[test]
fn checker_accepts_manifest_and_emits_report() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "cross-report-completion-ok")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    assert!(
        output.status.success(),
        "checker failed stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report =
        load_json(&out_dir.join("cross_report_consistency_completion_contract.report.json"))?;
    assert_eq!(string_field(&report, "status")?, "pass");
    assert_eq!(
        string_field(&report, "schema_version")?,
        "cross_report_consistency_completion_contract.report.v1"
    );
    assert!(
        report
            .get("source_artifact_count")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            >= 9
    );
    assert_eq!(
        report
            .get("unit_required_test_count")
            .and_then(Value::as_u64),
        Some(7)
    );
    assert_eq!(
        report.get("e2e_executed_count").and_then(Value::as_u64),
        Some(1)
    );

    let generated =
        load_json(&out_dir.join("cross_report_consistency_completion_contract.generated.json"))?;
    assert_eq!(
        generated.get("consistency_hash").and_then(Value::as_str),
        Some("83be1ea069445394")
    );

    let rows = load_jsonl(&out_dir.join("cross_report_consistency_completion_contract.log.jsonl"))?;
    let events: BTreeSet<_> = rows
        .iter()
        .filter_map(|row| optional_string_field(row, "event"))
        .collect();
    for event in [
        "cross_report_completion_source",
        "cross_report_completion_unit",
        "cross_report_completion_e2e",
        "cross_report_completion_summary",
    ] {
        assert!(events.contains(event), "missing telemetry event {event}");
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_unit_test_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "cross-report-fail-unit")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let tests = manifest["unit_primary"]["required_test_names"]
        .as_array_mut()
        .ok_or_else(|| test_error("required_test_names should be array"))?;
    tests.push(json!("missing_cross_report_unit_test"));
    let bad_manifest = out_dir.join("bad_contract.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing unit test"
    );
    let report =
        load_json(&out_dir.join("cross_report_consistency_completion_contract.report.json"))?;
    let errors = array_field(&report, "errors")?;
    assert!(
        errors.iter().any(|error| error
            .as_str()
            .is_some_and(|text| text.contains("unit_primary references missing Rust test"))),
        "report should name missing unit test: {errors:?}"
    );
    Ok(())
}

#[test]
fn checker_rejects_stale_consistency_hash() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "cross-report-fail-hash")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["consistency_invariants"]["consistency_hash"] = json!("0000000000000000");
    let bad_manifest = out_dir.join("bad_contract.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(!output.status.success(), "checker should reject stale hash");
    let report =
        load_json(&out_dir.join("cross_report_consistency_completion_contract.report.json"))?;
    let errors = array_field(&report, "errors")?;
    assert!(
        errors.iter().any(|error| error
            .as_str()
            .is_some_and(|text| text.contains("consistency_hash drift"))),
        "report should name stale consistency hash: {errors:?}"
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_completion_test_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "cross-report-fail-completion")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let tests = manifest["completion_debt_evidence"]["required_test_names"]
        .as_array_mut()
        .ok_or_else(|| test_error("completion required tests should be array"))?;
    tests.push(json!("missing_cross_report_completion_contract_test"));
    let bad_manifest = out_dir.join("bad_contract.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing completion test"
    );
    let report =
        load_json(&out_dir.join("cross_report_consistency_completion_contract.report.json"))?;
    let errors = array_field(&report, "errors")?;
    assert!(
        errors.iter().any(|error| error.as_str().is_some_and(
            |text| text.contains("completion_debt_evidence references missing Rust test")
        )),
        "report should name missing completion test: {errors:?}"
    );
    Ok(())
}
