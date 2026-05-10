//! Change-impact scheduler completion-debt contract (bd-26xb.2 / bd-26xb.2.1).

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
    root.join("tests/conformance/change_impact_scheduler_completion_contract.v1.json")
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
        .arg(root.join("scripts/check_change_impact_scheduler_completion_contract.sh"))
        .current_dir(root)
        .env("FRANKENLIBC_CHANGE_IMPACT_CONTRACT", contract)
        .env("FRANKENLIBC_CHANGE_IMPACT_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_CHANGE_IMPACT_REPORT",
            out_dir.join("change_impact_scheduler_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_CHANGE_IMPACT_LOG",
            out_dir.join("change_impact_scheduler_completion_contract.log.jsonl"),
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
        "change-impact-scheduler-completion-contract"
    );
    assert_eq!(string_field(&manifest, "bead")?, "bd-26xb.2");
    assert_eq!(
        string_field(&manifest, "completion_debt_bead")?,
        "bd-26xb.2.1"
    );
    let evidence = manifest
        .get("completion_debt_evidence")
        .ok_or_else(|| test_error("missing completion_debt_evidence"))?;
    assert_eq!(string_field(evidence, "bead")?, "bd-26xb.2.1");
    assert_eq!(string_field(evidence, "original_bead")?, "bd-26xb.2");
    assert!(
        evidence
            .get("next_audit_score_threshold")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            >= 800
    );
    Ok(())
}

#[test]
fn impact_rules_are_file_and_budget_backed() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let policy = load_json(&root.join("tests/conformance/perf_budget_policy.json"))?;
    let budget_classes: BTreeSet<_> = policy
        .get("budgets")
        .and_then(Value::as_object)
        .ok_or_else(|| test_error("perf budget classes should be object"))?
        .keys()
        .map(String::as_str)
        .collect();

    let mut rule_ids = BTreeSet::new();
    for rule in array_field(&manifest, "impact_rules")? {
        rule_ids.insert(string_field(rule, "rule_id")?.to_owned());
        assert!(
            budget_classes.contains(string_field(rule, "budget_class")?),
            "rule budget class should exist"
        );
        assert!(!array_field(rule, "changed_path_prefixes")?.is_empty());
        assert!(!array_field(rule, "symbols")?.is_empty());
        for test in array_field(rule, "required_tests")? {
            let test = test
                .as_str()
                .ok_or_else(|| test_error("required test should be string"))?;
            assert!(root.join(test).is_file(), "missing required test {test}");
        }
    }
    assert_eq!(
        rule_ids,
        BTreeSet::from([
            "malloc_hotpath".to_owned(),
            "runtime_math_policy".to_owned(),
            "stdio_format".to_owned(),
            "string_hotpath".to_owned(),
        ])
    );
    Ok(())
}

#[test]
fn scheduler_scenarios_cover_selective_and_full_suite() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let scenarios = array_field(&manifest, "e2e_scenarios")?;
    let decisions: BTreeSet<_> = scenarios
        .iter()
        .filter_map(|scenario| scenario.get("expected_decision").and_then(Value::as_str))
        .collect();
    assert!(decisions.contains("selective"));
    assert!(decisions.contains("full_suite"));
    assert!(scenarios.iter().any(|scenario| {
        scenario
            .get("false_negative_sentinel")
            .and_then(Value::as_bool)
            == Some(true)
            && scenario.get("expected_reason").and_then(Value::as_str)
                == Some("false_negative_sentinel")
    }));
    assert!(scenarios.iter().any(|scenario| {
        scenario.get("expected_reason").and_then(Value::as_str) == Some("unknown_impact")
    }));
    Ok(())
}

#[test]
fn checker_accepts_manifest_and_emits_evidence() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "change-impact-completion-ok")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    assert!(
        output.status.success(),
        "checker failed stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report =
        load_json(&out_dir.join("change_impact_scheduler_completion_contract.report.json"))?;
    assert_eq!(string_field(&report, "status")?, "pass");
    assert_eq!(
        report.get("impact_rule_count").and_then(Value::as_u64),
        Some(4)
    );
    assert_eq!(
        report.get("scenario_count").and_then(Value::as_u64),
        Some(5)
    );
    let scenario_results = array_field(&report, "scenario_results")?;
    assert!(scenario_results.iter().any(|scenario| {
        scenario.get("scenario_id").and_then(Value::as_str) == Some("string_low_pressure_selective")
            && scenario.get("decision").and_then(Value::as_str) == Some("selective")
    }));
    assert!(scenario_results.iter().any(|scenario| {
        scenario.get("scenario_id").and_then(Value::as_str)
            == Some("false_negative_sentinel_full_suite")
            && scenario.get("decision").and_then(Value::as_str) == Some("full_suite")
    }));

    let rows = load_jsonl(&out_dir.join("change_impact_scheduler_completion_contract.log.jsonl"))?;
    let events: BTreeSet<_> = rows
        .iter()
        .filter_map(|row| optional_string_field(row, "event"))
        .collect();
    for event in [
        "change_impact_component",
        "change_impact_rule",
        "change_impact_scenario",
        "change_impact_summary",
    ] {
        assert!(events.contains(event), "missing telemetry event {event}");
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_required_test_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "change-impact-completion-fail-test")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let tests = manifest
        .get_mut("impact_rules")
        .and_then(Value::as_array_mut)
        .and_then(|rules| rules.first_mut())
        .and_then(|rule| rule.get_mut("required_tests"))
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("required tests should be array"))?;
    tests.push(json!(
        "crates/frankenlibc-harness/tests/missing_change_impact_test.rs"
    ));
    let bad_manifest = out_dir.join("bad_contract.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker unexpectedly accepted missing required test binding"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("required_tests missing file"));
    Ok(())
}

#[test]
fn checker_rejects_missing_false_negative_sentinel() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "change-impact-completion-fail-sentinel")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let scenarios = manifest
        .get_mut("e2e_scenarios")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("e2e scenarios should be array"))?;
    scenarios.retain(|scenario| {
        scenario
            .get("false_negative_sentinel")
            .and_then(Value::as_bool)
            != Some(true)
    });
    let bad_manifest = out_dir.join("bad_contract.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker unexpectedly accepted missing false-negative sentinel"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("false_negative_sentinel"));
    Ok(())
}

#[test]
fn checker_rejects_stale_unit_test_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "change-impact-completion-fail-unit")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let tests = manifest
        .get_mut("unit_primary")
        .and_then(|section| section.get_mut("required_test_names"))
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("unit test names should be array"))?;
    tests.push(json!("missing_change_impact_scheduler_completion_test"));
    let bad_manifest = out_dir.join("bad_contract.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker unexpectedly accepted stale unit test binding"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("missing Rust test"));
    Ok(())
}
