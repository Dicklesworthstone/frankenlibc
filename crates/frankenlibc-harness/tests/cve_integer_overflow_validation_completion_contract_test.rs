//! CVE integer-overflow validation completion-debt contract (bd-1m5.4 / bd-1m5.4.1).

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
    root.join("tests/cve_arena/results/integer_overflow_validation_completion_contract.v1.json")
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
        .arg(root.join("scripts/check_cve_integer_overflow_validation_completion_contract.sh"))
        .current_dir(root)
        .env("FRANKENLIBC_CVE_INTOVF_COMPLETION_CONTRACT", contract)
        .env("FRANKENLIBC_CVE_INTOVF_COMPLETION_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_CVE_INTOVF_COMPLETION_REPORT",
            out_dir.join("cve_integer_overflow_validation_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_CVE_INTOVF_COMPLETION_LOG",
            out_dir.join("cve_integer_overflow_validation_completion_contract.log.jsonl"),
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
        "cve-integer-overflow-validation-completion-contract"
    );
    assert_eq!(string_field(&manifest, "bead")?, "bd-1m5.4");
    assert_eq!(
        string_field(&manifest, "completion_debt_bead")?,
        "bd-1m5.4.1"
    );

    let evidence = manifest
        .get("completion_debt_evidence")
        .ok_or_else(|| test_error("missing completion_debt_evidence"))?;
    assert_eq!(string_field(evidence, "bead")?, "bd-1m5.4.1");
    assert_eq!(string_field(evidence, "original_bead")?, "bd-1m5.4");
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
fn manifest_binds_unit_and_e2e_missing_items() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let unit = manifest
        .get("unit_primary")
        .ok_or_else(|| test_error("missing unit_primary"))?;
    let e2e = manifest
        .get("e2e_primary")
        .ok_or_else(|| test_error("missing e2e_primary"))?;
    assert_eq!(string_field(unit, "missing_item_id")?, "tests.unit.primary");
    assert_eq!(string_field(e2e, "missing_item_id")?, "tests.e2e.primary");
    assert!(
        array_field(unit, "required_test_names")?.len() >= 5,
        "unit evidence should bind completion tests"
    );
    assert_eq!(array_field(e2e, "scenarios")?.len(), 3);
    Ok(())
}

#[test]
fn source_artifacts_are_file_backed() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    for artifact in array_field(&manifest, "source_artifacts")? {
        let path = root.join(string_field(artifact, "path")?);
        let source = std::fs::read_to_string(&path)?;
        for needle in array_field(artifact, "required_needles")? {
            let needle = needle
                .as_str()
                .ok_or_else(|| test_error("needle should be string"))?;
            assert!(
                source.contains(needle),
                "{} missing needle {needle}",
                path.display()
            );
        }
    }
    Ok(())
}

#[test]
fn cve_cases_bind_integer_overflow_manifests() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let mut cves = BTreeSet::new();
    for case in array_field(&manifest, "cve_cases")? {
        let cve_id = string_field(case, "cve_id")?;
        cves.insert(cve_id.to_owned());
        let case_manifest = load_json(&root.join(string_field(case, "manifest_path")?))?;
        assert_eq!(string_field(&case_manifest, "cve_id")?, cve_id);
        assert!(root.join(string_field(case, "trigger_path")?).is_file());

        let required_healing: BTreeSet<_> = array_field(case, "required_healing_actions")?
            .iter()
            .filter_map(Value::as_str)
            .collect();
        let tsm = case_manifest
            .get("expected_tsm")
            .or_else(|| case_manifest.get("expected_tsm_behavior"))
            .ok_or_else(|| test_error("missing TSM section"))?;
        let manifest_healing: BTreeSet<_> = array_field(tsm, "healing_actions")?
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(
            required_healing.is_subset(&manifest_healing),
            "{cve_id} healing actions drifted"
        );
    }
    assert_eq!(
        cves,
        BTreeSet::from(["CVE-2023-6246".to_owned(), "CVE-2024-46461".to_owned()])
    );
    Ok(())
}

#[test]
fn checker_accepts_manifest_and_emits_evidence() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "cve-intovf-completion-ok")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    assert!(
        output.status.success(),
        "checker failed stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = load_json(
        &out_dir.join("cve_integer_overflow_validation_completion_contract.report.json"),
    )?;
    assert_eq!(string_field(&report, "status")?, "pass");
    assert_eq!(
        report.get("cve_case_count").and_then(Value::as_u64),
        Some(2)
    );
    assert_eq!(
        report.get("e2e_scenario_count").and_then(Value::as_u64),
        Some(3)
    );
    let summary = report
        .get("summary")
        .ok_or_else(|| test_error("missing summary"))?;
    assert_eq!(
        summary.get("total_intovf_tests").and_then(Value::as_u64),
        Some(2)
    );
    assert_eq!(summary.get("total_issues").and_then(Value::as_u64), Some(0));

    let rows =
        load_jsonl(&out_dir.join("cve_integer_overflow_validation_completion_contract.log.jsonl"))?;
    let events: BTreeSet<_> = rows
        .iter()
        .filter_map(|row| optional_string_field(row, "event"))
        .collect();
    for event in [
        "cve_integer_overflow_component",
        "cve_integer_overflow_case",
        "cve_integer_overflow_e2e",
        "cve_integer_overflow_summary",
    ] {
        assert!(events.contains(event), "missing telemetry event {event}");
    }
    assert!(rows.iter().any(|row| {
        optional_string_field(row, "event") == Some("cve_integer_overflow_e2e")
            && optional_string_field(row, "scenario_id")
                == Some("generate_isolated_integer_overflow_report")
            && optional_string_field(row, "status") == Some("pass")
    }));
    Ok(())
}

#[test]
fn checker_rejects_missing_clamp_healing_action() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "cve-intovf-completion-fail-healing")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let healing = manifest
        .get_mut("cve_cases")
        .and_then(Value::as_array_mut)
        .and_then(|cases| cases.first_mut())
        .and_then(|case| case.get_mut("required_healing_actions"))
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("required healing actions should be array"))?;
    healing.retain(|item| item.as_str() != Some("ClampSize"));
    let bad_manifest = out_dir.join("bad_contract.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker unexpectedly accepted missing ClampSize binding"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("required_healing_actions"));
    Ok(())
}

#[test]
fn checker_rejects_missing_e2e_scenario_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "cve-intovf-completion-fail-e2e")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let scenarios = manifest
        .get_mut("e2e_primary")
        .and_then(|section| section.get_mut("scenarios"))
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("e2e scenarios should be array"))?;
    scenarios.retain(|scenario| {
        scenario.get("scenario_id").and_then(Value::as_str) != Some("compile_glibc_syslog_trigger")
    });
    let bad_manifest = out_dir.join("bad_contract.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker unexpectedly accepted missing e2e scenario"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("e2e_primary.scenarios"));
    Ok(())
}

#[test]
fn checker_rejects_stale_unit_test_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "cve-intovf-completion-fail-unit")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let tests = manifest
        .get_mut("unit_primary")
        .and_then(|section| section.get_mut("required_test_names"))
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("unit test names should be array"))?;
    tests.push(json!("missing_cve_integer_overflow_completion_test"));
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
