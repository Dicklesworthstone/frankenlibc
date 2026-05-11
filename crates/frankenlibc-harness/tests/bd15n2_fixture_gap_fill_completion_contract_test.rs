//! Contract tests for bd-15n.2.1 fixture gap-fill completion evidence.

use std::collections::BTreeSet;
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
    let path = root.join("tests/conformance/bd15n2_fixture_gap_fill_completion_contract.v1.json");
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
        "bd15n2-fixture-gap-completion-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<std::process::Output> {
    Ok(Command::new("bash")
        .arg(root.join("scripts/check_bd15n2_fixture_gap_fill_completion_contract.sh"))
        .current_dir(root)
        .env("FRANKENLIBC_BD15N2_COMPLETION_CONTRACT", contract)
        .env(
            "FRANKENLIBC_BD15N2_COMPLETION_REPORT",
            out_dir.join("bd15n2_fixture_gap_fill_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_BD15N2_COMPLETION_LOG",
            out_dir.join("bd15n2_fixture_gap_fill_completion_contract.log.jsonl"),
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

fn file_line_ref_exists(root: &Path, file_line_ref: &str) -> TestResult {
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

#[test]
fn manifest_binds_unit_and_e2e_gap_fill_evidence() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_manifest(&root)?;
    assert_eq!(manifest["bead"].as_str(), Some("bd-15n.2"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-15n.2.1")
    );

    let missing = string_set(&manifest["audit"]["missing_item_ids"])?;
    assert!(missing.contains("tests.unit.primary"));
    assert!(missing.contains("tests.e2e.primary"));

    let evidence = &manifest["completion_debt_evidence"];
    assert_eq!(evidence["bead"].as_str(), Some("bd-15n.2.1"));
    assert_eq!(evidence["original_bead"].as_str(), Some("bd-15n.2"));
    assert!(
        evidence["next_audit_score_threshold"].as_u64().unwrap_or(0) >= 800,
        "completion evidence should target a passing next audit score"
    );

    for file_line_ref in evidence["implementation_refs"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "refs array"))?
    {
        file_line_ref_exists(
            &root,
            file_line_ref
                .as_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "ref string"))?,
        )?;
    }

    let fixtures = string_set(&evidence["required_fixtures"])?;
    for fixture_id in ["fixture_ctype", "fixture_math", "fixture_socket"] {
        assert!(
            fixtures.contains(fixture_id),
            "missing fixture {fixture_id}"
        );
    }
    let modes = string_set(&evidence["required_modes"])?;
    assert!(modes.contains("strict"));
    assert!(modes.contains("hardened"));

    let test_sources = evidence["test_sources"]
        .as_object()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "test sources object"))?;
    let c_fixture_test = std::fs::read_to_string(
        root.join(
            test_sources["c_fixture_suite_test"]
                .as_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "c fixture test path"))?,
        ),
    )?;
    assert!(c_fixture_test.contains("fn bd15n2_fixtures_have_traceability_and_mode_expectations"));
    let e2e_test = std::fs::read_to_string(
        root.join(
            test_sources["gap_fill_artifacts_test"]
                .as_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "e2e test path"))?,
        ),
    )?;
    assert!(e2e_test.contains("fn fixture_gap_fill_gate_emits_valid_bd15n2_artifacts"));

    let artifacts = evidence["source_artifacts"]
        .as_object()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "source artifacts object"))?;
    for value in artifacts.values() {
        let rel_path = value
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "artifact path"))?;
        assert!(
            root.join(rel_path).is_file(),
            "source artifact should exist: {rel_path}"
        );
    }

    let commands = string_set(&evidence["validation_commands"])?;
    assert!(
        commands
            .iter()
            .all(|command| command.starts_with("rch exec -- ")),
        "validation commands should be RCH-backed"
    );
    assert!(
        commands
            .iter()
            .any(|command| command.contains("bd15n2_fixture_gap_fill_completion_contract_test"))
    );
    assert!(
        commands
            .iter()
            .any(|command| command.contains("c_fixture_suite_test"))
    );

    Ok(())
}

#[test]
fn checker_emits_report_and_jsonl() -> TestResult {
    let root = workspace_root()?;
    let contract =
        root.join("tests/conformance/bd15n2_fixture_gap_fill_completion_contract.v1.json");
    let out_dir = unique_output_dir(&root, "pass")?;
    let output = run_checker(&root, &contract, &out_dir)?;
    assert!(
        output.status.success(),
        "checker failed stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report =
        read_json(&out_dir.join("bd15n2_fixture_gap_fill_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-15n.2.1"));
    assert_eq!(report["original_bead"].as_str(), Some("bd-15n.2"));
    assert_eq!(string_set(&report["fixture_ids"])?.len(), 3);
    assert_eq!(string_set(&report["modes"])?.len(), 2);
    assert!(
        report["unit_refs"]
            .as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "unit refs array"))?
            .iter()
            .any(|item| item.as_str()
                == Some(
                    "c_fixture_suite_test::bd15n2_fixtures_have_traceability_and_mode_expectations"
                )),
        "report should include unit metadata test ref"
    );
    assert!(
        report["e2e_refs"]
            .as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "e2e refs array"))?
            .iter()
            .any(|item| item.as_str()
                == Some(
                    "gap_fill_artifacts_test::fixture_gap_fill_gate_emits_valid_bd15n2_artifacts"
                )),
        "report should include e2e artifact test ref"
    );

    let rows = read_jsonl(&out_dir.join("bd15n2_fixture_gap_fill_completion_contract.log.jsonl"))?;
    assert_eq!(rows.len(), 1, "checker should emit one telemetry row");
    let row = &rows[0];
    assert!(json_str_field_is(
        row,
        "event",
        "bd15n2_fixture_gap_fill_completion_contract_validated"
    ));
    assert!(json_str_field_is(row, "completion_debt_bead", "bd-15n.2.1"));
    assert!(json_str_field_is(row, "status", "pass"));
    assert!(json_str_field_is(row, "failure_signature", "none"));
    assert!(string_set(&row["missing_item_ids"])?.contains("tests.e2e.primary"));

    Ok(())
}

#[test]
fn checker_rejects_missing_hardened_mode_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-mode")?;
    let mut manifest = read_manifest(&root)?;
    manifest["completion_debt_evidence"]["required_modes"] = serde_json::json!(["strict"]);
    let stale_contract = out_dir.join("missing_hardened_mode_contract.v1.json");
    write_json(&stale_contract, &manifest)?;

    let output = run_checker(&root, &stale_contract, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing hardened mode binding"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("required_modes must be strict,hardened"),
        "checker output should name missing mode binding: {combined}"
    );

    Ok(())
}

#[test]
fn checker_rejects_stale_report_fail_count() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "stale-report")?;
    let mut manifest = read_manifest(&root)?;
    let mut report = read_json(&root.join("tests/cve_arena/results/bd-15n.2/report.json"))?;
    report["summary"]["fail_count"] = serde_json::json!(1);
    let stale_report = out_dir.join("stale_bd15n2_report.json");
    write_json(&stale_report, &report)?;
    let stale_report_rel = stale_report
        .strip_prefix(&root)?
        .to_string_lossy()
        .replace('\\', "/");
    manifest["completion_debt_evidence"]["source_artifacts"]["gap_fill_report"] =
        serde_json::json!(stale_report_rel);
    let stale_contract = out_dir.join("stale_report_contract.v1.json");
    write_json(&stale_contract, &manifest)?;

    let output = run_checker(&root, &stale_contract, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject stale report fail count"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("gap_fill_report.summary.fail_count must be 0"),
        "checker output should name report fail_count drift: {combined}"
    );

    Ok(())
}

#[test]
fn checker_rejects_local_cargo_validation_command() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "local-cargo")?;
    let mut manifest = read_manifest(&root)?;
    manifest["completion_debt_evidence"]["validation_commands"][0] =
        serde_json::json!("cargo test -p frankenlibc-harness --test c_fixture_suite_test");
    let stale_contract = out_dir.join("local_cargo_contract.v1.json");
    write_json(&stale_contract, &manifest)?;

    let output = run_checker(&root, &stale_contract, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject local cargo validation command"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("validation_commands must use rch exec"),
        "checker output should name local cargo command: {combined}"
    );

    Ok(())
}
