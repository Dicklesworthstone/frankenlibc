//! Contract tests for bd-66wz.3.1 pointer-validation adversarial completion evidence.

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
    let path =
        root.join("tests/conformance/pointer_validation_adversarial_completion_contract.v1.json");
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
        "pointer-validation-adversarial-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<std::process::Output> {
    Ok(Command::new("bash")
        .arg(root.join("scripts/check_pointer_validation_adversarial_completion_contract.sh"))
        .current_dir(root)
        .env(
            "FRANKENLIBC_POINTER_VALIDATION_ADVERSARIAL_CONTRACT",
            contract,
        )
        .env(
            "FRANKENLIBC_POINTER_VALIDATION_ADVERSARIAL_REPORT",
            out_dir.join("pointer_validation_adversarial_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_POINTER_VALIDATION_ADVERSARIAL_LOG",
            out_dir.join("pointer_validation_adversarial_completion_contract.log.jsonl"),
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
fn manifest_binds_pointer_adversarial_unit_evidence() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_manifest(&root)?;
    assert_eq!(manifest["bead"].as_str(), Some("bd-66wz.3"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-66wz.3.1")
    );
    assert!(
        manifest["audit"]["missing_item_ids"]
            .as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing item array"))?
            .iter()
            .any(|item| item.as_str() == Some("tests.unit.primary")),
        "audit evidence should bind the missing unit test item"
    );

    let evidence = &manifest["completion_debt_evidence"];
    assert_eq!(evidence["bead"].as_str(), Some("bd-66wz.3.1"));
    assert_eq!(evidence["original_bead"].as_str(), Some("bd-66wz.3"));
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

    let ptr_source_path = evidence["test_sources"]["ptr_validator_unit"]
        .as_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "ptr source path"))?;
    let ptr_source = std::fs::read_to_string(root.join(ptr_source_path))?;
    let cases = evidence["adversarial_cases"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "cases array"))?;
    let case_ids = cases
        .iter()
        .map(|case| {
            case["id"]
                .as_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "case id"))
                .map(str::to_owned)
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    for case_id in [
        "foreign_validate_unknown_unbounded",
        "foreign_free_reported",
        "double_free_reported",
        "uaf_cache_invalidated_after_free",
        "canary_corruption_free_quarantines",
        "foreign_early_exit_skips_deep_integrity",
    ] {
        assert!(case_ids.contains(case_id), "missing case {case_id}");
    }
    assert_eq!(case_ids.len(), 6, "case set should be exact");

    for case in cases {
        let test_name = case["test"]
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "test name"))?;
        assert!(
            ptr_source.contains(&format!("fn {test_name}")),
            "case references missing ptr_validator test {test_name}"
        );
        for token in case["required_tokens"]
            .as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "required tokens array"))?
        {
            let token = token
                .as_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "required token"))?;
            assert!(
                ptr_source.contains(token),
                "ptr_validator source should contain required token {token}"
            );
        }
    }

    let unit = &evidence["unit_primary"];
    assert_eq!(unit["missing_item_id"].as_str(), Some("tests.unit.primary"));
    let commands = string_set(&unit["validation_commands"])?;
    assert!(
        commands
            .iter()
            .all(|command| command.starts_with("rch exec -- ")),
        "validation commands should be RCH-backed"
    );
    assert!(
        commands
            .iter()
            .any(|command| command.contains("frankenlibc-membrane")
                && command.contains("ptr_validator")),
        "manifest should require the ptr_validator unit lane"
    );
    assert!(
        commands
            .iter()
            .any(|command| command.contains("frankenlibc-harness")
                && command.contains("pointer_validation_adversarial_completion_contract_test")),
        "manifest should require this contract harness lane"
    );

    Ok(())
}

#[test]
fn checker_emits_report_and_jsonl() -> TestResult {
    let root = workspace_root()?;
    let contract =
        root.join("tests/conformance/pointer_validation_adversarial_completion_contract.v1.json");
    let out_dir = unique_output_dir(&root, "pass")?;
    let output = run_checker(&root, &contract, &out_dir)?;
    assert!(
        output.status.success(),
        "checker failed stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report =
        read_json(&out_dir.join("pointer_validation_adversarial_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-66wz.3.1"));
    assert_eq!(report["original_bead"].as_str(), Some("bd-66wz.3"));
    assert_eq!(string_set(&report["adversarial_case_ids"])?.len(), 6);
    assert!(
        report["test_refs"]
            .as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "test refs array"))?
            .iter()
            .any(|item| item.as_str()
                == Some("ptr_validator_unit::canary_corruption_detected_via_pipeline_free")),
        "report should include canary adversarial unit test ref"
    );

    let rows =
        read_jsonl(&out_dir.join("pointer_validation_adversarial_completion_contract.log.jsonl"))?;
    assert_eq!(rows.len(), 1, "checker should emit one telemetry row");
    let row = &rows[0];
    assert!(json_str_field_is(
        row,
        "event",
        "pointer_validation_adversarial_completion_contract_validated"
    ));
    assert!(json_str_field_is(
        row,
        "completion_debt_bead",
        "bd-66wz.3.1"
    ));
    assert!(json_str_field_is(
        row,
        "missing_item_id",
        "tests.unit.primary"
    ));
    assert!(json_str_field_is(row, "status", "pass"));
    assert!(json_str_field_is(row, "failure_signature", "none"));
    assert_eq!(string_set(&row["adversarial_case_ids"])?.len(), 6);

    Ok(())
}

#[test]
fn checker_rejects_missing_adversarial_case() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-case")?;
    let mut manifest = read_manifest(&root)?;
    let cases = manifest["completion_debt_evidence"]["adversarial_cases"]
        .as_array_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "cases array"))?;
    cases.retain(|case| case["id"].as_str() != Some("canary_corruption_free_quarantines"));
    let stale_contract = out_dir.join("missing_pointer_case_contract.v1.json");
    write_json(&stale_contract, &manifest)?;

    let output = run_checker(&root, &stale_contract, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing adversarial case"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("adversarial_cases missing canary_corruption_free_quarantines"),
        "checker output should name missing case: {combined}"
    );

    let report =
        read_json(&out_dir.join("pointer_validation_adversarial_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    let rows =
        read_jsonl(&out_dir.join("pointer_validation_adversarial_completion_contract.log.jsonl"))?;
    assert_eq!(rows.len(), 1);
    assert!(json_str_field_is(
        &rows[0],
        "event",
        "pointer_validation_adversarial_completion_contract_failed"
    ));

    Ok(())
}

#[test]
fn checker_rejects_local_cargo_validation_command() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "local-cargo")?;
    let mut manifest = read_manifest(&root)?;
    manifest["completion_debt_evidence"]["unit_primary"]["validation_commands"][0] = serde_json::json!(
        "cargo test --locked -p frankenlibc-membrane ptr_validator --lib -- --nocapture"
    );
    let stale_contract = out_dir.join("local_cargo_pointer_contract.v1.json");
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
        combined.contains("unit_primary.validation_commands must use rch exec"),
        "checker output should name local cargo command: {combined}"
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_required_case_token() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-token")?;
    let mut manifest = read_manifest(&root)?;
    let cases = manifest["completion_debt_evidence"]["adversarial_cases"]
        .as_array_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "cases array"))?;
    let foreign_case = cases
        .iter_mut()
        .find(|case| case["id"].as_str() == Some("foreign_validate_unknown_unbounded"))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "foreign case"))?;
    foreign_case["required_tokens"] = serde_json::json!(["ValidationOutcome::Foreign"]);
    let stale_contract = out_dir.join("missing_token_pointer_contract.v1.json");
    write_json(&stale_contract, &manifest)?;

    let output = run_checker(&root, &stale_contract, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject incomplete token binding"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains(
            "adversarial_cases.foreign_validate_unknown_unbounded.required_tokens missing"
        ),
        "checker output should name missing token binding: {combined}"
    );

    Ok(())
}
