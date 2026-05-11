use frankenlibc_harness::structured_log::validate_log_line;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

static CHECKER_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn checker_lock() -> MutexGuard<'static, ()> {
    CHECKER_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate directory has workspace parent")
        .parent()
        .expect("workspace parent has repo root")
        .to_path_buf()
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/per_symbol_fixture_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_per_symbol_fixture_completion_contract.sh")
}

fn read_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn read_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    std::fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}

fn string_set(value: &Value) -> BTreeSet<String> {
    value
        .as_array()
        .expect("expected array")
        .iter()
        .map(|item| item.as_str().expect("expected string").to_string())
        .collect()
}

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let path = root.join("target/conformance").join(format!(
        "per-symbol-fixture-completion-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env(
            "FRANKENLIBC_PER_SYMBOL_FIXTURE_COMPLETION_CONTRACT",
            contract,
        )
        .env("FRANKENLIBC_PER_SYMBOL_FIXTURE_COMPLETION_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_PER_SYMBOL_FIXTURE_COMPLETION_REPORT",
            out_dir.join("per_symbol_fixture_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_PER_SYMBOL_FIXTURE_COMPLETION_LOG",
            out_dir.join("per_symbol_fixture_completion_contract.log.jsonl"),
        )
        .env(
            "FRANKENLIBC_PER_SYMBOL_FIXTURE_COMPLETION_GATE_DIR",
            out_dir.join("source-gates"),
        )
        .output()?)
}

fn output_text(output: &Output) -> String {
    format!(
        "status={}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn assert_checker_failed(output: &Output) {
    assert!(
        !output.status.success(),
        "checker unexpectedly passed:\n{}",
        output_text(output)
    );
}

fn source_text(root: &Path, path: &str) -> TestResult<String> {
    Ok(std::fs::read_to_string(root.join(path))?)
}

#[test]
fn manifest_binds_unit_golden_and_conformance_items() -> TestResult {
    let root = repo_root();
    let manifest = read_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("per_symbol_fixture_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-ldj.5"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-ldj.5.1")
    );

    for path in manifest["source_artifacts"]
        .as_object()
        .expect("source_artifacts object")
        .values()
    {
        let rel = path.as_str().expect("source artifact path string");
        assert!(root.join(rel).exists(), "source artifact missing: {rel}");
    }

    let binding_ids: BTreeSet<_> = manifest["completion_debt_evidence"]["missing_item_bindings"]
        .as_array()
        .expect("missing item bindings array")
        .iter()
        .map(|item| item["id"].as_str().expect("binding id").to_string())
        .collect();
    assert_eq!(
        binding_ids,
        BTreeSet::from([
            "tests.unit.primary".to_string(),
            "tests.golden.primary".to_string(),
            "tests.conformance.primary".to_string(),
        ])
    );

    let contract = &manifest["completion_debt_evidence"]["required_per_symbol_contract"];
    assert_eq!(
        contract["minimum_total_exported_symbols"].as_u64(),
        Some(4000)
    );
    assert_eq!(contract["minimum_fixture_json_cases"].as_u64(), Some(1284));
    assert_eq!(
        contract["minimum_expected_errno_required_cases"].as_u64(),
        Some(1242)
    );
    assert_eq!(
        string_set(&contract["required_source_gates"]),
        BTreeSet::from([
            "scripts/check_symbol_fixture_coverage.sh".to_string(),
            "scripts/check_fixture_schema_validation.sh --validate-only".to_string(),
            "scripts/check_golden_fixture_protocol_completion_contract.sh".to_string(),
        ])
    );

    let test_sources = manifest["completion_debt_evidence"]["test_sources"]
        .as_object()
        .expect("test_sources object");
    for source in test_sources.values() {
        let path = source["path"].as_str().expect("test path");
        let text = source_text(&root, path)?;
        for test_ref in source["required_test_refs"]
            .as_array()
            .expect("test refs array")
        {
            let test_name = test_ref.as_str().expect("test name");
            assert!(
                text.contains(&format!("fn {test_name}")),
                "{path} missing required test {test_name}"
            );
        }
    }

    Ok(())
}

#[test]
fn checker_runs_source_gates_and_emits_completion_evidence() -> TestResult {
    let _guard = checker_lock();
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "valid")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report = read_json(&out_dir.join("per_symbol_fixture_completion_contract.report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("per_symbol_fixture_completion_contract.report.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["source_bead"].as_str(), Some("bd-ldj.5"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-ldj.5.1"));
    assert_eq!(
        report["summary"]["covered_exported_symbols"].as_u64(),
        Some(405)
    );
    assert_eq!(report["summary"]["fixture_json_cases"].as_u64(), Some(1284));
    assert_eq!(
        report["summary"]["expected_errno_required_cases"].as_u64(),
        Some(1242)
    );
    for gate in [
        "symbol_fixture_coverage",
        "fixture_schema_validation",
        "golden_fixture_protocol_completion",
    ] {
        assert_eq!(
            report["source_gate_results"][gate]["exit_code"].as_i64(),
            Some(0),
            "source gate {gate} should pass"
        );
    }
    assert!(report["errors"].as_array().unwrap().is_empty());

    Ok(())
}

#[test]
fn completion_logs_validate_against_structured_schema() -> TestResult {
    let _guard = checker_lock();
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "logs")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let rows = read_jsonl(&out_dir.join("per_symbol_fixture_completion_contract.log.jsonl"))?;
    let events: BTreeSet<_> = rows
        .iter()
        .map(|row| row["event"].as_str().unwrap().to_string())
        .collect();
    for required in [
        "per_symbol_fixture_completion_summary",
        "per_symbol_fixture_unit_bindings",
        "per_symbol_fixture_golden_bindings",
        "per_symbol_fixture_conformance_bindings",
        "per_symbol_fixture_completion_contract_pass",
    ] {
        assert!(events.contains(required), "missing event {required}");
    }
    assert!(
        !events.contains("per_symbol_fixture_completion_contract_fail"),
        "pass log must not contain fail event"
    );

    let log_text =
        std::fs::read_to_string(out_dir.join("per_symbol_fixture_completion_contract.log.jsonl"))?;
    for (index, line) in log_text.lines().enumerate() {
        validate_log_line(line, index + 1)
            .map_err(|errors| format!("structured log validation failed: {errors:?}"))?;
    }

    Ok(())
}

#[test]
fn checker_rejects_missing_golden_binding() -> TestResult {
    let _guard = checker_lock();
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "missing-golden")?;
    let mut manifest = read_json(&contract_path(&root))?;
    let bindings = manifest["completion_debt_evidence"]["missing_item_bindings"]
        .as_array_mut()
        .expect("bindings array");
    bindings.retain(|item| item["id"].as_str() != Some("tests.golden.primary"));
    let mutated = out_dir.join("missing_golden_contract.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report = read_json(&out_dir.join("per_symbol_fixture_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .to_string()
            .contains("tests.golden.primary"),
        "report should cite missing golden binding: {report}"
    );

    Ok(())
}

#[test]
fn checker_rejects_understated_fixture_inventory() -> TestResult {
    let _guard = checker_lock();
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "inventory")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["required_per_symbol_contract"]["minimum_fixture_json_cases"] =
        json!(9_999_999);
    let mutated = out_dir.join("understated_inventory_contract.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report = read_json(&out_dir.join("per_symbol_fixture_completion_contract.report.json"))?;
    assert!(
        report["errors"]
            .to_string()
            .contains("fixture_json_cases is below contract minimum"),
        "report should cite fixture inventory drift: {report}"
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_source_test_ref() -> TestResult {
    let _guard = checker_lock();
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "missing-test")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["test_sources"]["completion_harness"]
        ["required_test_refs"]
        .as_array_mut()
        .expect("completion harness refs array")
        .push(json!("not_a_real_test_name"));
    let mutated = out_dir.join("missing_test_ref_contract.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert_checker_failed(&output);
    let report = read_json(&out_dir.join("per_symbol_fixture_completion_contract.report.json"))?;
    assert!(
        report["errors"]
            .to_string()
            .contains("not_a_real_test_name"),
        "report should cite missing test ref: {report}"
    );

    Ok(())
}
