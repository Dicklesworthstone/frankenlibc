use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

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
        .expect("workspace parent has repo parent")
        .to_path_buf()
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/stub_regression_guard_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_stub_regression_guard_completion_contract.sh")
}

fn load_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let out = root.join("target/conformance").join(format!(
        "stub_regression_guard_completion_contract_{label}_{}_{}",
        std::process::id(),
        stamp
    ));
    std::fs::create_dir_all(&out)?;
    Ok(out)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_STUB_REGRESSION_COMPLETION_CONTRACT", contract)
        .env(
            "FRANKENLIBC_STUB_REGRESSION_COMPLETION_REPORT",
            out_dir.join("stub_regression_guard_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_STUB_REGRESSION_COMPLETION_LOG",
            out_dir.join("stub_regression_guard_completion_contract.log.jsonl"),
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

fn log_records(path: &Path) -> TestResult<Vec<Value>> {
    let body = std::fs::read_to_string(path)?;
    body.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| Ok(serde_json::from_str::<Value>(line)?))
        .collect()
}

#[test]
fn manifest_binds_unit_and_telemetry_items() -> TestResult {
    let root = repo_root();
    let manifest = load_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("stub_regression_guard_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-1p5v"));
    assert_eq!(manifest["completion_debt_bead"].as_str(), Some("bd-1p5v.1"));

    let missing_items: BTreeSet<_> = manifest["missing_item_bindings"]
        .as_array()
        .ok_or("missing_item_bindings must be array")?
        .iter()
        .filter_map(|item| item["id"].as_str())
        .collect();
    assert_eq!(
        missing_items,
        BTreeSet::from(["telemetry.primary", "tests.unit.primary"])
    );

    for binding in manifest["missing_item_bindings"]
        .as_array()
        .ok_or("missing_item_bindings must be array")?
    {
        assert_eq!(binding["next_audit_threshold"].as_u64(), Some(900));
        assert!(
            !binding["implementation_refs"]
                .as_array()
                .ok_or("implementation_refs must be array")?
                .is_empty(),
            "each missing item must cite implementation refs"
        );
        assert!(
            !binding["test_refs"]
                .as_array()
                .ok_or("test_refs must be array")?
                .is_empty(),
            "each missing item must cite test refs"
        );
    }

    let checks: BTreeSet<_> =
        manifest["stub_regression_guard_completion_contract"]["required_guard_checks"]
            .as_array()
            .ok_or("required_guard_checks must be array")?
            .iter()
            .filter_map(|check| check.as_str())
            .collect();
    assert_eq!(
        checks,
        BTreeSet::from([
            "artifact_current",
            "burn_down_thresholds_valid",
            "downgrade_evidence_valid",
            "matrix_stub_policy_valid",
            "stale_waivers_absent",
            "symbol_coverage_valid",
            "waiver_evidence_valid",
            "waiver_schema_valid"
        ])
    );

    Ok(())
}

#[test]
fn manifest_source_anchors_resolve() -> TestResult {
    let root = repo_root();
    let manifest = load_json(&contract_path(&root))?;
    let source_artifacts = manifest["source_artifacts"]
        .as_object()
        .ok_or("source_artifacts must be object")?;

    for (key, rel) in source_artifacts {
        let rel = rel.as_str().ok_or("source artifact path must be string")?;
        assert!(root.join(rel).is_file(), "source artifact {key} missing");
    }

    for (source_key, anchors) in manifest["source_anchors"]
        .as_object()
        .ok_or("source_anchors must be object")?
    {
        let source_path = source_artifacts[source_key]
            .as_str()
            .ok_or("source path must be string")?;
        let source_text = std::fs::read_to_string(root.join(source_path))?;
        for anchor in anchors.as_array().ok_or("anchors must be array")? {
            let anchor = anchor.as_str().ok_or("anchor must be string")?;
            assert!(
                source_text.contains(anchor),
                "{source_key} source is missing anchor: {anchor}"
            );
        }
    }

    Ok(())
}

#[test]
fn checker_emits_completion_report_and_log() -> TestResult {
    let _lock = checker_lock();
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "pass")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report = load_json(&out_dir.join("stub_regression_guard_completion_contract.report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("stub_regression_guard_completion_contract.report.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["failure_signature"].as_str(), Some("none"));
    assert_eq!(report["summary"]["missing_item_count"].as_u64(), Some(2));
    assert_eq!(report["summary"]["guard_check_count"].as_u64(), Some(8));
    assert_eq!(report["summary"]["guard_waiver_count"].as_u64(), Some(0));
    assert_eq!(
        report["summary"]["guard_stale_waiver_count"].as_u64(),
        Some(0)
    );
    assert_eq!(
        report["summary"]["guard_symbol_violations"].as_u64(),
        Some(0)
    );
    assert_eq!(
        report["summary"]["guard_matrix_violations"].as_u64(),
        Some(0)
    );

    let records =
        log_records(&out_dir.join("stub_regression_guard_completion_contract.log.jsonl"))?;
    let events: BTreeSet<_> = records
        .iter()
        .filter_map(|record| record["event"].as_str())
        .collect();
    assert_eq!(
        events,
        BTreeSet::from([
            "stub_regression_guard_completion.telemetry_contract",
            "stub_regression_guard_completion.unit_binding",
            "stub_regression_guard_completion.validated"
        ])
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_guard_check_binding() -> TestResult {
    let _lock = checker_lock();
    let root = repo_root();
    let mut manifest = load_json(&contract_path(&root))?;
    let out_dir = unique_out_dir(&root, "mutated_checks")?;
    let mutated_contract = out_dir.join("mutated_contract.json");

    manifest["stub_regression_guard_completion_contract"]["required_guard_checks"] =
        serde_json::json!([
            "artifact_current",
            "waiver_schema_valid",
            "symbol_coverage_valid",
            "matrix_stub_policy_valid",
            "stale_waivers_absent",
            "waiver_evidence_valid",
            "burn_down_thresholds_valid"
        ]);
    write_json(&mutated_contract, &manifest)?;

    let output = run_checker(&root, &mutated_contract, &out_dir)?;
    assert!(!output.status.success(), "{}", output_text(&output));
    let combined = output_text(&output);
    assert!(
        combined.contains("FAIL[required_guard_checks]"),
        "expected required_guard_checks failure, got {combined}"
    );

    let report = load_json(&out_dir.join("stub_regression_guard_completion_contract.report.json"))?;
    assert_eq!(
        report["failure_signature"].as_str(),
        Some("required_guard_checks")
    );
    let records =
        log_records(&out_dir.join("stub_regression_guard_completion_contract.log.jsonl"))?;
    assert!(records.iter().any(|record| {
        record["event"].as_str() == Some("stub_regression_guard_completion.failed")
    }));

    Ok(())
}
