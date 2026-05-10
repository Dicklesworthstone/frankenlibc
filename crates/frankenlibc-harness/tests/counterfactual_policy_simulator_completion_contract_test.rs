use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn test_error(message: impl Into<String>) -> Box<dyn std::error::Error> {
    message.into().into()
}

fn workspace_root() -> TestResult<PathBuf> {
    Ok(PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| test_error("cannot resolve workspace root"))?
        .to_path_buf())
}

fn manifest_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/counterfactual_policy_simulator_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_counterfactual_policy_simulator_completion_contract.sh")
}

fn load_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn array_field<'a>(value: &'a Value, field: &str) -> TestResult<&'a Vec<Value>> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| test_error(format!("{field} must be an array")))
}

fn object_field<'a>(
    value: &'a Value,
    field: &str,
) -> TestResult<&'a serde_json::Map<String, Value>> {
    value
        .get(field)
        .and_then(Value::as_object)
        .ok_or_else(|| test_error(format!("{field} must be an object")))
}

fn string_set(value: &Value) -> TestResult<BTreeSet<String>> {
    value
        .as_array()
        .ok_or_else(|| test_error("value should be array"))?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| test_error("array item should be string"))
        })
        .collect::<Result<BTreeSet<_>, _>>()
}

fn unique_output_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| test_error(format!("system time before epoch: {err}")))?
        .as_nanos();
    let dir = root
        .join("target/conformance")
        .join(format!("{label}-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn run_checker(root: &Path, manifest: &Path, out_dir: &Path) -> TestResult<Output> {
    let report = out_dir.join("report.json");
    let log = out_dir.join("events.jsonl");
    Command::new(checker_path(root))
        .env("FRANKENLIBC_COUNTERFACTUAL_POLICY_CONTRACT", manifest)
        .env("FRANKENLIBC_COUNTERFACTUAL_POLICY_OUT_DIR", out_dir)
        .env("FRANKENLIBC_COUNTERFACTUAL_POLICY_REPORT", &report)
        .env("FRANKENLIBC_COUNTERFACTUAL_POLICY_LOG", &log)
        .output()
        .map_err(|err| test_error(format!("failed to run checker: {err}")))
}

#[test]
fn manifest_anchors_completion_debt() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;

    assert_eq!(
        manifest["manifest_id"].as_str(),
        Some("counterfactual-policy-simulator-completion-contract")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-26xb.5"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-26xb.5.1")
    );

    let evidence = object_field(&manifest, "completion_debt_evidence")?;
    assert_eq!(evidence["bead"].as_str(), Some("bd-26xb.5.1"));
    assert_eq!(evidence["original_bead"].as_str(), Some("bd-26xb.5"));
    assert_eq!(
        string_set(&evidence["missing_items_closed"])?,
        BTreeSet::from([
            "tests.e2e.primary".to_string(),
            "tests.unit.primary".to_string(),
        ])
    );
    assert!(
        evidence["next_audit_score_threshold"]
            .as_u64()
            .is_some_and(|threshold| threshold >= 800)
    );

    let artifact_ids: BTreeSet<_> = array_field(&manifest, "source_artifacts")?
        .iter()
        .filter_map(|item| item["artifact_id"].as_str())
        .collect();
    for required in [
        "runtime_evidence_replay_gate",
        "runtime_evidence_replay_checker",
        "runtime_evidence_module",
        "pareto_regret_controller",
        "proof_carrying_policy_audit",
        "policy_table_loader",
    ] {
        assert!(
            artifact_ids.contains(required),
            "missing source artifact {required}"
        );
    }
    Ok(())
}

#[test]
fn policy_cases_cover_safe_and_blocking_promotion() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let policy = object_field(&manifest, "promotion_policy")?;
    assert_eq!(
        policy["default_decision"].as_str(),
        Some("block_until_counterfactual_dossier_passes")
    );
    assert_eq!(policy["strict_repair_allowed"].as_bool(), Some(false));
    assert_eq!(policy["max_risk_regression_ppm"].as_u64(), Some(0));
    assert_eq!(policy["max_regret_ppm"].as_u64(), Some(0));

    let cases = array_field(&manifest, "counterfactual_cases")?;
    let decisions: BTreeSet<_> = cases
        .iter()
        .filter_map(|case| case["expected_promotion_decision"].as_str())
        .collect();
    assert_eq!(
        decisions,
        BTreeSet::from(["block_promotion", "promote_candidate"])
    );

    let failures: BTreeSet<_> = cases
        .iter()
        .filter_map(|case| case["expected_failure_signature"].as_str())
        .collect();
    for required in [
        "none",
        "strict_repair_candidate",
        "risk_regression",
        "latency_regression",
        "regret_budget_exceeded",
    ] {
        assert!(
            failures.contains(required),
            "missing failure coverage {required}"
        );
    }
    assert!(
        cases
            .iter()
            .any(|case| case["mode"].as_str() == Some("strict"))
    );
    assert!(
        cases
            .iter()
            .any(|case| case["mode"].as_str() == Some("hardened"))
    );
    Ok(())
}

#[test]
fn structured_log_fields_bind_acceptance_contract() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let log_contract = object_field(&manifest, "structured_log_contract")?;
    let fields = string_set(&log_contract["required_fields"])?;
    for required in [
        "trace_id",
        "mode",
        "api_family",
        "symbol",
        "decision_path",
        "healing_action",
        "errno",
        "latency_ns",
        "artifact_refs",
        "counterfactual_action",
        "promotion_decision",
        "failure_signature",
    ] {
        assert!(fields.contains(required), "missing log field {required}");
    }
    let events = string_set(&log_contract["required_events"])?;
    assert_eq!(
        events,
        BTreeSet::from([
            "counterfactual_case".to_string(),
            "counterfactual_source".to_string(),
            "counterfactual_summary".to_string(),
            "promotion_decision".to_string(),
        ])
    );
    Ok(())
}

#[test]
fn checker_accepts_manifest_and_emits_logs() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "counterfactual-policy-completion")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    assert!(
        output.status.success(),
        "checker failed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("counterfactual_policy_simulator_completion_contract: PASS"));

    let report = load_json(&out_dir.join("report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["case_count"].as_u64(), Some(6));
    assert_eq!(
        array_field(&report, "case_results")?
            .iter()
            .filter(|case| case["promotion_decision"].as_str() == Some("promote_candidate"))
            .count(),
        2
    );

    let log = fs::read_to_string(out_dir.join("events.jsonl"))?;
    assert!(log.contains("\"event\": \"counterfactual_case\""));
    assert!(log.contains("\"event\": \"promotion_decision\""));
    assert!(log.contains("\"event\": \"counterfactual_summary\""));
    Ok(())
}

#[test]
fn checker_rejects_missing_counterfactual_dossier() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "counterfactual-policy-missing-dossier")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let cases = manifest
        .get_mut("counterfactual_cases")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("counterfactual_cases should be array"))?;
    let first = cases
        .iter_mut()
        .find(|case| case["case_id"].as_str() == Some("strict-string-allow-promotes"))
        .ok_or_else(|| test_error("missing strict-string-allow-promotes"))?;
    first
        .as_object_mut()
        .ok_or_else(|| test_error("case should be object"))?
        .remove("counterfactual");
    let bad_manifest = out_dir.join("bad_contract.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker unexpectedly accepted missing counterfactual dossier"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("missing_counterfactual_dossier"));
    Ok(())
}

#[test]
fn checker_rejects_missing_required_test_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "counterfactual-policy-missing-test")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let tests = manifest
        .get_mut("completion_debt_evidence")
        .and_then(|evidence| evidence.get_mut("unit_primary"))
        .and_then(|unit| unit.get_mut("required_test_names"))
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("required test names should be array"))?;
    tests.push(json!("missing_counterfactual_policy_completion_test"));
    let bad_manifest = out_dir.join("bad_contract.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker unexpectedly accepted missing required test binding"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("missing Rust test"));
    Ok(())
}

#[test]
fn checker_rejects_strict_repair_policy_drift() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "counterfactual-policy-strict-repair")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["promotion_policy"]["strict_repair_allowed"] = Value::Bool(true);
    let bad_manifest = out_dir.join("bad_contract.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker unexpectedly accepted strict repair policy drift"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("strict_repair_allowed must be false"));
    Ok(())
}
