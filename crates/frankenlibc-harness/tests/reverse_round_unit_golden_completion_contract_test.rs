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
    root.join("tests/conformance/reverse_round_unit_golden_completion_contract.v1.json")
}

fn reverse_report_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/reverse_round_contracts.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_reverse_round_unit_golden_completion_contract.sh")
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
    Command::new(checker_path(root))
        .env("FRANKENLIBC_REVERSE_ROUND_UNIT_GOLDEN_CONTRACT", manifest)
        .env("FRANKENLIBC_REVERSE_ROUND_UNIT_GOLDEN_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_REVERSE_ROUND_UNIT_GOLDEN_REPORT",
            out_dir.join("report.json"),
        )
        .env(
            "FRANKENLIBC_REVERSE_ROUND_UNIT_GOLDEN_LOG",
            out_dir.join("events.jsonl"),
        )
        .output()
        .map_err(|err| test_error(format!("failed to run checker: {err}")))
}

#[test]
fn manifest_anchors_completion_debt() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    assert_eq!(
        manifest["manifest_id"].as_str(),
        Some("reverse-round-unit-golden-completion-contract")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-2a2.4"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-2a2.4.1")
    );

    let evidence = object_field(&manifest, "completion_debt_evidence")?;
    assert_eq!(
        string_set(&evidence["missing_items_closed"])?,
        BTreeSet::from([
            "tests.golden.primary".to_string(),
            "tests.unit.primary".to_string(),
        ])
    );
    assert!(
        evidence["next_audit_score_threshold"]
            .as_u64()
            .is_some_and(|threshold| threshold >= 800)
    );
    Ok(())
}

#[test]
fn round_scope_binds_r7_r11_unit_contracts() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let reverse_report = load_json(&reverse_report_path(&root))?;
    let scope = object_field(&manifest, "round_scope")?;
    let required_rounds: Vec<_> = array_field(&manifest["round_scope"], "required_rounds")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(required_rounds, vec!["R7", "R8", "R9", "R10", "R11"]);

    let min_families = scope["minimum_math_families_per_round"]
        .as_u64()
        .ok_or_else(|| test_error("minimum_math_families_per_round missing"))?;
    let min_classes = scope["minimum_math_classes_per_round"]
        .as_u64()
        .ok_or_else(|| test_error("minimum_math_classes_per_round missing"))?;
    for round_id in required_rounds {
        let round = &reverse_report["round_results"][round_id];
        assert!(
            round["math_families"]
                .as_object()
                .is_some_and(|families| families.len() as u64 >= min_families),
            "{round_id}: math family coverage drifted"
        );
        assert!(
            round["branch_diversity"]["class_count"]
                .as_u64()
                .is_some_and(|count| count >= min_classes),
            "{round_id}: math class coverage drifted"
        );
        assert!(
            round["implementation_plan"]
                .as_array()
                .is_some_and(|items| !items.is_empty()),
            "{round_id}: implementation plan missing"
        );
        assert!(
            round["verification_strategy"]
                .as_array()
                .is_some_and(|items| !items.is_empty()),
            "{round_id}: verification strategy missing"
        );
    }
    Ok(())
}

#[test]
fn golden_snapshot_matches_checked_in_reverse_round_output() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let reverse_report = load_json(&reverse_report_path(&root))?;
    let golden = object_field(&manifest, "golden_expectations")?;
    assert_eq!(reverse_report["report_hash"], golden["report_hash"]);
    assert_eq!(
        reverse_report["golden_output"]["hash"],
        golden["report_hash"]
    );
    assert!(
        golden["round_hashes"].is_object(),
        "round_hashes must be an object"
    );
    for round_id in ["R7", "R8", "R9", "R10", "R11"] {
        assert_eq!(
            reverse_report["golden_output"]["round_hashes"][round_id],
            golden["round_hashes"][round_id],
            "{round_id}: golden hash drifted"
        );
    }
    assert!(golden["summary"].is_object(), "summary must be an object");
    for field in [
        "rounds_verified",
        "total_math_families",
        "modules_missing",
        "invariants_total",
        "invariants_specified",
        "math_class_count",
        "all_rounds_diverse",
    ] {
        assert_eq!(
            reverse_report["summary"][field], golden["summary"][field],
            "golden summary drift for {field}"
        );
    }
    Ok(())
}

#[test]
fn checker_accepts_manifest_and_emits_report() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "reverse-round-unit-golden")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    assert!(
        output.status.success(),
        "checker failed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("reverse_round_unit_golden_completion_contract: PASS"));

    let report = load_json(&out_dir.join("report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["rounds"].as_array().map(Vec::len), Some(5));
    let log = fs::read_to_string(out_dir.join("events.jsonl"))?;
    assert!(log.contains("\"event\": \"reverse_round_unit_round\""));
    assert!(log.contains("\"event\": \"reverse_round_golden_check\""));
    assert!(log.contains("\"event\": \"reverse_round_unit_summary\""));
    Ok(())
}

#[test]
fn checker_rejects_missing_required_round() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "reverse-round-missing-round")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let rounds = manifest
        .get_mut("round_scope")
        .and_then(|scope| scope.get_mut("required_rounds"))
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("required rounds should be array"))?;
    rounds.retain(|round| round.as_str() != Some("R11"));
    let bad_manifest = out_dir.join("bad_contract.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker unexpectedly accepted missing required round"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("required_rounds must be exactly R7-R11"));
    Ok(())
}

#[test]
fn checker_rejects_golden_hash_drift() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "reverse-round-golden-drift")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["golden_expectations"]["round_hashes"]["R9"] = json!("000000000000");
    let bad_manifest = out_dir.join("bad_contract.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker unexpectedly accepted golden hash drift"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("golden round hash drift for R9"));
    Ok(())
}

#[test]
fn checker_rejects_missing_required_test_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "reverse-round-missing-test")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let tests = manifest
        .get_mut("completion_debt_evidence")
        .and_then(|evidence| evidence.get_mut("unit_primary"))
        .and_then(|unit| unit.get_mut("required_test_names"))
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("unit required tests should be array"))?;
    tests.push(json!("missing_reverse_round_completion_test"));
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
