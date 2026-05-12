//! Contract tests for bd-3tc.1 changepoint drift policy completion evidence.

use serde_json::Value;
use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn test_error(message: impl Into<String>) -> Box<dyn Error> {
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
    root.join("tests/conformance/changepoint_drift_policy_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_changepoint_drift_policy_completion_contract.sh")
}

fn load_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
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
    let path = root.join("target/conformance").join(format!(
        "changepoint-drift-policy-{label}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(root: &Path, manifest: &Path, out_dir: &Path) -> TestResult<Output> {
    Command::new("bash")
        .arg(checker_path(root))
        .env("FRANKENLIBC_CHANGEPOINT_COMPLETION_CONTRACT", manifest)
        .env("FRANKENLIBC_CHANGEPOINT_COMPLETION_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_CHANGEPOINT_COMPLETION_REPORT",
            out_dir.join("report.json"),
        )
        .env(
            "FRANKENLIBC_CHANGEPOINT_COMPLETION_LOG",
            out_dir.join("events.jsonl"),
        )
        .env(
            "FRANKENLIBC_CHANGEPOINT_COMPLETION_GATE_STDOUT",
            out_dir.join("gate_stdout.txt"),
        )
        .env(
            "FRANKENLIBC_CHANGEPOINT_COMPLETION_GATE_STDERR",
            out_dir.join("gate_stderr.txt"),
        )
        .current_dir(root)
        .output()
        .map_err(|err| test_error(format!("failed to run checker: {err}")))
}

fn output_text(output: &Output) -> String {
    format!(
        "status={}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn read_log_events(path: &Path) -> TestResult<BTreeSet<String>> {
    fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let row: Value = serde_json::from_str(line)?;
            row["event"]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| test_error("log row missing event"))
        })
        .collect::<Result<BTreeSet<_>, _>>()
}

fn assert_file_line_ref_exists(root: &Path, value: &str) -> TestResult {
    let (path, line) = value
        .rsplit_once(':')
        .ok_or_else(|| test_error("file line ref should contain ':'"))?;
    let line_no: usize = line.parse()?;
    assert!(line_no > 0, "line ref must be positive");
    let full_path = root.join(path);
    assert!(full_path.is_file(), "file-line ref missing path {value}");
    let text = fs::read_to_string(full_path)?;
    let line_count = text.lines().count();
    assert!(line_no <= line_count, "file-line ref outside file: {value}");
    assert!(
        text.lines()
            .nth(line_no - 1)
            .is_some_and(|line| !line.trim().is_empty()),
        "file-line ref points at blank line: {value}"
    );
    Ok(())
}

#[test]
fn contract_anchors_unit_e2e_and_telemetry_items() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("changepoint_drift_policy_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-3tc"));
    assert_eq!(manifest["completion_debt_bead"].as_str(), Some("bd-3tc.1"));
    assert_eq!(
        string_set(&manifest["completion_debt_evidence"]["missing_items_closed"])?,
        BTreeSet::from([
            "tests.unit.primary".to_string(),
            "tests.e2e.primary".to_string(),
            "telemetry.primary".to_string(),
        ])
    );
    assert!(
        manifest["audit_reference"]["score_threshold"]
            .as_u64()
            .unwrap_or(0)
            >= 800
    );
    for reference in manifest["implementation_refs"]
        .as_array()
        .ok_or_else(|| test_error("implementation refs should be array"))?
    {
        assert_file_line_ref_exists(
            &root,
            reference
                .as_str()
                .ok_or_else(|| test_error("implementation ref should be string"))?,
        )?;
    }
    Ok(())
}

#[test]
fn source_artifacts_bind_existing_changepoint_surfaces() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let sources = manifest["source_artifacts"]
        .as_array()
        .ok_or_else(|| test_error("source artifacts should be array"))?;
    let ids = sources
        .iter()
        .map(|source| {
            source["id"]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| test_error("source id should be string"))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    assert_eq!(
        ids,
        BTreeSet::from([
            "changepoint_module".to_string(),
            "completion_checker".to_string(),
            "completion_harness".to_string(),
            "gate_script".to_string(),
            "harness_test".to_string(),
            "policy_artifact".to_string(),
            "runtime_math_mod".to_string(),
            "statistical_kernel_contract".to_string(),
        ])
    );
    for source in sources {
        let path = source["path"]
            .as_str()
            .ok_or_else(|| test_error("source path should be string"))?;
        let text = fs::read_to_string(root.join(path))?;
        for needle in source["required_needles"]
            .as_array()
            .ok_or_else(|| test_error("required needles should be array"))?
        {
            let needle = needle
                .as_str()
                .ok_or_else(|| test_error("needle should be string"))?;
            assert!(
                text.contains(needle),
                "{path} should contain required needle {needle}"
            );
        }
    }
    Ok(())
}

#[test]
fn unit_contract_binds_bocpd_inline_tests() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let unit = &manifest["unit_primary"];
    assert_eq!(unit["missing_item_id"].as_str(), Some("tests.unit.primary"));
    let inline_tests = string_set(&unit["required_inline_unit_tests"])?;
    assert_eq!(inline_tests.len(), 9);
    let changepoint = fs::read_to_string(
        root.join("crates/frankenlibc-membrane/src/runtime_math/changepoint.rs"),
    )?;
    for test_name in &inline_tests {
        assert!(
            changepoint.contains(&format!("fn {test_name}(")),
            "missing inline test {test_name}"
        );
    }
    let policy = load_json(&root.join("tests/conformance/changepoint_drift_policy.json"))?;
    let expected = unit["required_policy_summary"]
        .as_object()
        .ok_or_else(|| test_error("required_policy_summary should be object"))?;
    for (key, value) in expected {
        assert_eq!(
            policy["summary"][key].as_u64(),
            value.as_u64(),
            "policy summary drifted for {key}"
        );
    }
    Ok(())
}

#[test]
fn e2e_contract_replays_changepoint_gate() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let e2e = &manifest["e2e_primary"];
    assert_eq!(e2e["missing_item_id"].as_str(), Some("tests.e2e.primary"));
    assert_eq!(
        e2e["gate_script"].as_str(),
        Some("scripts/check_changepoint_drift.sh")
    );
    let gate_script = root.join(e2e["gate_script"].as_str().unwrap());
    assert!(gate_script.is_file());
    let gate_output = Command::new("bash")
        .arg(&gate_script)
        .current_dir(&root)
        .output()?;
    assert!(
        gate_output.status.success(),
        "{}",
        output_text(&gate_output)
    );
    let stdout = String::from_utf8_lossy(&gate_output.stdout);
    for needle in string_set(&e2e["required_gate_stdout"])? {
        assert!(
            stdout.contains(&needle),
            "gate stdout should contain {needle}"
        );
    }
    Ok(())
}

#[test]
fn checker_accepts_contract_and_emits_telemetry() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "pass")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("changepoint_drift_policy_completion_contract: PASS"));

    let report = load_json(&out_dir.join("report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("changepoint_drift_policy_completion_contract.report.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-3tc.1"));
    assert_eq!(report["source_count"].as_u64(), Some(8));
    assert_eq!(report["inline_unit_test_count"].as_u64(), Some(9));
    assert_eq!(report["harness_test_count"].as_u64(), Some(3));
    assert_eq!(report["failure_signature"].as_str(), Some("none"));
    assert_eq!(report["policy_summary"]["unit_tests"].as_u64(), Some(9));

    let events = read_log_events(&out_dir.join("events.jsonl"))?;
    assert!(events.contains("changepoint_drift.source_artifacts_validated"));
    assert!(events.contains("changepoint_drift.unit_bindings_validated"));
    assert!(events.contains("changepoint_drift.e2e_gate_replayed"));
    assert!(events.contains("changepoint_drift.telemetry_validated"));
    assert!(events.contains("changepoint_drift.completion_contract_validated"));
    let gate_stdout = fs::read_to_string(out_dir.join("gate_stdout.txt"))?;
    assert!(gate_stdout.contains("check_changepoint_drift: PASS"));
    Ok(())
}

#[test]
fn checker_rejects_missing_unit_test_binding() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let tests = manifest["unit_primary"]["required_inline_unit_tests"]
        .as_array_mut()
        .ok_or_else(|| test_error("required inline tests should be array"))?;
    tests.retain(|test| test.as_str() != Some("change_point_count_increments"));

    let out_dir = unique_output_dir(&root, "missing-unit")?;
    let mutated = out_dir.join("mutated_contract.json");
    write_json(&mutated, &manifest)?;
    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject mutated contract"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("inline unit test count is below minimum")
            || stderr.contains("unit_primary.required_inline_unit_tests"),
        "unexpected stderr: {}",
        output_text(&output)
    );
    Ok(())
}
