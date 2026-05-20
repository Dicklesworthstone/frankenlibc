use serde_json::Value;
use std::collections::BTreeSet;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn test_error(message: impl Into<String>) -> Box<dyn Error> {
    std::io::Error::other(message.into()).into()
}

fn workspace_root() -> TestResult<PathBuf> {
    Ok(Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| test_error("crate manifest should have crates parent"))?
        .parent()
        .ok_or_else(|| test_error("crates directory should have workspace parent"))?
        .to_path_buf())
}

fn artifact_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/condvar_perf_validation.v1.json")
}

fn proof_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/proofs/condvar-nochange-v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_condvar_perf_validation.sh")
}

fn report_path(out_dir: &Path) -> PathBuf {
    out_dir.join("condvar_perf_validation.report.json")
}

fn log_path(out_dir: &Path) -> PathBuf {
    out_dir.join("condvar_perf_validation.log.jsonl")
}

fn load_json(path: &Path) -> TestResult<Value> {
    let content = std::fs::read_to_string(path)
        .map_err(|err| test_error(format!("{} should be readable: {err}", path.display())))?;
    serde_json::from_str(&content)
        .map_err(|err| test_error(format!("{} should parse as JSON: {err}", path.display())))
}

fn load_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    std::fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str(line).map_err(|err| {
                test_error(format!("invalid JSONL row in {}: {err}", path.display()))
            })
        })
        .collect()
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    std::fs::write(path, format!("{}\n", serde_json::to_string_pretty(value)?))?;
    Ok(())
}

fn unique_output_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| test_error(format!("system clock should be after Unix epoch: {err}")))?
        .as_nanos();
    let path = root.join("target/conformance").join(format!(
        "condvar_perf_validation_{label}_{}_{}",
        std::process::id(),
        stamp
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn string_field<'a>(value: &'a Value, key: &str, context: &str) -> TestResult<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| test_error(format!("{context}.{key} must be a string")))
}

fn bool_field(value: &Value, key: &str, context: &str) -> TestResult<bool> {
    value
        .get(key)
        .and_then(Value::as_bool)
        .ok_or_else(|| test_error(format!("{context}.{key} must be a bool")))
}

fn u64_field(value: &Value, key: &str, context: &str) -> TestResult<u64> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| test_error(format!("{context}.{key} must be an unsigned integer")))
}

fn f64_field(value: &Value, key: &str, context: &str) -> TestResult<f64> {
    value
        .get(key)
        .and_then(Value::as_f64)
        .ok_or_else(|| test_error(format!("{context}.{key} must be numeric")))
}

fn array_field<'a>(value: &'a Value, key: &str, context: &str) -> TestResult<&'a Vec<Value>> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| test_error(format!("{context}.{key} must be an array")))
}

fn run_checker(root: &Path, artifact: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .arg("--validate-only")
        .current_dir(root)
        .env("FRANKENLIBC_CONDVAR_PERF_ARTIFACT_PATH", artifact)
        .env("FRANKENLIBC_CONDVAR_PERF_REPORT", report_path(out_dir))
        .env("FRANKENLIBC_CONDVAR_PERF_LOG", log_path(out_dir))
        .env("FRANKENLIBC_CONDVAR_PERF_TRACE_ID", "bd-sshi7::test")
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

fn expect_checker_success(output: &Output) -> TestResult {
    if output.status.success() {
        return Ok(());
    }
    Err(test_error(format!(
        "checker failed: {}",
        output_text(output)
    )))
}

fn expect_checker_failure(output: &Output) -> TestResult {
    if !output.status.success() {
        return Ok(());
    }
    Err(test_error(format!(
        "checker unexpectedly passed: {}",
        output_text(output)
    )))
}

#[test]
fn contract_binds_condvar_perf_budget_and_nochange_proof() -> TestResult {
    let root = workspace_root()?;
    let artifact = load_json(&artifact_path(&root))?;
    assert_eq!(string_field(&artifact, "version", "artifact")?, "v1");
    assert!(
        checker_path(&root).is_file(),
        "missing condvar perf checker"
    );
    assert!(
        proof_path(&root).is_file(),
        "missing condvar no-change proof"
    );

    let baselines = array_field(&artifact, "baselines", "artifact")?;
    assert_eq!(baselines.len(), 6);
    let names = baselines
        .iter()
        .map(|row| string_field(row, "name", "baseline"))
        .collect::<Result<BTreeSet<_>, _>>()?;
    assert_eq!(
        names,
        BTreeSet::from([
            "broadcast_4_waiters",
            "broadcast_no_waiters",
            "init_destroy",
            "signal_no_waiters",
            "timedwait_past_deadline",
            "wait_signal_roundtrip",
        ])
    );
    for baseline in baselines {
        let name = string_field(baseline, "name", "baseline")?;
        assert!(
            bool_field(baseline, "within_budget", name)?,
            "{name} should stay within the recorded perf budget"
        );
        assert!(
            f64_field(baseline, "p95_ns", name)? <= f64_field(baseline, "budget_ns", name)?,
            "{name} p95 must not exceed budget"
        );
    }

    let opportunity = array_field(&artifact, "opportunity_matrix", "artifact")?;
    assert_eq!(opportunity.len(), 6);
    let max_score = opportunity
        .iter()
        .map(|row| f64_field(row, "optimization_score", "opportunity"))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .fold(0.0, f64::max);
    assert_eq!(max_score, 1.5);

    let decision = artifact
        .get("optimization_decision")
        .ok_or_else(|| test_error("optimization_decision missing"))?;
    assert_eq!(
        string_field(decision, "selected", "optimization_decision")?,
        "none"
    );
    assert_eq!(
        f64_field(decision, "threshold", "optimization_decision")?,
        2.0
    );
    assert!(
        f64_field(decision, "max_opportunity_score", "optimization_decision")?
            < f64_field(decision, "threshold", "optimization_decision")?
    );

    let regression = artifact
        .get("regression_verification")
        .ok_or_else(|| test_error("regression_verification missing"))?;
    assert!(bool_field(
        regression,
        "all_condvar_tests_pass",
        "regression_verification"
    )?);
    assert_eq!(
        u64_field(regression, "test_count", "regression_verification")?,
        68
    );

    Ok(())
}

#[test]
fn checker_emits_isolated_pass_report_and_jsonl() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "pass")?;
    let output = run_checker(&root, &artifact_path(&root), &out_dir)?;
    expect_checker_success(&output)?;

    let report = load_json(&report_path(&out_dir))?;
    assert_eq!(
        string_field(&report, "report_schema", "report")?,
        "condvar_perf_validation.report.v1"
    );
    assert_eq!(string_field(&report, "bead", "report")?, "bd-2nzx");
    assert_eq!(
        string_field(&report, "gate", "report")?,
        "condvar_perf_validation"
    );
    assert_eq!(string_field(&report, "mode", "report")?, "validate-only");
    assert_eq!(string_field(&report, "outcome", "report")?, "pass");
    assert!(bool_field(&report, "pass", "report")?);
    assert_eq!(
        string_field(&report, "failure_signature", "report")?,
        "none"
    );
    assert_eq!(u64_field(&report, "baselines_total", "report")?, 6);
    assert_eq!(u64_field(&report, "baselines_within_budget", "report")?, 6);
    assert_eq!(u64_field(&report, "opportunity_entries", "report")?, 6);
    assert_eq!(f64_field(&report, "max_opportunity_score", "report")?, 1.5);
    assert_eq!(f64_field(&report, "optimization_threshold", "report")?, 2.0);
    assert_eq!(
        string_field(&report, "optimization_selected", "report")?,
        "none"
    );
    assert!(array_field(&report, "errors", "report")?.is_empty());

    let events = load_jsonl(&log_path(&out_dir))?;
    assert_eq!(events.len(), 1);
    assert_eq!(
        string_field(&events[0], "gate", "log")?,
        "condvar_perf_validation"
    );
    assert_eq!(string_field(&events[0], "mode", "log")?, "validate-only");
    assert_eq!(string_field(&events[0], "result", "log")?, "PASS");
    assert_eq!(string_field(&events[0], "outcome", "log")?, "pass");

    Ok(())
}

#[test]
fn checker_rejects_budget_regression_fixture() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "budget_regression")?;
    let mut artifact = load_json(&artifact_path(&root))?;
    let first_baseline = artifact["baselines"][0]
        .as_object_mut()
        .ok_or_else(|| test_error("first baseline should be an object"))?;
    first_baseline.insert("within_budget".into(), Value::Bool(false));
    first_baseline.insert("p95_ns".into(), Value::from(5000.0));
    first_baseline.insert("budget_ns".into(), Value::from(50.0));
    let mutated = out_dir.join("condvar_perf_validation.budget_regression.json");
    write_json(&mutated, &artifact)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    expect_checker_failure(&output)?;

    let report = load_json(&report_path(&out_dir))?;
    assert_eq!(string_field(&report, "outcome", "report")?, "fail");
    assert!(!bool_field(&report, "pass", "report")?);
    assert_eq!(
        string_field(&report, "failure_signature", "report")?,
        "Baseline init_destroy"
    );
    assert!(
        array_field(&report, "errors", "report")?
            .iter()
            .any(|err| err
                .as_str()
                .is_some_and(|text| text.contains("exceeds budget"))),
        "budget regression should be visible in report errors"
    );

    let events = load_jsonl(&log_path(&out_dir))?;
    assert_eq!(events.len(), 1);
    assert_eq!(string_field(&events[0], "result", "log")?, "FAIL");
    assert_eq!(string_field(&events[0], "outcome", "log")?, "fail");

    Ok(())
}
