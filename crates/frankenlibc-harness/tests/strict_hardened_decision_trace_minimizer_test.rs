use serde_json::Value;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

struct CheckerRun {
    output: Output,
    report: PathBuf,
    log: PathBuf,
}

fn test_error(message: impl Into<String>) -> Box<dyn Error> {
    std::io::Error::other(message.into()).into()
}

fn ensure(condition: bool, message: impl Into<String>) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(test_error(message))
    }
}

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    Ok(manifest
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| test_error("workspace root"))?
        .to_path_buf())
}

fn unique_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| test_error(format!("system time before UNIX_EPOCH: {err}")))?
        .as_nanos();
    let dir = root
        .join("target")
        .join("test-strict-hardened-decision-trace-minimizer")
        .join(format!("{label}-{stamp}-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn load_json(path: &Path) -> TestResult<Value> {
    let content = std::fs::read_to_string(path)
        .map_err(|err| test_error(format!("{} should be readable: {err}", path.display())))?;
    serde_json::from_str(&content)
        .map_err(|err| test_error(format!("{} should parse as JSON: {err}", path.display())))
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    let content = serde_json::to_string_pretty(value)
        .map_err(|err| test_error(format!("{} serialization failed: {err}", path.display())))?;
    std::fs::write(path, format!("{content}\n"))
        .map_err(|err| test_error(format!("{} write failed: {err}", path.display())))
}

fn string_field<'a>(value: &'a Value, key: &str, context: &str) -> TestResult<&'a str> {
    value
        .get(key)
        .ok_or_else(|| test_error(format!("{context}.{key} is missing")))?
        .as_str()
        .ok_or_else(|| test_error(format!("{context}.{key} must be a string")))
}

fn require_json_field(value: &Value, key: &str, context: &str) -> TestResult {
    ensure(
        value.get(key).is_some(),
        format!("{context}.{key} is missing"),
    )
}

fn same_text(left: &str, right: &str) -> bool {
    left.chars().eq(right.chars())
}

fn trace_cases_mut(manifest: &mut Value) -> TestResult<&mut Vec<Value>> {
    manifest
        .get_mut("trace_cases")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("manifest.trace_cases must be an array"))
}

fn first_case_mut(manifest: &mut Value) -> TestResult<&mut Value> {
    trace_cases_mut(manifest)?
        .first_mut()
        .ok_or_else(|| test_error("manifest.trace_cases must have a first case"))
}

fn first_row_mut(case: &mut Value) -> TestResult<&mut Value> {
    case.get_mut("rows")
        .and_then(Value::as_array_mut)
        .and_then(|rows| rows.first_mut())
        .ok_or_else(|| test_error("trace case must have a first row"))
}

fn row_at_mut(case: &mut Value, index: usize) -> TestResult<&mut Value> {
    case.get_mut("rows")
        .and_then(Value::as_array_mut)
        .and_then(|rows| rows.get_mut(index))
        .ok_or_else(|| test_error(format!("trace case missing row {index}")))
}

fn run_checker(
    root: &Path,
    manifest_override: Option<&Path>,
    label: &str,
) -> TestResult<CheckerRun> {
    run_checker_with_args(root, manifest_override, label, &[])
}

fn run_checker_with_args(
    root: &Path,
    manifest_override: Option<&Path>,
    label: &str,
    extra_args: &[&str],
) -> TestResult<CheckerRun> {
    let out_dir = unique_dir(root, label)?;
    let report = out_dir.join("report.json");
    let log = out_dir.join("log.jsonl");
    let mut command =
        Command::new(root.join("scripts/check_strict_hardened_decision_trace_minimizer.sh"));
    command
        .arg("--validate-only")
        .current_dir(root)
        .env("STRICT_HARDENED_DECISION_TRACE_MINIMIZER_REPORT", &report)
        .env("STRICT_HARDENED_DECISION_TRACE_MINIMIZER_LOG", &log);
    command.args(extra_args);
    if let Some(path) = manifest_override {
        command.env("STRICT_HARDENED_DECISION_TRACE_MINIMIZER_MANIFEST", path);
    }
    let output = command.output().map_err(|err| {
        test_error(format!(
            "failed to run strict/hardened decision trace minimizer checker: {err}"
        ))
    })?;
    Ok(CheckerRun {
        output,
        report,
        log,
    })
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn report(run: &CheckerRun) -> TestResult<Value> {
    load_json(&run.report)
}

fn expect_failure(run: &CheckerRun, signature: &str) -> TestResult {
    ensure(
        !run.output.status.success(),
        format!(
            "checker unexpectedly passed for {signature}\nstdout:\n{}\nstderr:\n{}",
            stdout(&run.output),
            stderr(&run.output)
        ),
    )?;
    ensure(
        stderr(&run.output).contains(&format!("FAIL[{signature}]")),
        format!(
            "stderr should contain failure signature {signature}\nstderr:\n{}",
            stderr(&run.output)
        ),
    )?;
    let report = report(run)?;
    ensure(
        same_text(
            string_field(&report, "failure_signature", "report")?,
            signature,
        ),
        format!("report.failure_signature should be {signature}"),
    )
}

fn mutated_manifest(
    root: &Path,
    label: &str,
    mutate: impl FnOnce(&mut Value) -> TestResult,
) -> TestResult<PathBuf> {
    let mut manifest = load_json(
        &root.join("tests/conformance/strict_hardened_decision_trace_minimizer.v1.json"),
    )?;
    mutate(&mut manifest)?;
    let path = unique_dir(root, label)?.join("manifest.json");
    write_json(&path, &manifest)?;
    Ok(path)
}

fn bundles(report: &Value) -> TestResult<&Vec<Value>> {
    report
        .get("summary")
        .and_then(|summary| summary.get("bundles"))
        .and_then(Value::as_array)
        .ok_or_else(|| test_error("report.summary.bundles must be an array"))
}

#[test]
fn checker_passes_and_emits_minimized_bundles() -> TestResult {
    let root = workspace_root()?;
    let script = root.join("scripts/check_strict_hardened_decision_trace_minimizer.sh");
    ensure(script.exists(), "checker script must exist")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script)?.permissions();
        ensure(
            perms.mode() & 0o111 != 0,
            "checker script must be executable",
        )?;
    }

    let run = run_checker(&root, None, "canonical")?;
    ensure(
        run.output.status.success(),
        format!(
            "checker should pass\nstdout:\n{}\nstderr:\n{}",
            stdout(&run.output),
            stderr(&run.output)
        ),
    )?;
    let report = report(&run)?;
    ensure(
        same_text(string_field(&report, "outcome", "report")?, "pass"),
        "report.outcome should be pass",
    )?;
    let bundles = bundles(&report)?;
    ensure(
        bundles.len() == 2,
        "expected divergence and no-divergence bundles",
    )?;
    let divergent = bundles
        .iter()
        .find(|bundle| {
            bundle
                .get("case_id")
                .and_then(Value::as_str)
                .is_some_and(|case_id| same_text(case_id, "synthetic_strict_hardened_divergence"))
        })
        .ok_or_else(|| test_error("missing divergent bundle"))?;
    let minimized = divergent
        .get("minimized_trace")
        .and_then(Value::as_array)
        .ok_or_else(|| test_error("divergent minimized_trace must be an array"))?;
    ensure(
        minimized.len() == 2,
        "divergent case must keep exactly strict+hardened rows",
    )?;
    let first_key = divergent
        .get("first_divergent_key")
        .and_then(Value::as_object)
        .ok_or_else(|| test_error("divergent first_divergent_key must be an object"))?;
    ensure(
        first_key
            .get("decision_path")
            .and_then(Value::as_str)
            .is_some_and(|value| same_text(value, "validate.pointer.full")),
        "first divergent decision_path should be preserved",
    )?;
    let signature = divergent
        .get("expected_failure_signature")
        .and_then(Value::as_str)
        .ok_or_else(|| test_error("divergent expected_failure_signature must be a string"))?;
    ensure(
        same_text(
            signature,
            "mode_divergence:decision_action,outcome,healing_action",
        ),
        "divergence signature should name changed fields",
    )?;
    let log = std::fs::read_to_string(&run.log)?;
    let log_row: Value = serde_json::from_str(log.trim())?;
    for field in [
        "trace_id",
        "mode",
        "api_family",
        "symbol",
        "decision_path",
        "latency_ns",
        "artifact_refs",
    ] {
        require_json_field(&log_row, field, "log row")?;
    }
    Ok(())
}

#[test]
fn checker_output_is_deterministic_for_identical_input() -> TestResult {
    let root = workspace_root()?;
    let first = run_checker(&root, None, "deterministic-a")?;
    let second = run_checker(&root, None, "deterministic-b")?;
    ensure(
        first.output.status.success(),
        "first checker run should pass",
    )?;
    ensure(
        second.output.status.success(),
        "second checker run should pass",
    )?;
    let first_report = report(&first)?;
    let second_report = report(&second)?;
    ensure(
        bundles(&first_report)? == bundles(&second_report)?,
        "minimized bundles should be deterministic",
    )
}

#[test]
fn no_divergence_control_emits_empty_minimized_trace() -> TestResult {
    let root = workspace_root()?;
    let run = run_checker_with_args(
        &root,
        None,
        "no-divergence",
        &["--case", "synthetic_no_divergence_control"],
    )?;
    ensure(
        run.output.status.success(),
        format!(
            "no-divergence case should pass\nstdout:\n{}\nstderr:\n{}",
            stdout(&run.output),
            stderr(&run.output)
        ),
    )?;
    let report = report(&run)?;
    let bundles = bundles(&report)?;
    ensure(
        bundles.len() == 1,
        "--case no-divergence should emit exactly one bundle",
    )?;
    let bundle = bundles
        .first()
        .ok_or_else(|| test_error("missing no-divergence bundle"))?;
    let minimized = bundle
        .get("minimized_trace")
        .and_then(Value::as_array)
        .ok_or_else(|| test_error("no-divergence minimized_trace must be an array"))?;
    ensure(
        minimized.is_empty(),
        "no-divergence control should emit an empty minimized_trace",
    )?;
    ensure(
        bundle
            .get("expected_failure_signature")
            .and_then(Value::as_str)
            .is_some_and(|value| same_text(value, "no_divergence")),
        "no-divergence control should report the no_divergence signature",
    )
}

#[test]
fn checker_rejects_missing_case_schema_version() -> TestResult {
    let root = workspace_root()?;
    let manifest = mutated_manifest(&root, "missing-case-schema", |manifest| {
        first_case_mut(manifest)?
            .as_object_mut()
            .ok_or_else(|| test_error("first case must be object"))?
            .remove("schema_version");
        Ok(())
    })?;
    let run = run_checker(&root, Some(&manifest), "missing-case-schema")?;
    expect_failure(&run, "missing_string")
}

#[test]
fn checker_rejects_missing_case_artifact_refs() -> TestResult {
    let root = workspace_root()?;
    let manifest = mutated_manifest(&root, "missing-case-artifacts", |manifest| {
        first_case_mut(manifest)?
            .as_object_mut()
            .ok_or_else(|| test_error("first case must be object"))?
            .remove("artifact_refs");
        Ok(())
    })?;
    let run = run_checker(&root, Some(&manifest), "missing-case-artifacts")?;
    expect_failure(&run, "missing_array")
}

#[test]
fn checker_rejects_missing_row_artifact_refs() -> TestResult {
    let root = workspace_root()?;
    let manifest = mutated_manifest(&root, "missing-row-artifacts", |manifest| {
        first_row_mut(first_case_mut(manifest)?)?
            .as_object_mut()
            .ok_or_else(|| test_error("first row must be object"))?
            .insert("artifact_refs".to_owned(), Value::Array(Vec::new()));
        Ok(())
    })?;
    let run = run_checker(&root, Some(&manifest), "missing-row-artifacts")?;
    expect_failure(&run, "missing_row_artifact_refs")
}

#[test]
fn checker_rejects_missing_decision_path() -> TestResult {
    let root = workspace_root()?;
    let manifest = mutated_manifest(&root, "missing-decision-path", |manifest| {
        row_at_mut(first_case_mut(manifest)?, 2)?
            .as_object_mut()
            .ok_or_else(|| test_error("row must be object"))?
            .remove("decision_path");
        Ok(())
    })?;
    let run = run_checker(&root, Some(&manifest), "missing-decision-path")?;
    expect_failure(&run, "missing_required_row_field")
}

#[test]
fn checker_rejects_missing_hardened_pair() -> TestResult {
    let root = workspace_root()?;
    let manifest = mutated_manifest(&root, "missing-mode-pair", |manifest| {
        let rows = first_case_mut(manifest)?
            .get_mut("rows")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| test_error("rows must be array"))?;
        rows.remove(3);
        Ok(())
    })?;
    let run = run_checker(&root, Some(&manifest), "missing-mode-pair")?;
    expect_failure(&run, "missing_mode_pair")
}

#[test]
fn checker_rejects_signature_drift() -> TestResult {
    let root = workspace_root()?;
    let manifest = mutated_manifest(&root, "signature-drift", |manifest| {
        first_case_mut(manifest)?
            .as_object_mut()
            .ok_or_else(|| test_error("first case must be object"))?
            .insert(
                "expected_failure_signature".to_owned(),
                Value::String("mode_divergence:outcome".to_owned()),
            );
        Ok(())
    })?;
    let run = run_checker(&root, Some(&manifest), "signature-drift")?;
    expect_failure(&run, "expected_failure_signature_mismatch")
}
