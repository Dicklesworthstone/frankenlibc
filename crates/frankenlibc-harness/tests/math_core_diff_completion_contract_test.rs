//! Contract tests for bd-xrmnr.1 math core diff completion evidence.

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
    root.join("tests/conformance/math_core_diff_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_math_core_diff_completion_contract.sh")
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
        "math-core-diff-{label}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(root: &Path, manifest: &Path, out_dir: &Path) -> TestResult<Output> {
    Command::new("bash")
        .arg(checker_path(root))
        .env("FRANKENLIBC_MATH_CORE_DIFF_COMPLETION_CONTRACT", manifest)
        .env("FRANKENLIBC_MATH_CORE_DIFF_COMPLETION_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_MATH_CORE_DIFF_COMPLETION_REPORT",
            out_dir.join("report.json"),
        )
        .env(
            "FRANKENLIBC_MATH_CORE_DIFF_COMPLETION_LOG",
            out_dir.join("events.jsonl"),
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

fn set_required_command(manifest: &mut Value, expected: &str, replacement: &str) -> TestResult {
    let commands = manifest["conformance_binding"]["required_commands"]
        .as_array_mut()
        .ok_or_else(|| test_error("required commands should be array"))?;
    let mut replaced = false;
    for command in commands {
        if command.as_str() == Some(expected) {
            *command = Value::String(replacement.to_string());
            replaced = true;
        }
    }
    assert!(replaced, "expected command was not present: {expected}");
    Ok(())
}

fn assert_file_line_ref_exists(root: &Path, value: &str) -> TestResult {
    let (path, line) = value
        .rsplit_once(':')
        .ok_or_else(|| test_error("file line ref should contain ':'"))?;
    let line_no: usize = line.parse()?;
    assert!(line_no > 0, "line ref must be positive");
    let full_path = root.join(path);
    assert!(full_path.is_file(), "file-line ref missing path {value}");
    let line_count = fs::read_to_string(full_path)?.lines().count();
    assert!(line_no <= line_count, "file-line ref outside file: {value}");
    Ok(())
}

const ABI_MATH_DIFF_COMMAND: &str = "RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_frankenlibc_math_core_diff_abi cargo test -p frankenlibc-abi --test conformance_diff_math -- --nocapture";
const HARNESS_TEST_COMMAND: &str = "RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_frankenlibc_math_core_diff_harness cargo test -p frankenlibc-harness --test math_core_diff_completion_contract_test -- --nocapture";
const HARNESS_CLIPPY_COMMAND: &str = "RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_frankenlibc_math_core_diff_clippy cargo clippy -p frankenlibc-harness --test math_core_diff_completion_contract_test -- -D warnings";

#[test]
fn contract_binds_math_core_diff_completion_debt() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("math_core_diff_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-xrmnr"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-xrmnr.1")
    );
    assert_eq!(
        string_set(&manifest["completion_debt_evidence"]["missing_items_closed"])?,
        BTreeSet::from([
            "telemetry.primary".to_string(),
            "tests.conformance.primary".to_string(),
        ])
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
fn source_artifacts_bind_math_core_diff_surfaces() -> TestResult {
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
            "completion_checker".to_string(),
            "completion_contract".to_string(),
            "completion_harness".to_string(),
            "core_math_exports".to_string(),
            "math_abi".to_string(),
            "math_diff_harness".to_string(),
        ])
    );
    let diff_tests = string_set(&manifest["conformance_binding"]["required_test_names"])?;
    for expected in [
        "diff_sqrt_exact",
        "diff_fabs_exact",
        "diff_floor_ceil_exact",
        "diff_fmod_exact",
        "diff_sin_cos_tan_within_4_ulps",
        "diff_atan2_within_4_ulps",
        "diff_exp_log_pow_within_4_ulps",
        "diff_hyperbolic_within_4_ulps",
        "math_diff_coverage_report",
    ] {
        assert!(
            diff_tests.contains(expected),
            "missing math diff test {expected}"
        );
    }
    let commands = string_set(&manifest["conformance_binding"]["required_commands"])?;
    for expected in [
        ABI_MATH_DIFF_COMMAND,
        HARNESS_TEST_COMMAND,
        HARNESS_CLIPPY_COMMAND,
    ] {
        assert!(
            commands.contains(expected),
            "missing remote-only command {expected}"
        );
        assert!(
            expected.contains("RCH_FORCE_REMOTE=true")
                && expected.contains("rch exec -- env CARGO_TARGET_DIR="),
            "command must force remote rch with isolated target dir: {expected}"
        );
    }
    Ok(())
}

#[test]
fn checker_accepts_math_core_diff_completion_contract() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "accept")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("math_core_diff_completion_contract: PASS"),
        "{}",
        output_text(&output)
    );
    let report = load_json(&out_dir.join("report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("math_core_diff_completion_contract.report.v1")
    );
    assert_eq!(report["passed"].as_bool(), Some(true));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-xrmnr.1"));
    let events = read_log_events(&out_dir.join("events.jsonl"))?;
    for expected in [
        "math_core_diff.source_artifacts_validated",
        "math_core_diff.conformance_binding_validated",
        "math_core_diff.telemetry_binding_validated",
        "math_core_diff.completion_contract_validated",
    ] {
        assert!(events.contains(expected), "missing log event {expected}");
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_required_telemetry_event() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let events = manifest["telemetry_binding"]["required_events"]
        .as_array_mut()
        .ok_or_else(|| test_error("required events should be array"))?;
    events.retain(|event| event.as_str() != Some("math_core_diff.completion_contract_failed"));
    let out_dir = unique_output_dir(&root, "missing-event")?;
    let bad_manifest = out_dir.join("missing-event-contract.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(!output.status.success(), "{}", output_text(&output));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("telemetry missing events"),
        "{}",
        output_text(&output)
    );
    let report = load_json(&out_dir.join("report.json"))?;
    assert_eq!(report["passed"].as_bool(), Some(false));
    assert!(
        read_log_events(&out_dir.join("events.jsonl"))?
            .contains("math_core_diff.completion_contract_failed")
    );
    Ok(())
}

#[test]
fn checker_rejects_local_cargo_validation_command() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&manifest_path(&root))?;
    set_required_command(
        &mut manifest,
        ABI_MATH_DIFF_COMMAND,
        "cargo test -p frankenlibc-abi --test conformance_diff_math",
    )?;
    let out_dir = unique_output_dir(&root, "local-cargo")?;
    let bad_manifest = out_dir.join("local-cargo-contract.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(!output.status.success(), "{}", output_text(&output));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("must run cargo through rch exec"),
        "{}",
        output_text(&output)
    );
    Ok(())
}

#[test]
fn checker_rejects_non_remote_rch_validation_commands() -> TestResult {
    let root = workspace_root()?;
    let base = load_json(&manifest_path(&root))?;

    let mut missing_force = base.clone();
    set_required_command(
        &mut missing_force,
        ABI_MATH_DIFF_COMMAND,
        "RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_frankenlibc_math_core_diff_bad cargo test -p frankenlibc-abi --test conformance_diff_math -- --nocapture",
    )?;
    let out_dir = unique_output_dir(&root, "missing-force")?;
    let bad_manifest = out_dir.join("missing-force-contract.json");
    write_json(&bad_manifest, &missing_force)?;
    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(!output.status.success(), "{}", output_text(&output));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("must set RCH_FORCE_REMOTE=true"),
        "{}",
        output_text(&output)
    );

    let mut missing_target_dir = base.clone();
    set_required_command(
        &mut missing_target_dir,
        HARNESS_TEST_COMMAND,
        "RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary rch exec -- env cargo test -p frankenlibc-harness --test math_core_diff_completion_contract_test -- --nocapture",
    )?;
    let out_dir = unique_output_dir(&root, "missing-target-dir")?;
    let bad_manifest = out_dir.join("missing-target-dir-contract.json");
    write_json(&bad_manifest, &missing_target_dir)?;
    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(!output.status.success(), "{}", output_text(&output));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("must set isolated CARGO_TARGET_DIR"),
        "{}",
        output_text(&output)
    );

    let mut shell_wrapped = base.clone();
    set_required_command(
        &mut shell_wrapped,
        HARNESS_CLIPPY_COMMAND,
        "RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary rch exec -- bash -c 'cargo clippy -p frankenlibc-harness --test math_core_diff_completion_contract_test -- -D warnings'",
    )?;
    let out_dir = unique_output_dir(&root, "shell-wrapped")?;
    let bad_manifest = out_dir.join("shell-wrapped-contract.json");
    write_json(&bad_manifest, &shell_wrapped)?;
    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(!output.status.success(), "{}", output_text(&output));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("must not shell-wrap cargo"),
        "{}",
        output_text(&output)
    );

    let mut local_fallback = base;
    set_required_command(
        &mut local_fallback,
        ABI_MATH_DIFF_COMMAND,
        "RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_frankenlibc_math_core_diff_bad cargo test -p frankenlibc-abi --test conformance_diff_math -- --nocapture [RCH] local (remote execution failed)",
    )?;
    let out_dir = unique_output_dir(&root, "local-fallback")?;
    let bad_manifest = out_dir.join("local-fallback-contract.json");
    write_json(&bad_manifest, &local_fallback)?;
    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(!output.status.success(), "{}", output_text(&output));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("must not include local rch fallback"),
        "{}",
        output_text(&output)
    );

    Ok(())
}
