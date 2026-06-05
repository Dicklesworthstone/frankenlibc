//! Gate coverage for the bd-juvqm.9 rch validation-lane plan.
//!
//! The committed manifest gives agents copyable, focused `rch cargo` lanes
//! for common FrankenLibC surfaces. These tests run the shell checker against
//! the canonical plan and against mutated plans that would otherwise let local
//! cargo, workspace-wide gates, or missing target-dir isolation slip through.

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
        .join("test-rch-validation-lane-plan")
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

fn repo_relative(root: &Path, path: &Path) -> TestResult<String> {
    Ok(path
        .strip_prefix(root)
        .map_err(|err| {
            test_error(format!(
                "{} should be inside workspace root {}: {err}",
                path.display(),
                root.display()
            ))
        })?
        .to_string_lossy()
        .replace(std::path::MAIN_SEPARATOR, "/"))
}

fn adjusted_manifest(
    root: &Path,
    out_dir: &Path,
    manifest_override: Option<&Path>,
    report: &Path,
    log: &Path,
) -> TestResult<PathBuf> {
    let source = manifest_override
        .map(Path::to_path_buf)
        .unwrap_or_else(|| root.join("tests/conformance/rch_validation_lane_plan.v1.json"));
    let mut manifest = load_json(&source)?;
    let report_contract = manifest
        .get_mut("report_contract")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| test_error("manifest.report_contract must be an object"))?;
    report_contract.insert(
        "output_path".to_owned(),
        Value::String(repo_relative(root, report)?),
    );
    report_contract.insert(
        "log_path".to_owned(),
        Value::String(repo_relative(root, log)?),
    );

    let path = out_dir.join("manifest.json");
    write_json(&path, &manifest)?;
    Ok(path)
}

fn string_field<'a>(value: &'a Value, key: &str, context: &str) -> TestResult<&'a str> {
    value
        .get(key)
        .ok_or_else(|| test_error(format!("{context}.{key} is missing")))?
        .as_str()
        .ok_or_else(|| test_error(format!("{context}.{key} must be a string")))
}

fn require_log_row_field(log_row: &Value, field: &str) -> TestResult {
    if log_row.get(field).is_some() {
        Ok(())
    } else {
        Err(test_error(format!(
            "log row missing required field `{field}`"
        )))
    }
}

fn surface_mut<'a>(manifest: &'a mut Value, surface_id: &str) -> TestResult<&'a mut Value> {
    manifest
        .get_mut("surfaces")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("manifest.surfaces must be an array"))?
        .iter_mut()
        .find(|surface| surface.get("surface_id").and_then(Value::as_str) == Some(surface_id))
        .ok_or_else(|| test_error(format!("surface {surface_id} should exist")))
}

fn remove_surface(manifest: &mut Value, surface_id: &str) -> TestResult {
    let surfaces = manifest
        .get_mut("surfaces")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("manifest.surfaces must be an array"))?;
    let old_len = surfaces.len();
    surfaces
        .retain(|surface| surface.get("surface_id").and_then(Value::as_str) != Some(surface_id));
    ensure(
        surfaces.len() + 1 == old_len,
        format!("surface {surface_id} should have been removed"),
    )
}

fn run_checker(
    root: &Path,
    manifest_override: Option<&Path>,
    label: &str,
) -> TestResult<CheckerRun> {
    let out_dir = unique_dir(root, label)?;
    let report = out_dir.join("report.json");
    let log = out_dir.join("log.jsonl");
    let manifest = adjusted_manifest(root, &out_dir, manifest_override, &report, &log)?;
    let mut command = Command::new(root.join("scripts/check_rch_validation_lane_plan.sh"));
    command
        .arg("--validate-only")
        .current_dir(root)
        .env("RCH_VALIDATION_LANE_PLAN_REPORT", &report)
        .env("RCH_VALIDATION_LANE_PLAN_LOG", &log)
        .env("RCH_VALIDATION_LANE_PLAN_MANIFEST", &manifest);
    let output = command
        .output()
        .map_err(|err| test_error(format!("failed to run rch validation lane checker: {err}")))?;
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

fn same_text(left: &str, right: &str) -> bool {
    left.chars().eq(right.chars())
}

fn set_surface_string(
    manifest: &mut Value,
    surface_id: &str,
    field: &str,
    value: &str,
) -> TestResult {
    let surface = surface_mut(manifest, surface_id)?;
    let object = surface
        .as_object_mut()
        .ok_or_else(|| test_error(format!("surface {surface_id} must be an object")))?;
    object.insert(field.to_owned(), Value::String(value.to_owned()));
    Ok(())
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
    let report = load_json(&run.report)?;
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
    let mut manifest = load_json(&root.join("tests/conformance/rch_validation_lane_plan.v1.json"))?;
    mutate(&mut manifest)?;
    let path = unique_dir(root, label)?.join("manifest.json");
    write_json(&path, &manifest)?;
    Ok(path)
}

#[test]
fn checker_passes_current_rch_validation_lane_plan() -> TestResult {
    let root = workspace_root()?;
    let script = root.join("scripts/check_rch_validation_lane_plan.sh");
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

    let run = run_checker(&root, None, "pass")?;
    ensure(
        run.output.status.success(),
        format!(
            "checker should pass\nstdout:\n{}\nstderr:\n{}",
            stdout(&run.output),
            stderr(&run.output)
        ),
    )?;
    let report = load_json(&run.report)?;
    ensure(
        same_text(string_field(&report, "outcome", "report")?, "pass"),
        "report.outcome should be pass",
    )?;
    let cargo_lanes = report
        .get("summary")
        .and_then(|summary| summary.get("cargo_lanes"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    ensure(
        cargo_lanes >= 10,
        "checker should count focused cargo lanes",
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
        require_log_row_field(&log_row, field)?;
    }
    Ok(())
}

#[test]
fn checker_rejects_local_bare_cargo_lane() -> TestResult {
    let root = workspace_root()?;
    let manifest = mutated_manifest(&root, "bare-cargo", |manifest| {
        set_surface_string(
            manifest,
            "harness-conformance-gates",
            "minimal_test_cmd",
            "cargo test -p frankenlibc-harness --test fixture_schema_validation_test",
        )
    })?;
    let run = run_checker(&root, Some(&manifest), "bare-cargo")?;
    expect_failure(&run, "bare_cargo_command")
}

#[test]
fn checker_rejects_workspace_gate_inside_surface_lane() -> TestResult {
    let root = workspace_root()?;
    let manifest = mutated_manifest(&root, "workspace-gate", |manifest| {
        set_surface_string(
            manifest,
            "membrane-runtime-math",
            "minimal_test_cmd",
            "RCH_FORCE_REMOTE=true rch cargo test --workspace",
        )
    })?;
    let run = run_checker(&root, Some(&manifest), "workspace-gate")?;
    expect_failure(&run, "workspace_gate_forbidden")
}

#[test]
fn checker_rejects_remote_only_lane_without_force_env() -> TestResult {
    let root = workspace_root()?;
    let manifest = mutated_manifest(&root, "missing-remote-force", |manifest| {
        set_surface_string(
            manifest,
            "abi-pthread",
            "minimal_test_cmd",
            "rch cargo test -p frankenlibc-abi --lib pthread_abi",
        )
    })?;
    let run = run_checker(&root, Some(&manifest), "missing-remote-force")?;
    expect_failure(&run, "missing_remote_force")
}

#[test]
fn checker_rejects_bash_wrapped_cargo_lane() -> TestResult {
    let root = workspace_root()?;
    let manifest = mutated_manifest(&root, "bash-wrapped-cargo", |manifest| {
        set_surface_string(
            manifest,
            "core-resolv",
            "minimal_test_cmd",
            "RCH_FORCE_REMOTE=true bash -c 'cargo test -p frankenlibc-core --lib resolv'",
        )
    })?;
    let run = run_checker(&root, Some(&manifest), "bash-wrapped-cargo")?;
    expect_failure(&run, "bash_wrapped_cargo_lane")
}

#[test]
fn checker_rejects_missing_local_fallback_policy() -> TestResult {
    let root = workspace_root()?;
    let manifest = mutated_manifest(&root, "local-fallback-policy", |manifest| {
        let rules = manifest
            .get_mut("rules")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| test_error("manifest.rules must be an object"))?;
        rules.insert(
            "local_fallback_is_invalid_proof".to_string(),
            Value::String("local fallback can be used when remote execution fails".to_string()),
        );
        Ok(())
    })?;
    let run = run_checker(&root, Some(&manifest), "local-fallback-policy")?;
    expect_failure(&run, "local_fallback_policy_missing")
}

#[test]
fn checker_rejects_missing_target_dir_guidance() -> TestResult {
    let root = workspace_root()?;
    let manifest = mutated_manifest(&root, "target-dir", |manifest| {
        set_surface_string(manifest, "abi-stdio", "target_dir_pattern", "target")
    })?;
    let run = run_checker(&root, Some(&manifest), "target-dir")?;
    expect_failure(&run, "missing_cargo_target_dir")
}

#[test]
fn checker_rejects_missing_required_surface() -> TestResult {
    let root = workspace_root()?;
    let manifest = mutated_manifest(&root, "missing-surface", |manifest| {
        remove_surface(manifest, "abi-string")
    })?;
    let run = run_checker(&root, Some(&manifest), "missing-surface")?;
    expect_failure(&run, "missing_surface")
}
