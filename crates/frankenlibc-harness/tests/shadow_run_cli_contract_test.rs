//! Conformance gate for the harness binary `shadow-run` subcommand.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

fn manifest_contract_path(root: &Path) -> PathBuf {
    root.join("tests")
        .join("conformance")
        .join("shadow_run_cli_contract.v1.json")
}

fn load_json(path: &Path) -> TestResult<Value> {
    let content = std::fs::read_to_string(path).map_err(|err| format!("read {path:?}: {err}"))?;
    serde_json::from_str(&content).map_err(|err| format!("parse {path:?}: {err}"))
}

fn require(condition: bool, message: impl Into<String>) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn json_string<'a>(value: &'a Value, field: &str) -> TestResult<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing or non-string `{field}`"))
}

fn json_bool(value: &Value, field: &str) -> TestResult<bool> {
    value
        .get(field)
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("missing or non-bool `{field}`"))
}

fn json_u64(value: &Value, field: &str) -> TestResult<u64> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("missing or non-u64 `{field}`"))
}

fn json_array<'a>(value: &'a Value, field: &str) -> TestResult<&'a Vec<Value>> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("missing or non-array `{field}`"))
}

fn cargo_target_dir_for_bin() -> PathBuf {
    if let Ok(p) = std::env::var("CARGO_TARGET_DIR") {
        PathBuf::from(p)
    } else if let Ok(p) = std::env::var("CARGO_MANIFEST_DIR") {
        Path::new(&p)
            .parent()
            .and_then(Path::parent)
            .map(|root| root.join("target"))
            .unwrap_or_else(|| PathBuf::from("target"))
    } else {
        PathBuf::from("target")
    }
}

fn find_harness_binary() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_harness") {
        return Some(PathBuf::from(path));
    }
    let root = cargo_target_dir_for_bin();
    for prof in ["debug", "release"] {
        let candidate = root.join(prof).join("harness");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

fn libc_preload_path() -> Option<PathBuf> {
    [
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/usr/lib/x86_64-linux-gnu/libc.so.6",
        "/lib64/libc.so.6",
    ]
    .into_iter()
    .map(PathBuf::from)
    .find(|path| path.exists())
}

fn unique_tmp_dir(label: &str) -> TestResult<PathBuf> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("clock: {e}"))?
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "frankenlibc_shadow_run_cli_contract_{label}_{}_{ts}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {dir:?}: {e}"))?;
    Ok(dir)
}

fn shadow_manifest(scenario: Value) -> Value {
    serde_json::json!({
        "schema_version": "v1",
        "manifest_id": "shadow-run-cli-contract-manifest",
        "generated_utc": "2026-05-14T00:00:00Z",
        "description": "shadow-run CLI contract fixture",
        "replay_defaults": {
            "seed_key": "FRANKENLIBC_E2E_SEED",
            "env_keys": ["FRANKENLIBC_E2E_SEED"],
            "deterministic_inputs": "static"
        },
        "scenarios": [scenario]
    })
}

fn matching_scenario(command: Value) -> Value {
    serde_json::json!({
        "id": "cli.shadow.match",
        "class": "cli-contract",
        "label": "shadow_match",
        "priority": 1,
        "description": "Shadow-run parity check for a deterministic command.",
        "command": command,
        "mode_expectations": {
            "strict": {
                "expected_outcome": "pass",
                "pass_condition": "exit_code == 0",
                "allowed_exit_codes": [0]
            }
        },
        "artifact_policy": {
            "capture_stdout": true,
            "capture_stderr": true,
            "capture_env_on_failure": true,
            "capture_bundle_on_failure": true,
            "required_artifacts": [
                "baseline.stdout.txt",
                "baseline.stderr.txt",
                "baseline.exit_code",
                "stdout.txt",
                "stderr.txt",
                "exit_code"
            ]
        },
        "replay": {
            "seed_key": "FRANKENLIBC_E2E_SEED",
            "env_keys": ["FRANKENLIBC_E2E_SEED", "FRANKENLIBC_MODE", "LD_PRELOAD"],
            "deterministic_inputs": "static argv"
        }
    })
}

fn write_manifest(path: &Path, scenario: Value) -> TestResult {
    let manifest = shadow_manifest(scenario);
    let body = serde_json::to_string_pretty(&manifest).map_err(|err| err.to_string())?;
    std::fs::write(path, body).map_err(|e| format!("write {path:?}: {e}"))
}

struct ShadowRunPaths {
    manifest: PathBuf,
    out_dir: PathBuf,
    report: PathBuf,
    log: PathBuf,
    artifact_index: PathBuf,
}

impl ShadowRunPaths {
    fn new(root: &Path, label: &str) -> Self {
        Self {
            manifest: root.join(format!("{label}.manifest.json")),
            out_dir: root.join(format!("{label}.out")),
            report: root.join(format!("{label}.report.json")),
            log: root.join(format!("{label}.log.jsonl")),
            artifact_index: root.join(format!("{label}.artifacts.json")),
        }
    }

    fn markdown_report(&self) -> PathBuf {
        self.report.with_extension("md")
    }
}

fn run_shadow_run(
    bin: &Path,
    paths: &ShadowRunPaths,
    workspace: &Path,
    lib_path: &Path,
    mode: &str,
    fail_on_mismatch: bool,
) -> TestResult<Output> {
    let mut cmd = Command::new(bin);
    cmd.arg("shadow-run")
        .arg("--manifest")
        .arg(&paths.manifest)
        .arg("--workspace-root")
        .arg(workspace)
        .arg("--out-dir")
        .arg(&paths.out_dir)
        .arg("--report")
        .arg(&paths.report)
        .arg("--log")
        .arg(&paths.log)
        .arg("--artifact-index")
        .arg(&paths.artifact_index)
        .arg("--lib-path")
        .arg(lib_path)
        .arg("--reference")
        .arg("glibc")
        .arg("--mode")
        .arg(mode)
        .arg("--timeout-ms")
        .arg("2000")
        .arg("--no-syscall-trace");
    if fail_on_mismatch {
        cmd.arg("--fail-on-mismatch");
    }
    cmd.output().map_err(|err| format!("run shadow-run: {err}"))
}

fn read_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    let body = std::fs::read_to_string(path).map_err(|e| format!("read {path:?}: {e}"))?;
    body.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).map_err(|err| format!("parse log row: {err}")))
        .collect()
}

#[test]
fn manifest_anchors_shadow_run_subcommand() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_contract_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "shadow-run-cli-contract",
        "manifest_id",
    )?;
    require(
        json_string(&m, "subcommand_name")? == "shadow-run",
        "subcommand_name",
    )?;
    require(
        json_string(&m, "binary_target")? == "harness",
        "binary_target",
    )?;
    let required_flags: Vec<&str> = json_array(&m, "required_flags")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    require(required_flags == ["--manifest"], "required_flags")
}

#[test]
fn manifest_policy_pins_cli_invariants() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_contract_path(&root))?;
    let policy = m
        .get("policy")
        .ok_or_else(|| "missing policy".to_string())?;
    for (field, message) in [
        (
            "must_register_shadow_run_subcommand",
            "must_register_shadow_run_subcommand must be true",
        ),
        (
            "must_require_manifest_path",
            "must_require_manifest_path must be true",
        ),
        (
            "must_reject_unknown_mode_before_writing_outputs",
            "must_reject_unknown_mode_before_writing_outputs must be true",
        ),
        (
            "must_write_report_log_markdown_and_artifact_index",
            "must_write_report_log_markdown_and_artifact_index must be true",
        ),
        (
            "must_preserve_manifest_reference_and_runtime_mode_metadata",
            "must_preserve_manifest_reference_and_runtime_mode_metadata must be true",
        ),
        (
            "must_emit_structured_shadow_run_log_rows",
            "must_emit_structured_shadow_run_log_rows must be true",
        ),
        (
            "fail_on_mismatch_must_exit_nonzero_after_artifacts",
            "fail_on_mismatch_must_exit_nonzero_after_artifacts must be true",
        ),
        (
            "no_syscall_trace_must_disable_strace_dependency",
            "no_syscall_trace_must_disable_strace_dependency must be true",
        ),
    ] {
        require(json_bool(policy, field)?, message)?;
    }

    let output = m
        .get("output_contract")
        .ok_or_else(|| "missing output_contract".to_string())?;
    let report_fields: Vec<&str> = json_array(output, "report_required_fields")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for (field, message) in [
        (
            "schema_version",
            "report_required_fields missing schema_version",
        ),
        ("manifest_id", "report_required_fields missing manifest_id"),
        ("summary", "report_required_fields missing summary"),
        ("scenarios", "report_required_fields missing scenarios"),
    ] {
        require(report_fields.contains(&field), message)?;
    }
    require(
        json_bool(output, "writes_report_before_fail_on_mismatch_exit")?,
        "fail-on-mismatch artifact policy",
    )
}

#[test]
fn cli_writes_report_log_markdown_and_artifact_index() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        return Ok(());
    };
    let Some(lib_path) = libc_preload_path() else {
        return Ok(());
    };
    let root = unique_tmp_dir("success")?;
    let paths = ShadowRunPaths::new(&root, "success");
    write_manifest(
        &paths.manifest,
        matching_scenario(serde_json::json!(["/bin/echo", "shadow-ok"])),
    )?;

    let run = run_shadow_run(&bin, &paths, &root, &lib_path, "strict", false)?;
    require(
        run.status.success(),
        format!(
            "shadow-run failed:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&run.stdout),
            String::from_utf8_lossy(&run.stderr)
        ),
    )?;

    let report = load_json(&paths.report)?;
    require(
        json_string(&report, "schema_version")? == "v1",
        "report schema_version",
    )?;
    require(
        json_string(&report, "manifest_id")? == "shadow-run-cli-contract-manifest",
        "manifest_id",
    )?;
    require(json_string(&report, "reference")? == "glibc", "reference")?;
    let summary = report
        .get("summary")
        .ok_or_else(|| "missing summary".to_string())?;
    require(json_u64(summary, "total_runs")? == 1, "summary.total_runs")?;
    require(json_u64(summary, "passed")? == 1, "summary.passed")?;
    let scenarios = json_array(&report, "scenarios")?;
    require(scenarios.len() == 1, "strict mode should emit one scenario")?;
    let scenario = scenarios
        .first()
        .ok_or_else(|| "strict mode should emit one scenario".to_string())?;
    require(
        json_string(scenario, "status")? == "pass",
        "scenario status",
    )?;
    require(json_string(scenario, "mode")? == "strict", "scenario mode")?;
    let _artifact_refs = json_array(scenario, "artifact_refs")?;

    require(paths.markdown_report().exists(), "markdown report missing")?;
    let artifact_index = load_json(&paths.artifact_index)?;
    require(
        artifact_index.get("run_id").and_then(Value::as_str)
            == Some("shadow-run-cli-contract-manifest"),
        "artifact index run_id",
    )?;
    let rows = read_jsonl(&paths.log)?;
    require(!rows.is_empty(), "structured log should not be empty")?;
    let match_row = rows
        .iter()
        .find(|row| {
            row.get("event").and_then(Value::as_str) == Some("conformance.shadow_run_match")
        })
        .ok_or_else(|| "missing shadow_run_match row".to_string())?;
    for (field, message) in [
        ("trace_id", "match log missing trace_id"),
        ("mode", "match log missing mode"),
        ("api_family", "match log missing api_family"),
        ("symbol", "match log missing symbol"),
        ("outcome", "match log missing outcome"),
        ("artifact_refs", "match log missing artifact_refs"),
    ] {
        require(match_row.get(field).is_some(), message)?;
    }
    Ok(())
}

#[test]
fn cli_rejects_unknown_mode_without_writing_outputs() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        return Ok(());
    };
    let Some(lib_path) = libc_preload_path() else {
        return Ok(());
    };
    let root = unique_tmp_dir("bad_mode")?;
    let paths = ShadowRunPaths::new(&root, "bad-mode");
    write_manifest(
        &paths.manifest,
        matching_scenario(serde_json::json!(["/bin/echo", "shadow-ok"])),
    )?;

    let run = run_shadow_run(&bin, &paths, &root, &lib_path, "reckless", false)?;
    require(!run.status.success(), "unknown mode should fail")?;
    let stderr = String::from_utf8_lossy(&run.stderr);
    require(
        stderr.contains("Unsupported mode 'reckless'"),
        format!("unexpected stderr: {stderr}"),
    )?;
    require(!paths.report.exists(), "unknown mode wrote report")?;
    require(!paths.log.exists(), "unknown mode wrote log")?;
    require(
        !paths.artifact_index.exists(),
        "unknown mode wrote artifact index",
    )
}

#[test]
fn fail_on_mismatch_exits_nonzero_after_writing_artifacts() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        return Ok(());
    };
    let Some(lib_path) = libc_preload_path() else {
        return Ok(());
    };
    let root = unique_tmp_dir("mismatch")?;
    let paths = ShadowRunPaths::new(&root, "mismatch");
    write_manifest(
        &paths.manifest,
        matching_scenario(serde_json::json!([
            "/bin/sh",
            "-c",
            "if [ -n \"$LD_PRELOAD\" ]; then echo candidate; else echo reference; fi"
        ])),
    )?;

    let run = run_shadow_run(&bin, &paths, &root, &lib_path, "strict", true)?;
    require(!run.status.success(), "--fail-on-mismatch should fail")?;
    let stderr = String::from_utf8_lossy(&run.stderr);
    require(
        stderr.contains("Shadow run mismatch"),
        format!("unexpected stderr: {stderr}"),
    )?;
    let report = load_json(&paths.report)?;
    let summary = report
        .get("summary")
        .ok_or_else(|| "missing summary".to_string())?;
    require(
        summary.get("diverged").and_then(Value::as_u64) == Some(1),
        "diverged count",
    )?;
    let rows = read_jsonl(&paths.log)?;
    require(
        rows.iter().any(|row| {
            row.get("event").and_then(Value::as_str) == Some("conformance.shadow_run_divergence")
        }),
        "mismatch run should log shadow_run_divergence",
    )?;
    require(paths.artifact_index.exists(), "artifact index missing")
}
