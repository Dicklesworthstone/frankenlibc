//! Conformance gate for the hidden harness binary
//! `conformance-matrix-case` subprocess entrypoint.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

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

fn manifest_path(root: &Path) -> PathBuf {
    root.join("tests")
        .join("conformance")
        .join("conformance_matrix_case_cli_contract.v1.json")
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

fn run_case(
    bin: &Path,
    function: &str,
    mode: &str,
    stdin_body: &[u8],
    env_mode: Option<&str>,
) -> TestResult<Output> {
    let mut cmd = Command::new(bin);
    cmd.arg("conformance-matrix-case")
        .arg("--function")
        .arg(function)
        .arg("--mode")
        .arg(mode)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(env_mode) = env_mode {
        cmd.env("FRANKENLIBC_MODE", env_mode);
    } else {
        cmd.env_remove("FRANKENLIBC_MODE");
    }

    let mut child = cmd.spawn().map_err(|err| format!("spawn case: {err}"))?;
    child
        .stdin
        .take()
        .ok_or_else(|| "missing child stdin".to_string())?
        .write_all(stdin_body)
        .map_err(|err| format!("write stdin: {err}"))?;
    child
        .wait_with_output()
        .map_err(|err| format!("wait case: {err}"))
}

fn parse_stdout_json(output: &Output) -> TestResult<Value> {
    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_slice(&output.stdout)
        .map_err(|err| format!("parse stdout JSON: {err}; stdout={stdout:?}"))
}

#[test]
fn manifest_anchors_hidden_case_subprocess() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "conformance-matrix-case-cli-contract",
        "manifest_id",
    )?;
    require(
        json_string(&m, "subcommand_name")? == "conformance-matrix-case",
        "subcommand_name",
    )?;
    require(
        json_string(&m, "visibility")? == "hidden_subprocess_entrypoint",
        "visibility",
    )?;
    let required_flags: Vec<&str> = json_array(&m, "required_flags")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    require(required_flags == ["--function", "--mode"], "required_flags")
}

#[test]
fn manifest_policy_pins_case_runner_invariants() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    let policy = m
        .get("policy")
        .ok_or_else(|| "missing policy".to_string())?;
    for (field, message) in [
        (
            "must_remain_registered_even_though_hidden",
            "must_remain_registered_even_though_hidden must be true",
        ),
        (
            "must_accept_case_inputs_from_stdin",
            "must_accept_case_inputs_from_stdin must be true",
        ),
        (
            "must_emit_success_envelope_for_supported_fixture",
            "must_emit_success_envelope_for_supported_fixture must be true",
        ),
        (
            "must_emit_error_envelope_for_unsupported_fixture",
            "must_emit_error_envelope_for_unsupported_fixture must be true",
        ),
        (
            "must_record_startup_mode_evidence",
            "must_record_startup_mode_evidence must be true",
        ),
        (
            "invalid_stdin_must_fail_closed_without_json_envelope",
            "invalid_stdin_must_fail_closed_without_json_envelope must be true",
        ),
    ] {
        require(json_bool(policy, field)?, message)?;
    }

    let output = m
        .get("output_contract")
        .ok_or_else(|| "missing output_contract".to_string())?;
    let success_fields: Vec<&str> = json_array(output, "success_required_fields")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for (field, message) in [
        ("kind", "success_required_fields missing kind"),
        ("run", "success_required_fields missing run"),
        (
            "startup_runtime_mode",
            "success_required_fields missing startup_runtime_mode",
        ),
        (
            "startup_frankenlibc_mode",
            "success_required_fields missing startup_frankenlibc_mode",
        ),
        (
            "startup_mode_matches",
            "success_required_fields missing startup_mode_matches",
        ),
    ] {
        require(success_fields.contains(&field), message)?;
    }
    require(
        output.get("startup_mode_evidence").is_some(),
        "startup_mode_evidence",
    )
}

#[test]
fn cli_emits_ok_envelope_for_supported_fixture() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        return Ok(());
    };
    let stdin =
        serde_json::to_vec(&serde_json::json!({"s": [97, 0]})).map_err(|err| err.to_string())?;
    let output = run_case(&bin, "strlen", "strict", &stdin, Some("strict"))?;
    require(
        output.status.success(),
        format!(
            "case runner failed:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )?;
    let envelope = parse_stdout_json(&output)?;
    require(
        envelope.get("kind").and_then(Value::as_str) == Some("ok"),
        "kind",
    )?;
    require(
        envelope.get("startup_runtime_mode").and_then(Value::as_str) == Some("strict"),
        "startup_runtime_mode",
    )?;
    require(
        envelope
            .get("startup_frankenlibc_mode")
            .and_then(Value::as_str)
            == Some("strict"),
        "startup_frankenlibc_mode",
    )?;
    require(
        envelope
            .get("startup_mode_matches")
            .and_then(Value::as_bool)
            == Some(true),
        "startup_mode_matches",
    )?;
    let run = envelope
        .get("run")
        .ok_or_else(|| "missing run".to_string())?;
    require(
        run.get("host_output").and_then(Value::as_str) == Some("1"),
        "host_output",
    )?;
    require(
        run.get("impl_output").and_then(Value::as_str) == Some("1"),
        "impl_output",
    )?;
    require(
        run.get("host_parity").and_then(Value::as_bool) == Some(true),
        "host_parity",
    )
}

#[test]
fn cli_emits_error_envelope_for_unsupported_fixture() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        return Ok(());
    };
    let stdin = serde_json::to_vec(&serde_json::json!({})).map_err(|err| err.to_string())?;
    let output = run_case(&bin, "__missing_fixture_contract", "hardened", &stdin, None)?;
    require(
        output.status.success(),
        "unsupported fixture should still envelope",
    )?;
    let envelope = parse_stdout_json(&output)?;
    require(
        envelope.get("kind").and_then(Value::as_str) == Some("error"),
        "kind",
    )?;
    require(
        envelope.get("run").is_none(),
        "error envelope should omit run",
    )?;
    require(
        envelope
            .get("error")
            .and_then(Value::as_str)
            .is_some_and(|err| err.contains("unsupported function")),
        "error message",
    )?;
    require(
        envelope.get("startup_runtime_mode").and_then(Value::as_str) == Some("hardened"),
        "startup_runtime_mode",
    )?;
    require(
        envelope
            .get("startup_frankenlibc_mode")
            .and_then(Value::as_str)
            == Some("<unset>"),
        "startup_frankenlibc_mode",
    )?;
    require(
        envelope
            .get("startup_mode_matches")
            .and_then(Value::as_bool)
            == Some(false),
        "startup_mode_matches",
    )
}

#[test]
fn invalid_stdin_fails_closed_before_envelope() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        return Ok(());
    };
    let output = run_case(&bin, "strlen", "strict", b"{not-json", Some("strict"))?;
    require(!output.status.success(), "invalid JSON stdin should fail")?;
    require(
        output.stdout.is_empty(),
        "invalid stdin should not emit envelope",
    )?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    require(
        stderr.contains("invalid case inputs json"),
        format!("unexpected stderr: {stderr}"),
    )
}
