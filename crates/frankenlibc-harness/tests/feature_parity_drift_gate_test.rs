//! Integration test: feature parity fail-fast drift gate (bd-w2c3.10)

use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "workspace root").into())
}

fn unique_temp_path(name: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    Ok(std::env::temp_dir().join(format!("frankenlibc-{name}-{stamp}-{}", std::process::id())))
}

fn missing_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn required_array<'a>(
    value: &'a serde_json::Value,
    field: &str,
) -> TestResult<&'a Vec<serde_json::Value>> {
    value[field]
        .as_array()
        .ok_or_else(|| missing_data(format!("{field} must be an array")).into())
}

fn required_object<'a>(
    value: &'a serde_json::Value,
    field: &str,
) -> TestResult<&'a serde_json::Map<String, serde_json::Value>> {
    value[field]
        .as_object()
        .ok_or_else(|| missing_data(format!("{field} must be an object")).into())
}

fn structured_event(stdout: &str) -> TestResult<serde_json::Value> {
    parse_event_line(stdout)
        .ok_or_else(|| missing_data("structured event line not found in stdout").into())
}

fn read_json(path: &Path, description: &str) -> TestResult<serde_json::Value> {
    let text = std::fs::read_to_string(path)?;
    serde_json::from_str(&text)
        .map_err(|err| missing_data(format!("{description} JSON must parse: {err}")).into())
}

fn run_drift_gate_with_envs(
    script: &Path,
    root: &Path,
    envs: &[(&str, &Path)],
) -> TestResult<std::process::Output> {
    let mut command = Command::new("bash");
    command.arg(script).current_dir(root);
    for (key, value) in envs {
        command.env(key, value);
    }
    Ok(command.output()?)
}

fn ensure_script_exists(script: &Path) -> TestResult {
    if script.exists() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("missing script {}", script.display()),
        )
        .into())
    }
}

fn parse_event_line(stdout: &str) -> Option<serde_json::Value> {
    for line in stdout.lines().rev() {
        let trimmed = line.trim();
        if !trimmed.starts_with('{') {
            continue;
        }
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed)
            && value.get("trace_id").is_some()
            && value.get("artifact_refs").is_some()
        {
            return Some(value);
        }
    }
    None
}

#[test]
fn gate_passes_and_emits_required_diagnostic_schema() -> TestResult {
    let root = workspace_root()?;
    let script = root.join("scripts/check_feature_parity_drift.sh");
    ensure_script_exists(&script)?;

    let out_path = unique_temp_path("fp-drift-pass.json")?;
    let output =
        run_drift_gate_with_envs(&script, &root, &[("FLC_FP_DRIFT_DIAGNOSTICS", &out_path)])?;

    assert!(
        output.status.success(),
        "gate should pass with canonical ownership\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = read_json(&out_path, "drift diagnostics")?;
    let diagnostics = required_array(&report, "diagnostics")?;
    assert!(!diagnostics.is_empty(), "diagnostics must be non-empty");

    for row in diagnostics {
        assert!(row["gap_id"].is_string(), "gap_id must be present");
        assert!(row["owner_bead"].is_string(), "owner_bead must be present");
        assert!(
            row["source_file"].is_string(),
            "source_file must be present"
        );
        assert!(
            row["expected_vs_actual"].is_object(),
            "expected_vs_actual must be present"
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let event = structured_event(&stdout)?;
    for key in [
        "trace_id",
        "mode",
        "api_family",
        "symbol",
        "decision_path",
        "healing_action",
        "errno",
        "latency_ns",
        "artifact_refs",
    ] {
        assert!(
            event.get(key).is_some(),
            "structured event missing key `{key}`"
        );
    }
    Ok(())
}

#[test]
fn gate_fails_when_unresolved_drift_loses_owner() -> TestResult {
    let root = workspace_root()?;
    let script = root.join("scripts/check_feature_parity_drift.sh");
    ensure_script_exists(&script)?;

    let issues_src = root.join(".beads/issues.jsonl");
    let issues_mut = unique_temp_path("issues-mut.jsonl")?;
    let mut lines_out = Vec::new();
    for raw in std::fs::read_to_string(&issues_src)?.lines() {
        if raw.trim().is_empty() {
            continue;
        }
        let mut row: serde_json::Value = serde_json::from_str(raw)
            .map_err(|err| missing_data(format!("issues.jsonl line must be valid JSON: {err}")))?;
        if row["id"].as_str() == Some("bd-w2c3.10") {
            row["status"] = serde_json::Value::String("orphaned".to_string());
        }
        lines_out.push(serde_json::to_string(&row)?);
    }
    std::fs::write(&issues_mut, lines_out.join("\n") + "\n")?;

    let out_path = unique_temp_path("fp-drift-fail.json")?;
    let output = run_drift_gate_with_envs(
        &script,
        &root,
        &[
            ("FLC_FP_ISSUES_JSONL", &issues_mut),
            ("FLC_FP_DRIFT_DIAGNOSTICS", &out_path),
        ],
    )?;

    assert!(
        !output.status.success(),
        "gate should fail when ownership is dropped\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = read_json(&out_path, "drift diagnostics")?;
    let summary = required_object(&report, "summary")?;
    let fail_count = summary
        .get("fail_count")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| missing_data("summary.fail_count must be u64"))?;
    assert!(
        fail_count > 0,
        "fail_count must be > 0 when ownership is dropped"
    );

    let diagnostics = required_array(&report, "diagnostics")?;
    assert!(
        diagnostics.iter().any(|row| {
            row["owner_bead"].as_str() == Some("bd-w2c3.10")
                && row["status"].as_str() == Some("fail")
        }),
        "expected at least one failed diagnostic for orphaned owner bead bd-w2c3.10"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let event = structured_event(&stdout)?;
    assert_eq!(
        event["errno"].as_i64(),
        Some(1),
        "errno should be 1 on fail"
    );
    Ok(())
}
