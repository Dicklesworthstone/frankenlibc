//! Integration test: deterministic release gate DAG runner (bd-5fw.2)
//!
//! Validates that:
//! 1. `release_gate_dag.v1.json` exists and has required schema fields.
//! 2. Gate dependencies are topological in declared order.
//! 3. `scripts/release_dry_run.sh` exists and is executable.
//! 4. Dry-run mode passes and emits dossier/state/log artifacts.
//! 5. Fail-fast simulation emits deterministic resume token.
//! 6. Resume token restarts from deterministic gate index with audit trail.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

fn require(condition: bool, message: impl Into<String>) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

fn load_dag() -> TestResult<Value> {
    let path = workspace_root()?.join("tests/conformance/release_gate_dag.v1.json");
    let content = std::fs::read_to_string(&path).map_err(|e| format!("read {path:?}: {e}"))?;
    serde_json::from_str(&content).map_err(|e| format!("parse {path:?}: {e}"))
}

fn json_array<'a>(value: &'a Value, field: &str) -> TestResult<&'a Vec<Value>> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("missing or non-array `{field}`"))
}

fn json_string<'a>(value: &'a Value, field: &str) -> TestResult<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing or non-string `{field}`"))
}

fn json_u64(value: &Value, field: &str) -> TestResult<u64> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("missing or non-u64 `{field}`"))
}

fn json_object_exists(value: &Value, field: &str) -> TestResult {
    require(
        value.get(field).is_some_and(Value::is_object),
        format!("missing or non-object `{field}`"),
    )
}

fn read_json(path: &Path) -> TestResult<Value> {
    let body = std::fs::read_to_string(path).map_err(|e| format!("read {path:?}: {e}"))?;
    serde_json::from_str(&body).map_err(|e| format!("parse {path:?}: {e}"))
}

fn read_jsonl_records(path: &Path) -> TestResult<Vec<Value>> {
    let body = std::fs::read_to_string(path).map_err(|e| format!("read {path:?}: {e}"))?;
    body.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).map_err(|e| format!("parse {path:?}: {e}")))
        .collect()
}

fn gate_index(dag: &Value, gate_name: &str) -> TestResult<usize> {
    json_array(dag, "gates")?
        .iter()
        .position(|gate| gate.get("gate_name").and_then(Value::as_str) == Some(gate_name))
        .ok_or_else(|| format!("gate `{gate_name}` must exist in release_gate_dag.v1.json"))
}

fn unique_tmp_path(prefix: &str, suffix: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("system time before UNIX_EPOCH: {e}"))?
        .as_nanos();
    Ok(std::env::temp_dir().join(format!("{prefix}-{}-{nanos}{suffix}", std::process::id())))
}

fn usize_to_u64(value: usize) -> TestResult<u64> {
    u64::try_from(value).map_err(|e| format!("usize to u64 conversion failed: {e}"))
}

fn u64_to_usize(value: u64) -> TestResult<usize> {
    usize::try_from(value).map_err(|e| format!("u64 to usize conversion failed: {e}"))
}

fn release_dry_run_script(root: &Path) -> PathBuf {
    root.join("scripts/release_dry_run.sh")
}

fn dependency_entry_error() -> String {
    "dependency entry must be a string".to_owned()
}

#[test]
fn dag_exists_and_valid() -> TestResult {
    let dag = load_dag()?;
    require(json_u64(&dag, "schema_version")? == 1, "schema_version")?;
    require(json_string(&dag, "bead")? == "bd-5fw.2", "bead")?;
    json_object_exists(&dag, "gate_ordering_policy")?;
    json_object_exists(&dag, "resume_policy")?;
    json_object_exists(&dag, "structured_log_requirements")?;

    let gates = json_array(&dag, "gates")?;
    require(!gates.is_empty(), "gates must be non-empty")?;
    for gate in gates {
        json_string(gate, "gate_name")?;
        json_array(gate, "depends_on")?;
        require(
            gate.get("command")
                .and_then(Value::as_str)
                .is_some_and(|v| !v.is_empty()),
            "gate command missing",
        )?;
    }
    Ok(())
}

#[test]
fn dependencies_are_topological_in_declared_order() -> TestResult {
    let dag = load_dag()?;
    let gates = json_array(&dag, "gates")?;
    let mut seen = HashSet::new();

    for gate in gates {
        let gate_name = json_string(gate, "gate_name")?;
        for dep in json_array(gate, "depends_on")? {
            let dep_name = dep.as_str().ok_or_else(dependency_entry_error)?;
            require(
                seen.contains(dep_name),
                "dependency must appear before dependent gate",
            )?;
        }
        seen.insert(gate_name);
    }
    Ok(())
}

#[test]
fn runner_script_exists_and_executable() -> TestResult {
    let root = workspace_root()?;
    let script = release_dry_run_script(&root);
    require(script.exists(), "scripts/release_dry_run.sh must exist")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script)
            .map_err(|e| format!("metadata {script:?}: {e}"))?
            .permissions();
        require(
            perms.mode() & 0o111 != 0,
            "release_dry_run.sh must be executable",
        )?;
    }

    Ok(())
}

#[test]
fn dry_run_passes_and_emits_artifacts() -> TestResult {
    let root = workspace_root()?;
    let script = release_dry_run_script(&root);
    let log_path = unique_tmp_path("release-dry-run-pass-log", ".jsonl")?;
    let state_path = unique_tmp_path("release-dry-run-pass-state", ".json")?;
    let dossier_path = unique_tmp_path("release-dry-run-pass-dossier", ".json")?;

    let output = Command::new("bash")
        .arg(&script)
        .arg("--mode")
        .arg("dry-run")
        .arg("--log-path")
        .arg(&log_path)
        .arg("--state-path")
        .arg(&state_path)
        .arg("--dossier-path")
        .arg(&dossier_path)
        .current_dir(&root)
        .output()
        .map_err(|e| format!("execute release_dry_run.sh: {e}"))?;

    if !output.status.success() {
        return Err(format!(
            "release_dry_run.sh failed\nstatus={:?}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    require(log_path.exists(), "log output must exist")?;
    require(state_path.exists(), "state output must exist")?;
    require(dossier_path.exists(), "dossier output must exist")?;

    let log_body = std::fs::read_to_string(&log_path)
        .map_err(|e| format!("read release dry-run log {log_path:?}: {e}"))?;
    let lines: Vec<&str> = log_body
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    require(!lines.is_empty(), "log should contain gate rows")?;

    let dossier = read_json(&dossier_path)?;
    let gate_count = u64_to_usize(json_u64(&dossier, "gate_count")?)?;
    require(
        gate_count >= lines.len(),
        "dossier gate_count should cover logged rows",
    )
}

#[test]
fn fail_fast_then_resume_is_deterministic() -> TestResult {
    let root = workspace_root()?;
    let script = release_dry_run_script(&root);
    let dag = load_dag()?;
    let gates = json_array(&dag, "gates")?;
    let expected_resume_index = gate_index(&dag, "e2e")?;
    let fail_log = unique_tmp_path("release-dry-run-fail-log", ".jsonl")?;
    let fail_state = unique_tmp_path("release-dry-run-fail-state", ".json")?;
    let fail_dossier = unique_tmp_path("release-dry-run-fail-dossier", ".json")?;

    let fail_output = Command::new("bash")
        .arg(&script)
        .arg("--mode")
        .arg("dry-run")
        .arg("--log-path")
        .arg(&fail_log)
        .arg("--state-path")
        .arg(&fail_state)
        .arg("--dossier-path")
        .arg(&fail_dossier)
        .env("FRANKENLIBC_RELEASE_SIMULATE_FAIL_GATE", "e2e")
        .current_dir(&root)
        .output()
        .map_err(|e| format!("execute release_dry_run.sh fail-fast run: {e}"))?;

    require(
        !fail_output.status.success(),
        "simulated failure gate must force non-zero exit",
    )?;
    require(
        fail_state.exists(),
        "state file should be written on failure",
    )?;
    require(fail_log.exists(), "log file should be written on failure")?;

    let state_json = read_json(&fail_state)?;
    require(
        json_string(&state_json, "failed_gate")? == "e2e",
        "expected fail-fast at e2e gate",
    )?;
    require(
        json_u64(&state_json, "failed_gate_index")? == usize_to_u64(expected_resume_index)?,
        "failed gate index should match e2e gate position",
    )?;
    let token = json_string(&state_json, "resume_token")?;
    require(
        token.starts_with("v1:"),
        "resume token should use v1 format",
    )?;

    let resume_log = unique_tmp_path("release-dry-run-resume-log", ".jsonl")?;
    let resume_state = unique_tmp_path("release-dry-run-resume-state", ".json")?;
    let resume_dossier = unique_tmp_path("release-dry-run-resume-dossier", ".json")?;

    let resume_output = Command::new("bash")
        .arg(&script)
        .arg("--mode")
        .arg("dry-run")
        .arg("--resume-token")
        .arg(token)
        .arg("--log-path")
        .arg(&resume_log)
        .arg("--state-path")
        .arg(&resume_state)
        .arg("--dossier-path")
        .arg(&resume_dossier)
        .current_dir(&root)
        .output()
        .map_err(|e| format!("execute release_dry_run.sh resume run: {e}"))?;

    if !resume_output.status.success() {
        return Err(format!(
            "resume run failed\nstatus={:?}\nstdout:\n{}\nstderr:\n{}",
            resume_output.status,
            String::from_utf8_lossy(&resume_output.stdout),
            String::from_utf8_lossy(&resume_output.stderr)
        ));
    }

    let rows = read_jsonl_records(&resume_log)?;
    require(
        rows.len() == gates.len(),
        "resume run should emit one row per gate",
    )?;

    for row in rows.iter().take(expected_resume_index) {
        require(
            json_string(row, "status")? == "resume_skip",
            "gates before resume index should be resume_skip",
        )?;
    }

    let Some(resumed) = rows.get(expected_resume_index) else {
        return Err("resume row at expected index must exist".to_owned());
    };
    require(
        json_string(resumed, "gate_name")? == "e2e",
        "resume should restart at e2e gate index",
    )?;
    require(
        json_string(resumed, "status")? == "pass",
        "resume should execute failed gate successfully after clearing failure env",
    )
}
