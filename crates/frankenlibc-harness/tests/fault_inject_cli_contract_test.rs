//! Conformance gate for the harness binary `fault-inject` subcommand.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

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
        .join("fault_inject_cli_contract.v1.json")
}

fn catalog_path(root: &Path) -> PathBuf {
    root.join("tests")
        .join("conformance")
        .join("fault_injection_scenarios.v1.yaml")
}

fn load_json(path: &Path) -> TestResult<Value> {
    let content = std::fs::read_to_string(path).map_err(|err| format!("read {path:?}: {err}"))?;
    serde_json::from_str(&content).map_err(|err| format!("parse {path:?}: {err}"))
}

fn load_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    let content = std::fs::read_to_string(path).map_err(|err| format!("read {path:?}: {err}"))?;
    content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).map_err(|err| format!("parse jsonl: {err}")))
        .collect()
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
    if let Some(bin) = option_env!("CARGO_BIN_EXE_harness") {
        return Some(PathBuf::from(bin));
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

fn unique_tmp_dir(stem: &str) -> TestResult<PathBuf> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("clock: {e}"))?
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "fault_inject_cli_{stem}_{}_{ts}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir {dir:?}: {e}"))?;
    Ok(dir)
}

fn run_fault_inject_cli(bin: &Path, dir: &Path) -> TestResult<std::process::Output> {
    let root = workspace_root()?;
    Command::new(bin)
        .arg("fault-inject")
        .arg("--manifest")
        .arg(catalog_path(&root))
        .arg("--scenario")
        .arg("memory.oom_budget")
        .arg("--out-dir")
        .arg(dir.join("out"))
        .arg("--report")
        .arg(dir.join("fault.report.json"))
        .arg("--log")
        .arg(dir.join("fault.log.jsonl"))
        .arg("--artifact-index")
        .arg(dir.join("fault.artifacts.json"))
        .arg("--mode")
        .arg("both")
        .arg("--fail-on-mismatch")
        .output()
        .map_err(|e| format!("spawn harness fault-inject: {e}"))
}

#[test]
fn manifest_anchors_to_fault_inject_subcommand() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "fault-inject-cli-contract",
        "manifest_id mismatch",
    )?;
    require(json_string(&m, "bead")? == "bd-3fil", "bead mismatch")?;
    require(
        json_string(&m, "subcommand_name")? == "fault-inject",
        "subcommand_name mismatch",
    )?;
    require(
        json_string(&m, "canonical_manifest_path")?
            == "tests/conformance/fault_injection_scenarios.v1.yaml",
        "canonical manifest path mismatch",
    )?;
    require(
        json_string(&m, "io_pattern")?
            == "yaml_or_json_manifest_to_json_report_plus_structured_jsonl_log_plus_artifact_index",
        "io_pattern mismatch",
    )
}

#[test]
fn manifest_policy_pins_required_invariants() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    let policy = m.get("policy").ok_or("missing policy")?;
    for key in [
        "must_load_canonical_fault_catalog",
        "must_create_parent_directories_for_outputs",
        "must_write_report_log_and_artifact_index",
        "must_record_manifest_as_artifact_when_manifest_path_exists",
        "must_emit_one_structured_log_row_per_executed_case",
        "must_preserve_strict_and_hardened_mode_rows_for_mode_both",
        "unknown_scenario_must_fail_closed",
        "fail_on_mismatch_must_exit_nonzero_when_failures_present",
    ] {
        require(json_bool(policy, key)?, key)?;
    }
    Ok(())
}

#[test]
fn canonical_fault_catalog_remains_pinned() -> TestResult {
    let root = workspace_root()?;
    let body = std::fs::read_to_string(catalog_path(&root)).map_err(|e| format!("read: {e}"))?;
    for needle in [
        "manifest_id: bd-3fil-franken-fault-catalog",
        "id: memory.oom_budget",
        "domain: memory",
        "strict:",
        "hardened:",
        "classification: OutOfMemoryInjected",
    ] {
        require(body.contains(needle), needle)?;
    }
    Ok(())
}

#[test]
fn harness_source_registers_fault_inject_subcommand() -> TestResult {
    let root = workspace_root()?;
    let src = std::fs::read_to_string(root.join("crates/frankenlibc-harness/src/bin/harness.rs"))
        .map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        src.contains("FaultInject {"),
        "harness.rs must declare FaultInject Command variant",
    )?;
    require(
        src.contains("fault_injection::FaultManifest::from_path"),
        "FaultInject arm must load the fault manifest",
    )?;
    require(
        src.contains("fault_injection::run_manifest_with_default_executor"),
        "FaultInject arm must execute the default fault runner",
    )?;
    require(
        src.contains("fail_on_mismatch && fault_report.summary.failed > 0"),
        "FaultInject arm must fail closed when --fail-on-mismatch sees failed cases",
    )
}

#[test]
fn cli_writes_report_log_and_artifact_index_for_single_scenario() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let dir = unique_tmp_dir("ok")?;
    let out = run_fault_inject_cli(&bin, &dir)?;
    require(
        out.status.success(),
        format!(
            "fault-inject failed: status={:?} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ),
    )?;

    for (label, artifact) in [
        ("report", dir.join("fault.report.json")),
        ("log", dir.join("fault.log.jsonl")),
        ("artifact index", dir.join("fault.artifacts.json")),
    ] {
        require(artifact.exists(), label)?;
    }

    let report = load_json(&dir.join("fault.report.json"))?;
    require(
        json_string(&report, "schema_version")? == "v1",
        "report schema_version",
    )?;
    require(json_string(&report, "bead")? == "bd-3fil", "report bead")?;
    require(
        json_string(&report, "manifest_id")? == "bd-3fil-franken-fault-catalog",
        "report manifest_id",
    )?;
    require(
        json_string(&report, "scenario_filter")? == "memory.oom_budget",
        "scenario_filter",
    )?;

    let summary = report.get("summary").ok_or("missing summary")?;
    require(json_u64(summary, "scenario_count")? == 1, "scenario_count")?;
    require(json_u64(summary, "total_cases")? == 4, "total_cases")?;
    require(json_u64(summary, "failed")? == 0, "failed")?;
    require(
        json_u64(summary, "false_negatives")? == 0,
        "false_negatives",
    )?;
    require(
        summary
            .get("by_mode")
            .and_then(|v| v.get("strict"))
            .and_then(Value::as_u64)
            == Some(2),
        "strict mode count",
    )?;
    require(
        summary
            .get("by_mode")
            .and_then(|v| v.get("hardened"))
            .and_then(Value::as_u64)
            == Some(2),
        "hardened mode count",
    )
}

#[test]
fn cli_log_and_artifact_index_expose_joinable_fault_evidence() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        return Ok(());
    };
    let dir = unique_tmp_dir("join")?;
    let out = run_fault_inject_cli(&bin, &dir)?;
    require(
        out.status.success(),
        format!(
            "fault-inject failed: status={:?} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ),
    )?;

    let rows = load_jsonl(&dir.join("fault.log.jsonl"))?;
    require(rows.len() == 4, "single scenario must emit four log rows")?;
    let modes: BTreeSet<&str> = rows
        .iter()
        .filter_map(|row| row.get("mode").and_then(Value::as_str))
        .collect();
    require(modes.contains("strict"), "missing strict log row")?;
    require(modes.contains("hardened"), "missing hardened log row")?;
    for row in &rows {
        require(
            row.get("event").and_then(Value::as_str) == Some("fault_injection"),
            "log event must be fault_injection",
        )?;
        require(
            row.get("gate").and_then(Value::as_str) == Some("fault_injection"),
            "log gate must be fault_injection",
        )?;
        require(
            row.get("scenario_id").and_then(Value::as_str) == Some("memory.oom_budget"),
            "log scenario_id must be memory.oom_budget",
        )?;
        require(
            row.get("outcome").and_then(Value::as_str) == Some("pass"),
            "log outcome must be pass",
        )?;
    }

    let artifact_index = load_json(&dir.join("fault.artifacts.json"))?;
    let artifacts = artifact_index
        .get("artifacts")
        .and_then(Value::as_array)
        .ok_or("artifact index missing artifacts")?;
    for kind in ["log", "report", "manifest"] {
        require(
            artifacts
                .iter()
                .any(|artifact| artifact.get("kind").and_then(Value::as_str) == Some(kind)),
            kind,
        )?;
    }
    require(
        artifacts.iter().any(|artifact| {
            artifact
                .get("join_keys")
                .and_then(|v| v.get("trace_ids"))
                .and_then(Value::as_array)
                .is_some_and(|ids| ids.len() == 4)
        }),
        "artifact index must expose four trace join keys",
    )
}

#[test]
fn cli_unknown_scenario_fails_closed() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        return Ok(());
    };
    let root = workspace_root()?;
    let dir = unique_tmp_dir("bad_scenario")?;
    let out = Command::new(&bin)
        .arg("fault-inject")
        .arg("--manifest")
        .arg(catalog_path(&root))
        .arg("--scenario")
        .arg("memory.no_such_fault")
        .arg("--out-dir")
        .arg(dir.join("out"))
        .arg("--report")
        .arg(dir.join("bad.report.json"))
        .arg("--log")
        .arg(dir.join("bad.log.jsonl"))
        .arg("--artifact-index")
        .arg(dir.join("bad.artifacts.json"))
        .output()
        .map_err(|e| format!("spawn harness fault-inject: {e}"))?;
    require(!out.status.success(), "unknown scenario must fail closed")?;
    let diagnostic = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    require(
        diagnostic.contains("memory.no_such_fault"),
        "unknown scenario failure must name the missing scenario",
    )
}
