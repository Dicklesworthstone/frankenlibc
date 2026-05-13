//! Conformance gate for the harness binary `explain-dossier`
//! subcommand (bd-hk1t2).

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
        .join("explain_dossier_cli_contract.v1.json")
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
    let p = std::env::temp_dir().join(format!("bd_hk1t2_{stem}_{}_{ts}", std::process::id()));
    std::fs::create_dir_all(&p).map_err(|e| format!("mkdir {p:?}: {e}"))?;
    Ok(p)
}

#[test]
fn manifest_anchors_to_hk1t2_with_subcommand_name() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "explain-dossier-cli-contract",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-hk1t2", "bead")?;
    require(
        json_string(&m, "subcommand_name")? == "explain-dossier",
        "subcommand_name",
    )
}

#[test]
fn manifest_policy_pins_required_invariants() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    let policy = m
        .get("policy")
        .ok_or_else(|| "missing policy".to_string())?;
    for f in [
        "must_emit_exactly_one_jsonl_record_on_jsonl_path",
        "must_write_markdown_starting_with_dossier_header",
        "fail_closed_when_expected_commit_not_40_char_sha",
        "fail_closed_on_load_error",
        "fail_closed_on_dossier_error",
        "all_five_evidence_rows_present_when_success",
    ] {
        require(json_bool(policy, f)?, format!("{f} must be true"))?;
    }
    Ok(())
}

#[test]
fn harness_source_registers_explain_dossier_subcommand() -> TestResult {
    let root = workspace_root()?;
    let src = std::fs::read_to_string(root.join("crates/frankenlibc-harness/src/bin/harness.rs"))
        .map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        src.contains("ExplainDossier {"),
        "harness.rs must declare ExplainDossier Command variant",
    )?;
    require(
        src.contains("explain_dossier::{")
            && src.contains("build_dossier")
            && src.contains("load_dossier_inputs_from_disk")
            && src.contains("render_markdown"),
        "main() must import build_dossier + load_dossier_inputs_from_disk + render_markdown",
    )?;
    require(
        src.contains("\"kind\": \"dossier\""),
        "ExplainDossier arm must emit kind=dossier",
    )
}

fn run_cli(
    bin: &Path,
    workspace_root: &Path,
    expected_commit: &str,
    output_markdown: &Path,
    output_jsonl: &Path,
) -> TestResult<std::process::Output> {
    Command::new(bin)
        .arg("explain-dossier")
        .arg("--workspace-root")
        .arg(workspace_root)
        .arg("--expected-commit")
        .arg(expected_commit)
        .arg("--output-markdown")
        .arg(output_markdown)
        .arg("--output-jsonl")
        .arg(output_jsonl)
        .output()
        .map_err(|e| format!("spawn: {e}"))
}

#[test]
fn cli_fails_closed_on_non_sha_expected_commit() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let ws = unique_tmp_dir("bad_sha")?;
    let md = ws.join("out.md");
    let jl = ws.join("out.jsonl");
    let out = run_cli(&bin, &ws, "not-a-sha", &md, &jl)?;
    let _ = std::fs::remove_dir_all(&ws);
    require(
        !out.status.success(),
        "non-sha --expected-commit must cause non-zero exit",
    )?;
    require(
        String::from_utf8_lossy(&out.stderr).contains("must be a 40-char ascii-hex SHA"),
        "stderr must explain SHA format requirement",
    )
}

#[test]
fn cli_fails_closed_on_missing_evidence_files() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let ws = unique_tmp_dir("empty_ws")?;
    let md = ws.join("out.md");
    let jl = ws.join("out.jsonl");
    // 40-char SHA but no evidence files in workspace.
    let sha = "1".repeat(40);
    let out = run_cli(&bin, &ws, &sha, &md, &jl)?;
    let _ = std::fs::remove_dir_all(&ws);
    require(
        !out.status.success(),
        "empty workspace must cause non-zero exit",
    )?;
    require(
        String::from_utf8_lossy(&out.stderr).contains("load_dossier_inputs_from_disk"),
        "stderr must surface load_dossier_inputs_from_disk failure",
    )
}

#[test]
fn cli_fails_closed_on_missing_required_flags() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let out = Command::new(&bin)
        .arg("explain-dossier")
        .output()
        .map_err(|e| format!("spawn: {e}"))?;
    require(
        !out.status.success(),
        "missing required flags must cause non-zero exit (clap-level)",
    )
}
