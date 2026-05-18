//! Conformance gate for the harness binary `traceability` subcommand.

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
        .join("traceability_cli_contract.v1.json")
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

fn json_value_string<'a>(value: &'a Value, context: &str) -> TestResult<&'a str> {
    value.as_str().ok_or_else(|| context.to_owned())
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
        "traceability_cli_contract_{stem}_{}_{ts}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir {dir:?}: {e}"))?;
    Ok(dir)
}

fn run_traceability_cli(
    bin: &Path,
    markdown_output: &Path,
    json_output: &Path,
) -> TestResult<std::process::Output> {
    let root = workspace_root()?;
    Command::new(bin)
        .arg("traceability")
        .arg("--support-matrix")
        .arg(root.join("support_matrix.json"))
        .arg("--fixture")
        .arg(root.join("tests/conformance/fixtures"))
        .arg("--conformance-matrix")
        .arg(root.join("tests/conformance/conformance_matrix.v1.json"))
        .arg("--c-fixture-spec")
        .arg(root.join("tests/conformance/c_fixture_spec.json"))
        .arg("--output-md")
        .arg(markdown_output)
        .arg("--output-json")
        .arg(json_output)
        .output()
        .map_err(|e| format!("spawn harness traceability: {e}"))
}

fn run_traceability_cli_with_support_matrix(
    bin: &Path,
    support_matrix: &Path,
    markdown_output: &Path,
    json_output: &Path,
) -> TestResult<std::process::Output> {
    let root = workspace_root()?;
    Command::new(bin)
        .arg("traceability")
        .arg("--support-matrix")
        .arg(support_matrix)
        .arg("--fixture")
        .arg(root.join("tests/conformance/fixtures"))
        .arg("--conformance-matrix")
        .arg(root.join("tests/conformance/conformance_matrix.v1.json"))
        .arg("--c-fixture-spec")
        .arg(root.join("tests/conformance/c_fixture_spec.json"))
        .arg("--output-md")
        .arg(markdown_output)
        .arg("--output-json")
        .arg(json_output)
        .output()
        .map_err(|e| format!("spawn harness traceability with support matrix override: {e}"))
}

#[test]
fn manifest_anchors_to_traceability_subcommand() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    require(
        json_string(&m, "manifest_id")? == "traceability-cli-contract",
        "manifest_id mismatch",
    )?;
    require(json_string(&m, "bead")? == "bd-2tq.4", "bead mismatch")?;
    require(
        json_string(&m, "subcommand_name")? == "traceability",
        "subcommand_name mismatch",
    )?;
    require(
        json_string(&m, "io_pattern")?
            == "support_matrix_plus_fixture_catalog_plus_conformance_matrix_plus_c_fixture_spec_to_markdown_and_json_traceability_matrix",
        "io_pattern mismatch",
    )
}

#[test]
fn manifest_policy_pins_required_invariants() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    let policy = m.get("policy").ok_or("missing policy")?;
    for key in [
        "must_create_parent_directories_for_both_outputs",
        "must_write_markdown_traceability_matrix",
        "must_write_pretty_json_traceability_matrix",
        "must_preserve_bd_2tq_4_source_report_bead",
        "must_reject_missing_support_matrix_with_nonzero_exit",
        "must_reject_unreadable_fixture_dir_with_nonzero_exit",
        "must_reject_invalid_conformance_matrix_with_nonzero_exit",
        "must_reject_missing_c_fixture_spec_with_nonzero_exit",
        "must_keep_artifact_refs_repo_relative",
        "must_emit_non_empty_entries_for_canonical_inputs",
    ] {
        require(json_bool(policy, key)?, key)?;
    }
    Ok(())
}

#[test]
fn manifest_underlying_lib_functions_are_pinned() -> TestResult {
    let root = workspace_root()?;
    let m = load_json(&manifest_path(&root))?;
    let funcs = json_array(&m, "underlying_lib_functions")?;
    for expected in [
        "frankenlibc_harness::report::PosixObligationMatrixReport::from_paths",
        "frankenlibc_harness::traceability::TraceabilityMatrix::from_posix_obligation_report",
        "frankenlibc_harness::traceability::TraceabilityMatrix::to_markdown",
        "frankenlibc_harness::traceability::TraceabilityMatrix::to_json",
    ] {
        require(funcs.iter().any(|v| v.as_str() == Some(expected)), expected)?;
    }
    Ok(())
}

#[test]
fn harness_source_registers_traceability_subcommand() -> TestResult {
    let root = workspace_root()?;
    let src = std::fs::read_to_string(root.join("crates/frankenlibc-harness/src/bin/harness.rs"))
        .map_err(|e| format!("read harness.rs: {e}"))?;
    require(
        src.contains("Traceability {"),
        "harness.rs must declare Traceability Command variant",
    )?;
    require(
        src.contains("PosixObligationMatrixReport::from_paths"),
        "Traceability arm must call PosixObligationMatrixReport::from_paths",
    )?;
    require(
        src.contains("TraceabilityMatrix::from_posix_obligation_report"),
        "Traceability arm must build TraceabilityMatrix from POSIX obligation report",
    )?;
    require(
        src.contains("std::fs::write(&output_md, matrix.to_markdown())"),
        "Traceability arm must write matrix.to_markdown()",
    )?;
    require(
        src.contains("std::fs::write(&output_json, matrix.to_json())"),
        "Traceability arm must write matrix.to_json()",
    )
}

#[test]
fn cli_writes_markdown_and_json_traceability_outputs() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let dir = unique_tmp_dir("ok")?;
    let markdown_output = dir.join("nested").join("traceability_matrix.current.md");
    let json_output = dir.join("nested").join("traceability_matrix.current.json");
    let root_prefix = format!("{}/", workspace_root()?.display());

    let out = run_traceability_cli(&bin, &markdown_output, &json_output)?;
    if !out.status.success() {
        return Err(format!(
            "traceability command failed: status={:?} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    require(
        markdown_output.exists(),
        "traceability must create markdown output",
    )?;
    require(json_output.exists(), "traceability must create JSON output")?;

    let markdown =
        std::fs::read_to_string(&markdown_output).map_err(|e| format!("read markdown: {e}"))?;
    require(
        markdown.contains("# Traceability Matrix"),
        "markdown output must contain heading",
    )?;
    require(
        markdown.contains("| Test | Symbol | Spec | Coverage | Category |"),
        "markdown output must contain traceability table header",
    )?;

    let matrix = load_json(&json_output)?;
    let entries = json_array(&matrix, "entries")?;
    require(
        !entries.is_empty(),
        "canonical inputs must produce traceability entries",
    )?;
    for entry in entries.iter().take(64) {
        for field in [
            "test_id",
            "symbol",
            "spec_section",
            "category",
            "description",
            "coverage_state",
        ] {
            require(entry.get(field).and_then(Value::as_str).is_some(), field)?;
        }
        let artifacts = json_array(entry, "artifact_refs")?;
        for artifact in artifacts {
            let artifact_ref =
                json_value_string(artifact, "artifact_refs entries must be strings")?;
            require(
                !artifact_ref.starts_with(&root_prefix),
                "artifact refs must stay repo-relative",
            )?;
        }
    }
    Ok(())
}

#[test]
fn cli_missing_support_matrix_fails_closed() -> TestResult {
    let Some(bin) = find_harness_binary() else {
        eprintln!("skip: harness binary not built in this profile");
        return Ok(());
    };
    let dir = unique_tmp_dir("missing")?;
    let markdown_output = dir.join("traceability.md");
    let json_output = dir.join("traceability.json");
    let missing_support_matrix = dir.join("missing_support_matrix.json");

    let out = run_traceability_cli_with_support_matrix(
        &bin,
        &missing_support_matrix,
        &markdown_output,
        &json_output,
    )?;
    require(!out.status.success(), "missing support matrix must fail")?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    require(
        stderr.contains("failed generating POSIX obligation report"),
        "stderr must preserve POSIX obligation report failure context",
    )?;
    require(
        stderr.contains("failed reading support matrix"),
        "stderr must preserve missing support matrix diagnostic",
    )
}
