//! Completion-contract tests for bd-3rw.4.1 API/support docs evidence.

use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn test_error(message: impl Into<String>) -> Box<dyn Error> {
    std::io::Error::other(message.into()).into()
}

fn workspace_root() -> TestResult<PathBuf> {
    Ok(Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| test_error("crate manifest should have crates parent"))?
        .parent()
        .ok_or_else(|| test_error("crates directory should have workspace parent"))?
        .to_path_buf())
}

fn manifest_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/api_support_docs_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_api_support_docs_completion_contract.sh")
}

fn load_json(path: &Path) -> TestResult<Value> {
    let content = std::fs::read_to_string(path)
        .map_err(|err| test_error(format!("{} should be readable: {err}", path.display())))?;
    serde_json::from_str(&content)
        .map_err(|err| test_error(format!("{} should parse as JSON: {err}", path.display())))
}

fn load_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    let mut rows = Vec::new();
    for line in std::fs::read_to_string(path)?.lines() {
        if !line.trim().is_empty() {
            rows.push(serde_json::from_str(line)?);
        }
    }
    Ok(rows)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, format!("{}\n", serde_json::to_string_pretty(value)?))?;
    Ok(())
}

fn unique_output_dir(root: &Path, prefix: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| test_error(format!("system clock should be after Unix epoch: {err}")))?
        .as_nanos();
    let path = root
        .join("target/conformance")
        .join(format!("{prefix}-{}-{stamp}", std::process::id()));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn array_field<'a>(value: &'a Value, key: &str, context: &str) -> TestResult<&'a Vec<Value>> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| test_error(format!("{context}.{key} must be an array")))
}

fn object_field<'a>(
    value: &'a Value,
    key: &str,
    context: &str,
) -> TestResult<&'a serde_json::Map<String, Value>> {
    value
        .get(key)
        .and_then(Value::as_object)
        .ok_or_else(|| test_error(format!("{context}.{key} must be an object")))
}

fn string_set(value: &Value, key: &str, context: &str) -> TestResult<BTreeSet<String>> {
    array_field(value, key, context)?
        .iter()
        .map(|row| {
            row.as_str()
                .map(str::to_owned)
                .ok_or_else(|| test_error(format!("{context}.{key} must contain strings")))
        })
        .collect::<Result<_, _>>()
}

fn run_checker(
    root: &Path,
    manifest: &Path,
    out_dir: &Path,
    skip_base: bool,
) -> TestResult<Output> {
    let mut command = Command::new("bash");
    command
        .arg(checker_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_API_SUPPORT_DOCS_COMPLETION_CONTRACT", manifest)
        .env("FRANKENLIBC_API_SUPPORT_DOCS_COMPLETION_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_API_SUPPORT_DOCS_COMPLETION_REPORT",
            out_dir.join("api_support_docs_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_API_SUPPORT_DOCS_COMPLETION_LOG",
            out_dir.join("api_support_docs_completion_contract.log.jsonl"),
        );
    if skip_base {
        command.env("FRANKENLIBC_API_SUPPORT_DOCS_SKIP_BASE_GATES", "1");
    }
    Ok(command.output()?)
}

fn checker_report(out_dir: &Path) -> PathBuf {
    out_dir.join("api_support_docs_completion_contract.report.json")
}

fn checker_log(out_dir: &Path) -> PathBuf {
    out_dir.join("api_support_docs_completion_contract.log.jsonl")
}

fn expect_checker_success(output: &Output) -> TestResult {
    if output.status.success() {
        return Ok(());
    }
    Err(test_error(format!(
        "checker failed stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )))
}

fn expect_checker_failure(output: &Output) -> TestResult {
    if !output.status.success() {
        return Ok(());
    }
    Err(test_error(format!(
        "checker unexpectedly passed stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )))
}

fn write_mutated_manifest(
    root: &Path,
    prefix: &str,
    manifest: &Value,
) -> TestResult<(PathBuf, PathBuf)> {
    let out_dir = unique_output_dir(root, prefix)?;
    let path = out_dir.join("manifest.json");
    write_json(&path, manifest)?;
    Ok((path, out_dir))
}

fn failure_signatures(report: &Value) -> BTreeSet<&str> {
    report
        .get("errors")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|row| row.get("failure_signature").and_then(Value::as_str))
        .collect()
}

#[test]
fn manifest_binds_api_support_docs_completion_evidence() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("api_support_docs_completion_contract.v1")
    );
    assert_eq!(manifest["bead_id"].as_str(), Some("bd-3rw.4.1"));
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-3rw.4"));

    let sources = object_field(&manifest, "source_artifacts", "manifest")?;
    for required in [
        "docs_env_generator",
        "docs_env_gate",
        "docs_source_map",
        "docs_source_trace",
        "docs_semantic_gate",
        "support_matrix",
        "support_matrix_maintenance_gate",
        "support_matrix_universe_gate",
        "symbol_fixture_coverage",
        "fuzz_phase1_completion_gate",
        "completion_gate",
        "completion_harness_test",
    ] {
        let path = sources
            .get(required)
            .and_then(Value::as_str)
            .ok_or_else(|| test_error(format!("missing source artifact {required}")))?;
        assert!(
            root.join(path).is_file(),
            "source artifact {required} missing at {path}"
        );
    }

    let api = &manifest["api_surface_contract"];
    assert_eq!(api["surface_id"].as_str(), Some("API"));
    assert_eq!(api["future_target_path"].as_str(), Some("API.md"));
    let required_sections: BTreeSet<_> =
        array_field(api, "required_sections", "api_surface_contract")?
            .iter()
            .filter_map(|row| row["section_id"].as_str())
            .collect();
    assert_eq!(
        required_sections,
        BTreeSet::from(["classification-and-parity", "fixture-and-traceability"])
    );

    let binding_ids: BTreeSet<_> = array_field(&manifest, "missing_item_bindings", "manifest")?
        .iter()
        .filter_map(|binding| binding["missing_item_id"].as_str())
        .collect();
    assert_eq!(
        binding_ids,
        BTreeSet::from([
            "telemetry.primary",
            "tests.conformance.primary",
            "tests.e2e.primary",
            "tests.fuzz.primary",
            "tests.unit.primary",
        ])
    );

    for binding in array_field(&manifest, "missing_item_bindings", "manifest")? {
        for command in array_field(binding, "required_commands", "missing_item_bindings[]")? {
            let command = command
                .as_str()
                .ok_or_else(|| test_error("command string"))?;
            assert!(
                !command.contains(" cargo ")
                    || command.contains("rch cargo ")
                    || command.contains("rch exec -- cargo "),
                "cargo command must be routed through rch: {command}"
            );
        }
    }

    let tests = &manifest["required_test_functions"];
    assert!(
        tests
            .get("crates/frankenlibc-harness/tests/api_support_docs_completion_contract_test.rs")
            .is_some()
    );
    assert!(
        string_set(
            &manifest["telemetry_contract"],
            "required_events",
            "telemetry_contract"
        )?
        .contains("api_support_docs_completion_contract_validated")
    );
    Ok(())
}

#[test]
fn checker_accepts_contract_and_emits_report_log() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "api-support-docs-pass")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir, false)?;
    expect_checker_success(&output)?;

    let report = load_json(&checker_report(&out_dir))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["bead_id"].as_str(), Some("bd-3rw.4.1"));
    assert_eq!(report["original_bead"].as_str(), Some("bd-3rw.4"));
    assert_eq!(report["summary"]["binding_count"].as_u64(), Some(5));
    assert!(
        report["base_gate_results"].as_array().map_or(0, Vec::len) >= 5,
        "checker should replay all base gates"
    );

    let rows = load_jsonl(&checker_log(&out_dir))?;
    let events: BTreeSet<_> = rows
        .iter()
        .filter_map(|row| row.get("event").and_then(Value::as_str))
        .collect();
    for expected in [
        "api_support_docs_sources_validated",
        "api_support_docs_surface_bindings_validated",
        "api_support_docs_base_gates_validated",
        "api_support_docs_completion_contract_validated",
    ] {
        assert!(events.contains(expected), "missing event {expected}");
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_api_surface_binding() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["api_surface_contract"]["surface_id"] = json!("MISSING_API_SURFACE");
    let (path, out_dir) = write_mutated_manifest(&root, "missing-api-surface", &manifest)?;
    let output = run_checker(&root, &path, &out_dir, true)?;
    expect_checker_failure(&output)?;
    let report = load_json(&checker_report(&out_dir))?;
    assert!(failure_signatures(&report).contains("api_surface_contract_failed"));
    Ok(())
}

#[test]
fn checker_rejects_bare_cargo_command() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let commands = manifest["missing_item_bindings"][0]["required_commands"]
        .as_array_mut()
        .ok_or_else(|| test_error("required_commands should be an array"))?;
    commands.push(json!(
        "cargo test -p frankenlibc-harness --test api_support_docs_completion_contract_test"
    ));
    let (path, out_dir) = write_mutated_manifest(&root, "bare-cargo", &manifest)?;
    let output = run_checker(&root, &path, &out_dir, true)?;
    expect_checker_failure(&output)?;
    let report = load_json(&checker_report(&out_dir))?;
    assert!(failure_signatures(&report).contains("bare_cargo_command"));
    Ok(())
}

#[test]
fn checker_rejects_missing_required_event() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let events = manifest["telemetry_contract"]["required_events"]
        .as_array_mut()
        .ok_or_else(|| test_error("required_events should be an array"))?;
    events.retain(|event| event.as_str() != Some("api_support_docs_completion_contract_validated"));
    let (path, out_dir) = write_mutated_manifest(&root, "missing-event", &manifest)?;
    let output = run_checker(&root, &path, &out_dir, true)?;
    expect_checker_failure(&output)?;
    let report = load_json(&checker_report(&out_dir))?;
    assert!(failure_signatures(&report).contains("telemetry_contract_failed"));
    Ok(())
}
