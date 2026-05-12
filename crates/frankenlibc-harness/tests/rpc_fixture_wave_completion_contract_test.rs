//! Completion-contract tests for bd-mu4lw.3 RPC fixture wave evidence.

use serde_json::Value;
use std::collections::BTreeSet;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const REQUIRED_EVENTS: &[&str] = &[
    "source_artifacts_validated",
    "child_beads_validated",
    "rpc_fixture_validated",
    "claim_realism_validated",
    "validation_commands_validated",
    "test_surfaces_validated",
    "telemetry_contract_validated",
    "rpc_fixture_wave_completion_contract_validated",
];

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
    root.join("tests/conformance/rpc_fixture_wave_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_rpc_fixture_wave_completion_contract.sh")
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
        if line.trim().is_empty() {
            continue;
        }
        rows.push(serde_json::from_str(line)?);
    }
    Ok(rows)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
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

fn field<'a>(value: &'a Value, key: &str, context: &str) -> TestResult<&'a Value> {
    value
        .get(key)
        .ok_or_else(|| test_error(format!("{context}.{key} is missing")))
}

fn string_field<'a>(value: &'a Value, key: &str, context: &str) -> TestResult<&'a str> {
    field(value, key, context)?
        .as_str()
        .ok_or_else(|| test_error(format!("{context}.{key} must be a string")))
}

fn array_field<'a>(value: &'a Value, key: &str, context: &str) -> TestResult<&'a Vec<Value>> {
    field(value, key, context)?
        .as_array()
        .ok_or_else(|| test_error(format!("{context}.{key} must be an array")))
}

fn string_set(value: &Value, key: &str, context: &str) -> TestResult<BTreeSet<String>> {
    array_field(value, key, context)?
        .iter()
        .map(|row| {
            row.as_str()
                .map(str::to_owned)
                .ok_or_else(|| test_error(format!("{context}.{key} must contain only strings")))
        })
        .collect::<Result<_, _>>()
}

fn run_checker(root: &Path, manifest: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_RPC_FIXTURE_WAVE_CONTRACT", manifest)
        .env("FRANKENLIBC_RPC_FIXTURE_WAVE_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_RPC_FIXTURE_WAVE_REPORT",
            out_dir.join("rpc_fixture_wave_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_RPC_FIXTURE_WAVE_LOG",
            out_dir.join("rpc_fixture_wave_completion_contract.events.jsonl"),
        )
        .output()?)
}

fn run_checker_with_readme(
    root: &Path,
    manifest: &Path,
    out_dir: &Path,
    readme: &Path,
) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_RPC_FIXTURE_WAVE_CONTRACT", manifest)
        .env("FRANKENLIBC_RPC_FIXTURE_WAVE_OUT_DIR", out_dir)
        .env("FRANKENLIBC_RPC_FIXTURE_WAVE_README", readme)
        .env(
            "FRANKENLIBC_RPC_FIXTURE_WAVE_REPORT",
            out_dir.join("rpc_fixture_wave_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_RPC_FIXTURE_WAVE_LOG",
            out_dir.join("rpc_fixture_wave_completion_contract.events.jsonl"),
        )
        .output()?)
}

fn checker_report(out_dir: &Path) -> PathBuf {
    out_dir.join("rpc_fixture_wave_completion_contract.report.json")
}

fn checker_log(out_dir: &Path) -> PathBuf {
    out_dir.join("rpc_fixture_wave_completion_contract.events.jsonl")
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
fn contract_binds_rpc_fixture_wave_sources() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    assert_eq!(
        string_field(&manifest, "schema_version", "manifest")?,
        "rpc_fixture_wave_completion_contract.v1"
    );
    assert_eq!(
        string_field(&manifest, "bead_id", "manifest")?,
        "bd-mu4lw.3"
    );
    assert_eq!(string_field(&manifest, "epic_id", "manifest")?, "bd-mu4lw");

    let artifacts: BTreeSet<_> = array_field(&manifest, "source_artifacts", "manifest")?
        .iter()
        .filter_map(|row| row.get("id").and_then(Value::as_str))
        .collect();
    for required in [
        "beads_ledger",
        "fixture_coverage_prioritizer",
        "rpc_fixture",
        "fixture_executor",
        "rpc_fixture_harness_test",
        "readme_claim_surface",
        "support_matrix",
        "artifact_precedence_manifest",
        "artifact_precedence_gate",
        "artifact_precedence_test",
        "completion_contract",
        "completion_gate",
        "completion_harness_test",
    ] {
        assert!(artifacts.contains(required), "missing artifact {required}");
    }

    let completion = field(&manifest, "completion_contract", "manifest")?;
    let child_beads = string_set(completion, "closed_child_beads", "completion_contract")?;
    assert!(child_beads.contains("bd-mu4lw.1"));
    assert!(child_beads.contains("bd-mu4lw.2"));

    let symbols = string_set(
        completion,
        "required_first_wave_symbols",
        "completion_contract",
    )?;
    assert_eq!(symbols.len(), 12);
    assert!(symbols.contains("__rpc_thread_createerr"));
    assert!(symbols.contains("authnone_create"));

    let modes = string_set(completion, "required_modes", "completion_contract")?;
    assert_eq!(
        modes,
        BTreeSet::from(["hardened".to_string(), "strict".to_string()])
    );
    Ok(())
}

#[test]
fn checker_accepts_rpc_fixture_wave_completion_contract() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "rpc-fixture-wave-check")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    expect_checker_success(&output)?;

    let report = load_json(&checker_report(&out_dir))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("rpc_fixture_wave_completion_contract.report.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(
        report["summary"]["rpc_first_wave_symbol_count"].as_u64(),
        Some(12)
    );
    assert_eq!(report["summary"]["required_mode_count"].as_u64(), Some(2));
    for check in [
        "source_artifacts",
        "child_beads",
        "rpc_fixture",
        "claim_realism",
        "validation_commands",
        "test_surfaces",
        "telemetry",
    ] {
        assert_eq!(
            report["checks"][check].as_str(),
            Some("pass"),
            "check {check} should pass"
        );
    }
    Ok(())
}

#[test]
fn checker_emits_structured_rpc_completion_telemetry() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "rpc-fixture-wave-log")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    expect_checker_success(&output)?;

    let rows = load_jsonl(&checker_log(&out_dir))?;
    let events: BTreeSet<_> = rows
        .iter()
        .filter_map(|row| row.get("event").and_then(Value::as_str))
        .collect();
    for required in REQUIRED_EVENTS {
        assert!(
            events.contains(required),
            "missing telemetry event {required}"
        );
    }
    for row in rows {
        assert_eq!(row["bead_id"].as_str(), Some("bd-mu4lw.3"));
        assert!(
            row["trace_id"]
                .as_str()
                .unwrap_or_default()
                .contains("bd-mu4lw.3")
        );
        assert!(row["source_commit"].as_str().is_some());
        assert!(row["target_dir"].as_str().is_some());
        assert!(row["failure_signature"].as_str().is_some());
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_rpc_fixture_symbol() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let symbols = manifest["completion_contract"]["required_first_wave_symbols"]
        .as_array_mut()
        .ok_or_else(|| test_error("required_first_wave_symbols should be mutable array"))?;
    symbols.retain(|value| value.as_str() != Some("authnone_create"));
    symbols.push(Value::String(
        "missing_rpc_symbol_for_negative_test".to_string(),
    ));

    let out_dir = unique_output_dir(&root, "rpc-fixture-wave-missing-symbol")?;
    let manifest_fixture = out_dir.join("missing-symbol.contract.json");
    write_json(&manifest_fixture, &manifest)?;
    let output = run_checker(&root, &manifest_fixture, &out_dir)?;
    expect_checker_failure(&output)?;

    let report = load_json(&checker_report(&out_dir))?;
    assert!(failure_signatures(&report).contains("rpc_fixture_symbol_coverage"));
    Ok(())
}

#[test]
fn checker_rejects_stale_rpc_readme_stub_wording() -> TestResult {
    let root = workspace_root()?;
    let readme = std::fs::read_to_string(root.join("README.md"))?;
    let bad_readme = readme.replace(
        "| `rpc_abi.rs` | Native XDR plus deterministic legacy RPC safe defaults |",
        "| `rpc_abi.rs` | RPC function stubs |",
    );

    let out_dir = unique_output_dir(&root, "rpc-fixture-wave-bad-readme")?;
    let readme_fixture = out_dir.join("README.bad-rpc-stub.md");
    std::fs::write(&readme_fixture, bad_readme)?;
    let output = run_checker_with_readme(&root, &manifest_path(&root), &out_dir, &readme_fixture)?;
    expect_checker_failure(&output)?;

    let report = load_json(&checker_report(&out_dir))?;
    assert!(failure_signatures(&report).contains("readme_rpc_stub_claim"));
    Ok(())
}

#[test]
fn checker_rejects_non_rch_cargo_validation_command() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let commands = manifest["completion_contract"]["runtime_validation"]
        .as_array_mut()
        .ok_or_else(|| test_error("runtime_validation should be mutable array"))?;
    for command in commands {
        if command.as_str().unwrap_or_default().contains(
            "cargo test -p frankenlibc-harness --test rpc_fixture_wave_completion_contract_test",
        ) {
            *command = Value::String(
                "cargo test -p frankenlibc-harness --test rpc_fixture_wave_completion_contract_test -- --nocapture"
                    .to_string(),
            );
            break;
        }
    }

    let out_dir = unique_output_dir(&root, "rpc-fixture-wave-local-cargo")?;
    let manifest_fixture = out_dir.join("local-cargo.contract.json");
    write_json(&manifest_fixture, &manifest)?;
    let output = run_checker(&root, &manifest_fixture, &out_dir)?;
    expect_checker_failure(&output)?;

    let report = load_json(&checker_report(&out_dir))?;
    assert!(failure_signatures(&report).contains("non_rch_validation_command"));
    Ok(())
}

#[test]
fn checker_rejects_missing_required_telemetry_event() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let events = manifest["completion_contract"]["required_telemetry_events"]
        .as_array_mut()
        .ok_or_else(|| test_error("required_telemetry_events should be mutable array"))?;
    events.retain(|value| value.as_str() != Some("claim_realism_validated"));

    let out_dir = unique_output_dir(&root, "rpc-fixture-wave-missing-event")?;
    let manifest_fixture = out_dir.join("missing-event.contract.json");
    write_json(&manifest_fixture, &manifest)?;
    let output = run_checker(&root, &manifest_fixture, &out_dir)?;
    expect_checker_failure(&output)?;

    let report = load_json(&checker_report(&out_dir))?;
    assert!(failure_signatures(&report).contains("missing_telemetry_event"));
    Ok(())
}
