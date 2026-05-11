//! Observability dashboard completion-debt contract tests (bd-282v / bd-282v.1).

use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const REQUIRED_SOURCE_IDS: &[&str] = &[
    "dashboard_aggregator",
    "dashboard_writer",
    "dashboard_capture_pipeline",
    "dashboard_unit_test",
    "allocator_jsonl_export",
    "cli_capture_command",
    "dashboard_e2e_test",
];
const REQUIRED_BINDINGS: &[(&str, &str)] = &[
    ("unit_primary", "tests.unit.primary"),
    ("e2e_primary", "tests.e2e.primary"),
    ("telemetry_primary", "telemetry.primary"),
];
const REQUIRED_EVENTS: &[&str] = &[
    "observability_dashboard_source_bound",
    "observability_dashboard_test_binding_bound",
    "observability_dashboard_telemetry_bound",
    "observability_dashboard_completion_contract_summary",
];
const REQUIRED_LOG_FIELDS: &[&str] = &[
    "timestamp",
    "trace_id",
    "event",
    "bead_id",
    "completion_debt_bead",
    "artifact_id",
    "artifact_path",
    "missing_item_id",
    "evidence_kind",
    "source_line_ref",
    "status",
    "artifact_refs",
    "failure_signature",
];

fn test_error(message: impl Into<String>) -> Box<dyn std::error::Error> {
    Box::new(std::io::Error::other(message.into()))
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
    root.join("tests/conformance/observability_dashboard_completion_contract.v1.json")
}

fn load_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
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
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| test_error(format!("system clock should be after Unix epoch: {err}")))?
        .as_nanos();
    let path = root
        .join("target/conformance")
        .join(format!("{prefix}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn string_field<'a>(value: &'a Value, field: &str) -> TestResult<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| test_error(format!("missing string field {field}")))
}

fn array_field<'a>(value: &'a Value, field: &str) -> TestResult<&'a Vec<Value>> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| test_error(format!("missing array field {field}")))
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<std::process::Output> {
    Ok(Command::new("bash")
        .arg(root.join("scripts/check_observability_dashboard_completion_contract.sh"))
        .current_dir(root)
        .env("FRANKENLIBC_OBSERVABILITY_DASHBOARD_CONTRACT", contract)
        .env("FRANKENLIBC_OBSERVABILITY_DASHBOARD_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_OBSERVABILITY_DASHBOARD_REPORT",
            out_dir.join("observability_dashboard_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_OBSERVABILITY_DASHBOARD_LOG",
            out_dir.join("observability_dashboard_completion_contract.log.jsonl"),
        )
        .output()?)
}

fn assert_success(output: &std::process::Output) {
    assert!(
        output.status.success(),
        "checker should pass\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_failure(output: &std::process::Output, expected_stderr: &str) {
    assert!(
        !output.status.success(),
        "checker should fail\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(expected_stderr),
        "stderr should contain {expected_stderr:?}\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn function_exists(source: &str, name: &str) -> bool {
    source.contains(&format!("fn {name}(")) || source.contains(&format!("fn {name}<"))
}

#[test]
fn manifest_binds_observability_dashboard_completion_debt() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    assert_eq!(string_field(&manifest, "schema_version")?, "v1");
    assert_eq!(
        string_field(&manifest, "manifest_id")?,
        "observability-dashboard-completion-contract"
    );
    assert_eq!(string_field(&manifest, "bead")?, "bd-282v");
    assert_eq!(
        string_field(&manifest, "completion_debt_bead")?,
        "bd-282v.1"
    );

    let completion = manifest
        .get("completion_debt_evidence")
        .ok_or_else(|| test_error("missing completion_debt_evidence"))?;
    assert_eq!(string_field(completion, "bead")?, "bd-282v.1");
    assert_eq!(string_field(completion, "original_bead")?, "bd-282v");
    assert_eq!(
        string_field(completion, "test_source")?,
        "crates/frankenlibc-harness/tests/observability_dashboard_completion_contract_test.rs"
    );
    assert_eq!(
        string_field(completion, "checker")?,
        "scripts/check_observability_dashboard_completion_contract.sh"
    );

    for field in ["unit_primary", "e2e_primary", "telemetry_primary"] {
        let section = completion
            .get(field)
            .ok_or_else(|| test_error(format!("missing completion section {field}")))?;
        assert!(
            !array_field(section, "required_test_names")?.is_empty(),
            "{field} should bind test names"
        );
    }
    Ok(())
}

#[test]
fn source_evidence_pins_dashboard_pipeline_unit_and_e2e_paths() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let sources = array_field(&manifest, "source_evidence")?;
    let ids: BTreeSet<_> = sources
        .iter()
        .filter_map(|source| source.get("artifact_id").and_then(Value::as_str))
        .collect();

    for required in REQUIRED_SOURCE_IDS {
        assert!(ids.contains(required), "missing source artifact {required}");
    }

    for source in sources {
        let path_text = string_field(source, "path")?;
        let path = root.join(path_text);
        assert!(path.is_file(), "{} missing", path.display());
        let content = std::fs::read_to_string(&path)?;
        let line_ref = string_field(source, "line_ref")?;
        let (_, line_text) = line_ref
            .rsplit_once(':')
            .ok_or_else(|| test_error("line_ref should be file:line"))?;
        let line_number = line_text.parse::<usize>()?;
        let lines = content.lines().collect::<Vec<_>>();
        assert!(
            line_number > 0
                && line_number <= lines.len()
                && !lines[line_number - 1].trim().is_empty(),
            "{line_ref} should point at a non-empty line"
        );

        for needle in array_field(source, "required_needles")? {
            let needle = needle
                .as_str()
                .ok_or_else(|| test_error("needle should be string"))?;
            assert!(
                content.contains(needle),
                "{} missing needle {needle}",
                path.display()
            );
        }
    }
    Ok(())
}

#[test]
fn test_bindings_reference_existing_tests_and_rch_commands() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let sources = array_field(&manifest, "source_evidence")?;
    let source_map = sources
        .iter()
        .map(|source| {
            Ok((
                string_field(source, "artifact_id")?.to_string(),
                string_field(source, "path")?.to_string(),
            ))
        })
        .collect::<TestResult<std::collections::BTreeMap<_, _>>>()?;

    let bindings = array_field(&manifest, "test_bindings")?;
    let binding_pairs: BTreeSet<_> = bindings
        .iter()
        .map(|binding| {
            Ok((
                string_field(binding, "binding_id")?.to_string(),
                string_field(binding, "missing_item_id")?.to_string(),
            ))
        })
        .collect::<TestResult<BTreeSet<_>>>()?;
    for (binding_id, missing_item) in REQUIRED_BINDINGS {
        assert!(
            binding_pairs.contains(&((*binding_id).to_string(), (*missing_item).to_string())),
            "missing binding {binding_id}"
        );
    }

    for binding in bindings {
        for command in array_field(binding, "required_commands")? {
            let command = command
                .as_str()
                .ok_or_else(|| test_error("command should be string"))?;
            if command.contains("cargo ") {
                assert!(
                    command.contains("rch exec"),
                    "cargo validation must be rch-backed: {command}"
                );
            }
        }

        if let Some(refs) = binding.get("required_test_refs").and_then(Value::as_array) {
            for test_ref in refs {
                let source_id = string_field(test_ref, "source_artifact_id")?;
                let name = string_field(test_ref, "name")?;
                let source_path = source_map
                    .get(source_id)
                    .ok_or_else(|| test_error(format!("unknown source id {source_id}")))?;
                let source_text = std::fs::read_to_string(root.join(source_path))?;
                assert!(
                    function_exists(&source_text, name),
                    "{source_path} should define {name}"
                );
            }
        }
    }
    Ok(())
}

#[test]
fn checker_accepts_contract_and_emits_telemetry() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "observability-dashboard-contract-pass")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    assert_success(&output);

    let report_path = out_dir.join("observability_dashboard_completion_contract.report.json");
    let log_path = out_dir.join("observability_dashboard_completion_contract.log.jsonl");
    let report = load_json(&report_path)?;
    assert_eq!(
        string_field(&report, "schema_version")?,
        "observability_dashboard_completion_contract.report.v1"
    );
    assert_eq!(string_field(&report, "status")?, "pass");
    assert_eq!(
        report["checked_source_artifacts"].as_u64(),
        Some(REQUIRED_SOURCE_IDS.len() as u64)
    );
    assert!(
        report["checked_telemetry_outputs"].as_u64().unwrap_or(0) >= 8,
        "checker should count dashboard telemetry outputs"
    );

    let rows = load_jsonl(&log_path)?;
    let events: BTreeSet<_> = rows
        .iter()
        .filter_map(|row| row.get("event").and_then(Value::as_str))
        .collect();
    for event in REQUIRED_EVENTS {
        assert!(events.contains(event), "missing log event {event}");
    }
    for row in rows {
        for field in REQUIRED_LOG_FIELDS {
            assert!(row.get(field).is_some(), "row missing field {field}");
        }
        assert_eq!(row["bead_id"].as_str(), Some("bd-282v"));
        assert_eq!(row["completion_debt_bead"].as_str(), Some("bd-282v.1"));
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_unit_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "observability-dashboard-contract-missing-unit")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let bindings = manifest["test_bindings"]
        .as_array_mut()
        .ok_or_else(|| test_error("test_bindings should be array"))?;
    bindings.retain(|binding| binding["binding_id"].as_str() != Some("unit_primary"));

    let bad_contract = out_dir.join("missing-unit.json");
    write_json(&bad_contract, &manifest)?;
    let output = run_checker(&root, &bad_contract, &out_dir)?;
    assert_failure(&output, "test_bindings missing required binding ids");
    Ok(())
}

#[test]
fn checker_rejects_missing_telemetry_output() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "observability-dashboard-contract-missing-output")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let outputs = manifest["telemetry_contract"]["required_generated_outputs"]
        .as_array_mut()
        .ok_or_else(|| test_error("required_generated_outputs should be array"))?;
    outputs.retain(|output| output.as_str() != Some("observability_dashboard.statsd"));

    let bad_contract = out_dir.join("missing-output.json");
    write_json(&bad_contract, &manifest)?;
    let output = run_checker(&root, &bad_contract, &out_dir)?;
    assert_failure(
        &output,
        "telemetry_contract.required_generated_outputs must match dashboard output contract",
    );
    Ok(())
}

#[test]
fn checker_rejects_stale_source_needle() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "observability-dashboard-contract-stale-needle")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let sources = manifest["source_evidence"]
        .as_array_mut()
        .ok_or_else(|| test_error("source_evidence should be array"))?;
    let first = sources
        .first_mut()
        .ok_or_else(|| test_error("source_evidence should not be empty"))?;
    first["required_needles"] = json!(["missing-observability-dashboard-sentinel"]);

    let bad_contract = out_dir.join("stale-needle.json");
    write_json(&bad_contract, &manifest)?;
    let output = run_checker(&root, &bad_contract, &out_dir)?;
    assert_failure(
        &output,
        "source_evidence[dashboard_aggregator] missing needle",
    );
    Ok(())
}
