//! Contract tests for bd-32e.7.1 TSM logging completion evidence.

use std::collections::BTreeSet;
use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let crates_dir = manifest
        .parent()
        .ok_or_else(|| io::Error::other("frankenlibc-harness manifest should have a parent"))?;
    let root = crates_dir.parent().ok_or_else(|| {
        io::Error::other("frankenlibc-harness manifest should live below workspace root")
    })?;
    Ok(root.to_path_buf())
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/tsm_logging_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_tsm_logging_completion_contract.sh")
}

fn read_json(path: &Path) -> TestResult<serde_json::Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn write_json(path: &Path, value: &serde_json::Value) -> TestResult {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn read_jsonl(path: &Path) -> TestResult<Vec<serde_json::Value>> {
    std::fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}

fn string_set(value: &serde_json::Value) -> TestResult<BTreeSet<String>> {
    let array = value
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "expected array"))?;
    let mut set = BTreeSet::new();
    for item in array {
        set.insert(
            item.as_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "expected string"))?
                .to_string(),
        );
    }
    Ok(set)
}

fn unique_output_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let path = root.join("target/conformance").join(format!(
        "tsm-logging-completion-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_TSM_LOGGING_CONTRACT", contract)
        .env(
            "FRANKENLIBC_TSM_LOGGING_REPORT",
            out_dir.join("tsm_logging_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_TSM_LOGGING_LOG",
            out_dir.join("tsm_logging_completion_contract.log.jsonl"),
        )
        .output()?)
}

fn output_text(output: &Output) -> String {
    format!(
        "status={}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn assert_file_line_ref_exists(root: &Path, file_line_ref: &str) -> TestResult {
    let (path, line) = file_line_ref.rsplit_once(':').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "file-line ref should contain ':'",
        )
    })?;
    let line_no: usize = line.parse()?;
    assert!(line_no > 0, "file-line ref line must be positive");
    let full_path = root.join(path);
    assert!(
        full_path.is_file(),
        "file-line ref path should exist: {file_line_ref}"
    );
    let line_count = std::fs::read_to_string(full_path)?.lines().count();
    assert!(
        line_no <= line_count,
        "file-line ref outside file: {file_line_ref}"
    );
    Ok(())
}

fn source_texts(
    root: &Path,
    manifest: &serde_json::Value,
) -> TestResult<std::collections::BTreeMap<String, String>> {
    let sources = manifest["source_artifacts"]
        .as_object()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "source_artifacts object"))?;
    let mut texts = std::collections::BTreeMap::new();
    for (key, path) in sources {
        let path = path
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "source path string"))?;
        texts.insert(key.clone(), std::fs::read_to_string(root.join(path))?);
    }
    Ok(texts)
}

fn json_str_field_is(row: &serde_json::Value, field: &str, expected: &str) -> bool {
    row.get(field)
        .and_then(serde_json::Value::as_str)
        .is_some_and(|value| value.eq(expected))
}

#[test]
fn manifest_binds_logging_controls_fields_and_missing_items() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&contract_path(&root))?;
    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("tsm_logging_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-32e.7"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-32e.7.1")
    );
    assert!(
        manifest["audit_reference"]["score_threshold"]
            .as_u64()
            .unwrap_or(0)
            >= 800
    );

    for file_line_ref in manifest["implementation_refs"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "refs array"))?
    {
        assert_file_line_ref_exists(
            &root,
            file_line_ref
                .as_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "ref string"))?,
        )?;
    }

    let sources = source_texts(&root, &manifest)?;
    let ptr_source = sources
        .get("ptr_validator")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "ptr source"))?;
    for control in [
        "set_validation_logging_enabled",
        "clear_validation_logs",
        "export_validation_log_jsonl",
    ] {
        assert!(
            ptr_source.contains(&format!("fn {control}"))
                || ptr_source.contains(&format!("pub fn {control}")),
            "ptr validator missing logging control {control}"
        );
    }

    let logging = &manifest["logging_contract"];
    let log_fields = string_set(&logging["required_log_fields"])?;
    for field in [
        "trace_id",
        "span_id",
        "parent_span_id",
        "decision_id",
        "decision_path",
        "security_context",
        "capability_scope",
        "security_verdict",
        "stage_inputs",
        "artifact_refs",
    ] {
        assert!(log_fields.contains(field), "missing log field {field}");
        assert!(
            ptr_source.contains(&format!("{field}:")),
            "ValidationLogRow missing source field {field}"
        );
    }

    let runtime_events = string_set(&logging["required_runtime_events"])?;
    for event in [
        "validation_stage",
        "validation_transition",
        "validation_order_rewrite",
        "validation_budget_overrun",
    ] {
        assert!(runtime_events.contains(event), "missing event {event}");
        assert!(
            ptr_source.contains(&format!("\"{event}\"")),
            "ptr validator source missing event {event}"
        );
    }

    let item_ids: BTreeSet<_> = ["unit_primary", "e2e_primary", "telemetry_primary"]
        .into_iter()
        .filter_map(|section| manifest[section]["missing_item_id"].as_str())
        .collect();
    for item in [
        "tests.unit.primary",
        "tests.e2e.primary",
        "telemetry.primary",
    ] {
        assert!(item_ids.contains(item), "missing item binding {item}");
    }

    for section in ["unit_primary", "e2e_primary", "telemetry_primary"] {
        for test_ref in manifest[section]["required_test_refs"]
            .as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "test refs array"))?
        {
            let source = test_ref["source"]
                .as_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "source string"))?;
            let name = test_ref["name"]
                .as_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "name string"))?;
            let text = sources.get(source).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "test source should exist")
            })?;
            assert!(
                text.contains(&format!("fn {name}")),
                "{section} references missing test {source}::{name}"
            );
        }
    }

    Ok(())
}

#[test]
fn checker_emits_report_and_jsonl() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "pass")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report = read_json(&out_dir.join("tsm_logging_completion_contract.report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("tsm_logging_completion_contract.report.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["original_bead"].as_str(), Some("bd-32e.7"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-32e.7.1"));

    let missing_items = string_set(&report["missing_items_bound"])?;
    for item in [
        "tests.unit.primary",
        "tests.e2e.primary",
        "telemetry.primary",
    ] {
        assert!(missing_items.contains(item), "report missing item {item}");
    }
    let runtime_events = string_set(&report["required_runtime_events"])?;
    assert!(runtime_events.contains("validation_budget_overrun"));
    let log_fields = string_set(&report["required_log_fields"])?;
    assert!(log_fields.contains("decision_id"));
    assert!(log_fields.contains("security_verdict"));

    let rows = read_jsonl(&out_dir.join("tsm_logging_completion_contract.log.jsonl"))?;
    assert_eq!(rows.len(), 1, "checker should emit one telemetry row");
    let row = &rows[0];
    assert!(json_str_field_is(
        row,
        "event",
        "tsm_logging_completion_contract_validated"
    ));
    assert!(json_str_field_is(row, "completion_debt_bead", "bd-32e.7.1"));
    assert!(json_str_field_is(row, "status", "pass"));
    assert!(json_str_field_is(row, "failure_signature", "none"));
    assert!(string_set(&row["required_levels"])?.contains("error"));
    assert!(string_set(&row["required_security_verdicts"])?.contains("deny"));

    Ok(())
}

#[test]
fn checker_rejects_missing_budget_overrun_event() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "stale")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["logging_contract"]["required_runtime_events"] = serde_json::json!([
        "validation_stage",
        "validation_transition",
        "validation_order_rewrite"
    ]);
    manifest["telemetry_primary"]["required_events"] = serde_json::json!([
        "validation_stage",
        "validation_transition",
        "validation_order_rewrite",
        "tsm_logging_completion_contract_validated",
        "tsm_logging_completion_contract_failed"
    ]);
    let stale_contract = out_dir.join("stale_tsm_logging_completion_contract.v1.json");
    write_json(&stale_contract, &manifest)?;

    let output = run_checker(&root, &stale_contract, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing budget-overrun event"
    );
    let combined = output_text(&output);
    assert!(
        combined
            .contains("logging_contract.required_runtime_events missing validation_budget_overrun"),
        "checker output should name missing runtime event: {combined}"
    );

    let report = read_json(&out_dir.join("tsm_logging_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "errors array"))?
            .iter()
            .any(|item| item
                .as_str()
                .unwrap_or("")
                .contains("validation_budget_overrun")),
        "report should retain missing-event error"
    );

    let rows = read_jsonl(&out_dir.join("tsm_logging_completion_contract.log.jsonl"))?;
    assert_eq!(rows.len(), 1);
    assert!(json_str_field_is(
        &rows[0],
        "event",
        "tsm_logging_completion_contract_failed"
    ));

    Ok(())
}
