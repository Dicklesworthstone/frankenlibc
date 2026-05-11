//! Gentoo Portage mechanics completion-debt contract (bd-2icq.2 / bd-2icq.2.1).

use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const REQUIRED_ARTIFACTS: &[&str] = &[
    "portage_workflow_refresher",
    "use_flag_matrix",
    "portage_bashrc_template",
    "ebuild_hook_implementation",
    "base_image_golden_contract",
];

const REQUIRED_EVENTS: &[&str] = &[
    "gentoo_portage_mechanics_artifact",
    "gentoo_portage_mechanics_golden",
    "gentoo_portage_mechanics_contract_summary",
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
    root.join("tests/conformance/gentoo_portage_mechanics_completion_contract.v1.json")
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

fn json_str_eq(row: &Value, field: &str, expected: &str) -> bool {
    row.get(field)
        .and_then(Value::as_str)
        .is_some_and(|actual| actual.eq(expected))
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<std::process::Output> {
    Ok(Command::new("bash")
        .arg(root.join("scripts/check_gentoo_portage_mechanics_completion_contract.sh"))
        .current_dir(root)
        .env("FRANKENLIBC_GENTOO_PORTAGE_MECHANICS_CONTRACT", contract)
        .env("FRANKENLIBC_GENTOO_PORTAGE_MECHANICS_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_GENTOO_PORTAGE_MECHANICS_REPORT",
            out_dir.join("gentoo_portage_mechanics_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_GENTOO_PORTAGE_MECHANICS_LOG",
            out_dir.join("gentoo_portage_mechanics_completion_contract.log.jsonl"),
        )
        .output()?)
}

#[test]
fn manifest_anchors_portage_mechanics_completion_debt() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    assert_eq!(string_field(&manifest, "schema_version")?, "v1");
    assert_eq!(
        string_field(&manifest, "manifest_id")?,
        "gentoo-portage-mechanics-completion-contract"
    );
    assert_eq!(string_field(&manifest, "bead")?, "bd-2icq.2");
    assert_eq!(
        string_field(&manifest, "completion_debt_bead")?,
        "bd-2icq.2.1"
    );

    let evidence = manifest
        .get("completion_debt_evidence")
        .ok_or_else(|| test_error("missing completion_debt_evidence"))?;
    assert_eq!(string_field(evidence, "bead")?, "bd-2icq.2.1");
    assert_eq!(string_field(evidence, "original_bead")?, "bd-2icq.2");
    assert_eq!(
        string_field(evidence, "test_source")?,
        "crates/frankenlibc-harness/tests/gentoo_portage_mechanics_completion_contract_test.rs"
    );
    assert_eq!(
        string_field(evidence, "checker")?,
        "scripts/check_gentoo_portage_mechanics_completion_contract.sh"
    );
    Ok(())
}

#[test]
fn source_evidence_pins_portage_docs_hooks_and_use_flags() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let sources = array_field(&manifest, "source_evidence")?;
    let ids: BTreeSet<_> = sources
        .iter()
        .filter_map(|source| source.get("artifact_id").and_then(Value::as_str))
        .collect();

    for required in REQUIRED_ARTIFACTS {
        assert!(ids.contains(required), "missing artifact {required}");
    }

    for source in sources {
        let path = root.join(string_field(source, "path")?);
        assert!(path.is_file(), "{} missing", path.display());
        let content = std::fs::read_to_string(&path)?;
        let line_ref = string_field(source, "line_ref")?;
        assert!(line_ref.contains(':'), "line_ref should be file:line");
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
fn golden_contract_pins_base_image_mechanics() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let golden_contract = manifest
        .get("golden_contract")
        .ok_or_else(|| test_error("missing golden_contract"))?;
    assert_eq!(
        string_field(golden_contract, "missing_item_id")?,
        "tests.golden.primary"
    );

    let golden = load_json(&root.join(string_field(golden_contract, "golden_file")?))?;
    for section in array_field(golden_contract, "required_sections")? {
        let section = section
            .as_str()
            .ok_or_else(|| test_error("section should be string"))?;
        assert!(golden.get(section).is_some(), "missing section {section}");
    }

    let mut paths = BTreeSet::new();
    let mut lines = Vec::new();
    for section in golden
        .as_object()
        .ok_or_else(|| test_error("golden should be object"))?
        .values()
    {
        if let Some(path) = section.get("path").and_then(Value::as_str) {
            paths.insert(path);
        }
        if let Some(required_lines) = section.get("required_lines").and_then(Value::as_array) {
            for line in required_lines {
                if let Some(line) = line.as_str() {
                    lines.push(line);
                }
            }
        }
    }

    for path in array_field(golden_contract, "required_paths")? {
        let path = path
            .as_str()
            .ok_or_else(|| test_error("required path should be string"))?;
        assert!(paths.contains(path), "missing golden path {path}");
    }
    for fragment in array_field(golden_contract, "required_line_fragments")? {
        let fragment = fragment
            .as_str()
            .ok_or_else(|| test_error("required fragment should be string"))?;
        assert!(
            lines.iter().any(|line| line.contains(fragment)),
            "missing golden line fragment {fragment}"
        );
    }
    Ok(())
}

#[test]
fn checker_accepts_contract_and_emits_telemetry() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "gentoo-portage-mechanics-ok")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    assert!(
        output.status.success(),
        "checker failed stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report =
        load_json(&out_dir.join("gentoo_portage_mechanics_completion_contract.report.json"))?;
    assert_eq!(string_field(&report, "status")?, "pass");
    assert_eq!(
        report.get("source_artifact_count").and_then(Value::as_u64),
        Some(REQUIRED_ARTIFACTS.len() as u64)
    );
    assert_eq!(
        report.get("golden_status").and_then(Value::as_str),
        Some("pass")
    );

    let rows = load_jsonl(&out_dir.join("gentoo_portage_mechanics_completion_contract.log.jsonl"))?;
    assert_eq!(rows.len(), REQUIRED_ARTIFACTS.len() + 2);
    for event in REQUIRED_EVENTS {
        assert!(
            rows.iter().any(|row| json_str_eq(row, "event", event)
                && json_str_eq(row, "status", "pass")
                && json_str_eq(row, "failure_signature", "none")),
            "missing passing telemetry event {event}"
        );
    }
    for artifact in REQUIRED_ARTIFACTS {
        assert!(
            rows.iter()
                .any(|row| json_str_eq(row, "artifact_id", artifact)
                    && json_str_eq(row, "status", "pass")),
            "missing telemetry row for {artifact}"
        );
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_golden_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "gentoo-portage-mechanics-bad-golden")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let golden_contract = manifest
        .get_mut("golden_contract")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| test_error("golden_contract should be object"))?;
    golden_contract.insert(
        "required_sections".to_string(),
        json!(["stage3", "missing_builder"]),
    );
    let bad_manifest = out_dir.join("bad_contract.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing golden section"
    );
    let report =
        load_json(&out_dir.join("gentoo_portage_mechanics_completion_contract.report.json"))?;
    let errors = array_field(&report, "errors")?;
    assert!(
        errors.iter().any(|error| error
            .as_str()
            .is_some_and(|text| text.contains("missing golden section missing_builder"))),
        "report should name missing golden section: {errors:?}"
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_telemetry_field() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "gentoo-portage-mechanics-bad-telemetry")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let fields = manifest
        .get_mut("telemetry_contract")
        .and_then(|value| value.get_mut("required_log_fields"))
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("required_log_fields should be array"))?;
    fields.retain(|field| {
        !field
            .as_str()
            .is_some_and(|actual| actual.eq("failure_signature"))
    });
    let bad_manifest = out_dir.join("bad_contract.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject telemetry field drift"
    );
    let report =
        load_json(&out_dir.join("gentoo_portage_mechanics_completion_contract.report.json"))?;
    let errors = array_field(&report, "errors")?;
    assert!(
        errors.iter().any(|error| error
            .as_str()
            .is_some_and(|text| text.contains("required_log_fields drifted"))),
        "report should name telemetry drift: {errors:?}"
    );
    Ok(())
}

#[test]
fn checker_rejects_stale_source_needle() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "gentoo-portage-mechanics-bad-needle")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let sources = manifest
        .get_mut("source_evidence")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("source_evidence should be array"))?;
    let first_source = sources
        .get_mut(0)
        .ok_or_else(|| test_error("source_evidence should not be empty"))?;
    let needles = first_source
        .get_mut("required_needles")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("required_needles should be array"))?;
    needles.push(json!("missing Portage completion debt needle"));
    let bad_manifest = out_dir.join("bad_contract.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject stale source needle"
    );
    let report =
        load_json(&out_dir.join("gentoo_portage_mechanics_completion_contract.report.json"))?;
    let errors = array_field(&report, "errors")?;
    assert!(
        errors.iter().any(|error| error
            .as_str()
            .is_some_and(|text| { text.contains("missing Portage completion debt needle") })),
        "report should name missing needle: {errors:?}"
    );
    Ok(())
}
