//! Integration test: semantic contract inventory gate (bd-bp8fl.1.1)
//!
//! Validates that the inventory seeded from support_semantic_overlay.v1.json is
//! source-linked, summary-consistent, and backed by a deterministic report/log
//! script.
//!
//! Run:
//!   cargo test -p frankenlibc-harness --test semantic_contract_inventory_test

use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn failure(message: impl Into<String>) -> Box<dyn Error> {
    io::Error::other(message.into()).into()
}

fn ensure(condition: bool, message: impl Into<String>) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(failure(message))
    }
}

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let crate_dir = Path::new(manifest)
        .parent()
        .ok_or_else(|| failure("manifest directory must have crate parent"))?;
    let root = crate_dir
        .parent()
        .ok_or_else(|| failure("crate directory must have workspace parent"))?;
    Ok(root.to_path_buf())
}

fn load_json(path: &Path) -> TestResult<serde_json::Value> {
    let content = std::fs::read_to_string(path)
        .map_err(|error| failure(format!("{} should be readable: {error}", path.display())))?;
    serde_json::from_str(&content)
        .map_err(|error| failure(format!("{} should parse as JSON: {error}", path.display())))
}

fn json_array<'a>(
    value: &'a serde_json::Value,
    context: &str,
) -> TestResult<&'a Vec<serde_json::Value>> {
    value
        .as_array()
        .ok_or_else(|| failure(format!("{context} must be an array")))
}

fn json_object<'a>(
    value: &'a serde_json::Value,
    context: &str,
) -> TestResult<&'a serde_json::Map<String, serde_json::Value>> {
    value
        .as_object()
        .ok_or_else(|| failure(format!("{context} must be an object")))
}

fn json_str<'a>(value: &'a serde_json::Value, context: &str) -> TestResult<&'a str> {
    value
        .as_str()
        .ok_or_else(|| failure(format!("{context} must be a string")))
}

#[test]
fn artifact_exists_and_has_required_shape() -> TestResult {
    let root = workspace_root()?;
    let artifact = load_json(&root.join("tests/conformance/semantic_contract_inventory.v1.json"))?;

    ensure(
        artifact["schema_version"].as_str() == Some("v1"),
        "schema_version must be v1",
    )?;
    ensure(
        artifact["bead"].as_str() == Some("bd-bp8fl.1.1"),
        "bead must be bd-bp8fl.1.1",
    )?;
    let entries = json_array(&artifact["entries"], "entries")?;
    json_object(
        &artifact["semantic_contract_classes"],
        "semantic_contract_classes",
    )?;
    json_object(&artifact["claim_policy"], "claim_policy")?;
    json_object(&artifact["summary"], "summary")?;

    ensure(
        entries.len() >= 10,
        "inventory must preserve at least the seed overlay entries",
    )?;

    for row in entries {
        let id = row["id"].as_str().unwrap_or("<missing id>");
        for field in [
            "surface",
            "symbols",
            "module",
            "source_path",
            "source_line",
            "line_marker",
            "support_matrix_status",
            "semantic_class",
            "contract_kind",
            "current_behavior",
            "user_risk",
            "required_followup",
            "evidence_artifacts",
        ] {
            ensure(!row[field].is_null(), format!("{id}: missing {field}"))?;
        }
    }

    Ok(())
}

#[test]
fn seed_overlay_entries_are_all_covered() -> TestResult {
    let root = workspace_root()?;
    let artifact = load_json(&root.join("tests/conformance/semantic_contract_inventory.v1.json"))?;
    let seed = load_json(&root.join("tests/conformance/support_semantic_overlay.v1.json"))?;

    let mut seed_ids = HashSet::new();
    for row in json_array(&seed["audited_entries"], "seed audited_entries")? {
        seed_ids.insert(json_str(&row["id"], "seed audited_entries[].id")?.to_string());
    }

    let mut inventory_seed_ids = HashSet::new();
    for row in json_array(&artifact["entries"], "artifact entries")? {
        if let Some(seed_id) = row["seed_overlay_id"].as_str() {
            inventory_seed_ids.insert(seed_id.to_string());
        }
    }

    let missing: Vec<_> = seed_ids.difference(&inventory_seed_ids).collect();
    ensure(
        missing.is_empty(),
        format!("missing seed overlay ids: {missing:?}"),
    )
}

#[test]
fn summary_counts_match_entries_and_sources_are_linked() -> TestResult {
    let root = workspace_root()?;
    let artifact = load_json(&root.join("tests/conformance/semantic_contract_inventory.v1.json"))?;
    let entries = json_array(&artifact["entries"], "artifact entries")?;
    let summary = json_object(&artifact["summary"], "artifact summary")?;

    let mut by_class: HashMap<String, u64> = HashMap::new();
    let mut by_source: HashMap<String, u64> = HashMap::new();
    let mut ids = HashSet::new();

    for row in entries {
        let id = json_str(&row["id"], "entry id")?;
        ensure(
            ids.insert(id.to_string()),
            format!("duplicate inventory id {id}"),
        )?;

        let class = json_str(&row["semantic_class"], "entry semantic_class")?;
        *by_class.entry(class.to_string()).or_insert(0) += 1;

        let source_path = json_str(&row["source_path"], "entry source_path")?;
        *by_source.entry(source_path.to_string()).or_insert(0) += 1;

        let source = root.join(source_path);
        ensure(
            source.exists(),
            format!("{id}: missing source {}", source.display()),
        )?;
        let source_text = std::fs::read_to_string(&source).map_err(|error| {
            failure(format!("{} should be readable: {error}", source.display()))
        })?;
        let marker = json_str(&row["line_marker"], "entry line_marker")?;
        ensure(
            source_text.contains(marker),
            format!(
                "{id}: source {} missing marker {marker:?}",
                source.display()
            ),
        )?;
    }

    let expected_entry_count = Some(u64::try_from(entries.len())?);
    ensure(
        summary.get("entry_count").and_then(|v| v.as_u64()) == expected_entry_count,
        "summary.entry_count mismatch",
    )?;

    let expected_by_class = serde_json::to_value(by_class)?;
    ensure(
        summary.get("by_semantic_class") == Some(&expected_by_class),
        "summary.by_semantic_class mismatch",
    )?;

    let expected_by_source = serde_json::to_value(by_source)?;
    ensure(
        summary.get("by_source_path") == Some(&expected_by_source),
        "summary.by_source_path mismatch",
    )
}

#[test]
fn gate_script_passes_and_emits_structured_report_and_log() -> TestResult {
    let root = workspace_root()?;
    let script = root.join("scripts/check_semantic_contract_inventory.sh");
    ensure(script.exists(), format!("missing {}", script.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script)
            .map_err(|error| failure(format!("{} metadata failed: {error}", script.display())))?
            .permissions();
        ensure(
            perms.mode() & 0o111 != 0,
            "check_semantic_contract_inventory.sh must be executable",
        )?;
    }

    let output = Command::new(&script)
        .current_dir(&root)
        .output()
        .map_err(|error| {
            failure(format!(
                "failed to run semantic contract inventory gate: {error}"
            ))
        })?;
    ensure(
        output.status.success(),
        format!(
            "semantic contract inventory gate failed:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        ),
    )?;

    let report_path = root.join("target/conformance/semantic_contract_inventory.report.json");
    let log_path = root.join("target/conformance/semantic_contract_inventory.log.jsonl");
    ensure(
        report_path.exists(),
        format!("missing {}", report_path.display()),
    )?;
    ensure(log_path.exists(), format!("missing {}", log_path.display()))?;

    let report = load_json(&report_path)?;
    ensure(
        report["schema_version"].as_str() == Some("v1"),
        "report schema_version must be v1",
    )?;
    ensure(
        report["bead"].as_str() == Some("bd-bp8fl.1.1"),
        "report bead must be bd-bp8fl.1.1",
    )?;
    ensure(
        report["status"].as_str() == Some("pass"),
        "report status must be pass",
    )?;
    for check in [
        "json_parse",
        "top_level_shape",
        "entries_present",
        "entry_schema",
        "unique_ids",
        "seed_overlay_coverage",
        "summary_counts",
        "source_summary_counts",
        "source_markers",
    ] {
        ensure(
            report["checks"][check].as_str() == Some("pass"),
            format!("report checks.{check} should pass"),
        )?;
    }

    let log_line = std::fs::read_to_string(&log_path)
        .map_err(|error| {
            failure(format!(
                "{} should be readable: {error}",
                log_path.display()
            ))
        })?
        .lines()
        .find(|line| !line.trim().is_empty())
        .ok_or_else(|| failure("log should contain at least one row"))?
        .to_string();
    let event: serde_json::Value = serde_json::from_str(&log_line)
        .map_err(|error| failure(format!("log row should parse: {error}")))?;
    for key in [
        "trace_id",
        "bead_id",
        "scenario_id",
        "runtime_mode",
        "replacement_level",
        "api_family",
        "symbol",
        "oracle_kind",
        "expected",
        "actual",
        "errno",
        "decision_path",
        "healing_action",
        "latency_ns",
        "artifact_refs",
        "source_commit",
        "target_dir",
        "failure_signature",
    ] {
        ensure(
            event.get(key).is_some(),
            format!("structured log row missing {key}"),
        )?;
    }

    Ok(())
}
