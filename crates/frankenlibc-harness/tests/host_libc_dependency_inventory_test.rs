//! Integration test: host libc dependency inventory gate (bd-bp8fl.6.1)
//!
//! Verifies that the source-level inventory contract produces a complete,
//! structured dependency report for L0/L1 interpose and L2/L3 replacement
//! promotion decisions.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

type TestResult<T = ()> = Result<T, String>;

const REQUIRED_LOG_FIELDS: &[&str] = &[
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
];

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let root = Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))?
        .to_path_buf();
    Ok(root)
}

fn load_json(path: &Path) -> TestResult<serde_json::Value> {
    let content =
        std::fs::read_to_string(path).map_err(|err| format!("{}: {err}", path.display()))?;
    serde_json::from_str(&content).map_err(|err| format!("{}: {err}", path.display()))
}

fn load_contract() -> TestResult<serde_json::Value> {
    load_json(&workspace_root()?.join("tests/conformance/host_libc_dependency_inventory.v1.json"))
}

fn json_array<'a>(
    value: &'a serde_json::Value,
    field: &str,
) -> TestResult<&'a Vec<serde_json::Value>> {
    value[field]
        .as_array()
        .ok_or_else(|| format!("{field} must be a JSON array"))
}

fn string_array(value: &serde_json::Value, field: &str) -> TestResult<Vec<String>> {
    json_array(value, field)?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("{field} must contain only strings"))
        })
        .collect()
}

fn summary_string_array(value: &serde_json::Value, field: &str) -> TestResult<Vec<String>> {
    value["summary"][field]
        .as_array()
        .ok_or_else(|| format!("summary.{field} must be a JSON array"))?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("summary.{field} must contain only strings"))
        })
        .collect()
}

fn require(condition: bool, message: impl Into<String>) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn run_gate() -> TestResult<serde_json::Value> {
    let root = workspace_root()?;
    let output = Command::new("bash")
        .arg("scripts/check_host_libc_dependency_inventory.sh")
        .current_dir(&root)
        .env("FRANKENLIBC_REQUIRE_RELEASE_ARTIFACT", "0")
        .output()
        .map_err(|err| format!("inventory gate did not run: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "inventory gate failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    load_json(&root.join("target/conformance/host_libc_dependency_inventory.report.json"))
}

#[test]
fn contract_has_required_shape_and_fields() -> TestResult {
    let contract = load_contract()?;
    require(
        contract["schema_version"].as_str() == Some("v1"),
        "schema_version must be v1",
    )?;
    require(
        contract["bead"].as_str() == Some("bd-bp8fl.6.1"),
        "bead must be bd-bp8fl.6.1",
    )?;
    require(contract["inputs"].is_object(), "inputs must be an object")?;
    require(
        contract["release_artifact_policy"].is_object(),
        "release artifact policy must be present",
    )?;
    require(
        json_array(&contract, "negative_claim_tests")?.len() >= 3,
        "negative standalone-claim tests must be documented",
    )?;

    let log_fields = string_array(&contract, "required_log_fields")?;
    require(
        log_fields == REQUIRED_LOG_FIELDS,
        format!("required_log_fields mismatch: {log_fields:?}"),
    )?;
    Ok(())
}

#[test]
fn gate_emits_complete_inventory_report_and_log() -> TestResult {
    let report = run_gate()?;
    require(
        report["schema_version"].as_str() == Some("v1"),
        "report schema_version must be v1",
    )?;
    require(
        report["bead"].as_str() == Some("bd-bp8fl.6.1"),
        "report bead must be bd-bp8fl.6.1",
    )?;
    require(
        report["status"].as_str() == Some("pass"),
        format!("inventory report did not pass: {report:?}"),
    )?;
    require(
        report["summary"]["inventory_event_count"].as_u64() > Some(0),
        "inventory must contain rows",
    )?;
    require(
        report["summary"]["l2_l3_blocker_count"].as_u64() > Some(0),
        "current inventory must identify L2/L3 blockers rather than silently approving replacement",
    )?;

    let root = workspace_root()?;
    let log_path = root.join("target/conformance/host_libc_dependency_inventory.log.jsonl");
    let log = std::fs::read_to_string(&log_path)
        .map_err(|err| format!("{}: {err}", log_path.display()))?;
    let first_line = log
        .lines()
        .find(|line| !line.trim().is_empty())
        .ok_or_else(|| format!("{} was empty", log_path.display()))?;
    let first_row: serde_json::Value = serde_json::from_str(first_line)
        .map_err(|err| format!("first inventory log row did not parse: {err}"))?;
    for field in REQUIRED_LOG_FIELDS {
        require(
            first_row.get(*field).is_some(),
            format!("first log row missing required field {field}"),
        )?;
    }
    Ok(())
}

#[test]
fn required_categories_and_anchor_symbols_are_present() -> TestResult {
    let contract = load_contract()?;
    let report = run_gate()?;

    let required_categories: HashSet<_> = string_array(&contract, "required_inventory_categories")?
        .into_iter()
        .collect();
    let seen_categories: HashSet<_> = summary_string_array(&report, "required_categories_seen")?
        .into_iter()
        .collect();
    require(
        seen_categories == required_categories,
        format!("required category mismatch: {seen_categories:?}"),
    )?;

    let required_symbols: HashSet<_> = string_array(&contract, "required_anchor_symbols")?
        .into_iter()
        .collect();
    let seen_symbols: HashSet<_> = summary_string_array(&report, "required_anchor_symbols_seen")?
        .into_iter()
        .collect();
    require(
        seen_symbols == required_symbols,
        format!("required symbol mismatch: {seen_symbols:?}"),
    )?;
    Ok(())
}

#[test]
fn replacement_policy_separates_interpose_from_standalone_claims() -> TestResult {
    let report = run_gate()?;
    let top_blockers = json_array(&report, "top_blockers")?;
    require(!top_blockers.is_empty(), "top blockers should be listed")?;

    let has_startup_blocker = top_blockers.iter().any(|row| {
        row["symbol"].as_str() == Some("__libc_start_main")
            || row["symbol"].as_str() == Some("__cxa_thread_atexit_impl")
    });
    require(
        has_startup_blocker,
        "startup/CRT host dependency must be surfaced as a standalone blocker",
    )?;

    for row in top_blockers {
        let blocked: HashSet<_> = row["blocked_replacement_levels"]
            .as_array()
            .ok_or_else(|| "blocked_replacement_levels must be an array".to_string())?
            .iter()
            .map(|level| {
                level
                    .as_str()
                    .ok_or_else(|| "blocked_replacement_levels must contain strings".to_string())
            })
            .collect::<TestResult<HashSet<_>>>()?;
        require(
            blocked.contains("L2") || blocked.contains("L3"),
            format!("blocker rows must block standalone levels: {row:?}"),
        )?;
    }
    Ok(())
}
