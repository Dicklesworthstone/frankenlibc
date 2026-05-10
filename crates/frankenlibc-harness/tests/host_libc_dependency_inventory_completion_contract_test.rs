//! Contract tests for bd-bp8fl.6.1.1 host libc dependency inventory completion.

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const EXPECTED_MISSING_ITEMS: &[(&str, &str)] = &[
    ("unit_primary", "tests.unit.primary"),
    ("e2e_primary", "tests.e2e.primary"),
    ("conformance_primary", "tests.conformance.primary"),
    ("telemetry_primary", "telemetry.primary"),
];

const EXPECTED_TELEMETRY_EVENTS: &[&str] = &[
    "host_libc_dependency_inventory_completion_contract_validated",
    "host_libc_dependency_inventory_summary",
    "host_libc_dependency_inventory_blockers_preserved",
    "host_libc_dependency_release_artifact_policy_bound",
];

const EXPECTED_TELEMETRY_FIELDS: &[&str] = &[
    "timestamp",
    "trace_id",
    "event",
    "level",
    "bead_id",
    "completion_debt_bead",
    "original_bead",
    "status",
    "source_commit",
    "missing_items_bound",
    "test_refs",
    "inventory_summary",
    "release_artifact",
    "negative_claim_results",
    "artifact_refs",
    "failure_signature",
];

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
    root.join("tests/conformance/host_libc_dependency_inventory_completion_contract.v1.json")
}

fn inventory_contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/host_libc_dependency_inventory.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_host_libc_dependency_inventory_completion_contract.sh")
}

fn read_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn read_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    std::fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}

fn string_set(value: &Value) -> TestResult<BTreeSet<String>> {
    let array = value
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "expected string array"))?;
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
        "host-libc-dep-completion-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(
    root: &Path,
    contract: &Path,
    inventory_contract: &Path,
    out_dir: &Path,
) -> TestResult<std::process::Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_HOST_DEP_COMPLETION_CONTRACT", contract)
        .env(
            "FRANKENLIBC_HOST_DEP_INVENTORY_CONTRACT",
            inventory_contract,
        )
        .env(
            "FRANKENLIBC_HOST_DEP_COMPLETION_REPORT",
            out_dir.join("host_libc_dependency_inventory_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_HOST_DEP_COMPLETION_LOG",
            out_dir.join("host_libc_dependency_inventory_completion_contract.log.jsonl"),
        )
        .env(
            "FRANKENLIBC_HOST_DEP_COMPLETION_INVENTORY_REPORT",
            out_dir
                .join("host_libc_dependency_inventory_completion_contract.inventory.report.json"),
        )
        .env(
            "FRANKENLIBC_HOST_DEP_COMPLETION_INVENTORY_LOG",
            out_dir.join("host_libc_dependency_inventory_completion_contract.inventory.log.jsonl"),
        )
        .output()?)
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
    let text = std::fs::read_to_string(full_path)?;
    let lines: Vec<_> = text.lines().collect();
    assert!(
        line_no <= lines.len(),
        "file-line ref outside file: {file_line_ref}"
    );
    assert!(
        !lines[line_no - 1].trim().is_empty(),
        "file-line ref should not cite a blank line: {file_line_ref}"
    );
    Ok(())
}

fn source_texts(root: &Path, manifest: &Value) -> TestResult<BTreeMap<String, String>> {
    let sources = manifest["completion_debt_evidence"]["test_sources"]
        .as_object()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "test_sources object"))?;
    let mut texts = BTreeMap::new();
    for (key, path) in sources {
        let path = path
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "source path string"))?;
        texts.insert(key.clone(), std::fs::read_to_string(root.join(path))?);
    }
    Ok(texts)
}

fn assert_test_refs_exist(
    section_name: &str,
    section: &Value,
    sources: &BTreeMap<String, String>,
) -> TestResult {
    let refs = section["required_test_refs"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "test refs array"))?;
    assert!(!refs.is_empty(), "{section_name} should name test refs");
    for test_ref in refs {
        let source = test_ref["source"]
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "source string"))?;
        let name = test_ref["name"]
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "test name string"))?;
        let text = sources
            .get(source)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "source declared"))?;
        assert!(
            text.contains(&format!("fn {name}")) || text.contains(&format!("def {name}")),
            "{section_name} references missing test {source}::{name}"
        );
    }
    Ok(())
}

fn checker_output_message(output: &std::process::Output) -> String {
    format!(
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn manifest_binds_unit_e2e_conformance_and_telemetry_evidence() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&contract_path(&root))?;

    assert_eq!(manifest["bead"].as_str(), Some("bd-bp8fl.6.1"));
    let evidence = &manifest["completion_debt_evidence"];
    assert_eq!(evidence["bead"].as_str(), Some("bd-bp8fl.6.1.1"));
    assert_eq!(evidence["original_bead"].as_str(), Some("bd-bp8fl.6.1"));
    assert!(
        evidence["next_audit_score_threshold"].as_u64().unwrap_or(0) >= 800,
        "completion evidence should target a passing next-audit score"
    );

    for file_line_ref in evidence["implementation_refs"]
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

    let inventory_contract = read_json(&inventory_contract_path(&root))?;
    assert_eq!(
        string_set(&evidence["required_inventory_categories"])?,
        string_set(&inventory_contract["required_inventory_categories"])?,
        "completion manifest should bind every inventory category"
    );
    assert_eq!(
        string_set(&evidence["required_anchor_symbols"])?,
        string_set(&inventory_contract["required_anchor_symbols"])?,
        "completion manifest should bind every anchor symbol"
    );
    assert_eq!(
        string_set(&evidence["required_log_fields"])?,
        string_set(&inventory_contract["required_log_fields"])?,
        "completion manifest should bind every inventory log field"
    );

    let sources = source_texts(&root, &manifest)?;
    for (section, missing_item) in EXPECTED_MISSING_ITEMS {
        let section_value = &evidence[*section];
        assert_eq!(
            section_value["missing_item_id"].as_str(),
            Some(*missing_item)
        );
        assert!(
            section_value["next_audit_score_threshold"]
                .as_u64()
                .unwrap_or(0)
                >= 800,
            "{section} should carry a passing next-audit threshold"
        );
        assert_test_refs_exist(section, section_value, &sources)?;
    }

    for command in evidence["unit_primary"]["required_commands"]
        .as_array()
        .into_iter()
        .flatten()
        .chain(
            evidence["e2e_primary"]["required_commands"]
                .as_array()
                .into_iter()
                .flatten(),
        )
        .chain(
            evidence["conformance_primary"]["required_commands"]
                .as_array()
                .into_iter()
                .flatten(),
        )
    {
        let command = command
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "command string"))?;
        assert!(
            !command.contains("cargo ") || command.contains("rch exec --"),
            "cargo validation commands must be routed through rch: {command}"
        );
    }

    let telemetry_events = string_set(&evidence["telemetry_primary"]["required_events"])?;
    for expected in EXPECTED_TELEMETRY_EVENTS {
        assert!(
            telemetry_events.contains(*expected),
            "telemetry should require {expected}"
        );
    }
    let telemetry_fields = string_set(&evidence["telemetry_primary"]["required_fields"])?;
    for expected in EXPECTED_TELEMETRY_FIELDS {
        assert!(
            telemetry_fields.contains(*expected),
            "telemetry should require field {expected}"
        );
    }

    Ok(())
}

#[test]
fn checker_emits_report_and_jsonl() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "pass")?;
    let output = run_checker(
        &root,
        &contract_path(&root),
        &inventory_contract_path(&root),
        &out_dir,
    )?;
    assert!(
        output.status.success(),
        "checker should pass:\n{}",
        checker_output_message(&output)
    );

    let report_path =
        out_dir.join("host_libc_dependency_inventory_completion_contract.report.json");
    let log_path = out_dir.join("host_libc_dependency_inventory_completion_contract.log.jsonl");
    let report = read_json(&report_path)?;
    let events = read_jsonl(&log_path)?;

    assert_eq!(
        report["schema_version"].as_str(),
        Some("host_libc_dependency_inventory_completion_contract.report.v1")
    );
    assert_eq!(
        report["completion_debt_bead"].as_str(),
        Some("bd-bp8fl.6.1.1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert!(
        report["summary"]["inventory_event_count"]
            .as_u64()
            .unwrap_or(0)
            > 0,
        "completion report should summarize inventory rows"
    );
    assert!(
        report["summary"]["l2_l3_blocker_count"]
            .as_u64()
            .unwrap_or(0)
            > 0,
        "completion report should preserve standalone blockers"
    );

    let emitted: BTreeSet<_> = events
        .iter()
        .filter_map(|event| event["event"].as_str())
        .collect();
    for expected in EXPECTED_TELEMETRY_EVENTS {
        assert!(
            emitted.contains(expected),
            "checker log should emit {expected}"
        );
    }
    for event in events {
        for field in EXPECTED_TELEMETRY_FIELDS {
            assert!(
                event.get(*field).is_some(),
                "telemetry event should include {field}"
            );
        }
    }

    Ok(())
}

#[test]
fn checker_replays_inventory_gate_and_preserves_blockers() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "inventory-replay")?;
    let output = run_checker(
        &root,
        &contract_path(&root),
        &inventory_contract_path(&root),
        &out_dir,
    )?;
    assert!(
        output.status.success(),
        "checker should pass:\n{}",
        checker_output_message(&output)
    );

    let report =
        read_json(&out_dir.join("host_libc_dependency_inventory_completion_contract.report.json"))?;
    let inventory_report = read_json(
        &out_dir.join("host_libc_dependency_inventory_completion_contract.inventory.report.json"),
    )?;
    let inventory_log = read_jsonl(
        &out_dir.join("host_libc_dependency_inventory_completion_contract.inventory.log.jsonl"),
    )?;

    assert_eq!(
        report["release_artifact"]["status"].as_str(),
        Some("missing")
    );
    assert_eq!(
        report["release_artifact"]["required"].as_bool(),
        Some(false)
    );
    assert!(
        report["summary"]["l2_l3_blocker_count"]
            .as_u64()
            .unwrap_or(0)
            > 0,
        "source-only replay should still block standalone replacement claims"
    );
    assert_eq!(
        report["summary"]["unapproved_direct_libc_call_count"].as_u64(),
        Some(0),
        "unapproved call-throughs should remain clean"
    );

    let categories = string_set(&inventory_report["summary"]["required_categories_seen"])?;
    let required_categories =
        string_set(&read_json(&inventory_contract_path(&root))?["required_inventory_categories"])?;
    assert_eq!(categories, required_categories);

    let result_ids: BTreeSet<_> = report["negative_claim_results"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "negative results"))?
        .iter()
        .filter_map(|row| row["id"].as_str())
        .collect();
    assert!(result_ids.contains("neg-l3-dynamic-glibc-needed"));
    assert!(
        !inventory_log.is_empty(),
        "inventory replay should emit JSONL rows"
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_required_log_field_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-log-field")?;
    let mut manifest = read_json(&contract_path(&root))?;
    let fields = manifest["completion_debt_evidence"]["required_log_fields"]
        .as_array_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "log fields array"))?;
    if let Some(index) = fields
        .iter()
        .position(|value| matches!(value.as_str(), Some("failure_signature")))
    {
        fields.remove(index);
    }
    let bad_contract = out_dir.join("bad_contract.json");
    write_json(&bad_contract, &manifest)?;

    let output = run_checker(
        &root,
        &bad_contract,
        &inventory_contract_path(&root),
        &out_dir,
    )?;
    assert!(
        !output.status.success(),
        "checker should reject missing log field:\n{}",
        checker_output_message(&output)
    );
    let report =
        read_json(&out_dir.join("host_libc_dependency_inventory_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|error| error
                .as_str()
                .is_some_and(|text| text.contains("required_log_fields"))),
        "failure report should explain missing required_log_fields"
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_inventory_contract_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-inventory-contract")?;
    let missing_inventory_contract = out_dir.join("missing_host_libc_dependency_inventory.json");

    let output = run_checker(
        &root,
        &contract_path(&root),
        &missing_inventory_contract,
        &out_dir,
    )?;
    assert!(
        !output.status.success(),
        "checker should reject missing inventory contract:\n{}",
        checker_output_message(&output)
    );
    let report =
        read_json(&out_dir.join("host_libc_dependency_inventory_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|error| error.as_str().is_some_and(|text| {
                text.contains("inventory contract")
                    || text.contains("required_inventory_categories")
            })),
        "failure report should explain missing inventory contract"
    );
    Ok(())
}
