//! Contract tests for bd-66wz.4.1 deterministic allocator/membrane sequence evidence.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
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

fn manifest_path(root: &Path) -> PathBuf {
    root.join(
        "tests/conformance/allocator_membrane_deterministic_sequence_completion_contract.v1.json",
    )
}

fn read_manifest(root: &Path) -> TestResult<serde_json::Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(
        manifest_path(root),
    )?)?)
}

fn write_json(path: &Path, value: &serde_json::Value) -> TestResult {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn unique_output_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let path = root.join("target/conformance").join(format!(
        "allocator-sequence-completion-{label}-{}-{stamp}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<std::process::Output> {
    Ok(Command::new("bash")
        .arg(
            root.join(
                "scripts/check_allocator_membrane_deterministic_sequence_completion_contract.sh",
            ),
        )
        .current_dir(root)
        .env("FRANKENLIBC_ALLOCATOR_SEQUENCE_CONTRACT", contract)
        .env(
            "FRANKENLIBC_ALLOCATOR_SEQUENCE_REPORT",
            out_dir
                .join("allocator_membrane_deterministic_sequence_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_ALLOCATOR_SEQUENCE_LOG",
            out_dir.join("allocator_membrane_deterministic_sequence_completion_contract.log.jsonl"),
        )
        .output()?)
}

fn read_json(path: &Path) -> TestResult<serde_json::Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
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

fn source_texts(root: &Path, manifest: &serde_json::Value) -> TestResult<BTreeMap<String, String>> {
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
    section: &serde_json::Value,
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
            text.contains(&format!("fn {name}")),
            "{section_name} references missing test {source}::{name}"
        );
    }
    Ok(())
}

#[test]
fn manifest_binds_deterministic_sequence_unit_and_property_evidence() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_manifest(&root)?;
    let evidence = &manifest["completion_debt_evidence"];

    assert_eq!(manifest["bead"].as_str(), Some("bd-66wz.4"));
    assert_eq!(evidence["bead"].as_str(), Some("bd-66wz.4.1"));
    assert_eq!(evidence["original_bead"].as_str(), Some("bd-66wz.4"));
    assert!(
        evidence["next_audit_score_threshold"].as_u64().unwrap_or(0) >= 800,
        "completion evidence should target a passing next audit score"
    );

    let invariants = string_set(&evidence["invariant_classes"])?;
    for expected in [
        "deterministic_replay",
        "foreign_pointer_unknown_unbounded",
        "live_pointer_permissiveness",
        "temporal_safety_after_free",
        "no_stale_cached_valid_after_free",
        "double_free_detection",
        "canary_corruption_detection",
    ] {
        assert!(
            invariants.contains(expected),
            "invariant evidence should include {expected}"
        );
    }

    for field in [
        "deterministic_replay_mismatches",
        "freed_cached_valid_false_negatives",
        "double_free_false_negatives",
        "canary_corruption_false_negatives",
    ] {
        assert_eq!(
            evidence["detection_guarantees"][field].as_u64(),
            Some(0),
            "detection guarantee {field} should be zero"
        );
    }

    let sequence = &evidence["sequence_contract"];
    assert_eq!(sequence["fixed_seeds"].as_array().map(Vec::len), Some(4));
    assert_eq!(sequence["steps_per_seed"].as_u64(), Some(2000));
    assert_eq!(sequence["slot_count"].as_u64(), Some(32));

    let sources = source_texts(&root, &manifest)?;
    for (section, missing_item) in [
        ("unit_primary", "tests.unit.primary"),
        ("property_primary", "tests.property.primary"),
    ] {
        let section_value = &evidence[section];
        assert_eq!(
            section_value["missing_item_id"].as_str(),
            Some(missing_item)
        );
        assert_test_refs_exist(section, section_value, &sources)?;
    }

    let property_names: BTreeSet<_> = evidence["property_primary"]["required_test_refs"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "property refs"))?
        .iter()
        .filter_map(|item| item["name"].as_str())
        .collect();
    for expected in [
        "allocated_pointer_property_validates_as_live",
        "freed_pointer_property_becomes_temporal_violation",
        "dependency_safe_order_property_holds",
        "deterministic_allocator_membrane_sequences_hold_core_invariants",
    ] {
        assert!(
            property_names.contains(expected),
            "property evidence should bind {expected}"
        );
    }

    Ok(())
}

#[test]
fn checker_emits_report_and_log() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "pass")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    assert!(
        output.status.success(),
        "checker failed stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = read_json(
        &out_dir.join("allocator_membrane_deterministic_sequence_completion_contract.report.json"),
    )?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-66wz.4.1"));
    assert_eq!(report["bead"].as_str(), Some("bd-66wz.4"));
    assert!(
        report["missing_items_bound"]
            .as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing items"))?
            .iter()
            .any(|item| item.as_str() == Some("tests.property.primary")),
        "report should bind tests.property.primary"
    );

    let rows = read_jsonl(
        &out_dir.join("allocator_membrane_deterministic_sequence_completion_contract.log.jsonl"),
    )?;
    assert_eq!(rows.len(), 1, "checker should emit one telemetry row");
    let row = &rows[0];
    assert_eq!(
        row["event"].as_str(),
        Some("allocator_membrane_deterministic_sequence_completion_contract_validated")
    );
    assert_eq!(row["completion_debt_bead"].as_str(), Some("bd-66wz.4.1"));
    assert_eq!(row["original_bead"].as_str(), Some("bd-66wz.4"));
    assert_eq!(row["failure_signature"].as_str(), Some("none"));

    Ok(())
}

#[test]
fn checker_rejects_missing_sequence_property_marker() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-marker")?;
    let mut manifest = read_manifest(&root)?;
    manifest["completion_debt_evidence"]["sequence_contract"]["required_source_markers"]
        .as_array_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "markers array"))?
        .push(serde_json::json!("missing_deterministic_sequence_marker"));
    let stale_contract = out_dir.join("stale_allocator_sequence_completion_contract.v1.json");
    write_json(&stale_contract, &manifest)?;

    let output = run_checker(&root, &stale_contract, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing source markers"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("missing_deterministic_sequence_marker"),
        "checker output should name the missing marker: {combined}"
    );

    let report = read_json(
        &out_dir.join("allocator_membrane_deterministic_sequence_completion_contract.report.json"),
    )?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "errors array"))?
            .iter()
            .any(|item| item
                .as_str()
                .unwrap_or("")
                .contains("missing_deterministic_sequence_marker")),
        "report should retain the stale marker error"
    );

    Ok(())
}
