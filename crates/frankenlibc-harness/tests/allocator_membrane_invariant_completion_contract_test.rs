//! Contract tests for bd-66wz.5 allocator/membrane invariant completion evidence.

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

fn read_manifest(root: &Path) -> TestResult<serde_json::Value> {
    let path =
        root.join("tests/conformance/allocator_membrane_invariant_completion_contract.v1.json");
    let text = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&text)?)
}

fn write_json(path: &Path, value: &serde_json::Value) -> TestResult {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn unique_output_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let path = root.join("target/conformance").join(format!(
        "allocator-membrane-invariant-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<std::process::Output> {
    Ok(Command::new("bash")
        .arg(root.join("scripts/check_allocator_membrane_invariant_completion_contract.sh"))
        .current_dir(root)
        .env(
            "FRANKENLIBC_ALLOCATOR_MEMBRANE_INVARIANT_CONTRACT",
            contract,
        )
        .env(
            "FRANKENLIBC_ALLOCATOR_MEMBRANE_INVARIANT_REPORT",
            out_dir.join("allocator_membrane_invariant_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_ALLOCATOR_MEMBRANE_INVARIANT_LOG",
            out_dir.join("allocator_membrane_invariant_completion_contract.log.jsonl"),
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
fn manifest_binds_allocator_membrane_unit_and_telemetry_evidence() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_manifest(&root)?;
    assert_eq!(manifest["bead"].as_str(), Some("bd-66wz"));
    assert_eq!(
        manifest["completion_debt_evidence"]["bead"].as_str(),
        Some("bd-66wz.5")
    );
    assert_eq!(
        manifest["completion_debt_evidence"]["original_bead"].as_str(),
        Some("bd-66wz")
    );

    let evidence = &manifest["completion_debt_evidence"];
    assert!(
        evidence["next_audit_score_threshold"].as_u64().unwrap_or(0) >= 800,
        "completion evidence should target a passing next audit score"
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

    let invariant_classes = string_set(&evidence["invariant_classes"])?;
    for expected in [
        "generation_monotonicity",
        "quarantine_state_transition",
        "use_after_free_detection",
        "double_free_detection",
        "canary_corruption_detection",
        "foreign_pointer_classification",
        "tls_cache_invalidation",
        "deterministic_sequence_invariants",
        "adversarial_fault_matrix",
        "concurrent_double_free_stress",
    ] {
        assert!(
            invariant_classes.contains(expected),
            "invariant evidence should include {expected}"
        );
    }

    for field in [
        "uaf_false_negatives",
        "double_free_false_negatives",
        "fault_matrix_false_negatives",
        "heap_integrity_failures",
    ] {
        assert_eq!(
            evidence["detection_guarantees"][field].as_u64(),
            Some(0),
            "detection guarantee {field} should be fail-closed at zero"
        );
    }

    let source_texts = source_texts(&root, &manifest)?;
    for (section, missing_item) in [
        ("unit_primary", "tests.unit.primary"),
        ("telemetry_primary", "telemetry.primary"),
    ] {
        let section_value = &evidence[section];
        assert_eq!(
            section_value["missing_item_id"].as_str(),
            Some(missing_item)
        );
        assert!(
            section_value["next_audit_score_threshold"]
                .as_u64()
                .unwrap_or(0)
                >= 800,
            "{section} should carry a passing next-audit threshold"
        );
        assert_test_refs_exist(section, section_value, &source_texts)?;
    }

    let unit_names: BTreeSet<_> = evidence["unit_primary"]["required_test_refs"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "unit refs"))?
        .iter()
        .filter_map(|item| item["name"].as_str())
        .collect();
    for expected in [
        "proof_uaf_detection_probability_one",
        "proof_double_free_always_detected",
        "prop_canary_detects_any_byte_flip",
        "allocated_pointer_property_validates_as_live",
        "deterministic_allocator_membrane_sequences_hold_core_invariants",
        "adversarial_pointer_fault_injection_matrix_has_zero_false_negatives",
    ] {
        assert!(
            unit_names.contains(expected),
            "unit evidence should bind {expected}"
        );
    }

    let telemetry = &evidence["telemetry_primary"];
    let required_events = string_set(&telemetry["required_events"])?;
    for event in [
        "allocator_membrane_invariant_completion_contract_validated",
        "allocator_membrane_invariant_completion_contract_failed",
        "validation_stage",
        "fault_injection",
        "double_free_report",
    ] {
        assert!(
            required_events.contains(event),
            "telemetry evidence should require event {event}"
        );
    }

    let required_fields = string_set(&telemetry["required_fields"])?;
    for field in [
        "timestamp",
        "trace_id",
        "event",
        "completion_debt_bead",
        "original_bead",
        "invariant_classes",
        "detection_guarantees",
        "test_refs",
        "artifact_refs",
        "failure_signature",
    ] {
        assert!(
            required_fields.contains(field),
            "telemetry evidence should require field {field}"
        );
    }

    Ok(())
}

#[test]
fn checker_emits_report_and_log() -> TestResult {
    let root = workspace_root()?;
    let contract =
        root.join("tests/conformance/allocator_membrane_invariant_completion_contract.v1.json");
    let out_dir = unique_output_dir(&root, "pass")?;
    let output = run_checker(&root, &contract, &out_dir)?;
    assert!(
        output.status.success(),
        "allocator membrane invariant checker failed stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report =
        read_json(&out_dir.join("allocator_membrane_invariant_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-66wz.5"));
    assert_eq!(report["original_bead"].as_str(), Some("bd-66wz"));
    assert!(
        report["missing_items_bound"]
            .as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing items"))?
            .iter()
            .any(|item| item.as_str() == Some("tests.unit.primary")),
        "report should bind tests.unit.primary"
    );

    let rows =
        read_jsonl(&out_dir.join("allocator_membrane_invariant_completion_contract.log.jsonl"))?;
    assert_eq!(rows.len(), 1, "checker should emit one telemetry row");
    let row = &rows[0];
    assert_eq!(
        row["event"].as_str(),
        Some("allocator_membrane_invariant_completion_contract_validated")
    );
    assert_eq!(row["completion_debt_bead"].as_str(), Some("bd-66wz.5"));
    assert_eq!(row["original_bead"].as_str(), Some("bd-66wz"));
    assert_eq!(row["failure_signature"].as_str(), Some("none"));
    assert!(
        row["invariant_classes"]
            .as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invariant classes"))?
            .iter()
            .any(|item| item.as_str() == Some("adversarial_fault_matrix")),
        "log should retain invariant class evidence"
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_unit_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "stale")?;
    let mut manifest = read_manifest(&root)?;
    manifest["completion_debt_evidence"]["unit_primary"]["required_test_refs"] = serde_json::json!([
        {
            "source": "arena_unit",
            "name": "stale_missing_allocator_membrane_unit_test"
        }
    ]);
    let stale_contract = out_dir.join("stale_allocator_membrane_invariant_contract.v1.json");
    write_json(&stale_contract, &manifest)?;

    let output = run_checker(&root, &stale_contract, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject stale unit-test binding"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("stale_missing_allocator_membrane_unit_test"),
        "checker output should name the missing unit test: {combined}"
    );

    let report =
        read_json(&out_dir.join("allocator_membrane_invariant_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "errors array"))?
            .iter()
            .any(|item| item
                .as_str()
                .unwrap_or("")
                .contains("stale_missing_allocator_membrane_unit_test")),
        "report should retain the stale binding error"
    );

    let rows =
        read_jsonl(&out_dir.join("allocator_membrane_invariant_completion_contract.log.jsonl"))?;
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0]["event"].as_str(),
        Some("allocator_membrane_invariant_completion_contract_failed")
    );

    Ok(())
}
