//! Contract tests for bd-2x5.4.1 allocator/membrane completion evidence.

use std::collections::BTreeSet;
use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let crates_dir = manifest
        .parent()
        .ok_or_else(|| io::Error::other("frankenlibc-harness manifest must have a parent"))?;
    let root = crates_dir.parent().ok_or_else(|| {
        io::Error::other("frankenlibc-harness manifest must live below workspace root")
    })?;
    Ok(root.to_path_buf())
}

fn read_manifest(root: &Path) -> TestResult<serde_json::Value> {
    let path = root.join("tests/conformance/allocator_membrane_unit_property_contract.v1.json");
    let text = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&text)?)
}

fn json_string_set(value: &serde_json::Value) -> TestResult<BTreeSet<String>> {
    let values = value.as_array().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "value should be a JSON array of strings",
        )
    })?;
    let mut result = BTreeSet::new();
    for item in values {
        let text = item.as_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "array entry should be a string")
        })?;
        result.insert(text.to_string());
    }
    Ok(result)
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
        full_path.exists(),
        "file-line ref path should exist: {file_line_ref}"
    );
    let line_count = std::fs::read_to_string(&full_path)?.lines().count();
    assert!(
        line_no <= line_count,
        "file-line ref outside file: {file_line_ref}"
    );
    Ok(())
}

#[test]
fn manifest_binds_allocator_unit_and_property_evidence() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_manifest(&root)?;
    let evidence = &manifest["completion_debt_evidence"];

    assert_eq!(manifest["bead"].as_str(), Some("bd-2x5.4"));
    assert_eq!(evidence["bead"].as_str(), Some("bd-2x5.4.1"));
    assert_eq!(evidence["original_bead"].as_str(), Some("bd-2x5.4"));
    assert!(
        evidence["next_audit_score_threshold"].as_u64().unwrap_or(0) >= 800,
        "completion evidence should target a passing next audit score"
    );

    let sources = evidence["test_sources"].as_object().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "test_sources should be an object",
        )
    })?;
    let mut source_texts = std::collections::BTreeMap::new();
    for (key, path) in sources {
        let path = path.as_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "test source path should be a string",
            )
        })?;
        source_texts.insert(key.as_str(), std::fs::read_to_string(root.join(path))?);
    }

    for (section, missing_item_id) in [
        ("unit_primary", "tests.unit.primary"),
        ("property_primary", "tests.property.primary"),
        ("telemetry_primary", "telemetry.primary"),
    ] {
        let section_value = &evidence[section];
        assert_eq!(
            section_value["missing_item_id"].as_str(),
            Some(missing_item_id),
            "{section} should bind its audit missing item"
        );
        assert!(
            section_value["next_audit_score_threshold"]
                .as_u64()
                .unwrap_or(0)
                >= 800,
            "{section} should carry a passing next-audit threshold"
        );
        let refs = section_value["required_test_refs"]
            .as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "test refs missing"))?;
        assert!(!refs.is_empty(), "{section} should name required tests");
        for test_ref in refs {
            let source = test_ref["source"].as_str().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "test source should be a string")
            })?;
            let name = test_ref["name"].as_str().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "test name should be a string")
            })?;
            let text = source_texts.get(source).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "test source should be declared")
            })?;
            assert!(
                text.contains(&format!("fn {name}")),
                "{section} references missing test {source}::{name}"
            );
        }
    }

    let refs = evidence["implementation_refs"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "implementation refs missing"))?;
    assert!(
        refs.len() >= 8,
        "implementation refs should cover allocator, fingerprint, validator, and gate surfaces"
    );
    for file_line_ref in refs {
        let file_line_ref = file_line_ref.as_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "implementation ref should be a string",
            )
        })?;
        assert_file_line_ref_exists(&root, file_line_ref)?;
    }

    let property_names: BTreeSet<_> = evidence["property_primary"]["required_test_refs"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "property refs missing"))?
        .iter()
        .filter_map(|item| item["name"].as_str())
        .collect();
    for expected in [
        "prop_canary_detects_any_byte_flip",
        "allocated_pointer_property_validates_as_live",
        "dependency_safe_order_property_holds",
        "deterministic_allocator_membrane_sequences_hold_core_invariants",
        "adversarial_pointer_fault_injection_matrix_has_zero_false_negatives",
    ] {
        assert!(
            property_names.contains(expected),
            "property evidence should bind {expected}"
        );
    }

    let telemetry = &evidence["telemetry_primary"];
    let required_events = json_string_set(&telemetry["required_events"])?;
    for event in [
        "allocator_membrane_unit_property_contract_validated",
        "validation_stage",
        "fault_injection_matrix",
        "fault_injection_log",
        "double_free_report",
    ] {
        assert!(
            required_events.contains(event),
            "telemetry evidence should require event {event}"
        );
    }

    let required_fields = json_string_set(&telemetry["required_fields"])?;
    for field in [
        "timestamp",
        "trace_id",
        "event",
        "completion_debt_bead",
        "original_bead",
        "source_commit",
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
    let report =
        root.join("target/conformance/allocator_membrane_unit_property_contract.test.report.json");
    let log =
        root.join("target/conformance/allocator_membrane_unit_property_contract.test.log.jsonl");

    let output = Command::new("bash")
        .arg(root.join("scripts/check_allocator_membrane_unit_property_contract.sh"))
        .env("FRANKENLIBC_ALLOCATOR_MEMBRANE_REPORT", &report)
        .env("FRANKENLIBC_ALLOCATOR_MEMBRANE_LOG", &log)
        .output()?;
    assert!(
        output.status.success(),
        "allocator membrane contract checker should pass, stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_json: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&report)?)?;
    assert_eq!(report_json["status"].as_str(), Some("pass"));
    assert_eq!(
        report_json["completion_debt_bead"].as_str(),
        Some("bd-2x5.4.1")
    );
    assert_eq!(report_json["original_bead"].as_str(), Some("bd-2x5.4"));
    assert!(
        report_json["missing_items"]
            .as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing_items array"))?
            .iter()
            .any(|item| item.as_str() == Some("tests.property.primary")),
        "report should bind tests.property.primary"
    );

    let log_content = std::fs::read_to_string(&log)?;
    let log_row: serde_json::Value = serde_json::from_str(log_content.trim())?;
    assert_eq!(
        log_row["event"].as_str(),
        Some("allocator_membrane_unit_property_contract_validated")
    );
    assert_eq!(log_row["completion_debt_bead"].as_str(), Some("bd-2x5.4.1"));
    assert_eq!(log_row["original_bead"].as_str(), Some("bd-2x5.4"));
    assert_eq!(log_row["failure_signature"].as_str(), Some("none"));
    assert!(
        log_row["artifact_refs"]
            .as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "artifact_refs array"))?
            .iter()
            .any(|item| {
                item.as_str()
                    == Some(
                        "target/conformance/allocator_membrane_unit_property_contract.test.report.json",
                    )
            }),
        "completion log should point at the report artifact"
    );

    Ok(())
}

#[test]
fn checker_rejects_stale_property_test_binding() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = read_manifest(&root)?;
    manifest["completion_debt_evidence"]["property_primary"]["required_test_refs"] = serde_json::json!([
        {
            "source": "fingerprint_unit",
            "name": "stale_missing_allocator_membrane_property_test"
        }
    ]);

    let stale_manifest =
        root.join("target/conformance/allocator_membrane_unit_property_contract.stale.json");
    let stale_report =
        root.join("target/conformance/allocator_membrane_unit_property_contract.stale.report.json");
    let stale_log =
        root.join("target/conformance/allocator_membrane_unit_property_contract.stale.log.jsonl");
    if let Some(parent) = stale_manifest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(
        &stale_manifest,
        serde_json::to_string_pretty(&manifest)? + "\n",
    )?;

    let output = Command::new("bash")
        .arg(root.join("scripts/check_allocator_membrane_unit_property_contract.sh"))
        .env("FRANKENLIBC_ALLOCATOR_MEMBRANE_CONTRACT", &stale_manifest)
        .env("FRANKENLIBC_ALLOCATOR_MEMBRANE_REPORT", &stale_report)
        .env("FRANKENLIBC_ALLOCATOR_MEMBRANE_LOG", &stale_log)
        .output()?;
    assert!(
        !output.status.success(),
        "stale completion evidence should fail validation"
    );
    let merged = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        merged.contains("stale_missing_allocator_membrane_property_test"),
        "checker output should name the stale missing test: {merged}"
    );

    let report_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&stale_report)?)?;
    assert_eq!(report_json["status"].as_str(), Some("fail"));
    assert!(
        report_json["errors"]
            .as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "errors array"))?
            .iter()
            .any(|item| item
                .as_str()
                .unwrap_or("")
                .contains("stale_missing_allocator_membrane_property_test")),
        "report should retain the stale binding error"
    );

    Ok(())
}
