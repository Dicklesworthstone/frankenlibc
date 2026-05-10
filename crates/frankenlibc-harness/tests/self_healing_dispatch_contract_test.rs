//! Contract tests for bd-32e.4.1 self-healing dispatch completion evidence.

use serde_json::json;
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
    let path = root.join("tests/conformance/self_healing_dispatch_contract.v1.json");
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
fn manifest_binds_self_healing_dispatch_evidence() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_manifest(&root)?;
    let evidence = &manifest["completion_debt_evidence"];

    assert_eq!(manifest["bead"].as_str(), Some("bd-32e.4"));
    assert_eq!(evidence["bead"].as_str(), Some("bd-32e.4.1"));
    assert_eq!(evidence["original_bead"].as_str(), Some("bd-32e.4"));
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
        ("e2e_primary", "tests.e2e.primary"),
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
        refs.len() >= 10,
        "implementation refs should cover healing enum, policy, logging, checker, and harness"
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

    let dispatch = &evidence["dispatch_contract"];
    let required_actions = json_string_set(&dispatch["required_healing_actions"])?;
    for action in [
        "ClampSize",
        "TruncateWithNull",
        "IgnoreDoubleFree",
        "IgnoreForeignFree",
        "ReallocAsMalloc",
        "ReturnSafeDefault",
        "UpgradeToSafeVariant",
    ] {
        assert!(
            required_actions.contains(action),
            "dispatch contract should bind healing action {action}"
        );
        assert!(
            source_texts
                .get("heal_unit")
                .is_some_and(|text| text.contains(action)),
            "heal.rs should contain action {action}"
        );
    }
    let required_variants = json_string_set(&dispatch["required_enum_variants"])?;
    assert!(
        required_variants.contains("None"),
        "enum variants should include the no-op action"
    );

    let log_fields = json_string_set(&dispatch["required_healing_log_fields"])?;
    for field in [
        "trace_id",
        "decision_id",
        "runtime_mode",
        "api_family",
        "decision_path",
        "outcome",
        "healing_action",
        "escalated",
        "details",
    ] {
        assert!(
            log_fields.contains(field),
            "dispatch contract should require healing log field {field}"
        );
        assert!(
            source_texts
                .get("heal_unit")
                .is_some_and(|text| text.contains(field)),
            "heal.rs should contain healing log field {field}"
        );
    }

    let telemetry = &evidence["telemetry_primary"];
    let required_events = json_string_set(&telemetry["required_events"])?;
    for event in [
        "self_healing_dispatch_contract_validated",
        "healing_dispatch",
        "healing_evidence",
        "hardened_repair_matrix",
        "runtime_evidence_verifier",
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
        "required_healing_actions",
        "required_counter_fields",
        "required_healing_log_fields",
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
    let report = root.join("target/conformance/self_healing_dispatch_contract.test.report.json");
    let log = root.join("target/conformance/self_healing_dispatch_contract.test.log.jsonl");

    let output = Command::new("bash")
        .arg(root.join("scripts/check_self_healing_dispatch_contract.sh"))
        .env("FRANKENLIBC_SELF_HEALING_REPORT", &report)
        .env("FRANKENLIBC_SELF_HEALING_LOG", &log)
        .output()?;
    assert!(
        output.status.success(),
        "self-healing dispatch checker should pass, stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_json: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&report)?)?;
    assert_eq!(report_json["status"].as_str(), Some("pass"));
    assert_eq!(
        report_json["completion_debt_bead"].as_str(),
        Some("bd-32e.4.1")
    );
    assert_eq!(report_json["original_bead"].as_str(), Some("bd-32e.4"));

    let actions = json_string_set(&report_json["required_healing_actions"])?;
    assert!(actions.contains("ClampSize"));
    assert!(actions.contains("UpgradeToSafeVariant"));
    let live_variants = json_string_set(&report_json["live_enum_variants"])?;
    assert!(live_variants.contains("None"));

    let log_content = std::fs::read_to_string(&log)?;
    let log_row: serde_json::Value = serde_json::from_str(log_content.trim())?;
    assert_eq!(
        log_row["event"].as_str(),
        Some("self_healing_dispatch_contract_validated")
    );
    assert_eq!(log_row["completion_debt_bead"].as_str(), Some("bd-32e.4.1"));
    assert_eq!(log_row["original_bead"].as_str(), Some("bd-32e.4"));
    assert_eq!(log_row["failure_signature"].as_str(), Some("none"));
    let log_fields = json_string_set(&log_row["required_healing_log_fields"])?;
    assert!(log_fields.contains("healing_action"));

    Ok(())
}

#[test]
fn checker_rejects_missing_healing_action_binding() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = read_manifest(&root)?;
    manifest["completion_debt_evidence"]["dispatch_contract"]["required_healing_actions"] =
        json!([
            "ClampSize",
            "TruncateWithNull",
            "IgnoreDoubleFree",
            "IgnoreForeignFree",
            "ReallocAsMalloc",
            "ReturnSafeDefault"
        ]);

    let fixture_dir = root.join("target/conformance/self_healing_dispatch_contract_mutation");
    std::fs::create_dir_all(&fixture_dir)?;
    let fixture = fixture_dir.join("missing_upgrade_action.json");
    let report = fixture_dir.join("missing_upgrade_action.report.json");
    let log = fixture_dir.join("missing_upgrade_action.log.jsonl");
    std::fs::write(&fixture, serde_json::to_string_pretty(&manifest)? + "\n")?;

    let output = Command::new("bash")
        .arg(root.join("scripts/check_self_healing_dispatch_contract.sh"))
        .env("FRANKENLIBC_SELF_HEALING_CONTRACT", &fixture)
        .env("FRANKENLIBC_SELF_HEALING_REPORT", &report)
        .env("FRANKENLIBC_SELF_HEALING_LOG", &log)
        .output()?;
    assert!(
        !output.status.success(),
        "checker should reject missing UpgradeToSafeVariant action binding"
    );

    let report_json: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&report)?)?;
    assert_eq!(report_json["status"].as_str(), Some("fail"));
    let errors = report_json["errors"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "errors should be array"))?;
    assert!(
        errors
            .iter()
            .filter_map(serde_json::Value::as_str)
            .any(|message| message.contains("required_healing_actions missing")),
        "failure report should mention the missing healing action"
    );

    let log_content = std::fs::read_to_string(&log)?;
    let log_row: serde_json::Value = serde_json::from_str(log_content.trim())?;
    assert_eq!(
        log_row["event"].as_str(),
        Some("self_healing_dispatch_contract_failed")
    );
    assert!(
        log_row["failure_signature"]
            .as_str()
            .is_some_and(|value| value.contains("required_healing_actions missing")),
        "failure log should include the action-drift signature"
    );

    Ok(())
}
