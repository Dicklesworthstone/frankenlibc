// runtime_math_admission_gate_test.rs — bd-3ot.3
// Verifies that the runtime-math admission gate runs without errors,
// enforces all required policies, and produces an auditable ledger.

use std::process::Command;

#[test]
fn admission_gate_passes() {
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();

    let script = repo_root.join("scripts/runtime_math_admission_gate.py");
    assert!(
        script.exists(),
        "runtime_math_admission_gate.py not found at {:?}",
        script
    );

    let output = Command::new("python3")
        .arg(&script)
        .current_dir(repo_root)
        .output()
        .expect("failed to run runtime_math_admission_gate.py");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "Failed to parse admission gate report: {}\nstdout: {}\nstderr: {}",
            e, stdout, stderr
        );
    });

    let status = report["status"].as_str().unwrap_or("unknown");
    assert_eq!(
        status,
        "pass",
        "Admission gate failed.\nErrors: {}\nFindings: {}",
        report["summary"]["errors"],
        serde_json::to_string_pretty(&report["findings"]).unwrap_or_default()
    );

    // Required report fields
    let required_keys = [
        "schema_version",
        "bead",
        "summary",
        "policies_enforced",
        "admission_ledger",
        "findings",
        "feature_gate_config",
        "artifacts_consumed",
        "controller_manifest_summary",
        "artifact_integrity",
        "tooling_contract",
        "artifacts_emitted",
    ];
    for key in required_keys {
        assert!(
            report.get(key).is_some(),
            "Report missing required key: {key}"
        );
    }

    // Summary fields
    let summary = &report["summary"];
    assert_eq!(summary["errors"].as_u64().unwrap_or(999), 0);
    assert!(summary["total_modules"].as_u64().unwrap_or(0) > 0);
    assert!(summary["admitted"].as_u64().is_some());
    assert!(summary["retired"].as_u64().is_some());
    assert!(summary["blocked"].as_u64().is_some());

    // Policies enforced must be non-empty
    let policies = report["policies_enforced"].as_array().unwrap();
    assert!(
        policies.len() >= 4,
        "Expected at least 4 policies enforced, got {}",
        policies.len()
    );

    let controller_summary = &report["controller_manifest_summary"];
    assert!(controller_summary["total_entries"].as_u64().unwrap_or(0) > 0);
    assert!(
        controller_summary["production_manifest_entries"]
            .as_u64()
            .is_some()
    );
    assert!(
        controller_summary["missing_decision_hook"]
            .as_u64()
            .is_some()
    );
    assert!(controller_summary["missing_invariant"].as_u64().is_some());
    assert!(controller_summary["missing_fallback"].as_u64().is_some());
    assert!(
        controller_summary["missing_benefit_target"]
            .as_u64()
            .is_some()
    );

    let emitted = report["artifacts_emitted"]
        .as_object()
        .expect("artifacts_emitted should be object");
    assert_eq!(
        emitted
            .get("structured_log")
            .and_then(serde_json::Value::as_str),
        Some("target/conformance/runtime_math_admission_gate.log.jsonl")
    );

    let tooling_contract = report["tooling_contract"]
        .as_object()
        .expect("tooling_contract should be object");
    for key in [
        "has_asupersync_dependency",
        "asupersync_feature_present",
        "default_enables_asupersync_tooling",
        "frankentui_feature_present",
        "frankentui_dependency_set_complete",
    ] {
        assert_eq!(
            tooling_contract
                .get(key)
                .and_then(serde_json::Value::as_bool),
            Some(true),
            "tooling contract expectation failed for key: {key}"
        );
    }
    assert!(
        tooling_contract.get("parse_error").is_none(),
        "tooling_contract.parse_error should not be present"
    );

    let integrity = report["artifact_integrity"]
        .as_object()
        .expect("artifact_integrity should be object");
    for key in [
        "governance",
        "manifest",
        "ablation_report",
        "linkage",
        "value_proof",
        "harness_cargo_manifest",
    ] {
        let entry = integrity.get(key).unwrap_or_else(|| {
            panic!("artifact_integrity missing entry: {key}");
        });
        let sha = entry["sha256"]
            .as_str()
            .unwrap_or_else(|| panic!("artifact_integrity.{key}.sha256 missing"));
        assert_eq!(
            sha.len(),
            64,
            "artifact_integrity.{key}.sha256 must be 64 hex chars"
        );
        assert!(
            sha.chars().all(|c| c.is_ascii_hexdigit()),
            "artifact_integrity.{key}.sha256 must be hex"
        );
        assert!(
            entry["size_bytes"].as_u64().unwrap_or(0) > 0,
            "artifact_integrity.{key}.size_bytes must be positive"
        );
    }
}

#[test]
fn admission_ledger_completeness() {
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();

    let report_path = repo_root.join("tests/runtime_math/admission_gate_report.v1.json");
    assert!(
        report_path.exists(),
        "Admission gate report not found at {:?}",
        report_path
    );

    let content = std::fs::read_to_string(&report_path).expect("failed to read report");
    let report: serde_json::Value =
        serde_json::from_str(&content).expect("report is not valid JSON");

    let ledger = report["admission_ledger"].as_array().unwrap();
    assert!(!ledger.is_empty(), "admission_ledger must be non-empty");

    // Every ledger entry must have required fields
    for entry in ledger {
        assert!(entry["module"].as_str().is_some(), "entry missing module");
        assert!(entry["tier"].as_str().is_some(), "entry missing tier");
        assert!(
            entry["ablation_decision"].as_str().is_some(),
            "entry missing ablation_decision"
        );
        assert!(
            entry["admission_status"].as_str().is_some(),
            "entry missing admission_status"
        );

        let status = entry["admission_status"].as_str().unwrap();
        assert!(
            [
                "ADMITTED",
                "RETIRED",
                "BLOCKED",
                "BLOCKED_NO_GOVERNANCE",
                "NOT_IN_MANIFEST",
                "REVIEW"
            ]
            .contains(&status),
            "Unknown admission_status: {status}"
        );
    }

    // Admitted + retired + blocked should cover all modules
    let total = report["summary"]["total_modules"].as_u64().unwrap();
    assert_eq!(
        ledger.len() as u64,
        total,
        "Ledger length ({}) != total_modules ({total})",
        ledger.len()
    );
}

#[test]
fn retirement_lockout_invariants() {
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();

    let report_path = repo_root.join("tests/runtime_math/admission_gate_report.v1.json");
    let content = std::fs::read_to_string(&report_path).expect("failed to read report");
    let report: serde_json::Value =
        serde_json::from_str(&content).expect("report is not valid JSON");

    let ledger = report["admission_ledger"].as_array().unwrap();

    // Invariant: research-tier modules must have RETIRED status
    for entry in ledger {
        if entry["tier"].as_str() == Some("research") {
            assert_eq!(
                entry["admission_status"].as_str().unwrap(),
                "RETIRED",
                "Research module {} must be RETIRED, got {}",
                entry["module"],
                entry["admission_status"]
            );
        }
    }

    // Invariant: production_core modules must have ADMITTED status
    for entry in ledger {
        if entry["tier"].as_str() == Some("production_core") {
            assert_eq!(
                entry["admission_status"].as_str().unwrap(),
                "ADMITTED",
                "Production core module {} must be ADMITTED, got {}",
                entry["module"],
                entry["admission_status"]
            );
        }
    }

    // Invariant: no BLOCKED modules (all are classified)
    assert_eq!(
        report["summary"]["blocked"].as_u64().unwrap(),
        0,
        "No modules should be blocked when governance is complete"
    );
}

#[test]
fn controller_manifest_artifact_is_complete() {
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();

    let manifest_path = repo_root.join("tests/runtime_math/controller_manifest.v1.json");
    assert!(
        manifest_path.exists(),
        "Controller manifest not found at {:?}",
        manifest_path
    );

    let content = std::fs::read_to_string(&manifest_path).expect("failed to read manifest");
    let manifest: serde_json::Value =
        serde_json::from_str(&content).expect("manifest is not valid JSON");

    for key in [
        "schema_version",
        "bead",
        "summary",
        "controllers",
        "sources",
    ] {
        assert!(
            manifest.get(key).is_some(),
            "controller manifest missing key: {key}"
        );
    }

    let controllers = manifest["controllers"]
        .as_array()
        .expect("controllers must be an array");
    assert!(
        !controllers.is_empty(),
        "controllers array must be non-empty"
    );

    for controller in controllers {
        for key in [
            "module",
            "tier",
            "decision_hook",
            "invariant",
            "fallback_when_data_missing",
            "runtime_cost_target",
        ] {
            assert!(
                controller.get(key).is_some(),
                "controller entry missing key: {key}"
            );
        }
    }
}

#[test]
fn admission_gate_emits_structured_log_with_required_fields() {
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();

    let script = repo_root.join("scripts/runtime_math_admission_gate.py");
    let output = Command::new("python3")
        .arg(&script)
        .current_dir(repo_root)
        .output()
        .expect("failed to run runtime_math_admission_gate.py");
    assert!(
        output.status.success(),
        "runtime_math_admission_gate.py failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let log_path = repo_root.join("target/conformance/runtime_math_admission_gate.log.jsonl");
    assert!(
        log_path.exists(),
        "missing structured log at {:?}",
        log_path
    );

    let (line_count, errors) = frankenlibc_harness::structured_log::validate_log_file(&log_path)
        .expect("structured log should be readable");
    assert_eq!(line_count, 1, "expected exactly one summary log line");
    assert!(errors.is_empty(), "structured log errors: {errors:#?}");

    let content = std::fs::read_to_string(&log_path).expect("failed to read structured log");
    let line = content
        .lines()
        .find(|row| !row.trim().is_empty())
        .expect("structured log should contain one event");
    let row: serde_json::Value = serde_json::from_str(line).expect("log row should parse");

    for key in [
        "trace_id",
        "mode",
        "api_family",
        "symbol",
        "decision_path",
        "healing_action",
        "errno",
        "latency_ns",
        "artifact_refs",
    ] {
        assert!(row.get(key).is_some(), "structured log missing key: {key}");
    }
    assert_eq!(row["event"].as_str(), Some("runtime_math_admission_gate"));
    assert_eq!(row["bead_id"].as_str(), Some("bd-w2c3.5.3"));
    assert_eq!(row["outcome"].as_str(), Some("pass"));
    let decision_path = row["decision_path"].as_str().unwrap_or_default();
    assert!(
        decision_path.contains("integrity") && decision_path.contains("tooling_contract"),
        "decision_path should include integrity + tooling_contract stages, got {decision_path}"
    );
}
