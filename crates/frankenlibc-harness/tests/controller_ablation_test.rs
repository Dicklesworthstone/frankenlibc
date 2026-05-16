// controller_ablation_test.rs — bd-3ot.2
// Verifies that the controller ablation harness runs without errors,
// produces valid partition decisions, and generates a migration plan.

use std::error::Error;
use std::io;
use std::process::Command;

#[test]
fn controller_ablation_passes() -> Result<(), Box<dyn Error>> {
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();

    let script = repo_root.join("scripts/controller_ablation.py");
    assert!(
        script.exists(),
        "controller_ablation.py not found at {:?}",
        script
    );

    let output = Command::new("python3")
        .arg(&script)
        .current_dir(repo_root)
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    let report: serde_json::Value = serde_json::from_str(&stdout).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Failed to parse ablation report: {e}\nstdout: {stdout}\nstderr: {stderr}"),
        )
    })?;

    // Gate: status must be "pass" (zero errors)
    let status = report["status"].as_str().unwrap_or("unknown");
    assert_eq!(
        status,
        "pass",
        "Controller ablation failed.\nErrors: {}\nFindings: {}",
        report["summary"]["errors"],
        serde_json::to_string_pretty(&report["findings"]).unwrap_or_default()
    );

    // Validate required report fields
    let required_keys = [
        "schema_version",
        "bead",
        "summary",
        "partition_decisions",
        "migration_plan",
        "expected_research_annex_omissions",
        "findings",
        "governance_source",
        "manifest_source",
    ];
    for key in required_keys {
        assert!(
            report.get(key).is_some(),
            "Report missing required key: {key}"
        );
    }

    // Validate summary fields
    let summary = &report["summary"];
    assert_eq!(summary["errors"].as_u64().unwrap_or(999), 0);
    assert_eq!(
        summary["warnings"].as_u64().unwrap_or(999),
        0,
        "Expected research-annex omissions must not be emitted as warnings"
    );
    assert!(summary["total_modules"].as_u64().unwrap_or(0) > 0);
    assert!(summary["production_retain"].as_u64().is_some());
    assert!(summary["research_retire"].as_u64().is_some());

    // Validate partition decisions are non-empty
    let decisions = report["partition_decisions"].as_array().unwrap();
    assert!(
        !decisions.is_empty(),
        "partition_decisions must be non-empty"
    );

    // Every decision must have required fields
    for d in decisions {
        assert!(d["module"].as_str().is_some(), "decision missing module");
        assert!(d["tier"].as_str().is_some(), "decision missing tier");
        assert!(
            d["decision"].as_str().is_some(),
            "decision missing decision"
        );
        assert!(
            d["partition"].as_str().is_some(),
            "decision missing partition"
        );

        let decision_val = d["decision"].as_str().unwrap();
        assert!(
            ["RETAIN", "RETIRE", "BLOCK"].contains(&decision_val),
            "Unknown decision value: {decision_val}"
        );
    }

    // Validate migration plan
    let plan = &report["migration_plan"];
    assert!(plan["total_to_retire"].as_u64().is_some());
    assert!(plan["feature_gate"].as_str().is_some());
    assert!(plan["modules"].as_array().is_some());

    // Migration plan module count must match research_retire count
    let retire_count = summary["research_retire"].as_u64().unwrap();
    let plan_count = plan["modules"].as_array().unwrap().len() as u64;
    assert_eq!(
        retire_count, plan_count,
        "Migration plan module count ({plan_count}) != research_retire ({retire_count})"
    );

    let expected_omissions = &report["expected_research_annex_omissions"];
    assert_eq!(
        expected_omissions["count"].as_u64(),
        Some(retire_count),
        "Expected omission count must match research_retire"
    );
    assert_eq!(
        summary["expected_research_annex_omissions"].as_u64(),
        Some(retire_count),
        "Summary expected omission count must match research_retire"
    );
    Ok(())
}

#[test]
fn controller_ablation_report_artifact_exists() {
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();

    let report_path = repo_root.join("tests/runtime_math/controller_ablation_report.v1.json");
    assert!(
        report_path.exists(),
        "Controller ablation report artifact not found at {:?}",
        report_path
    );

    let content = std::fs::read_to_string(&report_path).expect("failed to read report");
    let report: serde_json::Value =
        serde_json::from_str(&content).expect("report is not valid JSON");

    assert_eq!(
        report["schema_version"].as_str().unwrap_or(""),
        "v1",
        "Report schema_version must be v1"
    );
    assert_eq!(
        report["bead"].as_str().unwrap_or(""),
        "bd-3ot.2",
        "Report bead must be bd-3ot.2"
    );
}

#[test]
fn controller_ablation_partition_invariants() {
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();

    let report_path = repo_root.join("tests/runtime_math/controller_ablation_report.v1.json");
    let content = std::fs::read_to_string(&report_path).expect("failed to read report");
    let report: serde_json::Value =
        serde_json::from_str(&content).expect("report is not valid JSON");

    let decisions = report["partition_decisions"].as_array().unwrap();

    // Invariant: production_core always maps to RETAIN
    for d in decisions {
        if d["tier"].as_str() == Some("production_core") {
            assert_eq!(
                d["decision"].as_str().unwrap(),
                "RETAIN",
                "production_core module {} must be RETAIN",
                d["module"]
            );
            assert_eq!(d["partition"].as_str().unwrap(), "production");
        }
    }

    // Invariant: research always maps to RETIRE
    for d in decisions {
        if d["tier"].as_str() == Some("research") {
            assert_eq!(
                d["decision"].as_str().unwrap(),
                "RETIRE",
                "research module {} must be RETIRE",
                d["module"]
            );
            assert_eq!(d["partition"].as_str().unwrap(), "research_annex");
        }
    }

    // Invariant: sum of retain + retire + blocked == total
    let summary = &report["summary"];
    let total = summary["total_modules"].as_u64().unwrap();
    let retain = summary["production_retain"].as_u64().unwrap();
    let retire = summary["research_retire"].as_u64().unwrap();
    let blocked = summary["blocked"].as_u64().unwrap();
    let expected_omissions = summary["expected_research_annex_omissions"]
        .as_u64()
        .unwrap();
    assert_eq!(
        total,
        retain + retire + blocked,
        "Partition counts don't sum to total: {retain}+{retire}+{blocked} != {total}"
    );
    assert_eq!(
        expected_omissions, retire,
        "Expected research-annex omissions should exactly match retired research modules"
    );

    let omission_modules = report["expected_research_annex_omissions"]["modules"]
        .as_array()
        .unwrap();
    assert_eq!(
        omission_modules.len() as u64,
        retire,
        "Expected omission module list should match retired research modules"
    );
}
