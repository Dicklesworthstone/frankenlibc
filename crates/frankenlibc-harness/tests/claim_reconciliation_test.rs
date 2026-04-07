// claim_reconciliation_test.rs — bd-w2c3.10.1
// Verifies that the claim reconciliation engine detects no errors
// across FEATURE_PARITY/support/reality/replacement/docs artifacts.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn unique_temp_path(name: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("frankenlibc-{name}-{stamp}-{}", std::process::id()))
}

#[test]
fn claim_reconciliation_gate_passes() {
    let repo_root = workspace_root();

    let script = repo_root.join("scripts/claim_reconciliation.py");
    assert!(
        script.exists(),
        "claim_reconciliation.py not found at {:?}",
        script
    );

    let output = Command::new("python3")
        .arg(&script)
        .current_dir(&repo_root)
        .output()
        .expect("failed to run claim_reconciliation.py");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Parse the JSON report
    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "Failed to parse reconciliation report: {}\nstdout: {}\nstderr: {}",
            e, stdout, stderr
        );
    });

    let status = report["status"].as_str().unwrap_or("unknown");
    let errors = report["summary"]["errors"].as_u64().unwrap_or(999);
    let warnings = report["summary"]["warnings"].as_u64().unwrap_or(0);

    // Gate: zero errors required, warnings are informational
    assert_eq!(
        status,
        "pass",
        "Claim reconciliation failed with {} errors and {} warnings.\nFindings:\n{}",
        errors,
        warnings,
        serde_json::to_string_pretty(&report["findings"]).unwrap_or_default()
    );

    assert_eq!(
        errors, 0,
        "Claim reconciliation found {} error(s). See report for details.",
        errors
    );

    assert_eq!(
        report["report_artifact_path"].as_str(),
        Some("tests/conformance/claim_reconciliation_report.v1.json"),
        "canonical report artifact path must be stable"
    );
    assert!(
        report["input_artifacts"].is_array(),
        "input_artifacts must be emitted for deterministic replay"
    );
    assert!(
        report["owner_summary"].is_array(),
        "owner_summary must be present even when there are no findings"
    );

    let canonical_path = repo_root.join("tests/conformance/claim_reconciliation_report.v1.json");
    let canonical: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&canonical_path).expect("canonical claim reconciliation report"),
    )
    .expect("canonical claim reconciliation report must parse");
    assert_eq!(
        canonical, report,
        "canonical claim_reconciliation_report.v1.json is stale"
    );
}

#[test]
fn claim_reconciliation_detects_readme_drift_and_routes_owner() {
    let repo_root = workspace_root();
    let script = repo_root.join("scripts/claim_reconciliation.py");
    let readme_src = repo_root.join("README.md");
    let mutated_readme_path = unique_temp_path("claim-reconciliation-readme.md");

    let mutated_readme = std::fs::read_to_string(&readme_src)
        .expect("README.md should exist")
        .replace("total_exported=3980", "total_exported=1");
    std::fs::write(&mutated_readme_path, mutated_readme).expect("failed to write mutated README");

    let output = Command::new("python3")
        .arg(&script)
        .current_dir(&repo_root)
        .env("FLC_CLAIM_RECON_README", &mutated_readme_path)
        .output()
        .expect("failed to run claim_reconciliation.py with mutated README");

    assert!(
        !output.status.success(),
        "mutated README claim should fail reconciliation\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "Failed to parse reconciliation report: {}\nstdout: {}\nstderr: {}",
            e, stdout, stderr
        );
    });

    assert_eq!(report["status"].as_str(), Some("fail"));
    let findings = report["findings"]
        .as_array()
        .expect("findings must be an array");
    let stale_readme = findings.iter().find(|finding| {
        finding["category"].as_str() == Some("readme_stale")
            && finding["owner_bead"].as_str() == Some("bd-w2c3.10")
    });
    let stale_readme = stale_readme.expect("expected readme_stale finding routed to bd-w2c3.10");
    assert_eq!(stale_readme["source"].as_str(), Some("README.md"));
    assert!(
        stale_readme["remediation"]
            .as_str()
            .unwrap_or_default()
            .contains("README.md"),
        "README drift finding should include remediation text"
    );
    assert!(
        stale_readme["artifact_refs"]
            .as_array()
            .unwrap_or(&Vec::new())
            .iter()
            .any(|value| value.as_str() == Some("README.md")),
        "README drift finding should reference README.md"
    );

    let owner_summary = report["owner_summary"]
        .as_array()
        .expect("owner_summary must be array");
    assert!(
        owner_summary.iter().any(|row| {
            row["owner_bead"].as_str() == Some("bd-w2c3.10")
                && row["finding_count"].as_u64().unwrap_or(0) >= 1
        }),
        "owner summary must include bd-w2c3.10"
    );
}
