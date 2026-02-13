// claim_reconciliation_test.rs — bd-w2c3.10.1
// Verifies that the claim reconciliation engine detects no errors
// across FEATURE_PARITY/support/reality/replacement/docs artifacts.

use std::process::Command;

#[test]
fn claim_reconciliation_gate_passes() {
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();

    let script = repo_root.join("scripts/claim_reconciliation.py");
    assert!(
        script.exists(),
        "claim_reconciliation.py not found at {:?}",
        script
    );

    let output = Command::new("python3")
        .arg(&script)
        .current_dir(repo_root)
        .output()
        .expect("failed to run claim_reconciliation.py");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Parse the JSON report
    let report: serde_json::Value =
        serde_json::from_str(&stdout).unwrap_or_else(|e| {
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
        status, "pass",
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
}
