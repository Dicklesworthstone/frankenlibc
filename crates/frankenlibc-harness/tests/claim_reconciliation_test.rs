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
        .replace("total_exported=3996", "total_exported=1");
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

#[test]
fn claim_reconciliation_detects_replacement_level_blocker_drift_and_routes_owner() {
    let repo_root = workspace_root();
    let script = repo_root.join("scripts/claim_reconciliation.py");
    let levels_src = repo_root.join("tests/conformance/replacement_levels.json");
    let mutated_levels_path = unique_temp_path("claim-reconciliation-replacement-levels.json");

    let canonical_blocker = "L1 claim promotion remains blocked until current_level and release_tag_policy.current_release_level move from L0 to L1 together under the bd-gtf.4 objective gate.";
    let mutated_blocker = "Eliminate all 6 stub symbols before L1 claim promotion.";
    let levels_text =
        std::fs::read_to_string(&levels_src).expect("replacement_levels.json should exist");
    assert!(
        levels_text.contains(canonical_blocker),
        "replacement_levels.json must contain the canonical L1 blocker line"
    );
    let mutated_levels = levels_text.replace(canonical_blocker, mutated_blocker);
    std::fs::write(&mutated_levels_path, mutated_levels)
        .expect("failed to write mutated replacement_levels.json");

    let output = Command::new("python3")
        .arg(&script)
        .current_dir(&repo_root)
        .env("FLC_CLAIM_RECON_REPLACEMENT_LEVELS", &mutated_levels_path)
        .output()
        .expect("failed to run claim_reconciliation.py with mutated replacement levels");

    assert!(
        !output.status.success(),
        "mutated replacement level blocker should fail reconciliation\nstdout={}\nstderr={}",
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
    let stale_blocker = findings.iter().find(|finding| {
        finding["category"].as_str() == Some("replacement_level_blocker_stale")
            && finding["owner_bead"].as_str() == Some("bd-w2c3.2.3")
    });
    let stale_blocker =
        stale_blocker.expect("expected replacement-level blocker drift routed to bd-w2c3.2.3");
    assert!(
        stale_blocker["source"]
            .as_str()
            .unwrap_or_default()
            .contains("replacement_levels.json"),
        "replacement-level drift finding should cite replacement_levels.json"
    );
    assert!(
        stale_blocker["message"]
            .as_str()
            .unwrap_or_default()
            .contains("stub_count"),
        "replacement-level drift finding should explain the stale blocker count"
    );
    assert!(
        stale_blocker["artifact_refs"]
            .as_array()
            .unwrap_or(&Vec::new())
            .iter()
            .any(|value| value.as_str() == Some("tests/conformance/replacement_levels.json")),
        "replacement-level drift finding should reference replacement_levels.json"
    );
}

#[test]
fn claim_reconciliation_detects_readme_smoke_overclaim_and_routes_replacement_owner() {
    let repo_root = workspace_root();
    let script = repo_root.join("scripts/claim_reconciliation.py");
    let readme_src = repo_root.join("README.md");
    let mutated_readme_path = unique_temp_path("claim-reconciliation-readme-smoke.md");

    let mutated_readme = std::fs::read_to_string(&readme_src)
        .expect("README.md should exist")
        .replace(
            "The checked curated preload smoke battery is green in both strict and hardened modes, but broader production hardening and release-claim closure are still in progress; use the canonical smoke artifact and gates rather than paraphrased README prose when the exact status matters.",
            "The latest broad preload smoke run is **fully green** and both strict and hardened modes pass all workloads.",
        );
    std::fs::write(&mutated_readme_path, mutated_readme)
        .expect("failed to write mutated README smoke overclaim");

    let output = Command::new("python3")
        .arg(&script)
        .current_dir(&repo_root)
        .env("FLC_CLAIM_RECON_README", &mutated_readme_path)
        .output()
        .expect("failed to run claim_reconciliation.py with mutated README smoke overclaim");

    assert!(
        !output.status.success(),
        "mutated README smoke overclaim should fail reconciliation\nstdout={}\nstderr={}",
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
    let smoke_claim = findings.iter().find(|finding| {
        finding["category"].as_str() == Some("replacement_smoke_claim_contradiction")
            && finding["owner_bead"].as_str() == Some("bd-w2c3.2.3")
    });
    let smoke_claim =
        smoke_claim.expect("expected replacement smoke claim contradiction routed to bd-w2c3.2.3");
    assert_eq!(smoke_claim["source"].as_str(), Some("README.md"));
    assert!(
        smoke_claim["message"]
            .as_str()
            .unwrap_or_default()
            .contains("ld_preload_smoke_summary.v1.json"),
        "replacement smoke contradiction should cite the canonical smoke summary"
    );
    assert!(
        smoke_claim["artifact_refs"]
            .as_array()
            .unwrap_or(&Vec::new())
            .iter()
            .any(|value| value.as_str() == Some("tests/conformance/replacement_levels.json")),
        "replacement smoke contradiction should reference replacement_levels.json"
    );
    assert!(
        smoke_claim["artifact_refs"]
            .as_array()
            .unwrap_or(&Vec::new())
            .iter()
            .any(|value| {
                value.as_str() == Some("tests/conformance/ld_preload_smoke_summary.v1.json")
            }),
        "replacement smoke contradiction should reference ld_preload_smoke_summary.v1.json"
    );
}

#[test]
fn claim_reconciliation_detects_readme_smoke_summary_drift_and_routes_owner() {
    let repo_root = workspace_root();
    let script = repo_root.join("scripts/claim_reconciliation.py");
    let readme_src = repo_root.join("README.md");
    let mutated_readme_path = unique_temp_path("claim-reconciliation-readme-smoke-summary.md");

    let canonical = "Canonical checked smoke artifact: `tests/conformance/ld_preload_smoke_summary.v1.json` (run `20260404T011731Z`, checked April 4, 2026) reports 58 passes / 0 fails / 6 skips overall, with strict 29/0/3 and hardened 29/0/3 across the curated preload smoke battery.";
    let stale = "Canonical checked smoke artifact: `tests/conformance/ld_preload_smoke_summary.v1.json` (run `20260405T000000Z`, checked April 5, 2026) reports 57 passes / 1 fails / 6 skips overall, with strict 28/1/3 and hardened 29/0/3 across the curated preload smoke battery.";
    let readme = std::fs::read_to_string(&readme_src).expect("README.md should exist");
    assert!(
        readme.contains(canonical),
        "README.md must contain the canonical checked smoke summary line"
    );

    let mutated_readme = readme.replace(canonical, stale);
    std::fs::write(&mutated_readme_path, mutated_readme)
        .expect("failed to write mutated README smoke summary");

    let output = Command::new("python3")
        .arg(&script)
        .current_dir(&repo_root)
        .env("FLC_CLAIM_RECON_README", &mutated_readme_path)
        .output()
        .expect("failed to run claim_reconciliation.py with mutated README smoke summary");

    assert!(
        !output.status.success(),
        "mutated README smoke summary should fail reconciliation\nstdout={}\nstderr={}",
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
    assert!(
        findings.iter().any(|finding| {
            finding["category"].as_str() == Some("smoke_summary_claim_stale")
                && finding["owner_bead"].as_str() == Some("bd-3rw.5.1")
                && finding["field"].as_str() == Some("checked_date_display")
        }),
        "expected checked_date_display smoke-summary drift routed to bd-3rw.5.1"
    );
    assert!(
        findings.iter().any(|finding| {
            finding["category"].as_str() == Some("smoke_summary_claim_stale")
                && finding["owner_bead"].as_str() == Some("bd-3rw.5.1")
                && finding["field"].as_str() == Some("summary.passes")
        }),
        "expected overall smoke pass-count drift routed to bd-3rw.5.1"
    );
    assert!(
        findings.iter().any(|finding| {
            finding["category"].as_str() == Some("smoke_summary_claim_stale")
                && finding["owner_bead"].as_str() == Some("bd-3rw.5.1")
                && finding["field"].as_str() == Some("modes.strict.passes")
        }),
        "expected per-mode smoke drift routed to bd-3rw.5.1"
    );
    assert!(
        findings.iter().all(|finding| {
            finding["category"].as_str() != Some("smoke_summary_claim_stale")
                || finding["artifact_refs"]
                    .as_array()
                    .unwrap_or(&Vec::new())
                    .iter()
                    .any(|value| {
                        value.as_str() == Some("tests/conformance/ld_preload_smoke_summary.v1.json")
                    })
        }),
        "smoke-summary drift findings should reference the canonical smoke artifact"
    );
}
