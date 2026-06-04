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

fn parse_report(stdout: &str, stderr: &str) -> serde_json::Value {
    let parsed = serde_json::from_str(stdout);
    let error = parsed
        .as_ref()
        .err()
        .map(ToString::to_string)
        .unwrap_or_default();
    assert!(
        parsed.is_ok(),
        "Failed to parse reconciliation report: {}\nstdout: {}\nstderr: {}",
        error,
        stdout,
        stderr
    );
    parsed.expect("claim reconciliation report parse checked above")
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
    let report = parse_report(&stdout, &stderr);

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
    let support_matrix = repo_root.join("support_matrix.json");
    let mutated_readme_path = unique_temp_path("claim-reconciliation-readme.md");

    let support: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&support_matrix).expect("support_matrix.json should exist"),
    )
    .expect("support_matrix.json should parse");
    let total_exported = support["total_exported"]
        .as_u64()
        .expect("support_matrix total_exported should be numeric");
    let total_claim = format!("total_exported={total_exported}");

    let mutated_readme = std::fs::read_to_string(&readme_src)
        .expect("README.md should exist")
        .replace(&total_claim, "total_exported=1");
    assert_ne!(
        mutated_readme,
        std::fs::read_to_string(&readme_src).expect("README.md should still be readable"),
        "README mutation fixture must replace the current total_exported claim"
    );
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
    let report = parse_report(&stdout, &stderr);

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
fn claim_reconciliation_detects_replacement_level_smoke_drift_and_routes_owner() {
    let repo_root = workspace_root();
    let script = repo_root.join("scripts/claim_reconciliation.py");
    let levels_src = repo_root.join("tests/conformance/replacement_levels.json");
    let mutated_levels_path = unique_temp_path("claim-reconciliation-replacement-levels.json");

    let mut levels: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&levels_src).expect("replacement_levels.json should exist"),
    )
    .expect("replacement_levels.json should parse");
    let l1 = levels["levels"]
        .as_array_mut()
        .expect("levels must be an array")
        .iter_mut()
        .find(|entry| entry["level"].as_str() == Some("L1"))
        .expect("L1 level must exist");
    let smoke = l1["objective_gate"]["obligations"]
        .as_array_mut()
        .expect("objective obligations must be an array")
        .iter_mut()
        .find(|entry| entry["id"].as_str() == Some("hardened_smoke_battery"))
        .expect("hardened_smoke_battery obligation must exist");
    smoke["actual"]["run_id"] = serde_json::json!("20260602T073740Z-2701357");
    smoke["actual"]["overall_failed"] = serde_json::json!(true);
    smoke["actual"]["strict_status"] = serde_json::json!("red");
    smoke["actual"]["hardened_status"] = serde_json::json!("red");
    smoke["actual"]["perf_failures"] = serde_json::json!(6);
    smoke["actual"]["signature_guard_failures"] = serde_json::json!(12);
    smoke["outcome"] = serde_json::json!("blocked");
    l1["objective_gate"]["status"] = serde_json::json!("blocked");
    std::fs::write(
        &mutated_levels_path,
        serde_json::to_string_pretty(&levels).expect("mutated levels should serialize"),
    )
        .expect("failed to write mutated replacement_levels.json");

    let output = Command::new("python3")
        .arg(&script)
        .current_dir(&repo_root)
        .env("FLC_CLAIM_RECON_REPLACEMENT_LEVELS", &mutated_levels_path)
        .output()
        .expect("failed to run claim_reconciliation.py with mutated replacement levels");

    assert!(
        !output.status.success(),
        "mutated replacement level smoke evidence should fail reconciliation\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let report = parse_report(&stdout, &stderr);

    assert_eq!(report["status"].as_str(), Some("fail"));
    let findings = report["findings"]
        .as_array()
        .expect("findings must be an array");
    let stale_smoke = findings.iter().find(|finding| {
        finding["category"].as_str() == Some("replacement_level_smoke_evidence_stale")
            && finding["owner_bead"].as_str() == Some("bd-w2c3.2.3")
    });
    let stale_smoke =
        stale_smoke.expect("expected replacement-level smoke drift routed to bd-w2c3.2.3");
    assert!(
        stale_smoke["source"]
            .as_str()
            .unwrap_or_default()
            .contains("replacement_levels.json"),
        "replacement-level smoke drift finding should cite replacement_levels.json"
    );
    assert!(
        stale_smoke["message"]
            .as_str()
            .unwrap_or_default()
            .contains("ld_preload_smoke_summary.v1.json"),
        "replacement-level smoke drift finding should cite the canonical smoke summary"
    );
    assert!(
        stale_smoke["artifact_refs"]
            .as_array()
            .unwrap_or(&Vec::new())
            .iter()
            .any(|value| value.as_str() == Some("tests/conformance/replacement_levels.json")),
        "replacement-level smoke drift finding should reference replacement_levels.json"
    );
    assert!(
        stale_smoke["artifact_refs"]
            .as_array()
            .unwrap_or(&Vec::new())
            .iter()
            .any(|value| {
                value.as_str() == Some("tests/conformance/ld_preload_smoke_summary.v1.json")
            }),
        "replacement-level smoke drift finding should reference ld_preload_smoke_summary.v1.json"
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
            "The checked curated preload smoke battery has 60 pass / 0 fail / 4 optional skips across strict and hardened modes. This is a curated workload signal, not broad production workload readiness; non-curated workload stability and release-claim closure for L2/L3 replacement levels remain active work. The strict/hardened mode dichotomy itself is not a research artifact; it runs real binaries today.",
            "The latest broad preload smoke run is **fully green** and both strict and hardened modes pass all workloads.",
        );
    assert_ne!(
        mutated_readme,
        std::fs::read_to_string(&readme_src).expect("README.md should still be readable"),
        "README smoke overclaim mutation fixture must replace the current curated smoke sentence"
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
    let report = parse_report(&stdout, &stderr);

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

    let canonical = "Canonical checked smoke artifact: `tests/conformance/ld_preload_smoke_summary.v1.json` (run `SnowyMill-ldfix-20260603T034530Z`, checked June 3, 2026) reports 60 passes / 0 fails / 4 skips overall, with strict 30/0/2 and hardened 30/0/2 across the curated preload smoke battery.";
    let stale = "Canonical checked smoke artifact: `tests/conformance/ld_preload_smoke_summary.v1.json` (run `20260404T011731Z`, checked April 4, 2026) reports 58 passes / 0 fails / 6 skips overall, with strict 29/0/3 and hardened 29/0/3 across the curated preload smoke battery.";
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
    let report = parse_report(&stdout, &stderr);

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
