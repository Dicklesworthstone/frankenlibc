//! Integration test: healing oracle gate (bd-l93x.4)
//!
//! Validates:
//! 1. Baseline healing oracle artifact exists and has required schema.
//! 2. Summary counts are consistent with case rows.
//! 3. Strict+hardened case coverage is present for all unsafe conditions.
//! 4. Gate script executes and emits deterministic report/log artifacts.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace_root() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn load_json(path: &Path) -> serde_json::Value {
    let content = std::fs::read_to_string(path).expect("json should be readable");
    serde_json::from_str(&content).expect("json should parse")
}

#[test]
fn artifact_exists_and_has_required_shape() {
    let root = workspace_root();
    let artifact_path = root.join("tests/conformance/healing_oracle_report.v1.json");
    assert!(
        artifact_path.exists(),
        "missing {}",
        artifact_path.display()
    );

    let artifact = load_json(&artifact_path);
    assert_eq!(artifact["schema_version"].as_str(), Some("v1"));
    assert_eq!(artifact["bead"].as_str(), Some("bd-l93x.4"));
    assert!(artifact["summary"].is_object(), "summary must be object");
    assert!(artifact["cases"].is_array(), "cases must be array");
}

#[test]
fn summary_counts_match_case_rows() {
    let root = workspace_root();
    let artifact = load_json(&root.join("tests/conformance/healing_oracle_report.v1.json"));
    let rows = artifact["cases"].as_array().expect("cases should be array");
    let summary = artifact["summary"]
        .as_object()
        .expect("summary should be object");

    let total = rows.len() as u64;
    let passed = rows
        .iter()
        .filter(|row| row["status"].as_str() == Some("pass"))
        .count() as u64;
    let failed = rows
        .iter()
        .filter(|row| row["status"].as_str() != Some("pass"))
        .count() as u64;
    let detected = rows
        .iter()
        .filter(|row| row["detected"].as_bool() == Some(true))
        .count() as u64;
    let repaired = rows
        .iter()
        .filter(|row| row["repaired"].as_bool() == Some(true))
        .count() as u64;
    let posix_valid = rows
        .iter()
        .filter(|row| row["posix_valid"].as_bool() == Some(true))
        .count() as u64;
    let evidence_logged = rows
        .iter()
        .filter(|row| row["evidence_logged"].as_bool() == Some(true))
        .count() as u64;

    assert_eq!(
        summary.get("total_cases").and_then(|v| v.as_u64()),
        Some(total),
        "summary.total_cases mismatch"
    );
    assert_eq!(
        summary.get("passed").and_then(|v| v.as_u64()),
        Some(passed),
        "summary.passed mismatch"
    );
    assert_eq!(
        summary.get("failed").and_then(|v| v.as_u64()),
        Some(failed),
        "summary.failed mismatch"
    );
    assert_eq!(
        summary.get("detected").and_then(|v| v.as_u64()),
        Some(detected),
        "summary.detected mismatch"
    );
    assert_eq!(
        summary.get("repaired").and_then(|v| v.as_u64()),
        Some(repaired),
        "summary.repaired mismatch"
    );
    assert_eq!(
        summary.get("posix_valid").and_then(|v| v.as_u64()),
        Some(posix_valid),
        "summary.posix_valid mismatch"
    );
    assert_eq!(
        summary.get("evidence_logged").and_then(|v| v.as_u64()),
        Some(evidence_logged),
        "summary.evidence_logged mismatch"
    );
}

#[test]
fn strict_and_hardened_rows_cover_all_conditions() {
    let root = workspace_root();
    let artifact = load_json(&root.join("tests/conformance/healing_oracle_report.v1.json"));
    let rows = artifact["cases"].as_array().expect("cases should be array");

    let mut strict_conditions: BTreeSet<String> = BTreeSet::new();
    let mut hardened_conditions: BTreeSet<String> = BTreeSet::new();
    for row in rows {
        let mode = row["mode"].as_str().unwrap_or_default();
        let condition = row["condition"].as_str().unwrap_or_default().to_string();
        if condition.is_empty() {
            continue;
        }
        if mode == "strict" {
            strict_conditions.insert(condition.clone());
        }
        if mode == "hardened" {
            hardened_conditions.insert(condition);
        }
    }

    assert_eq!(
        strict_conditions, hardened_conditions,
        "strict/hardened should cover identical condition set"
    );
    assert_eq!(
        strict_conditions.len(),
        7,
        "expected all 7 unsafe conditions to be covered"
    );
}

#[test]
fn gate_script_passes_and_emits_artifacts() {
    let root = workspace_root();
    let script = root.join("scripts/check_healing_oracle.sh");
    assert!(script.exists(), "missing {}", script.display());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_healing_oracle.sh must be executable"
        );
    }

    let output = Command::new(&script)
        .current_dir(&root)
        .output()
        .expect("failed to run healing oracle gate");
    assert!(
        output.status.success(),
        "healing oracle gate failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_path = root.join("target/conformance/healing_oracle_gate.report.json");
    let log_path = root.join("target/conformance/healing_oracle_gate.log.jsonl");
    assert!(report_path.exists(), "missing {}", report_path.display());
    assert!(log_path.exists(), "missing {}", log_path.display());

    let report = load_json(&report_path);
    assert_eq!(report["schema_version"].as_str(), Some("v1"));
    assert_eq!(report["bead"].as_str(), Some("bd-l93x.4"));
    for check in [
        "shape_valid",
        "no_pass_to_nonpass_regressions",
        "no_missing_baseline_cases",
        "summary_consistent",
        "strict_and_hardened_covered",
    ] {
        assert_eq!(
            report["checks"][check].as_str(),
            Some("pass"),
            "report checks.{check} should be pass"
        );
    }

    let first_line = std::fs::read_to_string(&log_path)
        .expect("gate log should be readable")
        .lines()
        .find(|line| !line.trim().is_empty())
        .expect("gate log should contain at least one row")
        .to_string();
    let event: serde_json::Value = serde_json::from_str(&first_line).expect("log row should parse");
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
        "case_count",
        "pass_count",
        "fail_count",
    ] {
        assert!(event.get(key).is_some(), "structured log row missing {key}");
    }
}
