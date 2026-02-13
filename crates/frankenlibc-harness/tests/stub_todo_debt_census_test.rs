//! Integration test: unified stub/TODO debt census guard (bd-1pbw).
//!
//! Validates:
//! 1) artifact exists and has required top-level sections.
//! 2) reconciliation and summary counts are self-consistent.
//! 3) check_stub_todo_debt_census.sh executes successfully and emits report/log.

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
    let artifact_path = root.join("tests/conformance/stub_todo_debt_census.v1.json");
    assert!(artifact_path.exists(), "missing {}", artifact_path.display());
    let artifact = load_json(&artifact_path);

    assert_eq!(artifact["schema_version"].as_str(), Some("v1"));
    assert_eq!(artifact["bead"].as_str(), Some("bd-1pbw"));
    assert!(artifact["source"].is_object(), "source must be object");
    assert!(
        artifact["exported_taxonomy_view"].is_object(),
        "exported_taxonomy_view must be object"
    );
    assert!(
        artifact["critical_source_debt"].is_object(),
        "critical_source_debt must be object"
    );
    assert!(artifact["risk_policy"].is_object(), "risk_policy must be object");
    assert!(
        artifact["risk_ranked_debt"].is_array(),
        "risk_ranked_debt must be array"
    );
    assert!(
        artifact["reconciliation"].is_object(),
        "reconciliation must be object"
    );
    assert!(artifact["summary"].is_object(), "summary must be object");
}

#[test]
fn reconciliation_counts_match_entries() {
    let root = workspace_root();
    let artifact = load_json(&root.join("tests/conformance/stub_todo_debt_census.v1.json"));

    let entries = artifact["critical_source_debt"]["entries"]
        .as_array()
        .expect("critical_source_debt.entries must be array");
    assert!(!entries.is_empty(), "critical_source_debt.entries must not be empty");

    let mut non_exported = std::collections::BTreeSet::new();
    let mut exported_shadow = std::collections::BTreeSet::new();
    for row in entries {
        let symbol = row["symbol"].as_str().expect("entry.symbol must be string");
        if row["in_support_matrix"]
            .as_bool()
            .expect("entry.in_support_matrix must be bool")
        {
            exported_shadow.insert(symbol.to_string());
        } else {
            non_exported.insert(symbol.to_string());
        }
    }

    let recon = artifact["reconciliation"].as_object().unwrap();
    assert_eq!(
        recon.get("critical_non_exported_todo_count")
            .and_then(|v| v.as_u64()),
        Some(non_exported.len() as u64),
        "critical_non_exported_todo_count mismatch"
    );
    assert_eq!(
        recon.get("critical_exported_shadow_todo_count")
            .and_then(|v| v.as_u64()),
        Some(exported_shadow.len() as u64),
        "critical_exported_shadow_todo_count mismatch"
    );
    assert_eq!(
        recon.get("ambiguity_resolved").and_then(|v| v.as_bool()),
        Some(true),
        "ambiguity_resolved must be true"
    );

    let ranking = artifact["risk_ranked_debt"].as_array().unwrap();
    assert_eq!(
        artifact["summary"]["priority_item_count"].as_u64(),
        Some(ranking.len() as u64),
        "summary.priority_item_count mismatch"
    );
    if let Some(first) = ranking.first() {
        assert_eq!(
            artifact["summary"]["top_priority_symbol"].as_str(),
            first["symbol"].as_str(),
            "summary.top_priority_symbol mismatch"
        );
    }
}

#[test]
fn gate_script_passes_and_emits_artifacts() {
    let root = workspace_root();
    let script = root.join("scripts/check_stub_todo_debt_census.sh");
    assert!(script.exists(), "missing {}", script.display());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_stub_todo_debt_census.sh must be executable"
        );
    }

    let output = Command::new(&script)
        .current_dir(&root)
        .output()
        .expect("failed to run stub/todo debt gate");
    assert!(
        output.status.success(),
        "stub/todo debt gate failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_path = root.join("target/conformance/stub_todo_debt_census.report.json");
    let log_path = root.join("target/conformance/stub_todo_debt_census.log.jsonl");
    assert!(report_path.exists(), "missing {}", report_path.display());
    assert!(log_path.exists(), "missing {}", log_path.display());

    let report = load_json(&report_path);
    assert_eq!(report["schema_version"].as_str(), Some("v1"));
    assert_eq!(report["bead"].as_str(), Some("bd-1pbw"));
    for check in [
        "artifact_reproducible",
        "exported_taxonomy_consistent",
        "source_debt_consistent",
        "risk_ranking_consistent",
        "reconciliation_consistent",
    ] {
        assert_eq!(
            report["checks"][check].as_str(),
            Some("pass"),
            "report checks.{check} should be pass"
        );
    }

    let log_line = std::fs::read_to_string(&log_path)
        .expect("log should be readable")
        .lines()
        .find(|line| !line.trim().is_empty())
        .expect("log should contain at least one row")
        .to_string();
    let event: serde_json::Value = serde_json::from_str(&log_line).expect("log row should parse");
    for key in [
        "timestamp",
        "trace_id",
        "level",
        "event",
        "bead_id",
        "stream",
        "gate",
        "mode",
        "api_family",
        "symbol",
        "outcome",
        "errno",
        "duration_ms",
        "artifact_refs",
        "details",
    ] {
        assert!(event.get(key).is_some(), "structured log row missing {key}");
    }
}
