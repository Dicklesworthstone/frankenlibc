//! Integration test: callthrough census + decommission sequencing gate (bd-7ef9)
//!
//! Validates:
//! 1. callthrough_census artifact exists and has required top-level sections.
//! 2. symbol/module/wave summary counts are self-consistent.
//! 3. check_callthrough_census.sh exists, is executable, and passes.
//! 4. gate emits deterministic report + structured log artifacts.
//!
//! Run:
//!   cargo test -p frankenlibc-harness --test callthrough_census_test

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
    let artifact_path = root.join("tests/conformance/callthrough_census.v1.json");
    assert!(artifact_path.exists(), "missing {}", artifact_path.display());
    let artifact = load_json(&artifact_path);

    assert_eq!(artifact["schema_version"].as_str(), Some("v1"));
    assert_eq!(artifact["bead"].as_str(), Some("bd-7ef9"));
    assert!(artifact["source"].is_object(), "source must be object");
    assert!(
        artifact["ranking_policy"].is_object(),
        "ranking_policy must be object"
    );
    assert!(
        artifact["module_census"].is_array(),
        "module_census must be array"
    );
    assert!(
        artifact["symbol_census"].is_array(),
        "symbol_census must be array"
    );
    assert!(
        artifact["decommission_waves"].is_array(),
        "decommission_waves must be array"
    );
    assert!(artifact["summary"].is_object(), "summary must be object");
}

#[test]
fn artifact_summary_counts_match_rows() {
    let root = workspace_root();
    let artifact = load_json(&root.join("tests/conformance/callthrough_census.v1.json"));

    let modules = artifact["module_census"].as_array().unwrap();
    let symbols = artifact["symbol_census"].as_array().unwrap();
    let waves = artifact["decommission_waves"].as_array().unwrap();
    let summary = artifact["summary"].as_object().unwrap();

    assert!(!modules.is_empty(), "module_census must not be empty");
    assert!(!symbols.is_empty(), "symbol_census must not be empty");
    assert!(!waves.is_empty(), "decommission_waves must not be empty");

    assert_eq!(
        summary.get("module_count").and_then(|v| v.as_u64()),
        Some(modules.len() as u64),
        "summary.module_count mismatch"
    );
    assert_eq!(
        summary.get("symbol_count").and_then(|v| v.as_u64()),
        Some(symbols.len() as u64),
        "summary.symbol_count mismatch"
    );
    assert_eq!(
        summary.get("wave_count").and_then(|v| v.as_u64()),
        Some(waves.len() as u64),
        "summary.wave_count mismatch"
    );

    let strict_hot = symbols
        .iter()
        .filter(|row| row["perf_class"].as_str() == Some("strict_hotpath"))
        .count() as u64;
    let cold = symbols
        .iter()
        .filter(|row| row["perf_class"].as_str() == Some("coldpath"))
        .count() as u64;
    assert_eq!(
        summary.get("strict_hotpath_count").and_then(|v| v.as_u64()),
        Some(strict_hot),
        "summary.strict_hotpath_count mismatch"
    );
    assert_eq!(
        summary.get("coldpath_count").and_then(|v| v.as_u64()),
        Some(cold),
        "summary.coldpath_count mismatch"
    );
}

#[test]
fn gate_script_passes_and_emits_artifacts() {
    let root = workspace_root();
    let script = root.join("scripts/check_callthrough_census.sh");
    assert!(script.exists(), "missing {}", script.display());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_callthrough_census.sh must be executable"
        );
    }

    let output = Command::new(&script)
        .current_dir(&root)
        .output()
        .expect("failed to run callthrough census gate");
    assert!(
        output.status.success(),
        "callthrough census gate failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_path = root.join("target/conformance/callthrough_census.report.json");
    let log_path = root.join("target/conformance/callthrough_census.log.jsonl");
    assert!(report_path.exists(), "missing {}", report_path.display());
    assert!(log_path.exists(), "missing {}", log_path.display());

    let report = load_json(&report_path);
    assert_eq!(report["schema_version"].as_str(), Some("v1"));
    assert_eq!(report["bead"].as_str(), Some("bd-7ef9"));
    for check in [
        "artifact_reproducible",
        "support_matrix_alignment",
        "module_counts_consistent",
        "wave_coverage_complete",
        "wave_dependencies_valid",
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
        "trace_id",
        "mode",
        "api_family",
        "symbol",
        "decision_path",
        "healing_action",
        "errno",
        "latency_ns",
        "artifact_refs",
        "symbol_count",
        "module_count",
        "wave_count",
    ] {
        assert!(
            event.get(key).is_some(),
            "structured log row missing {key}"
        );
    }
}
