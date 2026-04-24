//! Integration test: workload-ranked top-N API wave planning gate
//! (bd-3mam baseline, bd-1x3.2 uplift).
//!
//! Validates:
//! 1. workload_api_wave_plan artifact exists and has required sections.
//! 2. summary counts are consistent with ranking rows.
//! 3. check_workload_api_wave_plan.sh exists, is executable, and passes.
//! 4. gate emits deterministic report + structured log artifacts.
//!
//! Run:
//!   cargo test -p frankenlibc-harness --test workload_api_wave_plan_test

use std::collections::HashSet;
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

fn required_summary_u64(summary: &serde_json::Map<String, serde_json::Value>, key: &str) -> u64 {
    summary
        .get(key)
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_else(|| panic!("summary.{key} must be a non-negative integer"))
}

#[test]
fn artifact_exists_and_has_required_shape() {
    let root = workspace_root();
    let artifact_path = root.join("tests/conformance/workload_api_wave_plan.v1.json");
    assert!(
        artifact_path.exists(),
        "missing {}",
        artifact_path.display()
    );

    let artifact = load_json(&artifact_path);
    assert_eq!(artifact["schema_version"].as_str(), Some("v1"));
    assert_eq!(artifact["bead"].as_str(), Some("bd-3mam"));
    assert_eq!(artifact["uplift_bead"].as_str(), Some("bd-1x3.2"));

    assert!(artifact["inputs"].is_object(), "inputs must be object");
    assert!(artifact["scoring"].is_object(), "scoring must be object");
    assert!(
        artifact["module_ranking"].is_array(),
        "module_ranking must be array"
    );
    assert!(
        artifact["symbol_ranking_top_n"].is_array(),
        "symbol_ranking_top_n must be array"
    );
    assert!(
        artifact["implementation_waves"].is_object(),
        "implementation_waves must be object"
    );
    assert!(
        artifact["downgrade_policy"].is_object(),
        "downgrade_policy must be object"
    );
    assert!(artifact["wave_plan"].is_array(), "wave_plan must be array");
    assert!(
        artifact["integration_hooks"].is_object(),
        "integration_hooks must be object"
    );
    assert!(artifact["summary"].is_object(), "summary must be object");
}

#[test]
fn summary_counts_match_rows_and_hooks_present() {
    let root = workspace_root();
    let artifact = load_json(&root.join("tests/conformance/workload_api_wave_plan.v1.json"));

    let modules = artifact["module_ranking"].as_array().unwrap();
    let symbols = artifact["symbol_ranking_top_n"].as_array().unwrap();
    let waves = artifact["wave_plan"].as_array().unwrap();
    let summary = artifact["summary"].as_object().unwrap();
    let candidate_symbols = required_summary_u64(summary, "candidate_symbols");

    if candidate_symbols == 0 {
        assert!(
            modules.is_empty(),
            "module_ranking should be empty when all workload candidates are resolved"
        );
        assert!(
            symbols.is_empty(),
            "symbol_ranking_top_n should be empty when all workload candidates are resolved"
        );
        assert!(
            waves.is_empty(),
            "wave_plan should be empty when all workload candidates are resolved"
        );
    } else {
        assert!(!modules.is_empty(), "module_ranking must not be empty");
        assert!(
            !symbols.is_empty(),
            "symbol_ranking_top_n must not be empty"
        );
        assert!(!waves.is_empty(), "wave_plan must not be empty");
    }

    assert_eq!(
        summary.get("top_n").and_then(|v| v.as_u64()),
        Some(symbols.len() as u64),
        "summary.top_n mismatch"
    );
    assert_eq!(
        summary.get("module_count").and_then(|v| v.as_u64()),
        Some(modules.len() as u64),
        "summary.module_count mismatch"
    );
    assert_eq!(
        summary.get("wave_count").and_then(|v| v.as_u64()),
        Some(waves.len() as u64),
        "summary.wave_count mismatch"
    );
    let top50_size = required_summary_u64(summary, "top50_size");
    let top200_size = required_summary_u64(summary, "top200_size");
    let downgrade_count = required_summary_u64(summary, "downgrade_symbol_count");
    let top50_symbols = artifact["implementation_waves"]["top50"]["symbols"]
        .as_array()
        .expect("implementation_waves.top50.symbols must be array");
    let top200_symbols = artifact["implementation_waves"]["top200"]["symbols"]
        .as_array()
        .expect("implementation_waves.top200.symbols must be array");
    let downgraded = artifact["downgrade_policy"]["waived_symbols"]
        .as_array()
        .expect("downgrade_policy.waived_symbols must be array");
    assert_eq!(
        top50_size,
        top50_symbols.len() as u64,
        "summary.top50_size mismatch"
    );
    assert_eq!(
        top200_size,
        top200_symbols.len() as u64,
        "summary.top200_size mismatch"
    );
    assert_eq!(
        downgrade_count,
        downgraded.len() as u64,
        "summary.downgrade_symbol_count mismatch"
    );

    if candidate_symbols == 0 {
        assert!(
            matches!(summary.get("top_blocker_module"), Some(value) if value.is_null()),
            "summary.top_blocker_module should be null when there are no workload candidates"
        );
    } else {
        let top_blocker = summary
            .get("top_blocker_module")
            .and_then(|v| v.as_str())
            .expect("summary.top_blocker_module must be string");
        let module_names: HashSet<&str> = modules
            .iter()
            .filter_map(|row| row["module"].as_str())
            .collect();
        assert!(
            module_names.contains(top_blocker),
            "summary.top_blocker_module must appear in module_ranking"
        );
    }

    let hooks = artifact["integration_hooks"].as_object().unwrap();
    for key in ["setjmp", "tls", "threading", "hard_parts"] {
        let arr = hooks
            .get(key)
            .and_then(|v| v.as_array())
            .unwrap_or_else(|| panic!("integration_hooks.{key} must be array"));
        assert!(!arr.is_empty(), "integration_hooks.{key} must not be empty");
    }
}

#[test]
fn gate_script_passes_and_emits_artifacts() {
    let root = workspace_root();
    let script = root.join("scripts/check_workload_api_wave_plan.sh");
    assert!(script.exists(), "missing {}", script.display());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_workload_api_wave_plan.sh must be executable"
        );
    }

    let output = Command::new(&script)
        .current_dir(&root)
        .output()
        .expect("failed to run workload_api_wave_plan gate");
    assert!(
        output.status.success(),
        "workload_api_wave_plan gate failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_path = root.join("target/conformance/workload_api_wave_plan.report.json");
    let log_path = root.join("target/conformance/workload_api_wave_plan.log.jsonl");
    assert!(report_path.exists(), "missing {}", report_path.display());
    assert!(log_path.exists(), "missing {}", log_path.display());

    let report = load_json(&report_path);
    assert_eq!(report["schema_version"].as_str(), Some("v1"));
    assert_eq!(report["bead"].as_str(), Some("bd-1x3.2"));
    for check in [
        "artifact_reproducible",
        "ranking_consistency",
        "wave_dependencies_acyclic",
        "integration_hooks_present",
        "implementation_waves_consistent",
        "downgrade_policy_consistent",
        "summary_consistency",
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
        "latency_ns",
        "artifact_refs",
    ] {
        assert!(event.get(key).is_some(), "structured log row missing {key}");
    }
}
