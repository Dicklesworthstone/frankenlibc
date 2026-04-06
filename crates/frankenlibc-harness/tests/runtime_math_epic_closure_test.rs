//! Integration test: aggregate runtime-math epic closure gate (`bd-5vr`).
//!
//! Validates that the aggregate gate exists, runs successfully, emits a
//! structured JSONL log, and produces a deterministic summary report tying the
//! runtime-math closure artifacts together.

use std::path::{Path, PathBuf};

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
    let content = std::fs::read_to_string(path).expect("json file should exist");
    serde_json::from_str(&content).expect("json should parse")
}

#[test]
fn gate_script_exists_and_is_executable() {
    let root = workspace_root();
    let script = root.join("scripts/check_runtime_math_epic_closure.sh");
    assert!(
        script.exists(),
        "scripts/check_runtime_math_epic_closure.sh must exist"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_runtime_math_epic_closure.sh must be executable"
        );
    }
}

#[test]
fn gate_script_emits_valid_report_and_log() {
    let root = workspace_root();
    let script = root.join("scripts/check_runtime_math_epic_closure.sh");

    let output = std::process::Command::new(&script)
        .current_dir(&root)
        .output()
        .expect("failed to run epic closure gate");

    assert!(
        output.status.success(),
        "epic closure gate failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_path = root.join("target/conformance/runtime_math_epic_closure.report.json");
    let log_path = root.join("target/conformance/runtime_math_epic_closure.log.jsonl");
    let checks_path = root.join("target/conformance/runtime_math_epic_closure.checks.jsonl");

    let (line_count, errors) = frankenlibc_harness::structured_log::validate_log_file(&log_path)
        .expect("structured log should be readable");
    assert!(
        errors.is_empty(),
        "structured log validation errors:\n{:#?}",
        errors
    );

    let report = load_json(&report_path);
    assert_eq!(report["schema_version"].as_str(), Some("v1"));
    assert_eq!(report["bead"].as_str(), Some("bd-5vr"));
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(
        report["summary"]["failed_checks"].as_u64(),
        Some(0),
        "aggregate gate should not report failures"
    );
    assert_eq!(
        report["summary"]["all_checks_passed"].as_bool(),
        Some(true),
        "aggregate gate should mark all checks as passed"
    );
    assert_eq!(
        report["summary"]["admission_blocked"].as_u64(),
        Some(0),
        "admission gate must not leave blocked runtime-math modules"
    );
    assert_eq!(
        report["summary"]["ablation_blocked"].as_u64(),
        Some(0),
        "ablation report must not leave blocked modules"
    );
    assert_eq!(
        report["summary"]["all_rounds_diverse"].as_bool(),
        Some(true),
        "reverse-round branch diversity must hold"
    );

    let checks = report["checks"]
        .as_array()
        .expect("report.checks must be an array");
    let total_checks = report["summary"]["total_checks"]
        .as_u64()
        .expect("summary.total_checks must be present") as usize;
    assert_eq!(checks.len(), total_checks);
    assert!(
        total_checks >= 9,
        "expected at least 9 aggregate closure checks, got {total_checks}"
    );
    for check in checks {
        assert_eq!(check["status"].as_str(), Some("pass"));
        assert!(
            check["artifact_refs"]
                .as_array()
                .is_some_and(|refs| !refs.is_empty()),
            "every check must carry artifact references"
        );
        assert!(
            check["summary_line"].as_str().is_some(),
            "every check must include a summary line"
        );
    }

    let manifest = load_json(&root.join("tests/runtime_math/production_kernel_manifest.v1.json"));
    assert_eq!(
        report["summary"]["production_modules"].as_u64(),
        Some(manifest["production_modules"].as_array().unwrap().len() as u64)
    );
    assert_eq!(
        report["summary"]["research_only_modules"].as_u64(),
        Some(manifest["research_only_modules"].as_array().unwrap().len() as u64)
    );

    let code_module_count =
        std::fs::read_to_string(root.join("crates/frankenlibc-membrane/src/runtime_math/mod.rs"))
            .expect("runtime_math mod.rs should exist")
            .lines()
            .filter(|line| line.starts_with("pub mod "))
            .count() as u64;
    assert_eq!(
        report["summary"]["total_modules"].as_u64(),
        Some(code_module_count),
        "summary.total_modules must match declared runtime_math modules"
    );

    let log_body = std::fs::read_to_string(&log_path).expect("log file should be readable");
    let log_events: Vec<serde_json::Value> = log_body
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("log line should parse"))
        .collect();
    let check_events = log_events
        .iter()
        .filter(|entry| entry["event"].as_str() == Some("runtime_math.epic_closure.check"))
        .count();
    let summary_events = log_events
        .iter()
        .filter(|entry| entry["event"].as_str() == Some("runtime_math.epic_closure.summary"))
        .count();
    assert_eq!(check_events, total_checks);
    assert_eq!(summary_events, 1);
    assert_eq!(line_count, log_events.len());

    let checks_body = std::fs::read_to_string(&checks_path).expect("checks jsonl should exist");
    let rendered_checks = checks_body
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count();
    assert_eq!(rendered_checks, total_checks);

    let artifacts = report["artifacts"]
        .as_object()
        .expect("artifacts must be an object");
    for key in [
        "manifest",
        "admission_report",
        "controller_manifest",
        "ablation_report",
        "governance",
        "linkage",
        "reverse_round_contracts",
        "value_proof",
        "structured_log",
        "checks_log",
    ] {
        assert!(artifacts.contains_key(key), "missing artifact ref: {key}");
    }
}
