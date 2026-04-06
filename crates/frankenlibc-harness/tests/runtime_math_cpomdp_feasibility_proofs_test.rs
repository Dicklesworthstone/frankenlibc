//! Integration test: runtime_math CPOMDP feasibility proofs (bd-249m.4)
//!
//! Validates that:
//! 1. The gate script exists and is executable.
//! 2. The gate script runs successfully.
//! 3. The gate emits structured JSONL logs plus JSON proof artifacts.
//! 4. The report encodes the expected feasible policy and zero duality gap.

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
fn gate_script_exists_and_executable() {
    let root = workspace_root();
    let script = root.join("scripts/check_runtime_math_cpomdp_feasibility_proofs.sh");
    assert!(
        script.exists(),
        "scripts/check_runtime_math_cpomdp_feasibility_proofs.sh must exist"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_runtime_math_cpomdp_feasibility_proofs.sh must be executable"
        );
    }
}

#[test]
fn gate_script_emits_logs_and_reports() {
    let root = workspace_root();
    let script = root.join("scripts/check_runtime_math_cpomdp_feasibility_proofs.sh");

    let output = std::process::Command::new(&script)
        .current_dir(&root)
        .output()
        .expect("failed to run CPOMDP feasibility proofs gate script");

    assert!(
        output.status.success(),
        "gate script failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let log_path = root.join("target/conformance/runtime_math_cpomdp_feasibility_proofs.log.jsonl");
    let report_path =
        root.join("target/conformance/runtime_math_cpomdp_feasibility_proofs.report.json");
    let feasibility_path = root.join("target/conformance/cpomdp_feasibility.json");
    let sensitivity_path = root.join("target/conformance/cpomdp_sensitivity.json");

    let (line_count, errors) = frankenlibc_harness::structured_log::validate_log_file(&log_path)
        .expect("log file should be readable");
    assert!(
        errors.is_empty(),
        "structured log validation errors:\n{:#?}",
        errors
    );
    assert!(
        line_count >= 6,
        "expected multiple log lines (got {line_count})"
    );

    let report = load_json(&report_path);
    assert_eq!(report["schema_version"].as_str(), Some("v1"));
    assert_eq!(report["bead"].as_str(), Some("bd-249m.4"));
    assert_eq!(report["summary"]["failed"].as_u64(), Some(0));
    assert_eq!(
        report["feasibility"]["feasible_policy"]["actions"]["Clean"].as_str(),
        Some("Allow")
    );
    assert_eq!(
        report["feasibility"]["feasible_policy"]["actions"]["Ambiguous"].as_str(),
        Some("Allow")
    );
    assert_eq!(
        report["feasibility"]["feasible_policy"]["actions"]["BoundsAlert"].as_str(),
        Some("Allow")
    );
    assert_eq!(
        report["feasibility"]["feasible_policy"]["actions"]["TemporalAlert"].as_str(),
        Some("Repair")
    );
    assert_eq!(
        report["feasibility"]["primal_solution"]["objective"].as_f64(),
        Some(1.0)
    );
    assert_eq!(
        report["feasibility"]["dual_solution"]["objective"].as_f64(),
        Some(1.0)
    );
    assert_eq!(
        report["feasibility"]["exhaustive_search"]["best_deterministic_matches_primal"].as_bool(),
        Some(true)
    );

    let feasibility = load_json(&feasibility_path);
    assert_eq!(feasibility["epsilon"].as_f64(), Some(0.001));
    assert_eq!(feasibility["throughput_target"].as_f64(), Some(0.95));
    assert_eq!(
        feasibility["feasible_policy"]["unsafe_allow_probability"].as_f64(),
        Some(0.00064)
    );

    let sensitivity = load_json(&sensitivity_path);
    let points = sensitivity["points"]
        .as_array()
        .expect("points should be an array");
    assert_eq!(points.len(), 7);
    assert_eq!(points[0]["epsilon"].as_f64(), Some(0.0001));
    assert_eq!(points[3]["epsilon"].as_f64(), Some(0.001));
    assert_eq!(points[6]["epsilon"].as_f64(), Some(0.01));
}
