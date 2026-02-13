// release_dry_run_test.rs — bd-w2c3.10.2
// Verifies that the release dry-run DAG runner produces a valid dossier
// and that the DAG schema is internally consistent.

use std::process::Command;

#[test]
fn release_dag_schema_valid() {
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();

    let dag_path = repo_root.join("tests/conformance/release_gate_dag.v1.json");
    assert!(dag_path.exists(), "DAG file not found at {:?}", dag_path);

    let content = std::fs::read_to_string(&dag_path).expect("failed to read DAG file");
    let dag: serde_json::Value =
        serde_json::from_str(&content).expect("DAG is not valid JSON");

    // Validate schema version
    assert_eq!(
        dag["schema_version"].as_u64().unwrap_or(0),
        1,
        "schema_version must be 1"
    );

    // Validate gates array
    let gates = dag["gates"].as_array().expect("gates must be an array");
    assert!(!gates.is_empty(), "gates must not be empty");

    // Validate topological order: every depends_on must appear before the gate
    let names: Vec<&str> = gates
        .iter()
        .map(|g| g["gate_name"].as_str().unwrap_or(""))
        .collect();

    for (idx, gate) in gates.iter().enumerate() {
        let name = gate["gate_name"].as_str().unwrap_or("");
        assert!(!name.is_empty(), "gate[{idx}] has empty gate_name");

        if let Some(deps) = gate["depends_on"].as_array() {
            for dep in deps {
                let dep_name = dep.as_str().unwrap_or("");
                let dep_idx = names.iter().position(|&n| n == dep_name);
                assert!(
                    dep_idx.is_some() && dep_idx.unwrap() < idx,
                    "gate '{name}': dependency '{dep_name}' must appear before it in the DAG"
                );
            }
        }

        // Validate new fields
        assert!(
            gate.get("critical").is_some(),
            "gate '{name}' must have 'critical' field"
        );
    }

    // Validate no duplicate gate names
    let unique: std::collections::HashSet<&str> = names.iter().copied().collect();
    assert_eq!(
        unique.len(),
        names.len(),
        "gate_name values must be unique"
    );
}

#[test]
fn release_dry_run_produces_valid_dossier() {
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();

    let script = repo_root.join("scripts/release_dry_run.sh");
    assert!(
        script.exists(),
        "release_dry_run.sh not found at {:?}",
        script
    );

    let dossier_path = std::env::temp_dir().join("frankenlibc_test_dossier.json");

    let output = Command::new("bash")
        .arg(&script)
        .args(["--mode", "dry-run", "--dossier-path"])
        .arg(&dossier_path)
        .current_dir(repo_root)
        .output()
        .expect("failed to run release_dry_run.sh");

    assert!(
        output.status.success(),
        "release dry-run failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        dossier_path.exists(),
        "dossier file not produced at {:?}",
        dossier_path
    );

    let content = std::fs::read_to_string(&dossier_path).expect("failed to read dossier");
    let dossier: serde_json::Value =
        serde_json::from_str(&content).expect("dossier is not valid JSON");

    // Validate dossier schema v2
    assert_eq!(
        dossier["schema_version"].as_u64().unwrap_or(0),
        2,
        "dossier schema_version must be 2"
    );

    // Validate summary
    let summary = &dossier["summary"];
    assert_eq!(
        summary["verdict"].as_str().unwrap_or(""),
        "PASS",
        "dry-run verdict must be PASS"
    );

    let total = summary["total"].as_u64().unwrap_or(0);
    let passed = summary["passed"].as_u64().unwrap_or(0);
    assert!(total > 0, "must have at least 1 gate");
    assert_eq!(total, passed, "all gates must pass in dry-run");

    // Validate artifact_index present
    assert!(
        dossier["artifact_index"].is_object(),
        "artifact_index must be an object"
    );

    // Validate per-gate fields
    let gates = dossier["gates"].as_array().expect("gates must be array");
    for gate in gates {
        assert!(
            gate["rationale"].is_string(),
            "gate {} must have rationale",
            gate["gate_name"]
        );
        assert!(
            gate["critical"].is_boolean(),
            "gate {} must have critical field",
            gate["gate_name"]
        );
    }

    // Cleanup
    let _ = std::fs::remove_file(&dossier_path);
}

#[test]
fn release_dry_run_fail_fast_produces_resume_state() {
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();

    let script = repo_root.join("scripts/release_dry_run.sh");
    let state_path = std::env::temp_dir().join("frankenlibc_test_resume_state.json");
    let log_path = std::env::temp_dir().join("frankenlibc_test_resume_log.jsonl");

    let output = Command::new("bash")
        .arg(&script)
        .args([
            "--mode",
            "dry-run",
            "--state-path",
        ])
        .arg(&state_path)
        .args(["--log-path"])
        .arg(&log_path)
        .env("FRANKENLIBC_RELEASE_SIMULATE_FAIL_GATE", "unit")
        .current_dir(repo_root)
        .output()
        .expect("failed to run release_dry_run.sh");

    // Should fail
    assert!(
        !output.status.success(),
        "expected failure when simulating gate fail"
    );

    // State file should exist with blocker chain
    assert!(
        state_path.exists(),
        "resume state file not produced at {:?}",
        state_path
    );

    let content = std::fs::read_to_string(&state_path).expect("failed to read state");
    let state: serde_json::Value =
        serde_json::from_str(&content).expect("state is not valid JSON");

    assert_eq!(
        state["failed_gate"].as_str().unwrap_or(""),
        "unit",
        "failed_gate must be 'unit'"
    );

    assert!(
        state["blocker_chain"].is_array(),
        "state must contain blocker_chain"
    );

    let chain = state["blocker_chain"]
        .as_array()
        .unwrap();
    assert!(
        !chain.is_empty(),
        "blocker_chain must not be empty"
    );

    assert!(
        state["resume_token"].is_string()
            && state["resume_token"].as_str().unwrap_or("").starts_with("v1:"),
        "resume_token must start with v1:"
    );

    // Cleanup
    let _ = std::fs::remove_file(&state_path);
    let _ = std::fs::remove_file(&log_path);
}
