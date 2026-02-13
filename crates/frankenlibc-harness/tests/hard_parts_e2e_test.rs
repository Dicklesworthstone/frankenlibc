//! Integration test: hard-parts cross-boundary E2E catalog + classification gate (bd-2mwc).

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
    let content = std::fs::read_to_string(path).expect("json file should be readable");
    serde_json::from_str(&content).expect("json should parse")
}

#[test]
fn hard_parts_e2e_artifacts_have_expected_schema() {
    let root = workspace_root();
    let catalog_path = root.join("tests/conformance/hard_parts_e2e_catalog.v1.json");
    let matrix_path = root.join("tests/conformance/hard_parts_e2e_failure_matrix.v1.json");
    assert!(catalog_path.exists(), "missing {}", catalog_path.display());
    assert!(matrix_path.exists(), "missing {}", matrix_path.display());

    let catalog = load_json(&catalog_path);
    assert_eq!(catalog["schema_version"].as_str(), Some("v1"));
    assert_eq!(catalog["bead"].as_str(), Some("bd-2mwc"));
    assert!(catalog["generated_at"].is_string());
    assert!(catalog["sources"].is_object());
    assert!(catalog["deterministic_replay"].is_object());
    assert!(catalog["artifact_capture"].is_object());
    assert!(catalog["scenarios"].is_array());

    let scenarios = catalog["scenarios"].as_array().unwrap();
    assert_eq!(scenarios.len(), 6, "expected six hard-parts e2e scenarios");

    let required_subsystems = catalog["summary"]["required_subsystems"]
        .as_array()
        .expect("required_subsystems must be an array");
    assert_eq!(required_subsystems.len(), 6, "expected six hard-part subsystems");

    let matrix = load_json(&matrix_path);
    assert_eq!(matrix["schema_version"].as_str(), Some("v1"));
    assert_eq!(matrix["bead"].as_str(), Some("bd-2mwc"));
    assert!(matrix["classification_order"].is_array());
    assert!(matrix["classes"].is_array());
    assert!(matrix["required_output_fields"].is_array());
}

#[test]
fn hard_parts_e2e_gate_script_passes_and_emits_classification() {
    let root = workspace_root();
    let script = root.join("scripts/check_hard_parts_e2e.sh");
    assert!(script.exists(), "missing {}", script.display());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_hard_parts_e2e.sh must be executable"
        );
    }

    let seed = "62029";
    let output = Command::new("bash")
        .arg(&script)
        .env("FRANKENLIBC_HARD_PARTS_E2E_SEED", seed)
        .env("FRANKENLIBC_HARD_PARTS_E2E_TIMEOUT_SECONDS", "1")
        .env("FRANKENLIBC_HARD_PARTS_E2E_SCENARIO_CLASS", "smoke")
        .env("FRANKENLIBC_HARD_PARTS_E2E_RETRY_MAX", "0")
        .env("FRANKENLIBC_HARD_PARTS_E2E_STRESS_ITERS", "1")
        .env("FRANKENLIBC_HARD_PARTS_E2E_STABILITY_ITERS", "1")
        .current_dir(&root)
        .output()
        .expect("failed to execute check_hard_parts_e2e.sh");

    assert!(
        output.status.success(),
        "hard-parts e2e gate failed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let e2e_dir = root.join("target/e2e_suite");
    assert!(e2e_dir.exists(), "expected {} to exist", e2e_dir.display());

    let mut runs: Vec<_> = std::fs::read_dir(&e2e_dir)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            let name = entry.file_name().to_string_lossy().to_string();
            name.starts_with("e2e-") && name.ends_with(&format!("-s{seed}"))
        })
        .collect();
    runs.sort_by_key(|entry| entry.file_name());

    let latest = runs
        .last()
        .expect("expected at least one hard-parts e2e run directory");
    let report_path = latest.path().join("hard_parts_failure_classification.json");
    assert!(
        report_path.exists(),
        "missing classification report {}",
        report_path.display()
    );

    let report = load_json(&report_path);
    assert_eq!(report["schema_version"].as_str(), Some("v1"));
    assert_eq!(report["bead"].as_str(), Some("bd-2mwc"));
    assert!(report["trace_id"].is_string());
    assert!(report["class_counts"].is_object());
    assert!(report["classifications"].is_array());

    let rows = report["classifications"].as_array().unwrap();
    assert!(
        !rows.is_empty(),
        "classification report must contain at least one row"
    );
}
