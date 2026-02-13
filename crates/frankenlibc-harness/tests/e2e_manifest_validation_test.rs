//! Validation tests for deterministic E2E scenario manifests (bd-b5a.1).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn workspace_root() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn unique_temp_path(file_name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("frankenlibc-{nanos}-{file_name}"))
}

#[test]
fn validator_rejects_under_specified_scenario() {
    let root = workspace_root();
    let validator = root.join("scripts/validate_e2e_manifest.py");

    let invalid_manifest = r#"{
  "schema_version": "v1",
  "manifest_id": "invalid",
  "description": "missing required per-scenario fields",
  "replay_defaults": {
    "seed_key": "FRANKENLIBC_E2E_SEED",
    "env_keys": ["FRANKENLIBC_E2E_SEED"],
    "deterministic_inputs": "seed"
  },
  "scenarios": [
    {
      "id": "smoke.bad_case",
      "class": "smoke",
      "label": "bad_case",
      "priority": 0,
      "description": "Missing mode_expectations, artifact_policy, replay",
      "command": ["/bin/echo", "oops"]
    }
  ]
}"#;

    let temp_path = unique_temp_path("invalid-e2e-manifest.json");
    std::fs::write(&temp_path, invalid_manifest).expect("should write invalid manifest");

    let output = Command::new("python3")
        .arg(&validator)
        .arg("validate")
        .arg("--manifest")
        .arg(&temp_path)
        .output()
        .expect("validator should execute");

    let _ = std::fs::remove_file(&temp_path);

    assert!(
        !output.status.success(),
        "validator must reject under-specified scenario manifests"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("MANIFEST_ERROR:"),
        "validator should emit MANIFEST_ERROR diagnostics"
    );
}

#[test]
fn validator_metadata_lookup_succeeds_for_known_case() {
    let root = workspace_root();
    let validator = root.join("scripts/validate_e2e_manifest.py");
    let manifest = root.join("tests/conformance/e2e_scenario_manifest.v1.json");

    let output = Command::new("python3")
        .arg(&validator)
        .arg("metadata")
        .arg("--manifest")
        .arg(&manifest)
        .arg("--scenario-class")
        .arg("fault")
        .arg("--label")
        .arg("echo_empty")
        .arg("--mode")
        .arg("strict")
        .output()
        .expect("validator metadata command should execute");

    assert!(
        output.status.success(),
        "metadata lookup should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.starts_with("fault.echo_empty\tpass\t"),
        "metadata output should include scenario_id and expected outcome"
    );
}
