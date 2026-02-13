//! Integration test: hard-parts docs/parity/support/reality truth reconciliation gate (bd-8sho).

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
fn hard_parts_truth_artifact_has_expected_schema() {
    let root = workspace_root();
    let path = root.join("tests/conformance/hard_parts_truth_table.v1.json");
    assert!(path.exists(), "missing {}", path.display());

    let doc = load_json(&path);
    assert_eq!(doc["schema_version"].as_str(), Some("v1"));
    assert_eq!(doc["bead"].as_str(), Some("bd-8sho"));
    assert!(doc["generated_at"].is_string());
    assert!(doc["sources"].is_object());
    assert!(doc["reality_snapshot"].is_object());
    assert!(doc["subsystems"].is_array());
    assert!(doc["contradictions"].is_array());
    assert!(doc["summary"].is_object());

    let subsystems = doc["subsystems"]
        .as_array()
        .expect("subsystems must be array");
    assert_eq!(subsystems.len(), 6, "expected six hard-part subsystem rows");

    let contradiction_count = doc["summary"]["contradiction_count"]
        .as_u64()
        .expect("summary.contradiction_count must be u64");
    assert_eq!(contradiction_count, 0, "contradiction count must be zero");
}

#[test]
fn hard_parts_truth_guard_script_passes() {
    let root = workspace_root();
    let script = root.join("scripts/check_hard_parts_truth.sh");
    assert!(script.exists(), "missing {}", script.display());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_hard_parts_truth.sh must be executable"
        );
    }

    let output = Command::new("bash")
        .arg(script)
        .current_dir(&root)
        .output()
        .expect("failed to run check_hard_parts_truth.sh");

    assert!(
        output.status.success(),
        "hard-parts truth guard failed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
