//! Integration test: test-obligation dashboard + closure blockers (bd-3cco)

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
fn artifact_exists_and_has_expected_schema() {
    let root = workspace_root();
    let path = root.join("tests/conformance/test_obligation_dashboard.v1.json");
    let doc = load_json(&path);

    assert_eq!(doc["schema_version"].as_str(), Some("v1"));
    assert_eq!(doc["bead"].as_str(), Some("bd-3cco"));
    assert!(doc["summary"].is_object());
    assert!(doc["coverage_by_subsystem"].is_array());
    assert!(doc["blockers"].is_array());
    assert!(doc["by_bead"].is_array());
}

#[test]
fn blockers_have_required_fields_and_no_closed_bead_blockers() {
    let root = workspace_root();
    let path = root.join("tests/conformance/test_obligation_dashboard.v1.json");
    let doc = load_json(&path);
    let blockers = doc["blockers"]
        .as_array()
        .expect("blockers must be an array");

    for row in blockers {
        let bead_id = row["bead_id"].as_str().unwrap_or("<unknown>");
        assert!(
            row["bead_status"].is_string(),
            "{bead_id}: missing bead_status"
        );
        assert!(row["blocker"].is_string(), "{bead_id}: missing blocker");
        assert!(row["category"].is_string(), "{bead_id}: missing category");
        assert!(
            row["coverage_status"].is_string(),
            "{bead_id}: missing coverage_status"
        );
        assert!(row["subsystem"].is_string(), "{bead_id}: missing subsystem");
        assert_ne!(
            row["bead_status"].as_str(),
            Some("closed"),
            "{bead_id}: closed bead must not retain blockers"
        );
    }
}

#[test]
fn gate_script_exists_and_succeeds() {
    let root = workspace_root();
    let script = root.join("scripts/check_test_obligation_dashboard.sh");
    assert!(script.exists(), "missing {}", script.display());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_test_obligation_dashboard.sh must be executable"
        );
    }

    let output = Command::new(&script)
        .current_dir(&root)
        .output()
        .expect("failed to run test-obligation dashboard gate script");

    assert!(
        output.status.success(),
        "gate script failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
