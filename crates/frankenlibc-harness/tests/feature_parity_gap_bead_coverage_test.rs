//! Integration test: feature parity gap->bead coverage dashboard (bd-w2c3.1.3)

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
fn artifacts_exist_with_expected_schema() {
    let root = workspace_root();
    let json_path = root.join("tests/conformance/feature_parity_gap_bead_coverage.v1.json");
    let md_path = root.join("tests/conformance/feature_parity_gap_bead_dashboard.v1.md");

    assert!(json_path.exists(), "missing {}", json_path.display());
    assert!(md_path.exists(), "missing {}", md_path.display());

    let doc = load_json(&json_path);
    assert_eq!(doc["schema_version"].as_str(), Some("v1"));
    assert_eq!(doc["bead"].as_str(), Some("bd-w2c3.1.3"));
    assert!(doc["summary"].is_object());
    assert!(doc["rows"].is_array());
    assert!(doc["critical_blockers"].is_array());
    assert!(doc["dependency_bottlenecks"].is_array());
}

#[test]
fn rows_have_required_mapping_fields_and_are_covered() {
    let root = workspace_root();
    let json_path = root.join("tests/conformance/feature_parity_gap_bead_coverage.v1.json");
    let doc = load_json(&json_path);
    let rows = doc["rows"].as_array().expect("rows must be an array");
    assert!(!rows.is_empty(), "rows must be non-empty");

    for row in rows {
        let gap_id = row["gap_id"].as_str().unwrap_or("<unknown>");
        assert!(
            row["owner_bead"].is_string(),
            "{gap_id}: missing owner_bead"
        );
        assert!(
            row["source_file"].is_string(),
            "{gap_id}: missing source_file"
        );
        assert!(
            row["dependency_path"].is_array(),
            "{gap_id}: missing dependency_path"
        );
        assert!(
            row["expected_vs_actual"].is_object(),
            "{gap_id}: missing expected_vs_actual"
        );
        assert!(
            row["owner_found"].as_bool().unwrap_or(false),
            "{gap_id}: unresolved gap is uncovered"
        );
    }

    let uncovered = doc["summary"]["uncovered_gaps"]
        .as_u64()
        .expect("summary.uncovered_gaps must be u64");
    assert_eq!(uncovered, 0, "summary.uncovered_gaps must be zero");
}

#[test]
fn gate_script_exists_and_succeeds() {
    let root = workspace_root();
    let script = root.join("scripts/check_feature_parity_gap_bead_coverage.sh");
    assert!(script.exists(), "missing {}", script.display());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_feature_parity_gap_bead_coverage.sh must be executable"
        );
    }

    let output = Command::new(&script)
        .current_dir(&root)
        .output()
        .expect("failed to run feature parity gap-bead coverage gate script");

    assert!(
        output.status.success(),
        "gate script failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
