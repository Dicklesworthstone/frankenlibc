//! Integration test: bd-15n.2 fixture gap-fill strict+hardened artifact gate.

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
fn fixture_gap_fill_gate_emits_valid_bd15n2_artifacts() {
    let root = workspace_root();
    let script = root.join("scripts/check_bd15n2_fixture_gap_fill.sh");
    assert!(script.exists(), "missing {}", script.display());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_bd15n2_fixture_gap_fill.sh must be executable"
        );
    }

    let output = Command::new(&script)
        .current_dir(&root)
        .output()
        .expect("failed to run bd-15n.2 fixture gap-fill gate script");

    assert!(
        output.status.success(),
        "gate script failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let out_dir = root.join("tests/cve_arena/results/bd-15n.2");
    let trace_path = out_dir.join("trace.jsonl");
    let index_path = out_dir.join("artifact_index.json");
    let report_path = out_dir.join("report.json");

    assert!(trace_path.exists(), "missing {}", trace_path.display());
    assert!(index_path.exists(), "missing {}", index_path.display());
    assert!(report_path.exists(), "missing {}", report_path.display());

    let trace = std::fs::read_to_string(&trace_path).expect("trace should be readable");
    let mut result_rows = 0usize;
    let mut strict_seen = false;
    let mut hardened_seen = false;
    let mut ctype_seen = false;
    let mut math_seen = false;
    let mut socket_seen = false;

    for raw in trace.lines() {
        if raw.trim().is_empty() {
            continue;
        }
        let row: serde_json::Value =
            serde_json::from_str(raw).expect("trace line should be valid json");
        assert!(row["timestamp"].is_string());
        assert!(row["trace_id"].is_string());
        assert!(row["level"].is_string());
        assert!(row["event"].is_string());
        if row["event"].as_str() == Some("test_result") {
            result_rows += 1;
            match row["mode"].as_str() {
                Some("strict") => strict_seen = true,
                Some("hardened") => hardened_seen = true,
                other => panic!("unexpected mode in test_result row: {other:?}"),
            }
            match row["fixture_id"].as_str() {
                Some("fixture_ctype") => ctype_seen = true,
                Some("fixture_math") => math_seen = true,
                Some("fixture_socket") => socket_seen = true,
                _ => {}
            }
            assert!(row["spec_ref"].as_str().map(str::trim).unwrap_or("") != "");
            assert!(row["artifact_refs"].is_array());
            assert!(row["details"]["expected_vs_actual"].is_object());
        }
    }

    assert!(result_rows >= 6, "expected at least 6 test_result rows");
    assert!(strict_seen, "strict mode test_result rows missing");
    assert!(hardened_seen, "hardened mode test_result rows missing");
    assert!(ctype_seen, "fixture_ctype rows missing");
    assert!(math_seen, "fixture_math rows missing");
    assert!(socket_seen, "fixture_socket rows missing");

    let index = load_json(&index_path);
    assert_eq!(index["index_version"].as_i64(), Some(1));
    assert_eq!(index["bead_id"].as_str(), Some("bd-15n.2"));
    let artifacts = index["artifacts"].as_array().expect("artifacts should be array");
    assert!(!artifacts.is_empty(), "artifact index should not be empty");

    let report = load_json(&report_path);
    assert_eq!(report["schema_version"].as_str(), Some("v1"));
    assert_eq!(report["bead"].as_str(), Some("bd-15n.2"));
    assert_eq!(report["summary"]["fail_count"].as_i64(), Some(0));
    assert!(report["mode_profiles"]["strict"].is_object());
    assert!(report["mode_profiles"]["hardened"].is_object());

    let fixtures = report["fixtures"].as_array().expect("fixtures should be array");
    assert!(fixtures.len() >= 3, "expected at least three fixture metadata entries");
}
