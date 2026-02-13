//! Integration test: thread hot-path optimization dossier guard (bd-18rq).
//!
//! Validates:
//! 1) thread optimization artifact has required sections.
//! 2) guard script passes with canonical inputs.
//! 3) guard script fails when selected opportunity score falls below threshold.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, OnceLock};

fn script_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

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

#[test]
fn artifact_shape_is_valid() {
    let root = workspace_root();
    let artifact_path = root.join("tests/conformance/thread_hotpath_optimization.v1.json");
    assert!(artifact_path.exists(), "missing {}", artifact_path.display());

    let artifact = load_json(&artifact_path);
    assert_eq!(artifact["schema_version"].as_str(), Some("v1"));
    assert_eq!(artifact["bead"].as_str(), Some("bd-18rq"));
    assert!(artifact["baseline_captures"].is_object());
    assert!(artifact["profile_bundle"].is_object());
    assert!(artifact["opportunity_selection"].is_object());
    assert!(artifact["single_lever_optimization"].is_object());
    assert!(artifact["summary"].is_object());

    let selected = artifact["opportunity_selection"]["selected_entry_score"]
        .as_f64()
        .expect("selected_entry_score must be f64");
    let threshold = artifact["opportunity_selection"]["threshold"]
        .as_f64()
        .expect("threshold must be f64");
    assert!(selected >= threshold, "selected score must satisfy threshold");
}

#[test]
fn guard_script_passes_with_current_inputs() {
    let _guard = script_lock().lock().unwrap();
    let root = workspace_root();
    let script = root.join("scripts/check_thread_hotpath_optimization.sh");
    assert!(script.exists(), "missing {}", script.display());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_thread_hotpath_optimization.sh must be executable"
        );
    }

    let output = Command::new(&script)
        .current_dir(&root)
        .output()
        .expect("failed to run thread optimization guard");
    assert!(
        output.status.success(),
        "thread optimization guard failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_path = root.join("target/conformance/thread_hotpath_optimization.report.json");
    let log_path = root.join("target/conformance/thread_hotpath_optimization.log.jsonl");
    assert!(report_path.exists(), "missing {}", report_path.display());
    assert!(log_path.exists(), "missing {}", log_path.display());

    let report = load_json(&report_path);
    assert_eq!(report["schema_version"].as_str(), Some("v1"));
    assert_eq!(report["bead"].as_str(), Some("bd-18rq"));
    for key in [
        "artifact_shape_valid",
        "baseline_budget_valid",
        "opportunity_selection_valid",
        "support_matrix_alignment_valid",
        "single_lever_proof_valid",
    ] {
        assert_eq!(
            report["checks"][key].as_str(),
            Some("pass"),
            "report checks.{key} should be pass"
        );
    }
}

#[test]
fn guard_script_fails_when_opportunity_score_below_threshold() {
    let _guard = script_lock().lock().unwrap();
    let root = workspace_root();
    let script = root.join("scripts/check_thread_hotpath_optimization.sh");
    let opp_path = root.join("tests/conformance/opportunity_matrix.json");
    let mut opp = load_json(&opp_path);
    let entries = opp["entries"].as_array_mut().expect("entries should be array");
    let mut touched = false;
    for row in entries.iter_mut() {
        if row["id"].as_str() == Some("opp-005") {
            row["score"] = serde_json::json!(1.9);
            touched = true;
            break;
        }
    }
    assert!(touched, "opp-005 should exist in opportunity_matrix");

    let tmp_name = format!(
        "opportunity_matrix_low_thread_{}_{}.json",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let tmp_path = std::env::temp_dir().join(tmp_name);
    std::fs::write(&tmp_path, serde_json::to_string_pretty(&opp).unwrap() + "\n").unwrap();

    let output = Command::new(&script)
        .env("FRANKENLIBC_THREAD_OPP_MATRIX_PATH", &tmp_path)
        .current_dir(&root)
        .output()
        .expect("failed to run thread optimization guard with modified opportunity matrix");

    let _ = std::fs::remove_file(&tmp_path);

    assert!(
        !output.status.success(),
        "guard should fail when selected opportunity score < threshold"
    );
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("selected score mismatch vs opportunity_matrix"),
        "failure output should mention selected score mismatch; output:\n{}",
        combined
    );
}
