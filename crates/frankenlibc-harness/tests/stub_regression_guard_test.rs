//! Integration test: stub regression prevention guard + waiver policy
//! (bd-1p5v uplifted by bd-1x3.3).
//!
//! Validates:
//! 1) waiver policy artifact has required shape.
//! 2) guard script passes with the canonical policy.
//! 3) guard script fails deterministically when a required waiver is removed.

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
fn waiver_policy_has_required_shape() {
    let root = workspace_root();
    let policy_path = root.join("tests/conformance/stub_regression_waiver_policy.v1.json");
    assert!(policy_path.exists(), "missing {}", policy_path.display());
    let policy = load_json(&policy_path);

    assert_eq!(policy["schema_version"].as_str(), Some("v1"));
    assert_eq!(policy["bead"].as_str(), Some("bd-1p5v"));
    assert!(policy["policy"].is_object(), "policy must be object");
    assert!(policy["waivers"].is_array(), "waivers must be array");
    assert!(
        policy["matrix_waivers"].is_array(),
        "matrix_waivers must be array"
    );
    assert!(policy["summary"].is_object(), "summary must be object");

    let waivers = policy["waivers"].as_array().unwrap();
    assert!(!waivers.is_empty(), "waivers must not be empty");
    for waiver in waivers {
        for key in [
            "symbol",
            "scope",
            "risk_tier",
            "reason",
            "owner_bead",
            "approved_by",
            "expires_utc",
        ] {
            assert!(
                waiver.get(key).is_some(),
                "waiver missing required field {key}"
            );
        }
    }

    let policy_obj = policy["policy"].as_object().unwrap();
    assert!(
        policy_obj
            .get("burn_down_thresholds")
            .and_then(|v| v.as_object())
            .is_some(),
        "policy.burn_down_thresholds must be object"
    );
    assert!(
        policy_obj
            .get("downgrade_evidence_requirements")
            .and_then(|v| v.as_array())
            .is_some(),
        "policy.downgrade_evidence_requirements must be array"
    );
}

#[test]
fn guard_script_passes_with_current_policy() {
    let _guard = script_lock().lock().unwrap();
    let root = workspace_root();
    let script = root.join("scripts/check_stub_regression_guard.sh");
    assert!(script.exists(), "missing {}", script.display());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_stub_regression_guard.sh must be executable"
        );
    }

    let output = Command::new(&script)
        .current_dir(&root)
        .output()
        .expect("failed to run stub regression guard");
    assert!(
        output.status.success(),
        "stub regression guard failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_path = root.join("target/conformance/stub_regression_guard.report.json");
    let log_path = root.join("target/conformance/stub_regression_guard.log.jsonl");
    assert!(report_path.exists(), "missing {}", report_path.display());
    assert!(log_path.exists(), "missing {}", log_path.display());

    let report = load_json(&report_path);
    assert_eq!(report["schema_version"].as_str(), Some("v1"));
    assert_eq!(report["bead"].as_str(), Some("bd-1x3.3"));
    assert_eq!(report["uplift_bead"].as_str(), Some("bd-1p5v"));
    for check in [
        "artifact_current",
        "waiver_schema_valid",
        "symbol_coverage_valid",
        "matrix_stub_policy_valid",
        "stale_waivers_absent",
        "waiver_evidence_valid",
        "burn_down_thresholds_valid",
        "downgrade_evidence_valid",
    ] {
        assert_eq!(
            report["checks"][check].as_str(),
            Some("pass"),
            "report checks.{check} should be pass"
        );
    }
}

#[test]
fn guard_script_fails_when_required_waiver_missing() {
    let _guard = script_lock().lock().unwrap();
    let root = workspace_root();
    let script = root.join("scripts/check_stub_regression_guard.sh");
    let policy_path = root.join("tests/conformance/stub_regression_waiver_policy.v1.json");
    let mut policy = load_json(&policy_path);

    let waivers = policy["waivers"]
        .as_array_mut()
        .expect("waivers must be array");
    let original_len = waivers.len();
    waivers.retain(|row| row["symbol"].as_str() != Some("setjmp"));
    assert!(
        waivers.len() < original_len,
        "test fixture edit should remove at least one waiver"
    );

    let tmp_name = format!(
        "stub_regression_policy_missing_setjmp_{}_{}.json",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let tmp_path = std::env::temp_dir().join(tmp_name);
    std::fs::write(
        &tmp_path,
        serde_json::to_string_pretty(&policy).unwrap() + "\n",
    )
    .unwrap();

    let output = Command::new(&script)
        .env("FRANKENLIBC_STUB_WAIVER_POLICY_PATH", &tmp_path)
        .current_dir(&root)
        .output()
        .expect("failed to run stub regression guard");

    let _ = std::fs::remove_file(&tmp_path);

    assert!(
        !output.status.success(),
        "guard should fail when required waiver is missing"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}\n{stderr}");
    assert!(
        combined.contains("setjmp: missing_waiver"),
        "failure diagnostics should mention missing waiver for setjmp; output:\n{}",
        combined
    );

    let report_path = root.join("target/conformance/stub_regression_guard.report.json");
    let report = load_json(&report_path);
    assert_eq!(
        report["checks"]["symbol_coverage_valid"].as_str(),
        Some("fail"),
        "symbol_coverage_valid should fail for missing waiver fixture"
    );
}

#[test]
fn guard_script_fails_when_burn_down_threshold_is_too_strict() {
    let _guard = script_lock().lock().unwrap();
    let root = workspace_root();
    let script = root.join("scripts/check_stub_regression_guard.sh");
    let policy_path = root.join("tests/conformance/stub_regression_waiver_policy.v1.json");
    let mut policy = load_json(&policy_path);

    policy["policy"]["burn_down_thresholds"]["max_symbols_unscheduled"] =
        serde_json::Value::from(10_u64);

    let tmp_name = format!(
        "stub_regression_policy_threshold_fail_{}_{}.json",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let tmp_path = std::env::temp_dir().join(tmp_name);
    std::fs::write(
        &tmp_path,
        serde_json::to_string_pretty(&policy).unwrap() + "\n",
    )
    .unwrap();

    let output = Command::new(&script)
        .env("FRANKENLIBC_STUB_WAIVER_POLICY_PATH", &tmp_path)
        .current_dir(&root)
        .output()
        .expect("failed to run stub regression guard");

    let _ = std::fs::remove_file(&tmp_path);

    assert!(
        !output.status.success(),
        "guard should fail when burn-down threshold is exceeded"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}\n{stderr}");
    assert!(
        combined.contains("max_symbols_unscheduled exceeded"),
        "expected threshold failure diagnostics; output:\n{}",
        combined
    );

    let report_path = root.join("target/conformance/stub_regression_guard.report.json");
    let report = load_json(&report_path);
    assert_eq!(
        report["checks"]["burn_down_thresholds_valid"].as_str(),
        Some("fail"),
        "burn_down_thresholds_valid should fail for strict threshold fixture"
    );
}
