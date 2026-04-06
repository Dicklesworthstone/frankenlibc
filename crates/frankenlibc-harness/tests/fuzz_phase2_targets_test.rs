// fuzz_phase2_targets_test.rs — bd-1oz.7
// Integration tests for phase-2 fuzz readiness and nightly policy coverage.

use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn repo_root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn load_json(path: &Path) -> serde_json::Value {
    let content = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));
    serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("Invalid JSON in {}: {}", path.display(), e))
}

fn temp_dir(label: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("frankenlibc-{label}-{nanos}"));
    fs::create_dir_all(&path).expect("create temp dir");
    path
}

#[cfg(unix)]
fn set_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    let mut perms = fs::metadata(path).expect("metadata").permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms).expect("set permissions");
}

#[test]
fn phase2_report_generates_successfully() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fuzz_phase2_targets.v1.json");
    let output = Command::new("python3")
        .args([
            root.join("scripts/generate_fuzz_phase2_targets.py")
                .to_str()
                .unwrap(),
            "-o",
            report_path.to_str().unwrap(),
        ])
        .current_dir(&root)
        .output()
        .expect("failed to execute phase-2 target generator");
    assert!(
        output.status.success(),
        "Phase-2 target generator failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(report_path.exists());
}

#[test]
fn phase2_schema_complete() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fuzz_phase2_targets.v1.json");
    let data = load_json(&report_path);

    assert_eq!(data["schema_version"].as_str(), Some("v1"));
    assert_eq!(data["bead"].as_str(), Some("bd-1oz.7"));
    assert!(data["validation_hash"].is_string());
    assert!(data["target_assessments"].is_array());
    assert!(data["smoke_test_configs"].is_object());
    assert!(data["nightly_policy"].is_object());
    assert!(data["coverage_summary"].is_object());
}

#[test]
fn phase2_targets_cover_required_transition_families() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fuzz_phase2_targets.v1.json");
    let data = load_json(&report_path);

    let families = data["coverage_summary"]["transition_families"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|item| item.as_str())
        .collect::<std::collections::BTreeSet<_>>();

    for required in ["resolver", "locale", "runtime-math"] {
        assert!(
            families.contains(required),
            "missing transition family: {required}"
        );
    }
}

#[test]
fn phase2_targets_are_smoke_viable() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fuzz_phase2_targets.v1.json");
    let data = load_json(&report_path);

    let targets = data["target_assessments"].as_array().unwrap();
    assert_eq!(targets.len(), 4, "expected 4 phase-2 targets");
    for target in targets {
        let name = target["target"].as_str().unwrap_or("unknown");
        assert!(
            target["smoke_viable"].as_bool().unwrap(),
            "target {name} is not smoke-viable"
        );
    }
}

#[test]
fn phase2_nightly_policy_matches_target_inventory() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fuzz_phase2_targets.v1.json");
    let data = load_json(&report_path);

    let targets = data["target_assessments"].as_array().unwrap();
    let target_names = targets
        .iter()
        .map(|item| item["target"].as_str().unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    let policy_targets = data["nightly_policy"]["required_targets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item.as_str().unwrap())
        .collect::<std::collections::BTreeSet<_>>();

    assert_eq!(
        data["nightly_policy"]["target_group"].as_str(),
        Some("phase2")
    );
    assert_eq!(data["nightly_policy"]["max_crashes"].as_u64(), Some(0));
    assert_eq!(target_names, policy_targets);
}

#[test]
fn phase2_readiness_thresholds_are_reasonable() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fuzz_phase2_targets.v1.json");
    let data = load_json(&report_path);

    let summary = &data["summary"];
    assert!(
        summary["average_readiness_score"].as_f64().unwrap() >= 70.0,
        "average readiness should stay above 70"
    );
    assert!(
        summary["total_symbols_covered"].as_u64().unwrap() >= 10,
        "phase-2 report should cover at least 10 symbols"
    );
}

#[test]
fn fuzz_nightly_build_check_fallback_writes_phase2_summary() {
    let root = repo_root();
    let temp = temp_dir("fuzz-nightly-build-check");
    let fake_bin = temp.join("bin");
    let artifacts_dir = temp.join("artifacts");
    let cargo_log = temp.join("cargo.log");
    fs::create_dir_all(&fake_bin).expect("create fake bin");

    let fake_cargo = fake_bin.join("cargo");
    fs::write(
        &fake_cargo,
        r#"#!/usr/bin/env bash
printf '%s\n' "$@" >>"${FAKE_CARGO_LOG}"
exit 0
"#,
    )
    .expect("write fake cargo");
    #[cfg(unix)]
    set_executable(&fake_cargo);

    let output = Command::new("bash")
        .arg(root.join("scripts/fuzz_nightly.sh"))
        .args(["--duration", "1", "--target-group", "phase2"])
        .current_dir(&root)
        .env("PATH", format!("{}:/usr/bin:/bin", fake_bin.display()))
        .env("FUZZ_ARTIFACTS", &artifacts_dir)
        .env("FAKE_CARGO_LOG", &cargo_log)
        .output()
        .expect("run fuzz nightly");

    assert!(
        output.status.success(),
        "fuzz_nightly.sh should pass in build-check mode\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let summary_path = fs::read_dir(&artifacts_dir)
        .expect("read artifacts dir")
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with("-summary.json"))
        })
        .expect("summary artifact");
    let summary = load_json(&summary_path);
    assert_eq!(summary["mode"].as_str(), Some("build-check-only"));
    assert_eq!(summary["target_group"].as_str(), Some("phase2"));
    assert_eq!(summary["targets"].as_u64(), Some(4));
    assert_eq!(summary["verdict"].as_str(), Some("pass"));
    assert!(
        summary["note"]
            .as_str()
            .is_some_and(|note| note.contains("cargo-fuzz not installed")),
        "build-check summary should explain the fallback"
    );

    let logged = fs::read_to_string(&cargo_log).expect("read fake cargo log");
    assert!(
        logged.contains("check"),
        "build-check fallback should execute cargo check"
    );
}
