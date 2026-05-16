use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::json;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn load_json(path: &Path) -> serde_json::Value {
    let content = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("invalid JSON in {}: {e}", path.display()))
}

fn temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("frankenlibc-{label}-{nanos}"));
    fs::create_dir_all(&path).expect("create temp dir");
    path
}

fn run_checker(manifest: &Path, report: &Path) -> std::process::Output {
    let root = repo_root();
    Command::new("bash")
        .arg(root.join("scripts/check_fuzz_corpus_quality.sh"))
        .args(["--manifest", manifest.to_str().unwrap()])
        .args(["--report", report.to_str().unwrap()])
        .current_dir(&root)
        .output()
        .expect("run fuzz corpus quality checker")
}

#[test]
fn manifest_binds_checker_policy_and_validation_commands() {
    let root = repo_root();
    let manifest = load_json(&root.join("tests/conformance/fuzz_corpus_quality.v1.json"));

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("fuzz_corpus_quality.v1")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-n0apt.2"));
    assert_eq!(
        manifest["artifacts"]["checker"].as_str(),
        Some("scripts/check_fuzz_corpus_quality.sh")
    );
    assert_eq!(
        manifest["policy"]["required_directed_targets"]["fuzz_ctype"]["min_readable_seed_files"]
            .as_u64(),
        Some(7)
    );

    let commands = manifest["validation"]["commands"].as_array().unwrap();
    assert!(commands.iter().any(|cmd| {
        cmd.as_str()
            .is_some_and(|cmd| cmd.contains("check_fuzz_corpus_quality.sh"))
    }));
    assert!(commands.iter().any(|cmd| {
        cmd.as_str()
            .is_some_and(|cmd| cmd.contains("rch exec") && cmd.contains("fuzz_corpus_quality_test"))
    }));
}

#[test]
fn checker_accepts_current_inventory_and_reports_gaps() {
    let root = repo_root();
    let temp = temp_dir("fuzz-corpus-quality-pass");
    let report = temp.join("report.json");
    let output = run_checker(
        &root.join("tests/conformance/fuzz_corpus_quality.v1.json"),
        &report,
    );

    assert!(
        output.status.success(),
        "checker should accept current inventory\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_json = load_json(&report);
    assert_eq!(
        report_json["schema_version"].as_str(),
        Some("fuzz_corpus_quality.report.v1")
    );
    assert_eq!(report_json["summary"]["status"].as_str(), Some("pass"));
    assert!(
        report_json["summary"]["total_targets"].as_u64().unwrap() >= 60,
        "scanner should inventory the full fuzz target surface"
    );

    let targets = report_json["target_assessments"].as_array().unwrap();
    let ctype = targets
        .iter()
        .find(|target| target["target"].as_str() == Some("fuzz_ctype"))
        .expect("fuzz_ctype assessment");
    assert!(ctype["corpus_dir_exists"].as_bool().unwrap());
    assert!(ctype["corpus_file_count"].as_u64().unwrap() >= 22);
    assert!(ctype["readable_seed_file_count"].as_u64().unwrap() >= 7);
    assert!(
        ctype["source_has_directive_parser_signal"]
            .as_bool()
            .unwrap()
    );
    assert!(
        ctype["smoke_command"]
            .as_str()
            .is_some_and(|cmd| cmd.contains("RCH_FORCE_REMOTE=true") && cmd.contains("fuzz_ctype"))
    );
}

#[test]
fn checker_rejects_missing_required_target() {
    let root = repo_root();
    let temp = temp_dir("fuzz-corpus-quality-missing-target");
    let manifest_path = temp.join("manifest.json");
    let report = temp.join("report.json");
    let mut manifest = load_json(&root.join("tests/conformance/fuzz_corpus_quality.v1.json"));
    manifest["policy"]["required_targets"]
        .as_array_mut()
        .unwrap()
        .push(json!("fuzz_missing_required_target"));
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .expect("write mutated manifest");

    let output = run_checker(&manifest_path, &report);
    assert!(
        !output.status.success(),
        "checker should reject missing required target"
    );

    let report_json = load_json(&report);
    let errors = report_json["findings"]["errors"].as_array().unwrap();
    assert!(errors.iter().any(|error| {
        error["code"].as_str() == Some("missing_required_target")
            && error["target"].as_str() == Some("fuzz_missing_required_target")
    }));
}

#[test]
fn checker_rejects_required_directed_seed_shortfall() {
    let root = repo_root();
    let temp = temp_dir("fuzz-corpus-quality-directed-shortfall");
    let manifest_path = temp.join("manifest.json");
    let report = temp.join("report.json");
    let mut manifest = load_json(&root.join("tests/conformance/fuzz_corpus_quality.v1.json"));
    manifest["policy"]["required_directed_targets"]["fuzz_ctype"]["min_readable_seed_files"] =
        json!(999);
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .expect("write mutated manifest");

    let output = run_checker(&manifest_path, &report);
    assert!(
        !output.status.success(),
        "checker should reject impossible directed seed threshold"
    );

    let report_json = load_json(&report);
    let errors = report_json["findings"]["errors"].as_array().unwrap();
    assert!(errors.iter().any(|error| {
        error["target"].as_str() == Some("fuzz_ctype")
            && error["code"].as_str() == Some("below_required_readable_seed_files")
    }));
}
