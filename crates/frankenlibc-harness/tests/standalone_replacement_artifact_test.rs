//! Integration tests for the standalone replacement artifact forge gate.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "event",
    "mode",
    "artifact_path",
    "artifact_status",
    "claim_status",
    "source_commit",
    "artifact_sha256",
    "command",
    "exit_code",
    "failure_signature",
    "artifact_refs",
];

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

fn manifest() -> serde_json::Value {
    load_json(&workspace_root().join("tests/conformance/standalone_replacement_artifact.v1.json"))
}

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after Unix epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn run_gate(mode: &str, prefix: &str) -> (PathBuf, PathBuf, PathBuf, std::process::Output) {
    let root = workspace_root();
    let temp = unique_temp_dir(prefix);
    let out_dir = temp.join("out");
    let cargo_target = temp.join("cargo-target");
    let report = temp.join("standalone_replacement_artifact.report.json");
    let log = temp.join("standalone_replacement_artifact.log.jsonl");
    let output = Command::new(root.join("scripts/check_standalone_replacement_artifact.sh"))
        .arg(mode)
        .current_dir(&root)
        .env("STANDALONE_REPLACEMENT_OUT_DIR", &out_dir)
        .env("STANDALONE_REPLACEMENT_CARGO_TARGET_DIR", &cargo_target)
        .env("STANDALONE_REPLACEMENT_REPORT", &report)
        .env("STANDALONE_REPLACEMENT_LOG", &log)
        .env_remove("FRANKENLIBC_STANDALONE_LIB")
        .env_remove("LD_PRELOAD")
        .output()
        .expect("standalone replacement artifact gate should run");
    (temp, report, log, output)
}

#[test]
fn manifest_matches_forge_contract() {
    let manifest = manifest();
    assert_eq!(manifest["schema_version"].as_str(), Some("v1"));
    assert_eq!(manifest["bead"].as_str(), Some("bd-srtkq"));
    assert_eq!(
        manifest["artifact_policy"]["canonical_artifact_name"].as_str(),
        Some("libfrankenlibc_replace.so")
    );
    assert_eq!(
        manifest["artifact_policy"]["source_cdylib_name"].as_str(),
        Some("libfrankenlibc_abi.so")
    );
    assert_eq!(
        manifest["artifact_policy"]["ld_preload_substitutes_allowed"].as_bool(),
        Some(false)
    );

    let fields: Vec<_> = manifest["required_log_fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect();
    assert_eq!(fields, REQUIRED_LOG_FIELDS);

    let classifications: HashSet<_> = manifest["expected_failure_classifications"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["failure_signature"].as_str().unwrap())
        .collect();
    for signature in [
        "standalone_artifact_missing",
        "standalone_artifact_stale",
        "wrong_artifact_profile",
        "non_elf_artifact",
        "host_glibc_dependency",
        "symbol_evidence_missing",
    ] {
        assert!(classifications.contains(signature), "missing {signature}");
    }
}

#[test]
fn validate_only_writes_report_and_required_log_fields() {
    let (_temp, report, log, output) = run_gate("--validate-only", "standalone-artifact-validate");
    assert!(
        output.status.success(),
        "validate-only failed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report = load_json(&report);
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["claim_status"].as_str(), Some("schema_validated"));
    assert_eq!(
        report["artifact_state"]["status"].as_str(),
        Some("not_checked")
    );

    let log = std::fs::read_to_string(log).expect("log should be readable");
    let rows: Vec<serde_json::Value> = log
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("log line should parse"))
        .collect();
    assert_eq!(rows.len(), 1);
    for field in REQUIRED_LOG_FIELDS {
        assert!(rows[0].get(*field).is_some(), "log row missing {field}");
    }
}

#[test]
fn check_mode_reports_missing_artifact_as_claim_blocked() {
    let (_temp, report, _log, output) = run_gate("--check", "standalone-artifact-missing");
    assert!(
        output.status.success(),
        "check mode should pass as a gate while blocking claims\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report = load_json(&report);
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["claim_status"].as_str(), Some("claim_blocked"));
    assert_eq!(report["artifact_state"]["status"].as_str(), Some("missing"));
    assert_eq!(
        report["artifact_state"]["failure_signature"].as_str(),
        Some("standalone_artifact_missing")
    );
}

#[test]
fn forge_mode_can_materialize_a_supplied_shared_object_for_fast_tests() {
    if Command::new("cc").arg("--version").output().is_err() {
        return;
    }

    let root = workspace_root();
    let temp = unique_temp_dir("standalone-artifact-forge");
    let source_c = temp.join("sample.c");
    let source_so = temp.join("libfrankenlibc_abi.so");
    std::fs::write(
        &source_c,
        "int frankenlibc_sample_symbol(void) { return 7; }\n",
    )
    .expect("write sample source");
    let cc_output = Command::new("cc")
        .arg("-shared")
        .arg("-fPIC")
        .arg(&source_c)
        .arg("-o")
        .arg(&source_so)
        .output()
        .expect("cc should run");
    if !cc_output.status.success() {
        return;
    }

    let out_dir = temp.join("out");
    let cargo_target = temp.join("cargo-target");
    let report = temp.join("standalone_replacement_artifact.report.json");
    let log = temp.join("standalone_replacement_artifact.log.jsonl");
    let output = Command::new(root.join("scripts/check_standalone_replacement_artifact.sh"))
        .arg("--forge")
        .current_dir(&root)
        .env("STANDALONE_REPLACEMENT_OUT_DIR", &out_dir)
        .env("STANDALONE_REPLACEMENT_CARGO_TARGET_DIR", &cargo_target)
        .env("STANDALONE_REPLACEMENT_REPORT", &report)
        .env("STANDALONE_REPLACEMENT_LOG", &log)
        .env("STANDALONE_REPLACEMENT_SOURCE_LIB", &source_so)
        .env("STANDALONE_REPLACEMENT_SKIP_BUILD", "1")
        .env_remove("LD_PRELOAD")
        .output()
        .expect("forge mode should run");
    assert!(
        output.status.success(),
        "forge mode failed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let forged = cargo_target.join("release/libfrankenlibc_replace.so");
    assert!(
        forged.exists(),
        "forge should materialize canonical artifact"
    );
    let report = load_json(&report);
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["artifact_state"]["status"].as_str(), Some("current"));
    assert!(
        matches!(
            report["claim_status"].as_str(),
            Some("claim_blocked") | Some("artifact_current")
        ),
        "sample artifact may block claims, but the forge itself should classify it"
    );
}

#[test]
fn gate_script_exists_and_is_executable() {
    let script = workspace_root().join("scripts/check_standalone_replacement_artifact.sh");
    assert!(script.exists(), "gate script must exist");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_standalone_replacement_artifact.sh must be executable"
        );
    }
}
