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

fn run_checker(args: &[String]) -> std::process::Output {
    let root = repo_root();
    Command::new("bash")
        .arg(root.join("scripts/check_fuzz_smoke_manifest.sh"))
        .args(args)
        .current_dir(&root)
        .output()
        .expect("run fuzz smoke manifest checker")
}

fn smoke_command(target: &str, corpus_path: &str) -> String {
    format!(
        "RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary rch exec -- env \
         CARGO_TARGET_DIR=/tmp/rch_target_frankenlibc_fuzz_smoke_{target} \
         cargo run --manifest-path crates/frankenlibc-fuzz/Cargo.toml --bin {target} \
         -- -runs=1 {corpus_path}"
    )
}

fn corpus_file_count(root: &Path, corpus_path: &str) -> u64 {
    fs::read_dir(root.join(corpus_path))
        .unwrap_or_else(|e| panic!("failed to read corpus {corpus_path}: {e}"))
        .filter_map(Result::ok)
        .filter(|entry| entry.path().is_file())
        .count() as u64
}

fn valid_proof(manifest: &serde_json::Value) -> serde_json::Value {
    let root = repo_root();
    let commands = manifest["smoke_targets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|target| {
            let name = target["target"].as_str().unwrap();
            let corpus_path = target["corpus_path"].as_str().unwrap();
            let files = corpus_file_count(&root, corpus_path);
            let runs = files + 1;
            json!({
                "target": name,
                "corpus_path": corpus_path,
                "worker": "ts2",
                "exit_code": 0,
                "done_runs": runs,
                "stdout_summary": format!("Done {runs} runs in 0 second(s)"),
                "stderr_summary": "",
                "command": smoke_command(name, corpus_path)
            })
        })
        .collect::<Vec<_>>();

    json!({
        "schema_version": "fuzz_smoke_proof.v1",
        "commands": commands
    })
}

#[test]
fn manifest_binds_remote_smoke_tier_and_validation_commands() {
    let root = repo_root();
    let manifest = load_json(&root.join("tests/conformance/fuzz_smoke_manifest.v1.json"));

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("fuzz_smoke_manifest.v1")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-n0apt.3"));
    assert_eq!(
        manifest["artifacts"]["checker"].as_str(),
        Some("scripts/check_fuzz_smoke_manifest.sh")
    );
    assert_eq!(
        manifest["artifacts"]["proof_schema"].as_str(),
        Some("fuzz_smoke_proof.v1")
    );

    let targets = manifest["smoke_targets"].as_array().unwrap();
    assert_eq!(targets.len(), 10);
    let names = targets
        .iter()
        .map(|target| target["target"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        vec![
            "fuzz_b64",
            "fuzz_c11threads",
            "fuzz_ctype",
            "fuzz_loc_codec",
            "fuzz_math",
            "fuzz_membrane",
            "fuzz_printf_adversarial",
            "fuzz_pthread_keys",
            "fuzz_regex",
            "fuzz_string"
        ]
    );

    let commands = manifest["validation"]["commands"].as_array().unwrap();
    assert!(commands.iter().any(|cmd| {
        cmd.as_str()
            .is_some_and(|cmd| cmd.contains("check_fuzz_smoke_manifest.sh --proof"))
    }));
    assert!(commands.iter().any(|cmd| {
        cmd.as_str()
            .is_some_and(|cmd| cmd.contains("rch exec") && cmd.contains("fuzz_smoke_manifest_test"))
    }));
}

#[test]
fn checker_prints_commands_and_accepts_checked_remote_proof() {
    let root = repo_root();
    let manifest_path = root.join("tests/conformance/fuzz_smoke_manifest.v1.json");
    let manifest = load_json(&manifest_path);
    let temp = temp_dir("fuzz-smoke-valid-proof");
    let proof = temp.join("proof.json");
    let report = temp.join("report.json");
    fs::write(
        &proof,
        serde_json::to_string_pretty(&valid_proof(&manifest)).unwrap(),
    )
    .expect("write proof");

    let print_output = run_checker(&[
        "--manifest".to_string(),
        manifest_path.display().to_string(),
        "--print-commands".to_string(),
        "--report".to_string(),
        temp.join("commands-report.json").display().to_string(),
    ]);
    assert!(
        print_output.status.success(),
        "print commands should pass\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&print_output.stdout),
        String::from_utf8_lossy(&print_output.stderr)
    );
    let printed = String::from_utf8_lossy(&print_output.stdout);
    assert!(printed.contains("RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary rch exec -- env"));
    assert!(printed.contains("--bin fuzz_ctype"));
    assert!(!printed.contains("bash -c"));

    let output = run_checker(&[
        "--manifest".to_string(),
        manifest_path.display().to_string(),
        "--proof".to_string(),
        proof.display().to_string(),
        "--report".to_string(),
        report.display().to_string(),
    ]);
    assert!(
        output.status.success(),
        "checker should accept valid remote proof\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_json = load_json(&report);
    assert_eq!(
        report_json["schema_version"].as_str(),
        Some("fuzz_smoke_manifest.report.v1")
    );
    assert_eq!(report_json["summary"]["status"].as_str(), Some("pass"));
    assert_eq!(
        report_json["summary"]["proof_checked"].as_bool(),
        Some(true)
    );
    assert_eq!(
        report_json["summary"]["proof_command_count"].as_u64(),
        Some(10)
    );
}

#[test]
fn checker_rejects_missing_manifest_target() {
    let root = repo_root();
    let temp = temp_dir("fuzz-smoke-missing-target");
    let manifest_path = temp.join("manifest.json");
    let report = temp.join("report.json");
    let mut manifest = load_json(&root.join("tests/conformance/fuzz_smoke_manifest.v1.json"));
    manifest["smoke_targets"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "target": "fuzz_missing_smoke_target",
            "corpus_path": "crates/frankenlibc-fuzz/corpus/fuzz_missing_smoke_target",
            "reason": "negative test only"
        }));
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .expect("write mutated manifest");

    let output = run_checker(&[
        "--manifest".to_string(),
        manifest_path.display().to_string(),
        "--report".to_string(),
        report.display().to_string(),
    ]);
    assert!(
        !output.status.success(),
        "checker should reject missing target"
    );

    let report_json = load_json(&report);
    let errors = report_json["findings"]["errors"].as_array().unwrap();
    assert!(errors.iter().any(|error| {
        error["target"].as_str() == Some("fuzz_missing_smoke_target")
            && error["code"].as_str() == Some("missing_fuzz_target_source")
    }));
}

#[test]
fn checker_rejects_local_rch_fallback_marker() {
    let root = repo_root();
    let manifest_path = root.join("tests/conformance/fuzz_smoke_manifest.v1.json");
    let manifest = load_json(&manifest_path);
    let temp = temp_dir("fuzz-smoke-local-fallback");
    let proof = temp.join("proof.json");
    let report = temp.join("report.json");
    let mut proof_json = valid_proof(&manifest);
    proof_json["commands"][0]["stdout_summary"] =
        json!("[RCH] local (remote execution failed)\nDone 1 runs");
    fs::write(&proof, serde_json::to_string_pretty(&proof_json).unwrap()).expect("write proof");

    let output = run_checker(&[
        "--manifest".to_string(),
        manifest_path.display().to_string(),
        "--proof".to_string(),
        proof.display().to_string(),
        "--report".to_string(),
        report.display().to_string(),
    ]);
    assert!(
        !output.status.success(),
        "checker should reject local rch fallback proof"
    );

    let report_json = load_json(&report);
    let errors = report_json["findings"]["errors"].as_array().unwrap();
    assert!(
        errors
            .iter()
            .any(|error| { error["code"].as_str() == Some("local_rch_fallback_marker") })
    );
}
