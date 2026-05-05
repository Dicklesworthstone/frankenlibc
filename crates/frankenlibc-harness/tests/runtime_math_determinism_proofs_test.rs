//! Integration test: runtime_math determinism + invariant proofs (bd-1fk1)
//!
//! Validates that:
//! 1. The gate script exists and is executable.
//! 2. The gate script runs successfully.
//! 3. The gate emits structured JSONL logs and a JSON report.
//! 4. The report indicates both modes passed with zero failures.

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

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
    let content = std::fs::read_to_string(path).expect("json file should exist");
    serde_json::from_str(&content).expect("json should parse")
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[test]
fn runtime_math_kernel_snapshot_golden_checksum_matches_manifest() {
    let root = workspace_root();
    let golden_dir = root.join("tests/runtime_math/golden");
    let snapshot_path = golden_dir.join("kernel_snapshot_smoke.v1.json");
    let sha_path = golden_dir.join("sha256sums.txt");

    let sha_body = std::fs::read_to_string(&sha_path).expect("sha256sums.txt should be readable");
    let rows = sha_body
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect::<Vec<_>>();
    assert_eq!(
        rows.len(),
        1,
        "runtime math golden checksum manifest should pin exactly one snapshot"
    );

    let mut fields = rows[0].split_whitespace();
    let expected_hash = fields.next().expect("checksum row should include hash");
    let expected_name = fields
        .next()
        .expect("checksum row should include snapshot file name");
    assert_eq!(
        fields.next(),
        None,
        "checksum row should contain only hash and file name"
    );
    assert_eq!(expected_name, "kernel_snapshot_smoke.v1.json");
    assert!(
        expected_hash.len() == 64
            && expected_hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "checksum should be a lowercase SHA-256 hex digest"
    );

    let snapshot_bytes = std::fs::read(&snapshot_path).expect("snapshot should be readable");
    let actual_hash = hex_lower(&Sha256::digest(&snapshot_bytes));
    assert_eq!(
        actual_hash, expected_hash,
        "sha256sums.txt must match the committed runtime math golden snapshot"
    );

    let snapshot: serde_json::Value =
        serde_json::from_slice(&snapshot_bytes).expect("snapshot should parse as JSON");
    assert_eq!(snapshot["version"].as_str(), Some("v1"));
    assert_eq!(
        snapshot["scenario"]["id"].as_str(),
        Some("runtime_math_kernel_snapshot_smoke")
    );
    assert_eq!(snapshot["scenario"]["seed"].as_u64(), Some(0xDEAD_BEEF));
    assert_eq!(snapshot["scenario"]["steps"].as_u64(), Some(512));
    assert!(
        snapshot["strict"].is_object() && snapshot["hardened"].is_object(),
        "snapshot_gate.sh uses --mode both, so both mode snapshots must be present"
    );
}

#[test]
fn gate_script_exists_and_executable() {
    let root = workspace_root();
    let script = root.join("scripts/check_runtime_math_determinism_proofs.sh");
    assert!(
        script.exists(),
        "scripts/check_runtime_math_determinism_proofs.sh must exist"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_runtime_math_determinism_proofs.sh must be executable"
        );
    }
}

#[test]
fn gate_script_emits_logs_and_report() {
    let root = workspace_root();
    let script = root.join("scripts/check_runtime_math_determinism_proofs.sh");

    let output = std::process::Command::new(&script)
        .current_dir(&root)
        .output()
        .expect("failed to run determinism proofs gate script");

    assert!(
        output.status.success(),
        "gate script failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let log_path = root.join("target/conformance/runtime_math_determinism_proofs.log.jsonl");
    let report_path = root.join("target/conformance/runtime_math_determinism_proofs.report.json");

    let (line_count, errors) = frankenlibc_harness::structured_log::validate_log_file(&log_path)
        .expect("log file should be readable");
    assert!(
        errors.is_empty(),
        "structured log validation errors:\n{:#?}",
        errors
    );
    assert!(
        line_count >= 6,
        "expected multiple log lines (got {line_count})"
    );
    let log_body = std::fs::read_to_string(&log_path).expect("determinism log should be readable");
    let log_events: Vec<serde_json::Value> = log_body
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("log line should parse"))
        .collect();
    assert!(
        log_events
            .iter()
            .any(|entry| entry["event"].as_str() == Some("runtime_math.determinism.proof_step")),
        "determinism log should include TRACE proof_step events"
    );
    assert!(
        log_events.iter().any(|entry| entry["event"].as_str()
            == Some("runtime_math.determinism.gram_eigenvalue_check")),
        "determinism log should include DEBUG gram_eigenvalue_check events"
    );
    assert!(
        log_events
            .iter()
            .any(|entry| entry["event"].as_str()
                == Some("runtime_math.determinism.boundary_assumption")),
        "determinism log should include WARN boundary_assumption events"
    );
    assert!(
        log_events
            .iter()
            .any(|entry| entry["event"].as_str() == Some("runtime_math.determinism.mode_finish")),
        "determinism log should include mode_finish summaries"
    );

    let report = load_json(&report_path);
    assert_eq!(
        report["schema_version"].as_str(),
        Some("v1"),
        "report schema_version must be v1"
    );
    assert_eq!(
        report["bead"].as_str(),
        Some("bd-1fk1"),
        "bead marker must match"
    );
    assert_eq!(
        report["summary"]["modes"].as_u64(),
        Some(2),
        "expected 2 modes in summary"
    );
    assert_eq!(
        report["summary"]["failed"].as_u64(),
        Some(0),
        "report indicates mode failures"
    );
    assert_eq!(
        report["modes"].as_array().map(|a| a.len()),
        Some(2),
        "report must include two mode rows"
    );
}
