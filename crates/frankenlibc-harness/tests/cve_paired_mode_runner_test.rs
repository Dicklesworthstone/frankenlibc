// cve_paired_mode_runner_test.rs — bd-1m5.7
// Integration tests for the strict detection + paired-mode CVE evidence runner.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn load_json(path: &Path) -> serde_json::Value {
    let read_context = format!("failed to read {}", path.display());
    let content = std::fs::read_to_string(path).expect(&read_context);
    let parse_context = format!("invalid JSON in {}", path.display());
    serde_json::from_str(&content).expect(&parse_context)
}

fn load_jsonl(path: &Path) -> Vec<serde_json::Value> {
    let read_context = format!("failed to read {}", path.display());
    std::fs::read_to_string(path)
        .expect(&read_context)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("jsonl row should parse"))
        .collect()
}

fn unique_temp_path(stem: &str, ext: &str) -> PathBuf {
    let root = repo_root();
    let path = root.join("target/conformance").join(format!(
        "{stem}_{}_{}.{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        ext
    ));
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    path
}

fn run_generator_with_args(args: &[&str]) -> std::process::Output {
    let root = repo_root();
    Command::new("python3")
        .arg(root.join("scripts/generate_cve_paired_mode_runner.py"))
        .args(args)
        .current_dir(&root)
        .output()
        .expect("failed to execute paired-mode runner")
}

fn test_source_text(root: &Path, relative_path: &str) -> String {
    std::fs::read_to_string(root.join(relative_path)).expect("test source should be readable")
}

fn assert_required_tests_are_declared(
    evidence: &serde_json::Value,
    section: &str,
    test_source_text: &str,
) {
    let tests = evidence[section]["required_test_names"]
        .as_array()
        .expect("required_test_names should be an array");
    assert!(
        !tests.is_empty(),
        "{section}.required_test_names should be non-empty"
    );
    for test_name in tests {
        let test_name = test_name
            .as_str()
            .expect("required_test_names should contain strings");
        assert!(
            test_source_text.contains(&format!("fn {test_name}(")),
            "{section} references missing test {test_name}"
        );
    }
}

#[test]
fn paired_report_generates_successfully() {
    let report_path = unique_temp_path("paired_mode_evidence", "json");
    let log_path = unique_temp_path("paired_mode_evidence", "jsonl");
    let output = run_generator_with_args(&[
        "-o",
        report_path.to_str().unwrap(),
        "--log",
        log_path.to_str().unwrap(),
        "--timestamp",
        "2026-03-19T00:00:00Z",
    ]);
    assert!(
        output.status.success(),
        "Paired-mode runner failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(report_path.exists());
    assert!(log_path.exists());
}

#[test]
fn paired_report_schema_complete() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/paired_mode_evidence.v1.json");
    let data = load_json(&report_path);

    assert_eq!(data["schema_version"].as_str(), Some("v1"));
    assert_eq!(data["bead"].as_str(), Some("bd-1m5.7"));
    assert_eq!(data["completion_debt_bead"].as_str(), Some("bd-1m5.7.1"));

    let summary = &data["summary"];
    for field in &[
        "total_paired_scenarios",
        "strict_detected",
        "hardened_prevented",
        "unique_detection_flags",
        "unique_healing_actions",
        "unique_dossier_ids",
    ] {
        assert!(!summary[field].is_null(), "Missing summary field: {field}");
    }
    assert!(data["paired_evidence"].is_array());
}

#[test]
fn completion_debt_evidence_binds_all_audit_items() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/paired_mode_evidence.v1.json");
    let data = load_json(&report_path);
    let evidence = &data["completion_debt_evidence"];

    assert_eq!(evidence["bead"].as_str(), Some("bd-1m5.7.1"));
    assert_eq!(evidence["original_bead"].as_str(), Some("bd-1m5.7"));
    assert_eq!(
        evidence["test_source"].as_str(),
        Some("crates/frankenlibc-harness/tests/cve_paired_mode_runner_test.rs")
    );

    let source = test_source_text(&root, evidence["test_source"].as_str().unwrap());
    for (section, missing_item) in [
        ("unit_primary", "tests.unit.primary"),
        ("e2e_primary", "tests.e2e.primary"),
        ("fuzz_primary", "tests.fuzz.primary"),
        ("conformance_primary", "tests.conformance.primary"),
        ("telemetry_primary", "telemetry.primary"),
    ] {
        assert_eq!(
            evidence[section]["missing_item_id"].as_str(),
            Some(missing_item),
            "{section}.missing_item_id"
        );
        assert_required_tests_are_declared(evidence, section, &source);
    }

    assert_eq!(
        evidence["fuzz_primary"]["required_entry_field"].as_str(),
        Some("paired_fuzz_seed")
    );
    let telemetry_events: HashSet<_> = evidence["telemetry_primary"]["required_events"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    assert!(telemetry_events.contains("paired_mode_scenario"));
    assert!(telemetry_events.contains("paired_mode_summary"));
}

#[test]
fn paired_all_strict_detected() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/paired_mode_evidence.v1.json");
    let data = load_json(&report_path);

    let evidence = data["paired_evidence"].as_array().unwrap();
    assert!(!evidence.is_empty(), "No paired evidence entries");

    for e in evidence {
        let cve_id = e["cve_id"].as_str().unwrap_or("unknown");
        assert_eq!(
            e["strict_mode"]["verdict"].as_str().unwrap(),
            "detected",
            "{} not detected in strict mode",
            cve_id
        );
    }
}

#[test]
fn paired_all_hardened_prevented() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/paired_mode_evidence.v1.json");
    let data = load_json(&report_path);

    let evidence = data["paired_evidence"].as_array().unwrap();
    for e in evidence {
        let cve_id = e["cve_id"].as_str().unwrap_or("unknown");
        assert_eq!(
            e["hardened_mode"]["verdict"].as_str().unwrap(),
            "prevented",
            "{} not prevented in hardened mode",
            cve_id
        );
    }
}

#[test]
fn paired_unique_dossier_ids() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/paired_mode_evidence.v1.json");
    let data = load_json(&report_path);

    let evidence = data["paired_evidence"].as_array().unwrap();
    let dossier_ids: HashSet<&str> = evidence
        .iter()
        .map(|e| e["dossier_id"].as_str().unwrap())
        .collect();
    assert_eq!(
        dossier_ids.len(),
        evidence.len(),
        "Duplicate dossier IDs found"
    );
}

#[test]
fn paired_evidence_bundles_joinable() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/paired_mode_evidence.v1.json");
    let data = load_json(&report_path);

    let evidence = data["paired_evidence"].as_array().unwrap();
    for e in evidence {
        let cve_id = e["cve_id"].as_str().unwrap_or("unknown");
        let joinable: Vec<&str> = e["evidence_bundle"]["joinable_on"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(
            joinable.contains(&"dossier_id"),
            "{} not joinable on dossier_id",
            cve_id
        );
        assert!(
            joinable.contains(&"cve_id"),
            "{} not joinable on cve_id",
            cve_id
        );
    }
}

#[test]
fn paired_entries_define_fuzz_replay_seed_contract() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/paired_mode_evidence.v1.json");
    let data = load_json(&report_path);
    let evidence = data["paired_evidence"].as_array().unwrap();
    let seed_fields: HashSet<_> =
        data["completion_debt_evidence"]["fuzz_primary"]["required_seed_fields"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(serde_json::Value::as_str)
            .collect();

    assert!(!evidence.is_empty(), "No paired evidence entries");
    for entry in evidence {
        let cve_id = entry["cve_id"].as_str().unwrap_or("unknown");
        let seed = &entry["paired_fuzz_seed"];
        assert_eq!(
            seed["seed_payload_schema"].as_str(),
            Some("cve-paired-mode-fuzz-seed/v1"),
            "{cve_id} seed schema"
        );
        for field in &seed_fields {
            assert!(
                seed.get(*field).is_some(),
                "{cve_id} paired_fuzz_seed missing {field}"
            );
        }
        assert!(
            seed["mutation_axes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|axis| axis.as_str() == Some("runtime_mode")),
            "{cve_id} seed should vary runtime_mode"
        );
    }
}

#[test]
fn paired_no_validation_errors() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/paired_mode_evidence.v1.json");
    let data = load_json(&report_path);

    let val_errors = data["summary"]["validation_errors"].as_u64().unwrap();
    assert_eq!(val_errors, 0, "Validation errors found");
}

#[test]
fn structured_log_contains_paired_mode_evidence() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/paired_mode_evidence.v1.json");
    let log_path = root.join("tests/cve_arena/results/paired_mode_evidence.log.jsonl");
    let data = load_json(&report_path);
    let rows = load_jsonl(&log_path);
    let required_fields: HashSet<_> =
        data["completion_debt_evidence"]["telemetry_primary"]["required_fields"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(serde_json::Value::as_str)
            .collect();
    let evidence_count = data["paired_evidence"].as_array().unwrap().len();

    assert_eq!(rows.len(), evidence_count + 1);
    let scenario = rows
        .iter()
        .find(|row| row["event"].as_str() == Some("paired_mode_scenario"))
        .expect("scenario telemetry row should exist");
    for field in &required_fields {
        assert!(
            scenario.get(*field).is_some(),
            "scenario telemetry missing {field}"
        );
    }
    assert_eq!(
        scenario["completion_debt_bead"].as_str(),
        Some("bd-1m5.7.1")
    );
    assert_eq!(scenario["parent_bead"].as_str(), Some("bd-1m5.7"));

    let summary = rows
        .iter()
        .find(|row| row["event"].as_str() == Some("paired_mode_summary"))
        .expect("summary telemetry row should exist");
    assert_eq!(summary["outcome"].as_str(), Some("pass"));
    assert_eq!(summary["completion_debt_bead"].as_str(), Some("bd-1m5.7.1"));
}

#[test]
fn paired_mode_checker_accepts_completion_debt_bindings() {
    let root = repo_root();
    let report_path = unique_temp_path("paired_mode_checker_report", "json");
    let log_path = unique_temp_path("paired_mode_checker_log", "jsonl");

    let output = Command::new("bash")
        .arg(root.join("scripts/check_cve_paired_mode_runner.sh"))
        .current_dir(&root)
        .env("FRANKENLIBC_CVE_PAIRED_MODE_REPORT", &report_path)
        .env("FRANKENLIBC_CVE_PAIRED_MODE_LOG", &log_path)
        .env(
            "FRANKENLIBC_CVE_PAIRED_MODE_TIMESTAMP",
            "2026-03-19T00:00:00Z",
        )
        .output()
        .expect("failed to execute paired-mode checker");
    assert!(
        output.status.success(),
        "paired-mode checker failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = load_json(&report_path);
    assert_eq!(
        report["completion_debt_evidence"]["bead"].as_str(),
        Some("bd-1m5.7.1")
    );
    let rows = load_jsonl(&log_path);
    assert!(
        rows.iter()
            .any(|row| row["event"].as_str() == Some("paired_mode_summary")
                && row["outcome"].as_str() == Some("pass")),
        "checker log should include passing paired_mode_summary telemetry"
    );
}

#[test]
fn paired_fuzz_replay_seed_keys_are_deterministic() {
    let first_report = unique_temp_path("paired_mode_seed_first", "json");
    let second_report = unique_temp_path("paired_mode_seed_second", "json");
    let fixed_ts = "2026-03-19T00:00:00Z";

    for report_path in [&first_report, &second_report] {
        let output = run_generator_with_args(&[
            "-o",
            report_path.to_str().unwrap(),
            "--timestamp",
            fixed_ts,
        ]);
        assert!(
            output.status.success(),
            "generator failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let first = load_json(&first_report);
    let second = load_json(&second_report);
    assert_eq!(first["generated_at"], second["generated_at"]);
    let first_entries = first["paired_evidence"].as_array().unwrap();
    let second_entries = second["paired_evidence"].as_array().unwrap();
    assert_eq!(first_entries.len(), second_entries.len());
    for (left, right) in first_entries.iter().zip(second_entries.iter()) {
        assert_eq!(left["cve_id"], right["cve_id"]);
        assert_eq!(left["dossier_id"], right["dossier_id"]);
        assert_eq!(left["paired_fuzz_seed"], right["paired_fuzz_seed"]);
    }
}
