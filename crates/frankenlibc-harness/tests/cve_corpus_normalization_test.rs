// cve_corpus_normalization_test.rs — bd-1m5.5
// Integration tests for CVE corpus normalization and deterministic replay metadata.

use std::collections::HashSet;
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
    let content = std::fs::read_to_string(path).expect("CVE corpus JSON file must be readable");
    serde_json::from_str(&content).expect("CVE corpus JSON file must parse")
}

fn unique_temp_path(name: &str, extension: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock must be after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "frankenlibc_{name}_{}_{}.{}",
        std::process::id(),
        nanos,
        extension
    ))
}

fn run_generator_with_args(extra_args: &[&str]) -> std::process::Output {
    let root = repo_root();
    let mut args = vec![
        root.join("scripts/generate_cve_corpus_normalization.py")
            .to_str()
            .unwrap()
            .to_string(),
    ];
    args.extend(extra_args.iter().map(|value| value.to_string()));
    Command::new("python3")
        .args(args)
        .current_dir(&root)
        .output()
        .expect("failed to execute corpus normalization generator")
}

fn load_jsonl(path: &Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(path)
        .expect("CVE corpus JSONL file must be readable")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("each JSONL line must parse"))
        .collect()
}

fn test_source_text(root: &Path, rel: &str) -> String {
    std::fs::read_to_string(root.join(rel)).expect("completion-debt test source must be readable")
}

fn assert_required_tests_are_declared(evidence: &serde_json::Value, section: &str, source: &str) {
    let tests = evidence[section]["required_test_names"]
        .as_array()
        .expect("completion-debt section must carry required_test_names array");
    assert!(
        !tests.is_empty(),
        "{section}.required_test_names must not be empty"
    );
    for name in tests {
        let name = name
            .as_str()
            .expect("completion-debt required test name must be a string");
        assert!(
            source.contains(&format!("fn {name}(")),
            "{section} references missing test function {name}"
        );
    }
}

#[test]
fn corpus_report_generates_successfully() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/corpus_normalization.v1.json");
    let output = Command::new("python3")
        .args([
            root.join("scripts/generate_cve_corpus_normalization.py")
                .to_str()
                .unwrap(),
            "-o",
            report_path.to_str().unwrap(),
        ])
        .current_dir(&root)
        .output()
        .expect("failed to execute corpus normalization validator");
    assert!(
        output.status.success(),
        "Corpus normalization failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(report_path.exists());
}

#[test]
fn corpus_report_schema_complete() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/corpus_normalization.v1.json");
    let data = load_json(&report_path);

    assert_eq!(data["schema_version"].as_str(), Some("v1"));
    assert_eq!(data["bead"].as_str(), Some("bd-1m5.5"));

    let summary = &data["summary"];
    for field in &[
        "total_cve_tests",
        "manifests_valid",
        "vulnerability_classes",
        "unique_healing_actions",
        "unique_cwe_ids",
        "categories",
    ] {
        assert!(!summary[field].is_null(), "Missing summary field: {field}");
    }
    assert!(data["corpus_index"].is_array());
    assert!(data["normalization_changes"].is_array());
}

#[test]
fn corpus_all_manifests_valid() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/corpus_normalization.v1.json");
    let data = load_json(&report_path);

    let corpus = data["corpus_index"].as_array().unwrap();
    assert!(!corpus.is_empty(), "No CVE tests in corpus");

    for entry in corpus {
        let cve_id = entry["cve_id"].as_str().unwrap_or("unknown");
        assert!(
            entry["manifest_valid"].as_bool().unwrap(),
            "Invalid manifest for {}",
            cve_id
        );
    }
}

#[test]
fn corpus_all_entries_have_replay_keys() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/corpus_normalization.v1.json");
    let data = load_json(&report_path);

    let corpus = data["corpus_index"].as_array().unwrap();
    for entry in corpus {
        let cve_id = entry["cve_id"].as_str().unwrap_or("unknown");
        let replay_key = entry["replay"]["replay_key"].as_str();
        assert!(
            replay_key.is_some() && !replay_key.unwrap().is_empty(),
            "Missing replay_key for {}",
            cve_id
        );
    }
}

#[test]
fn corpus_all_entries_have_vulnerability_classes() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/corpus_normalization.v1.json");
    let data = load_json(&report_path);

    let corpus = data["corpus_index"].as_array().unwrap();
    for entry in corpus {
        let cve_id = entry["cve_id"].as_str().unwrap_or("unknown");
        let classes = entry["vulnerability_classes"].as_array().unwrap();
        assert!(
            !classes.is_empty(),
            "No vulnerability classes for {}",
            cve_id
        );
        let first = classes[0].as_str().unwrap();
        assert_ne!(
            first, "unknown",
            "Unknown vulnerability class for {}",
            cve_id
        );
    }
}

#[test]
fn corpus_all_entries_have_dual_mode_expectations() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/corpus_normalization.v1.json");
    let data = load_json(&report_path);

    let corpus = data["corpus_index"].as_array().unwrap();
    for entry in corpus {
        let cve_id = entry["cve_id"].as_str().unwrap_or("unknown");
        let replay = &entry["replay"];
        assert!(
            !replay["expected_strict"]["crashes"].is_null(),
            "Missing strict crashes expectation for {}",
            cve_id
        );
        assert!(
            !replay["expected_hardened"]["crashes"].is_null(),
            "Missing hardened crashes expectation for {}",
            cve_id
        );
    }
}

#[test]
fn corpus_multiple_vulnerability_classes_covered() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/corpus_normalization.v1.json");
    let data = load_json(&report_path);

    let classes = data["summary"]["vulnerability_classes"].as_array().unwrap();
    assert!(
        classes.len() >= 3,
        "Only {} vulnerability classes covered (need >= 3)",
        classes.len()
    );
}

#[test]
fn corpus_entries_include_scenario_ids_and_manifest_hashes() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/corpus_normalization.v1.json");
    let data = load_json(&report_path);

    let corpus = data["corpus_index"].as_array().unwrap();
    for entry in corpus {
        let cve_id = entry["cve_id"].as_str().unwrap_or("unknown");
        let scenario_id = entry["scenario_id"].as_str().unwrap_or("");
        let digest = entry["manifest_sha256"].as_str().unwrap_or("");
        assert!(
            scenario_id.starts_with(entry["base_cve_id"].as_str().unwrap()),
            "scenario_id should be derived from base CVE for {}",
            cve_id
        );
        assert_eq!(
            digest.len(),
            64,
            "manifest_sha256 must be a 64-char digest for {}",
            cve_id
        );
        assert!(
            digest.chars().all(|ch| ch.is_ascii_hexdigit()),
            "manifest_sha256 must be hex for {}",
            cve_id
        );
    }
}

#[test]
fn structured_log_contains_dual_mode_expectations() {
    let report_path = unique_temp_path("cve_corpus_normalization_report", "json");
    let log_path = unique_temp_path("cve_corpus_normalization", "jsonl");
    let fixed_ts = "2026-03-19T00:00:00Z";

    let output = run_generator_with_args(&[
        "-o",
        report_path.to_str().unwrap(),
        "--log",
        log_path.to_str().unwrap(),
        "--timestamp",
        fixed_ts,
    ]);
    assert!(
        output.status.success(),
        "generator failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report = load_json(&report_path);
    let total = report["summary"]["total_cve_tests"].as_u64().unwrap() as usize;
    let entries = load_jsonl(&log_path);
    let scenario_entries: Vec<_> = entries
        .iter()
        .filter(|entry| entry["event"].as_str() == Some("scenario_expectation"))
        .collect();
    assert_eq!(scenario_entries.len(), total * 2);
    assert_eq!(entries.len(), total * 2 + 1);

    for entry in scenario_entries {
        assert_eq!(entry["api_family"].as_str(), Some("cve_arena"));
        assert_eq!(entry["bead_id"].as_str(), Some("bd-1m5.5"));
        assert_eq!(entry["completion_debt_bead"].as_str(), Some("bd-1m5.5.1"));
        assert_eq!(entry["parent_bead"].as_str(), Some("bd-1m5.5"));
        assert_eq!(entry["timestamp"].as_str(), Some(fixed_ts));
        assert!(entry["trace_id"].as_str().unwrap().contains("bd-1m5.5:"));
        assert_eq!(entry["outcome"].as_str(), Some("expected"));
        assert_eq!(entry["failure_signature"].as_str(), Some("none"));
        assert!(entry["artifact_refs"].as_array().unwrap().len() >= 3);
        assert!(entry["expected_outcome"].is_string());
        assert!(entry["replay_key"].is_string());
        assert!(entry["fuzz_seed_id"].is_string());
        assert!(entry["scenario_id"].is_string());
        assert!(entry["manifest_sha256"].is_string());
        assert!(
            matches!(entry["mode"].as_str(), Some("strict") | Some("hardened")),
            "unexpected mode in log entry: {}",
            entry
        );
    }
}

#[test]
fn corpus_entries_define_fuzz_replay_seed_contract() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/corpus_normalization.v1.json");
    let data = load_json(&report_path);
    let corpus = data["corpus_index"].as_array().unwrap();
    assert!(!corpus.is_empty(), "No CVE tests in corpus");

    let mut seen_seed_ids = HashSet::new();
    for entry in corpus {
        let cve_id = entry["cve_id"].as_str().unwrap_or("unknown");
        let replay_key = entry["replay"]["replay_key"].as_str().unwrap();
        let fuzz = &entry["fuzz_replay_seed"];
        assert_eq!(
            fuzz["seed_payload_schema"].as_str(),
            Some("cve-arena-fuzz-seed/v1"),
            "{cve_id} fuzz seed schema drifted"
        );
        assert_eq!(
            fuzz["seed_id"].as_str().unwrap_or(""),
            format!("cve_arena:{replay_key}"),
            "{cve_id} seed_id must bind replay_key"
        );
        let digest = fuzz["seed_sha256"].as_str().unwrap_or("");
        assert_eq!(digest.len(), 64, "{cve_id} seed digest length");
        assert!(
            digest.chars().all(|ch| ch.is_ascii_hexdigit()),
            "{cve_id} seed digest must be hex"
        );
        assert!(
            seen_seed_ids.insert(fuzz["seed_id"].as_str().unwrap().to_string()),
            "{cve_id} duplicate fuzz seed_id"
        );

        let modes: Vec<_> = fuzz["replay_modes"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(serde_json::Value::as_str)
            .collect();
        assert_eq!(modes, vec!["strict", "hardened"], "{cve_id} replay modes");

        let axes: HashSet<_> = fuzz["mutation_axes"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(serde_json::Value::as_str)
            .collect();
        for axis in [
            "mode",
            "category",
            "cwe_ids",
            "trigger_files",
            "healing_actions",
        ] {
            assert!(axes.contains(axis), "{cve_id} missing fuzz axis {axis}");
        }
    }
}

#[test]
fn fuzz_replay_seed_keys_are_deterministic_under_fixed_timestamp() {
    let first_report = unique_temp_path("cve_corpus_fuzz_seed_first", "json");
    let second_report = unique_temp_path("cve_corpus_fuzz_seed_second", "json");
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
    let first_entries = first["corpus_index"].as_array().unwrap();
    let second_entries = second["corpus_index"].as_array().unwrap();
    assert_eq!(first_entries.len(), second_entries.len());

    for (left, right) in first_entries.iter().zip(second_entries.iter()) {
        assert_eq!(left["scenario_id"], right["scenario_id"]);
        assert_eq!(left["fuzz_replay_seed"], right["fuzz_replay_seed"]);
    }
}

#[test]
fn completion_debt_evidence_binds_all_audit_items() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/corpus_normalization.v1.json");
    let data = load_json(&report_path);
    let evidence = &data["completion_debt_evidence"];

    assert_eq!(evidence["bead"].as_str(), Some("bd-1m5.5.1"));
    assert_eq!(evidence["original_bead"].as_str(), Some("bd-1m5.5"));
    assert_eq!(
        evidence["test_source"].as_str(),
        Some("crates/frankenlibc-harness/tests/cve_corpus_normalization_test.rs")
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
        Some("fuzz_replay_seed")
    );
    let seed_fields: HashSet<_> = evidence["fuzz_primary"]["required_seed_fields"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    for field in [
        "seed_payload_schema",
        "seed_id",
        "seed_sha256",
        "mutation_axes",
        "replay_modes",
        "source_manifest_fields",
    ] {
        assert!(seed_fields.contains(field), "missing seed field {field}");
    }

    let telemetry = &evidence["telemetry_primary"];
    assert_eq!(
        telemetry["default_report_path"].as_str(),
        Some("tests/cve_arena/results/corpus_normalization.v1.json")
    );
    assert_eq!(
        telemetry["default_log_path"].as_str(),
        Some("tests/cve_arena/results/corpus_normalization.log.jsonl")
    );
    let required_events: HashSet<_> = telemetry["required_events"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    assert!(required_events.contains("scenario_expectation"));
    assert!(required_events.contains("corpus_summary"));
}

#[test]
fn normalization_checker_accepts_completion_debt_bindings() {
    let root = repo_root();
    let report_path = unique_temp_path("cve_corpus_normalization_gate_report", "json");
    let log_path = unique_temp_path("cve_corpus_normalization_gate_log", "jsonl");

    let output = Command::new("bash")
        .arg(root.join("scripts/check_cve_corpus_normalization.sh"))
        .current_dir(&root)
        .env("FRANKENLIBC_CVE_CORPUS_NORMALIZATION_REPORT", &report_path)
        .env("FRANKENLIBC_CVE_CORPUS_NORMALIZATION_LOG", &log_path)
        .env(
            "FRANKENLIBC_CVE_CORPUS_NORMALIZATION_TIMESTAMP",
            "2026-03-19T00:00:00Z",
        )
        .output()
        .expect("failed to execute CVE corpus normalization checker");
    assert!(
        output.status.success(),
        "CVE corpus checker failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = load_json(&report_path);
    assert_eq!(
        report["completion_debt_evidence"]["bead"].as_str(),
        Some("bd-1m5.5.1")
    );
    let rows = load_jsonl(&log_path);
    assert!(
        rows.iter()
            .any(|row| row["event"].as_str() == Some("corpus_summary")
                && row["outcome"].as_str() == Some("pass")),
        "checker log must include passing corpus_summary telemetry"
    );
}

#[test]
fn replay_keys_are_deterministic_under_fixed_timestamp() {
    let first_report = unique_temp_path("cve_corpus_normalization_first", "json");
    let second_report = unique_temp_path("cve_corpus_normalization_second", "json");
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
    assert_eq!(first["summary"], second["summary"]);

    let first_entries = first["corpus_index"].as_array().unwrap();
    let second_entries = second["corpus_index"].as_array().unwrap();
    assert_eq!(first_entries.len(), second_entries.len());

    for (left, right) in first_entries.iter().zip(second_entries.iter()) {
        assert_eq!(left["cve_id"], right["cve_id"]);
        assert_eq!(left["scenario_id"], right["scenario_id"]);
        assert_eq!(left["replay"]["replay_key"], right["replay"]["replay_key"]);
        assert_eq!(left["manifest_sha256"], right["manifest_sha256"]);
    }
}
