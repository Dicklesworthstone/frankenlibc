// cve_corpus_normalization_test.rs — bd-1m5.5
// Integration tests for CVE corpus normalization and deterministic replay metadata.

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
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e))
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("each JSONL line must parse"))
        .collect()
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
        assert_eq!(entry["timestamp"].as_str(), Some(fixed_ts));
        assert!(entry["trace_id"].as_str().unwrap().contains("bd-1m5.5:"));
        assert!(entry["expected_outcome"].is_string());
        assert!(entry["replay_key"].is_string());
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
