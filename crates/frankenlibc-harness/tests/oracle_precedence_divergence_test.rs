//! Integration test: oracle precedence and divergence classification gate (bd-bp8fl.1.6)
//!
//! Validates the conformance-work oracle contract that separates host-glibc
//! parity, POSIX/Linux normative behavior, documented FrankenLibC contracts,
//! hardened repairs, environment flake, and proof gaps.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "scenario_id",
    "runtime_mode",
    "replacement_level",
    "api_family",
    "symbol",
    "oracle_kind",
    "expected",
    "actual",
    "errno",
    "decision_path",
    "healing_action",
    "latency_ns",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
];

const REQUIRED_ORACLES: &[&str] = &[
    "environment_probe",
    "frankenlibc_contract",
    "hardened_safety_policy",
    "host_glibc",
    "linux_syscall",
    "posix_text",
];

const REQUIRED_CLASSES: &[&str] = &[
    "allowed_divergence",
    "flaky_environment",
    "parity_match",
    "proof_gap",
    "safety_repair",
    "unsupported_contract",
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

fn unique_temp_path(name: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("frankenlibc-{name}-{stamp}-{}", std::process::id()))
}

fn load_json(path: &Path) -> serde_json::Value {
    let content = std::fs::read_to_string(path).expect("json should be readable");
    serde_json::from_str(&content).expect("json should parse")
}

fn load_artifact() -> serde_json::Value {
    load_json(&workspace_root().join("tests/conformance/oracle_precedence_divergence.v1.json"))
}

fn parse_stdout_report(output: &Output) -> serde_json::Value {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(&stdout);
    assert!(
        parsed.is_ok(),
        "failed to parse gate stdout as JSON: {}\nstdout={stdout}\nstderr={stderr}",
        parsed.err().unwrap()
    );
    serde_json::from_str(&stdout).expect("gate stdout JSON parse was checked above")
}

#[test]
fn artifact_exists_and_declares_required_oracles_classes_and_logs() {
    let artifact = load_artifact();
    assert_eq!(artifact["schema_version"].as_str(), Some("v1"));
    assert_eq!(artifact["bead"].as_str(), Some("bd-bp8fl.1.6"));
    assert!(artifact["inputs"].is_object(), "inputs must be object");
    assert!(
        artifact["decision_rules"].is_array(),
        "decision_rules must be array"
    );
    assert!(
        artifact["semantic_class_mappings"].is_array(),
        "semantic_class_mappings must be array"
    );
    assert!(artifact["scenarios"].is_array(), "scenarios must be array");

    let log_fields: Vec<_> = artifact["required_log_fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|field| field.as_str().unwrap())
        .collect();
    assert_eq!(log_fields, REQUIRED_LOG_FIELDS);

    let oracles: HashSet<_> = artifact["oracle_kinds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["id"].as_str().unwrap())
        .collect();
    assert_eq!(oracles, REQUIRED_ORACLES.iter().copied().collect());

    let ranks: HashSet<_> = artifact["oracle_kinds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["precedence_rank"].as_u64().unwrap())
        .collect();
    assert_eq!(
        ranks.len(),
        REQUIRED_ORACLES.len(),
        "oracle precedence ranks must be unique"
    );

    let classes: HashSet<_> = artifact["divergence_classifications"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["id"].as_str().unwrap())
        .collect();
    assert_eq!(classes, REQUIRED_CLASSES.iter().copied().collect());
}

#[test]
fn semantic_contract_classes_map_to_claim_blocking_divergence_classes() {
    let root = workspace_root();
    let artifact = load_artifact();
    let semantic_join =
        load_json(&root.join("tests/conformance/semantic_contract_symbol_join.v1.json"));

    let semantic_classes: HashSet<_> = semantic_join["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["semantic_class"].as_str().unwrap())
        .collect();
    let required_classes: HashSet<_> = REQUIRED_CLASSES.iter().copied().collect();
    let required_oracles: HashSet<_> = REQUIRED_ORACLES.iter().copied().collect();

    let mappings: HashMap<_, _> = artifact["semantic_class_mappings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| (row["semantic_class"].as_str().unwrap(), row))
        .collect();

    assert_eq!(
        mappings.keys().copied().collect::<HashSet<_>>(),
        semantic_classes
    );
    for (semantic_class, row) in mappings {
        let divergence_class = row["divergence_class"].as_str().unwrap();
        assert!(
            required_classes.contains(divergence_class),
            "{semantic_class}: unknown divergence class {divergence_class}"
        );
        let primary_oracle = row["primary_oracle"].as_str().unwrap();
        assert!(
            required_oracles.contains(primary_oracle),
            "{semantic_class}: unknown primary oracle {primary_oracle}"
        );
        assert!(
            row["claim_effect"].as_str().unwrap().contains("block"),
            "{semantic_class}: mappings must block overbroad user claims"
        );
    }
}

#[test]
fn scenarios_cover_modes_levels_oracles_divergence_classes_and_negative_claims() {
    let root = workspace_root();
    let artifact = load_artifact();
    let required_classes: HashSet<_> = REQUIRED_CLASSES.iter().copied().collect();
    let required_oracles: HashSet<_> = REQUIRED_ORACLES.iter().copied().collect();
    let mut by_class: HashMap<String, u64> = HashMap::new();
    let mut by_oracle: HashMap<String, u64> = HashMap::new();
    let mut negative_claim_tests = 0_u64;

    for scenario in artifact["scenarios"].as_array().unwrap() {
        let id = scenario["scenario_id"].as_str().unwrap();
        let class = scenario["divergence_class"].as_str().unwrap();
        let oracle = scenario["primary_oracle"].as_str().unwrap();
        assert!(required_classes.contains(class), "{id}: unknown class");
        assert!(required_oracles.contains(oracle), "{id}: unknown oracle");
        *by_class.entry(class.to_string()).or_default() += 1;
        *by_oracle.entry(oracle.to_string()).or_default() += 1;

        let modes: HashSet<_> = scenario["runtime_modes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|mode| mode.as_str().unwrap())
            .collect();
        assert!(modes.contains("strict"), "{id}: missing strict mode");
        assert!(modes.contains("hardened"), "{id}: missing hardened mode");

        let levels: HashSet<_> = scenario["replacement_levels"]
            .as_array()
            .unwrap()
            .iter()
            .map(|level| level.as_str().unwrap())
            .collect();
        assert!(levels.contains("L0"), "{id}: missing L0");
        assert!(levels.contains("L1"), "{id}: missing L1");
        assert!(
            !scenario["symbols"].as_array().unwrap().is_empty(),
            "{id}: symbols must not be empty"
        );

        for artifact_ref in scenario["artifact_refs"].as_array().unwrap() {
            let rel = artifact_ref.as_str().unwrap();
            assert!((root.join(rel)).exists(), "{id}: missing artifact {rel}");
        }
        for negative in scenario["negative_claim_tests"].as_array().unwrap() {
            assert_eq!(
                negative["expected_result"].as_str(),
                Some("claim_blocked"),
                "{id}: negative claim test must block overclaim"
            );
            assert!(
                !negative["failure_signature"].as_str().unwrap().is_empty(),
                "{id}: negative claim must name failure signature"
            );
            negative_claim_tests += 1;
        }
    }

    for class in REQUIRED_CLASSES {
        assert!(
            by_class.contains_key(*class),
            "missing scenario class {class}"
        );
    }
    for oracle in REQUIRED_ORACLES {
        assert!(
            by_oracle.contains_key(*oracle),
            "missing primary oracle scenario {oracle}"
        );
    }
    assert_eq!(
        artifact["summary"]["by_divergence_class"],
        serde_json::to_value(by_class).unwrap()
    );
    assert_eq!(
        artifact["summary"]["by_primary_oracle"],
        serde_json::to_value(by_oracle).unwrap()
    );
    assert_eq!(
        artifact["summary"]["negative_claim_test_count"].as_u64(),
        Some(negative_claim_tests)
    );
}

#[test]
fn gate_script_passes_and_emits_structured_report_and_log() {
    let root = workspace_root();
    let script = root.join("scripts/check_oracle_precedence_divergence.sh");
    assert!(script.exists(), "missing {}", script.display());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_oracle_precedence_divergence.sh must be executable"
        );
    }

    let output = Command::new(&script)
        .current_dir(&root)
        .output()
        .expect("failed to run oracle precedence gate");
    assert!(
        output.status.success(),
        "oracle precedence gate failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = parse_stdout_report(&output);
    assert_eq!(report["schema_version"].as_str(), Some("v1"));
    assert_eq!(report["bead"].as_str(), Some("bd-bp8fl.1.6"));
    assert_eq!(report["status"].as_str(), Some("pass"));
    for check in [
        "json_parse",
        "artifact_shape",
        "required_log_fields",
        "input_artifacts_exist",
        "oracle_kind_coverage",
        "oracle_precedence_unique",
        "divergence_class_coverage",
        "decision_rules_use_known_oracles",
        "semantic_class_mapping_coverage",
        "scenario_divergence_coverage",
        "scenario_oracle_coverage",
        "scenario_schema_and_artifacts",
        "summary_matches_artifact",
    ] {
        assert_eq!(
            report["checks"][check].as_str(),
            Some("pass"),
            "checks.{check} should pass"
        );
    }

    let report_path = root.join("target/conformance/oracle_precedence_divergence.report.json");
    let log_path = root.join("target/conformance/oracle_precedence_divergence.log.jsonl");
    assert!(report_path.exists(), "missing {}", report_path.display());
    assert!(log_path.exists(), "missing {}", log_path.display());

    let log_line = std::fs::read_to_string(&log_path)
        .expect("log should be readable")
        .lines()
        .find(|line| !line.trim().is_empty())
        .expect("log should contain at least one row")
        .to_string();
    let event: serde_json::Value = serde_json::from_str(&log_line).expect("log row should parse");
    for key in REQUIRED_LOG_FIELDS {
        assert!(
            event.get(*key).is_some(),
            "structured log row missing {key}"
        );
    }
}

#[test]
fn missing_required_divergence_class_blocks_gate() {
    let root = workspace_root();
    let script = root.join("scripts/check_oracle_precedence_divergence.sh");
    let canonical_path = root.join("tests/conformance/oracle_precedence_divergence.v1.json");
    let mutated_path = unique_temp_path("oracle-precedence-missing-class.json");
    let mut artifact = load_json(&canonical_path);

    artifact["divergence_classifications"]
        .as_array_mut()
        .unwrap()
        .retain(|row| row["id"].as_str() != Some("proof_gap"));
    std::fs::write(
        &mutated_path,
        serde_json::to_string_pretty(&artifact).unwrap() + "\n",
    )
    .expect("failed to write mutated oracle precedence artifact");

    let output = Command::new(&script)
        .current_dir(&root)
        .env("FLC_ORACLE_PRECEDENCE_ARTIFACT", &mutated_path)
        .output()
        .expect("failed to run oracle precedence gate with mutated artifact");
    assert!(
        !output.status.success(),
        "missing proof_gap classification should fail the gate\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = parse_stdout_report(&output);
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert_eq!(
        report["checks"]["divergence_class_coverage"].as_str(),
        Some("fail")
    );
}
