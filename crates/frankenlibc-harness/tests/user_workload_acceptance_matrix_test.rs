//! Integration test: user workload acceptance matrix gate (bd-bp8fl.10.1)
//!
//! Validates that persona/workload planning preserves L0/L1 and future L2/L3
//! ambition while blocking unsupported or missing-evidence user claims.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;

const REQUIRED_DOMAINS: &[&str] = &[
    "shell_coreutils",
    "build_tools",
    "language_runtimes",
    "package_manager",
    "threaded_services",
    "resolver_nss",
    "locale_iconv",
    "stdio_libio",
    "allocator",
    "startup_linking",
    "performance_sensitive",
];

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

fn load_matrix() -> serde_json::Value {
    load_json(&workspace_root().join("tests/conformance/user_workload_acceptance_matrix.v1.json"))
}

#[test]
fn artifact_exists_and_has_required_shape() {
    let matrix = load_matrix();
    assert_eq!(matrix["schema_version"].as_str(), Some("v1"));
    assert_eq!(matrix["bead"].as_str(), Some("bd-bp8fl.10.1"));
    assert!(matrix["inputs"].is_object(), "inputs must be object");
    assert!(matrix["personas"].is_array(), "personas must be array");
    assert!(
        matrix["failure_taxonomy"].is_array(),
        "failure_taxonomy must be array"
    );
    assert!(matrix["workloads"].is_array(), "workloads must be array");
    assert!(matrix["summary"].is_object(), "summary must be object");

    let required: Vec<_> = matrix["required_log_fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|field| field.as_str().unwrap())
        .collect();
    assert_eq!(required, REQUIRED_LOG_FIELDS);
}

#[test]
fn workloads_cover_required_domains_modes_and_levels() {
    let matrix = load_matrix();
    let personas: HashSet<_> = matrix["personas"]
        .as_array()
        .unwrap()
        .iter()
        .map(|persona| persona["id"].as_str().unwrap())
        .collect();

    let mut coverage: HashMap<String, u64> = HashMap::new();
    let mut negative_claim_tests = 0_u64;
    for workload in matrix["workloads"].as_array().unwrap() {
        let id = workload["id"].as_str().unwrap();
        assert!(
            personas.contains(workload["persona_id"].as_str().unwrap()),
            "{id}: persona_id must reference a persona"
        );

        let domains: HashSet<_> = workload["coverage_domains"]
            .as_array()
            .unwrap()
            .iter()
            .map(|domain| domain.as_str().unwrap())
            .collect();
        assert!(
            domains.contains(workload["primary_domain"].as_str().unwrap()),
            "{id}: coverage_domains must include primary_domain"
        );
        for domain in domains {
            *coverage.entry(domain.to_string()).or_default() += 1;
        }

        let modes: HashSet<_> = workload["runtime_modes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|mode| mode.as_str().unwrap())
            .collect();
        assert!(modes.contains("strict"), "{id}: missing strict mode");
        assert!(modes.contains("hardened"), "{id}: missing hardened mode");

        let levels: HashSet<_> = workload["replacement_levels"]
            .as_array()
            .unwrap()
            .iter()
            .map(|level| level.as_str().unwrap())
            .collect();
        for level in ["L0", "L1", "L2", "L3"] {
            assert!(levels.contains(level), "{id}: missing {level}");
        }

        assert!(
            !workload["required_unit_tests"]
                .as_array()
                .unwrap()
                .is_empty(),
            "{id}: required_unit_tests must not be empty"
        );
        assert!(
            !workload["deterministic_e2e_scripts"]
                .as_array()
                .unwrap()
                .is_empty(),
            "{id}: deterministic_e2e_scripts must not be empty"
        );
        assert!(
            !workload["user_facing_diagnostics"]
                .as_array()
                .unwrap()
                .is_empty(),
            "{id}: user_facing_diagnostics must not be empty"
        );
        assert_eq!(
            workload["structured_log_fields"].as_str(),
            Some("required_log_fields"),
            "{id}: structured_log_fields should reference the top-level log contract"
        );

        for negative in workload["negative_claim_tests"].as_array().unwrap() {
            assert_eq!(
                negative["expected_result"].as_str(),
                Some("claim_blocked"),
                "{id}: unsupported or missing-evidence cases must remain blocked"
            );
            negative_claim_tests += 1;
        }
    }

    for domain in REQUIRED_DOMAINS {
        assert!(
            coverage.contains_key(*domain),
            "required domain {domain} must be covered"
        );
    }
    assert_eq!(
        matrix["summary"]["negative_claim_test_count"].as_u64(),
        Some(negative_claim_tests)
    );
    assert_eq!(
        matrix["summary"]["required_domain_coverage"],
        serde_json::to_value(coverage).unwrap()
    );
}

#[test]
fn failure_taxonomy_and_workload_scenarios_are_consistent() {
    let matrix = load_matrix();
    let taxonomy: HashSet<_> = matrix["failure_taxonomy"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["id"].as_str().unwrap())
        .collect();

    assert!(
        taxonomy.contains("unsupported_claim"),
        "taxonomy must include unsupported_claim"
    );
    assert!(
        taxonomy.contains("diagnostics_gap"),
        "taxonomy must include diagnostics_gap"
    );

    for workload in matrix["workloads"].as_array().unwrap() {
        let id = workload["id"].as_str().unwrap();
        for scenario in workload["failure_scenarios"].as_array().unwrap() {
            let taxonomy_id = scenario["taxonomy_id"].as_str().unwrap();
            assert!(
                taxonomy.contains(taxonomy_id),
                "{id}: unknown taxonomy id {taxonomy_id}"
            );
            assert!(
                !scenario["expected_failure_signature"]
                    .as_str()
                    .unwrap()
                    .is_empty(),
                "{id}: expected_failure_signature must not be empty"
            );
            assert!(
                !scenario["blocks_claim_levels"]
                    .as_array()
                    .unwrap()
                    .is_empty(),
                "{id}: blocks_claim_levels must not be empty"
            );
        }
    }
}

#[test]
fn gate_script_passes_and_emits_structured_report_and_log() {
    let root = workspace_root();
    let script = root.join("scripts/check_user_workload_acceptance_matrix.sh");
    assert!(
        script.exists(),
        "missing {}",
        script.strip_prefix(&root).unwrap().display()
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_user_workload_acceptance_matrix.sh must be executable"
        );
    }

    let output = Command::new(&script)
        .current_dir(&root)
        .output()
        .expect("failed to run user workload acceptance matrix gate");
    assert!(
        output.status.success(),
        "user workload acceptance matrix gate failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_path = root.join("target/conformance/user_workload_acceptance_matrix.report.json");
    let log_path = root.join("target/conformance/user_workload_acceptance_matrix.log.jsonl");
    let report = load_json(&report_path);
    assert_eq!(report["schema_version"].as_str(), Some("v1"));
    assert_eq!(report["bead"].as_str(), Some("bd-bp8fl.10.1"));
    assert_eq!(report["status"].as_str(), Some("pass"));
    for check in [
        "json_parse",
        "top_level_shape",
        "required_log_fields",
        "personas",
        "failure_taxonomy",
        "workload_rows",
        "domain_coverage",
        "summary_counts",
        "negative_claim_policy",
    ] {
        assert_eq!(
            report["checks"][check].as_str(),
            Some("pass"),
            "report checks.{check} should pass"
        );
    }

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
