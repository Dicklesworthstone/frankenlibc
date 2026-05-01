//! Integration test: standalone readiness proof matrix gate (bd-bp8fl.6.6)
//!
//! Validates that L2/L3 replacement claims stay blocked until artifact-level
//! proof obligations are current.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;

const REQUIRED_DIMENSIONS: &[&str] = &[
    "loader_startup_crt_tls_init_fini_secure",
    "versioned_symbol_exports",
    "host_glibc_free_execution",
    "syscall_arch_obligations",
    "failure_diagnostics",
    "real_program_standalone_smoke",
    "performance_budget",
    "resolver_nss_locale_iconv",
    "pthread_stdio_native",
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
    load_json(&workspace_root().join("tests/conformance/standalone_readiness_proof_matrix.v1.json"))
}

#[test]
fn artifact_exists_and_has_required_shape() {
    let matrix = load_matrix();
    assert_eq!(matrix["schema_version"].as_str(), Some("v1"));
    assert_eq!(matrix["bead"].as_str(), Some("bd-bp8fl.6.6"));
    assert!(matrix["inputs"].is_object(), "inputs must be object");
    assert!(
        matrix["claim_policy"].is_object(),
        "claim_policy must be object"
    );
    assert!(
        matrix["readiness_levels"].is_array(),
        "readiness_levels must be array"
    );
    assert!(
        matrix["obligations"].is_array(),
        "obligations must be array"
    );
    assert!(matrix["summary"].is_object(), "summary must be object");

    let log_fields: Vec<_> = matrix["required_log_fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|field| field.as_str().unwrap())
        .collect();
    assert_eq!(log_fields, REQUIRED_LOG_FIELDS);
}

#[test]
fn replacement_levels_remain_blocked_for_l2_l3() {
    let root = workspace_root();
    let matrix = load_matrix();
    let levels = load_json(&root.join("tests/conformance/replacement_levels.json"));

    assert_eq!(levels["current_level"].as_str(), Some("L0"));
    assert_eq!(
        levels["release_tag_policy"]["current_release_level"].as_str(),
        Some("L0")
    );
    assert_eq!(
        matrix["claim_policy"]["symbol_counts_are_insufficient"].as_bool(),
        Some(true)
    );
    assert_eq!(
        matrix["claim_policy"]["missing_evidence_result"].as_str(),
        Some("claim_blocked")
    );

    let readiness: HashMap<_, _> = matrix["readiness_levels"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| (entry["level"].as_str().unwrap(), entry))
        .collect();
    for level in ["L2", "L3"] {
        let entry = readiness.get(level).unwrap();
        assert_eq!(
            entry["current_claim_status"].as_str(),
            Some("blocked"),
            "{level}: current claim status must remain blocked"
        );
        assert!(
            !entry["blocked_reason"].as_str().unwrap().is_empty(),
            "{level}: blocked_reason must not be empty"
        );
    }
}

#[test]
fn obligations_cover_dimensions_and_block_overclaims() {
    let root = workspace_root();
    let matrix = load_matrix();
    let required_dimensions: HashSet<_> = REQUIRED_DIMENSIONS.iter().copied().collect();
    let mut dimension_coverage: HashMap<String, u64> = HashMap::new();
    let mut by_level: HashMap<String, u64> = HashMap::new();
    let mut negative_claim_tests = 0_u64;

    for obligation in matrix["obligations"].as_array().unwrap() {
        let id = obligation["id"].as_str().unwrap();
        let level = obligation["level"].as_str().unwrap();
        assert!(["L2", "L3"].contains(&level), "{id}: invalid level");
        *by_level.entry(level.to_string()).or_default() += 1;

        assert_eq!(
            obligation["current_state"].as_str(),
            Some("blocked"),
            "{id}: current_state must be blocked"
        );
        assert!(
            !obligation["blocker_reason"].as_str().unwrap().is_empty(),
            "{id}: blocker_reason must not be empty"
        );
        assert_eq!(
            obligation["log_fields"].as_str(),
            Some("required_log_fields"),
            "{id}: log_fields must reference required_log_fields"
        );

        let mut dimensions = vec![obligation["dimension"].as_str().unwrap()];
        if let Some(secondary) = obligation["secondary_dimensions"].as_array() {
            dimensions.extend(secondary.iter().map(|value| value.as_str().unwrap()));
        }
        for dimension in dimensions {
            assert!(
                required_dimensions.contains(dimension),
                "{id}: unknown dimension {dimension}"
            );
            *dimension_coverage.entry(dimension.to_string()).or_default() += 1;
        }

        for artifact in obligation["evidence_artifacts"].as_array().unwrap() {
            let rel = artifact.as_str().unwrap();
            assert!((root.join(rel)).exists(), "{id}: missing artifact {rel}");
        }
        for command in obligation["check_commands"].as_array().unwrap() {
            let command = command.as_str().unwrap();
            let script = command.split_whitespace().next().unwrap();
            assert!(
                (root.join(script)).exists(),
                "{id}: missing script {script}"
            );
        }
        assert!(
            !obligation["unit_tests_required"]
                .as_array()
                .unwrap()
                .is_empty(),
            "{id}: unit_tests_required must not be empty"
        );
        assert!(
            !obligation["e2e_or_smoke_required"]
                .as_array()
                .unwrap()
                .is_empty(),
            "{id}: e2e_or_smoke_required must not be empty"
        );

        for test in obligation["negative_claim_tests"].as_array().unwrap() {
            assert_eq!(
                test["expected_result"].as_str(),
                Some("claim_blocked"),
                "{id}: negative claim tests must block overclaims"
            );
            negative_claim_tests += 1;
        }
    }

    for dimension in REQUIRED_DIMENSIONS {
        assert!(
            dimension_coverage.contains_key(*dimension),
            "required dimension {dimension} must be covered"
        );
    }
    assert_eq!(
        matrix["summary"]["by_level"],
        serde_json::to_value(by_level).unwrap()
    );
    assert_eq!(
        matrix["summary"]["dimension_coverage"],
        serde_json::to_value(dimension_coverage).unwrap()
    );
    assert_eq!(
        matrix["summary"]["negative_claim_test_count"].as_u64(),
        Some(negative_claim_tests)
    );
}

#[test]
fn gate_script_passes_and_emits_structured_report_and_log() {
    let root = workspace_root();
    let script = root.join("scripts/check_standalone_readiness_matrix.sh");
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
            "check_standalone_readiness_matrix.sh must be executable"
        );
    }

    let output = Command::new(&script)
        .current_dir(&root)
        .output()
        .expect("failed to run standalone readiness matrix gate");
    assert!(
        output.status.success(),
        "standalone readiness matrix gate failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_path = root.join("target/conformance/standalone_readiness_proof_matrix.report.json");
    let log_path = root.join("target/conformance/standalone_readiness_proof_matrix.log.jsonl");
    let report = load_json(&report_path);
    assert_eq!(report["schema_version"].as_str(), Some("v1"));
    assert_eq!(report["bead"].as_str(), Some("bd-bp8fl.6.6"));
    assert_eq!(report["status"].as_str(), Some("pass"));
    for check in [
        "json_parse",
        "top_level_shape",
        "required_log_fields",
        "current_level_guard",
        "readiness_levels",
        "obligations",
        "dimension_coverage",
        "claim_policy",
        "summary_counts",
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
