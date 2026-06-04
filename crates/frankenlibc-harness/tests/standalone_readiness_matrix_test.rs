//! Integration test: standalone readiness proof matrix gate (bd-bp8fl.6.6)
//!
//! Validates that L2/L3 replacement claims stay blocked until artifact-level
//! proof obligations are current.

use std::collections::{HashMap, HashSet};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

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
    "proof_row_id",
    "scenario_id",
    "runtime_mode",
    "replacement_level",
    "artifact_refs",
    "required_evidence",
    "present_evidence",
    "missing_evidence",
    "expected_decision",
    "actual_decision",
    "source_commit",
    "target_dir",
    "failure_signature",
];

const REQUIRED_PROOF_SURFACES: &[&str] = &[
    "loader_startup",
    "crt_objects",
    "tls",
    "init_fini",
    "destructors",
    "secure_execution_mode",
    "symbol_version_nodes",
    "relocation_dlfcn_behavior",
    "syscall_coverage",
    "arch_specific_obligations",
    "host_glibc_free_execution",
    "diagnostics",
    "real_program_standalone_smoke",
    "cross_environment_evidence",
];

const STANDALONE_ARTIFACT_REF: &str = "tests/conformance/standalone_replacement_artifact.v1.json";

fn is_hex_commit(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn source_commit_is_current(value: &str, current_head: &str) -> bool {
    value == "current" || value == current_head
}

fn git_head(root: &Path) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .arg("rev-parse")
        .arg("HEAD")
        .output()
        .expect("git rev-parse HEAD should run");
    assert!(
        output.status.success(),
        "git rev-parse HEAD failed with status {}",
        output.status,
    );
    let stdout = String::from_utf8(output.stdout).expect("git rev-parse HEAD should emit UTF-8");
    let head = stdout.trim().to_owned();
    assert!(
        is_hex_commit(&head),
        "git HEAD must be a 40-hex commit, got {head:?}",
    );
    head
}

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

fn unique_target_path(root: &Path, label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after UNIX_EPOCH")
        .as_nanos();
    root.join(format!(
        "target/standalone_readiness_matrix_test/{label}-{}-{nanos}.json",
        std::process::id()
    ))
}

fn write_json(path: &Path, value: &serde_json::Value) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("target parent should be creatable");
    }
    let content = serde_json::to_string_pretty(value).expect("json should serialize");
    std::fs::write(path, format!("{content}\n")).expect("json should be writable");
}

fn json_array_contains(value: &serde_json::Value, needle: &str) -> bool {
    value
        .as_array()
        .unwrap()
        .iter()
        .any(|entry| entry.as_str() == Some(needle))
}

fn json_array_lacks(value: &serde_json::Value, needle: &str) -> bool {
    !json_array_contains(value, needle)
}

fn assert_repo_relative_existing_path(root: &Path, rel: &str, context: &str) {
    let path = Path::new(rel);
    assert!(!rel.is_empty(), "{context}: artifact ref must not be empty");
    assert!(
        !path.is_absolute(),
        "{context}: artifact ref must stay repo-relative: {rel}"
    );
    assert!(
        !path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::Prefix(_))),
        "{context}: artifact ref must not escape the repo root: {rel}"
    );
    assert!(
        (root.join(path)).exists(),
        "{context}: missing artifact {rel}"
    );
}

fn assert_source_commit_freshness_policy(matrix: &serde_json::Value) {
    let policy = &matrix["source_commit_freshness_policy"];
    assert_eq!(
        policy["recorded_source_commit_field"].as_str(),
        Some("source_commit"),
    );
    assert_eq!(
        policy["comparison_target"].as_str(),
        Some("current git HEAD")
    );
    assert_eq!(
        policy["stale_result"].as_str(),
        Some("block_standalone_readiness_matrix_evidence"),
    );
    assert_eq!(
        policy["standalone_readiness_evidence_allowed_when_stale"].as_bool(),
        Some(false),
    );
    assert_eq!(
        policy["rejected_evidence_kind"].as_str(),
        Some("stale_source_commit"),
    );
}

fn assert_recorded_source_commit_is_current(root: &Path, matrix: &serde_json::Value) {
    let source_commit = matrix["source_commit"]
        .as_str()
        .expect("source_commit must be present");
    assert!(
        source_commit == "current" || is_hex_commit(source_commit),
        "source_commit must be 'current' or a 40-hex commit, got {source_commit:?}",
    );
    let current_head = git_head(root);
    assert!(
        source_commit_is_current(source_commit, &current_head),
        "source_commit must be 'current' or match current git HEAD",
    );
}

#[test]
fn artifact_exists_and_has_required_shape() {
    let root = workspace_root();
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
    let source_commit = matrix["source_commit"]
        .as_str()
        .expect("source_commit must be present");
    assert_eq!(source_commit, "current");
    assert_recorded_source_commit_is_current(&root, &matrix);
    assert_source_commit_freshness_policy(&matrix);

    let log_fields: Vec<_> = matrix["required_log_fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|field| field.as_str().unwrap())
        .collect();
    assert_eq!(log_fields, REQUIRED_LOG_FIELDS);
}

#[test]
fn stale_source_commit_policy_blocks_standalone_readiness_evidence() {
    let root = workspace_root();
    let matrix = load_matrix();
    let source_commit = matrix["source_commit"]
        .as_str()
        .expect("source_commit must be present");
    assert!(
        source_commit == "current" || is_hex_commit(source_commit),
        "source_commit must be 'current' or a 40-hex commit, got {source_commit:?}",
    );
    let current_head = git_head(&root);
    assert_source_commit_freshness_policy(&matrix);
    if !source_commit_is_current(source_commit, &current_head) {
        let policy = &matrix["source_commit_freshness_policy"];
        assert_eq!(
            policy["stale_result"].as_str(),
            Some("block_standalone_readiness_matrix_evidence"),
            "stale source commits must block standalone readiness evidence",
        );
        assert_eq!(
            policy["standalone_readiness_evidence_allowed_when_stale"].as_bool(),
            Some(false),
            "stale source commits must not allow standalone readiness evidence",
        );
        assert_eq!(
            policy["rejected_evidence_kind"].as_str(),
            Some("stale_source_commit"),
            "stale source commits must use stale_source_commit",
        );
    }
}

#[test]
#[should_panic(expected = "source_commit must be 'current' or match current git HEAD")]
fn stale_recorded_source_commit_helper_rejects_standalone_readiness_evidence() {
    let root = workspace_root();
    let mut matrix = load_matrix();
    matrix["source_commit"] = serde_json::json!("0000000000000000000000000000000000000000");
    assert_recorded_source_commit_is_current(&root, &matrix);
}

#[test]
fn standalone_artifact_is_first_class_readiness_evidence() {
    let root = workspace_root();
    let matrix = load_matrix();

    assert_eq!(
        matrix["inputs"]["standalone_replacement_artifact"].as_str(),
        Some(STANDALONE_ARTIFACT_REF)
    );
    assert_repo_relative_existing_path(&root, STANDALONE_ARTIFACT_REF, "inputs");

    let proof_rows = matrix["proof_rows"].as_array().unwrap();
    for proof_row_id in ["symbol_version_nodes", "host_glibc_free_execution"] {
        let row = proof_rows
            .iter()
            .find(|row| row["proof_row_id"].as_str() == Some(proof_row_id))
            .expect("proof row must exist");
        assert!(
            json_array_contains(&row["artifact_refs"], STANDALONE_ARTIFACT_REF),
            "{proof_row_id}: artifact_refs must include {STANDALONE_ARTIFACT_REF}"
        );
    }

    let obligations = matrix["obligations"].as_array().unwrap();
    for obligation_id in ["l2-versioned-symbol-subset", "l2-host-dependency-allowlist"] {
        let obligation = obligations
            .iter()
            .find(|entry| entry["id"].as_str() == Some(obligation_id))
            .expect("obligation must exist");
        assert!(
            json_array_contains(&obligation["evidence_artifacts"], STANDALONE_ARTIFACT_REF),
            "{obligation_id}: evidence_artifacts must include {STANDALONE_ARTIFACT_REF}"
        );
    }
}

#[test]
fn standalone_forge_audits_are_present_failing_evidence() {
    let matrix = load_matrix();
    let proof_rows = matrix["proof_rows"].as_array().unwrap();

    let symbol_row = proof_rows
        .iter()
        .find(|row| row["proof_row_id"].as_str() == Some("symbol_version_nodes"))
        .expect("symbol_version_nodes proof row must exist");
    assert!(
        json_array_contains(
            &symbol_row["present_evidence"],
            "current standalone forge symbol/version audit with sampled symbols present",
        ),
        "symbol_version_nodes must treat current forge audit as present evidence"
    );
    assert!(
        json_array_lacks(
            &symbol_row["missing_evidence"],
            "current standalone artifact symbol/version audit",
        ),
        "symbol_version_nodes must not classify the current forge audit as missing"
    );
    for blocker in [
        "full claimed-subset version-node parity",
        "cleared host version requirements in standalone forge report",
    ] {
        assert!(
            json_array_contains(&symbol_row["missing_evidence"], blocker),
            "symbol_version_nodes missing_evidence must include {blocker}"
        );
    }

    let host_row = proof_rows
        .iter()
        .find(|row| row["proof_row_id"].as_str() == Some("host_glibc_free_execution"))
        .expect("host_glibc_free_execution proof row must exist");
    assert!(
        json_array_contains(
            &host_row["present_evidence"],
            "current standalone forge dependency audit with host_glibc_dependency=true",
        ),
        "host_glibc_free_execution must treat current forge audit as present evidence"
    );
    assert!(
        json_array_lacks(
            &host_row["missing_evidence"],
            "current libfrankenlibc_replace.so dynamic dependency audit",
        ),
        "host_glibc_free_execution must not classify the current forge audit as missing"
    );
    for blocker in [
        "host-glibc-free dynamic dependency audit",
        "cleared loader/libc/libgcc/unwind/TLS blocker set",
    ] {
        assert!(
            json_array_contains(&host_row["missing_evidence"], blocker),
            "host_glibc_free_execution missing_evidence must include {blocker}"
        );
    }

    let obligations = matrix["obligations"].as_array().unwrap();
    let version_obligation = obligations
        .iter()
        .find(|entry| entry["id"].as_str() == Some("l2-versioned-symbol-subset"))
        .expect("l2-versioned-symbol-subset obligation must exist");
    assert!(
        version_obligation["blocker_reason"]
            .as_str()
            .unwrap()
            .contains("Current forge evidence"),
        "versioned-symbol obligation must name current forge evidence"
    );

    let host_obligation = obligations
        .iter()
        .find(|entry| entry["id"].as_str() == Some("l2-host-dependency-allowlist"))
        .expect("l2-host-dependency-allowlist obligation must exist");
    let host_reason = host_obligation["blocker_reason"].as_str().unwrap();
    for blocker in ["host loader", "libc", "libgcc", "unwind", "TLS"] {
        assert!(
            host_reason.contains(blocker),
            "host dependency blocker reason must mention {blocker}"
        );
    }
}

#[test]
fn replacement_levels_remain_blocked_for_l2_l3() {
    let root = workspace_root();
    let matrix = load_matrix();
    let levels = load_json(&root.join("tests/conformance/replacement_levels.json"));

    assert_eq!(levels["current_level"].as_str(), Some("L1"));
    assert_eq!(
        levels["release_tag_policy"]["current_release_level"].as_str(),
        Some("L1")
    );
    assert_eq!(
        matrix["claim_policy"]["current_level_must_remain"].as_str(),
        Some("L1")
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
            assert_repo_relative_existing_path(&root, rel, id);
        }
        for command in obligation["check_commands"].as_array().unwrap() {
            let command = command.as_str().unwrap();
            let script = command.split_whitespace().next().unwrap();
            assert_repo_relative_existing_path(&root, script, id);
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
fn proof_rows_cover_standalone_surfaces_and_fail_closed() {
    let root = workspace_root();
    let matrix = load_matrix();
    let required_surfaces: HashSet<_> = REQUIRED_PROOF_SURFACES.iter().copied().collect();
    let declared_surfaces: HashSet<_> = matrix["required_proof_surfaces"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect();
    assert_eq!(declared_surfaces, required_surfaces);

    let mut covered_surfaces = HashSet::new();
    let proof_rows = matrix["proof_rows"].as_array().unwrap();
    for row in proof_rows {
        let proof_row_id = row["proof_row_id"].as_str().unwrap();
        let surface = row["surface"].as_str().unwrap();
        covered_surfaces.insert(surface);
        assert!(
            required_surfaces.contains(surface),
            "{proof_row_id}: unexpected proof surface {surface}"
        );
        assert!(
            ["L2", "L3"].contains(&row["replacement_level"].as_str().unwrap()),
            "{proof_row_id}: proof row must target L2 or L3"
        );
        assert_eq!(
            row["expected_decision"].as_str(),
            Some("claim_blocked"),
            "{proof_row_id}: expected decision must fail closed"
        );
        assert_eq!(
            row["actual_decision"].as_str(),
            Some("claim_blocked"),
            "{proof_row_id}: actual decision must fail closed"
        );
        for evidence_field in ["required_evidence", "present_evidence", "missing_evidence"] {
            assert!(
                !row[evidence_field].as_array().unwrap().is_empty(),
                "{proof_row_id}: {evidence_field} must not be empty"
            );
        }
        for artifact in row["artifact_refs"].as_array().unwrap() {
            let rel = artifact.as_str().unwrap();
            assert_repo_relative_existing_path(&root, rel, proof_row_id);
        }
    }

    assert_eq!(covered_surfaces, required_surfaces);
    assert_eq!(
        matrix["summary"]["proof_row_count"].as_u64(),
        Some(proof_rows.len() as u64)
    );
    assert_eq!(
        matrix["summary"]["claim_blocked_proof_row_count"].as_u64(),
        Some(proof_rows.len() as u64)
    );
    assert_eq!(
        matrix["summary"]["missing_evidence_proof_row_count"].as_u64(),
        Some(proof_rows.len() as u64)
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
        "standalone_artifact_input",
        "current_level_guard",
        "readiness_levels",
        "proof_rows",
        "obligations",
        "standalone_artifact_refs",
        "standalone_forge_evidence_semantics",
        "source_commit_freshness_policy",
        "recorded_source_commit_freshness",
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

#[test]
fn gate_rejects_stale_recorded_source_commit() {
    let root = workspace_root();
    let script = root.join("scripts/check_standalone_readiness_matrix.sh");
    let mut matrix = load_matrix();
    matrix["source_commit"] = serde_json::json!("0000000000000000000000000000000000000000");
    let matrix_path = unique_target_path(&root, "stale-source-matrix");
    let report_path = unique_target_path(&root, "stale-source-report");
    let log_path = unique_target_path(&root, "stale-source-log");
    write_json(&matrix_path, &matrix);

    let output = Command::new(&script)
        .current_dir(&root)
        .env("FLC_STANDALONE_READINESS_MATRIX", &matrix_path)
        .env("FLC_STANDALONE_READINESS_REPORT", &report_path)
        .env("FLC_STANDALONE_READINESS_LOG", &log_path)
        .output()
        .expect("failed to run standalone readiness matrix gate");
    assert!(
        !output.status.success(),
        "stale recorded source_commit must fail the gate"
    );
    let report = load_json(&report_path);
    assert_eq!(
        report["checks"]["recorded_source_commit_freshness"].as_str(),
        Some("fail"),
    );
    assert!(
        report["errors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|error| error
                .as_str()
                .unwrap_or_default()
                .contains("source_commit must be 'current' or match current git HEAD")),
        "report should identify stale source_commit failure: {report:#?}",
    );
}

#[test]
fn gate_rejects_missing_source_commit_freshness_policy() {
    let root = workspace_root();
    let script = root.join("scripts/check_standalone_readiness_matrix.sh");
    let mut matrix = load_matrix();
    matrix
        .as_object_mut()
        .expect("matrix must be object")
        .remove("source_commit_freshness_policy");
    let matrix_path = unique_target_path(&root, "missing-source-policy-matrix");
    let report_path = unique_target_path(&root, "missing-source-policy-report");
    let log_path = unique_target_path(&root, "missing-source-policy-log");
    write_json(&matrix_path, &matrix);

    let output = Command::new(&script)
        .current_dir(&root)
        .env("FLC_STANDALONE_READINESS_MATRIX", &matrix_path)
        .env("FLC_STANDALONE_READINESS_REPORT", &report_path)
        .env("FLC_STANDALONE_READINESS_LOG", &log_path)
        .output()
        .expect("failed to run standalone readiness matrix gate");
    assert!(
        !output.status.success(),
        "missing source_commit_freshness_policy must fail the gate"
    );
    let report = load_json(&report_path);
    assert_eq!(
        report["checks"]["source_commit_freshness_policy"].as_str(),
        Some("fail"),
    );
    assert!(
        report["errors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|error| error
                .as_str()
                .unwrap_or_default()
                .contains("source_commit_freshness_policy")),
        "report should identify source_commit_freshness_policy failure: {report:#?}",
    );
}
