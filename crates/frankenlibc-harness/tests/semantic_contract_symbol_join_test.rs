//! Integration test: semantic contract symbol-join gate (bd-bp8fl.1.2)
//!
//! Verifies that the joined semantic overlay stays synchronized with the
//! semantic inventory, support_matrix.json, libc.map, and ABI source exports.
//!
//! Run:
//!   cargo test -p frankenlibc-harness --test semantic_contract_symbol_join_test

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

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
fn artifact_preserves_inventory_rows_and_blocks_claim_promotion() {
    let root = workspace_root();
    let artifact = load_json(&root.join("tests/conformance/semantic_contract_symbol_join.v1.json"));
    let inventory = load_json(&root.join("tests/conformance/semantic_contract_inventory.v1.json"));

    assert_eq!(artifact["schema_version"].as_str(), Some("v1"));
    assert_eq!(artifact["bead"].as_str(), Some("bd-bp8fl.1.2"));
    assert_eq!(
        artifact["claim_policy"]["support_taxonomy_is_not_semantic_parity"].as_bool(),
        Some(true)
    );
    assert_eq!(
        artifact["claim_policy"]
            ["full_replacement_claim_requires_all_rows_semantic_parity_status_full"]
            .as_bool(),
        Some(true)
    );
    let join_schema = artifact["join_schema"]
        .as_object()
        .expect("artifact must declare join_schema");
    for (section, expected_fields) in [
        (
            "key_fields",
            vec!["symbol", "version_node", "namespace_header", "abi_family"],
        ),
        (
            "status_fields",
            vec![
                "support_status",
                "semantic_contract",
                "semantic_parity_status",
                "oracle_kind",
                "replacement_level",
            ],
        ),
        (
            "evidence_fields",
            vec![
                "source_artifact",
                "freshness_metadata",
                "artifact_refs",
                "join_decision",
                "failure_signature",
            ],
        ),
    ] {
        let fields: Vec<_> = join_schema[section]
            .as_array()
            .expect("join_schema sections must be arrays")
            .iter()
            .map(|value| value.as_str().expect("join_schema field names"))
            .collect();
        assert_eq!(fields, expected_fields, "join_schema.{section}");
    }

    let rows = artifact["entries"]
        .as_array()
        .expect("entries must be array");
    let inventory_entries = inventory["entries"]
        .as_array()
        .expect("inventory entries must be array");

    assert_eq!(
        rows.len(),
        inventory_entries.len(),
        "joined overlay must cover every semantic inventory entry"
    );

    let rows_by_id: HashMap<&str, &serde_json::Value> = rows
        .iter()
        .map(|row| {
            (
                row["inventory_id"]
                    .as_str()
                    .expect("row inventory_id must be string"),
                row,
            )
        })
        .collect();
    assert_eq!(
        rows_by_id.len(),
        rows.len(),
        "inventory_id values must be unique"
    );

    let mut blocker_classes = HashSet::new();
    for inventory_row in inventory_entries {
        let row_id = inventory_row["id"].as_str().expect("inventory id");
        let row = rows_by_id
            .get(row_id)
            .expect("joined overlay must cover every semantic inventory row");

        assert_eq!(
            row["surface"], inventory_row["surface"],
            "{row_id}: surface"
        );
        assert_eq!(
            row["source_path"], inventory_row["source_path"],
            "{row_id}: source_path"
        );
        assert_eq!(
            row["taxonomy_status"], inventory_row["support_matrix_status"],
            "{row_id}: taxonomy_status"
        );
        assert_eq!(
            row["semantic_class"], inventory_row["semantic_class"],
            "{row_id}: semantic_class"
        );
        assert_eq!(
            row["symbol_refs"], inventory_row["symbols"],
            "{row_id}: symbols"
        );

        assert_eq!(
            row["taxonomy_status_is_semantic_parity"].as_bool(),
            Some(false),
            "{row_id}: taxonomy status must not be promoted to parity"
        );
        let parity_status = row["semantic_parity_status"]
            .as_str()
            .expect("semantic_parity_status must be string");
        assert!(
            parity_status.starts_with("blocked_"),
            "{row_id}: semantic parity status must remain blocked, got {parity_status}"
        );
        blocker_classes.insert(row["semantic_class"].as_str().unwrap().to_string());
    }

    for class in [
        "abort_only",
        "compat_noop",
        "deterministic_fallback",
        "limited_bootstrap",
        "unsupported_platform_contract",
    ] {
        assert!(
            blocker_classes.contains(class),
            "joined overlay must preserve blocker class {class}"
        );
    }
}

#[test]
fn gate_script_passes_and_emits_structured_report_and_log() {
    let root = workspace_root();
    let script = root.join("scripts/check_semantic_contract_symbol_join.sh");
    assert!(script.exists(), "missing {}", script.display());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_semantic_contract_symbol_join.sh must be executable"
        );
    }

    let output = Command::new(&script)
        .current_dir(&root)
        .output()
        .expect("failed to run semantic contract symbol-join gate");
    assert!(
        output.status.success(),
        "semantic contract symbol-join gate failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = parse_stdout_report(&output);
    assert_eq!(report["schema_version"].as_str(), Some("v1"));
    assert_eq!(report["bead"].as_str(), Some("bd-bp8fl.1.2"));
    assert_eq!(report["status"].as_str(), Some("pass"));
    for check in [
        "json_parse",
        "artifact_shape",
        "join_schema_declared",
        "inventory_row_coverage",
        "version_script_read",
        "version_node_map_loaded",
        "support_matrix_symbols_loaded",
        "abi_source_symbols_loaded",
        "summary_matches_current_join",
        "row_contract_shape",
        "row_join_expectations",
        "source_exports_cover_exact_symbols",
        "support_matrix_missing_symbols_are_accounted",
        "resolved_join_rows_complete",
        "conflicting_symbol_rows",
    ] {
        assert_eq!(
            report["checks"][check].as_str(),
            Some("pass"),
            "checks.{check} should pass"
        );
    }

    assert_eq!(
        report["summary"]["support_matrix_missing_exact_symbol_count"].as_u64(),
        Some(6)
    );
    assert_eq!(
        report["summary"]["version_script_missing_exact_symbol_count"].as_u64(),
        Some(2)
    );
    assert_eq!(
        report["summary"]["source_missing_exact_symbol_count"].as_u64(),
        Some(0)
    );
    assert_eq!(
        report["summary"]["resolved_symbol_join_row_count"].as_u64(),
        Some(88)
    );
    assert_eq!(
        report["summary"]["conflicting_exact_symbol_join_count"].as_u64(),
        Some(0)
    );

    let resolved_rows = report["resolved_symbol_join_rows"]
        .as_array()
        .expect("report must include resolved per-symbol join rows");
    let pthread_row = resolved_rows
        .iter()
        .find(|row| row["symbol"].as_str() == Some("__pthread_register_cancel"))
        .expect("resolved rows must include exact pthread cancellation symbol");
    assert_eq!(pthread_row["version_node"].as_str(), Some("GLIBC_2.2.5"));
    assert_eq!(pthread_row["namespace_header"].as_str(), Some("pthread.h"));
    assert_eq!(
        pthread_row["oracle_kind"].as_str(),
        Some("support_matrix_version_script_abi_source_join")
    );
    assert_eq!(
        pthread_row["replacement_level"].as_str(),
        Some("L0_interpose_and_L1_planning")
    );
    assert_eq!(pthread_row["join_decision"].as_str(), Some("joined_exact"));

    let report_path = root.join("target/conformance/semantic_contract_symbol_join.report.json");
    let log_path = root.join("target/conformance/semantic_contract_symbol_join.log.jsonl");
    assert!(report_path.exists(), "missing {}", report_path.display());
    assert!(log_path.exists(), "missing {}", log_path.display());

    let log_line = std::fs::read_to_string(&log_path)
        .expect("log should be readable")
        .lines()
        .find(|line| !line.trim().is_empty())
        .expect("log should contain at least one row")
        .to_string();
    let event: serde_json::Value = serde_json::from_str(&log_line).expect("log row should parse");
    for key in [
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
    ] {
        assert!(event.get(key).is_some(), "structured log row missing {key}");
    }
}

#[test]
fn alternate_version_script_nodes_are_reflected_in_resolved_rows() {
    let root = workspace_root();
    let script = root.join("scripts/check_semantic_contract_symbol_join.sh");
    let canonical_version_script = root.join("crates/frankenlibc-abi/version_scripts/libc.map");
    let mutated_version_script = unique_temp_path("semantic-contract-version-script.map");
    let text = std::fs::read_to_string(&canonical_version_script)
        .expect("canonical version script should be readable");
    let mutated = text.replacen("GLIBC_2.2.5 {", "GLIBC_JOIN_TEST_1.0 {", 1);
    std::fs::write(&mutated_version_script, mutated)
        .expect("failed to write mutated version script");

    let output = Command::new(&script)
        .current_dir(&root)
        .env("FLC_SEMANTIC_JOIN_VERSION_SCRIPT", &mutated_version_script)
        .output()
        .expect("failed to run semantic contract symbol-join gate with version node fixture");
    assert!(
        output.status.success(),
        "version-node fixture should preserve joins while changing node labels:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = parse_stdout_report(&output);
    let resolved_rows = report["resolved_symbol_join_rows"]
        .as_array()
        .expect("report must include resolved per-symbol join rows");
    let pthread_row = resolved_rows
        .iter()
        .find(|row| row["symbol"].as_str() == Some("__pthread_register_cancel"))
        .expect("resolved rows must include exact pthread cancellation symbol");
    assert_eq!(
        pthread_row["version_node"].as_str(),
        Some("GLIBC_JOIN_TEST_1.0")
    );
}

#[test]
fn stale_missing_support_matrix_expectation_blocks_claim() {
    let root = workspace_root();
    let script = root.join("scripts/check_semantic_contract_symbol_join.sh");
    let canonical_path = root.join("tests/conformance/semantic_contract_symbol_join.v1.json");
    let mutated_path = unique_temp_path("semantic-contract-symbol-join-stale.json");
    let mut artifact = load_json(&canonical_path);

    let rows = artifact["entries"]
        .as_array_mut()
        .expect("artifact entries must be mutable array");
    let cxx_row = rows
        .iter_mut()
        .find(|row| row["inventory_id"].as_str() == Some("sem-cxx-abi-fail-stop"))
        .expect("canonical artifact must contain C++ ABI fail-stop row");
    cxx_row["expected_missing_support_matrix_symbols"] = serde_json::json!([]);

    std::fs::write(
        &mutated_path,
        serde_json::to_string_pretty(&artifact).unwrap() + "\n",
    )
    .expect("failed to write mutated semantic join artifact");

    let output = Command::new(&script)
        .current_dir(&root)
        .env("FLC_SEMANTIC_JOIN_ARTIFACT", &mutated_path)
        .output()
        .expect("failed to run semantic contract symbol-join gate with stale artifact");
    assert!(
        !output.status.success(),
        "stale missing-support expectation should fail the gate\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = parse_stdout_report(&output);
    assert_eq!(report["status"].as_str(), Some("fail"));
    let errors = report["errors"]
        .as_array()
        .expect("failure report must include errors");
    assert!(
        errors.iter().any(|error| {
            error
                .as_str()
                .unwrap_or_default()
                .contains("sem-cxx-abi-fail-stop: expected_missing_support_matrix_symbols stale")
        }),
        "failure should identify the stale C++ ABI support-matrix expectation: {errors:?}"
    );
    assert_eq!(
        report["checks"]["row_join_expectations"].as_str(),
        Some("fail")
    );
}
