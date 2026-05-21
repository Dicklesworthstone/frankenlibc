//! Integration test: closure contract v1 gate (bd-5fw.1)
//!
//! Validates that:
//! 1. `closure_contract.v1.json` exists and has required schema fields.
//! 2. Every level defines non-empty obligations with machine-checkable predicates.
//! 3. Transition requirements reference known invariant IDs.
//! 4. Gate script exists and is executable.
//! 5. Gate script passes on current checkout and emits structured logs.
//! 6. Gate script fails deterministically for an intentionally broken contract.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;
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

fn load_contract() -> serde_json::Value {
    let path = workspace_root().join("tests/conformance/closure_contract.v1.json");
    let content =
        std::fs::read_to_string(&path).expect("closure_contract.v1.json should be readable");
    serde_json::from_str(&content).expect("closure_contract.v1.json should be valid JSON")
}

fn unique_tmp_path(prefix: &str, suffix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after UNIX_EPOCH")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{}-{nanos}{suffix}", std::process::id()))
}

#[test]
fn contract_exists_and_valid() {
    let doc = load_contract();
    assert_eq!(
        doc["schema_version"].as_u64(),
        Some(1),
        "schema_version must be 1"
    );
    assert_eq!(doc["contract_id"].as_str(), Some("closure_contract.v1"));
    assert_eq!(doc["bead"].as_str(), Some("bd-5fw.1"));
    assert!(doc["description"].is_string(), "description missing");
    assert!(
        doc["contract_sources"].is_array(),
        "contract_sources missing"
    );
    assert!(doc["levels"].is_array(), "levels missing");
    assert!(
        doc["transition_requirements"].is_object(),
        "transition_requirements missing"
    );
    assert!(
        doc["structured_log_requirements"].is_object(),
        "structured_log_requirements missing"
    );
    assert!(
        doc["bead_closure_freshness"].is_object(),
        "bead_closure_freshness missing"
    );
}

#[test]
fn all_levels_have_machine_checkable_obligations() {
    let doc = load_contract();
    let levels = doc["levels"].as_array().unwrap();
    assert_eq!(levels.len(), 4, "expected exactly 4 level entries");

    let expected_levels = ["L0", "L1", "L2", "L3"];
    for expected in expected_levels {
        let level = levels
            .iter()
            .find(|entry| entry["level"].as_str() == Some(expected))
            .expect("missing expected level entry");
        assert!(
            level["obligations"]
                .as_array()
                .is_some_and(|v| !v.is_empty()),
            "{expected}: obligations must be non-empty"
        );

        for obligation in level["obligations"].as_array().unwrap() {
            let oid = obligation["invariant_id"].as_str().unwrap_or("<missing>");
            assert!(
                obligation["description"].is_string(),
                "{oid}: description missing"
            );
            assert!(
                obligation["predicate"].is_object(),
                "{oid}: predicate missing"
            );
            assert!(
                obligation["check_cmd"]
                    .as_str()
                    .is_some_and(|v| !v.is_empty()),
                "{oid}: check_cmd missing"
            );
            assert!(
                obligation["artifact_paths"]
                    .as_array()
                    .is_some_and(|v| !v.is_empty()),
                "{oid}: artifact_paths missing"
            );
            assert!(
                obligation["failure_message"].is_string(),
                "{oid}: failure_message missing"
            );
        }
    }
}

#[test]
fn transition_requirements_reference_known_invariants() {
    let doc = load_contract();
    let mut ids = HashSet::new();

    for level in doc["levels"].as_array().unwrap() {
        for obligation in level["obligations"].as_array().unwrap() {
            ids.insert(
                obligation["invariant_id"]
                    .as_str()
                    .expect("invariant_id must be string")
                    .to_string(),
            );
        }
    }

    for key in ["L0_to_L1", "L1_to_L2", "L2_to_L3"] {
        let Some(refs) = doc["transition_requirements"][key].as_array() else {
            assert!(
                doc["transition_requirements"][key].is_array(),
                "{key} missing"
            );
            return;
        };
        assert!(!refs.is_empty(), "{key} must not be empty");
        for reference in refs {
            let rid = reference.as_str().expect("transition item must be string");
            assert!(
                ids.contains(rid),
                "{key} references unknown invariant_id {rid}"
            );
        }
    }
}

#[test]
fn bead_closure_freshness_policy_is_machine_checkable() {
    let doc = load_contract();
    let policy = &doc["bead_closure_freshness"];
    assert_eq!(policy["bead"].as_str(), Some("bd-3yr14.7"));
    assert_eq!(
        policy["event_env"].as_str(),
        Some("FRANKENLIBC_CLOSURE_FRESHNESS_EVENT")
    );

    let required_event_fields: HashSet<_> = policy["required_event_fields"]
        .as_array()
        .expect("required event fields should be an array")
        .iter()
        .map(|value| value.as_str().expect("event field should be string"))
        .collect();
    for field in [
        "bead_id",
        "in_progress_at_utc",
        "closed_at_utc",
        "completion_contract_path",
    ] {
        assert!(
            required_event_fields.contains(field),
            "closure freshness policy missing event field {field}"
        );
    }

    let required_artifact_fields: HashSet<_> = policy["required_artifact_freshness_fields"]
        .as_array()
        .expect("required artifact fields should be an array")
        .iter()
        .map(|value| value.as_str().expect("artifact field should be string"))
        .collect();
    for field in ["generated_at_utc", "chain_hash"] {
        assert!(
            required_artifact_fields.contains(field),
            "closure freshness policy missing artifact field {field}"
        );
    }

    let failure_signatures: HashSet<_> = policy["failure_signatures"]
        .as_array()
        .expect("failure signatures should be an array")
        .iter()
        .map(|value| value.as_str().expect("failure signature should be string"))
        .collect();
    for signature in [
        "missing_completion_contract_generated_at_utc",
        "missing_completion_contract_chain_hash",
        "completion_contract_predates_in_progress",
        "completion_contract_postdates_closed",
    ] {
        assert!(
            failure_signatures.contains(signature),
            "closure freshness policy missing failure signature {signature}"
        );
    }
}

#[test]
fn completion_debt_evidence_binds_required_audit_items() {
    let doc = load_contract();
    let evidence = &doc["completion_debt_evidence"];
    assert_eq!(evidence["bead"].as_str(), Some("bd-5fw.1.1"));
    assert_eq!(
        evidence["test_source"].as_str(),
        Some("crates/frankenlibc-harness/tests/closure_contract_test.rs")
    );

    let unit_tests: HashSet<_> = evidence["unit_primary"]["required_test_names"]
        .as_array()
        .expect("unit test names should be an array")
        .iter()
        .map(|value| value.as_str().expect("unit test name should be string"))
        .collect();
    assert_eq!(
        unit_tests,
        HashSet::from([
            "contract_exists_and_valid",
            "all_levels_have_machine_checkable_obligations",
            "transition_requirements_reference_known_invariants",
            "bead_closure_freshness_policy_is_machine_checkable",
        ])
    );

    let e2e_tests: HashSet<_> = evidence["e2e_primary"]["required_test_names"]
        .as_array()
        .expect("e2e test names should be an array")
        .iter()
        .map(|value| value.as_str().expect("e2e test name should be string"))
        .collect();
    assert_eq!(
        e2e_tests,
        HashSet::from([
            "gate_script_passes_and_emits_required_log_fields",
            "gate_script_fails_for_intentionally_broken_contract",
            "gate_script_rejects_predated_completion_contract_artifact",
        ])
    );

    let telemetry_fields: HashSet<_> = evidence["telemetry_primary"]["required_fields"]
        .as_array()
        .expect("telemetry fields should be an array")
        .iter()
        .map(|value| value.as_str().expect("telemetry field should be string"))
        .collect();
    for field in [
        "trace_id",
        "mode",
        "gate_name",
        "level",
        "invariant_id",
        "check_cmd",
        "result",
        "exit_code",
        "duration_ms",
        "artifact_ref",
        "artifact_refs",
        "detail",
        "failure_reason",
    ] {
        assert!(
            telemetry_fields.contains(field),
            "telemetry evidence missing required field {field}"
        );
    }
}

#[test]
fn gate_script_exists_and_executable() {
    let root = workspace_root();
    let script = root.join("scripts/check_closure_contract.sh");
    assert!(script.exists(), "check_closure_contract.sh must exist");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_closure_contract.sh must be executable"
        );
    }
}

#[test]
fn gate_script_passes_and_emits_required_log_fields() {
    let root = workspace_root();
    let script = root.join("scripts/check_closure_contract.sh");
    let log_path = unique_tmp_path("closure-contract-pass", ".jsonl");
    let contract_path = unique_tmp_path("closure-contract-pass", ".json");

    // Keep this test deterministic even when unrelated closed-critique evidence
    // debt in the shared workspace temporarily breaks check_closure_gate.sh.
    let mut stable_contract = load_contract();
    let levels = stable_contract["levels"].as_array_mut().unwrap();
    let l0 = levels
        .iter_mut()
        .find(|entry| entry["level"].as_str() == Some("L0"))
        .expect("L0 level should exist");
    let obligations = l0["obligations"].as_array_mut().unwrap();
    let closure_gate = obligations
        .iter_mut()
        .find(|entry| entry["invariant_id"].as_str() == Some("l0.closure_evidence_gate"))
        .expect("l0.closure_evidence_gate should exist");
    closure_gate["predicate"] = serde_json::json!({
        "type": "path_exists",
        "path": "tests/conformance/closure_evidence_schema.json"
    });
    closure_gate["check_cmd"] =
        serde_json::Value::String("test -f tests/conformance/closure_evidence_schema.json".into());
    std::fs::write(
        &contract_path,
        serde_json::to_string_pretty(&stable_contract).expect("serialize stable contract"),
    )
    .expect("write stable contract");

    let output = Command::new("bash")
        .arg(&script)
        .current_dir(&root)
        .env("FRANKENLIBC_CLOSURE_LOG", &log_path)
        .env("FRANKENLIBC_CLOSURE_CONTRACT_PATH", &contract_path)
        .output()
        .expect("check_closure_contract.sh should execute");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "check_closure_contract.sh failed\nstatus={:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        stdout,
        stderr
    );

    assert!(
        log_path.exists(),
        "expected structured log at {}",
        log_path.display()
    );
    let body = std::fs::read_to_string(&log_path).expect("log file should be readable");
    let lines: Vec<&str> = body.lines().filter(|l| !l.trim().is_empty()).collect();
    assert!(
        !lines.is_empty(),
        "structured log should have at least one entry"
    );

    let doc = load_contract();
    let required_fields: Vec<String> = doc["structured_log_requirements"]["required_fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();

    for line in lines {
        let row: serde_json::Value = serde_json::from_str(line).expect("log row must be JSON");
        for field in &required_fields {
            assert!(
                !row[field].is_null(),
                "structured log row missing required field '{field}'"
            );
        }
    }

    let _ = std::fs::remove_file(log_path);
    let _ = std::fs::remove_file(contract_path);
}

#[test]
fn gate_script_fails_for_intentionally_broken_contract() {
    let root = workspace_root();
    let script = root.join("scripts/check_closure_contract.sh");

    let mut broken = load_contract();
    let levels = broken["levels"].as_array_mut().unwrap();
    let l0 = levels
        .iter_mut()
        .find(|entry| entry["level"].as_str() == Some("L0"))
        .expect("L0 level should exist");
    let obligations = l0["obligations"].as_array_mut().unwrap();
    let first = obligations
        .iter_mut()
        .find(|entry| entry["invariant_id"].as_str() == Some("l0.contract_sources_present"))
        .expect("expected l0.contract_sources_present obligation");
    first["predicate"]["paths"][0] =
        serde_json::Value::String("__nonexistent__/PLAN_TO_PORT_GLIBC_TO_RUST.md".to_string());
    first["failure_message"] = serde_json::Value::String(
        "Intentional test breakage: missing required contract source".to_string(),
    );

    let broken_path = unique_tmp_path("closure-contract-broken", ".json");
    let broken_log = unique_tmp_path("closure-contract-broken-log", ".jsonl");
    std::fs::write(
        &broken_path,
        serde_json::to_string_pretty(&broken).expect("serialize broken contract"),
    )
    .expect("write broken contract file");

    let output = Command::new("bash")
        .arg(&script)
        .current_dir(&root)
        .env("FRANKENLIBC_CLOSURE_CONTRACT_PATH", &broken_path)
        .env("FRANKENLIBC_CLOSURE_LOG", &broken_log)
        .env("FRANKENLIBC_CLOSURE_LEVEL", "L0")
        .output()
        .expect("check_closure_contract.sh should execute with broken contract");

    assert!(
        !output.status.success(),
        "broken contract should force gate failure"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let merged = format!("{stdout}\n{stderr}");
    assert!(
        merged.contains("l0.contract_sources_present"),
        "failure output must name the violated invariant"
    );
    assert!(
        merged.contains("FAILED"),
        "failure output should include FAILED summary"
    );

    let _ = std::fs::remove_file(broken_path);
    let _ = std::fs::remove_file(broken_log);
}

#[test]
fn gate_script_rejects_stale_completion_debt_evidence() {
    let root = workspace_root();
    let script = root.join("scripts/check_closure_contract.sh");

    let mut broken = load_contract();
    let telemetry = broken["completion_debt_evidence"]["telemetry_primary"]["required_fields"]
        .as_array_mut()
        .expect("telemetry fields should exist");
    telemetry.retain(|field| field.as_str() != Some("failure_reason"));

    let broken_path = unique_tmp_path("closure-contract-debt-evidence-broken", ".json");
    let broken_log = unique_tmp_path("closure-contract-debt-evidence-broken-log", ".jsonl");
    std::fs::write(
        &broken_path,
        serde_json::to_string_pretty(&broken).expect("serialize broken contract"),
    )
    .expect("write broken contract file");

    let output = Command::new("bash")
        .arg(&script)
        .current_dir(&root)
        .env("FRANKENLIBC_CLOSURE_CONTRACT_PATH", &broken_path)
        .env("FRANKENLIBC_CLOSURE_LOG", &broken_log)
        .env("FRANKENLIBC_CLOSURE_LEVEL", "L0")
        .output()
        .expect("check_closure_contract.sh should execute with stale debt evidence");

    assert!(
        !output.status.success(),
        "stale completion-debt telemetry evidence should force gate failure"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let merged = format!("{stdout}\n{stderr}");
    assert!(
        merged.contains("telemetry_primary.required_fields missing 'failure_reason'"),
        "failure output must name the stale telemetry binding: {merged}"
    );
    assert!(
        merged.contains("FAILED"),
        "failure output should include FAILED summary"
    );
}

#[test]
fn gate_script_rejects_predated_completion_contract_artifact() {
    let root = workspace_root();
    let script = root.join("scripts/check_closure_contract.sh");

    let mut stable_contract = load_contract();
    let levels = stable_contract["levels"].as_array_mut().unwrap();
    let l0 = levels
        .iter_mut()
        .find(|entry| entry["level"].as_str() == Some("L0"))
        .expect("L0 level should exist");
    let obligations = l0["obligations"].as_array_mut().unwrap();
    let closure_gate = obligations
        .iter_mut()
        .find(|entry| entry["invariant_id"].as_str() == Some("l0.closure_evidence_gate"))
        .expect("l0.closure_evidence_gate should exist");
    closure_gate["predicate"] = serde_json::json!({
        "type": "path_exists",
        "path": "tests/conformance/closure_evidence_schema.json"
    });
    closure_gate["check_cmd"] =
        serde_json::Value::String("test -f tests/conformance/closure_evidence_schema.json".into());

    let contract_path = unique_tmp_path("closure-contract-freshness", ".json");
    std::fs::write(
        &contract_path,
        serde_json::to_string_pretty(&stable_contract).expect("serialize stable contract"),
    )
    .expect("write stable contract");

    let artifact_path = unique_tmp_path("closure-contract-predated-artifact", ".json");
    let artifact = serde_json::json!({
        "schema_version": "test_completion_contract.v1",
        "generated_at_utc": "2026-05-21T00:05:00Z",
        "chain_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    });
    std::fs::write(
        &artifact_path,
        serde_json::to_string_pretty(&artifact).expect("serialize predated artifact"),
    )
    .expect("write predated artifact");

    let event_path = unique_tmp_path("closure-contract-freshness-event", ".json");
    let event = serde_json::json!({
        "bead_id": "bd-test",
        "in_progress_at_utc": "2026-05-21T00:10:00Z",
        "closed_at_utc": "2026-05-21T00:20:00Z",
        "completion_contract_path": artifact_path.to_string_lossy().to_string()
    });
    std::fs::write(
        &event_path,
        serde_json::to_string_pretty(&event).expect("serialize freshness event"),
    )
    .expect("write freshness event");

    let log_path = unique_tmp_path("closure-contract-freshness-log", ".jsonl");
    let output = Command::new("bash")
        .arg(&script)
        .current_dir(&root)
        .env("FRANKENLIBC_CLOSURE_CONTRACT_PATH", &contract_path)
        .env("FRANKENLIBC_CLOSURE_FRESHNESS_EVENT", &event_path)
        .env("FRANKENLIBC_CLOSURE_LOG", &log_path)
        .env("FRANKENLIBC_CLOSURE_LEVEL", "L0")
        .output()
        .expect("check_closure_contract.sh should execute with freshness event");

    assert!(
        !output.status.success(),
        "predated completion-contract artifact should force gate failure"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let merged = format!("{stdout}\n{stderr}");
    assert!(
        merged.contains("bead_closure_freshness.bd-test"),
        "failure output must name the stale closure freshness record: {merged}"
    );
    assert!(
        merged.contains("completion_contract_predates_in_progress"),
        "failure output must include the predated-artifact signature: {merged}"
    );
}
