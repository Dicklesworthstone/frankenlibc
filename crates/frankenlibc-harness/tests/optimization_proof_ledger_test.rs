//! Integration test: Optimization proof ledger contract (bd-30o.2)
//!
//! Validates that:
//! 1. The optimization proof ledger JSON exists and is valid.
//! 2. Template/checklist/rejection criteria are complete.
//! 3. Candidate parser extracts required fields.
//! 4. Candidate validator enforces behavior coverage + perf constraints.
//! 5. E2E gate script passes on sample records.
//! 6. Summary statistics are consistent.
//!
//! Run: cargo test -p frankenlibc-harness --test optimization_proof_ledger_test

use std::collections::HashSet;
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

fn load_ledger() -> serde_json::Value {
    let path = workspace_root().join("tests/conformance/optimization_proof_ledger.v1.json");
    let content =
        std::fs::read_to_string(&path).expect("optimization_proof_ledger.v1.json should exist");
    serde_json::from_str(&content).expect("optimization_proof_ledger.v1.json should be valid JSON")
}

#[derive(Debug)]
struct CandidateRecord {
    trace_id: String,
    candidate_id: String,
    proof_status: String,
    perf_delta: f64,
    acceptance_reason: String,
}

fn parse_candidate_record(candidate: &serde_json::Value) -> Result<CandidateRecord, String> {
    let trace_id = candidate["trace_id"]
        .as_str()
        .ok_or("missing trace_id")?
        .to_string();
    let candidate_id = candidate["candidate_id"]
        .as_str()
        .ok_or("missing candidate_id")?
        .to_string();
    let proof_status = candidate["proof_status"]
        .as_str()
        .ok_or("missing proof_status")?
        .to_string();
    let perf_delta = candidate["measurement"]["perf_delta_pct"]
        .as_f64()
        .ok_or("missing measurement.perf_delta_pct")?;
    let acceptance_reason = candidate["acceptance_reason"]
        .as_str()
        .ok_or("missing acceptance_reason")?
        .to_string();

    Ok(CandidateRecord {
        trace_id,
        candidate_id,
        proof_status,
        perf_delta,
        acceptance_reason,
    })
}

fn validate_candidate(
    candidate: &serde_json::Value,
    template: &serde_json::Value,
) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();

    let required_fields: HashSet<&str> = template["required_fields"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    let statuses: HashSet<&str> = template["proof_statuses"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    let check_statuses: HashSet<&str> = template["behavior_check_statuses"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    let min_coverage: HashSet<&str> = template["minimum_input_class_coverage"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    let min_improvement = template["minimum_improvement_pct_for_verified"]
        .as_f64()
        .unwrap();

    let cid = candidate["candidate_id"].as_str().unwrap_or("?");
    for field in &required_fields {
        if candidate[*field].is_null() {
            errors.push(format!("{cid}: missing required field {field}"));
        }
    }

    let proof_status = candidate["proof_status"].as_str().unwrap_or("");
    if !statuses.contains(proof_status) {
        errors.push(format!("{cid}: invalid proof_status {proof_status}"));
    }

    let measurement = &candidate["measurement"];
    for field in ["metric", "mode", "before", "after", "perf_delta_pct", "evidence_refs"] {
        if measurement[field].is_null() {
            errors.push(format!("{cid}: measurement missing {field}"));
        }
    }
    let evidence_refs = measurement["evidence_refs"].as_array().unwrap_or(&Vec::new()).len();
    if evidence_refs < 2 {
        errors.push(format!(
            "{cid}: measurement.evidence_refs must include before+after artifacts"
        ));
    }

    let empty_checks: Vec<serde_json::Value> = Vec::new();
    let checks = candidate["behavior_checks"]
        .as_array()
        .unwrap_or(&empty_checks);
    if checks.is_empty() {
        errors.push(format!("{cid}: behavior_checks must be non-empty"));
    }

    let mut coverage = HashSet::new();
    let mut failed_checks = 0;
    for check in checks {
        let status = check["status"].as_str().unwrap_or("");
        if !check_statuses.contains(status) {
            errors.push(format!("{cid}: invalid behavior check status {status}"));
        }
        if status == "fail" {
            failed_checks += 1;
        }
        if let Some(classes) = check["input_classes"].as_array() {
            for cls in classes {
                if let Some(cls_str) = cls.as_str() {
                    coverage.insert(cls_str.to_string());
                }
            }
        }
    }

    if proof_status == "verified" {
        for cls in &min_coverage {
            if !coverage.contains(*cls) {
                errors.push(format!("{cid}: missing required input class coverage {cls}"));
            }
        }
        if failed_checks > 0 {
            errors.push(format!("{cid}: verified candidate includes failed checks"));
        }
        let delta = measurement["perf_delta_pct"].as_f64().unwrap_or(f64::INFINITY);
        if delta > -min_improvement {
            errors.push(format!(
                "{cid}: verified candidate perf_delta_pct={delta} must be <= -{min_improvement}"
            ));
        }
    }

    if proof_status == "rejected" {
        let empty_reasons: Vec<serde_json::Value> = Vec::new();
        let reasons = candidate["rejection_reasons"]
            .as_array()
            .unwrap_or(&empty_reasons);
        if reasons.is_empty() {
            errors.push(format!(
                "{cid}: rejected candidate must provide rejection_reasons"
            ));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

#[test]
fn ledger_exists_and_valid() {
    let ledger = load_ledger();
    assert!(ledger["schema_version"].is_number(), "Missing schema_version");
    assert!(ledger["proof_template"].is_object(), "Missing proof_template");
    assert!(ledger["logging_contract"].is_object(), "Missing logging_contract");
    assert!(ledger["candidates"].is_array(), "Missing candidates");
    assert!(ledger["summary"].is_object(), "Missing summary");
}

#[test]
fn template_defines_required_contract() {
    let ledger = load_ledger();
    let template = &ledger["proof_template"];

    let required_fields: HashSet<&str> = template["required_fields"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    for field in [
        "trace_id",
        "candidate_id",
        "proof_status",
        "measurement",
        "behavior_checks",
        "acceptance_reason",
    ] {
        assert!(
            required_fields.contains(field),
            "required_fields missing {field}"
        );
    }

    let checklist_ids: HashSet<&str> = template["checklist"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v["id"].as_str())
        .collect();
    for id in [
        "equivalence_invariants",
        "input_class_coverage",
        "before_after_measurement_binding",
        "strict_hardened_guardrail",
    ] {
        assert!(checklist_ids.contains(id), "checklist missing {id}");
    }

    let criteria_ids: HashSet<&str> = template["rejection_criteria"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v["id"].as_str())
        .collect();
    for id in [
        "missing_required_fields",
        "missing_behavior_coverage",
        "behavior_check_failure",
        "ambiguous_perf_delta",
        "missing_evidence_links",
    ] {
        assert!(criteria_ids.contains(id), "rejection_criteria missing {id}");
    }
}

#[test]
fn parser_extracts_candidate_fields() {
    let ledger = load_ledger();
    let candidates = ledger["candidates"].as_array().unwrap();
    assert!(!candidates.is_empty(), "candidates must not be empty");

    let record = parse_candidate_record(&candidates[0]).expect("sample candidate should parse");
    assert!(
        record.trace_id.contains("::"),
        "trace_id should include scoped separator"
    );
    assert!(
        !record.candidate_id.is_empty(),
        "candidate_id should be non-empty"
    );
    assert!(
        ["pending", "verified", "rejected", "waived"].contains(&record.proof_status.as_str()),
        "proof_status should be from known set"
    );
    assert!(record.perf_delta.is_finite(), "perf_delta should be finite");
    assert!(
        !record.acceptance_reason.is_empty(),
        "acceptance_reason should be non-empty"
    );
}

#[test]
fn parser_rejects_missing_trace_id() {
    let mut candidate = serde_json::json!({
        "candidate_id": "cand-missing-trace",
        "proof_status": "pending",
        "measurement": { "perf_delta_pct": -1.0 },
        "acceptance_reason": "pending"
    });
    candidate["trace_id"] = serde_json::Value::Null;
    let parsed = parse_candidate_record(&candidate);
    assert!(parsed.is_err(), "parser should reject missing trace_id");
}

#[test]
fn validator_accepts_verified_sample() {
    let ledger = load_ledger();
    let template = &ledger["proof_template"];
    let candidates = ledger["candidates"].as_array().unwrap();
    let verified = candidates
        .iter()
        .find(|c| c["proof_status"].as_str() == Some("verified"))
        .expect("must have a verified candidate");
    let result = validate_candidate(verified, template);
    assert!(result.is_ok(), "verified sample should validate: {result:?}");
}

#[test]
fn validator_rejects_failed_check_in_verified_candidate() {
    let ledger = load_ledger();
    let template = &ledger["proof_template"];
    let candidates = ledger["candidates"].as_array().unwrap();
    let mut verified = candidates
        .iter()
        .find(|c| c["proof_status"].as_str() == Some("verified"))
        .expect("must have a verified candidate")
        .clone();
    verified["behavior_checks"][0]["status"] = serde_json::json!("fail");

    let result = validate_candidate(&verified, template);
    assert!(result.is_err(), "validator should reject failed check");
    let errors = result.err().unwrap().join(" | ");
    assert!(
        errors.contains("failed checks"),
        "expected failed checks error, got: {errors}"
    );
}

#[test]
fn validator_rejects_missing_coverage_in_verified_candidate() {
    let ledger = load_ledger();
    let template = &ledger["proof_template"];
    let candidates = ledger["candidates"].as_array().unwrap();
    let mut verified = candidates
        .iter()
        .find(|c| c["proof_status"].as_str() == Some("verified"))
        .expect("must have a verified candidate")
        .clone();
    verified["behavior_checks"][0]["input_classes"] = serde_json::json!(["in_bounds"]);
    verified["behavior_checks"][1]["input_classes"] = serde_json::json!(["boundary"]);

    let result = validate_candidate(&verified, template);
    assert!(result.is_err(), "validator should reject missing coverage");
    let errors = result.err().unwrap().join(" | ");
    assert!(
        errors.contains("missing required input class coverage"),
        "expected coverage error, got: {errors}"
    );
}

#[test]
fn summary_consistent() {
    let ledger = load_ledger();
    let candidates = ledger["candidates"].as_array().unwrap();
    let summary = &ledger["summary"];

    assert_eq!(
        summary["total_candidates"].as_u64().unwrap() as usize,
        candidates.len(),
        "total_candidates mismatch"
    );

    for status in ["verified", "rejected", "pending", "waived"] {
        let actual = candidates
            .iter()
            .filter(|c| c["proof_status"].as_str() == Some(status))
            .count();
        assert_eq!(
            summary[status].as_u64().unwrap() as usize,
            actual,
            "{status} count mismatch"
        );
    }

    let required_log_fields = ledger["logging_contract"]["required_fields"]
        .as_array()
        .unwrap()
        .len();
    assert_eq!(
        summary["required_log_fields"].as_u64().unwrap() as usize,
        required_log_fields,
        "required_log_fields mismatch"
    );
}

#[test]
fn gate_script_exists_and_executable() {
    let root = workspace_root();
    let script = root.join("scripts/check_optimization_proof_ledger.sh");
    assert!(
        script.exists(),
        "scripts/check_optimization_proof_ledger.sh must exist"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_optimization_proof_ledger.sh must be executable"
        );
    }
}

#[test]
fn e2e_gate_script_passes() {
    let root = workspace_root();
    let script = root.join("scripts/check_optimization_proof_ledger.sh");
    let status = std::process::Command::new("bash")
        .arg(script)
        .current_dir(&root)
        .status()
        .expect("failed to run check_optimization_proof_ledger.sh");
    assert!(
        status.success(),
        "check_optimization_proof_ledger.sh should pass"
    );
}
