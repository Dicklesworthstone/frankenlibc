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

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .ok_or_else(|| format!("crate directory has no parent: {manifest}"))?
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("workspace root has no parent: {manifest}"))
}

fn load_ledger() -> TestResult<Value> {
    let path = workspace_root()?.join("tests/conformance/optimization_proof_ledger.v1.json");
    let content = std::fs::read_to_string(&path).map_err(|err| format!("read {path:?}: {err}"))?;
    serde_json::from_str(&content).map_err(|err| format!("parse {path:?}: {err}"))
}

fn json_array<'a>(value: &'a Value, field: &str) -> TestResult<&'a Vec<Value>> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("missing or non-array `{field}`"))
}

fn json_string<'a>(value: &'a Value, field: &str) -> TestResult<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing or non-string `{field}`"))
}

fn json_f64(value: &Value, field: &str) -> TestResult<f64> {
    value
        .get(field)
        .and_then(Value::as_f64)
        .ok_or_else(|| format!("missing or non-number `{field}`"))
}

fn json_u64(value: &Value, field: &str) -> TestResult<u64> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("missing or non-u64 `{field}`"))
}

fn nested_f64(value: &Value, parent: &str, field: &str) -> TestResult<f64> {
    value
        .get(parent)
        .and_then(|parent_value| parent_value.get(field))
        .and_then(Value::as_f64)
        .ok_or_else(|| format!("missing or non-number `{parent}.{field}`"))
}

fn first_value<'a>(values: &'a [Value], context: &str) -> TestResult<&'a Value> {
    values
        .first()
        .ok_or_else(|| format!("{context} must not be empty"))
}

fn verified_candidate(candidates: &[Value]) -> TestResult<&Value> {
    candidates
        .iter()
        .find(|c| c.get("proof_status").and_then(Value::as_str) == Some("verified"))
        .ok_or_else(|| "must have a verified candidate".to_string())
}

fn behavior_check_mut<'a>(
    candidate: &'a mut Value,
    index: usize,
    field: &str,
) -> TestResult<&'a mut Value> {
    candidate
        .get_mut("behavior_checks")
        .and_then(Value::as_array_mut)
        .and_then(|checks| checks.get_mut(index))
        .and_then(|check| check.get_mut(field))
        .ok_or_else(|| format!("missing behavior_checks[{index}].{field}"))
}

fn result_errors(result: Result<(), Vec<String>>, message: &str) -> TestResult<String> {
    result
        .err()
        .map(|errors| errors.join(" | "))
        .ok_or_else(|| message.to_string())
}

#[derive(Debug)]
struct CandidateRecord {
    trace_id: String,
    candidate_id: String,
    proof_status: String,
    perf_delta: f64,
    acceptance_reason: String,
}

fn parse_candidate_record(candidate: &Value) -> Result<CandidateRecord, String> {
    let trace_id = json_string(candidate, "trace_id")?.to_string();
    let candidate_id = json_string(candidate, "candidate_id")?.to_string();
    let proof_status = json_string(candidate, "proof_status")?.to_string();
    let perf_delta = nested_f64(candidate, "measurement", "perf_delta_pct")?;
    let acceptance_reason = json_string(candidate, "acceptance_reason")?.to_string();

    Ok(CandidateRecord {
        trace_id,
        candidate_id,
        proof_status,
        perf_delta,
        acceptance_reason,
    })
}

fn validate_candidate(candidate: &Value, template: &Value) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();

    let required_fields: HashSet<&str> = match json_array(template, "required_fields") {
        Ok(fields) => fields.iter().filter_map(Value::as_str).collect(),
        Err(err) => return Err(vec![err]),
    };
    let statuses: HashSet<&str> = match json_array(template, "proof_statuses") {
        Ok(fields) => fields.iter().filter_map(Value::as_str).collect(),
        Err(err) => return Err(vec![err]),
    };
    let check_statuses: HashSet<&str> = match json_array(template, "behavior_check_statuses") {
        Ok(fields) => fields.iter().filter_map(Value::as_str).collect(),
        Err(err) => return Err(vec![err]),
    };
    let min_coverage: HashSet<&str> = match json_array(template, "minimum_input_class_coverage") {
        Ok(fields) => fields.iter().filter_map(Value::as_str).collect(),
        Err(err) => return Err(vec![err]),
    };
    let min_improvement = match json_f64(template, "minimum_improvement_pct_for_verified") {
        Ok(value) => value,
        Err(err) => return Err(vec![err]),
    };

    let cid = candidate
        .get("candidate_id")
        .and_then(Value::as_str)
        .unwrap_or("?");
    for field in &required_fields {
        if candidate[*field].is_null() {
            errors.push(format!("{cid}: missing required field {field}"));
        }
    }

    let proof_status = candidate
        .get("proof_status")
        .and_then(Value::as_str)
        .unwrap_or("");
    if !statuses.contains(proof_status) {
        errors.push(format!("{cid}: invalid proof_status {proof_status}"));
    }

    let measurement = candidate.get("measurement").unwrap_or(&Value::Null);
    for field in [
        "metric",
        "mode",
        "before",
        "after",
        "perf_delta_pct",
        "evidence_refs",
    ] {
        if measurement[field].is_null() {
            errors.push(format!("{cid}: measurement missing {field}"));
        }
    }
    let evidence_refs = measurement
        .get("evidence_refs")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    if evidence_refs < 2 {
        errors.push(format!(
            "{cid}: measurement.evidence_refs must include before+after artifacts"
        ));
    }

    if let Some(checks) = candidate.get("behavior_checks").and_then(Value::as_array) {
        if checks.is_empty() {
            errors.push(format!("{cid}: behavior_checks must be non-empty"));
        }

        let mut coverage = HashSet::new();
        let mut failed_checks = 0;
        for check in checks {
            let status = check.get("status").and_then(Value::as_str).unwrap_or("");
            if !check_statuses.contains(status) {
                errors.push(format!("{cid}: invalid behavior check status {status}"));
            }
            if status == "fail" {
                failed_checks += 1;
            }
            if let Some(classes) = check.get("input_classes").and_then(Value::as_array) {
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
                    errors.push(format!(
                        "{cid}: missing required input class coverage {cls}"
                    ));
                }
            }
            if failed_checks > 0 {
                errors.push(format!("{cid}: verified candidate includes failed checks"));
            }
            let delta = measurement
                .get("perf_delta_pct")
                .and_then(Value::as_f64)
                .unwrap_or(f64::INFINITY);
            if delta > -min_improvement {
                errors.push(format!(
                    "{cid}: verified candidate perf_delta_pct={delta} must be <= -{min_improvement}"
                ));
            }
        }
    } else {
        errors.push(format!("{cid}: behavior_checks must be non-empty"));
    }

    if proof_status == "rejected" {
        let reasons = candidate
            .get("rejection_reasons")
            .and_then(Value::as_array)
            .map_or(0, Vec::len);
        if reasons == 0 {
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
fn ledger_exists_and_valid() -> TestResult {
    let ledger = load_ledger()?;
    assert!(
        ledger["schema_version"].is_number(),
        "Missing schema_version"
    );
    assert!(
        ledger["proof_template"].is_object(),
        "Missing proof_template"
    );
    assert!(
        ledger["logging_contract"].is_object(),
        "Missing logging_contract"
    );
    assert!(ledger["candidates"].is_array(), "Missing candidates");
    assert!(ledger["summary"].is_object(), "Missing summary");
    Ok(())
}

#[test]
fn template_defines_required_contract() -> TestResult {
    let ledger = load_ledger()?;
    let template = &ledger["proof_template"];

    let required_fields: HashSet<&str> = json_array(template, "required_fields")?
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

    let checklist_ids: HashSet<&str> = json_array(template, "checklist")?
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

    let criteria_ids: HashSet<&str> = json_array(template, "rejection_criteria")?
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
    Ok(())
}

#[test]
fn parser_extracts_candidate_fields() -> TestResult {
    let ledger = load_ledger()?;
    let candidates = json_array(&ledger, "candidates")?;
    assert!(!candidates.is_empty(), "candidates must not be empty");

    let record = parse_candidate_record(first_value(candidates, "candidates")?)?;
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
    Ok(())
}

#[test]
fn parser_rejects_missing_trace_id() -> TestResult {
    let mut candidate = serde_json::json!({
        "candidate_id": "cand-missing-trace",
        "proof_status": "pending",
        "measurement": { "perf_delta_pct": -1.0 },
        "acceptance_reason": "pending"
    });
    candidate["trace_id"] = serde_json::Value::Null;
    let parsed = parse_candidate_record(&candidate);
    assert!(parsed.is_err(), "parser should reject missing trace_id");
    Ok(())
}

#[test]
fn validator_accepts_verified_sample() -> TestResult {
    let ledger = load_ledger()?;
    let template = &ledger["proof_template"];
    let candidates = json_array(&ledger, "candidates")?;
    let verified = verified_candidate(candidates)?;
    let result = validate_candidate(verified, template);
    assert!(
        result.is_ok(),
        "verified sample should validate: {result:?}"
    );
    Ok(())
}

#[test]
fn validator_rejects_failed_check_in_verified_candidate() -> TestResult {
    let ledger = load_ledger()?;
    let template = &ledger["proof_template"];
    let candidates = json_array(&ledger, "candidates")?;
    let mut verified = verified_candidate(candidates)?.clone();
    *behavior_check_mut(&mut verified, 0, "status")? = serde_json::json!("fail");

    let result = validate_candidate(&verified, template);
    assert!(result.is_err(), "validator should reject failed check");
    let errors = result_errors(result, "validator should reject failed check")?;
    assert!(
        errors.contains("failed checks"),
        "expected failed checks error, got: {errors}"
    );
    Ok(())
}

#[test]
fn validator_rejects_missing_coverage_in_verified_candidate() -> TestResult {
    let ledger = load_ledger()?;
    let template = &ledger["proof_template"];
    let candidates = json_array(&ledger, "candidates")?;
    let mut verified = verified_candidate(candidates)?.clone();
    *behavior_check_mut(&mut verified, 0, "input_classes")? = serde_json::json!(["in_bounds"]);
    *behavior_check_mut(&mut verified, 1, "input_classes")? = serde_json::json!(["boundary"]);

    let result = validate_candidate(&verified, template);
    assert!(result.is_err(), "validator should reject missing coverage");
    let errors = result_errors(result, "validator should reject missing coverage")?;
    assert!(
        errors.contains("missing required input class coverage"),
        "expected coverage error, got: {errors}"
    );
    Ok(())
}

#[test]
fn summary_consistent() -> TestResult {
    let ledger = load_ledger()?;
    let candidates = json_array(&ledger, "candidates")?;
    let summary = &ledger["summary"];

    assert_eq!(
        json_u64(summary, "total_candidates")? as usize,
        candidates.len(),
        "total_candidates mismatch"
    );

    for status in ["verified", "rejected", "pending", "waived"] {
        let actual = candidates
            .iter()
            .filter(|c| c["proof_status"].as_str() == Some(status))
            .count();
        assert_eq!(
            json_u64(summary, status)? as usize,
            actual,
            "{status} count mismatch"
        );
    }

    let required_log_fields = json_array(&ledger["logging_contract"], "required_fields")?.len();
    assert_eq!(
        json_u64(summary, "required_log_fields")? as usize,
        required_log_fields,
        "required_log_fields mismatch"
    );
    Ok(())
}

#[test]
fn gate_script_exists_and_executable() -> TestResult {
    let root = workspace_root()?;
    let script = root.join("scripts/check_optimization_proof_ledger.sh");
    assert!(
        script.exists(),
        "scripts/check_optimization_proof_ledger.sh must exist"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script)
            .map_err(|err| format!("metadata {script:?}: {err}"))?
            .permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_optimization_proof_ledger.sh must be executable"
        );
    }
    Ok(())
}

#[test]
fn e2e_gate_script_passes() -> TestResult {
    let root = workspace_root()?;
    let script = root.join("scripts/check_optimization_proof_ledger.sh");
    let status = std::process::Command::new("bash")
        .arg(script)
        .current_dir(&root)
        .status()
        .map_err(|err| format!("run check_optimization_proof_ledger.sh: {err}"))?;
    assert!(
        status.success(),
        "check_optimization_proof_ledger.sh should pass"
    );
    Ok(())
}
