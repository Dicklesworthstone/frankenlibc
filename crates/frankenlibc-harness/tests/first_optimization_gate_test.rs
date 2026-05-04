//! Integration test: first optimization evidence gate (bd-bp8fl.8.4).

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

type TestResult<T = ()> = Result<T, String>;

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "symbol",
    "api_family",
    "benchmark_id",
    "before_value",
    "after_value",
    "threshold",
    "parity_ref",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
];

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

fn load_json(path: &Path) -> TestResult<serde_json::Value> {
    let content =
        std::fs::read_to_string(path).map_err(|err| format!("{}: {err}", path.display()))?;
    serde_json::from_str(&content).map_err(|err| format!("{}: {err}", path.display()))
}

fn require(condition: bool, message: impl Into<String>) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

#[test]
fn committed_gate_selects_verified_before_after_candidate() -> TestResult {
    let root = workspace_root()?;
    let gate = load_json(&root.join("tests/conformance/first_optimization_gate.v1.json"))?;
    let ledger = load_json(&root.join("tests/conformance/optimization_proof_ledger.v1.json"))?;

    require(
        gate["schema_version"].as_str() == Some("v1"),
        "schema_version must be v1",
    )?;
    require(
        gate["bead"].as_str() == Some("bd-bp8fl.8.4"),
        "bead must be bd-bp8fl.8.4",
    )?;

    let selected = &gate["selected_optimization"];
    let candidate_id = selected["candidate_id"]
        .as_str()
        .ok_or_else(|| "selected candidate_id missing".to_string())?;
    let candidates = ledger["candidates"]
        .as_array()
        .ok_or_else(|| "ledger candidates must be an array".to_string())?;
    let candidate = candidates
        .iter()
        .find(|row| row["candidate_id"].as_str() == Some(candidate_id))
        .ok_or_else(|| format!("candidate {candidate_id} missing from ledger"))?;

    require(
        candidate["proof_status"].as_str() == Some("verified"),
        "candidate must be verified",
    )?;
    require(
        candidate["symbol"] == selected["symbol"],
        "candidate symbol must match selected symbol",
    )?;

    let before = selected["measurement"]["before_value"]
        .as_f64()
        .ok_or_else(|| "selected before_value must be numeric".to_string())?;
    let after = selected["measurement"]["after_value"]
        .as_f64()
        .ok_or_else(|| "selected after_value must be numeric".to_string())?;
    let threshold = selected["threshold"]["p50_ns"]
        .as_f64()
        .ok_or_else(|| "threshold p50_ns must be numeric".to_string())?;
    require(after < before, "after value must improve before value")?;
    require(after <= threshold, "after value must be within threshold")?;
    require(
        candidate["measurement"]["before"].as_f64() == Some(before),
        "candidate before value mismatch",
    )?;
    require(
        candidate["measurement"]["after"].as_f64() == Some(after),
        "candidate after value mismatch",
    )?;
    Ok(())
}

#[test]
fn behavior_coverage_budget_and_deferred_hot_paths_are_explicit() -> TestResult {
    let root = workspace_root()?;
    let gate = load_json(&root.join("tests/conformance/first_optimization_gate.v1.json"))?;
    let ledger = load_json(&root.join("tests/conformance/optimization_proof_ledger.v1.json"))?;
    let perf_budget = load_json(&root.join("tests/conformance/perf_budget_policy.json"))?;

    let selected = &gate["selected_optimization"];
    let candidate_id = selected["candidate_id"]
        .as_str()
        .ok_or_else(|| "selected candidate_id missing".to_string())?;
    let candidate = ledger["candidates"]
        .as_array()
        .and_then(|rows| {
            rows.iter()
                .find(|row| row["candidate_id"].as_str() == Some(candidate_id))
        })
        .ok_or_else(|| format!("candidate {candidate_id} missing from ledger"))?;

    let mut coverage = HashSet::new();
    for check in candidate["behavior_checks"]
        .as_array()
        .ok_or_else(|| "behavior_checks must be an array".to_string())?
    {
        require(
            check["status"].as_str() == Some("pass"),
            "candidate behavior check must pass",
        )?;
        for input_class in check["input_classes"]
            .as_array()
            .ok_or_else(|| "input_classes must be an array".to_string())?
        {
            if let Some(value) = input_class.as_str() {
                coverage.insert(value.to_owned());
            }
        }
    }
    for required in ["null_ptr", "in_bounds", "boundary", "oversize"] {
        require(
            coverage.contains(required),
            format!("missing behavior coverage for {required}"),
        )?;
    }

    require(
        perf_budget["workload_budget_extension"]["parity_first"].as_bool() == Some(true),
        "perf budget policy must be parity first",
    )?;
    require(
        perf_budget["workload_budget_extension"]["baseline_first"].as_bool() == Some(true),
        "perf budget policy must be baseline first",
    )?;
    require(
        gate["deferred_hot_paths"]
            .as_array()
            .is_some_and(|rows| rows.len() >= 3),
        "deferred hot paths must stay visible",
    )?;
    Ok(())
}

#[test]
fn gate_script_emits_report_and_structured_log() -> TestResult {
    let root = workspace_root()?;
    let script = root.join("scripts/check_first_optimization_gate.sh");
    require(script.exists(), format!("missing {}", script.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script)
            .map_err(|err| format!("{}: {err}", script.display()))?
            .permissions();
        require(
            perms.mode() & 0o111 != 0,
            "check_first_optimization_gate.sh must be executable",
        )?;
    }

    let report = root.join("target/conformance/first_optimization_gate.report.json");
    let log = root.join("target/conformance/first_optimization_gate.log.jsonl");
    let output = Command::new(&script)
        .current_dir(&root)
        .output()
        .map_err(|err| format!("failed to run first optimization gate: {err}"))?;
    require(
        output.status.success(),
        format!(
            "first optimization gate failed:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )?;
    require(report.exists(), format!("missing {}", report.display()))?;
    require(log.exists(), format!("missing {}", log.display()))?;

    let report_json = load_json(&report)?;
    require(
        report_json["status"].as_str() == Some("pass"),
        "gate report status must pass",
    )?;

    let log_content =
        std::fs::read_to_string(&log).map_err(|err| format!("{}: {err}", log.display()))?;
    let row: serde_json::Value = serde_json::from_str(log_content.trim())
        .map_err(|err| format!("log row parse error: {err}"))?;
    for field in REQUIRED_LOG_FIELDS {
        require(
            row.get(*field).is_some(),
            format!("log row missing field {field}"),
        )?;
    }
    require(
        row["bead_id"].as_str() == Some("bd-bp8fl.8.4"),
        "log row bead_id mismatch",
    )?;
    require(
        row["failure_signature"].as_str() == Some("none"),
        "log row failure_signature should be none",
    )?;
    Ok(())
}
