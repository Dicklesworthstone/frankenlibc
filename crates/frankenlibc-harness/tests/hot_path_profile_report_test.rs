//! Integration test: hot-path profile report gate (bd-bp8fl.8.3).

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

type TestResult<T = ()> = Result<T, String>;

const REQUIRED_PROFILE_FIELDS: &[&str] = &[
    "profile_id",
    "workload_or_microbenchmark",
    "api_family",
    "symbol",
    "runtime_mode",
    "replacement_level",
    "profile_tool",
    "sample_count",
    "hotness_score",
    "baseline_artifact",
    "parity_proof_refs",
    "host_baseline",
    "coverage_state",
    "artifact_refs",
    "failure_signature",
];

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "profile_id",
    "api_family",
    "symbol",
    "runtime_mode",
    "hotness_score",
    "baseline_ref",
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

fn json_array<'a>(
    value: &'a serde_json::Value,
    field: &str,
) -> TestResult<&'a Vec<serde_json::Value>> {
    value[field]
        .as_array()
        .ok_or_else(|| format!("{field} must be a JSON array"))
}

fn string_field<'a>(value: &'a serde_json::Value, field: &str) -> TestResult<&'a str> {
    value[field]
        .as_str()
        .ok_or_else(|| format!("{field} must be a JSON string"))
}

fn require(condition: bool, message: impl Into<String>) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

#[test]
fn committed_profile_artifact_has_required_scope_and_contract() -> TestResult {
    let root = workspace_root()?;
    let artifact = load_json(&root.join("tests/conformance/hot_path_profile_report.v1.json"))?;

    require(
        artifact["schema_version"].as_str() == Some("v1"),
        "schema_version must be v1",
    )?;
    require(
        artifact["bead"].as_str() == Some("bd-bp8fl.8.3"),
        "bead must be bd-bp8fl.8.3",
    )?;
    require(
        artifact["artifact_hash"].as_str().is_some(),
        "artifact_hash must be present",
    )?;

    let records = json_array(&artifact, "profile_records")?;
    require(!records.is_empty(), "profile_records must not be empty")?;
    require(
        artifact["summary"]["profile_record_count"].as_u64() == Some(records.len() as u64),
        "profile_record_count must match records",
    )?;
    require(
        artifact["summary"]["measured_profile_record_count"]
            .as_u64()
            .is_some_and(|count| count > 0),
        "measured profile count must be positive",
    )?;
    require(
        artifact["summary"]["missing_profile_record_count"]
            .as_u64()
            .is_some_and(|count| count > 0),
        "missing profile count must be positive",
    )?;
    require(
        artifact["summary"]["host_comparison_available_count"]
            .as_u64()
            .is_some_and(|count| count > 0),
        "raw host comparisons must be present",
    )?;
    require(
        artifact["summary"]["host_comparison_limited_count"]
            .as_u64()
            .is_some_and(|count| count > 0),
        "host comparison limits must be present",
    )?;

    let profile_fields: HashSet<_> = json_array(&artifact, "required_profile_fields")?
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    for field in REQUIRED_PROFILE_FIELDS {
        require(
            profile_fields.contains(field),
            format!("required profile field missing from artifact: {field}"),
        )?;
    }

    let log_fields: HashSet<_> = json_array(&artifact, "required_log_fields")?
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    for field in REQUIRED_LOG_FIELDS {
        require(
            log_fields.contains(field),
            format!("required log field missing from artifact: {field}"),
        )?;
    }
    Ok(())
}

#[test]
fn profile_records_are_ranked_proofed_and_actionable() -> TestResult {
    let root = workspace_root()?;
    let artifact = load_json(&root.join("tests/conformance/hot_path_profile_report.v1.json"))?;
    let records = json_array(&artifact, "profile_records")?;

    let mut seen = HashSet::new();
    let mut last_score = f64::INFINITY;
    let mut has_membrane_validate = false;
    let mut has_missing_profile = false;
    let mut has_host_comparison = false;
    let mut has_host_limit = false;
    let mut families = HashSet::new();

    for record in records {
        for field in REQUIRED_PROFILE_FIELDS {
            require(
                record.get(*field).is_some(),
                format!("profile record missing field {field}: {record}"),
            )?;
        }
        let profile_id = string_field(record, "profile_id")?;
        require(
            seen.insert(profile_id.to_owned()),
            format!("duplicate profile id {profile_id}"),
        )?;
        let score = record["hotness_score"]
            .as_f64()
            .ok_or_else(|| format!("{profile_id}: hotness_score must be numeric"))?;
        require(
            score <= last_score,
            format!("{profile_id}: records are not sorted by descending score"),
        )?;
        last_score = score;

        let mode = string_field(record, "runtime_mode")?;
        require(
            ["strict", "hardened"].contains(&mode),
            format!("{profile_id}: invalid runtime_mode"),
        )?;
        require(
            record["baseline_artifact"].is_object(),
            format!("{profile_id}: baseline_artifact must be object"),
        )?;
        require(
            !json_array(record, "parity_proof_refs")?.is_empty(),
            format!("{profile_id}: parity proof refs must be non-empty"),
        )?;
        require(
            !json_array(record, "artifact_refs")?.is_empty(),
            format!("{profile_id}: artifact refs must be non-empty"),
        )?;

        let family = string_field(record, "api_family")?;
        families.insert(family.to_owned());
        if family == "membrane" && string_field(record, "symbol")?.starts_with("validate_") {
            has_membrane_validate = true;
        }
        if record["coverage_state"].as_str() == Some("missing_profile") {
            has_missing_profile = true;
            require(
                string_field(record, "failure_signature")? != "none",
                format!("{profile_id}: missing profile rows need a failure signature"),
            )?;
        }
        let host = &record["host_baseline"];
        if host["available"].as_bool() == Some(true) {
            has_host_comparison = true;
        }
        if host["available"].as_bool() != Some(true) && host["limit"].as_str().is_some() {
            has_host_limit = true;
        }
    }

    for required in ["membrane", "string", "malloc", "pthread", "syscall"] {
        require(
            families.contains(required),
            format!("profile report missing required family {required}"),
        )?;
    }
    require(
        has_membrane_validate,
        "membrane validate_* rows must be ranked",
    )?;
    require(
        has_missing_profile,
        "missing profile rows must stay visible",
    )?;
    require(
        has_host_comparison,
        "measured raw host comparisons must exist",
    )?;
    require(has_host_limit, "host comparison limits must be documented")?;
    require(
        !json_array(&artifact, "optimization_beads_to_create")?.is_empty(),
        "optimization bead seeds must be present",
    )?;
    Ok(())
}

#[test]
fn generator_self_test_canonical_check_and_stale_artifact_rejection_pass() -> TestResult {
    let root = workspace_root()?;
    let script = root.join("scripts/generate_hot_path_profile_report.py");
    require(script.exists(), format!("missing {}", script.display()))?;

    let self_test = Command::new("python3")
        .arg(&script)
        .arg("--self-test")
        .current_dir(&root)
        .output()
        .map_err(|err| format!("failed to run generator self-test: {err}"))?;
    require(
        self_test.status.success(),
        format!(
            "generator self-test failed:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&self_test.stdout),
            String::from_utf8_lossy(&self_test.stderr)
        ),
    )?;

    let canonical_check = Command::new("python3")
        .arg(&script)
        .arg("--check")
        .arg("--output")
        .arg("tests/conformance/hot_path_profile_report.v1.json")
        .current_dir(&root)
        .output()
        .map_err(|err| format!("failed to run generator canonical check: {err}"))?;
    require(
        canonical_check.status.success(),
        format!(
            "generator canonical check failed:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&canonical_check.stdout),
            String::from_utf8_lossy(&canonical_check.stderr)
        ),
    )?;

    let artifact = load_json(&root.join("tests/conformance/hot_path_profile_report.v1.json"))?;
    let mut stale = artifact.clone();
    stale["input_digests"]["profile_pipeline"] = serde_json::json!("synthetic-stale-digest");
    let stale_path = root.join("target/conformance/hot_path_profile_report.stale.json");
    let stale_parent = stale_path
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", stale_path.display()))?;
    std::fs::create_dir_all(stale_parent)
        .map_err(|err| format!("failed to create stale artifact dir: {err}"))?;
    let stale_bytes = serde_json::to_vec_pretty(&stale)
        .map_err(|err| format!("failed to serialize stale artifact: {err}"))?;
    std::fs::write(&stale_path, stale_bytes)
        .map_err(|err| format!("failed to write stale artifact: {err}"))?;

    let stale_check = Command::new("python3")
        .arg(&script)
        .arg("--check")
        .arg("--output")
        .arg(&stale_path)
        .current_dir(&root)
        .output()
        .map_err(|err| format!("failed to run stale artifact check: {err}"))?;
    require(
        !stale_check.status.success(),
        "stale artifact check should fail",
    )?;
    let stderr = String::from_utf8_lossy(&stale_check.stderr);
    require(
        stderr.contains("stale"),
        format!("stale artifact failure should mention stale, stderr={stderr}"),
    )?;
    Ok(())
}

#[test]
fn gate_script_emits_valid_report_and_structured_jsonl() -> TestResult {
    let root = workspace_root()?;
    let script = root.join("scripts/check_hot_path_profile_report.sh");
    require(script.exists(), format!("missing {}", script.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script)
            .map_err(|err| format!("{}: {err}", script.display()))?
            .permissions();
        require(
            perms.mode() & 0o111 != 0,
            "check_hot_path_profile_report.sh must be executable",
        )?;
    }

    let report_path = root.join("target/conformance/hot_path_profile_report.report.json");
    let log_path = root.join("target/conformance/hot_path_profile_report.log.jsonl");
    let output = Command::new(&script)
        .current_dir(&root)
        .output()
        .map_err(|err| format!("failed to run hot path profile gate: {err}"))?;
    require(
        output.status.success(),
        format!(
            "hot path profile gate failed:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )?;
    require(
        report_path.exists(),
        format!("missing {}", report_path.display()),
    )?;
    require(log_path.exists(), format!("missing {}", log_path.display()))?;

    let report = load_json(&report_path)?;
    require(
        report["bead"].as_str() == Some("bd-bp8fl.8.3"),
        "report bead mismatch",
    )?;

    let log_content = std::fs::read_to_string(&log_path)
        .map_err(|err| format!("{}: {err}", log_path.display()))?;
    let mut rows = 0usize;
    for raw in log_content.lines().filter(|line| !line.trim().is_empty()) {
        let row: serde_json::Value =
            serde_json::from_str(raw).map_err(|err| format!("log row parse error: {err}"))?;
        rows += 1;
        for field in REQUIRED_LOG_FIELDS {
            require(
                row.get(*field).is_some(),
                format!("log row missing field {field}"),
            )?;
        }
        require(
            row["bead_id"].as_str() == Some("bd-bp8fl.8.3"),
            "log row bead_id mismatch",
        )?;
        require(
            row["baseline_ref"].as_str().is_some(),
            "log row baseline_ref missing",
        )?;
        require(
            row["artifact_refs"]
                .as_array()
                .is_some_and(|items| !items.is_empty()),
            "log row artifact_refs missing",
        )?;
    }
    require(rows > 0, "structured log must contain rows")?;
    Ok(())
}
