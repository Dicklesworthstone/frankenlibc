//! Integration test: feature parity gap grouping gate (bd-bp8fl.3.1)
//!
//! Validates that all feature_parity_gap_ledger.v1.json gaps are grouped into
//! actionable batches exactly once, with explicit owner/evidence dimensions.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;

type TestResult<T = ()> = Result<T, String>;

const REQUIRED_BATCH_FIELDS: &[&str] = &[
    "title",
    "feature_parity_sections",
    "symbol_family",
    "abi_modules",
    "support_statuses",
    "semantic_statuses",
    "evidence_artifacts",
    "source_owner",
    "owner_beads",
    "priority",
    "oracle_kind",
    "replacement_levels",
    "closure_blockers",
    "gap_count",
    "gap_ids",
    "actionable_next_step",
];

const REQUIRED_GATE_CHECKS: &[&str] = &[
    "json_parse",
    "top_level_shape",
    "batch_schema",
    "artifact_contract",
    "artifact_freshness",
    "evidence_artifacts_exist",
    "abi_modules_exist",
    "unique_batch_ids",
    "unique_ledger_gap_ids",
    "exact_gap_coverage",
    "known_ledger_sections",
    "owner_bead_coverage",
    "semantic_status_coverage",
    "summary_counts",
];

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "ledger_row_id",
    "section",
    "symbol_family",
    "owner_bead",
    "expected",
    "actual",
    "artifact_refs",
    "failure_signature",
    "scenario_id",
    "runtime_mode",
    "replacement_level",
    "api_family",
    "oracle_kind",
    "source_commit",
    "target_dir",
];

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let root = Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))?
        .to_path_buf();
    Ok(root)
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

fn json_object<'a>(
    value: &'a serde_json::Value,
    field: &str,
) -> TestResult<&'a serde_json::Map<String, serde_json::Value>> {
    value[field]
        .as_object()
        .ok_or_else(|| format!("{field} must be a JSON object"))
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

fn require_eq<T>(actual: T, expected: T, label: &str) -> TestResult
where
    T: std::fmt::Debug + PartialEq,
{
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "{label} mismatch: actual={actual:?} expected={expected:?}"
        ))
    }
}

fn len_as_u64(len: usize, label: &str) -> TestResult<u64> {
    u64::try_from(len).map_err(|err| format!("{label} length conversion failed: {err}"))
}

fn artifact_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/feature_parity_gap_groups.v1.json")
}

fn ledger_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/feature_parity_gap_ledger.v1.json")
}

fn coverage_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/feature_parity_gap_bead_coverage.v1.json")
}

fn load_artifact_and_ledger() -> TestResult<(PathBuf, serde_json::Value, serde_json::Value)> {
    let root = workspace_root()?;
    let artifact = load_json(&artifact_path(&root))?;
    let ledger = load_json(&ledger_path(&root))?;
    Ok((root, artifact, ledger))
}

fn gap_ids_from_ledger(ledger: &serde_json::Value) -> TestResult<HashSet<String>> {
    let mut ids = HashSet::new();
    for gap in json_array(ledger, "gaps")? {
        let id = string_field(gap, "gap_id")?.to_owned();
        require(
            ids.insert(id.clone()),
            format!("duplicate ledger gap id {id}"),
        )?;
    }
    Ok(ids)
}

fn batch_id(batch: &serde_json::Value) -> &str {
    batch["batch_id"].as_str().unwrap_or("<missing batch_id>")
}

fn write_json(path: &Path, value: &serde_json::Value) -> TestResult {
    let content = serde_json::to_string_pretty(value)
        .map_err(|err| format!("{} serialization failed: {err}", path.display()))?;
    std::fs::write(path, format!("{content}\n"))
        .map_err(|err| format!("{} write failed: {err}", path.display()))
}

fn run_gate_with_inputs(
    root: &Path,
    case_name: &str,
    artifact: &serde_json::Value,
    ledger: &serde_json::Value,
) -> TestResult<(std::process::Output, PathBuf)> {
    let out_dir = root.join("target/conformance/feature_parity_gap_groups_negative");
    std::fs::create_dir_all(&out_dir)
        .map_err(|err| format!("{} mkdir failed: {err}", out_dir.display()))?;
    let artifact_path = out_dir.join(format!("{case_name}.groups.json"));
    let ledger_path = out_dir.join(format!("{case_name}.ledger.json"));
    let report_path = out_dir.join(format!("{case_name}.report.json"));
    let log_path = out_dir.join(format!("{case_name}.log.jsonl"));
    let regenerated_path = out_dir.join(format!("{case_name}.regenerated.json"));
    write_json(&artifact_path, artifact)?;
    write_json(&ledger_path, ledger)?;
    let script = root.join("scripts/check_feature_parity_gap_groups.sh");
    let output = Command::new(&script)
        .current_dir(root)
        .env("FRANKENLIBC_FEATURE_PARITY_GAP_GROUPS", &artifact_path)
        .env("FRANKENLIBC_FEATURE_PARITY_GAP_LEDGER", &ledger_path)
        .env("FRANKENLIBC_FEATURE_PARITY_GAP_GROUP_REPORT", &report_path)
        .env("FRANKENLIBC_FEATURE_PARITY_GAP_GROUP_LOG", &log_path)
        .env(
            "FRANKENLIBC_FEATURE_PARITY_GAP_REGENERATED",
            &regenerated_path,
        )
        .output()
        .map_err(|err| format!("failed to run feature parity gap groups gate: {err}"))?;
    Ok((output, report_path))
}

fn expect_gate_failure(
    root: &Path,
    case_name: &str,
    artifact: &serde_json::Value,
    ledger: &serde_json::Value,
    expected_check: &str,
) -> TestResult {
    let (output, report_path) = run_gate_with_inputs(root, case_name, artifact, ledger)?;
    require(
        !output.status.success(),
        format!("{case_name}: gate should fail but passed"),
    )?;
    let report = load_json(&report_path)?;
    require_eq(
        report["checks"][expected_check].as_str(),
        Some("fail"),
        &format!("{case_name}: checks.{expected_check}"),
    )?;
    require(
        !json_array(&report, "errors")?.is_empty(),
        format!("{case_name}: failing report must include errors"),
    )
}

#[test]
fn artifact_exists_and_has_required_shape() -> TestResult {
    let root = workspace_root()?;
    let artifact = load_json(&artifact_path(&root))?;
    require_eq(artifact["schema_version"].as_str(), Some("v1"), "schema")?;
    require_eq(artifact["bead"].as_str(), Some("bd-bp8fl.3.1"), "bead")?;
    require(artifact["inputs"].is_object(), "inputs must be object")?;
    require(
        artifact["batch_policy"].is_object(),
        "batch_policy must be object",
    )?;
    require(
        artifact["generated_outputs"].is_object(),
        "generated_outputs must be object",
    )?;
    require(artifact["batches"].is_array(), "batches must be array")?;
    require(artifact["summary"].is_object(), "summary must be object")?;
    let required_log_fields = json_array(&artifact, "required_log_fields")?;
    require_eq(
        required_log_fields.len(),
        REQUIRED_LOG_FIELDS.len(),
        "required_log_fields length",
    )?;
    for field in REQUIRED_LOG_FIELDS {
        require(
            required_log_fields
                .iter()
                .any(|value| value.as_str() == Some(field)),
            format!("artifact required_log_fields missing {field}"),
        )?;
    }
    let grouping_axes = json_array(&artifact, "required_grouping_axes")?;
    for axis in [
        "feature_parity_sections",
        "symbol_family",
        "abi_modules",
        "support_statuses",
        "semantic_statuses",
        "owner_beads",
        "oracle_kind",
        "replacement_levels",
        "evidence_artifacts",
        "closure_blockers",
        "source_owner",
        "priority",
    ] {
        require(
            grouping_axes
                .iter()
                .any(|value| value.as_str() == Some(axis)),
            format!("artifact required_grouping_axes missing {axis}"),
        )?;
    }

    let batches = json_array(&artifact, "batches")?;
    require(
        batches.len() >= 10,
        format!("batches should not collapse the plan: {}", batches.len()),
    )?;
    for batch in batches {
        let batch_id = batch_id(batch);
        for field in REQUIRED_BATCH_FIELDS {
            require(
                !batch[*field].is_null(),
                format!("{batch_id}: missing {field}"),
            )?;
        }
        require(
            !json_array(batch, "feature_parity_sections")?.is_empty(),
            format!("{batch_id}: feature_parity_sections must not be empty"),
        )?;
        require(
            !json_array(batch, "abi_modules")?.is_empty(),
            format!("{batch_id}: abi_modules must not be empty"),
        )?;
        for module_ref in json_array(batch, "abi_modules")? {
            let module_ref = module_ref
                .as_str()
                .ok_or_else(|| format!("{batch_id}: abi module refs must be strings"))?;
            let module_path = root.join(module_ref.trim_end_matches('/'));
            require(
                module_path.exists(),
                format!("{batch_id}: missing ABI module {module_ref}"),
            )?;
        }
        require(
            !json_array(batch, "support_statuses")?.is_empty(),
            format!("{batch_id}: support_statuses must not be empty"),
        )?;
        require(
            !json_array(batch, "semantic_statuses")?.is_empty(),
            format!("{batch_id}: semantic_statuses must not be empty"),
        )?;
        require(
            !json_array(batch, "evidence_artifacts")?.is_empty(),
            format!("{batch_id}: evidence_artifacts must not be empty"),
        )?;
        for artifact_ref in json_array(batch, "evidence_artifacts")? {
            let artifact_ref = artifact_ref
                .as_str()
                .ok_or_else(|| format!("{batch_id}: evidence artifact refs must be strings"))?;
            let artifact_path = root.join(artifact_ref.trim_end_matches('/'));
            require(
                artifact_path.exists(),
                format!("{batch_id}: missing evidence artifact {artifact_ref}"),
            )?;
        }
        require(
            batch["priority"].as_u64().is_some(),
            format!("{batch_id}: priority must be numeric"),
        )?;
        require(
            !string_field(batch, "symbol_family")?.trim().is_empty(),
            format!("{batch_id}: symbol_family must not be empty"),
        )?;
        require(
            !string_field(batch, "source_owner")?.trim().is_empty(),
            format!("{batch_id}: source_owner must not be empty"),
        )?;
        require(
            !json_array(batch, "owner_beads")?.is_empty(),
            format!("{batch_id}: owner_beads must not be empty"),
        )?;
        require(
            !string_field(batch, "oracle_kind")?.trim().is_empty(),
            format!("{batch_id}: oracle_kind must not be empty"),
        )?;
        require(
            !json_array(batch, "replacement_levels")?.is_empty(),
            format!("{batch_id}: replacement_levels must not be empty"),
        )?;
        require(
            !json_array(batch, "closure_blockers")?.is_empty(),
            format!("{batch_id}: closure_blockers must not be empty"),
        )?;
    }
    Ok(())
}

#[test]
fn batches_preserve_owner_bead_and_semantic_status_scope() -> TestResult {
    let (root, artifact, ledger) = load_artifact_and_ledger()?;
    let coverage = load_json(&coverage_path(&root))?;
    let coverage_rows = json_array(&coverage, "rows")?;
    let mut owner_by_gap = HashMap::new();
    for row in coverage_rows {
        owner_by_gap.insert(
            string_field(row, "gap_id")?.to_owned(),
            string_field(row, "owner_bead")?.to_owned(),
        );
    }
    let mut status_by_gap = HashMap::new();
    for gap in json_array(&ledger, "gaps")? {
        status_by_gap.insert(
            string_field(gap, "gap_id")?.to_owned(),
            string_field(gap, "status")?.to_owned(),
        );
    }

    for batch in json_array(&artifact, "batches")? {
        let batch_id = batch_id(batch);
        let owners: HashSet<_> = json_array(batch, "owner_beads")?
            .iter()
            .filter_map(|value| value.as_str())
            .collect();
        let statuses: HashSet<_> = json_array(batch, "semantic_statuses")?
            .iter()
            .filter_map(|value| value.as_str())
            .collect();
        for gap_id in json_array(batch, "gap_ids")? {
            let gap_id = gap_id
                .as_str()
                .ok_or_else(|| format!("{batch_id}: gap_ids must be strings"))?;
            let owner = owner_by_gap
                .get(gap_id)
                .ok_or_else(|| format!("{batch_id}: no owner coverage for {gap_id}"))?;
            require(
                owners.contains(owner.as_str()),
                format!("{batch_id}: owner_beads missing {owner} for {gap_id}"),
            )?;
            let status = status_by_gap
                .get(gap_id)
                .ok_or_else(|| format!("{batch_id}: no ledger status for {gap_id}"))?;
            require(
                statuses.contains(status.as_str()),
                format!("{batch_id}: semantic_statuses missing {status} for {gap_id}"),
            )?;
        }
    }
    Ok(())
}

#[test]
fn batches_cover_every_ledger_gap_exactly_once() -> TestResult {
    let (_root, artifact, ledger) = load_artifact_and_ledger()?;
    let ledger_ids = gap_ids_from_ledger(&ledger)?;

    let mut seen = HashSet::new();
    let mut duplicates = Vec::new();
    for batch in json_array(&artifact, "batches")? {
        let gap_ids = json_array(batch, "gap_ids")?;
        require_eq(
            batch["gap_count"].as_u64(),
            Some(len_as_u64(gap_ids.len(), "gap_ids")?),
            &format!("{} gap_count", batch_id(batch)),
        )?;
        for gap_id in gap_ids {
            let id = gap_id
                .as_str()
                .ok_or_else(|| format!("{} gap_ids must be strings", batch_id(batch)))?
                .to_owned();
            if !seen.insert(id.clone()) {
                duplicates.push(id);
            }
        }
    }

    let missing: Vec<_> = ledger_ids.difference(&seen).cloned().collect();
    let extra: Vec<_> = seen.difference(&ledger_ids).cloned().collect();
    require(
        duplicates.is_empty(),
        format!("duplicate gap ids: {duplicates:?}"),
    )?;
    require(missing.is_empty(), format!("missing gap ids: {missing:?}"))?;
    require(extra.is_empty(), format!("unknown gap ids: {extra:?}"))?;
    Ok(())
}

#[test]
fn summary_counts_match_ledger_and_batches() -> TestResult {
    let (_root, artifact, ledger) = load_artifact_and_ledger()?;

    let batches = json_array(&artifact, "batches")?;
    let mut batched_gap_count = 0usize;
    for batch in batches {
        batched_gap_count += json_array(batch, "gap_ids")?.len();
    }
    let ledger_gaps = json_array(&ledger, "gaps")?;

    let mut by_section: HashMap<String, u64> = HashMap::new();
    for gap in ledger_gaps {
        let section = gap["section"].as_str().unwrap_or("machine_delta");
        *by_section.entry(section.to_string()).or_insert(0) += 1;
    }

    let summary = json_object(&artifact, "summary")?;
    require_eq(
        summary.get("ledger_gap_count").and_then(|v| v.as_u64()),
        Some(len_as_u64(ledger_gaps.len(), "ledger_gaps")?),
        "summary.ledger_gap_count",
    )?;
    require_eq(
        summary.get("batch_count").and_then(|v| v.as_u64()),
        Some(len_as_u64(batches.len(), "batches")?),
        "summary.batch_count",
    )?;
    require_eq(
        summary.get("batched_gap_count").and_then(|v| v.as_u64()),
        Some(len_as_u64(batched_gap_count, "batched_gap_count")?),
        "summary.batched_gap_count",
    )?;
    let expected_sections = serde_json::to_value(by_section)
        .map_err(|err| format!("section count serialization failed: {err}"))?;
    require_eq(
        summary.get("by_feature_parity_section"),
        Some(&expected_sections),
        "summary.by_feature_parity_section",
    )?;
    Ok(())
}

#[test]
fn gate_script_passes_and_emits_structured_report_and_log() -> TestResult {
    let root = workspace_root()?;
    let script = root.join("scripts/check_feature_parity_gap_groups.sh");
    require(
        script.exists(),
        format!("missing gate script {}", script.display()),
    )?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script)
            .map_err(|err| format!("{}: {err}", script.display()))?
            .permissions();
        require(
            perms.mode() & 0o111 != 0,
            "check_feature_parity_gap_groups.sh must be executable",
        )?;
    }

    let output = Command::new(&script)
        .current_dir(&root)
        .output()
        .map_err(|err| format!("failed to run feature parity gap groups gate: {err}"))?;
    require(
        output.status.success(),
        format!(
            "feature parity gap groups gate failed:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )?;

    let report_path = root.join("target/conformance/feature_parity_gap_groups.report.json");
    let log_path = root.join("target/conformance/feature_parity_gap_groups.log.jsonl");
    let regenerated_path =
        root.join("target/conformance/feature_parity_gap_groups.regenerated.v1.json");
    require(
        report_path.exists(),
        format!("missing {}", report_path.display()),
    )?;
    require(log_path.exists(), format!("missing {}", log_path.display()))?;
    require(
        regenerated_path.exists(),
        format!("missing {}", regenerated_path.display()),
    )?;

    let report = load_json(&report_path)?;
    require_eq(
        report["schema_version"].as_str(),
        Some("v1"),
        "report schema",
    )?;
    require_eq(report["bead"].as_str(), Some("bd-bp8fl.3.1"), "report bead")?;
    require_eq(report["status"].as_str(), Some("pass"), "report status")?;
    for check in REQUIRED_GATE_CHECKS {
        require_eq(
            report["checks"][*check].as_str(),
            Some("pass"),
            &format!("report checks.{check}"),
        )?;
    }
    require(
        report["owner_counts"].is_object(),
        "report must include owner_counts",
    )?;
    require(
        report["evidence_artifact_counts"].is_object(),
        "report must include evidence_artifact_counts",
    )?;
    require(
        report["symbol_family_counts"].is_object(),
        "report must include symbol_family_counts",
    )?;
    require(
        report["owner_bead_counts"].is_object(),
        "report must include owner_bead_counts",
    )?;
    require(
        report["support_status_counts"].is_object(),
        "report must include support_status_counts",
    )?;
    require(
        report["semantic_status_counts"].is_object(),
        "report must include semantic_status_counts",
    )?;
    let batch_summaries = json_array(&report, "batch_summaries")?;
    let artifact = load_json(&artifact_path(&root))?;
    let batches = json_array(&artifact, "batches")?;
    require_eq(
        batch_summaries.len(),
        batches.len(),
        "report.batch_summaries length",
    )?;
    for summary in batch_summaries {
        let batch_id = string_field(summary, "batch_id")?;
        require(
            summary["status_counts"].is_object(),
            format!("{batch_id}: status_counts must be object"),
        )?;
        require(
            summary["kind_counts"].is_object(),
            format!("{batch_id}: kind_counts must be object"),
        )?;
        require(
            summary["provenance_paths"].is_object(),
            format!("{batch_id}: provenance_paths must be object"),
        )?;
        require(
            !json_array(summary, "representative_primary_keys")?.is_empty(),
            format!("{batch_id}: representative_primary_keys must not be empty"),
        )?;
        require(
            !json_array(summary, "owner_beads")?.is_empty(),
            format!("{batch_id}: owner_beads must not be empty"),
        )?;
        require(
            !json_array(summary, "replacement_levels")?.is_empty(),
            format!("{batch_id}: replacement_levels must not be empty"),
        )?;
    }

    let log = std::fs::read_to_string(&log_path)
        .map_err(|err| format!("{}: {err}", log_path.display()))?;
    let log_rows: Vec<_> = log.lines().filter(|line| !line.trim().is_empty()).collect();
    let ledger = load_json(&ledger_path(&root))?;
    let ledger_gap_count = json_array(&ledger, "gaps")?.len();
    require_eq(
        log_rows.len(),
        batches.len() + ledger_gap_count + 1,
        "structured log row count",
    )?;
    let mut batch_log_rows = HashSet::new();
    let mut ledger_log_rows = HashSet::new();
    for line in log_rows {
        let event: serde_json::Value =
            serde_json::from_str(line).map_err(|err| format!("log row should parse: {err}"))?;
        for key in REQUIRED_LOG_FIELDS {
            require(
                event.get(*key).is_some(),
                format!("structured log row missing {key}"),
            )?;
        }
        if let Some(scenario_id) = event["scenario_id"].as_str()
            && let Some(batch_id) = scenario_id.strip_prefix("feature-parity-gap-batch:")
        {
            batch_log_rows.insert(batch_id.to_owned());
            require(
                event["source_owner"].as_str().is_some(),
                format!("{batch_id}: batch log must include source_owner"),
            )?;
            require(
                event["status_counts"].is_object(),
                format!("{batch_id}: batch log must include status_counts"),
            )?;
        } else if let Some(scenario_id) = event["scenario_id"].as_str()
            && let Some(gap_id) = scenario_id.strip_prefix("feature-parity-gap-row:")
        {
            ledger_log_rows.insert(gap_id.to_owned());
            require_eq(
                event["ledger_row_id"].as_str(),
                Some(gap_id),
                &format!("{gap_id}: ledger_row_id"),
            )?;
            require(
                event["owner_bead"].as_str().is_some(),
                format!("{gap_id}: row log must include owner_bead"),
            )?;
        }
    }
    require_eq(batch_log_rows.len(), batches.len(), "batch log coverage")?;
    require_eq(
        ledger_log_rows.len(),
        ledger_gap_count,
        "ledger row log coverage",
    )?;
    Ok(())
}

#[test]
fn gate_rejects_duplicate_missing_owner_unknown_section_stale_and_count_drift() -> TestResult {
    let (root, artifact, ledger) = load_artifact_and_ledger()?;

    let mut duplicate_ledger = ledger.clone();
    let first_gap = duplicate_ledger["gaps"][0].clone();
    duplicate_ledger["gaps"]
        .as_array_mut()
        .ok_or_else(|| "gaps must be mutable array".to_string())?
        .push(first_gap);
    expect_gate_failure(
        &root,
        "duplicate_ledger_gap",
        &artifact,
        &duplicate_ledger,
        "unique_ledger_gap_ids",
    )?;

    let mut missing_owner_artifact = artifact.clone();
    missing_owner_artifact["batches"][0]["owner_beads"] = serde_json::json!([]);
    expect_gate_failure(
        &root,
        "missing_owner",
        &missing_owner_artifact,
        &ledger,
        "owner_bead_coverage",
    )?;

    let mut unknown_section_ledger = ledger.clone();
    unknown_section_ledger["gaps"][0]["section"] = serde_json::json!("unknown_section");
    expect_gate_failure(
        &root,
        "unknown_section",
        &artifact,
        &unknown_section_ledger,
        "known_ledger_sections",
    )?;

    let mut stale_artifact = artifact.clone();
    stale_artifact["generated_at_utc"] = serde_json::json!("2000-01-01T00:00:00Z");
    expect_gate_failure(
        &root,
        "stale_artifact",
        &stale_artifact,
        &ledger,
        "artifact_freshness",
    )?;

    let mut missing_gap_artifact = artifact.clone();
    let first_batch = missing_gap_artifact["batches"][0]
        .as_object_mut()
        .ok_or_else(|| "first batch must be object".to_string())?;
    first_batch
        .get_mut("gap_ids")
        .and_then(|value| value.as_array_mut())
        .ok_or_else(|| "gap_ids must be mutable array".to_string())?
        .pop();
    first_batch.insert("gap_count".to_string(), serde_json::json!(7));
    expect_gate_failure(
        &root,
        "missing_gap_count_drift",
        &missing_gap_artifact,
        &ledger,
        "exact_gap_coverage",
    )?;

    Ok(())
}
