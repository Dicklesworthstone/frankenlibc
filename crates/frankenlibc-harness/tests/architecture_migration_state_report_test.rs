use serde_json::Value;
use std::collections::BTreeSet;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn test_error(message: impl Into<String>) -> Box<dyn Error> {
    std::io::Error::other(message.into()).into()
}

fn workspace_root() -> TestResult<PathBuf> {
    Ok(Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| test_error("crate manifest should have crates parent"))?
        .parent()
        .ok_or_else(|| test_error("crates directory should have workspace parent"))?
        .to_path_buf())
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/architecture_migration_state_report.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_architecture_migration_state_report.sh")
}

fn report_path(out_dir: &Path) -> PathBuf {
    out_dir.join("architecture_migration_state_report.report.json")
}

fn log_path(out_dir: &Path) -> PathBuf {
    out_dir.join("architecture_migration_state_report.log.jsonl")
}

fn load_json(path: &Path) -> TestResult<Value> {
    let content = std::fs::read_to_string(path)
        .map_err(|err| test_error(format!("{} should be readable: {err}", path.display())))?;
    serde_json::from_str(&content)
        .map_err(|err| test_error(format!("{} should parse as JSON: {err}", path.display())))
}

fn load_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    std::fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str(line).map_err(|err| {
                test_error(format!("invalid JSONL row in {}: {err}", path.display()))
            })
        })
        .collect()
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    std::fs::write(path, format!("{}\n", serde_json::to_string_pretty(value)?))?;
    Ok(())
}

fn unique_output_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| test_error(format!("system clock should be after Unix epoch: {err}")))?
        .as_nanos();
    let path = root.join("target/conformance").join(format!(
        "architecture_migration_state_report_{label}_{}_{}",
        std::process::id(),
        stamp
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn string_field<'a>(value: &'a Value, key: &str, context: &str) -> TestResult<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| test_error(format!("{context}.{key} must be a string")))
}

fn bool_field(value: &Value, key: &str, context: &str) -> TestResult<bool> {
    value
        .get(key)
        .and_then(Value::as_bool)
        .ok_or_else(|| test_error(format!("{context}.{key} must be a bool")))
}

fn array_field<'a>(value: &'a Value, key: &str, context: &str) -> TestResult<&'a Vec<Value>> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| test_error(format!("{context}.{key} must be an array")))
}

fn string_set(value: &Value, key: &str, context: &str) -> TestResult<BTreeSet<String>> {
    array_field(value, key, context)?
        .iter()
        .map(|row| {
            row.as_str()
                .map(str::to_owned)
                .ok_or_else(|| test_error(format!("{context}.{key} must contain only strings")))
        })
        .collect::<Result<_, _>>()
}

fn path_field<'a>(value: &'a Value, key: &str, context: &str) -> TestResult<&'a str> {
    string_field(value, key, context)
}

fn relative_path(root: &Path, path: &Path) -> TestResult<String> {
    Ok(path
        .strip_prefix(root)
        .map_err(|err| {
            test_error(format!(
                "{} should be under repo root: {err}",
                path.display()
            ))
        })?
        .to_string_lossy()
        .into_owned())
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .arg("--validate-only")
        .current_dir(root)
        .env("ARCH_MIGRATION_STATE_REPORT_CONTRACT", contract)
        .env("ARCH_MIGRATION_STATE_REPORT_REPORT", report_path(out_dir))
        .env("ARCH_MIGRATION_STATE_REPORT_LOG", log_path(out_dir))
        .output()?)
}

fn output_text(output: &Output) -> String {
    format!(
        "status={}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn expect_checker_success(output: &Output) -> TestResult {
    if output.status.success() {
        return Ok(());
    }
    Err(test_error(format!(
        "checker failed: {}",
        output_text(output)
    )))
}

fn expect_checker_failure(output: &Output) -> TestResult {
    if !output.status.success() {
        return Ok(());
    }
    Err(test_error(format!(
        "checker unexpectedly passed: {}",
        output_text(output)
    )))
}

#[test]
fn contract_binds_architecture_migration_state_sources() -> TestResult {
    let root = workspace_root()?;
    let contract = load_json(&contract_path(&root))?;

    assert_eq!(
        string_field(&contract, "schema_version", "contract")?,
        "architecture_migration_state_report.v1"
    );
    assert_eq!(
        string_field(&contract, "generated_by_bead", "contract")?,
        "bd-0agsk.16"
    );
    assert_eq!(
        string_field(&contract, "canonical_command", "contract")?,
        "scripts/check_architecture_migration_state_report.sh --validate-only"
    );
    assert_eq!(
        string_set(&contract, "source_todo_ids", "contract")?,
        BTreeSet::from([
            "TODO-1001".to_string(),
            "TODO-1002".to_string(),
            "TODO-1003".to_string(),
        ])
    );

    let branch_policy = contract
        .get("branch_reference_policy")
        .ok_or_else(|| test_error("branch_reference_policy missing"))?;
    assert_eq!(
        string_field(branch_policy, "default_branch", "branch_reference_policy")?,
        "main"
    );
    assert!(
        !bool_field(
            branch_policy,
            "legacy_branch_aliases_allowed",
            "branch_reference_policy"
        )?,
        "legacy branch aliases must stay forbidden"
    );

    let source_artifacts = array_field(&contract, "source_artifacts", "contract")?;
    assert_eq!(source_artifacts.len(), 10);
    let source_ids: BTreeSet<_> = source_artifacts
        .iter()
        .map(|row| string_field(row, "id", "source_artifacts"))
        .collect::<Result<_, _>>()?;
    for required in [
        "support_matrix",
        "reality_report",
        "replacement_levels",
        "support_matrix_maintenance",
        "ld_preload_smoke",
        "runtime_mode_evidence",
        "hardened_coverage_inventory",
        "contributor_quickstart",
        "tooling_boundary",
        "runtime_math_required_modules",
    ] {
        assert!(
            source_ids.contains(required),
            "missing source id {required}"
        );
    }
    for artifact in source_artifacts {
        let path = path_field(artifact, "path", "source_artifacts")?;
        assert!(root.join(path).is_file(), "missing source artifact {path}");
    }

    let relevant_scripts = string_set(&contract, "relevant_scripts", "contract")?;
    assert_eq!(relevant_scripts.len(), 10);
    assert!(relevant_scripts.contains("scripts/check_architecture_migration_state_report.sh"));
    for script in &relevant_scripts {
        assert!(
            root.join(script).is_file(),
            "missing relevant script {script}"
        );
    }

    let support_summary = contract
        .get("support_matrix_summary")
        .ok_or_else(|| test_error("support_matrix_summary missing"))?;
    assert_eq!(support_summary["total_exported"].as_u64(), Some(4119));
    assert_eq!(support_summary["native_surface_pct"].as_f64(), Some(68.2));
    assert_eq!(
        support_summary["host_callthrough_surface_pct"].as_f64(),
        Some(31.8)
    );

    let claim_summary = contract
        .get("claim_summary")
        .ok_or_else(|| test_error("claim_summary missing"))?;
    assert_eq!(
        string_field(claim_summary, "current_level", "claim_summary")?,
        "L1"
    );
    assert_eq!(
        string_field(claim_summary, "replacement_claim", "claim_summary")?,
        "not_promoted"
    );

    let crate_flows = array_field(&contract, "crate_to_artifact_flow", "contract")?;
    assert_eq!(crate_flows.len(), 6);
    let family_rows = array_field(&contract, "module_family_status", "contract")?;
    assert_eq!(family_rows.len(), 9);
    let glossary_terms: BTreeSet<_> =
        array_field(&contract, "strict_hardened_glossary", "contract")?
            .iter()
            .map(|row| string_field(row, "term", "strict_hardened_glossary"))
            .collect::<Result<_, _>>()?;
    assert_eq!(
        glossary_terms,
        BTreeSet::from([
            "both_modes",
            "hardened_mode",
            "startup_evidence",
            "strict_mode",
        ])
    );

    Ok(())
}

#[test]
fn checker_emits_isolated_pass_report_and_jsonl() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "pass")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    expect_checker_success(&output)?;

    let report = load_json(&report_path(&out_dir))?;
    assert_eq!(
        string_field(&report, "schema_version", "report")?,
        "architecture_migration_state_report.report.v1"
    );
    assert_eq!(string_field(&report, "bead", "report")?, "bd-0agsk.16");
    assert_eq!(string_field(&report, "mode", "report")?, "validate-only");
    assert_eq!(string_field(&report, "outcome", "report")?, "pass");
    assert_eq!(
        string_field(&report, "failure_signature", "report")?,
        "none"
    );
    assert_eq!(report["summary"]["source_artifacts"].as_u64(), Some(10));
    assert_eq!(report["summary"]["scripts"].as_u64(), Some(10));
    assert_eq!(report["summary"]["module_families"].as_u64(), Some(9));
    assert_eq!(report["summary"]["total_symbols"].as_u64(), Some(4119));
    assert_eq!(
        string_field(&report["summary"], "current_level", "report.summary")?,
        "L1"
    );

    let events = load_jsonl(&log_path(&out_dir))?;
    assert_eq!(events.len(), 1);
    assert_eq!(
        string_field(&events[0], "event", "log")?,
        "architecture_migration_state_report_validated"
    );
    assert_eq!(string_field(&events[0], "outcome", "log")?, "pass");
    assert_eq!(
        string_field(&events[0], "failure_signature", "log")?,
        "none"
    );

    Ok(())
}

#[test]
fn checker_rejects_schema_drift() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "schema_drift")?;
    let mut contract = load_json(&contract_path(&root))?;
    contract["schema_version"] = Value::String("architecture_migration_state_report.v0".into());
    let mutated = out_dir.join("architecture_migration_state_report.schema_drift.json");
    write_json(&mutated, &contract)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    expect_checker_failure(&output)?;

    let report = load_json(&report_path(&out_dir))?;
    assert_eq!(string_field(&report, "outcome", "report")?, "fail");
    assert_eq!(
        string_field(&report, "failure_signature", "report")?,
        "schema_version"
    );
    let expected_contract = relative_path(&root, &mutated)?;
    assert_eq!(
        string_field(&report, "contract", "report")?,
        expected_contract.as_str()
    );

    let events = load_jsonl(&log_path(&out_dir))?;
    assert_eq!(events.len(), 1);
    assert_eq!(
        string_field(&events[0], "event", "log")?,
        "architecture_migration_state_report_failed"
    );
    assert_eq!(
        string_field(&events[0], "failure_signature", "log")?,
        "schema_version"
    );

    Ok(())
}
