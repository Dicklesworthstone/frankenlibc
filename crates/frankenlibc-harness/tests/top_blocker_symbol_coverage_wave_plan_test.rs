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
    root.join("tests/conformance/top_blocker_symbol_coverage_wave_plan.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_top_blocker_symbol_coverage_wave_plan.sh")
}

fn report_path(out_dir: &Path) -> PathBuf {
    out_dir.join("top_blocker_symbol_coverage_wave_plan.report.json")
}

fn log_path(out_dir: &Path) -> PathBuf {
    out_dir.join("top_blocker_symbol_coverage_wave_plan.log.jsonl")
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
        "top_blocker_symbol_coverage_wave_plan_{label}_{}_{}",
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

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .arg("--validate-only")
        .current_dir(root)
        .env("TOP_BLOCKER_SYMBOL_WAVE_PLAN_CONTRACT", contract)
        .env("TOP_BLOCKER_SYMBOL_WAVE_PLAN_REPORT", report_path(out_dir))
        .env("TOP_BLOCKER_SYMBOL_WAVE_PLAN_LOG", log_path(out_dir))
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
fn contract_binds_top_blocker_wave_policy_and_inputs() -> TestResult {
    let root = workspace_root()?;
    let contract = load_json(&contract_path(&root))?;

    assert_eq!(
        string_field(&contract, "schema_version", "contract")?,
        "top_blocker_symbol_coverage_wave_plan.v1"
    );
    assert_eq!(
        string_field(&contract, "generated_by_bead", "contract")?,
        "bd-0agsk.18"
    );
    assert_eq!(
        string_field(&contract, "canonical_command", "contract")?,
        "scripts/check_top_blocker_symbol_coverage_wave_plan.sh --validate-only"
    );

    let input_artifacts = string_set(&contract, "input_artifacts", "contract")?;
    for required in [
        "support_matrix.json",
        "crates/frankenlibc-abi/version_scripts/libc.map",
        "tests/conformance/support_reality_drift_triage.v1.json",
        "tests/conformance/replacement_readiness_acceptance_thresholds.v1.json",
        "tests/conformance/family_coverage_thresholds.v1.json",
        "tests/conformance/fixture_coverage_prioritizer.v1.json",
        "tests/conformance/hardened_mode_coverage_inventory.v1.json",
        "tests/conformance/symbol_fixture_coverage.v1.json",
        "tests/conformance/per_symbol_fixture_tests.v1.json",
    ] {
        assert!(
            input_artifacts.contains(required),
            "missing input artifact {required}"
        );
        assert!(root.join(required).is_file(), "missing file {required}");
    }

    let selection = contract
        .get("selection_policy")
        .ok_or_else(|| test_error("selection_policy missing"))?;
    assert_eq!(
        selection["coverage_wave_count"].as_u64(),
        Some(8),
        "coverage wave count should stay aligned with checker expectations"
    );
    assert_eq!(
        string_set(selection, "allowed_candidate_statuses", "selection_policy")?,
        BTreeSet::from(["Implemented".to_string(), "RawSyscall".to_string()])
    );

    let context = contract
        .get("current_gate_context")
        .ok_or_else(|| test_error("current_gate_context missing"))?;
    assert_eq!(
        string_field(context, "claim_gate_decision", "current_gate_context")?,
        "blocked"
    );
    assert_eq!(context["missing_export_count"].as_u64(), Some(5));
    assert_eq!(
        context["hardened_coverage_gap_group_count"].as_u64(),
        Some(4)
    );

    let export_wave = contract
        .get("export_parity_wave")
        .ok_or_else(|| test_error("export_parity_wave missing"))?;
    assert_eq!(
        string_field(export_wave, "wave_id", "export_parity_wave")?,
        "wave-00-version-script-export-parity"
    );
    assert_eq!(
        string_set(export_wave, "symbols", "export_parity_wave")?,
        BTreeSet::from([
            "_IO_2_1_stderr_".to_string(),
            "_IO_2_1_stdin_".to_string(),
            "_IO_2_1_stdout_".to_string(),
            "__ns_name_uncompressed_p".to_string(),
            "__ns_samename".to_string(),
        ])
    );

    let coverage_waves = array_field(&contract, "coverage_waves", "contract")?;
    assert_eq!(coverage_waves.len(), 8);
    assert_eq!(
        string_field(&coverage_waves[0], "campaign_id", "coverage_waves[0]")?,
        "fcq-unistd-process-filesystem"
    );
    assert_eq!(
        string_field(&coverage_waves[1], "campaign_id", "coverage_waves[1]")?,
        "fcq-stdio-libio"
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
        "top_blocker_symbol_coverage_wave_plan.report.v1"
    );
    assert_eq!(string_field(&report, "bead", "report")?, "bd-0agsk.18");
    assert_eq!(string_field(&report, "mode", "report")?, "validate-only");
    assert_eq!(string_field(&report, "outcome", "report")?, "pass");
    assert_eq!(
        string_field(&report, "failure_signature", "report")?,
        "none"
    );
    assert_eq!(report["summary"]["coverage_wave_count"].as_u64(), Some(8));
    assert_eq!(
        report["summary"]["export_missing_symbols"].as_u64(),
        Some(5)
    );
    assert_eq!(
        report["summary"]["hardened_gap_prerequisites"].as_u64(),
        Some(4)
    );

    let events = load_jsonl(&log_path(&out_dir))?;
    assert_eq!(events.len(), 1);
    assert_eq!(
        string_field(&events[0], "event", "log")?,
        "top_blocker_symbol_coverage_wave_plan_validated"
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
    contract["schema_version"] = Value::String("top_blocker_symbol_coverage_wave_plan.v0".into());
    let mutated = out_dir.join("top_blocker_symbol_coverage_wave_plan.schema_drift.json");
    write_json(&mutated, &contract)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    expect_checker_failure(&output)?;

    let report = load_json(&report_path(&out_dir))?;
    assert_eq!(string_field(&report, "outcome", "report")?, "fail");
    assert_eq!(
        string_field(&report, "failure_signature", "report")?,
        "schema_version"
    );
    assert_eq!(
        string_field(&report, "contract", "report")?,
        mutated.to_string_lossy().as_ref()
    );

    let events = load_jsonl(&log_path(&out_dir))?;
    assert_eq!(events.len(), 1);
    assert_eq!(
        string_field(&events[0], "event", "log")?,
        "top_blocker_symbol_coverage_wave_plan_failed"
    );
    assert_eq!(
        string_field(&events[0], "failure_signature", "log")?,
        "schema_version"
    );

    Ok(())
}
