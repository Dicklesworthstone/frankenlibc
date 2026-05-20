use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
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

fn manifest_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/cli_contract_gate_inventory.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_cli_contract_gate_inventory.sh")
}

fn report_path(out_dir: &Path) -> PathBuf {
    out_dir.join("cli_contract_gate_inventory.report.json")
}

fn log_path(out_dir: &Path) -> PathBuf {
    out_dir.join("cli_contract_gate_inventory.log.jsonl")
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
        "cli_contract_gate_inventory_{label}_{}_{}",
        std::process::id(),
        stamp
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn relative_path(root: &Path, path: &Path) -> TestResult<String> {
    Ok(path
        .strip_prefix(root)
        .map_err(|err| {
            test_error(format!(
                "{} should live below {}: {err}",
                path.display(),
                root.display()
            ))
        })?
        .to_string_lossy()
        .replace('\\', "/"))
}

fn string_field<'a>(value: &'a Value, key: &str, context: &str) -> TestResult<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| test_error(format!("{context}.{key} must be a string")))
}

fn u64_field(value: &Value, key: &str, context: &str) -> TestResult<u64> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| test_error(format!("{context}.{key} must be an unsigned integer")))
}

fn object_field<'a>(
    value: &'a Value,
    key: &str,
    context: &str,
) -> TestResult<&'a serde_json::Map<String, Value>> {
    value
        .get(key)
        .and_then(Value::as_object)
        .ok_or_else(|| test_error(format!("{context}.{key} must be an object")))
}

fn array_field<'a>(value: &'a Value, key: &str, context: &str) -> TestResult<&'a Vec<Value>> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| test_error(format!("{context}.{key} must be an array")))
}

fn string_set_field(value: &Value, key: &str, context: &str) -> TestResult<BTreeSet<String>> {
    array_field(value, key, context)?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| test_error(format!("{context}.{key} entries must be strings")))
        })
        .collect::<Result<_, _>>()
}

fn run_checker(root: &Path, manifest: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .env("FRANKENLIBC_CLI_CONTRACT_GATE_INVENTORY", manifest)
        .env("FRANKENLIBC_CLI_CONTRACT_GATE_INVENTORY_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_CLI_CONTRACT_GATE_INVENTORY_REPORT",
            report_path(out_dir),
        )
        .env(
            "FRANKENLIBC_CLI_CONTRACT_GATE_INVENTORY_LOG",
            log_path(out_dir),
        )
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

fn candidate_statuses(report: &Value) -> TestResult<BTreeMap<String, String>> {
    let mut statuses = BTreeMap::new();
    for row in array_field(report, "candidate_invariants", "report")? {
        statuses.insert(
            string_field(row, "id", "candidate")?.to_owned(),
            string_field(row, "status", "candidate")?.to_owned(),
        );
    }
    Ok(statuses)
}

fn failure_signatures(report: &Value) -> TestResult<BTreeSet<String>> {
    array_field(report, "failures", "report")?
        .iter()
        .map(|failure| string_field(failure, "failure_signature", "failure").map(str::to_owned))
        .collect::<Result<_, _>>()
}

#[test]
fn manifest_binds_cli_inventory_contract_and_candidate_beads() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;

    assert_eq!(
        string_field(&manifest, "schema_version", "manifest")?,
        "cli_contract_gate_inventory.v1"
    );
    assert!(
        checker_path(&root).is_file(),
        "missing CLI contract gate inventory checker"
    );

    let scanner = object_field(&manifest, "scanner", "manifest")?;
    assert_eq!(
        scanner.get("tracked_glob").and_then(Value::as_str),
        Some("crates/frankenlibc-harness/tests/*cli_contract*test.rs")
    );
    assert_eq!(
        scanner.get("output_path").and_then(Value::as_str),
        Some("target/conformance/cli_contract_gate_inventory.report.json")
    );
    assert_eq!(
        scanner.get("log_path").and_then(Value::as_str),
        Some("target/conformance/cli_contract_gate_inventory.log.jsonl")
    );
    assert!(
        scanner
            .get("minimum_tracked_gate_count")
            .and_then(Value::as_u64)
            .is_some_and(|count| count >= 200)
    );

    let candidates = array_field(&manifest, "candidate_invariants", "manifest")?;
    let candidate_ids = candidates
        .iter()
        .map(|row| string_field(row, "id", "candidate").map(str::to_owned))
        .collect::<Result<BTreeSet<_>, _>>()?;
    assert_eq!(
        candidate_ids,
        BTreeSet::from([
            "no_current_dir_mutation".to_owned(),
            "no_env_set_var".to_owned(),
            "no_network_socket".to_owned(),
            "no_process_kill".to_owned(),
            "paired_gate_file_contract".to_owned(),
        ])
    );

    let tracker_by_id = candidates
        .iter()
        .map(|row| {
            Ok((
                string_field(row, "id", "candidate")?.to_owned(),
                row.get("tracker_bead_id")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            ))
        })
        .collect::<TestResult<BTreeMap<_, _>>>()?;
    assert_eq!(
        tracker_by_id.get("no_current_dir_mutation"),
        Some(&Some("bd-92g0t".to_owned()))
    );
    assert_eq!(
        tracker_by_id.get("no_network_socket"),
        Some(&Some("bd-e8xvs".to_owned()))
    );
    assert_eq!(
        tracker_by_id.get("no_process_kill"),
        Some(&Some("bd-gt20s".to_owned()))
    );

    let required_report_fields = string_set_field(&manifest, "required_report_fields", "manifest")?;
    for field in [
        "schema_version",
        "status",
        "source_commit",
        "report_path",
        "log_path",
        "tracked_gate_count",
        "dirty_pending_candidates",
        "candidate_invariants",
        "recommendations",
        "negative_controls",
        "failures",
    ] {
        assert!(
            required_report_fields.contains(field),
            "required_report_fields should include {field}"
        );
    }

    assert_eq!(
        string_set_field(&manifest, "required_negative_controls", "manifest")?,
        BTreeSet::from([
            "dirty_candidate_not_recommended".to_owned(),
            "duplicate_candidate_id_fails".to_owned(),
            "missing_report_field_fails".to_owned(),
            "tracked_gate_count_threshold_fails".to_owned(),
        ])
    );

    Ok(())
}

#[test]
fn checker_emits_isolated_pass_report_and_jsonl() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let min_tracked = manifest["scanner"]["minimum_tracked_gate_count"]
        .as_u64()
        .ok_or_else(|| test_error("scanner.minimum_tracked_gate_count missing"))?;
    let out_dir = unique_output_dir(&root, "pass")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    expect_checker_success(&output)?;

    let report = load_json(&report_path(&out_dir))?;
    assert_eq!(
        string_field(&report, "schema_version", "report")?,
        "cli_contract_gate_inventory.report.v1"
    );
    assert_eq!(string_field(&report, "status", "report")?, "pass");
    assert_eq!(
        string_field(&report, "report_path", "report")?,
        relative_path(&root, &report_path(&out_dir))?
    );
    assert_eq!(
        string_field(&report, "log_path", "report")?,
        relative_path(&root, &log_path(&out_dir))?
    );
    assert!(
        u64_field(&report, "tracked_gate_count", "report")? >= min_tracked,
        "tracked gate count should satisfy the manifest threshold"
    );
    assert!(array_field(&report, "dirty_pending_candidates", "report")?.is_empty());
    assert!(array_field(&report, "recommendations", "report")?.is_empty());
    assert!(array_field(&report, "failures", "report")?.is_empty());

    let statuses = candidate_statuses(&report)?;
    for candidate in [
        "no_env_set_var",
        "paired_gate_file_contract",
        "no_current_dir_mutation",
        "no_network_socket",
        "no_process_kill",
    ] {
        assert_eq!(
            statuses.get(candidate).map(String::as_str),
            Some("implemented_tracked"),
            "{candidate} should now be tracked rather than recommended"
        );
    }

    let controls = array_field(&report, "negative_controls", "report")?;
    let control_statuses = controls
        .iter()
        .map(|row| {
            Ok((
                string_field(row, "control_id", "negative_control")?.to_owned(),
                string_field(row, "status", "negative_control")?.to_owned(),
            ))
        })
        .collect::<TestResult<BTreeMap<_, _>>>()?;
    assert_eq!(
        control_statuses,
        BTreeMap::from([
            (
                "dirty_candidate_not_recommended".to_owned(),
                "pass".to_owned()
            ),
            ("duplicate_candidate_id_fails".to_owned(), "pass".to_owned()),
            ("missing_report_field_fails".to_owned(), "pass".to_owned()),
            (
                "tracked_gate_count_threshold_fails".to_owned(),
                "pass".to_owned(),
            ),
        ])
    );

    let events = load_jsonl(&log_path(&out_dir))?;
    assert_eq!(events.len(), 5);
    assert_eq!(
        string_field(&events[0], "event", "log")?,
        "cli_contract_gate_inventory"
    );
    assert_eq!(string_field(&events[0], "status", "log")?, "pass");
    assert_eq!(u64_field(&events[0], "recommendation_count", "log")?, 0);
    assert_eq!(u64_field(&events[0], "dirty_pending_count", "log")?, 0);
    for event in events.iter().skip(1) {
        assert_eq!(string_field(event, "event", "log")?, "negative_control");
        assert_eq!(string_field(event, "status", "log")?, "pass");
    }

    Ok(())
}

#[test]
fn checker_rejects_malformed_manifest_with_structured_failure() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "malformed")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["schema_version"] = Value::String("cli_contract_gate_inventory.v0".to_owned());
    let mutated = out_dir.join("cli_contract_gate_inventory.bad_schema.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    expect_checker_failure(&output)?;

    let report = load_json(&report_path(&out_dir))?;
    assert_eq!(string_field(&report, "status", "report")?, "fail");
    assert!(failure_signatures(&report)?.contains("schema_version"));
    assert_eq!(
        string_field(&report, "report_path", "report")?,
        relative_path(&root, &report_path(&out_dir))?
    );
    assert_eq!(
        string_field(&report, "log_path", "report")?,
        relative_path(&root, &log_path(&out_dir))?
    );

    let events = load_jsonl(&log_path(&out_dir))?;
    assert_eq!(events.len(), 5);
    assert_eq!(
        string_field(&events[0], "event", "log")?,
        "cli_contract_gate_inventory"
    );
    assert_eq!(string_field(&events[0], "status", "log")?, "fail");
    for event in events.iter().skip(1) {
        assert_eq!(string_field(event, "event", "log")?, "negative_control");
        assert_eq!(string_field(event, "status", "log")?, "pass");
    }

    Ok(())
}
