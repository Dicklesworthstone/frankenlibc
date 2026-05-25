//! Completion-contract tests for bd-1ff3.1 hard-parts unit-pack evidence.

use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const REQUIRED_SUBSYSTEMS: &[&str] = &["startup", "setjmp", "iconv", "nss"];
const REQUIRED_EVENTS: &[&str] = &[
    "source_artifacts_validated",
    "subsystem_unit_packs_validated",
    "fixture_cases_validated",
    "missing_item_bindings_validated",
    "hard_parts_unit_packs_completion_contract_validated",
];

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
    root.join("tests/conformance/hard_parts_unit_packs_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_hard_parts_unit_packs_completion_contract.sh")
}

fn load_json(path: &Path) -> TestResult<Value> {
    let content = std::fs::read_to_string(path)
        .map_err(|err| test_error(format!("{} should be readable: {err}", path.display())))?;
    serde_json::from_str(&content)
        .map_err(|err| test_error(format!("{} should parse as JSON: {err}", path.display())))
}

fn load_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    let mut rows = Vec::new();
    for line in std::fs::read_to_string(path)?.lines() {
        if line.trim().is_empty() {
            continue;
        }
        rows.push(serde_json::from_str(line)?);
    }
    Ok(rows)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    std::fs::write(path, format!("{}\n", serde_json::to_string_pretty(value)?))?;
    Ok(())
}

fn unique_output_dir(root: &Path, prefix: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| test_error(format!("system clock should be after Unix epoch: {err}")))?
        .as_nanos();
    let path = root
        .join("target/conformance")
        .join(format!("{prefix}-{}-{stamp}", std::process::id()));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn field<'a>(value: &'a Value, key: &str, context: &str) -> TestResult<&'a Value> {
    value
        .get(key)
        .ok_or_else(|| test_error(format!("{context}.{key} is missing")))
}

fn string_field<'a>(value: &'a Value, key: &str, context: &str) -> TestResult<&'a str> {
    field(value, key, context)?
        .as_str()
        .ok_or_else(|| test_error(format!("{context}.{key} must be a string")))
}

fn array_field<'a>(value: &'a Value, key: &str, context: &str) -> TestResult<&'a Vec<Value>> {
    field(value, key, context)?
        .as_array()
        .ok_or_else(|| test_error(format!("{context}.{key} must be an array")))
}

fn run_checker(root: &Path, manifest: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_HARD_PARTS_UNIT_PACKS_CONTRACT", manifest)
        .env("FRANKENLIBC_HARD_PARTS_UNIT_PACKS_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_HARD_PARTS_UNIT_PACKS_REPORT",
            out_dir.join("hard_parts_unit_packs_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_HARD_PARTS_UNIT_PACKS_LOG",
            out_dir.join("hard_parts_unit_packs_completion_contract.log.jsonl"),
        )
        .output()?)
}

fn checker_report(out_dir: &Path) -> PathBuf {
    out_dir.join("hard_parts_unit_packs_completion_contract.report.json")
}

fn checker_log(out_dir: &Path) -> PathBuf {
    out_dir.join("hard_parts_unit_packs_completion_contract.log.jsonl")
}

fn expect_checker_success(output: &Output) -> TestResult {
    if output.status.success() {
        return Ok(());
    }
    Err(test_error(format!(
        "checker failed stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )))
}

fn expect_checker_failure(output: &Output) -> TestResult {
    if !output.status.success() {
        return Ok(());
    }
    Err(test_error(format!(
        "checker unexpectedly passed stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )))
}

fn write_mutated_manifest(
    root: &Path,
    prefix: &str,
    manifest: &Value,
) -> TestResult<(PathBuf, PathBuf)> {
    let out_dir = unique_output_dir(root, prefix)?;
    let path = out_dir.join("manifest.json");
    write_json(&path, manifest)?;
    Ok((path, out_dir))
}

fn failure_signatures(report: &Value) -> BTreeSet<&str> {
    report
        .get("errors")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|row| row.get("failure_signature").and_then(Value::as_str))
        .collect()
}

#[test]
fn manifest_binds_bd_1ff3_unit_pack_sources() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    assert_eq!(
        string_field(&manifest, "schema_version", "manifest")?,
        "hard_parts_unit_packs_completion_contract.v1"
    );
    assert_eq!(string_field(&manifest, "bead_id", "manifest")?, "bd-1ff3.1");
    assert_eq!(
        string_field(&manifest, "original_bead", "manifest")?,
        "bd-1ff3"
    );
    assert_eq!(
        string_field(&manifest, "trace_id", "manifest")?,
        "bd-1ff3.1::hard-parts-unit-packs::v1"
    );

    for artifact in array_field(&manifest, "source_artifacts", "manifest")? {
        let path = string_field(artifact, "path", "source_artifacts[]")?;
        assert!(root.join(path).is_file(), "missing source artifact {path}");
    }
    Ok(())
}

#[test]
fn manifest_covers_startup_nss_iconv_setjmp() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let contract = field(&manifest, "unit_pack_contract", "manifest")?;
    let subsystems = array_field(contract, "required_subsystems", "unit_pack_contract")?;
    let ids: BTreeSet<_> = subsystems
        .iter()
        .filter_map(|row| row.get("id").and_then(Value::as_str))
        .collect();
    for required in REQUIRED_SUBSYSTEMS {
        assert!(ids.contains(required), "missing subsystem {required}");
    }
    let test_count: usize = subsystems
        .iter()
        .map(|row| {
            row.get("required_tests")
                .and_then(Value::as_array)
                .map_or(0, Vec::len)
        })
        .sum();
    assert_eq!(test_count, 42);
    Ok(())
}

#[test]
fn checker_accepts_unit_pack_contract() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "hard-parts-unit-packs-ok")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    expect_checker_success(&output)?;

    let report = load_json(&checker_report(&out_dir))?;
    assert_eq!(string_field(&report, "status", "report")?, "pass");
    let summary = field(&report, "summary", "report")?;
    assert_eq!(
        field(summary, "subsystem_count", "summary")?.as_u64(),
        Some(4)
    );
    assert_eq!(
        field(summary, "unit_test_count", "summary")?.as_u64(),
        Some(42)
    );
    assert_eq!(
        field(summary, "fixture_case_count", "summary")?.as_u64(),
        Some(17)
    );

    let rows = load_jsonl(&checker_log(&out_dir))?;
    let events: BTreeSet<_> = rows
        .iter()
        .filter_map(|row| row.get("event").and_then(Value::as_str))
        .collect();
    for required in REQUIRED_EVENTS {
        assert!(events.contains(required), "missing event {required}");
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_startup_unit_test() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let subsystems = manifest
        .pointer_mut("/unit_pack_contract/required_subsystems")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("required_subsystems should exist"))?;
    let startup = subsystems
        .iter_mut()
        .find(|row| row.get("id").and_then(Value::as_str) == Some("startup"))
        .ok_or_else(|| test_error("startup subsystem should exist"))?;
    let tests = startup
        .get_mut("required_tests")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("startup tests should exist"))?;
    tests.retain(|name| name.as_str() != Some("startup_phase0_rejects_missing_main"));

    let (manifest_path, out_dir) =
        write_mutated_manifest(&root, "hard-parts-unit-packs-no-test", &manifest)?;
    let output = run_checker(&root, &manifest_path, &out_dir)?;
    expect_checker_failure(&output)?;
    let report = load_json(&checker_report(&out_dir))?;
    assert!(failure_signatures(&report).contains("missing_unit_test"));
    Ok(())
}

#[test]
fn checker_rejects_missing_subsystem() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let subsystems = manifest
        .pointer_mut("/unit_pack_contract/required_subsystems")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("required_subsystems should exist"))?;
    subsystems.retain(|row| row.get("id").and_then(Value::as_str) != Some("setjmp"));

    let (manifest_path, out_dir) =
        write_mutated_manifest(&root, "hard-parts-unit-packs-no-subsystem", &manifest)?;
    let output = run_checker(&root, &manifest_path, &out_dir)?;
    expect_checker_failure(&output)?;
    let report = load_json(&checker_report(&out_dir))?;
    assert!(failure_signatures(&report).contains("missing_subsystem_coverage"));
    Ok(())
}

#[test]
fn checker_rejects_missing_fixture_case() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let subsystems = manifest
        .pointer_mut("/unit_pack_contract/required_subsystems")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("required_subsystems should exist"))?;
    let nss = subsystems
        .iter_mut()
        .find(|row| row.get("id").and_then(Value::as_str) == Some("nss"))
        .ok_or_else(|| test_error("nss subsystem should exist"))?;
    let fixtures = nss
        .get_mut("fixture_cases")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("nss fixture cases should exist"))?;
    fixtures.retain(|row| {
        row.get("case").and_then(Value::as_str) != Some("hosts_lookup_inline_comments_and_aliases")
    });

    let (manifest_path, out_dir) =
        write_mutated_manifest(&root, "hard-parts-unit-packs-no-fixture", &manifest)?;
    let output = run_checker(&root, &manifest_path, &out_dir)?;
    expect_checker_failure(&output)?;
    let report = load_json(&checker_report(&out_dir))?;
    assert!(failure_signatures(&report).contains("missing_fixture_case"));
    Ok(())
}

#[test]
fn checker_rejects_missing_unit_binding() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["missing_item_bindings"] = json!([]);

    let (manifest_path, out_dir) =
        write_mutated_manifest(&root, "hard-parts-unit-packs-no-binding", &manifest)?;
    let output = run_checker(&root, &manifest_path, &out_dir)?;
    expect_checker_failure(&output)?;
    let report = load_json(&checker_report(&out_dir))?;
    assert!(failure_signatures(&report).contains("missing_completion_binding"));
    Ok(())
}
