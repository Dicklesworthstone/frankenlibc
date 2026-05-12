//! Gentoo ecosystem validation parent completion contract (bd-2icq / bd-2icq.25).

use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const REQUIRED_BINDINGS: &[&str] = &[
    "tests.unit.primary",
    "tests.e2e.primary",
    "tests.fuzz.primary",
    "tests.conformance.primary",
    "telemetry.primary",
];

const REQUIRED_EVENTS: &[&str] = &[
    "gentoo_ecosystem_validation.source_artifact",
    "gentoo_ecosystem_validation.missing_item_binding",
    "gentoo_ecosystem_validation.required_test_ref",
    "gentoo_ecosystem_validation.telemetry_contract",
    "gentoo_ecosystem_validation.validated",
];

fn test_error(message: impl Into<String>) -> Box<dyn std::error::Error> {
    Box::new(std::io::Error::other(message.into()))
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
    root.join("tests/conformance/gentoo_ecosystem_validation_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_gentoo_ecosystem_validation_completion_contract.sh")
}

fn load_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
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

fn unique_output_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| test_error(format!("system clock should be after Unix epoch: {err}")))?
        .as_nanos();
    let path = root.join("target/conformance").join(format!(
        "gentoo-ecosystem-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn string_field<'a>(value: &'a Value, field: &str) -> TestResult<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| test_error(format!("missing string field {field}")))
}

fn array_field<'a>(value: &'a Value, field: &str) -> TestResult<&'a Vec<Value>> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| test_error(format!("missing array field {field}")))
}

fn string_set(value: &Value) -> TestResult<BTreeSet<String>> {
    value
        .as_array()
        .ok_or_else(|| test_error("expected array"))?
        .iter()
        .map(|item| {
            item.as_str()
                .ok_or_else(|| test_error("expected string"))
                .map(str::to_owned)
        })
        .collect()
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_GENTOO_ECOSYSTEM_CONTRACT", contract)
        .env("FRANKENLIBC_GENTOO_ECOSYSTEM_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_GENTOO_ECOSYSTEM_REPORT",
            out_dir.join("report.json"),
        )
        .env(
            "FRANKENLIBC_GENTOO_ECOSYSTEM_LOG",
            out_dir.join("events.jsonl"),
        )
        .output()?)
}

fn output_text(output: &Output) -> String {
    format!(
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn mutated_manifest(root: &Path, label: &str, manifest: &Value) -> TestResult<(PathBuf, PathBuf)> {
    let out_dir = unique_output_dir(root, label)?;
    let path = out_dir.join("contract.json");
    write_json(&path, manifest)?;
    Ok((path, out_dir))
}

#[test]
fn manifest_anchors_bd2icq25_missing_items() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    assert_eq!(
        string_field(&manifest, "schema_version")?,
        "gentoo_ecosystem_validation_completion_contract.v1"
    );
    assert_eq!(
        string_field(&manifest, "manifest_id")?,
        "gentoo-ecosystem-validation-completion-contract"
    );
    assert_eq!(string_field(&manifest, "bead")?, "bd-2icq");
    assert_eq!(
        string_field(&manifest, "completion_debt_bead")?,
        "bd-2icq.25"
    );

    let expected: BTreeSet<_> = REQUIRED_BINDINGS
        .iter()
        .map(|item| (*item).to_owned())
        .collect();
    assert_eq!(
        string_set(
            manifest
                .get("required_missing_items")
                .ok_or_else(|| test_error("missing required_missing_items"))?
        )?,
        expected
    );
    Ok(())
}

#[test]
fn source_artifacts_are_file_backed() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let artifacts = array_field(&manifest, "source_artifacts")?;
    assert!(
        artifacts.len() >= 12,
        "parent contract should bind the full Gentoo lane"
    );
    for artifact in artifacts {
        let path = root.join(string_field(artifact, "path")?);
        assert!(path.is_file(), "{} missing", path.display());
        assert!(
            !array_field(artifact, "line_refs")?.is_empty(),
            "{} should carry closeout line refs",
            string_field(artifact, "id")?
        );
        assert!(
            !array_field(artifact, "required_needles")?.is_empty(),
            "{} should carry drift needles",
            string_field(artifact, "id")?
        );
    }
    Ok(())
}

#[test]
fn evidence_bindings_cover_unit_e2e_fuzz_conformance_and_telemetry() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let bindings = array_field(&manifest, "evidence_bindings")?;
    let ids: BTreeSet<_> = bindings
        .iter()
        .filter_map(|binding| binding.get("id").and_then(Value::as_str))
        .collect();

    for required in REQUIRED_BINDINGS {
        assert!(ids.contains(required), "missing binding {required}");
    }

    let fuzz = bindings
        .iter()
        .find(|binding| binding.get("id").and_then(Value::as_str) == Some("tests.fuzz.primary"))
        .ok_or_else(|| test_error("missing fuzz binding"))?;
    let targets: BTreeSet<_> = array_field(fuzz, "required_targets")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for required in ["fuzz_string", "fuzz_malloc", "fuzz_membrane", "fuzz_printf"] {
        assert!(targets.contains(required), "missing fuzz target {required}");
    }
    Ok(())
}

#[test]
fn checker_accepts_contract_and_emits_report_log() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "accepts")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    assert!(
        output.status.success(),
        "checker failed: {}",
        output_text(&output)
    );

    let report = load_json(&out_dir.join("report.json"))?;
    assert_eq!(string_field(&report, "status")?, "pass");
    assert_eq!(string_field(&report, "bead")?, "bd-2icq");
    assert_eq!(string_field(&report, "completion_debt_bead")?, "bd-2icq.25");
    assert_eq!(
        string_set(
            report
                .get("missing_items_bound")
                .ok_or_else(|| test_error("missing missing_items_bound"))?
        )?,
        REQUIRED_BINDINGS
            .iter()
            .map(|item| (*item).to_owned())
            .collect()
    );

    let rows = load_jsonl(&out_dir.join("events.jsonl"))?;
    let events: BTreeSet<_> = rows
        .iter()
        .filter_map(|row| row.get("event").and_then(Value::as_str))
        .collect();
    for required in REQUIRED_EVENTS {
        assert!(
            events.contains(required),
            "missing telemetry event {required}"
        );
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_fuzz_binding() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["evidence_bindings"]
        .as_array_mut()
        .ok_or_else(|| test_error("evidence_bindings should be an array"))?
        .retain(|binding| binding.get("id").and_then(Value::as_str) != Some("tests.fuzz.primary"));
    let (path, out_dir) = mutated_manifest(&root, "missing-fuzz", &manifest)?;
    let output = run_checker(&root, &path, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker accepted missing fuzz binding"
    );
    assert!(output_text(&output).contains("tests.fuzz.primary"));
    Ok(())
}

#[test]
fn checker_rejects_missing_source_artifact() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["source_artifacts"]
        .as_array_mut()
        .ok_or_else(|| test_error("source_artifacts should be an array"))?
        .retain(|artifact| {
            artifact.get("id").and_then(Value::as_str) != Some("gentoo_telemetry_contract")
        });
    let (path, out_dir) = mutated_manifest(&root, "missing-source", &manifest)?;
    let output = run_checker(&root, &path, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker accepted missing source artifact"
    );
    assert!(output_text(&output).contains("gentoo_telemetry_contract"));
    Ok(())
}

#[test]
fn checker_rejects_missing_telemetry_event() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let events = manifest["telemetry_contract"]["required_events"]
        .as_array_mut()
        .ok_or_else(|| test_error("required_events should be an array"))?;
    events.retain(|event| event.as_str() != Some("gentoo_ecosystem_validation.validated"));
    events.push(json!("gentoo_ecosystem_validation.synthetic_placeholder"));
    let (path, out_dir) = mutated_manifest(&root, "missing-event", &manifest)?;
    let output = run_checker(&root, &path, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker accepted missing telemetry event"
    );
    assert!(output_text(&output).contains("validated"));
    Ok(())
}
