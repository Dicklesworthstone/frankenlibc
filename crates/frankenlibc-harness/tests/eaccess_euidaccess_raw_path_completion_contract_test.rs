use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn test_error(message: impl Into<String>) -> Box<dyn std::error::Error> {
    message.into().into()
}

fn workspace_root() -> TestResult<PathBuf> {
    Ok(PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| test_error("cannot resolve workspace root"))?
        .to_path_buf())
}

fn manifest_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/eaccess_euidaccess_raw_path_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_eaccess_euidaccess_raw_path_completion_contract.sh")
}

fn load_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn unique_output_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| test_error(format!("system time before epoch: {err}")))?
        .as_nanos();
    let dir = root.join("target/conformance").join(format!(
        "eaccess-euidaccess-{label}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn run_checker(root: &Path, manifest: &Path, out_dir: &Path) -> TestResult<Output> {
    Command::new(checker_path(root))
        .env("FRANKENLIBC_EACCESS_EUIDACCESS_CONTRACT", manifest)
        .env("FRANKENLIBC_EACCESS_EUIDACCESS_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_EACCESS_EUIDACCESS_REPORT",
            out_dir.join("report.json"),
        )
        .env(
            "FRANKENLIBC_EACCESS_EUIDACCESS_LOG",
            out_dir.join("events.jsonl"),
        )
        .output()
        .map_err(|err| test_error(format!("failed to run checker: {err}")))
}

fn object_field<'a>(
    value: &'a Value,
    field: &str,
) -> TestResult<&'a serde_json::Map<String, Value>> {
    value
        .get(field)
        .and_then(Value::as_object)
        .ok_or_else(|| test_error(format!("{field} must be an object")))
}

fn string_set(value: &Value) -> TestResult<BTreeSet<String>> {
    value
        .as_array()
        .ok_or_else(|| test_error("value should be array"))?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| test_error("array item should be string"))
        })
        .collect::<Result<BTreeSet<_>, _>>()
}

fn read_log_events(path: &Path) -> TestResult<BTreeSet<String>> {
    fs::read_to_string(path)?
        .lines()
        .map(|line| {
            let value: Value = serde_json::from_str(line)?;
            value["event"]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| test_error("log row missing event"))
        })
        .collect()
}

#[test]
fn contract_anchors_eaccess_euidaccess_completion_debt() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    assert_eq!(
        manifest["manifest_id"].as_str(),
        Some("eaccess-euidaccess-raw-path-completion-contract")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-2vv.26"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-2vv.26.1")
    );

    let evidence = object_field(&manifest, "completion_debt_evidence")?;
    assert_eq!(
        string_set(&evidence["missing_items_closed"])?,
        BTreeSet::from(["tests.unit.primary".to_string()])
    );
    assert!(
        evidence["next_audit_score_threshold"]
            .as_u64()
            .is_some_and(|threshold| threshold >= 800)
    );
    Ok(())
}

#[test]
fn raw_path_expectations_bind_eaccess_to_faccessat_at_eaccess() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let expectations = object_field(&manifest, "raw_path_expectations")?;
    assert_eq!(
        expectations["expected_support_status"].as_str(),
        Some("RawSyscall")
    );
    assert_eq!(
        expectations["eaccess_route"].as_str(),
        Some("faccessat(AT_FDCWD, path, mode, AT_EACCESS)")
    );
    assert_eq!(
        expectations["euidaccess_route"].as_str(),
        Some("eaccess(path, mode)")
    );
    assert_eq!(
        string_set(&expectations["symbols"])?,
        BTreeSet::from(["eaccess".to_string(), "euidaccess".to_string()])
    );
    Ok(())
}

#[test]
fn source_artifacts_bind_raw_path_and_unit_evidence() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let artifacts = manifest["source_artifacts"]
        .as_array()
        .ok_or_else(|| test_error("source_artifacts should be array"))?;
    assert_eq!(artifacts.len(), 5);

    for artifact in artifacts {
        let path = artifact["path"]
            .as_str()
            .ok_or_else(|| test_error("artifact path should be string"))?;
        let text = fs::read_to_string(root.join(path))?;
        for needle in artifact["required_needles"]
            .as_array()
            .ok_or_else(|| test_error("required_needles should be array"))?
        {
            let needle = needle
                .as_str()
                .ok_or_else(|| test_error("needle should be string"))?;
            assert!(
                text.contains(needle),
                "{path} should contain required needle {needle}"
            );
        }
        if let Some(forbidden) = artifact["forbidden_needles"].as_array() {
            for needle in forbidden {
                let needle = needle
                    .as_str()
                    .ok_or_else(|| test_error("forbidden needle should be string"))?;
                assert!(
                    !text.contains(needle),
                    "{path} should not contain host delegation marker {needle}"
                );
            }
        }
    }
    Ok(())
}

#[test]
fn checker_accepts_contract_and_emits_report() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "pass")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    assert!(
        output.status.success(),
        "checker failed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("eaccess_euidaccess_raw_path_completion_contract: PASS"));

    let report = load_json(&out_dir.join("report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["source_count"].as_u64(), Some(5));
    assert_eq!(
        string_set(&report["missing_items_closed"])?,
        BTreeSet::from(["tests.unit.primary".to_string()])
    );

    let events = read_log_events(&out_dir.join("events.jsonl"))?;
    for event in [
        "eaccess_euidaccess_source",
        "eaccess_euidaccess_unit_binding",
        "eaccess_euidaccess_completion_summary",
    ] {
        assert!(events.contains(event), "telemetry log missing {event}");
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_unit_test_ref() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-unit-ref")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["completion_debt_evidence"]["unit_primary"]["required_test_refs"][0]["name"] =
        json!("missing_eaccess_euidaccess_unit_test");
    let bad_manifest = out_dir.join("bad_contract.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker unexpectedly accepted missing unit test ref"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("missing_eaccess_euidaccess_unit_test"));
    Ok(())
}

#[test]
fn checker_rejects_missing_raw_path_needle() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-raw-path")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["source_artifacts"][0]["required_needles"] =
        json!(["nonexistent_eaccess_raw_path_marker"]);
    let bad_manifest = out_dir.join("bad_contract.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker unexpectedly accepted missing raw-path needle"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("nonexistent_eaccess_raw_path_marker"));
    Ok(())
}

#[test]
fn checker_rejects_missing_unit_item() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-unit-item")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["completion_debt_evidence"]["missing_items_closed"] = json!([]);
    let bad_manifest = out_dir.join("bad_contract.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker unexpectedly accepted missing unit item"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("missing_items_closed must be"));
    Ok(())
}
