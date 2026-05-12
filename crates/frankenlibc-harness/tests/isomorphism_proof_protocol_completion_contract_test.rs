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
    root.join("tests/conformance/isomorphism_proof_protocol_completion_contract.v1.json")
}

fn protocol_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/isomorphism_proof_protocol.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_isomorphism_proof_protocol_completion_contract.sh")
}

fn load_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
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

fn unique_output_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| test_error(format!("system time before epoch: {err}")))?
        .as_nanos();
    let dir = root
        .join("target/conformance")
        .join(format!("{label}-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn run_checker(root: &Path, manifest: &Path, out_dir: &Path) -> TestResult<Output> {
    Command::new(checker_path(root))
        .env("FRANKENLIBC_ISOMORPHISM_PROTOCOL_CONTRACT", manifest)
        .env("FRANKENLIBC_ISOMORPHISM_PROTOCOL_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_ISOMORPHISM_PROTOCOL_REPORT",
            out_dir.join("report.json"),
        )
        .env(
            "FRANKENLIBC_ISOMORPHISM_PROTOCOL_LOG",
            out_dir.join("events.jsonl"),
        )
        .output()
        .map_err(|err| test_error(format!("failed to run checker: {err}")))
}

#[test]
fn contract_anchors_completion_debt() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    assert_eq!(
        manifest["manifest_id"].as_str(),
        Some("isomorphism-proof-protocol-completion-contract")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-2bd"));
    assert_eq!(manifest["completion_debt_bead"].as_str(), Some("bd-2bd.1"));

    let evidence = object_field(&manifest, "completion_debt_evidence")?;
    assert_eq!(
        string_set(&evidence["missing_items_closed"])?,
        BTreeSet::from([
            "telemetry.primary".to_string(),
            "tests.e2e.primary".to_string(),
            "tests.golden.primary".to_string(),
            "tests.unit.primary".to_string(),
        ])
    );
    assert!(
        evidence["next_audit_score_threshold"]
            .as_u64()
            .is_some_and(|threshold| threshold >= 800)
    );
    Ok(())
}

#[test]
fn protocol_expectations_match_golden_artifact() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    let protocol = load_json(&protocol_path(&root))?;
    let expectations = object_field(&manifest, "protocol_expectations")?;
    let categories = string_set(&expectations["required_categories"])?;
    let protocol_categories = protocol["proof_categories"]
        .as_object()
        .ok_or_else(|| test_error("protocol proof_categories must be object"))?
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    assert_eq!(protocol_categories, categories);

    let template_fields = string_set(&expectations["required_template_fields"])?;
    let protocol_fields = string_set(&protocol["proof_template"]["required_fields"])?;
    assert!(
        template_fields.is_subset(&protocol_fields),
        "protocol template lost required fields"
    );

    let proofs = expectations["required_existing_proofs"]
        .as_array()
        .ok_or_else(|| test_error("required_existing_proofs must be array"))?;
    assert_eq!(proofs.len(), 3);
    for proof in proofs {
        let path = proof["proof_path"]
            .as_str()
            .ok_or_else(|| test_error("proof_path missing"))?;
        assert!(root.join(path).is_file(), "required proof missing: {path}");
    }
    Ok(())
}

#[test]
fn checker_accepts_contract_and_emits_telemetry() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "isomorphism-protocol")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    assert!(
        output.status.success(),
        "checker failed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("isomorphism_proof_protocol_completion_contract: PASS"));

    let report = load_json(&out_dir.join("report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["category_count"].as_u64(), Some(6));
    assert_eq!(report["proof_count"].as_u64(), Some(3));

    let log = fs::read_to_string(out_dir.join("events.jsonl"))?;
    for event in [
        "isomorphism_protocol_source",
        "isomorphism_protocol_template",
        "isomorphism_protocol_proof",
        "isomorphism_protocol_e2e",
        "isomorphism_protocol_summary",
    ] {
        assert!(log.contains(event), "telemetry log missing {event}");
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_required_category() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "isomorphism-missing-category")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let categories = manifest["protocol_expectations"]["required_categories"]
        .as_array_mut()
        .ok_or_else(|| test_error("required_categories should be array"))?;
    categories.retain(|category| category.as_str() != Some("memory_semantics"));
    let bad_manifest = out_dir.join("bad_contract.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker unexpectedly accepted missing required category"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("protocol categories must be exactly"));
    Ok(())
}

#[test]
fn checker_rejects_disabled_e2e_gate() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "isomorphism-disabled-e2e")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["e2e_gate"]["command"] = json!("true");
    let bad_manifest = out_dir.join("bad_contract.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker unexpectedly accepted disabled e2e gate"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("e2e_gate.command must remain"));
    Ok(())
}

#[test]
fn checker_rejects_missing_telemetry_item() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "isomorphism-missing-telemetry")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let missing = manifest["completion_debt_evidence"]["missing_items_closed"]
        .as_array_mut()
        .ok_or_else(|| test_error("missing_items_closed should be array"))?;
    missing.retain(|item| item.as_str() != Some("telemetry.primary"));
    let bad_manifest = out_dir.join("bad_contract.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker unexpectedly accepted missing telemetry closure"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("missing_items_closed must be"));
    Ok(())
}
