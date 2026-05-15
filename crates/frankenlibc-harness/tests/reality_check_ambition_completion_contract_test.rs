use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn repo_root() -> TestResult<PathBuf> {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("crate directory should have workspace parent")?;
    let root = crate_dir
        .parent()
        .ok_or("workspace parent should have repo parent")?;
    Ok(root.to_path_buf())
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/reality_check_ambition_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_reality_check_ambition_completion_contract.sh")
}

fn read_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn read_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    Ok(std::fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<Result<Vec<_>, _>>()?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn write_text(path: &Path, value: &str) -> TestResult {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, value)?;
    Ok(())
}

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let out = root.join("target/conformance").join(format!(
        "reality_check_ambition_completion_contract_{label}_{}_{}",
        std::process::id(),
        nanos
    ));
    std::fs::create_dir_all(&out)?;
    Ok(out)
}

fn repo_relative(root: &Path, path: &Path) -> TestResult<String> {
    Ok(path
        .strip_prefix(root)?
        .to_string_lossy()
        .replace(std::path::MAIN_SEPARATOR, "/"))
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_REALITY_CHECK_AMBITION_CONTRACT", contract)
        .env("FRANKENLIBC_REALITY_CHECK_AMBITION_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_REALITY_CHECK_AMBITION_REPORT",
            out_dir.join("reality_check_ambition_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_REALITY_CHECK_AMBITION_LOG",
            out_dir.join("reality_check_ambition_completion_contract.log.jsonl"),
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

fn function_exists(root: &Path, source_path: &str, name: &str) -> TestResult<bool> {
    let text = std::fs::read_to_string(root.join(source_path))?;
    Ok(text.contains(&format!("fn {name}(")) || text.contains(&format!("fn {name}<")))
}

fn string_set(value: &Value) -> TestResult<BTreeSet<String>> {
    json_array(value, "string set")?
        .iter()
        .map(|item| Ok(json_str(item, "string set item")?.to_owned()))
        .collect()
}

fn json_object<'a>(
    value: &'a Value,
    description: &str,
) -> TestResult<&'a serde_json::Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| format!("{description} must be object").into())
}

fn json_array<'a>(value: &'a Value, description: &str) -> TestResult<&'a Vec<Value>> {
    value
        .as_array()
        .ok_or_else(|| format!("{description} must be array").into())
}

fn json_array_mut<'a>(value: &'a mut Value, description: &str) -> TestResult<&'a mut Vec<Value>> {
    value
        .as_array_mut()
        .ok_or_else(|| format!("{description} must be mutable array").into())
}

fn json_str<'a>(value: &'a Value, description: &str) -> TestResult<&'a str> {
    value
        .as_str()
        .ok_or_else(|| format!("{description} must be string").into())
}

fn json_u64(value: &Value, description: &str) -> TestResult<u64> {
    value
        .as_u64()
        .ok_or_else(|| format!("{description} must be unsigned integer").into())
}

fn child_ids() -> [&'static str; 16] {
    [
        "bd-bp8fl.1",
        "bd-bp8fl.2",
        "bd-bp8fl.3",
        "bd-bp8fl.4",
        "bd-bp8fl.5",
        "bd-bp8fl.6",
        "bd-bp8fl.7",
        "bd-bp8fl.8",
        "bd-bp8fl.9",
        "bd-bp8fl.10",
        "bd-bp8fl.11",
        "bd-bp8fl.12",
        "bd-bp8fl.13",
        "bd-bp8fl.14",
        "bd-bp8fl.15",
        "bd-bp8fl.16",
    ]
}

fn current_parent_and_children_fixture() -> TestResult<String> {
    let mut rows = vec![json!({
        "id": "bd-bp8fl",
        "status": "closed",
        "acceptance_criteria": "Preserve the full reality-check closure program. bd-bp8fl.13 through bd-bp8fl.16 are cleanup children. Required test classes are named. Required deterministic evidence is named. Structured logs must include trace_id. Source-of-truth freshness checks are required. Claim gates must include positive and negative cases. Closure must state that no existing feature, function, artifact, or ambition was removed.",
        "close_reason": "trace_id=bd-bp8fl:reality-check-parent-closure\nclosed_as_parent=true\nno_feature_loss=true\nAll 16 child workstreams are closed.\nbr show bd-bp8fl --no-db\nbr --no-db dep cycles --json\nbv --robot-insights\nRemaining limitations are intentionally retained."
    })];
    rows.extend(child_ids().into_iter().map(|id| {
        json!({
            "id": id,
            "status": "closed"
        })
    }));
    Ok(rows
        .into_iter()
        .map(|row| serde_json::to_string(&row))
        .collect::<Result<Vec<_>, _>>()?
        .join("\n")
        + "\n")
}

fn mutated_child_status_fixture(child_id: &str, status: &str) -> TestResult<String> {
    let mut content = String::new();
    for line in current_parent_and_children_fixture()?.lines() {
        let mut row: Value = serde_json::from_str(line)?;
        if row["id"].as_str() == Some(child_id) {
            row["status"] = json!(status);
        }
        content.push_str(&serde_json::to_string(&row)?);
        content.push('\n');
    }
    Ok(content)
}

fn point_manifest_at_fixture(root: &Path, manifest: &mut Value, out_dir: &Path) -> TestResult {
    let issues_path = out_dir.join("issues_current.jsonl");
    write_text(&issues_path, &current_parent_and_children_fixture()?)?;
    manifest["source_artifacts"]["issues_jsonl"] = json!(repo_relative(root, &issues_path)?);
    Ok(())
}

#[test]
fn manifest_binds_reality_check_ambition_sources() -> TestResult {
    let root = repo_root()?;
    let manifest = read_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("reality_check_ambition_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-bp8fl"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-bp8fl.17")
    );
    assert!(
        json_u64(
            &manifest["next_audit_score_threshold"],
            "next audit score threshold"
        )? >= 800
    );

    let artifacts = json_object(&manifest["source_artifacts"], "source_artifacts")?;
    for (artifact_id, path) in artifacts {
        let path = path.as_str().ok_or("artifact path must be string")?;
        assert!(
            root.join(path).exists(),
            "source artifact {artifact_id} missing at {path}"
        );
    }

    let children = manifest["required_child_workstreams"]
        .as_array()
        .ok_or("required_child_workstreams must be array")?;
    assert_eq!(children.len(), 16);
    let child_ids: BTreeSet<_> = children
        .iter()
        .filter_map(|child| child["id"].as_str())
        .collect();
    for expected in [
        "bd-bp8fl.1",
        "bd-bp8fl.2",
        "bd-bp8fl.3",
        "bd-bp8fl.4",
        "bd-bp8fl.5",
        "bd-bp8fl.6",
        "bd-bp8fl.7",
        "bd-bp8fl.8",
        "bd-bp8fl.9",
        "bd-bp8fl.10",
        "bd-bp8fl.11",
        "bd-bp8fl.12",
        "bd-bp8fl.13",
        "bd-bp8fl.14",
        "bd-bp8fl.15",
        "bd-bp8fl.16",
    ] {
        assert!(child_ids.contains(expected), "missing child {expected}");
    }

    let item_ids: BTreeSet<_> = manifest["missing_item_bindings"]
        .as_array()
        .ok_or("missing_item_bindings must be array")?
        .iter()
        .filter_map(|binding| binding["id"].as_str())
        .collect();
    assert_eq!(
        item_ids,
        BTreeSet::from([
            "telemetry.primary",
            "tests.conformance.primary",
            "tests.e2e.primary",
            "tests.unit.primary"
        ])
    );

    for binding in json_array(&manifest["missing_item_bindings"], "missing item bindings")? {
        for test_ref in json_array(&binding["required_test_refs"], "required test refs")? {
            let source_id = json_str(&test_ref["source"], "test ref source")?;
            let name = json_str(&test_ref["name"], "test ref name")?;
            let source_path = json_str(
                artifacts
                    .get(source_id)
                    .ok_or_else(|| format!("missing source artifact {source_id}"))?,
                "source artifact path",
            )?;
            assert!(
                function_exists(&root, source_path, name)?,
                "missing test ref {source_id}::{name}"
            );
        }
    }

    Ok(())
}

#[test]
fn checker_accepts_contract_and_emits_report_log() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "pass")?;
    let mut manifest = read_json(&contract_path(&root))?;
    point_manifest_at_fixture(&root, &mut manifest, &out_dir)?;
    let contract = out_dir.join("contract_pass.json");
    write_json(&contract, &manifest)?;
    let output = run_checker(&root, &contract, &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report =
        read_json(&out_dir.join("reality_check_ambition_completion_contract.report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("reality_check_ambition_completion_contract.report.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["source_bead"].as_str(), Some("bd-bp8fl"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-bp8fl.17"));
    assert_eq!(
        report["summaries"]["children"]["child_workstream_count"].as_u64(),
        Some(16)
    );
    assert_eq!(
        report["summaries"]["children"]["closed_child_workstream_count"].as_u64(),
        Some(16)
    );
    assert_eq!(
        report["summaries"]["bindings"]["binding_count"].as_u64(),
        Some(4)
    );

    let rows = read_jsonl(&out_dir.join("reality_check_ambition_completion_contract.log.jsonl"))?;
    let events: BTreeSet<_> = rows
        .iter()
        .filter_map(|row| row["event"].as_str())
        .collect();
    for expected in [
        "reality_check_sources_bound",
        "reality_check_child_workstreams_validated",
        "reality_check_claims_validated",
        "reality_check_missing_items_bound",
        "reality_check_command_policy_validated",
        "reality_check_telemetry_validated",
        "reality_check_completion_contract_pass",
    ] {
        assert!(events.contains(expected), "missing event {expected}");
    }
    for row in rows {
        for field in [
            "timestamp",
            "event",
            "source_bead",
            "completion_debt_bead",
            "status",
            "artifact_refs",
            "failure_signature",
            "details",
        ] {
            assert!(!row[field].is_null(), "log record missing {field}: {row}");
        }
    }

    Ok(())
}

#[test]
fn checker_rejects_child_status_drift() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "child_status")?;
    let mut manifest = read_json(&contract_path(&root))?;
    let issues_path = out_dir.join("issues_child_status.jsonl");
    let issues = mutated_child_status_fixture("bd-bp8fl.16", "open")?;
    write_text(&issues_path, &issues)?;
    manifest["source_artifacts"]["issues_jsonl"] = json!(repo_relative(&root, &issues_path)?);
    let mutated = out_dir.join("contract_child_status.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject child status drift:\n{}",
        output_text(&output)
    );
    let report =
        read_json(&out_dir.join("reality_check_ambition_completion_contract.report.json"))?;
    let errors = json_array(&report["errors"], "report errors")?;
    assert!(
        errors.iter().any(|error| error
            .as_str()
            .unwrap_or("")
            .contains("child workstream status drift")),
        "expected child status drift error, got {errors:?}"
    );

    Ok(())
}

#[test]
fn checker_rejects_bare_cargo_command() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "bare_cargo")?;
    let mut manifest = read_json(&contract_path(&root))?;
    point_manifest_at_fixture(&root, &mut manifest, &out_dir)?;
    manifest["missing_item_bindings"][0]["required_commands"][0] = json!(
        "cargo test -p frankenlibc-harness --test reality_check_ambition_completion_contract_test"
    );
    let mutated = out_dir.join("contract_bare_cargo.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject bare cargo command:\n{}",
        output_text(&output)
    );
    let report =
        read_json(&out_dir.join("reality_check_ambition_completion_contract.report.json"))?;
    let errors = json_array(&report["errors"], "report errors")?;
    assert!(
        errors
            .iter()
            .any(|error| error.as_str().unwrap_or("").contains("bare cargo")),
        "expected bare cargo error, got {errors:?}"
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_required_event() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "event_drift")?;
    let mut manifest = read_json(&contract_path(&root))?;
    point_manifest_at_fixture(&root, &mut manifest, &out_dir)?;
    let events = json_array_mut(
        &mut manifest["telemetry_contract"]["required_events"],
        "required events",
    )?;
    events.retain(|event| event.as_str() != Some("reality_check_claims_validated"));
    let mutated = out_dir.join("contract_event_drift.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing telemetry event:\n{}",
        output_text(&output)
    );
    let report =
        read_json(&out_dir.join("reality_check_ambition_completion_contract.report.json"))?;
    let errors = json_array(&report["errors"], "report errors")?;
    assert!(
        errors.iter().any(|error| error
            .as_str()
            .unwrap_or("")
            .contains("telemetry_contract.required_events mismatch")),
        "expected telemetry event drift error, got {errors:?}"
    );
    assert!(string_set(&manifest["telemetry_contract"]["required_events"])?.len() >= 6);

    Ok(())
}
