use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate directory has workspace parent")
        .parent()
        .expect("workspace parent has repo parent")
        .to_path_buf()
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/e2e_reality_gate_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_e2e_reality_gate_completion_contract.sh")
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

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let out = root.join("target/conformance").join(format!(
        "e2e_reality_gate_completion_contract_{label}_{}_{}",
        std::process::id(),
        nanos
    ));
    std::fs::create_dir_all(&out)?;
    Ok(out)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_E2E_REALITY_CONTRACT", contract)
        .env("FRANKENLIBC_E2E_REALITY_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_E2E_REALITY_REPORT",
            out_dir.join("e2e_reality_gate_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_E2E_REALITY_LOG",
            out_dir.join("e2e_reality_gate_completion_contract.log.jsonl"),
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

fn string_set(value: &Value) -> BTreeSet<String> {
    value
        .as_array()
        .expect("value should be array")
        .iter()
        .map(|item| {
            item.as_str()
                .expect("array item should be string")
                .to_owned()
        })
        .collect()
}

fn mutated_manifest(root: &Path, label: &str, manifest: &Value) -> TestResult<(PathBuf, PathBuf)> {
    let out_dir = unique_out_dir(root, label)?;
    let path = out_dir.join("mutated_contract.json");
    write_json(&path, manifest)?;
    Ok((path, out_dir))
}

#[test]
fn manifest_binds_e2e_reality_gate_sources() -> TestResult {
    let root = repo_root();
    let manifest = read_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("e2e_reality_gate_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-mtj"));
    assert_eq!(manifest["completion_debt_bead"].as_str(), Some("bd-mtj.1"));
    assert!(manifest["next_audit_score_threshold"].as_u64().unwrap() >= 800);

    let artifacts = manifest["source_artifacts"]
        .as_object()
        .ok_or("source_artifacts must be object")?;
    assert!(artifacts.len() >= 29);
    for (artifact_id, spec) in artifacts {
        let path = spec["path"]
            .as_str()
            .ok_or("artifact path must be string")?;
        assert!(
            root.join(path).exists(),
            "source artifact {artifact_id} missing at {path}"
        );
    }

    let lanes = manifest["proof_lanes"]
        .as_array()
        .ok_or("proof_lanes must be array")?;
    assert_eq!(lanes.len(), 5);
    let lane_ids: BTreeSet<_> = lanes
        .iter()
        .filter_map(|lane| lane["id"].as_str())
        .collect();
    for expected in [
        "scenario-manifest",
        "ld-preload-smoke",
        "standalone-link-run",
        "dual-mode-strict-hardened",
        "abi-surface",
    ] {
        assert!(lane_ids.contains(expected), "missing lane {expected}");
    }

    for lane in lanes {
        let test_artifact = lane["test_artifact"]
            .as_str()
            .ok_or("test_artifact must be string")?;
        let test_path = artifacts[test_artifact]["path"]
            .as_str()
            .ok_or("test artifact path must be string")?;
        let test_text = std::fs::read_to_string(root.join(test_path))?;
        for test_ref in lane["required_test_refs"]
            .as_array()
            .ok_or("required_test_refs must be array")?
        {
            let test_ref = test_ref.as_str().ok_or("test ref must be string")?;
            assert!(
                test_text.contains(test_ref),
                "lane {} missing test ref {test_ref}",
                lane["id"]
            );
        }
    }

    let item_ids: BTreeSet<_> = manifest["missing_item_bindings"]
        .as_array()
        .ok_or("missing_item_bindings must be array")?
        .iter()
        .filter_map(|item| item["id"].as_str())
        .collect();
    for expected in [
        "tests.unit.primary",
        "tests.e2e.primary",
        "telemetry.primary",
    ] {
        assert!(
            item_ids.contains(expected),
            "missing item binding {expected}"
        );
    }

    Ok(())
}

#[test]
fn checker_accepts_contract_and_replays_e2e_gates() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "valid")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report = read_json(&out_dir.join("e2e_reality_gate_completion_contract.report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("e2e_reality_gate_completion_contract.report.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["source_bead"].as_str(), Some("bd-mtj"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-mtj.1"));
    assert_eq!(report["summary"]["source_count"].as_u64(), Some(29));
    assert_eq!(report["summary"]["lane_count"].as_u64(), Some(5));
    assert_eq!(report["summary"]["missing_item_count"].as_u64(), Some(3));
    assert_eq!(report["summary"]["child_gate_count"].as_u64(), Some(5));

    let records = read_jsonl(&out_dir.join("e2e_reality_gate_completion_contract.log.jsonl"))?;
    let events: BTreeSet<_> = records
        .iter()
        .filter_map(|record| record["event"].as_str())
        .collect();
    for event in [
        "e2e_reality_sources_bound",
        "e2e_reality_lanes_validated",
        "e2e_reality_missing_items_bound",
        "e2e_reality_telemetry_validated",
        "e2e_reality_child_gates_replayed",
        "e2e_reality_completion_contract_pass",
    ] {
        assert!(events.contains(event), "missing telemetry event {event}");
    }

    Ok(())
}

#[test]
fn checker_rejects_missing_lane_artifact() -> TestResult {
    let root = repo_root();
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["proof_lanes"][0]["artifact_ids"] =
        json!(["e2e_scenario_manifest", "missing_artifact"]);
    let (path, out_dir) = mutated_manifest(&root, "missing-lane-artifact", &manifest)?;

    let output = run_checker(&root, &path, &out_dir)?;
    assert!(!output.status.success());
    let report = read_json(&out_dir.join("e2e_reality_gate_completion_contract.report.json"))?;
    let errors: Vec<&str> = report["errors"]
        .as_array()
        .expect("errors should be array")
        .iter()
        .filter_map(|error| error.as_str())
        .collect();
    assert!(
        errors
            .iter()
            .any(|error| error.contains("references missing artifact")),
        "missing artifact error absent: {errors:?}"
    );

    Ok(())
}

#[test]
fn checker_rejects_bare_cargo_command() -> TestResult {
    let root = repo_root();
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["missing_item_bindings"][0]["required_commands"] = json!([
        "cargo test -p frankenlibc-harness --test e2e_reality_gate_completion_contract_test"
    ]);
    let (path, out_dir) = mutated_manifest(&root, "bare-cargo", &manifest)?;

    let output = run_checker(&root, &path, &out_dir)?;
    assert!(!output.status.success());
    let report = read_json(&out_dir.join("e2e_reality_gate_completion_contract.report.json"))?;
    let errors: Vec<&str> = report["errors"]
        .as_array()
        .expect("errors should be array")
        .iter()
        .filter_map(|error| error.as_str())
        .collect();
    assert!(
        errors.iter().any(|error| error.contains("must use rch")),
        "bare cargo rejection absent: {errors:?}"
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_required_telemetry_event() -> TestResult {
    let root = repo_root();
    let mut manifest = read_json(&contract_path(&root))?;
    let events = string_set(&manifest["telemetry_contract"]["required_events"]);
    manifest["telemetry_contract"]["required_events"] = json!(
        events
            .into_iter()
            .filter(|event| event != "e2e_reality_child_gates_replayed")
            .collect::<Vec<_>>()
    );
    let (path, out_dir) = mutated_manifest(&root, "telemetry-event", &manifest)?;

    let output = run_checker(&root, &path, &out_dir)?;
    assert!(!output.status.success());
    let report = read_json(&out_dir.join("e2e_reality_gate_completion_contract.report.json"))?;
    let errors: Vec<&str> = report["errors"]
        .as_array()
        .expect("errors should be array")
        .iter()
        .filter_map(|error| error.as_str())
        .collect();
    assert!(
        errors
            .iter()
            .any(|error| error.contains("required_events missing")),
        "telemetry drift rejection absent: {errors:?}"
    );

    Ok(())
}
