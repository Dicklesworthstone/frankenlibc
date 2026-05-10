//! Completion-debt contract for bd-bp8fl.1.1 / bd-bp8fl.1.1.1.

use frankenlibc_harness::structured_log::validate_log_line;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const REQUIRED_MISSING_ITEMS: &[&str] = &[
    "tests.unit.primary",
    "tests.e2e.primary",
    "telemetry.primary",
];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate directory has workspace parent")
        .parent()
        .expect("workspace parent has repo parent")
        .to_path_buf()
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/semantic_contract_inventory_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_semantic_contract_inventory_completion_contract.sh")
}

fn load_json(path: &Path) -> TestResult<Value> {
    let text = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&text)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn jsonl_rows(path: &Path) -> TestResult<Vec<Value>> {
    let text = std::fs::read_to_string(path)?;
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let out = root.join("target/conformance").join(format!(
        "semantic_contract_inventory_completion_contract_{label}_{}_{}",
        std::process::id(),
        stamp
    ));
    std::fs::create_dir_all(&out)?;
    Ok(out)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env("SEMANTIC_CONTRACT_INVENTORY_COMPLETION_CONTRACT", contract)
        .env("SEMANTIC_CONTRACT_INVENTORY_COMPLETION_OUT_DIR", out_dir)
        .env(
            "SEMANTIC_CONTRACT_INVENTORY_COMPLETION_REPORT",
            out_dir.join("semantic_contract_inventory_completion_contract.report.json"),
        )
        .env(
            "SEMANTIC_CONTRACT_INVENTORY_COMPLETION_LOG",
            out_dir.join("semantic_contract_inventory_completion_contract.log.jsonl"),
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

fn string_set(value: &Value) -> TestResult<BTreeSet<String>> {
    value
        .as_array()
        .ok_or("expected array")?
        .iter()
        .map(|item| {
            item.as_str()
                .ok_or_else(|| "expected string".into())
                .map(str::to_owned)
        })
        .collect::<Result<_, Box<dyn std::error::Error>>>()
}

#[test]
fn manifest_binds_source_inventory_and_missing_items() -> TestResult {
    let root = repo_root();
    let manifest = load_json(&contract_path(&root))?;
    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("semantic_contract_inventory_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-bp8fl.1.1"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-bp8fl.1.1.1")
    );

    let source_artifacts = manifest["source_artifacts"]
        .as_object()
        .ok_or("source_artifacts must be object")?;
    for (artifact_id, path) in source_artifacts {
        let path = path.as_str().ok_or("source artifact path must be string")?;
        assert!(
            root.join(path).exists(),
            "source artifact {artifact_id} missing at {path}"
        );
    }

    let source_manifest = load_json(
        &root.join(
            manifest["source_contract"]["manifest"]["path"]
                .as_str()
                .ok_or("source manifest path")?,
        ),
    )?;
    assert_eq!(source_manifest["bead"].as_str(), Some("bd-bp8fl.1.1"));
    assert!(
        source_manifest["summary"]["entry_count"]
            .as_u64()
            .unwrap_or_default()
            >= 18,
        "source inventory should bind at least 18 semantic contract rows"
    );
    assert!(
        source_manifest["summary"]["seed_overlay_covered"]
            .as_u64()
            .unwrap_or_default()
            >= 10,
        "source inventory should retain all seed overlay rows"
    );

    let item_ids: BTreeSet<_> = manifest["missing_item_bindings"]
        .as_array()
        .ok_or("missing_item_bindings must be array")?
        .iter()
        .filter_map(|item| item["id"].as_str())
        .collect();
    for item in REQUIRED_MISSING_ITEMS {
        assert!(item_ids.contains(item), "missing item binding {item}");
    }

    Ok(())
}

#[test]
fn source_checker_and_tests_are_anchored() -> TestResult {
    let root = repo_root();
    let manifest = load_json(&contract_path(&root))?;
    let checker_path_text = manifest["source_contract"]["checker"]["path"]
        .as_str()
        .ok_or("checker path")?;
    let checker_source = std::fs::read_to_string(root.join(checker_path_text))?;
    for needle in manifest["source_contract"]["checker"]["required_needles"]
        .as_array()
        .ok_or("required checker needles")?
    {
        let needle = needle.as_str().ok_or("needle string")?;
        assert!(
            checker_source.contains(needle),
            "source checker missing needle {needle}"
        );
    }

    let source_test_path = manifest["source_contract"]["source_tests"]["path"]
        .as_str()
        .ok_or("source test path")?;
    let source_test = std::fs::read_to_string(root.join(source_test_path))?;
    for test_ref in manifest["source_contract"]["source_tests"]["required_test_refs"]
        .as_array()
        .ok_or("required source tests")?
    {
        let test_ref = test_ref.as_str().ok_or("test ref string")?;
        assert!(
            source_test.contains(&format!("fn {test_ref}")),
            "source inventory test missing {test_ref}"
        );
    }

    let completion_source = std::fs::read_to_string(root.join(file!()))?;
    for test_ref in manifest["completion_debt_evidence"]["required_test_refs"]
        .as_array()
        .ok_or("completion required tests")?
    {
        let test_ref = test_ref.as_str().ok_or("completion test ref string")?;
        assert!(
            completion_source.contains(&format!("fn {test_ref}")),
            "completion source missing {test_ref}"
        );
    }

    Ok(())
}

#[test]
fn checker_runs_source_gate_and_emits_completion_evidence() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "pass")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report =
        load_json(&out_dir.join("semantic_contract_inventory_completion_contract.report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("semantic_contract_inventory_completion_contract.report.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["original_bead"].as_str(), Some("bd-bp8fl.1.1"));
    assert_eq!(
        report["completion_debt_bead"].as_str(),
        Some("bd-bp8fl.1.1.1")
    );
    assert!(
        report["summary"]["source_entry_count"]
            .as_u64()
            .unwrap_or_default()
            >= 18
    );
    assert!(
        report["summary"]["source_seed_overlay_covered"]
            .as_u64()
            .unwrap_or_default()
            >= 10
    );
    assert!(
        report["source_checker"]["source_log_rows"]
            .as_u64()
            .unwrap_or_default()
            >= 1
    );

    let rows =
        jsonl_rows(&out_dir.join("semantic_contract_inventory_completion_contract.log.jsonl"))?;
    assert!(
        rows.len() >= 4,
        "expected source manifest, checker, test, and summary rows"
    );
    let events: BTreeSet<_> = rows
        .iter()
        .filter_map(|row| row["event"].as_str())
        .collect();
    for event in [
        "semantic_contract_inventory_source_gate",
        "semantic_contract_inventory_source_checker_gate",
        "semantic_contract_inventory_source_tests_gate",
        "semantic_contract_inventory_completion_contract_validated",
    ] {
        assert!(events.contains(event), "missing completion event {event}");
    }

    for (index, row) in rows.iter().enumerate() {
        for field in string_set(
            &load_json(&contract_path(&root))?["completion_debt_evidence"]["required_log_fields"],
        )? {
            assert!(row.get(&field).is_some(), "row {index} missing {field}");
        }
        let serialized = serde_json::to_string(row)?;
        validate_log_line(&serialized, index + 1).map_err(|errors| {
            std::io::Error::other(format!("structured log row {index} rejected: {errors:?}"))
        })?;
    }

    Ok(())
}

#[test]
fn checker_rejects_missing_seed_overlay_coverage() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "missing_seed_coverage")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["source_contract"]["manifest"]["min_seed_overlay_covered"] = json!(999);
    let bad_contract = out_dir.join("missing_seed_coverage_contract.json");
    write_json(&bad_contract, &manifest)?;

    let output = run_checker(&root, &bad_contract, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject impossible seed coverage\n{}",
        output_text(&output)
    );
    assert!(
        output_text(&output).contains("seed overlay coverage"),
        "failure should name seed overlay coverage"
    );

    let report =
        load_json(&out_dir.join("semantic_contract_inventory_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .ok_or("errors array")?
            .iter()
            .any(|error| error
                .as_str()
                .unwrap_or_default()
                .contains("seed overlay coverage")),
        "report should retain seed coverage error"
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_telemetry_trace_id() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "missing_trace_id")?;
    let mut manifest = load_json(&contract_path(&root))?;
    let fields = manifest["completion_debt_evidence"]["required_log_fields"]
        .as_array_mut()
        .ok_or("required_log_fields array")?;
    fields.retain(|field| field.as_str() != Some("trace_id"));
    let bad_contract = out_dir.join("missing_trace_id_contract.json");
    write_json(&bad_contract, &manifest)?;

    let output = run_checker(&root, &bad_contract, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing trace_id\n{}",
        output_text(&output)
    );
    assert!(
        output_text(&output).contains("trace_id"),
        "failure should mention missing trace_id"
    );

    let rows =
        jsonl_rows(&out_dir.join("semantic_contract_inventory_completion_contract.log.jsonl"))?;
    assert!(
        rows.iter().any(|row| row["event"].as_str()
            == Some("semantic_contract_inventory_completion_contract_failed")),
        "failure run should emit failed completion event"
    );

    Ok(())
}
