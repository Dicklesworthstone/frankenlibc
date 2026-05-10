use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

static CHECKER_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn checker_lock() -> MutexGuard<'static, ()> {
    CHECKER_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate directory has workspace parent")
        .parent()
        .expect("workspace parent has repo parent")
        .to_path_buf()
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/dual_mode_unit_integrity_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_dual_mode_unit_integrity_completion_contract.sh")
}

fn load_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let out = root.join("target/conformance").join(format!(
        "dual_mode_unit_integrity_completion_contract_{label}_{}_{}",
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
        .env(
            "FRANKENLIBC_DUAL_MODE_UNIT_INTEGRITY_COMPLETION_CONTRACT",
            contract,
        )
        .env(
            "FRANKENLIBC_DUAL_MODE_UNIT_INTEGRITY_COMPLETION_REPORT",
            out_dir.join("dual_mode_unit_integrity_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_DUAL_MODE_UNIT_INTEGRITY_COMPLETION_LOG",
            out_dir.join("dual_mode_unit_integrity_completion_contract.log.jsonl"),
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

fn log_records(path: &Path) -> TestResult<Vec<Value>> {
    let body = std::fs::read_to_string(path)?;
    body.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| Ok(serde_json::from_str::<Value>(line)?))
        .collect()
}

#[test]
fn manifest_binds_unit_and_e2e_items() -> TestResult {
    let root = repo_root();
    let manifest = load_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("dual_mode_unit_integrity_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-oai.4"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-oai.4.1")
    );

    let missing_items: BTreeSet<_> = manifest["missing_item_bindings"]
        .as_array()
        .ok_or("missing_item_bindings must be array")?
        .iter()
        .filter_map(|item| item["id"].as_str())
        .collect();
    assert_eq!(
        missing_items,
        BTreeSet::from(["tests.e2e.primary", "tests.unit.primary"])
    );

    let source_artifacts = manifest["source_artifacts"]
        .as_object()
        .ok_or("source_artifacts must be object")?;
    for (name, rel) in source_artifacts {
        let rel = rel.as_str().ok_or("source artifact path must be string")?;
        assert!(root.join(rel).is_file(), "source artifact {name} missing");
    }

    assert_eq!(
        manifest["dual_mode_unit_contract"]["env_key"].as_str(),
        Some("FRANKENLIBC_MODE")
    );
    assert_eq!(
        manifest["dual_mode_unit_contract"]["snapshot_schema_min_field_count"].as_u64(),
        Some(154)
    );
    assert_eq!(
        manifest["dual_mode_unit_contract"]["deterministic_replay_required"].as_bool(),
        Some(true)
    );
    assert_eq!(
        manifest["dual_mode_unit_contract"]["raptorq_redundancy_verification_required"].as_bool(),
        Some(true)
    );

    Ok(())
}

#[test]
fn runtime_math_sources_cover_snapshot_evidence_and_replay_tests() -> TestResult {
    let root = repo_root();
    let manifest = load_json(&contract_path(&root))?;
    let source_artifacts = manifest["source_artifacts"]
        .as_object()
        .ok_or("source_artifacts must be object")?;

    for (source_key, anchors) in manifest["source_anchors"]
        .as_object()
        .ok_or("source_anchors must be object")?
    {
        let source_path = source_artifacts[source_key]
            .as_str()
            .ok_or("source path must be string")?;
        let source_text = std::fs::read_to_string(root.join(source_path))?;
        for anchor in anchors.as_array().ok_or("anchors must be array")? {
            let anchor = anchor.as_str().ok_or("anchor must be string")?;
            assert!(
                source_text.contains(anchor),
                "{source_key} source is missing anchor: {anchor}"
            );
        }
    }

    let runtime_math_path = source_artifacts["runtime_math"]
        .as_str()
        .ok_or("runtime_math path must be string")?;
    let runtime_math_text = std::fs::read_to_string(root.join(runtime_math_path))?;
    for test_name in manifest["completion_coverage"]["unit"]["runtime_math_inline_tests"]
        .as_array()
        .ok_or("runtime_math tests must be array")?
    {
        let test_name = test_name.as_str().ok_or("test name must be string")?;
        assert!(
            runtime_math_text.contains(&format!("fn {test_name}")),
            "runtime_math source is missing test ref {test_name}"
        );
    }

    let snapshot_path = source_artifacts["snapshot_golden"]
        .as_str()
        .ok_or("snapshot_golden path must be string")?;
    let snapshot = load_json(&root.join(snapshot_path))?;
    for mode in ["strict", "hardened"] {
        let fields = snapshot[mode]["snapshot"]
            .as_object()
            .ok_or("snapshot mode must contain object fields")?;
        assert!(
            fields.len() >= 154,
            "{mode} snapshot should carry the schema baseline"
        );
        assert!(fields.contains_key("redundancy_overhead_ppm"));
        assert!(fields.contains_key("redundancy_loss_rate_ppm"));
    }

    Ok(())
}

#[test]
fn checker_emits_structured_completion_evidence() -> TestResult {
    let _lock = checker_lock();
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "pass")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report =
        load_json(&out_dir.join("dual_mode_unit_integrity_completion_contract.report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("dual_mode_unit_integrity_completion_contract.report.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["failure_signature"].as_str(), Some("none"));
    assert_eq!(
        report["summary"]["env_key"].as_str(),
        Some("FRANKENLIBC_MODE")
    );
    assert_eq!(report["summary"]["missing_item_count"].as_u64(), Some(2));
    assert_eq!(report["summary"]["unit_test_ref_count"].as_u64(), Some(17));
    assert_eq!(report["summary"]["e2e_test_ref_count"].as_u64(), Some(5));
    assert_eq!(
        report["summary"]["deterministic_replay_required"].as_bool(),
        Some(true)
    );

    let records =
        log_records(&out_dir.join("dual_mode_unit_integrity_completion_contract.log.jsonl"))?;
    let events: BTreeSet<_> = records
        .iter()
        .filter_map(|record| record["event"].as_str())
        .collect();
    assert_eq!(
        events,
        BTreeSet::from([
            "dual_mode_unit_integrity_contract_validated",
            "dual_mode_unit_integrity_e2e_bindings",
            "dual_mode_unit_integrity_summary",
            "dual_mode_unit_integrity_unit_bindings"
        ])
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_runtime_math_anchor() -> TestResult {
    let _lock = checker_lock();
    let root = repo_root();
    let mut manifest = load_json(&contract_path(&root))?;
    let anchors = manifest["source_anchors"]["runtime_math"]
        .as_array_mut()
        .ok_or("runtime_math anchors must be array")?;
    anchors[0] = Value::String("missing runtime math completion anchor".to_string());

    let out_dir = unique_out_dir(&root, "fail")?;
    let mutated = out_dir.join("dual_mode_unit_integrity_completion_contract.mutated.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "mutated contract should fail\n{}",
        output_text(&output)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("source_anchor_missing"),
        "failure should identify missing source anchor\n{}",
        output_text(&output)
    );

    Ok(())
}
