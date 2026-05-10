use serde_json::{Value, json};
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
    root.join("tests/conformance/runtime_hot_path_perf_golden_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_runtime_hot_path_perf_golden_completion_contract.sh")
}

fn load_json(path: &Path) -> TestResult<Value> {
    let text = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&text)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let out = root.join("target/conformance").join(format!(
        "runtime_hot_path_perf_golden_completion_contract_{label}_{}_{}",
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
            "FRANKENLIBC_RUNTIME_HOT_PATH_PERF_GOLDEN_CONTRACT",
            contract,
        )
        .env(
            "FRANKENLIBC_RUNTIME_HOT_PATH_PERF_GOLDEN_REPORT",
            out_dir.join("runtime_hot_path_perf_golden_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_RUNTIME_HOT_PATH_PERF_GOLDEN_LOG",
            out_dir.join("runtime_hot_path_perf_golden_completion_contract.log.jsonl"),
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
    let text = std::fs::read_to_string(path)?;
    text.lines()
        .map(|line| Ok(serde_json::from_str::<Value>(line)?))
        .collect()
}

#[test]
fn manifest_binds_runtime_hot_path_golden_evidence() -> TestResult {
    let root = repo_root();
    let manifest = load_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("runtime_hot_path_perf_golden_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-73r"));
    assert_eq!(manifest["completion_debt_bead"].as_str(), Some("bd-73r.1"));
    assert_eq!(
        manifest["completion_debt_evidence"]["missing_items_closed"],
        json!(["tests.golden.primary"])
    );

    let source_artifacts = manifest["source_artifacts"]
        .as_object()
        .ok_or("source_artifacts must be object")?;
    for key in [
        "golden_snapshot",
        "golden_sha256s",
        "snapshot_gate",
        "perf_gate",
        "perf_budget_policy",
        "perf_baseline",
        "completion_checker",
        "completion_harness_test",
    ] {
        let path = source_artifacts[key]
            .as_str()
            .ok_or("source artifact path must be string")?;
        assert!(root.join(path).is_file(), "missing {key} artifact {path}");
    }

    let golden = &manifest["completion_debt_evidence"]["golden_primary"];
    assert_eq!(
        golden["missing_item_id"].as_str(),
        Some("tests.golden.primary")
    );
    assert_eq!(
        golden["expected_sha256"].as_str(),
        Some("90ee952d0398f187d583ce552014cad53d102c5102118ab6e83b6e1b788a7651")
    );

    let required = &manifest["required_golden_contract"];
    assert_eq!(
        required["perf_targets_ns"]["strict_hot_path_max"].as_u64(),
        Some(20)
    );
    assert_eq!(
        required["perf_targets_ns"]["hardened_hot_path_max"].as_u64(),
        Some(200)
    );
    assert_eq!(required["scenario"]["steps"].as_u64(), Some(512));
    assert_eq!(required["modes"], json!(["strict", "hardened"]));

    let required_tests: Vec<&str> = golden["required_test_refs"]
        .as_array()
        .ok_or("required_test_refs must be array")?
        .iter()
        .filter_map(|entry| entry["name"].as_str())
        .collect();
    for test in [
        "runtime_math_kernel_snapshot_golden_checksum_matches_manifest",
        "checker_rejects_snapshot_hash_drift",
        "checker_rejects_budget_target_drift",
    ] {
        assert!(
            required_tests.contains(&test),
            "missing test binding {test}"
        );
    }

    Ok(())
}

#[test]
fn checker_validates_runtime_hot_path_perf_golden_contract() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "valid")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report =
        load_json(&out_dir.join("runtime_hot_path_perf_golden_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["source_bead"].as_str(), Some("bd-73r"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-73r.1"));
    assert_eq!(
        report["golden"]["sha256"].as_str(),
        Some("90ee952d0398f187d583ce552014cad53d102c5102118ab6e83b6e1b788a7651")
    );
    assert_eq!(
        report["budget_targets"]["strict_hot_path_max"].as_u64(),
        Some(20)
    );
    assert_eq!(
        report["budget_targets"]["hardened_hot_path_max"].as_u64(),
        Some(200)
    );
    assert_eq!(
        report["gate_bindings"]["snapshot_gate"].as_bool(),
        Some(true)
    );
    assert_eq!(report["gate_bindings"]["perf_gate"].as_bool(), Some(true));

    Ok(())
}

#[test]
fn checker_emits_report_and_jsonl() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "jsonl")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report =
        load_json(&out_dir.join("runtime_hot_path_perf_golden_completion_contract.report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("runtime_hot_path_perf_golden_completion_contract.report.v1")
    );
    assert_eq!(report["events"].as_array().map(Vec::len), Some(4));

    let records =
        log_records(&out_dir.join("runtime_hot_path_perf_golden_completion_contract.log.jsonl"))?;
    let events: Vec<&str> = records
        .iter()
        .filter_map(|record| record["event"].as_str())
        .collect();
    for expected in [
        "runtime_hot_path_perf_golden_hash_verified",
        "runtime_hot_path_perf_budget_targets_verified",
        "runtime_hot_path_perf_gate_bindings_verified",
        "runtime_hot_path_perf_golden_completion_contract_pass",
    ] {
        assert!(events.contains(&expected), "missing event {expected}");
    }
    for record in records {
        for field in [
            "event",
            "bead_id",
            "source_bead",
            "completion_debt_bead",
            "status",
            "outcome",
            "artifact_refs",
            "failure_signature",
        ] {
            assert!(
                !record[field].is_null(),
                "log record missing {field}: {record}"
            );
        }
    }

    Ok(())
}

#[test]
fn checker_rejects_snapshot_hash_drift() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "hash_drift")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["golden_primary"]["expected_sha256"] =
        json!("0000000000000000000000000000000000000000000000000000000000000000");
    let mutated = out_dir.join("contract_hash_drift.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject snapshot hash drift:\n{}",
        output_text(&output)
    );
    let report =
        load_json(&out_dir.join("runtime_hot_path_perf_golden_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .ok_or("errors must be array")?
            .iter()
            .any(|error| error
                .as_str()
                .unwrap_or("")
                .contains("golden snapshot hash drift")
                || error
                    .as_str()
                    .unwrap_or("")
                    .contains("sha256 manifest digest")),
        "report should name hash drift: {report}"
    );

    Ok(())
}

#[test]
fn checker_rejects_budget_target_drift() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "budget_drift")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["required_golden_contract"]["perf_targets_ns"]["strict_hot_path_max"] = json!(21);
    let mutated = out_dir.join("contract_budget_drift.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject budget target drift:\n{}",
        output_text(&output)
    );
    let report =
        load_json(&out_dir.join("runtime_hot_path_perf_golden_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .ok_or("errors must be array")?
            .iter()
            .any(|error| error
                .as_str()
                .unwrap_or("")
                .contains("strict_hotpath.strict_mode_ns drift")),
        "report should name strict budget drift: {report}"
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_snapshot_gate_binding() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "missing_snapshot_gate")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["source_artifacts"]
        .as_object_mut()
        .ok_or("source_artifacts must be object")?
        .remove("snapshot_gate");
    let mutated = out_dir.join("contract_missing_snapshot_gate.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing snapshot gate:\n{}",
        output_text(&output)
    );
    let report =
        load_json(&out_dir.join("runtime_hot_path_perf_golden_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .ok_or("errors must be array")?
            .iter()
            .any(|error| error.as_str().unwrap_or("").contains("snapshot_gate")),
        "report should name snapshot_gate: {report}"
    );

    Ok(())
}
