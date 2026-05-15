use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const PASS_EVENTS: &[&str] = &[
    "aarch64_conformance_perf_matrix_completion.unit_binding",
    "aarch64_conformance_perf_matrix_completion.e2e_binding",
    "aarch64_conformance_perf_matrix_completion.fuzz_binding",
    "aarch64_conformance_perf_matrix_completion.conformance_binding",
    "aarch64_conformance_perf_matrix_completion.telemetry_contract",
    "aarch64_conformance_perf_matrix_completion.validated",
];

fn repo_root() -> TestResult<PathBuf> {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_dir = crate_dir
        .parent()
        .ok_or("crate directory has workspace parent")?;
    let repo_dir = workspace_dir
        .parent()
        .ok_or("workspace parent has repo parent")?;
    Ok(repo_dir.to_path_buf())
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/aarch64_conformance_perf_matrix_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_aarch64_conformance_perf_matrix_completion_contract.sh")
}

fn read_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn read_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    Ok(std::fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<Result<Vec<_>, _>>()?)
}

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let out = root.join("target/conformance").join(format!(
        "aarch64_conformance_perf_matrix_completion_{label}_{}_{}",
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
        .env("FRANKENLIBC_AARCH64_CONFORMANCE_PERF_CONTRACT", contract)
        .env(
            "FRANKENLIBC_AARCH64_CONFORMANCE_PERF_REPORT",
            out_dir.join("aarch64_conformance_perf_matrix_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_AARCH64_CONFORMANCE_PERF_LOG",
            out_dir.join("aarch64_conformance_perf_matrix_completion_contract.log.jsonl"),
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

#[test]
fn manifest_binds_all_completion_items() -> TestResult {
    let root = repo_root()?;
    let manifest = read_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("aarch64_conformance_perf_matrix_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-1gg.4"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-1gg.4.1")
    );

    let missing_items: BTreeSet<_> = manifest["missing_item_bindings"]
        .as_array()
        .ok_or("missing_item_bindings must be array")?
        .iter()
        .filter_map(|binding| binding["id"].as_str())
        .collect();
    assert_eq!(
        missing_items,
        BTreeSet::from([
            "telemetry.primary",
            "tests.conformance.primary",
            "tests.e2e.primary",
            "tests.fuzz.primary",
            "tests.unit.primary"
        ])
    );

    let details = &manifest["aarch64_conformance_perf_matrix_contract"];
    assert_eq!(
        details["required_target"].as_str(),
        Some("aarch64-unknown-linux-gnu")
    );
    assert_eq!(details["next_audit_threshold"].as_u64(), Some(900));
    assert_eq!(
        details["required_aarch64_reason_code"].as_str(),
        Some("aarch64_bringup_missing")
    );
    assert_eq!(
        details["required_support_claim_allowed"].as_bool(),
        Some(false)
    );

    let source_artifacts = manifest["source_artifacts"]
        .as_object()
        .ok_or("source_artifacts object")?;
    for (key, rel) in source_artifacts {
        let rel = rel.as_str().ok_or("source path string")?;
        assert!(root.join(rel).is_file(), "source artifact {key} missing");
    }

    Ok(())
}

#[test]
fn source_anchors_resolve() -> TestResult {
    let root = repo_root()?;
    let manifest = read_json(&contract_path(&root))?;
    let source_artifacts = manifest["source_artifacts"]
        .as_object()
        .ok_or("source_artifacts object")?;

    for (source_key, anchors) in manifest["source_anchors"]
        .as_object()
        .ok_or("source_anchors object")?
    {
        let source_path = source_artifacts[source_key]
            .as_str()
            .ok_or("source path string")?;
        let text = std::fs::read_to_string(root.join(source_path))?;
        for anchor in anchors.as_array().ok_or("anchor array")? {
            let anchor = anchor.as_str().ok_or("anchor string")?;
            assert!(
                text.contains(anchor),
                "{source_key} source is missing anchor: {anchor}"
            );
        }
    }

    Ok(())
}

#[test]
fn checker_emits_report_and_jsonl() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "pass")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report = read_json(
        &out_dir.join("aarch64_conformance_perf_matrix_completion_contract.report.json"),
    )?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("aarch64_conformance_perf_matrix_completion_contract.report.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["failure_signature"].as_str(), Some("none"));
    assert_eq!(report["summary"]["missing_item_count"].as_u64(), Some(5));
    assert_eq!(report["summary"]["aarch64_row_count"].as_u64(), Some(1));
    assert_eq!(report["summary"]["fuzz_target_count"].as_u64(), Some(66));
    assert_eq!(
        report["summary"]["conformance_pass_rate_percent"].as_f64(),
        Some(100.0)
    );

    let rows =
        read_jsonl(&out_dir.join("aarch64_conformance_perf_matrix_completion_contract.log.jsonl"))?;
    let events: BTreeSet<_> = rows
        .iter()
        .filter_map(|row| row["event"].as_str())
        .collect();
    assert_eq!(events, PASS_EVENTS.iter().copied().collect());

    Ok(())
}

#[test]
fn checker_rejects_missing_aarch64_environment_coverage() -> TestResult {
    let root = repo_root()?;
    let mut manifest = read_json(&contract_path(&root))?;
    let out_dir = unique_out_dir(&root, "mutated_arch")?;
    let mutated = out_dir.join("mutated_contract.json");

    manifest["aarch64_conformance_perf_matrix_contract"]["required_architectures"] =
        serde_json::json!(["x86_64"]);
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(!output.status.success(), "{}", output_text(&output));
    let report = read_json(
        &out_dir.join("aarch64_conformance_perf_matrix_completion_contract.report.json"),
    )?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert_eq!(
        report["failure_signature"].as_str(),
        Some("architecture_contract_drift")
    );

    Ok(())
}
