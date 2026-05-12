use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const PASS_EVENTS: &[&str] = &[
    "abi_drift_auto_bisect_completion.unit_binding",
    "abi_drift_auto_bisect_completion.e2e_transcript",
    "abi_drift_auto_bisect_completion.telemetry_contract",
    "abi_drift_auto_bisect_completion.validated",
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
    root.join("tests/conformance/abi_drift_auto_bisect_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_abi_drift_auto_bisect_completion_contract.sh")
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
        "abi_drift_auto_bisect_completion_{label}_{}_{}",
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
        .env("FRANKENLIBC_ABI_DRIFT_AUTO_BISECT_CONTRACT", contract)
        .env(
            "FRANKENLIBC_ABI_DRIFT_AUTO_BISECT_REPORT",
            out_dir.join("abi_drift_auto_bisect_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_ABI_DRIFT_AUTO_BISECT_LOG",
            out_dir.join("abi_drift_auto_bisect_completion_contract.log.jsonl"),
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
fn manifest_binds_auto_bisect_completion_items() -> TestResult {
    let root = repo_root();
    let manifest = read_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("abi_drift_auto_bisect_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-26xb.7"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-26xb.7.1")
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
            "tests.e2e.primary",
            "tests.unit.primary"
        ])
    );

    let scenarios = manifest["bisect_engine_contract"]["scenarios"]
        .as_array()
        .ok_or("scenarios must be array")?;
    assert_eq!(scenarios.len(), 3);
    assert!(scenarios.iter().all(|scenario| {
        scenario["candidate_root_cause"]["first_bad_commit"]
            == scenario["expected_first_bad_commit"]
    }));

    let tooling = &manifest["tooling_contract"];
    assert_eq!(
        tooling["deterministic_orchestration"]["dependency"].as_str(),
        Some("asupersync-conformance")
    );
    assert_eq!(
        tooling["deterministic_diff_snapshot"]["dependency"].as_str(),
        Some("ftui-harness")
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
fn source_anchors_and_line_refs_resolve() -> TestResult {
    let root = repo_root();
    let manifest = read_json(&contract_path(&root))?;
    let source_artifacts = manifest["source_artifacts"]
        .as_object()
        .ok_or("source_artifacts object")?;

    for (source_key, anchors) in manifest["source_anchors"]
        .as_object()
        .ok_or("source_anchors object")?
    {
        let Some(source_path) = source_artifacts
            .get(source_key)
            .and_then(|path| path.as_str())
        else {
            continue;
        };
        let text = std::fs::read_to_string(root.join(source_path))?;
        for anchor in anchors.as_array().ok_or("anchor array")? {
            let anchor = anchor.as_str().ok_or("anchor string")?;
            assert!(
                text.contains(anchor),
                "{source_key} source is missing anchor: {anchor}"
            );
        }
    }

    for binding in manifest["missing_item_bindings"]
        .as_array()
        .ok_or("missing_item_bindings array")?
    {
        for refs_key in ["implementation_refs", "test_refs", "telemetry_refs"] {
            let Some(refs) = binding.get(refs_key).and_then(|refs| refs.as_array()) else {
                continue;
            };
            for ref_value in refs {
                let ref_text = ref_value.as_str().ok_or("line ref string")?;
                let (path, line) = ref_text.rsplit_once(':').ok_or("line ref shape")?;
                let line: usize = line.parse()?;
                let text = std::fs::read_to_string(root.join(path))?;
                let lines: Vec<_> = text.lines().collect();
                assert!(
                    line > 0 && line <= lines.len() && !lines[line - 1].trim().is_empty(),
                    "bad line ref {ref_text}"
                );
            }
        }
    }

    Ok(())
}

#[test]
fn checker_emits_reproducible_transcripts_and_telemetry() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "pass")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report = read_json(&out_dir.join("abi_drift_auto_bisect_completion_contract.report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("abi_drift_auto_bisect_completion_contract.report.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["failure_signature"].as_str(), Some("none"));
    assert_eq!(report["summary"]["missing_item_count"].as_u64(), Some(3));
    assert_eq!(report["summary"]["scenario_count"].as_u64(), Some(3));
    assert_eq!(report["summary"]["total_probe_count"].as_u64(), Some(8));

    let transcripts = report["transcripts"]
        .as_array()
        .ok_or("transcripts array")?;
    assert_eq!(transcripts.len(), 3);
    assert_eq!(
        transcripts[0]["first_bad_commit"].as_str(),
        Some("abi-mid-003")
    );

    let rows = read_jsonl(&out_dir.join("abi_drift_auto_bisect_completion_contract.log.jsonl"))?;
    let events: BTreeSet<_> = rows
        .iter()
        .filter_map(|row| row["event"].as_str())
        .collect();
    assert_eq!(events, PASS_EVENTS.iter().copied().collect());

    Ok(())
}

#[test]
fn checker_rejects_first_bad_candidate_drift() -> TestResult {
    let root = repo_root();
    let mut manifest = read_json(&contract_path(&root))?;
    let out_dir = unique_out_dir(&root, "mutated_first_bad")?;
    let mutated = out_dir.join("mutated_contract.json");

    manifest["bisect_engine_contract"]["scenarios"][0]["expected_first_bad_commit"] =
        serde_json::json!("abi-mid-004");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(!output.status.success(), "{}", output_text(&output));
    let report = read_json(&out_dir.join("abi_drift_auto_bisect_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert_eq!(
        report["failure_signature"].as_str(),
        Some("first_bad_drift")
    );

    Ok(())
}

#[test]
fn checker_rejects_non_monotonic_histories() -> TestResult {
    let root = repo_root();
    let mut manifest = read_json(&contract_path(&root))?;
    let out_dir = unique_out_dir(&root, "mutated_monotonic")?;
    let mutated = out_dir.join("mutated_contract.json");

    manifest["bisect_engine_contract"]["scenarios"][1]["commits"][8]["status"] =
        serde_json::json!("pass");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(!output.status.success(), "{}", output_text(&output));
    let report = read_json(&out_dir.join("abi_drift_auto_bisect_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert_eq!(
        report["failure_signature"].as_str(),
        Some("non_monotonic_history")
    );

    Ok(())
}
