use serde_json::{Value, json};
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

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "timestamp",
    "event",
    "bead_id",
    "source_bead",
    "completion_debt_bead",
    "status",
    "outcome",
    "source_commit",
    "schema_version",
    "artifact_refs",
    "test_refs",
    "failure_signature",
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
    root.join("tests/conformance/api_support_docs_generation_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_api_support_docs_generation_completion_contract.sh")
}

fn load_json(path: &Path) -> TestResult<Value> {
    let text = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&text)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn read_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    std::fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| Ok(serde_json::from_str::<Value>(line)?))
        .collect()
}

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let out = root.join("target/conformance").join(format!(
        "api_support_docs_generation_completion_contract_{label}_{}_{}",
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
        .env("FRANKENLIBC_API_SUPPORT_DOCS_COMPLETION_CONTRACT", contract)
        .env("FRANKENLIBC_API_SUPPORT_DOCS_COMPLETION_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_API_SUPPORT_DOCS_COMPLETION_REPORT",
            out_dir.join("api_support_docs_generation_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_API_SUPPORT_DOCS_COMPLETION_LOG",
            out_dir.join("api_support_docs_generation_completion_contract.log.jsonl"),
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
fn manifest_binds_live_docs_generation_evidence() -> TestResult {
    let root = repo_root()?;
    let manifest = load_json(&contract_path(&root))?;
    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("api_support_docs_generation_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-3rw.4"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-3rw.4.1")
    );

    let source_artifacts = manifest["source_artifacts"]
        .as_object()
        .ok_or("source_artifacts object")?;
    for (source_id, path) in source_artifacts {
        let path = path.as_str().ok_or("source path string")?;
        assert!(
            root.join(path).exists(),
            "source artifact {source_id} missing at {path}"
        );
    }

    let snapshot = &manifest["expected_reality_snapshot"];
    assert_eq!(
        snapshot["generated_at_utc"].as_str(),
        Some("2026-06-03T21:45:00Z")
    );
    assert_eq!(snapshot["total_exported"].as_u64(), Some(4119));
    assert_eq!(snapshot["counts"]["implemented"].as_u64(), Some(2391));
    assert_eq!(snapshot["counts"]["raw_syscall"].as_u64(), Some(414));
    assert_eq!(snapshot["counts"]["wraps_host_libc"].as_u64(), Some(1314));
    assert_eq!(snapshot["counts"]["stub"].as_u64(), Some(0));

    let reality = load_json(&root.join("tests/conformance/reality_report.v1.json"))?;
    assert_eq!(reality["generated_at_utc"], snapshot["generated_at_utc"]);
    assert_eq!(reality["total_exported"], snapshot["total_exported"]);
    assert_eq!(reality["counts"], snapshot["counts"]);

    let readme = std::fs::read_to_string(root.join("README.md"))?;
    let feature = std::fs::read_to_string(root.join("FEATURE_PARITY.md"))?;
    for doc in manifest["doc_generation_contract"]["docs"]
        .as_array()
        .ok_or("docs array")?
    {
        let doc_id = doc["id"].as_str().ok_or("doc id string")?;
        let text = match doc_id {
            "readme" => &readme,
            "feature_parity" => &feature,
            other => return Err(format!("unexpected doc id {other:?}").into()),
        };
        for needle in doc["required_text"]
            .as_array()
            .ok_or("required_text array")?
        {
            let needle = needle.as_str().ok_or("needle string")?;
            assert!(text.contains(needle), "doc missing {needle}");
        }
    }

    let bindings = manifest["missing_item_bindings"]
        .as_array()
        .ok_or("missing_item_bindings array")?;
    for required in REQUIRED_BINDINGS {
        assert!(
            bindings
                .iter()
                .any(|binding| binding["id"].as_str() == Some(*required)),
            "missing binding {required}"
        );
    }
    Ok(())
}

#[test]
fn checker_validates_contract_and_emits_report() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "valid")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report =
        load_json(&out_dir.join("api_support_docs_generation_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["source_bead"].as_str(), Some("bd-3rw.4"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-3rw.4.1"));
    assert_eq!(report["summary"]["docs_checked"].as_u64(), Some(2));
    assert_eq!(report["summary"]["bindings_checked"].as_u64(), Some(5));
    assert_eq!(report["summary"]["total_exported"].as_u64(), Some(4119));
    Ok(())
}

#[test]
fn checker_emits_jsonl_rows_with_required_fields() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "jsonl")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let rows =
        read_jsonl(&out_dir.join("api_support_docs_generation_completion_contract.log.jsonl"))?;
    assert_eq!(
        rows.len(),
        8,
        "checker should emit eight pass telemetry rows"
    );
    for row in rows {
        for field in REQUIRED_LOG_FIELDS {
            assert!(!row[field].is_null(), "log row missing {field}: {row}");
        }
        assert_eq!(row["status"].as_str(), Some("pass"));
        assert_eq!(row["failure_signature"].as_str(), Some("none"));
    }
    Ok(())
}

#[test]
fn checker_rejects_reality_snapshot_drift() -> TestResult {
    let root = repo_root()?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["expected_reality_snapshot"]["total_exported"] = json!(4120);

    let out_dir = unique_out_dir(&root, "reality-drift")?;
    let mutated = out_dir.join("mutated_contract.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(!output.status.success(), "{}", output_text(&output));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("reality_report total_exported drifted"),
        "{}",
        output_text(&output)
    );
    Ok(())
}

#[test]
fn checker_rejects_fuzzed_unknown_support_status() -> TestResult {
    let root = repo_root()?;
    let mut manifest = load_json(&contract_path(&root))?;
    let mut support = load_json(&root.join("support_matrix.json"))?;
    support["symbols"][0]["status"] = json!("ExperimentalFuzzedStatus");

    let out_dir = unique_out_dir(&root, "fuzzed-status")?;
    let mutated_support = out_dir.join("support_matrix.fuzzed.json");
    let mutated_contract = out_dir.join("mutated_contract.json");
    write_json(&mutated_support, &support)?;
    manifest["source_artifacts"]["support_matrix"] = json!(mutated_support);
    write_json(&mutated_contract, &manifest)?;

    let output = run_checker(&root, &mutated_contract, &out_dir)?;
    assert!(!output.status.success(), "{}", output_text(&output));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("unknown support status"),
        "{}",
        output_text(&output)
    );
    Ok(())
}

#[test]
fn checker_rejects_bare_cargo_required_command() -> TestResult {
    let root = repo_root()?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["missing_item_bindings"][0]["required_commands"]
        .as_array_mut()
        .ok_or("commands array")?
        .push(json!(
            "cargo test -p frankenlibc-harness --test api_support_docs_generation_completion_contract_test"
        ));

    let out_dir = unique_out_dir(&root, "bare-cargo")?;
    let mutated = out_dir.join("mutated_contract.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(!output.status.success(), "{}", output_text(&output));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("must route cargo through rch"),
        "{}",
        output_text(&output)
    );
    Ok(())
}
