//! Contract tests for bd-cxafv.1 C++ ABI fail-stop completion evidence.

use serde_json::Value;
use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn repo_root() -> TestResult<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let crates_dir = manifest
        .parent()
        .ok_or_else(|| io::Error::other("manifest should have a crates parent"))?;
    let root = crates_dir
        .parent()
        .ok_or_else(|| io::Error::other("manifest should live under the workspace root"))?;
    Ok(root.to_path_buf())
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/cxx_abi_fail_stop_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_cxx_abi_fail_stop_completion_contract.sh")
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
    std::fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| Ok(serde_json::from_str::<Value>(line)?))
        .collect()
}

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let path = root.join("target/conformance").join(format!(
        "cxx_abi_fail_stop_completion_contract_{label}_{}_{}",
        std::process::id(),
        stamp
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env(
            "FRANKENLIBC_CXX_ABI_FAIL_STOP_COMPLETION_CONTRACT",
            contract,
        )
        .env(
            "FRANKENLIBC_CXX_ABI_FAIL_STOP_COMPLETION_REPORT",
            out_dir.join("cxx_abi_fail_stop_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_CXX_ABI_FAIL_STOP_COMPLETION_LOG",
            out_dir.join("cxx_abi_fail_stop_completion_contract.log.jsonl"),
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

fn manifest_invariant_ids(manifest: &Value) -> TestResult<BTreeSet<String>> {
    let invariants = manifest["completion_debt_evidence"]["required_source_invariants"]
        .as_array()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "required_source_invariants should be an array",
            )
        })?;
    invariants
        .iter()
        .map(|entry| -> TestResult<String> {
            let id = entry["id"].as_str().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invariant id should be a string",
                )
            })?;
            Ok(id.to_string())
        })
        .collect()
}

fn string_array(value: &Value, context: &str) -> TestResult<Vec<String>> {
    value
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, context.to_string()))?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, context.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

#[test]
fn manifest_binds_cxx_abi_fail_stop_completion_evidence() -> TestResult {
    let root = repo_root()?;
    let manifest = read_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("cxx_abi_fail_stop_completion_contract.v1")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-cxafv"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-cxafv.1")
    );

    let evidence = &manifest["completion_debt_evidence"];
    assert_eq!(evidence["bead"].as_str(), Some("bd-cxafv.1"));
    assert_eq!(evidence["original_bead"].as_str(), Some("bd-cxafv"));
    assert_eq!(
        string_array(
            &evidence["covered_symbols"],
            "covered_symbols should be strings"
        )?,
        vec!["__cxa_pure_virtual", "__cxa_deleted_virtual"]
    );
    assert_eq!(
        string_array(
            &evidence["tracked_but_not_completion_bound_symbols"],
            "tracked symbols should be strings",
        )?,
        vec!["__cxa_throw_bad_array_new_length", "__cxa_call_unexpected"]
    );
    assert_eq!(
        evidence["conformance_primary"]["missing_item_id"].as_str(),
        Some("tests.conformance.primary")
    );
    assert!(
        evidence["conformance_primary"]["next_audit_score_threshold"]
            .as_u64()
            .is_some_and(|score| score >= 800)
    );

    assert_eq!(
        manifest_invariant_ids(&manifest)?,
        BTreeSet::from([
            "cxx-fail-stop-deleted-virtual-stderr-fixture".to_string(),
            "cxx-fail-stop-fixtures-prove-sigabrt".to_string(),
            "cxx-fail-stop-implementation-exports-covered-hooks".to_string(),
            "cxx-fail-stop-process-helper-captures-stderr".to_string(),
            "cxx-fail-stop-pure-virtual-stderr-fixture".to_string(),
            "cxx-fail-stop-semantic-contract-remains-abort-only".to_string(),
        ])
    );

    let required_commands = string_array(
        &evidence["conformance_primary"]["required_commands"],
        "required_commands should be strings",
    )?;
    let command_text = required_commands.join("\n");
    assert!(command_text.contains("rch exec --"));
    assert!(command_text.contains("RCH_REQUIRE_REMOTE=1"));
    assert!(command_text.contains("CARGO_TARGET_DIR="));
    for command in command_text.lines().filter(|line| line.contains("cargo ")) {
        assert!(
            command.contains("rch exec --"),
            "cargo command must route through rch: {command}"
        );
        assert!(
            command.contains("RCH_REQUIRE_REMOTE=1"),
            "cargo command must require remote execution: {command}"
        );
    }

    Ok(())
}

#[test]
fn checker_accepts_current_cxx_abi_fail_stop_evidence() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "positive")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report = read_json(&out_dir.join("cxx_abi_fail_stop_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["bead"].as_str(), Some("bd-cxafv.1"));
    assert_eq!(report["original_bead"].as_str(), Some("bd-cxafv"));

    let rows = read_jsonl(&out_dir.join("cxx_abi_fail_stop_completion_contract.log.jsonl"))?;
    assert!(rows.iter().any(|row| {
        row["event"].as_str() == Some("cxx_abi_fail_stop_completion_contract_validated")
            && row["status"].as_str() == Some("pass")
    }));
    assert!(
        rows.iter()
            .filter(|row| row["event"].as_str() == Some("cxx_abi_fail_stop_source_invariant"))
            .all(|row| row["status"].as_str() == Some("pass")),
        "all source invariants should pass"
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_deleted_virtual_stderr_probe() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "deleted_virtual_regression")?;
    let fake_tests = out_dir.join("unistd_abi_test_deleted_virtual_regression.rs");
    let original_tests =
        std::fs::read_to_string(root.join("crates/frankenlibc-abi/tests/unistd_abi_test.rs"))?;
    let regressed_tests = original_tests.replace(
        "\"deleted virtual method called\"",
        "\"deleted virtual diagnostic changed\"",
    );
    std::fs::write(&fake_tests, regressed_tests)?;

    let fake_tests_rel = fake_tests
        .strip_prefix(&root)?
        .to_string_lossy()
        .into_owned();
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["source_artifacts"]["unistd_abi_tests"] = Value::String(fake_tests_rel.clone());
    manifest["completion_debt_evidence"]["test_sources"]["unistd_abi_tests"] =
        Value::String(fake_tests_rel);
    let fake_contract = out_dir.join("contract_deleted_virtual_regression.json");
    write_json(&fake_contract, &manifest)?;

    let output = run_checker(&root, &fake_contract, &out_dir)?;
    assert!(!output.status.success(), "{}", output_text(&output));
    let report = read_json(&out_dir.join("cxx_abi_fail_stop_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    let errors = report["errors"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "errors should be an array"))?
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(errors.contains("cxx-fail-stop-deleted-virtual-stderr-fixture"));

    Ok(())
}
