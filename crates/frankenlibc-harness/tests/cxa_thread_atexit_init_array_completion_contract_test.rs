//! Contract tests for bd-yf86e.1 __cxa_thread_atexit_impl init-array completion.

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
    root.join("tests/conformance/cxa_thread_atexit_init_array_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_cxa_thread_atexit_init_array_completion_contract.sh")
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
        "cxa_thread_atexit_init_array_completion_contract_{label}_{}_{}",
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
            "FRANKENLIBC_CXA_THREAD_ATEXIT_INIT_ARRAY_COMPLETION_CONTRACT",
            contract,
        )
        .env(
            "FRANKENLIBC_CXA_THREAD_ATEXIT_INIT_ARRAY_COMPLETION_REPORT",
            out_dir.join("cxa_thread_atexit_init_array_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_CXA_THREAD_ATEXIT_INIT_ARRAY_COMPLETION_LOG",
            out_dir.join("cxa_thread_atexit_init_array_completion_contract.log.jsonl"),
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

#[test]
fn manifest_binds_cxa_thread_atexit_init_array_completion_evidence() -> TestResult {
    let root = repo_root()?;
    let manifest = read_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("cxa_thread_atexit_init_array_completion_contract.v1")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-yf86e"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-yf86e.1")
    );

    let evidence = &manifest["completion_debt_evidence"];
    assert_eq!(evidence["bead"].as_str(), Some("bd-yf86e.1"));
    assert_eq!(evidence["original_bead"].as_str(), Some("bd-yf86e"));
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
            "host-cxa-cache-is-atomic-not-oncelock".to_string(),
            "host-cxa-resolver-has-reentry-escape".to_string(),
            "sweep-regression-gate-builds-current-abi-before-smoke".to_string(),
            "tls-fallback-breaks-recursive-registration".to_string(),
        ])
    );

    let required_commands = evidence["conformance_primary"]["required_commands"]
        .as_array()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "required_commands should be an array",
            )
        })?
        .iter()
        .map(|value| {
            value.as_str().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "required command should be string",
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let command_text = required_commands.join("\n");
    assert!(command_text.contains("rch exec --"));
    for command in command_text.lines().filter(|line| line.contains("cargo ")) {
        assert!(
            command.contains("rch exec --"),
            "cargo command must route through rch: {command}"
        );
    }

    Ok(())
}

#[test]
fn checker_validates_atomic_resolver_and_reentry_guard() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "positive")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report =
        read_json(&out_dir.join("cxa_thread_atexit_init_array_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["bead"].as_str(), Some("bd-yf86e.1"));
    assert_eq!(report["original_bead"].as_str(), Some("bd-yf86e"));

    let rows =
        read_jsonl(&out_dir.join("cxa_thread_atexit_init_array_completion_contract.log.jsonl"))?;
    assert!(rows.iter().any(|row| {
        row["event"].as_str() == Some("cxa_thread_atexit_init_array_completion_contract_validated")
            && row["status"].as_str() == Some("pass")
    }));
    assert!(
        rows.iter()
            .filter(|row| row["event"].as_str()
                == Some("cxa_thread_atexit_init_array_source_invariant"))
            .all(|row| row["status"].as_str() == Some("pass")),
        "all source invariants should pass"
    );

    Ok(())
}

#[test]
fn checker_rejects_once_lock_regression() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "once_lock_regression")?;
    let fake_impl = out_dir.join("startup_abi_once_lock_regression.rs");
    let original_impl =
        std::fs::read_to_string(root.join("crates/frankenlibc-abi/src/startup_abi.rs"))?;
    let regressed_impl = original_impl
        .replace(
            "static HOST_CXA_THREAD_ATEXIT_IMPL: std::sync::atomic::AtomicUsize",
            "static HOST_CXA_THREAD_ATEXIT_IMPL: std::sync::OnceLock<HostCxaThreadAtExitImplFn>",
        )
        .replace(
            "std::sync::atomic::AtomicUsize::new(0)",
            "std::sync::OnceLock::new()",
        );
    std::fs::write(&fake_impl, regressed_impl)?;

    let mut manifest = read_json(&contract_path(&root))?;
    manifest["source_artifacts"]["implementation"] = Value::String(
        fake_impl
            .strip_prefix(&root)?
            .to_string_lossy()
            .into_owned(),
    );
    let fake_contract = out_dir.join("contract_once_lock_regression.json");
    write_json(&fake_contract, &manifest)?;

    let output = run_checker(&root, &fake_contract, &out_dir)?;
    assert!(!output.status.success(), "{}", output_text(&output));
    let report =
        read_json(&out_dir.join("cxa_thread_atexit_init_array_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    let errors = report["errors"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "errors should be an array"))?
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(errors.contains("host-cxa-cache-is-atomic-not-oncelock"));

    Ok(())
}
