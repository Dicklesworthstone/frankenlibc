//! Completion contract tests for bd-z84.1.

use frankenlibc_harness::structured_log::validate_log_line;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const CONTRACT_REL: &str = "tests/conformance/pthread_mutex_futex_core_completion_contract.v1.json";
const CHECKER_REL: &str = "scripts/check_pthread_mutex_futex_core_completion_contract.sh";
const EXPECTED_SCHEMA: &str = "pthread_mutex_futex_core_completion_contract.v1";
const EXPECTED_REPORT_SCHEMA: &str = "pthread_mutex_futex_core_completion_contract.report.v1";
const EXPECTED_EVENTS: &[&str] = &[
    "pthread_mutex_futex_core.sources_validated",
    "pthread_mutex_futex_core.unit_binding",
    "pthread_mutex_futex_core.e2e_binding",
    "pthread_mutex_futex_core.prior_gates_replayed",
    "pthread_mutex_futex_core.telemetry_contract",
    "pthread_mutex_futex_core.completion_contract_validated",
];

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    Ok(manifest
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| io::Error::other("manifest should live below workspace root"))?
        .to_path_buf())
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

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let dir = root.join("target/conformance").join(format!(
        "pthread-mutex-futex-core-completion-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn checker_report(out_dir: &Path) -> PathBuf {
    out_dir.join("report.json")
}

fn checker_log(out_dir: &Path) -> PathBuf {
    out_dir.join("events.jsonl")
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(root.join(CHECKER_REL))
        .current_dir(root)
        .env("FRANKENLIBC_PTHREAD_MUTEX_FUTEX_CORE_CONTRACT", contract)
        .env("FRANKENLIBC_PTHREAD_MUTEX_FUTEX_CORE_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_PTHREAD_MUTEX_FUTEX_CORE_REPORT",
            checker_report(out_dir),
        )
        .env(
            "FRANKENLIBC_PTHREAD_MUTEX_FUTEX_CORE_LOG",
            checker_log(out_dir),
        )
        .env(
            "FRANKENLIBC_PTHREAD_MUTEX_FUTEX_CORE_GATE_DIR",
            out_dir.join("prior_gates"),
        )
        .output()?)
}

fn expect_checker_success(root: &Path, out_dir: &Path) -> TestResult<Output> {
    let output = run_checker(root, &root.join(CONTRACT_REL), out_dir)?;
    assert!(
        output.status.success(),
        "checker failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(output)
}

fn expect_checker_failure(output: Output, signature: &str) {
    assert!(
        !output.status.success(),
        "checker unexpectedly succeeded\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains(signature),
        "checker failure missing signature {signature:?}\n{combined}"
    );
}

fn string_field<'a>(value: &'a Value, key: &str) -> TestResult<&'a str> {
    value.get(key).and_then(Value::as_str).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, format!("{key} string missing")).into()
    })
}

fn object_field<'a>(value: &'a Value, key: &str) -> TestResult<&'a serde_json::Map<String, Value>> {
    value.get(key).and_then(Value::as_object).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, format!("{key} object missing")).into()
    })
}

fn array_field<'a>(value: &'a Value, key: &str) -> TestResult<&'a Vec<Value>> {
    value.get(key).and_then(Value::as_array).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, format!("{key} array missing")).into()
    })
}

fn string_set(values: &[Value]) -> TestResult<BTreeSet<String>> {
    values
        .iter()
        .map(|value| {
            value.as_str().map(ToOwned::to_owned).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "expected string value").into()
            })
        })
        .collect()
}

fn load_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    std::fs::read_to_string(path)?
        .lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(index, line)| {
            validate_log_line(line, index + 1).map_err(|errors| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("structured log line {} failed: {errors:?}", index + 1),
                )
            })?;
            Ok(serde_json::from_str(line)?)
        })
        .collect()
}

#[test]
fn contract_binds_bd_z84_completion_debt() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&root.join(CONTRACT_REL))?;
    assert_eq!(string_field(&manifest, "schema_version")?, EXPECTED_SCHEMA);
    assert_eq!(string_field(&manifest, "bead_id")?, "bd-z84.1");
    assert_eq!(string_field(&manifest, "original_bead")?, "bd-z84");

    let completion = manifest
        .get("completion_contract")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "completion contract missing"))?;
    assert_eq!(
        string_set(array_field(completion, "missing_item_ids")?)?,
        BTreeSet::from([
            "telemetry.primary".to_string(),
            "tests.e2e.primary".to_string(),
            "tests.unit.primary".to_string()
        ])
    );
    assert_eq!(
        array_field(completion, "required_unit_tests")?.len(),
        5,
        "bd-z84.1 must bind the five focused futex mutex tests"
    );
    assert_eq!(
        array_field(completion, "required_prior_gates")?.len(),
        3,
        "bd-z84.1 must replay semantics, callthrough, and invariant gates"
    );
    Ok(())
}

#[test]
fn source_anchors_resolve() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&root.join(CONTRACT_REL))?;
    let source_artifacts = object_field(&manifest, "source_artifacts")?;

    for (artifact_id, path) in source_artifacts {
        let path = path.as_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{artifact_id} path should be a string"),
            )
        })?;
        assert!(root.join(path).exists(), "source artifact missing: {path}");
    }

    for (artifact_id, anchors) in object_field(&manifest, "source_anchors")? {
        let path = source_artifacts
            .get(artifact_id)
            .and_then(Value::as_str)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{artifact_id} source path missing"),
                )
            })?;
        let text = std::fs::read_to_string(root.join(path))?;
        for anchor in anchors
            .as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "anchors must be array"))?
        {
            let anchor = anchor.as_str().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "anchor must be string")
            })?;
            assert!(
                text.contains(anchor),
                "{artifact_id} missing source anchor {anchor:?}"
            );
        }
    }
    Ok(())
}

#[test]
fn checker_accepts_contract_and_emits_structured_log() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_out_dir(&root, "accepts")?;
    let output = expect_checker_success(&root, &out_dir)?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("PASS: pthread mutex futex-core completion contract"),
        "pass marker missing from stdout: {stdout}"
    );

    let report = read_json(&checker_report(&out_dir))?;
    assert_eq!(
        string_field(&report, "schema_version")?,
        EXPECTED_REPORT_SCHEMA
    );
    assert_eq!(string_field(&report, "status")?, "pass");
    let summary = object_field(&report, "summary")?;
    assert_eq!(
        summary.get("missing_item_count").and_then(Value::as_u64),
        Some(3)
    );
    assert_eq!(
        summary.get("prior_gate_count").and_then(Value::as_u64),
        Some(3)
    );

    let records = load_jsonl(&checker_log(&out_dir))?;
    let events = records
        .iter()
        .map(|record| Ok(string_field(record, "event")?.to_owned()))
        .collect::<TestResult<BTreeSet<_>>>()?;
    for event in EXPECTED_EVENTS {
        assert!(events.contains(*event), "missing event {event}");
    }
    Ok(())
}

#[test]
fn checker_replays_prior_completion_gates() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_out_dir(&root, "prior-gates")?;
    expect_checker_success(&root, &out_dir)?;
    let report = read_json(&checker_report(&out_dir))?;
    let gates = object_field(&report, "prior_gate_results")?;
    assert!(gates.contains_key("semantics"));
    assert!(gates.contains_key("callthrough"));
    assert!(gates.contains_key("state_invariants"));
    for gate_id in ["semantics", "callthrough", "state_invariants"] {
        assert_eq!(
            gates
                .get(gate_id)
                .and_then(|gate| gate.get("exit_code"))
                .and_then(Value::as_u64),
            Some(0),
            "prior gate {gate_id} should pass"
        );
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_e2e_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_out_dir(&root, "missing-e2e")?;
    let contract_path = out_dir.join("contract.missing-e2e.json");
    let mut manifest = read_json(&root.join(CONTRACT_REL))?;
    let bindings = manifest
        .get_mut("missing_item_bindings")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "missing_item_bindings missing")
        })?;
    bindings
        .retain(|binding| binding.get("id").and_then(Value::as_str) != Some("tests.e2e.primary"));
    write_json(&contract_path, &manifest)?;

    let output = run_checker(&root, &contract_path, &out_dir)?;
    expect_checker_failure(output, "missing_e2e_binding");
    Ok(())
}

#[test]
fn checker_rejects_cargo_command_without_rch() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_out_dir(&root, "cargo-without-rch")?;
    let contract_path = out_dir.join("contract.cargo-without-rch.json");
    let mut manifest = read_json(&root.join(CONTRACT_REL))?;
    manifest["missing_item_bindings"][0]["required_commands"] =
        json!(["cargo test -p frankenlibc-abi --test pthread_mutex_core_test"]);
    write_json(&contract_path, &manifest)?;

    let output = run_checker(&root, &contract_path, &out_dir)?;
    expect_checker_failure(output, "cargo_not_rch");
    Ok(())
}
