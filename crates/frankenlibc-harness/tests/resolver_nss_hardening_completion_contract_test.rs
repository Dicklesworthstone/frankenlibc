//! Completion contract tests for bd-1j4.3.1 resolver/NSS hardening evidence.

use std::collections::BTreeSet;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

static CHECKER_LOCK: Mutex<()> = Mutex::new(());

fn workspace_root() -> TestResult<PathBuf> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_dir = manifest_dir
        .parent()
        .ok_or("crate directory must have workspace parent")?;
    let root = workspace_dir
        .parent()
        .ok_or("workspace parent must have repo root")?;
    Ok(root.to_path_buf())
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/resolver_nss_hardening_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_resolver_nss_hardening_completion_contract.sh")
}

fn read_json(path: &Path) -> TestResult<serde_json::Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn write_json(path: &Path, value: &serde_json::Value) -> TestResult {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn read_jsonl(path: &Path) -> TestResult<Vec<serde_json::Value>> {
    std::fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let path = root.join("target/conformance").join(format!(
        "resolver-nss-hardening-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<std::process::Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_RESOLVER_NSS_HARDENING_CONTRACT", contract)
        .env(
            "FRANKENLIBC_RESOLVER_NSS_HARDENING_REPORT",
            out_dir.join("resolver_nss_hardening_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_RESOLVER_NSS_HARDENING_LOG",
            out_dir.join("resolver_nss_hardening_completion_contract.log.jsonl"),
        )
        .output()?)
}

fn checker_message(output: &std::process::Output) -> String {
    format!(
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn run_passing_checker(root: &Path, label: &str) -> TestResult<PathBuf> {
    let _guard = CHECKER_LOCK.lock().map_err(|_| "checker lock poisoned")?;
    let out_dir = unique_out_dir(root, label)?;
    let output = run_checker(root, &contract_path(root), &out_dir)?;
    assert!(output.status.success(), "{}", checker_message(&output));
    Ok(out_dir)
}

fn string_set(value: &serde_json::Value, context: &str) -> TestResult<BTreeSet<String>> {
    value
        .as_array()
        .ok_or_else(|| format!("{context} must be an array"))?
        .iter()
        .enumerate()
        .map(|(index, value)| -> TestResult<String> {
            Ok(value
                .as_str()
                .ok_or_else(|| format!("{context}[{index}] must be a string"))?
                .to_string())
        })
        .collect()
}

#[test]
fn manifest_binds_bd1j43_completion_items() -> TestResult {
    let root = workspace_root()?;
    let contract = read_json(&contract_path(&root))?;

    assert_eq!(
        contract["schema_version"].as_str(),
        Some("resolver_nss_hardening_completion_contract.v1")
    );
    assert_eq!(contract["bead"].as_str(), Some("bd-1j4.3"));
    assert_eq!(
        contract["completion_debt_bead"].as_str(),
        Some("bd-1j4.3.1")
    );

    let evidence = &contract["completion_debt_evidence"];
    assert_eq!(evidence["original_bead"].as_str(), Some("bd-1j4.3"));
    assert_eq!(evidence["next_audit_score_threshold"].as_u64(), Some(800));

    let missing_items: BTreeSet<String> = evidence["missing_item_bindings"]
        .as_array()
        .ok_or("completion_debt_evidence.missing_item_bindings must be array")?
        .iter()
        .enumerate()
        .map(|(index, binding)| -> TestResult<String> {
            Ok(binding["missing_item_id"]
                .as_str()
                .ok_or_else(|| {
                    format!("missing_item_bindings[{index}].missing_item_id must be string")
                })?
                .to_string())
        })
        .collect::<TestResult<_>>()?;
    assert_eq!(
        missing_items,
        BTreeSet::from([
            "tests.unit.primary".to_string(),
            "tests.e2e.primary".to_string(),
            "tests.fuzz.primary".to_string(),
            "tests.golden.primary".to_string(),
            "tests.conformance.primary".to_string(),
            "telemetry.primary".to_string(),
        ])
    );

    let required_cases: BTreeSet<String> = evidence["golden_primary"]["required_cases"]
        .as_array()
        .ok_or("golden_primary.required_cases must be array")?
        .iter()
        .enumerate()
        .map(|(index, case)| -> TestResult<String> {
            Ok(case
                .as_str()
                .ok_or_else(|| format!("golden_primary.required_cases[{index}] must be string"))?
                .to_string())
        })
        .collect::<TestResult<_>>()?;
    assert!(required_cases.contains("getaddrinfo_hosts_file_subset"));
    assert!(required_cases.contains("getaddrinfo_hosts_file_subset_hardened"));
    assert!(required_cases.contains("gethostbyname_numeric_ipv4"));
    assert!(required_cases.contains("gethostbyname_numeric_ipv4_hardened"));

    Ok(())
}

#[test]
fn checker_passes_and_emits_report_log() -> TestResult {
    let root = workspace_root()?;
    let out_dir = run_passing_checker(&root, "pass")?;
    let report =
        read_json(&out_dir.join("resolver_nss_hardening_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(
        report["event"].as_str(),
        Some("resolver_nss_hardening.completion_contract_validated")
    );
    assert!(report["unit_test_ref_count"].as_u64().unwrap_or_default() >= 6);
    assert!(report["golden_case_count"].as_u64().unwrap_or_default() >= 8);
    assert!(
        report["fuzz_corpus_seed_count"]
            .as_u64()
            .unwrap_or_default()
            >= 11
    );
    assert!(
        report["conformance_test_ref_count"]
            .as_u64()
            .unwrap_or_default()
            >= 3
    );

    let rows = read_jsonl(&out_dir.join("resolver_nss_hardening_completion_contract.log.jsonl"))?;
    let events: BTreeSet<String> = rows
        .iter()
        .filter_map(|row| row["event"].as_str().map(str::to_string))
        .collect();
    for required in [
        "resolver_nss_hardening.source_ref",
        "resolver_nss_hardening.missing_item_bound",
        "resolver_nss_hardening.fuzz_corpus_bound",
        "resolver_nss_hardening.golden_case_bound",
        "resolver_nss_hardening.completion_contract_validated",
    ] {
        assert!(
            events.contains(required),
            "missing telemetry event {required}: {events:?}"
        );
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_fuzz_corpus_binding() -> TestResult {
    let root = workspace_root()?;
    let mut contract = read_json(&contract_path(&root))?;
    contract["completion_debt_evidence"]["fuzz_primary"]["corpus_requirements"]
        .as_array_mut()
        .ok_or("fuzz_primary.corpus_requirements must be array")?
        .retain(|requirement| requirement["artifact"].as_str() != Some("fuzz_resolver_corpus"));

    let out_dir = unique_out_dir(&root, "missing-fuzz-corpus")?;
    let tampered = out_dir.join("contract.json");
    write_json(&tampered, &contract)?;

    let _guard = CHECKER_LOCK.lock().map_err(|_| "checker lock poisoned")?;
    let output = run_checker(&root, &tampered, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should fail for missing fuzz corpus binding"
    );
    let report =
        read_json(&out_dir.join("resolver_nss_hardening_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    let message = checker_message(&output);
    assert!(
        message.contains("fuzz corpus requirements"),
        "unexpected checker output: {message}"
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_telemetry_field() -> TestResult {
    let root = workspace_root()?;
    let mut contract = read_json(&contract_path(&root))?;
    contract["completion_debt_evidence"]["telemetry_primary"]["required_fields"]
        .as_array_mut()
        .ok_or("telemetry_primary.required_fields must be array")?
        .retain(|field| !matches!(field.as_str(), Some("failure_signature")));

    let out_dir = unique_out_dir(&root, "missing-telemetry")?;
    let tampered = out_dir.join("contract.json");
    write_json(&tampered, &contract)?;

    let _guard = CHECKER_LOCK.lock().map_err(|_| "checker lock poisoned")?;
    let output = run_checker(&root, &tampered, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should fail for missing telemetry field"
    );
    let report =
        read_json(&out_dir.join("resolver_nss_hardening_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    let fields = string_set(&report["missing_items"], "report.missing_items")?;
    assert!(fields.contains("telemetry.primary"));
    let message = checker_message(&output);
    assert!(
        message.contains("telemetry fields missing"),
        "unexpected checker output: {message}"
    );
    Ok(())
}
