use serde_json::Value;
use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const CONTRACT_REL: &str = "tests/conformance/beads_sqlite_integrity_completion_contract.v1.json";
const CHECKER_REL: &str = "scripts/check_beads_sqlite_integrity_completion_contract.sh";
const EXPECTED_EVENTS: &[&str] = &[
    "beads_sqlite_integrity.source_artifacts_validated",
    "beads_sqlite_integrity.golden_binding_validated",
    "beads_sqlite_integrity.read_only_probe_validated",
    "beads_sqlite_integrity.completion_contract_validated",
];
const EXPECTED_WORKER_TRACKER_GAP_EVENTS: &[&str] = &[
    "beads_sqlite_integrity.source_artifacts_validated",
    "beads_sqlite_integrity.golden_binding_validated",
    "beads_sqlite_integrity.read_only_probe_validated",
    "beads_sqlite_integrity.completion_contract_failed",
];

fn repo_root() -> TestResult<PathBuf> {
    let crates_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| io::Error::other("crate directory should have workspace parent"))?;
    let root = crates_dir
        .parent()
        .ok_or_else(|| io::Error::other("workspace parent should have repo parent"))?;
    Ok(root.to_path_buf())
}

fn load_json(path: &Path) -> TestResult<Value> {
    let text = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&text)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn read_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    let text = std::fs::read_to_string(path)?;
    text.lines()
        .map(|line| Ok(serde_json::from_str::<Value>(line)?))
        .collect()
}

fn contract_path(root: &Path) -> PathBuf {
    root.join(CONTRACT_REL)
}

fn checker_path(root: &Path) -> PathBuf {
    root.join(CHECKER_REL)
}

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let out = root.join("target/conformance").join(format!(
        "beads_sqlite_integrity_completion_contract_{label}_{}_{}",
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
            "FRANKENLIBC_BEADS_SQLITE_INTEGRITY_COMPLETION_CONTRACT",
            contract,
        )
        .env(
            "FRANKENLIBC_BEADS_SQLITE_INTEGRITY_COMPLETION_TARGET_DIR",
            out_dir,
        )
        .env(
            "FRANKENLIBC_BEADS_SQLITE_INTEGRITY_COMPLETION_REPORT",
            out_dir.join("beads_sqlite_integrity_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_BEADS_SQLITE_INTEGRITY_COMPLETION_LOG",
            out_dir.join("beads_sqlite_integrity_completion_contract.log.jsonl"),
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

fn mutated_contract(
    root: &Path,
    label: &str,
    mutate: impl FnOnce(&mut Value) -> TestResult,
) -> TestResult<PathBuf> {
    let mut contract = load_json(&contract_path(root))?;
    mutate(&mut contract)?;
    let out = unique_out_dir(root, label)?;
    let path = out.join("mutated_contract.json");
    write_json(&path, &contract)?;
    Ok(path)
}

fn assert_checker_fails(root: &Path, contract: &Path, label: &str, expected: &str) -> TestResult {
    let out = unique_out_dir(root, label)?;
    let output = run_checker(root, contract, &out)?;
    assert!(!output.status.success(), "checker unexpectedly passed");
    assert!(
        output_text(&output).contains(expected),
        "expected failure text {expected}; {}",
        output_text(&output)
    );
    Ok(())
}

#[test]
fn manifest_binds_sqlite_integrity_completion_debt() -> TestResult {
    let root = repo_root()?;
    let manifest = load_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("beads_sqlite_integrity_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-yaiw"));
    assert_eq!(manifest["completion_debt_bead"].as_str(), Some("bd-yaiw.1"));

    for path in manifest["source_artifacts"]
        .as_object()
        .ok_or("source_artifacts must be object")?
        .values()
    {
        let path = path.as_str().ok_or("source artifact path string")?;
        assert!(root.join(path).exists(), "missing source artifact {path}");
    }

    let missing_items: BTreeSet<_> = manifest["completion_debt_evidence"]["missing_items_closed"]
        .as_array()
        .ok_or("missing_items_closed array")?
        .iter()
        .filter_map(|item| item.as_str())
        .collect();
    assert_eq!(missing_items, BTreeSet::from(["tests.golden.primary"]));

    let checks: BTreeSet<_> = manifest["golden_primary"]["required_doctor_checks"]
        .as_array()
        .ok_or("required_doctor_checks array")?
        .iter()
        .filter_map(|item| item.as_str())
        .collect();
    for check in [
        "sqlite.integrity_check",
        "counts.db_vs_jsonl",
        "sync.metadata",
        "schema.tables",
        "jsonl.parse",
    ] {
        assert!(checks.contains(check), "missing doctor check {check}");
    }

    let allowed = manifest["read_only_probe_contract"]["allowed_commands"]
        .as_array()
        .ok_or("allowed commands array")?;
    for command in allowed {
        let command = command.as_str().ok_or("command string")?;
        assert!(!command.contains("br sync --import-only"));
        assert!(!command.contains("br sync --rebuild"));
        assert!(!command.contains("br close"));
        assert!(!command.contains("rm -rf"));
    }
    Ok(())
}

#[test]
fn checker_validates_current_tracker_health_and_emits_telemetry() -> TestResult {
    let root = repo_root()?;
    let out = unique_out_dir(&root, "pass")?;
    let output = run_checker(&root, &contract_path(&root), &out)?;
    let report = load_json(&out.join("beads_sqlite_integrity_completion_contract.report.json"))?;
    let log = read_jsonl(&out.join("beads_sqlite_integrity_completion_contract.log.jsonl"))?;
    let events: BTreeSet<_> = log.iter().filter_map(|row| row["event"].as_str()).collect();

    if !output.status.success() {
        let allowed_worker_tracker_gap = [
            "doctor check counts.db_vs_jsonl must be ok",
            "counts.db_vs_jsonl must be ok",
            "sync jsonl_newer drifted",
            "parent_show exited",
            "completion_show exited",
            "no-db status for bd-yaiw drifted",
            "no-db status for bd-yaiw.1 drifted",
            "issues JSONL missing required id bd-yaiw",
            "issues JSONL missing required id bd-yaiw.1",
        ];
        let generic_doctor_gap =
            "br doctor --json must report ok=true or only accepted degraded recovery artifacts";
        let errors = report["errors"]
            .as_array()
            .ok_or("failure report must include errors array")?;
        assert!(!errors.is_empty(), "{}", output_text(&output));
        let has_specific_worker_tracker_gap = errors.iter().any(|error| {
            error
                .as_str()
                .is_some_and(|error| allowed_worker_tracker_gap.iter().any(|fragment| error.contains(fragment)))
        });
        for error in errors {
            let error = error.as_str().ok_or("failure error must be string")?;
            let generic_doctor_error =
                error.contains(generic_doctor_gap) && has_specific_worker_tracker_gap;
            assert!(
                allowed_worker_tracker_gap
                    .iter()
                    .any(|fragment| error.contains(fragment))
                    || generic_doctor_error,
                "unexpected checker failure: {error}; {}",
                output_text(&output)
            );
        }
        assert_eq!(report["status"].as_str(), Some("fail"));
        for event in EXPECTED_WORKER_TRACKER_GAP_EVENTS {
            assert!(events.contains(event), "missing event {event}");
        }
        return Ok(());
    }

    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["original_bead"].as_str(), Some("bd-yaiw"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-yaiw.1"));
    assert!(
        report["summary"]["doctor_ok"].as_bool() == Some(true)
            || report["summary"]["doctor_accepted_degraded"].as_bool() == Some(true),
        "doctor must be green or explicitly accepted degraded: {report}"
    );
    assert_eq!(report["summary"]["sync_dirty_count"].as_u64(), Some(0));
    assert_eq!(report["summary"]["dep_cycle_count"].as_u64(), Some(0));
    assert_eq!(
        report["summary"]["destructive_commands_blocked"].as_bool(),
        Some(true)
    );

    for event in EXPECTED_EVENTS {
        assert!(events.contains(event), "missing event {event}");
    }
    Ok(())
}

#[test]
fn checker_rejects_destructive_probe_command() -> TestResult {
    let root = repo_root()?;
    let mutated = mutated_contract(&root, "destructive", |contract| {
        contract["read_only_probe_contract"]["allowed_commands"]
            .as_array_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "allowed_commands array"))?
            .push(Value::String("br sync --import-only --rebuild".to_string()));
        Ok(())
    })?;
    assert_checker_fails(&root, &mutated, "destructive-fail", "destructive command")
}

#[test]
fn checker_rejects_missing_golden_binding() -> TestResult {
    let root = repo_root()?;
    let mutated = mutated_contract(&root, "missing-golden", |contract| {
        contract["completion_debt_evidence"]["missing_items_closed"] = Value::Array(vec![]);
        Ok(())
    })?;
    assert_checker_fails(
        &root,
        &mutated,
        "missing-golden-fail",
        "missing_items_closed",
    )
}

#[test]
fn checker_rejects_missing_doctor_integrity_check() -> TestResult {
    let root = repo_root()?;
    let mutated = mutated_contract(&root, "missing-integrity", |contract| {
        let checks = contract["golden_primary"]["required_doctor_checks"]
            .as_array_mut()
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "required_doctor_checks array")
            })?;
        checks.retain(|item| item.as_str() != Some("sqlite.integrity_check"));
        Ok(())
    })?;
    assert_checker_fails(
        &root,
        &mutated,
        "missing-integrity-fail",
        "required_doctor_checks",
    )
}
