use serde_json::{Value, json};
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

static CHECKER_LOCK: Mutex<()> = Mutex::new(());

fn repo_root() -> TestResult<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let crates_dir = manifest
        .parent()
        .ok_or_else(|| io::Error::other("frankenlibc-harness manifest should have a parent"))?;
    let root = crates_dir.parent().ok_or_else(|| {
        io::Error::other("frankenlibc-harness manifest should live below workspace root")
    })?;
    Ok(root.to_path_buf())
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/allocator_e2e_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_allocator_e2e_completion_contract.sh")
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

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let out = root.join("target/conformance").join(format!(
        "allocator_e2e_completion_contract_{label}_{}_{}",
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
        .env("FRANKENLIBC_ALLOCATOR_E2E_COMPLETION_CONTRACT", contract)
        .env("FRANKENLIBC_ALLOCATOR_E2E_COMPLETION_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_ALLOCATOR_E2E_COMPLETION_REPORT",
            out_dir.join("allocator_e2e_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_ALLOCATOR_E2E_COMPLETION_LOG",
            out_dir.join("allocator_e2e_completion_contract.log.jsonl"),
        )
        .output()?)
}

fn run_checker_serial(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<Output> {
    let _guard = CHECKER_LOCK.lock().map_err(|_| "checker lock poisoned")?;
    run_checker(root, contract, out_dir)
}

fn output_text(output: &Output) -> String {
    format!(
        "status={}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn read_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    std::fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| Ok(serde_json::from_str::<Value>(line)?))
        .collect()
}

fn string_values(value: &Value) -> TestResult<Vec<String>> {
    let array = value.as_array().ok_or("expected array")?;
    let mut values = Vec::with_capacity(array.len());
    for item in array {
        values.push(item.as_str().ok_or("expected string item")?.to_string());
    }
    Ok(values)
}

#[test]
fn manifest_binds_e2e_and_conformance_completion_evidence() -> TestResult {
    let root = repo_root()?;
    let manifest = load_json(&contract_path(&root))?;
    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("allocator_e2e_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-2x5.5"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-2x5.5.1")
    );

    let source_artifacts = manifest["source_artifacts"]
        .as_object()
        .ok_or("source_artifacts object")?;
    for required in [
        "allocator_e2e_gate",
        "c_fixture_spec",
        "malloc_fixture",
        "malloc_stress_fixture",
        "allocator_conformance_fixture",
        "allocator_conformance_harness",
        "completion_checker",
        "completion_harness_test",
    ] {
        let path = source_artifacts[required].as_str().ok_or("source path")?;
        assert!(root.join(path).exists(), "source artifact missing: {path}");
    }

    let bindings = manifest["missing_item_bindings"]
        .as_array()
        .ok_or("missing_item_bindings array")?;
    let e2e = bindings
        .iter()
        .find(|item| item["id"].as_str() == Some("tests.e2e.primary"))
        .ok_or("tests.e2e.primary binding")?;
    let conformance = bindings
        .iter()
        .find(|item| item["id"].as_str() == Some("tests.conformance.primary"))
        .ok_or("tests.conformance.primary binding")?;
    assert_eq!(e2e["kind"].as_str(), Some("e2e"));
    assert_eq!(conformance["kind"].as_str(), Some("conformance"));

    let e2e_tests: Vec<_> = e2e["required_test_refs"]
        .as_array()
        .ok_or("e2e test refs")?
        .iter()
        .filter_map(|item| item.as_str())
        .collect();
    for required in [
        "allocator_e2e_gate_runs_host_strict_hardened",
        "allocator_e2e_gate_diffs_strict_hardened_against_host",
        "malloc_stress_fixture_covers_concurrency_fragmentation_and_signature",
        "checker_validates_allocator_e2e_completion_contract",
    ] {
        assert!(e2e_tests.contains(&required), "missing e2e ref {required}");
    }

    let conformance_tests: Vec<_> = conformance["required_test_refs"]
        .as_array()
        .ok_or("conformance test refs")?
        .iter()
        .filter_map(|item| item.as_str())
        .collect();
    for required in [
        "allocator_fixture_valid_schema",
        "allocator_covers_malloc",
        "allocator_covers_realloc",
        "allocator_fixture_executes_via_isolated_harness",
    ] {
        assert!(
            conformance_tests.contains(&required),
            "missing conformance ref {required}"
        );
    }

    let fixture = load_json(&root.join("tests/conformance/fixtures/allocator.json"))?;
    assert_eq!(fixture["version"].as_str(), Some("v1"));
    assert_eq!(fixture["family"].as_str(), Some("allocator"));
    assert!(fixture["cases"].as_array().ok_or("cases array")?.len() >= 5);

    Ok(())
}

#[test]
fn checker_validates_allocator_e2e_completion_contract() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "validates")?;
    let output = run_checker_serial(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("PASS: allocator E2E completion contract")
    );

    let report = load_json(&out_dir.join("allocator_e2e_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["source_bead"].as_str(), Some("bd-2x5.5"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-2x5.5.1"));
    assert_eq!(report["summary"]["fixtures_bound"].as_u64(), Some(2));
    assert_eq!(
        report["summary"]["allocator_conformance_cases"].as_u64(),
        Some(5)
    );

    Ok(())
}

#[test]
fn checker_emits_allocator_completion_report_and_jsonl() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "jsonl")?;
    let output = run_checker_serial(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report = load_json(&out_dir.join("allocator_e2e_completion_contract.report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("allocator_e2e_completion_contract.report.v1")
    );
    let events = string_values(&report["events"])?;
    for event in [
        "allocator_e2e_completion_summary",
        "allocator_e2e_fixture_bindings",
        "allocator_e2e_conformance_bindings",
        "allocator_e2e_test_bindings",
        "allocator_e2e_completion_contract_pass",
    ] {
        assert!(events.iter().any(|value| value == event), "missing {event}");
    }

    let rows = read_jsonl(&out_dir.join("allocator_e2e_completion_contract.log.jsonl"))?;
    assert_eq!(rows.len(), 5, "checker should emit five telemetry rows");
    for row in rows {
        for field in [
            "timestamp",
            "event",
            "bead_id",
            "source_bead",
            "status",
            "outcome",
            "source_commit",
            "schema_version",
            "artifact_refs",
            "test_refs",
            "fixtures",
            "conformance_cases",
            "failure_signature",
        ] {
            assert!(!row[field].is_null(), "log row missing {field}: {row}");
        }
        assert_eq!(row["status"].as_str(), Some("pass"));
        assert_eq!(row["failure_signature"].as_str(), Some("none"));
    }

    Ok(())
}

#[test]
fn checker_rejects_missing_stress_fixture_binding() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing_stress")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["required_fixture_spec"]["fixtures"]
        .as_object_mut()
        .ok_or("fixtures object")?
        .remove("fixture_malloc_stress");
    let mutated = out_dir.join("missing_stress_fixture_contract.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker_serial(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing stress fixture binding:\n{}",
        output_text(&output)
    );
    let combined = output_text(&output);
    assert!(
        combined.contains("tests.e2e.primary.required_test_refs")
            || combined.contains("fixtures_bound")
            || combined.contains("fixture_malloc_stress"),
        "unexpected rejection output:\n{combined}"
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_conformance_test_ref() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing_conformance_ref")?;
    let mut manifest = load_json(&contract_path(&root))?;
    let refs = manifest["completion_debt_evidence"]["test_sources"]
        ["allocator_conformance_harness"]["required_test_refs"]
        .as_array_mut()
        .ok_or("required_test_refs array")?;
    refs.retain(|item| item.as_str() != Some("allocator_covers_realloc"));
    let mutated = out_dir.join("missing_conformance_test_ref_contract.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker_serial(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing conformance test ref:\n{}",
        output_text(&output)
    );
    let combined = output_text(&output);
    assert!(
        combined.contains("allocator_conformance_harness.required_test_refs")
            && combined.contains("allocator_covers_realloc"),
        "unexpected rejection output:\n{combined}"
    );

    Ok(())
}

#[test]
fn checker_rejects_unknown_telemetry_event() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "bad_event")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["telemetry_events"][0] =
        json!("allocator_unimplemented_placeholder_event");
    let mutated = out_dir.join("bad_telemetry_event_contract.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker_serial(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject unknown telemetry event:\n{}",
        output_text(&output)
    );
    let combined = output_text(&output);
    assert!(
        combined.contains("unsupported event")
            && combined.contains("allocator_unimplemented_placeholder_event"),
        "unexpected rejection output:\n{combined}"
    );

    Ok(())
}
