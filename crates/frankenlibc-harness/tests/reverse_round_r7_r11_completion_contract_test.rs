use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

static CHECKER_LOCK: Mutex<()> = Mutex::new(());

fn repo_root() -> TestResult<PathBuf> {
    Ok(Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("crate directory must have workspace parent")?
        .parent()
        .ok_or("workspace parent must have repo parent")?
        .to_path_buf())
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/reverse_round_r7_r11_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_reverse_round_r7_r11_completion_contract.sh")
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
        "reverse_round_r7_r11_completion_contract_{label}_{}_{}",
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
        .env("FRANKENLIBC_RR_R7_R11_COMPLETION_CONTRACT", contract)
        .env("FRANKENLIBC_RR_R7_R11_COMPLETION_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_RR_R7_R11_COMPLETION_REPORT",
            out_dir.join("reverse_round_r7_r11_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_RR_R7_R11_COMPLETION_LOG",
            out_dir.join("reverse_round_r7_r11_completion_contract.log.jsonl"),
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
fn manifest_binds_unit_and_e2e_completion_evidence() -> TestResult {
    let root = repo_root()?;
    let manifest = load_json(&contract_path(&root))?;
    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("reverse_round_r7_r11_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-2a2.1"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-2a2.1.1")
    );

    let source_artifacts = manifest["source_artifacts"]
        .as_object()
        .ok_or("source_artifacts object")?;
    for required in [
        "reverse_round_generator",
        "reverse_round_report",
        "reverse_round_gate",
        "reverse_round_harness",
        "reverse_round_plan",
        "runtime_math_epic_gate",
        "completion_checker",
        "completion_harness_test",
    ] {
        let path = source_artifacts[required].as_str().ok_or("source path")?;
        assert!(root.join(path).exists(), "source artifact missing: {path}");
    }

    let bindings = manifest["missing_item_bindings"]
        .as_array()
        .ok_or("missing_item_bindings array")?;
    let unit = bindings
        .iter()
        .find(|item| item["id"].as_str() == Some("tests.unit.primary"))
        .ok_or("tests.unit.primary binding")?;
    let e2e = bindings
        .iter()
        .find(|item| item["id"].as_str() == Some("tests.e2e.primary"))
        .ok_or("tests.e2e.primary binding")?;
    assert_eq!(unit["kind"].as_str(), Some("unit"));
    assert_eq!(e2e["kind"].as_str(), Some("e2e"));

    let unit_tests: Vec<_> = unit["required_test_refs"]
        .as_array()
        .ok_or("unit test refs")?
        .iter()
        .filter_map(|item| item.as_str())
        .collect();
    for required in [
        "contracts_schema_complete",
        "contracts_all_modules_exist",
        "contracts_r7_r11_verification_hooks_capture_all_declared_paths",
        "checker_validates_reverse_round_r7_r11_completion_contract",
    ] {
        assert!(
            unit_tests.contains(&required),
            "missing unit ref {required}"
        );
    }

    let e2e_tests: Vec<_> = e2e["required_test_refs"]
        .as_array()
        .ok_or("e2e test refs")?
        .iter()
        .filter_map(|item| item.as_str())
        .collect();
    for required in [
        "contracts_report_generates_successfully",
        "gate_script_emits_report_and_structured_log",
        "contracts_reproducible",
        "reverse_round_plan_doc_sections_include_execution_contracts",
    ] {
        assert!(e2e_tests.contains(&required), "missing e2e ref {required}");
    }

    let report = load_json(&root.join("tests/conformance/reverse_round_contracts.v1.json"))?;
    assert_eq!(report["schema_version"].as_str(), Some("v1"));
    assert_eq!(report["bead"].as_str(), Some("bd-2a2.5"));
    assert_eq!(report["summary"]["rounds_verified"].as_u64(), Some(35));
    assert_eq!(report["summary"]["modules_missing"].as_u64(), Some(0));
    for round_id in ["R7", "R8", "R9", "R10", "R11"] {
        assert!(
            report["round_results"][round_id].is_object(),
            "missing round {round_id}"
        );
    }

    Ok(())
}

#[test]
fn checker_validates_reverse_round_r7_r11_completion_contract() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "validates")?;
    let output = run_checker_serial(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("PASS: reverse-round R7-R11 completion contract")
    );

    let report = load_json(&out_dir.join("reverse_round_r7_r11_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["source_bead"].as_str(), Some("bd-2a2.1"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-2a2.1.1"));
    assert_eq!(report["summary"]["bound_rounds"].as_u64(), Some(5));
    assert_eq!(report["summary"]["modules_found"].as_u64(), Some(140));
    assert_eq!(report["summary"]["modules_missing"].as_u64(), Some(0));
    assert_eq!(
        report["summary"]["cross_round_checks_passing"].as_u64(),
        Some(6)
    );

    Ok(())
}

#[test]
fn checker_emits_completion_report_and_jsonl() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "jsonl")?;
    let output = run_checker_serial(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report = load_json(&out_dir.join("reverse_round_r7_r11_completion_contract.report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("reverse_round_r7_r11_completion_contract.report.v1")
    );
    let events = string_values(&report["events"])?;
    for event in [
        "reverse_round_r7_r11_completion_summary",
        "reverse_round_r7_r11_round_bindings",
        "reverse_round_r7_r11_source_bindings",
        "reverse_round_r7_r11_test_bindings",
        "reverse_round_r7_r11_completion_contract_pass",
    ] {
        assert!(events.iter().any(|value| value == event), "missing {event}");
    }

    let rows = read_jsonl(&out_dir.join("reverse_round_r7_r11_completion_contract.log.jsonl"))?;
    assert_eq!(rows.len(), 5, "checker should emit five telemetry rows");
    for row in rows {
        for field in [
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
            "round_ids",
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
fn checker_rejects_missing_round_binding() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing_round")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["required_reverse_round_contract"]["required_rounds"]
        .as_object_mut()
        .ok_or("required_rounds object")?
        .remove("R11");
    let mutated = out_dir.join("missing_round_contract.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker_serial(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing round binding:\n{}",
        output_text(&output)
    );
    let stderr_stdout = output_text(&output);
    assert!(
        stderr_stdout.contains("required_reverse_round_contract.required_rounds")
            && stderr_stdout.contains("R11"),
        "unexpected rejection output:\n{stderr_stdout}"
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_source_test_ref() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing_test_ref")?;
    let mut manifest = load_json(&contract_path(&root))?;
    let refs = manifest["completion_debt_evidence"]["test_sources"]["reverse_round_harness"]
        ["required_test_refs"]
        .as_array_mut()
        .ok_or("required_test_refs array")?;
    refs.retain(|item| item.as_str() != Some("contracts_all_modules_exist"));
    let mutated = out_dir.join("missing_source_test_ref_contract.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker_serial(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing source test ref:\n{}",
        output_text(&output)
    );
    let stderr_stdout = output_text(&output);
    assert!(
        stderr_stdout.contains("test_sources.reverse_round_harness.required_test_refs")
            && stderr_stdout.contains("contracts_all_modules_exist"),
        "unexpected rejection output:\n{stderr_stdout}"
    );

    Ok(())
}

#[test]
fn checker_rejects_unimplemented_telemetry_event() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "bad_event")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["completion_debt_evidence"]["telemetry_events"][0] = json!("todo_unimplemented_event");
    let mutated = out_dir.join("bad_telemetry_event_contract.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker_serial(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject unknown telemetry event:\n{}",
        output_text(&output)
    );
    let stderr_stdout = output_text(&output);
    assert!(
        stderr_stdout.contains("unsupported event")
            && stderr_stdout.contains("todo_unimplemented_event"),
        "unexpected rejection output:\n{stderr_stdout}"
    );

    Ok(())
}
