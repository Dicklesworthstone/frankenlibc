//! Contract tests for bd-rqn.1 production-kernel manifest completion evidence.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn workspace_root() -> TestResult<PathBuf> {
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
    root.join("tests/conformance/production_kernel_manifest_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_production_kernel_manifest_completion_contract.sh")
}

fn workspace_relative_path(root: &Path, path: &str) -> TestResult<PathBuf> {
    let relative = Path::new(path);
    let has_escape = relative.is_absolute()
        || relative
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::Prefix(_)));
    if has_escape {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("path should stay under workspace root: {path}"),
        )
        .into());
    }
    Ok(root.join(relative))
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

fn string_set(value: &serde_json::Value) -> TestResult<BTreeSet<String>> {
    let array = value
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "expected string array"))?;
    let mut set = BTreeSet::new();
    for item in array {
        set.insert(
            item.as_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "expected string"))?
                .to_string(),
        );
    }
    Ok(set)
}

fn unique_output_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let path = root.join("target/conformance").join(format!(
        "production-kernel-manifest-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<std::process::Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env(
            "FRANKENLIBC_PRODUCTION_KERNEL_COMPLETION_CONTRACT",
            contract,
        )
        .env(
            "FRANKENLIBC_PRODUCTION_KERNEL_COMPLETION_REPORT",
            out_dir.join("production_kernel_manifest_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_PRODUCTION_KERNEL_COMPLETION_LOG",
            out_dir.join("production_kernel_manifest_completion_contract.log.jsonl"),
        )
        .env(
            "FRANKENLIBC_PRODUCTION_KERNEL_COMPLETION_GATE_TRANSCRIPT",
            out_dir.join("production_kernel_manifest_completion_contract.gate.txt"),
        )
        .output()?)
}

fn run_passing_checker(root: &Path, label: &str) -> TestResult<PathBuf> {
    let out_dir = unique_output_dir(root, label)?;
    let output = run_checker(root, &contract_path(root), &out_dir)?;
    assert!(
        output.status.success(),
        "checker failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(out_dir)
}

fn checker_output_message(output: &std::process::Output) -> String {
    format!(
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn assert_file_line_ref_exists(root: &Path, file_line_ref: &str) -> TestResult {
    let (path, line) = file_line_ref.rsplit_once(':').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "file-line ref should contain ':'",
        )
    })?;
    let line_no: usize = line.parse()?;
    assert!(line_no > 0, "file-line ref line must be positive");
    let full_path = workspace_relative_path(root, path)?;
    assert!(
        full_path.is_file(),
        "file-line ref path should exist: {file_line_ref}"
    );
    let contents = std::fs::read_to_string(full_path)?;
    let lines: Vec<_> = contents.lines().collect();
    assert!(
        line_no <= lines.len() && !lines[line_no - 1].trim().is_empty(),
        "file-line ref should point to a non-empty line: {file_line_ref}"
    );
    Ok(())
}

fn source_texts(root: &Path, manifest: &serde_json::Value) -> TestResult<BTreeMap<String, String>> {
    let sources = manifest["completion_debt_evidence"]["test_sources"]
        .as_object()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "test_sources object"))?;
    let mut texts = BTreeMap::new();
    for (key, path) in sources {
        let path = path
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "source path string"))?;
        texts.insert(
            key.clone(),
            std::fs::read_to_string(workspace_relative_path(root, path)?)?,
        );
    }
    Ok(texts)
}

fn assert_test_refs_exist(
    section: &serde_json::Value,
    source_texts: &BTreeMap<String, String>,
) -> TestResult<BTreeSet<String>> {
    let refs = section["required_test_refs"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "required_test_refs array"))?;
    let mut names = BTreeSet::new();
    for test_ref in refs {
        let source = test_ref["source"]
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "test source"))?;
        let name = test_ref["name"]
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "test name"))?;
        let text = source_texts
            .get(source)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "source not loaded"))?;
        assert!(
            text.contains(&format!("fn {name}")),
            "{source} should contain test function {name}"
        );
        names.insert(format!("{source}::{name}"));
    }
    Ok(names)
}

#[test]
fn manifest_binds_unit_e2e_migration_and_telemetry_evidence() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&contract_path(&root))?;
    assert_eq!(manifest["bead"].as_str(), Some("bd-rqn"));
    assert_eq!(manifest["completion_debt_bead"].as_str(), Some("bd-rqn.1"));

    let evidence = &manifest["completion_debt_evidence"];
    assert_eq!(evidence["bead"].as_str(), Some("bd-rqn.1"));
    assert_eq!(evidence["original_bead"].as_str(), Some("bd-rqn"));
    assert!(
        evidence["next_audit_score_threshold"].as_u64().unwrap_or(0) >= 800,
        "completion evidence should force a passing next audit score"
    );

    for file_line_ref in evidence["implementation_refs"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "refs array"))?
    {
        assert_file_line_ref_exists(
            &root,
            file_line_ref
                .as_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "ref string"))?,
        )?;
    }

    let artifacts = evidence["artifacts"]
        .as_object()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "artifacts object"))?;
    for path in artifacts.values() {
        let path = path
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "artifact path"))?;
        assert!(
            workspace_relative_path(&root, path)?.is_file(),
            "artifact should exist: {path}"
        );
    }

    let production_manifest = read_json(&workspace_relative_path(
        &root,
        artifacts["production_manifest"]
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "production manifest"))?,
    )?)?;
    assert_eq!(production_manifest["schema_version"].as_str(), Some("v1"));
    assert_eq!(
        production_manifest["production_modules"]
            .as_array()
            .map(Vec::len),
        Some(25)
    );
    assert_eq!(
        production_manifest["research_only_modules"]
            .as_array()
            .map(Vec::len),
        Some(44)
    );
    assert_eq!(
        production_manifest["default_feature_set"]
            .as_array()
            .map(Vec::len),
        Some(1)
    );
    assert_eq!(
        production_manifest["optional_feature_set"]
            .as_array()
            .map(Vec::len),
        Some(1)
    );

    let source_texts = source_texts(&root, &manifest)?;
    let cargo_text = source_texts
        .get("profile_gates")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "profile source"))?;
    assert!(
        cargo_text.contains("runtime-math-production")
            && cargo_text.contains("runtime-math-research"),
        "profile gate tests should bind production/research features"
    );

    for (section, missing_item) in [
        ("unit_primary", "tests.unit.primary"),
        ("e2e_primary", "tests.e2e.primary"),
        ("migrations_primary", "migrations.primary"),
        ("telemetry_primary", "telemetry.primary"),
    ] {
        let block = &evidence[section];
        assert_eq!(block["missing_item_id"].as_str(), Some(missing_item));
        assert!(
            !assert_test_refs_exist(block, &source_texts)?.is_empty(),
            "{section} should bind tests"
        );
        let commands = block["required_commands"]
            .as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "commands array"))?;
        assert!(!commands.is_empty(), "{section} should list commands");
        for command in commands {
            let command = command
                .as_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "command string"))?;
            if command.contains("cargo ") || command.contains("check_runtime_math_profile_gates.sh")
            {
                assert!(
                    command.contains("rch exec"),
                    "cargo/profile command should be offloaded through rch: {command}"
                );
            }
        }
    }

    let telemetry = &evidence["telemetry_primary"];
    let events = string_set(&telemetry["required_events"])?;
    for event in [
        "production_kernel_manifest_summary",
        "production_kernel_manifest_gate_replayed",
        "production_kernel_migration_validated",
        "production_kernel_completion_contract_validated",
        "production_kernel_completion_contract_failed",
    ] {
        assert!(events.contains(event), "missing telemetry event {event}");
    }
    let fields = string_set(&telemetry["required_fields"])?;
    for field in [
        "trace_id",
        "mode",
        "api_family",
        "symbol",
        "outcome",
        "errno",
        "timing_ns",
        "artifact_refs",
        "failure_signature",
    ] {
        assert!(fields.contains(field), "missing telemetry field {field}");
    }
    Ok(())
}

#[test]
fn checker_emits_report_and_jsonl() -> TestResult {
    let root = workspace_root()?;
    let out_dir = run_passing_checker(&root, "ok")?;

    let report =
        read_json(&out_dir.join("production_kernel_manifest_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(
        report["summary"]["production_module_count"].as_u64(),
        Some(25)
    );
    assert_eq!(
        report["summary"]["research_only_module_count"].as_u64(),
        Some(44)
    );
    assert_eq!(
        report["summary"]["total_runtime_math_modules"].as_u64(),
        Some(69)
    );
    assert_eq!(report["summary"]["gate_count"].as_u64(), Some(4));

    let rows =
        read_jsonl(&out_dir.join("production_kernel_manifest_completion_contract.log.jsonl"))?;
    assert!(
        rows.len() >= 7,
        "checker should emit multiple telemetry rows"
    );
    assert!(rows.iter().any(|row| matches!(
        (
            row.get("event").and_then(serde_json::Value::as_str),
            row.get("status").and_then(serde_json::Value::as_str),
            row.get("failure_signature")
                .and_then(serde_json::Value::as_str),
        ),
        (
            Some("production_kernel_completion_contract_validated"),
            Some("pass"),
            Some("none")
        )
    )));
    for row in &rows {
        for field in [
            "timestamp",
            "trace_id",
            "event",
            "completion_debt_bead",
            "original_bead",
            "source_commit",
            "status",
            "mode",
            "api_family",
            "symbol",
            "outcome",
            "errno",
            "timing_ns",
            "artifact_refs",
        ] {
            assert!(row.get(field).is_some(), "row missing field {field}");
        }
        assert_eq!(row["completion_debt_bead"].as_str(), Some("bd-rqn.1"));
        assert_eq!(row["original_bead"].as_str(), Some("bd-rqn"));
        assert_eq!(row["api_family"].as_str(), Some("runtime_math"));
    }
    Ok(())
}

#[test]
fn checker_replays_runtime_math_gates() -> TestResult {
    let root = workspace_root()?;
    let out_dir = run_passing_checker(&root, "gate-replay")?;
    let transcript = std::fs::read_to_string(
        out_dir.join("production_kernel_manifest_completion_contract.gate.txt"),
    )?;
    assert!(transcript.contains("OK: runtime_math production manifest covers 69 modules"));
    assert!(transcript.contains("check_math_governance: PASS"));
    assert!(transcript.contains("PASS: runtime_math classification matrix covers 69 modules"));
    assert!(transcript.contains("PASS: production-set policy gate validated 25 modules"));
    Ok(())
}

#[test]
fn checker_validates_manifest_partition_and_migration() -> TestResult {
    let root = workspace_root()?;
    let out_dir = run_passing_checker(&root, "migration")?;
    let report =
        read_json(&out_dir.join("production_kernel_manifest_completion_contract.report.json"))?;
    assert_eq!(
        report["summary"]["admission_summary"]["admitted"].as_u64(),
        Some(25)
    );
    assert_eq!(
        report["summary"]["admission_summary"]["retired"].as_u64(),
        Some(44)
    );
    assert_eq!(
        report["summary"]["admission_summary"]["blocked"].as_u64(),
        Some(0)
    );

    let manifest = read_json(&root.join("tests/runtime_math/production_kernel_manifest.v1.json"))?;
    let production = string_set(&manifest["production_modules"])?;
    let research = string_set(&manifest["research_only_modules"])?;
    assert!(production.is_disjoint(&research));
    assert_eq!(production.len(), 25);
    assert_eq!(research.len(), 44);
    Ok(())
}

#[test]
fn checker_rejects_missing_research_feature_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-feature-binding")?;
    let mut manifest = read_json(&contract_path(&root))?;
    let bindings =
        manifest["completion_debt_evidence"]["migration_contract"]["required_feature_bindings"]
            .as_array_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "feature binding array"))?;
    bindings.retain(|row| {
        !matches!(
            row.as_str(),
            Some("runtime-math-research = [\"runtime-math-production\"]")
        )
    });
    let bad_contract = out_dir.join("bad_contract.json");
    write_json(&bad_contract, &manifest)?;

    let output = run_checker(&root, &bad_contract, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing feature binding:\n{}",
        checker_output_message(&output)
    );
    let report =
        read_json(&out_dir.join("production_kernel_manifest_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|error| error
                .as_str()
                .is_some_and(|text| text.contains("required_feature_bindings"))),
        "failure report should explain missing feature binding"
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_telemetry_field_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-telemetry-field")?;
    let mut manifest = read_json(&contract_path(&root))?;
    let fields = manifest["completion_debt_evidence"]["telemetry_primary"]["required_fields"]
        .as_array_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "telemetry fields array"))?;
    fields.retain(|row| !matches!(row.as_str(), Some("timing_ns")));
    let bad_contract = out_dir.join("bad_contract.json");
    write_json(&bad_contract, &manifest)?;

    let output = run_checker(&root, &bad_contract, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing telemetry field:\n{}",
        checker_output_message(&output)
    );
    let report =
        read_json(&out_dir.join("production_kernel_manifest_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|error| error
                .as_str()
                .is_some_and(|text| text.contains("timing_ns"))),
        "failure report should name missing telemetry field"
    );
    Ok(())
}
