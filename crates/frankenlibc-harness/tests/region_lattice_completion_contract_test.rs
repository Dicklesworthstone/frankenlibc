//! Contract tests for bd-32e.3.1 region-lattice completion evidence.

use std::collections::BTreeSet;
use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let crates_dir = manifest
        .parent()
        .ok_or_else(|| io::Error::other("frankenlibc-harness manifest should have a parent"))?;
    let root = crates_dir.parent().ok_or_else(|| {
        io::Error::other("frankenlibc-harness manifest should live below the workspace root")
    })?;
    Ok(root.to_path_buf())
}

fn read_manifest(root: &Path) -> TestResult<serde_json::Value> {
    let path = root.join("tests/conformance/region_lattice_completion_contract.v1.json");
    let text = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&text)?)
}

fn write_json(path: &Path, value: &serde_json::Value) -> TestResult {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn unique_output_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let path = root.join("target/conformance").join(format!(
        "region-lattice-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<std::process::Output> {
    Ok(Command::new("bash")
        .arg(root.join("scripts/check_region_lattice_completion_contract.sh"))
        .current_dir(root)
        .env("FRANKENLIBC_REGION_LATTICE_CONTRACT", contract)
        .env(
            "FRANKENLIBC_REGION_LATTICE_REPORT",
            out_dir.join("region_lattice_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_REGION_LATTICE_LOG",
            out_dir.join("region_lattice_completion_contract.log.jsonl"),
        )
        .output()?)
}

fn read_json(path: &Path) -> TestResult<serde_json::Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
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

fn json_str_field_is(row: &serde_json::Value, field: &str, expected: &str) -> bool {
    row.get(field)
        .and_then(serde_json::Value::as_str)
        .is_some_and(|value| value.eq(expected))
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
    let full_path = root.join(path);
    assert!(
        full_path.is_file(),
        "file-line ref path should exist: {file_line_ref}"
    );
    let line_count = std::fs::read_to_string(full_path)?.lines().count();
    assert!(
        line_no <= line_count,
        "file-line ref outside file: {file_line_ref}"
    );
    Ok(())
}

fn source_texts(
    root: &Path,
    manifest: &serde_json::Value,
) -> TestResult<std::collections::BTreeMap<String, String>> {
    let sources = manifest["completion_debt_evidence"]["test_sources"]
        .as_object()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "test_sources object"))?;
    let mut texts = std::collections::BTreeMap::new();
    for (key, path) in sources {
        let path = path
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "source path string"))?;
        texts.insert(key.clone(), std::fs::read_to_string(root.join(path))?);
    }
    Ok(texts)
}

#[test]
fn manifest_binds_lattice_unit_e2e_and_telemetry_evidence() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_manifest(&root)?;
    assert_eq!(manifest["bead"].as_str(), Some("bd-32e.3"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-32e.3.1")
    );

    let evidence = &manifest["completion_debt_evidence"];
    assert_eq!(evidence["bead"].as_str(), Some("bd-32e.3.1"));
    assert_eq!(evidence["original_bead"].as_str(), Some("bd-32e.3"));
    assert!(
        evidence["next_audit_score_threshold"].as_u64().unwrap_or(0) >= 800,
        "completion evidence should target a passing next audit score"
    );

    let states = string_set(&manifest["source_contract"]["lattice_states"])?;
    for state in [
        "Valid",
        "Readable",
        "Writable",
        "Quarantined",
        "Freed",
        "Invalid",
        "Unknown",
    ] {
        assert!(states.contains(state), "missing lattice state {state}");
    }
    assert!(
        string_set(&manifest["source_contract"]["required_laws"])?
            .contains("join_never_increases_permissiveness"),
        "lattice contract should bind the monotonic-safety law"
    );

    for refs_key in ["implementation_refs", "proof_refs"] {
        for file_line_ref in manifest["source_contract"][refs_key]
            .as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "refs array"))?
        {
            assert_file_line_ref_exists(
                &root,
                file_line_ref.as_str().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "file-line ref string")
                })?,
            )?;
        }
    }

    let source_texts = source_texts(&root, &manifest)?;
    for (section, missing_item) in [
        ("unit_primary", "tests.unit.primary"),
        ("e2e_primary", "tests.e2e.primary"),
        ("telemetry_primary", "telemetry.primary"),
    ] {
        let section_value = &evidence[section];
        assert_eq!(
            section_value["missing_item_id"].as_str(),
            Some(missing_item)
        );
        let refs = section_value["required_test_refs"]
            .as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "test refs array"))?;
        assert!(!refs.is_empty(), "{section} should name test refs");
        for test_ref in refs {
            let source = test_ref["source"]
                .as_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "source string"))?;
            let name = test_ref["name"]
                .as_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "test name string"))?;
            let text = source_texts.get(source).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "source should be declared")
            })?;
            assert!(
                text.contains(&format!("fn {name}(")),
                "{section} references missing test {source}::{name}"
            );
        }
    }

    let required_fields = string_set(&evidence["telemetry_primary"]["required_fields"])?;
    for field in [
        "trace_id",
        "completion_debt_bead",
        "original_bead",
        "source_commit",
        "test_refs",
        "artifact_refs",
        "failure_signature",
    ] {
        assert!(
            required_fields.contains(field),
            "telemetry should require field {field}"
        );
    }

    Ok(())
}

#[test]
fn checker_emits_report_and_jsonl() -> TestResult {
    let root = workspace_root()?;
    let contract = root.join("tests/conformance/region_lattice_completion_contract.v1.json");
    let out_dir = unique_output_dir(&root, "pass")?;
    let output = run_checker(&root, &contract, &out_dir)?;
    assert!(
        output.status.success(),
        "checker failed stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = read_json(&out_dir.join("region_lattice_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-32e.3.1"));
    assert_eq!(report["original_bead"].as_str(), Some("bd-32e.3"));
    assert!(
        report["law_count"].as_u64().unwrap_or(0) >= 10,
        "report should count lattice laws"
    );
    assert!(
        report["test_refs"]
            .as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "test refs array"))?
            .iter()
            .any(|item| item.as_str() == Some("lattice::prop_absorption_join")),
        "report should include lattice property refs"
    );

    let rows = read_jsonl(&out_dir.join("region_lattice_completion_contract.log.jsonl"))?;
    assert_eq!(rows.len(), 1, "checker should emit one telemetry row");
    let row = &rows[0];
    assert!(json_str_field_is(
        row,
        "event",
        "region_lattice_completion_contract_validated"
    ));
    assert!(json_str_field_is(row, "completion_debt_bead", "bd-32e.3.1"));
    assert!(json_str_field_is(row, "status", "pass"));
    assert!(json_str_field_is(row, "failure_signature", "none"));
    assert!(
        row["artifact_refs"]
            .as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "artifact refs array"))?
            .iter()
            .any(|item| {
                item.as_str()
                    == Some("tests/conformance/region_lattice_completion_contract.v1.json")
            }),
        "telemetry should point at the contract artifact"
    );

    Ok(())
}

#[test]
fn checker_rejects_stale_lattice_test_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "stale")?;
    let mut manifest = read_manifest(&root)?;
    manifest["completion_debt_evidence"]["unit_primary"]["required_test_refs"] = serde_json::json!([
        {"source": "lattice", "name": "missing_region_lattice_completion_test"}
    ]);
    let stale_contract = out_dir.join("stale_region_lattice_completion_contract.v1.json");
    write_json(&stale_contract, &manifest)?;

    let output = run_checker(&root, &stale_contract, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject stale test bindings"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("missing_region_lattice_completion_test"),
        "checker output should name the stale binding: {combined}"
    );

    let report = read_json(&out_dir.join("region_lattice_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "errors array"))?
            .iter()
            .any(|item| item
                .as_str()
                .unwrap_or("")
                .contains("missing_region_lattice_completion_test")),
        "report should retain the stale binding error"
    );

    Ok(())
}
