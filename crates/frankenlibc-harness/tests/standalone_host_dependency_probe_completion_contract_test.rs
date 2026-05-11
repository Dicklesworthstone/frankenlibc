use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const CONTRACT_REL: &str =
    "tests/conformance/standalone_host_dependency_probe_completion_contract.v1.json";
const CHECKER_REL: &str = "scripts/check_standalone_host_dependency_probe_completion_contract.sh";
const EXPECTED_EVENTS: [&str; 3] = [
    "standalone_host_probe_conformance_bound",
    "standalone_host_probe_stale_source_bound",
    "standalone_host_probe_completion_contract_validated",
];

fn checker_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .expect("checker lock poisoned")
}

fn workspace_root() -> io::Result<PathBuf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "workspace root"))
}

fn workspace_relative_path(root: &Path, path: &str) -> io::Result<PathBuf> {
    let candidate = Path::new(path);
    if candidate.is_absolute() || candidate.components().any(|c| c.as_os_str() == "..") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("path must be repo-relative: {path}"),
        ));
    }
    Ok(root.join(candidate))
}

fn read_json(path: &Path) -> io::Result<Value> {
    let text = std::fs::read_to_string(path)?;
    serde_json::from_str(&text).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

fn write_json(path: &Path, value: &Value) -> io::Result<()> {
    std::fs::create_dir_all(
        path.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "path should have parent")
        })?,
    )?;
    let text = serde_json::to_string_pretty(value)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    std::fs::write(path, format!("{text}\n"))
}

fn read_jsonl(path: &Path) -> io::Result<Vec<Value>> {
    let text = std::fs::read_to_string(path)?;
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str(line)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
        })
        .collect()
}

fn unique_output_dir(root: &Path, label: &str) -> io::Result<PathBuf> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_nanos();
    let dir = root.join("target").join("conformance").join(format!(
        "standalone_host_probe_completion_contract_test-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn run_checker(root: &Path, contract_path: &Path, out_dir: &Path) -> io::Result<Output> {
    Command::new("bash")
        .arg(workspace_relative_path(root, CHECKER_REL)?)
        .current_dir(root)
        .env(
            "FRANKENLIBC_STANDALONE_HOST_PROBE_COMPLETION_CONTRACT",
            contract_path,
        )
        .env(
            "FRANKENLIBC_STANDALONE_HOST_PROBE_COMPLETION_OUT_DIR",
            out_dir,
        )
        .output()
}

fn output_text(output: &Output) -> String {
    format!(
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn string_set(value: &Value) -> io::Result<BTreeSet<String>> {
    value
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "expected array"))?
        .iter()
        .map(|item| {
            item.as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "expected string"))
        })
        .collect()
}

fn function_exists(source_text: &str, name: &str) -> bool {
    source_text.contains(&format!("fn {name}("))
        || source_text.contains(&format!("fn {name}<"))
        || source_text.contains(&format!("def {name}("))
}

fn assert_line_ref(root: &Path, ref_obj: &Value) -> TestResult {
    let path = ref_obj["path"]
        .as_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "ref path"))?;
    let line = ref_obj["line"]
        .as_u64()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "ref line"))?
        as usize;
    let anchor = ref_obj["anchor"]
        .as_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "ref anchor"))?;
    let text = std::fs::read_to_string(workspace_relative_path(root, path)?)?;
    let lines = text.lines().collect::<Vec<_>>();
    assert!(
        line > 0 && line <= lines.len() && lines[line - 1].contains(anchor),
        "{path}:{line} missing anchor {anchor}"
    );
    Ok(())
}

#[test]
fn manifest_binds_host_dependency_probe_conformance_evidence() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&root.join(CONTRACT_REL))?;
    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("standalone_host_dependency_probe_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-zyck1.35"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-zyck1.35.1")
    );
    assert_eq!(
        string_set(&manifest["audit"]["missing_items"])?,
        ["tests.conformance.primary"]
            .iter()
            .map(|item| (*item).to_string())
            .collect()
    );

    let source_artifacts = manifest["source_artifacts"]
        .as_object()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "source_artifacts"))?;
    for path in source_artifacts.values().filter_map(Value::as_str) {
        assert!(
            workspace_relative_path(&root, path)?.is_file(),
            "source artifact should exist: {path}"
        );
    }
    for ref_obj in manifest["implementation_refs"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "implementation refs"))?
    {
        assert_line_ref(&root, ref_obj)?;
    }

    let conformance = manifest["conformance_contract"]
        .as_object()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "conformance_contract"))?;
    assert_eq!(
        conformance["source_plan_bead"].as_str(),
        Some("bd-b92jd.1.1")
    );
    assert_eq!(conformance["required_probe_count"].as_u64(), Some(14));
    assert_eq!(
        conformance["required_claim_blocked_count"].as_u64(),
        Some(13)
    );
    assert_eq!(
        conformance["required_source_commit_freshness_policy"]["stale_result"].as_str(),
        Some("block_standalone_host_dependency_probe_evidence")
    );
    assert_eq!(
        conformance["required_source_commit_freshness_policy"]
            ["host_dependency_probe_evidence_allowed_when_stale"]
            .as_bool(),
        Some(false)
    );

    let mut binding_covers = BTreeMap::new();
    for binding in manifest["evidence_bindings"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "evidence_bindings"))?
    {
        let binding_id = binding["binding_id"]
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "binding_id"))?;
        let covers = string_set(&binding["covers"])?;
        binding_covers.insert(binding_id.to_string(), covers);
        for key in binding["required_artifact_keys"]
            .as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "required_artifact_keys"))?
            .iter()
            .filter_map(Value::as_str)
        {
            assert!(
                source_artifacts.contains_key(key),
                "missing artifact key {key}"
            );
        }
        for command in binding["required_commands"]
            .as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "required_commands"))?
            .iter()
            .filter_map(Value::as_str)
        {
            if command.contains("cargo ") {
                assert!(
                    command.contains("rch exec"),
                    "cargo command must be rch-backed: {command}"
                );
            }
        }
        for test_ref in binding["required_test_refs"]
            .as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "required_test_refs"))?
        {
            let source = test_ref["source"]
                .as_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "test source"))?;
            let name = test_ref["name"]
                .as_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "test name"))?;
            let path = source_artifacts[source]
                .as_str()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "source path"))?;
            let text = std::fs::read_to_string(workspace_relative_path(&root, path)?)?;
            assert!(
                function_exists(&text, name),
                "{source} should define {name}"
            );
        }
    }
    assert!(
        binding_covers["standalone_host_dependency_probe_stale_source_gate"]
            .contains("tests.conformance.primary")
    );
    Ok(())
}

#[test]
fn checker_emits_host_probe_completion_report_and_jsonl() -> TestResult {
    let _lock = checker_lock();
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "valid")?;
    let output = run_checker(&root, &root.join(CONTRACT_REL), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report = read_json(
        &out_dir.join("standalone_host_dependency_probe_completion_contract.report.json"),
    )?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("standalone_host_dependency_probe_completion_contract.report.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["summary"]["coverage_count"].as_u64(), Some(1));
    assert_eq!(report["summary"]["binding_count"].as_u64(), Some(1));
    assert_eq!(report["summary"]["probe_count"].as_u64(), Some(14));
    assert_eq!(report["summary"]["claim_blocked_count"].as_u64(), Some(13));

    let rows = read_jsonl(
        &out_dir.join("standalone_host_dependency_probe_completion_contract.log.jsonl"),
    )?;
    assert_eq!(rows.len(), EXPECTED_EVENTS.len());
    let seen = rows
        .iter()
        .filter_map(|row| row["event"].as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(seen, EXPECTED_EVENTS.iter().copied().collect());
    for row in rows {
        for field in [
            "timestamp",
            "trace_id",
            "level",
            "event",
            "bead_id",
            "original_bead",
            "completion_debt_bead",
            "status",
            "evidence_binding_ids",
            "missing_item_ids",
            "artifact_refs",
            "validation_commands",
            "source_commit",
            "probe_count",
            "claim_blocked_count",
            "stale_result",
            "failure_signature",
        ] {
            assert!(row.get(field).is_some(), "log row missing {field}");
        }
        assert_eq!(row["status"].as_str(), Some("pass"));
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_freshness_policy_binding() -> TestResult {
    let _lock = checker_lock();
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-freshness")?;
    let mut manifest = read_json(&root.join(CONTRACT_REL))?;
    manifest["conformance_contract"]["required_source_commit_freshness_policy"]
        .as_object_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "freshness policy"))?
        .remove("rejected_evidence_kind");

    let tampered = out_dir.join("tampered_contract.json");
    write_json(&tampered, &manifest)?;
    let output = run_checker(&root, &tampered, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should fail without freshness policy binding"
    );
    assert!(
        output_text(&output).contains("required_source_commit_freshness_policy mismatch"),
        "{}",
        output_text(&output)
    );
    Ok(())
}

#[test]
fn checker_rejects_underbound_conformance_binding() -> TestResult {
    let _lock = checker_lock();
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "underbound-conformance")?;
    let mut manifest = read_json(&root.join(CONTRACT_REL))?;
    manifest["completion_coverage"][0]["binding_ids"] = json!([]);

    let tampered = out_dir.join("tampered_contract.json");
    write_json(&tampered, &manifest)?;
    let output = run_checker(&root, &tampered, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should fail with underbound conformance evidence"
    );
    assert!(
        output_text(&output).contains("tests.conformance.primary must bind"),
        "{}",
        output_text(&output)
    );
    Ok(())
}

#[test]
fn checker_rejects_local_cargo_validation_command() -> TestResult {
    let _lock = checker_lock();
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "local-cargo")?;
    let mut manifest = read_json(&root.join(CONTRACT_REL))?;
    manifest["completion_coverage"][0]["validation_commands"]
        .as_array_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "validation_commands"))?
        .push(json!("cargo test -p frankenlibc-harness"));

    let tampered = out_dir.join("tampered_contract.json");
    write_json(&tampered, &manifest)?;
    let output = run_checker(&root, &tampered, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject local cargo validation"
    );
    assert!(
        output_text(&output).contains("cargo validation must be rch-backed"),
        "{}",
        output_text(&output)
    );
    Ok(())
}
