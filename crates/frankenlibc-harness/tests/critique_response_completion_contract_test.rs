use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn workspace_root() -> TestResult<PathBuf> {
    let crates_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("crate directory should have workspace parent")?;
    let root = crates_dir
        .parent()
        .ok_or("workspace parent should have repo parent")?;
    Ok(root.to_path_buf())
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/critique_response_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_critique_response_completion_contract.sh")
}

fn read_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn read_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    Ok(std::fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<Result<Vec<_>, _>>()?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn write_text(path: &Path, value: &str) -> TestResult {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, value)?;
    Ok(())
}

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let out = root.join("target/conformance").join(format!(
        "critique_response_completion_contract_{label}_{}_{}",
        std::process::id(),
        nanos
    ));
    std::fs::create_dir_all(&out)?;
    Ok(out)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env(
            "FRANKENLIBC_CRITIQUE_RESPONSE_COMPLETION_CONTRACT",
            contract,
        )
        .env("FRANKENLIBC_CRITIQUE_RESPONSE_COMPLETION_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_CRITIQUE_RESPONSE_COMPLETION_REPORT",
            out_dir.join("critique_response_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_CRITIQUE_RESPONSE_COMPLETION_LOG",
            out_dir.join("critique_response_completion_contract.log.jsonl"),
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

fn dependency_ids() -> [&'static str; 16] {
    [
        "bd-226", "bd-3ot", "bd-30o", "bd-b5a", "bd-33p", "bd-15n", "bd-29b", "bd-5fw", "bd-4rl",
        "bd-3fb", "bd-kan", "bd-1zd", "bd-mtj", "bd-1x3", "bd-h5x", "bd-1j4",
    ]
}

fn issue_fixture() -> TestResult<String> {
    let dependencies = dependency_ids()
        .into_iter()
        .map(|id| json!({"id": id, "status": "closed"}))
        .collect::<Vec<_>>();
    let mut rows = vec![json!({
        "id": "bd-3qq",
        "status": "closed",
        "close_reason": "HA1zgq Critique Response: project is real, honest, and falsifiable. 3980+ classified symbols, host-backed wrappers explicitly accounted, zero stubs, comprehensive tests, CVE arena, differential testing, formal proofs.",
        "dependencies": dependencies,
    })];
    rows.extend(
        dependency_ids()
            .into_iter()
            .map(|id| json!({"id": id, "status": "closed"})),
    );
    Ok(rows
        .into_iter()
        .map(|row| serde_json::to_string(&row))
        .collect::<Result<Vec<_>, _>>()?
        .join("\n")
        + "\n")
}

fn repo_relative(root: &Path, path: &Path) -> TestResult<String> {
    Ok(path
        .strip_prefix(root)?
        .to_string_lossy()
        .replace(std::path::MAIN_SEPARATOR, "/"))
}

fn fixture_contract(root: &Path, label: &str, manifest: &Value) -> TestResult<(PathBuf, PathBuf)> {
    let out_dir = unique_out_dir(root, label)?;
    let issues_path = out_dir.join("issues_current.jsonl");
    write_text(&issues_path, &issue_fixture()?)?;
    let mut manifest = manifest.clone();
    manifest["source_artifacts"]["issues_jsonl"] = json!(repo_relative(root, &issues_path)?);
    let contract_path = out_dir.join("contract.json");
    write_json(&contract_path, &manifest)?;
    Ok((contract_path, out_dir))
}

fn string_set(value: &Value) -> TestResult<BTreeSet<String>> {
    value
        .as_array()
        .ok_or("expected string array")?
        .iter()
        .map(|item| {
            item.as_str()
                .ok_or_else(|| "array item must be string".into())
                .map(str::to_owned)
        })
        .collect::<Result<BTreeSet<_>, Box<dyn std::error::Error>>>()
}

fn json_array<'a>(value: &'a Value, description: &str) -> TestResult<&'a Vec<Value>> {
    value
        .as_array()
        .ok_or_else(|| format!("{description} must be array").into())
}

fn json_str<'a>(value: &'a Value, description: &str) -> TestResult<&'a str> {
    value
        .as_str()
        .ok_or_else(|| format!("{description} must be string").into())
}

fn json_u64(value: &Value, description: &str) -> TestResult<u64> {
    value
        .as_u64()
        .ok_or_else(|| format!("{description} must be unsigned integer").into())
}

fn source_artifacts(manifest: &Value) -> TestResult<&serde_json::Map<String, Value>> {
    manifest["source_artifacts"]
        .as_object()
        .ok_or_else(|| "source_artifacts must be object".into())
}

fn function_exists(root: &Path, source_path: &str, name: &str) -> TestResult<bool> {
    let text = std::fs::read_to_string(root.join(source_path))?;
    Ok(text.contains(&format!("fn {name}(")) || text.contains(&format!("fn {name}<")))
}

fn assert_file_line_ref_exists(root: &Path, file_line_ref: &str) -> TestResult {
    let (path, line) = file_line_ref
        .rsplit_once(':')
        .ok_or("file-line ref must contain colon")?;
    let line_no: usize = line.parse()?;
    let text = std::fs::read_to_string(root.join(path))?;
    let line_text = text
        .lines()
        .nth(line_no.checked_sub(1).ok_or("line numbers are 1-based")?)
        .ok_or("line number outside file")?;
    assert!(
        !line_text.trim().is_empty(),
        "{file_line_ref} points at a blank line"
    );
    Ok(())
}

#[test]
fn manifest_binds_critique_response_completion_debt() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("critique_response_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-3qq"));
    assert_eq!(manifest["completion_debt_bead"].as_str(), Some("bd-3qq.1"));
    assert!(
        json_u64(
            &manifest["next_audit_score_threshold"],
            "next audit score threshold"
        )? >= 800
    );

    let artifacts = source_artifacts(&manifest)?;
    for (artifact_id, path) in artifacts {
        let path = path.as_str().ok_or("artifact path must be string")?;
        assert!(
            root.join(path).exists(),
            "source artifact {artifact_id} missing at {path}"
        );
    }

    let missing_ids = json_array(&manifest["missing_item_bindings"], "missing_item_bindings")?
        .iter()
        .map(|binding| Ok(json_str(&binding["id"], "missing item binding id")?.to_string()))
        .collect::<TestResult<BTreeSet<_>>>()?;
    assert_eq!(
        missing_ids,
        [
            "telemetry.primary",
            "tests.e2e.primary",
            "tests.unit.primary"
        ]
        .into_iter()
        .map(String::from)
        .collect()
    );

    for implementation_ref in json_array(&manifest["implementation_refs"], "implementation_refs")? {
        assert_file_line_ref_exists(
            root.as_path(),
            json_str(implementation_ref, "implementation ref")?,
        )?;
    }

    let dependency_ids = string_set(&manifest["required_dependency_closure"])?;
    assert_eq!(dependency_ids.len(), 16);
    for expected in ["bd-226", "bd-33p", "bd-5fw", "bd-1x3", "bd-mtj"] {
        assert!(
            dependency_ids.contains(expected),
            "missing dependency {expected}"
        );
    }

    assert_eq!(
        manifest["claim_bindings"]["support_surface"]["expected_stub"].as_u64(),
        Some(0)
    );
    assert_eq!(
        manifest["claim_bindings"]["stub_census"]["expected_reachable_stubs"].as_u64(),
        Some(0)
    );
    assert_eq!(
        manifest["claim_bindings"]["ld_preload_smoke"]["expected_fails"].as_u64(),
        Some(0)
    );

    for binding in json_array(&manifest["missing_item_bindings"], "missing_item_bindings")? {
        for file_line_ref in json_array(
            &binding["implementation_refs"],
            "binding implementation_refs",
        )? {
            assert_file_line_ref_exists(root.as_path(), json_str(file_line_ref, "file-line ref")?)?;
        }
        for test_ref in json_array(&binding["required_test_refs"], "binding required_test_refs")? {
            let source = json_str(&test_ref["source"], "test ref source")?;
            let name = json_str(&test_ref["name"], "test ref name")?;
            let source_path = json_str(
                artifacts
                    .get(source)
                    .ok_or_else(|| format!("missing source artifact {source}"))?,
                "source artifact path",
            )?;
            assert!(
                function_exists(root.as_path(), source_path, name)?,
                "missing test function {source}::{name}"
            );
        }
    }

    Ok(())
}

#[test]
fn checker_emits_report_and_structured_log() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&contract_path(&root))?;
    let (contract, out_dir) = fixture_contract(&root, "pass", &manifest)?;
    let output = run_checker(&root, &contract, &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report = read_json(&out_dir.join("critique_response_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["error_count"].as_u64(), Some(0));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-3qq.1"));
    assert!(
        json_u64(&report["support_summary"]["total"], "support summary total")? >= 3980,
        "support matrix total should satisfy the original classified-symbol claim"
    );
    assert_eq!(report["stub_summary"]["reachable_stubs"].as_u64(), Some(0));
    assert_eq!(report["ld_preload_summary"]["fails"].as_u64(), Some(0));

    let rows = read_jsonl(&out_dir.join("critique_response_completion_contract.log.jsonl"))?;
    let events: BTreeSet<_> = rows
        .iter()
        .filter_map(|row| row["event"].as_str())
        .collect();
    for expected in [
        "critique_response_dependencies_validated",
        "critique_response_support_surface_validated",
        "critique_response_ld_preload_validated",
        "critique_response_missing_items_bound",
        "critique_response_completion_contract_validated",
    ] {
        assert!(events.contains(expected), "missing event {expected}");
    }
    for row in rows {
        assert_eq!(row["completion_debt_bead"].as_str(), Some("bd-3qq.1"));
        assert_eq!(row["original_bead"].as_str(), Some("bd-3qq"));
        assert!(json_str(&row["trace_id"], "trace id")?.starts_with("bd-3qq.1:"));
        assert_eq!(
            row["gate"].as_str(),
            Some("critique_response_completion_contract")
        );
        assert!(!json_array(&row["artifact_refs"], "artifact_refs")?.is_empty());
    }

    Ok(())
}

#[test]
fn checker_rejects_stub_count_drift() -> TestResult {
    let root = workspace_root()?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["claim_bindings"]["stub_census"]["expected_reachable_stubs"] = json!(1);
    let (mutated, out_dir) = fixture_contract(&root, "drift", &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(!output.status.success(), "{}", output_text(&output));

    let report = read_json(&out_dir.join("critique_response_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    let errors = report["errors"].as_array().ok_or("errors must be array")?;
    let mut has_reachable_stubs_error = false;
    for error in errors {
        has_reachable_stubs_error |= json_str(error, "error message")?.contains("reachable_stubs");
    }
    assert!(
        has_reachable_stubs_error,
        "expected reachable_stubs drift error, got {errors:?}"
    );

    Ok(())
}
