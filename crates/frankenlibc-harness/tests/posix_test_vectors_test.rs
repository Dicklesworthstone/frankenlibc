use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn test_error(message: impl Into<String>) -> Box<dyn Error> {
    std::io::Error::other(message.into()).into()
}

fn workspace_root() -> TestResult<PathBuf> {
    Ok(Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| test_error("crate manifest should have crates parent"))?
        .parent()
        .ok_or_else(|| test_error("crates directory should have workspace parent"))?
        .to_path_buf())
}

fn vectors_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/posix_test_vectors.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_posix_test_vectors.sh")
}

fn report_path(out_dir: &Path) -> PathBuf {
    out_dir.join("posix_test_vectors.report.json")
}

fn log_path(out_dir: &Path) -> PathBuf {
    out_dir.join("posix_test_vectors.log.jsonl")
}

fn load_json(path: &Path) -> TestResult<Value> {
    let content = std::fs::read_to_string(path)
        .map_err(|err| test_error(format!("{} should be readable: {err}", path.display())))?;
    serde_json::from_str(&content)
        .map_err(|err| test_error(format!("{} should parse as JSON: {err}", path.display())))
}

fn load_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    std::fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str(line).map_err(|err| {
                test_error(format!("invalid JSONL row in {}: {err}", path.display()))
            })
        })
        .collect()
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    std::fs::write(path, format!("{}\n", serde_json::to_string_pretty(value)?))?;
    Ok(())
}

fn unique_output_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| test_error(format!("system clock should be after Unix epoch: {err}")))?
        .as_nanos();
    let path = root.join("target/conformance").join(format!(
        "posix_test_vectors_{label}_{}_{}",
        std::process::id(),
        stamp
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn string_field<'a>(value: &'a Value, key: &str, context: &str) -> TestResult<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| test_error(format!("{context}.{key} must be a string")))
}

fn u64_field(value: &Value, key: &str, context: &str) -> TestResult<u64> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| test_error(format!("{context}.{key} must be an unsigned integer")))
}

fn object_field<'a>(
    value: &'a Value,
    key: &str,
    context: &str,
) -> TestResult<&'a serde_json::Map<String, Value>> {
    value
        .get(key)
        .and_then(Value::as_object)
        .ok_or_else(|| test_error(format!("{context}.{key} must be an object")))
}

fn array_field<'a>(value: &'a Value, key: &str, context: &str) -> TestResult<&'a Vec<Value>> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| test_error(format!("{context}.{key} must be an array")))
}

fn run_checker(root: &Path, vectors: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .arg("--validate-only")
        .current_dir(root)
        .env("FRANKENLIBC_POSIX_TEST_VECTORS", vectors)
        .env(
            "FRANKENLIBC_POSIX_TEST_VECTORS_REPORT",
            report_path(out_dir),
        )
        .env("FRANKENLIBC_POSIX_TEST_VECTORS_LOG", log_path(out_dir))
        .env("FRANKENLIBC_POSIX_TEST_VECTORS_RUN_ID", "rust-harness")
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

fn expect_checker_success(output: &Output) -> TestResult {
    if output.status.success() {
        return Ok(());
    }
    Err(test_error(format!(
        "checker failed: {}",
        output_text(output)
    )))
}

fn expect_checker_failure(output: &Output) -> TestResult {
    if !output.status.success() {
        return Ok(());
    }
    Err(test_error(format!(
        "checker unexpectedly passed: {}",
        output_text(output)
    )))
}

#[derive(Default)]
struct VectorCounts {
    functions: u64,
    positive: u64,
    boundary: u64,
    error: u64,
    undefined: u64,
}

fn count_vectors(contract: &Value) -> TestResult<VectorCounts> {
    let mut counts = VectorCounts::default();
    for (family_name, family) in object_field(contract, "families", "contract")? {
        for (function_name, function) in family
            .as_object()
            .ok_or_else(|| test_error(format!("{family_name} must be an object")))?
        {
            counts.functions += 1;
            let context = format!("{family_name}/{function_name}");
            for vector in function
                .get("test_vectors")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                match string_field(vector, "category", &context)? {
                    "positive" => counts.positive += 1,
                    "boundary" => counts.boundary += 1,
                    "error" => counts.error += 1,
                    other => {
                        return Err(test_error(format!(
                            "{context} has unknown vector category {other}"
                        )));
                    }
                }
            }
            if let Some(error_conditions) = function.get("error_conditions") {
                counts.error += error_conditions
                    .as_array()
                    .ok_or_else(|| {
                        test_error(format!("{context}.error_conditions must be an array"))
                    })?
                    .len() as u64;
            }
            if let Some(undefined_behaviors) = function.get("undefined_behaviors") {
                counts.undefined += undefined_behaviors
                    .as_array()
                    .ok_or_else(|| {
                        test_error(format!("{context}.undefined_behaviors must be an array"))
                    })?
                    .len() as u64;
            }
        }
    }
    Ok(counts)
}

#[test]
fn contract_binds_posix_vector_inventory_and_counts() -> TestResult {
    let root = workspace_root()?;
    let contract = load_json(&vectors_path(&root))?;

    assert_eq!(
        string_field(&contract, "schema_version", "contract")?,
        "1.0"
    );
    assert_eq!(
        string_field(&contract, "spec_reference", "contract")?,
        "IEEE Std 1003.1-2017 (POSIX.1)"
    );
    assert!(
        checker_path(&root).is_file(),
        "missing POSIX vector checker"
    );

    let families = object_field(&contract, "families", "contract")?;
    assert_eq!(
        families.keys().cloned().collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "ctype".to_string(),
            "math".to_string(),
            "stdio".to_string(),
            "stdlib".to_string(),
            "string".to_string(),
        ])
    );

    let mut functions_by_family = BTreeMap::new();
    for (family_name, family) in families {
        let functions = family
            .as_object()
            .ok_or_else(|| test_error(format!("{family_name} must be an object")))?;
        functions_by_family.insert(
            family_name.as_str(),
            functions
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
        );
        for (function_name, function) in functions {
            let context = format!("{family_name}/{function_name}");
            assert!(
                function
                    .get("spec_section")
                    .and_then(Value::as_str)
                    .is_some(),
                "{context} must bind a POSIX spec section"
            );
            assert!(
                function.get("test_vectors").is_some()
                    || function.get("error_conditions").is_some(),
                "{context} must expose vectors or error conditions"
            );
        }
    }

    assert_eq!(
        functions_by_family["string"],
        BTreeSet::from([
            "memcpy", "memmove", "memset", "strchr", "strcmp", "strlen", "strncmp", "strrchr",
            "strstr", "strtok",
        ])
    );
    assert_eq!(
        functions_by_family["stdlib"],
        BTreeSet::from(["abs", "atoi", "getenv", "qsort", "strtol"])
    );
    assert_eq!(
        functions_by_family["stdio"],
        BTreeSet::from(["snprintf", "sscanf"])
    );
    assert_eq!(
        functions_by_family["ctype"],
        BTreeSet::from(["isalpha", "isdigit", "tolower"])
    );
    assert_eq!(
        functions_by_family["math"],
        BTreeSet::from(["pow", "sin", "sqrt"])
    );

    let counts = count_vectors(&contract)?;
    let summary = contract
        .get("coverage_summary")
        .ok_or_else(|| test_error("coverage_summary missing"))?;
    assert_eq!(u64_field(summary, "families_covered", "summary")?, 5);
    assert_eq!(
        u64_field(summary, "functions_with_vectors", "summary")?,
        counts.functions
    );
    assert_eq!(
        u64_field(summary, "total_positive_vectors", "summary")?,
        counts.positive
    );
    assert_eq!(
        u64_field(summary, "total_boundary_vectors", "summary")?,
        counts.boundary
    );
    assert_eq!(
        u64_field(summary, "total_error_vectors", "summary")?,
        counts.error
    );
    assert_eq!(
        u64_field(summary, "total_undefined_documented", "summary")?,
        counts.undefined
    );

    Ok(())
}

#[test]
fn checker_emits_isolated_pass_report_and_jsonl() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "pass")?;
    let output = run_checker(&root, &vectors_path(&root), &out_dir)?;
    expect_checker_success(&output)?;

    let report = load_json(&report_path(&out_dir))?;
    assert_eq!(
        string_field(&report, "report_schema", "report")?,
        "posix_test_vectors.report.v1"
    );
    assert_eq!(string_field(&report, "bead", "report")?, "bd-2tq.1");
    assert_eq!(string_field(&report, "mode", "report")?, "validate-only");
    assert_eq!(string_field(&report, "outcome", "report")?, "pass");
    assert_eq!(string_field(&report, "status", "report")?, "PASS");
    assert_eq!(
        string_field(&report, "failure_signature", "report")?,
        "none"
    );
    assert_eq!(u64_field(&report, "families", "report")?, 5);
    assert_eq!(u64_field(&report, "functions", "report")?, 23);
    assert_eq!(u64_field(&report, "total_vectors", "report")?, 115);
    assert_eq!(u64_field(&report, "structure_issues", "report")?, 0);

    let summary = report
        .get("summary")
        .ok_or_else(|| test_error("summary missing"))?;
    assert_eq!(u64_field(summary, "functions_with_vectors", "summary")?, 23);
    assert_eq!(u64_field(summary, "total_positive_vectors", "summary")?, 63);
    assert_eq!(u64_field(summary, "total_boundary_vectors", "summary")?, 40);
    assert_eq!(u64_field(summary, "total_error_vectors", "summary")?, 12);

    let events = load_jsonl(&log_path(&out_dir))?;
    assert_eq!(events.len(), 1);
    assert_eq!(
        string_field(&events[0], "event", "log")?,
        "posix_test_vectors_validated"
    );
    assert_eq!(string_field(&events[0], "outcome", "log")?, "pass");
    assert_eq!(
        string_field(&events[0], "failure_signature", "log")?,
        "none"
    );

    Ok(())
}

#[test]
fn checker_rejects_stale_summary_counts() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "summary_drift")?;
    let mut contract = load_json(&vectors_path(&root))?;
    contract["coverage_summary"]["functions_with_vectors"] = Value::from(20);
    let mutated = out_dir.join("posix_test_vectors.summary_drift.json");
    write_json(&mutated, &contract)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    expect_checker_failure(&output)?;

    let report = load_json(&report_path(&out_dir))?;
    assert_eq!(string_field(&report, "outcome", "report")?, "fail");
    assert_eq!(string_field(&report, "status", "report")?, "FAIL");
    assert_eq!(
        string_field(&report, "failure_signature", "report")?,
        "coverage_summary.functions_with_vectors"
    );
    assert_eq!(u64_field(&report, "structure_issues", "report")?, 1);
    assert!(
        array_field(&report, "structure_errors", "report")?
            .iter()
            .any(|err| err
                .as_str()
                .is_some_and(|text| text.contains("expected 23"))),
        "summary drift error should record the expected function count"
    );

    let events = load_jsonl(&log_path(&out_dir))?;
    assert_eq!(events.len(), 1);
    assert_eq!(
        string_field(&events[0], "event", "log")?,
        "posix_test_vectors_failed"
    );
    assert_eq!(
        string_field(&events[0], "failure_signature", "log")?,
        "coverage_summary.functions_with_vectors"
    );

    Ok(())
}
