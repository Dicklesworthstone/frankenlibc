//! Integration test: uncovered hot-path benchmark manifest gate (bd-b92jd.2.2).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type Mutator = Box<dyn Fn(&mut Value) -> TestResult>;
type NegativeCase = (&'static str, Mutator, &'static str);

const CURRENT_COVERED_MODULES: &[&str] = &["string_abi", "malloc_abi", "pthread_abi"];
const REQUIRED_MODULES: &[&str] = &[
    "c11threads_abi",
    "ctype_abi",
    "errno_abi",
    "resolv_abi",
    "stdio_abi",
    "stdlib_abi",
    "time_abi",
    "wchar_abi",
];

fn test_error(message: impl Into<String>) -> Box<dyn std::error::Error> {
    message.into().into()
}

fn workspace_root() -> TestResult<PathBuf> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| {
            test_error(format!(
                "could not derive workspace root from {manifest_dir:?}"
            ))
        })
}

fn load_json(path: &Path) -> TestResult<Value> {
    let content = std::fs::read_to_string(path)
        .map_err(|err| test_error(format!("{} should be readable: {err}", path.display())))?;
    serde_json::from_str(&content)
        .map_err(|err| test_error(format!("{} should parse as JSON: {err}", path.display())))
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    let content = serde_json::to_string_pretty(value)
        .map_err(|err| test_error(format!("{} serialization failed: {err}", path.display())))?;
    std::fs::write(path, format!("{content}\n"))
        .map_err(|err| test_error(format!("{} write failed: {err}", path.display())))
}

fn unique_temp_dir(label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| test_error(format!("system time before UNIX_EPOCH: {err}")))?
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "frankenlibc-{label}-{stamp}-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn json_array<'a>(value: &'a Value, field: &str) -> TestResult<&'a Vec<Value>> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| test_error(format!("{field} must be an array")))
}

fn object_mut<'a>(
    value: &'a mut Value,
    context: &str,
) -> TestResult<&'a mut serde_json::Map<String, Value>> {
    value
        .as_object_mut()
        .ok_or_else(|| test_error(format!("{context} must be an object")))
}

fn rows_mut(value: &mut Value) -> TestResult<&mut Vec<Value>> {
    value
        .get_mut("rows")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| test_error("manifest.rows must be an array"))
}

fn row_ids(rows: &[Value]) -> BTreeSet<String> {
    rows.iter()
        .filter_map(|row| row.get("row_id").and_then(Value::as_str).map(str::to_owned))
        .collect()
}

fn expected_uncovered_row_ids(policy: &Value) -> TestResult<BTreeSet<String>> {
    let covered: BTreeSet<&str> = CURRENT_COVERED_MODULES.iter().copied().collect();
    let rows = policy
        .get("hotpath_symbols")
        .and_then(|value| value.get("strict_hotpath"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            test_error("perf_budget_policy.hotpath_symbols.strict_hotpath must be array")
        })?;
    Ok(rows
        .iter()
        .filter_map(|row| {
            let module = row.get("module")?.as_str()?;
            let symbol = row.get("symbol")?.as_str()?;
            (!covered.contains(module)).then(|| format!("{module}:{symbol}"))
        })
        .collect())
}

fn validate_manifest(root: &Path, path: &Path) -> TestResult<Output> {
    Command::new("python3")
        .arg(root.join("scripts/generate_uncovered_hotpath_benchmark_manifest.py"))
        .arg("--validate-manifest")
        .arg(path)
        .current_dir(root)
        .output()
        .map_err(|err| test_error(format!("failed to run manifest validator: {err}")))
}

fn stderr_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

#[test]
fn committed_manifest_matches_current_uncovered_hotpath_set() -> TestResult {
    let root = workspace_root()?;
    let manifest =
        load_json(&root.join("tests/conformance/uncovered_hotpath_benchmark_manifest.v1.json"))?;
    let policy = load_json(&root.join("tests/conformance/perf_budget_policy.json"))?;
    let prevention = load_json(&root.join("tests/conformance/perf_regression_prevention.v1.json"))?;

    assert_eq!(manifest["schema_version"].as_str(), Some("v1"));
    assert_eq!(manifest["bead"].as_str(), Some("bd-b92jd.2.2"));
    assert_eq!(
        manifest["summary"]["current_uncovered_symbol_count"].as_u64(),
        Some(62)
    );
    assert_eq!(
        manifest["summary"]["total_strict_hotpath_symbols"].as_u64(),
        Some(152)
    );
    assert_eq!(
        manifest["summary"]["current_uncovered_symbol_count"],
        prevention["hotpath_symbol_coverage"]["not_covered"]
    );

    let rows = json_array(&manifest, "rows")?;
    assert_eq!(rows.len(), 62);
    assert_eq!(
        row_ids(rows).len(),
        rows.len(),
        "row_id values must be unique"
    );
    assert_eq!(row_ids(rows), expected_uncovered_row_ids(&policy)?);

    let module_set: BTreeSet<String> = rows
        .iter()
        .map(|row| {
            row["module"]
                .as_str()
                .ok_or_else(|| test_error("row.module must be string"))
                .map(str::to_owned)
        })
        .collect::<TestResult<_>>()?;
    let required: BTreeSet<String> = REQUIRED_MODULES
        .iter()
        .map(|item| item.to_string())
        .collect();
    assert_eq!(module_set, required);

    let mut counts = BTreeMap::<String, usize>::new();
    for row in rows {
        let module = row["module"]
            .as_str()
            .ok_or_else(|| test_error("row.module must be string"))?;
        *counts.entry(module.to_owned()).or_insert(0) += 1;
        assert_eq!(row["perf_class"].as_str(), Some("strict_hotpath"));
        assert!(
            row["benchmark_assignment"]["api_family"].as_str().is_some(),
            "{} missing api_family",
            row["row_id"]
        );
        assert!(
            row["benchmark_assignment"]["benchmark_file"]
                .as_str()
                .is_some_and(|path| path.starts_with("crates/frankenlibc-bench/benches/")),
            "{} has invalid benchmark_file",
            row["row_id"]
        );
        if module == "resolv_abi" {
            assert!(
                row["safety"]["unsafe_to_benchmark_reason"]
                    .as_str()
                    .is_some(),
                "resolver rows must record real-network blocker"
            );
        }
    }
    assert_eq!(counts.get("wchar_abi"), Some(&22));
    assert_eq!(counts.get("ctype_abi"), Some(&14));
    assert_eq!(counts.get("stdio_abi"), Some(&11));
    Ok(())
}

#[test]
fn gate_script_emits_current_report_and_structured_logs() -> TestResult {
    let root = workspace_root()?;
    let output = Command::new("bash")
        .arg(root.join("scripts/check_uncovered_hotpath_benchmark_manifest.sh"))
        .current_dir(&root)
        .output()
        .map_err(|err| test_error(format!("failed to run uncovered manifest gate: {err}")))?;
    assert!(
        output.status.success(),
        "gate failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = load_json(
        &root.join("target/conformance/uncovered_hotpath_benchmark_manifest.report.json"),
    )?;
    assert_eq!(
        report["summary"]["current_uncovered_symbol_count"].as_u64(),
        Some(62)
    );
    let log = std::fs::read_to_string(
        root.join("target/conformance/uncovered_hotpath_benchmark_manifest.log.jsonl"),
    )?;
    let events: Vec<Value> = log
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    assert_eq!(events.len(), REQUIRED_MODULES.len());
    for event in events {
        for field in json_array(&report, "required_log_fields")? {
            let field = field
                .as_str()
                .ok_or_else(|| test_error("required_log_fields entries must be strings"))?;
            assert!(!event[field].is_null(), "log event missing {field}");
        }
    }
    Ok(())
}

#[test]
fn negative_cases_fail_closed_with_stable_signatures() -> TestResult {
    let root = workspace_root()?;
    let manifest_path = root.join("tests/conformance/uncovered_hotpath_benchmark_manifest.v1.json");
    let manifest = load_json(&manifest_path)?;
    let temp = unique_temp_dir("uncovered-hotpath")?;

    let cases: Vec<NegativeCase> = vec![
        (
            "duplicate_row",
            Box::new(|value| {
                let first = rows_mut(value)?
                    .first()
                    .cloned()
                    .ok_or_else(|| test_error("manifest must contain at least one row"))?;
                rows_mut(value)?.push(first);
                Ok(())
            }),
            "duplicate row_id",
        ),
        (
            "missing_row",
            Box::new(|value| {
                rows_mut(value)?.remove(0);
                Ok(())
            }),
            "missing expected rows",
        ),
        (
            "stale_support_status",
            Box::new(|value| {
                let rows = rows_mut(value)?;
                let first = rows
                    .first_mut()
                    .ok_or_else(|| test_error("manifest must contain at least one row"))?;
                object_mut(first, "row")?
                    .insert("status".to_string(), Value::String("Stub".to_string()));
                Ok(())
            }),
            "stale support_matrix status",
        ),
        (
            "covered_module_leak",
            Box::new(|value| {
                let rows = rows_mut(value)?;
                let first = rows
                    .first_mut()
                    .ok_or_else(|| test_error("manifest must contain at least one row"))?;
                object_mut(first, "row")?.insert(
                    "module".to_string(),
                    Value::String("string_abi".to_string()),
                );
                Ok(())
            }),
            "covered module leaked",
        ),
        (
            "missing_assignment",
            Box::new(|value| {
                let rows = rows_mut(value)?;
                let first = rows
                    .first_mut()
                    .ok_or_else(|| test_error("manifest must contain at least one row"))?;
                object_mut(&mut first["benchmark_assignment"], "benchmark_assignment")?
                    .insert("api_family".to_string(), Value::String(String::new()));
                Ok(())
            }),
            "missing benchmark assignment",
        ),
    ];

    for (name, mutate, expected) in cases {
        let mut mutated = manifest.clone();
        mutate(&mut mutated)?;
        let path = temp.join(format!("{name}.json"));
        write_json(&path, &mutated)?;
        let output = validate_manifest(&root, &path)?;
        assert!(
            !output.status.success(),
            "{name} should fail validation but passed"
        );
        let stderr = stderr_text(&output);
        assert!(
            stderr.contains(expected),
            "{name} expected signature {expected:?}, got stderr:\n{stderr}"
        );
    }
    Ok(())
}
