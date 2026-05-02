//! Integration test: benchmark coverage inventory gate (bd-bp8fl.8.1).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;

type TestResult<T = ()> = Result<T, String>;

const REQUIRED_FAMILIES: &[&str] = &[
    "string", "malloc", "stdio", "pthread", "syscall", "membrane",
];
const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "scenario_id",
    "runtime_mode",
    "replacement_level",
    "api_family",
    "symbol",
    "oracle_kind",
    "expected",
    "actual",
    "errno",
    "decision_path",
    "healing_action",
    "latency_ns",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
];

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

fn load_json(path: &Path) -> TestResult<serde_json::Value> {
    let content =
        std::fs::read_to_string(path).map_err(|err| format!("{}: {err}", path.display()))?;
    serde_json::from_str(&content).map_err(|err| format!("{}: {err}", path.display()))
}

fn json_array<'a>(
    value: &'a serde_json::Value,
    field: &str,
) -> TestResult<&'a Vec<serde_json::Value>> {
    value[field]
        .as_array()
        .ok_or_else(|| format!("{field} must be a JSON array"))
}

fn string_field<'a>(value: &'a serde_json::Value, field: &str) -> TestResult<&'a str> {
    value[field]
        .as_str()
        .ok_or_else(|| format!("{field} must be a JSON string"))
}

fn require(condition: bool, message: impl Into<String>) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn family_map(report: &serde_json::Value) -> TestResult<HashMap<String, &serde_json::Value>> {
    let mut map = HashMap::new();
    for family in json_array(report, "families")? {
        let id = string_field(family, "family")?.to_owned();
        require(
            map.insert(id.clone(), family).is_none(),
            format!("duplicate family {id}"),
        )?;
    }
    Ok(map)
}

#[test]
fn committed_inventory_artifact_preserves_required_scope() -> TestResult {
    let root = workspace_root()?;
    let artifact = load_json(&root.join("tests/conformance/benchmark_coverage_inventory.v1.json"))?;

    require(
        artifact["schema_version"].as_str() == Some("v1"),
        "schema_version must be v1",
    )?;
    require(
        artifact["bead"].as_str() == Some("bd-bp8fl.8.1"),
        "bead must be bd-bp8fl.8.1",
    )?;

    let families = family_map(&artifact)?;
    for required in REQUIRED_FAMILIES {
        require(
            families.contains_key(*required),
            format!("missing required family {required}"),
        )?;
    }

    let summary = &artifact["summary"];
    require(
        summary["fully_baselined_families"]
            .as_array()
            .and_then(|rows| rows.iter().find(|row| row.as_str() == Some("membrane")))
            .is_some(),
        "membrane must be fully baselined",
    )?;
    require(
        !summary["missing_required_baseline_families"]
            .as_array()
            .ok_or_else(|| "missing_required_baseline_families must be array".to_string())?
            .is_empty(),
        "current inventory must expose missing required baselines",
    )?;

    let log_fields: HashSet<_> = json_array(&artifact, "required_log_fields")?
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    for field in REQUIRED_LOG_FIELDS {
        require(
            log_fields.contains(field),
            format!("required log field missing from artifact: {field}"),
        )?;
    }
    Ok(())
}

#[test]
fn family_rows_name_benchmarks_baselines_workloads_and_next_actions() -> TestResult {
    let root = workspace_root()?;
    let artifact = load_json(&root.join("tests/conformance/benchmark_coverage_inventory.v1.json"))?;
    let families = family_map(&artifact)?;

    for required in REQUIRED_FAMILIES {
        let family = families
            .get(*required)
            .ok_or_else(|| format!("missing required family {required}"))?;
        require(
            family["baseline_coverage"].is_array(),
            format!("{required}: baseline_coverage must be array"),
        )?;
        require(
            family["workload_artifacts"].is_array(),
            format!("{required}: workload_artifacts must be array"),
        )?;
        require(
            family["next_action"]
                .as_str()
                .is_some_and(|value| !value.is_empty()),
            format!("{required}: next_action must be non-empty"),
        )?;
        if *required != "syscall" {
            require(
                family["has_bench_file"].as_bool() == Some(true),
                format!("{required}: expected an existing bench file"),
            )?;
        } else {
            require(
                family["coverage_state"].as_str() == Some("gap"),
                "syscall must remain a gap until a benchmark suite exists",
            )?;
        }
    }

    let string = families
        .get("string")
        .ok_or_else(|| "missing string family".to_string())?;
    require(
        !json_array(string, "missing_baseline_slots")?.is_empty(),
        "string should identify missing strict/hardened baseline slots",
    )?;

    let pthread = families
        .get("pthread")
        .ok_or_else(|| "missing pthread family".to_string())?;
    require(
        !json_array(pthread, "missing_spec_suites")?.is_empty(),
        "pthread should identify missing perf_baseline_spec suites",
    )?;
    Ok(())
}

#[test]
fn gate_script_emits_valid_report_and_structured_jsonl() -> TestResult {
    let root = workspace_root()?;
    let script = root.join("scripts/check_benchmark_coverage_inventory.sh");
    require(script.exists(), format!("missing {}", script.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script)
            .map_err(|err| format!("{}: {err}", script.display()))?
            .permissions();
        require(
            perms.mode() & 0o111 != 0,
            "check_benchmark_coverage_inventory.sh must be executable",
        )?;
    }

    let report_path = root.join("target/conformance/benchmark_coverage_inventory.report.json");
    let log_path = root.join("target/conformance/benchmark_coverage_inventory.log.jsonl");
    let output = Command::new(&script)
        .current_dir(&root)
        .output()
        .map_err(|err| format!("failed to run benchmark coverage gate: {err}"))?;
    require(
        output.status.success(),
        format!(
            "benchmark coverage gate failed:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )?;
    require(
        report_path.exists(),
        format!("missing {}", report_path.display()),
    )?;
    require(log_path.exists(), format!("missing {}", log_path.display()))?;

    let report = load_json(&report_path)?;
    require(
        report["bead"].as_str() == Some("bd-bp8fl.8.1"),
        "report bead mismatch",
    )?;
    let report_family_count = json_array(&report, "families")?.len();

    let log_content = std::fs::read_to_string(&log_path)
        .map_err(|err| format!("{}: {err}", log_path.display()))?;
    let mut rows = 0usize;
    for raw in log_content.lines().filter(|line| !line.trim().is_empty()) {
        let row: serde_json::Value =
            serde_json::from_str(raw).map_err(|err| format!("log row parse error: {err}"))?;
        rows += 1;
        for field in REQUIRED_LOG_FIELDS {
            require(
                row.get(*field).is_some(),
                format!("log row missing field {field}"),
            )?;
        }
        require(
            row["bead_id"].as_str() == Some("bd-bp8fl.8.1"),
            "log row bead_id mismatch",
        )?;
        require(
            row["oracle_kind"].as_str() == Some("derived_inventory_gate"),
            "log row oracle_kind mismatch",
        )?;
        require(
            row["runtime_mode"].as_str() == Some("strict+hardened"),
            "log row runtime_mode mismatch",
        )?;
    }
    require(
        rows == report_family_count,
        format!("log rows {rows} != report families {report_family_count}"),
    )?;
    Ok(())
}
