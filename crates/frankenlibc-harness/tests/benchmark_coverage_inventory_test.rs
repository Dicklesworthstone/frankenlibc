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
    "benchmark_id",
    "coverage_state",
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
const REQUIRED_INVENTORY_ROW_FIELDS: &[&str] = &[
    "row_id",
    "api_family",
    "symbol",
    "crate/module",
    "current_benchmark",
    "missing_benchmark_reason",
    "runtime_mode",
    "replacement_level",
    "user_workload_exposure",
    "baseline_artifact",
    "owner_bead",
    "benchmark_id",
    "coverage_state",
    "artifact_refs",
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
    require(
        artifact["artifact_hash"].as_str().is_some(),
        "artifact_hash must be present",
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

    let row_fields: HashSet<_> = json_array(&artifact, "required_inventory_row_fields")?
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    for field in REQUIRED_INVENTORY_ROW_FIELDS {
        require(
            row_fields.contains(field),
            format!("required inventory row field missing from artifact: {field}"),
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
fn inventory_rows_are_symbol_mode_owned_and_actionable() -> TestResult {
    let root = workspace_root()?;
    let artifact = load_json(&root.join("tests/conformance/benchmark_coverage_inventory.v1.json"))?;
    let rows = json_array(&artifact, "inventory_rows")?;
    require(!rows.is_empty(), "inventory_rows must not be empty")?;
    require(
        artifact["summary"]["inventory_row_count"].as_u64() == Some(rows.len() as u64),
        "inventory_row_count must match rows",
    )?;
    require(
        artifact["summary"]["missing_owner_row_count"].as_u64() == Some(0),
        "all inventory rows must have owner beads",
    )?;

    let mut seen = HashSet::new();
    let mut has_string_gap = false;
    let mut has_membrane_covered = false;
    for row in rows {
        for field in REQUIRED_INVENTORY_ROW_FIELDS {
            require(
                row.get(*field).is_some(),
                format!("inventory row missing {field}: {row}"),
            )?;
        }
        let row_id = string_field(row, "row_id")?;
        require(
            seen.insert(row_id.to_owned()),
            format!("duplicate row {row_id}"),
        )?;
        require(
            ["strict", "hardened"].contains(&string_field(row, "runtime_mode")?),
            format!("{row_id}: invalid runtime_mode"),
        )?;
        require(
            string_field(row, "owner_bead")?.starts_with("bd-"),
            format!("{row_id}: missing owner_bead"),
        )?;
        require(
            row["current_benchmark"].is_object(),
            format!("{row_id}: current_benchmark must be object"),
        )?;
        require(
            row["baseline_artifact"].is_object(),
            format!("{row_id}: baseline_artifact must be object"),
        )?;
        require(
            row["user_workload_exposure"].is_object(),
            format!("{row_id}: user_workload_exposure must be object"),
        )?;

        let family = string_field(row, "api_family")?;
        let coverage = string_field(row, "coverage_state")?;
        if family == "string" && coverage == "gap" {
            has_string_gap = true;
            require(
                row["missing_benchmark_reason"].as_str() != Some("none"),
                "string gap rows must name the missing benchmark reason",
            )?;
        }
        if family == "membrane" && coverage == "covered" {
            has_membrane_covered = true;
            require(
                row["baseline_artifact"]["present"].as_bool() == Some(true),
                "covered membrane rows must reference a present baseline artifact",
            )?;
        }
    }

    require(
        has_string_gap,
        "inventory must expose string hot-path benchmark gaps",
    )?;
    require(
        has_membrane_covered,
        "inventory must preserve covered membrane gate rows",
    )?;
    Ok(())
}

#[test]
fn generator_self_test_canonical_check_and_stale_artifact_rejection_pass() -> TestResult {
    let root = workspace_root()?;
    let script = root.join("scripts/generate_benchmark_coverage_inventory.py");
    require(script.exists(), format!("missing {}", script.display()))?;

    let self_test = Command::new("python3")
        .arg(&script)
        .arg("--self-test")
        .current_dir(&root)
        .output()
        .map_err(|err| format!("failed to run generator self-test: {err}"))?;
    require(
        self_test.status.success(),
        format!(
            "generator self-test failed:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&self_test.stdout),
            String::from_utf8_lossy(&self_test.stderr)
        ),
    )?;

    let canonical_check = Command::new("python3")
        .arg(&script)
        .arg("--check")
        .arg("--output")
        .arg("tests/conformance/benchmark_coverage_inventory.v1.json")
        .current_dir(&root)
        .output()
        .map_err(|err| format!("failed to run generator canonical check: {err}"))?;
    require(
        canonical_check.status.success(),
        format!(
            "generator canonical check failed:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&canonical_check.stdout),
            String::from_utf8_lossy(&canonical_check.stderr)
        ),
    )?;

    let artifact = load_json(&root.join("tests/conformance/benchmark_coverage_inventory.v1.json"))?;
    let mut stale = artifact.clone();
    stale["input_digests"]["support_matrix"] = serde_json::json!("synthetic-stale-digest");
    let stale_path = root.join("target/conformance/benchmark_coverage_inventory.stale.json");
    let stale_parent = stale_path
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", stale_path.display()))?;
    std::fs::create_dir_all(stale_parent)
        .map_err(|err| format!("failed to create stale artifact dir: {err}"))?;
    let stale_bytes = serde_json::to_vec_pretty(&stale)
        .map_err(|err| format!("failed to serialize stale artifact: {err}"))?;
    std::fs::write(&stale_path, stale_bytes)
        .map_err(|err| format!("failed to write stale artifact: {err}"))?;

    let stale_check = Command::new("python3")
        .arg(&script)
        .arg("--check")
        .arg("--output")
        .arg(&stale_path)
        .current_dir(&root)
        .output()
        .map_err(|err| format!("failed to run stale artifact check: {err}"))?;
    require(
        !stale_check.status.success(),
        "stale artifact check should fail",
    )?;
    let stderr = String::from_utf8_lossy(&stale_check.stderr);
    require(
        stderr.contains("stale"),
        format!("stale artifact failure should mention stale, stderr={stderr}"),
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
        require(
            row["benchmark_id"].as_str().is_some(),
            "log row benchmark_id missing",
        )?;
        require(
            row["coverage_state"].as_str().is_some(),
            "log row coverage_state missing",
        )?;
    }
    require(
        rows == report_family_count,
        format!("log rows {rows} != report families {report_family_count}"),
    )?;
    Ok(())
}
