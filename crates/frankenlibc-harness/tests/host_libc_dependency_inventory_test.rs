//! Integration test: host libc dependency inventory gate (bd-bp8fl.6.1)
//!
//! Verifies that the source-level inventory contract produces a complete,
//! structured dependency report for L0/L1 interpose and L2/L3 replacement
//! promotion decisions.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, String>;

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "scenario_id",
    "runtime_mode",
    "replacement_level",
    "api_family",
    "symbol",
    "artifact_path",
    "dependency_kind",
    "library",
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
    let root = Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))?
        .to_path_buf();
    Ok(root)
}

fn load_json(path: &Path) -> TestResult<serde_json::Value> {
    let content =
        std::fs::read_to_string(path).map_err(|err| format!("{}: {err}", path.display()))?;
    serde_json::from_str(&content).map_err(|err| format!("{}: {err}", path.display()))
}

fn load_contract() -> TestResult<serde_json::Value> {
    load_json(&workspace_root()?.join("tests/conformance/host_libc_dependency_inventory.v1.json"))
}

fn json_array<'a>(
    value: &'a serde_json::Value,
    field: &str,
) -> TestResult<&'a Vec<serde_json::Value>> {
    value[field]
        .as_array()
        .ok_or_else(|| format!("{field} must be a JSON array"))
}

fn string_array(value: &serde_json::Value, field: &str) -> TestResult<Vec<String>> {
    json_array(value, field)?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("{field} must contain only strings"))
        })
        .collect()
}

fn summary_string_array(value: &serde_json::Value, field: &str) -> TestResult<Vec<String>> {
    value["summary"][field]
        .as_array()
        .ok_or_else(|| format!("summary.{field} must be a JSON array"))?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("summary.{field} must contain only strings"))
        })
        .collect()
}

fn require(condition: bool, message: impl Into<String>) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn run_gate_with_env(envs: &[(&str, &str)]) -> TestResult<(std::process::Output, PathBuf)> {
    let root = workspace_root()?;
    let mut command = Command::new("bash");
    command
        .arg("scripts/check_host_libc_dependency_inventory.sh")
        .current_dir(&root)
        .env("FRANKENLIBC_REQUIRE_RELEASE_ARTIFACT", "0");
    for (key, value) in envs {
        command.env(key, value);
    }
    let output = command
        .output()
        .map_err(|err| format!("inventory gate did not run: {err}"))?;
    Ok((output, root))
}

fn unique_suffix(label: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    format!("{}-{}-{nanos}", label, std::process::id())
}

fn run_gate_named(label: &str) -> TestResult<(serde_json::Value, PathBuf)> {
    let root = workspace_root()?;
    let suffix = unique_suffix(label);
    let report_path = root.join(format!(
        "target/conformance/host_libc_dependency_inventory.{suffix}.report.json"
    ));
    let log_path = root.join(format!(
        "target/conformance/host_libc_dependency_inventory.{suffix}.log.jsonl"
    ));
    let report_path_s = report_path.to_string_lossy().into_owned();
    let log_path_s = log_path.to_string_lossy().into_owned();

    let (output, _) = run_gate_with_env(&[
        ("FRANKENLIBC_HOST_DEP_REPORT", report_path_s.as_str()),
        ("FRANKENLIBC_HOST_DEP_LOG", log_path_s.as_str()),
    ])?;
    if !output.status.success() {
        return Err(format!(
            "inventory gate failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok((load_json(&report_path)?, log_path))
}

fn run_gate() -> TestResult<serde_json::Value> {
    run_gate_named("report").map(|(report, _)| report)
}

#[test]
fn contract_has_required_shape_and_fields() -> TestResult {
    let contract = load_contract()?;
    require(
        contract["schema_version"].as_str() == Some("v1"),
        "schema_version must be v1",
    )?;
    require(
        contract["bead"].as_str() == Some("bd-bp8fl.6.1"),
        "bead must be bd-bp8fl.6.1",
    )?;
    require(contract["inputs"].is_object(), "inputs must be an object")?;
    require(
        contract["release_artifact_policy"].is_object(),
        "release artifact policy must be present",
    )?;
    require(
        contract["artifact_inventory"].is_object(),
        "artifact inventory policy must be present",
    )?;
    require(
        contract["source_surfaces"].is_object(),
        "source surface inventory policy must be present",
    )?;
    require(
        contract["stale_artifact_policy"].is_object(),
        "stale artifact policy must be present",
    )?;
    require(
        contract["false_positive_suppression"].is_object(),
        "false positive suppression policy must be present",
    )?;
    require(
        json_array(&contract, "negative_claim_tests")?.len() >= 3,
        "negative standalone-claim tests must be documented",
    )?;
    require(
        json_array(&contract, "artifact_presence_scenarios")?.len() == 3,
        "artifact presence scenarios must cover source-only, strict-missing, and present-artifact",
    )?;
    require(
        contract["profile_allowlist_policy"].is_object(),
        "profile allowlist policy must be documented",
    )?;
    let dynamic_tools = string_array(&contract["release_artifact_policy"], "dynamic_audit_tools")?;
    for tool in ["readelf -d", "ldd", "objdump -p", "nm -D --undefined-only"] {
        require(
            dynamic_tools.iter().any(|seen| seen == tool),
            format!("dynamic audit tools must include {tool}"),
        )?;
    }

    let log_fields = string_array(&contract, "required_log_fields")?;
    require(
        log_fields == REQUIRED_LOG_FIELDS,
        format!("required_log_fields mismatch: {log_fields:?}"),
    )?;
    Ok(())
}

#[test]
fn gate_emits_complete_inventory_report_and_log() -> TestResult {
    let (report, log_path) = run_gate_named("complete-log")?;
    require(
        report["schema_version"].as_str() == Some("v1"),
        "report schema_version must be v1",
    )?;
    require(
        report["bead"].as_str() == Some("bd-bp8fl.6.1"),
        "report bead must be bd-bp8fl.6.1",
    )?;
    require(
        report["status"].as_str() == Some("pass"),
        format!("inventory report did not pass: {report:?}"),
    )?;
    require(
        report["summary"]["inventory_event_count"].as_u64() > Some(0),
        "inventory must contain rows",
    )?;
    require(
        report["summary"]["l2_l3_blocker_count"].as_u64() > Some(0),
        "current inventory must identify L2/L3 blockers rather than silently approving replacement",
    )?;
    require(
        report["summary"]["dependency_counts_by_category"].is_object(),
        "report must include dependency_counts_by_category",
    )?;
    require(
        report["summary"]["library_counts"].is_object(),
        "report must include library_counts",
    )?;

    let log = std::fs::read_to_string(&log_path)
        .map_err(|err| format!("{}: {err}", log_path.display()))?;
    let first_line = log
        .lines()
        .find(|line| !line.trim().is_empty())
        .ok_or_else(|| format!("{} was empty", log_path.display()))?;
    let first_row: serde_json::Value = serde_json::from_str(first_line)
        .map_err(|err| format!("first inventory log row did not parse: {err}"))?;
    for field in REQUIRED_LOG_FIELDS {
        require(
            first_row.get(*field).is_some(),
            format!("first log row missing required field {field}"),
        )?;
    }
    require(
        first_row["artifact_path"].is_string(),
        "log row artifact_path must be a string",
    )?;
    require(
        first_row["dependency_kind"].is_string(),
        "log row dependency_kind must be a string",
    )?;
    require(
        first_row["library"].is_string(),
        "log row library must be a string",
    )?;
    Ok(())
}

#[test]
fn strict_missing_release_artifact_mode_fails_with_signature() -> TestResult {
    let root = workspace_root()?;
    let missing_artifact = root.join("target/conformance/definitely_missing_libfrankenlibc_abi.so");
    let report_path =
        root.join("target/conformance/host_libc_dependency_inventory.strict_missing.report.json");
    let log_path =
        root.join("target/conformance/host_libc_dependency_inventory.strict_missing.log.jsonl");
    let missing_artifact_s = missing_artifact.to_string_lossy().into_owned();
    let report_path_s = report_path.to_string_lossy().into_owned();
    let log_path_s = log_path.to_string_lossy().into_owned();

    let (output, _) = run_gate_with_env(&[
        ("FRANKENLIBC_REQUIRE_RELEASE_ARTIFACT", "1"),
        ("FRANKENLIBC_RELEASE_ARTIFACT", missing_artifact_s.as_str()),
        ("FRANKENLIBC_HOST_DEP_REPORT", report_path_s.as_str()),
        ("FRANKENLIBC_HOST_DEP_LOG", log_path_s.as_str()),
    ])?;
    require(
        !output.status.success(),
        "strict missing release artifact mode should fail",
    )?;

    let report = load_json(&report_path)?;
    require(
        report["status"].as_str() == Some("fail"),
        format!("strict missing report should fail: {report:?}"),
    )?;
    require(
        report["release_artifact"]["status"].as_str() == Some("missing"),
        "strict missing report must record release artifact status",
    )?;
    require(
        report["errors"].as_array().is_some_and(|errors| {
            errors.iter().any(|err| {
                err.as_str()
                    .is_some_and(|text| text.contains("release artifact missing"))
            })
        }),
        "strict missing report must include a release artifact error",
    )?;

    let log = std::fs::read_to_string(&log_path)
        .map_err(|err| format!("{}: {err}", log_path.display()))?;
    require(
        log.contains("\"failure_signature\":\"release_artifact_missing\""),
        "strict missing log must preserve the release_artifact_missing failure signature",
    )?;
    Ok(())
}

#[test]
fn present_release_artifact_mode_uses_readelf_or_nm_evidence() -> TestResult {
    let root = workspace_root()?;
    let report_path =
        root.join("target/conformance/host_libc_dependency_inventory.present_elf.report.json");
    let log_path =
        root.join("target/conformance/host_libc_dependency_inventory.present_elf.log.jsonl");
    let report_path_s = report_path.to_string_lossy().into_owned();
    let log_path_s = log_path.to_string_lossy().into_owned();

    let (output, _) = run_gate_with_env(&[
        ("FRANKENLIBC_REQUIRE_RELEASE_ARTIFACT", "1"),
        ("FRANKENLIBC_RELEASE_ARTIFACT", "/bin/true"),
        ("FRANKENLIBC_HOST_DEP_REPORT", report_path_s.as_str()),
        ("FRANKENLIBC_HOST_DEP_LOG", log_path_s.as_str()),
    ])?;
    if !output.status.success() {
        return Err(format!(
            "present ELF inventory gate failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let report = load_json(&report_path)?;
    require(
        report["release_artifact"]["status"].as_str() == Some("present"),
        "present ELF report must record release artifact status",
    )?;
    require(
        report["release_artifact"]["required"].as_bool() == Some(true),
        "present ELF report must record strict artifact requirement",
    )?;
    require(
        report["release_artifact"]["stale"].as_bool() == Some(false),
        "present ELF fixture should not be treated as stale without explicit stale enforcement",
    )?;
    let log = std::fs::read_to_string(&log_path)
        .map_err(|err| format!("{}: {err}", log_path.display()))?;
    require(
        log.contains("\"release_artifact_status\":\"present\""),
        "present ELF log must include present-artifact rows",
    )?;
    require(
        log.contains("\"tool\":\"readelf -d\"")
            || log.contains("\"tool\":\"nm -D --undefined-only\""),
        "present ELF log must include readelf or nm evidence",
    )?;
    require(
        log.contains("\"tool\":\"objdump -p\"") || log.contains("\"tool\":\"ldd\""),
        "present ELF log must include objdump or ldd evidence",
    )?;
    Ok(())
}

#[test]
fn strict_stale_release_artifact_mode_fails_with_signature() -> TestResult {
    let root = workspace_root()?;
    let report_path =
        root.join("target/conformance/host_libc_dependency_inventory.stale.report.json");
    let log_path = root.join("target/conformance/host_libc_dependency_inventory.stale.log.jsonl");
    let report_path_s = report_path.to_string_lossy().into_owned();
    let log_path_s = log_path.to_string_lossy().into_owned();

    let (output, _) = run_gate_with_env(&[
        ("FRANKENLIBC_REQUIRE_RELEASE_ARTIFACT", "1"),
        ("FRANKENLIBC_ENFORCE_RELEASE_STALENESS", "1"),
        ("FRANKENLIBC_RELEASE_ARTIFACT", "/bin/true"),
        ("FRANKENLIBC_HOST_DEP_REPORT", report_path_s.as_str()),
        ("FRANKENLIBC_HOST_DEP_LOG", log_path_s.as_str()),
    ])?;
    require(
        !output.status.success(),
        "strict stale release artifact mode should fail",
    )?;

    let report = load_json(&report_path)?;
    require(
        report["status"].as_str() == Some("fail"),
        format!("stale report should fail: {report:?}"),
    )?;
    require(
        report["release_artifact"]["stale"].as_bool() == Some(true),
        "stale report must mark release artifact stale",
    )?;
    require(
        report["errors"].as_array().is_some_and(|errors| {
            errors.iter().any(|err| {
                err.as_str()
                    .is_some_and(|text| text.contains("release artifact stale"))
            })
        }),
        "stale report must include a release artifact stale error",
    )?;

    let log = std::fs::read_to_string(&log_path)
        .map_err(|err| format!("{}: {err}", log_path.display()))?;
    require(
        log.contains("\"failure_signature\":\"stale_release_artifact\""),
        "stale log must preserve the stale_release_artifact failure signature",
    )?;
    Ok(())
}

#[test]
fn required_categories_and_anchor_symbols_are_present() -> TestResult {
    let contract = load_contract()?;
    let report = run_gate()?;

    let required_categories: HashSet<_> = string_array(&contract, "required_inventory_categories")?
        .into_iter()
        .collect();
    let seen_categories: HashSet<_> = summary_string_array(&report, "required_categories_seen")?
        .into_iter()
        .collect();
    require(
        seen_categories == required_categories,
        format!("required category mismatch: {seen_categories:?}"),
    )?;

    let required_symbols: HashSet<_> = string_array(&contract, "required_anchor_symbols")?
        .into_iter()
        .collect();
    let seen_symbols: HashSet<_> = summary_string_array(&report, "required_anchor_symbols_seen")?
        .into_iter()
        .collect();
    require(
        seen_symbols == required_symbols,
        format!("required symbol mismatch: {seen_symbols:?}"),
    )?;
    Ok(())
}

#[test]
fn source_surfaces_are_inventoried_without_self_reference_noise() -> TestResult {
    let (report, log_path) = run_gate_named("surface-noise")?;
    let counts = report["summary"]["source_surface_counts"]
        .as_object()
        .ok_or_else(|| "summary.source_surface_counts must be an object".to_string())?;
    for category in [
        "build_script_host_dependency",
        "test_host_oracle_reference",
        "generated_doc_host_dependency",
    ] {
        require(
            counts
                .get(category)
                .and_then(serde_json::Value::as_u64)
                .is_some_and(|count| count > 0),
            format!("source surface category {category} must have rows"),
        )?;
    }

    let log = std::fs::read_to_string(&log_path)
        .map_err(|err| format!("{}: {err}", log_path.display()))?;
    for suppressed in [
        "scripts/check_host_libc_dependency_inventory.sh",
        "crates/frankenlibc-harness/tests/host_libc_dependency_inventory_test.rs",
        "tests/conformance/host_libc_dependency_inventory.v1.json",
    ] {
        require(
            !log.contains(suppressed),
            format!("generic source-surface scan must suppress self-reference path {suppressed}"),
        )?;
    }
    Ok(())
}

#[test]
fn allowlist_policy_is_enforced_and_negative_claims_are_resolved() -> TestResult {
    let report = run_gate()?;
    require(
        report["summary"]["unapproved_direct_libc_call_count"].as_u64() == Some(0),
        format!(
            "unapproved direct libc callthroughs must fail the gate: {:?}",
            report["summary"]["unapproved_direct_libc_call_count"]
        ),
    )?;
    require(
        report["summary"]["unresolved_allowlist_modules"]
            .as_array()
            .is_some_and(Vec::is_empty),
        "allowlist entries must resolve to ABI modules or explicit sentinels",
    )?;
    require(
        !summary_string_array(&report, "allowlist_modules_seen")?.is_empty(),
        "report should name allowlisted modules where direct libc calls were observed",
    )?;

    let negative_results = json_array(&report, "negative_claim_results")?;
    let result_ids: HashSet<_> = negative_results
        .iter()
        .map(|row| {
            row["id"]
                .as_str()
                .ok_or_else(|| "negative claim result id must be a string".to_string())
        })
        .collect::<TestResult<HashSet<_>>>()?;
    for id in [
        "neg-l2-host-symbol-resolution",
        "neg-l3-dynamic-glibc-needed",
        "neg-startup-host-delegation",
        "neg-unapproved-interpose-callthrough",
    ] {
        require(
            result_ids.contains(id),
            format!("missing negative claim result {id}"),
        )?;
    }
    for row in negative_results {
        let status = row["status"]
            .as_str()
            .ok_or_else(|| format!("negative claim status must be string: {row:?}"))?;
        require(
            status == "blocked_by_inventory" || status == "guard_clean",
            format!("negative claim must be blocked or cleanly guarded: {row:?}"),
        )?;
    }
    Ok(())
}

#[test]
fn replacement_policy_separates_interpose_from_standalone_claims() -> TestResult {
    let report = run_gate()?;
    let top_blockers = json_array(&report, "top_blockers")?;
    require(!top_blockers.is_empty(), "top blockers should be listed")?;

    let has_startup_blocker = top_blockers.iter().any(|row| {
        row["symbol"].as_str() == Some("__libc_start_main")
            || row["symbol"].as_str() == Some("__cxa_thread_atexit_impl")
    });
    require(
        has_startup_blocker,
        "startup/CRT host dependency must be surfaced as a standalone blocker",
    )?;

    for row in top_blockers {
        let blocked: HashSet<_> = row["blocked_replacement_levels"]
            .as_array()
            .ok_or_else(|| "blocked_replacement_levels must be an array".to_string())?
            .iter()
            .map(|level| {
                level
                    .as_str()
                    .ok_or_else(|| "blocked_replacement_levels must contain strings".to_string())
            })
            .collect::<TestResult<HashSet<_>>>()?;
        require(
            blocked.contains("L2") || blocked.contains("L3"),
            format!("blocker rows must block standalone levels: {row:?}"),
        )?;
    }
    Ok(())
}
