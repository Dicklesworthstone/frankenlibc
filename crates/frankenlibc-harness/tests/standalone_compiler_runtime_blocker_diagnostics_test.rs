//! Integration test: standalone compiler-runtime blocker diagnostics (bd-zyck1.87).
//!
//! Keeps the libgcc/unwind diagnostic artifact tied to the current forge blocker
//! snapshot and prevents report-only investigation rows from silently becoming
//! replacement-level promotion evidence.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

const DIAGNOSTIC_PATH: &str =
    "tests/conformance/standalone_compiler_runtime_blocker_diagnostics.v1.json";
const HOST_PROBE_PLAN_PATH: &str =
    "tests/conformance/standalone_host_dependency_probe_plan.v1.json";

const EXPECTED_UNWIND_SYMBOLS: &[&str] = &[
    "_Unwind_Backtrace@GCC_3.3",
    "_Unwind_DeleteException@GCC_3.0",
    "_Unwind_GetDataRelBase@GCC_3.0",
    "_Unwind_GetIP@GCC_3.0",
    "_Unwind_GetIPInfo@GCC_4.2.0",
    "_Unwind_GetLanguageSpecificData@GCC_3.0",
    "_Unwind_GetRegionStart@GCC_3.0",
    "_Unwind_GetTextRelBase@GCC_3.0",
    "_Unwind_RaiseException@GCC_3.0",
    "_Unwind_Resume@GCC_3.0",
    "_Unwind_SetGR@GCC_3.0",
    "_Unwind_SetIP@GCC_3.0",
];

const EXPECTED_LIBGCC_VERSION_REQUIREMENTS: &[&str] = &[
    "libgcc_s.so.1:GCC_3.0",
    "libgcc_s.so.1:GCC_3.3",
    "libgcc_s.so.1:GCC_4.2.0",
];

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

fn load_json(root: &Path, rel: &str) -> TestResult<Value> {
    let path = root.join(rel);
    let content =
        std::fs::read_to_string(&path).map_err(|err| format!("{}: {err}", path.display()))?;
    serde_json::from_str(&content).map_err(|err| format!("{}: {err}", path.display()))
}

fn get_path<'a>(mut value: &'a Value, dotted: &str) -> TestResult<&'a Value> {
    for segment in dotted.split('.') {
        value = value
            .get(segment)
            .ok_or_else(|| format!("{dotted}: missing segment {segment}"))?;
    }
    Ok(value)
}

fn as_str<'a>(value: &'a Value, ctx: &str) -> TestResult<&'a str> {
    value
        .as_str()
        .ok_or_else(|| format!("{ctx} must be a string"))
}

fn as_bool(value: &Value, ctx: &str) -> TestResult<bool> {
    value
        .as_bool()
        .ok_or_else(|| format!("{ctx} must be a bool"))
}

fn as_array<'a>(value: &'a Value, ctx: &str) -> TestResult<&'a Vec<Value>> {
    value
        .as_array()
        .ok_or_else(|| format!("{ctx} must be an array"))
}

fn string_vec(value: &Value, ctx: &str) -> TestResult<Vec<String>> {
    as_array(value, ctx)?
        .iter()
        .enumerate()
        .map(|(idx, item)| as_str(item, &format!("{ctx}[{idx}]")).map(str::to_owned))
        .collect()
}

fn string_set(value: &Value, ctx: &str) -> TestResult<BTreeSet<String>> {
    Ok(string_vec(value, ctx)?.into_iter().collect())
}

fn ensure(condition: bool, message: impl Into<String>) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn ensure_eq<T>(left: T, right: T, context: impl Into<String>) -> TestResult
where
    T: PartialEq + std::fmt::Debug,
{
    if left == right {
        Ok(())
    } else {
        Err(format!("{}: left={left:?} right={right:?}", context.into()))
    }
}

fn exact_set(expected: &[&str]) -> BTreeSet<String> {
    expected.iter().map(|value| (*value).to_owned()).collect()
}

#[test]
fn compiler_runtime_diagnostic_contract_is_report_only() -> TestResult {
    let root = workspace_root()?;
    let diagnostic = load_json(&root, DIAGNOSTIC_PATH)?;

    ensure_eq(
        as_str(&diagnostic["schema_version"], "schema_version")?,
        "v1",
        "schema_version",
    )?;
    ensure_eq(
        as_str(&diagnostic["manifest_id"], "manifest_id")?,
        "standalone-compiler-runtime-blocker-diagnostics",
        "manifest_id",
    )?;
    ensure_eq(as_str(&diagnostic["bead"], "bead")?, "bd-zyck1.87", "bead")?;
    ensure_eq(
        as_str(&diagnostic["source_commit"], "source_commit")?,
        "current",
        "source_commit",
    )?;

    let policy = &diagnostic["report_policy"];
    ensure(
        !as_bool(&policy["promotion_allowed"], "promotion_allowed")?,
        "promotion must be disabled",
    )?;
    ensure(
        !as_bool(
            &policy["replacement_level_change_allowed"],
            "replacement_level_change_allowed",
        )?,
        "replacement level changes must be disabled",
    )?;
    ensure(
        !as_bool(
            &policy["default_build_profile_change_allowed"],
            "default_build_profile_change_allowed",
        )?,
        "default build profile changes must be disabled",
    )?;
    ensure(
        !as_bool(
            &policy["panic_strategy_change_allowed"],
            "panic_strategy_change_allowed",
        )?,
        "panic strategy changes must be disabled",
    )?;
    ensure(
        as_bool(
            &policy["non_baseline_experiments_require_separate_bead"],
            "non_baseline_experiments_require_separate_bead",
        )?,
        "non-baseline experiments must require a separate bead",
    )?;
    ensure_eq(
        as_str(&policy["stale_result"], "stale_result")?,
        "block_compiler_runtime_blocker_diagnostics",
        "stale_result",
    )
}

#[test]
fn compiler_runtime_profile_records_build_and_link_knobs() -> TestResult {
    let root = workspace_root()?;
    let diagnostic = load_json(&root, DIAGNOSTIC_PATH)?;
    let profile = &diagnostic["toolchain_profile"];

    ensure_eq(
        as_str(&profile["cargo_package"], "cargo_package")?,
        "frankenlibc-abi",
        "cargo_package",
    )?;
    ensure_eq(
        as_str(&profile["cargo_profile"], "cargo_profile")?,
        "release",
        "cargo_profile",
    )?;
    ensure_eq(
        string_vec(&profile["cargo_features"], "cargo_features")?,
        vec!["standalone".to_owned()],
        "cargo_features",
    )?;
    ensure_eq(
        as_str(&profile["target_triple"], "target_triple")?,
        "x86_64-unknown-linux-gnu",
        "target_triple",
    )?;
    ensure_eq(
        as_str(&profile["rust_toolchain_channel"], "rust_toolchain_channel")?,
        "nightly-2026-04-28",
        "rust_toolchain_channel",
    )?;
    ensure(
        as_str(
            &profile["panic_strategy"]["current"],
            "panic_strategy.current",
        )? == "implicit-unwind",
        "current panic strategy must stay implicit-unwind",
    )?;
    ensure(
        !as_bool(
            &profile["panic_strategy"]["default_change_allowed"],
            "panic_strategy.default_change_allowed",
        )?,
        "panic strategy default changes must not be allowed by this artifact",
    )?;

    let build_command = string_vec(&profile["build_command"], "build_command")?;
    ensure_eq(
        build_command,
        vec![
            "rch".to_owned(),
            "exec".to_owned(),
            "--".to_owned(),
            "cargo".to_owned(),
            "build".to_owned(),
            "-p".to_owned(),
            "frankenlibc-abi".to_owned(),
            "--release".to_owned(),
            "--features=standalone".to_owned(),
        ],
        "build_command",
    )?;

    let link_args = as_array(&profile["relevant_link_args"], "relevant_link_args")?;
    ensure_eq(link_args.len(), 1, "relevant_link_args.len")?;
    ensure_eq(
        as_str(&link_args[0]["source"], "link_args[0].source")?,
        "crates/frankenlibc-abi/build.rs",
        "link arg source",
    )?;
    ensure_eq(
        as_str(&link_args[0]["arg"], "link_args[0].arg")?,
        "-Wl,--version-script=crates/frankenlibc-abi/version_scripts/libc.map",
        "version script link arg",
    )
}

#[test]
fn compiler_runtime_diagnostic_matches_current_forge_snapshot() -> TestResult {
    let root = workspace_root()?;
    let diagnostic = load_json(&root, DIAGNOSTIC_PATH)?;
    let plan = load_json(&root, HOST_PROBE_PLAN_PATH)?;
    let snapshot = get_path(
        &plan,
        "current_forge_blocker_projection.current_forge_blocker_value_snapshot",
    )?;

    ensure_eq(
        as_str(
            &diagnostic["inputs"]["standalone_host_dependency_probe_plan"],
            "inputs.standalone_host_dependency_probe_plan",
        )?,
        HOST_PROBE_PLAN_PATH,
        "host probe plan input",
    )?;
    ensure_eq(
        as_str(
            &diagnostic["current_forge_evidence"]["latest_probe_claim_status"],
            "latest_probe_claim_status",
        )?,
        as_str(&snapshot["claim_status"], "snapshot.claim_status")?,
        "claim_status",
    )?;
    ensure_eq(
        as_str(
            &diagnostic["current_forge_evidence"]["latest_probe_failure_signature"],
            "latest_probe_failure_signature",
        )?,
        as_str(&snapshot["failure_signature"], "snapshot.failure_signature")?,
        "failure_signature",
    )?;

    let observed_needed = string_set(
        &diagnostic["current_forge_evidence"]["evidence_command_results"]["readelf_dynamic"]["observed_needed_libraries"],
        "readelf_dynamic.observed_needed_libraries",
    )?;
    let snapshot_needed = string_set(&snapshot["needed_libraries"], "snapshot.needed_libraries")?;
    ensure_eq(observed_needed, snapshot_needed, "needed libraries")?;

    let observed_resolved = string_set(
        &diagnostic["current_forge_evidence"]["evidence_command_results"]["ldd"]["observed_host_resolved_libraries"],
        "ldd.observed_host_resolved_libraries",
    )?;
    let snapshot_resolved = string_set(
        &snapshot["host_resolved_libraries"],
        "snapshot.host_resolved_libraries",
    )?;
    ensure_eq(
        observed_resolved,
        snapshot_resolved,
        "host resolved libraries",
    )
}

#[test]
fn compiler_runtime_blocker_rows_pin_libgcc_and_unwind_values() -> TestResult {
    let root = workspace_root()?;
    let diagnostic = load_json(&root, DIAGNOSTIC_PATH)?;
    let mappings = as_array(&diagnostic["blocker_mappings"], "blocker_mappings")?;
    ensure_eq(mappings.len(), 2, "blocker_mappings.len")?;

    let libgcc = mappings
        .iter()
        .find(|row| row["blocker_id"].as_str() == Some("libgcc-runtime-dependency"))
        .ok_or_else(|| "missing libgcc-runtime-dependency mapping".to_string())?;
    ensure_eq(
        as_str(&libgcc["blocking_reason"], "libgcc.blocking_reason")?,
        "libgcc_runtime_dependency",
        "libgcc blocking reason",
    )?;
    ensure_eq(
        string_vec(
            &libgcc["observed_values"]["needed_libraries"],
            "libgcc.needed_libraries",
        )?,
        vec!["libgcc_s.so.1".to_owned()],
        "libgcc needed libraries",
    )?;
    ensure_eq(
        string_set(
            &libgcc["observed_values"]["host_version_requirements"],
            "libgcc.host_version_requirements",
        )?,
        exact_set(EXPECTED_LIBGCC_VERSION_REQUIREMENTS),
        "libgcc version requirements",
    )?;

    let unwind = mappings
        .iter()
        .find(|row| row["blocker_id"].as_str() == Some("undefined-unwind-symbols"))
        .ok_or_else(|| "missing undefined-unwind-symbols mapping".to_string())?;
    ensure_eq(
        as_str(&unwind["blocking_reason"], "unwind.blocking_reason")?,
        "undefined_unwind_symbols",
        "unwind blocking reason",
    )?;
    ensure_eq(
        string_set(
            &unwind["observed_values"]["undefined_unwind_symbols"],
            "unwind.undefined_unwind_symbols",
        )?,
        exact_set(EXPECTED_UNWIND_SYMBOLS),
        "unwind symbols",
    )?;
    ensure_eq(
        diagnostic["summary"]["undefined_unwind_symbol_count"].as_u64(),
        Some(EXPECTED_UNWIND_SYMBOLS.len() as u64),
        "summary.undefined_unwind_symbol_count",
    )
}

#[test]
fn compiler_runtime_experiment_matrix_keeps_non_baseline_lanes_report_only() -> TestResult {
    let root = workspace_root()?;
    let diagnostic = load_json(&root, DIAGNOSTIC_PATH)?;
    let experiments = as_array(&diagnostic["experiment_matrix"], "experiment_matrix")?;
    ensure(
        experiments.len() >= 3,
        "experiment_matrix must include baseline and at least two follow-up lanes",
    )?;

    let baseline = experiments
        .iter()
        .find(|row| row["experiment_id"].as_str() == Some("baseline-release-standalone"))
        .ok_or_else(|| "missing baseline-release-standalone experiment".to_string())?;
    ensure_eq(
        as_str(&baseline["status"], "baseline.status")?,
        "observed_baseline",
        "baseline status",
    )?;
    ensure_eq(
        as_str(&baseline["panic_strategy"], "baseline.panic_strategy")?,
        "implicit-unwind",
        "baseline panic strategy",
    )?;

    for experiment in experiments {
        if experiment["experiment_id"].as_str() == Some("baseline-release-standalone") {
            continue;
        }
        ensure_eq(
            as_str(
                &experiment["expected_claim_status"],
                "experiment.expected_claim_status",
            )?,
            "report_only",
            format!(
                "{} expected_claim_status",
                as_str(&experiment["experiment_id"], "experiment_id")?
            ),
        )?;
        ensure(
            as_bool(
                &experiment["must_not_change_default_profile"],
                "experiment.must_not_change_default_profile",
            )?,
            format!(
                "{} must not change default profile",
                as_str(&experiment["experiment_id"], "experiment_id")?
            ),
        )?;
    }
    Ok(())
}
