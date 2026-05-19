//! Integration test: standalone TLS blocker diagnostics (bd-zyck1.89).
//!
//! Keeps the current `__tls_get_addr@GLIBC_2.3` forge blocker tied to both
//! artifact evidence and the live Rust source TLS inventory.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

const DIAGNOSTIC_PATH: &str = "tests/conformance/standalone_tls_blocker_diagnostics.v1.json";
const HOST_PROBE_PLAN_PATH: &str =
    "tests/conformance/standalone_host_dependency_probe_plan.v1.json";
const EXPECTED_TLS_SYMBOL: &str = "__tls_get_addr@GLIBC_2.3";

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

fn as_u64(value: &Value, ctx: &str) -> TestResult<u64> {
    value.as_u64().ok_or_else(|| format!("{ctx} must be a u64"))
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

fn u64_vec(value: &Value, ctx: &str) -> TestResult<Vec<u64>> {
    as_array(value, ctx)?
        .iter()
        .enumerate()
        .map(|(idx, item)| as_u64(item, &format!("{ctx}[{idx}]")))
        .collect()
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

fn collect_rs_files(root: &Path, files: &mut Vec<PathBuf>) -> TestResult {
    for entry in std::fs::read_dir(root).map_err(|err| format!("{}: {err}", root.display()))? {
        let entry = entry.map_err(|err| format!("{}: {err}", root.display()))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|err| format!("{}: {err}", path.display()))?;
        if file_type.is_dir() {
            collect_rs_files(&path, files)?;
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            files.push(path);
        }
    }
    Ok(())
}

fn is_thread_local_macro_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("thread_local!") || trimmed.starts_with("std::thread_local!")
}

fn scan_live_thread_local_inventory(root: &Path) -> TestResult<BTreeMap<String, Vec<u64>>> {
    let mut files = Vec::new();
    for source_root in [
        "crates/frankenlibc-abi/src",
        "crates/frankenlibc-core/src",
        "crates/frankenlibc-membrane/src",
    ] {
        collect_rs_files(&root.join(source_root), &mut files)?;
    }

    let mut inventory = BTreeMap::new();
    for path in files {
        let rel = path
            .strip_prefix(root)
            .map_err(|err| format!("{}: {err}", path.display()))?
            .to_string_lossy()
            .replace('\\', "/");
        let content =
            std::fs::read_to_string(&path).map_err(|err| format!("{}: {err}", path.display()))?;
        let lines = content
            .lines()
            .enumerate()
            .filter_map(|(idx, line)| is_thread_local_macro_line(line).then_some(idx as u64 + 1))
            .collect::<Vec<_>>();
        if !lines.is_empty() {
            inventory.insert(rel, lines);
        }
    }
    Ok(inventory)
}

fn manifest_thread_local_inventory(diagnostic: &Value) -> TestResult<BTreeMap<String, Vec<u64>>> {
    let mut inventory = BTreeMap::new();
    for row in as_array(
        &diagnostic["source_surface_scan"]["thread_local_inventory"],
        "thread_local_inventory",
    )? {
        let path = as_str(&row["path"], "inventory.path")?.to_owned();
        let line_numbers = u64_vec(&row["line_numbers"], "inventory.line_numbers")?;
        let count = as_u64(
            &row["thread_local_macro_count"],
            "inventory.thread_local_macro_count",
        )?;
        ensure_eq(
            line_numbers.len() as u64,
            count,
            format!("{path} thread_local_macro_count"),
        )?;
        ensure(
            inventory.insert(path.clone(), line_numbers).is_none(),
            format!("duplicate inventory path {path}"),
        )?;
    }
    Ok(inventory)
}

#[test]
fn tls_blocker_diagnostic_is_report_only() -> TestResult {
    let root = workspace_root()?;
    let diagnostic = load_json(&root, DIAGNOSTIC_PATH)?;
    let policy = &diagnostic["report_policy"];

    ensure_eq(
        as_str(&diagnostic["manifest_id"], "manifest_id")?,
        "standalone-tls-blocker-diagnostics",
        "manifest id",
    )?;
    ensure_eq(as_str(&diagnostic["bead"], "bead")?, "bd-zyck1.89", "bead")?;
    for field in [
        "promotion_allowed",
        "replacement_level_change_allowed",
        "default_build_profile_change_allowed",
        "default_tls_model_change_allowed",
        "source_rewrite_allowed",
    ] {
        ensure(
            !as_bool(&policy[field], field)?,
            format!("report policy field {field} must be false"),
        )?;
    }
    ensure_eq(
        as_str(&policy["stale_result"], "policy.stale_result")?,
        "block_standalone_tls_blocker_diagnostics",
        "stale result",
    )
}

#[test]
fn tls_blocker_diagnostic_matches_current_forge_snapshot() -> TestResult {
    let root = workspace_root()?;
    let diagnostic = load_json(&root, DIAGNOSTIC_PATH)?;
    let plan = load_json(&root, HOST_PROBE_PLAN_PATH)?;
    let snapshot = get_path(
        &plan,
        "current_forge_blocker_projection.current_forge_blocker_value_snapshot",
    )?;
    let evidence = &diagnostic["current_forge_evidence"];

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
            &evidence["latest_probe_claim_status"],
            "latest_probe_claim_status",
        )?,
        as_str(&snapshot["claim_status"], "snapshot.claim_status")?,
        "claim status",
    )?;
    ensure_eq(
        as_str(
            &evidence["latest_probe_failure_signature"],
            "latest_probe_failure_signature",
        )?,
        as_str(&snapshot["failure_signature"], "snapshot.failure_signature")?,
        "failure signature",
    )?;
    ensure_eq(
        string_set(
            &evidence["observed_artifact_symbols"]["undefined_tls_symbols"],
            "evidence.undefined_tls_symbols",
        )?,
        string_set(
            &snapshot["undefined_tls_symbols"],
            "snapshot.undefined_tls_symbols",
        )?,
        "undefined TLS symbols",
    )?;
    ensure_eq(
        string_vec(
            &evidence["evidence_command_results"]["nm_dynamic"]["observed_undefined_tls_symbols"],
            "nm_dynamic.observed_undefined_tls_symbols",
        )?,
        vec![EXPECTED_TLS_SYMBOL.to_owned()],
        "nm dynamic TLS symbol",
    )?;
    ensure(
        string_set(
            &snapshot["host_version_requirements"],
            "snapshot.host_version_requirements",
        )?
        .contains("ld-linux-x86-64.so.2:GLIBC_2.3"),
        "snapshot must keep the ld-linux GLIBC_2.3 version need tied to the TLS blocker",
    )
}

#[test]
fn owned_tls_cache_probe_records_current_artifact_tls_buckets() -> TestResult {
    let root = workspace_root()?;
    let diagnostic = load_json(&root, DIAGNOSTIC_PATH)?;
    let probe = &diagnostic["owned_tls_cache_artifact_probe"];

    ensure_eq(
        as_str(&probe["latest_probe_result"], "latest_probe_result")?,
        "pass_remote",
        "owned TLS probe result",
    )?;
    let command = as_str(&probe["latest_probe_command"], "latest_probe_command")?;
    ensure(
        command.contains("rch exec")
            && command.contains("owned-tls-cache")
            && command.contains("owned-unwind-stub"),
        "owned TLS probe command must record the remote build and feature gates",
    )?;
    ensure_eq(
        string_vec(
            &probe["observed_artifact_symbols"]["undefined_tls_symbols"],
            "owned_tls_cache_artifact_probe.undefined_tls_symbols",
        )?,
        vec![EXPECTED_TLS_SYMBOL.to_owned()],
        "owned TLS probe must keep the live TLS blocker",
    )?;
    ensure_eq(
        string_set(
            &probe["observed_artifact_symbols"]["needed_libraries"],
            "owned_tls_cache_artifact_probe.needed_libraries",
        )?,
        BTreeSet::from(["ld-linux-x86-64.so.2".to_owned()]),
        "owned TLS probe must record only the remaining loader NEEDED library",
    )?;
    ensure_eq(
        as_u64(
            &probe["tls_relocation_summary"]["dtpmod64_relocation_count"],
            "dtpmod64_relocation_count",
        )?,
        4,
        "DTPMOD64 relocation count",
    )?;
    ensure_eq(
        as_u64(
            &probe["tls_relocation_summary"]["tls_get_addr_jump_slot_count"],
            "tls_get_addr_jump_slot_count",
        )?,
        1,
        "tls_get_addr jump slot count",
    )?;

    let buckets = as_array(&probe["tls_descriptor_buckets"], "tls_descriptor_buckets")?;
    ensure_eq(buckets.len(), 6, "TLS descriptor bucket count")?;
    let owner_buckets = buckets
        .iter()
        .map(|bucket| as_str(&bucket["owner_bucket"], "owner_bucket").map(str::to_owned))
        .collect::<TestResult<BTreeSet<_>>>()?;
    for expected in [
        "rust_std_panic_local_panic_count",
        "rust_std_io_output_capture",
        "rust_std_thread_local_destructors",
        "rust_std_thread_current_id",
        "rust_std_thread_current_handle",
        "rust_std_thread_spawnhook",
    ] {
        ensure(
            owner_buckets.contains(expected),
            format!("missing owned TLS descriptor bucket {expected}"),
        )?;
    }

    let residual = as_array(
        &probe["residual_artifact_tls_emitters"],
        "residual_artifact_tls_emitters",
    )?;
    ensure_eq(residual.len(), 6, "residual artifact TLS emitter count")?;
    let residual_symbols = residual
        .iter()
        .map(|row| as_str(&row["symbol"], "residual_artifact_tls_emitters.symbol"))
        .collect::<TestResult<Vec<_>>>()?;
    ensure(
        residual
            .iter()
            .all(|row| row.get("crate").and_then(Value::as_str) == Some("std")),
        "residual artifact TLS emitters must all be std-owned after first-party cleanup",
    )?;
    ensure(
        residual_symbols
            .iter()
            .all(|symbol| !symbol.contains("RandomState") && !symbol.contains("KEYS")),
        "residual artifact TLS emitters must not retain std RandomState KEYS",
    )?;
    ensure(
        as_str(&probe["classification"], "classification")?.contains("claim-blocked"),
        "owned TLS probe classification must keep bd-c51oi claim-blocked",
    )
}

#[test]
fn source_inventory_matches_live_thread_local_macro_sites() -> TestResult {
    let root = workspace_root()?;
    let diagnostic = load_json(&root, DIAGNOSTIC_PATH)?;
    let manifest = manifest_thread_local_inventory(&diagnostic)?;
    let live = scan_live_thread_local_inventory(&root)?;
    ensure_eq(&manifest, &live, "thread_local inventory must match source")?;

    let total = manifest.values().map(Vec::len).sum::<usize>() as u64;
    ensure_eq(
        total,
        as_u64(
            &diagnostic["source_surface_scan"]["total_thread_local_macro_count"],
            "total_thread_local_macro_count",
        )?,
        "total thread_local macro count",
    )?;
    ensure_eq(
        manifest.len() as u64,
        as_u64(
            &diagnostic["source_surface_scan"]["thread_local_source_file_count"],
            "thread_local_source_file_count",
        )?,
        "thread_local source file count",
    )?;

    for (path, lines) in &manifest {
        let content = std::fs::read_to_string(root.join(path))
            .map_err(|err| format!("{}: {err}", root.join(path).display()))?;
        let source_lines = content.lines().collect::<Vec<_>>();
        for line_number in lines {
            let line = source_lines
                .get(*line_number as usize - 1)
                .ok_or_else(|| format!("{path}:{line_number} is outside file"))?;
            ensure(
                is_thread_local_macro_line(line),
                format!("{path}:{line_number} must be a thread_local macro line"),
            )?;
        }
    }
    Ok(())
}

#[test]
fn source_owner_groups_cover_every_inventory_path() -> TestResult {
    let root = workspace_root()?;
    let diagnostic = load_json(&root, DIAGNOSTIC_PATH)?;
    let manifest_paths = manifest_thread_local_inventory(&diagnostic)?
        .into_keys()
        .collect::<BTreeSet<_>>();
    let mut group_paths = BTreeSet::new();
    for group in as_array(&diagnostic["source_owner_groups"], "source_owner_groups")? {
        for path in string_vec(&group["paths"], "group.paths")? {
            ensure(
                group_paths.insert(path.clone()),
                format!("duplicate source_owner_groups path {path}"),
            )?;
        }
    }
    ensure_eq(
        group_paths,
        manifest_paths,
        "source owner groups must cover exactly the TLS inventory paths",
    )
}

#[test]
fn negative_control_gate_requires_artifact_and_source_evidence() -> TestResult {
    let root = workspace_root()?;
    let diagnostic = load_json(&root, DIAGNOSTIC_PATH)?;
    let gate = &diagnostic["negative_control_gate"];

    ensure(
        as_str(&gate["source_scan_command"], "source_scan_command")?.contains("thread_local!"),
        "source scan command must search thread_local macro sites",
    )?;
    ensure(
        as_str(&gate["artifact_nm_command"], "artifact_nm_command")?.contains("nm -D"),
        "artifact nm command must inspect the dynamic symbol table",
    )?;
    ensure(
        as_str(
            &gate["artifact_readelf_command"],
            "artifact_readelf_command",
        )?
        .contains("readelf -Ws"),
        "artifact readelf command must inspect undefined symbol bindings",
    )?;
    let pass_conditions = string_vec(&gate["future_pass_conditions"], "future_pass_conditions")?;
    ensure(
        pass_conditions
            .iter()
            .any(|condition| condition.contains("undefined_tls_symbols is empty")),
        "future pass conditions must require empty undefined_tls_symbols",
    )?;
    ensure(
        pass_conditions
            .iter()
            .any(|condition| condition.contains("no undefined __tls_get_addr")),
        "future pass conditions must require no undefined __tls_get_addr",
    )?;
    ensure(
        as_str(&gate["claim_guard"], "claim_guard")?.contains("cannot promote"),
        "claim guard must block promotion without artifact controls",
    )
}

#[test]
fn compiler_runtime_experiment_keeps_tls_blocker_positive_control() -> TestResult {
    let root = workspace_root()?;
    let diagnostic = load_json(&root, DIAGNOSTIC_PATH)?;
    let confirmation =
        &diagnostic["current_forge_evidence"]["compiler_runtime_experiment_confirmation"];

    for lane in [
        "baseline_release_standalone",
        "panic_abort_compiler_runtime_minimized",
    ] {
        ensure_eq(
            string_vec(
                &confirmation[lane]["undefined_tls_symbols"],
                &format!("{lane}.undefined_tls_symbols"),
            )?,
            vec![EXPECTED_TLS_SYMBOL.to_owned()],
            format!("{lane} TLS symbol"),
        )?;
    }
    ensure(
        as_str(&confirmation["classification"], "classification")?
            .contains("leaves the TLS relocation unchanged"),
        "experiment confirmation must explain that panic-abort leaves the TLS blocker in place",
    )
}
