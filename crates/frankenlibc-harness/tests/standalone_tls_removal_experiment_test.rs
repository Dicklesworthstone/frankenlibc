//! Conformance gate for the TLS-removal experiment manifest (bd-juvqm.5).
//!
//! Validates the schema, lane invariants, and per-symbol/per-owner-surface
//! disposition rows of `tests/conformance/standalone_tls_removal_experiment.v1.json`.
//! Mutation tests prove the gate fails closed on:
//!   * stale source_commit
//!   * missing TLS symbol row
//!   * missing owner-surface row
//!   * hidden glibc version need (any row that drops the GLIBC_2.3 version requirement
//!     without supplying nm/readelf evidence)
//!   * illegal promotion (claim_status flipped to ready while a cluster still has thread_local!)
//!   * default forge path / replacement level / TLS model change attempted on baseline
//!
//! No live build is required — this is the contract the live experiment must
//! eventually satisfy. The acceptance bar is `report_only` until every cluster
//! reaches `pthread_key_substituted`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

const BASELINE_LANE: &str = "baseline-release-standalone";
const LOCAL_EXEC_LANE: &str = "local-exec-tls-model-probe";
const OWNED_TLS_LANE: &str = "owned-tls-cache-source-surface";
const TLS_SYMBOL: &str = "__tls_get_addr@GLIBC_2.3";
const TLS_VERSION_REQ: &str = "ld-linux-x86-64.so.2:GLIBC_2.3";
const EXPECTED_OWNER_SURFACE_COUNT: usize = 19;
const EXPECTED_NON_TARGETED_TLS_EMITTER_COUNT: usize = 3;

#[derive(Debug, Clone, Eq, PartialEq)]
struct ThreadLocalMacroSite {
    path: String,
    line: usize,
    macro_invocation: String,
    storage_symbols: Vec<String>,
}

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

fn manifest_path(root: &Path) -> PathBuf {
    root.join("tests")
        .join("conformance")
        .join("standalone_tls_removal_experiment.v1.json")
}

fn abi_cargo_toml_path(root: &Path) -> PathBuf {
    root.join("crates")
        .join("frankenlibc-abi")
        .join("Cargo.toml")
}

fn abi_unistd_path(root: &Path) -> PathBuf {
    root.join("crates")
        .join("frankenlibc-abi")
        .join("src")
        .join("unistd_abi.rs")
}

fn abi_resolv_path(root: &Path) -> PathBuf {
    root.join("crates")
        .join("frankenlibc-abi")
        .join("src")
        .join("resolv_abi.rs")
}

fn abi_string_path(root: &Path) -> PathBuf {
    root.join("crates")
        .join("frankenlibc-abi")
        .join("src")
        .join("string_abi.rs")
}

fn abi_rpc_path(root: &Path) -> PathBuf {
    root.join("crates")
        .join("frankenlibc-abi")
        .join("src")
        .join("rpc_abi.rs")
}

fn abi_glibc_internal_path(root: &Path) -> PathBuf {
    root.join("crates")
        .join("frankenlibc-abi")
        .join("src")
        .join("glibc_internal_abi.rs")
}

fn abi_errno_path(root: &Path) -> PathBuf {
    root.join("crates")
        .join("frankenlibc-abi")
        .join("src")
        .join("errno_abi.rs")
}

fn abi_dlfcn_path(root: &Path) -> PathBuf {
    root.join("crates")
        .join("frankenlibc-abi")
        .join("src")
        .join("dlfcn_abi.rs")
}

fn abi_dirent_path(root: &Path) -> PathBuf {
    root.join("crates")
        .join("frankenlibc-abi")
        .join("src")
        .join("dirent_abi.rs")
}

fn abi_ctype_path(root: &Path) -> PathBuf {
    root.join("crates")
        .join("frankenlibc-abi")
        .join("src")
        .join("ctype_abi.rs")
}

fn abi_runtime_policy_path(root: &Path) -> PathBuf {
    root.join("crates")
        .join("frankenlibc-abi")
        .join("src")
        .join("runtime_policy.rs")
}

fn abi_startup_path(root: &Path) -> PathBuf {
    root.join("crates")
        .join("frankenlibc-abi")
        .join("src")
        .join("startup_abi.rs")
}

fn abi_signal_path(root: &Path) -> PathBuf {
    root.join("crates")
        .join("frankenlibc-abi")
        .join("src")
        .join("signal_abi.rs")
}

fn abi_stdio_path(root: &Path) -> PathBuf {
    root.join("crates")
        .join("frankenlibc-abi")
        .join("src")
        .join("stdio_abi.rs")
}

fn abi_wchar_path(root: &Path) -> PathBuf {
    root.join("crates")
        .join("frankenlibc-abi")
        .join("src")
        .join("wchar_abi.rs")
}

fn abi_stdlib_path(root: &Path) -> PathBuf {
    root.join("crates")
        .join("frankenlibc-abi")
        .join("src")
        .join("stdlib_abi.rs")
}

fn abi_grp_path(root: &Path) -> PathBuf {
    root.join("crates")
        .join("frankenlibc-abi")
        .join("src")
        .join("grp_abi.rs")
}

fn abi_pwd_path(root: &Path) -> PathBuf {
    root.join("crates")
        .join("frankenlibc-abi")
        .join("src")
        .join("pwd_abi.rs")
}

fn abi_pthread_path(root: &Path) -> PathBuf {
    root.join("crates")
        .join("frankenlibc-abi")
        .join("src")
        .join("pthread_abi.rs")
}

fn abi_inet_path(root: &Path) -> PathBuf {
    root.join("crates")
        .join("frankenlibc-abi")
        .join("src")
        .join("inet_abi.rs")
}

fn abi_time_path(root: &Path) -> PathBuf {
    root.join("crates")
        .join("frankenlibc-abi")
        .join("src")
        .join("time_abi.rs")
}

fn abi_src_dir(root: &Path) -> PathBuf {
    root.join("crates").join("frankenlibc-abi").join("src")
}

fn load_manifest() -> TestResult<Value> {
    let root = workspace_root()?;
    let path = manifest_path(&root);
    let content = std::fs::read_to_string(&path).map_err(|err| format!("read {path:?}: {err}"))?;
    serde_json::from_str(&content).map_err(|err| format!("parse {path:?}: {err}"))
}

fn require(condition: bool, message: impl Into<String>) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn json_field<'a>(value: &'a Value, field: &str) -> TestResult<&'a Value> {
    value
        .get(field)
        .ok_or_else(|| format!("missing field `{field}`"))
}

fn json_array<'a>(value: &'a Value, field: &str) -> TestResult<&'a Vec<Value>> {
    json_field(value, field)?
        .as_array()
        .ok_or_else(|| format!("`{field}` must be an array"))
}

fn json_string<'a>(value: &'a Value, field: &str) -> TestResult<&'a str> {
    json_field(value, field)?
        .as_str()
        .ok_or_else(|| format!("`{field}` must be a string"))
}

fn json_bool(value: &Value, field: &str) -> TestResult<bool> {
    json_field(value, field)?
        .as_bool()
        .ok_or_else(|| format!("`{field}` must be a bool"))
}

fn json_u64(value: &Value, field: &str) -> TestResult<u64> {
    json_field(value, field)?
        .as_u64()
        .ok_or_else(|| format!("`{field}` must be a u64"))
}

fn lane<'a>(manifest: &'a Value, lane_id: &str) -> TestResult<&'a Value> {
    json_array(manifest, "experiment_lanes")?
        .iter()
        .find(|l| l.get("lane_id").and_then(Value::as_str) == Some(lane_id))
        .ok_or_else(|| format!("missing lane `{lane_id}`"))
}

fn thread_local_invocation(line: &str) -> Option<&'static str> {
    let trimmed = line.trim_start();
    if trimmed.starts_with("std::thread_local!") {
        Some("std::thread_local!")
    } else if trimmed.starts_with("thread_local!") {
        Some("thread_local!")
    } else {
        None
    }
}

fn has_owned_tls_fallback_gate(lines: &[&str], idx: usize) -> bool {
    let start = idx.saturating_sub(8);
    lines[start..idx]
        .iter()
        .any(|line| line.contains("#[cfg(not(feature = \"owned-tls-cache\"))]"))
}

fn storage_symbols_in_thread_local_block(lines: &[&str], idx: usize) -> Vec<String> {
    let mut symbols = Vec::new();
    for line in lines.iter().skip(idx + 1) {
        let trimmed = line.trim_start();
        if trimmed == "}" {
            break;
        }
        if let Some(rest) = trimmed.strip_prefix("static ")
            && let Some(name) = rest
                .split(|c: char| c == ':' || c.is_ascii_whitespace())
                .next()
        {
            symbols.push(name.to_string());
        }
    }
    symbols
}

fn ungated_thread_local_macro_sites(root: &Path) -> TestResult<Vec<ThreadLocalMacroSite>> {
    let src_dir = abi_src_dir(root);
    let mut files: Vec<PathBuf> = std::fs::read_dir(&src_dir)
        .map_err(|err| format!("read ABI source dir {src_dir:?}: {err}"))?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("rs"))
        .collect();
    files.sort();

    let mut sites = Vec::new();
    for path in files {
        let content =
            std::fs::read_to_string(&path).map_err(|err| format!("read {path:?}: {err}"))?;
        let lines: Vec<&str> = content.lines().collect();
        for (idx, line) in lines.iter().enumerate() {
            let Some(macro_invocation) = thread_local_invocation(line) else {
                continue;
            };
            if has_owned_tls_fallback_gate(&lines, idx) {
                continue;
            }
            let path = path
                .strip_prefix(root)
                .map_err(|err| format!("strip workspace prefix from ABI path: {err}"))?
                .to_string_lossy()
                .replace('\\', "/");
            sites.push(ThreadLocalMacroSite {
                path,
                line: idx + 1,
                macro_invocation: macro_invocation.to_string(),
                storage_symbols: storage_symbols_in_thread_local_block(&lines, idx),
            });
        }
    }

    Ok(sites)
}

fn manifest_non_targeted_tls_sites(manifest: &Value) -> TestResult<Vec<ThreadLocalMacroSite>> {
    let required_fields: BTreeSet<&str> =
        json_array(manifest, "required_non_targeted_tls_emitter_fields")?
            .iter()
            .map(|v| {
                v.as_str().ok_or_else(|| {
                    "required_non_targeted_tls_emitter_fields entries must be strings".to_string()
                })
            })
            .collect::<Result<_, _>>()?;
    for required in [
        "path",
        "line",
        "macro_invocation",
        "storage_symbols",
        "gate_disposition",
        "baseline_disposition",
        "claim_status_until_exit",
        "remediation_plan",
    ] {
        require(
            required_fields.contains(required),
            format!("required_non_targeted_tls_emitter_fields must include {required}"),
        )?;
    }

    let mut sites = Vec::new();
    for row in json_array(manifest, "non_targeted_tls_emitters")? {
        for field in &required_fields {
            require(
                row.get(*field).is_some(),
                format!("non_targeted_tls_emitters row missing {field}"),
            )?;
        }
        require(
            json_string(row, "gate_disposition")? == "ungated",
            "non-targeted TLS emitter gate_disposition",
        )?;
        require(
            json_string(row, "baseline_disposition")? == "still_thread_local",
            "non-targeted TLS emitter baseline_disposition",
        )?;
        require(
            json_string(row, "claim_status_until_exit")? == "claim_blocked",
            "non-targeted TLS emitter claim_status_until_exit",
        )?;
        let storage_symbols = json_array(row, "storage_symbols")?
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| "storage_symbols entries must be strings".to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;
        require(
            !storage_symbols.is_empty(),
            "non-targeted TLS emitter storage_symbols must be nonempty",
        )?;
        sites.push(ThreadLocalMacroSite {
            path: json_string(row, "path")?.to_string(),
            line: json_u64(row, "line")? as usize,
            macro_invocation: json_string(row, "macro_invocation")?.to_string(),
            storage_symbols,
        });
    }
    Ok(sites)
}

fn format_thread_local_sites(sites: &[ThreadLocalMacroSite]) -> String {
    sites
        .iter()
        .map(|site| {
            format!(
                "{}:{}:{}:{:?}",
                site.path, site.line, site.macro_invocation, site.storage_symbols
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// Pure validator. Returns the rejection codes that fire on this manifest.
fn evaluate(manifest: &Value) -> Vec<String> {
    let mut rej: Vec<String> = Vec::new();

    if manifest.get("schema_version").and_then(Value::as_str) != Some("v1") {
        rej.push("missing_or_invalid_schema_version".to_string());
    }
    if manifest.get("bead").and_then(Value::as_str) != Some("bd-juvqm.5") {
        rej.push("missing_or_invalid_bead".to_string());
    }
    let sc = manifest
        .get("source_commit")
        .and_then(Value::as_str)
        .unwrap_or("");
    let is_sha = sc.len() == 40 && sc.chars().all(|c| c.is_ascii_hexdigit());
    if !is_sha && sc != "current" {
        rej.push("stale_source_commit".to_string());
    }

    let policy = manifest
        .get("report_policy")
        .cloned()
        .unwrap_or(Value::Null);
    let must_be_false = [
        "promotion_allowed",
        "replacement_level_change_allowed",
        "default_forge_path_change_allowed",
        "default_build_profile_change_allowed",
        "default_tls_model_change_allowed",
        "source_rewrite_allowed_in_default_lane",
    ];
    for f in must_be_false {
        if policy.get(f).and_then(Value::as_bool) != Some(false) {
            rej.push(format!("policy_{f}_must_be_false"));
        }
    }
    if policy.get("report_only").and_then(Value::as_bool) != Some(true) {
        rej.push("report_only_must_be_true".to_string());
    }
    if policy
        .get("claim_status_until_all_clusters_exit")
        .and_then(Value::as_str)
        != Some("claim_blocked")
    {
        rej.push("claim_status_until_all_clusters_exit_must_be_claim_blocked".to_string());
    }

    // TLS symbol row must include __tls_get_addr@GLIBC_2.3.
    let Some(tls_rows) = manifest
        .get("tls_symbol_disposition_rows")
        .and_then(Value::as_array)
    else {
        rej.push("missing_tls_symbol_row".to_string());
        return rej;
    };
    let symbols: BTreeSet<&str> = tls_rows
        .iter()
        .filter_map(|r| r.get("symbol").and_then(Value::as_str))
        .collect();
    if !symbols.contains(TLS_SYMBOL) {
        rej.push("missing_tls_symbol_row".to_string());
    }
    // The GLIBC_2.3 version requirement must be referenced by at least one row.
    let any_tls_with_version_req = tls_rows
        .iter()
        .any(|r| r.get("version_requirement").and_then(Value::as_str) == Some(TLS_VERSION_REQ));
    if !any_tls_with_version_req {
        rej.push("hidden_glibc_version_need".to_string());
    }

    // Owner-surface rows must cover the targeted clusters.
    let Some(surface_rows) = manifest
        .get("owner_surface_disposition_rows")
        .and_then(Value::as_array)
    else {
        rej.push("missing_owner_surface_row".to_string());
        return rej;
    };
    if surface_rows.len() != EXPECTED_OWNER_SURFACE_COUNT {
        rej.push("missing_owner_surface_row".to_string());
    }

    let Some(non_targeted_rows) = manifest
        .get("non_targeted_tls_emitters")
        .and_then(Value::as_array)
    else {
        rej.push("missing_non_targeted_tls_emitter_inventory".to_string());
        return rej;
    };
    let summary = manifest.get("summary").unwrap_or(&Value::Null);
    let summary_non_targeted_count = summary
        .get("non_targeted_tls_emitter_count")
        .and_then(Value::as_u64);
    if non_targeted_rows.len() != EXPECTED_NON_TARGETED_TLS_EMITTER_COUNT
        || summary_non_targeted_count != Some(non_targeted_rows.len() as u64)
    {
        rej.push("missing_non_targeted_tls_emitter_inventory".to_string());
    }

    // Promotion guard: claim_status_until_exit may not be "ready" while
    // owned_tls_cache_disposition is "pthread_key_substituted_when_complete".
    for r in tls_rows.iter().chain(surface_rows.iter()) {
        let claim = r
            .get("claim_status_until_exit")
            .and_then(Value::as_str)
            .unwrap_or("");
        let owned = r
            .get("owned_tls_cache_disposition")
            .and_then(Value::as_str)
            .unwrap_or("");
        if claim == "ready" && owned.ends_with("_when_complete") {
            rej.push("illegal_promotion".to_string());
            break;
        }
    }

    // Lane geometry.
    if let Ok(b) = lane(manifest, BASELINE_LANE) {
        if b.get("tls_model").and_then(Value::as_str) != Some("initial-exec") {
            rej.push("default_tls_model_changed_on_baseline".to_string());
        }
        if b.get("must_not_change_default_tls_model")
            .and_then(Value::as_bool)
            != Some(true)
        {
            rej.push("default_forge_path_changed".to_string());
        }
    } else {
        rej.push("missing_baseline_lane".to_string());
    }

    rej
}

#[test]
fn manifest_loads_and_passes_canonical_validation() -> TestResult {
    let m = load_manifest()?;
    let r = evaluate(&m);
    require(
        r.is_empty(),
        format!("canonical manifest must validate cleanly; got {r:?}"),
    )
}

#[test]
fn manifest_id_and_bead_anchor_to_juvqm5() -> TestResult {
    let m = load_manifest()?;
    require(
        json_string(&m, "manifest_id")? == "standalone-tls-removal-experiment",
        "manifest_id",
    )?;
    require(
        json_string(&m, "bead")? == "bd-juvqm.5",
        "bead must be bd-juvqm.5",
    )
}

#[test]
fn three_lanes_present_with_correct_roles() -> TestResult {
    let m = load_manifest()?;
    let lanes = json_array(&m, "experiment_lanes")?;
    require(lanes.len() == 3, "must have exactly 3 lanes")?;

    let baseline = lane(&m, BASELINE_LANE)?;
    require(
        json_string(baseline, "role")? == "baseline",
        "baseline role",
    )?;
    require(
        json_string(baseline, "tls_model")? == "initial-exec",
        "baseline tls_model",
    )?;

    let local_exec = lane(&m, LOCAL_EXEC_LANE)?;
    require(
        json_string(local_exec, "role")? == "comparison",
        "local-exec role",
    )?;
    require(
        json_string(local_exec, "expected_failure_signature")?
            == "non_pic_tls_relocation_in_shared_dependency",
        "local-exec failure signature",
    )?;

    let owned = lane(&m, OWNED_TLS_LANE)?;
    require(
        json_string(owned, "role")? == "experiment",
        "owned-tls-cache role",
    )?;
    require(
        json_string(owned, "build_status_until_owned_substitute_complete")?
            == "report_only_blocked",
        "owned-tls-cache must remain report_only_blocked",
    )
}

#[test]
fn report_policy_locks_default_forge_replacement_and_tls_model() -> TestResult {
    let m = load_manifest()?;
    let policy = json_field(&m, "report_policy")?;
    require(json_bool(policy, "report_only")?, "report_only true")?;
    for f in [
        "promotion_allowed",
        "replacement_level_change_allowed",
        "default_forge_path_change_allowed",
        "default_build_profile_change_allowed",
        "default_tls_model_change_allowed",
        "source_rewrite_allowed_in_default_lane",
    ] {
        require(!json_bool(policy, f)?, format!("{f} must be false"))?;
    }
    require(
        json_string(policy, "claim_status_until_all_clusters_exit")? == "claim_blocked",
        "claim_status_until_all_clusters_exit",
    )?;
    let rejected: BTreeSet<String> = json_array(policy, "rejected_evidence_kinds")?
        .iter()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect();
    for kind in [
        "missing_tls_symbol_row",
        "missing_owner_surface_row",
        "missing_non_targeted_tls_emitter_inventory",
        "untracked_non_targeted_tls_emitter",
        "hidden_glibc_version_need",
        "stale_source_commit",
        "illegal_promotion",
        "default_forge_path_changed",
        "replacement_level_changed",
        "default_tls_model_changed_on_baseline",
    ] {
        require(
            rejected.contains(kind),
            format!("rejected_evidence_kinds must include {kind}"),
        )?;
    }
    Ok(())
}

#[test]
fn tls_symbol_row_pins_glibc_2_3_version_requirement() -> TestResult {
    let m = load_manifest()?;
    let rows = json_array(&m, "tls_symbol_disposition_rows")?;
    require(!rows.is_empty(), "must have at least one TLS symbol row")?;
    let row = rows
        .iter()
        .find(|r| r.get("symbol").and_then(Value::as_str) == Some(TLS_SYMBOL))
        .ok_or_else(|| format!("missing TLS row for {TLS_SYMBOL}"))?;
    require(
        json_string(row, "version_requirement")? == TLS_VERSION_REQ,
        "version_requirement",
    )?;
    require(
        json_string(row, "baseline_disposition")? == "still_undefined",
        "baseline disposition",
    )?;
    require(
        json_string(row, "claim_status_until_exit")? == "claim_blocked",
        "claim status",
    )
}

#[test]
fn owner_surface_clusters_are_tracked_with_total_thread_local_count() -> TestResult {
    let m = load_manifest()?;
    let rows = json_array(&m, "owner_surface_disposition_rows")?;
    require(
        rows.len() == EXPECTED_OWNER_SURFACE_COUNT,
        format!(
            "expected {EXPECTED_OWNER_SURFACE_COUNT} owner-surface rows, saw {}",
            rows.len()
        ),
    )?;
    let total: u64 = rows
        .iter()
        .filter_map(|r| r.get("thread_local_macro_count").and_then(Value::as_u64))
        .sum();
    let summary = json_field(&m, "summary")?;
    let summary_total = summary
        .get("thread_local_macro_count_in_targeted_clusters")
        .and_then(Value::as_u64)
        .ok_or_else(|| "summary thread_local_macro_count_in_targeted_clusters".to_string())?;
    require(
        total == summary_total,
        format!("summary total ({summary_total}) must equal sum of owner-surface rows ({total})"),
    )?;
    for r in rows {
        require(
            json_string(r, "expected_runtime_replacement_primitive")? == "pthread_setspecific",
            "expected_runtime_replacement_primitive",
        )?;
        require(
            json_string(r, "claim_status_until_exit")? == "claim_blocked",
            "owner-surface claim_status_until_exit",
        )?;
    }
    Ok(())
}

#[test]
fn non_targeted_thread_local_emitters_are_inventory_locked() -> TestResult {
    let root = workspace_root()?;
    let m = load_manifest()?;
    let expected = manifest_non_targeted_tls_sites(&m)?;
    let actual = ungated_thread_local_macro_sites(&root)?;

    require(
        expected.len() == EXPECTED_NON_TARGETED_TLS_EMITTER_COUNT,
        format!(
            "expected {EXPECTED_NON_TARGETED_TLS_EMITTER_COUNT} non-targeted TLS emitters, got {}",
            expected.len()
        ),
    )?;
    require(
        actual == expected,
        format!(
            "ungated ABI thread_local! inventory drifted; expected [{}], actual [{}]",
            format_thread_local_sites(&expected),
            format_thread_local_sites(&actual)
        ),
    )?;

    let summary = json_field(&m, "summary")?;
    require(
        summary
            .get("non_targeted_tls_emitter_count")
            .and_then(Value::as_u64)
            == Some(expected.len() as u64),
        "summary non_targeted_tls_emitter_count",
    )?;
    require(
        summary
            .get("ungated_thread_local_macro_count_in_abi_src")
            .and_then(Value::as_u64)
            == Some(actual.len() as u64),
        "summary ungated_thread_local_macro_count_in_abi_src",
    )?;
    require(
        json_string(summary, "claim_status")? == "claim_blocked",
        "inventory must not promote claim_status",
    )?;
    require(
        !json_bool(summary, "promotion_allowed")?,
        "inventory must not allow promotion",
    )
}

#[test]
fn fixture_stale_source_commit_is_rejected() -> TestResult {
    let mut m = load_manifest()?;
    m.as_object_mut().unwrap().insert(
        "source_commit".to_string(),
        Value::String("not-a-sha".into()),
    );
    let r = evaluate(&m);
    require(
        r.contains(&"stale_source_commit".to_string()),
        format!("must reject stale_source_commit; got {r:?}"),
    )
}

#[test]
fn fixture_missing_tls_symbol_row_is_rejected() -> TestResult {
    let mut m = load_manifest()?;
    m.as_object_mut().unwrap().insert(
        "tls_symbol_disposition_rows".to_string(),
        Value::Array(vec![]),
    );
    let r = evaluate(&m);
    require(
        r.contains(&"missing_tls_symbol_row".to_string()),
        format!("must reject missing_tls_symbol_row; got {r:?}"),
    )
}

#[test]
fn fixture_missing_owner_surface_row_is_rejected() -> TestResult {
    let mut m = load_manifest()?;
    let arr = m
        .as_object_mut()
        .unwrap()
        .get_mut("owner_surface_disposition_rows")
        .unwrap()
        .as_array_mut()
        .unwrap();
    arr.pop();
    let r = evaluate(&m);
    require(
        r.contains(&"missing_owner_surface_row".to_string()),
        format!("must reject missing_owner_surface_row; got {r:?}"),
    )
}

#[test]
fn fixture_missing_non_targeted_tls_inventory_is_rejected() -> TestResult {
    let mut m = load_manifest()?;
    m.as_object_mut()
        .unwrap()
        .remove("non_targeted_tls_emitters");
    let r = evaluate(&m);
    require(
        r.contains(&"missing_non_targeted_tls_emitter_inventory".to_string()),
        format!("must reject missing_non_targeted_tls_emitter_inventory; got {r:?}"),
    )
}

#[test]
fn fixture_hidden_glibc_version_need_is_rejected() -> TestResult {
    let mut m = load_manifest()?;
    let rows = m
        .as_object_mut()
        .unwrap()
        .get_mut("tls_symbol_disposition_rows")
        .unwrap()
        .as_array_mut()
        .unwrap();
    for r in rows.iter_mut() {
        r.as_object_mut().unwrap().insert(
            "version_requirement".to_string(),
            Value::String("hidden".into()),
        );
    }
    let r = evaluate(&m);
    require(
        r.contains(&"hidden_glibc_version_need".to_string()),
        format!("must reject hidden_glibc_version_need; got {r:?}"),
    )
}

#[test]
fn fixture_illegal_promotion_is_rejected() -> TestResult {
    let mut m = load_manifest()?;
    let rows = m
        .as_object_mut()
        .unwrap()
        .get_mut("owner_surface_disposition_rows")
        .unwrap()
        .as_array_mut()
        .unwrap();
    rows[0].as_object_mut().unwrap().insert(
        "claim_status_until_exit".to_string(),
        Value::String("ready".into()),
    );
    let r = evaluate(&m);
    require(
        r.contains(&"illegal_promotion".to_string()),
        format!("must reject illegal_promotion; got {r:?}"),
    )
}

#[test]
fn fixture_baseline_tls_model_change_is_rejected() -> TestResult {
    let mut m = load_manifest()?;
    let lanes = m
        .as_object_mut()
        .unwrap()
        .get_mut("experiment_lanes")
        .unwrap()
        .as_array_mut()
        .unwrap();
    for l in lanes.iter_mut() {
        if l.get("lane_id").and_then(Value::as_str) == Some(BASELINE_LANE) {
            l.as_object_mut()
                .unwrap()
                .insert("tls_model".to_string(), Value::String("local-exec".into()));
            break;
        }
    }
    let r = evaluate(&m);
    require(
        r.contains(&"default_tls_model_changed_on_baseline".to_string()),
        format!("must reject default_tls_model_changed_on_baseline; got {r:?}"),
    )
}

#[test]
fn fixture_default_forge_unlock_is_rejected() -> TestResult {
    let mut m = load_manifest()?;
    let lanes = m
        .as_object_mut()
        .unwrap()
        .get_mut("experiment_lanes")
        .unwrap()
        .as_array_mut()
        .unwrap();
    for l in lanes.iter_mut() {
        if l.get("lane_id").and_then(Value::as_str) == Some(BASELINE_LANE) {
            l.as_object_mut().unwrap().insert(
                "must_not_change_default_tls_model".to_string(),
                Value::Bool(false),
            );
            break;
        }
    }
    let r = evaluate(&m);
    require(
        r.contains(&"default_forge_path_changed".to_string()),
        format!("must reject default_forge_path_changed; got {r:?}"),
    )
}

#[test]
fn summary_anchors_to_lane_and_cluster_counts() -> TestResult {
    let m = load_manifest()?;
    let summary = json_field(&m, "summary")?;
    require(
        summary
            .get("tls_blocker_symbol_count_baseline")
            .and_then(Value::as_u64)
            == Some(1),
        "summary baseline TLS blocker count",
    )?;
    require(
        summary
            .get("tls_blocker_symbol_count_owned_tls_cache_when_complete")
            .and_then(Value::as_u64)
            == Some(0),
        "summary owned-tls when complete",
    )?;
    require(
        summary
            .get("owner_surface_cluster_count")
            .and_then(Value::as_u64)
            == Some(EXPECTED_OWNER_SURFACE_COUNT as u64),
        "summary owner_surface_cluster_count",
    )?;
    require(
        summary
            .get("non_targeted_tls_emitter_count")
            .and_then(Value::as_u64)
            == Some(EXPECTED_NON_TARGETED_TLS_EMITTER_COUNT as u64),
        "summary non_targeted_tls_emitter_count",
    )?;
    require(
        json_string(summary, "claim_status")? == "claim_blocked",
        "summary claim_status",
    )?;
    require(
        !json_bool(summary, "promotion_allowed")?,
        "summary promotion_allowed must be false",
    )
}

#[test]
fn owned_tls_cache_feature_gate_is_wired_but_not_promoted() -> TestResult {
    let root = workspace_root()?;
    let m = load_manifest()?;
    let summary = json_field(&m, "summary")?;
    require(
        json_string(summary, "owned_tls_cache_feature_gate_status")? == "wired",
        "owned_tls_cache feature gate status",
    )?;
    let substituted = summary
        .get("owned_tls_cache_substituted_macro_count")
        .and_then(Value::as_u64)
        .ok_or_else(|| "summary owned_tls_cache_substituted_macro_count".to_string())?;
    let remaining = summary
        .get("owned_tls_cache_remaining_macro_count")
        .and_then(Value::as_u64)
        .ok_or_else(|| "summary owned_tls_cache_remaining_macro_count".to_string())?;
    let total = summary
        .get("thread_local_macro_count_in_targeted_clusters")
        .and_then(Value::as_u64)
        .ok_or_else(|| "summary thread_local_macro_count_in_targeted_clusters".to_string())?;
    require(
        substituted == 84,
        "owned-tls slices substitute crypt/gensalt, four NIS helper macros, resolver backend caches, resolver nsaddr, resolver h_errno state, resolver hostent/servent/protoent storage, resolver printable-DNS helper buffers, resolver hostalias/LOC/symbol fallback buffers, getmntent, getpass, cuserid, C++ EH globals, gethostbyname2 scratch state, fgetspent shadow entry state, RPC rpcent state, utmp state, pututxline return buffer, NSS systemd block flag, fstab state, ttyent state, getdate tm, services iterator state, networks iterator state, protocols iterator state, hosts iterator state, netgroup iterator state, alias iterator state, string ABI recursion/scratch state, RPC ABI scratch/state slots, glibc-internal cleanup/resolver/shadow state, the core errno slot, dlfcn dlerror state, dirent readdir entry buffer, ctype table-location slots, runtime-policy mode/trace/contract state, startup thread-at-exit/reentry state, signal critical/deferred controller state, stdio tmpnam/fgetln buffers, wchar c16 surrogate/fgetwln buffers, stdlib getusershell/qecvt/qfcvt scratch state, group ABI reentrant storage, passwd/gshadow/shadow ABI non-reentrant storage, pthread control state, inet_ntoa static buffer storage, and time ABI non-reentrant static buffers",
    )?;
    require(
        substituted + remaining == total,
        "owned-tls substituted plus remaining count",
    )?;
    require(
        json_string(summary, "claim_status")? == "claim_blocked",
        "summary remains claim_blocked",
    )?;
    require(
        !json_bool(summary, "promotion_allowed")?,
        "owned-tls slice must not promote replacement claims",
    )?;

    let cargo_toml = std::fs::read_to_string(abi_cargo_toml_path(&root))
        .map_err(|err| format!("read frankenlibc-abi Cargo.toml: {err}"))?;
    require(
        cargo_toml
            .lines()
            .any(|line| line.trim() == "owned-tls-cache = []"),
        "frankenlibc-abi Cargo.toml must define owned-tls-cache feature",
    )?;

    let unistd = std::fs::read_to_string(abi_unistd_path(&root))
        .map_err(|err| format!("read unistd_abi.rs: {err}"))?;
    require(
        unistd.contains("CRYPT_BUF_OWNED_TLS")
            && unistd.contains("GENSALT_OWNED_TLS")
            && unistd.contains("NIS_SPERRNO_OWNED_TLS")
            && unistd.contains("NIS_DOMAIN_OF_OWNED_TLS")
            && unistd.contains("NIS_LEAF_OF_OWNED_TLS")
            && unistd.contains("NIS_NAME_OF_OWNED_TLS")
            && unistd.contains("RES_NSADDR_OWNED_TLS")
            && unistd.contains("GETMNTENT_BUF_OWNED_TLS")
            && unistd.contains("GETPASS_BUF_OWNED_TLS")
            && unistd.contains("CUSERID_BUF_OWNED_TLS")
            && unistd.contains("CXA_EH_GLOBALS_OWNED_TLS")
            && unistd.contains("GETHOSTBYNAME2_OWNED_TLS")
            && unistd.contains("FGETSPENT_STATE_OWNED_TLS")
            && unistd.contains("RPC_ENTRY_OWNED_TLS")
            && unistd.contains("UTMP_STATE_OWNED_TLS")
            && unistd.contains("UTMPX_BUF_OWNED_TLS")
            && unistd.contains("NSS_SYSTEMD_BLOCK_FLAG_OWNED_TLS")
            && unistd.contains("FSTAB_STATE_OWNED_TLS")
            && unistd.contains("TTYENT_STATE_OWNED_TLS")
            && unistd.contains("GETDATE_TM_OWNED_TLS")
            && unistd.contains("SERV_ITER_OWNED_TLS")
            && unistd.contains("NET_ITER_OWNED_TLS")
            && unistd.contains("PROTO_ITER_OWNED_TLS")
            && unistd.contains("HOST_ITER_OWNED_TLS")
            && unistd.contains("NETGROUP_ITER_OWNED_TLS")
            && unistd.contains("ALIAS_ITER_OWNED_TLS")
            && unistd.contains("crate::owned_tls_cache::OwnedTlsCache"),
        "unistd ABI must route the crypt/gensalt, NIS helper, resolver nsaddr, getmntent, getpass, cuserid, C++ EH globals, gethostbyname2 scratch state, fgetspent shadow entry state, RPC rpcent state, utmp-state, pututxline return-buffer, NSS systemd block-flag, fstab-state, ttyent-state, getdate-tm, services-iterator, networks-iterator, protocols-iterator, hosts-iterator, netgroup-iterator, and alias-iterator slices through owned TLS cache",
    )?;

    let resolv = std::fs::read_to_string(abi_resolv_path(&root))
        .map_err(|err| format!("read resolv_abi.rs: {err}"))?;
    require(
        resolv.contains("HOSTS_BACKEND_OWNED_TLS")
            && resolv.contains("SERVICES_BACKEND_OWNED_TLS")
            && resolv.contains("PROC_NET_ROUTE_OWNED_TLS")
            && resolv.contains("PROC_NET_IF_INET6_OWNED_TLS")
            && resolv.contains("H_ERRNO_OWNED_TLS")
            && resolv.contains("GETHOSTBYNAME_OWNED_TLS")
            && resolv.contains("SERVENT_OWNED_TLS")
            && resolv.contains("PROTOENT_OWNED_TLS")
            && resolv.contains("P_FALLBACK_BUF_OWNED_TLS")
            && resolv.contains("P_OPTION_BUF_OWNED_TLS")
            && resolv.contains("SECSTODATE_BUF_OWNED_TLS")
            && resolv.contains("P_TIME_BUF_OWNED_TLS")
            && resolv.contains("HOSTALIAS_BUF_OWNED_TLS")
            && resolv.contains("LOC_NTOA_BUF_OWNED_TLS")
            && resolv.contains("SYM_NTOP_BUF_OWNED_TLS")
            && resolv.contains("SYM_NTOS_BUF_OWNED_TLS")
            && resolv.contains("crate::owned_tls_cache::OwnedTlsCache"),
        "resolver ABI must route backend caches, h_errno state, hostent/servent/protoent storage, printable-DNS helper buffers, and fixed fallback return buffers through owned TLS cache",
    )?;

    let string = std::fs::read_to_string(abi_string_path(&root))
        .map_err(|err| format!("read string_abi.rs: {err}"))?;
    require(
        string.contains("STRING_MEMBRANE_DEPTH_OWNED_TLS")
            && string.contains("STRTOK_SAVE_OWNED_TLS")
            && string.contains("STRERROR_BUF_OWNED_TLS")
            && string.contains("STRSIGNAL_BUF_OWNED_TLS")
            && string.contains("crate::owned_tls_cache::OwnedTlsCache"),
        "string ABI must route membrane recursion depth, strtok save pointer, strerror buffer, and strsignal buffer through owned TLS cache",
    )?;

    let rpc = std::fs::read_to_string(abi_rpc_path(&root))
        .map_err(|err| format!("read rpc_abi.rs: {err}"))?;
    require(
        rpc.contains("XDR_REFERENCE_DEPTH_OWNED_TLS")
            && rpc.contains("SPERRNO_BUF_OWNED_TLS")
            && rpc.contains("SPCREATEERR_BUF_OWNED_TLS")
            && rpc.contains("RPC_CREATEERR_OWNED_TLS")
            && rpc.contains("RPC_SVC_FDSET_OWNED_TLS")
            && rpc.contains("RPC_SVC_MAX_POLLFD_OWNED_TLS")
            && rpc.contains("RPC_SVC_POLLFD_OWNED_TLS")
            && rpc.contains("crate::owned_tls_cache::OwnedTlsCache"),
        "RPC ABI must route xdr recursion depth, clnt scratch buffers, rpc_createerr, svc_fdset, svc_max_pollfd, and svc_pollfd through owned TLS cache",
    )?;

    let glibc_internal = std::fs::read_to_string(abi_glibc_internal_path(&root))
        .map_err(|err| format!("read glibc_internal_abi.rs: {err}"))?;
    require(
        glibc_internal.contains("PTHREAD_CLEANUP_HEAD_OWNED_TLS")
            && glibc_internal.contains("RES_STATE_OWNED_TLS")
            && glibc_internal.contains("RCMD_ERRSTR_OWNED_TLS")
            && glibc_internal.contains("SGETSPENT_OWNED_TLS")
            && glibc_internal.contains("GLIBC_INTERNAL_H_ERRNO_OWNED_TLS")
            && glibc_internal.contains("RESOLV_CONTEXT_HEAD_OWNED_TLS")
            && glibc_internal.contains("crate::owned_tls_cache::OwnedTlsCache"),
        "glibc-internal ABI must route pthread cleanup head, resolver state, rcmd errstr, sgetspent scratch, h_errno, and resolver context head through owned TLS cache",
    )?;

    let errno = std::fs::read_to_string(abi_errno_path(&root))
        .map_err(|err| format!("read errno_abi.rs: {err}"))?;
    require(
        errno.contains("ERRNO_OWNED_TLS")
            && errno.contains("crate::owned_tls_cache::OwnedTlsCache"),
        "errno ABI must route __errno_location through owned TLS cache",
    )?;

    let dlfcn = std::fs::read_to_string(abi_dlfcn_path(&root))
        .map_err(|err| format!("read dlfcn_abi.rs: {err}"))?;
    require(
        dlfcn.contains("DLERROR_OWNED_TLS")
            && dlfcn.contains("DlErrorState")
            && dlfcn.contains("crate::owned_tls_cache::OwnedTlsCache"),
        "dlfcn ABI must route dlerror pending/stable state through owned TLS cache",
    )?;

    let dirent = std::fs::read_to_string(abi_dirent_path(&root))
        .map_err(|err| format!("read dirent_abi.rs: {err}"))?;
    require(
        dirent.contains("READDIR_ENTRY_OWNED_TLS")
            && dirent.contains("crate::owned_tls_cache::OwnedTlsCache"),
        "dirent ABI must route readdir static entry buffer through owned TLS cache",
    )?;

    let ctype = std::fs::read_to_string(abi_ctype_path(&root))
        .map_err(|err| format!("read ctype_abi.rs: {err}"))?;
    require(
        ctype.contains("CTYPE_LOC_OWNED_TLS")
            && ctype.contains("CtypeLocPtrs")
            && ctype.contains("crate::owned_tls_cache::OwnedTlsCache"),
        "ctype ABI must route table-location pointer slots through owned TLS cache",
    )?;

    let runtime_policy = std::fs::read_to_string(abi_runtime_policy_path(&root))
        .map_err(|err| format!("read runtime_policy.rs: {err}"))?;
    require(
        runtime_policy.contains("RUNTIME_POLICY_OWNED_TLS")
            && runtime_policy.contains("RuntimePolicyTls")
            && runtime_policy.contains("with_mode_cache")
            && runtime_policy.contains("with_decision_contract_machine")
            && runtime_policy.contains("crate::owned_tls_cache::OwnedTlsCache"),
        "runtime policy must route mode, trace, explainability, reentry, and contract state through owned TLS cache",
    )?;

    let startup = std::fs::read_to_string(abi_startup_path(&root))
        .map_err(|err| format!("read startup_abi.rs: {err}"))?;
    require(
        startup.contains("STARTUP_OWNED_TLS")
            && startup.contains("StartupTls")
            && startup.contains("enter_tls_atexit_reentry")
            && startup.contains("enter_host_cxa_lookup_reentry")
            && startup.contains("take_tls_atexit_entries")
            && startup.contains("crate::owned_tls_cache::OwnedTlsCache"),
        "startup ABI must route thread-at-exit list, capture flag, and reentry guards through owned TLS cache",
    )?;

    let signal = std::fs::read_to_string(abi_signal_path(&root))
        .map_err(|err| format!("read signal_abi.rs: {err}"))?;
    require(
        signal.contains("SIGNAL_OWNED_TLS")
            && signal.contains("SignalTls")
            && signal.contains("with_signal_critical_depth")
            && signal.contains("with_deferred_signals")
            && signal.contains("with_signal_hji_controller")
            && signal.contains("crate::owned_tls_cache::OwnedTlsCache"),
        "signal ABI must route critical-section, classification, deferred-signal, and HJI controller state through owned TLS cache",
    )?;

    let stdio = std::fs::read_to_string(abi_stdio_path(&root))
        .map_err(|err| format!("read stdio_abi.rs: {err}"))?;
    require(
        stdio.contains("TMPNAM_BUF_OWNED_TLS")
            && stdio.contains("FGETLN_BUFFER_OWNED_TLS")
            && stdio.contains("crate::owned_tls_cache::OwnedTlsCache"),
        "stdio ABI must route tmpnam static buffer and fgetln line buffer through owned TLS cache",
    )?;

    let wchar = std::fs::read_to_string(abi_wchar_path(&root))
        .map_err(|err| format!("read wchar_abi.rs: {err}"))?;
    require(
        wchar.contains("C16_SURROGATE_OWNED_TLS")
            && wchar.contains("FGETWLN_BUFFER_OWNED_TLS")
            && wchar.contains("crate::owned_tls_cache::OwnedTlsCache"),
        "wchar ABI must route C11 char16 surrogate state and fgetwln line buffer through owned TLS cache",
    )?;

    let stdlib = std::fs::read_to_string(abi_stdlib_path(&root))
        .map_err(|err| format!("read stdlib_abi.rs: {err}"))?;
    require(
        stdlib.contains("STDLIB_OWNED_TLS")
            && stdlib.contains("StdlibTls")
            && stdlib.contains("with_shell_state")
            && stdlib.contains("with_qecvt_buf")
            && stdlib.contains("with_qfcvt_buf")
            && stdlib.contains("crate::owned_tls_cache::OwnedTlsCache"),
        "stdlib ABI must route getusershell iterator/cache and qecvt/qfcvt buffers through owned TLS cache",
    )?;

    let grp = std::fs::read_to_string(abi_grp_path(&root))
        .map_err(|err| format!("read grp_abi.rs: {err}"))?;
    require(
        grp.contains("GRP_OWNED_TLS")
            && grp.contains("with_grp_storage")
            && grp.contains("unsafe impl Send for GrpStorage")
            && grp.contains("crate::owned_tls_cache::OwnedTlsCache"),
        "group ABI must route non-reentrant group storage through owned TLS cache",
    )?;

    let pwd = std::fs::read_to_string(abi_pwd_path(&root))
        .map_err(|err| format!("read pwd_abi.rs: {err}"))?;
    require(
        pwd.contains("PWD_OWNED_TLS")
            && pwd.contains("GSHADOW_OWNED_TLS")
            && pwd.contains("SHADOW_OWNED_TLS")
            && pwd.contains("with_pwd_storage")
            && pwd.contains("with_shadow_storage")
            && pwd.contains("unsafe impl Send for PwdStorage")
            && pwd.contains("unsafe impl Send for ShadowTlsStorage")
            && pwd.contains("crate::owned_tls_cache::OwnedTlsCache"),
        "passwd ABI must route non-reentrant passwd, gshadow, and shadow storage through owned TLS cache",
    )?;

    let pthread = std::fs::read_to_string(abi_pthread_path(&root))
        .map_err(|err| format!("read pthread_abi.rs: {err}"))?;
    require(
        pthread.contains("PTHREAD_OWNED_TLS")
            && pthread.contains("PthreadTlsState")
            && pthread.contains("with_pthread_tls")
            && pthread.contains("try_with_pthread_tls")
            && pthread.contains("crate::owned_tls_cache::OwnedTlsCache"),
        "pthread ABI must route policy, cancellation, backend, and self-cache state through owned TLS cache",
    )?;

    let inet = std::fs::read_to_string(abi_inet_path(&root))
        .map_err(|err| format!("read inet_abi.rs: {err}"))?;
    require(
        inet.contains("INET_NTOA_BUF_OWNED_TLS")
            && inet.contains("with_inet_ntoa_buffer")
            && inet.contains("crate::owned_tls_cache::OwnedTlsCache"),
        "inet ABI must route inet_ntoa static buffer storage through owned TLS cache",
    )?;

    let time = std::fs::read_to_string(abi_time_path(&root))
        .map_err(|err| format!("read time_abi.rs: {err}"))?;
    require(
        time.contains("TIME_OWNED_TLS")
            && time.contains("TimeTls")
            && time.contains("with_gmtime_buf")
            && time.contains("with_localtime_buf")
            && time.contains("with_asctime_buf")
            && time.contains("with_ctime_buf")
            && time.contains("crate::owned_tls_cache::OwnedTlsCache"),
        "time ABI must route gmtime/localtime/asctime/ctime static buffers through owned TLS cache",
    )
}
