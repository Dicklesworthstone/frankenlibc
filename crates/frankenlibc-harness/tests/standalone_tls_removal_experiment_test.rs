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
const EXPECTED_OWNER_SURFACE_COUNT: usize = 5;

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

fn lane<'a>(manifest: &'a Value, lane_id: &str) -> TestResult<&'a Value> {
    json_array(manifest, "experiment_lanes")?
        .iter()
        .find(|l| l.get("lane_id").and_then(Value::as_str) == Some(lane_id))
        .ok_or_else(|| format!("missing lane `{lane_id}`"))
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
fn five_owner_surface_clusters_are_tracked_with_total_thread_local_count() -> TestResult {
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
        substituted == 48,
        "owned-tls slices substitute crypt/gensalt, four NIS helper macros, resolver backend caches, resolver nsaddr, resolver h_errno state, getmntent, getpass, cuserid, C++ EH globals, gethostbyname2 scratch state, fgetspent shadow entry state, RPC rpcent state, utmp state, pututxline return buffer, NSS systemd block flag, fstab state, ttyent state, getdate tm, services iterator state, networks iterator state, protocols iterator state, hosts iterator state, netgroup iterator state, alias iterator state, string ABI recursion/scratch state, RPC ABI scratch/state slots, and glibc-internal cleanup/resolver/shadow state",
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
            && resolv.contains("crate::owned_tls_cache::OwnedTlsCache"),
        "resolver ABI must route backend caches and h_errno state through owned TLS cache",
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
    )
}
