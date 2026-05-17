//! Conformance gate for the owned-unwind experiment manifest (bd-juvqm.4).
//!
//! Validates the schema, lane invariants, and per-symbol disposition rows of
//! `tests/conformance/standalone_owned_unwind_experiment.v1.json`. Mutation
//! tests prove the gate fails closed on:
//!   * stale source_commit
//!   * missing symbol row (a baseline-undefined symbol must always be tracked)
//!   * illegal promotion (claim_status flipped to ready while a row is unresolved)
//!   * blocker regression (panic-abort row added an `_Unwind_*` not in the baseline)
//!   * default forge path / replacement level change attempted
//!
//! No live build is required — this is the contract the live experiment must
//! eventually satisfy. The acceptance bar is `report_only` until every owned
//! substitute reaches `nm_evidence_passed`.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

const BASELINE_LANE: &str = "baseline-release-standalone";
const PANIC_ABORT_LANE: &str = "panic-abort-compiler-runtime-minimized";
const OWNED_UNWIND_LANE: &str = "owned-unwind-stub-experiment";
const EXPECTED_BASELINE_SYMBOL_COUNT: usize = 12;
const EXPECTED_PANIC_ABORT_SYMBOL_COUNT: usize = 10;

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
        .join("standalone_owned_unwind_experiment.v1.json")
}

fn abi_crate_path(root: &Path, rel: &str) -> PathBuf {
    root.join("crates").join("frankenlibc-abi").join(rel)
}

fn load_manifest() -> TestResult<Value> {
    let root = workspace_root()?;
    let path = manifest_path(&root);
    let content = std::fs::read_to_string(&path).map_err(|err| format!("read {path:?}: {err}"))?;
    serde_json::from_str(&content).map_err(|err| format!("parse {path:?}: {err}"))
}

fn load_json_file(path: &Path) -> TestResult<Value> {
    let content = std::fs::read_to_string(path).map_err(|err| format!("read {path:?}: {err}"))?;
    serde_json::from_str(&content).map_err(|err| format!("parse {path:?}: {err}"))
}

fn unique_temp_dir(label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| format!("system clock before unix epoch: {err}"))?
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "frankenlibc-standalone-owned-unwind-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).map_err(|err| format!("create {}: {err}", dir.display()))?;
    Ok(dir)
}

fn write_executable(path: &Path, content: &str) -> TestResult {
    std::fs::write(path, content).map_err(|err| format!("write {}: {err}", path.display()))?;
    let mut permissions = std::fs::metadata(path)
        .map_err(|err| format!("stat {}: {err}", path.display()))?
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(path, permissions)
        .map_err(|err| format!("chmod {}: {err}", path.display()))
}

fn fake_rch_local_fallback_path(temp: &Path) -> TestResult<OsString> {
    let fake_bin = temp.join("fake-rch-local-bin");
    std::fs::create_dir_all(&fake_bin).map_err(|err| format!("{}: {err}", fake_bin.display()))?;
    write_executable(
        &fake_bin.join("rch"),
        r#"#!/bin/sh
echo "[RCH] local (test-injected fallback)" >&2
exit 0
"#,
    )?;
    let mut path = OsString::from(fake_bin);
    path.push(":");
    path.push(std::env::var_os("PATH").unwrap_or_default());
    Ok(path)
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

/// Pure validator. Returns the list of rejection codes (per
/// report_policy.rejected_evidence_kinds) that fire on this manifest.
fn evaluate(manifest: &Value) -> Vec<String> {
    let mut rejections: Vec<String> = Vec::new();

    // schema_version must be present and equal to "v1".
    if manifest.get("schema_version").and_then(Value::as_str) != Some("v1") {
        rejections.push("missing_or_invalid_schema_version".to_string());
    }
    // bead must be present and equal to "bd-juvqm.4".
    if manifest.get("bead").and_then(Value::as_str) != Some("bd-juvqm.4") {
        rejections.push("missing_or_invalid_bead".to_string());
    }
    // source_commit must be a 40-char hex SHA or "current".
    let source_commit = manifest
        .get("source_commit")
        .and_then(Value::as_str)
        .unwrap_or("");
    let is_sha = source_commit.len() == 40 && source_commit.chars().all(|c| c.is_ascii_hexdigit());
    if !is_sha && source_commit != "current" {
        rejections.push("stale_source_commit".to_string());
    }
    // report_policy must remain locked down.
    let policy = manifest
        .get("report_policy")
        .cloned()
        .unwrap_or(Value::Null);
    let must_be_false = [
        "promotion_allowed",
        "replacement_level_change_allowed",
        "default_forge_path_change_allowed",
        "default_build_profile_change_allowed",
        "panic_strategy_change_allowed_on_baseline",
    ];
    for f in must_be_false {
        if policy.get(f).and_then(Value::as_bool) != Some(false) {
            rejections.push(format!("policy_{f}_must_be_false"));
        }
    }
    if policy.get("report_only").and_then(Value::as_bool) != Some(true) {
        rejections.push("report_only_must_be_true".to_string());
    }
    if policy
        .get("claim_status_until_all_symbols_exit")
        .and_then(Value::as_str)
        != Some("claim_blocked")
    {
        rejections.push("claim_status_until_all_symbols_exit_must_be_claim_blocked".to_string());
    }

    // Symbol disposition rows must cover every baseline-undefined symbol.
    let rows = manifest
        .get("symbol_disposition_rows")
        .and_then(Value::as_array);
    let Some(rows) = rows else {
        rejections.push("missing_symbol_row".to_string());
        return rejections;
    };

    let baseline_undefined: BTreeSet<String> = rows
        .iter()
        .filter(|r| {
            r.get("baseline_disposition").and_then(Value::as_str) == Some("still_undefined")
        })
        .filter_map(|r| r.get("symbol").and_then(Value::as_str).map(str::to_owned))
        .collect();
    if baseline_undefined.len() != EXPECTED_BASELINE_SYMBOL_COUNT {
        rejections.push("missing_symbol_row".to_string());
    }

    // panic-abort lane: row count consistency. The manifest claims 10 still
    // undefined; if any row's panic_abort_disposition flips back to "still_undefined"
    // for a symbol previously marked removed_by_panic_abort, that's a regression.
    let panic_abort_undefined_count = rows
        .iter()
        .filter(|r| {
            r.get("panic_abort_disposition").and_then(Value::as_str) == Some("still_undefined")
        })
        .count();
    if panic_abort_undefined_count != EXPECTED_PANIC_ABORT_SYMBOL_COUNT {
        rejections.push("blocker_regression".to_string());
    }

    // Promotion guard: claim_status_until_exit may not be "ready" while
    // owned_surface_status is "design_only".
    for r in rows {
        let claim = r
            .get("claim_status_until_exit")
            .and_then(Value::as_str)
            .unwrap_or("");
        let surface = r
            .get("owned_surface_status")
            .and_then(Value::as_str)
            .unwrap_or("");
        if claim == "ready" && surface != "nm_evidence_passed" {
            rejections.push("illegal_promotion".to_string());
            break;
        }
    }

    // Lane geometry: baseline must keep panic_strategy=implicit-unwind so the
    // contract cannot silently swap the default profile.
    if let Ok(b) = lane(manifest, BASELINE_LANE) {
        if b.get("panic_strategy").and_then(Value::as_str) != Some("implicit-unwind") {
            rejections.push("panic_strategy_changed_on_baseline".to_string());
        }
        if b.get("must_not_change_default_profile")
            .and_then(Value::as_bool)
            != Some(true)
        {
            rejections.push("default_forge_path_changed".to_string());
        }
    } else {
        rejections.push("missing_baseline_lane".to_string());
    }

    rejections
}

#[test]
fn manifest_loads_and_passes_canonical_validation() -> TestResult {
    let m = load_manifest()?;
    let rejections = evaluate(&m);
    require(
        rejections.is_empty(),
        format!("canonical manifest must validate cleanly; got {rejections:?}"),
    )
}

#[test]
fn manifest_id_and_bead_anchor_to_juvqm4() -> TestResult {
    let m = load_manifest()?;
    require(
        json_string(&m, "manifest_id")? == "standalone-owned-unwind-experiment",
        "manifest_id must be standalone-owned-unwind-experiment",
    )?;
    require(
        json_string(&m, "bead")? == "bd-juvqm.4",
        "bead must be bd-juvqm.4",
    )
}

#[test]
fn three_lanes_are_present_with_correct_roles() -> TestResult {
    let m = load_manifest()?;
    let lanes = json_array(&m, "experiment_lanes")?;
    require(lanes.len() == 3, "must have exactly 3 lanes")?;

    let baseline = lane(&m, BASELINE_LANE)?;
    require(
        json_string(baseline, "role")? == "baseline",
        "baseline role",
    )?;
    require(
        json_string(baseline, "panic_strategy")? == "implicit-unwind",
        "baseline panic_strategy",
    )?;

    let panic_abort = lane(&m, PANIC_ABORT_LANE)?;
    require(
        json_string(panic_abort, "role")? == "comparison",
        "panic-abort role",
    )?;
    require(
        json_string(panic_abort, "panic_strategy")? == "abort",
        "panic-abort panic_strategy",
    )?;

    let owned = lane(&m, OWNED_UNWIND_LANE)?;
    require(
        json_string(owned, "role")? == "experiment",
        "owned-unwind role",
    )?;
    require(
        json_string(owned, "panic_strategy")? == "abort",
        "owned-unwind panic_strategy",
    )?;
    require(
        json_string(owned, "build_status_until_owned_substitute_complete")? == "pass",
        "owned-unwind source gate and release lane must pass before evidence rows exit",
    )
}

#[test]
fn owned_unwind_stub_feature_is_wired_to_abi_symbols() -> TestResult {
    let root = workspace_root()?;
    let cargo_toml = std::fs::read_to_string(abi_crate_path(&root, "Cargo.toml"))
        .map_err(|err| format!("read frankenlibc-abi Cargo.toml: {err}"))?;
    require(
        cargo_toml.contains("owned-unwind-stub = []"),
        "frankenlibc-abi must expose owned-unwind-stub feature",
    )?;

    let lib_rs = std::fs::read_to_string(abi_crate_path(&root, "src/lib.rs"))
        .map_err(|err| format!("read frankenlibc-abi lib.rs: {err}"))?;
    require(
        lib_rs.contains("feature = \"standalone\", feature = \"owned-unwind-stub\""),
        "owned_unwind_abi module must be gated by standalone and owned-unwind-stub",
    )?;
    require(
        lib_rs.contains("pub mod owned_unwind_abi;"),
        "owned_unwind_abi module must be wired into the ABI crate",
    )?;

    let owned = std::fs::read_to_string(abi_crate_path(&root, "src/owned_unwind_abi.rs"))
        .map_err(|err| format!("read owned_unwind_abi.rs: {err}"))?;
    for symbol in [
        "_Unwind_Backtrace",
        "_Unwind_GetDataRelBase",
        "_Unwind_GetIP",
        "_Unwind_GetIPInfo",
        "_Unwind_GetLanguageSpecificData",
        "_Unwind_GetRegionStart",
        "_Unwind_GetTextRelBase",
        "_Unwind_Resume",
        "_Unwind_SetGR",
        "_Unwind_SetIP",
    ] {
        require(
            owned.contains(&format!("fn {symbol}")),
            format!("owned unwind stub must define {symbol}"),
        )?;
    }
    Ok(())
}

#[test]
fn report_policy_locks_default_forge_and_replacement_level() -> TestResult {
    let m = load_manifest()?;
    let policy = json_field(&m, "report_policy")?;
    require(
        json_bool(policy, "report_only")?,
        "report_only must be true",
    )?;
    for f in [
        "promotion_allowed",
        "replacement_level_change_allowed",
        "default_forge_path_change_allowed",
        "default_build_profile_change_allowed",
        "panic_strategy_change_allowed_on_baseline",
    ] {
        require(!json_bool(policy, f)?, format!("{f} must be false"))?;
    }
    require(
        json_string(policy, "claim_status_until_all_symbols_exit")? == "claim_blocked",
        "claim_status_until_all_symbols_exit must be claim_blocked",
    )?;
    let rejected: BTreeSet<String> = json_array(policy, "rejected_evidence_kinds")?
        .iter()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect();
    for kind in [
        "missing_symbol_row",
        "blocker_regression",
        "stale_source_commit",
        "illegal_promotion",
        "default_forge_path_changed",
        "replacement_level_changed",
        "panic_strategy_changed_on_baseline",
    ] {
        require(
            rejected.contains(kind),
            format!("rejected_evidence_kinds must include {kind}"),
        )?;
    }
    Ok(())
}

#[test]
fn baseline_undefined_symbol_count_is_twelve() -> TestResult {
    let m = load_manifest()?;
    let rows = json_array(&m, "symbol_disposition_rows")?;
    let baseline_undefined = rows
        .iter()
        .filter(|r| {
            r.get("baseline_disposition").and_then(Value::as_str) == Some("still_undefined")
        })
        .count();
    require(
        baseline_undefined == EXPECTED_BASELINE_SYMBOL_COUNT,
        format!(
            "baseline must keep all {EXPECTED_BASELINE_SYMBOL_COUNT} \
            _Unwind_* symbols undefined; saw {baseline_undefined}"
        ),
    )
}

#[test]
fn panic_abort_lane_removes_two_unwind_symbols() -> TestResult {
    let m = load_manifest()?;
    let rows = json_array(&m, "symbol_disposition_rows")?;
    let removed = rows
        .iter()
        .filter(|r| {
            r.get("panic_abort_disposition").and_then(Value::as_str)
                == Some("removed_by_panic_abort")
        })
        .count();
    require(
        removed == 2,
        format!("expected 2 panic-abort removals, got {removed}"),
    )?;
    let still = rows
        .iter()
        .filter(|r| {
            r.get("panic_abort_disposition").and_then(Value::as_str) == Some("still_undefined")
        })
        .count();
    require(
        still == EXPECTED_PANIC_ABORT_SYMBOL_COUNT,
        format!(
            "expected {EXPECTED_PANIC_ABORT_SYMBOL_COUNT} symbols still undefined under \
             panic-abort, saw {still}"
        ),
    )
}

#[test]
fn every_owned_substitute_row_has_nm_evidence() -> TestResult {
    let m = load_manifest()?;
    let rows = json_array(&m, "symbol_disposition_rows")?;
    let mut substitute_count = 0;
    for r in rows {
        let owned = r
            .get("owned_unwind_disposition")
            .and_then(Value::as_str)
            .unwrap_or("");
        if owned == "owned_substitute" {
            substitute_count += 1;
            let surface = r
                .get("owned_surface_status")
                .and_then(Value::as_str)
                .unwrap_or("");
            let claim = r
                .get("claim_status_until_exit")
                .and_then(Value::as_str)
                .unwrap_or("");
            require(
                surface == "nm_evidence_passed",
                format!(
                    "row {:?}: owned_substitute must have nm_evidence_passed, saw {surface}",
                    r.get("symbol")
                ),
            )?;
            require(
                claim == "exit_evidence_passed",
                format!(
                    "row {:?}: owned_substitute must have exit_evidence_passed, saw {claim}",
                    r.get("symbol")
                ),
            )?;
        }
    }
    require(
        substitute_count == 12,
        "owned-unwind lane must own all 12 _Unwind_* rows",
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
fn fixture_missing_symbol_row_is_rejected() -> TestResult {
    let mut m = load_manifest()?;
    let rows = m
        .as_object_mut()
        .unwrap()
        .get_mut("symbol_disposition_rows")
        .unwrap()
        .as_array_mut()
        .unwrap();
    // Remove the first row — baseline_undefined count drops to 11.
    rows.remove(0);
    let r = evaluate(&m);
    require(
        r.contains(&"missing_symbol_row".to_string()),
        format!("must reject missing_symbol_row; got {r:?}"),
    )
}

#[test]
fn fixture_blocker_regression_is_rejected() -> TestResult {
    let mut m = load_manifest()?;
    // Flip a previously removed_by_panic_abort row back to still_undefined —
    // that's a regression.
    let rows = m
        .as_object_mut()
        .unwrap()
        .get_mut("symbol_disposition_rows")
        .unwrap()
        .as_array_mut()
        .unwrap();
    for r in rows.iter_mut() {
        if r.get("panic_abort_disposition").and_then(Value::as_str)
            == Some("removed_by_panic_abort")
        {
            r.as_object_mut().unwrap().insert(
                "panic_abort_disposition".to_string(),
                Value::String("still_undefined".into()),
            );
            break;
        }
    }
    let r = evaluate(&m);
    require(
        r.contains(&"blocker_regression".to_string()),
        format!("must reject blocker_regression; got {r:?}"),
    )
}

#[test]
fn fixture_illegal_promotion_is_rejected() -> TestResult {
    let mut m = load_manifest()?;
    // Flip an evidence-passed row back to design_only while claiming ready.
    let rows = m
        .as_object_mut()
        .unwrap()
        .get_mut("symbol_disposition_rows")
        .unwrap()
        .as_array_mut()
        .unwrap();
    let row = rows.first_mut().ok_or("missing first symbol row")?;
    row.as_object_mut().unwrap().insert(
        "owned_surface_status".to_string(),
        Value::String("design_only".into()),
    );
    row.as_object_mut().unwrap().insert(
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
fn fixture_baseline_panic_strategy_change_is_rejected() -> TestResult {
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
                .insert("panic_strategy".to_string(), Value::String("abort".into()));
            break;
        }
    }
    let r = evaluate(&m);
    require(
        r.contains(&"panic_strategy_changed_on_baseline".to_string()),
        format!("must reject panic_strategy_changed_on_baseline; got {r:?}"),
    )
}

#[test]
fn fixture_default_profile_unlock_is_rejected() -> TestResult {
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
                "must_not_change_default_profile".to_string(),
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
fn summary_blocker_counts_match_lane_expectations() -> TestResult {
    let m = load_manifest()?;
    let summary = json_field(&m, "summary")?;
    require(
        json_u64(summary, "blocker_symbol_count_baseline")?
            == EXPECTED_BASELINE_SYMBOL_COUNT as u64,
        "summary baseline count",
    )?;
    require(
        json_u64(summary, "blocker_symbol_count_panic_abort")?
            == EXPECTED_PANIC_ABORT_SYMBOL_COUNT as u64,
        "summary panic_abort count",
    )?;
    require(
        json_u64(summary, "blocker_symbol_count_owned_unwind_when_complete")? == 0,
        "summary owned_unwind count when complete",
    )?;
    require(
        json_string(summary, "claim_status")? == "report_only",
        "summary claim_status",
    )?;
    require(
        !json_bool(summary, "promotion_allowed")?,
        "summary promotion_allowed must be false",
    )
}

#[test]
fn owned_unwind_experiment_mode_rejects_rch_local_fallback() -> TestResult {
    let root = workspace_root()?;
    let temp = unique_temp_dir("rch-local")?;
    let out_dir = temp.join("out");
    let target_root = temp.join("targets");
    let report = temp.join("standalone_owned_unwind_experiment.report.json");
    let log = temp.join("standalone_owned_unwind_experiment.log.jsonl");
    let fake_path = fake_rch_local_fallback_path(&temp)?;

    let output = Command::new(root.join("scripts/check_standalone_replacement_artifact.sh"))
        .arg("--owned-unwind-experiment")
        .current_dir(&root)
        .env("STANDALONE_REPLACEMENT_OUT_DIR", &out_dir)
        .env(
            "STANDALONE_OWNED_UNWIND_EXPERIMENT_TARGET_ROOT",
            &target_root,
        )
        .env("STANDALONE_OWNED_UNWIND_EXPERIMENT_REPORT", &report)
        .env("STANDALONE_OWNED_UNWIND_EXPERIMENT_LOG", &log)
        .env("PATH", fake_path)
        .env_remove("FRANKENLIBC_STANDALONE_LIB")
        .env_remove("LD_PRELOAD")
        .output()
        .map_err(|err| format!("owned-unwind experiment gate failed to start: {err}"))?;
    require(
        !output.status.success(),
        format!(
            "owned-unwind experiment should fail on RCH local fallback\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )?;

    let report_json = load_json_file(&report)?;
    require(
        json_string(&report_json, "status")? == "fail",
        "report status must fail on RCH local fallback",
    )?;
    let lanes = json_array(&report_json, "lanes")?;
    require(
        lanes.len() == 3,
        "owned-unwind report must include all 3 lanes",
    )?;
    for lane_id in [BASELINE_LANE, PANIC_ABORT_LANE, OWNED_UNWIND_LANE] {
        let lane = lanes
            .iter()
            .find(|lane| lane.get("lane_id").and_then(Value::as_str) == Some(lane_id))
            .ok_or_else(|| format!("missing lane {lane_id}"))?;
        require(
            json_string(lane, "build_status")? == "fail",
            format!("{lane_id} build_status must fail"),
        )?;
        let artifact_state = json_field(lane, "artifact_state")?;
        require(
            json_string(artifact_state, "failure_signature")? == "rch_local_fallback",
            format!("{lane_id} failure_signature must be rch_local_fallback"),
        )?;
    }
    require(
        log.exists(),
        format!("experiment log should exist at {}", log.display()),
    )
}
