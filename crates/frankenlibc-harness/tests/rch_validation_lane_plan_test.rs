//! Conformance gate for `tests/conformance/rch_validation_lane_plan.v1.json`
//! (bd-juvqm.9).
//!
//! The plan is a machine-readable map of which `rch cargo …` invocation
//! and which `CARGO_TARGET_DIR` an agent should use for each common
//! validation surface. This gate enforces:
//!
//!   * Schema sanity — required top-level fields and a
//!     non-trivial `surfaces` count.
//!   * No bare `cargo` — every `minimal_test_cmd` and
//!     `minimal_clippy_cmd` (when not `n/a`) must be `rch cargo …`
//!     so a peer agent can copy the command verbatim and stay
//!     within the swarm-safe lane.
//!   * Focused scope — every entry pins a `-p <crate>` flag so the
//!     workspace-wide gate is not the default.
//!   * Target-dir isolation — every `target_dir_pattern` follows
//!     the per-bead/per-agent rule (`<agent>` and `<bead>`
//!     placeholders both present).
//!   * Hang runbook — at least 5 ordered steps so an agent can
//!     diagnose without re-running blindly.
//!   * Regeneration note exists (peers replacing entries must
//!     deprecate, not delete).

use serde_json::Value;
use std::error::Error;
use std::path::{Path, PathBuf};

type TestResult = Result<(), Box<dyn Error>>;

fn test_error(message: impl Into<String>) -> Box<dyn Error> {
    std::io::Error::other(message.into()).into()
}

fn ensure(condition: bool, message: impl Into<String>) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(test_error(message))
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn plan_path() -> PathBuf {
    workspace_root().join("tests/conformance/rch_validation_lane_plan.v1.json")
}

fn load_plan() -> Result<Value, Box<dyn Error>> {
    let text = std::fs::read_to_string(plan_path())
        .map_err(|err| test_error(format!("plan should be readable: {err}")))?;
    serde_json::from_str(&text)
        .map_err(|err| test_error(format!("plan should parse as JSON: {err}")))
}

fn surfaces(plan: &Value) -> Result<&Vec<Value>, Box<dyn Error>> {
    plan["surfaces"]
        .as_array()
        .ok_or_else(|| test_error("plan.surfaces must be an array"))
}

#[test]
fn plan_has_required_top_level_shape() -> TestResult {
    let plan = load_plan()?;
    ensure(
        plan["schema_version"] == "v1",
        "schema_version must be \"v1\"",
    )?;
    ensure(plan["bead"] == "bd-juvqm.9", "bead must be bd-juvqm.9")?;
    ensure(
        plan["manifest_id"] == "rch-validation-lane-plan",
        "manifest_id must be rch-validation-lane-plan",
    )?;
    let rules = plan["rules"]
        .as_object()
        .ok_or_else(|| test_error("plan.rules must be an object"))?;
    ensure(
        rules.get("all_cargo_through_rch") == Some(&Value::Bool(true)),
        "rules.all_cargo_through_rch must be true",
    )?;
    for required_rule in [
        "rationale_no_local_cargo",
        "target_dir_isolation_pattern",
        "target_dir_isolation_rationale",
        "broad_workspace_gate_policy",
        "post_remote_exit_hang_policy",
        "fmt_policy",
        "clippy_lane",
    ] {
        ensure(
            rules.get(required_rule).is_some(),
            format!("rules.{required_rule} must be present"),
        )?;
    }
    ensure(
        plan["regeneration_note"]
            .as_str()
            .map(|s| s.len() > 40)
            .unwrap_or(false),
        "regeneration_note must be a non-trivial string",
    )?;
    Ok(())
}

#[test]
fn surfaces_count_is_non_trivial() -> TestResult {
    let plan = load_plan()?;
    let s = surfaces(&plan)?;
    ensure(
        s.len() >= 8,
        format!(
            "plan must enumerate at least 8 surfaces so an agent can route any common validation; got {}",
            s.len()
        ),
    )?;
    Ok(())
}

#[test]
fn every_surface_has_required_fields() -> TestResult {
    let plan = load_plan()?;
    let s = surfaces(&plan)?;
    for entry in s {
        for field in [
            "surface_id",
            "scope",
            "minimal_test_cmd",
            "minimal_clippy_cmd",
            "target_dir_pattern",
            "owning_bead",
        ] {
            ensure(
                entry.get(field).and_then(|v| v.as_str()).is_some(),
                format!("surface entry missing string field {field}: {entry}"),
            )?;
        }
    }
    Ok(())
}

#[test]
fn minimal_test_cmd_routes_through_rch_or_a_script() -> TestResult {
    let plan = load_plan()?;
    let s = surfaces(&plan)?;
    for entry in s {
        let cmd = entry["minimal_test_cmd"].as_str().unwrap_or("");
        let surface_id = entry["surface_id"].as_str().unwrap_or("?");
        // Either `rch cargo …` (the standard lane) or a `scripts/`
        // shell wrapper that itself invokes rch (the script is
        // explicitly noted in scope/cmd text). Bare `cargo …` is
        // forbidden — that would skip the swarm-safe lane.
        let routes_through_rch = cmd.starts_with("rch cargo ") || cmd.starts_with("scripts/");
        ensure(
            routes_through_rch,
            format!(
                "surface {surface_id} minimal_test_cmd must start with `rch cargo` or `scripts/`; got: {cmd}"
            ),
        )?;
        ensure(
            !cmd.contains(" cargo ") || cmd.contains("rch cargo "),
            format!(
                "surface {surface_id} minimal_test_cmd uses bare `cargo …` (not via rch): {cmd}"
            ),
        )?;
    }
    Ok(())
}

#[test]
fn minimal_clippy_cmd_routes_through_rch_or_is_na() -> TestResult {
    let plan = load_plan()?;
    let s = surfaces(&plan)?;
    for entry in s {
        let cmd = entry["minimal_clippy_cmd"].as_str().unwrap_or("");
        let surface_id = entry["surface_id"].as_str().unwrap_or("?");
        if cmd == "n/a (shell scripts)" {
            continue;
        }
        ensure(
            cmd.starts_with("rch cargo clippy"),
            format!(
                "surface {surface_id} minimal_clippy_cmd must start with `rch cargo clippy` (or be `n/a (shell scripts)`); got: {cmd}"
            ),
        )?;
    }
    Ok(())
}

#[test]
fn cargo_commands_are_focused_with_p_flag() -> TestResult {
    let plan = load_plan()?;
    let s = surfaces(&plan)?;
    for entry in s {
        let test_cmd = entry["minimal_test_cmd"].as_str().unwrap_or("");
        let clippy_cmd = entry["minimal_clippy_cmd"].as_str().unwrap_or("");
        let surface_id = entry["surface_id"].as_str().unwrap_or("?");

        if test_cmd.starts_with("rch cargo ") {
            ensure(
                test_cmd.contains(" -p "),
                format!(
                    "surface {surface_id} minimal_test_cmd must include `-p <crate>` (not workspace-wide): {test_cmd}"
                ),
            )?;
        }
        if clippy_cmd.starts_with("rch cargo clippy") {
            ensure(
                clippy_cmd.contains(" -p "),
                format!(
                    "surface {surface_id} minimal_clippy_cmd must include `-p <crate>` (not workspace-wide): {clippy_cmd}"
                ),
            )?;
        }
    }
    Ok(())
}

#[test]
fn target_dir_pattern_carries_agent_and_bead_placeholders() -> TestResult {
    let plan = load_plan()?;
    let s = surfaces(&plan)?;
    for entry in s {
        let pattern = entry["target_dir_pattern"].as_str().unwrap_or("");
        let surface_id = entry["surface_id"].as_str().unwrap_or("?");
        if pattern.starts_with("set inside the script") {
            // Shell-script-internal target dirs are documented but
            // not literal patterns; skip placeholder check.
            continue;
        }
        ensure(
            pattern.contains("<agent>"),
            format!(
                "surface {surface_id} target_dir_pattern missing <agent> placeholder: {pattern}"
            ),
        )?;
        ensure(
            pattern.contains("<bead>"),
            format!(
                "surface {surface_id} target_dir_pattern missing <bead> placeholder: {pattern}"
            ),
        )?;
    }
    Ok(())
}

#[test]
fn surface_ids_are_unique() -> TestResult {
    let plan = load_plan()?;
    let s = surfaces(&plan)?;
    let mut ids: Vec<&str> = s.iter().filter_map(|e| e["surface_id"].as_str()).collect();
    ids.sort();
    let total = ids.len();
    ids.dedup();
    ensure(
        ids.len() == total,
        format!(
            "plan.surfaces must have unique surface_id values; saw duplicate among {total} entries"
        ),
    )?;
    Ok(())
}

#[test]
fn post_remote_exit_hang_runbook_is_ordered_and_complete() -> TestResult {
    let plan = load_plan()?;
    let runbook = plan["post_remote_exit_hang_runbook"]
        .as_array()
        .ok_or_else(|| test_error("post_remote_exit_hang_runbook must be an array"))?;
    ensure(
        runbook.len() >= 5,
        format!(
            "runbook must record >=5 ordered steps; got {}",
            runbook.len()
        ),
    )?;
    for (idx, step) in runbook.iter().enumerate() {
        let text = step.as_str().unwrap_or("");
        let expected_prefix = format!("{}.", idx + 1);
        ensure(
            text.starts_with(&expected_prefix),
            format!(
                "runbook step {idx} must start with `{}.` for ordered enumeration; got: {text}",
                idx + 1
            ),
        )?;
    }
    Ok(())
}

#[test]
fn broad_gate_allowlist_entries_carry_rationale() -> TestResult {
    let plan = load_plan()?;
    let allowlist = plan["broad_gate_allowlist"]
        .as_array()
        .ok_or_else(|| test_error("broad_gate_allowlist must be an array"))?;
    for entry in allowlist {
        let cmd = entry["command"].as_str().unwrap_or("");
        ensure(
            cmd.contains("--workspace"),
            format!("broad_gate_allowlist command must use --workspace: {cmd}"),
        )?;
        ensure(
            entry["rationale"]
                .as_str()
                .map(|r| r.len() > 30)
                .unwrap_or(false),
            format!("broad_gate_allowlist {cmd} must carry a non-trivial rationale"),
        )?;
    }
    Ok(())
}
