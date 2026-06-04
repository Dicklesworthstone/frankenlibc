//! Integration test: dlfcn replace-boundary sentinel (bd-b92jd.5.2)
//!
//! Inventories every host dlopen/dlsym/dlvsym/dlclose call site in
//! `crates/frankenlibc-abi/src/dlfcn_abi.rs` against
//! `tests/conformance/dlfcn_replace_boundary_sentinel.v1.json`. While
//! `current_level` is an interpose level (L0/L1) the listed call sites are
//! permitted under their cited annotation (interpose_only,
//! bootstrap_passthrough, host_handle_passthrough). Promotion to standalone
//! replacement levels is blocked until every interpose_only /
//! host_handle_passthrough site disappears, and any new
//! `crate::host_resolve::resolve_host_symbol_raw("dlopen"|"dlsym"|"dlvsym"|"dlclose")`
//! call appearing in the source is detected as drift.

use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::Command;

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

fn ensure_eq<T>(actual: T, expected: T, context: impl Into<String>) -> TestResult
where
    T: std::fmt::Debug + PartialEq,
{
    if actual == expected {
        Ok(())
    } else {
        Err(test_error(format!(
            "{}: expected {:?}, got {:?}",
            context.into(),
            expected,
            actual
        )))
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn load_json(path: &Path) -> Result<Value, Box<dyn Error>> {
    let content = std::fs::read_to_string(path)
        .map_err(|err| test_error(format!("{} should be readable: {err}", path.display())))?;
    serde_json::from_str(&content)
        .map_err(|err| test_error(format!("{} should parse as JSON: {err}", path.display())))
}

fn read_text(path: &Path) -> Result<String, Box<dyn Error>> {
    std::fs::read_to_string(path)
        .map_err(|err| test_error(format!("{} should be readable: {err}", path.display())))
}

fn as_str<'a>(value: &'a Value, context: &str) -> Result<&'a str, Box<dyn Error>> {
    value
        .as_str()
        .ok_or_else(|| test_error(format!("{context} must be a string")))
}

fn as_array<'a>(value: &'a Value, context: &str) -> Result<&'a Vec<Value>, Box<dyn Error>> {
    value
        .as_array()
        .ok_or_else(|| test_error(format!("{context} must be an array")))
}

fn sentinel_path() -> PathBuf {
    workspace_root().join("tests/conformance/dlfcn_replace_boundary_sentinel.v1.json")
}

fn dlfcn_source_path() -> PathBuf {
    workspace_root().join("crates/frankenlibc-abi/src/dlfcn_abi.rs")
}

fn git_head(root: &Path) -> Result<String, Box<dyn Error>> {
    let output = Command::new("git")
        .arg("rev-parse")
        .arg("HEAD")
        .current_dir(root)
        .output()
        .map_err(|err| test_error(format!("git rev-parse HEAD should run: {err}")))?;
    ensure(
        output.status.success(),
        format!(
            "git rev-parse HEAD failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ),
    )?;
    let head = String::from_utf8(output.stdout)
        .map_err(|err| test_error(format!("git HEAD should be UTF-8: {err}")))?
        .trim()
        .to_owned();
    ensure(
        is_hex_commit(&head),
        format!("git rev-parse HEAD returned invalid commit {head:?}"),
    )?;
    Ok(head)
}

fn is_hex_commit(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn source_commit_is_current(value: &str, current_head: &str) -> bool {
    value == "current" || value == current_head
}

fn expected_source_commit_freshness_policy() -> Value {
    json!({
        "recorded_source_commit_field": "source_commit",
        "comparison_target": "current git HEAD",
        "stale_result": "block_dlfcn_replace_boundary_sentinel",
        "sentinel_evidence_allowed_when_stale": false,
        "rejected_evidence_kind": "stale_source_commit",
    })
}

fn assert_source_commit_freshness_policy(sentinel: &Value) -> TestResult {
    ensure_eq(
        sentinel["source_commit_freshness_policy"].clone(),
        expected_source_commit_freshness_policy(),
        "source_commit_freshness_policy",
    )
}

fn assert_recorded_source_commit_is_current(root: &Path, sentinel: &Value) -> TestResult {
    let source_commit = as_str(&sentinel["source_commit"], "source_commit")?;
    ensure(
        source_commit == "current" || is_hex_commit(source_commit),
        format!("source_commit must be 'current' or a full hex git commit, got {source_commit:?}"),
    )?;
    let current_head = git_head(root)?;
    ensure(
        source_commit_is_current(source_commit, &current_head),
        "source_commit must be 'current' or match current git HEAD",
    )
}

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "callsite_id",
    "handle_type",
    "resolution_path",
    "host_symbol",
    "annotation",
    "expected_replacement_level",
    "actual_replacement_level",
    "decision",
    "artifact_refs",
    "source_commit",
    "failure_signature",
];

const REJECTED_EVIDENCE_KINDS: &[&str] = &[
    "unannotated_host_callsite",
    "host_callsite_count_drift",
    "host_callsite_after_standalone_promotion",
    "missing_native_handle_guard",
    "support_matrix_drift",
    "stale_source_commit",
    "replacement_level_drift_without_evidence",
];

const ALLOWED_ANNOTATIONS: &[&str] = &[
    "interpose_only",
    "bootstrap_passthrough",
    "host_handle_passthrough",
];

#[test]
fn sentinel_artifact_is_well_formed() -> TestResult {
    let sentinel = load_json(&sentinel_path())?;
    ensure_eq(
        sentinel["schema_version"].as_str(),
        Some("v1"),
        "schema_version",
    )?;
    ensure_eq(sentinel["bead"].as_str(), Some("bd-b92jd.5.2"), "bead")?;
    ensure_eq(
        sentinel["source_commit"].as_str(),
        Some("current"),
        "checked-in dlfcn sentinel source_commit must use current marker",
    )?;
    assert_recorded_source_commit_is_current(&workspace_root(), &sentinel)?;
    let freshness_policy = &sentinel["source_commit_freshness_policy"];
    assert_source_commit_freshness_policy(&sentinel)?;
    ensure_eq(
        freshness_policy["recorded_source_commit_field"].as_str(),
        Some("source_commit"),
        "source_commit_freshness_policy.recorded_source_commit_field",
    )?;
    ensure_eq(
        freshness_policy["comparison_target"].as_str(),
        Some("current git HEAD"),
        "source_commit_freshness_policy.comparison_target",
    )?;
    ensure_eq(
        freshness_policy["stale_result"].as_str(),
        Some("block_dlfcn_replace_boundary_sentinel"),
        "source_commit_freshness_policy.stale_result",
    )?;
    ensure_eq(
        freshness_policy["sentinel_evidence_allowed_when_stale"].as_bool(),
        Some(false),
        "source_commit_freshness_policy.sentinel_evidence_allowed_when_stale",
    )?;
    ensure_eq(
        freshness_policy["rejected_evidence_kind"].as_str(),
        Some("stale_source_commit"),
        "source_commit_freshness_policy.rejected_evidence_kind",
    )?;

    let subject = &sentinel["subject"];
    let module = as_str(&subject["module"], "subject.module")?;
    ensure(
        workspace_root().join(module).exists(),
        format!("subject.module must exist on disk: {module}"),
    )?;
    let policy = as_str(&subject["policy_artifact"], "subject.policy_artifact")?;
    ensure(
        workspace_root().join(policy).exists(),
        format!("subject.policy_artifact must exist: {policy}"),
    )?;

    for key in [
        "dlfcn_source",
        "dlfcn_boundary_policy",
        "support_matrix",
        "replacement_levels",
    ] {
        let path = sentinel["inputs"]
            .get(key)
            .and_then(|v| v.as_str())
            .ok_or_else(|| test_error(format!("inputs.{key} must be a string")))?;
        ensure(
            workspace_root().join(path).exists(),
            format!("inputs.{key} must reference an existing artifact: {path}"),
        )?;
    }

    let log_fields: Vec<&str> = as_array(&sentinel["required_log_fields"], "required_log_fields")?
        .iter()
        .map(|v| v.as_str().unwrap_or_default())
        .collect();
    ensure_eq(
        log_fields,
        REQUIRED_LOG_FIELDS.to_vec(),
        "required_log_fields",
    )?;

    let policy_obj = &sentinel["policy"];
    ensure_eq(
        policy_obj["default_decision"].as_str(),
        Some("block_until_replace_mode_evidence_current"),
        "policy.default_decision",
    )?;
    ensure_eq(
        policy_obj["max_total_host_callsites_at_standalone_levels"].as_u64(),
        Some(0),
        "max_total_host_callsites_at_standalone_levels must be 0",
    )?;
    let standalone_levels: Vec<&str> = as_array(
        &policy_obj["standalone_replacement_levels"],
        "policy.standalone_replacement_levels",
    )?
    .iter()
    .map(|v| v.as_str().unwrap_or_default())
    .collect();
    ensure_eq(
        standalone_levels,
        vec!["L2", "L3"],
        "standalone_replacement_levels",
    )?;

    let allowed: Vec<&str> = as_array(&policy_obj["allowed_at_L0"], "policy.allowed_at_L0")?
        .iter()
        .map(|v| v.as_str().unwrap_or_default())
        .collect();
    for marker in ALLOWED_ANNOTATIONS {
        ensure(
            allowed.contains(marker),
            format!("policy.allowed_at_L0 must include {marker}"),
        )?;
    }
    let allowed_l1: Vec<&str> = as_array(&policy_obj["allowed_at_L1"], "policy.allowed_at_L1")?
        .iter()
        .map(|v| v.as_str().unwrap_or_default())
        .collect();
    for marker in ALLOWED_ANNOTATIONS {
        ensure(
            allowed_l1.contains(marker),
            format!("policy.allowed_at_L1 must include {marker}"),
        )?;
    }

    let rejected: Vec<&str> = as_array(
        &policy_obj["rejected_evidence_kinds"],
        "policy.rejected_evidence_kinds",
    )?
    .iter()
    .map(|v| v.as_str().unwrap_or_default())
    .collect();
    for kind in REJECTED_EVIDENCE_KINDS {
        ensure(
            rejected.contains(kind),
            format!("rejected_evidence_kinds must include {kind}"),
        )?;
    }

    Ok(())
}

#[test]
fn stale_source_commit_policy_blocks_dlfcn_sentinel_evidence() -> TestResult {
    let mut sentinel = load_json(&sentinel_path())?;
    sentinel["source_commit"] = json!("0000000000000000000000000000000000000000");

    let error = assert_recorded_source_commit_is_current(&workspace_root(), &sentinel)
        .expect_err("stale recorded source_commit should be rejected");
    ensure(
        error
            .to_string()
            .contains("source_commit must be 'current' or match current git HEAD"),
        format!("unexpected stale source_commit error: {error}"),
    )?;

    let policy = &sentinel["source_commit_freshness_policy"];
    ensure_eq(
        policy["stale_result"].as_str(),
        Some("block_dlfcn_replace_boundary_sentinel"),
        "stale dlfcn sentinel source_commit must block sentinel evidence",
    )?;
    ensure_eq(
        policy["sentinel_evidence_allowed_when_stale"].as_bool(),
        Some(false),
        "stale dlfcn sentinel source_commit must not allow sentinel evidence",
    )?;
    ensure_eq(
        policy["rejected_evidence_kind"].as_str(),
        Some("stale_source_commit"),
        "stale dlfcn sentinel source_commit must use stale_source_commit",
    )?;

    Ok(())
}

#[test]
fn host_callsites_match_source_count_and_annotations() -> TestResult {
    let sentinel = load_json(&sentinel_path())?;
    let source = read_text(&dlfcn_source_path())?;

    let mut by_host_symbol: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_annotation: BTreeMap<String, usize> = BTreeMap::new();
    let mut total = 0usize;
    let mut seen_ids: BTreeSet<String> = BTreeSet::new();

    for entry in as_array(&sentinel["host_callsites"], "host_callsites")? {
        let id = as_str(&entry["callsite_id"], "callsite.callsite_id")?;
        ensure(
            seen_ids.insert(id.to_string()),
            format!("duplicate callsite_id {id}"),
        )?;
        let symbol = as_str(&entry["host_symbol"], "callsite.host_symbol")?;
        let annotation = as_str(&entry["annotation"], "callsite.annotation")?;
        ensure(
            ALLOWED_ANNOTATIONS.contains(&annotation),
            format!("callsite {id}: annotation {annotation} not in allowed list"),
        )?;
        let pattern = as_str(&entry["source_pattern"], "callsite.source_pattern")?;
        let context = as_str(&entry["context_anchor"], "callsite.context_anchor")?;
        // Each callsite is disambiguated by a context_anchor that appears
        // exactly once in dlfcn_abi.rs and is followed within 10 lines by
        // the source_pattern. This pins each callsite to a unique location
        // even when multiple sites share the same source_pattern.
        let lines: Vec<&str> = source.lines().collect();
        let context_hits: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter_map(|(i, l)| if *l == context { Some(i) } else { None })
            .collect();
        ensure(
            context_hits.len() == 1,
            format!(
                "callsite {id}: context_anchor {context:?} matched {} times; must match exactly 1",
                context_hits.len()
            ),
        )?;
        let anchor_idx = context_hits[0];
        let window_end = (anchor_idx + 10).min(lines.len());
        let window_match = lines[anchor_idx + 1..window_end].contains(&pattern);
        ensure(
            window_match,
            format!(
                "callsite {id}: source_pattern {pattern:?} not found within 10 lines after context_anchor at line {} — drift detected",
                anchor_idx + 1
            ),
        )?;

        *by_host_symbol.entry(symbol.to_string()).or_default() += 1;
        *by_annotation.entry(annotation.to_string()).or_default() += 1;
        total += 1;
    }

    let expected = &sentinel["expected_callsite_counts"];
    ensure_eq(
        expected["total"].as_u64().map(|n| n as usize),
        Some(total),
        "expected_callsite_counts.total must equal host_callsites length",
    )?;

    let expected_by_symbol = expected["by_host_symbol"]
        .as_object()
        .ok_or_else(|| test_error("expected_callsite_counts.by_host_symbol must be object"))?;
    for (symbol, count) in expected_by_symbol {
        let actual = by_host_symbol.get(symbol).copied().unwrap_or(0) as u64;
        let expected_count = count.as_u64().unwrap_or(0);
        ensure_eq(actual, expected_count, format!("by_host_symbol[{symbol}]"))?;
    }

    let expected_by_ann = expected["by_annotation"]
        .as_object()
        .ok_or_else(|| test_error("expected_callsite_counts.by_annotation must be object"))?;
    for (ann, count) in expected_by_ann {
        let actual = by_annotation.get(ann).copied().unwrap_or(0) as u64;
        let expected_count = count.as_u64().unwrap_or(0);
        ensure_eq(actual, expected_count, format!("by_annotation[{ann}]"))?;
    }

    // Independent reality check: count `resolve_host_symbol_raw(` invocations
    // in dlfcn_abi.rs (`(` excludes any doc-comment mention).
    let raw_pattern = "crate::host_resolve::resolve_host_symbol_raw(";
    let raw_in_source = source.matches(raw_pattern).count();
    let raw_expected = expected["resolve_host_symbol_raw_calls_in_source"]
        .as_u64()
        .unwrap_or(u64::MAX) as usize;
    ensure_eq(
        raw_in_source,
        raw_expected,
        format!(
            "resolve_host_symbol_raw( call count in dlfcn_abi.rs is {raw_in_source}, sentinel expected {raw_expected}; any unannotated new host call site is drift"
        ),
    )?;

    let dlvsym_next_pattern = "crate::host_resolve::host_dlvsym_next_raw";
    let dlvsym_next_count = source.matches(dlvsym_next_pattern).count();
    let expected_dlvsym_next =
        expected["host_dlvsym_next_raw_calls"].as_u64().unwrap_or(0) as usize;
    ensure_eq(
        dlvsym_next_count,
        expected_dlvsym_next,
        "host_dlvsym_next_raw call count drift",
    )?;

    Ok(())
}

#[test]
fn native_handle_guards_are_present_in_source() -> TestResult {
    let sentinel = load_json(&sentinel_path())?;
    let source = read_text(&dlfcn_source_path())?;
    for guard in as_array(
        &sentinel["required_native_handle_guards"],
        "required_native_handle_guards",
    )? {
        let guard = as_str(guard, "required_native_handle_guards[]")?;
        ensure(
            source.contains(guard),
            format!("required native-handle guard not found in dlfcn_abi.rs: {guard}"),
        )?;
    }
    Ok(())
}

#[test]
fn no_unannotated_host_call_appears_in_source() -> TestResult {
    // Independent drift detection: every `resolve_host_symbol_raw("X")` literal
    // present in dlfcn_abi.rs must reference an x in the sentinel's
    // {dlopen, dlsym, dlvsym, dlclose, dlerror} catalogue.
    let sentinel = load_json(&sentinel_path())?;
    let source = read_text(&dlfcn_source_path())?;

    let mut declared_symbols: BTreeSet<String> = BTreeSet::new();
    for entry in as_array(&sentinel["host_callsites"], "host_callsites")? {
        let symbol = as_str(&entry["host_symbol"], "callsite.host_symbol")?;
        declared_symbols.insert(symbol.to_string());
    }

    let mut idx = 0usize;
    let needle = "resolve_host_symbol_raw(\"";
    while let Some(pos) = source[idx..].find(needle) {
        let start = idx + pos + needle.len();
        let end = source[start..]
            .find('"')
            .ok_or_else(|| test_error("malformed resolve_host_symbol_raw call in dlfcn_abi.rs"))?;
        let symbol = &source[start..start + end];
        ensure(
            declared_symbols.contains(symbol),
            format!(
                "drift: dlfcn_abi.rs invokes resolve_host_symbol_raw({symbol:?}) but sentinel host_callsites does not declare {symbol} — annotate the new callsite or revert it"
            ),
        )?;
        idx = start + end;
    }

    Ok(())
}

#[test]
fn support_matrix_status_matches_sentinel_expectations() -> TestResult {
    let sentinel = load_json(&sentinel_path())?;
    let support = load_json(&workspace_root().join("support_matrix.json"))?;
    let mut by_symbol: BTreeMap<&str, &str> = BTreeMap::new();
    for sym in as_array(&support["symbols"], "support.symbols")? {
        let module = sym["module"].as_str().unwrap_or("");
        if module != "dlfcn_abi" {
            continue;
        }
        if let (Some(name), Some(status)) = (sym["symbol"].as_str(), sym["status"].as_str()) {
            by_symbol.insert(name, status);
        }
    }
    let required = sentinel["support_matrix_required_status"]["dlfcn_abi"]
        .as_object()
        .ok_or_else(|| test_error("support_matrix_required_status.dlfcn_abi must be object"))?;
    for (symbol, expected) in required {
        let expected = as_str(expected, "support_matrix_required_status[symbol]")?;
        let actual = by_symbol
            .get(symbol.as_str())
            .copied()
            .unwrap_or("(missing)");
        ensure_eq(
            actual,
            expected,
            format!("support_matrix.json dlfcn_abi::{symbol} status drift"),
        )?;
    }
    Ok(())
}

#[test]
fn standalone_replacement_promotion_blocked_while_host_callsites_remain() -> TestResult {
    // L1 is still a host-backed interpose level. While any host_callsite has
    // annotation interpose_only or host_handle_passthrough, standalone
    // replacement levels must remain unclaimed.
    let sentinel = load_json(&sentinel_path())?;
    let levels = load_json(&workspace_root().join("tests/conformance/replacement_levels.json"))?;
    let current = as_str(&levels["current_level"], "replacement_levels.current_level")?;
    let standalone_levels: BTreeSet<String> = as_array(
        &sentinel["policy"]["standalone_replacement_levels"],
        "policy.standalone_replacement_levels",
    )?
    .iter()
    .map(|v| v.as_str().unwrap_or_default().to_owned())
    .collect();

    let mut interpose_count = 0usize;
    for entry in as_array(&sentinel["host_callsites"], "host_callsites")? {
        let ann = as_str(&entry["annotation"], "callsite.annotation")?;
        if ann == "interpose_only" || ann == "host_handle_passthrough" {
            interpose_count += 1;
        }
    }

    if interpose_count > 0 {
        ensure(
            !standalone_levels.contains(current),
            format!(
                "current_level={current} but {interpose_count} interpose-only / host-handle host-delegation site(s) remain in dlfcn_abi.rs; promotion to standalone replacement is blocked until they are removed or carry an explicit replace_mode_native_required annotation",
            ),
        )?;
    }
    Ok(())
}

#[test]
fn dlfcn_boundary_policy_artifact_remains_consistent() -> TestResult {
    let sentinel = load_json(&sentinel_path())?;
    let policy =
        load_json(&workspace_root().join("tests/conformance/dlfcn_boundary_policy.v1.json"))?;
    // The legacy boundary policy declares "approved_host_calls = 0" for the
    // post-replace future. The sentinel co-exists with it by tracking the
    // current host call count and refusing replacement-level promotion.
    let approved = policy["guard_rails"]["approved_host_calls"]
        .as_object()
        .ok_or_else(|| test_error("guard_rails.approved_host_calls must be object"))?;
    for (sym, count) in approved {
        let count = count.as_u64().unwrap_or(u64::MAX);
        ensure(
            count == 0,
            format!(
                "dlfcn_boundary_policy.v1.json approved_host_calls[{sym}]={count} — sentinel requires 0 approved host calls in the post-replace contract; current host calls are tracked separately under host_callsites with annotation"
            ),
        )?;
    }
    let _ = sentinel; // sentinel is the SOT for current callsite census; the consistency check above does not need to dereference it further.
    Ok(())
}

#[test]
fn verification_command_targets_sentinel_test() -> TestResult {
    let sentinel = load_json(&sentinel_path())?;
    let cmd = as_str(&sentinel["verification_command"], "verification_command")?;
    for marker in [
        "rch exec",
        "cargo test",
        "-p frankenlibc-harness",
        "dlfcn_replace_boundary_sentinel_test",
    ] {
        ensure(
            cmd.contains(marker),
            format!("verification_command must mention {marker}: got {cmd}"),
        )?;
    }
    Ok(())
}
