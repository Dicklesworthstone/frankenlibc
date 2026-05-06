//! Integration test: perf waiver audit gate (bd-b92jd.2.3).
//!
//! Loads `tests/conformance/perf_waiver_audit.v1.json` and the live
//! `tests/conformance/perf_budget_policy.json#active_waivers` and refuses
//! perf parity advancement unless every active waiver:
//!
//!   * declares a non-broad `suite_ids` list (no `*`, `all`, or `any`);
//!   * carries a non-empty `owner` bead;
//!   * carries a non-empty `failure_signature`;
//!   * carries every required field listed in
//!     `policy.required_waiver_fields`;
//!   * has `expires_at` strictly after the harness run date and within
//!     `max_expires_at_horizon_days` of today;
//!   * has a unique `bead_id` across active_waivers.
//!
//! Fail-closed: any drift surfaces as a harness-test failure with a
//! per-rejection reason naming the offending waiver.

use serde_json::{Value, json};
use std::collections::BTreeSet;
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

fn audit_path() -> PathBuf {
    workspace_root().join("tests/conformance/perf_waiver_audit.v1.json")
}

fn budget_policy_path() -> PathBuf {
    workspace_root().join("tests/conformance/perf_budget_policy.json")
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
        "stale_result": "block_perf_waiver_audit",
        "waiver_audit_allowed_when_stale": false,
        "rejected_evidence_kind": "stale_source_commit",
    })
}

fn assert_source_commit_freshness_policy(audit: &Value) -> TestResult {
    ensure_eq(
        audit["source_commit_freshness_policy"].clone(),
        expected_source_commit_freshness_policy(),
        "source_commit_freshness_policy",
    )
}

fn assert_recorded_source_commit_is_current(root: &Path, audit: &Value) -> TestResult {
    let source_commit = as_str(&audit["source_commit"], "source_commit")?;
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
    "waiver_id",
    "owner",
    "suite_ids",
    "expires_at",
    "audit_decision",
    "rejection_reason",
    "failure_signature",
    "artifact_refs",
    "source_commit",
];

const REJECTED_EVIDENCE_KINDS: &[&str] = &[
    "broad_symbol_wildcard",
    "missing_owner",
    "missing_failure_signature",
    "missing_suite_ids",
    "expired_waiver",
    "expires_at_too_far",
    "duplicate_bead_id",
];

/// Days since the Unix epoch for a `YYYY-MM-DD` date string. We avoid
/// pulling in chrono — a simple Gregorian conversion is enough for the
/// expiry bounds checks below.
fn date_to_days_since_epoch(s: &str) -> Result<i64, Box<dyn Error>> {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 3 {
        return Err(test_error(format!("date {s:?} not in YYYY-MM-DD form")));
    }
    let year: i64 = parts[0]
        .parse()
        .map_err(|_| test_error(format!("date {s:?}: bad year")))?;
    let month: i64 = parts[1]
        .parse()
        .map_err(|_| test_error(format!("date {s:?}: bad month")))?;
    let day: i64 = parts[2]
        .parse()
        .map_err(|_| test_error(format!("date {s:?}: bad day")))?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return Err(test_error(format!("date {s:?}: out of range")));
    }
    // Howard Hinnant's days_from_civil — works for proleptic Gregorian
    // dates after 1970-01-01 which is all we need.
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = (y - era * 400) as u64;
    let m = month as u64;
    let d = day as u64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Ok(era * 146097 + doe as i64 - 719468)
}

fn today_days_since_epoch() -> i64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_secs();
    (now / 86_400) as i64
}

#[test]
fn audit_artifact_is_well_formed() -> TestResult {
    let audit = load_json(&audit_path())?;
    ensure_eq(
        audit["schema_version"].as_str(),
        Some("v1"),
        "schema_version",
    )?;
    ensure_eq(audit["bead"].as_str(), Some("bd-b92jd.2.3"), "bead")?;
    ensure_eq(
        audit["source_commit"].as_str(),
        Some("current"),
        "checked-in perf waiver audit source_commit must use current marker",
    )?;
    assert_recorded_source_commit_is_current(&workspace_root(), &audit)?;
    let freshness_policy = &audit["source_commit_freshness_policy"];
    assert_source_commit_freshness_policy(&audit)?;
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
        Some("block_perf_waiver_audit"),
        "source_commit_freshness_policy.stale_result",
    )?;
    ensure_eq(
        freshness_policy["waiver_audit_allowed_when_stale"].as_bool(),
        Some(false),
        "source_commit_freshness_policy.waiver_audit_allowed_when_stale",
    )?;
    ensure_eq(
        freshness_policy["rejected_evidence_kind"].as_str(),
        Some("stale_source_commit"),
        "source_commit_freshness_policy.rejected_evidence_kind",
    )?;

    let log_fields: Vec<&str> = as_array(&audit["required_log_fields"], "required_log_fields")?
        .iter()
        .map(|v| v.as_str().unwrap_or_default())
        .collect();
    ensure_eq(
        log_fields,
        REQUIRED_LOG_FIELDS.to_vec(),
        "required_log_fields",
    )?;

    let policy = &audit["policy"];
    ensure_eq(
        policy["default_decision"].as_str(),
        Some("block_until_waivers_narrow_and_unexpired"),
        "policy.default_decision",
    )?;
    let rejected: Vec<&str> = as_array(
        &policy["rejected_evidence_kinds"],
        "rejected_evidence_kinds",
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
fn stale_source_commit_policy_blocks_perf_waiver_audit() -> TestResult {
    let mut audit = load_json(&audit_path())?;
    audit["source_commit"] = json!("0000000000000000000000000000000000000000");

    let error = assert_recorded_source_commit_is_current(&workspace_root(), &audit)
        .expect_err("stale recorded source_commit should be rejected");
    ensure(
        error
            .to_string()
            .contains("source_commit must be 'current' or match current git HEAD"),
        format!("unexpected stale source_commit error: {error}"),
    )?;

    let policy = &audit["source_commit_freshness_policy"];
    ensure_eq(
        policy["stale_result"].as_str(),
        Some("block_perf_waiver_audit"),
        "stale perf waiver audit source_commit must block waiver audit evidence",
    )?;
    ensure_eq(
        policy["waiver_audit_allowed_when_stale"].as_bool(),
        Some(false),
        "stale perf waiver audit source_commit must not allow waiver audit evidence",
    )?;
    ensure_eq(
        policy["rejected_evidence_kind"].as_str(),
        Some("stale_source_commit"),
        "stale perf waiver audit source_commit must use stale_source_commit",
    )?;

    Ok(())
}

#[test]
fn live_active_waivers_pass_audit_contract() -> TestResult {
    let audit = load_json(&audit_path())?;
    let policy_doc = load_json(&budget_policy_path())?;
    let waivers = as_array(&policy_doc["active_waivers"], "active_waivers")?;

    let max_total = audit["policy"]["max_total_waivers"].as_u64().unwrap_or(0) as usize;
    ensure(
        waivers.len() <= max_total,
        format!(
            "active_waivers count {} exceeds policy.max_total_waivers {max_total}",
            waivers.len()
        ),
    )?;

    let broad_patterns: Vec<&str> = as_array(
        &audit["policy"]["broad_symbol_patterns"],
        "broad_symbol_patterns",
    )?
    .iter()
    .map(|v| v.as_str().unwrap_or_default())
    .collect();
    let required_fields: Vec<&str> = as_array(
        &audit["policy"]["required_waiver_fields"],
        "required_waiver_fields",
    )?
    .iter()
    .map(|v| v.as_str().unwrap_or_default())
    .collect();
    let max_horizon_days = audit["max_expires_at_horizon_days"].as_i64().unwrap_or(0);
    let today_days = today_days_since_epoch();
    let mut bead_ids: BTreeSet<String> = BTreeSet::new();

    for waiver in waivers {
        let bead_id = as_str(&waiver["bead_id"], "waiver.bead_id")?;
        ensure(
            bead_ids.insert(bead_id.to_string()),
            format!("duplicate_bead_id: {bead_id}"),
        )?;

        for field in &required_fields {
            ensure(
                !waiver[field].is_null(),
                format!("waiver {bead_id}: required field {field} missing"),
            )?;
        }

        let owner = as_str(&waiver["owner"], "waiver.owner")?;
        ensure(
            !owner.is_empty(),
            format!("waiver {bead_id}: missing_owner"),
        )?;

        let failure_signature = as_str(&waiver["failure_signature"], "waiver.failure_signature")?;
        ensure(
            !failure_signature.is_empty(),
            format!("waiver {bead_id}: missing_failure_signature"),
        )?;

        let suite_ids = as_array(&waiver["suite_ids"], "waiver.suite_ids")?;
        ensure(
            !suite_ids.is_empty(),
            format!("waiver {bead_id}: missing_suite_ids"),
        )?;
        for s in suite_ids {
            let s = as_str(s, "waiver.suite_ids[]")?;
            ensure(
                !broad_patterns.contains(&s),
                format!("waiver {bead_id}: broad_symbol_wildcard {s:?} is forbidden"),
            )?;
        }

        // Symbols list, when present, also must not include broad wildcards.
        if let Some(symbols) = waiver["symbols"].as_array() {
            for s in symbols {
                let s = as_str(s, "waiver.symbols[]")?;
                ensure(
                    !broad_patterns.contains(&s),
                    format!(
                        "waiver {bead_id}: broad_symbol_wildcard {s:?} in symbols is forbidden"
                    ),
                )?;
            }
        }

        let expires_at = as_str(&waiver["expires_at"], "waiver.expires_at")?;
        let expiry_days = date_to_days_since_epoch(expires_at)?;
        ensure(
            expiry_days > today_days,
            format!(
                "waiver {bead_id}: expired_waiver expires_at={expires_at} (today_days={today_days}, expiry_days={expiry_days})"
            ),
        )?;
        let horizon = today_days + max_horizon_days;
        ensure(
            expiry_days <= horizon,
            format!(
                "waiver {bead_id}: expires_at_too_far expires_at={expires_at} exceeds {max_horizon_days}-day horizon"
            ),
        )?;
    }
    Ok(())
}

#[test]
fn live_waivers_match_expected_set_in_audit() -> TestResult {
    let audit = load_json(&audit_path())?;
    let policy_doc = load_json(&budget_policy_path())?;
    let live = as_array(&policy_doc["active_waivers"], "active_waivers")?;
    let expected = as_array(&audit["expected_active_waivers"], "expected_active_waivers")?;

    let mut live_ids: Vec<&str> = live
        .iter()
        .map(|w| w["bead_id"].as_str().unwrap_or_default())
        .collect();
    live_ids.sort();
    let mut expected_ids: Vec<&str> = expected
        .iter()
        .map(|w| w["bead_id"].as_str().unwrap_or_default())
        .collect();
    expected_ids.sort();
    ensure_eq(
        live_ids,
        expected_ids,
        "live active_waivers bead_id set must equal expected_active_waivers set in the audit",
    )?;

    // Per matched bead_id, suite_ids, owner, expires_at, and
    // failure_signature must all match.
    for exp in expected {
        let exp_bead = as_str(&exp["bead_id"], "expected.bead_id")?;
        let live_match = live
            .iter()
            .find(|w| w["bead_id"].as_str() == Some(exp_bead))
            .ok_or_else(|| test_error(format!("expected waiver {exp_bead} not in live policy")))?;

        ensure_eq(
            live_match["owner"].as_str(),
            exp["owner"].as_str(),
            format!("waiver {exp_bead}: owner drift"),
        )?;
        ensure_eq(
            live_match["expires_at"].as_str(),
            exp["expires_at"].as_str(),
            format!("waiver {exp_bead}: expires_at drift"),
        )?;
        ensure_eq(
            live_match["failure_signature"].as_str(),
            exp["failure_signature"].as_str(),
            format!("waiver {exp_bead}: failure_signature drift"),
        )?;

        let live_suites: Vec<&str> = as_array(&live_match["suite_ids"], "live.suite_ids")?
            .iter()
            .map(|v| v.as_str().unwrap_or_default())
            .collect();
        let exp_suites: Vec<&str> = as_array(&exp["suite_ids"], "expected.suite_ids")?
            .iter()
            .map(|v| v.as_str().unwrap_or_default())
            .collect();
        ensure_eq(
            live_suites,
            exp_suites,
            format!("waiver {exp_bead}: suite_ids drift"),
        )?;
    }
    Ok(())
}

#[test]
fn waiver_suites_match_unenforced_suites_in_perf_regression_prevention() -> TestResult {
    // Cross-check that every live waiver suite_id is one of the suites
    // currently flagged as enforced_in_gate=false in perf_regression_prevention.
    // A waiver covering an already-enforced suite would be redundant; a
    // waiver missing an unenforced suite would silently leak a regression.
    let policy_doc = load_json(&budget_policy_path())?;
    let prevention =
        load_json(&workspace_root().join("tests/conformance/perf_regression_prevention.v1.json"))?;

    let mut unenforced: BTreeSet<String> = BTreeSet::new();
    for row in as_array(&prevention["bench_file_inventory"], "bench_file_inventory")? {
        if !row["enforced_in_gate"].as_bool().unwrap_or(true)
            && let Some(s) = row["suite_id"].as_str()
        {
            unenforced.insert(s.to_string());
        }
    }

    let mut waived: BTreeSet<String> = BTreeSet::new();
    for waiver in as_array(&policy_doc["active_waivers"], "active_waivers")? {
        for s in as_array(&waiver["suite_ids"], "waiver.suite_ids")? {
            waived.insert(as_str(s, "waiver.suite_ids[]")?.to_string());
        }
    }

    ensure_eq(
        waived,
        unenforced,
        "waiver suite_ids must equal the set of suites with enforced_in_gate=false in perf_regression_prevention.v1.json",
    )
}

#[test]
fn audit_consuming_gates_exist() -> TestResult {
    let audit = load_json(&audit_path())?;
    let root = workspace_root();
    for gate in as_array(&audit["consuming_gates"], "consuming_gates")? {
        let path = as_str(gate, "consuming_gates[]")?;
        ensure(
            root.join(path).exists(),
            format!("consuming_gates entry not found on disk: {path}"),
        )?;
    }
    Ok(())
}
