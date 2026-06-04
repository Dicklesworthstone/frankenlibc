//! Integration test: Replacement levels maturity model (bd-2bu)
//!
//! Validates that:
//! 1. The replacement levels JSON exists and is valid.
//! 2. All four levels (L0–L3) are defined with required fields.
//! 3. Current assessment matches support_matrix.json counts.
//! 4. Status progression is monotonically non-decreasing.
//! 5. Gate criteria monotonically tighten across levels.
//! 6. Transition requirements reference consecutive levels.
//! 7. The CI gate script exists and is executable.
//! 8. README replacement-level claim matches current_level.
//! 9. Release tag policy is aligned with current_level.
//! 10. README smoke-readiness prose does not outrun replacement-level blockers or red smoke evidence.
//!
//! Run: cargo test -p frankenlibc-harness --test replacement_levels_test

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn workspace_root() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn load_levels() -> serde_json::Value {
    let path = workspace_root().join("tests/conformance/replacement_levels.json");
    let content = std::fs::read_to_string(&path).expect("replacement_levels.json should exist");
    serde_json::from_str(&content).expect("replacement_levels.json should be valid JSON")
}

fn load_matrix() -> serde_json::Value {
    let path = workspace_root().join("support_matrix.json");
    let content = std::fs::read_to_string(&path).expect("support_matrix.json should exist");
    serde_json::from_str(&content).expect("support_matrix.json should be valid JSON")
}

fn load_readme() -> String {
    let path = workspace_root().join("README.md");
    std::fs::read_to_string(&path).expect("README.md should exist")
}

fn load_l1_crt_startup_tls_matrix() -> serde_json::Value {
    let path = workspace_root().join("tests/conformance/l1_crt_startup_tls_proof_matrix.v1.json");
    let content =
        std::fs::read_to_string(&path).expect("l1_crt_startup_tls_proof_matrix should exist");
    serde_json::from_str(&content).expect("l1_crt_startup_tls_proof_matrix should be valid JSON")
}

fn load_smoke_summary() -> serde_json::Value {
    let path = workspace_root().join("tests/conformance/ld_preload_smoke_summary.v1.json");
    let content = std::fs::read_to_string(&path).expect("ld_preload_smoke_summary should exist");
    serde_json::from_str(&content).expect("ld_preload_smoke_summary should be valid JSON")
}

fn unique_temp_path(prefix: &str, suffix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock drifted before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{}-{nanos}{suffix}", std::process::id()))
}

const L1_CRT_REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "proof_row_id",
    "runtime_mode",
    "replacement_level",
    "expected_order",
    "actual_order",
    "expected_status",
    "actual_status",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
];

const L1_CRT_REQUIRED_ROWS: &[&str] = &[
    "process_startup",
    "argc_argv_envp_handoff",
    "tls_initialization",
    "pthread_tls_keys",
    "constructors",
    "destructors",
    "atexit_on_exit",
    "init_fini_arrays",
    "errno_tls_isolation",
    "secure_mode",
    "failure_diagnostics",
];

fn is_full_git_commit(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn source_commit_is_current(value: &str, current_head: &str) -> bool {
    value == "current" || value == current_head
}

fn git_head(root: &Path) -> Result<String, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .arg("rev-parse")
        .arg("HEAD")
        .output()
        .map_err(|err| format!("git rev-parse HEAD should run: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "git rev-parse HEAD failed with status {}",
            output.status
        ));
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|err| format!("git rev-parse HEAD emitted non-UTF8: {err}"))?;
    let head = stdout.trim().to_owned();
    if !is_full_git_commit(&head) {
        return Err(format!("git HEAD must be a 40-hex commit, got {head:?}"));
    }
    Ok(head)
}

fn l1_crt_startup_tls_source_commit_policy(
    matrix: &serde_json::Value,
) -> Option<&serde_json::Value> {
    matrix
        .as_object()
        .and_then(|object| object.get("source_commit_freshness_policy"))
}

fn json_string_array(value: &serde_json::Value, field: &str) -> Result<Vec<String>, Vec<String>> {
    value[field]
        .as_array()
        .ok_or_else(|| vec![format!("{field} must be an array")])?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| vec![format!("{field} must contain only strings")])
        })
        .collect()
}

fn parse_date_ordinal(timestamp: &str) -> Result<i64, String> {
    let date = timestamp
        .split_once('T')
        .map(|(date, _)| date)
        .ok_or_else(|| format!("timestamp missing T separator: {timestamp}"))?;
    let mut parts = date.split('-');
    let year: i64 = parts
        .next()
        .ok_or_else(|| format!("timestamp missing year: {timestamp}"))?
        .parse()
        .map_err(|err| format!("timestamp year did not parse: {timestamp}: {err}"))?;
    let month: usize = parts
        .next()
        .ok_or_else(|| format!("timestamp missing month: {timestamp}"))?
        .parse()
        .map_err(|err| format!("timestamp month did not parse: {timestamp}: {err}"))?;
    let day: i64 = parts
        .next()
        .ok_or_else(|| format!("timestamp missing day: {timestamp}"))?
        .parse()
        .map_err(|err| format!("timestamp day did not parse: {timestamp}: {err}"))?;
    if !(1..=12).contains(&month) {
        return Err(format!("timestamp month out of range: {timestamp}"));
    }
    let month_offsets = [0_i64, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    let leap_days = year / 4 - year / 100 + year / 400;
    Ok(year * 365 + leap_days + month_offsets[month - 1] + day)
}

fn validate_l1_crt_startup_tls_matrix(matrix: &serde_json::Value) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();

    if matrix["schema_version"].as_str() != Some("v1") {
        errors.push("schema_version must be v1".to_string());
    }
    if matrix["bead"].as_str() != Some("bd-bp8fl.6.3") {
        errors.push("bead must be bd-bp8fl.6.3".to_string());
    }
    if matrix["claim_policy"]["replacement_level"].as_str() != Some("L1") {
        errors.push("claim_policy.replacement_level must be L1".to_string());
    }
    let current_head = match git_head(&workspace_root()) {
        Ok(head) => head,
        Err(err) => {
            errors.push(format!(
                "git HEAD must be readable for source_commit freshness: {err}"
            ));
            String::new()
        }
    };
    match matrix["source_commit"].as_str() {
        Some("current") => {}
        Some(source_commit)
            if is_full_git_commit(source_commit)
                && source_commit_is_current(source_commit, &current_head) => {}
        Some(source_commit) if is_full_git_commit(source_commit) => {
            errors.push("source_commit must be 'current' or match current git HEAD".to_string())
        }
        Some(source_commit) => errors.push(format!(
            "source_commit must be 'current' or a 40-hex git commit, got {source_commit:?}"
        )),
        None => errors.push("source_commit must be present".to_string()),
    }

    match l1_crt_startup_tls_source_commit_policy(matrix).and_then(|policy| policy.as_object()) {
        Some(policy) => {
            for (field, expected) in [
                ("recorded_source_commit_field", "source_commit"),
                ("comparison_target", "current git HEAD"),
                (
                    "stale_result",
                    "block_l1_crt_startup_tls_proof_matrix_evidence",
                ),
                ("rejected_evidence_kind", "stale_source_commit"),
            ] {
                if policy.get(field).and_then(|value| value.as_str()) != Some(expected) {
                    errors.push(format!(
                        "source_commit_freshness_policy.{field} must be {expected}"
                    ));
                }
            }
            if policy
                .get("startup_tls_matrix_evidence_allowed_when_stale")
                .and_then(|value| value.as_bool())
                != Some(false)
            {
                errors.push(
                    "source_commit_freshness_policy.startup_tls_matrix_evidence_allowed_when_stale must be false"
                        .to_string(),
                );
            }
        }
        None => errors.push("source_commit_freshness_policy must be an object".to_string()),
    }

    let log_fields = json_string_array(matrix, "required_log_fields").unwrap_or_else(|errs| {
        errors.extend(errs);
        Vec::new()
    });
    let expected_log_fields: Vec<String> = L1_CRT_REQUIRED_LOG_FIELDS
        .iter()
        .map(|field| (*field).to_string())
        .collect();
    if log_fields != expected_log_fields {
        errors.push(format!(
            "required_log_fields mismatch: expected {expected_log_fields:?}, got {log_fields:?}"
        ));
    }

    let required_ids = json_string_array(matrix, "required_proof_row_ids").unwrap_or_else(|errs| {
        errors.extend(errs);
        Vec::new()
    });
    let expected_required_ids: Vec<String> = L1_CRT_REQUIRED_ROWS
        .iter()
        .map(|row| (*row).to_string())
        .collect();
    if required_ids != expected_required_ids {
        errors.push(format!(
            "required_proof_row_ids mismatch: expected {expected_required_ids:?}, got {required_ids:?}"
        ));
    }

    let generated_at = matrix["generated_at_utc"].as_str().unwrap_or("");
    let generated_ordinal = match parse_date_ordinal(generated_at) {
        Ok(value) => value,
        Err(err) => {
            errors.push(format!("generated_at_utc invalid: {err}"));
            0
        }
    };
    let max_age_days = matrix["claim_policy"]["max_evidence_age_days"]
        .as_i64()
        .unwrap_or(0);
    if max_age_days <= 0 {
        errors.push("claim_policy.max_evidence_age_days must be positive".to_string());
    }

    let rows = matrix["proof_rows"].as_array().unwrap_or_else(|| {
        errors.push("proof_rows must be an array".to_string());
        static EMPTY: Vec<serde_json::Value> = Vec::new();
        &EMPTY
    });
    let mut seen_rows = HashSet::new();
    let allowed_statuses: HashSet<&str> = ["pass", "blocked", "required"].into_iter().collect();
    let allowed_decisions: HashSet<&str> = ["satisfied", "claim_blocked"].into_iter().collect();

    for row in rows {
        let id = row["id"].as_str().unwrap_or("<missing>");
        if !seen_rows.insert(id.to_string()) {
            errors.push(format!("duplicate proof row id {id}"));
        }
        if row["replacement_level"].as_str() != Some("L1") {
            errors.push(format!("{id}: replacement_level must be L1"));
        }

        let modes = row["runtime_modes"]
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.as_str())
                    .collect::<HashSet<_>>()
            })
            .unwrap_or_default();
        if !modes.contains("strict") || !modes.contains("hardened") {
            errors.push(format!(
                "{id}: runtime_modes must include strict and hardened"
            ));
        }

        for field in [
            "expected_order",
            "actual_order",
            "artifact_refs",
            "check_commands",
            "symbols",
        ] {
            if !row[field].is_array() {
                errors.push(format!("{id}: {field} must be an array"));
            }
        }
        if row["artifact_refs"]
            .as_array()
            .map(|items| items.is_empty())
            .unwrap_or(true)
        {
            errors.push(format!("{id}: artifact_refs must not be empty"));
        }
        if row["check_commands"]
            .as_array()
            .map(|items| items.is_empty())
            .unwrap_or(true)
        {
            errors.push(format!("{id}: check_commands must not be empty"));
        }
        if row["failure_signature"]
            .as_str()
            .map(|text| text.is_empty())
            .unwrap_or(true)
        {
            errors.push(format!("{id}: failure_signature must be non-empty"));
        }

        let expected_status = row["expected_status"].as_str().unwrap_or("<missing>");
        let actual_status = row["actual_status"].as_str().unwrap_or("<missing>");
        let promotion_decision = row["promotion_decision"].as_str().unwrap_or("<missing>");
        if !allowed_statuses.contains(expected_status) {
            errors.push(format!(
                "{id}: expected_status {expected_status:?} is invalid"
            ));
        }
        if !allowed_statuses.contains(actual_status) {
            errors.push(format!("{id}: actual_status {actual_status:?} is invalid"));
        }
        if !allowed_decisions.contains(promotion_decision) {
            errors.push(format!(
                "{id}: promotion_decision {promotion_decision:?} is invalid"
            ));
        }
        let satisfied = promotion_decision == "satisfied";
        if (actual_status == "pass") != satisfied {
            errors.push(format!(
                "{id}: actual_status={actual_status} contradicts promotion_decision={promotion_decision}"
            ));
        }

        if satisfied {
            match row["evidence_generated_at_utc"].as_str() {
                Some(evidence_at) => match parse_date_ordinal(evidence_at) {
                    Ok(evidence_ordinal) => {
                        if generated_ordinal > 0
                            && max_age_days > 0
                            && generated_ordinal - evidence_ordinal > max_age_days
                        {
                            errors.push(format!(
                                "{id}: evidence is stale by {} days",
                                generated_ordinal - evidence_ordinal
                            ));
                        }
                    }
                    Err(err) => errors.push(format!("{id}: evidence timestamp invalid: {err}")),
                },
                None => errors.push(format!(
                    "{id}: satisfied rows must include evidence_generated_at_utc"
                )),
            }
        }
    }

    for required in L1_CRT_REQUIRED_ROWS {
        if !seen_rows.contains(*required) {
            errors.push(format!("missing required proof row {required}"));
        }
    }

    let negative_tests = matrix["negative_claim_tests"]
        .as_array()
        .unwrap_or_else(|| {
            errors.push("negative_claim_tests must be an array".to_string());
            static EMPTY: Vec<serde_json::Value> = Vec::new();
            &EMPTY
        });
    if negative_tests.len() < 3 {
        errors.push("negative_claim_tests must include at least three cases".to_string());
    }
    for test in negative_tests {
        let id = test["id"].as_str().unwrap_or("<missing>");
        if test["expected_result"].as_str() != Some("claim_blocked") {
            errors.push(format!(
                "{id}: negative claim expected_result must be claim_blocked"
            ));
        }
        if test["failure_signature"]
            .as_str()
            .map(|text| text.is_empty())
            .unwrap_or(true)
        {
            errors.push(format!("{id}: negative claim missing failure_signature"));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

#[test]
fn levels_exists_and_valid() {
    let lvl = load_levels();
    assert!(lvl["schema_version"].is_number(), "Missing schema_version");
    assert!(lvl["levels"].is_array(), "Missing levels array");
    assert!(
        lvl["current_assessment"].is_object(),
        "Missing current_assessment"
    );
    assert!(lvl["current_level"].is_string(), "Missing current_level");
    assert!(
        lvl["transition_requirements"].is_object(),
        "Missing transition_requirements"
    );
}

#[test]
fn all_four_levels_defined() {
    let lvl = load_levels();
    let levels = lvl["levels"].as_array().unwrap();

    assert_eq!(levels.len(), 4, "Expected exactly 4 levels");

    let expected = ["L0", "L1", "L2", "L3"];
    let found: Vec<&str> = levels.iter().filter_map(|l| l["level"].as_str()).collect();
    assert_eq!(found, expected, "Levels must be L0, L1, L2, L3 in order");

    let required_fields = [
        "level",
        "name",
        "description",
        "deployment",
        "host_glibc_required",
        "gate_criteria",
        "status",
    ];

    for entry in levels {
        let lid = entry["level"].as_str().unwrap_or("?");
        for field in &required_fields {
            assert!(
                !entry[field].is_null(),
                "{lid}: missing required field \"{field}\""
            );
        }

        // Gate criteria sub-fields
        let gc = &entry["gate_criteria"];
        for gf in [
            "max_callthrough_pct",
            "max_stub_pct",
            "min_implemented_pct",
            "e2e_smoke_required",
        ] {
            assert!(!gc[gf].is_null(), "{lid}: gate_criteria missing \"{gf}\"");
        }
    }
}

#[test]
fn assessment_matches_support_matrix() {
    let lvl = load_levels();
    let matrix = load_matrix();

    let symbols = matrix["symbols"].as_array().unwrap();
    let assessment = &lvl["current_assessment"];

    // Count statuses from matrix
    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut module_counts: HashMap<(String, String), usize> = HashMap::new();

    for sym in symbols {
        let status = sym["status"].as_str().unwrap_or("Unknown").to_string();
        let module = sym["module"].as_str().unwrap_or("unknown").to_string();
        *counts.entry(status.clone()).or_default() += 1;
        *module_counts.entry((status, module)).or_default() += 1;
    }

    let matrix_total = symbols.len();
    let implemented_count = *counts.get("Implemented").unwrap_or(&0);
    let raw_syscall_count = *counts.get("RawSyscall").unwrap_or(&0);
    let wraps_host_count = *counts.get("WrapsHostLibc").unwrap_or(&0);
    let glibc_callthrough_count = *counts.get("GlibcCallThrough").unwrap_or(&0);
    let host_backed_count = wraps_host_count + glibc_callthrough_count;
    let native_count = implemented_count + raw_syscall_count;
    let claimed_total = assessment["total_symbols"].as_u64().unwrap() as usize;
    assert_eq!(
        claimed_total, matrix_total,
        "total_symbols mismatch: claimed={claimed_total} matrix={matrix_total}"
    );

    for (json_key, actual) in [
        ("implemented", implemented_count),
        ("raw_syscall", raw_syscall_count),
        ("native", native_count),
        ("wraps_host_libc", wraps_host_count),
        ("glibc_callthrough", glibc_callthrough_count),
        ("callthrough", host_backed_count),
        ("stub", *counts.get("Stub").unwrap_or(&0)),
    ] {
        let claimed = assessment[json_key].as_u64().unwrap() as usize;
        assert_eq!(
            claimed, actual,
            "{json_key}: claimed={claimed} matrix={actual}"
        );
    }

    // Check host-backed callthrough breakdowns.
    let ct_breakdown = assessment["callthrough_breakdown"].as_object().unwrap();
    for (module, claimed_val) in ct_breakdown {
        let claimed = claimed_val.as_u64().unwrap() as usize;
        let actual = module_counts
            .get(&("WrapsHostLibc".to_string(), module.clone()))
            .copied()
            .unwrap_or(0)
            + module_counts
                .get(&("GlibcCallThrough".to_string(), module.clone()))
                .copied()
                .unwrap_or(0);
        assert_eq!(
            claimed, actual,
            "callthrough_breakdown.{module}: claimed={claimed} matrix={actual}"
        );
    }

    let wraps_breakdown = assessment["wraps_host_libc_breakdown"].as_object().unwrap();
    for (module, claimed_val) in wraps_breakdown {
        let claimed = claimed_val.as_u64().unwrap() as usize;
        let actual = *module_counts
            .get(&("WrapsHostLibc".to_string(), module.clone()))
            .unwrap_or(&0);
        assert_eq!(
            claimed, actual,
            "wraps_host_libc_breakdown.{module}: claimed={claimed} matrix={actual}"
        );
    }

    let glibc_breakdown = assessment["glibc_callthrough_breakdown"]
        .as_object()
        .unwrap();
    for (module, claimed_val) in glibc_breakdown {
        let claimed = claimed_val.as_u64().unwrap() as usize;
        let actual = *module_counts
            .get(&("GlibcCallThrough".to_string(), module.clone()))
            .unwrap_or(&0);
        assert_eq!(
            claimed, actual,
            "glibc_callthrough_breakdown.{module}: claimed={claimed} matrix={actual}"
        );
    }

    // Check stub breakdown
    let stub_breakdown = assessment["stub_breakdown"].as_object().unwrap();
    for (module, claimed_val) in stub_breakdown {
        let claimed = claimed_val.as_u64().unwrap() as usize;
        let actual = *module_counts
            .get(&("Stub".to_string(), module.clone()))
            .unwrap_or(&0);
        assert_eq!(
            claimed, actual,
            "stub_breakdown.{module}: claimed={claimed} matrix={actual}"
        );
    }
}

#[test]
fn status_progression_consistent() {
    let lvl = load_levels();
    let levels = lvl["levels"].as_array().unwrap();

    let status_order: HashMap<&str, usize> = [
        ("achieved", 0),
        ("in_progress", 1),
        ("planned", 2),
        ("roadmap", 3),
    ]
    .into_iter()
    .collect();

    let valid_statuses: HashSet<&str> = ["achieved", "in_progress", "planned", "roadmap"]
        .into_iter()
        .collect();

    let mut prev_order: Option<usize> = None;
    let mut prev_level = "";

    for entry in levels {
        let lid = entry["level"].as_str().unwrap_or("?");
        let status = entry["status"].as_str().unwrap_or("unknown");

        assert!(
            valid_statuses.contains(status),
            "{lid}: invalid status \"{status}\""
        );

        let order = status_order[status];
        if let Some(po) = prev_order {
            assert!(
                order >= po,
                "{lid} ({status}) is less mature than {prev_level} — status should be monotonically non-decreasing"
            );
        }
        prev_order = Some(order);
        prev_level = lid;
    }

    // current_level must have status "achieved"
    let current = lvl["current_level"].as_str().unwrap_or("");
    let current_entry = levels.iter().find(|e| e["level"].as_str() == Some(current));
    assert!(
        current_entry.is_some(),
        "current_level={current} not found in levels"
    );
    assert_eq!(
        current_entry.unwrap()["status"].as_str().unwrap_or(""),
        "achieved",
        "current_level={current} must have status \"achieved\""
    );
}

#[test]
fn gate_criteria_monotonically_tighten() {
    let lvl = load_levels();
    let levels = lvl["levels"].as_array().unwrap();

    let mut prev_callthrough: Option<(String, u64)> = None;
    let mut prev_stub: Option<(String, u64)> = None;
    let mut prev_implemented: Option<(String, u64)> = None;

    for entry in levels {
        let lid = entry["level"].as_str().unwrap_or("?").to_string();
        let gc = &entry["gate_criteria"];

        if let Some(val) = gc["max_callthrough_pct"].as_u64() {
            if let Some((ref prev_lid, prev_val)) = prev_callthrough {
                assert!(
                    val <= prev_val,
                    "max_callthrough_pct: {lid}={val} > {prev_lid}={prev_val} (should be non-increasing)"
                );
            }
            prev_callthrough = Some((lid.clone(), val));
        }

        if let Some(val) = gc["max_stub_pct"].as_u64() {
            if let Some((ref prev_lid, prev_val)) = prev_stub {
                assert!(
                    val <= prev_val,
                    "max_stub_pct: {lid}={val} > {prev_lid}={prev_val} (should be non-increasing)"
                );
            }
            prev_stub = Some((lid.clone(), val));
        }

        if let Some(val) = gc["min_implemented_pct"].as_u64() {
            if let Some((ref prev_lid, prev_val)) = prev_implemented {
                assert!(
                    val >= prev_val,
                    "min_implemented_pct: {lid}={val} < {prev_lid}={prev_val} (should be non-decreasing)"
                );
            }
            prev_implemented = Some((lid.clone(), val));
        }
    }
}

#[test]
fn transition_requirements_reference_consecutive_levels() {
    let lvl = load_levels();
    let transitions = lvl["transition_requirements"].as_object().unwrap();

    let expected_keys = ["L0_to_L1", "L1_to_L2", "L2_to_L3"];
    for key in &expected_keys {
        assert!(
            transitions.contains_key(*key),
            "Missing transition_requirements.{key}"
        );
        let reqs = transitions[*key].as_array().unwrap();
        assert!(!reqs.is_empty(), "transition_requirements.{key} is empty");
        for req in reqs {
            assert!(
                req.is_string() && !req.as_str().unwrap().is_empty(),
                "transition_requirements.{key}: each requirement must be a non-empty string"
            );
        }
    }
}

#[test]
fn percentages_consistent() {
    let lvl = load_levels();
    let assessment = &lvl["current_assessment"];

    let total = assessment["total_symbols"].as_u64().unwrap() as f64;
    assert!(total > 0.0, "total_symbols must be > 0");

    let implemented = assessment["implemented"].as_u64().unwrap() as f64;
    let raw_syscall = assessment["raw_syscall"].as_u64().unwrap() as f64;
    let native = assessment["native"].as_u64().unwrap() as f64;
    let wraps_host_libc = assessment["wraps_host_libc"].as_u64().unwrap() as f64;
    let glibc_callthrough = assessment["glibc_callthrough"].as_u64().unwrap() as f64;
    let callthrough = assessment["callthrough"].as_u64().unwrap() as f64;
    let stub = assessment["stub"].as_u64().unwrap() as f64;

    assert_eq!(
        native as u64,
        (implemented + raw_syscall) as u64,
        "native count must equal implemented + raw_syscall"
    );
    assert_eq!(
        callthrough as u64,
        (wraps_host_libc + glibc_callthrough) as u64,
        "callthrough count must equal WrapsHostLibc + GlibcCallThrough"
    );

    // Counts must sum to total
    let sum = implemented + raw_syscall + callthrough + stub;
    assert_eq!(
        sum as u64, total as u64,
        "Status counts ({sum}) don't sum to total ({total})"
    );

    // Percentages must be roughly correct (within 1% due to rounding)
    let check_pct = |name: &str, count: f64, claimed_pct: u64| {
        let actual_pct = (count * 100.0 / total).round() as u64;
        let diff = actual_pct.abs_diff(claimed_pct);
        assert!(
            diff <= 1,
            "{name}_pct: claimed={claimed_pct} computed={actual_pct} (diff={diff} > 1)"
        );
    };

    check_pct(
        "implemented",
        implemented,
        assessment["implemented_pct"].as_u64().unwrap(),
    );
    check_pct(
        "raw_syscall",
        raw_syscall,
        assessment["raw_syscall_pct"].as_u64().unwrap(),
    );
    check_pct("native", native, assessment["native_pct"].as_u64().unwrap());
    check_pct(
        "wraps_host_libc",
        wraps_host_libc,
        assessment["wraps_host_libc_pct"].as_u64().unwrap(),
    );
    check_pct(
        "glibc_callthrough",
        glibc_callthrough,
        assessment["glibc_callthrough_pct"].as_u64().unwrap(),
    );
    check_pct(
        "callthrough",
        callthrough,
        assessment["callthrough_pct"].as_u64().unwrap(),
    );
    check_pct("stub", stub, assessment["stub_pct"].as_u64().unwrap());
}

#[test]
fn claim_drift_guard_consistent_with_readme_and_release_policy() {
    let lvl = load_levels();
    let readme = load_readme();

    let levels = lvl["levels"].as_array().unwrap();
    let current = lvl["current_level"].as_str().unwrap_or("");
    let current_entry = levels
        .iter()
        .find(|e| e["level"].as_str() == Some(current))
        .expect("current_level must exist in levels[]");
    let current_name = current_entry["name"]
        .as_str()
        .expect("current level must have a name");

    let expected_claim =
        format!("Declared replacement level claim: **{current} — {current_name}**.");
    assert!(
        readme.contains(&expected_claim),
        "README replacement-level claim line missing/stale: {expected_claim}"
    );
    assert_eq!(
        readme
            .matches("Declared replacement level claim: **")
            .count(),
        1,
        "README must contain exactly one replacement-level claim line"
    );

    let policy = lvl["release_tag_policy"]
        .as_object()
        .expect("release_tag_policy must be an object");
    assert!(
        policy.contains_key("tag_format")
            && policy["tag_format"]
                .as_str()
                .map(|s| !s.is_empty())
                .unwrap_or(false),
        "release_tag_policy.tag_format must be a non-empty string"
    );

    let suffixes = policy["level_tag_suffix"]
        .as_object()
        .expect("release_tag_policy.level_tag_suffix must be an object");
    for lid in ["L0", "L1", "L2", "L3"] {
        let expected = format!("-{lid}");
        let actual = suffixes
            .get(lid)
            .and_then(|v| v.as_str())
            .unwrap_or("<missing>");
        assert_eq!(
            actual, expected,
            "release_tag_policy.level_tag_suffix.{lid} must equal {expected}"
        );
    }

    let claimed_release_level = policy["current_release_level"].as_str().unwrap_or("");
    assert_eq!(
        claimed_release_level, current,
        "release_tag_policy.current_release_level must match current_level"
    );

    let example = policy["current_release_tag_example"].as_str().unwrap_or("");
    assert!(
        !example.is_empty(),
        "release_tag_policy.current_release_tag_example must be non-empty"
    );
    assert!(
        example.ends_with(&format!("-{current}")),
        "current_release_tag_example must end with -{current}, got {example}"
    );
}

#[test]
fn readme_smoke_claims_do_not_outrun_replacement_level_blockers() {
    let lvl = load_levels();
    let readme = load_readme().to_ascii_lowercase();
    let smoke = load_smoke_summary();

    let levels = lvl["levels"].as_array().unwrap();
    let l1 = levels
        .iter()
        .find(|entry| entry["level"].as_str() == Some("L1"))
        .expect("L1 level must exist");

    let blockers = l1["blockers"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|value| value.as_str())
                .collect::<Vec<_>>()
                .join(" ")
                .to_ascii_lowercase()
        })
        .unwrap_or_default();

    let hardened_smoke_incomplete =
        blockers.contains("hardened-mode e2e smoke") && blockers.contains("incomplete");
    let smoke_red = smoke["summary"]["overall_failed"].as_bool().unwrap_or(true)
        || smoke["modes"]["strict"]["status"].as_str() != Some("green")
        || smoke["modes"]["hardened"]["status"].as_str() != Some("green");

    if hardened_smoke_incomplete || smoke_red {
        assert!(
            !readme.contains("latest broad preload smoke run is **fully green**"),
            "README must not claim broad preload smoke is fully green while L1 hardened smoke remains blocked"
        );
        assert!(
            !readme.contains("both strict and hardened modes pass all workloads"),
            "README must not claim paired strict+hardened smoke closure while L1 hardened smoke remains blocked"
        );
        assert!(
            !readme.contains("green strict + hardened smoke runs"),
            "README must not claim strict+hardened smoke is green while the checked smoke artifact is red"
        );
        assert!(
            !readme.contains("curated preload smoke battery is green in both strict and hardened modes"),
            "README must not claim curated smoke is green while the checked smoke artifact is red"
        );
    }
}

#[test]
fn blocker_text_does_not_reference_resolved_numeric_counts() {
    let lvl = load_levels();
    let assessment = &lvl["current_assessment"];
    let stub_count = assessment["stub"].as_u64().unwrap_or(0);
    let callthrough_count = assessment["callthrough"].as_u64().unwrap_or(0);

    let mut texts = Vec::new();
    for entry in lvl["levels"].as_array().unwrap() {
        if let Some(blockers) = entry["blockers"].as_array() {
            for blocker in blockers {
                if let Some(text) = blocker.as_str() {
                    texts.push(text.to_lowercase());
                }
            }
        }
    }
    for (_, requirements) in lvl["transition_requirements"].as_object().unwrap() {
        for requirement in requirements.as_array().unwrap() {
            if let Some(text) = requirement.as_str() {
                texts.push(text.to_lowercase());
            }
        }
    }

    if stub_count == 0 {
        assert!(
            texts.iter().all(|text| !text.contains("6 stub symbols")),
            "replacement_levels.json must not keep stale stub-count blockers once stub=0"
        );
    }

    if callthrough_count == 0 {
        assert!(
            texts.iter().all(|text| {
                !text.contains("call-throughs (")
                    && !text.contains("callthroughs (")
                    && !text.contains(" call-through symbols")
            }),
            "replacement_levels.json must not keep stale non-zero call-through blockers once callthrough=0"
        );
    }
}

#[test]
fn gate_script_exists_and_executable() {
    let root = workspace_root();
    let script = root.join("scripts/check_replacement_levels.sh");
    assert!(
        script.exists(),
        "scripts/check_replacement_levels.sh must exist"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_replacement_levels.sh must be executable"
        );
    }
}

#[test]
fn l1_objective_gate_consumes_current_crt_startup_tls_matrix() {
    let levels = load_levels();
    let matrix = load_l1_crt_startup_tls_matrix();
    let smoke = load_smoke_summary();
    let l1 = levels["levels"]
        .as_array()
        .and_then(|items| {
            items
                .iter()
                .find(|entry| entry["level"].as_str() == Some("L1"))
        })
        .expect("L1 level entry should exist");
    let objective_gate = &l1["objective_gate"];
    let obligations = objective_gate["obligations"]
        .as_array()
        .expect("L1 objective gate obligations should be an array");
    let crt_obligation = obligations
        .iter()
        .find(|entry| entry["id"].as_str() == Some("crt_startup_tls_proof_matrix"))
        .expect("L1 objective gate should bind the CRT/startup/TLS proof matrix");
    let summary = &matrix["summary"];

    assert_eq!(
        crt_obligation["expected"]["current_gate_status"].as_str(),
        Some("pass")
    );
    assert_eq!(
        crt_obligation["expected"]["blocked_row_count"].as_u64(),
        Some(0)
    );
    assert_eq!(
        crt_obligation["actual"]["current_gate_status"].as_str(),
        summary["current_gate_status"].as_str(),
        "replacement_levels.json should consume the proof matrix current_gate_status"
    );
    assert_eq!(
        crt_obligation["actual"]["blocked_row_count"].as_u64(),
        summary["blocked_row_count"].as_u64(),
        "replacement_levels.json should consume the proof matrix blocked_row_count"
    );
    assert_eq!(
        crt_obligation["outcome"].as_str(),
        Some("pass"),
        "CRT/startup/TLS proof matrix must not remain an L1 blocker after all rows pass"
    );
    let smoke_obligation = obligations
        .iter()
        .find(|entry| entry["id"].as_str() == Some("hardened_smoke_battery"))
        .expect("L1 objective gate should bind the checked preload smoke summary");
    assert_eq!(
        smoke_obligation["actual"]["run_id"].as_str(),
        smoke["run_id"].as_str(),
        "replacement_levels.json should consume the current smoke run id"
    );
    assert_eq!(
        smoke_obligation["actual"]["overall_failed"].as_bool(),
        smoke["summary"]["overall_failed"].as_bool(),
        "replacement_levels.json should consume the current smoke overall status"
    );
    assert_eq!(
        smoke_obligation["actual"]["strict_status"].as_str(),
        smoke["modes"]["strict"]["status"].as_str(),
        "replacement_levels.json should consume strict smoke status"
    );
    assert_eq!(
        smoke_obligation["actual"]["hardened_status"].as_str(),
        smoke["modes"]["hardened"]["status"].as_str(),
        "replacement_levels.json should consume hardened smoke status"
    );
    assert_eq!(
        smoke_obligation["actual"]["perf_failures"].as_u64(),
        smoke["summary"]["perf_failures"].as_u64(),
        "replacement_levels.json should consume smoke perf failure count"
    );
    assert_eq!(
        smoke_obligation["actual"]["signature_guard_failures"].as_u64(),
        smoke["summary"]["signature_guard_failures"].as_u64(),
        "replacement_levels.json should consume smoke signature-guard failure count"
    );
    assert_eq!(
        smoke_obligation["outcome"].as_str(),
        Some("pass"),
        "green strict/hardened smoke evidence must pass the L1 smoke obligation"
    );

    let blocked_obligations: Vec<_> = obligations
        .iter()
        .filter(|entry| entry["outcome"].as_str() == Some("blocked"))
        .filter_map(|entry| entry["id"].as_str())
        .collect();
    assert_eq!(
        blocked_obligations,
        Vec::<&str>::new(),
        "L1 objective gate should have no blocked obligations when smoke, CRT, and promotion controls pass"
    );
    let promotion_obligation = obligations
        .iter()
        .find(|entry| entry["id"].as_str() == Some("promotion_claim_control"))
        .expect("L1 objective gate should bind explicit promotion control");
    assert_eq!(promotion_obligation["outcome"].as_str(), Some("pass"));
    assert_eq!(
        promotion_obligation["actual"]["current_level"].as_str(),
        Some("L1")
    );
    assert_eq!(
        promotion_obligation["actual"]["release_tag_policy.current_release_level"].as_str(),
        Some("L1")
    );
    assert_eq!(objective_gate["status"].as_str(), Some("pass"));
    assert_eq!(levels["current_level"].as_str(), Some("L1"));
    assert_eq!(
        levels["release_tag_policy"]["current_release_level"].as_str(),
        Some("L1")
    );
}

#[test]
fn l1_crt_startup_tls_proof_matrix_validates_required_rows() {
    let matrix = load_l1_crt_startup_tls_matrix();
    let errors = match validate_l1_crt_startup_tls_matrix(&matrix) {
        Ok(()) => Vec::new(),
        Err(errors) => errors,
    };
    assert!(
        errors.is_empty(),
        "L1 CRT/startup/TLS proof matrix should validate: {errors:?}"
    );
}

#[test]
fn l1_crt_startup_tls_proof_matrix_rejects_missing_required_row() {
    let mut matrix = load_l1_crt_startup_tls_matrix();
    let rows = matrix["proof_rows"].as_array_mut().unwrap();
    rows.retain(|row| row["id"].as_str() != Some("secure_mode"));

    let errors = validate_l1_crt_startup_tls_matrix(&matrix)
        .expect_err("matrix missing a required proof row must fail");
    assert!(
        errors
            .iter()
            .any(|error| error.contains("missing required proof row secure_mode")),
        "missing-row error not found: {errors:?}"
    );
}

#[test]
fn l1_crt_startup_tls_proof_matrix_rejects_stale_evidence() {
    let mut matrix = load_l1_crt_startup_tls_matrix();
    let rows = matrix["proof_rows"].as_array_mut().unwrap();
    let startup = rows
        .iter_mut()
        .find(|row| row["id"].as_str() == Some("process_startup"))
        .expect("process_startup row must exist");
    startup["evidence_generated_at_utc"] = serde_json::json!("2000-01-01T00:00:00Z");

    let errors = validate_l1_crt_startup_tls_matrix(&matrix)
        .expect_err("stale evidence must fail validation");
    assert!(
        errors
            .iter()
            .any(|error| error.contains("evidence is stale")),
        "stale-evidence error not found: {errors:?}"
    );
}

#[test]
fn l1_crt_startup_tls_proof_matrix_rejects_contradictory_evidence() {
    let mut matrix = load_l1_crt_startup_tls_matrix();
    let rows = matrix["proof_rows"].as_array_mut().unwrap();
    let startup = rows
        .iter_mut()
        .find(|row| row["id"].as_str() == Some("process_startup"))
        .expect("process_startup row must exist");
    startup["promotion_decision"] = serde_json::json!("claim_blocked");

    let errors = validate_l1_crt_startup_tls_matrix(&matrix)
        .expect_err("contradictory evidence must fail validation");
    assert!(
        errors
            .iter()
            .any(|error| error.contains("contradicts promotion_decision")),
        "contradictory-evidence error not found: {errors:?}"
    );
}

#[test]
fn l1_crt_startup_tls_proof_matrix_rejects_missing_source_commit_policy() {
    let mut matrix = load_l1_crt_startup_tls_matrix();
    matrix
        .as_object_mut()
        .unwrap()
        .remove("source_commit_freshness_policy");

    let errors = validate_l1_crt_startup_tls_matrix(&matrix)
        .expect_err("matrix without source_commit_freshness_policy must fail validation");
    assert!(
        errors
            .iter()
            .any(|error| error.contains("source_commit_freshness_policy must be an object")),
        "missing source-commit policy error not found: {errors:?}"
    );
}

#[test]
fn l1_crt_startup_tls_proof_matrix_rejects_policy_that_allows_stale_evidence() {
    let mut matrix = load_l1_crt_startup_tls_matrix();
    matrix["source_commit_freshness_policy"]["startup_tls_matrix_evidence_allowed_when_stale"] =
        serde_json::json!(true);

    let errors = validate_l1_crt_startup_tls_matrix(&matrix)
        .expect_err("matrix policy that allows stale source commits must fail validation");
    assert!(
        errors.iter().any(|error| error.contains(
            "source_commit_freshness_policy.startup_tls_matrix_evidence_allowed_when_stale must be false"
        )),
        "stale-policy allowance error not found: {errors:?}"
    );
}

#[test]
fn stale_source_commit_policy_blocks_l1_crt_startup_tls_matrix_evidence() {
    let matrix = load_l1_crt_startup_tls_matrix();
    let source_commit = matrix["source_commit"]
        .as_str()
        .expect("source_commit must be present");
    assert!(
        source_commit == "current" || is_full_git_commit(source_commit),
        "source_commit must be current or a 40-hex commit, got {source_commit:?}"
    );
    let current_head = git_head(&workspace_root()).expect("git HEAD should be readable");
    let policy = l1_crt_startup_tls_source_commit_policy(&matrix)
        .expect("source_commit_freshness_policy must be present");
    if !source_commit_is_current(source_commit, &current_head) {
        assert_eq!(
            policy["stale_result"].as_str(),
            Some("block_l1_crt_startup_tls_proof_matrix_evidence"),
            "stale source commits must block L1 CRT/startup/TLS matrix evidence",
        );
        assert_eq!(
            policy["startup_tls_matrix_evidence_allowed_when_stale"].as_bool(),
            Some(false),
            "stale source commits must not allow L1 CRT/startup/TLS matrix evidence",
        );
        assert_eq!(
            policy["rejected_evidence_kind"].as_str(),
            Some("stale_source_commit"),
            "stale source commits must use the stale_source_commit rejection kind",
        );
    }
}

#[test]
fn l1_crt_startup_tls_proof_matrix_rejects_stale_recorded_source_commit() {
    let mut matrix = load_l1_crt_startup_tls_matrix();
    matrix["source_commit"] = serde_json::json!("0000000000000000000000000000000000000000");

    let errors = validate_l1_crt_startup_tls_matrix(&matrix)
        .expect_err("stale matrix source_commit must fail validation");
    assert!(
        errors.iter().any(|error| {
            error.contains("source_commit must be 'current' or match current git HEAD")
        }),
        "stale source_commit error not found: {errors:?}"
    );
}

#[test]
fn gate_script_rejects_stale_l1_crt_startup_tls_source_commit() {
    let root = workspace_root();
    let script = root.join("scripts/check_replacement_levels.sh");
    let mut matrix = load_l1_crt_startup_tls_matrix();
    matrix["source_commit"] = serde_json::json!("0000000000000000000000000000000000000000");
    let matrix_path = unique_temp_path("l1-crt-startup-tls-stale-source", ".json");
    std::fs::write(
        &matrix_path,
        serde_json::to_string_pretty(&matrix).expect("matrix should serialize"),
    )
    .expect("stale matrix fixture should be writable");
    let report_path = unique_temp_path("replacement-levels-stale-source-report", ".json");
    let log_path = unique_temp_path("replacement-levels-stale-source-log", ".jsonl");

    let output = Command::new(&script)
        .env("FLC_L1_CRT_MATRIX_PATH", &matrix_path)
        .env("FLC_REPLACEMENT_LEVELS_REPORT_PATH", &report_path)
        .env("FLC_REPLACEMENT_LEVELS_LOG_PATH", &log_path)
        .output()
        .expect("replacement-level script should run");

    assert!(
        !output.status.success(),
        "stale matrix source_commit should fail replacement-level gate"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("source_commit must be 'current' or match current git HEAD"),
        "stale source_commit failure should be reported in stdout:\n{stdout}"
    );
}

#[test]
fn gate_script_refreshes_l1_objective_gate_artifacts() {
    let root = workspace_root();
    let script = root.join("scripts/check_replacement_levels.sh");
    let report_path = unique_temp_path("replacement-levels-report", ".json");
    let log_path = unique_temp_path("replacement-levels-log", ".jsonl");

    let output = Command::new(&script)
        .env("FLC_REPLACEMENT_LEVELS_REPORT_PATH", &report_path)
        .env("FLC_REPLACEMENT_LEVELS_LOG_PATH", &log_path)
        .current_dir(&root)
        .output()
        .expect("failed to run check_replacement_levels.sh");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "check_replacement_levels.sh should pass\nstdout={stdout}\nstderr={stderr}"
    );
    assert!(
        stdout.contains("PASS: Structured L1 objective gate artifacts refreshed"),
        "gate script should report refreshed L1 artifacts\nstdout={stdout}"
    );
    assert!(
        report_path.exists(),
        "replacement-level report was not written to {:?}",
        report_path
    );
    assert!(
        log_path.exists(),
        "replacement-level log was not written to {:?}",
        log_path
    );

    let report: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&report_path).expect("failed to read replacement-level report"),
    )
    .expect("replacement-level report is not valid JSON");
    assert_eq!(
        report["bead_id"].as_str(),
        Some("bd-gtf.4"),
        "L1 gate report must be attributed to bd-gtf.4"
    );
    assert_eq!(
        report["gate_id"].as_str(),
        Some("replacement_levels_l1_gate"),
        "unexpected gate_id in replacement-level report"
    );
    assert_eq!(
        report["status"].as_str(),
        Some("pass"),
        "replacement-level consistency gate should succeed for the checked-in artifacts"
    );
    assert_eq!(
        report["objective_gate_status"].as_str(),
        Some("pass"),
        "replacement-level report should surface the passing objective gate"
    );
    let script_checks = report["script_checks"]
        .as_array()
        .expect("report.script_checks must be an array");
    assert_eq!(
        script_checks.len(),
        8,
        "expected eight script checks in report"
    );
    assert!(
        script_checks
            .iter()
            .all(|check| check["outcome"].as_str() == Some("pass")),
        "all script checks should pass for the checked-in replacement-level artifacts"
    );

    let log_lines =
        std::fs::read_to_string(&log_path).expect("failed to read replacement-level log");
    let rows: Vec<serde_json::Value> = log_lines
        .lines()
        .map(|line| serde_json::from_str(line).expect("replacement-level log row is invalid JSON"))
        .collect();
    assert!(
        !rows.is_empty(),
        "replacement-level log should contain at least one structured row"
    );
    let mut saw_l1_crt_matrix_row = false;
    for row in rows {
        if row["source"].as_str() == Some("l1_crt_startup_tls_proof_matrix") {
            saw_l1_crt_matrix_row = true;
            assert_eq!(row["bead_id"].as_str(), Some("bd-bp8fl.6.3"));
            for field in L1_CRT_REQUIRED_LOG_FIELDS {
                assert!(
                    row.get(*field).is_some(),
                    "L1 CRT proof row missing required log field {field}: {row:?}"
                );
            }
        } else {
            assert_eq!(row["bead_id"].as_str(), Some("bd-gtf.4"));
        }
        assert!(
            row["trace_id"].as_str().is_some(),
            "log row missing trace_id"
        );
        assert!(
            row["artifact_ref"].as_str().is_some(),
            "log row missing artifact_ref"
        );
    }
    assert!(
        saw_l1_crt_matrix_row,
        "replacement-level log should include L1 CRT/startup/TLS proof matrix rows"
    );

    let _ = std::fs::remove_file(report_path);
    let _ = std::fs::remove_file(log_path);
}
