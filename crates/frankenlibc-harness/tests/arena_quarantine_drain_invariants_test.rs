//! Conformance gate for the AllocationArena quarantine-drain
//! invariants (bd-66wz.1 / completion-debt bd-66wz.1.1).
//!
//! Pins, at conformance level, that frankenlibc-membrane's
//! AllocationArena::drain_quarantine:
//! 1. Pops entries from the FRONT (FIFO order) while either bytes
//!    pressure is over QUARANTINE_MAX_BYTES OR the entry count is
//!    over quarantine_controller::current_depth().
//! 2. Marks each evicted slot SafetyState::Freed (so a UAF lookup of
//!    the evicted address reports Freed, not Quarantined).
//! 3. Returns the evicted entries to the caller.
//!
//! Plus pins that the two unit tests
//! `quarantine_drain_evicts_oldest_when_entry_count_exceeded` and
//! `quarantine_drain_evicts_oldest_until_within_budget` exist in
//! arena.rs's `mod tests`.

use std::path::{Path, PathBuf};

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

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
        .join("arena_quarantine_drain_invariants.v1.json")
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

fn json_string<'a>(value: &'a Value, field: &str) -> TestResult<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing or non-string `{field}`"))
}

fn json_bool(value: &Value, field: &str) -> TestResult<bool> {
    value
        .get(field)
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("missing or non-bool `{field}`"))
}

fn read_file(root: &Path, rel: &str) -> TestResult<String> {
    let p = root.join(rel);
    std::fs::read_to_string(&p).map_err(|e| format!("read {p:?}: {e}"))
}

fn extract_drain_quarantine_body(src: &str) -> TestResult<&str> {
    let header = "fn drain_quarantine(&self, shard: &mut ArenaShard)";
    let start = src
        .find(header)
        .ok_or_else(|| format!("could not locate `{header}` in arena.rs"))?;
    let body_start = src[start..]
        .find('{')
        .ok_or_else(|| "no opening brace after drain_quarantine header".to_string())?
        + start;
    let bytes = src.as_bytes();
    let mut depth: i32 = 0;
    let mut end = body_start;
    for (i, &b) in bytes.iter().enumerate().skip(body_start) {
        match b {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    end = i + 1;
                    break;
                }
            }
            _ => {}
        }
    }
    if depth != 0 {
        return Err("unbalanced braces while extracting drain_quarantine body".to_string());
    }
    Ok(&src[body_start..end])
}

#[test]
fn manifest_anchors_to_66wz_1_with_completion_debt_bead() -> TestResult {
    let m = load_manifest()?;
    require(
        json_string(&m, "manifest_id")? == "arena-quarantine-drain-invariants",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-66wz.1", "bead")?;
    require(
        json_string(&m, "completion_debt_bead")? == "bd-66wz.1.1",
        "completion_debt_bead",
    )?;
    require(
        json_string(&m, "code_artifact_function")?
            == "frankenlibc_membrane::arena::AllocationArena::drain_quarantine",
        "code_artifact_function",
    )?;
    require(
        json_string(&m, "code_artifact_file")? == "crates/frankenlibc-membrane/src/arena.rs",
        "code_artifact_file",
    )?;
    require(
        json_string(&m, "primary_unit_test_function")?
            == "quarantine_drain_evicts_oldest_when_entry_count_exceeded",
        "primary_unit_test_function",
    )?;
    require(
        json_string(&m, "secondary_unit_test_function")?
            == "quarantine_drain_evicts_oldest_until_within_budget",
        "secondary_unit_test_function",
    )
}

#[test]
fn manifest_policy_pins_required_invariants() -> TestResult {
    let m = load_manifest()?;
    let policy = m
        .get("policy")
        .ok_or_else(|| "missing policy".to_string())?;
    for f in [
        "fail_closed_when_invariant_missing",
        "fail_closed_when_unit_tests_missing",
        "drain_must_be_fifo",
        "drain_must_respect_quarantine_controller_depth",
    ] {
        require(json_bool(policy, f)?, format!("{f} must be true"))?;
    }
    let kinds = m
        .get("rejected_evidence_kinds")
        .and_then(Value::as_array)
        .ok_or_else(|| "missing rejected_evidence_kinds".to_string())?;
    let names: Vec<&str> = kinds.iter().filter_map(Value::as_str).collect();
    for k in [
        "missing_drain_invariant",
        "missing_primary_unit_test",
        "missing_secondary_unit_test",
        "drain_uses_pop_back_instead_of_pop_front",
    ] {
        require(
            names.contains(&k),
            format!("rejected_evidence_kinds missing {k}"),
        )?;
    }
    Ok(())
}

#[test]
fn manifest_audit_reference_pins_pre_repair_score() -> TestResult {
    let m = load_manifest()?;
    let aref = m
        .get("audit_reference")
        .ok_or_else(|| "missing audit_reference".to_string())?;
    require(
        json_string(aref, "pass")? == "2026-05-10T03-16-16Z",
        "audit_reference.pass",
    )?;
    require(
        json_string(aref, "missing_item_id")? == "tests.unit.primary",
        "audit_reference.missing_item_id",
    )?;
    require(
        aref.get("score_before").and_then(Value::as_u64) == Some(285),
        "score_before",
    )?;
    require(
        aref.get("score_threshold").and_then(Value::as_u64) == Some(700),
        "score_threshold",
    )
}

#[test]
fn drain_quarantine_body_satisfies_required_invariants() -> TestResult {
    let root = workspace_root()?;
    let src = read_file(&root, "crates/frankenlibc-membrane/src/arena.rs")?;
    let body = extract_drain_quarantine_body(&src)?;
    let m = load_manifest()?;
    let invariants = m
        .get("required_invariants")
        .and_then(Value::as_array)
        .ok_or_else(|| "missing required_invariants".to_string())?;
    for inv in invariants {
        let id = json_string(inv, "id")?;
        let pat = json_string(inv, "match_substring")?;
        require(
            body.contains(pat),
            format!(
                "drain_quarantine body missing required invariant `{id}` (substring `{pat}` not found)"
            ),
        )?;
    }
    // Stronger: drain_quarantine must NOT use pop_back (which would
    // make the eviction LIFO, defeating FIFO oldest-first semantics).
    require(
        !body.contains("pop_back"),
        "drain_quarantine must not call pop_back — FIFO oldest-first eviction is the contract",
    )
}

#[test]
fn primary_unit_test_function_exists_in_arena_rs() -> TestResult {
    let root = workspace_root()?;
    let src = read_file(&root, "crates/frankenlibc-membrane/src/arena.rs")?;
    require(
        src.contains("fn quarantine_drain_evicts_oldest_when_entry_count_exceeded"),
        "arena.rs must contain unit test `fn quarantine_drain_evicts_oldest_when_entry_count_exceeded`",
    )?;
    // Stronger: the unit test must explicitly assert FIFO ordering by
    // checking the drained entry's user_base equals oldest_user.
    require(
        src.contains(
            "\"expected oldest entry to be drained first when count threshold is exceeded\"",
        ),
        "primary unit test must assert oldest entry drained first",
    )
}

#[test]
fn secondary_unit_test_function_exists_in_arena_rs() -> TestResult {
    let root = workspace_root()?;
    let src = read_file(&root, "crates/frankenlibc-membrane/src/arena.rs")?;
    require(
        src.contains("fn quarantine_drain_evicts_oldest_until_within_budget"),
        "arena.rs must contain unit test `fn quarantine_drain_evicts_oldest_until_within_budget`",
    )?;
    require(
        src.contains("\"expected oldest quarantine entry to be drained first\""),
        "secondary unit test must assert oldest entry drained first",
    )?;
    require(
        src.contains("\"expected quarantine bytes within budget after drain\""),
        "secondary unit test must assert quarantine bytes within budget after drain",
    )
}
