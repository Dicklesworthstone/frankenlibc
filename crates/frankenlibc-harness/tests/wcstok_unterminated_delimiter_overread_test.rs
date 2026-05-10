//! Conformance gate for the wcstok unterminated-delimiter overread
//! fix (bd-0cjqo / completion-debt bd-0cjqo.1).
//!
//! Pins, at conformance level, that frankenlibc-abi's wcstok:
//! 1. Bounds delimiter scans by `malloc_abi::known_remaining`.
//! 2. Calls `scan_w_string(delim, delim_bound)` — not the unbounded
//!    variant.
//! 3. Rejects tracked-unterminated delimiters BEFORE constructing the
//!    delim slice that previously caused an out-of-bounds read.
//! 4. Has a passing ABI-level regression test
//!    `wcstok_rejects_tracked_unterminated_delimiter`.
//!
//! Strategy: the harness crate doesn't link the ABI's runtime
//! (private membrane state etc.), so we pin the contract at SOURCE
//! level via substring guards on the wchar_abi.rs implementation +
//! grep the ABI integration test file for the regression test name.
//! This is the same shape used by other source-pinning conformance
//! gates in this repo (e.g. ABI no-mangle export gap allowlist).

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
        .join("wcstok_unterminated_delimiter_overread.v1.json")
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

fn extract_wcstok_body(src: &str) -> TestResult<&str> {
    // Lift just the body of the `pub unsafe extern "C" fn wcstok`
    // function so a guard match isn't satisfied by an unrelated
    // helper or a comment elsewhere in the file.
    let header = "pub unsafe extern \"C\" fn wcstok(";
    let start = src
        .find(header)
        .ok_or_else(|| format!("could not locate `{header}` in wchar_abi.rs"))?;
    // Walk forward to find the opening `{` of the body and then
    // brace-match to its closing `}` at the matching depth.
    let body_start = src[start..]
        .find('{')
        .ok_or_else(|| "no opening brace after wcstok header".to_string())?
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
        return Err("unbalanced braces while extracting wcstok body".to_string());
    }
    Ok(&src[body_start..end])
}

#[test]
fn manifest_anchors_to_0cjqo_with_completion_debt_bead() -> TestResult {
    let m = load_manifest()?;
    require(
        json_string(&m, "manifest_id")? == "wcstok-unterminated-delimiter-overread",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-0cjqo", "bead")?;
    require(
        json_string(&m, "completion_debt_bead")? == "bd-0cjqo.1",
        "completion_debt_bead",
    )?;
    require(
        json_string(&m, "vulnerable_function")? == "frankenlibc_abi::wchar_abi::wcstok",
        "vulnerable_function",
    )?;
    require(
        json_string(&m, "vulnerable_file")? == "crates/frankenlibc-abi/src/wchar_abi.rs",
        "vulnerable_file",
    )?;
    require(
        json_string(&m, "regression_test_function")?
            == "wcstok_rejects_tracked_unterminated_delimiter",
        "regression_test_function",
    )?;
    require(
        json_string(&m, "regression_test_file")?
            == "crates/frankenlibc-abi/tests/wchar_abi_test.rs",
        "regression_test_file",
    )
}

#[test]
fn manifest_policy_pins_required_invariants() -> TestResult {
    let m = load_manifest()?;
    let policy = m
        .get("policy")
        .ok_or_else(|| "missing policy".to_string())?;
    for f in [
        "fail_closed_when_guard_missing",
        "fail_closed_when_regression_test_missing",
        "regression_test_must_assert_null_token_and_null_save_ptr",
    ] {
        require(json_bool(policy, f)?, format!("{f} must be true"))?;
    }
    let kinds = m
        .get("rejected_evidence_kinds")
        .and_then(Value::as_array)
        .ok_or_else(|| "missing rejected_evidence_kinds".to_string())?;
    let names: Vec<&str> = kinds.iter().filter_map(Value::as_str).collect();
    for k in [
        "missing_known_remaining_guard",
        "missing_scan_w_string_bounded_call",
        "missing_unterminated_reject_before_slice",
        "missing_regression_test",
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
        json_string(aref, "missing_item_id")? == "tests.conformance.primary",
        "audit_reference.missing_item_id",
    )?;
    require(
        aref.get("score_before").and_then(Value::as_u64) == Some(470),
        "score_before",
    )?;
    require(
        aref.get("score_threshold").and_then(Value::as_u64) == Some(700),
        "score_threshold",
    )
}

#[test]
fn wcstok_implementation_uses_known_remaining_to_bound_delim_scan() -> TestResult {
    let root = workspace_root()?;
    let src = read_file(&root, "crates/frankenlibc-abi/src/wchar_abi.rs")?;
    let body = extract_wcstok_body(&src)?;
    let m = load_manifest()?;
    let guards = m
        .get("required_guards")
        .and_then(Value::as_array)
        .ok_or_else(|| "missing required_guards".to_string())?;
    for g in guards {
        let id = json_string(g, "id")?;
        let pat = json_string(g, "match_substring")?;
        require(
            body.contains(pat),
            format!(
                "wcstok body missing required guard `{id}` (substring `{pat}` not found in wcstok body)"
            ),
        )?;
    }
    Ok(())
}

#[test]
fn wcstok_unterminated_reject_precedes_slice_construction() -> TestResult {
    // Stronger guard: the unterminated-reject `if !delim_terminated`
    // branch MUST appear before the `slice::from_raw_parts(delim,
    // delim_len)` construction — that ordering is what makes the
    // fix sound. If the slice is constructed first, the OOB read can
    // happen even with the guard present.
    let root = workspace_root()?;
    let src = read_file(&root, "crates/frankenlibc-abi/src/wchar_abi.rs")?;
    let body = extract_wcstok_body(&src)?;
    let reject_idx = body
        .find("if !delim_terminated")
        .ok_or_else(|| "wcstok body missing `if !delim_terminated`".to_string())?;
    let slice_idx = body
        .find("slice::from_raw_parts(delim, delim_len)")
        .ok_or_else(|| {
            "wcstok body missing `slice::from_raw_parts(delim, delim_len)` construction".to_string()
        })?;
    require(
        reject_idx < slice_idx,
        format!(
            "unterminated-reject branch (offset {reject_idx}) must precede delim slice construction (offset {slice_idx}) — reordering would re-introduce the overread"
        ),
    )
}

#[test]
fn regression_test_function_exists_in_wchar_abi_test_file() -> TestResult {
    let root = workspace_root()?;
    let src = read_file(&root, "crates/frankenlibc-abi/tests/wchar_abi_test.rs")?;
    require(
        src.contains("fn wcstok_rejects_tracked_unterminated_delimiter"),
        "wchar_abi_test.rs must contain the regression test `fn wcstok_rejects_tracked_unterminated_delimiter`",
    )?;
    // The regression test must assert both (a) the returned token
    // pointer is null AND (b) the save_ptr is null. Either alone
    // would be insufficient: a non-null save_ptr would still let a
    // subsequent wcstok call walk into the tracked-unterminated
    // memory.
    require(
        src.contains("assert!(tok.is_null());"),
        "regression test must assert `tok.is_null()`",
    )?;
    require(
        src.contains("assert!(save.is_null());"),
        "regression test must assert `save.is_null()`",
    )
}
