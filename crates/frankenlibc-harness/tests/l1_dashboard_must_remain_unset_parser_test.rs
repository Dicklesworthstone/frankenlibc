//! Integration test: parse and enforce the L1 dashboard's
//! `must_remain_unset_until_all_rows_pass` constraint sentences
//! (bd-fiq8r).
//!
//! The dashboard manifest (`tests/conformance/l1_dry_run_readiness_dashboard.v1.json`)
//! lists human-readable sentences such as:
//!
//!     "replacement_levels.current_level == L2"
//!
//! describing higher replacement states that this L1 dashboard must not
//! claim implicitly. Every live artifact must NEGATE each cited constraint:
//! current_level must not currently equal L2, and release_tag_policy
//! current_release_level must not currently equal L2. The previous test
//! only substring-checked for keywords; this test
//! parses each sentence into (artifact_key, dotted_path, op, expected),
//! resolves the path against the cited inputs[artifact_key] artifact,
//! and asserts the live value does NOT satisfy the cited equality
//! (i.e. the must-remain-unset invariant holds today).

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

fn load_json(path: &Path) -> Result<Value, Box<dyn Error>> {
    let content = std::fs::read_to_string(path)
        .map_err(|err| test_error(format!("{} should be readable: {err}", path.display())))?;
    serde_json::from_str(&content)
        .map_err(|err| test_error(format!("{} should parse as JSON: {err}", path.display())))
}

fn dashboard_path() -> PathBuf {
    workspace_root().join("tests/conformance/l1_dry_run_readiness_dashboard.v1.json")
}

#[derive(Debug)]
struct ParsedConstraint<'a> {
    raw: &'a str,
    artifact_key: String,
    field_path: String,
    op: ConstraintOp,
    expected: String,
}

#[derive(Debug, PartialEq, Eq)]
enum ConstraintOp {
    Eq,
    Ne,
}

/// Parse a sentence like `replacement_levels.current_level == L2` or
/// `release_tag_policy.current_release_level != L2`. Returns the parts
/// the test will resolve in the dashboard inputs map.
fn parse_constraint(s: &str) -> Result<ParsedConstraint<'_>, Box<dyn Error>> {
    let (lhs, op, rhs) = if let Some((l, r)) = s.split_once(" == ") {
        (l.trim(), ConstraintOp::Eq, r.trim())
    } else if let Some((l, r)) = s.split_once(" != ") {
        (l.trim(), ConstraintOp::Ne, r.trim())
    } else {
        return Err(test_error(format!(
            "constraint sentence {s:?} must contain ' == ' or ' != '"
        )));
    };
    let (artifact, path) = lhs.split_once('.').ok_or_else(|| {
        test_error(format!(
            "constraint LHS {lhs:?} must be of form `<artifact>.<dotted-path>`"
        ))
    })?;
    if path.is_empty() {
        return Err(test_error(format!(
            "constraint LHS {lhs:?} dotted-path empty after `<artifact>.`"
        )));
    }
    Ok(ParsedConstraint {
        raw: s,
        artifact_key: artifact.to_string(),
        field_path: path.to_string(),
        op,
        expected: rhs.to_string(),
    })
}

fn select_field<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cursor = root;
    for segment in path.split('.') {
        cursor = match cursor {
            Value::Object(map) => map.get(segment)?,
            _ => return None,
        };
    }
    Some(cursor)
}

#[test]
fn every_must_remain_unset_sentence_parses_into_artifact_field_op_expected() -> TestResult {
    let dashboard = load_json(&dashboard_path())?;
    let sentences = dashboard["policy"]["must_remain_unset_until_all_rows_pass"]
        .as_array()
        .ok_or_else(|| {
            test_error("policy.must_remain_unset_until_all_rows_pass must be an array")
        })?;
    ensure(
        !sentences.is_empty(),
        "policy.must_remain_unset_until_all_rows_pass must declare at least one constraint",
    )?;
    for entry in sentences {
        let s = entry.as_str().ok_or_else(|| {
            test_error("must_remain_unset_until_all_rows_pass entry must be a string")
        })?;
        let parsed = parse_constraint(s)?;
        ensure(
            !parsed.artifact_key.is_empty(),
            format!("constraint {s:?}: artifact_key empty"),
        )?;
        ensure(
            !parsed.expected.is_empty(),
            format!("constraint {s:?}: expected empty"),
        )?;
    }
    Ok(())
}

#[test]
fn every_must_remain_unset_eq_constraint_is_currently_false_in_live_artifact() -> TestResult {
    // The dashboard cites `<artifact>.<field> == L2` as the higher-level
    // end-state this L1 dashboard cannot claim. Every live artifact MUST
    // currently FAIL the equality. If the live value already equals the
    // cited target, the dashboard's "must remain unset" guarantee has been
    // silently broken.
    let dashboard = load_json(&dashboard_path())?;
    let inputs = dashboard["inputs"]
        .as_object()
        .ok_or_else(|| test_error("dashboard.inputs must be an object"))?;
    let sentences = dashboard["policy"]["must_remain_unset_until_all_rows_pass"]
        .as_array()
        .ok_or_else(|| {
            test_error("policy.must_remain_unset_until_all_rows_pass must be an array")
        })?;
    let root = workspace_root();
    for entry in sentences {
        let s = entry
            .as_str()
            .ok_or_else(|| test_error("must_remain_unset entry must be a string"))?;
        let parsed = parse_constraint(s)?;
        if parsed.op != ConstraintOp::Eq {
            // != constraints describe what must be permanently true and
            // are not addressed by this guard; skip cleanly.
            continue;
        }
        let artifact_path = inputs
            .get(&parsed.artifact_key)
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                test_error(format!(
                    "constraint {s:?}: artifact_key {} not in dashboard.inputs",
                    parsed.artifact_key
                ))
            })?;
        let abs = root.join(artifact_path);
        ensure(
            abs.exists(),
            format!("constraint {s:?}: cited artifact {artifact_path} missing on disk"),
        )?;
        let json = load_json(&abs)?;
        let actual = select_field(&json, &parsed.field_path).ok_or_else(|| {
            test_error(format!(
                "constraint {} : field path {} did not resolve in {}",
                parsed.raw, parsed.field_path, artifact_path
            ))
        })?;
        let actual_str = match actual {
            Value::String(s) => s.clone(),
            Value::Bool(b) => b.to_string(),
            Value::Number(n) => n.to_string(),
            other => other.to_string(),
        };
        ensure(
            actual_str != parsed.expected,
            format!(
                "must_remain_unset constraint VIOLATED: {} resolved to {} == {} in {}; the dashboard claims this state should NOT yet hold",
                parsed.raw, parsed.field_path, parsed.expected, artifact_path
            ),
        )?;
    }
    Ok(())
}

#[test]
fn parse_constraint_rejects_malformed_sentences() {
    // Negative parser cases: each input must NOT parse cleanly.
    let bad: &[&str] = &[
        "replacement_levels.current_level", // no operator
        "==L1",                             // empty LHS / no space
        "replacement_levels == L1",         // no dotted-path after artifact
        "replacement_levels. == L1",        // dotted-path empty
        "current_level == L1",              // no `<artifact>.` prefix (no dot)
    ];
    for input in bad {
        let result = parse_constraint(input);
        assert!(
            result.is_err(),
            "expected parse_constraint({input:?}) to fail; got {result:?}"
        );
    }
}

#[test]
fn parse_constraint_accepts_eq_and_ne_forms() -> TestResult {
    let eq = parse_constraint("replacement_levels.current_level == L1")?;
    assert_eq!(eq.artifact_key, "replacement_levels");
    assert_eq!(eq.field_path, "current_level");
    assert_eq!(eq.op, ConstraintOp::Eq);
    assert_eq!(eq.expected, "L1");

    let ne = parse_constraint("replacement_levels.release_tag_policy.current_release_level != L1")?;
    assert_eq!(ne.artifact_key, "replacement_levels");
    assert_eq!(ne.field_path, "release_tag_policy.current_release_level");
    assert_eq!(ne.op, ConstraintOp::Ne);
    assert_eq!(ne.expected, "L1");
    Ok(())
}
