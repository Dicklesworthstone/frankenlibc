//! Golden artifact: SHA-256 fingerprint of FrankenLibC's errno table
//! (bd-nfjj0).
//!
//! `tests/conformance/errno_table_golden.v1.json` freezes:
//!
//!   * `total_constant_count` — number of `pub const E*: i32` rows in
//!     `crates/frankenlibc-core/src/errno/mod.rs`.
//!   * `total_message_count` — number of `strerror_message` rows covered
//!     by 0 plus every parsed errno constant value.
//!   * `constants_sha256` — SHA-256 over canonical
//!     `<NAME>=<number>\n` lines sorted by errno name.
//!   * `messages_sha256` — SHA-256 over canonical
//!     `<number>=<message>\n` lines sorted by numeric errno.
//!
//! Any silent renumber, addition, deletion, or message rewording fails
//! one of these exact-golden checks.

use frankenlibc_core::errno::strerror_message;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
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

fn read_text(path: &Path) -> Result<String, Box<dyn Error>> {
    std::fs::read_to_string(path)
        .map_err(|err| test_error(format!("{} should be readable: {err}", path.display())))
}

fn load_json(path: &Path) -> Result<Value, Box<dyn Error>> {
    let content = read_text(path)?;
    serde_json::from_str(&content)
        .map_err(|err| test_error(format!("{} should parse as JSON: {err}", path.display())))
}

fn errno_source_path() -> PathBuf {
    workspace_root().join("crates/frankenlibc-core/src/errno/mod.rs")
}

fn golden_path() -> PathBuf {
    workspace_root().join("tests/conformance/errno_table_golden.v1.json")
}

fn parse_errno_constants(source: &str) -> Result<BTreeMap<String, i32>, Box<dyn Error>> {
    let mut constants = BTreeMap::new();
    for (line_number, raw) in source.lines().enumerate() {
        let line = raw.trim();
        let Some(rest) = line.strip_prefix("pub const ") else {
            continue;
        };
        let Some((name_and_ty, value_with_semicolon)) = rest.split_once(" = ") else {
            continue;
        };
        let Some(name) = name_and_ty.strip_suffix(": i32") else {
            continue;
        };
        if !name.starts_with('E')
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        {
            continue;
        }
        let value_text = value_with_semicolon.strip_suffix(';').ok_or_else(|| {
            test_error(format!(
                "errno constant line {} must end with ';': {line}",
                line_number + 1
            ))
        })?;
        let value: i32 = value_text.parse().map_err(|err| {
            test_error(format!(
                "errno constant line {} has invalid value {value_text:?}: {err}",
                line_number + 1
            ))
        })?;
        ensure(
            constants.insert(name.to_owned(), value).is_none(),
            format!("duplicate errno constant name {name}"),
        )?;
    }
    Ok(constants)
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn sha256_canonical_lines(lines: &[String]) -> String {
    let mut canonical = lines.join("\n");
    canonical.push('\n');
    let digest = Sha256::digest(canonical.as_bytes());
    hex_lower(&digest)
}

fn constants_canonical_lines(constants: &BTreeMap<String, i32>) -> Vec<String> {
    constants
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect()
}

fn message_canonical_lines(constants: &BTreeMap<String, i32>) -> Vec<String> {
    let mut numbers: BTreeSet<i32> = constants.values().copied().collect();
    numbers.insert(0);
    numbers
        .into_iter()
        .map(|number| format!("{number}={}", strerror_message(number)))
        .collect()
}

fn golden_u64(golden: &Value, key: &str) -> Result<u64, Box<dyn Error>> {
    golden[key]
        .as_u64()
        .ok_or_else(|| test_error(format!("{key} must be a u64")))
}

fn golden_str<'a>(golden: &'a Value, key: &str) -> Result<&'a str, Box<dyn Error>> {
    golden[key]
        .as_str()
        .ok_or_else(|| test_error(format!("{key} must be a string")))
}

#[test]
fn errno_table_golden_artifact_is_well_formed() -> TestResult {
    let golden = load_json(&golden_path())?;
    ensure_eq(
        golden["schema_version"].as_str(),
        Some("v1"),
        "schema_version",
    )?;
    ensure_eq(golden["bead"].as_str(), Some("bd-nfjj0"), "bead")?;
    ensure(
        !golden_str(&golden, "source_commit")?.is_empty(),
        "source_commit must be set",
    )?;
    ensure_eq(
        golden["subject"]["module"].as_str(),
        Some("crates/frankenlibc-core/src/errno/mod.rs"),
        "subject.module",
    )?;
    ensure_eq(
        golden["golden_confidence"]["strategy"].as_str(),
        Some("exact_sha256_over_canonical_lines"),
        "golden_confidence.strategy",
    )?;
    for key in ["constants_sha256", "messages_sha256"] {
        let digest = golden_str(&golden, key)?;
        ensure(
            digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()),
            format!("{key} must be a 64-character hex SHA-256 digest"),
        )?;
    }
    Ok(())
}

#[test]
fn errno_constants_fingerprint_matches_golden() -> TestResult {
    let golden = load_json(&golden_path())?;
    let source = read_text(&errno_source_path())?;
    let constants = parse_errno_constants(&source)?;
    ensure(
        constants.len() >= 50,
        format!(
            "errno parser must find a non-trivial constant table; got {} rows",
            constants.len()
        ),
    )?;

    let live_count = constants.len() as u64;
    ensure_eq(
        live_count,
        golden_u64(&golden, "total_constant_count")?,
        "total_constant_count",
    )?;

    let live_hash = sha256_canonical_lines(&constants_canonical_lines(&constants));
    ensure_eq(
        live_hash.as_str(),
        golden_str(&golden, "constants_sha256")?,
        "constants_sha256 drift: errno numeric assignments changed. Update the golden only with an intentional errno compatibility review.",
    )
}

#[test]
fn strerror_messages_fingerprint_matches_golden() -> TestResult {
    let golden = load_json(&golden_path())?;
    let source = read_text(&errno_source_path())?;
    let constants = parse_errno_constants(&source)?;
    let message_lines = message_canonical_lines(&constants);

    ensure_eq(
        message_lines.len() as u64,
        golden_u64(&golden, "total_message_count")?,
        "total_message_count",
    )?;
    ensure(
        message_lines.iter().any(|line| line == "0=Success"),
        "message table must include 0=Success",
    )?;
    ensure(
        message_lines
            .iter()
            .all(|line| !line.ends_with("=Unknown error")),
        "every frozen errno constant must have a specific strerror_message entry",
    )?;

    let live_hash = sha256_canonical_lines(&message_lines);
    ensure_eq(
        live_hash.as_str(),
        golden_str(&golden, "messages_sha256")?,
        "messages_sha256 drift: strerror_message output changed. Update the golden only with an intentional errno compatibility review.",
    )
}

#[test]
fn unknown_errno_fallback_stays_outside_the_golden_table() {
    assert_eq!(strerror_message(9999), "Unknown error");
}
