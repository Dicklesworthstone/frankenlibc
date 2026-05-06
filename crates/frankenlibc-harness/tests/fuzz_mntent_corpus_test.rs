//! Regression coverage for the fuzz_mntent seed corpus.

use frankenlibc_core::mntent::{has_mnt_opt, parse_mntent_line};
use std::error::Error;
use std::fmt::Debug;
use std::path::{Path, PathBuf};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

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
    T: PartialEq + Debug,
{
    if actual == expected {
        Ok(())
    } else {
        Err(test_error(format!(
            "{} mismatch: got {actual:?}, expected {expected:?}",
            context.into()
        )))
    }
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn corpus_dir() -> PathBuf {
    repo_root().join("crates/frankenlibc-fuzz/corpus/fuzz_mntent")
}

fn read_seed(name: &str) -> TestResult<Vec<u8>> {
    let path = corpus_dir().join(name);
    std::fs::read(&path)
        .map_err(|err| test_error(format!("failed to read {}: {err}", path.display())))
}

fn split_option_seed(seed: &[u8]) -> TestResult<(&[u8], &[u8])> {
    let marker = b"\n---\n";
    let split_at = seed
        .windows(marker.len())
        .position(|window| window == marker)
        .ok_or_else(|| test_error("option seed must contain delimiter"))?;
    let needle_start = split_at
        .checked_add(marker.len())
        .ok_or_else(|| test_error("option seed delimiter offset overflowed"))?;
    let opts = seed
        .get(..split_at)
        .ok_or_else(|| test_error("option seed opts range is invalid"))?;
    let needle = seed
        .get(needle_start..)
        .ok_or_else(|| test_error("option seed needle range is invalid"))?;
    Ok((opts, needle.strip_suffix(b"\n").unwrap_or(needle)))
}

#[test]
fn fuzz_mntent_corpus_exists_and_has_minimal_edges() -> TestResult {
    let entries = std::fs::read_dir(corpus_dir())
        .map_err(|err| test_error(format!("fuzz_mntent corpus directory must exist: {err}")))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| {
            test_error(format!(
                "fuzz_mntent corpus entries must be readable: {err}"
            ))
        })?;

    ensure(
        entries.len() >= 6,
        "fuzz_mntent needs parser and option-token seeds",
    )
}

#[test]
fn fuzz_mntent_corpus_reaches_parser_edges() -> TestResult {
    let basic = read_seed("seed_basic_mount")?;
    let parsed =
        parse_mntent_line(&basic).ok_or_else(|| test_error("basic mount seed should parse"))?;
    ensure_eq(parsed.fsname, b"/dev/sda1".as_slice(), "fsname")?;
    ensure_eq(parsed.dir, b"/".as_slice(), "dir")?;
    ensure_eq(parsed.mtype, b"ext4".as_slice(), "mtype")?;
    ensure_eq(parsed.opts, b"rw,relatime".as_slice(), "opts")?;
    ensure_eq(parsed.freq, 0, "freq")?;
    ensure_eq(parsed.passno, 1, "passno")?;

    let defaulted = read_seed("seed_missing_freq_passno")?;
    let parsed = parse_mntent_line(&defaulted)
        .ok_or_else(|| test_error("defaulted mount seed should parse"))?;
    ensure_eq(parsed.freq, 0, "defaulted freq")?;
    ensure_eq(parsed.passno, 0, "defaulted passno")?;

    let comment = read_seed("seed_comment_line")?;
    ensure(
        parse_mntent_line(&comment).is_none(),
        "comment seed should exercise skipped-line path",
    )
}

#[test]
fn fuzz_mntent_corpus_reaches_option_boundary_edges() -> TestResult {
    let whole = read_seed("seed_hasmntopt_whole_token")?;
    let (opts, needle) = split_option_seed(&whole)?;
    ensure_eq(has_mnt_opt(opts, needle), Some(3), "whole-token option")?;

    let substring = read_seed("seed_hasmntopt_substring_reject")?;
    let (opts, needle) = split_option_seed(&substring)?;
    ensure_eq(
        has_mnt_opt(opts, needle),
        None,
        "substring seed should prove comma-token boundary rejection",
    )?;

    let key_value = read_seed("seed_hasmntopt_key_value")?;
    let (opts, needle) = split_option_seed(&key_value)?;
    ensure_eq(has_mnt_opt(opts, needle), Some(3), "key-value option")
}
