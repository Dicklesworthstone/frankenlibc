#![no_main]
//! Structure-aware fuzz target for `<mntent.h>` parser helpers.
//!
//! `frankenlibc_core::mntent` parses fstab/mtab lines and searches
//! comma-delimited mount option tokens. The unit tests cover curated rows;
//! this target widens coverage to arbitrary byte strings while checking
//! parser/search invariants that do not require a host oracle.
//!
//! Invariants:
//! - parse_mntent_line is deterministic and never panics on byte input.
//! - Parsed rows format back to a line that reparses to equivalent fields.
//! - has_mnt_opt only reports whole comma-token matches and agrees with a
//!   simple split-based reference.
//! - parse_mntent_freq_passno is deterministic for arbitrary byte fields.
//!
//! Bead: bd-owyne

use arbitrary::{Arbitrary, Unstructured};
use frankenlibc_core::mntent::{
    MntFields, format_mntent_line, has_mnt_opt, parse_mntent_freq_passno, parse_mntent_line,
};
use libfuzzer_sys::fuzz_target;

const MAX_LINE: usize = 4096;
const MAX_OPTS: usize = 1024;
const MAX_FIELD: usize = 256;

#[derive(Debug, Arbitrary)]
struct MntentFuzzInput {
    line: Vec<u8>,
    opts: Vec<u8>,
    needle: Vec<u8>,
    freq: Vec<u8>,
    passno: Vec<u8>,
    op: u8,
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_LINE + MAX_OPTS + (MAX_FIELD * 3) + 64 {
        return;
    }

    if let Ok(input) = MntentFuzzInput::arbitrary(&mut Unstructured::new(data)) {
        fuzz_structured_input(&input);
    }
    fuzz_raw_seed(data);
});

fn fuzz_structured_input(input: &MntentFuzzInput) {
    if input.line.len() > MAX_LINE
        || input.opts.len() > MAX_OPTS
        || input.needle.len() > MAX_FIELD
        || input.freq.len() > MAX_FIELD
        || input.passno.len() > MAX_FIELD
    {
        return;
    }
    match input.op % 4 {
        0 => fuzz_parse_line(&input.line),
        1 => fuzz_option_lookup(&input.opts, &input.needle),
        2 => fuzz_freq_passno(&input.freq, &input.passno),
        3 => fuzz_all_paths(input),
        _ => unreachable!(),
    }
}

fn fuzz_raw_seed(data: &[u8]) {
    if data.len() <= MAX_LINE {
        fuzz_parse_line(data);
    }
    if let Some((opts, needle)) = split_option_seed(data) {
        fuzz_option_lookup(opts, needle);
    }
}

fn split_option_seed(data: &[u8]) -> Option<(&[u8], &[u8])> {
    let marker = b"\n---\n";
    let split_at = data
        .windows(marker.len())
        .position(|window| public_bytes_equal(window, marker))?;
    let needle_start = split_at.checked_add(marker.len())?;
    let opts = data.get(..split_at)?;
    let needle = data.get(needle_start..)?;
    let needle = needle.strip_suffix(b"\n").unwrap_or(needle);
    if opts.len() > MAX_OPTS || needle.len() > MAX_FIELD {
        return None;
    }
    Some((opts, needle))
}

fn fuzz_parse_line(line: &[u8]) {
    let parsed = parse_mntent_line(line);
    let parsed_again = parse_mntent_line(line);
    assert_eq!(
        parsed, parsed_again,
        "parse_mntent_line is non-deterministic"
    );

    if let Some(fields) = parsed {
        assert!(
            !fields.fsname.is_empty()
                && !fields.dir.is_empty()
                && !fields.mtype.is_empty()
                && !fields.opts.is_empty(),
            "parsed mntent rows must carry the four required fields"
        );
        assert_format_roundtrip(fields);
        fuzz_option_lookup(fields.opts, b"rw");
        fuzz_option_lookup(fields.opts, b"ro");
    }
}

fn assert_format_roundtrip(fields: MntFields<'_>) {
    let mut out = Vec::new();
    format_mntent_line(&fields, &mut out);
    let reparsed = parse_mntent_line(&out);
    assert!(reparsed.is_some(), "formatted mntent row must parse");
    let Some(reparsed) = reparsed else {
        return;
    };
    assert_eq!(
        reparsed.fsname, fields.fsname,
        "fsname changed after format"
    );
    assert_eq!(reparsed.dir, fields.dir, "dir changed after format");
    assert_eq!(reparsed.mtype, fields.mtype, "mtype changed after format");
    assert_eq!(reparsed.opts, fields.opts, "opts changed after format");
    assert_eq!(reparsed.freq, fields.freq, "freq changed after format");
    assert_eq!(
        reparsed.passno, fields.passno,
        "passno changed after format"
    );
}

fn fuzz_option_lookup(opts: &[u8], needle: &[u8]) {
    let actual = has_mnt_opt(opts, needle);
    let actual_again = has_mnt_opt(opts, needle);
    assert_eq!(actual, actual_again, "has_mnt_opt is non-deterministic");

    let expected = reference_option_offset(opts, needle);
    assert_eq!(
        actual, expected,
        "has_mnt_opt disagrees with split reference: opts={opts:?} needle={needle:?}"
    );

    if let Some(offset) = actual {
        assert!(!needle.is_empty(), "empty needle must never match");
        assert!(
            offset + needle.len() <= opts.len(),
            "reported option offset extends beyond opts"
        );
        assert_eq!(
            &opts[offset..offset + needle.len()],
            needle,
            "reported option offset does not point at needle"
        );
        assert!(
            offset == 0 || is_option_separator(opts[offset - 1]),
            "reported option match is not start/comma bounded"
        );
        let end = offset + needle.len();
        assert!(
            end == opts.len() || is_option_separator(opts[end]),
            "reported option match is not end/comma bounded"
        );
    }
}

fn reference_option_offset(opts: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    let mut offset = 0usize;
    for token in opts.split(|&byte| is_option_separator(byte)) {
        if public_bytes_equal(token, needle) {
            return Some(offset);
        }
        offset += token.len() + 1;
    }
    None
}

fn is_option_separator(byte: u8) -> bool {
    byte.cmp(&b',').is_eq()
}

fn public_bytes_equal(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && left.iter().zip(right).all(|(l, r)| l.cmp(r).is_eq())
}

fn fuzz_freq_passno(freq: &[u8], passno: &[u8]) {
    let first = parse_mntent_freq_passno(freq, passno);
    let second = parse_mntent_freq_passno(freq, passno);
    assert_eq!(
        first, second,
        "parse_mntent_freq_passno is non-deterministic"
    );
}

fn fuzz_all_paths(input: &MntentFuzzInput) {
    fuzz_parse_line(&input.line);
    fuzz_option_lookup(&input.opts, &input.needle);
    fuzz_freq_passno(&input.freq, &input.passno);
}
