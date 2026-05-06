#![no_main]
//! Structure-aware fuzz target for /etc-database parsers lifted to
//! `frankenlibc_core` by the porting-to-rust epic.
//!
//! Covers four parsers that accept untrusted byte content from globally
//! readable `/etc/*` files and back the getprotoent / getnetent /
//! getaliasent / getnetgrent ABI surface:
//!
//!   * [`resolv::parse_protocols_line`]
//!   * [`resolv::parse_networks_line`]
//!   * [`aliases::parse_aliases_line`]
//!   * [`netgroup::parse_netgroup_triples`]
//!
//! The closely-related `parse_hosts_line` and `parse_services_line` are
//! already exercised by `fuzz_resolv`; this target fills the remaining
//! gap noted in bd-yfyv8.
//!
//! Invariants checked across all four ops:
//!   * No panic on any well-typed `Vec<u8>` input
//!   * On `Some(entry)` the canonical name field is non-empty (parser
//!     contract — empty names should always yield `None`)
//!   * Aliases / members / triple fields filter empties as documented
//!   * Determinism: same input, twice, identical output
//!
//! For `parse_netgroup_triples` the target also exercises the
//! pointer-arithmetic offset computation
//! (`name.as_ptr() as usize - line.as_ptr() as usize + name.len()`) so
//! adversarial group/content overlap that could produce out-of-bounds
//! slicing fails closed in CI rather than at runtime.
//!
//! Bead: bd-yfyv8

use arbitrary::{Arbitrary, Unstructured};
use frankenlibc_core::aliases;
use frankenlibc_core::netgroup;
use frankenlibc_core::resolv;
use libfuzzer_sys::fuzz_target;

const MAX_LINE: usize = 4096;
const MAX_CONTENT: usize = 8192;
const MAX_GROUP: usize = 256;

#[derive(Debug, Arbitrary)]
struct EtcDbFuzzInput {
    line: Vec<u8>,
    content: Vec<u8>,
    group: Vec<u8>,
    op: u8,
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_LINE + MAX_CONTENT + MAX_GROUP + 64 {
        return;
    }

    if let Ok(input) = EtcDbFuzzInput::arbitrary(&mut Unstructured::new(data)) {
        fuzz_structured_input(&input);
    }
    fuzz_raw_seed(data);
});

fn fuzz_structured_input(input: &EtcDbFuzzInput) {
    if input.line.len() > MAX_LINE
        || input.content.len() > MAX_CONTENT
        || input.group.len() > MAX_GROUP
    {
        return;
    }
    match input.op % 4 {
        0 => fuzz_parse_protocols_line(&input.line),
        1 => fuzz_parse_networks_line(&input.line),
        2 => fuzz_parse_aliases_line(&input.line),
        3 => fuzz_parse_netgroup_triples(&input.content, &input.group),
        _ => unreachable!(),
    }
}

fn fuzz_raw_seed(data: &[u8]) {
    if data.len() <= MAX_LINE {
        fuzz_parse_protocols_line(data);
        fuzz_parse_networks_line(data);
        fuzz_parse_aliases_line(data);
    }
}

fn fuzz_parse_protocols_line(line: &[u8]) {
    let first = resolv::parse_protocols_line(line);
    let second = resolv::parse_protocols_line(line);
    assert_eq!(
        first, second,
        "parse_protocols_line is non-deterministic for line={line:?}"
    );

    if let Some(entry) = first {
        assert!(
            !entry.name.is_empty(),
            "parse_protocols_line accepted an empty name: line={line:?}"
        );
        for alias in &entry.aliases {
            assert!(
                !alias.is_empty(),
                "parse_protocols_line yielded an empty alias: line={line:?}"
            );
        }
    }
}

fn fuzz_parse_networks_line(line: &[u8]) {
    let first = resolv::parse_networks_line(line);
    let second = resolv::parse_networks_line(line);
    assert_eq!(
        first, second,
        "parse_networks_line is non-deterministic for line={line:?}"
    );

    if let Some(entry) = first {
        assert!(
            !entry.name.is_empty(),
            "parse_networks_line accepted an empty name: line={line:?}"
        );
        for alias in &entry.aliases {
            assert!(
                !alias.is_empty(),
                "parse_networks_line yielded an empty alias: line={line:?}"
            );
        }
    }
}

fn fuzz_parse_aliases_line(line: &[u8]) {
    let first = aliases::parse_aliases_line(line);
    let second = aliases::parse_aliases_line(line);
    assert_eq!(
        first, second,
        "parse_aliases_line is non-deterministic for line={line:?}"
    );

    if let Some(entry) = first {
        assert!(
            !entry.name.is_empty(),
            "parse_aliases_line accepted an empty name: line={line:?}"
        );
        for member in &entry.members {
            assert!(
                !member.is_empty(),
                "parse_aliases_line yielded an empty member: line={line:?}"
            );
        }
    }
}

fn fuzz_parse_netgroup_triples(content: &[u8], group: &[u8]) {
    // The internal extract_triples_into routine derives an offset from
    // pointer arithmetic against the line slice; an adversarial group
    // value that aliases across multiple lines could in principle produce
    // a degenerate offset. Run it twice and assert determinism + that
    // every returned triple round-trips through field-trim invariants.
    let first = netgroup::parse_netgroup_triples(content, group);
    let second = netgroup::parse_netgroup_triples(content, group);
    assert_eq!(first, second, "parse_netgroup_triples is non-deterministic");

    for triple in &first {
        // Trim invariants: returned bytes must not start or end with
        // ASCII whitespace (parser is documented to trim per-field).
        assert!(
            !starts_or_ends_with_ws(&triple.host),
            "host has leading/trailing whitespace: {triple:?}"
        );
        assert!(
            !starts_or_ends_with_ws(&triple.user),
            "user has leading/trailing whitespace: {triple:?}"
        );
        assert!(
            !starts_or_ends_with_ws(&triple.domain),
            "domain has leading/trailing whitespace: {triple:?}"
        );
    }
}

fn starts_or_ends_with_ws(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    matches!(bytes[0], b' ' | b'\t') || matches!(bytes[bytes.len() - 1], b' ' | b'\t')
}
