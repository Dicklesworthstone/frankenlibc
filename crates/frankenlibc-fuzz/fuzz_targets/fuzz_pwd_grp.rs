#![no_main]
//! Structure-aware fuzz target for FrankenLibC pwd/grp (password/group database parsing).
//!
//! Exercises parse_passwd_line, lookup_by_name, lookup_by_uid, parse_all,
//! and the equivalent grp functions. Invariants:
//! - No panics on any well-typed input
//! - Parsed entries have non-empty username/group name
//! - Lookups are deterministic
//! - parse_all never returns entries with empty names
//!
//! Bead: bd-2hh.4

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

use frankenlibc_core::grp;
use frankenlibc_core::pwd;

const DIRECTED_PREFIX: &[u8] = b"pwdgrp:";

#[derive(Debug, Arbitrary)]
struct PwdGrpFuzzInput {
    data: Vec<u8>,
    name: Vec<u8>,
    uid: u32,
    gid: u32,
    op: u8,
}

fuzz_target!(|data: &[u8]| {
    if let Some(input) = directed_input(data) {
        fuzz_pwd_grp(input);
        return;
    }

    let mut raw = Unstructured::new(data);
    let Ok(input) = PwdGrpFuzzInput::arbitrary(&mut raw) else {
        return;
    };

    fuzz_pwd_grp(input);
});

fn fuzz_pwd_grp(input: PwdGrpFuzzInput) {
    match input.op % 8 {
        0 => fuzz_parse_passwd_line(&input),
        1 => fuzz_pwd_lookup_by_name(&input),
        2 => fuzz_pwd_lookup_by_uid(&input),
        3 => fuzz_pwd_parse_all(&input),
        4 => fuzz_parse_group_line(&input),
        5 => fuzz_grp_lookup_by_name(&input),
        6 => fuzz_grp_lookup_by_gid(&input),
        _ => fuzz_grp_parse_all(&input),
    }
}

/// Decode readable directed seeds shaped as:
///
/// ```text
/// pwdgrp:<op>
/// name:<lookup-name>
/// uid:<uid>
/// gid:<gid>
/// ---
/// <passwd-or-group-content>
/// ```
///
/// Header fields are optional. The op is one of `pwd_line`, `pwd_name`,
/// `pwd_uid`, `pwd_all`, `grp_line`, `grp_name`, `grp_gid`, or `grp_all`.
/// Legacy libFuzzer corpus bytes still use the `Arbitrary` struct path.
fn directed_input(data: &[u8]) -> Option<PwdGrpFuzzInput> {
    let rest = data.strip_prefix(DIRECTED_PREFIX)?;
    let (op_name, payload) = split_once_byte(rest, b'\n')?;
    let empty_header: &[u8] = b"";
    let (header, body) = split_once_marker(payload, b"\n---\n").unwrap_or((empty_header, payload));

    let mut name = Vec::new();
    let mut uid = 0u32;
    let mut gid = 0u32;
    for raw_line in header.split(|&byte| byte == b'\n') {
        let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        if line.is_empty() {
            continue;
        }
        if let Some(value) = line.strip_prefix(b"name:") {
            name = value.to_vec();
        } else if let Some(value) = line.strip_prefix(b"uid:") {
            uid = parse_directed_u32(value)?;
        } else {
            let value = line.strip_prefix(b"gid:")?;
            gid = parse_directed_u32(value)?;
        }
    }

    Some(PwdGrpFuzzInput {
        data: strip_single_trailing_newline(body).to_vec(),
        name,
        uid,
        gid,
        op: directed_op(op_name)?,
    })
}

fn directed_op(op_name: &[u8]) -> Option<u8> {
    match op_name {
        b"pwd_line" => Some(0),
        b"pwd_name" => Some(1),
        b"pwd_uid" => Some(2),
        b"pwd_all" => Some(3),
        b"grp_line" => Some(4),
        b"grp_name" => Some(5),
        b"grp_gid" => Some(6),
        b"grp_all" => Some(7),
        _ => None,
    }
}

fn split_once_byte(data: &[u8], byte: u8) -> Option<(&[u8], &[u8])> {
    let split_at = data.iter().position(|&b| b == byte)?;
    let (head, tail) = data.split_at(split_at);
    Some((head, tail.get(1..)?))
}

fn split_once_marker<'a>(data: &'a [u8], marker: &[u8]) -> Option<(&'a [u8], &'a [u8])> {
    if marker.is_empty() {
        return None;
    }

    let split_at = data
        .windows(marker.len())
        .position(|window| window == marker)?;
    let (head, tail) = data.split_at(split_at);
    Some((head, tail.get(marker.len()..)?))
}

fn strip_single_trailing_newline(data: &[u8]) -> &[u8] {
    data.strip_suffix(b"\n").unwrap_or(data)
}

fn parse_directed_u32(value: &[u8]) -> Option<u32> {
    if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
        return None;
    }
    core::str::from_utf8(value).ok()?.parse().ok()
}

fn fuzz_parse_passwd_line(input: &PwdGrpFuzzInput) {
    let line = &input.data[..input.data.len().min(1024)];
    if let Some(entry) = pwd::parse_passwd_line(line) {
        assert!(
            !entry.pw_name.is_empty(),
            "parsed passwd entry should have a non-empty name"
        );
    }
}

fn fuzz_pwd_lookup_by_name(input: &PwdGrpFuzzInput) {
    let content = &input.data[..input.data.len().min(4096)];
    let name = &input.name[..input.name.len().min(256)];

    let r1 = pwd::lookup_by_name(content, name);
    let r2 = pwd::lookup_by_name(content, name);
    assert_eq!(
        r1.is_some(),
        r2.is_some(),
        "determinism: one lookup succeeded and one failed"
    );

    match (&r1, &r2) {
        (Some(a), Some(b)) => {
            assert_eq!(a.pw_name, b.pw_name, "determinism: names should match");
            assert_eq!(a.pw_uid, b.pw_uid, "determinism: uids should match");
        }
        (None, None) => {}
        _ => {}
    }
}

fn fuzz_pwd_lookup_by_uid(input: &PwdGrpFuzzInput) {
    let content = &input.data[..input.data.len().min(4096)];

    let r1 = pwd::lookup_by_uid(content, input.uid);
    let r2 = pwd::lookup_by_uid(content, input.uid);
    assert_eq!(
        r1.is_some(),
        r2.is_some(),
        "determinism: one lookup succeeded and one failed"
    );

    match (&r1, &r2) {
        (Some(a), Some(b)) => {
            assert_eq!(a.pw_uid, b.pw_uid);
            assert_eq!(a.pw_name, b.pw_name);
        }
        (None, None) => {}
        _ => {}
    }
}

fn fuzz_pwd_parse_all(input: &PwdGrpFuzzInput) {
    let content = &input.data[..input.data.len().min(8192)];
    let entries = pwd::parse_all(content);
    for entry in &entries {
        assert!(
            !entry.pw_name.is_empty(),
            "parse_all should not return entries with empty names"
        );
    }

    // Determinism.
    let entries2 = pwd::parse_all(content);
    assert_eq!(
        entries.len(),
        entries2.len(),
        "parse_all should be deterministic"
    );
}

fn fuzz_parse_group_line(input: &PwdGrpFuzzInput) {
    let line = &input.data[..input.data.len().min(1024)];
    if let Some(entry) = grp::parse_group_line(line) {
        assert!(
            !entry.gr_name.is_empty(),
            "parsed group entry should have a non-empty name"
        );
    }
}

fn fuzz_grp_lookup_by_name(input: &PwdGrpFuzzInput) {
    let content = &input.data[..input.data.len().min(4096)];
    let name = &input.name[..input.name.len().min(256)];

    let r1 = grp::lookup_by_name(content, name);
    let r2 = grp::lookup_by_name(content, name);
    assert_eq!(
        r1.is_some(),
        r2.is_some(),
        "determinism: one lookup succeeded and one failed"
    );

    match (&r1, &r2) {
        (Some(a), Some(b)) => {
            assert_eq!(a.gr_name, b.gr_name);
            assert_eq!(a.gr_gid, b.gr_gid);
        }
        (None, None) => {}
        _ => {}
    }
}

fn fuzz_grp_lookup_by_gid(input: &PwdGrpFuzzInput) {
    let content = &input.data[..input.data.len().min(4096)];

    let r1 = grp::lookup_by_gid(content, input.gid);
    let r2 = grp::lookup_by_gid(content, input.gid);
    assert_eq!(
        r1.is_some(),
        r2.is_some(),
        "determinism: one lookup succeeded and one failed"
    );

    match (&r1, &r2) {
        (Some(a), Some(b)) => {
            assert_eq!(a.gr_gid, b.gr_gid);
            assert_eq!(a.gr_name, b.gr_name);
        }
        (None, None) => {}
        _ => {}
    }
}

fn fuzz_grp_parse_all(input: &PwdGrpFuzzInput) {
    let content = &input.data[..input.data.len().min(8192)];
    let entries = grp::parse_all(content);
    for entry in &entries {
        assert!(
            !entry.gr_name.is_empty(),
            "parse_all should not return group entries with empty names"
        );
    }

    let entries2 = grp::parse_all(content);
    assert_eq!(entries.len(), entries2.len());
}
