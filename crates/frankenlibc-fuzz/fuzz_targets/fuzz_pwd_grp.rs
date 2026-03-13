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

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use frankenlibc_core::grp;
use frankenlibc_core::pwd;

#[derive(Debug, Arbitrary)]
struct PwdGrpFuzzInput {
    data: Vec<u8>,
    name: Vec<u8>,
    uid: u32,
    gid: u32,
    op: u8,
}

fuzz_target!(|input: PwdGrpFuzzInput| {
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
});

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

    match (&r1, &r2) {
        (Some(a), Some(b)) => {
            assert_eq!(a.pw_name, b.pw_name, "determinism: names should match");
            assert_eq!(a.pw_uid, b.pw_uid, "determinism: uids should match");
        }
        (None, None) => {}
        _ => panic!("determinism: one lookup succeeded and one failed"),
    }
}

fn fuzz_pwd_lookup_by_uid(input: &PwdGrpFuzzInput) {
    let content = &input.data[..input.data.len().min(4096)];

    let r1 = pwd::lookup_by_uid(content, input.uid);
    let r2 = pwd::lookup_by_uid(content, input.uid);

    match (&r1, &r2) {
        (Some(a), Some(b)) => {
            assert_eq!(a.pw_uid, b.pw_uid);
            assert_eq!(a.pw_name, b.pw_name);
        }
        (None, None) => {}
        _ => panic!("determinism: one lookup succeeded and one failed"),
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

    match (&r1, &r2) {
        (Some(a), Some(b)) => {
            assert_eq!(a.gr_name, b.gr_name);
            assert_eq!(a.gr_gid, b.gr_gid);
        }
        (None, None) => {}
        _ => panic!("determinism: one lookup succeeded and one failed"),
    }
}

fn fuzz_grp_lookup_by_gid(input: &PwdGrpFuzzInput) {
    let content = &input.data[..input.data.len().min(4096)];

    let r1 = grp::lookup_by_gid(content, input.gid);
    let r2 = grp::lookup_by_gid(content, input.gid);

    match (&r1, &r2) {
        (Some(a), Some(b)) => {
            assert_eq!(a.gr_gid, b.gr_gid);
            assert_eq!(a.gr_name, b.gr_name);
        }
        (None, None) => {}
        _ => panic!("determinism: one lookup succeeded and one failed"),
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
