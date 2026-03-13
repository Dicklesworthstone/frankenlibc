#![no_main]
//! Structure-aware fuzz target for FrankenLibC dirent (directory entry parsing).
//!
//! Exercises parse_dirent64 with fuzzer-generated binary buffers and offsets.
//! Invariants:
//! - No panics on any input
//! - Returned offset is always > input offset (forward progress)
//! - Returned DirEntry fields are internally consistent
//! - Repeated parsing of same buffer is deterministic
//!
//! Bead: bd-2hh.4

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use frankenlibc_core::dirent;

#[derive(Debug, Arbitrary)]
struct DirentFuzzInput {
    buffer: Vec<u8>,
    offset: u16,
    op: u8,
}

fuzz_target!(|input: DirentFuzzInput| {
    match input.op % 3 {
        0 => fuzz_parse_single(&input),
        1 => fuzz_parse_exhaustive(&input),
        _ => fuzz_determinism(&input),
    }
});

fn fuzz_parse_single(input: &DirentFuzzInput) {
    let buf = &input.buffer[..input.buffer.len().min(8192)];
    let offset = input.offset as usize;

    if let Some((entry, next_offset)) = dirent::parse_dirent64(buf, offset) {
        // Forward progress: next offset must be greater than current.
        assert!(
            next_offset > offset,
            "parse_dirent64 must make forward progress: {offset} -> {next_offset}"
        );
        // Next offset must not exceed buffer length.
        assert!(
            next_offset <= buf.len(),
            "next offset {next_offset} exceeds buffer length {}",
            buf.len()
        );
        // Name must not be empty.
        assert!(
            !entry.d_name.is_empty(),
            "parsed directory entry name must not be empty"
        );
    }
}

fn fuzz_parse_exhaustive(input: &DirentFuzzInput) {
    let buf = &input.buffer[..input.buffer.len().min(8192)];
    let mut offset = 0;
    let mut count = 0;
    let max_entries = 1000; // prevent degenerate loops

    while offset < buf.len() && count < max_entries {
        match dirent::parse_dirent64(buf, offset) {
            Some((entry, next_offset)) => {
                assert!(next_offset > offset);
                assert!(next_offset <= buf.len());
                assert!(!entry.d_name.is_empty());
                offset = next_offset;
                count += 1;
            }
            None => break,
        }
    }
}

fn fuzz_determinism(input: &DirentFuzzInput) {
    let buf = &input.buffer[..input.buffer.len().min(4096)];
    let offset = input.offset as usize;

    let r1 = dirent::parse_dirent64(buf, offset);
    let r2 = dirent::parse_dirent64(buf, offset);

    match (r1, r2) {
        (Some((e1, o1)), Some((e2, o2))) => {
            assert_eq!(o1, o2, "determinism: offsets should match");
            assert_eq!(e1.d_name, e2.d_name, "determinism: names should match");
            assert_eq!(e1.d_ino, e2.d_ino, "determinism: inodes should match");
            assert_eq!(e1.d_type, e2.d_type, "determinism: types should match");
        }
        (None, None) => {}
        _ => panic!("determinism: one parse succeeded and one failed"),
    }
}
