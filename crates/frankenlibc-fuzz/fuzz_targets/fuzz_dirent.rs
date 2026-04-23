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
        // Name *can* be empty in fuzz-crafted wire data (e.g., when
        // the byte at offset 19 is NUL). The kernel never returns
        // such an entry, but parse_dirent64 accepts the wire format
        // as-is and lets the consumer decide. Just bound the length.
        assert!(
            entry.d_name.len() <= buf.len(),
            "parsed d_name length exceeds buffer"
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
                // Empty d_name is a valid wire-format possibility
                // (parse_dirent64 doesn't reject it). Same rationale
                // as fuzz_parse_dirent64 above.
                assert!(entry.d_name.len() <= buf.len());
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
    assert_eq!(
        r1.is_some(),
        r2.is_some(),
        "determinism: one parse succeeded and one failed"
    );

    match (r1, r2) {
        (Some((e1, o1)), Some((e2, o2))) => {
            assert_eq!(o1, o2, "determinism: offsets should match");
            assert_eq!(e1.d_name, e2.d_name, "determinism: names should match");
            assert_eq!(e1.d_ino, e2.d_ino, "determinism: inodes should match");
            assert_eq!(e1.d_type, e2.d_type, "determinism: types should match");
        }
        (None, None) => {}
        _ => {}
    }
}
