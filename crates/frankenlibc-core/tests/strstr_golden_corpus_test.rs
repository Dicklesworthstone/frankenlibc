//! Golden-output corpus pin for `strstr`.
//!
//! Locks the byte-for-byte behavior of [`frankenlibc_core::string::strstr`]
//! across a deterministic corpus that exercises every branch: empty needle,
//! needle longer than haystack, first occurrence after many false first-byte
//! hits, embedded NUL terminators, overlapping partial matches, single-byte
//! needles, and the not-found tail. The corpus result stream is hashed with
//! SHA-256 so a behavior-preserving optimization (e.g. switching the
//! first-byte scan from scalar to SIMD) can be proven isomorphic: the digest
//! must not change.

use frankenlibc_core::string::strstr;
use sha2::{Digest, Sha256};

/// Build the deterministic (haystack, needle) corpus. Every haystack carries
/// a trailing NUL so it is a valid C string, matching how the ABI layer calls
/// `strstr`.
fn corpus() -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut cases: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();

    let nul = |mut v: Vec<u8>| {
        v.push(0);
        v
    };

    // Empty needle matches at 0 regardless of haystack.
    cases.push((nul(b"".to_vec()), nul(b"".to_vec())));
    cases.push((nul(b"abc".to_vec()), nul(b"".to_vec())));

    // Needle longer than haystack.
    cases.push((nul(b"ab".to_vec()), nul(b"abc".to_vec())));

    // Single-byte needle, present and absent.
    cases.push((nul(b"hello world".to_vec()), nul(b"o".to_vec())));
    cases.push((nul(b"hello world".to_vec()), nul(b"z".to_vec())));

    // Match at start, middle, end.
    cases.push((nul(b"abcdef".to_vec()), nul(b"abc".to_vec())));
    cases.push((nul(b"abcdef".to_vec()), nul(b"cde".to_vec())));
    cases.push((nul(b"abcdef".to_vec()), nul(b"def".to_vec())));

    // Many false first-byte hits before the real match (the SIMD-probe win
    // path): a run of 'a' that shares the needle's first byte.
    cases.push((nul(b"aaaaaaaaaaaaaaaaaaab".to_vec()), nul(b"aaab".to_vec())));
    cases.push((nul(b"aaaaaaaaaaaaaaaaaaaa".to_vec()), nul(b"aaab".to_vec())));

    // Overlapping partial matches.
    cases.push((nul(b"ababababab".to_vec()), nul(b"abab".to_vec())));
    cases.push((nul(b"aabaacaadaab".to_vec()), nul(b"aab".to_vec())));

    // Embedded NUL truncates the searchable region before a would-be match.
    cases.push((nul(b"abc\0defXYZ".to_vec()), nul(b"XYZ".to_vec())));
    cases.push((nul(b"abc\0abc".to_vec()), nul(b"abc".to_vec())));

    // First byte appears, but the candidate runs past the end of the string.
    cases.push((nul(b"xxxxxA".to_vec()), nul(b"Abc".to_vec())));

    // The absent-needle benchmark workload, at several sizes: 'Z' never
    // occurs in an all-'A' haystack, so the scan walks to the NUL.
    for &size in &[16usize, 64, 256, 1024] {
        let mut hay = vec![b'A'; size];
        hay.push(0);
        cases.push((hay, nul(b"ZQ".to_vec())));
    }

    // Needle equal to the whole haystack, and needle that is the haystack
    // plus one trailing byte (off-by-one boundary).
    cases.push((nul(b"exact".to_vec()), nul(b"exact".to_vec())));
    cases.push((nul(b"exact".to_vec()), nul(b"exactt".to_vec())));

    // Repeated structure with a late unique tail.
    cases.push((
        nul(b"the quick brown fox the quick".to_vec()),
        nul(b"brown".to_vec()),
    ));
    cases.push((
        nul(b"the quick brown fox the quick".to_vec()),
        nul(b"quick".to_vec()),
    ));

    cases
}

#[test]
fn strstr_golden_corpus_digest_is_pinned() {
    let mut hasher = Sha256::new();
    let mut line = String::new();
    for (idx, (haystack, needle)) in corpus().iter().enumerate() {
        let result = strstr(haystack, needle);
        line.clear();
        // Stable, fully-determined record per case.
        let result_field = match result {
            Some(pos) => format!("{pos}"),
            None => String::from("none"),
        };
        line.push_str(&format!("{idx};{result_field}\n"));
        hasher.update(line.as_bytes());
    }
    let digest = hasher.finalize();
    let digest_hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();

    // Captured from the pre-optimization scalar `strstr` (the SIMD first-byte
    // probe must reproduce this exact digest).
    const EXPECTED: &str = "4cbd66be7606fdc9012d7f842d58794b4c0efdfb113935faa65bb783e98a07e8";
    eprintln!("STRSTR_GOLDEN_SHA256={digest_hex}");
    assert_eq!(
        digest_hex, EXPECTED,
        "strstr corpus digest changed — behavior parity broken"
    );
}
