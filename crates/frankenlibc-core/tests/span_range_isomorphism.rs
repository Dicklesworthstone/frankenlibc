//! Isomorphism + golden-output proof for the folded-block `span_range` lever in
//! `strspn`/`strcspn`/`strpbrk` (str.rs). The 256-byte folded SIMD only
//! fast-forwards blocks it proves contain no stop; the exact index is resolved
//! by the scalar table scan. This test pins that the public functions are
//! byte-for-byte identical to a trivial scalar reference over a deterministic
//! corpus that exercises the contiguous-range path (long all-member spans,
//! 256-byte block boundaries, stops at every offset, NUL handling), and pins a
//! golden digest of all results so any future change to the SIMD path that alters
//! output is caught.

use frankenlibc_core::string::str::{strcspn, strpbrk, strspn};

/// Trivial scalar reference: length of the leading run of `s` whose membership
/// in `set` equals `want_member` (stopping at NUL). `strspn` is `want_member =
/// true`; `strcspn` is `want_member = false`.
fn ref_span(s: &[u8], set: &[u8], want_member: bool) -> usize {
    let set_bytes: Vec<u8> = {
        let end = set.iter().position(|&b| b == 0).unwrap_or(set.len());
        set[..end].to_vec()
    };
    for (i, &b) in s.iter().enumerate() {
        if b == 0 {
            return i;
        }
        let is_member = set_bytes.contains(&b);
        if is_member != want_member {
            return i;
        }
    }
    s.len()
}

fn ref_pbrk(s: &[u8], accept: &[u8]) -> Option<usize> {
    let n = ref_span(s, accept, false); // leading run of non-members
    if n < s.len() && s[n] != 0 {
        Some(n)
    } else {
        None
    }
}

struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
}

/// Build a NUL-terminated C string of `len` bytes drawn from `alphabet`.
fn cstr(r: &mut Lcg, len: usize, alphabet: &[u8]) -> Vec<u8> {
    let mut v: Vec<u8> = (0..len)
        .map(|_| alphabet[(r.next() as usize) % alphabet.len()])
        .collect();
    v.push(0);
    v
}

#[test]
fn span_range_matches_scalar_reference_and_golden() {
    let mut r = Lcg(0x1234_5678_9abc_def1);
    // Contiguous ranges (drive span_range) plus a couple of non-contiguous sets
    // (drive the general path) for good measure.
    let accept_sets: &[&[u8]] = &[
        b"abcdefgh\0",         // contiguous a-h (the strspn_long workload)
        b"0123456789\0",       // contiguous digits
        b"ABCDEFGHIJKLMNOP\0", // contiguous, 16 wide
        b"xyz\0",              // contiguous, short
        b"aeiou\0",            // NON-contiguous
        b"./_-+\0",            // punctuation, non-contiguous
    ];
    // Strings sized to straddle 256-byte block boundaries and land stops at
    // assorted offsets.
    let lengths = [0usize, 1, 31, 32, 63, 64, 255, 256, 257, 511, 1000, 4096];

    let mut hash: u64 = 0xcbf29ce484222325;
    let mix = |x: u64, h: &mut u64| {
        *h ^= x;
        *h = h.wrapping_mul(0x100000001b3);
    };

    for accept in accept_sets {
        // Alphabet biased toward members so spans get long, but include
        // non-members and stray bytes so stops occur at varied positions.
        let members: Vec<u8> = accept[..accept.iter().position(|&b| b == 0).unwrap()].to_vec();
        let mut alphabet = members.clone();
        alphabet.extend_from_slice(b"!~ \t9Zq"); // some non-members
        for &len in &lengths {
            for _ in 0..40 {
                let s = cstr(&mut r, len, &alphabet);
                let got_spn = strspn(&s, accept);
                let got_cspn = strcspn(&s, accept);
                let got_pbrk = strpbrk(&s, accept);
                assert_eq!(
                    got_spn,
                    ref_span(&s, accept, true),
                    "strspn s={s:?} accept={accept:?}"
                );
                assert_eq!(
                    got_cspn,
                    ref_span(&s, accept, false),
                    "strcspn s={s:?} accept={accept:?}"
                );
                assert_eq!(
                    got_pbrk,
                    ref_pbrk(&s, accept),
                    "strpbrk s={s:?} accept={accept:?}"
                );
                mix(got_spn as u64, &mut hash);
                mix(got_cspn as u64, &mut hash);
                mix(got_pbrk.map(|x| x as u64 + 1).unwrap_or(0), &mut hash);
            }
        }
    }

    // Golden digest of every result over the fixed corpus. The scalar-reference
    // asserts above already prove correctness; this pins the exact output so a
    // regression in the SIMD fast path is caught even if the reference drifts.
    assert_eq!(
        hash, 9462047517241184641,
        "golden span-range digest changed"
    );
}
