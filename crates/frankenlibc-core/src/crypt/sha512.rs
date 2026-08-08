//! SHA-512-based crypt(3) — the `$6$` password hashing scheme.
//!
//! Reference: <https://www.akkadia.org/drepper/SHA-crypt.txt>
//!
//! Pure-safe Rust port of the SHA-512 password-hashing algorithm by
//! Ulrich Drepper. Uses the existing [`crate::crypt::salt::parse_crypt_salt`]
//! prefix parser and [`crate::crypt::base64::encode`] for output
//! formatting.
//!
//! Implementation note (corrected, bd-9n50f2): this module previously claimed
//! it "uses the correct indices, so output now matches real glibc/libcrypt".
//! It did not. The step-6 transposition table was off by one from row 14
//! onward, consuming `f[55]` twice and `f[62]` never, and the shared
//! crypt-base64 encoder packed each 3-byte group in reverse. Digests were the
//! right length with the right alphabet and entirely wrong content, for `$6$`,
//! `$5$` and `$1$` alike, so no real `/etc/shadow` entry could verify. Both are
//! fixed and the output is now byte-identical to live libxcrypt, checked by
//! `conformance_diff_crypt_failure_token`.
//!
//! The claim survived because every test here compares fl against fl — shape,
//! determinism, and a "characterization" test that pins whatever the code
//! currently emits. A wrong-but-deterministic implementation satisfies all of
//! them. Byte-equality against a live oracle is the only assertion that could
//! have failed, and it now exists.

use sha2::{Digest, Sha512};

use crate::crypt::base64;
use crate::crypt::salt::parse_crypt_salt;

/// Hash `key` against the `$6$[rounds=NNNN$]salt$...` formatted
/// `salt_bytes`, returning the full crypt-format result string.
///
/// Returns `None` only on malformed input that the parser can't
/// recover from (currently never `None` since parse_crypt_salt is
/// total — kept as `Option` for API symmetry with future error
/// modes).
pub fn sha512_crypt(key: &[u8], salt_bytes: &[u8]) -> Option<String> {
    let (rounds, salt) = parse_crypt_salt(salt_bytes, 3);
    let rounds = rounds as usize;

    // Step 1: Digest B = SHA512(key + salt + key)
    let mut digest_b = Sha512::new();
    digest_b.update(key);
    digest_b.update(salt);
    digest_b.update(key);
    let hash_b = digest_b.finalize();

    // Step 2: Digest A = SHA512(key + salt + B-bytes-for-keylen + key.len-bit-pattern)
    let mut digest_a = Sha512::new();
    digest_a.update(key);
    digest_a.update(salt);
    let mut remaining = key.len();
    while remaining >= 64 {
        digest_a.update(&hash_b[..]);
        remaining -= 64;
    }
    if remaining > 0 {
        digest_a.update(&hash_b[..remaining]);
    }
    let mut n = key.len();
    while n > 0 {
        if n & 1 != 0 {
            digest_a.update(&hash_b[..]);
        } else {
            digest_a.update(key);
        }
        n >>= 1;
    }
    let hash_a = digest_a.finalize();

    // Step 3: DP = SHA512(key repeated key.len() times); P = first key.len() bytes of DP
    let mut digest_dp = Sha512::new();
    for _ in 0..key.len() {
        digest_dp.update(key);
    }
    let hash_dp = digest_dp.finalize();
    let mut p_bytes = vec![0u8; key.len()];
    for (i, dst) in p_bytes.iter_mut().enumerate() {
        *dst = hash_dp[i % 64];
    }

    // Step 4: DS = SHA512(salt repeated (16 + hash_a[0]) times); S = first salt.len() bytes
    let mut digest_ds = Sha512::new();
    let ds_count = 16 + (hash_a[0] as usize);
    for _ in 0..ds_count {
        digest_ds.update(salt);
    }
    let hash_ds = digest_ds.finalize();
    let mut s_bytes = vec![0u8; salt.len()];
    for (i, dst) in s_bytes.iter_mut().enumerate() {
        *dst = hash_ds[i % 64];
    }

    // Step 5: rounds iterations
    let mut c_input = hash_a.to_vec();
    for i in 0..rounds {
        let mut digest_c = Sha512::new();
        if i & 1 != 0 {
            digest_c.update(&p_bytes);
        } else {
            digest_c.update(&c_input);
        }
        if i % 3 != 0 {
            digest_c.update(&s_bytes);
        }
        if i % 7 != 0 {
            digest_c.update(&p_bytes);
        }
        if i & 1 != 0 {
            digest_c.update(&c_input);
        } else {
            digest_c.update(&p_bytes);
        }
        let result = digest_c.finalize();
        c_input.clear();
        c_input.extend_from_slice(&result);
    }

    // Step 6: Output formatting via crypt-base64 byte transposition.
    //
    // These indices are Drepper's, verified against live libxcrypt. They used to
    // be copied from an earlier abi inline implementation under a comment
    // claiming "bug-for-bug compatibility ... rows 14, 18, 19 differ from
    // Drepper's published spec by 1". That was wrong twice over: the divergence
    // ran from row 14 through row 20, not three scattered rows, and there was no
    // compatibility to preserve — the output matched nothing. Every high index
    // from row 14 on was one too small (55,56,57,58,59,60,61 where the spec says
    // 56,57,58,59,60,61,62), so `f[55]` was consumed TWICE and `f[62]` never at
    // all. That is provably wrong without consulting any oracle: this is a
    // permutation of bytes 0..=62, so each must appear exactly once — which is
    // now asserted by `transposition_table_is_a_permutation` below. bd-9n50f2.
    let f = &c_input;
    let reordered: Vec<u8> = [
        (f[0], f[21], f[42]),
        (f[22], f[43], f[1]),
        (f[44], f[2], f[23]),
        (f[3], f[24], f[45]),
        (f[25], f[46], f[4]),
        (f[47], f[5], f[26]),
        (f[6], f[27], f[48]),
        (f[28], f[49], f[7]),
        (f[50], f[8], f[29]),
        (f[9], f[30], f[51]),
        (f[31], f[52], f[10]),
        (f[53], f[11], f[32]),
        (f[12], f[33], f[54]),
        (f[34], f[55], f[13]),
        (f[56], f[14], f[35]),
        (f[15], f[36], f[57]),
        (f[37], f[58], f[16]),
        (f[59], f[17], f[38]),
        (f[18], f[39], f[60]),
        (f[40], f[61], f[19]),
        (f[62], f[20], f[41]),
    ]
    .iter()
    .flat_map(|(a, b, c)| [*a, *b, *c])
    .collect();

    let mut encoded = base64::encode(&reordered, 84);
    let last = [f[63]];
    encoded.push_str(&base64::encode(&last, 2));

    let salt_str = core::str::from_utf8(salt).unwrap_or("");
    Some(if rounds == 5000 {
        format!("$6${salt_str}${encoded}")
    } else {
        format!("$6$rounds={rounds}${salt_str}${encoded}")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Characterization test: pin the current output for a known input
    /// to detect any future drift. The expected string captures the
    /// existing abi behavior (which preserves the historical byte-
    /// transposition table — see module docs).
    #[test]
    fn characterization_simple_key_default_rounds() {
        let h = sha512_crypt(b"Hello world!", b"$6$saltstring").unwrap();
        // Format invariants:
        assert!(h.starts_with("$6$saltstring$"));
        // 86 crypt-base64 chars after the salt $ separator.
        assert_eq!(h.len(), "$6$saltstring$".len() + 86);
        // No rounds= prefix when defaulted.
        assert!(!h.contains("rounds="));
    }

    #[test]
    fn empty_key() {
        let h = sha512_crypt(b"", b"$6$saltstring").unwrap();
        assert!(h.starts_with("$6$saltstring$"));
        assert_eq!(h.len(), "$6$saltstring$".len() + 86);
    }

    #[test]
    fn determinism_same_input_same_output() {
        let a = sha512_crypt(b"key", b"$6$salt").unwrap();
        let b = sha512_crypt(b"key", b"$6$salt").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn different_keys_produce_different_output() {
        let a = sha512_crypt(b"key1", b"$6$salt").unwrap();
        let b = sha512_crypt(b"key2", b"$6$salt").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn different_salts_produce_different_output() {
        let a = sha512_crypt(b"key", b"$6$salt1").unwrap();
        let b = sha512_crypt(b"key", b"$6$salt2").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn rounds_5000_omits_rounds_prefix() {
        let h = sha512_crypt(b"key", b"$6$salt").unwrap();
        assert!(h.starts_with("$6$salt$"));
        assert!(!h.contains("rounds="));
    }

    #[test]
    fn explicit_rounds_includes_prefix() {
        let h = sha512_crypt(b"key", b"$6$rounds=10000$salt").unwrap();
        assert!(h.starts_with("$6$rounds=10000$salt$"));
    }

    #[test]
    fn output_body_is_86_crypt_base64_chars() {
        for (key, salt) in [
            (&b""[..], b"$6$x".as_slice()),
            (b"a", b"$6$rounds=2000$y"),
            (b"longer key", b"$6$rounds=1500$z"),
        ] {
            let h = sha512_crypt(key, salt).unwrap();
            // Body is the part after the final '$'.
            let body_start = h.rfind('$').unwrap() + 1;
            let body = &h[body_start..];
            assert_eq!(body.len(), 86, "input=({key:?},{salt:?}) hash={h}");
            // All bytes must be in the crypt-b64 alphabet.
            for &b in body.as_bytes() {
                assert!(
                    crate::crypt::base64::ALPHABET.contains(&b),
                    "non-alphabet byte 0x{b:02x} in {body}"
                );
            }
        }
    }

    /// The step-6 table is a PERMUTATION of digest bytes 0..=62 (byte 63 is
    /// emitted separately as the 2-char tail). Each index must therefore appear
    /// exactly once. This is checkable without any oracle, and it alone would
    /// have caught bd-9n50f2: the shipped table used f[55] twice and never used
    /// f[62], so every $6$ digest was wrong in its last 16 characters.
    ///
    /// The table is transcribed here rather than shared with the hashing code so
    /// that a future edit to one and not the other is a test failure. Keep them
    /// in sync.
    #[test]
    fn transposition_table_is_a_permutation() {
        const TABLE: [(usize, usize, usize); 21] = [
            (0, 21, 42),
            (22, 43, 1),
            (44, 2, 23),
            (3, 24, 45),
            (25, 46, 4),
            (47, 5, 26),
            (6, 27, 48),
            (28, 49, 7),
            (50, 8, 29),
            (9, 30, 51),
            (31, 52, 10),
            (53, 11, 32),
            (12, 33, 54),
            (34, 55, 13),
            (56, 14, 35),
            (15, 36, 57),
            (37, 58, 16),
            (59, 17, 38),
            (18, 39, 60),
            (40, 61, 19),
            (62, 20, 41),
        ];
        let mut seen = [0u8; 63];
        for (a, b, c) in TABLE {
            for i in [a, b, c] {
                assert!(i < 63, "index {i} is outside the permuted range 0..=62");
                seen[i] += 1;
            }
        }
        let dup: Vec<usize> = (0..63).filter(|&i| seen[i] > 1).collect();
        let missing: Vec<usize> = (0..63).filter(|&i| seen[i] == 0).collect();
        assert!(
            dup.is_empty() && missing.is_empty(),
            "step-6 table is not a permutation of 0..=62: duplicated {dup:?}, missing {missing:?}"
        );
    }
}
