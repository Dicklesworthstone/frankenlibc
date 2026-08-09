//! SHA-256-based crypt(3) — the `$5$` password hashing scheme.
//!
//! Reference: <https://www.akkadia.org/drepper/SHA-crypt.txt>
//!
//! Same algorithm structure as [`crate::crypt::sha512`] but with
//! SHA-256 in place of SHA-512 (32-byte chaining values instead of
//! 64-byte). Output is the 31-byte hash encoded as 43 crypt-base64
//! chars.

use sha2::{Digest, Sha256};

use crate::crypt::base64;
use crate::crypt::salt::parse_crypt_salt;

/// Hash `key` against the `$5$[rounds=NNNN$]salt$...` formatted
/// `salt_bytes`, returning the full crypt-format result string.
pub fn sha256_crypt(key: &[u8], salt_bytes: &[u8]) -> Option<String> {
    let setting = parse_crypt_salt(salt_bytes, 3)?;
    let salt = setting.salt;
    let rounds = setting.rounds as usize;

    let mut digest_b = Sha256::new();
    digest_b.update(key);
    digest_b.update(salt);
    digest_b.update(key);
    let hash_b = digest_b.finalize();

    let mut digest_a = Sha256::new();
    digest_a.update(key);
    digest_a.update(salt);
    let mut remaining = key.len();
    while remaining >= 32 {
        digest_a.update(&hash_b[..]);
        remaining -= 32;
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

    let mut digest_dp = Sha256::new();
    for _ in 0..key.len() {
        digest_dp.update(key);
    }
    let hash_dp = digest_dp.finalize();
    let mut p_bytes = vec![0u8; key.len()];
    for (i, dst) in p_bytes.iter_mut().enumerate() {
        *dst = hash_dp[i % 32];
    }

    let mut digest_ds = Sha256::new();
    let ds_count = 16 + (hash_a[0] as usize);
    for _ in 0..ds_count {
        digest_ds.update(salt);
    }
    let hash_ds = digest_ds.finalize();
    let mut s_bytes = vec![0u8; salt.len()];
    for (i, dst) in s_bytes.iter_mut().enumerate() {
        *dst = hash_ds[i % 32];
    }

    let mut c_input = hash_a.to_vec();
    for i in 0..rounds {
        let mut digest_c = Sha256::new();
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

    let f = &c_input;
    let reordered: Vec<u8> = [
        (f[0], f[10], f[20]),
        (f[21], f[1], f[11]),
        (f[12], f[22], f[2]),
        (f[3], f[13], f[23]),
        (f[24], f[4], f[14]),
        (f[15], f[25], f[5]),
        (f[6], f[16], f[26]),
        (f[27], f[7], f[17]),
        (f[18], f[28], f[8]),
        (f[9], f[19], f[29]),
    ]
    .iter()
    .flat_map(|(a, b, c)| [*a, *b, *c])
    .collect();

    let mut encoded = base64::encode(&reordered, 40);
    // Drepper's final group for $5$ is b64_from_24bit(0, alt_result[31],
    // alt_result[30], 3), i.e. B1 = f[31] and B0 = f[30]. With the group
    // packed big-endian and right-aligned, that is the byte order below.
    // It used to read [f[30], f[31]], which was correct ONLY against the old
    // reversed encoder — fixing the encoder without flipping this pair would
    // have moved the bug rather than removed it. bd-9n50f2.
    let last = [f[31], f[30]];
    encoded.push_str(&base64::encode(&last, 3));

    let salt_str = core::str::from_utf8(salt).unwrap_or("");
    // The prefix is echoed when the INPUT carried one, not when the count
    // differs from the default — `$5$rounds=5000$s$` keeps its prefix on the
    // host. bd-fegsgf.
    Some(if setting.rounds_custom {
        format!("$5$rounds={rounds}${salt_str}${encoded}")
    } else {
        format!("$5${salt_str}${encoded}")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known-answer vectors captured from the live host libxcrypt
    /// (`libcrypt.so.1`) while closing bd-fegsgf. These pin the byte-for-byte
    /// output without needing the host at test time, so a regression in the
    /// digest, the transposition table or the base-64 encoder fails here and
    /// not only in the abi differential gate.
    #[test]
    fn known_answers_match_host_libxcrypt() {
        for (key, salt, expect) in [
            (
                &b"Hello world!"[..],
                &b"$5$saltstring"[..],
                "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5",
            ),
            (
                b"password",
                b"$5$saltsaltsalt$",
                "$5$saltsaltsalt$/N7c7rmQoc7bVRcUisZxkSYJRyapzgVkea220umjO3C",
            ),
            (
                b"",
                b"$5$emptysalt$",
                "$5$emptysalt$7Ggii2OZa/7DQx2XFDomXtHl2Ea.SGT2XvtgDslxc.8",
            ),
            (
                b"password",
                b"$5$rounds=1000$x$",
                "$5$rounds=1000$x$qJLv4pvDPeZRN4swJyhU3ZR3jSNhO4Xoyru4iIVxwM8",
            ),
        ] {
            assert_eq!(sha256_crypt(key, salt).as_deref(), Some(expect));
        }
    }

    /// An explicit `rounds=5000` must be echoed even though it equals the
    /// default — the only surviving `$5$` divergence before bd-fegsgf.
    #[test]
    fn explicit_default_rounds_keeps_prefix() {
        let h = sha256_crypt(b"password", b"$5$rounds=5000$saltsaltsalt$").unwrap();
        assert_eq!(
            h,
            "$5$rounds=5000$saltsaltsalt$/N7c7rmQoc7bVRcUisZxkSYJRyapzgVkea220umjO3C"
        );
    }

    /// A malformed `rounds=` is a rejected setting, not a request for the
    /// nearest legal count; the abi layer renders `None` as libxcrypt's `*0`.
    #[test]
    fn malformed_rounds_is_rejected() {
        for salt in [
            &b"$5$rounds=999$x$"[..],
            b"$5$rounds=1000000000$x$",
            b"$5$rounds=0500$x$",
            b"$5$rounds=abc$x$",
            b"$5$rounds=5000x$x$",
        ] {
            assert_eq!(sha256_crypt(b"password", salt), None, "salt={salt:?}");
        }
    }

    #[test]
    fn characterization_simple_key_default_rounds() {
        let h = sha256_crypt(b"Hello world!", b"$5$saltstring").unwrap();
        assert!(h.starts_with("$5$saltstring$"));
        // 43 crypt-base64 chars after the salt $ separator.
        assert_eq!(h.len(), "$5$saltstring$".len() + 43);
        assert!(!h.contains("rounds="));
    }

    #[test]
    fn empty_key() {
        let h = sha256_crypt(b"", b"$5$saltstring").unwrap();
        assert!(h.starts_with("$5$saltstring$"));
        assert_eq!(h.len(), "$5$saltstring$".len() + 43);
    }

    #[test]
    fn determinism_same_input_same_output() {
        let a = sha256_crypt(b"key", b"$5$salt").unwrap();
        let b = sha256_crypt(b"key", b"$5$salt").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn different_keys_produce_different_output() {
        let a = sha256_crypt(b"key1", b"$5$salt").unwrap();
        let b = sha256_crypt(b"key2", b"$5$salt").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn different_salts_produce_different_output() {
        let a = sha256_crypt(b"key", b"$5$salt1").unwrap();
        let b = sha256_crypt(b"key", b"$5$salt2").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn rounds_5000_omits_rounds_prefix() {
        let h = sha256_crypt(b"key", b"$5$salt").unwrap();
        assert!(h.starts_with("$5$salt$"));
        assert!(!h.contains("rounds="));
    }

    #[test]
    fn explicit_rounds_includes_prefix() {
        let h = sha256_crypt(b"key", b"$5$rounds=10000$salt").unwrap();
        assert!(h.starts_with("$5$rounds=10000$salt$"));
    }

    #[test]
    fn output_body_is_43_crypt_base64_chars() {
        for (key, salt) in [
            (&b""[..], b"$5$x".as_slice()),
            (b"a", b"$5$rounds=2000$y"),
            (b"longer key", b"$5$rounds=1500$z"),
        ] {
            let h = sha256_crypt(key, salt).unwrap();
            let body_start = h.rfind('$').unwrap() + 1;
            let body = &h[body_start..];
            assert_eq!(body.len(), 43, "input=({key:?},{salt:?}) hash={h}");
            for &b in body.as_bytes() {
                assert!(
                    crate::crypt::base64::ALPHABET.contains(&b),
                    "non-alphabet byte 0x{b:02x} in {body}"
                );
            }
        }
    }
}
