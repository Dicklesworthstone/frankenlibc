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
    let (rounds, salt) = parse_crypt_salt(salt_bytes, 3);
    let rounds = rounds as usize;

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
    let last = [f[30], f[31]];
    encoded.push_str(&base64::encode(&last, 3));

    let salt_str = core::str::from_utf8(salt).unwrap_or("");
    Some(if rounds == 5000 {
        format!("$5${salt_str}${encoded}")
    } else {
        format!("$5$rounds={rounds}${salt_str}${encoded}")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
