//! MD5-based crypt(3) — the `$1$` password hashing scheme.
//!
//! Reference: <http://www.freebsd.org/cgi/cvsweb.cgi/src/lib/libcrypt/crypt-md5.c>
//! (Poul-Henning Kamp's original FreeBSD implementation, also used by
//! glibc and most Linux distributions.)
//!
//! Salt is at most 8 bytes (truncated). Always 1000 rounds — the
//! `rounds=` parameter is NOT recognized for `$1$` hashes.

use md5::{Digest, Md5};

use crate::crypt::base64;

/// Maximum salt length per the PHK MD5-crypt convention.
pub const MAX_MD5_SALT: usize = 8;

/// Hash `key` against the `$1$salt$...` formatted `salt_bytes`,
/// returning the full crypt-format result string.
pub fn md5_crypt(key: &[u8], salt_bytes: &[u8]) -> Option<String> {
    if salt_bytes.len() < 3 {
        return None;
    }
    // Parse salt (max 8 chars after `$1$`, terminated by `$` or end).
    let rest = &salt_bytes[3..];
    let salt_end = rest
        .iter()
        .position(|&b| b == b'$')
        .unwrap_or(rest.len())
        .min(MAX_MD5_SALT);
    let salt = &rest[..salt_end];

    // Step 1: Digest B = MD5(key + salt + key)
    let mut digest_b = Md5::new();
    digest_b.update(key);
    digest_b.update(salt);
    digest_b.update(key);
    let hash_b = digest_b.finalize();

    // Step 2: Digest A = MD5(key + "$1$" + salt + B-bytes-for-keylen
    //                         + bit-pattern of key.len())
    let mut digest_a = Md5::new();
    digest_a.update(key);
    digest_a.update(b"$1$");
    digest_a.update(salt);

    let mut remaining = key.len();
    while remaining >= 16 {
        digest_a.update(&hash_b[..]);
        remaining -= 16;
    }
    if remaining > 0 {
        digest_a.update(&hash_b[..remaining]);
    }

    let mut n = key.len();
    while n > 0 {
        if n & 1 != 0 {
            digest_a.update([0u8]);
        } else {
            digest_a.update(&key[..1]);
        }
        n >>= 1;
    }
    let mut result = digest_a.finalize().to_vec();

    // Step 3: 1000 rounds of mixing.
    for i in 0..1000u32 {
        let mut digest_c = Md5::new();
        if i & 1 != 0 {
            digest_c.update(key);
        } else {
            digest_c.update(&result);
        }
        if i % 3 != 0 {
            digest_c.update(salt);
        }
        if i % 7 != 0 {
            digest_c.update(key);
        }
        if i & 1 != 0 {
            digest_c.update(&result);
        } else {
            digest_c.update(key);
        }
        let r = digest_c.finalize();
        result.clear();
        result.extend_from_slice(&r);
    }

    // Step 4: Output formatting via crypt-base64 byte transposition.
    let f = &result;
    let reordered: Vec<u8> = vec![
        f[0], f[6], f[12], f[1], f[7], f[13], f[2], f[8], f[14], f[3], f[9], f[15], f[4], f[10],
        f[5],
    ];
    let mut encoded = base64::encode(&reordered, 20);
    let last = [f[11]];
    encoded.push_str(&base64::encode(&last, 2));

    let salt_str = core::str::from_utf8(salt).unwrap_or("");
    Some(format!("$1${salt_str}${encoded}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn salt_is_truncated_to_8_chars() {
        // 12-char salt should match the same key against the 8-char prefix.
        let h12 = md5_crypt(b"key", b"$1$abcdefghijkl$").unwrap();
        let h8 = md5_crypt(b"key", b"$1$abcdefgh$").unwrap();
        let body12: &str = &h12[h12.rfind('$').unwrap() + 1..];
        let body8: &str = &h8[h8.rfind('$').unwrap() + 1..];
        assert_eq!(body12, body8);
    }

    #[test]
    fn output_length_is_constant() {
        // $1$<salt>$<22 base-64 chars>
        for (key, salt) in [
            (&b""[..], b"$1$$".as_slice()),
            (b"a", b"$1$x$"),
            (b"longer key", b"$1$abcdefgh$"),
        ] {
            let h = md5_crypt(key, salt).unwrap();
            let body_start = h.rfind('$').unwrap() + 1;
            assert_eq!(h[body_start..].len(), 22);
        }
    }

    #[test]
    fn determinism_same_input_same_output() {
        let a = md5_crypt(b"key", b"$1$salt$").unwrap();
        let b = md5_crypt(b"key", b"$1$salt$").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn different_keys_produce_different_output() {
        let a = md5_crypt(b"key1", b"$1$salt$").unwrap();
        let b = md5_crypt(b"key2", b"$1$salt$").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn different_salts_produce_different_output() {
        let a = md5_crypt(b"key", b"$1$salt1$").unwrap();
        let b = md5_crypt(b"key", b"$1$salt2$").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn salt_too_short_returns_none() {
        assert!(md5_crypt(b"key", b"$1").is_none());
    }

    #[test]
    fn empty_key_produces_valid_hash() {
        let h = md5_crypt(b"", b"$1$saltval$").unwrap();
        assert!(h.starts_with("$1$saltval$"));
        let body_start = h.rfind('$').unwrap() + 1;
        assert_eq!(h[body_start..].len(), 22);
    }

    #[test]
    fn output_body_uses_only_crypt_base64_alphabet() {
        let h = md5_crypt(b"any key", b"$1$abcdefgh$").unwrap();
        let body_start = h.rfind('$').unwrap() + 1;
        for &b in h[body_start..].as_bytes() {
            assert!(
                crate::crypt::base64::ALPHABET.contains(&b),
                "non-alphabet byte 0x{b:02x}"
            );
        }
    }

    #[test]
    fn rounds_param_in_salt_is_ignored_for_dollar_one() {
        // PHK MD5-crypt does NOT recognize rounds=. The salt parser
        // should treat the entire salt portion (up to next $) as
        // literal salt bytes.
        let h_no_rounds = md5_crypt(b"key", b"$1$salt$").unwrap();
        // With "rounds=10$" prefix, the salt is "rounds=1" (truncated to 8).
        let h_with_prefix = md5_crypt(b"key", b"$1$rounds=10$salt$").unwrap();
        // They MUST differ — no special handling of rounds=.
        assert_ne!(h_no_rounds, h_with_prefix);
    }
}
