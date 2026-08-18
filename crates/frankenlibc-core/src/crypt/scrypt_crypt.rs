//! The `$7$` crypt(3) scheme — Colin Percival's scrypt hash format.
//!
//! ```text
//!   $7$ N rrrrr ppppp <salt> $ <43 chars>
//!       ^ ^^^^^ ^^^^^ ^^^^^^   ^^^^^^^^^
//!       | |     |     |        scrypt output, 32 bytes
//!       | |     |     variable-length salt, used as RAW ASCII
//!       | |     p, 30-bit little-endian crypt base-64
//!       | r, 30-bit little-endian crypt base-64
//!       log2(N), one crypt base-64 character
//! ```
//!
//! ## Every field here was decoded from the live host, not from a document
//!
//! `crypt_gensalt("$7$", count, ..)` was probed across counts 6..11 and moved
//! the first character one step through the alphabet each time, which is what
//! identifies it as `log2(N)` rather than a cost index. The `r` and `p` widths
//! were then confirmed by feeding settings that differ only in those fields and
//! watching the hash change. Finally the whole thing was validated end to end
//! against `hashlib.scrypt`: decode the setting, run scrypt, re-encode, compare
//! to what `libcrypt.so.1` returned. It matched exactly, which is what makes
//! the parameter layout a measurement rather than a guess.
//!
//! ## THE OUTPUT ENCODING IS NOT [`crate::crypt::base64`]
//!
//! This is the trap in this file. `$1$`/`$5$`/`$6$` pack each THREE-byte group
//! big-endian into a 24-bit word and emit it six bits at a time; `$7$` runs a
//! single little-endian bit stream across the whole 32-byte output. Same
//! alphabet, same length, different answer. Measured on two vectors:
//!
//! ```text
//!   want         j52Gpvx3asOcAf5W/3mbFW2IoqiBftt2f5Q/EQOIZ11
//!   running LE   j52Gpvx3asOcAf5W/3mbFW2IoqiBftt2f5Q/EQOIZ11   <- matches
//!   group BE     63ovLsRxVue76e5nT4GEEVIYqoChHstO32wuFR82kIC   <- crypt::base64
//! ```
//!
//! Reusing `crypt::base64::encode` here would produce a hash that is
//! well-formed, correct length, correct alphabet and wrong in every character.
//! That is exactly bd-9n50f2, which shipped once already across `$1$`/`$5$`/
//! `$6$` simultaneously and made every real `/etc/shadow` hash unverifiable.
//! Hence a local encoder with its own name.

use crate::crypt::scrypt::scrypt;

/// The crypt(3) alphabet, shared with [`crate::crypt::base64`]; only the
/// PACKING differs. See the module docs.
const ALPHABET: &[u8; 64] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// scrypt output length for `$7$`, and the 43 characters that encodes to.
const DK_LEN: usize = 32;
const HASH_CHARS: usize = 43;
/// `r` and `p` are each 30 bits, five base-64 characters.
const PARAM_CHARS: usize = 5;

#[inline]
fn value_of(c: u8) -> Option<u32> {
    ALPHABET.iter().position(|&a| a == c).map(|i| i as u32)
}

/// Decode a 30-bit little-endian base-64 field: least-significant character first.
fn decode_param(field: &[u8]) -> Option<u32> {
    let mut value = 0u32;
    for (i, &c) in field.iter().enumerate() {
        value |= value_of(c)? << (6 * i as u32);
    }
    Some(value)
}

/// Encode `input` as a single little-endian bit stream. NOT `crypt::base64`.
fn encode_running_le(input: &[u8], chars: usize) -> String {
    let mut out = String::with_capacity(chars);
    let mut acc = 0u32;
    let mut bits = 0u32;
    for &byte in input {
        acc |= u32::from(byte) << bits;
        bits += 8;
        while bits >= 6 && out.len() < chars {
            out.push(ALPHABET[(acc & 0x3f) as usize] as char);
            acc >>= 6;
            bits -= 6;
        }
    }
    // The 32-byte output is not a multiple of three bytes, so the final
    // partial group still contributes a character.
    while out.len() < chars {
        out.push(ALPHABET[(acc & 0x3f) as usize] as char);
        acc >>= 6;
    }
    out
}

/// Hash `key` against a `$7$` setting, returning the full crypt string.
///
/// Returns `None` for a setting this scheme does not accept, which the ABI
/// layer turns into libxcrypt's failure token rather than a NULL.
pub fn scrypt_crypt(key: &[u8], setting: &[u8]) -> Option<String> {
    let rest = setting.strip_prefix(b"$7$")?;
    if rest.len() < 1 + 2 * PARAM_CHARS {
        return None;
    }
    let n_log2 = value_of(rest[0])?;
    // N is used as a shift below; anything at or past the word size is not a
    // parameter this build can honour, and clamping would silently weaken it.
    if n_log2 < 1 || n_log2 > 63 {
        return None;
    }
    let r = decode_param(&rest[1..1 + PARAM_CHARS])?;
    let p = decode_param(&rest[1 + PARAM_CHARS..1 + 2 * PARAM_CHARS])?;

    // The salt runs to the end of the setting, or to the `$` that separates a
    // previously-computed hash. Passing a full hash back in as the setting is
    // how every caller verifies a password, so this must accept it.
    let tail = &rest[1 + 2 * PARAM_CHARS..];
    let salt = match tail.iter().position(|&c| c == b'$') {
        Some(end) => &tail[..end],
        None => tail,
    };
    if salt.is_empty() {
        return None;
    }

    let n = 1usize.checked_shl(n_log2)?;
    let mut out = [0u8; DK_LEN];
    // The salt is fed to scrypt as RAW ASCII — the setting characters
    // themselves, not a decode of them. Measured: decoding the salt as base-64
    // first produces a different hash and matches nothing.
    scrypt(key, salt, n, r as usize, p as usize, &mut out)?;

    let prefix = core::str::from_utf8(&setting[..3 + 1 + 2 * PARAM_CHARS]).ok()?;
    let salt_text = core::str::from_utf8(salt).ok()?;
    Some(format!(
        "{prefix}{salt_text}${}",
        encode_running_le(&out, HASH_CHARS)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two packings differ, and only the running-LE one is `$7$`. Pinned
    /// directly so a future "tidy-up" that reaches for `crypt::base64` fails
    /// here rather than in a hash nobody can verify.
    #[test]
    fn output_packing_is_not_crypt_base64() {
        let raw: Vec<u8> = (0..32u8).collect();
        let ours = encode_running_le(&raw, HASH_CHARS);
        let grouped = crate::crypt::base64::encode(&raw, HASH_CHARS);
        assert_eq!(ours.len(), HASH_CHARS);
        assert_eq!(grouped.len(), HASH_CHARS);
        assert_ne!(
            ours, grouped,
            "if these ever agree, one of the two encoders has been changed and \
             $1$/$5$/$6$ or $7$ is now wrong (bd-9n50f2)"
        );
    }

    #[test]
    fn parameter_fields_decode_little_endian() {
        // "/...." is 1; "0...." is 2; "/0..." is 1 + 2*64 = 129.
        assert_eq!(decode_param(b"/....").unwrap(), 1);
        assert_eq!(decode_param(b"0....").unwrap(), 2);
        assert_eq!(decode_param(b"/0...").unwrap(), 1 + 2 * 64);
    }

    #[test]
    fn malformed_settings_are_refused() {
        assert!(scrypt_crypt(b"pw", b"$5$notscrypt").is_none());
        assert!(scrypt_crypt(b"pw", b"$7$").is_none());
        assert!(
            scrypt_crypt(b"pw", b"$7$A/....").is_none(),
            "truncated params"
        );
        assert!(
            scrypt_crypt(b"pw", b"$7$A/..../....").is_none(),
            "empty salt"
        );
        assert!(
            scrypt_crypt(b"pw", b"$7$!/..../....salt").is_none(),
            "bad N char"
        );
    }

    /// Vectors probed from live libxcrypt on this host.
    #[test]
    fn matches_live_libxcrypt_vectors() {
        let cases: &[(&str, &str, &str)] = &[
            (
                "pleaseletmein",
                "$7$A/..../....saltsalt",
                "$7$A/..../....saltsalt$j52Gpvx3asOcAf5W/3mbFW2IoqiBftt2f5Q/EQOIZ11",
            ),
            (
                "password",
                "$7$8/..../....abcdefgh",
                "$7$8/..../....abcdefgh$91Mm9rMVtydowqeGE8ctdQN.C27cyyVaMPv5BkctUv.",
            ),
            (
                "",
                "$7$6/..../....zzzzzzzz",
                "$7$6/..../....zzzzzzzz$twsHHnIZ5N9dVGAazpYW/5xPjmnnyERRkDI770WRld/",
            ),
            (
                "a",
                "$7$6/..../....zzzzzzzz",
                "$7$6/..../....zzzzzzzz$8bC5.IY9AFXMUl4iaCyhSE/ELi3JJWoyZU7Zi4Z0pq0",
            ),
            // p = 2 and r = 2: the two fields that would look identical if the
            // little-endian decode were reversed.
            (
                "password",
                "$7$6/..../1....abcdefgh",
                "$7$6/..../1....abcdefgh$bSIj281JqkJoEY5nOrDPSugWyy.B9.XnkOSzqYIJeo5",
            ),
            (
                "password",
                "$7$60..../....abcdefgh",
                "$7$60..../....abcdefgh$pGAk4Zxqs1cDKsjUFgbLFTJzUOMDR0pW9XkIgrH.P10",
            ),
            (
                "long password with spaces and symbols !@#$%^",
                "$7$8/..../....SaltySalt",
                "$7$8/..../....SaltySalt$.yd4PHsUCHjvS7oatqCKoEG0T.NirEqjge750V4p.f/",
            ),
        ];
        for (password, setting, expected) in cases {
            let got = scrypt_crypt(password.as_bytes(), setting.as_bytes());
            assert_eq!(got.as_deref(), Some(*expected), "setting {setting}");
        }
    }

    /// Verifying a password means passing the STORED HASH back as the setting.
    /// If the salt parse stopped at the wrong place this would silently differ.
    #[test]
    fn full_hash_round_trips_as_a_setting() {
        let stored = "$7$8/..../....abcdefgh$91Mm9rMVtydowqeGE8ctdQN.C27cyyVaMPv5BkctUv.";
        assert_eq!(
            scrypt_crypt(b"password", stored.as_bytes()).as_deref(),
            Some(stored)
        );
    }
}
