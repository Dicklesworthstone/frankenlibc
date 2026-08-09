//! SHA-crypt salt prefix parser (`$N$[rounds=NNNN$]salt$...`).
//!
//! The SHA-crypt wire format prefixes the encrypted hash with `$5$`
//! (SHA-256) or `$6$` (SHA-512), followed by an optional
//! `rounds=NNNN$` parameter, then the salt (up to 16 bytes,
//! terminated by `$`), then the encrypted body. This module extracts
//! the rounds + salt portion from a complete hash buffer.
//!
//! Used by `crypt_sha256` / `crypt_sha512` in the abi layer.
//!
//! ## `rounds=` is REJECTED, never clamped (bd-fegsgf)
//!
//! This parser used to clamp an out-of-range `rounds=` into
//! `[1000, 999999999]` and to fall back to 5000 for anything it could not
//! parse, so a malformed setting still produced a hash. The host
//! (libxcrypt `libcrypt.so.1`) does the opposite: it validates the field and
//! returns the `*0` failure token with `EINVAL` for every deviation. Probed
//! live on this host with `key="password"`:
//!
//! ```text
//!   $5$rounds=1000$x$                    -> $5$rounds=1000$x$qJLv4pv...   errno=0
//!   $5$rounds=1001$x$ / =4999$x$         -> accepted                       errno=0
//!   $5$rounds=999$x$                     -> *0  errno=22   (below minimum)
//!   $5$rounds=1000000000$x$              -> *0  errno=22   (above maximum)
//!   $5$rounds=0500$x$                    -> *0  errno=22   (leading zero)
//!   $5$rounds=+5000$x$ / = 5000$x$       -> *0  errno=22   (sign / space)
//!   $5$rounds=-1$x$ / =abc$x$ / =$slt$   -> *0  errno=22   (no leading 1-9)
//!   $5$rounds=99999999999999999999999$x$ -> *0  errno=22   (overflow)
//!   $5$rounds=5000x$slt$ / =12345 / =5000-> *0  errno=22   (no closing `$`)
//! ```
//!
//! Because the whole point of a `$` setting is that it can be re-derived from
//! a stored hash, silently substituting a different round count is worse than
//! failing: it mints a hash the host will never reproduce.
//!
//! ## `rounds_custom`, not `rounds != 5000`
//!
//! The callers used to re-emit the `rounds=` prefix whenever the count
//! differed from the 5000 default. The host instead echoes the prefix
//! whenever the *input setting carried one*, so an explicit
//! `$5$rounds=5000$saltsaltsalt$` round-trips with its prefix intact. That
//! single mismatch was the only remaining `$5$`/`$6$` divergence — the
//! digests themselves were already byte-identical.

/// Default SHA-crypt round count when no `rounds=` parameter is present.
pub const DEFAULT_SHA_ROUNDS: u32 = 5000;

/// Lower bound on the SHA-crypt round count (per RFC / glibc clamp).
pub const MIN_SHA_ROUNDS: u32 = 1000;

/// Upper bound on the SHA-crypt round count (per RFC / glibc clamp).
pub const MAX_SHA_ROUNDS: u32 = 999_999_999;

/// Maximum salt length per the SHA-crypt specification.
pub const MAX_SALT_LEN: usize = 16;

/// A parsed SHA-crypt setting: the round count, whether the input spelled it
/// out, and the salt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShaCryptSetting<'a> {
    /// Round count to run the key-stretching loop for.
    pub rounds: u32,
    /// True when the input setting carried an explicit `rounds=NNNN$` field.
    /// Drives whether the output re-emits that field — independently of
    /// whether `rounds` happens to equal [`DEFAULT_SHA_ROUNDS`].
    pub rounds_custom: bool,
    /// Salt bytes, borrowed from the input, at most [`MAX_SALT_LEN`] long.
    pub salt: &'a [u8],
}

/// Extract the rounds + salt portion from a SHA-crypt hash buffer.
///
/// `salt_bytes` is the full hash buffer (including the leading `$N$`
/// prefix); `prefix_len` is the byte length of that prefix (3 for
/// `$5$` / `$6$`).
///
/// Returns `None` when the setting is malformed, which the caller reports as
/// the `*0` failure token with `EINVAL` — see the module docs for the live
/// host probe that fixes each rule. A setting with no `rounds=` field is
/// always well-formed: the salt is simply everything up to the next `$`,
/// capped at [`MAX_SALT_LEN`].
pub fn parse_crypt_salt(salt_bytes: &[u8], prefix_len: usize) -> Option<ShaCryptSetting<'_>> {
    if prefix_len > salt_bytes.len() {
        return None;
    }
    let rest = &salt_bytes[prefix_len..];

    let (rounds, rounds_custom, salt_start) = match rest.strip_prefix(b"rounds=") {
        Some(num) => {
            // libxcrypt requires a leading 1-9: that single rule rejects the
            // empty field, a sign, leading whitespace, a leading zero and any
            // non-numeric text, all of which strtoul would otherwise accept or
            // silently read as zero.
            if !matches!(num.first(), Some(b'1'..=b'9')) {
                return None;
            }
            let digits = num.iter().take_while(|b| b.is_ascii_digit()).count();
            // The digit run must be terminated by the field separator; a
            // trailing `x`, or running off the end of the string, is a reject.
            if num.get(digits) != Some(&b'$') {
                return None;
            }
            // Saturating accumulation: an overflowing run cannot land back
            // inside the accepted range, so saturation and C's ERANGE reject
            // the same inputs.
            let mut value: u64 = 0;
            for &d in &num[..digits] {
                value = value
                    .saturating_mul(10)
                    .saturating_add(u64::from(d - b'0'));
            }
            if !(u64::from(MIN_SHA_ROUNDS)..=u64::from(MAX_SHA_ROUNDS)).contains(&value) {
                return None;
            }
            (value as u32, true, b"rounds=".len() + digits + 1)
        }
        None => (DEFAULT_SHA_ROUNDS, false, 0),
    };

    let salt_rest = &rest[salt_start..];
    let salt_end = salt_rest
        .iter()
        .position(|&b| b == b'$')
        .unwrap_or(salt_rest.len())
        .min(MAX_SALT_LEN);
    Some(ShaCryptSetting {
        rounds,
        rounds_custom,
        salt: &salt_rest[..salt_end],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(input: &[u8]) -> ShaCryptSetting<'_> {
        parse_crypt_salt(input, 3).expect("setting should parse")
    }

    #[test]
    fn parse_simple_no_rounds() {
        // $6$abcdef$rest...
        let s = ok(b"$6$abcdef$rest");
        assert_eq!(s.rounds, DEFAULT_SHA_ROUNDS);
        assert!(!s.rounds_custom);
        assert_eq!(s.salt, b"abcdef");
    }

    #[test]
    fn parse_explicit_rounds() {
        let s = ok(b"$6$rounds=10000$saltvalue$body");
        assert_eq!(s.rounds, 10000);
        assert!(s.rounds_custom);
        assert_eq!(s.salt, b"saltvalue");
    }

    /// An explicit `rounds=5000` is NOT the same setting as no `rounds=` field:
    /// the count matches the default but the output must still carry the
    /// prefix. This is the divergence bd-fegsgf was actually about.
    #[test]
    fn explicit_default_rounds_is_still_custom() {
        let s = ok(b"$5$rounds=5000$saltsaltsalt$");
        assert_eq!(s.rounds, DEFAULT_SHA_ROUNDS);
        assert!(s.rounds_custom);
        assert_eq!(s.salt, b"saltsaltsalt");
    }

    /// These four used to assert clamping (`rounds=10` -> 1000, `rounds=10^9`
    /// -> 999999999) and default-substitution (`rounds=abc`/`rounds=` -> 5000).
    /// The host rejects every one of them outright, so the old assertions were
    /// faithful descriptions of the bug and are replaced, not adjusted.
    /// bd-fegsgf.
    #[test]
    fn parse_rounds_below_minimum_is_rejected() {
        assert_eq!(parse_crypt_salt(b"$6$rounds=10$x$", 3), None);
        assert_eq!(parse_crypt_salt(b"$6$rounds=999$x$", 3), None);
    }

    #[test]
    fn parse_rounds_above_maximum_is_rejected() {
        assert_eq!(parse_crypt_salt(b"$6$rounds=1000000000$x$", 3), None);
        // Overflows u64 during accumulation; saturation must not wrap it back
        // into range.
        assert_eq!(
            parse_crypt_salt(b"$6$rounds=99999999999999999999999$x$", 3),
            None
        );
    }

    #[test]
    fn parse_garbage_rounds_is_rejected() {
        assert_eq!(parse_crypt_salt(b"$6$rounds=abc$slt$", 3), None);
        assert_eq!(parse_crypt_salt(b"$6$rounds=$slt$", 3), None);
        assert_eq!(parse_crypt_salt(b"$6$rounds=-1$x$", 3), None);
        assert_eq!(parse_crypt_salt(b"$6$rounds=+5000$x$", 3), None);
        assert_eq!(parse_crypt_salt(b"$6$rounds= 5000$x$", 3), None);
    }

    #[test]
    fn parse_rounds_leading_zero_is_rejected() {
        assert_eq!(parse_crypt_salt(b"$6$rounds=0500$x$", 3), None);
        assert_eq!(parse_crypt_salt(b"$6$rounds=00$x$", 3), None);
    }

    #[test]
    fn parse_rounds_unterminated_field_is_rejected() {
        // A digit run that is not closed by `$` — whether by a stray character
        // or by the end of the string — is not a rounds field.
        assert_eq!(parse_crypt_salt(b"$6$rounds=5000x$slt$", 3), None);
        assert_eq!(parse_crypt_salt(b"$6$rounds=12345", 3), None);
    }

    #[test]
    fn parse_rounds_at_min_boundary() {
        let s = ok(b"$6$rounds=1000$x$");
        assert_eq!(s.rounds, MIN_SHA_ROUNDS);
        assert!(s.rounds_custom);
    }

    #[test]
    fn parse_rounds_at_max_boundary() {
        let s = ok(b"$6$rounds=999999999$x$");
        assert_eq!(s.rounds, MAX_SHA_ROUNDS);
        assert!(s.rounds_custom);
    }

    #[test]
    fn parse_rounds_just_inside_boundaries() {
        assert_eq!(ok(b"$6$rounds=1001$x$").rounds, 1001);
        assert_eq!(ok(b"$6$rounds=999999998$x$").rounds, 999_999_998);
    }

    #[test]
    fn parse_salt_truncated_to_max_len() {
        // 20-byte salt should clip to 16.
        let s = ok(b"$6$0123456789ABCDEFXYZ$body");
        assert_eq!(s.salt.len(), MAX_SALT_LEN);
        assert_eq!(s.salt, b"0123456789ABCDEF");
    }

    #[test]
    fn parse_salt_no_trailing_dollar_consumes_to_end() {
        // No closing $ → salt is everything up to the cap.
        assert_eq!(ok(b"$6$abc").salt, b"abc");
    }

    #[test]
    fn parse_empty_salt() {
        let s = ok(b"$6$$body");
        assert_eq!(s.rounds, DEFAULT_SHA_ROUNDS);
        assert!(!s.rounds_custom);
        assert_eq!(s.salt, b"");
    }

    #[test]
    fn parse_explicit_rounds_then_empty_salt() {
        let s = ok(b"$6$rounds=7777$$body");
        assert_eq!(s.rounds, 7777);
        assert!(s.rounds_custom);
        assert_eq!(s.salt, b"");
    }

    #[test]
    fn parse_prefix_len_zero_no_consumption() {
        // No $N$ prefix → start at offset 0.
        let s = parse_crypt_salt(b"abc$body", 0).unwrap();
        assert_eq!(s.rounds, DEFAULT_SHA_ROUNDS);
        assert_eq!(s.salt, b"abc");
    }

    #[test]
    fn parse_prefix_len_past_end_is_rejected() {
        // Defensive: prefix_len > buffer.
        assert_eq!(parse_crypt_salt(b"$6", 99), None);
    }

    #[test]
    fn parse_explicit_rounds_with_max_salt() {
        let s = ok(b"$6$rounds=20000$0123456789ABCDEF$body");
        assert_eq!(s.rounds, 20000);
        assert_eq!(s.salt, b"0123456789ABCDEF");
        assert_eq!(s.salt.len(), MAX_SALT_LEN);
    }

    #[test]
    fn parse_real_world_sha512_hash() {
        // Typical /etc/shadow SHA-512 entry shape.
        let s = ok(b"$6$rounds=5000$abcdefghijklmnop$bodybodybodybody...");
        assert_eq!(s.rounds, 5000);
        assert!(s.rounds_custom);
        assert_eq!(s.salt, b"abcdefghijklmnop");
    }
}
