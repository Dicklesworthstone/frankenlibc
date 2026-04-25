//! SHA-crypt salt prefix parser (`$N$[rounds=NNNN$]salt$...`).
//!
//! The SHA-crypt wire format prefixes the encrypted hash with `$5$`
//! (SHA-256) or `$6$` (SHA-512), followed by an optional
//! `rounds=NNNN$` parameter, then the salt (up to 16 bytes,
//! terminated by `$`), then the encrypted body. This module extracts
//! the rounds + salt portion from a complete hash buffer.
//!
//! Used by `crypt_sha256` / `crypt_sha512` in the abi layer.

/// Default SHA-crypt round count when no `rounds=` parameter is present.
pub const DEFAULT_SHA_ROUNDS: u32 = 5000;

/// Lower bound on the SHA-crypt round count (per RFC / glibc clamp).
pub const MIN_SHA_ROUNDS: u32 = 1000;

/// Upper bound on the SHA-crypt round count (per RFC / glibc clamp).
pub const MAX_SHA_ROUNDS: u32 = 999_999_999;

/// Maximum salt length per the SHA-crypt specification.
pub const MAX_SALT_LEN: usize = 16;

/// Extract the rounds + salt portion from a SHA-crypt hash buffer.
///
/// `salt_bytes` is the full hash buffer (including the leading `$N$`
/// prefix); `prefix_len` is the byte length of that prefix (3 for
/// `$5$` / `$6$`).
///
/// Returns `(rounds, salt_slice)` where `salt_slice` borrows from
/// `salt_bytes` and is at most [`MAX_SALT_LEN`] bytes long. The
/// rounds value is clamped into `[MIN_SHA_ROUNDS, MAX_SHA_ROUNDS]`;
/// missing / non-numeric / out-of-range round counts decay to
/// [`DEFAULT_SHA_ROUNDS`].
pub fn parse_crypt_salt(salt_bytes: &[u8], prefix_len: usize) -> (u32, &[u8]) {
    if prefix_len > salt_bytes.len() {
        return (DEFAULT_SHA_ROUNDS, &[]);
    }
    let rest = &salt_bytes[prefix_len..];

    let (rounds, salt_start) = if let Some(after_eq) = rest.strip_prefix(b"rounds=") {
        let num_end = after_eq
            .iter()
            .position(|&b| b == b'$')
            .unwrap_or(after_eq.len());
        let rounds_str = core::str::from_utf8(&after_eq[..num_end]).unwrap_or("");
        let r = rounds_str
            .parse::<u32>()
            .unwrap_or(DEFAULT_SHA_ROUNDS)
            .clamp(MIN_SHA_ROUNDS, MAX_SHA_ROUNDS);
        // Skip past the rounds field and the trailing '$' (if present).
        let after_eq_consumed = num_end + b"rounds=".len();
        let salt_start = if num_end < after_eq.len() {
            after_eq_consumed + 1
        } else {
            after_eq_consumed
        };
        (r, salt_start)
    } else {
        (DEFAULT_SHA_ROUNDS, 0)
    };

    let salt_rest = &rest[salt_start..];
    let salt_end = salt_rest
        .iter()
        .position(|&b| b == b'$')
        .unwrap_or(salt_rest.len())
        .min(MAX_SALT_LEN);
    (rounds, &salt_rest[..salt_end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_no_rounds() {
        // $6$abcdef$rest...
        let (rounds, salt) = parse_crypt_salt(b"$6$abcdef$rest", 3);
        assert_eq!(rounds, DEFAULT_SHA_ROUNDS);
        assert_eq!(salt, b"abcdef");
    }

    #[test]
    fn parse_explicit_rounds() {
        let (rounds, salt) = parse_crypt_salt(b"$6$rounds=10000$saltvalue$body", 3);
        assert_eq!(rounds, 10000);
        assert_eq!(salt, b"saltvalue");
    }

    #[test]
    fn parse_rounds_clamps_low() {
        // 10 rounds → clamped up to MIN_SHA_ROUNDS (1000).
        let (rounds, _) = parse_crypt_salt(b"$6$rounds=10$x$", 3);
        assert_eq!(rounds, MIN_SHA_ROUNDS);
    }

    #[test]
    fn parse_rounds_clamps_high() {
        // 10^10 → clamped down to MAX_SHA_ROUNDS (999_999_999).
        let (rounds, _) = parse_crypt_salt(b"$6$rounds=1000000000$x$", 3);
        assert_eq!(rounds, MAX_SHA_ROUNDS);
    }

    #[test]
    fn parse_rounds_at_min_boundary() {
        let (rounds, _) = parse_crypt_salt(b"$6$rounds=1000$x$", 3);
        assert_eq!(rounds, 1000);
    }

    #[test]
    fn parse_rounds_at_max_boundary() {
        let (rounds, _) = parse_crypt_salt(b"$6$rounds=999999999$x$", 3);
        assert_eq!(rounds, MAX_SHA_ROUNDS);
    }

    #[test]
    fn parse_garbage_rounds_falls_back_to_default() {
        let (rounds, salt) = parse_crypt_salt(b"$6$rounds=abc$slt$", 3);
        assert_eq!(rounds, DEFAULT_SHA_ROUNDS);
        assert_eq!(salt, b"slt");
    }

    #[test]
    fn parse_empty_rounds_value_falls_back_to_default() {
        let (rounds, salt) = parse_crypt_salt(b"$6$rounds=$slt$", 3);
        assert_eq!(rounds, DEFAULT_SHA_ROUNDS);
        assert_eq!(salt, b"slt");
    }

    #[test]
    fn parse_salt_truncated_to_max_len() {
        // 20-byte salt should clip to 16.
        let input = b"$6$0123456789ABCDEFXYZ$body";
        let (_rounds, salt) = parse_crypt_salt(input, 3);
        assert_eq!(salt.len(), MAX_SALT_LEN);
        assert_eq!(salt, b"0123456789ABCDEF");
    }

    #[test]
    fn parse_salt_no_trailing_dollar_consumes_to_end() {
        // No closing $ → salt is everything up to the cap.
        let (_rounds, salt) = parse_crypt_salt(b"$6$abc", 3);
        assert_eq!(salt, b"abc");
    }

    #[test]
    fn parse_empty_salt() {
        let (rounds, salt) = parse_crypt_salt(b"$6$$body", 3);
        assert_eq!(rounds, DEFAULT_SHA_ROUNDS);
        assert_eq!(salt, b"");
    }

    #[test]
    fn parse_explicit_rounds_then_empty_salt() {
        let (rounds, salt) = parse_crypt_salt(b"$6$rounds=7777$$body", 3);
        assert_eq!(rounds, 7777);
        assert_eq!(salt, b"");
    }

    #[test]
    fn parse_explicit_rounds_no_trailing_dollar() {
        // "rounds=NNNN" with no trailing '$' — the parser treats the
        // entire tail as the rounds value, leaving zero salt bytes.
        let (rounds, salt) = parse_crypt_salt(b"$6$rounds=12345", 3);
        assert_eq!(rounds, 12345);
        assert_eq!(salt, b"");
    }

    #[test]
    fn parse_prefix_len_zero_no_consumption() {
        // No $N$ prefix → start at offset 0.
        let (rounds, salt) = parse_crypt_salt(b"abc$body", 0);
        assert_eq!(rounds, DEFAULT_SHA_ROUNDS);
        assert_eq!(salt, b"abc");
    }

    #[test]
    fn parse_prefix_len_past_end_returns_defaults() {
        // Defensive: prefix_len > buffer.
        let (rounds, salt) = parse_crypt_salt(b"$6", 99);
        assert_eq!(rounds, DEFAULT_SHA_ROUNDS);
        assert!(salt.is_empty());
    }

    #[test]
    fn parse_explicit_rounds_with_max_salt() {
        let input = b"$6$rounds=20000$0123456789ABCDEF$body";
        let (rounds, salt) = parse_crypt_salt(input, 3);
        assert_eq!(rounds, 20000);
        assert_eq!(salt, b"0123456789ABCDEF");
        assert_eq!(salt.len(), MAX_SALT_LEN);
    }

    #[test]
    fn parse_real_world_sha512_hash() {
        // Typical /etc/shadow SHA-512 entry shape.
        let input = b"$6$rounds=5000$abcdefghijklmnop$bodybodybodybody...";
        let (rounds, salt) = parse_crypt_salt(input, 3);
        assert_eq!(rounds, 5000);
        assert_eq!(salt, b"abcdefghijklmnop");
    }
}
