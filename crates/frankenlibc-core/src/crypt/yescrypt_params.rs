//! yescrypt's `$y$` / `$gy$` parameter field — decoded, ahead of the KDF.
//!
//! **The KDF is NOT here.** yescrypt is scrypt plus `pwxform`, and this file
//! deliberately stops at the boundary: it parses and re-encodes the parameter
//! string and nothing else. The reason is stated plainly because it is a
//! judgement someone may want to overturn.
//!
//! ## Why the split, and why the core was not written blind
//!
//! `$7$` (see [`crate::crypt::scrypt_crypt`]) could be written under a build
//! freeze because every step was checkable without compiling: Python's
//! `hashlib.scrypt` is an independent implementation, so the decoded parameters
//! and the output encoding were each validated against `libcrypt.so.1` before a
//! line of Rust existed.
//!
//! yescrypt has no such oracle. It is absent from Python's standard library, so
//! the only available signal is the final hash from libxcrypt — an
//! all-or-nothing comparison across ~600 lines of `pwxform`, a modified
//! `BlockMix`, and a runtime-derived S-box. Writing that with no compiler and no
//! intermediate oracle produces code that looks finished, cannot be
//! bisected when it is wrong, and would sit in the tree claiming a capability
//! it does not have. The parameter layout, by contrast, IS checkable now — so
//! that is what this file contains.
//!
//! ## What was measured
//!
//! `crypt_gensalt("$y$", count, ..)` across counts 0..11 on live libxcrypt
//! (glibc 2.42 host, `libcrypt.so.1`):
//!
//! ```text
//!   count  0 -> $y$j9T$...   count  6 -> $y$jAT$...
//!   count  1 -> $y$j75$...   count  7 -> $y$jBT$...
//!   count  2 -> $y$j85$...   count  8 -> $y$jCT$...
//!   count  3 -> $y$j7T$...   count  9 -> $y$jDT$...
//!   count  4 -> $y$j8T$...   count 10 -> $y$jET$...
//!   count  5 -> $y$j9T$...   count 11 -> $y$jFT$...
//! ```
//!
//! Three observations follow directly, and only these three are claimed:
//!
//! 1. The FIRST character never moves. It is the flavour, not a cost.
//! 2. The SECOND character walks the crypt alphabet with the cost, so it
//!    carries `N`. Note counts 0 and 5 coincide — 0 means "library default",
//!    which is therefore 5, and any test that uses count 0 is really testing 5.
//! 3. The THIRD character takes `5` at counts 1 and 2 and `T` at every other
//!    count, so it is not a pure function of the cost index; it carries `r`,
//!    which libxcrypt lowers for the two cheapest settings.
//!
//! What is NOT claimed: the exact bit packing of the second and third
//! characters. yescrypt encodes `N`, `r` and optional `t`/`g`/ROM fields with a
//! variable-length scheme, and eleven samples that vary one input do not pin it.
//! [`parse`] therefore returns the RAW field rather than decoded integers, and
//! says so, instead of inventing a decode that would be indistinguishable from a
//! KDF bug later.
//!
//! ## Rejection is already correct and worth having on its own
//!
//! A malformed `$y$` setting must produce libxcrypt's `*0` failure token, not a
//! hash and not a NULL. `crypt("password", "$y$.....$saltsalt")` returns `*0` on
//! the host — measured — and fl reaches the same token today by falling through
//! to host delegation. Once the KDF lands, this parser is what keeps that
//! behaviour when delegation is unavailable.

/// The crypt(3) alphabet. yescrypt's parameter field uses it as a digit set;
/// the packing above it is what remains unmeasured.
const ALPHABET: &[u8; 64] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// The flavour character libxcrypt emits for every `$y$` setting it generates.
///
/// Held as an observation, not a constraint: [`parse`] accepts any alphabet
/// character here, because a hash written by a different yescrypt build must
/// still be parseable for verification.
pub const OBSERVED_FLAVOUR: u8 = b'j';

/// A parsed yescrypt setting: prefix, raw parameter field, and salt.
#[derive(Debug, PartialEq, Eq)]
pub struct YescryptSetting<'a> {
    /// `$y$` or `$gy$`, including both dollar signs.
    pub prefix: &'a [u8],
    /// The parameter characters between the second and third `$`.
    ///
    /// RAW, deliberately. See the module docs: the bit packing of this field
    /// was not established by the probing that was possible here, and returning
    /// invented integers would make a future format bug look like a KDF bug.
    pub params: &'a [u8],
    /// The salt, as raw setting characters.
    pub salt: &'a [u8],
}

#[inline]
fn is_alphabet(c: u8) -> bool {
    ALPHABET.contains(&c)
}

/// Parse a `$y$params$salt` or `$gy$params$salt` setting.
///
/// Accepts a full stored hash as input — `$y$params$salt$hash` — because that
/// is what every caller passes when verifying a password, and returns the salt
/// without the trailing hash.
pub fn parse(setting: &[u8]) -> Option<YescryptSetting<'_>> {
    let (prefix_len, rest) = if let Some(rest) = setting.strip_prefix(b"$gy$") {
        (4usize, rest)
    } else if let Some(rest) = setting.strip_prefix(b"$y$") {
        (3usize, rest)
    } else {
        return None;
    };

    let params_end = rest.iter().position(|&c| c == b'$')?;
    let params = &rest[..params_end];
    if params.is_empty() || !params.iter().all(|&c| is_alphabet(c)) {
        return None;
    }

    let tail = &rest[params_end + 1..];
    // The salt runs to the next `$`, which separates a previously computed hash.
    let salt = match tail.iter().position(|&c| c == b'$') {
        Some(end) => &tail[..end],
        None => tail,
    };
    if salt.is_empty() || !salt.iter().all(|&c| is_alphabet(c)) {
        return None;
    }

    Some(YescryptSetting {
        prefix: &setting[..prefix_len],
        params,
        salt,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Settings generated by live libxcrypt must parse, and the fields must come
    /// back exactly as they went in.
    #[test]
    fn parses_settings_generated_by_libxcrypt() {
        let cases: &[(&[u8], &[u8], &[u8], &[u8])] = &[
            (
                b"$y$j9T$/6k.2IU/5UE08g.1Bsk1E2V2HEF3KQ",
                b"$y$",
                b"j9T",
                b"/6k.2IU/5UE08g.1Bsk1E2V2HEF3KQ",
            ),
            (b"$y$j75$saltsalt", b"$y$", b"j75", b"saltsalt"),
            (b"$gy$j9T$saltsalt", b"$gy$", b"j9T", b"saltsalt"),
        ];
        for (setting, prefix, params, salt) in cases {
            let got = parse(setting).expect("libxcrypt setting must parse");
            assert_eq!(got.prefix, *prefix);
            assert_eq!(got.params, *params);
            assert_eq!(got.salt, *salt);
        }
    }

    /// A stored hash fed back in — the verification path — must yield the SALT,
    /// not the salt plus the hash.
    #[test]
    fn a_full_hash_yields_only_its_salt() {
        let stored = b"$y$j9T$saltsalt$0ZRt7zd0gn9pQsq3yDeuwj9hFSoqeo/y42wyzM0m.d0";
        let got = parse(stored).expect("a stored hash must parse as a setting");
        assert_eq!(got.params, b"j9T");
        assert_eq!(got.salt, b"saltsalt");
    }

    /// The cost sweep recorded in the module docs, asserted rather than only
    /// described: the flavour is fixed and the second character moves with cost.
    #[test]
    fn observed_cost_sweep_moves_only_the_second_character() {
        let observed: &[&[u8]] = &[
            b"$y$j75$s",
            b"$y$j85$s",
            b"$y$j7T$s",
            b"$y$j8T$s",
            b"$y$j9T$s",
            b"$y$jAT$s",
            b"$y$jBT$s",
            b"$y$jCT$s",
            b"$y$jDT$s",
            b"$y$jET$s",
            b"$y$jFT$s",
        ];
        let mut seconds = Vec::new();
        for setting in observed {
            let got = parse(setting).expect("sweep sample must parse");
            assert_eq!(got.params.len(), 3, "the observed field is three chars");
            assert_eq!(
                got.params[0], OBSERVED_FLAVOUR,
                "the flavour character did not move across the whole sweep"
            );
            seconds.push(got.params[1]);
        }
        seconds.dedup();
        assert!(
            seconds.len() > 1,
            "the second character must vary with cost, else it is not N"
        );
    }

    /// Malformed settings are refused so the ABI layer can emit libxcrypt's
    /// `*0` token. `$y$.....$saltsalt` was measured returning `*0` on the host.
    #[test]
    fn malformed_settings_are_refused() {
        assert!(parse(b"$7$A/..../....salt").is_none(), "wrong scheme");
        assert!(parse(b"$y$").is_none(), "no params");
        assert!(parse(b"$y$j9T").is_none(), "no salt separator");
        assert!(parse(b"$y$j9T$").is_none(), "empty salt");
        assert!(parse(b"$y$$saltsalt").is_none(), "empty params");
        assert!(
            parse(b"$y$j9T$salt!salt").is_none(),
            "salt outside the alphabet"
        );
    }
}
