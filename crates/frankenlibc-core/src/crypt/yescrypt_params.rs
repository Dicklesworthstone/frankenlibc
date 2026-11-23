//! Native `$y$` yescrypt settings, hashing and salt generation.
//!
//! The KDF is the pinned, pure-Rust `yescrypt` crate with optional OS RNG and
//! password-format layers disabled. This boundary owns crypt(3)'s byte-string
//! contract: complete parameter consumption, canonical little-endian salt
//! decoding, full stored-hash inputs, failure classification and output format.
//! `$gy$` can be parsed but is not hashed here: gost-yescrypt is another scheme.
//!
//! Settings retain their exact cost. Unsupported ROM/upgrades are rejected;
//! excessive memory or work returns a distinct resource error, never a weaker
//! hash. The working-set ceiling allows all libxcrypt gensalt costs 1..=11
//! (up to a 1 GiB V array plus scratch). The dependency still uses infallible
//! allocations, so allocation exhaustion below that ceiling can abort; this is
//! not an allocation-failure-proof KDF. It has not been independently audited.
//!
//! The format and KDF are checked against independently loaded libxcrypt,
//! including empty salt/password, non-UTF-8 passwords, optional p/t fields and
//! malformed inputs. Successful output always contains the original setting's
//! parameter and salt spelling plus 43 hash characters.

use super::base64::{ALPHABET, decode_le, encode_le};

/// Native yescrypt failures, kept distinct until the ABI assigns errno.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidSetting,
    PasswordTooLong,
    ResourceLimit,
}

const MAX_SALT_BYTES: usize = 64;
const MAX_WORKSPACE_BYTES: u64 = (1 << 30) + (1 << 20);
const MAX_MIX_WORK: u64 = 1 << 26;

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
    /// Original spelling, retained in the result; [`hash`] validates and
    /// decodes all fields before entering the KDF.
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
    } else {
        (3usize, setting.strip_prefix(b"$y$")?)
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
    if !salt.iter().all(|&c| is_alphabet(c)) {
        return None;
    }

    Some(YescryptSetting {
        prefix: &setting[..prefix_len],
        params,
        salt,
    })
}

/// Decode one variable-width integer, including the minimum implicit value.
/// The first digit chooses a tier of 1..=6 digits; subsequent digits form a
/// big-endian base-64 integer within that tier. All reads and arithmetic are
/// checked before constructing the dependency's parameters.
fn parameter(input: &mut &[u8], minimum: u32) -> Result<u32, Error> {
    let (&first, rest) = input.split_first().ok_or(Error::InvalidSetting)?;
    let first = ALPHABET
        .iter()
        .position(|&byte| byte == first)
        .ok_or(Error::InvalidSetting)? as u32;
    let (extra, start, base) = match first {
        0..=47 => (0, 0, 0u32),
        48..=55 => (1, 48, 48),
        56..=59 => (2, 56, 560),
        60..=61 => (3, 60, 16_944),
        62 => (4, 62, 541_232),
        _ => (5, 63, 17_318_448),
    };
    let digits = rest.get(..extra).ok_or(Error::InvalidSetting)?;
    let mut value = first - start;
    for &digit in digits {
        let digit = ALPHABET
            .iter()
            .position(|&byte| byte == digit)
            .ok_or(Error::InvalidSetting)? as u32;
        value = value
            .checked_mul(64)
            .and_then(|value| value.checked_add(digit))
            .ok_or(Error::InvalidSetting)?;
    }
    *input = &rest[extra..];
    value
        .checked_add(base)
        .and_then(|value| value.checked_add(minimum))
        .ok_or(Error::InvalidSetting)
}

fn parameters(mut input: &[u8]) -> Result<yescrypt::Params, Error> {
    let mode =
        yescrypt::Mode::try_from(parameter(&mut input, 0)?).map_err(|_| Error::InvalidSetting)?;
    let log_n = parameter(&mut input, 1)?;
    if log_n > 63 {
        return Err(Error::InvalidSetting);
    }
    let n = 1u64 << log_n;
    let r = parameter(&mut input, 1)?;
    let (mut p, mut t) = (1, 0);
    if !input.is_empty() {
        let have = parameter(&mut input, 1)?;
        if have & 1 != 0 {
            p = parameter(&mut input, 2)?;
        }
        if have & 2 != 0 {
            t = parameter(&mut input, 1)?;
        }
        // g and NROM require an upgraded hash or an external shared ROM.
        // Neither the native KDF nor the normal libxcrypt backend provides it.
        if have & 12 != 0 {
            return Err(Error::InvalidSetting);
        }
        // libxcrypt ignores high `have` bits. Preserve that behavior while
        // requiring every encoded argument to be consumed, unlike a prefix
        // parse that could accidentally hash a different parameter string.
    }
    if !input.is_empty()
        || u64::from(r) * u64::from(p) >= (1 << 30)
        || n > u64::MAX / (u64::from(t) + 1)
        || (mode.is_classic() && t != 0)
        || (mode.is_rw() && n / u64::from(p) <= 1)
    {
        return Err(Error::InvalidSetting);
    }
    let block = 128u64 * u64::from(r);
    let v = block.checked_mul(n).ok_or(Error::InvalidSetting)?;
    let b = block
        .checked_mul(u64::from(p))
        .ok_or(Error::InvalidSetting)?;
    let scratch = block.checked_mul(2).ok_or(Error::InvalidSetting)?;
    let boxes = if mode.is_rw() {
        12_352u64 * u64::from(p)
    } else {
        0
    };
    let workspace = v
        .checked_add(b)
        .and_then(|bytes| bytes.checked_add(scratch))
        .and_then(|bytes| bytes.checked_add(boxes))
        .ok_or(Error::ResourceLimit)?;
    let lanes = if mode.is_rw() { 1 } else { u64::from(p) };
    let work = n
        .checked_mul(u64::from(r))
        .and_then(|work| work.checked_mul(lanes))
        .and_then(|work| work.checked_mul(u64::from(t) + 2))
        .ok_or(Error::ResourceLimit)?;
    if workspace > MAX_WORKSPACE_BYTES || workspace > isize::MAX as u64 || work > MAX_MIX_WORK {
        return Err(Error::ResourceLimit);
    }
    yescrypt::Params::new_with_all_params(mode, n, r, p, t, 0).map_err(|_| Error::InvalidSetting)
}

/// Hash arbitrary password bytes against a `$y$` setting or full stored hash.
pub fn hash(password: &[u8], setting: &[u8]) -> Result<String, Error> {
    if password.len() >= 512 {
        return Err(Error::PasswordTooLong);
    }
    if !setting.iter().copied().all(super::valid_hash_string_byte) {
        return Err(Error::InvalidSetting);
    }
    let parsed = parse(setting).ok_or(Error::InvalidSetting)?;
    if parsed.prefix != b"$y$" {
        return Err(Error::InvalidSetting);
    }
    let params = parameters(parsed.params)?;
    let mut salt = [0; MAX_SALT_BYTES];
    let length = decode_le(parsed.salt, &mut salt).ok_or(Error::InvalidSetting)?;
    let mut digest = [0; 32];
    yescrypt::yescrypt(password, &salt[..length], &params, &mut digest)
        .map_err(|_| Error::InvalidSetting)?;
    // All fields have already passed the ASCII crypt alphabet checks.
    let params = core::str::from_utf8(parsed.params).map_err(|_| Error::InvalidSetting)?;
    let salt = core::str::from_utf8(parsed.salt).map_err(|_| Error::InvalidSetting)?;
    Ok(format!("$y${params}${salt}${}", encode_le(&digest)))
}

/// Generate libxcrypt-compatible `$y$` parameters and salt without hashing.
/// Cost zero selects cost five; costs outside 1..=11 are rejected. Exactly
/// 16..=64 entropy bytes are encoded, capping longer inputs like libxcrypt.
pub fn gensalt(cost: u64, entropy: &[u8]) -> Result<String, Error> {
    let cost = if cost == 0 { 5 } else { cost };
    if !(1..=11).contains(&cost) || entropy.len() < 16 {
        return Err(Error::InvalidSetting);
    }
    let (log_n, r) = if cost <= 2 {
        (cost + 9, 8)
    } else {
        (cost + 7, 32)
    };
    let params = yescrypt::Params::new(yescrypt::Mode::Rw, 1 << log_n, r, 1)
        .map_err(|_| Error::InvalidSetting)?;
    Ok(format!(
        "$y${params}${}",
        encode_le(&entropy[..entropy.len().min(MAX_SALT_BYTES)])
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Settings generated by live libxcrypt must parse, and the fields must come
    /// back exactly as they went in.
    #[test]
    fn parses_settings_generated_by_libxcrypt() {
        type SettingCase<'a> = (&'a [u8], &'a [u8], &'a [u8], &'a [u8]);
        let cases: &[SettingCase<'_>] = &[
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

    #[test]
    fn native_hash_matches_independent_libxcrypt_vectors() {
        let cases: &[(&[u8], &[u8], &str)] = &[
            (
                b"password",
                b"$y$j75$saltsalt",
                "$y$j75$saltsalt$eWasoMp7uF0.AeHT3DZ8Zkum32fPmPJWiMVRQdwiBb4",
            ),
            (
                b"password",
                b"$y$j75$",
                "$y$j75$$MY7LY7iSiXDbIK//WLX8B9MRa5LUgGVUicMJCn3sKE1",
            ),
            (
                b"pw",
                b"$y$.3.$..",
                "$y$.3.$..$XxhZV47.JDRAgoO0vXRI0FbaT.c.k/SpZxgKioIEno0",
            ),
            (
                b"pw",
                b"$y$/3.$..",
                "$y$/3.$..$Crejyun9/DkyxXYhz3gWFB43sahuL9NxsP41CoBeddD",
            ),
            (
                b"pw",
                b"$y$j3.$..",
                "$y$j3.$..$8fngWTTq8zC/5K6gSgXu0X05lnVHCSAWy3M9jtUGnc2",
            ),
            (
                b"pw",
                b"$y$j3..0$..",
                "$y$j3..0$..$mdJxJtILuoRTfv07pvKVx5FFDcuKTeOSPZGn/.mB7BB",
            ),
            (
                b"pw",
                b"$y$j3./.$..",
                "$y$j3./.$..$YDrHlAy2D9Ihq58sM3Kl5wpV/CQzT3dw6d9v35Mbk1D",
            ),
        ];
        for &(password, setting, expected) in cases {
            assert_eq!(hash(password, setting).unwrap(), expected);
            assert_eq!(hash(password, expected.as_bytes()).unwrap(), expected);
        }
    }

    #[test]
    fn generated_costs_match_libxcrypt_and_fit_resource_policy() {
        let entropy: Vec<u8> = (0..64).collect();
        for (cost, params) in [
            "j75", "j85", "j7T", "j8T", "j9T", "jAT", "jBT", "jCT", "jDT", "jET", "jFT",
        ]
        .iter()
        .enumerate()
        {
            assert_eq!(
                gensalt(cost as u64 + 1, &entropy[..16]).unwrap(),
                format!("$y${params}$.2U.1EE/4Q.07ck0AoU1D.")
            );
            // Check the maximum cost without allocating its 1 GiB workspace.
            assert!(parameters(params.as_bytes()).is_ok());
        }
        assert_eq!(gensalt(0, &entropy), gensalt(5, &entropy));
        assert_eq!(gensalt(12, &entropy), Err(Error::InvalidSetting));
        assert_eq!(gensalt(1, &entropy[..15]), Err(Error::InvalidSetting));
        let mut longer = entropy.clone();
        longer.extend_from_slice(b"ignored beyond 64 bytes");
        assert_eq!(gensalt(1, &longer), gensalt(1, &entropy));
    }

    #[test]
    fn parameter_decoder_checks_every_tier_and_complete_input() {
        for (text, expected) in [
            (".", 0),
            ("j", 47),
            ("k.", 48),
            ("rz", 559),
            ("s..", 560),
            ("vzz", 16_943),
            ("w...", 16_944),
            ("xzzz", 541_231),
            ("y....", 541_232),
            ("yzzzz", 17_318_447),
            ("z.....", 17_318_448),
            ("zzzzzz", 1_091_060_271),
        ] {
            let mut bytes = text.as_bytes();
            assert_eq!(parameter(&mut bytes, 0), Ok(expected), "{text}");
            assert!(bytes.is_empty());
        }
        for text in [
            "", "!", "k", "r", "s", "s.", "w..", "y...", "z....", "z.....!",
        ] {
            let mut bytes = text.as_bytes();
            let decoded = parameter(&mut bytes, 0);
            assert!(decoded.is_err() || !bytes.is_empty(), "{text}");
        }
        for text in [
            "j75.", "j75/", "j750.", "j753..", "j75E", "j75z", "j75..0", "z75", "jz5", "j7z",
        ] {
            assert!(parameters(text.as_bytes()).is_err(), "{text}");
        }
        assert!(parameters(b"j75E.").is_ok());
        assert!(parameters(b"j75zzzzzz").is_ok());
    }

    #[test]
    fn invalid_settings_and_resource_failures_are_distinct() {
        for setting in [
            b"$gy$j75$..".as_slice(),
            b"$y$j75$A",
            b"$y$j75$AB",
            b"$y$j75$..$bad!",
            b"$y$j75$..$bad:",
        ] {
            assert_eq!(hash(b"password", setting), Err(Error::InvalidSetting));
        }
        assert_eq!(
            hash(&[b'x'; 512], b"$y$j3.$.."),
            Err(Error::PasswordTooLong)
        );
        assert_eq!(hash(b"password", b"$y$jGT$.."), Err(Error::ResourceLimit));
        assert!(matches!(
            parameters(b"jzzzzzz."),
            Err(Error::InvalidSetting)
        ));
        assert!(parameters(b"j3zzzzzz").is_err());
        assert!(parameters(b"j3..zzzzzz").is_err());
    }

    /// Malformed settings are refused so the ABI layer can emit libxcrypt's
    /// `*0` token. `$y$.....$saltsalt` was measured returning `*0` on the host.
    #[test]
    fn malformed_settings_are_refused() {
        assert!(parse(b"$7$A/..../....salt").is_none(), "wrong scheme");
        assert!(parse(b"$y$").is_none(), "no params");
        assert!(parse(b"$y$j9T").is_none(), "no salt separator");
        assert_eq!(parse(b"$y$j9T$").unwrap().salt, b"", "empty salt is valid");
        assert!(parse(b"$y$$saltsalt").is_none(), "empty params");
        assert!(
            parse(b"$y$j9T$salt!salt").is_none(),
            "salt outside the alphabet"
        );
    }
}
