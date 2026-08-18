//! bcrypt — the `$2a$` / `$2b$` / `$2y$` password hashing scheme.
//!
//! Reference: Provos & Mazieres, "A Future-Adaptable Password Scheme" (1999),
//! and the `EksBlowfish` construction in [`crate::crypt::blowfish`].
//!
//! ## Format
//!
//! ```text
//!   $2b$ cc $ ssssssssssssssssssssss hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh
//!        ^^   ^^^^^^^^^^^^^^^^^^^^^^ ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
//!        |    22 chars = 16 salt      31 chars = 23 of the 24 ciphertext
//!        |    bytes, bcrypt base-64   bytes, bcrypt base-64
//!        two decimal digits, log2 of the key-schedule iteration count
//! ```
//!
//! ## bcrypt's base-64 is NOT crypt's base-64
//!
//! [`crate::crypt::base64`] uses `./0-9A-Za-z` and packs least-significant
//! group first, because that is what the `$1$`/`$5$`/`$6$` schemes specify.
//! bcrypt uses `./A-Za-z0-9` and packs most-significant first. Reusing the
//! other module here would produce a plausible-looking hash that is wrong in
//! every character, so the two are deliberately kept apart.
//!
//! ## The 23-of-24 truncation is not a bug
//!
//! The ciphertext is three 64-bit blocks = 24 bytes, but the published format
//! encodes only 23. That discards the final byte, and every implementation must
//! discard it or its output will not compare equal to anyone else's.
//!
//! ## Vector
//!
//! Probed from live libxcrypt (`libcrypt.so.1`) on this host rather than copied
//! from a document:
//!
//! ```text
//!   crypt("password", "$2b$05$.OGB/.SE/ueHAeqKBO2NC.")
//!     = "$2b$05$.OGB/.SE/ueHAeqKBO2NC.l.rLVibUznFAk1jsn2/OhryTtvR79Iu"
//! ```

use crate::crypt::blowfish::Blowfish;

/// bcrypt's base-64 alphabet. See the module docs: this is not crypt's.
const ALPHABET: &[u8; 64] = b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// The magic plaintext, "OrpheanBeholderScryDoubt", as three big-endian pairs.
const MAGIC: [u32; 6] = [
    0x4f727068, 0x65616e42, 0x65686f6c, 0x64657253, 0x63727944, 0x6f756274,
];

/// Longest password bcrypt considers. Bytes past this are discarded, which is a
/// property of the scheme rather than of this implementation.
const MAX_KEY_LEN: usize = 72;

/// Cost bounds. libxcrypt rejects settings outside this range rather than
/// clamping them, so a caller cannot silently get a weaker hash than it asked
/// for.
const MIN_COST: u32 = 4;
const MAX_COST: u32 = 31;

/// The salt is always 128 bits, encoded as 22 base-64 characters.
const SALT_LEN: usize = 16;
const SALT_CHARS: usize = 22;
/// 23 of the 24 ciphertext bytes, encoded.
const HASH_CHARS: usize = 31;

#[inline]
fn decode_char(c: u8) -> Option<u8> {
    ALPHABET.iter().position(|&a| a == c).map(|i| i as u8)
}

/// Decode `chars` bcrypt base-64 characters into `out` bytes, MSB-first.
fn decode(input: &[u8], out: &mut [u8]) -> Option<()> {
    let mut acc = 0u32;
    let mut bits = 0u32;
    let mut written = 0usize;
    for &c in input {
        acc = (acc << 6) | u32::from(decode_char(c)?);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            if written < out.len() {
                out[written] = ((acc >> bits) & 0xff) as u8;
                written += 1;
            }
        }
    }
    if written == out.len() { Some(()) } else { None }
}

/// Encode 16 random bytes as the 22-character salt field of a `$2?$` setting.
///
/// Exposed for `crypt_gensalt`, which has to build a setting fl can then hash.
/// It uses bcrypt's MSB-first packing, NOT the running little-endian packing
/// the `$1$`/`$5$`/`$6$`/`$7$` salts use — measured against libxcrypt for the
/// same input bytes:
///
/// ```text
///   want          .OGB/.SE/ueHAeqKBO2NC.
///   MSB-first     .OGB/.SE/ueHAeqKBO2NC.   <- this
///   running LE    /Gu.CSe/FeOAIq.BL2uBO.
/// ```
pub fn encode_salt(entropy: &[u8]) -> String {
    encode(entropy, SALT_CHARS)
}

/// The salt length a `$2?$` setting carries, in characters.
pub const SETTING_SALT_CHARS: usize = SALT_CHARS;

/// Cost bounds a `$2?$` setting admits, exposed for `crypt_gensalt`.
pub const COST_RANGE: core::ops::RangeInclusive<u32> = MIN_COST..=MAX_COST;

/// Encode `input` as bcrypt base-64, MSB-first, emitting `chars` characters.
fn encode(input: &[u8], chars: usize) -> String {
    let mut out = String::with_capacity(chars);
    let mut acc = 0u32;
    let mut bits = 0u32;
    let mut i = 0usize;
    while out.len() < chars {
        if bits < 6 {
            let byte = if i < input.len() { input[i] } else { 0 };
            i += 1;
            acc = (acc << 8) | u32::from(byte);
            bits += 8;
        }
        bits -= 6;
        out.push(ALPHABET[((acc >> bits) & 0x3f) as usize] as char);
    }
    out
}

/// A parsed `$2?$cc$salt` setting.
struct Setting<'a> {
    variant: &'a [u8],
    cost: u32,
    salt: [u8; SALT_LEN],
    salt_chars: &'a [u8],
}

/// Parse `$2a$`/`$2b$`/`$2y$`/`$2x$` + two cost digits + `$` + 22 salt chars.
fn parse(setting: &[u8]) -> Option<Setting<'_>> {
    let rest = setting.strip_prefix(b"$2")?;
    let (variant_char, rest) = rest.split_first()?;
    // `$2x$` exists only to reproduce a sign-extension bug in an old
    // implementation for verification of legacy hashes. It is accepted here
    // because refusing it would make old shadow entries unverifiable, and it is
    // treated exactly like `$2a$` — this port has no signed-char path to differ.
    if !matches!(variant_char, b'a' | b'b' | b'y' | b'x') {
        return None;
    }
    let rest = rest.strip_prefix(b"$")?;
    if rest.len() < 3 {
        return None;
    }
    let (cost_digits, rest) = rest.split_at(2);
    if !cost_digits.iter().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let cost = u32::from(cost_digits[0] - b'0') * 10 + u32::from(cost_digits[1] - b'0');
    if !(MIN_COST..=MAX_COST).contains(&cost) {
        return None;
    }
    let rest = rest.strip_prefix(b"$")?;
    if rest.len() < SALT_CHARS {
        return None;
    }
    let salt_chars = &rest[..SALT_CHARS];
    let mut salt = [0u8; SALT_LEN];
    decode(salt_chars, &mut salt)?;
    Some(Setting {
        variant: &setting[1..3],
        cost,
        salt,
        salt_chars,
    })
}

/// Hash `key` against a `$2?$` bcrypt `setting`, returning the full crypt string.
///
/// Returns `None` for any setting this scheme does not accept, which the ABI
/// layer turns into libxcrypt's failure token rather than a NULL.
pub fn bcrypt_crypt(key: &[u8], setting: &[u8]) -> Option<String> {
    let parsed = parse(setting)?;

    // The key is the password plus its terminating NUL, truncated to 72 bytes.
    // The NUL is part of the keying material, not a C artefact: dropping it
    // changes every output.
    let mut material = Vec::with_capacity(key.len() + 1);
    material.extend_from_slice(key);
    material.push(0);
    material.truncate(MAX_KEY_LEN);

    let mut state = Blowfish::new_unkeyed();
    state.expand_key(&parsed.salt, &material);

    // 2^cost is why this is "expensive"; u32 shift is safe because cost <= 31.
    let iterations = 1u64 << parsed.cost;
    for _ in 0..iterations {
        state.expand_key_no_salt(&material);
        state.expand_key_no_salt(&parsed.salt);
    }

    let mut ctext = MAGIC;
    for _ in 0..64 {
        let mut pair = 0;
        while pair < 6 {
            let (mut l, mut r) = (ctext[pair], ctext[pair + 1]);
            state.encrypt_block(&mut l, &mut r);
            ctext[pair] = l;
            ctext[pair + 1] = r;
            pair += 2;
        }
    }

    let mut raw = [0u8; 24];
    for (i, word) in ctext.iter().enumerate() {
        raw[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }

    let variant = core::str::from_utf8(parsed.variant).ok()?;
    let salt_text = core::str::from_utf8(parsed.salt_chars).ok()?;
    Some(format!(
        "${variant}${:02}${salt_text}{}",
        parsed.cost,
        // 23, not 24 — see the module docs.
        encode(&raw[..23], HASH_CHARS),
    ))
}
