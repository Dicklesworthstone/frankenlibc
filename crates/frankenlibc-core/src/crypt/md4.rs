//! MD4 (RFC 1320) and the NTHASH scheme (`$3$`) built on it.
//!
//! ## Why fl needs MD4 at all
//!
//! Only for `$3$`. NTHASH is the Windows NT password hash — MD4 over the
//! password with each byte widened to a little-endian 16-bit unit — and
//! libxcrypt supports it so that a Samba or MS-CHAP credential store can live
//! in the same file as everything else. fl previously delegated `$3$` to the
//! host, which meant the usual hole: verifiable only where libxcrypt was
//! `dlsym`-able, and a failure token everywhere else.
//!
//! MD4 is cryptographically broken and NTHASH is unsalted and uniterated, so
//! this is a compatibility function and nothing else. It must never be reached
//! by anything choosing a hash rather than verifying one — note that
//! `crypt_gensalt` has no `$3$` prefix, which is libxcrypt making the same
//! point.
//!
//! ## The format, measured
//!
//! ```text
//!   crypt("password", "$3$")            = $3$$8846f7eaee8fb117ad06bdd830b7586c
//!   crypt("password", "$3$abc$")        = $3$$8846f7eaee8fb117ad06bdd830b7586c
//!   crypt("password", "$3$xyzzy$more")  = $3$$8846f7eaee8fb117ad06bdd830b7586c
//! ```
//!
//! The salt field is not merely optional, it is IGNORED: every setting above
//! produces the same digest, and the output always re-emits `$3$$` with an
//! empty salt regardless of what was supplied. That is a real interoperability
//! detail — a caller doing `strcmp(crypt(pw, stored), stored)` against a
//! `$3$abc$…` record would fail to authenticate a correct password if fl echoed
//! the salt back, so the empty field is required, not cosmetic.
//!
//! ## The widening is NOT UTF-8 decoding
//!
//! Each password BYTE becomes one little-endian 16-bit unit. It is not a UTF-8
//! to UTF-16 conversion: the two bytes of `"é"` in UTF-8 (`c3 a9`) become the
//! four bytes `c3 00 a9 00`, and a byte that is not valid UTF-8 at all is
//! widened just the same. Measured over 310 passwords including `\xff\xfe` and
//! every byte 1..=127. Implementing this as a real UTF-16 conversion would
//! agree on ASCII — which is most test vectors — and diverge on exactly the
//! passwords a user is most likely to have chosen deliberately.

use super::valid_hash_string_byte;

const INITIAL_STATE: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];

/// Round 2 and 3 read the message words out of order; round 1 reads them in
/// order. Transcribed from RFC 1320 section 3.4.
const ROUND2_ORDER: [usize; 16] = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15];
const ROUND3_ORDER: [usize; 16] = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15];
const ROUND1_SHIFTS: [u32; 4] = [3, 7, 11, 19];
const ROUND2_SHIFTS: [u32; 4] = [3, 5, 9, 13];
const ROUND3_SHIFTS: [u32; 4] = [3, 9, 11, 15];

/// The two round constants. RFC 1320 gives them as the square roots of 2 and 3
/// in 32-bit fixed point.
const ROUND2_CONSTANT: u32 = 0x5a82_7999;
const ROUND3_CONSTANT: u32 = 0x6ed9_eba1;

/// MD4 of `data`.
pub fn md4(data: &[u8]) -> [u8; 16] {
    let mut state = INITIAL_STATE;

    // Padding is MD5's: a 0x80 byte, zeros, then the LENGTH IN BITS as a
    // little-endian u64. Little-endian throughout is what separates MD4/MD5
    // from the SHA family, and getting it backwards produces a digest that is
    // wrong for every input, which at least fails loudly.
    let bit_length = (data.len() as u64).wrapping_mul(8);
    let mut tail = Vec::with_capacity(128);
    tail.push(0x80u8);
    while (data.len() + tail.len()) % 64 != 56 {
        tail.push(0);
    }
    tail.extend_from_slice(&bit_length.to_le_bytes());

    let mut block = [0u8; 64];
    let mut filled = 0usize;
    for &byte in data.iter().chain(tail.iter()) {
        block[filled] = byte;
        filled += 1;
        if filled == 64 {
            compress(&mut state, &block);
            filled = 0;
        }
    }
    debug_assert_eq!(filled, 0, "padding must land on a block boundary");

    let mut digest = [0u8; 16];
    for (index, word) in state.iter().enumerate() {
        digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    digest
}

fn compress(state: &mut [u32; 4], block: &[u8; 64]) {
    let mut words = [0u32; 16];
    for (index, word) in words.iter_mut().enumerate() {
        *word = u32::from_le_bytes([
            block[index * 4],
            block[index * 4 + 1],
            block[index * 4 + 2],
            block[index * 4 + 3],
        ]);
    }

    let [mut a, mut b, mut c, mut d] = *state;

    // Each round rotates the roles of a/b/c/d by one, so the operand being
    // updated walks a, d, c, b and back. Writing it as a rotation rather than
    // four unrolled statements per step keeps the shift and word indices next
    // to the tables they come from.
    for step in 0..16 {
        let f = (b & c) | (!b & d);
        a = a
            .wrapping_add(f)
            .wrapping_add(words[step])
            .rotate_left(ROUND1_SHIFTS[step % 4]);
        core::mem::swap(&mut a, &mut d);
        core::mem::swap(&mut d, &mut c);
        core::mem::swap(&mut c, &mut b);
    }
    for step in 0..16 {
        let g = (b & c) | (b & d) | (c & d);
        a = a
            .wrapping_add(g)
            .wrapping_add(words[ROUND2_ORDER[step]])
            .wrapping_add(ROUND2_CONSTANT)
            .rotate_left(ROUND2_SHIFTS[step % 4]);
        core::mem::swap(&mut a, &mut d);
        core::mem::swap(&mut d, &mut c);
        core::mem::swap(&mut c, &mut b);
    }
    for step in 0..16 {
        let h = b ^ c ^ d;
        a = a
            .wrapping_add(h)
            .wrapping_add(words[ROUND3_ORDER[step]])
            .wrapping_add(ROUND3_CONSTANT)
            .rotate_left(ROUND3_SHIFTS[step % 4]);
        core::mem::swap(&mut a, &mut d);
        core::mem::swap(&mut d, &mut c);
        core::mem::swap(&mut c, &mut b);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
}

/// The NT password hash: MD4 over the password with each byte widened to a
/// little-endian 16-bit unit.
pub fn nthash(password: &[u8]) -> [u8; 16] {
    let mut widened = Vec::with_capacity(password.len() * 2);
    for &byte in password {
        widened.push(byte);
        widened.push(0);
    }
    md4(&widened)
}

/// Hash `key` under an NTHASH `$3$` setting.
///
/// The salt field is parsed only to be discarded, and the output always carries
/// an EMPTY salt — see the module docs for why echoing it back would break
/// authentication against an existing record.
pub fn nthash_crypt(key: &[u8], setting: &[u8]) -> Option<String> {
    let rest = setting.strip_prefix(b"$3$")?;
    if !rest.iter().copied().all(valid_hash_string_byte) {
        return None;
    }
    let digest = nthash(key);
    let mut out = String::with_capacity(4 + 32);
    out.push_str("$3$$");
    for byte in digest {
        // Lowercase hex, written out rather than formatted, because this crate
        // is a libc and must not depend on formatting machinery it also
        // provides.
        const HEX: &[u8; 16] = b"0123456789abcdef";
        out.push(char::from(HEX[(byte >> 4) as usize]));
        out.push(char::from(HEX[(byte & 0xf) as usize]));
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 1320 appendix A.5. These are published constants, so they check MD4
    /// against something other than this project's own measurements.
    #[test]
    fn rfc1320_vectors() {
        for (message, expected) in [
            ("", "31d6cfe0d16ae931b73c59d7e0c089c0"),
            ("a", "bde52cb31de33e46245e05fbdbd6fb24"),
            ("abc", "a448017aaf21d8525fc10ae87aa6729d"),
            ("message digest", "d9130a8164549fe818874806e1c7014b"),
            (
                "abcdefghijklmnopqrstuvwxyz",
                "d79e1c308aa5bbcdeea8ed63df412da9",
            ),
            (
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "043f8582f241db351ce627e153e7f0e4",
            ),
            (
                "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "e33b4ddc9c38f2199c3e7b164fcc0536",
            ),
        ] {
            let digest = md4(message.as_bytes());
            let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
            assert_eq!(hex, expected, "MD4({message:?})");
        }
    }

    /// The padding boundaries, which is where a length-field or block-count
    /// error hides. 55 bytes is the largest input whose padding still fits the
    /// first block; 56 forces a second block that is pure padding; 64 is an
    /// exact block. These come from this crate's MD4 cross-checked against the
    /// RFC vectors above rather than from libcrypt, because the `$3$` path
    /// widens its input and so cannot address an arbitrary MD4 message.
    #[test]
    fn padding_boundaries() {
        for (length, expected) in [
            (55usize, "92f32bb82c95ad10e8f87ae58ab06807"),
            (56, "374d5f08103b7092c83b4626ebceffab"),
            (64, "b1abf956a5ae6f3221e5fe85e300fbb0"),
            (200, "ebd2de6bd766c2812cd60598d8d1c69f"),
        ] {
            let digest = md4(&vec![b'x'; length]);
            let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
            assert_eq!(hex, expected, "MD4 of {length} 'x' bytes");
        }
    }

    /// A password long enough that its WIDENED form spans several blocks.
    /// Probed from live libcrypt.
    #[test]
    fn long_password_spans_blocks() {
        assert_eq!(
            nthash_crypt(&[b'x'; 100], b"$3$").as_deref(),
            Some("$3$$c16e1f599bba2bab447a15fa2ca8aabb")
        );
    }

    /// Probed from live libcrypt.so.1.
    #[test]
    fn nthash_known_vectors() {
        for (password, expected) in [
            (&b""[..], "$3$$31d6cfe0d16ae931b73c59d7e0c089c0"),
            (b"a", "$3$$186cb09181e2c2ecaac768c47c729904"),
            (b"password", "$3$$8846f7eaee8fb117ad06bdd830b7586c"),
            (
                b"The quick brown fox",
                "$3$$b9894503d51bf4dfc6f4192d1666800a",
            ),
            // Not UTF-8 decoded: these two bytes widen to c3 00 a9 00.
            (b"\xc3\xa9", "$3$$08eb94a3771213775172fc988504a4c1"),
        ] {
            assert_eq!(
                nthash_crypt(password, b"$3$").as_deref(),
                Some(expected),
                "nthash_crypt({password:?})"
            );
        }
    }

    /// The salt is ignored, and the output always re-emits an EMPTY salt.
    #[test]
    fn salt_is_ignored_and_never_echoed() {
        let reference = nthash_crypt(b"password", b"$3$").expect("valid");
        for setting in [&b"$3$$"[..], b"$3$abc$", b"$3$xyzzy$more", b"$3$$$$"] {
            assert_eq!(
                nthash_crypt(b"password", setting).as_deref(),
                Some(reference.as_str()),
                "{setting:?} must produce the same, salt-free output"
            );
        }
        assert!(
            reference.starts_with("$3$$"),
            "the salt field must be emitted empty"
        );
        assert_eq!(reference.len(), 4 + 32);
    }

    #[test]
    fn acceptance_rule() {
        for setting in [&b""[..], b"$3", b"$", b"$1$", b"3$", b"$3x$"] {
            assert!(
                nthash_crypt(b"password", setting).is_none(),
                "{setting:?} must be refused"
            );
        }
        // The same five characters the rest of libxcrypt refuses.
        for bad in [b'!', b'*', b':', b';', b'\\', 0x01, 0x7f, 0xff, b' '] {
            let setting = [b'$', b'3', b'$', bad];
            assert!(
                nthash_crypt(b"password", &setting).is_none(),
                "a trailing {bad:#04x} must be refused"
            );
        }
    }
}
