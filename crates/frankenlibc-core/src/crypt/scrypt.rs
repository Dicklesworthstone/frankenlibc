//! scrypt — the memory-hard KDF behind the `$7$` and `$y$` crypt schemes.
//!
//! RFC 7914. Written from the specification rather than ported, because every
//! piece is arithmetic: Salsa20/8 has no S-box, `BlockMix` is a shuffle, and
//! `ROMix` is a lookup loop. That is the reason this was the tractable target
//! under a build freeze while bcrypt needed 1042 derived constants.
//!
//! ## Why this is a separate primitive from the crypt scheme
//!
//! Both `$7$` (scrypt proper) and `$y$` (yescrypt, still outstanding on
//! bd-c6ykz1) are wrappers around exactly this function with different
//! parameter encodings. Landing the KDF on its own means the format work for
//! each can be verified against the host separately, instead of a format bug
//! and a KDF bug being indistinguishable in one failing hash.
//!
//! ## Endianness is the whole game here
//!
//! Salsa20 words are LITTLE-endian, PBKDF2's block counter is BIG-endian, and
//! `Integerify` reads little-endian. Each is stated at its use site because
//! getting any one of them backwards yields a well-formed key that matches no
//! other implementation, and no intermediate value looks wrong.

use crate::crypt::pbkdf2::pbkdf2_hmac_sha256;

/// One Salsa20 block.
const BLOCK: usize = 64;

/// The Salsa20/8 core: 8 rounds, then add the input back.
///
/// Note this is the CORE, not the stream cipher — there is no key schedule and
/// no nonce. scrypt uses it purely as a 64-byte-to-64-byte mixing function.
fn salsa20_8(block: &mut [u8; BLOCK]) {
    let mut x = [0u32; 16];
    for (i, word) in x.iter_mut().enumerate() {
        // LITTLE-endian, per RFC 7914 section 3.
        *word = u32::from_le_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
    }
    let start = x;

    // Four double-rounds = eight rounds. `/8` names the round count, not a
    // divisor.
    for _ in 0..4 {
        // Column round.
        x[4] ^= x[0].wrapping_add(x[12]).rotate_left(7);
        x[8] ^= x[4].wrapping_add(x[0]).rotate_left(9);
        x[12] ^= x[8].wrapping_add(x[4]).rotate_left(13);
        x[0] ^= x[12].wrapping_add(x[8]).rotate_left(18);

        x[9] ^= x[5].wrapping_add(x[1]).rotate_left(7);
        x[13] ^= x[9].wrapping_add(x[5]).rotate_left(9);
        x[1] ^= x[13].wrapping_add(x[9]).rotate_left(13);
        x[5] ^= x[1].wrapping_add(x[13]).rotate_left(18);

        x[14] ^= x[10].wrapping_add(x[6]).rotate_left(7);
        x[2] ^= x[14].wrapping_add(x[10]).rotate_left(9);
        x[6] ^= x[2].wrapping_add(x[14]).rotate_left(13);
        x[10] ^= x[6].wrapping_add(x[2]).rotate_left(18);

        x[3] ^= x[15].wrapping_add(x[11]).rotate_left(7);
        x[7] ^= x[3].wrapping_add(x[15]).rotate_left(9);
        x[11] ^= x[7].wrapping_add(x[3]).rotate_left(13);
        x[15] ^= x[11].wrapping_add(x[7]).rotate_left(18);

        // Row round.
        x[1] ^= x[0].wrapping_add(x[3]).rotate_left(7);
        x[2] ^= x[1].wrapping_add(x[0]).rotate_left(9);
        x[3] ^= x[2].wrapping_add(x[1]).rotate_left(13);
        x[0] ^= x[3].wrapping_add(x[2]).rotate_left(18);

        x[6] ^= x[5].wrapping_add(x[4]).rotate_left(7);
        x[7] ^= x[6].wrapping_add(x[5]).rotate_left(9);
        x[4] ^= x[7].wrapping_add(x[6]).rotate_left(13);
        x[5] ^= x[4].wrapping_add(x[7]).rotate_left(18);

        x[11] ^= x[10].wrapping_add(x[9]).rotate_left(7);
        x[8] ^= x[11].wrapping_add(x[10]).rotate_left(9);
        x[9] ^= x[8].wrapping_add(x[11]).rotate_left(13);
        x[10] ^= x[9].wrapping_add(x[8]).rotate_left(18);

        x[12] ^= x[15].wrapping_add(x[14]).rotate_left(7);
        x[13] ^= x[12].wrapping_add(x[15]).rotate_left(9);
        x[14] ^= x[13].wrapping_add(x[12]).rotate_left(13);
        x[15] ^= x[14].wrapping_add(x[13]).rotate_left(18);
    }

    for i in 0..16 {
        let word = x[i].wrapping_add(start[i]);
        block[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
}

/// `BlockMix` over `2 * r` 64-byte blocks, writing the shuffled result to `out`.
///
/// The output ordering is the part implementations get wrong: even-indexed
/// results first, then odd-indexed. A straight copy produces a KDF that is
/// self-consistent and wrong.
fn block_mix(input: &[u8], out: &mut [u8], r: usize) {
    let blocks = 2 * r;
    let mut x = [0u8; BLOCK];
    x.copy_from_slice(&input[(blocks - 1) * BLOCK..]);

    for i in 0..blocks {
        for (dst, src) in x.iter_mut().zip(input[i * BLOCK..(i + 1) * BLOCK].iter()) {
            *dst ^= *src;
        }
        salsa20_8(&mut x);
        let target = if i % 2 == 0 { i / 2 } else { r + i / 2 };
        out[target * BLOCK..(target + 1) * BLOCK].copy_from_slice(&x);
    }
}

/// Read the `Integerify` value: the first 4 bytes of the LAST 64-byte block,
/// little-endian. `n` is a power of two, so the modulo is a mask.
fn integerify(block: &[u8], r: usize) -> usize {
    let last = (2 * r - 1) * BLOCK;
    u32::from_le_bytes([
        block[last],
        block[last + 1],
        block[last + 2],
        block[last + 3],
    ]) as usize
}

/// `ROMix`: the memory-hard core. Fills `n` blocks then walks them pseudorandomly.
fn romix(block: &mut [u8], n: usize, r: usize) {
    let block_len = 128 * r;
    let mut v = vec![0u8; n * block_len];
    let mut x = block.to_vec();
    let mut scratch = vec![0u8; block_len];

    for i in 0..n {
        v[i * block_len..(i + 1) * block_len].copy_from_slice(&x);
        block_mix(&x, &mut scratch, r);
        x.copy_from_slice(&scratch);
    }

    for _ in 0..n {
        // n is a power of two, checked by the caller, so `& (n - 1)` is the
        // modulo the RFC specifies.
        let j = integerify(&x, r) & (n - 1);
        for (dst, src) in x
            .iter_mut()
            .zip(v[j * block_len..(j + 1) * block_len].iter())
        {
            *dst ^= *src;
        }
        block_mix(&x, &mut scratch, r);
        x.copy_from_slice(&scratch);
    }

    block.copy_from_slice(&x);
}

/// scrypt, RFC 7914.
///
/// Returns `None` for parameters the construction does not admit: `n` must be a
/// power of two greater than 1, and `r`, `p` and the output length must be
/// non-zero. Refusing rather than clamping matters here — a silently weakened
/// KDF is worse than an error, because the caller still gets a hash.
pub fn scrypt(
    password: &[u8],
    salt: &[u8],
    n: usize,
    r: usize,
    p: usize,
    out: &mut [u8],
) -> Option<()> {
    if n < 2 || n & (n - 1) != 0 || r == 0 || p == 0 || out.is_empty() {
        return None;
    }
    // Guard the allocation implied by n * 128 * r before making it, so absurd
    // parameters fail instead of trying to reserve the address space.
    let block_len = 128usize.checked_mul(r)?;
    let _ = block_len.checked_mul(n)?;
    let total = block_len.checked_mul(p)?;

    let mut b = vec![0u8; total];
    pbkdf2_hmac_sha256(password, salt, 1, &mut b);

    for chunk in b.chunks_exact_mut(block_len) {
        romix(chunk, n, r);
    }

    pbkdf2_hmac_sha256(password, &b, 1, out);
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn unspace(s: &str) -> String {
        s.chars().filter(|c| !c.is_whitespace()).collect()
    }

    /// RFC 7914 vectors. Generated from OpenSSL via Python's `hashlib.scrypt`
    /// and cross-checked against the values the RFC prints, so this is an
    /// independent implementation agreeing with the document.
    #[test]
    fn scrypt_matches_rfc7914_vectors() {
        let cases: &[(&[u8], &[u8], usize, usize, usize, &str)] = &[
            (
                b"",
                b"",
                16,
                1,
                1,
                "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442\
              fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906",
            ),
            (
                b"password",
                b"NaCl",
                1024,
                8,
                16,
                "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162\
              2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640",
            ),
            (
                b"pleaseletmein",
                b"SodiumChloride",
                16384,
                8,
                1,
                "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2\
              d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887",
            ),
        ];
        for (password, salt, n, r, p, expected) in cases {
            let mut out = [0u8; 64];
            scrypt(password, salt, *n, *r, *p, &mut out).expect("valid parameters");
            assert_eq!(hex(&out), unspace(expected), "scrypt n={n} r={r} p={p}");
        }
    }

    /// Parameters the construction does not admit are REFUSED, not clamped. A
    /// silently weakened KDF is worse than an error because the caller still
    /// gets a hash and cannot tell.
    #[test]
    fn invalid_parameters_are_refused() {
        let mut out = [0u8; 32];
        assert!(scrypt(b"p", b"s", 0, 1, 1, &mut out).is_none(), "n=0");
        assert!(scrypt(b"p", b"s", 1, 1, 1, &mut out).is_none(), "n=1");
        assert!(
            scrypt(b"p", b"s", 12, 1, 1, &mut out).is_none(),
            "n not a power of two"
        );
        assert!(scrypt(b"p", b"s", 16, 0, 1, &mut out).is_none(), "r=0");
        assert!(scrypt(b"p", b"s", 16, 1, 0, &mut out).is_none(), "p=0");
        assert!(
            scrypt(b"p", b"s", 16, 1, 1, &mut []).is_none(),
            "empty output"
        );
    }

    /// `block_mix` interleaves its output even-indices-first. A straight copy is
    /// self-consistent and wrong, so pin the permutation directly rather than
    /// only through the end-to-end vectors.
    #[test]
    fn block_mix_uses_the_even_odd_permutation() {
        let r = 2;
        let input: Vec<u8> = (0..(2 * r * BLOCK)).map(|i| (i % 251) as u8).collect();
        let mut mixed = vec![0u8; 2 * r * BLOCK];
        block_mix(&input, &mut mixed, r);

        // Recompute the same four Salsa outputs in sequence and place them by
        // the spec's rule; the two must agree.
        let mut x = [0u8; BLOCK];
        x.copy_from_slice(&input[(2 * r - 1) * BLOCK..]);
        let mut expected = vec![0u8; 2 * r * BLOCK];
        for i in 0..(2 * r) {
            for (dst, src) in x.iter_mut().zip(input[i * BLOCK..(i + 1) * BLOCK].iter()) {
                *dst ^= *src;
            }
            salsa20_8(&mut x);
            let target = if i % 2 == 0 { i / 2 } else { r + i / 2 };
            expected[target * BLOCK..(target + 1) * BLOCK].copy_from_slice(&x);
        }
        assert_eq!(mixed, expected);
    }

    /// Salsa20/8 must depend on every input byte, and must not be the identity
    /// on inputs that carry any information.
    ///
    /// NOTE THE ZERO BLOCK IS A FIXED POINT, and that is correct rather than a
    /// bug. An earlier version of this test asserted the opposite -- "all-zero
    /// input must not pass through" -- which is a property of the full Salsa20
    /// STREAM CIPHER, whose state mixes the constants "expand 32-byte k" into
    /// words 0/5/10/15. The salsa20/8 CORE scrypt uses (RFC 7914 section 3) has
    /// no constants at all: it is pure add/rotate/xor over the caller's block
    /// followed by a feedforward add, so an all-zero block stays zero through
    /// every round. Confusing the two is easy and the assertion looked
    /// reasonable; it failed on this test's first ever compile.
    ///
    /// What actually pins the primitive is `scrypt_matches_rfc7914_vectors`.
    /// This test covers what those vectors cannot see individually: that no
    /// single input byte is ignored.
    #[test]
    fn salsa20_8_diffuses_every_input_byte() {
        let mut mixed_base = [0u8; BLOCK];
        salsa20_8(&mut mixed_base);
        assert_eq!(
            mixed_base, [0u8; BLOCK],
            "the constant-free salsa20/8 core must fix the zero block; if this \
             fails the round function grew a constant it should not have"
        );

        // A block with one bit set must not be the identity -- that IS a real
        // property, and it is the one the zero block cannot test.
        let mut single_bit = [0u8; BLOCK];
        single_bit[0] = 1;
        let mut mixed_single = single_bit;
        salsa20_8(&mut mixed_single);
        assert_ne!(
            mixed_single, single_bit,
            "salsa20/8 must not be the identity on a non-zero block"
        );

        for byte in 0..BLOCK {
            let mut flipped = [0u8; BLOCK];
            flipped[byte] = 1;
            let mut mixed = flipped;
            salsa20_8(&mut mixed);
            assert_ne!(mixed, mixed_base, "flipping byte {byte} changed nothing");
        }
    }
}
