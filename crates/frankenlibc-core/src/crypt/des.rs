//! DES-based `crypt(3)`: the original two-character-salt scheme, and BSDI's
//! `_`-prefixed extended form built on the same cipher.
//!
//! WHY THIS EXISTS AT ALL. `unistd_abi`'s dispatch documented this scheme as
//! "returns error; DES is obsolete", and every two-char setting fell through to
//! the host-delegation arm — which yields the failure token on any host where
//! libxcrypt is not `dlsym`-able. That is the silent-unverifiable-password
//! failure mode the bcrypt and `$7$` work already removed for their families.
//! The premise was also wrong: the incumbent still implements this. On glibc
//! 2.42 with libcrypt.so.1, `crypt("password", "ab")` answers
//! `abJnggxhB/yWI`. An `/etc/shadow` written before 1999 still holds these,
//! and a login path that cannot verify them fails open or fails shut, never
//! correctly.
//!
//! THE ALGORITHM, as Morris and Thompson specified it. The low 7 bits of each
//! of the first eight password bytes become a 56-bit DES key. The 12-bit salt
//! perturbs the E expansion: bit `j` of salt character `i` swaps `E[6i+j]` with
//! `E[6i+j+24]`, which is what makes a precomputed DES engine useless against a
//! salted hash. The all-zero block is then encrypted 25 times under that key,
//! and the resulting 64 bits are emitted MSB-first in eleven six-bit groups
//! (the last group zero-padded to 66 bits) through the crypt base-64 alphabet,
//! behind the two salt characters. Output is always 13 bytes.
//!
//! ACCEPTANCE RULE, measured byte by byte against libcrypt.so.1 across all 256
//! values at four positions, because it is not the rule it looks like. The
//! setting must be at least two bytes. The FIRST TWO must be crypt base-64
//! digits. Every byte AFTER them is held to a different and weaker standard:
//! printable ASCII, `0x21..=0x7e`, minus exactly five characters —
//!
//!     !  *  :  ;  \\
//!
//! — so `crypt("password", "ab:")` is refused while `crypt("password", "ab$")`
//! is accepted and hashes identically to `"ab"`. Only the first two bytes reach
//! the cipher; the rest are validated and discarded.
//!
//! Those five are not an arbitrary blocklist. `:` and `;` separate fields in
//! `/etc/passwd` and `/etc/shadow`, `\\` could escape one, and `!` and `*` are
//! the conventional markers for a locked and a disabled account. A hash string
//! containing any of them cannot be stored and read back as the same record, and
//! one beginning `*` could not be distinguished from the failure token. Refusing
//! them here is what stops a setting from smuggling a field boundary into a
//! credential file. A naive "must be base-64 throughout" check would be both too
//! strict (rejecting `ab$`) and, on its own, miss the point.
//!
//! Bit numbering follows FIPS 46 throughout: bit 1 is the most significant bit
//! of a block and the tables below are 1-based, transcribed as published so
//! they can be checked against the standard by eye.

/// Initial permutation.
const IP: [u8; 64] = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61,
    53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
];

/// Final permutation, the inverse of [`IP`].
const FP: [u8; 64] = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
];

/// Expansion 32 -> 48, before the salt perturbs it.
const E: [u8; 48] = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18,
    19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
];

/// Round-function output permutation.
const P: [u8; 32] = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19,
    13, 30, 6, 22, 11, 4, 25,
];

/// Key permutation 64 -> 56, dropping the parity bits.
const PC1: [u8; 56] = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60,
    52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
];

/// Subkey selection 56 -> 48.
const PC2: [u8; 48] = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52,
    31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
];

/// Left-rotation of each key half, per round.
const SHIFTS: [u32; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

/// The eight substitution boxes, each flattened row-major from the published
/// 4x16 form. Row is the outer two bits of the six-bit group, column the inner
/// four.
const S: [[u8; 64]; 8] = [
    [
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12,
        11, 9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9,
        1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
    ],
    [
        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1,
        10, 6, 9, 11, 5, 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15,
        4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
    ],
    [
        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5,
        14, 12, 11, 15, 1, 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6,
        9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
    ],
    [
        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2,
        12, 1, 10, 14, 9, 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1,
        13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
    ],
    [
        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15,
        10, 3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14,
        2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
    ],
    [
        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13,
        14, 0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5,
        15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
    ],
    [
        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5,
        12, 2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4,
        10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
    ],
    [
        13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6,
        11, 0, 14, 9, 2, 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10,
        8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
    ],
];

/// The crypt(3) base-64 alphabet. Note this is NOT RFC 4648: the digit values
/// run `.` `/` `0`..`9` `A`..`Z` `a`..`z`.
const A64: &[u8; 64] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// Whether `ch` may appear in a setting AFTER the two salt characters.
///
/// Printable ASCII minus the five characters that would corrupt or forge a
/// shadow-file record; see the acceptance rule in the module docs. Measured
/// against libcrypt.so.1 over all 256 byte values at positions 2, 3, 5 and 9,
/// which agreed exactly.
fn valid_trailing_byte(ch: u8) -> bool {
    matches!(ch, 0x21..=0x7e) && !matches!(ch, b'!' | b'*' | b':' | b';' | b'\\')
}

/// Alphabet position of `ch`, or `None` if it is not a crypt base-64 digit.
/// This is a lookup rather than a range test because the alphabet is not
/// contiguous in ASCII.
fn a64_value(ch: u8) -> Option<u32> {
    match ch {
        b'.' => Some(0),
        b'/' => Some(1),
        b'0'..=b'9' => Some(2 + u32::from(ch - b'0')),
        b'A'..=b'Z' => Some(12 + u32::from(ch - b'A')),
        b'a'..=b'z' => Some(38 + u32::from(ch - b'a')),
        _ => None,
    }
}

/// Bit `pos` (1-based, MSB first) of a `width`-bit value.
#[inline]
fn bit(value: u64, width: u32, pos: u8) -> u64 {
    (value >> (width - u32::from(pos))) & 1
}

/// Apply a 1-based permutation table to a `src_width`-bit value, MSB first.
fn permute(src: u64, src_width: u32, table: &[u8]) -> u64 {
    let mut out = 0u64;
    for &pos in table {
        out = (out << 1) | bit(src, src_width, pos);
    }
    out
}

/// The sixteen 48-bit round subkeys for a 64-bit key block.
fn key_schedule(key: u64) -> [u64; 16] {
    let permuted = permute(key, 64, &PC1);
    let mut c = (permuted >> 28) & 0x0fff_ffff;
    let mut d = permuted & 0x0fff_ffff;
    let mut subkeys = [0u64; 16];
    for (round, subkey) in subkeys.iter_mut().enumerate() {
        let shift = SHIFTS[round];
        c = ((c << shift) | (c >> (28 - shift))) & 0x0fff_ffff;
        d = ((d << shift) | (d >> (28 - shift))) & 0x0fff_ffff;
        *subkey = permute((c << 28) | d, 56, &PC2);
    }
    subkeys
}

/// One DES encryption of `block` under `subkeys`, using the salt-perturbed
/// expansion `expansion` in place of the standard E table.
fn encrypt_block(block: u64, subkeys: &[u64; 16], expansion: &[u8; 48]) -> u64 {
    let permuted = permute(block, 64, &IP);
    let mut left = (permuted >> 32) & 0xffff_ffff;
    let mut right = permuted & 0xffff_ffff;
    for subkey in subkeys {
        let expanded = permute(right, 32, expansion) ^ subkey;
        let mut substituted = 0u64;
        for (box_index, sbox) in S.iter().enumerate() {
            let group = (expanded >> (42 - 6 * box_index)) & 0x3f;
            let row = ((group >> 4) & 0b10) | (group & 1);
            let column = (group >> 1) & 0xf;
            substituted = (substituted << 4) | u64::from(sbox[(row * 16 + column) as usize]);
        }
        let f = permute(substituted, 32, &P);
        let next_right = left ^ f;
        left = right;
        right = next_right;
    }
    // The halves are exchanged once more before the final permutation.
    permute((right << 32) | left, 64, &FP)
}

/// Hash `key` under a traditional DES `setting`, returning the 13-byte result.
///
/// Returns `None` for any setting the incumbent rejects, which the caller turns
/// into libxcrypt's failure token: shorter than two bytes, or containing any
/// byte outside the crypt base-64 alphabet at ANY position.
/// Perturb the expansion with `salt_bits` bits of `salt`.
///
/// Bit `b` swaps `E[b]` with `E[b+24]`. Traditional DES supplies 12 bits, BSDI
/// extended DES supplies 24 — the same construction, twice as wide, which is
/// why a BSDI hash whose upper twelve salt bits are zero has the same body as
/// the traditional hash with the matching two-character salt. This is the whole
/// reason a salted DES hash defeats a precomputed table: it is a different
/// cipher, not merely a different input.
fn expansion_for_salt(salt: u32, salt_bits: u32) -> [u8; 48] {
    let mut expansion = E;
    for bit_index in 0..salt_bits as usize {
        if (salt >> bit_index) & 1 == 1 {
            expansion.swap(bit_index, bit_index + 24);
        }
    }
    expansion
}

/// Append the 64-bit result as eleven six-bit groups, MSB first, over the bits
/// padded to 66.
fn push_hash_body(out: &mut String, block: u64) {
    for group in 0..11 {
        let mut value = 0u64;
        for offset in 0..6 {
            let position = 6 * group + offset;
            let this_bit = if position < 64 {
                (block >> (63 - position)) & 1
            } else {
                0
            };
            value = (value << 1) | this_bit;
        }
        out.push(char::from(A64[value as usize]));
    }
}

/// Decode `count` little-endian crypt base-64 digits starting at `offset`.
fn decode_le_base64(setting: &[u8], offset: usize, count: usize) -> Option<u32> {
    let mut value = 0u32;
    for index in 0..count {
        value |= a64_value(setting[offset + index])? << (6 * index as u32);
    }
    Some(value)
}

/// The first eight key bytes, each shifted up one bit, zero-padded.
fn eight_byte_key(key: &[u8]) -> u64 {
    let mut key_block = 0u64;
    for index in 0..8 {
        let byte = key.get(index).copied().unwrap_or(0);
        key_block = (key_block << 8) | u64::from((byte & 0x7f) << 1);
    }
    key_block
}

/// Hash `key` under a traditional DES `setting`, returning the 13-byte result.
///
/// Returns `None` for any setting the incumbent rejects, which the caller turns
/// into libxcrypt's failure token.
pub fn des_crypt(key: &[u8], setting: &[u8]) -> Option<String> {
    if setting.len() < 2 {
        return None;
    }
    // The two halves of the acceptance rule are genuinely different tests, not
    // one test applied twice: the salt characters must be base-64 digits, the
    // trailing bytes need only be storable in a shadow record. Both are checked
    // even though only the salt reaches the cipher.
    let salt = decode_le_base64(setting, 0, 2)?;
    if !setting[2..].iter().copied().all(valid_trailing_byte) {
        return None;
    }

    // A short password is zero-padded; a longer one is TRUNCATED, which is why
    // traditional `crypt` cannot distinguish two passwords sharing their first
    // eight bytes. BSDI extended DES exists precisely to remove that cap.
    let subkeys = key_schedule(eight_byte_key(key));
    let expansion = expansion_for_salt(salt, 12);

    let mut block = 0u64;
    for _ in 0..25 {
        block = encrypt_block(block, &subkeys, &expansion);
    }

    let mut out = String::with_capacity(13);
    out.push(char::from(setting[0]));
    out.push(char::from(setting[1]));
    push_hash_body(&mut out, block);
    Some(out)
}

/// BSDI's key schedule, which consumes the WHOLE password rather than the first
/// eight bytes.
///
/// The first eight bytes set the key as usual. While bytes remain, the current
/// key block is encrypted under its own schedule — unsalted, one round — and the
/// next eight bytes are XORed into the result, which becomes the new key. So a
/// 40-byte passphrase contributes all 40 bytes, and two passphrases agreeing in
/// their first eight no longer collide.
fn crunched_key_schedule(key: &[u8]) -> [u64; 16] {
    // The advance rule is subtle and is what makes a short key zero-pad rather
    // than run off the end: the cursor moves only while the byte read was
    // non-zero, so it parks at the terminator.
    let mut position = 0usize;
    let mut key_block = 0u64;
    for _ in 0..8 {
        let byte = key.get(position).copied().unwrap_or(0);
        key_block = (key_block << 8) | u64::from((byte & 0x7f) << 1);
        if byte != 0 {
            position += 1;
        }
    }
    let mut subkeys = key_schedule(key_block);

    while position < key.len() {
        key_block = encrypt_block(key_block, &subkeys, &E);
        for byte_index in 0..8 {
            if position >= key.len() {
                break;
            }
            let byte = u64::from((key[position] & 0x7f) << 1);
            key_block ^= byte << (56 - 8 * byte_index);
            position += 1;
        }
        subkeys = key_schedule(key_block);
    }
    subkeys
}

/// Hash `key` under a BSDI extended DES `setting` (`_CCCCSSSS`), returning the
/// 20-byte result.
///
/// The format is an underscore, four base-64 digits of iteration count and four
/// of salt, all little-endian. Both widen traditional DES: the count replaces
/// its fixed 25, and the salt is 24 bits rather than 12. A count of zero is
/// treated as one — measured, not assumed; the incumbent gives byte-identical
/// answers for counts 0 and 1 across every salt probed.
///
/// The acceptance rule mirrors [`des_crypt`] exactly: all eight parameter
/// characters must be base-64 digits, and anything after them is held to the
/// same printable-minus-five standard and then discarded.
pub fn bsdi_crypt(key: &[u8], setting: &[u8]) -> Option<String> {
    if setting.len() < 9 || setting[0] != b'_' {
        return None;
    }
    let count = decode_le_base64(setting, 1, 4)?;
    let salt = decode_le_base64(setting, 5, 4)?;
    if !setting[9..].iter().copied().all(valid_trailing_byte) {
        return None;
    }

    let subkeys = crunched_key_schedule(key);
    let expansion = expansion_for_salt(salt, 24);

    let mut block = 0u64;
    for _ in 0..count.max(1) {
        block = encrypt_block(block, &subkeys, &expansion);
    }

    let mut out = String::with_capacity(20);
    for &byte in &setting[..9] {
        out.push(char::from(byte));
    }
    push_hash_body(&mut out, block);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Transcription check on the tables themselves, which needs no oracle and
    /// catches the failure this module is most exposed to: a single wrong digit
    /// in 736 hand-copied table entries. Every one of these properties is
    /// forced by the structure of DES, so a typo breaks at least one of them —
    /// whereas a typo in the S-boxes alone changes the hash without changing
    /// anything a reader would notice.
    #[test]
    fn tables_are_structurally_valid() {
        let mut ip_sorted = IP;
        ip_sorted.sort_unstable();
        let mut fp_sorted = FP;
        fp_sorted.sort_unstable();
        let expected_64: Vec<u8> = (1..=64).collect();
        assert_eq!(ip_sorted.to_vec(), expected_64, "IP must permute 1..=64");
        assert_eq!(fp_sorted.to_vec(), expected_64, "FP must permute 1..=64");

        let mut p_sorted = P;
        p_sorted.sort_unstable();
        let expected_32: Vec<u8> = (1..=32).collect();
        assert_eq!(p_sorted.to_vec(), expected_32, "P must permute 1..=32");

        // IP and FP must be inverses, which is the property that actually
        // matters and is not implied by each being a permutation.
        for (index, &position) in IP.iter().enumerate() {
            assert_eq!(
                FP[position as usize - 1] as usize,
                index + 1,
                "FP is not the inverse of IP at position {position}"
            );
        }

        // PC1 and PC2 select without repeating; PC1 drops exactly the eight
        // parity bits, every one of which is a multiple of 8.
        let mut pc1_sorted = PC1;
        pc1_sorted.sort_unstable();
        for pair in pc1_sorted.windows(2) {
            assert_ne!(pair[0], pair[1], "PC1 repeats an entry");
        }
        for parity in [8u8, 16, 24, 32, 40, 48, 56, 64] {
            assert!(!PC1.contains(&parity), "PC1 must drop parity bit {parity}");
        }
        let mut pc2_sorted = PC2;
        pc2_sorted.sort_unstable();
        for pair in pc2_sorted.windows(2) {
            assert_ne!(pair[0], pair[1], "PC2 repeats an entry");
        }

        // The rotations must total 28, or the key schedule would not return the
        // halves to their starting position after sixteen rounds.
        assert_eq!(
            SHIFTS.iter().sum::<u32>(),
            28,
            "key rotations must sum to 28"
        );

        // Every S-box row is a permutation of 0..=15. This is the check that
        // catches a mistyped substitution digit.
        for (box_index, sbox) in S.iter().enumerate() {
            for row in 0..4 {
                let mut values = sbox[row * 16..(row + 1) * 16].to_vec();
                values.sort_unstable();
                assert_eq!(
                    values,
                    (0..16).collect::<Vec<u8>>(),
                    "S{} row {row} is not a permutation of 0..=15",
                    box_index + 1
                );
            }
        }

        // The expansion must reference all 32 input bits, sixteen of them twice.
        for input_bit in 1..=32u8 {
            assert_eq!(
                E.iter().filter(|&&entry| entry == input_bit).count(),
                if input_bit % 4 == 1 || input_bit % 4 == 0 {
                    2
                } else {
                    1
                },
                "E references input bit {input_bit} the wrong number of times"
            );
        }
    }

    /// Probed from live libcrypt.so.1 (glibc 2.42), not copied from a document.
    #[test]
    fn known_vectors() {
        for (key, setting, expected) in [
            (&b""[..], "ab", "abmF1QH4PEr.E"),
            (b"password", "ab", "abJnggxhB/yWI"),
            (b"password", "zz", "zzXUHfURnGg8I"),
            (b"password", "..", "..UZoIyj/Hy/c"),
            (b"password", "ZZ", "ZZKRwXSu3tt8s"),
            (b"hello world", "Xy", "Xyy7mbARqDoBw"),
        ] {
            assert_eq!(
                des_crypt(key, setting.as_bytes()).as_deref(),
                Some(expected),
                "des_crypt({key:?}, {setting:?})"
            );
        }
    }

    #[test]
    fn key_is_capped_at_eight_bytes() {
        let eight = des_crypt(b"12345678", b"aB");
        assert_eq!(eight.as_deref(), Some("aB75dxyE/c05M"));
        assert_eq!(des_crypt(b"123456789", b"aB"), eight);
        assert_eq!(des_crypt(b"12345678X", b"aB"), eight);
        // Not merely equal to each other — equal to the eight-byte answer.
        assert_ne!(des_crypt(b"1234567", b"aB"), eight);
    }

    #[test]
    fn acceptance_rule() {
        let two_char = des_crypt(b"password", b"ab");
        assert!(two_char.is_some());
        // Trailing bytes are validated, then discarded.
        for setting in [&b"ab$"[..], b"ab_", b"ab-", b"ab~", b"abcdefghij"] {
            assert_eq!(
                des_crypt(b"password", setting),
                two_char,
                "{setting:?} must hash as its two-character prefix"
            );
        }
        // The salt characters themselves must be base-64 digits...
        for setting in [&b""[..], b"a", b"!a", b"a!", b":ab", b"*ab", b"_ab"] {
            assert!(
                des_crypt(b"password", setting).is_none(),
                "{setting:?} must be refused"
            );
        }
        // ...and the five shadow-record characters are refused anywhere.
        for bad in [b'!', b'*', b':', b';', b'\\'] {
            let setting = [b'a', b'b', bad];
            assert!(
                des_crypt(b"password", &setting).is_none(),
                "a trailing {:?} must be refused",
                char::from(bad)
            );
        }
        // Non-printable and high-bit bytes are refused too.
        for bad in [0x00u8, 0x01, 0x20, 0x7f, 0xff] {
            if bad == 0 {
                continue; // a C setting cannot contain NUL
            }
            let setting = [b'a', b'b', bad];
            assert!(
                des_crypt(b"password", &setting).is_none(),
                "a trailing byte {bad:#04x} must be refused"
            );
        }
    }

    /// The salt must actually reach the cipher: two different salts on the same
    /// password must give different hashes. A perturbation applied to the wrong
    /// table, or not applied at all, would still pass the fixed vectors above if
    /// they happened to share a salt — this makes that impossible.
    #[test]
    fn salt_changes_the_hash() {
        let mut seen = std::collections::HashSet::new();
        const A64_CHARS: &[u8; 64] = A64;
        for &first in A64_CHARS.iter() {
            let setting = [first, b'a'];
            let hash = des_crypt(b"password", &setting).expect("valid salt");
            assert!(
                seen.insert(hash[2..].to_owned()),
                "two distinct salts produced the same hash body"
            );
        }
        assert_eq!(seen.len(), 64);
    }

    /// Probed from live libcrypt.so.1. The settings are written out rather than
    /// built from a count/salt helper so the encoding itself is pinned: `_N...`
    /// is count 25, little-endian base-64, and `..../` is not.
    #[test]
    fn bsdi_known_vectors() {
        for (key, setting, expected) in [
            (&b""[..], "_........", "_........X8NBuQ4l6uQ"),
            (b"a", "_/.......", "_/.......PRz1ci0M3y6"),
            (b"password", "_/.......", "_/.......zqM49hRzxko"),
            (b"password", "_N.......", "_N.......UZoIyj/Hy/c"),
            (b"password", "_N...zz..", "_N...zz..XUHfURnGg8I"),
            (b"password", "_0.../...", "_0.../...1p8C52NiFEw"),
            (b"password", "_3...KFX2", "_3...KFX29tEKhP61Ln6"),
            (b"password", "_Y/..zzzz", "_Y/..zzzzLcER1hJEFj."),
            (
                b"The quick brown fox jumps over",
                "_8...Dwk1",
                "_8...Dwk1DEAUtG5UGSU",
            ),
            (b"\x7f\x01\xff", "_5...e...", "_5...e...9LQKOKoP70I"),
        ] {
            assert_eq!(
                bsdi_crypt(key, setting.as_bytes()).as_deref(),
                Some(expected),
                "bsdi_crypt({key:?}, {setting:?})"
            );
        }
    }

    /// BSDI exists to remove traditional DES's eight-byte cap. These four
    /// passwords share their first eight bytes and MUST all differ — the exact
    /// opposite of [`key_is_capped_at_eight_bytes`], and the property that
    /// proves key crunching runs at all.
    #[test]
    fn bsdi_consumes_the_whole_password() {
        let hashes: Vec<String> = [
            &b"12345678"[..],
            b"123456789",
            b"1234567890123456",
            b"12345678901234567",
        ]
        .iter()
        .map(|key| bsdi_crypt(key, b"_N.......").expect("valid setting"))
        .collect();
        assert_eq!(hashes[0], "_N.......EXlUiP8mHCU");
        assert_eq!(hashes[1], "_N.......eVPTtb4Te06");
        assert_eq!(hashes[2], "_N.......aylbIVkCLSo");
        assert_eq!(hashes[3], "_N.......S6X8Q6YmCew");
        let distinct: std::collections::HashSet<&String> = hashes.iter().collect();
        assert_eq!(
            distinct.len(),
            4,
            "key crunching did not run: passwords sharing eight bytes collided"
        );
    }

    /// The two schemes share one cipher, and this pins that they really do.
    /// BSDI at count 25 with a salt whose upper twelve bits are zero must
    /// produce the same eleven-character body as traditional DES with the
    /// corresponding two-character salt. Needs no oracle: if the count default,
    /// the salt widening or the expansion indexing were wrong in either path,
    /// the two bodies would part company.
    #[test]
    fn bsdi_at_count_25_equals_traditional_des() {
        for salt in [b"..", b"zz", b"ab", b"Z9"] {
            let low = a64_value(salt[0]).unwrap() | (a64_value(salt[1]).unwrap() << 6);
            let mut setting = Vec::from(&b"_"[..]);
            for index in 0..4 {
                setting.push(A64[((25u32 >> (6 * index)) & 0x3f) as usize]);
            }
            for index in 0..4 {
                setting.push(A64[((low >> (6 * index)) & 0x3f) as usize]);
            }
            let bsdi = bsdi_crypt(b"password", &setting).expect("valid BSDI setting");
            let des = des_crypt(b"password", salt).expect("valid DES setting");
            assert_eq!(
                &bsdi[9..],
                &des[2..],
                "the two schemes disagree at salt {:?} despite sharing the cipher",
                core::str::from_utf8(salt).unwrap()
            );
        }
    }

    /// A count of zero means one round, not zero rounds. Measured: the
    /// incumbent gives byte-identical bodies for counts 0 and 1 at every salt
    /// probed. Zero rounds would leave the all-zero block untouched and emit a
    /// body of eleven `.` characters, which is what this rules out.
    #[test]
    fn bsdi_count_zero_means_one_round() {
        let zero = bsdi_crypt(b"password", b"_........").expect("valid");
        let one = bsdi_crypt(b"password", b"_/.......").expect("valid");
        assert_eq!(zero[9..], one[9..], "counts 0 and 1 must share a body");
        assert_ne!(&zero[9..], "...........", "a zero-round hash is not a hash");
        // And the count must actually matter.
        let two = bsdi_crypt(b"password", b"_0.......").expect("valid");
        assert_ne!(
            one[9..],
            two[9..],
            "the iteration count did not reach the cipher"
        );
    }

    #[test]
    fn bsdi_acceptance_rule() {
        // Too short, wrong prefix, and a non-base-64 parameter character.
        for setting in [
            &b""[..],
            b"_",
            b"_/......",
            b"a/.......",
            b"__/.......",
            b"_:.......",
            b"_/......:",
        ] {
            assert!(
                bsdi_crypt(b"password", setting).is_none(),
                "{setting:?} must be refused"
            );
        }
        // Trailing bytes obey the same rule as traditional DES: validated,
        // then discarded.
        let nine = bsdi_crypt(b"password", b"_/.......").expect("valid");
        for extra in [&b"x"[..], b"$", b"~", b"xxxxxxxx"] {
            let mut setting = Vec::from(&b"_/......."[..]);
            setting.extend_from_slice(extra);
            assert_eq!(
                bsdi_crypt(b"password", &setting).as_deref(),
                Some(nine.as_str()),
                "trailing {extra:?} must be accepted and discarded"
            );
        }
        for bad in [b'!', b'*', b':', b';', b'\\', 0x01, 0x7f, 0xff, b' '] {
            let mut setting = Vec::from(&b"_/......."[..]);
            setting.push(bad);
            assert!(
                bsdi_crypt(b"password", &setting).is_none(),
                "trailing {bad:#04x} must be refused"
            );
        }
    }
}
