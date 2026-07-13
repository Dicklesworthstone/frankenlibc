//! POSIX base-64 encoding: `a64l` and `l64a`.
//!
//! Uses the System V base-64 alphabet: `.`, `/`, `0`-`9`, `A`-`Z`, `a`-`z`
//! (NOT the same as MIME/RFC 4648 base64).

/// The a64l/l64a alphabet (System V ordering).
/// Index 0 = '.', 1 = '/', 2-11 = '0'-'9', 12-37 = 'A'-'Z', 38-63 = 'a'-'z'
const ALPHABET: &[u8; 64] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// Reverse of [`ALPHABET`]: byte value → its 6-bit index (0..=63), or `-1` for any
/// byte outside the SVID base-64 alphabet (including NUL). A single table load per
/// character replaces `a64l`'s per-char range-match cascade (which does up to six
/// comparisons for the common `a`-`z` case). `-1` doubles as the terminator sentinel:
/// glibc's `a64l` stops at the first non-alphabet byte, exactly as the old `match`'s
/// `0 => break` / `_ => break` arms did. Shared by the ABI `a64l` inline fast path
/// (crates/frankenlibc-abi/src/stdlib_abi.rs) so both decode identically.
pub const A64L_DECODE: [i8; 256] = {
    let mut t = [-1i8; 256];
    let mut i = 0usize;
    while i < 64 {
        t[ALPHABET[i] as usize] = i as i8;
        i += 1;
    }
    t
};

/// `a64l` — convert a base-64 ASCII string to a long.
///
/// Per glibc man page: encodes a **32-bit** value. Reads up to 6 input
/// characters; though six 6-bit chunks could express 36 bits, glibc
/// truncates to 32 bits before returning. We zero-extend the result
/// from u32 to i64 to match — `a64l("zzzzzz")` returns 4294967295,
/// not -1 and not 68719476735.
pub fn a64l(s: &[u8]) -> i64 {
    let mut result: u64 = 0;
    let mut shift = 0u32;

    for &c in s.iter().take(6) {
        // `A64L_DECODE[c] < 0` covers both NUL and any non-alphabet byte, which
        // glibc treats as the terminator (was `c == 0` + a range-match `_ => break`).
        let v = A64L_DECODE[c as usize];
        if v < 0 {
            break;
        }
        result |= (v as u64) << shift;
        shift += 6;
    }

    // Truncate to 32 bits per glibc, then zero-extend back to long.
    (result as u32) as i64
}

/// `l64a` — convert a long to a base-64 ASCII string.
///
/// Per glibc: takes the **low 32 bits** of `value` (regardless of
/// sign), then encodes 1-6 chars while non-zero. So `l64a(-1)`
/// truncates to 0xFFFFFFFF and encodes as `"zzzzz1"` (six chars);
/// `l64a(0x100000000)` truncates to 0 and returns the empty string.
/// The previous impl rejected negative values outright and could emit
/// up to 11 chars for 64-bit inputs — both diverged from glibc.
pub fn l64a(value: i64) -> Vec<u8> {
    // Take low 32 bits per glibc; cast through u32 to zero-extend.
    let mut v = (value as u32) as u64;
    if v == 0 {
        return Vec::new();
    }

    let mut result = Vec::with_capacity(6);
    while v != 0 && result.len() < 6 {
        let idx = (v & 0x3F) as usize;
        result.push(ALPHABET[idx]);
        v >>= 6;
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_a64l_basic() {
        // '.' = 0, '/' = 1
        assert_eq!(a64l(b"."), 0);
        assert_eq!(a64l(b"/"), 1);
        // '0' = 2
        assert_eq!(a64l(b"0"), 2);
        // 'A' = 12
        assert_eq!(a64l(b"A"), 12);
        // 'a' = 38
        assert_eq!(a64l(b"a"), 38);
    }

    #[test]
    fn test_l64a_basic() {
        assert!(l64a(0).is_empty());
        assert_eq!(l64a(1), b"/");
        assert_eq!(l64a(2), b"0");
    }

    #[test]
    fn test_a64l_l64a_roundtrip() {
        for val in [1i64, 42, 100, 1000, 123456, 2_000_000_000] {
            let encoded = l64a(val);
            let decoded = a64l(&encoded);
            assert_eq!(decoded, val, "roundtrip failed for {val}");
        }
    }

    #[test]
    fn test_l64a_a64l_roundtrip_uses_low_32_bits() {
        for val in [
            i64::MIN,
            -2,
            -1,
            0,
            1,
            63,
            64,
            4095,
            4096,
            i32::MAX as i64,
            u32::MAX as i64,
            1i64 << 32,
            (1i64 << 40) + 12345,
            i64::MAX,
        ] {
            let expected = (val as u32) as i64;
            assert_eq!(
                a64l(&l64a(val)),
                expected,
                "low32 roundtrip failed for {val}"
            );
        }
    }

    #[test]
    fn test_l64a_outputs_canonical_alphabet_slice() {
        for val in [
            -1,
            0,
            1,
            62,
            63,
            64,
            65,
            1_000_000,
            i32::MAX as i64,
            u32::MAX as i64,
        ] {
            let encoded = l64a(val);
            assert!(
                encoded.len() <= 6,
                "encoded too long for {val}: {encoded:?}"
            );
            assert!(
                encoded.iter().all(|c| ALPHABET.contains(c)),
                "non-alphabet byte emitted for {val}: {encoded:?}"
            );
        }
    }

    #[test]
    fn test_l64a_depends_only_on_low_32_bits() {
        let high_bit = 1i64 << 32;

        for val in [0i64, 1, 42, 123_456, i32::MAX as i64, u32::MAX as i64] {
            assert_eq!(l64a(val), l64a(val + high_bit), "high bits changed {val}");
        }
        assert_eq!(l64a(-1), l64a(u32::MAX as i64));
        assert_eq!(a64l(&l64a(-1)), u32::MAX as i64);
    }

    #[test]
    fn test_a64l_empty_string() {
        assert_eq!(a64l(b""), 0);
        assert_eq!(a64l(b"\0"), 0);
    }

    #[test]
    fn test_a64l_stop_boundaries_preserve_prefix_value() {
        for prefix in [
            b"0".as_slice(),
            b"Az".as_slice(),
            b"abc".as_slice(),
            b"//////".as_slice(),
        ] {
            let expected = a64l(prefix);

            let mut invalid_terminated = prefix.to_vec();
            invalid_terminated.extend_from_slice(b"!zzzz");
            assert_eq!(a64l(&invalid_terminated), expected);

            let mut nul_terminated = prefix.to_vec();
            nul_terminated.extend_from_slice(b"\0zzzz");
            assert_eq!(a64l(&nul_terminated), expected);
        }
    }

    #[test]
    fn test_a64l_canonical_fixed_point_for_valid_prefixes() {
        for input in [
            b".".as_slice(),
            b"/".as_slice(),
            b"0".as_slice(),
            b"z".as_slice(),
            b"Az09".as_slice(),
            b"zzzzz1".as_slice(),
            b"zzzzzz".as_slice(),
        ] {
            let decoded = a64l(input);
            assert_eq!(
                a64l(&l64a(decoded)),
                decoded,
                "canonical fixed point failed for {input:?}"
            );
        }
    }

    #[test]
    fn test_a64l_max_six_chars() {
        // Only first 6 characters are processed.
        let s = b"//////z"; // 7 chars, last is ignored
        let result = a64l(s);
        let s6 = b"//////";
        let result6 = a64l(s6);
        assert_eq!(result, result6);
    }
}
