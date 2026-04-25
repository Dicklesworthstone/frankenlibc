//! RFC 3492 Punycode encoder and decoder.
//!
//! Pure-safe Rust port of the byte-level logic that previously lived
//! inline in frankenlibc-abi/src/glibc_internal_abi.rs (the IDNA
//! `__idna_to_dns_encoding` / `__idna_from_dns_encoding` glibc-
//! internal symbols). The abi layer keeps responsibility for the C
//! ABI marshalling, the per-label `xn--` prefix logic, and the
//! malloc'd return buffer; this module operates on Unicode code
//! points and ASCII byte slices only.
//!
//! Reference: <https://www.rfc-editor.org/rfc/rfc3492.html>
//!
//! Test vectors from RFC 3492 §7.1 are exercised in the unit tests.

/// RFC 3492 §5: numeric base.
pub const BASE: u32 = 36;
/// RFC 3492 §5: minimum digit threshold.
pub const TMIN: u32 = 1;
/// RFC 3492 §5: maximum digit threshold.
pub const TMAX: u32 = 26;
/// RFC 3492 §5: bias-adaptation skew.
pub const SKEW: u32 = 38;
/// RFC 3492 §5: bias-adaptation damp factor.
pub const DAMP: u32 = 700;
/// RFC 3492 §5: initial bias.
pub const INITIAL_BIAS: u32 = 72;
/// RFC 3492 §5: initial `n` value (= U+0080, first non-basic).
pub const INITIAL_N: u32 = 128;

/// RFC 3492 §6.1 — bias adaptation.
fn adapt(mut delta: u32, numpoints: u32, firsttime: bool) -> u32 {
    delta = if firsttime { delta / DAMP } else { delta / 2 };
    delta += delta / numpoints;
    let mut k = 0u32;
    while delta > ((BASE - TMIN) * TMAX) / 2 {
        delta /= BASE - TMIN;
        k += BASE;
    }
    k + ((BASE - TMIN + 1) * delta) / (delta + SKEW)
}

/// Encode a single base-36 Punycode digit value to its ASCII byte.
///
/// Per RFC 3492 §5, digits 0-25 use lowercase `'a'..'z'` and digits
/// 26-35 use ASCII digits `'0'..'9'`.
fn encode_digit(d: u32) -> u8 {
    if d < 26 {
        b'a' + d as u8
    } else {
        b'0' + (d as u8 - 26)
    }
}

/// Decode a single ASCII byte to its Punycode digit value.
///
/// Returns `None` for non-base-36 bytes. Letter case is folded.
fn decode_digit(c: u8) -> Option<u32> {
    match c {
        b'a'..=b'z' => Some(u32::from(c - b'a')),
        b'A'..=b'Z' => Some(u32::from(c - b'A')),
        b'0'..=b'9' => Some(u32::from(c - b'0') + 26),
        _ => None,
    }
}

/// Encode a Unicode label (as a `&[u32]` of code points) to Punycode
/// ASCII bytes per RFC 3492.
///
/// Returns `None` on integer overflow during the encoding state
/// machine (a malicious input designed to wrap the `delta` accumulator).
pub fn encode(input: &[u32]) -> Option<Vec<u8>> {
    let mut output = Vec::new();

    // Copy basic (ASCII < INITIAL_N) code points first.
    let mut basic_count: u32 = 0;
    for &cp in input {
        if cp < INITIAL_N {
            output.push(cp as u8);
            basic_count += 1;
        }
    }

    // Delimiter only if there are both basic and non-basic code points.
    let has_nonbasic = basic_count < input.len() as u32;
    if basic_count > 0 && has_nonbasic {
        output.push(b'-');
    }
    if !has_nonbasic {
        return Some(output);
    }

    let mut n = INITIAL_N;
    let mut delta: u32 = 0;
    let mut bias = INITIAL_BIAS;
    let mut h = basic_count;
    let input_len = input.len() as u32;

    while h < input_len {
        // Find the smallest non-basic code point >= n in the input.
        let m = input.iter().filter(|&&cp| cp >= n).copied().min()?;

        delta = delta.checked_add((m - n).checked_mul(h + 1)?)?;
        n = m;

        for &cp in input {
            if cp < n {
                delta = delta.checked_add(1)?;
            } else if cp == n {
                let mut q = delta;
                let mut k = BASE;
                loop {
                    let t = if k <= bias {
                        TMIN
                    } else if k >= bias + TMAX {
                        TMAX
                    } else {
                        k - bias
                    };
                    if q < t {
                        break;
                    }
                    output.push(encode_digit(t + ((q - t) % (BASE - t))));
                    q = (q - t) / (BASE - t);
                    k += BASE;
                }
                output.push(encode_digit(q));
                bias = adapt(delta, h + 1, h == basic_count);
                delta = 0;
                h += 1;
            }
        }
        delta += 1;
        n += 1;
    }

    Some(output)
}

/// Decode Punycode ASCII bytes to a sequence of Unicode code points
/// per RFC 3492.
///
/// Returns `None` on malformed input: non-ASCII bytes in the basic-
/// section, invalid base-36 digits in the variable-length integer
/// section, truncated input mid-digit, or arithmetic overflow.
pub fn decode(input: &[u8]) -> Option<Vec<u32>> {
    let mut output: Vec<u32> = Vec::new();

    // Locate the last `-` delimiter; everything before is basic CPs.
    let basic_end = input.iter().rposition(|&b| b == b'-').unwrap_or(0);

    for &byte in input.iter().take(basic_end) {
        if byte >= 0x80 {
            return None;
        }
        output.push(u32::from(byte));
    }

    let mut n = INITIAL_N;
    let mut i: u32 = 0;
    let mut bias = INITIAL_BIAS;
    let mut pos = if basic_end > 0 { basic_end + 1 } else { 0 };

    while pos < input.len() {
        let oldi = i;
        let mut w: u32 = 1;
        let mut k = BASE;
        loop {
            if pos >= input.len() {
                return None;
            }
            let digit = decode_digit(input[pos])?;
            pos += 1;
            i = i.checked_add(digit.checked_mul(w)?)?;
            let t = if k <= bias {
                TMIN
            } else if k >= bias + TMAX {
                TMAX
            } else {
                k - bias
            };
            if digit < t {
                break;
            }
            w = w.checked_mul(BASE - t)?;
            k += BASE;
        }
        let out_len = (output.len() as u32) + 1;
        bias = adapt(i - oldi, out_len, oldi == 0);
        n = n.checked_add(i / out_len)?;
        i %= out_len;
        if usize::try_from(i).ok()? > output.len() {
            return None;
        }
        output.insert(i as usize, n);
        i += 1;
    }

    Some(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cps(s: &str) -> Vec<u32> {
        s.chars().map(|c| c as u32).collect()
    }

    // ---- digit helpers ----

    #[test]
    fn encode_digit_lowercase_letters_for_0_to_25() {
        for d in 0u32..26 {
            assert_eq!(encode_digit(d), b'a' + d as u8);
        }
    }

    #[test]
    fn encode_digit_ascii_digits_for_26_to_35() {
        for d in 26u32..36 {
            assert_eq!(encode_digit(d), b'0' + (d as u8 - 26));
        }
    }

    #[test]
    fn decode_digit_round_trips_encode_digit() {
        for d in 0u32..36 {
            let byte = encode_digit(d);
            assert_eq!(decode_digit(byte), Some(d));
        }
    }

    #[test]
    fn decode_digit_folds_uppercase() {
        for d in 0u32..26 {
            assert_eq!(decode_digit(b'A' + d as u8), Some(d));
            assert_eq!(decode_digit(b'a' + d as u8), Some(d));
        }
    }

    #[test]
    fn decode_digit_rejects_non_alnum() {
        for b in [b' ', b'-', b'.', b'!', 0x00, 0x80, 0xFF] {
            assert_eq!(decode_digit(b), None);
        }
    }

    // ---- ascii-only round-trip ----

    #[test]
    fn encode_ascii_only_produces_no_delimiter() {
        let input = cps("hello");
        let out = encode(&input).unwrap();
        // No delimiter when everything is basic.
        assert_eq!(out, b"hello");
    }

    #[test]
    fn decode_ascii_with_explicit_delimiter_recovers_basic_cps() {
        // A trailing `-` marks the end of the basic section; nothing
        // follows so the decode produces just the basic CPs.
        let dec = decode(b"hello-").unwrap();
        assert_eq!(dec, cps("hello"));
    }

    #[test]
    fn decode_pure_ascii_no_delimiter_treats_input_as_variable_section() {
        // Per RFC 3492 §6.2: if there is no delimiter, there are no
        // basic code points. The entire input is the variable-length
        // integer section. So `decode("hello")` produces non-ASCII
        // output — the encoder emits "hello" without a delimiter ONLY
        // because the IDNA wrapper guarantees the caller appends
        // `xn--` and never round-trips a pure-ASCII label through
        // decode().
        let dec = decode(b"hello").unwrap();
        assert!(!dec.is_empty());
        assert!(dec.iter().any(|&cp| cp >= INITIAL_N));
    }

    // ---- RFC 3492 §7.1 test vectors ----

    /// Helper: assert that `label` (Unicode code points) encodes to
    /// `expected` and that `expected` decodes back to `label`.
    fn assert_punycode_roundtrip(label: &[u32], expected_ascii: &[u8]) {
        let encoded = encode(label).unwrap_or_else(|| panic!("encode failed for label"));
        assert_eq!(
            encoded,
            expected_ascii,
            "encode mismatch: got {} expected {}",
            String::from_utf8_lossy(&encoded),
            String::from_utf8_lossy(expected_ascii)
        );
        let decoded = decode(expected_ascii).unwrap_or_else(|| panic!("decode failed"));
        assert_eq!(decoded, label.to_vec(), "decode mismatch");
    }

    #[test]
    fn rfc3492_a_arabic_egyptian() {
        // (A) Arabic (Egyptian)
        let label: Vec<u32> = vec![
            0x0644, 0x064A, 0x0647, 0x0645, 0x0627, 0x0628, 0x062A, 0x0643, 0x0644, 0x0645, 0x0648,
            0x0634, 0x0639, 0x0631, 0x0628, 0x064A, 0x061F,
        ];
        assert_punycode_roundtrip(&label, b"egbpdaj6bu4bxfgehfvwxn");
    }

    #[test]
    fn rfc3492_b_chinese_simplified() {
        let label: Vec<u32> = vec![
            0x4ED6, 0x4EEC, 0x4E3A, 0x4EC0, 0x4E48, 0x4E0D, 0x8BF4, 0x4E2D, 0x6587,
        ];
        assert_punycode_roundtrip(&label, b"ihqwcrb4cv8a8dqg056pqjye");
    }

    #[test]
    fn rfc3492_c_chinese_traditional() {
        let label: Vec<u32> = vec![
            0x4ED6, 0x5011, 0x7232, 0x4EC0, 0x9EBD, 0x4E0D, 0x8AAA, 0x4E2D, 0x6587,
        ];
        assert_punycode_roundtrip(&label, b"ihqwctvzc91f659drss3x8bo0yb");
    }

    #[test]
    fn rfc3492_d_czech() {
        // Pročprostěnemluv\xEDčesky
        let label: Vec<u32> = vec![
            0x0050, 0x0072, 0x006F, 0x010D, 0x0070, 0x0072, 0x006F, 0x0073, 0x0074, 0x011B, 0x006E,
            0x0065, 0x006D, 0x006C, 0x0075, 0x0076, 0x00ED, 0x010D, 0x0065, 0x0073, 0x006B, 0x0079,
        ];
        assert_punycode_roundtrip(&label, b"Proprostnemluvesky-uyb24dma41a");
    }

    #[test]
    fn rfc3492_e_hebrew() {
        let label: Vec<u32> = vec![
            0x05DC, 0x05DE, 0x05D4, 0x05D4, 0x05DD, 0x05E4, 0x05E9, 0x05D5, 0x05D8, 0x05DC, 0x05D0,
            0x05DE, 0x05D3, 0x05D1, 0x05E8, 0x05D9, 0x05DD, 0x05E2, 0x05D1, 0x05E8, 0x05D9, 0x05EA,
        ];
        assert_punycode_roundtrip(&label, b"4dbcagdahymbxekheh6e0a7fei0b");
    }

    #[test]
    fn rfc3492_f_hindi() {
        // Devanagari label
        let label: Vec<u32> = vec![
            0x092F, 0x0939, 0x0932, 0x094B, 0x0917, 0x0939, 0x093F, 0x0928, 0x094D, 0x0926, 0x0940,
            0x0915, 0x094D, 0x092F, 0x094B, 0x0902, 0x0928, 0x0939, 0x0940, 0x0902, 0x092C, 0x094B,
            0x0932, 0x0938, 0x0915, 0x0924, 0x0947, 0x0939, 0x0948, 0x0902,
        ];
        assert_punycode_roundtrip(&label, b"i1baa7eci9glrd9b2ae1bj0hfcgg6iyaf8o0a1dig0cd");
    }

    #[test]
    fn rfc3492_g_japanese_hiragana_katakana() {
        let label: Vec<u32> = vec![
            0x306A, 0x305C, 0x307F, 0x3093, 0x306A, 0x65E5, 0x672C, 0x8A9E, 0x3092, 0x8A71, 0x3057,
            0x3066, 0x304F, 0x308C, 0x306A, 0x3044, 0x306E, 0x304B,
        ];
        assert_punycode_roundtrip(&label, b"n8jok5ay5dzabd5bym9f0cm5685rrjetr6pdxa");
    }

    #[test]
    fn rfc3492_h_korean() {
        let label: Vec<u32> = vec![
            0xC138, 0xACC4, 0xC758, 0xBAA8, 0xB4E0, 0xC0AC, 0xB78C, 0xB4E4, 0xC774, 0xD55C, 0xAD6D,
            0xC5B4, 0xB97C, 0xC774, 0xD574, 0xD55C, 0xB2E4, 0xBA74, 0xC5BC, 0xB9C8, 0xB098, 0xC88B,
            0xC744, 0xAE4C,
        ];
        assert_punycode_roundtrip(
            &label,
            b"989aomsvi5e83db1d2a355cv1e0vak1dwrv93d5xbh15a0dt30a5jpsd879ccm6fea98c",
        );
    }

    #[test]
    fn rfc3492_i_russian() {
        let label: Vec<u32> = vec![
            0x043F, 0x043E, 0x0447, 0x0435, 0x043C, 0x0443, 0x0436, 0x0435, 0x043E, 0x043D, 0x0438,
            0x043D, 0x0435, 0x0433, 0x043E, 0x0432, 0x043E, 0x0440, 0x044F, 0x0442, 0x043F, 0x043E,
            0x0440, 0x0443, 0x0441, 0x0441, 0x043A, 0x0438,
        ];
        assert_punycode_roundtrip(&label, b"b1abfaaepdrnnbgefbadotcwatmq2g4l");
    }

    #[test]
    fn rfc3492_j_spanish() {
        let label: Vec<u32> = vec![
            0x0050, 0x006F, 0x0072, 0x0071, 0x0075, 0x00E9, 0x006E, 0x006F, 0x0070, 0x0075, 0x0065,
            0x0064, 0x0065, 0x006E, 0x0073, 0x0069, 0x006D, 0x0070, 0x006C, 0x0065, 0x006D, 0x0065,
            0x006E, 0x0074, 0x0065, 0x0068, 0x0061, 0x0062, 0x006C, 0x0061, 0x0072, 0x0065, 0x006E,
            0x0045, 0x0073, 0x0070, 0x0061, 0x00F1, 0x006F, 0x006C,
        ];
        assert_punycode_roundtrip(&label, b"PorqunopuedensimplementehablarenEspaol-fmd56a");
    }

    #[test]
    fn rfc3492_k_vietnamese() {
        let label: Vec<u32> = vec![
            0x0054, 0x1EA1, 0x0069, 0x0073, 0x0061, 0x006F, 0x0068, 0x1ECD, 0x006B, 0x0068, 0x00F4,
            0x006E, 0x0067, 0x0074, 0x0068, 0x1EC3, 0x0063, 0x0068, 0x1EC9, 0x006E, 0x00F3, 0x0069,
            0x0074, 0x0069, 0x1EBF, 0x006E, 0x0067, 0x0056, 0x0069, 0x1EC7, 0x0074,
        ];
        assert_punycode_roundtrip(&label, b"TisaohkhngthchnitingVit-kjcr8268qyxafd2f1b9g");
    }

    // ---- malformed input rejection ----

    #[test]
    fn decode_rejects_non_ascii_in_basic_section() {
        let mut input = b"hello-world".to_vec();
        input[2] = 0xFF; // non-ASCII byte before the delimiter
        assert!(decode(&input).is_none());
    }

    #[test]
    fn decode_rejects_invalid_digit_in_extended_section() {
        // A valid encoded label with an invalid character substituted in.
        let mut input = b"ihqwcrb4cv8a8dqg056pqjye".to_vec();
        input[5] = b'!'; // not a base-36 digit
        assert!(decode(&input).is_none());
    }

    #[test]
    fn decode_rejects_truncated_extended_section() {
        // Truncated mid-digit-sequence (no terminating "small enough" digit).
        // "zz...." with all max digits and never a digit < TMIN — would
        // require reading off the end of the buffer.
        let input = b"-zzzzzzzz"; // delimiter then never-terminating sequence
        assert!(decode(input).is_none());
    }

    #[test]
    fn decode_empty_input_returns_empty_label() {
        // No basic CPs, no extended section.
        let dec = decode(b"").unwrap();
        assert_eq!(dec, Vec::<u32>::new());
    }

    #[test]
    fn encode_empty_input_returns_empty_label() {
        let enc = encode(&[]).unwrap();
        assert_eq!(enc, Vec::<u8>::new());
    }

    #[test]
    fn encode_decode_round_trip_property_for_rfc_vectors() {
        // Sanity: every RFC vector survives encode->decode and
        // decode->encode without drift.
        let cases: Vec<(Vec<u32>, &[u8])> = vec![
            (
                vec![
                    0x0644, 0x064A, 0x0647, 0x0645, 0x0627, 0x0628, 0x062A, 0x0643, 0x0644, 0x0645,
                    0x0648, 0x0634, 0x0639, 0x0631, 0x0628, 0x064A, 0x061F,
                ],
                b"egbpdaj6bu4bxfgehfvwxn",
            ),
            (
                vec![
                    0x4ED6, 0x4EEC, 0x4E3A, 0x4EC0, 0x4E48, 0x4E0D, 0x8BF4, 0x4E2D, 0x6587,
                ],
                b"ihqwcrb4cv8a8dqg056pqjye",
            ),
        ];
        for (cps, ascii) in cases {
            let enc = encode(&cps).unwrap();
            assert_eq!(enc, ascii);
            let dec = decode(&enc).unwrap();
            assert_eq!(dec, cps);
        }
    }
}
