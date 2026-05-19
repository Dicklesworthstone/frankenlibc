//! NetBSD `vis(3)` family — visual byte encoding/decoding.
//!
//! Pure-safe Rust port of the byte-level transformation. The C ABI
//! shim in `frankenlibc-abi::stdio_abi` handles raw-pointer NUL and
//! bounds.
//!
//! ## Encoding (default mode, no flags)
//!
//! - Printable ASCII (0x20..=0x7e) except `\\`, plus tab and
//!   newline → emitted as-is.
//! - `\\` → `\\\\`.
//! - Other non-printable c < 0x80 → `\\^X` where X = c XOR 0x40.
//! - 0x7f (DEL) → `\\^?`.
//! - High-bit bytes (c >= 0x80) → `\\M-X` for printable low-half
//!   bytes and `\\M^X` for low-half control bytes.
//!
//! ## Encoding ([`VIS_OCTAL`])
//!
//! All encoded non-printable bytes (anything outside 0x20..=0x7e
//! except the default-safe whitespace plus the mandatory
//! `\\`-escape) are rendered as `\\NNN` (3-digit octal).
//!
//! ## Decoding
//!
//! Recognizes the inverse forms above plus the C-style short
//! escapes `\\n \\t \\r \\b \\v \\a \\f \\0`. Octal escapes accept
//! one to three digits, matching the BSD decoder's push-back
//! behavior when a non-octal byte terminates the sequence. Anything
//! else after a `\\` is passed through verbatim.
//!
//! `VIS_SP`, `VIS_TAB`, and `VIS_NL` force the normally safe
//! whitespace bytes to be escaped. `VIS_CSTYLE` uses C-style escape
//! spellings for the standard control characters. `VIS_SAFE`,
//! `VIS_DQ`, `VIS_GLOB`, `VIS_SHELL`, and `VIS_META` alter the
//! encoded character set, while `VIS_NOSLASH` suppresses the leading
//! backslash in the default `\^X` / `\M-X` forms. `VIS_HTTPSTYLE`
//! uses URI `%xx` escapes and `VIS_MIMESTYLE` uses MIME
//! quoted-printable `=XX` escapes for bytes required by those formats.
//! Other libutil representation flags (`VIS_NOLOCALE`, etc.) are
//! accepted for flag-string compatibility but have no byte-level
//! effect in this safe C-locale encoder.

/// Render all non-printable bytes as `\NNN` octal triples instead
/// of the default `\^X` / `\M-X` notation.
pub const VIS_OCTAL: u32 = 0x01;
/// Force space to be escaped instead of using the default literal
/// passthrough.
pub const VIS_SP: u32 = 0x04;
/// Force tab to be escaped instead of using the default literal
/// passthrough.
pub const VIS_TAB: u32 = 0x08;
/// Force newline to be escaped instead of using the default literal
/// passthrough.
pub const VIS_NL: u32 = 0x10;
/// Use C-style escape spellings for standard control characters
/// that must be encoded.
pub const VIS_CSTYLE: u32 = 0x02;
/// Convenience mask for whitespace-forcing flags.
pub const VIS_WHITE: u32 = VIS_SP | VIS_TAB | VIS_NL;
/// NetBSD `VIS_SAFE` bit. Accepted for ABI flag parity; the v1
/// byte encoder allows the documented safe control bytes through.
pub const VIS_SAFE: u32 = 0x20;
/// Suppress the leading slash in default visual escape forms.
pub const VIS_NOSLASH: u32 = 0x40;
/// Use URI percent encoding (`%xx`) for bytes outside the HTTP-safe set.
pub const VIS_HTTPSTYLE: u32 = 0x80;
/// Historical alias for [`VIS_HTTPSTYLE`].
pub const VIS_HTTP1808: u32 = VIS_HTTPSTYLE;
/// Use MIME quoted-printable encoding (`=XX`) for MIME-unsafe bytes.
pub const VIS_MIMESTYLE: u32 = 0x100;
/// Encode double quotes.
pub const VIS_DQ: u32 = 0x8000;
/// Encode glob(3) magic characters.
pub const VIS_GLOB: u32 = 0x1000;
/// Encode shell metacharacters.
pub const VIS_SHELL: u32 = 0x2000;
/// Synonym for [`VIS_WHITE`] | [`VIS_GLOB`] | [`VIS_SHELL`].
pub const VIS_META: u32 = VIS_WHITE | VIS_GLOB | VIS_SHELL;

/// Parse a NetBSD `VIS_OPTIONS`-style flag string and return the
/// OR of the recognized `VIS_*` flag bits.
///
/// Tokens are comma-separated and case-sensitive. Recognized
/// tokens map to the corresponding `VIS_*` constants in this
/// module. NetBSD-only locale/decoder tokens with no byte-level
/// encoder effect here are accepted and ignored. Unknown tokens are
/// also ignored.
///
/// Whitespace inside tokens is trimmed; empty tokens (e.g. from
/// trailing commas) are skipped.
pub fn parse_vis_options(s: &[u8]) -> u32 {
    let mut flags: u32 = 0;
    for chunk in s.split(|&b| b == b',') {
        let trimmed = trim_ascii(chunk);
        if trimmed.is_empty() {
            continue;
        }
        match trimmed {
            b"VIS_OCTAL" => flags |= VIS_OCTAL,
            b"VIS_SP" => flags |= VIS_SP,
            b"VIS_TAB" => flags |= VIS_TAB,
            b"VIS_NL" => flags |= VIS_NL,
            b"VIS_CSTYLE" => flags |= VIS_CSTYLE,
            b"VIS_WHITE" => flags |= VIS_WHITE,
            b"VIS_SAFE" => flags |= VIS_SAFE,
            b"VIS_NOSLASH" => flags |= VIS_NOSLASH,
            b"VIS_HTTPSTYLE" | b"VIS_HTTP1808" => flags |= VIS_HTTPSTYLE,
            b"VIS_MIMESTYLE" => flags |= VIS_MIMESTYLE,
            b"VIS_DQ" => flags |= VIS_DQ,
            b"VIS_GLOB" => flags |= VIS_GLOB,
            b"VIS_SHELL" => flags |= VIS_SHELL,
            b"VIS_META" => flags |= VIS_META,
            // NetBSD-specific token accepted for VIS_OPTIONS parity.
            b"VIS_NOLOCALE" => {}
            _ => {} // Unknown token — silently ignore.
        }
    }
    flags
}

fn trim_ascii(s: &[u8]) -> &[u8] {
    let start = s
        .iter()
        .position(|&b| !b.is_ascii_whitespace())
        .unwrap_or(s.len());
    let end = s
        .iter()
        .rposition(|&b| !b.is_ascii_whitespace())
        .map(|i| i + 1)
        .unwrap_or(start);
    s.get(start..end).unwrap_or_default()
}

fn is_octal_digit(c: u8) -> bool {
    (b'0'..=b'7').contains(&c)
}

fn push_octal(c: u8, out: &mut Vec<u8>) {
    out.push(b'\\');
    out.push(b'0' + ((c >> 6) & 0x07));
    out.push(b'0' + ((c >> 3) & 0x07));
    out.push(b'0' + (c & 0x07));
}

fn decode_octal_escape(first_digit: u8, input: &[u8]) -> DecodeStep {
    let mut value = first_digit - b'0';
    let mut consumed = 2usize;

    let Some(&second_digit) = input.get(2) else {
        return DecodeStep::Byte {
            byte: value,
            consumed,
        };
    };
    if !is_octal_digit(second_digit) {
        return DecodeStep::Byte {
            byte: value,
            consumed,
        };
    }

    value = (value << 3) | (second_digit - b'0');
    consumed += 1;

    let Some(&third_digit) = input.get(3) else {
        return DecodeStep::Byte {
            byte: value,
            consumed,
        };
    };
    if !is_octal_digit(third_digit) {
        return DecodeStep::Byte {
            byte: value,
            consumed,
        };
    }
    if value & 0o40 != 0 {
        return DecodeStep::Invalid;
    }

    DecodeStep::Byte {
        byte: (value << 3) | (third_digit - b'0'),
        consumed: consumed + 1,
    }
}

fn lower_hex_digit(n: u8) -> u8 {
    let digit = n & 0x0f;
    if digit < 10 {
        b'0' + digit
    } else {
        b'a' + (digit - 10)
    }
}

fn upper_hex_digit(n: u8) -> u8 {
    let digit = n & 0x0f;
    if digit < 10 {
        b'0' + digit
    } else {
        b'A' + (digit - 10)
    }
}

fn push_http_escape(c: u8, out: &mut Vec<u8>) {
    out.push(b'%');
    out.push(lower_hex_digit(c >> 4));
    out.push(lower_hex_digit(c));
}

fn push_mime_escape(c: u8, out: &mut Vec<u8>) {
    out.push(b'=');
    out.push(upper_hex_digit(c >> 4));
    out.push(upper_hex_digit(c));
}

fn http_safe_passthrough(c: u8) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            b'$' | b'-' | b'_' | b'.' | b'+' | b'!' | b'*' | b'\'' | b'(' | b')' | b','
        )
}

fn mime_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

fn mime_must_escape(c: u8, nextc: Option<u8>) -> bool {
    c != b'\n'
        && ((mime_space(c) && matches!(nextc, Some(b'\r' | b'\n')))
            || (!mime_space(c) && (c < 33 || c == b'=' || c > 126))
            || matches!(
                c,
                b'#' | b'$' | b'@' | b'[' | b'\\' | b']' | b'^' | b'`' | b'{' | b'|' | b'}' | b'~'
            ))
}

fn whitespace_passthrough(c: u8, flags: u32) -> bool {
    matches!(c, b' ' if flags & VIS_SP == 0)
        || matches!(c, b'\t' if flags & VIS_TAB == 0)
        || matches!(c, b'\n' if flags & VIS_NL == 0)
}

fn safe_control_passthrough(c: u8, flags: u32) -> bool {
    flags & VIS_SAFE != 0 && matches!(c, b'\x08' | b'\x07' | b'\r')
}

fn flag_forces_escape(c: u8, flags: u32) -> bool {
    matches!(c, b'"' if flags & VIS_DQ != 0)
        || (flags & VIS_GLOB != 0 && matches!(c, b'*' | b'?' | b'[' | b'#'))
        || (flags & VIS_SHELL != 0
            && matches!(
                c,
                b'\''
                    | b'`'
                    | b'"'
                    | b';'
                    | b'&'
                    | b'<'
                    | b'>'
                    | b'('
                    | b')'
                    | b'|'
                    | b']'
                    | b'\\'
                    | b'$'
                    | b'!'
                    | b'^'
                    | b'~'
            ))
}

fn push_cstyle_escape(c: u8, nextc: Option<u8>, out: &mut Vec<u8>) -> bool {
    let escaped = match c {
        b'\0' => {
            if nextc.is_some_and(is_octal_digit) {
                push_octal(c, out);
                return true;
            }
            b'0'
        }
        0x07 => b'a',
        b'\x08' => b'b',
        0x0c => b'f',
        b'\n' => b'n',
        b'\r' => b'r',
        b' ' => b's',
        b'\t' => b't',
        0x0b => b'v',
        _ => return false,
    };
    out.push(b'\\');
    out.push(escaped);
    true
}

/// Encode a single byte `c` into `out`, appending the result.
/// `flags` is the OR of `VIS_*` constants.
pub fn encode_byte(c: u8, flags: u32, out: &mut Vec<u8>) {
    encode_byte_with_next(c, flags, None, out);
}

/// Encode a single byte, using `nextc` for `VIS_CSTYLE` NUL
/// disambiguation.
pub fn encode_byte_with_next(c: u8, flags: u32, nextc: Option<u8>, out: &mut Vec<u8>) {
    if flags & VIS_HTTPSTYLE != 0 && !http_safe_passthrough(c) {
        push_http_escape(c, out);
        return;
    }
    if flags & VIS_MIMESTYLE != 0 && mime_must_escape(c, nextc) {
        push_mime_escape(c, out);
        return;
    }
    encode_standard_byte_with_next(c, flags, nextc, out);
}

fn encode_standard_byte_with_next(c: u8, flags: u32, nextc: Option<u8>, out: &mut Vec<u8>) {
    let octal_mode = flags & VIS_OCTAL != 0;
    let cstyle_mode = flags & VIS_CSTYLE != 0;

    if c == b'\\' {
        if flags & VIS_NOSLASH == 0 {
            out.push(b'\\');
        }
        out.push(b'\\');
        return;
    }
    if flag_forces_escape(c, flags) && (0x20..=0x7e).contains(&c) {
        push_octal(c, out);
        return;
    }
    if (0x21..=0x7e).contains(&c)
        || whitespace_passthrough(c, flags)
        || safe_control_passthrough(c, flags)
    {
        out.push(c);
        return;
    }
    if cstyle_mode && push_cstyle_escape(c, nextc, out) {
        return;
    }
    if c == b' ' || c & 0x7f == b' ' {
        push_octal(c, out);
        return;
    }
    if octal_mode {
        push_octal(c, out);
        return;
    }
    if c >= 0x80 {
        if flags & VIS_NOSLASH == 0 {
            out.push(b'\\');
        }
        let low = c & 0x7f;
        out.push(b'M');
        if low == 0x7f {
            out.push(b'^');
            out.push(b'?');
        } else if low < 0x20 {
            out.push(b'^');
            out.push(low ^ 0x40);
        } else if low == b'\\' && flags & VIS_NOSLASH == 0 {
            out.push(b'-');
            out.push(b'\\');
            out.push(b'\\');
        } else {
            out.push(b'-');
            out.push(low);
        }
        return;
    }
    if c == 0x7f {
        if flags & VIS_NOSLASH == 0 {
            out.push(b'\\');
        }
        out.push(b'^');
        out.push(b'?');
        return;
    }
    // Control char in the low half: \^X.
    if flags & VIS_NOSLASH == 0 {
        out.push(b'\\');
    }
    out.push(b'^');
    out.push(c ^ 0x40);
}

/// Encode `src` into a fresh `Vec<u8>`. Mirrors the byte-stream
/// behavior of NetBSD `strvis(dst, src, flags)`.
pub fn strvis_to_vec(src: &[u8], flags: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(src.len() * 4 + 1);
    for (idx, &c) in src.iter().enumerate() {
        encode_byte_with_next(c, flags, src.get(idx + 1).copied(), &mut out);
    }
    out
}

/// Encode a single byte `c` into `out`, treating any byte present in
/// `extra` as needing escape (even bytes that would otherwise pass
/// through). Mirrors NetBSD `svis(3)`.
pub fn encode_byte_with_extra(c: u8, flags: u32, extra: &[u8], out: &mut Vec<u8>) {
    encode_byte_with_extra_and_next(c, flags, None, extra, out);
}

/// Encode a byte like [`encode_byte_with_extra`], using `nextc` for
/// `VIS_CSTYLE` NUL disambiguation.
pub fn encode_byte_with_extra_and_next(
    c: u8,
    flags: u32,
    nextc: Option<u8>,
    extra: &[u8],
    out: &mut Vec<u8>,
) {
    if flags & VIS_HTTPSTYLE != 0 && !http_safe_passthrough(c) {
        push_http_escape(c, out);
        return;
    }
    if flags & VIS_MIMESTYLE != 0 && mime_must_escape(c, nextc) {
        push_mime_escape(c, out);
        return;
    }
    if extra.contains(&c) && c != b'\\' && (0x20..=0x7e).contains(&c) {
        // Extra-escaped printable bytes still have to be safe inside
        // a NUL-terminated C output string. Caret form would turn
        // bytes like '@' through '_' into embedded control bytes, so
        // use octal for this forced-escape path in every mode.
        push_octal(c, out);
        return;
    }
    encode_standard_byte_with_next(c, flags, nextc, out);
}

/// Encode `src` into a fresh `Vec<u8>` with `extra` bytes also forced
/// to escape. Mirrors NetBSD `strsvis(dst, src, flags, extra)`.
pub fn strvis_to_vec_with_extra(src: &[u8], flags: u32, extra: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(src.len() * 4 + 1);
    for (idx, &c) in src.iter().enumerate() {
        encode_byte_with_extra_and_next(c, flags, src.get(idx + 1).copied(), extra, &mut out);
    }
    out
}

/// Result of decoding one logical input element.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeStep {
    /// Emit `byte` and advance `consumed` input bytes.
    Byte { byte: u8, consumed: usize },
    /// Reached end of input cleanly.
    Eof,
    /// Malformed escape — caller should signal error.
    Invalid,
}

/// Decode the next escape sequence (or single byte) from `input`.
/// Returns the byte to emit + how many bytes of input were consumed.
pub fn decode_one(input: &[u8]) -> DecodeStep {
    let Some(&first) = input.first() else {
        return DecodeStep::Eof;
    };
    if first != b'\\' {
        return DecodeStep::Byte {
            byte: first,
            consumed: 1,
        };
    }
    // We have a backslash escape — peek ahead.
    let Some(&second) = input.get(1) else {
        // Lone trailing backslash is malformed.
        return DecodeStep::Invalid;
    };
    match second {
        b'\\' => DecodeStep::Byte {
            byte: b'\\',
            consumed: 2,
        },
        b'n' => DecodeStep::Byte {
            byte: b'\n',
            consumed: 2,
        },
        b't' => DecodeStep::Byte {
            byte: b'\t',
            consumed: 2,
        },
        b'r' => DecodeStep::Byte {
            byte: b'\r',
            consumed: 2,
        },
        b'b' => DecodeStep::Byte {
            byte: 0x08,
            consumed: 2,
        },
        b's' => DecodeStep::Byte {
            byte: b' ',
            consumed: 2,
        },
        b'v' => DecodeStep::Byte {
            byte: 0x0b,
            consumed: 2,
        },
        b'a' => DecodeStep::Byte {
            byte: 0x07,
            consumed: 2,
        },
        b'f' => DecodeStep::Byte {
            byte: 0x0c,
            consumed: 2,
        },
        d @ b'0'..=b'7' => decode_octal_escape(d, input),
        b'^' => {
            let Some(&third) = input.get(2) else {
                return DecodeStep::Invalid;
            };
            if third == b'?' {
                DecodeStep::Byte {
                    byte: 0x7f,
                    consumed: 3,
                }
            } else {
                DecodeStep::Byte {
                    byte: third ^ 0x40,
                    consumed: 3,
                }
            }
        }
        b'M' => {
            if input.get(2) == Some(&b'^') {
                let Some(&third) = input.get(3) else {
                    return DecodeStep::Invalid;
                };
                let low = if third == b'?' { 0x7f } else { third ^ 0x40 };
                return DecodeStep::Byte {
                    byte: low | 0x80,
                    consumed: 4,
                };
            }
            if input.get(2) != Some(&b'-') {
                return DecodeStep::Invalid;
            }
            // \M-X (high-bit set). Stacked `\M-` prefixes only ever set
            // the high bit, and `0x80 | 0x80 == 0x80`, so collapse every
            // leading `\M-` group iteratively before decoding the inner
            // element. Recursing once per group (as a naive `decode_one`
            // would) lets a crafted `\M-\M-\M-...X` string overflow the
            // stack — `strunvis_to_vec` decodes untrusted input.
            let mut offset = 0usize;
            while input.get(offset) == Some(&b'\\') && input.get(offset + 1) == Some(&b'M') {
                if input.get(offset + 2) == Some(&b'-') {
                    offset += 3;
                } else {
                    break;
                }
            }
            // After the loop any remaining `\M` can only be the `\M^X`
            // control-byte form handled above, so recursion stays bounded.
            let rest = input.get(offset..).unwrap_or_default();
            match decode_one(rest) {
                DecodeStep::Byte { byte, consumed } => DecodeStep::Byte {
                    byte: byte | 0x80,
                    consumed: consumed + offset,
                },
                _ => DecodeStep::Invalid,
            }
        }
        // Unknown escape — pass the byte through (matches NetBSD's
        // permissive behavior for forward-compat).
        other => DecodeStep::Byte {
            byte: other,
            consumed: 2,
        },
    }
}

/// Decode an entire vis-encoded byte string into a fresh `Vec<u8>`.
/// Returns `None` on malformed input.
pub fn strunvis_to_vec(input: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0usize;
    while i < input.len() {
        match decode_one(input.get(i..).unwrap_or_default()) {
            DecodeStep::Byte { byte, consumed } => {
                out.push(byte);
                i += consumed;
            }
            DecodeStep::Eof => break,
            DecodeStep::Invalid => return None,
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(s: &[u8]) -> Vec<u8> {
        strvis_to_vec(s, 0)
    }
    fn enc_oct(s: &[u8]) -> Vec<u8> {
        strvis_to_vec(s, VIS_OCTAL)
    }
    fn dec(s: &[u8]) -> Option<Vec<u8>> {
        strunvis_to_vec(s)
    }

    // ---- printable / backslash passthrough ----

    #[test]
    fn printable_bytes_pass_through() {
        assert_eq!(enc(b"hello"), b"hello".to_vec());
        assert_eq!(enc(b" "), b" ".to_vec());
        assert_eq!(enc(b"\t"), b"\t".to_vec());
        assert_eq!(enc(b"\n"), b"\n".to_vec());
        assert_eq!(enc(b"~"), b"~".to_vec());
    }

    #[test]
    fn backslash_doubles() {
        assert_eq!(enc(b"a\\b"), b"a\\\\b".to_vec());
    }

    // ---- default mode: control chars use \^X ----

    #[test]
    fn control_chars_use_caret_escape() {
        assert_eq!(enc(b"\x01"), b"\\^A".to_vec());
        assert_eq!(enc(b"\x1f"), b"\\^_".to_vec());
        assert_eq!(enc(b"\x00"), b"\\^@".to_vec());
    }

    #[test]
    fn delete_is_caret_question() {
        assert_eq!(enc(b"\x7f"), b"\\^?".to_vec());
    }

    #[test]
    fn high_bit_uses_meta_prefix() {
        // 0xc1 = 0x80 | 0x41 ('A') → \M-A
        assert_eq!(enc(&[0xc1]), b"\\M-A".to_vec());
        // 0xff = 0x80 | 0x7f → \M^?
        assert_eq!(enc(&[0xff]), b"\\M^?".to_vec());
        // 0x80 = 0x80 | 0 → \M^@
        assert_eq!(enc(&[0x80]), b"\\M^@".to_vec());
        // 0xa0 = 0x80 | ' ' → octal, matching BSD's low-space rule.
        assert_eq!(enc(&[0xa0]), b"\\240".to_vec());
        // 0xdc = 0x80 | '\' keeps the low-half backslash doubled so
        // it cannot merge with a following escape while decoding.
        assert_eq!(enc(&[0xdc]), b"\\M-\\\\".to_vec());
    }

    #[test]
    fn noslash_suppresses_default_escape_prefix() {
        assert_eq!(strvis_to_vec(b"\\", VIS_NOSLASH), b"\\".to_vec());
        assert_eq!(strvis_to_vec(b"\x01", VIS_NOSLASH), b"^A".to_vec());
        assert_eq!(strvis_to_vec(b"\x7f", VIS_NOSLASH), b"^?".to_vec());
        assert_eq!(strvis_to_vec(&[0xc1], VIS_NOSLASH), b"M-A".to_vec());
        assert_eq!(strvis_to_vec(&[0x80], VIS_NOSLASH), b"M^@".to_vec());
    }

    #[test]
    fn noslash_does_not_change_octal_or_cstyle_forms() {
        assert_eq!(
            strvis_to_vec(b"\x01", VIS_NOSLASH | VIS_OCTAL),
            b"\\001".to_vec()
        );
        assert_eq!(
            strvis_to_vec(b"\n", VIS_NOSLASH | VIS_CSTYLE | VIS_NL),
            b"\\n".to_vec()
        );
        assert_eq!(strvis_to_vec(b" ", VIS_NOSLASH | VIS_SP), b"\\040".to_vec());
    }

    #[test]
    fn httpstyle_uses_uri_percent_lower_hex() {
        let safe = b"AZaz09$-_.+!*'(),";
        assert_eq!(strvis_to_vec(safe, VIS_HTTPSTYLE), safe.to_vec());
        assert_eq!(
            strvis_to_vec(b" /\\\x01\x7f\xff", VIS_HTTPSTYLE),
            b"%20%2f%5c%01%7f%ff".to_vec()
        );
    }

    #[test]
    fn httpstyle_takes_precedence_over_default_cstyle_octal_and_noslash() {
        let flags = VIS_HTTPSTYLE | VIS_CSTYLE | VIS_OCTAL | VIS_NOSLASH;
        assert_eq!(strvis_to_vec(b"\n\\\xff", flags), b"%0a%5c%ff".to_vec());
    }

    #[test]
    fn mimestyle_uses_quoted_printable_upper_hex() {
        assert_eq!(
            strvis_to_vec(b"#=@[\\]^`{|}~\x01\x7f\xff", VIS_MIMESTYLE),
            b"=23=3D=40=5B=5C=5D=5E=60=7B=7C=7D=7E=01=7F=FF".to_vec()
        );
        assert_eq!(
            strvis_to_vec(b"AZaz09!?\n", VIS_MIMESTYLE),
            b"AZaz09!?\n".to_vec()
        );
    }

    #[test]
    fn mimestyle_encodes_space_and_tab_at_line_end_only() {
        assert_eq!(strvis_to_vec(b" \tX", VIS_MIMESTYLE), b" \tX".to_vec());
        assert_eq!(
            strvis_to_vec(b" \t\r\n", VIS_MIMESTYLE),
            b" =09=0D\n".to_vec()
        );
        assert_eq!(
            strvis_to_vec(b"\x01", VIS_MIMESTYLE | VIS_OCTAL | VIS_CSTYLE),
            b"=01".to_vec()
        );
    }

    #[test]
    fn representation_styles_preserve_extra_for_safe_bytes() {
        assert_eq!(
            strvis_to_vec_with_extra(b"A/", VIS_HTTPSTYLE, b"A/"),
            b"\\101%2f".to_vec()
        );
        assert_eq!(
            strvis_to_vec_with_extra(b"A\\", VIS_MIMESTYLE, b"A\\"),
            b"\\101=5C".to_vec()
        );
    }

    // ---- VIS_OCTAL mode ----

    #[test]
    fn octal_mode_renders_three_digit_octal() {
        assert_eq!(enc_oct(b"\x01"), b"\\001".to_vec());
        assert_eq!(enc_oct(b"\x7f"), b"\\177".to_vec());
        assert_eq!(enc_oct(b"\xff"), b"\\377".to_vec());
        assert_eq!(enc_oct(b"\x00"), b"\\000".to_vec());
    }

    #[test]
    fn octal_mode_keeps_printable_passthrough() {
        assert_eq!(enc_oct(b"foo"), b"foo".to_vec());
        assert_eq!(enc_oct(b" \t\n"), b" \t\n".to_vec());
    }

    #[test]
    fn octal_mode_still_doubles_backslash() {
        assert_eq!(enc_oct(b"\\"), b"\\\\".to_vec());
    }

    #[test]
    fn whitespace_flags_force_default_escapes() {
        assert_eq!(strvis_to_vec(b" ", VIS_SP), b"\\040".to_vec());
        assert_eq!(strvis_to_vec(b"\t", VIS_TAB), b"\\^I".to_vec());
        assert_eq!(strvis_to_vec(b"\n", VIS_NL), b"\\^J".to_vec());
        assert_eq!(
            strvis_to_vec(b" \t\n", VIS_WHITE),
            b"\\040\\^I\\^J".to_vec()
        );
    }

    #[test]
    fn range_flags_force_documented_printable_sets() {
        assert_eq!(strvis_to_vec(b"\"", VIS_DQ), b"\\042".to_vec());
        assert_eq!(
            strvis_to_vec(b"*?[#", VIS_GLOB),
            b"\\052\\077\\133\\043".to_vec()
        );
        assert_eq!(
            strvis_to_vec(b"'`\";&<>()|]$!^~", VIS_SHELL),
            b"\\047\\140\\042\\073\\046\\074\\076\\050\\051\\174\\135\\044\\041\\136\\176".to_vec()
        );
        assert_eq!(strvis_to_vec(b"\\", VIS_SHELL), b"\\\\".to_vec());
        assert_eq!(
            strvis_to_vec(b" \t\n*?['`", VIS_META),
            b"\\040\\^I\\^J\\052\\077\\133\\047\\140".to_vec()
        );
    }

    #[test]
    fn cstyle_mode_uses_named_escapes_for_encoded_bytes() {
        let flags = VIS_CSTYLE | VIS_WHITE;
        assert_eq!(
            strvis_to_vec(b"\0\x07\x08\x0c\n\r \t\x0b", flags),
            b"\\0\\a\\b\\f\\n\\r\\s\\t\\v".to_vec()
        );
    }

    #[test]
    fn cstyle_nul_uses_octal_before_octal_digit() {
        assert_eq!(strvis_to_vec(&[0, b'7'], VIS_CSTYLE), b"\\0007".to_vec());
    }

    #[test]
    fn cstyle_octal_fallback_handles_unnamed_controls() {
        assert_eq!(
            strvis_to_vec(b"\x01", VIS_CSTYLE | VIS_OCTAL),
            b"\\001".to_vec()
        );
        assert_eq!(strvis_to_vec(b"\x01", VIS_CSTYLE), b"\\^A".to_vec());
    }

    #[test]
    fn vis_safe_bit_does_not_enable_cstyle() {
        assert_eq!(VIS_CSTYLE, 0x02);
        assert_eq!(VIS_SAFE, 0x20);
        assert_eq!(strvis_to_vec(b"\0", VIS_SAFE), b"\\^@".to_vec());
        assert_eq!(
            strvis_to_vec(b"\x07\x08\r", VIS_SAFE),
            b"\x07\x08\r".to_vec()
        );
        assert_eq!(strvis_to_vec(b"\0", VIS_CSTYLE), b"\\0".to_vec());
    }

    #[test]
    fn extra_printable_bytes_use_c_string_safe_octal() {
        let encoded = strvis_to_vec_with_extra(b"@A_?", 0, b"@A_?");
        assert_eq!(encoded, b"\\100\\101\\137\\077".to_vec());
        assert!(
            encoded
                .iter()
                .all(|&b| b != 0 && (0x20..=0x7e).contains(&b))
        );
        assert_eq!(dec(&encoded), Some(b"@A_?".to_vec()));
    }

    // ---- decode round trips ----

    #[test]
    fn decode_passthrough_printable() {
        assert_eq!(dec(b"hello"), Some(b"hello".to_vec()));
    }

    #[test]
    fn decode_double_backslash() {
        assert_eq!(dec(b"a\\\\b"), Some(b"a\\b".to_vec()));
    }

    #[test]
    fn decode_caret_escape() {
        assert_eq!(dec(b"\\^A"), Some(b"\x01".to_vec()));
        assert_eq!(dec(b"\\^@"), Some(b"\x00".to_vec()));
    }

    #[test]
    fn decode_caret_question_is_del() {
        assert_eq!(dec(b"\\^?"), Some(b"\x7f".to_vec()));
    }

    #[test]
    fn decode_meta_prefix() {
        assert_eq!(dec(b"\\M-A"), Some(vec![0xc1]));
        assert_eq!(dec(b"\\M^?"), Some(vec![0xff]));
        assert_eq!(dec(b"\\M^@"), Some(vec![0x80]));
    }

    #[test]
    fn decode_stacked_meta_prefixes_collapse_high_bit() {
        // Stacked `\M-` prefixes only set the high bit; `0x80|0x80`
        // is still `0x80`, so the result matches a single `\M-`.
        assert_eq!(dec(b"\\M-\\M-A"), Some(vec![0xc1]));
        assert_eq!(dec(b"\\M-\\M-\\M^?"), Some(vec![0xff]));
    }

    #[test]
    fn decode_deeply_nested_meta_does_not_overflow_stack() {
        // A crafted `\M-\M-...\M-A` string must not recurse once per
        // `\M-` group — deep recursion would overflow the stack, and
        // `strunvis` decodes untrusted input. With ~200k prefixes the
        // old per-group recursion aborted the process here.
        let mut input = Vec::new();
        for _ in 0..200_000 {
            input.extend_from_slice(b"\\M-");
        }
        input.push(b'A');
        assert_eq!(strunvis_to_vec(&input), Some(vec![0xc1]));
        assert_eq!(
            decode_one(&input),
            DecodeStep::Byte {
                byte: 0xc1,
                consumed: input.len(),
            },
        );
    }

    #[test]
    fn decode_stacked_meta_with_truncated_tail_is_invalid() {
        // A stacked-meta prefix that ends before a well-formed inner
        // element is still rejected, exactly as the single case is.
        assert_eq!(dec(b"\\M-\\M"), None);
        assert_eq!(dec(b"\\M-\\M-\\"), None);
    }

    #[test]
    fn decode_octal_triple() {
        assert_eq!(dec(b"\\001"), Some(b"\x01".to_vec()));
        assert_eq!(dec(b"\\377"), Some(vec![0xff]));
        assert_eq!(dec(b"\\000"), Some(b"\x00".to_vec()));
    }

    #[test]
    fn decode_octal_overflow_is_invalid() {
        assert_eq!(dec(b"\\400"), None);
        assert_eq!(dec(b"\\777"), None);
    }

    #[test]
    fn decode_short_c_escapes() {
        assert_eq!(dec(b"\\0"), Some(b"\0".to_vec()));
        assert_eq!(dec(b"\\n"), Some(b"\n".to_vec()));
        assert_eq!(dec(b"\\t"), Some(b"\t".to_vec()));
        assert_eq!(dec(b"\\r"), Some(b"\r".to_vec()));
        assert_eq!(dec(b"\\b"), Some(b"\x08".to_vec()));
        assert_eq!(dec(b"\\s"), Some(b" ".to_vec()));
        assert_eq!(dec(b"\\v"), Some(b"\x0b".to_vec()));
        assert_eq!(dec(b"\\a"), Some(b"\x07".to_vec()));
        assert_eq!(dec(b"\\f"), Some(b"\x0c".to_vec()));
    }

    #[test]
    fn decode_short_nul_before_non_octal_repushes_tail() {
        assert_eq!(dec(b"\\0\\a"), Some(b"\0\x07".to_vec()));
        assert_eq!(dec(b"\\0z"), Some(b"\0z".to_vec()));
    }

    #[test]
    fn decode_lone_trailing_backslash_is_invalid() {
        assert_eq!(dec(b"a\\"), None);
    }

    #[test]
    fn decode_short_octal_forms_match_bsd_pushback() {
        assert_eq!(dec(b"\\1"), Some(vec![0o1]));
        assert_eq!(dec(b"\\12"), Some(vec![0o12]));
        assert_eq!(dec(b"\\12x"), Some(vec![0o12, b'x']));
        assert_eq!(dec(b"\\178"), Some(vec![0o17, b'8']));
    }

    #[test]
    fn decode_unknown_escape_passes_through() {
        // \z is not a recognized form; we let the byte through
        // (matches NetBSD's permissive behavior).
        assert_eq!(dec(b"\\z"), Some(b"z".to_vec()));
    }

    // ---- round trip ----

    #[test]
    fn round_trip_default_mode() {
        for b in 0u8..=255 {
            let enc = strvis_to_vec(&[b], 0);
            let dec = strunvis_to_vec(&enc).unwrap();
            assert_eq!(dec, vec![b], "byte {b:#x} round-trip failed: enc={enc:?}");
        }
    }

    #[test]
    fn round_trip_octal_mode() {
        for b in 0u8..=255 {
            let enc = strvis_to_vec(&[b], VIS_OCTAL);
            let dec = strunvis_to_vec(&enc).unwrap();
            assert_eq!(dec, vec![b], "byte {b:#x} OCTAL round-trip failed");
        }
    }

    #[test]
    fn round_trip_arbitrary_payload() {
        let payload: Vec<u8> = (0..256u32).map(|i| ((i * 7 + 3) & 0xff) as u8).collect();
        let enc = strvis_to_vec(&payload, 0);
        let dec = strunvis_to_vec(&enc).unwrap();
        assert_eq!(dec, payload);
    }
}

// ---------------------------------------------------------------------------
// unvis — streaming single-byte decoder
// ---------------------------------------------------------------------------

/// Outcome of one [`UnvisDecoder::feed`] call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnvisOutcome {
    /// `byte` is a fully-decoded output byte — emit it.
    Valid(u8),
    /// `byte` is a fully-decoded output byte — emit it AND re-feed
    /// the *current* input byte (which closed the previous sequence
    /// rather than belonging to it).
    ValidPush(u8),
    /// Partial sequence — keep feeding bytes.
    NoChar,
    /// Malformed input — caller should reset state.
    Bad,
    /// Terminal (after caller signals end-of-input via [`feed_end`]):
    /// no pending byte to flush.
    End,
}

/// Streaming decoder state for the BSD `unvis(3)` byte machine.
/// Construct with [`UnvisDecoder::new`], feed input bytes one at a
/// time via [`feed`], and call [`feed_end`] after the last input
/// byte to flush any pending state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub struct UnvisDecoder {
    state: UnvisState,
    /// Accumulator for octal triples.
    octal_value: u8,
    /// Carry for `\M-` / `\M^X` sequences (high bit pending).
    pending_meta: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
enum UnvisState {
    #[default]
    Initial,
    AfterBackslash,
    AfterCaret,
    AfterMeta1,       // saw "\M"; expecting "-" or "^"
    AfterMeta2,       // saw "\M-"; next byte is the encoded inner char
    ShortNulOrOctal2, // saw "\0"; may be short NUL or an octal triple
    Octal2,           // saw "\D"; expecting two more digits
    Octal3,           // saw "\DD"; expecting one more digit
}

impl UnvisDecoder {
    /// Fresh decoder with empty state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Reset to initial state (caller does this after `Bad`).
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    /// Feed one input byte. The decoder may consume the byte, emit
    /// a finished output byte, or signal that it needs more input.
    pub fn feed(&mut self, c: u8) -> UnvisOutcome {
        match self.state {
            UnvisState::Initial => {
                if c == b'\\' {
                    self.state = UnvisState::AfterBackslash;
                    UnvisOutcome::NoChar
                } else {
                    let out = if self.pending_meta { c | 0x80 } else { c };
                    self.pending_meta = false;
                    UnvisOutcome::Valid(out)
                }
            }
            UnvisState::AfterBackslash => match c {
                b'\\' => {
                    self.state = UnvisState::Initial;
                    let out = if self.pending_meta { 0x5c | 0x80 } else { 0x5c };
                    self.pending_meta = false;
                    UnvisOutcome::Valid(out)
                }
                b'n' => {
                    self.state = UnvisState::Initial;
                    let v = b'\n';
                    let out = if self.pending_meta { v | 0x80 } else { v };
                    self.pending_meta = false;
                    UnvisOutcome::Valid(out)
                }
                b't' => {
                    self.state = UnvisState::Initial;
                    let v = b'\t';
                    let out = if self.pending_meta { v | 0x80 } else { v };
                    self.pending_meta = false;
                    UnvisOutcome::Valid(out)
                }
                b'r' => {
                    self.state = UnvisState::Initial;
                    let v = b'\r';
                    let out = if self.pending_meta { v | 0x80 } else { v };
                    self.pending_meta = false;
                    UnvisOutcome::Valid(out)
                }
                b'b' => {
                    self.state = UnvisState::Initial;
                    let v = 0x08u8;
                    let out = if self.pending_meta { v | 0x80 } else { v };
                    self.pending_meta = false;
                    UnvisOutcome::Valid(out)
                }
                b's' => {
                    self.state = UnvisState::Initial;
                    let v = b' ';
                    let out = if self.pending_meta { v | 0x80 } else { v };
                    self.pending_meta = false;
                    UnvisOutcome::Valid(out)
                }
                b'v' => {
                    self.state = UnvisState::Initial;
                    let v = 0x0bu8;
                    let out = if self.pending_meta { v | 0x80 } else { v };
                    self.pending_meta = false;
                    UnvisOutcome::Valid(out)
                }
                b'a' => {
                    self.state = UnvisState::Initial;
                    let v = 0x07u8;
                    let out = if self.pending_meta { v | 0x80 } else { v };
                    self.pending_meta = false;
                    UnvisOutcome::Valid(out)
                }
                b'f' => {
                    self.state = UnvisState::Initial;
                    let v = 0x0cu8;
                    let out = if self.pending_meta { v | 0x80 } else { v };
                    self.pending_meta = false;
                    UnvisOutcome::Valid(out)
                }
                b'^' => {
                    self.state = UnvisState::AfterCaret;
                    UnvisOutcome::NoChar
                }
                b'M' => {
                    self.state = UnvisState::AfterMeta1;
                    UnvisOutcome::NoChar
                }
                b'0' => {
                    self.octal_value = 0;
                    self.state = UnvisState::ShortNulOrOctal2;
                    UnvisOutcome::NoChar
                }
                b'1'..=b'7' => {
                    self.octal_value = c - b'0';
                    self.state = UnvisState::Octal2;
                    UnvisOutcome::NoChar
                }
                _ => {
                    // Unknown escape: emit the byte verbatim.
                    self.state = UnvisState::Initial;
                    let out = if self.pending_meta { c | 0x80 } else { c };
                    self.pending_meta = false;
                    UnvisOutcome::Valid(out)
                }
            },
            UnvisState::AfterCaret => {
                self.state = UnvisState::Initial;
                let v = if c == b'?' { 0x7f } else { c ^ 0x40 };
                let out = if self.pending_meta { v | 0x80 } else { v };
                self.pending_meta = false;
                UnvisOutcome::Valid(out)
            }
            UnvisState::AfterMeta1 => {
                if c == b'-' {
                    self.state = UnvisState::AfterMeta2;
                    UnvisOutcome::NoChar
                } else if c == b'^' {
                    self.pending_meta = true;
                    self.state = UnvisState::AfterCaret;
                    UnvisOutcome::NoChar
                } else {
                    self.reset();
                    UnvisOutcome::Bad
                }
            }
            UnvisState::AfterMeta2 => {
                // Reset to Initial first; the inner char goes through
                // the normal state machine but with the high-bit carry
                // set so the eventual emit ORs in 0x80.
                self.state = UnvisState::Initial;
                self.pending_meta = true;
                self.feed(c)
            }
            UnvisState::ShortNulOrOctal2 => {
                if (b'0'..=b'7').contains(&c) {
                    self.octal_value = c - b'0';
                    self.state = UnvisState::Octal3;
                    UnvisOutcome::NoChar
                } else {
                    self.finish_octal_push()
                }
            }
            UnvisState::Octal2 => {
                if (b'0'..=b'7').contains(&c) {
                    self.octal_value = (self.octal_value << 3) | (c - b'0');
                    self.state = UnvisState::Octal3;
                    UnvisOutcome::NoChar
                } else {
                    self.finish_octal_push()
                }
            }
            UnvisState::Octal3 => {
                if (b'0'..=b'7').contains(&c) {
                    if self.octal_value & 0o40 != 0 {
                        self.reset();
                        return UnvisOutcome::Bad;
                    }
                    self.octal_value = (self.octal_value << 3) | (c - b'0');
                    self.finish_octal()
                } else {
                    self.finish_octal_push()
                }
            }
        }
    }

    fn finish_octal(&mut self) -> UnvisOutcome {
        let out = if self.pending_meta {
            self.octal_value | 0x80
        } else {
            self.octal_value
        };
        self.reset();
        UnvisOutcome::Valid(out)
    }

    fn finish_octal_push(&mut self) -> UnvisOutcome {
        let out = if self.pending_meta {
            self.octal_value | 0x80
        } else {
            self.octal_value
        };
        self.reset();
        UnvisOutcome::ValidPush(out)
    }

    /// Signal end-of-input. Returns `End` if there's no pending
    /// state, `Valid(byte)` if a one- or two-digit octal sequence is
    /// pending, or `Bad` if another partial sequence was open.
    pub fn feed_end(&mut self) -> UnvisOutcome {
        if matches!(
            self.state,
            UnvisState::ShortNulOrOctal2 | UnvisState::Octal2 | UnvisState::Octal3
        ) {
            return self.finish_octal();
        }
        let was_initial = self.state == UnvisState::Initial && !self.pending_meta;
        self.reset();
        if was_initial {
            UnvisOutcome::End
        } else {
            UnvisOutcome::Bad
        }
    }

    /// Serialize current decoder state into a single `u32` cell for
    /// FFI callers that need to thread state through an opaque
    /// `int *astate` (NetBSD `unvis(3)` ABI). The packing is:
    ///
    /// ```text
    /// bits  0..7   : state tag (0 = Initial, 1 = AfterBackslash, ...)
    /// bit   8      : pending_meta
    /// bits 16..23  : octal accumulator
    /// ```
    pub fn save_state(&self) -> u32 {
        let tag: u8 = match self.state {
            UnvisState::Initial => 0,
            UnvisState::AfterBackslash => 1,
            UnvisState::AfterCaret => 2,
            UnvisState::AfterMeta1 => 3,
            UnvisState::AfterMeta2 => 4,
            UnvisState::ShortNulOrOctal2 => 5,
            UnvisState::Octal2 => 6,
            UnvisState::Octal3 => 7,
        };
        let mut packed = tag as u32;
        if self.pending_meta {
            packed |= 1 << 8;
        }
        packed |= (self.octal_value as u32) << 16;
        packed
    }

    /// Restore a decoder previously serialized via [`save_state`].
    /// Unrecognized state tags are mapped to `Initial`; this is by
    /// design so a zero-initialized cell is a valid fresh decoder.
    pub fn from_saved_state(packed: u32) -> Self {
        let tag = (packed & 0xff) as u8;
        let state = match tag {
            1 => UnvisState::AfterBackslash,
            2 => UnvisState::AfterCaret,
            3 => UnvisState::AfterMeta1,
            4 => UnvisState::AfterMeta2,
            5 => UnvisState::ShortNulOrOctal2,
            6 => UnvisState::Octal2,
            7 => UnvisState::Octal3,
            _ => UnvisState::Initial,
        };
        let pending_meta = (packed >> 8) & 1 != 0;
        let octal_value = ((packed >> 16) & 0xff) as u8;
        Self {
            state,
            octal_value,
            pending_meta,
        }
    }
}

#[cfg(test)]
mod unvis_tests {
    use super::*;

    fn drain(input: &[u8]) -> Result<Vec<u8>, ()> {
        let mut dec = UnvisDecoder::new();
        let mut out = Vec::new();
        let mut i = 0usize;
        while i < input.len() {
            match dec.feed(input.get(i).copied().unwrap_or_default()) {
                UnvisOutcome::Valid(b) => {
                    out.push(b);
                    i += 1;
                }
                UnvisOutcome::ValidPush(b) => {
                    out.push(b);
                    // Re-feed `input[i]` next iteration.
                }
                UnvisOutcome::NoChar => {
                    i += 1;
                }
                UnvisOutcome::Bad => return Err(()),
                UnvisOutcome::End => unreachable!(),
            }
        }
        match dec.feed_end() {
            UnvisOutcome::Valid(b) => {
                out.push(b);
                Ok(out)
            }
            UnvisOutcome::End => Ok(out),
            _ => Err(()),
        }
    }

    #[test]
    fn passthrough_printable() {
        assert_eq!(drain(b"hello"), Ok(b"hello".to_vec()));
    }

    #[test]
    fn double_backslash() {
        assert_eq!(drain(b"a\\\\b"), Ok(b"a\\b".to_vec()));
    }

    #[test]
    fn caret_escape() {
        assert_eq!(drain(b"\\^A\\^B"), Ok(b"\x01\x02".to_vec()));
        assert_eq!(drain(b"\\^?"), Ok(b"\x7f".to_vec()));
    }

    #[test]
    fn octal_triple() {
        assert_eq!(drain(b"\\001"), Ok(b"\x01".to_vec()));
        assert_eq!(drain(b"\\377"), Ok(vec![0xff]));
    }

    #[test]
    fn overflowing_octal_is_bad() {
        assert_eq!(drain(b"\\400"), Err(()));
        assert_eq!(drain(b"\\777"), Err(()));
    }

    #[test]
    fn meta_prefix() {
        assert_eq!(drain(b"\\M-A"), Ok(vec![0xc1]));
        assert_eq!(drain(b"\\M^?"), Ok(vec![0xff]));
        assert_eq!(drain(b"\\M^A"), Ok(vec![0x81]));
    }

    #[test]
    fn short_c_escapes() {
        assert_eq!(
            drain(b"\\0\\n\\t\\r\\b\\s\\v\\a\\f"),
            Ok(vec![0, b'\n', b'\t', b'\r', 0x08, b' ', 0x0b, 0x07, 0x0c])
        );
    }

    #[test]
    fn short_nul_repushes_non_octal_tail() {
        assert_eq!(drain(b"\\0\\a"), Ok(b"\0\x07".to_vec()));
        assert_eq!(drain(b"\\0z"), Ok(b"\0z".to_vec()));
    }

    #[test]
    fn lone_trailing_backslash_is_bad() {
        // After feeding "\", state is AfterBackslash; feed_end → Bad.
        assert_eq!(drain(b"\\"), Err(()));
    }

    #[test]
    fn short_octal_forms_complete_at_end_or_push_back() {
        assert_eq!(drain(b"\\1"), Ok(vec![0o1]));
        assert_eq!(drain(b"\\12"), Ok(vec![0o12]));
        assert_eq!(drain(b"\\12x"), Ok(vec![0o12, b'x']));
        assert_eq!(drain(b"\\178"), Ok(vec![0o17, b'8']));
        assert_eq!(drain(b"\\M-\\1"), Ok(vec![0x80 | 0o1]));
        assert_eq!(drain(b"\\M-\\12"), Ok(vec![0x80 | 0o12]));
    }

    #[test]
    fn unknown_escape_emits_byte() {
        // \z is not recognized; emit 'z' verbatim.
        assert_eq!(drain(b"\\z"), Ok(b"z".to_vec()));
    }

    #[test]
    fn malformed_meta_without_dash_or_caret_is_bad() {
        // \M followed by something other than '-' or '^' is malformed.
        assert_eq!(drain(b"\\Mx"), Err(()));
    }

    #[test]
    fn round_trip_arbitrary_bytes() {
        for b in 0u8..=255 {
            let enc = strvis_to_vec(&[b], 0);
            let decoded = drain(&enc).unwrap();
            assert_eq!(decoded, vec![b], "round-trip failed for byte {b:#x}");
        }
    }

    #[test]
    fn save_restore_initial_state_is_zero() {
        let dec = UnvisDecoder::new();
        assert_eq!(dec.save_state(), 0);
        let restored = UnvisDecoder::from_saved_state(0);
        assert_eq!(restored, UnvisDecoder::new());
    }

    #[test]
    fn save_restore_round_trips_every_open_state() {
        // Drive the decoder into each non-Initial state by feeding
        // partial sequences, then save/restore and verify behavior
        // matches the original.
        let prefixes: &[&[u8]] = &[
            b"\\",       // AfterBackslash
            b"\\^",      // AfterCaret
            b"\\M",      // AfterMeta1
            b"\\M-",     // AfterMeta2
            b"\\0",      // ShortNulOrOctal2
            b"\\1",      // Octal2
            b"\\12",     // Octal3
            b"\\M-\\",   // pending_meta + AfterBackslash
            b"\\M-\\0",  // pending_meta + ShortNulOrOctal2
            b"\\M-\\1",  // pending_meta + Octal2
            b"\\M-\\12", // pending_meta + Octal3
        ];
        for prefix in prefixes {
            let mut original = UnvisDecoder::new();
            for &b in *prefix {
                let _ = original.feed(b);
            }
            let packed = original.save_state();
            let restored = UnvisDecoder::from_saved_state(packed);
            assert_eq!(
                original, restored,
                "save/restore mismatch after prefix {prefix:?}",
            );

            // Drive both with the same closing byte and verify the
            // outcomes line up bit-for-bit.
            let closer: u8 = match *prefix {
                b"\\" => b'n',       // → Valid('\n')
                b"\\^" => b'A',      // → Valid(0x01)
                b"\\M" => b'-',      // → NoChar (AfterMeta2)
                b"\\M-" => b'a',     // → Valid(0xe1)
                b"\\0" => b'9',      // → ValidPush(0)
                b"\\1" => b'2',      // → NoChar (Octal3)
                b"\\12" => b'3',     // → Valid(0o123)
                b"\\M-\\" => b'n',   // → Valid(0x8a)
                b"\\M-\\0" => b'9',  // → ValidPush(0x80)
                b"\\M-\\1" => b'2',  // → NoChar
                b"\\M-\\12" => b'3', // → Valid(0o123 | 0x80)
                _ => b'X',
            };
            let mut a = original;
            let mut b = restored;
            assert_eq!(a.feed(closer), b.feed(closer), "drive mismatch");
            assert_eq!(a, b, "post-feed state mismatch");
        }
    }

    #[test]
    fn save_restore_streamed_round_trip_full_alphabet() {
        // Encode every byte, then drive the decoder via the
        // save/restore cycle on every step (simulating an FFI cell).
        for b in 0u8..=255 {
            let enc = strvis_to_vec(&[b], 0);
            let mut packed: u32 = 0;
            let mut out: Vec<u8> = Vec::new();
            let mut i = 0usize;
            while i < enc.len() {
                let mut dec = UnvisDecoder::from_saved_state(packed);
                let outcome = dec.feed(enc.get(i).copied().unwrap_or_default());
                packed = dec.save_state();
                match outcome {
                    UnvisOutcome::Valid(v) => {
                        out.push(v);
                        i += 1;
                    }
                    UnvisOutcome::ValidPush(v) => {
                        out.push(v);
                        // Don't advance i — same byte re-fed.
                    }
                    UnvisOutcome::NoChar => i += 1,
                    UnvisOutcome::Bad => {
                        assert_ne!(outcome, UnvisOutcome::Bad, "bad on byte {b:#x}");
                    }
                    UnvisOutcome::End => i += 1,
                }
            }
            // Flush.
            let mut dec = UnvisDecoder::from_saved_state(packed);
            if let UnvisOutcome::Valid(v) = dec.feed_end() {
                out.push(v);
            }
            assert_eq!(out, vec![b], "streamed round-trip failed for byte {b:#x}");
        }
    }

    #[test]
    fn parse_vis_options_recognizes_implemented_flags() {
        let s = b"VIS_OCTAL,VIS_TAB,VIS_NL,VIS_CSTYLE,VIS_SP,VIS_WHITE,VIS_SAFE,VIS_NOSLASH,VIS_HTTPSTYLE,VIS_MIMESTYLE,VIS_DQ,VIS_GLOB,VIS_SHELL,VIS_META";
        let flags = parse_vis_options(s);
        assert_eq!(
            flags,
            VIS_OCTAL
                | VIS_TAB
                | VIS_NL
                | VIS_CSTYLE
                | VIS_SP
                | VIS_SAFE
                | VIS_NOSLASH
                | VIS_HTTPSTYLE
                | VIS_MIMESTYLE
                | VIS_DQ
                | VIS_GLOB
                | VIS_SHELL
        );
        assert_eq!(flags & VIS_CSTYLE, 0x02);
        assert_eq!(flags & VIS_META, VIS_META);
        assert_eq!(VIS_HTTP1808, VIS_HTTPSTYLE);
    }

    #[test]
    fn parse_vis_options_ignores_whitespace_and_empty_tokens() {
        let s = b" VIS_OCTAL ,, VIS_TAB ,";
        let flags = parse_vis_options(s);
        assert_eq!(flags, VIS_OCTAL | VIS_TAB);
    }

    #[test]
    fn parse_vis_options_silently_discards_unknown_tokens() {
        // Unknown tokens (typos, future flags) don't fail; they
        // just don't contribute bits.
        let s = b"VIS_OCTAL,VIS_FOO_BAR,VIS_TAB";
        let flags = parse_vis_options(s);
        assert_eq!(flags, VIS_OCTAL | VIS_TAB);
    }

    #[test]
    fn parse_vis_options_silently_accepts_ignored_netbsd_flags() {
        // NetBSD-specific tokens with no byte-level encoder effect
        // here must NOT contribute random bits that would break the
        // encoder.
        let s = b"VIS_NOLOCALE,VIS_OCTAL";
        let flags = parse_vis_options(s);
        assert_eq!(flags, VIS_OCTAL);
    }

    #[test]
    fn parse_vis_options_empty_returns_zero() {
        assert_eq!(parse_vis_options(b""), 0);
        assert_eq!(parse_vis_options(b"   "), 0);
        assert_eq!(parse_vis_options(b",,,"), 0);
    }
}
