//! NetBSD `vis(3)` family — visual byte encoding/decoding.
//!
//! Pure-safe Rust port of the byte-level transformation. The C ABI
//! shim in `frankenlibc-abi::stdio_abi` handles raw-pointer NUL and
//! bounds.
//!
//! ## Encoding (default mode, no flags)
//!
//! - Printable ASCII (0x20..=0x7e) except `\\` → emitted as-is.
//! - `\\` → `\\\\`.
//! - Non-printable c < 0x80 → `\\^X` where X = c XOR 0x40.
//! - 0x7f (DEL) → `\\^?`.
//! - High-bit bytes (c >= 0x80) → `\\M-X` followed by the encoded
//!   form of c & 0x7f (recursive — but bounded since the next call
//!   sees a 7-bit byte).
//!
//! ## Encoding ([`VIS_OCTAL`])
//!
//! All non-printable bytes (anything outside 0x20..=0x7e plus the
//! mandatory `\\`-escape) are rendered as `\\NNN` (3-digit octal).
//!
//! ## Decoding
//!
//! Recognizes the inverse forms above plus the C-style short
//! escapes `\\n \\t \\r \\b \\v \\a \\f \\0`. Anything else after a
//! `\\` is passed through verbatim.
//!
//! Other libutil flags (`VIS_TAB`, `VIS_NL`, `VIS_HTTPSTYLE`,
//! `VIS_SAFE`, etc.) are accepted but currently ignored — the v1
//! port focuses on the byte-stream-safe defaults.

/// Render all non-printable bytes as `\NNN` octal triples instead
/// of the default `\^X` / `\M-X` notation.
pub const VIS_OCTAL: u32 = 0x01;
/// Encode space as a literal byte even though it qualifies as
/// "graph". (Default mode emits space as-is, so this is a no-op
/// for our v1.)
pub const VIS_SP: u32 = 0x04;
/// Encode tab as `\t` rather than `\^I`. Accepted but ignored in
/// v1; non-default tab handling differs only in cosmetics.
pub const VIS_TAB: u32 = 0x08;
/// Encode newline as `\n` rather than `\^J`. Accepted but ignored
/// in v1 (same rationale as `VIS_TAB`).
pub const VIS_NL: u32 = 0x10;
/// Encode `?` as `\?` to avoid trigraph collision. Accepted but
/// ignored in v1.
pub const VIS_CSTYLE: u32 = 0x20;

/// Encode a single byte `c` into `out`, appending the result.
/// `flags` is the OR of `VIS_*` constants.
pub fn encode_byte(c: u8, flags: u32, out: &mut Vec<u8>) {
    let octal_mode = flags & VIS_OCTAL != 0;

    if c == b'\\' {
        out.push(b'\\');
        out.push(b'\\');
        return;
    }
    if (0x20..=0x7e).contains(&c) {
        out.push(c);
        return;
    }
    if octal_mode {
        out.push(b'\\');
        out.push(b'0' + ((c >> 6) & 0x07));
        out.push(b'0' + ((c >> 3) & 0x07));
        out.push(b'0' + (c & 0x07));
        return;
    }
    if c >= 0x80 {
        // High bit set: emit \M- prefix then recursively encode the
        // low 7 bits. Recursion is bounded — the recursive call sees
        // a 7-bit byte and never re-enters this branch.
        out.push(b'\\');
        out.push(b'M');
        out.push(b'-');
        encode_byte(c & 0x7f, flags, out);
        return;
    }
    if c == 0x7f {
        out.push(b'\\');
        out.push(b'^');
        out.push(b'?');
        return;
    }
    // Control char in the low half: \^X.
    out.push(b'\\');
    out.push(b'^');
    out.push(c ^ 0x40);
}

/// Encode `src` into a fresh `Vec<u8>`. Mirrors the byte-stream
/// behavior of NetBSD `strvis(dst, src, flags)`.
pub fn strvis_to_vec(src: &[u8], flags: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(src.len() * 4 + 1);
    for &c in src {
        encode_byte(c, flags, &mut out);
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
        b'0'..=b'7' => {
            // Octal triple `\NNN`. Need two more octal digits.
            let d1 = second - b'0';
            let Some(&d2) = input.get(2) else {
                return DecodeStep::Invalid;
            };
            let Some(&d3) = input.get(3) else {
                return DecodeStep::Invalid;
            };
            if !d2.is_ascii_digit() || d2 > b'7' || !d3.is_ascii_digit() || d3 > b'7' {
                return DecodeStep::Invalid;
            }
            let v = (d1 << 6) | ((d2 - b'0') << 3) | (d3 - b'0');
            DecodeStep::Byte {
                byte: v,
                consumed: 4,
            }
        }
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
            // \M-X (high-bit set) — recursively decode X with high bit set.
            if input.get(2) != Some(&b'-') {
                return DecodeStep::Invalid;
            }
            let rest = &input[3..];
            match decode_one(rest) {
                DecodeStep::Byte { byte, consumed } => DecodeStep::Byte {
                    byte: byte | 0x80,
                    consumed: consumed + 3,
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
        match decode_one(&input[i..]) {
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
        // 0xff = 0x80 | 0x7f → \M-\^?
        assert_eq!(enc(&[0xff]), b"\\M-\\^?".to_vec());
        // 0x80 = 0x80 | 0 → \M-\^@
        assert_eq!(enc(&[0x80]), b"\\M-\\^@".to_vec());
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
    }

    #[test]
    fn octal_mode_still_doubles_backslash() {
        assert_eq!(enc_oct(b"\\"), b"\\\\".to_vec());
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
        assert_eq!(dec(b"\\M-\\^?"), Some(vec![0xff]));
    }

    #[test]
    fn decode_octal_triple() {
        assert_eq!(dec(b"\\001"), Some(b"\x01".to_vec()));
        assert_eq!(dec(b"\\377"), Some(vec![0xff]));
        assert_eq!(dec(b"\\000"), Some(b"\x00".to_vec()));
    }

    #[test]
    fn decode_short_c_escapes() {
        assert_eq!(dec(b"\\n"), Some(b"\n".to_vec()));
        assert_eq!(dec(b"\\t"), Some(b"\t".to_vec()));
        assert_eq!(dec(b"\\r"), Some(b"\r".to_vec()));
        assert_eq!(dec(b"\\b"), Some(b"\x08".to_vec()));
        assert_eq!(dec(b"\\v"), Some(b"\x0b".to_vec()));
        assert_eq!(dec(b"\\a"), Some(b"\x07".to_vec()));
        assert_eq!(dec(b"\\f"), Some(b"\x0c".to_vec()));
    }

    #[test]
    fn decode_lone_trailing_backslash_is_invalid() {
        assert_eq!(dec(b"a\\"), None);
    }

    #[test]
    fn decode_short_octal_is_invalid() {
        assert_eq!(dec(b"\\1"), None);
        assert_eq!(dec(b"\\12"), None);
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
    /// Carry for `\M-` sequences (high bit pending).
    pending_meta: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
enum UnvisState {
    #[default]
    Initial,
    AfterBackslash,
    AfterCaret,
    AfterMeta1, // saw "\M"; expecting "-"
    AfterMeta2, // saw "\M-"; next byte is the encoded inner char
    Octal2,     // saw "\D"; expecting two more digits
    Octal3,     // saw "\DD"; expecting one more digit
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
                b'0'..=b'7' => {
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
            UnvisState::Octal2 => {
                if (b'0'..=b'7').contains(&c) {
                    self.octal_value = (self.octal_value << 3) | (c - b'0');
                    self.state = UnvisState::Octal3;
                    UnvisOutcome::NoChar
                } else {
                    self.reset();
                    UnvisOutcome::Bad
                }
            }
            UnvisState::Octal3 => {
                if (b'0'..=b'7').contains(&c) {
                    let v = (self.octal_value << 3) | (c - b'0');
                    self.octal_value = 0;
                    self.state = UnvisState::Initial;
                    let out = if self.pending_meta { v | 0x80 } else { v };
                    self.pending_meta = false;
                    UnvisOutcome::Valid(out)
                } else {
                    self.reset();
                    UnvisOutcome::Bad
                }
            }
        }
    }

    /// Signal end-of-input. Returns `End` if there's no pending
    /// state, or `Bad` if a partial sequence was open.
    pub fn feed_end(&mut self) -> UnvisOutcome {
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
            UnvisState::Octal2 => 5,
            UnvisState::Octal3 => 6,
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
            5 => UnvisState::Octal2,
            6 => UnvisState::Octal3,
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
            match dec.feed(input[i]) {
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
    fn meta_prefix() {
        assert_eq!(drain(b"\\M-A"), Ok(vec![0xc1]));
        assert_eq!(drain(b"\\M-\\^?"), Ok(vec![0xff]));
        assert_eq!(drain(b"\\M-\\^A"), Ok(vec![0x81]));
    }

    #[test]
    fn short_c_escapes() {
        assert_eq!(
            drain(b"\\n\\t\\r\\b\\v\\a\\f"),
            Ok(vec![b'\n', b'\t', b'\r', 0x08, 0x0b, 0x07, 0x0c])
        );
    }

    #[test]
    fn lone_trailing_backslash_is_bad() {
        // After feeding "\", state is AfterBackslash; feed_end → Bad.
        assert_eq!(drain(b"\\"), Err(()));
    }

    #[test]
    fn malformed_octal_short_is_bad() {
        // Octal must be 3 digits; "\\1x" feeds 1, then 'x' as second
        // digit which isn't octal → Bad.
        assert_eq!(drain(b"\\1x"), Err(()));
    }

    #[test]
    fn unknown_escape_emits_byte() {
        // \z is not recognized; emit 'z' verbatim.
        assert_eq!(drain(b"\\z"), Ok(b"z".to_vec()));
    }

    #[test]
    fn malformed_meta_without_dash_is_bad() {
        // \M followed by something other than '-' is malformed.
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
            b"\\1",      // Octal2
            b"\\12",     // Octal3
            b"\\M-\\",   // pending_meta + AfterBackslash
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
                b"\\1" => b'2',      // → NoChar (Octal3)
                b"\\12" => b'3',     // → Valid(0o123)
                b"\\M-\\" => b'n',   // → Valid(0x8a)
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
                let outcome = dec.feed(enc[i]);
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
                    UnvisOutcome::Bad => panic!("bad on byte {b:#x}"),
                    UnvisOutcome::End => i += 1,
                }
            }
            // Flush.
            let mut dec = UnvisDecoder::from_saved_state(packed);
            let _ = dec.feed_end();
            assert_eq!(out, vec![b], "streamed round-trip failed for byte {b:#x}");
        }
    }
}
