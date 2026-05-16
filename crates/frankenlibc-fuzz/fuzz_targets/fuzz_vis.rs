#![no_main]
//! Structure-aware fuzz target for the NetBSD vis(3) byte codec.
//!
//! The vis family accepts arbitrary byte strings, emits escape-heavy
//! byte streams, and also exposes an incremental `unvis` state
//! machine through the ABI. This target exercises the pure core
//! encoder, whole-buffer decoder, option parser, and streaming
//! decoder with state save/restore after every byte.
//!
//! Directed corpus seeds can use `vis:<scenario>` for readable
//! high-value coverage while unprefixed inputs retain the original
//! byte-split structure-aware mode.

use frankenlibc_core::stdio::vis::{
    DecodeStep, UnvisDecoder, UnvisOutcome, VIS_CSTYLE, VIS_NL, VIS_OCTAL, VIS_SP, VIS_TAB,
    decode_one, parse_vis_options, strunvis_to_vec, strvis_to_vec, strvis_to_vec_with_extra,
};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT: usize = 512;
const MAX_PAYLOAD: usize = 160;
const MAX_EXTRA: usize = 48;
const MAX_ENCODED: usize = 240;
const KNOWN_FLAGS: u32 = VIS_OCTAL | VIS_SP | VIS_TAB | VIS_NL | VIS_CSTYLE;
const DIRECTED_PREFIX: &[u8] = b"vis:";

struct VisCase<'a> {
    op: u8,
    flags: u32,
    payload: &'a [u8],
    extra: &'a [u8],
    encoded: &'a [u8],
    options: &'a [u8],
}

fuzz_target!(|data: &[u8]| {
    let case = if let Some(case) = directed_case(data) {
        case
    } else {
        if data.is_empty() || data.len() > MAX_INPUT {
            return;
        }
        VisCase::from_bytes(data)
    };
    assert_eq!(case.flags & !KNOWN_FLAGS, 0);
    assert_eq!(parse_vis_options(case.options) & !KNOWN_FLAGS, 0);

    match case.op % 5 {
        0 => fuzz_encoder_roundtrip(case.payload, case.flags),
        1 => fuzz_extra_roundtrip(case.payload, case.extra, case.flags),
        2 => fuzz_decoder_cycles(case.encoded, case.flags),
        3 => fuzz_decode_one_progress(case.encoded),
        _ => fuzz_option_tokens(case.options),
    }
});

fn directed_case(data: &[u8]) -> Option<VisCase<'static>> {
    let scenario = data.strip_prefix(DIRECTED_PREFIX)?;
    let scenario = std::str::from_utf8(scenario).ok()?;
    let scenario = scenario.trim_matches(|c: char| c.is_ascii_whitespace());
    match scenario {
        "decode-one-lone-backslash" => Some(vis_case(3, 0, b"", b"", b"\\", b"")),
        "decoder-caret" => Some(vis_case(2, 0, b"", b"", b"\\^A\\^I\\^J", b"")),
        "decoder-octal" => Some(vis_case(
            2,
            VIS_OCTAL,
            b"",
            b"",
            b"\\040\\011\\012\\0007",
            b"",
        )),
        "encoder-cstyle-control" => Some(vis_case(
            0,
            VIS_CSTYLE | VIS_SP | VIS_TAB | VIS_NL,
            b"\0\x07\x08\x0c\n\r \t\x0b",
            b"",
            b"",
            b"",
        )),
        "encoder-octal-ambiguous-nul" => Some(vis_case(0, VIS_CSTYLE, b"\0\x37", b"", b"", b"")),
        "extra-shell" => Some(vis_case(1, VIS_CSTYLE, b"a/b c?*", b"/?*", b"", b"")),
        "options-all" => Some(vis_case(
            4,
            0,
            b"",
            b"",
            b"",
            b"VIS_OCTAL,VIS_TAB,VIS_NL,VIS_CSTYLE,VIS_SP,VIS_WHITE,VIS_SAFE,VIS_HTTPSTYLE",
        )),
        _ => None,
    }
}

fn vis_case(
    op: u8,
    flags: u32,
    payload: &'static [u8],
    extra: &'static [u8],
    encoded: &'static [u8],
    options: &'static [u8],
) -> VisCase<'static> {
    VisCase {
        op,
        flags,
        payload,
        extra,
        encoded,
        options,
    }
}

impl<'a> VisCase<'a> {
    fn from_bytes(data: &'a [u8]) -> Self {
        let (op, tail) = match data.split_first() {
            Some((&op, tail)) => (op, tail),
            None => (0, &[] as &[u8]),
        };
        let flags = flags_from_byte(tail.first().copied().unwrap_or_default());
        let body = tail.get(4..).unwrap_or_default();
        let (payload, rem) = split_at_selector(body, tail.get(1).copied().unwrap_or_default());
        let (extra, rem) = split_at_selector(rem, tail.get(2).copied().unwrap_or_default());
        let (encoded, options) = split_at_selector(rem, tail.get(3).copied().unwrap_or_default());
        Self {
            op,
            flags,
            payload: cap_prefix(payload, MAX_PAYLOAD),
            extra: cap_prefix(extra, MAX_EXTRA),
            encoded: cap_prefix(encoded, MAX_ENCODED),
            options,
        }
    }
}

fn cap_prefix(input: &[u8], max_len: usize) -> &[u8] {
    let len = input.len().min(max_len);
    input.get(..len).unwrap_or(input)
}

fn split_at_selector(input: &[u8], selector: u8) -> (&[u8], &[u8]) {
    if input.is_empty() {
        return (input, input);
    }
    let split = usize::from(selector) % (input.len() + 1);
    input.split_at(split)
}

fn flags_from_byte(byte: u8) -> u32 {
    let mut flags = 0;
    if byte & 0x01 != 0 {
        flags |= VIS_OCTAL;
    }
    if byte & 0x02 != 0 {
        flags |= VIS_SP;
    }
    if byte & 0x04 != 0 {
        flags |= VIS_TAB;
    }
    if byte & 0x08 != 0 {
        flags |= VIS_NL;
    }
    if byte & 0x10 != 0 {
        flags |= VIS_CSTYLE;
    }
    flags
}

fn fuzz_encoder_roundtrip(payload: &[u8], flags: u32) {
    let encoded = strvis_to_vec(payload, flags);
    assert!(encoded.len() <= payload.len().saturating_mul(4));
    assert_eq!(
        strunvis_to_vec(&encoded),
        Some(payload.to_vec()),
        "whole-buffer vis roundtrip failed for flags=0x{flags:x}"
    );
    assert_eq!(
        streaming_unvis(&encoded),
        Some(payload.to_vec()),
        "streaming vis roundtrip failed for flags=0x{flags:x}"
    );
}

fn fuzz_extra_roundtrip(payload: &[u8], extra: &[u8], flags: u32) {
    let encoded = strvis_to_vec_with_extra(payload, flags, extra);
    assert!(encoded.len() <= payload.len().saturating_mul(4));
    assert_eq!(
        strunvis_to_vec(&encoded),
        Some(payload.to_vec()),
        "whole-buffer strsvis roundtrip failed for flags=0x{flags:x}"
    );
    assert_eq!(
        streaming_unvis(&encoded),
        Some(payload.to_vec()),
        "streaming strsvis roundtrip failed for flags=0x{flags:x}"
    );
}

fn fuzz_decoder_cycles(encoded: &[u8], flags: u32) {
    let Some(decoded) = strunvis_to_vec(encoded) else {
        return;
    };
    let reencoded = strvis_to_vec(&decoded, flags);
    assert_eq!(strunvis_to_vec(&reencoded), Some(decoded.clone()));
    assert_eq!(streaming_unvis(&reencoded), Some(decoded));
}

fn fuzz_decode_one_progress(encoded: &[u8]) {
    let mut i = 0usize;
    while i < encoded.len() {
        let rem = encoded.get(i..).unwrap_or_default();
        match decode_one(rem) {
            DecodeStep::Byte { consumed, .. } => {
                assert!(consumed > 0);
                assert!(consumed <= encoded.len() - i);
                i += consumed;
            }
            DecodeStep::Eof => {
                assert_eq!(i, encoded.len());
                break;
            }
            DecodeStep::Invalid => {
                break;
            }
        }
    }
}

fn fuzz_option_tokens(options: &[u8]) {
    let parsed = parse_vis_options(options);
    assert_eq!(parsed & !KNOWN_FLAGS, 0);

    let mut combined = options.to_vec();
    combined.extend_from_slice(b",VIS_OCTAL,VIS_TAB,VIS_NL,VIS_CSTYLE,VIS_SP");
    let combined_flags = parse_vis_options(&combined);
    assert_eq!(combined_flags & !KNOWN_FLAGS, 0);
    assert_eq!(combined_flags & VIS_OCTAL, VIS_OCTAL);
}

fn streaming_unvis(input: &[u8]) -> Option<Vec<u8>> {
    let mut dec = UnvisDecoder::new();
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0usize;
    let mut refeed_budget = input.len().saturating_mul(2).saturating_add(1);

    while i < input.len() {
        let Some(&byte) = input.get(i) else {
            break;
        };
        match dec.feed(byte) {
            UnvisOutcome::Valid(byte) => {
                out.push(byte);
                i += 1;
            }
            UnvisOutcome::ValidPush(byte) => {
                out.push(byte);
                if refeed_budget == 0 {
                    return None;
                }
                refeed_budget -= 1;
            }
            UnvisOutcome::NoChar => {
                i += 1;
            }
            UnvisOutcome::Bad | UnvisOutcome::End => return None,
        }

        let packed = dec.save_state();
        dec = UnvisDecoder::from_saved_state(packed);
    }

    match dec.feed_end() {
        UnvisOutcome::Valid(byte) => {
            out.push(byte);
            Some(out)
        }
        UnvisOutcome::End => Some(out),
        _ => None,
    }
}
