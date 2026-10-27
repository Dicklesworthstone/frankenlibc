//! Bounded ONC RPC v2 message envelopes (RFC 5531, sections 9 and 10).
//!
//! This module knows wire integers, not C structure offsets or socket state.
//! XDR callbacks remain responsible for procedure-specific argument/results.
//! AUTH_NONE is framing, not authentication or protection against spoofing.

#[path = "records.rs"]
pub mod records;

#[path = "portmap.rs"]
pub mod portmap;

#[path = "service.rs"]
pub mod service;

use core::ops::Range;

pub const CALL_PREFIX_BYTES: usize = 24;
pub const NULL_CALL_BYTES: usize = 40;
pub const MAX_AUTH_BYTES: usize = 400;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    Truncated,
    WrongTransaction,
    NotReply,
    InvalidDiscriminant,
    AuthenticationTooLong,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemoteError {
    RpcVersion { low: u32, high: u32 },
    Authentication(u32),
    ProgramUnavailable,
    ProgramVersion { low: u32, high: u32 },
    ProcedureUnavailable,
    GarbageArguments,
    System,
}

impl RemoteError {
    /// Numeric `enum clnt_stat` from the public Sun RPC client ABI.
    pub const fn status(self) -> i32 {
        match self {
            Self::RpcVersion { .. } => 6,
            Self::Authentication(_) => 7,
            Self::ProgramUnavailable => 8,
            Self::ProgramVersion { .. } => 9,
            Self::ProcedureUnavailable => 10,
            Self::GarbageArguments => 11,
            Self::System => 12,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    Success {
        verifier_flavor: u32,
        verifier: Range<usize>,
        results: Range<usize>,
    },
    Failure(RemoteError),
}

/// Encode the six fixed call words. Credentials and arguments follow these.
/// Too-small destinations are rejected before any output is written.
pub fn encode_call_prefix(
    output: &mut [u8],
    xid: u32,
    program: u32,
    version: u32,
    procedure: u32,
) -> Result<usize, DecodeError> {
    let destination = output
        .get_mut(..CALL_PREFIX_BYTES)
        .ok_or(DecodeError::Truncated)?;
    for (slot, word) in destination
        .as_chunks_mut::<4>()
        .0
        .iter_mut()
        .zip([xid, 0, 2, program, version, procedure])
    {
        *slot = word.to_be_bytes();
    }
    Ok(CALL_PREFIX_BYTES)
}

/// Encode a call with AUTH_NONE credentials/verifier and an already-XDR payload.
pub fn encode_null_call(
    output: &mut [u8],
    xid: u32,
    program: u32,
    version: u32,
    procedure: u32,
    arguments: &[u8],
) -> Result<usize, DecodeError> {
    let length = NULL_CALL_BYTES
        .checked_add(arguments.len())
        .ok_or(DecodeError::Truncated)?;
    let output = output.get_mut(..length).ok_or(DecodeError::Truncated)?;
    encode_call_prefix(output, xid, program, version, procedure)?;
    output[CALL_PREFIX_BYTES..NULL_CALL_BYTES].fill(0);
    output[NULL_CALL_BYTES..].copy_from_slice(arguments);
    Ok(length)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl Cursor<'_> {
    fn word(&mut self) -> Result<u32, DecodeError> {
        let end = self.position.checked_add(4).ok_or(DecodeError::Truncated)?;
        let b = self
            .bytes
            .get(self.position..end)
            .ok_or(DecodeError::Truncated)?;
        let value = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        self.position = end;
        Ok(value)
    }

    fn verifier(&mut self) -> Result<(u32, Range<usize>), DecodeError> {
        let flavor = self.word()?;
        let length = self.word()? as usize;
        if length > MAX_AUTH_BYTES {
            return Err(DecodeError::AuthenticationTooLong);
        }
        let begin = self.position;
        let padded = length.checked_add(3).ok_or(DecodeError::Truncated)? & !3;
        let end = begin.checked_add(padded).ok_or(DecodeError::Truncated)?;
        self.bytes.get(begin..end).ok_or(DecodeError::Truncated)?;
        self.position = end;
        Ok((flavor, begin..begin + length))
    }
}

/// Decode only the RPC reply envelope. Returned ranges are within `bytes`.
/// Unknown discriminants, truncated unions and excessive verifiers fail closed.
/// Padding bytes are ignored as by the existing XDR opaque decoder; their
/// presence, including the final partial word, is nevertheless mandatory.
pub fn decode_reply(bytes: &[u8], expected_xid: u32) -> Result<Reply, DecodeError> {
    let mut input = Cursor { bytes, position: 0 };
    if input.word()? != expected_xid {
        return Err(DecodeError::WrongTransaction);
    }
    if input.word()? != 1 {
        return Err(DecodeError::NotReply);
    }
    let failure = match input.word()? {
        0 => {
            let (verifier_flavor, verifier) = input.verifier()?;
            match input.word()? {
                0 => {
                    return Ok(Reply::Success {
                        verifier_flavor,
                        verifier,
                        results: input.position..bytes.len(),
                    });
                }
                1 => RemoteError::ProgramUnavailable,
                2 => RemoteError::ProgramVersion {
                    low: input.word()?,
                    high: input.word()?,
                },
                3 => RemoteError::ProcedureUnavailable,
                4 => RemoteError::GarbageArguments,
                5 => RemoteError::System,
                _ => return Err(DecodeError::InvalidDiscriminant),
            }
        }
        1 => match input.word()? {
            0 => RemoteError::RpcVersion {
                low: input.word()?,
                high: input.word()?,
            },
            1 => RemoteError::Authentication(input.word()?),
            _ => return Err(DecodeError::InvalidDiscriminant),
        },
        _ => return Err(DecodeError::InvalidDiscriminant),
    };
    Ok(Reply::Failure(failure))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(values: &[u32]) -> Vec<u8> {
        values
            .iter()
            .flat_map(|value| value.to_be_bytes())
            .collect()
    }

    #[test]
    fn call_header_matches_independent_network_words() {
        let mut output = [0xa5; 48];
        let length =
            encode_null_call(&mut output, 0x12345678, 100000, 2, 3, &[0, 0, 0, 17]).unwrap();
        assert_eq!(length, 44);
        assert_eq!(
            &output[..length],
            words(&[0x12345678, 0, 2, 100000, 2, 3, 0, 0, 0, 0, 17])
        );
        assert_eq!(&output[length..], &[0xa5; 4]);
    }

    #[test]
    fn short_encode_is_non_destructive() {
        let mut output = [0xa5; 39];
        assert!(encode_null_call(&mut output, 1, 2, 3, 4, &[]).is_err());
        assert_eq!(output, [0xa5; 39]);
    }

    #[test]
    fn success_exposes_only_bounded_verifier_and_result_ranges() {
        let bytes = words(&[7, 1, 0, 0, 0, 0, 0, 42]);
        assert_eq!(
            decode_reply(&bytes, 7),
            Ok(Reply::Success {
                verifier_flavor: 0,
                verifier: 20..20,
                results: 24..32,
            })
        );
        for length in 0..24 {
            assert!(
                decode_reply(&bytes[..length], 7).is_err(),
                "prefix {length}"
            );
        }
    }

    #[test]
    fn unaligned_verifier_length_consumes_its_padding() {
        let mut bytes = words(&[1, 1, 0, 2, 3]);
        bytes.extend_from_slice(&[11, 22, 33, 0]);
        bytes.extend_from_slice(&words(&[0, 42]));
        assert_eq!(
            decode_reply(&bytes, 1),
            Ok(Reply::Success {
                verifier_flavor: 2,
                verifier: 20..23,
                results: 28..32,
            })
        );
        assert_eq!(decode_reply(&bytes[..23], 1), Err(DecodeError::Truncated));
    }

    #[test]
    fn accepted_errors_and_version_payload_are_decoded() {
        let cases = [
            (1, RemoteError::ProgramUnavailable),
            (3, RemoteError::ProcedureUnavailable),
            (4, RemoteError::GarbageArguments),
            (5, RemoteError::System),
        ];
        for (status, failure) in cases {
            assert_eq!(
                decode_reply(&words(&[1, 1, 0, 0, 0, status]), 1),
                Ok(Reply::Failure(failure))
            );
        }
        assert_eq!(
            decode_reply(&words(&[1, 1, 0, 0, 0, 2, 3, 9]), 1),
            Ok(Reply::Failure(RemoteError::ProgramVersion {
                low: 3,
                high: 9
            }))
        );
        assert!(decode_reply(&words(&[1, 1, 0, 0, 0, 2, 3]), 1).is_err());
    }

    #[test]
    fn denied_reply_unions_are_not_accepted_as_success() {
        assert_eq!(
            decode_reply(&words(&[8, 1, 1, 0, 2, 2]), 8),
            Ok(Reply::Failure(RemoteError::RpcVersion { low: 2, high: 2 }))
        );
        assert_eq!(
            decode_reply(&words(&[8, 1, 1, 1, 5]), 8),
            Ok(Reply::Failure(RemoteError::Authentication(5)))
        );
        assert!(decode_reply(&words(&[8, 1, 1, 1]), 8).is_err());
    }

    #[test]
    fn unrelated_and_non_reply_packets_are_not_results() {
        assert_eq!(
            decode_reply(&words(&[2, 1, 0, 0, 0, 0]), 1),
            Err(DecodeError::WrongTransaction)
        );
        assert_eq!(
            decode_reply(&words(&[1, 0, 0, 0, 0, 0]), 1),
            Err(DecodeError::NotReply)
        );
    }

    #[test]
    fn unknown_discriminants_fail_closed() {
        for message in [
            words(&[1, 1, 2]),
            words(&[1, 1, 0, 0, 0, 6]),
            words(&[1, 1, 1, 2]),
        ] {
            assert_eq!(
                decode_reply(&message, 1),
                Err(DecodeError::InvalidDiscriminant)
            );
        }
    }

    #[test]
    fn verifier_limit_is_checked_before_length_arithmetic() {
        for length in [401, u32::MAX] {
            assert_eq!(
                decode_reply(&words(&[1, 1, 0, 0, length]), 1),
                Err(DecodeError::AuthenticationTooLong)
            );
        }
        let mut bytes = words(&[1, 1, 0, 0, 400]);
        bytes.extend_from_slice(&[0; 400]);
        bytes.extend_from_slice(&0u32.to_be_bytes());
        assert!(matches!(decode_reply(&bytes, 1), Ok(Reply::Success { .. })));
    }

    #[test]
    fn remote_status_mapping_matches_client_abi() {
        assert_eq!(RemoteError::RpcVersion { low: 2, high: 2 }.status(), 6);
        assert_eq!(RemoteError::Authentication(1).status(), 7);
        assert_eq!(RemoteError::ProgramUnavailable.status(), 8);
        assert_eq!(RemoteError::ProgramVersion { low: 1, high: 2 }.status(), 9);
        assert_eq!(RemoteError::ProcedureUnavailable.status(), 10);
        assert_eq!(RemoteError::GarbageArguments.status(), 11);
        assert_eq!(RemoteError::System.status(), 12);
    }
}
