//! Allocation-free server envelopes for ONC RPC v2 (RFC 5531 sections 9–10).
//!
//! All offsets returned by the decoder are checked against the input slice.
//! AUTH_SYS exposes asserted identity only; it is not cryptographic authentication.

use super::{Cursor, DecodeError, MAX_AUTH_BYTES, RemoteError};
use core::ops::Range;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Auth {
    pub flavor: u32,
    pub body: Range<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Call {
    pub xid: u32,
    pub program: u32,
    pub version: u32,
    pub procedure: u32,
    pub credential: Auth,
    pub verifier: Auth,
    pub arguments: Range<usize>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallError {
    Malformed(DecodeError),
    NotCall,
    RpcVersion { xid: u32 },
}

impl From<DecodeError> for CallError {
    fn from(error: DecodeError) -> Self {
        Self::Malformed(error)
    }
}

/// Decode a call without allocating from lengths controlled by a peer. A
/// version mismatch is distinguishable from a malformed/irrelevant datagram.
pub fn decode_call(bytes: &[u8]) -> Result<Call, CallError> {
    let mut input = Cursor { bytes, position: 0 };
    let xid = input.word()?;
    if input.word()? != 0 {
        return Err(CallError::NotCall);
    }
    if input.word()? != 2 {
        return Err(CallError::RpcVersion { xid });
    }
    let program = input.word()?;
    let version = input.word()?;
    let procedure = input.word()?;
    let (flavor, body) = input.verifier()?;
    let credential = Auth { flavor, body };
    let (flavor, body) = input.verifier()?;
    Ok(Call {
        xid,
        program,
        version,
        procedure,
        credential,
        verifier: Auth { flavor, body },
        arguments: input.position..bytes.len(),
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemCredential<'a> {
    pub stamp: u32,
    pub machine: &'a [u8],
    pub uid: u32,
    pub gid: u32,
    pub groups: [u32; 16],
    pub group_count: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SystemCredentialPolicy {
    /// GNU accepts trailing bytes and embedded NULs in the counted hostname.
    Glibc,
    /// Reject identities that cannot be represented exactly by the cooked C ABI.
    ExactIdentity,
}

/// Parse bounded AUTH_SYS fields from RFC 5531 Appendix A, including padding.
/// Both policies require every declared field to fit; GNU compatibility never
/// permits its historical inline decoder's out-of-bounds reads on short bodies.
pub fn decode_system_credential(
    bytes: &[u8],
    policy: SystemCredentialPolicy,
) -> Result<SystemCredential<'_>, DecodeError> {
    if bytes.len() > MAX_AUTH_BYTES { return Err(DecodeError::AuthenticationTooLong); }
    let mut input = Cursor { bytes, position: 0 };
    let stamp = input.word()?;
    let length = input.word()? as usize;
    if length > 255 {
        return Err(DecodeError::AuthenticationTooLong);
    }
    let start = input.position;
    let end = start + ((length + 3) & !3);
    bytes.get(start..end).ok_or(DecodeError::Truncated)?;
    let machine = &bytes[start..start + length];
    // The public cooked credential is a C string. Embedded NULs cannot be
    // represented faithfully and must not silently change the asserted host.
    if policy == SystemCredentialPolicy::ExactIdentity && machine.contains(&0) {
        return Err(DecodeError::InvalidDiscriminant);
    }
    input.position = end;
    let uid = input.word()?;
    let gid = input.word()?;
    let group_count = input.word()? as usize;
    if group_count > 16 {
        return Err(DecodeError::AuthenticationTooLong);
    }
    let mut groups = [0; 16];
    for group in &mut groups[..group_count] { *group = input.word()?; }
    if policy == SystemCredentialPolicy::ExactIdentity && input.position != bytes.len() {
        return Err(DecodeError::InvalidDiscriminant);
    }
    Ok(SystemCredential { stamp, machine, uid, gid, groups, group_count })
}

/// Emit a success/error reply envelope. The caller appends XDR results after
/// the returned offset on success. Failure never changes a short destination.
/// Rejected messages do not contain an accepted-message verifier.
pub fn encode_reply_prefix(
    output: &mut [u8],
    xid: u32,
    verifier_flavor: u32,
    verifier: &[u8],
    failure: Option<RemoteError>,
) -> Result<usize, DecodeError> {
    let denied = matches!(
        failure,
        Some(RemoteError::RpcVersion { .. } | RemoteError::Authentication(_))
    );
    if !denied && verifier.len() > MAX_AUTH_BYTES {
        return Err(DecodeError::AuthenticationTooLong);
    }
    let padded = if denied { 0 } else { (verifier.len() + 3) & !3 };
    let length = match failure {
        Some(RemoteError::RpcVersion { .. }) => 24,
        Some(RemoteError::Authentication(_)) => 20,
        Some(RemoteError::ProgramVersion { .. }) => 32 + padded,
        _ => 24 + padded,
    };
    let output = output.get_mut(..length).ok_or(DecodeError::Truncated)?;
    output.fill(0);
    let mut position = 0;
    fn put(output: &mut [u8], position: &mut usize, value: u32) {
        output[*position..*position + 4].copy_from_slice(&value.to_be_bytes());
        *position += 4;
    }
    put(output, &mut position, xid);
    put(output, &mut position, 1);
    put(output, &mut position, u32::from(denied));
    if !denied {
        put(output, &mut position, verifier_flavor);
        put(output, &mut position, verifier.len() as u32);
        output[position..position + verifier.len()].copy_from_slice(verifier);
        position += padded;
    }
    match failure {
        None => put(output, &mut position, 0),
        Some(RemoteError::RpcVersion { low, high }) => {
            put(output, &mut position, 0);
            put(output, &mut position, low);
            put(output, &mut position, high);
        }
        Some(RemoteError::Authentication(why)) => {
            put(output, &mut position, 1);
            put(output, &mut position, why);
        }
        Some(RemoteError::ProgramUnavailable) => put(output, &mut position, 1),
        Some(RemoteError::ProgramVersion { low, high }) => {
            put(output, &mut position, 2);
            put(output, &mut position, low);
            put(output, &mut position, high);
        }
        Some(RemoteError::ProcedureUnavailable) => put(output, &mut position, 3),
        Some(RemoteError::GarbageArguments) => put(output, &mut position, 4),
        Some(RemoteError::System) => put(output, &mut position, 5),
    }
    Ok(position)
}
