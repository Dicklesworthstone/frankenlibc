//! Bounded AUTH_DES server proofs from RFC 1057 section 9.3 and RFC 2695.
//!
//! This module handles wire fields and DES blocks only. The ABI owns keyserver
//! lookup, session identity, replay serialization and caller-owned storage.
//! GNU's nickname is an opaque native-endian word, not an XDR integer.
//! DES exists here for legacy interoperability, not modern authentication.

use super::wire::service::SystemCredentialPolicy;
use crate::crypt::des::rpc_des_crypt;

pub const MAX_NAME: usize = 255;
pub const MAX_AUTH: usize = 400;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum AuthError {
    BadCredential = 1,
    RejectedCredential = 2,
    BadVerifier = 3,
    RejectedVerifier = 4,
    Failed = 7,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Credential<'a> {
    Fullname {
        name: &'a [u8],
        encrypted_key: [u8; 8],
        encrypted_window: [u8; 4],
    },
    Nickname(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request<'a> {
    pub credential: Credential<'a>,
    pub verifier: [u8; 12],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp {
    pub seconds: u32,
    pub micros: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameKind {
    Fullname,
    Nickname,
}

/// Decode only checked, bounded slices. GNU permits trailing bytes and ignores
/// the verifier flavor; its cryptographic proof, rather than that tag, matters.
/// ExactIdentity also rejects a counted name that cannot be represented as a
/// C string. Neither policy permits GNU's historical short-buffer reads.
pub fn decode_request<'a>(
    credential: &'a [u8],
    verifier: &[u8],
    policy: SystemCredentialPolicy,
) -> Result<Request<'a>, AuthError> {
    use AuthError::BadCredential;
    if credential.len() > MAX_AUTH || verifier.len() > MAX_AUTH {
        return Err(BadCredential);
    }
    let proof: [u8; 12] = verifier
        .get(..12)
        .ok_or(BadCredential)?
        .try_into()
        .map_err(|_| BadCredential)?;
    let kind = u32::from_be_bytes(
        credential
            .get(..4)
            .ok_or(BadCredential)?
            .try_into()
            .map_err(|_| BadCredential)?,
    );
    let (decoded, used) = match kind {
        0 => {
            let length = u32::from_be_bytes(
                credential
                    .get(4..8)
                    .ok_or(BadCredential)?
                    .try_into()
                    .map_err(|_| BadCredential)?,
            ) as usize;
            if length > MAX_NAME {
                return Err(BadCredential);
            }
            let padded = (length + 3) & !3;
            let used = 20 + padded;
            let bytes = credential.get(..used).ok_or(BadCredential)?;
            let mut name = &bytes[8..8 + length];
            if let Some(end) = name.iter().position(|&byte| byte == 0) {
                if policy == SystemCredentialPolicy::ExactIdentity {
                    return Err(BadCredential);
                }
                name = &name[..end];
            }
            let encrypted_key = bytes[8 + padded..16 + padded]
                .try_into()
                .map_err(|_| BadCredential)?;
            let encrypted_window = bytes[16 + padded..20 + padded]
                .try_into()
                .map_err(|_| BadCredential)?;
            (
                Credential::Fullname {
                    name,
                    encrypted_key,
                    encrypted_window,
                },
                used,
            )
        }
        1 => {
            let nickname = u32::from_ne_bytes(
                credential
                    .get(4..8)
                    .ok_or(BadCredential)?
                    .try_into()
                    .map_err(|_| BadCredential)?,
            );
            (Credential::Nickname(nickname), 8)
        }
        _ => return Err(BadCredential),
    };
    if policy == SystemCredentialPolicy::ExactIdentity
        && (used != credential.len() || verifier.len() != 12)
    {
        return Err(BadCredential);
    }
    Ok(Request {
        credential: decoded,
        verifier: proof,
    })
}

/// Recover the conversation timestamp/window and check the encrypted window
/// verifier. The caller must obtain the key from its trusted local key service.
pub fn decrypt_fullname(
    encrypted_window: [u8; 4],
    verifier: [u8; 12],
    key: &[u8; 8],
) -> Result<(Timestamp, u32), AuthError> {
    let mut blocks = [0u8; 16];
    blocks[..8].copy_from_slice(&verifier[..8]);
    blocks[8..12].copy_from_slice(&encrypted_window);
    blocks[12..].copy_from_slice(&verifier[8..]);
    let mut iv = [0u8; 8];
    rpc_des_crypt(key, &mut blocks, true, Some(&mut iv)).map_err(|_| AuthError::Failed)?;
    let stamp = timestamp(&blocks[..8]);
    let window = u32::from_be_bytes(blocks[8..12].try_into().unwrap());
    let check = u32::from_be_bytes(blocks[12..].try_into().unwrap());
    if check != window.wrapping_sub(1) {
        return Err(AuthError::BadCredential);
    }
    Ok((stamp, window))
}

pub fn decrypt_nickname(verifier: [u8; 12], key: &[u8; 8]) -> Result<Timestamp, AuthError> {
    let mut block: [u8; 8] = verifier[..8].try_into().unwrap();
    rpc_des_crypt(key, &mut block, true, None).map_err(|_| AuthError::Failed)?;
    Ok(timestamp(&block))
}

fn timestamp(block: &[u8]) -> Timestamp {
    Timestamp {
        seconds: u32::from_be_bytes(block[..4].try_into().unwrap()),
        micros: u32::from_be_bytes(block[4..8].try_into().unwrap()),
    }
}

/// Check a proof while the caller holds the session's replay lock. GNU permits
/// equal timestamps (retransmissions), but rejects movement backwards. A
/// fullname starts/refreshes a conversation; a nickname uses its cached window.
pub fn check_timestamp(
    stamp: Timestamp,
    previous: Option<Timestamp>,
    window: u32,
    now_seconds: i64,
    now_micros: u32,
    kind: NameKind,
) -> Result<(), AuthError> {
    let nickname = kind == NameKind::Nickname;
    if stamp.micros >= 1_000_000 {
        return Err(if nickname {
            AuthError::RejectedVerifier
        } else {
            AuthError::BadVerifier
        });
    }
    if previous.is_some_and(|previous| stamp < previous) {
        return Err(if nickname {
            AuthError::RejectedVerifier
        } else {
            AuthError::RejectedCredential
        });
    }
    // Wide arithmetic covers both the complete wire range and clock values
    // outside it, without wrapping a large window or time_t.
    let expires =
        (i128::from(stamp.seconds) + i128::from(window)) * 1_000_000 + i128::from(stamp.micros);
    let now = i128::from(now_seconds) * 1_000_000 + i128::from(now_micros);
    if expires <= now {
        return Err(if nickname {
            AuthError::RejectedVerifier
        } else {
            AuthError::BadCredential
        });
    }
    Ok(())
}

/// Encrypt the received timestamp minus one second and append the server's
/// opaque nickname. The output is owned by the caller until its RPC reply ends.
pub fn server_verifier(
    stamp: Timestamp,
    nickname: u32,
    key: &[u8; 8],
) -> Result<[u8; 12], AuthError> {
    let mut proof = [0u8; 12];
    proof[..4].copy_from_slice(&stamp.seconds.wrapping_sub(1).to_be_bytes());
    proof[4..8].copy_from_slice(&stamp.micros.to_be_bytes());
    rpc_des_crypt(key, &mut proof[..8], false, None).map_err(|_| AuthError::Failed)?;
    proof[8..].copy_from_slice(&nickname.to_ne_bytes());
    Ok(proof)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 8] = *b"12345678";
    // Independent GNU cbc_crypt/ecb_crypt observations: timestamp
    // 1700000000.123456, window 300, window verifier 299.
    const CBC: [u8; 16] = [
        0x1b, 0x91, 0xa0, 0x25, 0x12, 0x83, 0x04, 0xc2, 0xe2, 0xc9, 0xbc, 0xa1, 0x99, 0x77, 0x31,
        0x26,
    ];
    const PROOF: [u8; 8] = [0x2e, 0x2c, 0xc5, 0x8e, 0x7b, 0x58, 0xb3, 0x9e];

    fn fullname(name: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; 20 + ((name.len() + 3) & !3)];
        bytes[4..8].copy_from_slice(&(name.len() as u32).to_be_bytes());
        bytes[8..8 + name.len()].copy_from_slice(name);
        let tail = bytes.len() - 12;
        bytes[tail..tail + 8].copy_from_slice(b"SEALED!!");
        bytes[tail + 8..].copy_from_slice(&CBC[8..12]);
        bytes
    }

    fn verifier() -> [u8; 12] {
        let mut bytes = [0; 12];
        bytes[..8].copy_from_slice(&CBC[..8]);
        bytes[8..].copy_from_slice(&CBC[12..]);
        bytes
    }

    fn stamp() -> Timestamp {
        Timestamp {
            seconds: 1_700_000_000,
            micros: 123_456,
        }
    }

    #[test]
    fn fullname_and_server_proof_match_independent_gnu_des() {
        let bytes = fullname(b"unix.1001@example");
        let request = decode_request(&bytes, &verifier(), SystemCredentialPolicy::Glibc).unwrap();
        let Credential::Fullname {
            name,
            encrypted_key,
            encrypted_window,
        } = request.credential
        else {
            panic!("fullname decoded as nickname");
        };
        assert_eq!(name, b"unix.1001@example");
        assert_eq!(encrypted_key, *b"SEALED!!");
        assert_eq!(
            decrypt_fullname(encrypted_window, request.verifier, &KEY),
            Ok((stamp(), 300))
        );
        let proof = server_verifier(stamp(), 63, &KEY).unwrap();
        assert_eq!(&proof[..8], &PROOF);
        assert_eq!(&proof[8..], &63u32.to_ne_bytes());
    }

    #[test]
    fn nickname_is_opaque_and_uses_ecb_without_window_fields() {
        let mut bytes = 1u32.to_be_bytes().to_vec();
        bytes.extend_from_slice(&0x12345678u32.to_ne_bytes());
        let mut proof = verifier();
        proof[8..].fill(0xa5);
        let request = decode_request(&bytes, &proof, SystemCredentialPolicy::Glibc).unwrap();
        assert_eq!(request.credential, Credential::Nickname(0x12345678));
        assert_eq!(decrypt_nickname(proof, &KEY), Ok(stamp()));
    }

    #[test]
    fn truncated_or_oversized_wire_fields_never_decode() {
        let bytes = fullname(b"unix.1001@example");
        for end in 0..bytes.len() {
            assert_eq!(
                decode_request(&bytes[..end], &verifier(), SystemCredentialPolicy::Glibc),
                Err(AuthError::BadCredential)
            );
        }
        for end in 0..12 {
            assert_eq!(
                decode_request(&bytes, &verifier()[..end], SystemCredentialPolicy::Glibc),
                Err(AuthError::BadCredential)
            );
        }
        let mut excessive = bytes.clone();
        excessive[4..8].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(decode_request(&excessive, &verifier(), SystemCredentialPolicy::Glibc).is_err());
        assert!(decode_request(&[0; 401], &verifier(), SystemCredentialPolicy::Glibc).is_err());
        assert!(
            decode_request(
                &2u32.to_be_bytes(),
                &verifier(),
                SystemCredentialPolicy::Glibc
            )
            .is_err()
        );
    }

    #[test]
    fn exact_identity_rejects_nul_and_trailing_data() {
        let bytes = fullname(b"unix.1001@example\0different");
        let request = decode_request(&bytes, &verifier(), SystemCredentialPolicy::Glibc).unwrap();
        assert!(matches!(
            request.credential,
            Credential::Fullname {
                name: b"unix.1001@example",
                ..
            }
        ));
        assert!(
            decode_request(&bytes, &verifier(), SystemCredentialPolicy::ExactIdentity).is_err()
        );
        let mut bytes = fullname(b"unix.1001@example");
        bytes.extend_from_slice(b"tail");
        assert!(decode_request(&bytes, &verifier(), SystemCredentialPolicy::Glibc).is_ok());
        assert!(
            decode_request(&bytes, &verifier(), SystemCredentialPolicy::ExactIdentity).is_err()
        );
    }

    #[test]
    fn tampered_window_is_rejected_before_a_session_can_be_committed() {
        let mut window: [u8; 4] = CBC[8..12].try_into().unwrap();
        window[0] ^= 0x80;
        assert_eq!(
            decrypt_fullname(window, verifier(), &KEY),
            Err(AuthError::BadCredential)
        );
    }

    #[test]
    fn fullname_retransmission_replay_and_expiry_are_distinct() {
        let current = stamp();
        assert_eq!(
            check_timestamp(
                current,
                Some(current),
                300,
                1_700_000_001,
                0,
                NameKind::Fullname
            ),
            Ok(())
        );
        let newer = Timestamp {
            micros: current.micros + 1,
            ..current
        };
        assert_eq!(
            check_timestamp(
                current,
                Some(newer),
                300,
                1_700_000_001,
                0,
                NameKind::Fullname
            ),
            Err(AuthError::RejectedCredential)
        );
        assert_eq!(
            check_timestamp(
                current,
                None,
                300,
                1_700_000_300,
                123_456,
                NameKind::Fullname
            ),
            Err(AuthError::BadCredential)
        );
    }

    #[test]
    fn nickname_rejection_preserves_its_refresh_error_contract() {
        let current = stamp();
        let invalid = Timestamp {
            micros: 1_000_000,
            ..current
        };
        assert_eq!(
            check_timestamp(invalid, None, 300, 1_700_000_000, 0, NameKind::Fullname),
            Err(AuthError::BadVerifier)
        );
        assert_eq!(
            check_timestamp(invalid, None, 300, 1_700_000_000, 0, NameKind::Nickname),
            Err(AuthError::RejectedVerifier)
        );
        assert_eq!(
            check_timestamp(
                current,
                Some(Timestamp {
                    seconds: current.seconds + 1,
                    ..current
                }),
                300,
                1_700_000_000,
                0,
                NameKind::Nickname
            ),
            Err(AuthError::RejectedVerifier)
        );
        assert_eq!(
            check_timestamp(current, None, 300, 1_700_000_301, 0, NameKind::Nickname),
            Err(AuthError::RejectedVerifier)
        );
    }

    #[test]
    fn complete_wire_window_and_time_t_ranges_do_not_overflow() {
        let end = Timestamp {
            seconds: u32::MAX,
            micros: 999_999,
        };
        assert_eq!(
            check_timestamp(end, None, u32::MAX, i64::MAX, 0, NameKind::Fullname),
            Err(AuthError::BadCredential)
        );
        assert_eq!(
            check_timestamp(end, None, u32::MAX, i64::MIN, 0, NameKind::Fullname),
            Ok(())
        );
        assert_eq!(
            check_timestamp(
                end,
                None,
                u32::MAX,
                i64::from(u32::MAX),
                0,
                NameKind::Fullname
            ),
            Ok(())
        );
    }
}
