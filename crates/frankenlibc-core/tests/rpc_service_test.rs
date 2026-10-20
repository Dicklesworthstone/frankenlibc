//! Independent network-word checks; no production encoder constructs inputs.
use frankenlibc_core::rpc::wire::service::*;
use frankenlibc_core::rpc::wire::{DecodeError, RemoteError};

fn words(values: &[u32]) -> Vec<u8> {
    values.iter().flat_map(|x| x.to_be_bytes()).collect()
}

#[test]
fn null_call_has_exact_arguments_and_identity() {
    let data = words(&[77, 0, 2, 123, 7, 9, 0, 0, 0, 0, 42]);
    let c = decode_call(&data).unwrap();
    assert_eq!((c.xid, c.program, c.version, c.procedure), (77, 123, 7, 9));
    assert_eq!(
        c.credential,
        Auth {
            flavor: 0,
            body: 32..32
        }
    );
    assert_eq!(
        c.verifier,
        Auth {
            flavor: 0,
            body: 40..40
        }
    );
    assert_eq!(c.arguments, 40..44);
}

#[test]
fn every_truncated_null_call_is_rejected() {
    let data = words(&[77, 0, 2, 123, 7, 9, 0, 0, 0, 0]);
    for n in 0..40 {
        assert!(decode_call(&data[..n]).is_err(), "prefix {n}");
    }
}

#[test]
fn version_mismatch_keeps_xid_but_never_dispatches() {
    assert_eq!(
        decode_call(&words(&[77, 0, 9])),
        Err(CallError::RpcVersion { xid: 77 })
    );
    assert_eq!(decode_call(&words(&[77, 1, 2])), Err(CallError::NotCall));
}

#[test]
fn opaque_auth_padding_and_both_limits_are_checked() {
    let data = words(&[1, 0, 2, 2, 3, 4, 9, 3, 0x01020300, 8, 1, 0x04000000, 42]);
    let c = decode_call(&data).unwrap();
    assert_eq!(c.credential.body, 32..35);
    assert_eq!(c.verifier.body, 44..45);
    assert_eq!(c.arguments, 48..52);
    for data in [
        words(&[1, 0, 2, 2, 3, 4, 0, 401]),
        words(&[1, 0, 2, 2, 3, 4, 0, 0, 0, u32::MAX]),
    ] {
        assert_eq!(
            decode_call(&data),
            Err(CallError::Malformed(DecodeError::AuthenticationTooLong))
        );
    }
}

#[test]
fn auth_sys_decodes_all_groups_and_unaligned_machine() {
    let mut data = words(&[1234, 3, 0x61626300, 501, 20, 16]);
    data.extend(words(&(0..16).collect::<Vec<_>>()));
    let c = decode_system_credential(&data).unwrap();
    assert_eq!(
        (c.stamp, c.machine, c.uid, c.gid),
        (1234, b"abc".as_slice(), 501, 20)
    );
    assert_eq!(c.group_count, 16);
    assert_eq!(c.groups, std::array::from_fn(|i| i as u32));
}

#[test]
fn every_truncated_auth_sys_is_rejected() {
    let data = words(&[1, 3, 0x61626300, 2, 3, 2, 4, 5]);
    for n in 0..data.len() {
        assert!(decode_system_credential(&data[..n]).is_err(), "prefix {n}");
    }
    assert!(decode_system_credential(&data).is_ok());
}

#[test]
fn malformed_auth_sys_cannot_masquerade_as_a_shorter_identity() {
    for data in [
        words(&[1, 256]),
        words(&[1, 0, 2, 3, 17]),
        words(&[1, 3, 0x61006200, 2, 3, 0]),
        words(&[1, 0, 2, 3, 0, 99]),
    ] {
        assert!(decode_system_credential(&data).is_err());
    }
}

#[test]
fn null_success_reply_matches_network_words() {
    let mut out = [0xa5; 28];
    assert_eq!(encode_reply_prefix(&mut out, 9, 0, &[], None), Ok(24));
    assert_eq!(&out[..24], words(&[9, 1, 0, 0, 0, 0]));
    assert_eq!(&out[24..], &[0xa5; 4]);
}

#[test]
fn all_accepted_errors_have_the_correct_union() {
    for (error, status) in [
        (RemoteError::ProgramUnavailable, 1),
        (RemoteError::ProcedureUnavailable, 3),
        (RemoteError::GarbageArguments, 4),
        (RemoteError::System, 5),
    ] {
        let mut out = [0; 24];
        assert_eq!(
            encode_reply_prefix(&mut out, 7, 0, &[], Some(error)),
            Ok(24)
        );
        assert_eq!(out.as_slice(), words(&[7, 1, 0, 0, 0, status]));
    }
    let mut out = [0; 32];
    encode_reply_prefix(
        &mut out,
        7,
        0,
        &[],
        Some(RemoteError::ProgramVersion { low: 3, high: 9 }),
    )
    .unwrap();
    assert_eq!(out.as_slice(), words(&[7, 1, 0, 0, 0, 2, 3, 9]));
}

#[test]
fn denied_replies_omit_the_accepted_verifier() {
    for (error, expected) in [
        (
            RemoteError::RpcVersion { low: 2, high: 2 },
            words(&[7, 1, 1, 0, 2, 2]),
        ),
        (RemoteError::Authentication(1), words(&[7, 1, 1, 1, 1])),
    ] {
        let mut out = [0xa5; 32];
        let n = encode_reply_prefix(&mut out, 7, 9, &[5; 400], Some(error)).unwrap();
        assert_eq!(&out[..n], expected);
        assert!(out[n..].iter().all(|&b| b == 0xa5));
    }
}

#[test]
fn verifier_padding_is_zeroed_without_overwriting_the_result_region() {
    let mut out = [0xa5; 32];
    assert_eq!(
        encode_reply_prefix(&mut out, 7, 2, &[1, 2, 3], None),
        Ok(28)
    );
    assert_eq!(&out[..28], words(&[7, 1, 0, 2, 3, 0x01020300, 0]));
    assert_eq!(&out[28..], &[0xa5; 4]);
}

#[test]
fn all_short_reply_outputs_are_non_destructive() {
    for failure in [
        None,
        Some(RemoteError::System),
        Some(RemoteError::Authentication(5)),
        Some(RemoteError::RpcVersion { low: 2, high: 2 }),
        Some(RemoteError::ProgramVersion { low: 1, high: 3 }),
    ] {
        let mut full = [0; 64];
        let length = encode_reply_prefix(&mut full, 1, 0, &[], failure).unwrap();
        for n in 0..length {
            let mut out = vec![0xa5; n];
            assert_eq!(
                encode_reply_prefix(&mut out, 1, 0, &[], failure),
                Err(DecodeError::Truncated)
            );
            assert!(out.iter().all(|&b| b == 0xa5));
        }
    }
}
