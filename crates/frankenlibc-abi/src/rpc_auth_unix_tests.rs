use super::*;
use std::ffi::CString;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

struct Handle(*mut Auth);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe { destroy(self.0) };
    }
}
fn handle(name: &[u8], uid: i32, gid: i32, groups: &mut [i32]) -> Handle {
    let name = CString::new(name).unwrap();
    let pointer = unsafe {
        crate::rpc_abi::authunix_create(
            name.as_ptr().cast_mut(),
            uid,
            gid,
            groups.len() as i32,
            groups.as_mut_ptr(),
        )
    };
    assert!(!pointer.is_null(), "authunix_create failed");
    Handle(pointer.cast())
}
fn credential(auth: &Handle) -> Vec<u8> {
    unsafe {
        std::slice::from_raw_parts(
            (*auth.0).credential.oa_base.cast(),
            (*auth.0).credential.oa_length as usize,
        )
        .to_vec()
    }
}
fn word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn nickname(auth: &Handle, bytes: &mut [u8]) -> i32 {
    let mut verifier = OpaqueAuth {
        oa_flavor: 2,
        oa_base: bytes.as_mut_ptr().cast(),
        oa_length: bytes.len() as u32,
    };
    unsafe { validate(auth.0, &mut verifier) }
}
fn marshalled(auth: &Handle) -> Vec<u8> {
    let mut bytes = [0u8; 512];
    let mut xdr: Xdr = unsafe { std::mem::zeroed() };
    unsafe {
        crate::rpc_abi::xdrmem_create(
            (&mut xdr as *mut Xdr).cast(),
            bytes.as_mut_ptr().cast(),
            bytes.len() as u32,
            0,
        )
    };
    assert_eq!(unsafe { marshal(auth.0, &mut xdr) }, 1);
    let size = unsafe { ((*xdr.x_ops).x_getpostn)(&xdr) } as usize;
    bytes[..size].to_vec()
}

#[test]
fn auth_sys_encoder_covers_every_name_and_group_extent_without_tail_writes() {
    for name_length in 0..=MAX_NAME {
        let name = vec![0xfe; name_length];
        for count in 0..=MAX_GROUPS {
            let groups: Vec<_> = (0..count).map(|i| u32::MAX - i as u32).collect();
            let mut bytes = [0xa5; MAX_CREDENTIAL + 8];
            let length = encode(&mut bytes, 0x01020304, &name, u32::MAX, 42, &groups).unwrap();
            let padded = (name_length + 3) & !3;
            assert_eq!(length, 20 + padded + 4 * count);
            assert_eq!(word(&bytes, 0), 0x01020304);
            assert_eq!(word(&bytes, 4), name_length as u32);
            assert_eq!(&bytes[8..8 + name_length], name.as_slice());
            assert!(
                bytes[8 + name_length..8 + padded]
                    .iter()
                    .all(|&byte| byte == 0)
            );
            assert_eq!(word(&bytes, 8 + padded), u32::MAX);
            assert_eq!(word(&bytes, 12 + padded), 42);
            assert_eq!(word(&bytes, 16 + padded), count as u32);
            for (i, expected) in groups.iter().enumerate() {
                assert_eq!(word(&bytes, 20 + padded + i * 4), *expected);
            }
            assert!(bytes[length..].iter().all(|&byte| byte == 0xa5));
        }
    }
}

#[test]
fn auth_sys_encoding_rejection_does_not_mutate_output() {
    let mut bytes = [0xa5; MAX_CREDENTIAL];
    assert_eq!(encode(&mut bytes, 0, &[1; 256], 0, 0, &[]), None);
    assert_eq!(encode(&mut bytes, 0, b"a", 0, 0, &[0; 17]), None);
    assert_eq!(encode(&mut bytes[..19], 0, b"", 0, 0, &[]), None);
    assert_eq!(bytes, [0xa5; MAX_CREDENTIAL]);
}

#[test]
fn auth_sys_public_constructor_owns_input_and_marshals_both_auth_fields() {
    let mut groups = [0, 42, -1];
    let auth = handle(b"node", 1001, 1002, &mut groups);
    groups.fill(999);
    let body = credential(&auth);
    assert_eq!(body.len(), 36);
    assert_eq!(
        &body[4..],
        &[
            0, 0, 0, 4, b'n', b'o', b'd', b'e', 0, 0, 3, 233, 0, 0, 3, 234, 0, 0, 0, 3, 0, 0, 0, 0,
            0, 0, 0, 42, 255, 255, 255, 255,
        ]
    );
    let wire = marshalled(&auth);
    assert_eq!(word(&wire, 0), 1);
    assert_eq!(word(&wire, 4), body.len() as u32);
    assert_eq!(&wire[8..8 + body.len()], body.as_slice());
    assert_eq!(&wire[8 + body.len()..], &[0; 8]);
    assert_eq!(unsafe { refresh(auth.0) }, 0);
}

#[test]
fn auth_sys_nickname_negotiation_malformed_fallback_and_refresh_are_owned() {
    let auth = handle(b"node", 1001, 1002, &mut [42]);
    let original = credential(&auth);
    let mut verifier = [0, 0, 0, 2, 0, 0, 0, 3, b'a', b'b', b'c', 0];
    assert_eq!(nickname(&auth, &mut verifier), 1);
    verifier.fill(0xff);
    assert_eq!(credential(&auth), b"abc");
    assert_eq!(unsafe { (*auth.0).credential.oa_flavor }, 2);
    assert_eq!(
        marshalled(&auth),
        [
            0, 0, 0, 2, 0, 0, 0, 3, b'a', b'b', b'c', 0, 0, 0, 0, 0, 0, 0, 0, 0
        ]
    );
    assert_eq!(unsafe { refresh(auth.0) }, 1);
    assert_eq!(unsafe { (*auth.0).credential.oa_flavor }, 1);
    assert_eq!(&credential(&auth)[4..], &original[4..]);
    assert_eq!(unsafe { refresh(auth.0) }, 0);
    let verifier = [0, 0, 0, 2, 0, 0, 0, 3, b'a', b'b', b'c', 0];
    for length in 0..verifier.len() {
        assert_eq!(nickname(&auth, &mut verifier.clone()), 1);
        assert_eq!(nickname(&auth, &mut verifier[..length].to_vec()), 1);
        assert_eq!(unsafe { (*auth.0).credential.oa_flavor }, 1);
        assert_eq!(&credential(&auth)[4..], &original[4..]);
    }
    let mut too_large = [0, 0, 0, 2, 0, 0, 1, 145]; // 401 bytes, no allocation allowed.
    assert_eq!(nickname(&auth, &mut too_large), 1);
    assert_eq!(unsafe { (*auth.0).credential.oa_flavor }, 1);
}

#[test]
fn auth_sys_nickname_allows_empty_and_maximal_opaque_credentials() {
    let auth = handle(b"", -1, -1, &mut []);
    let mut empty = [0, 0, 0, 2, 0, 0, 0, 0];
    assert_eq!(nickname(&auth, &mut empty), 1);
    assert!(credential(&auth).is_empty());
    assert_eq!(unsafe { refresh(auth.0) }, 1);
    let mut maximal = vec![0; 408];
    maximal[3] = 2;
    maximal[4..8].copy_from_slice(&400u32.to_be_bytes());
    maximal[8..].fill(0xe7);
    assert_eq!(nickname(&auth, &mut maximal), 1);
    assert_eq!(credential(&auth), vec![0xe7; 400]);
    assert_eq!(marshalled(&auth).len(), 416);
}

#[test]
fn auth_sys_non_short_verifiers_do_not_replace_credentials() {
    let auth = handle(b"node", 1, 2, &mut []);
    let original = credential(&auth);
    for flavor in [0, 1, 3, 99, -1] {
        let mut verifier = OpaqueAuth {
            oa_flavor: flavor,
            oa_base: ptr::null_mut(),
            oa_length: 0,
        };
        assert_eq!(unsafe { validate(auth.0, &mut verifier) }, 1);
        assert_eq!(credential(&auth), original);
    }
}

#[test]
fn auth_sys_constructor_rejects_bad_extents_and_accepts_full_unsigned_ids() {
    unsafe {
        for count in [-1, 17, i32::MAX] {
            assert!(create(c"node".as_ptr().cast_mut(), 0, 0, count, ptr::null_mut()).is_null());
        }
        assert!(create(ptr::null_mut(), 0, 0, 0, ptr::null_mut()).is_null());
        assert!(create(c"node".as_ptr().cast_mut(), 0, 0, 1, ptr::null_mut()).is_null());
        let too_long = CString::new(vec![b'x'; 256]).unwrap();
        assert!(create(too_long.as_ptr().cast_mut(), 0, 0, 0, ptr::null_mut()).is_null());
    }
    let auth = handle(&[b'x'; 255], -1, i32::MIN, &mut [0; 16]);
    let body = credential(&auth);
    assert_eq!(body.len(), MAX_CREDENTIAL);
    assert_eq!(word(&body, 264), u32::MAX);
    assert_eq!(word(&body, 268), 0x8000_0000);
}

#[test]
fn auth_sys_default_constructor_uses_process_identity_and_groups() {
    let pointer = unsafe { crate::rpc_abi::authunix_create_default() };
    assert!(!pointer.is_null());
    let auth = Handle(pointer.cast());
    let body = credential(&auth);
    let name_length = word(&body, 4) as usize;
    let mut host = [0i8; 256];
    assert_eq!(
        unsafe { libc::gethostname(host.as_mut_ptr().cast(), host.len()) },
        0
    );
    let host = unsafe { std::ffi::CStr::from_ptr(host.as_ptr().cast()) }.to_bytes();
    assert_eq!(&body[8..8 + name_length], host);
    let offset = 8 + ((name_length + 3) & !3);
    assert_eq!(word(&body, offset), unsafe { libc::geteuid() });
    assert_eq!(word(&body, offset + 4), unsafe { libc::getegid() });
    let count = unsafe { libc::getgroups(0, ptr::null_mut()) };
    assert!(count >= 0);
    let mut groups = vec![0; count as usize];
    if count != 0 {
        assert_eq!(
            unsafe { libc::getgroups(count, groups.as_mut_ptr()) },
            count
        );
    }
    assert_eq!(word(&body, offset + 8) as usize, groups.len().min(16));
    for (index, expected) in groups.iter().take(16).enumerate() {
        assert_eq!(word(&body, offset + 12 + index * 4), *expected);
    }
}

#[test]
fn auth_sys_marshalling_rejects_decode_and_contains_reentrant_destroy() {
    let auth = handle(b"node", 1, 2, &mut []);
    let mut xdr: Xdr = unsafe { std::mem::zeroed() };
    xdr.x_op = 1;
    assert_eq!(unsafe { marshal(auth.0, &mut xdr) }, 0);
    // The first XDR write callback attempts destruction and nested marshaling.
    // Neither may mutate/free the outer operation's still-borrowed credential.
    let mut bytes = [0u8; 512];
    unsafe {
        crate::rpc_abi::xdrmem_create(
            (&mut xdr as *mut Xdr).cast(),
            bytes.as_mut_ptr().cast(),
            bytes.len() as u32,
            0,
        )
    };
    let original_ops = unsafe { &*xdr.x_ops };
    let original_put = original_ops.x_putint32;
    struct Context {
        auth: *mut Auth,
        put: unsafe extern "C" fn(*mut Xdr, *const i32) -> i32,
        calls: AtomicUsize,
    }
    unsafe extern "C" fn write(xdr: *mut Xdr, value: *const i32) -> i32 {
        let context = unsafe { &*(*xdr).x_public.cast::<Context>() };
        if context.calls.fetch_add(1, AtomicOrdering::Relaxed) == 0 {
            unsafe { destroy(context.auth) };
            assert_eq!(unsafe { marshal(context.auth, xdr) }, 0);
        }
        unsafe { (context.put)(xdr, value) }
    }
    let context = Context {
        auth: auth.0,
        put: original_put,
        calls: AtomicUsize::new(0),
    };
    // SAFETY: copying the function-pointer-only vtable makes an owned test
    // vtable; every operation except x_putint32 remains the real XDR backend.
    let mut operations = unsafe { ptr::read(xdr.x_ops) };
    operations.x_putint32 = write;
    xdr.x_ops = &operations;
    xdr.x_public = (&context as *const Context).cast_mut().cast();
    assert_eq!(unsafe { marshal(auth.0, &mut xdr) }, 1);
    assert!(context.calls.load(AtomicOrdering::Relaxed) > 0);
    assert_eq!(credential(&auth).len(), 24);
}

#[test]
fn auth_sys_native_udp_client_negotiates_nickname_and_refreshes_original() {
    use super::super::{Client, Timeval, XdrProc};
    use std::net::UdpSocket;
    use std::time::Duration;
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let address = server.local_addr().unwrap();
    let peer = std::thread::spawn(move || {
        let mut buffer = [0u8; 1024];
        for phase in 0..3 {
            let (length, sender) = server.recv_from(&mut buffer).unwrap();
            let request = &buffer[..length];
            assert_eq!(word(request, 4), 0); // CALL
            assert_eq!(word(request, 8), 2); // RPC version
            assert_eq!(word(request, 12), 0x2000_0042);
            assert_eq!(word(request, 16), 7);
            assert_eq!(word(request, 20), 3);
            let credential_length = word(request, 28) as usize;
            let credential = &request[32..32 + credential_length];
            if phase == 1 {
                assert_eq!(word(request, 24), 2);
                assert_eq!(credential, b"abc");
            } else {
                assert_eq!(word(request, 24), 1);
                assert_eq!(word(credential, 4), 4);
                assert_eq!(&credential[8..12], b"node");
                assert_eq!(word(credential, 12), 1001);
                assert_eq!(word(credential, 16), 1002);
                assert_eq!(word(credential, 20), 1);
                assert_eq!(word(credential, 24), 42);
            }
            let verifier = 32 + ((credential_length + 3) & !3);
            assert_eq!(word(request, verifier), 0);
            assert_eq!(word(request, verifier + 4), 0);
            assert_eq!(word(request, verifier + 8), 41);
            // Independent wire construction, not the implementation's encoder.
            let words = if phase == 0 {
                vec![word(request, 0), 1, 0, 2, 12, 2, 3, 0x6162_6300, 0, 42]
            } else {
                vec![word(request, 0), 1, 0, 0, 0, 0, 42 + phase]
            };
            let reply = words
                .iter()
                .flat_map(|word| word.to_be_bytes())
                .collect::<Vec<_>>();
            server.send_to(&reply, sender).unwrap();
        }
    });
    let auth = handle(b"node", 1001, 1002, &mut [42]);
    let mut address = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: address.port().to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes([127, 0, 0, 1]),
        },
        sin_zero: [0; 8],
    };
    let mut descriptor = -1;
    let client = unsafe {
        crate::rpc_abi::clntudp_create(
            (&mut address as *mut libc::sockaddr_in).cast(),
            0x2000_0042,
            7,
            Timeval {
                tv_sec: 2,
                tv_usec: 0,
            },
            &mut descriptor,
        )
    }
    .cast::<Client>();
    assert!(!client.is_null());
    unsafe extern "C" fn integer(xdr: *mut c_void, value: *mut c_void) -> c_int {
        unsafe { crate::rpc_abi::xdr_u_int(xdr, value.cast()) }
    }
    unsafe {
        (*client).auth = auth.0;
        for phase in 0..3 {
            if phase == 2 {
                assert_eq!(refresh(auth.0), 1);
            }
            let mut argument = 41u32;
            let mut result = 0u32;
            let status = ((*(*client).operations).call)(
                client,
                3,
                Some(integer as XdrProc),
                (&mut argument as *mut u32).cast(),
                Some(integer as XdrProc),
                (&mut result as *mut u32).cast(),
                Timeval {
                    tv_sec: 2,
                    tv_usec: 0,
                },
            );
            assert_eq!(status, 0, "phase {phase}");
            assert_eq!(result, 42 + phase);
        }
        ((*(*client).operations).destroy)(client);
    }
    // Destroying CLIENT must not invalidate its caller-owned authenticator.
    assert_eq!(unsafe { (*auth.0).credential.oa_flavor }, 1);
    peer.join().unwrap();
}
