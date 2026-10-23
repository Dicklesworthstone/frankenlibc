#![cfg(target_os = "linux")]

//! Integration tests for RPC ABI entrypoints (nativized symbols).
//!
//! Tests cover: DES crypto stubs, thread-local RPC state, key server stubs,
//! netname conversion functions, RPC error strings, and utility functions.

use std::ffi::{CStr, CString, c_char, c_int, c_void};

use frankenlibc_abi::malloc_abi::{free, malloc};
use frankenlibc_abi::rpc_abi::*;

// ---- DES crypto error code ----
const DESERR_NOHWDEVICE: c_int = 4;

unsafe fn malloc_unterminated(bytes: &[u8]) -> *mut c_char {
    let ptr = unsafe { malloc(bytes.len()).cast::<c_char>() };
    assert!(!ptr.is_null());
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr.cast::<u8>(), bytes.len()) };
    ptr
}

// ===========================================================================
// Unsupported RPC status contracts
// ===========================================================================

#[test]
fn unsupported_rpc_status_apis_return_failure_not_success() {
    assert_eq!(
        unsafe { _authenticate(std::ptr::null_mut(), std::ptr::null_mut()) },
        7,
        "_authenticate must return AUTH_FAILED"
    );
    assert_eq!(
        unsafe {
            callrpc(
                std::ptr::null(),
                0,
                0,
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        },
        13,
        "callrpc must report RPC_UNKNOWNHOST for a null hostname"
    );
    assert_eq!(
        unsafe {
            registerrpc(
                0,
                0,
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        },
        -1,
        "registerrpc must return its documented failure sentinel"
    );
}

// ===========================================================================
// DES crypto stubs
// ===========================================================================

#[test]
fn des_cbc_crypt_returns_nohwdevice() {
    let mut key = [0u8; 8];
    let mut buf = [0u8; 8];
    let mut ivec = [0u8; 8];
    let rc = unsafe {
        cbc_crypt(
            key.as_mut_ptr().cast(),
            buf.as_mut_ptr().cast(),
            8,
            0, // DES_ENCRYPT
            ivec.as_mut_ptr().cast(),
        )
    };
    assert_eq!(rc, DESERR_NOHWDEVICE);
}

#[test]
fn des_ecb_crypt_returns_nohwdevice() {
    let mut key = [0u8; 8];
    let mut buf = [0u8; 8];
    let rc = unsafe { ecb_crypt(key.as_mut_ptr().cast(), buf.as_mut_ptr().cast(), 8, 0) };
    assert_eq!(rc, DESERR_NOHWDEVICE);
}

#[test]
fn des_setparity_is_noop() {
    let mut key = [0x55u8; 8];
    let before = key;
    unsafe { des_setparity(key.as_mut_ptr().cast()) };
    // No-op: key should be unchanged (we don't modify it)
    assert_eq!(key, before);
}

#[test]
fn xencrypt_returns_failure() {
    let mut secret = [0u8; 64];
    let mut passwd = [0u8; 64];
    let rc = unsafe { xencrypt(secret.as_mut_ptr().cast(), passwd.as_mut_ptr().cast()) };
    assert_eq!(rc, 0, "xencrypt should fail (no DES support)");
}

#[test]
fn xdecrypt_returns_failure() {
    let mut secret = [0u8; 64];
    let mut passwd = [0u8; 64];
    let rc = unsafe { xdecrypt(secret.as_mut_ptr().cast(), passwd.as_mut_ptr().cast()) };
    assert_eq!(rc, 0, "xdecrypt should fail (no DES support)");
}

#[test]
fn passwd2des_returns_failure() {
    let mut passwd = [0u8; 64];
    let mut key = [0u8; 8];
    let rc = unsafe { passwd2des(passwd.as_mut_ptr().cast(), key.as_mut_ptr().cast()) };
    assert_eq!(rc, 0, "passwd2des should fail (no DES support)");
}

// ===========================================================================
// XDR void
// ===========================================================================

#[test]
fn xdr_void_returns_true() {
    let rc = unsafe { xdr_void() };
    assert_eq!(rc, 1, "xdr_void should always return TRUE (1)");
}

// ===========================================================================
// _rpc_dtablesize
// ===========================================================================

#[test]
fn rpc_dtablesize_returns_reasonable_value() {
    let size = unsafe { _rpc_dtablesize() };
    assert!(size > 0, "dtablesize must be positive");
    assert!(
        size <= 1024,
        "dtablesize should be clamped to FD_SETSIZE (1024)"
    );
}

// ===========================================================================
// Thread-local RPC state
// ===========================================================================

#[test]
fn rpc_thread_createerr_returns_non_null() {
    let ptr = unsafe { __rpc_thread_createerr() };
    assert!(
        !ptr.is_null(),
        "__rpc_thread_createerr should return non-null TLS pointer"
    );
}

#[test]
fn rpc_thread_svc_fdset_returns_non_null() {
    let ptr = unsafe { __rpc_thread_svc_fdset() };
    assert!(
        !ptr.is_null(),
        "__rpc_thread_svc_fdset should return non-null TLS pointer"
    );
}

#[test]
fn rpc_thread_svc_max_pollfd_returns_non_null() {
    let ptr = unsafe { __rpc_thread_svc_max_pollfd() };
    assert!(!ptr.is_null());
}

#[test]
fn rpc_thread_svc_pollfd_returns_non_null() {
    let ptr = unsafe { __rpc_thread_svc_pollfd() };
    assert!(!ptr.is_null());
}

#[test]
fn rpc_thread_tls_per_thread_isolation() {
    use std::sync::mpsc;

    let (tx, rx) = mpsc::channel();

    std::thread::spawn(move || {
        let ptr = unsafe { __rpc_thread_createerr() };
        tx.send(ptr as usize).unwrap();
    })
    .join()
    .unwrap();

    let other_ptr = rx.recv().unwrap();
    let my_ptr = unsafe { __rpc_thread_createerr() } as usize;

    // Different threads should get different TLS pointers
    assert_ne!(
        my_ptr, other_ptr,
        "TLS pointers should differ between threads"
    );
}

// ===========================================================================
// Key server stubs
// ===========================================================================

#[test]
fn key_secretkey_is_set_returns_false() {
    let rc = unsafe { key_secretkey_is_set() };
    assert_eq!(rc, 0, "No keyserver, so secret key is never set");
}

#[test]
fn key_functions_return_failure() {
    let name = CString::new("test").unwrap();
    let mut buf = [0u8; 64];

    assert_eq!(
        unsafe { key_decryptsession(name.as_ptr(), buf.as_mut_ptr().cast()) },
        -1
    );
    assert_eq!(
        unsafe { key_encryptsession(name.as_ptr(), buf.as_mut_ptr().cast()) },
        -1
    );
    assert_eq!(unsafe { key_gendes(buf.as_mut_ptr().cast()) }, -1);
    assert_eq!(
        unsafe { key_get_conv(buf.as_mut_ptr().cast(), buf.as_mut_ptr().cast()) },
        -1
    );
    assert_eq!(unsafe { key_setnet(buf.as_mut_ptr().cast()) }, -1);
    assert_eq!(unsafe { key_setsecret(name.as_ptr()) }, -1);
}

// ===========================================================================
// get_myaddress
// ===========================================================================

#[test]
fn get_myaddress_fills_loopback() {
    #[repr(C)]
    struct SockaddrIn {
        sin_family: u16,
        sin_port: u16,
        sin_addr: u32,
        sin_zero: [u8; 8],
    }

    let mut addr: SockaddrIn = unsafe { std::mem::zeroed() };
    unsafe { get_myaddress((&mut addr as *mut SockaddrIn).cast()) };

    assert_eq!(addr.sin_family, 2, "AF_INET = 2");
    assert_eq!(addr.sin_port, 0, "port should be 0");
    // 127.0.0.1 in network byte order = 0x0100007f on little-endian
    assert_eq!(addr.sin_addr, u32::from_be(0x7f000001));
}

// ===========================================================================
// getnetname
// ===========================================================================

#[test]
fn getnetname_returns_valid_name() {
    let mut buf = [0u8; 256];
    let rc = unsafe { getnetname(buf.as_mut_ptr().cast()) };
    assert_eq!(rc, 1, "getnetname should succeed");

    let name = unsafe { CStr::from_ptr(buf.as_ptr().cast()) }
        .to_str()
        .unwrap();
    assert!(
        name.starts_with("unix."),
        "netname should start with 'unix.': {}",
        name
    );
    assert!(name.contains('@'), "netname should contain '@': {}", name);
}

#[test]
fn getnetname_null_returns_failure() {
    let rc = unsafe { getnetname(std::ptr::null_mut()) };
    assert_eq!(rc, 0);
}

// ===========================================================================
// clnt_sperrno
// ===========================================================================

#[test]
fn clnt_sperrno_success() {
    let msg = unsafe { clnt_sperrno(0) };
    assert!(!msg.is_null());
    let s = unsafe { CStr::from_ptr(msg) }.to_str().unwrap();
    assert_eq!(s, "RPC: Success");
}

#[test]
fn clnt_sperrno_timeout() {
    let msg = unsafe { clnt_sperrno(5) };
    assert!(!msg.is_null());
    let s = unsafe { CStr::from_ptr(msg) }.to_str().unwrap();
    assert_eq!(s, "RPC: Timed out");
}

#[test]
fn clnt_sperrno_unknown() {
    let msg = unsafe { clnt_sperrno(999) };
    assert!(!msg.is_null());
    let s = unsafe { CStr::from_ptr(msg) }.to_str().unwrap();
    assert_eq!(s, "RPC: (unknown error code)");
}

// ===========================================================================
// clnt_perrno (verify it doesn't crash)
// ===========================================================================

#[test]
fn clnt_perrno_does_not_crash() {
    unsafe { clnt_perrno(0) };
    unsafe { clnt_perrno(5) };
    unsafe { clnt_perrno(999) };
}

#[test]
#[ignore = "requires real hardened mode bounds checking (bd-q3snos)"]
fn clnt_spcreateerror_ignores_tracked_unterminated_prefix() {
    let prefix = unsafe { malloc_unterminated(b"rpc_prefix") };

    let msg = unsafe { clnt_spcreateerror(prefix.cast_const()) };

    unsafe { free(prefix.cast::<c_void>()) };

    assert!(!msg.is_null());
    let rendered = unsafe { CStr::from_ptr(msg) }.to_bytes();
    assert_eq!(rendered, b": RPC: Success\n");
}

// ===========================================================================
// getrpcport
// ===========================================================================

#[test]
fn getrpcport_returns_zero() {
    let host = CString::new("localhost").unwrap();
    let rc = unsafe { getrpcport(host.as_ptr(), 100000, 2, 17) };
    assert_eq!(rc, 0, "getrpcport should return 0 (not found)");
}

// ===========================================================================
// getpublickey / getsecretkey
// ===========================================================================

#[test]
fn getpublickey_missing_identity_preserves_output() {
    let name = CString::new("unix.0@frankenlibc-unmapped.invalid").unwrap();
    let mut buf = [0xa5u8; 49];
    let rc = unsafe { getpublickey(name.as_ptr(), buf.as_mut_ptr().cast()) };
    assert_eq!(rc, 0);
    assert_eq!(buf, [0xa5; 49]);
}

#[test]
fn getsecretkey_returns_not_found() {
    let name = CString::new("unix.0@localhost").unwrap();
    let passwd = CString::new("test").unwrap();
    let mut buf = [0u8; 256];
    let rc = unsafe { getsecretkey(name.as_ptr(), buf.as_mut_ptr().cast(), passwd.as_ptr()) };
    assert_eq!(rc, 0, "No publickey database");
}

// ===========================================================================
// host2netname / netname2host / netname2user / user2netname
// ===========================================================================

/// Surround the public 256-byte destination with independent byte canaries.
fn assert_netname_output(buffer: &[u8; 258], expected: &[u8]) {
    assert_eq!(buffer[0], 0xa5);
    assert_eq!(buffer[257], 0xa5);
    assert_eq!(&buffer[1..1 + expected.len()], expected);
    assert_eq!(buffer[1 + expected.len()], 0);
}

#[test]
fn host2netname_writes_the_callers_character_buffer() {
    let host = CString::new("myhost").unwrap();
    let domain = CString::new("example.com").unwrap();
    let mut name = [0xa5u8; 258];
    // SAFETY: the destination has the public 256-byte capacity.
    let rc = unsafe {
        host2netname(
            name.as_mut_ptr().add(1).cast(),
            host.as_ptr(),
            domain.as_ptr(),
        )
    };
    assert_eq!(rc, 1);
    assert_netname_output(&name, b"unix.myhost@example.com");
}

#[test]
fn host2netname_uses_the_hostname_suffix_for_a_null_domain() {
    let host = CString::new("myhost.example.com.").unwrap();
    let mut name = [0xa5u8; 258];
    // SAFETY: valid input string and caller-owned 256-byte output.
    let rc = unsafe {
        host2netname(
            name.as_mut_ptr().add(1).cast(),
            host.as_ptr(),
            std::ptr::null(),
        )
    };
    assert_eq!(rc, 1);
    assert_netname_output(&name, b"unix.myhost@example.com");
}

#[test]
fn host2netname_preserves_non_utf8_bytes() {
    let host = CString::new(b"node\xff.suffix".as_slice()).unwrap();
    let domain = CString::new(b"domain\xfe.".as_slice()).unwrap();
    let mut name = [0xa5u8; 258];
    // SAFETY: C strings may contain arbitrary non-NUL bytes.
    let rc = unsafe {
        host2netname(
            name.as_mut_ptr().add(1).cast(),
            host.as_ptr(),
            domain.as_ptr(),
        )
    };
    assert_eq!(rc, 1);
    assert_netname_output(&name, b"unix.node\xff@domain\xfe");
}

#[test]
fn host2netname_rejects_an_empty_domain_and_clears_only_the_first_byte() {
    let host = CString::new("myhost").unwrap();
    let domain = CString::new("").unwrap();
    let mut name = [0xa5u8; 258];
    // SAFETY: valid input strings and a 256-byte caller-owned output.
    let rc = unsafe {
        host2netname(
            name.as_mut_ptr().add(1).cast(),
            host.as_ptr(),
            domain.as_ptr(),
        )
    };
    assert_eq!(rc, 0);
    assert_eq!(name[0], 0xa5);
    assert_eq!(name[1], 0);
    assert!(name[2..].iter().all(|&byte| byte == 0xa5));
}

#[test]
fn netname2host_does_not_invent_a_mapping_for_a_remote_domain() {
    let netname = CString::new("unix.myhost@frankenlibc-unmapped.invalid").unwrap();
    let mut hostname = [0xa5u8; 256];

    let rc = unsafe { netname2host(netname.as_ptr(), hostname.as_mut_ptr().cast(), 256) };
    assert_eq!(rc, 0);
    assert_eq!(hostname, [0xa5; 256]);
}

#[test]
fn netname2host_rejects_invalid() {
    let bad = CString::new("not_a_netname").unwrap();
    let mut hostname = [0u8; 256];
    let rc = unsafe { netname2host(bad.as_ptr(), hostname.as_mut_ptr().cast(), 256) };
    assert_eq!(rc, 0);
}

#[test]
fn netname2user_requires_an_authoritative_mapping() {
    let netname = CString::new("unix.1000@frankenlibc-unmapped.invalid").unwrap();
    let mut uid: libc::uid_t = 17;
    let mut gid: libc::gid_t = 19;
    let mut gidlen: c_int = 23;

    let rc = unsafe {
        netname2user(
            netname.as_ptr(),
            &mut uid,
            &mut gid,
            &mut gidlen,
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, 0);
    assert_eq!((uid, gid, gidlen), (17, 19, 23));
}

#[test]
fn netname2user_missing_identity_preserves_adjacent_storage() {
    #[repr(C)]
    struct Outputs {
        uid: libc::uid_t,
        uid_guard: u32,
        gid: libc::gid_t,
        gid_guard: u32,
        count: c_int,
        count_guard: u32,
    }
    let mut out = Outputs {
        uid: 17,
        uid_guard: 0x1234_5678,
        gid: 19,
        gid_guard: 0x9abc_def0,
        count: 23,
        count_guard: 0x1357_9bdf,
    };
    let name = CString::new("unix.4294967295@frankenlibc-unmapped.invalid").unwrap();
    // SAFETY: each output points to exactly the public C type's storage.
    let rc = unsafe {
        netname2user(
            name.as_ptr(),
            &mut out.uid,
            &mut out.gid,
            &mut out.count,
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, 0);
    assert_eq!((out.uid, out.gid, out.count), (17, 19, 23));
    assert_eq!(out.uid_guard, 0x1234_5678);
    assert_eq!(out.gid_guard, 0x9abc_def0);
    assert_eq!(out.count_guard, 0x1357_9bdf);
}

#[test]
fn netname2user_does_not_derive_credentials_from_unmapped_numeric_names() {
    for identity in ["4294967296", "18446744073709551615", "-1"] {
        let name = CString::new(format!("unix.{identity}@frankenlibc-unmapped.invalid")).unwrap();
        let mut uid: libc::uid_t = 17;
        let mut gid: libc::gid_t = 19;
        let mut count: c_int = 23;
        let mut groups: [libc::gid_t; 2] = [29, 31];
        // SAFETY: every output has the size and alignment of its public C type.
        let rc = unsafe {
            netname2user(
                name.as_ptr(),
                &mut uid,
                &mut gid,
                &mut count,
                groups.as_mut_ptr(),
            )
        };
        assert_eq!(rc, 0, "unmapped identity {identity}");
        assert_eq!((uid, gid, count, groups), (17, 19, 23, [29, 31]));
    }
}

#[test]
fn user2netname_writes_the_callers_buffer_and_formats_signed_uid_bits() {
    let domain = CString::new("example.com.").unwrap();
    for (uid, expected) in [
        (42, "unix.42@example.com"),
        (0x7fff_ffff, "unix.2147483647@example.com"),
        (0x8000_0000, "unix.-2147483648@example.com"),
        (0xffff_ffff, "unix.-1@example.com"),
    ] {
        let mut name = [0xa5u8; 258];
        // SAFETY: uid uses the public uid_t type and output has 256 bytes.
        let rc = unsafe { user2netname(name.as_mut_ptr().add(1).cast(), uid, domain.as_ptr()) };
        assert_eq!(rc, 1);
        assert_netname_output(&name, expected.as_bytes());
    }
}

#[test]
fn user2netname_rejects_an_overlong_domain_without_touching_the_buffer() {
    for tail in [b'd', b'.'] {
        let mut bytes = vec![b'd'; 238];
        bytes[237] = tail;
        let domain = CString::new(bytes).unwrap();
        let mut name = [0xa5u8; 258];
        // SAFETY: valid input string and a 256-byte caller-owned output.
        let rc = unsafe { user2netname(name.as_mut_ptr().add(1).cast(), 42, domain.as_ptr()) };
        assert_eq!(rc, 0);
        assert_eq!(name, [0xa5; 258]);
    }
}

// ===========================================================================
// _seterr_reply (basic smoke test)
// ===========================================================================

#[test]
fn seterr_reply_null_safety() {
    // Should not crash on null pointers
    unsafe { _seterr_reply(std::ptr::null_mut(), std::ptr::null_mut()) };
}

#[test]
fn seterr_reply_success_case() {
    // Simulate a MSG_ACCEPTED + SUCCESS reply
    // rpc_msg layout: xid(4) + direction(4) + rp_stat(4) + ar_stat(4) + ...
    let mut msg = [0u32; 8];
    msg[0] = 1; // xid
    msg[1] = 1; // REPLY (direction)
    msg[2] = 0; // MSG_ACCEPTED (rp_stat)
    msg[3] = 0; // SUCCESS (ar_stat)

    let mut error = [0u32; 6]; // rpc_err: re_status + union (24 bytes)

    unsafe {
        _seterr_reply(msg.as_mut_ptr().cast(), error.as_mut_ptr().cast());
    }

    assert_eq!(error[0], 0, "SUCCESS should map to re_status = 0");
}

// ===========================================================================
// rtime
// ===========================================================================

#[test]
fn rtime_returns_failure() {
    let rc = unsafe {
        rtime(
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, -1, "rtime should return -1 (not supported)");
}

// ===========================================================================
// bindresvport (test with invalid socket — should return -1)
// ===========================================================================

#[test]
fn bindresvport_invalid_socket_returns_error() {
    let rc = unsafe { bindresvport(-1, std::ptr::null_mut()) };
    assert_eq!(rc, -1, "bindresvport with invalid socket should fail");
}

// ===========================================================================
// bindresvport6 (IPv6 reserved-port bind)
// ===========================================================================

#[test]
fn bindresvport6_invalid_socket_returns_error() {
    let rc = unsafe { bindresvport6(-1, std::ptr::null_mut()) };
    assert_eq!(rc, -1, "bindresvport6 with invalid socket should fail");
}

#[test]
fn bindresvport6_binds_socket_to_reserved_port() {
    // Open a UDP/IPv6 socket and ask bindresvport6 to bind it to a
    // reserved port. Then read back the port via getsockname and
    // verify it's in the 512..=1023 range.
    let sd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
    if sd < 0 {
        // IPv6 may not be enabled on this host.
        return;
    }
    let mut sin6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    sin6.sin6_family = libc::AF_INET6 as u16;
    let rc = unsafe { bindresvport6(sd, &mut sin6 as *mut _ as *mut std::ffi::c_void) };
    if rc != 0 {
        // Binding to reserved ports requires CAP_NET_BIND_SERVICE
        // on Linux; tests usually run as non-root and will hit
        // EACCES/EPERM. Treat as inconclusive.
        unsafe { libc::close(sd) };
        return;
    }
    let mut got: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
    let r = unsafe { libc::getsockname(sd, &mut got as *mut _ as *mut libc::sockaddr, &mut len) };
    assert_eq!(r, 0);
    let port = u16::from_be(got.sin6_port);
    assert!(
        (512..=1023).contains(&port),
        "bindresvport6 chose port {port}, outside reserved range"
    );
    unsafe { libc::close(sd) };
}

#[test]
fn bindresvport6_null_sockaddr_works() {
    // Same as above but pass NULL sin6 — function uses internal storage.
    let sd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
    if sd < 0 {
        return;
    }
    let rc = unsafe { bindresvport6(sd, std::ptr::null_mut()) };
    if rc != 0 {
        unsafe { libc::close(sd) };
        return;
    }
    // After a successful bind we should still be able to read back
    // the bound port.
    let mut got: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
    let r = unsafe { libc::getsockname(sd, &mut got as *mut _ as *mut libc::sockaddr, &mut len) };
    assert_eq!(r, 0);
    let port = u16::from_be(got.sin6_port);
    assert!((512..=1023).contains(&port));
    unsafe { libc::close(sd) };
}
