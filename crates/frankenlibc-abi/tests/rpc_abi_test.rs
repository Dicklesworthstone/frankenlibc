#![cfg(target_os = "linux")]

//! Integration tests for RPC ABI entrypoints (nativized symbols).
//!
//! Tests cover: native DES crypto, thread-local RPC state, keyserver admission,
//! netname conversion functions, RPC error strings, and utility functions.

use std::ffi::{CStr, CString, c_char, c_int, c_void};

use frankenlibc_abi::malloc_abi::{free, malloc};
use frankenlibc_abi::rpc_abi::*;

// ---- DES crypto error code ----
const DESERR_NOHWDEVICE: c_int = 1;
const DESERR_BADPARAM: c_int = 3;

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
// Native DES crypto
// ===========================================================================

#[test]
fn des_cbc_crypt_uses_software_fallback_and_updates_iv() {
    let mut key: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
    let mut buf = *b"Now is the time for all ";
    let original = buf;
    let initial_iv: [u8; 8] = [0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef];
    let mut ivec = initial_iv;
    let rc = unsafe {
        cbc_crypt(
            key.as_mut_ptr().cast(),
            buf.as_mut_ptr().cast(),
            buf.len() as u32,
            0, // DES_ENCRYPT | DES_HW
            ivec.as_mut_ptr().cast(),
        )
    };
    assert_eq!(rc, DESERR_NOHWDEVICE);
    assert_eq!(
        buf,
        [
            0xe5, 0xc7, 0xcd, 0xde, 0x87, 0x2b, 0xf2, 0x7c, 0x43, 0xe9, 0x34, 0x00, 0x8c, 0x38,
            0x9c, 0x0f, 0x68, 0x37, 0x88, 0x49, 0x9a, 0x7c, 0x05, 0xf6
        ]
    );
    assert_eq!(ivec, buf[16..]);
    let final_iv = ivec;
    ivec = initial_iv;
    let rc = unsafe {
        cbc_crypt(
            key.as_mut_ptr().cast(),
            buf.as_mut_ptr().cast(),
            buf.len() as u32,
            3,
            ivec.as_mut_ptr().cast(),
        )
    };
    assert_eq!(rc, 0);
    assert_eq!(buf, original);
    assert_eq!(ivec, final_iv);
}

#[test]
fn des_ecb_crypt_matches_fips_vector() {
    let mut key: [u8; 8] = [0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1];
    let mut buf: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
    let original = buf;
    let rc = unsafe { ecb_crypt(key.as_mut_ptr().cast(), buf.as_mut_ptr().cast(), 8, 0) };
    assert_eq!(rc, DESERR_NOHWDEVICE);
    assert_eq!(buf, [0x85, 0xe8, 0x13, 0x54, 0x0f, 0x0a, 0xb4, 0x05]);
    let rc = unsafe { ecb_crypt(key.as_mut_ptr().cast(), buf.as_mut_ptr().cast(), 8, 3) };
    assert_eq!(rc, 0);
    assert_eq!(buf, original);
}

#[test]
fn des_setparity_matches_seven_bit_legacy_table() {
    let mut key: [u8; 8] = [0x80, 0xff, 0xfe, 0x7f, 0, 1, 2, 3];
    unsafe { des_setparity(key.as_mut_ptr().cast()) };
    assert_eq!(key, [1, 0x7f, 0x7f, 0x7f, 1, 1, 2, 2]);
}

#[test]
fn xencrypt_and_xdecrypt_match_gnu_secret_vector() {
    let mut secret = *b"00112233445566778899aabbccddeeff\0";
    let original = secret;
    let mut passwd = *b"password"; // All eight bytes are consumed; no NUL is required.
    let rc = unsafe { xencrypt(secret.as_mut_ptr().cast(), passwd.as_mut_ptr().cast()) };
    assert_eq!(rc, 1);
    assert_eq!(&secret, b"2ab97b02016d8e2d3ec03d15e13881d6\0");
    let rc = unsafe { xdecrypt(secret.as_mut_ptr().cast(), passwd.as_mut_ptr().cast()) };
    assert_eq!(rc, 1);
    assert_eq!(secret, original);
}

#[test]
fn des_hex_empty_odd_and_invalid_lengths_match_legacy_contract() {
    let mut passwd = *b"password";
    for transform in [xencrypt, xdecrypt] {
        let mut empty = [0u8, 0xa5];
        assert_eq!(
            unsafe { transform(empty.as_mut_ptr().cast(), passwd.as_mut_ptr().cast()) },
            1
        );
        assert_eq!(empty, [0, 0xa5]);
        let mut invalid = *b"00\0!";
        assert_eq!(
            unsafe { transform(invalid.as_mut_ptr().cast(), passwd.as_mut_ptr().cast()) },
            0
        );
        assert_eq!(&invalid, b"00\0!");
    }
    let mut odd = *b"00112233445566778\0!";
    assert_eq!(
        unsafe { xencrypt(odd.as_mut_ptr().cast(), passwd.as_mut_ptr().cast()) },
        1
    );
    assert_eq!(&odd, b"2ab97b02016d8e2d\0\0!");
}

#[test]
fn passwd2des_has_void_abi_and_consumes_at_most_eight_bytes() {
    let mut passwd = *b"123456789\0";
    let mut key = [0u8; 8];
    let transform: unsafe extern "C" fn(*mut c_char, *mut c_char) = passwd2des;
    unsafe { transform(passwd.as_mut_ptr().cast(), key.as_mut_ptr().cast()) };
    assert_eq!(key, [0x62, 0x64, 0x67, 0x68, 0x6b, 0x6d, 0x6e, 0x70]);
}

#[test]
fn des_invalid_lengths_and_faults_preserve_outputs() {
    let mut key = [0u8; 8];
    let mut buf = [0x5au8; 16];
    let mut iv = [0xa5u8; 8];
    for length in [1, 7, 9, 8193, u32::MAX] {
        assert_eq!(
            unsafe {
                cbc_crypt(
                    key.as_mut_ptr().cast(),
                    buf.as_mut_ptr().cast(),
                    length,
                    2,
                    iv.as_mut_ptr().cast(),
                )
            },
            DESERR_BADPARAM
        );
        assert_eq!(buf, [0x5a; 16]);
        assert_eq!(iv, [0xa5; 8]);
    }
    assert_eq!(
        unsafe {
            cbc_crypt(
                std::ptr::null_mut(),
                buf.as_mut_ptr().cast(),
                8,
                2,
                iv.as_mut_ptr().cast(),
            )
        },
        DESERR_BADPARAM
    );
    assert_eq!(
        unsafe {
            cbc_crypt(
                key.as_mut_ptr().cast(),
                buf.as_mut_ptr().cast(),
                8,
                2,
                std::ptr::null_mut(),
            )
        },
        DESERR_BADPARAM
    );
    assert_eq!(buf, [0x5a; 16]);
    assert_eq!(iv, [0xa5; 8]);
    let mut secret = *b"0011223344556677\0";
    assert_eq!(
        unsafe { xencrypt(secret.as_mut_ptr().cast(), std::ptr::null_mut()) },
        0
    );
    assert_eq!(&secret, b"0011223344556677\0");
}

#[test]
fn des_tracked_short_buffers_fail_without_mutation() {
    let key = unsafe { malloc_unterminated(b"password") };
    let short = unsafe { malloc_unterminated(&[0x5a; 7]) };
    let mut iv = [0xa5u8; 8];
    assert_eq!(
        unsafe { cbc_crypt(key, short, 8, 2, iv.as_mut_ptr().cast()) },
        DESERR_BADPARAM
    );
    assert_eq!(
        unsafe { std::slice::from_raw_parts(short.cast::<u8>(), 7) },
        &[0x5a; 7]
    );
    assert_eq!(iv, [0xa5; 8]);
    let secret = unsafe { malloc_unterminated(b"0011223344556677") };
    assert_eq!(unsafe { xencrypt(secret, key) }, 0);
    assert_eq!(
        unsafe { std::slice::from_raw_parts(secret.cast::<u8>(), 16) },
        b"0011223344556677"
    );
    unsafe {
        free(secret.cast());
        free(short.cast());
        free(key.cast());
    }
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
// Keyserver input admission (live daemon exchanges have an isolated runner)
// ===========================================================================

#[test]
fn key_public_key_requests_reject_invalid_storage_without_publication() {
    #[repr(C)]
    struct NetObject {
        length: u32,
        bytes: *mut c_char,
    }
    type PublicKeyCall =
        unsafe extern "C-unwind" fn(*const c_char, *mut c_void, *mut c_void) -> c_int;
    let calls: [PublicKeyCall; 2] = [key_encryptsession_pk, key_decryptsession_pk];
    let mut public = NetObject {
        length: 0,
        bytes: std::ptr::null_mut(),
    };
    for call in calls {
        let mut guarded = [0xa5u8; 24];
        let output = unsafe { guarded.as_mut_ptr().add(8).cast() };
        assert_eq!(
            unsafe { call(c"test".as_ptr(), std::ptr::null_mut(), output) },
            -1
        );
        assert_eq!(
            unsafe {
                call(
                    std::ptr::null(),
                    (&mut public as *mut NetObject).cast(),
                    output,
                )
            },
            -1
        );
        assert_eq!(
            unsafe {
                call(
                    c"test".as_ptr(),
                    (&mut public as *mut NetObject).cast(),
                    std::ptr::null_mut(),
                )
            },
            -1
        );
        public.length = 1025;
        assert_eq!(
            unsafe {
                call(
                    c"test".as_ptr(),
                    (&mut public as *mut NetObject).cast(),
                    output,
                )
            },
            -1
        );
        public.length = 0;
        assert_eq!(
            guarded, [0xa5; 24],
            "rejected requests must preserve the key and its canaries"
        );
    }
}

#[test]
fn key_functions_reject_null_storage_before_contacting_daemon() {
    let mut guarded = [0xa5u8; 24];
    let output = unsafe { guarded.as_mut_ptr().add(8).cast() };
    for call in [key_decryptsession, key_encryptsession] {
        assert_eq!(unsafe { call(std::ptr::null(), output) }, -1);
        assert_eq!(unsafe { call(c"test".as_ptr(), std::ptr::null_mut()) }, -1);
    }
    let mut public = [b'0'; 48];
    assert_eq!(unsafe { key_gendes(std::ptr::null_mut()) }, -1);
    assert_eq!(unsafe { key_get_conv(std::ptr::null_mut(), output) }, -1);
    assert_eq!(
        unsafe { key_get_conv(public.as_mut_ptr().cast(), std::ptr::null_mut()) },
        -1
    );
    assert_eq!(unsafe { key_setnet(std::ptr::null_mut()) }, -1);
    assert_eq!(unsafe { key_setsecret(std::ptr::null()) }, -1);
    assert_eq!(
        guarded, [0xa5; 24],
        "rejected requests must preserve the key and its canaries"
    );
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
    for tail in *b"d." {
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
fn rtime_rejects_missing_address_and_output() {
    let rc = unsafe {
        rtime(
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(rc, -1, "rtime must reject missing caller storage");
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

// Public key_prot.x layouts, independent of the implementation's private types.
mod key_protocol {
    use super::*;
    use std::ptr;

    type Codec = unsafe extern "C" fn(*mut c_void, *mut c_void) -> c_int;

    #[repr(C)]
    struct NetObj {
        len: u32,
        bytes: *mut c_char,
    }
    #[repr(C)]
    struct Arg2 {
        name: *mut c_char,
        public_key: NetObj,
        key: [u8; 8],
    }
    #[repr(C)]
    struct Cred {
        uid: u32,
        gid: u32,
        count: u32,
        groups: *mut u32,
    }
    #[repr(C)]
    struct CredResult {
        status: c_int,
        cred: Cred,
    }
    #[repr(C)]
    struct NetworkKeys {
        secret: [u8; 48],
        public: [u8; 48],
        name: *mut c_char,
    }
    #[repr(C)]
    struct NetworkResult {
        status: c_int,
        keys: NetworkKeys,
    }

    fn codecs(native: Codec, name: &CStr) -> Vec<Codec> {
        let mut result = vec![native];
        #[cfg(target_env = "gnu")]
        {
            static GNU: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
            let provider = *GNU.get_or_init(|| {
                // SAFETY: the process already uses GNU libc; retain its handle
                // for the lifetime of these independently resolved codecs.
                let handle = unsafe { libc::dlopen(c"libc.so.6".as_ptr(), libc::RTLD_NOW) };
                assert!(
                    !handle.is_null(),
                    "GNU XDR oracle is required on GNU targets"
                );
                handle as usize
            });
            let mut symbol = ptr::null_mut();
            for version in [c"GLIBC_2.2.5", c"GLIBC_2.17"] {
                // SAFETY: public XDR codecs have the signature declared above.
                symbol = unsafe {
                    libc::dlvsym(provider as *mut c_void, name.as_ptr(), version.as_ptr())
                };
                if !symbol.is_null() {
                    break;
                }
            }
            assert!(!symbol.is_null(), "missing GNU oracle: {name:?}");
            assert_ne!(
                symbol as usize, native as usize,
                "oracle resolved to candidate"
            );
            // SAFETY: the versioned symbol's public XDR signature is Codec.
            result.push(unsafe { std::mem::transmute::<*mut c_void, Codec>(symbol) });
        }
        result
    }

    fn run<T>(codec: Codec, value: &mut T, bytes: &mut [u8], op: c_int) -> c_int {
        // SAFETY: XDR is initialized before use; the supplied object and wire
        // buffer stay live, and each caller uses the codec's public C layout.
        unsafe {
            let mut stream: Xdr = std::mem::zeroed();
            xdrmem_create(
                ptr::addr_of_mut!(stream).cast(),
                bytes.as_mut_ptr().cast(),
                bytes.len() as u32,
                op,
            );
            codec(
                ptr::addr_of_mut!(stream).cast(),
                ptr::from_mut(value).cast(),
            )
        }
    }

    fn encode<T>(codec: Codec, value: &mut T, expected: &[u8]) {
        let mut wire = vec![0xa5; expected.len() + 16];
        assert_eq!(run(codec, value, &mut wire, 0), 1);
        assert_eq!(&wire[..expected.len()], expected);
        assert!(wire[expected.len()..].iter().all(|b| *b == 0xa5));
        // SAFETY: the size probe uses the same valid object and codec.
        assert_eq!(
            unsafe {
                xdr_sizeof(
                    codec as *const () as *mut c_void,
                    ptr::from_mut(value).cast(),
                )
            },
            expected.len() as u64
        );
    }

    fn release<T>(codec: Codec, value: &mut T) {
        // SAFETY: every owned field was allocated by this exact codec; failed
        // decodes retain zero-initialized pointers for fields not yet visited.
        unsafe {
            xdr_free(
                codec as *const () as *mut c_void,
                ptr::from_mut(value).cast(),
            )
        };
    }

    #[test]
    fn fixed_keys_use_exactly_48_bytes() {
        for codec in codecs(xdr_keybuf, c"xdr_keybuf") {
            let mut key = *b"0123456789abcdef0123456789abcdef0123456789abcdef";
            let expected = key;
            encode(codec, &mut key, &expected);
            let mut output = [0xa5; 64];
            assert_eq!(run(codec, &mut output, &mut key, 1), 1);
            assert_eq!(&output[..48], &expected);
            assert_eq!(&output[48..], &[0xa5; 16]);
            assert_eq!(run(codec, &mut output, &mut key[..47], 1), 0);
        }
    }

    #[test]
    fn public_keys_are_counted_binary_objects() {
        for codec in codecs(xdr_cryptkeyarg2, c"xdr_cryptkeyarg2") {
            let mut public = [0, 7, 0, 0xff, 0x80];
            let mut arg = Arg2 {
                name: c"peer".as_ptr().cast_mut(),
                public_key: NetObj {
                    len: 5,
                    bytes: public.as_mut_ptr().cast(),
                },
                key: *b"12345678",
            };
            let mut wire = [
                0, 0, 0, 4, b'p', b'e', b'e', b'r', 0, 0, 0, 5, 0, 7, 0, 0xff, 0x80, 0, 0, 0, b'1',
                b'2', b'3', b'4', b'5', b'6', b'7', b'8',
            ];
            encode(codec, &mut arg, &wire);
            // SAFETY: null pointers are the required initial state for XDR decode.
            let mut decoded: Arg2 = unsafe { std::mem::zeroed() };
            assert_eq!(run(codec, &mut decoded, &mut wire, 1), 1);
            assert_eq!(unsafe { CStr::from_ptr(decoded.name) }, c"peer");
            assert_eq!(decoded.public_key.len, 5);
            assert_eq!(
                unsafe { std::slice::from_raw_parts(decoded.public_key.bytes.cast::<u8>(), 5) },
                public
            );
            assert_eq!(decoded.key, *b"12345678");
            release(codec, &mut decoded);
            assert!(decoded.name.is_null() && decoded.public_key.bytes.is_null());
            arg.public_key.len = 1025;
            assert_eq!(run(codec, &mut arg, &mut wire, 0), 0);
        }
    }

    #[test]
    fn credentials_have_one_full_width_group_count() {
        for codec in codecs(xdr_unixcred, c"xdr_unixcred") {
            let mut groups = [7, u32::MAX, 0x8000_0001];
            let mut cred = Cred {
                uid: 42,
                gid: 9,
                count: 3,
                groups: groups.as_mut_ptr(),
            };
            let mut wire: Vec<u8> = [42u32, 9, 3, 7, u32::MAX, 0x8000_0001]
                .into_iter()
                .flat_map(u32::to_be_bytes)
                .collect();
            encode(codec, &mut cred, &wire);
            let mut decoded = Cred {
                uid: 0,
                gid: 0,
                count: 0,
                groups: ptr::null_mut(),
            };
            assert_eq!(run(codec, &mut decoded, &mut wire, 1), 1);
            assert_eq!((decoded.uid, decoded.gid, decoded.count), (42, 9, 3));
            assert_eq!(
                unsafe { std::slice::from_raw_parts(decoded.groups, 3) },
                groups
            );
            release(codec, &mut decoded);
            assert!(decoded.groups.is_null());
            // A short count would silently turn this invalid count into zero.
            cred.count = 0x1_0000;
            assert_eq!(run(codec, &mut cred, &mut wire, 0), 0);
        }
    }

    #[test]
    fn failed_results_never_visit_inactive_union_storage() {
        for (native, name) in [
            (xdr_cryptkeyres as Codec, c"xdr_cryptkeyres"),
            (xdr_getcredres, c"xdr_getcredres"),
            (xdr_key_netstres, c"xdr_key_netstres"),
        ] {
            for codec in codecs(native, name) {
                for status in [1i32, 2, 3, 99, -1] {
                    let mut value = [0xa5a5_a5a5_a5a5_a5a5u64; 16];
                    // SAFETY: value is aligned and large enough for every union.
                    unsafe { ptr::write(value.as_mut_ptr().cast::<i32>(), status) };
                    encode(codec, &mut value, &status.to_be_bytes());
                    let before = value;
                    let mut wire = status.to_be_bytes();
                    assert_eq!(run(codec, &mut value, &mut wire, 1), 1);
                    release(codec, &mut value);
                    assert_eq!(value, before, "inactive payload changed for {name:?}");
                }
            }
        }
    }

    #[test]
    fn successful_credential_results_contain_unix_credentials() {
        for codec in codecs(xdr_getcredres, c"xdr_getcredres") {
            let mut groups = [3, 17];
            let mut result = CredResult {
                status: 0,
                cred: Cred {
                    uid: 1001,
                    gid: 1002,
                    count: 2,
                    groups: groups.as_mut_ptr(),
                },
            };
            let mut wire: Vec<u8> = [0u32, 1001, 1002, 2, 3, 17]
                .into_iter()
                .flat_map(u32::to_be_bytes)
                .collect();
            encode(codec, &mut result, &wire);
            let mut decoded: CredResult = unsafe { std::mem::zeroed() };
            assert_eq!(run(codec, &mut decoded, &mut wire, 1), 1);
            assert_eq!(
                (
                    decoded.status,
                    decoded.cred.uid,
                    decoded.cred.gid,
                    decoded.cred.count
                ),
                (0, 1001, 1002, 2)
            );
            assert_eq!(
                unsafe { std::slice::from_raw_parts(decoded.cred.groups, 2) },
                groups
            );
            release(codec, &mut decoded);
            assert!(decoded.cred.groups.is_null());
        }
    }

    #[test]
    fn network_key_arguments_and_results_include_the_netname() {
        for (native, name, result) in [
            (xdr_key_netstarg as Codec, c"xdr_key_netstarg", false),
            (xdr_key_netstres, c"xdr_key_netstres", true),
        ] {
            for codec in codecs(native, name) {
                let mut value = NetworkResult {
                    status: 0,
                    keys: NetworkKeys {
                        secret: [b'a'; 48],
                        public: [b'b'; 48],
                        name: c"u@d".as_ptr().cast_mut(),
                    },
                };
                let mut wire = if result { vec![0u8; 4] } else { vec![] };
                wire.extend_from_slice(&value.keys.secret);
                wire.extend_from_slice(&value.keys.public);
                wire.extend_from_slice(&[0, 0, 0, 3, b'u', b'@', b'd', 0]);
                if result {
                    encode(codec, &mut value, &wire);
                } else {
                    encode(codec, &mut value.keys, &wire);
                }
                let mut decoded: NetworkResult = unsafe { std::mem::zeroed() };
                if result {
                    assert_eq!(run(codec, &mut decoded, &mut wire, 1), 1);
                } else {
                    assert_eq!(run(codec, &mut decoded.keys, &mut wire, 1), 1);
                }
                assert_eq!(decoded.keys.secret, [b'a'; 48]);
                assert_eq!(decoded.keys.public, [b'b'; 48]);
                assert_eq!(unsafe { CStr::from_ptr(decoded.keys.name) }, c"u@d");
                if result {
                    release(codec, &mut decoded);
                } else {
                    release(codec, &mut decoded.keys);
                }
                assert!(decoded.keys.name.is_null());
                for length in 0..wire.len() {
                    let mut partial: NetworkResult = unsafe { std::mem::zeroed() };
                    let rc = if result {
                        run(codec, &mut partial, &mut wire[..length], 1)
                    } else {
                        run(codec, &mut partial.keys, &mut wire[..length], 1)
                    };
                    assert_eq!(rc, 0, "truncated {name:?} at {length}");
                    if result {
                        release(codec, &mut partial);
                    } else {
                        release(codec, &mut partial.keys);
                    }
                }
            }
        }
    }
}
