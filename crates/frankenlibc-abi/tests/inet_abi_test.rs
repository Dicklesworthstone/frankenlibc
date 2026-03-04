//! ABI integration tests for inet_abi native implementations.
//!
//! Covers: htons, htonl, ntohs, ntohl, inet_pton, inet_ntop, inet_aton,
//! inet_ntoa, inet_addr, if_nametoindex, if_indextoname, if_nameindex,
//! if_freenameindex, getservbyname_r, getservbyport_r.

#![allow(unsafe_code)]

use std::ffi::{c_char, c_int, c_void, CStr, CString};

unsafe extern "C" {
    fn htons(hostshort: u16) -> u16;
    fn htonl(hostlong: u32) -> u32;
    fn ntohs(netshort: u16) -> u16;
    fn ntohl(netlong: u32) -> u32;
    fn inet_pton(af: c_int, src: *const c_char, dst: *mut c_void) -> c_int;
    fn inet_ntop(af: c_int, src: *const c_void, dst: *mut c_char, size: u32) -> *const c_char;
    fn inet_aton(cp: *const c_char, inp: *mut u32) -> c_int;
    fn inet_ntoa(addr: u32) -> *const c_char;
    fn inet_addr(cp: *const c_char) -> u32;
    fn if_nametoindex(ifname: *const c_char) -> libc::c_uint;
    fn if_indextoname(ifindex: libc::c_uint, ifname: *mut c_char) -> *mut c_char;
    fn if_nameindex() -> *mut c_void;
    fn if_freenameindex(ptr: *mut c_void);
    fn getservbyname_r(
        name: *const c_char,
        proto: *const c_char,
        result_buf: *mut c_void,
        buf: *mut c_char,
        buflen: usize,
        result: *mut *mut c_void,
    ) -> c_int;
    fn getservbyport_r(
        port: c_int,
        proto: *const c_char,
        result_buf: *mut c_void,
        buf: *mut c_char,
        buflen: usize,
        result: *mut *mut c_void,
    ) -> c_int;
}

const AF_INET: c_int = 2;
const AF_INET6: c_int = 10;
const INADDR_NONE: u32 = 0xFFFF_FFFF;

// ---------------------------------------------------------------------------
// htons / htonl / ntohs / ntohl — byte order conversions
// ---------------------------------------------------------------------------

#[test]
fn htons_converts_to_big_endian() {
    let result = unsafe { htons(0x1234) };
    assert_eq!(result, 0x1234u16.to_be());
}

#[test]
fn htons_zero() {
    assert_eq!(unsafe { htons(0) }, 0);
}

#[test]
fn htons_max() {
    let result = unsafe { htons(0xFFFF) };
    assert_eq!(result, 0xFFFFu16.to_be());
}

#[test]
fn htonl_converts_to_big_endian() {
    let result = unsafe { htonl(0x12345678) };
    assert_eq!(result, 0x12345678u32.to_be());
}

#[test]
fn htonl_zero() {
    assert_eq!(unsafe { htonl(0) }, 0);
}

#[test]
fn htonl_max() {
    let result = unsafe { htonl(0xFFFFFFFF) };
    assert_eq!(result, 0xFFFFFFFFu32.to_be());
}

#[test]
fn ntohs_converts_from_big_endian() {
    let net = 0x1234u16.to_be();
    assert_eq!(unsafe { ntohs(net) }, 0x1234);
}

#[test]
fn ntohl_converts_from_big_endian() {
    let net = 0x12345678u32.to_be();
    assert_eq!(unsafe { ntohl(net) }, 0x12345678);
}

#[test]
fn htons_ntohs_roundtrip() {
    for val in [0u16, 1, 80, 443, 8080, 0xFFFF] {
        let net = unsafe { htons(val) };
        assert_eq!(unsafe { ntohs(net) }, val);
    }
}

#[test]
fn htonl_ntohl_roundtrip() {
    for val in [0u32, 1, 0x7F000001, 0xC0A80001, 0xFFFFFFFF] {
        let net = unsafe { htonl(val) };
        assert_eq!(unsafe { ntohl(net) }, val);
    }
}

// ---------------------------------------------------------------------------
// inet_pton tests
// ---------------------------------------------------------------------------

#[test]
fn inet_pton_ipv4_loopback() {
    let src = CString::new("127.0.0.1").unwrap();
    let mut addr = [0u8; 4];
    let rc = unsafe { inet_pton(AF_INET, src.as_ptr(), addr.as_mut_ptr().cast()) };
    assert_eq!(rc, 1);
    assert_eq!(addr, [127, 0, 0, 1]);
}

#[test]
fn inet_pton_ipv4_zeros() {
    let src = CString::new("0.0.0.0").unwrap();
    let mut addr = [0xFFu8; 4];
    let rc = unsafe { inet_pton(AF_INET, src.as_ptr(), addr.as_mut_ptr().cast()) };
    assert_eq!(rc, 1);
    assert_eq!(addr, [0, 0, 0, 0]);
}

#[test]
fn inet_pton_ipv4_broadcast() {
    let src = CString::new("255.255.255.255").unwrap();
    let mut addr = [0u8; 4];
    let rc = unsafe { inet_pton(AF_INET, src.as_ptr(), addr.as_mut_ptr().cast()) };
    assert_eq!(rc, 1);
    assert_eq!(addr, [255, 255, 255, 255]);
}

#[test]
fn inet_pton_ipv4_private() {
    let src = CString::new("192.168.1.1").unwrap();
    let mut addr = [0u8; 4];
    let rc = unsafe { inet_pton(AF_INET, src.as_ptr(), addr.as_mut_ptr().cast()) };
    assert_eq!(rc, 1);
    assert_eq!(addr, [192, 168, 1, 1]);
}

#[test]
fn inet_pton_ipv4_invalid_returns_zero() {
    let src = CString::new("not.an.ip").unwrap();
    let mut addr = [0u8; 4];
    let rc = unsafe { inet_pton(AF_INET, src.as_ptr(), addr.as_mut_ptr().cast()) };
    assert_eq!(rc, 0);
}

#[test]
fn inet_pton_ipv4_empty_returns_zero() {
    let src = CString::new("").unwrap();
    let mut addr = [0u8; 4];
    let rc = unsafe { inet_pton(AF_INET, src.as_ptr(), addr.as_mut_ptr().cast()) };
    assert_eq!(rc, 0);
}

#[test]
fn inet_pton_ipv6_loopback() {
    let src = CString::new("::1").unwrap();
    let mut addr = [0u8; 16];
    let rc = unsafe { inet_pton(AF_INET6, src.as_ptr(), addr.as_mut_ptr().cast()) };
    assert_eq!(rc, 1);
    let mut expected = [0u8; 16];
    expected[15] = 1;
    assert_eq!(addr, expected);
}

#[test]
fn inet_pton_ipv6_all_zeros() {
    let src = CString::new("::").unwrap();
    let mut addr = [0xFFu8; 16];
    let rc = unsafe { inet_pton(AF_INET6, src.as_ptr(), addr.as_mut_ptr().cast()) };
    assert_eq!(rc, 1);
    assert_eq!(addr, [0u8; 16]);
}

#[test]
fn inet_pton_ipv6_full() {
    let src = CString::new("2001:0db8:85a3:0000:0000:8a2e:0370:7334").unwrap();
    let mut addr = [0u8; 16];
    let rc = unsafe { inet_pton(AF_INET6, src.as_ptr(), addr.as_mut_ptr().cast()) };
    assert_eq!(rc, 1);
    assert_eq!(addr[0..2], [0x20, 0x01]);
    assert_eq!(addr[2..4], [0x0d, 0xb8]);
}

#[test]
fn inet_pton_ipv6_compressed() {
    let src = CString::new("fe80::1").unwrap();
    let mut addr = [0u8; 16];
    let rc = unsafe { inet_pton(AF_INET6, src.as_ptr(), addr.as_mut_ptr().cast()) };
    assert_eq!(rc, 1);
    assert_eq!(addr[0..2], [0xfe, 0x80]);
    assert_eq!(addr[15], 1);
}

#[test]
fn inet_pton_bad_family_returns_neg1() {
    let src = CString::new("127.0.0.1").unwrap();
    let mut addr = [0u8; 4];
    let rc = unsafe { inet_pton(99, src.as_ptr(), addr.as_mut_ptr().cast()) };
    assert_eq!(rc, -1);
}

// ---------------------------------------------------------------------------
// inet_ntop tests
// ---------------------------------------------------------------------------

#[test]
fn inet_ntop_ipv4_loopback() {
    let addr: [u8; 4] = [127, 0, 0, 1];
    let mut buf = [0u8; 16];
    let ret = unsafe {
        inet_ntop(
            AF_INET,
            addr.as_ptr().cast(),
            buf.as_mut_ptr().cast(),
            buf.len() as u32,
        )
    };
    assert!(!ret.is_null());
    let s = unsafe { CStr::from_ptr(ret) };
    assert_eq!(s.to_bytes(), b"127.0.0.1");
}

#[test]
fn inet_ntop_ipv4_zeros() {
    let addr: [u8; 4] = [0, 0, 0, 0];
    let mut buf = [0u8; 16];
    let ret = unsafe {
        inet_ntop(
            AF_INET,
            addr.as_ptr().cast(),
            buf.as_mut_ptr().cast(),
            buf.len() as u32,
        )
    };
    assert!(!ret.is_null());
    let s = unsafe { CStr::from_ptr(ret) };
    assert_eq!(s.to_bytes(), b"0.0.0.0");
}

#[test]
fn inet_ntop_ipv4_broadcast() {
    let addr: [u8; 4] = [255, 255, 255, 255];
    let mut buf = [0u8; 16];
    let ret = unsafe {
        inet_ntop(
            AF_INET,
            addr.as_ptr().cast(),
            buf.as_mut_ptr().cast(),
            buf.len() as u32,
        )
    };
    assert!(!ret.is_null());
    let s = unsafe { CStr::from_ptr(ret) };
    assert_eq!(s.to_bytes(), b"255.255.255.255");
}

#[test]
fn inet_ntop_ipv4_buffer_too_small_returns_null() {
    let addr: [u8; 4] = [192, 168, 1, 1];
    let mut buf = [0u8; 4]; // Too small for "192.168.1.1\0"
    let ret = unsafe {
        inet_ntop(
            AF_INET,
            addr.as_ptr().cast(),
            buf.as_mut_ptr().cast(),
            buf.len() as u32,
        )
    };
    assert!(ret.is_null());
}

#[test]
fn inet_ntop_ipv6_loopback() {
    let mut addr = [0u8; 16];
    addr[15] = 1;
    let mut buf = [0u8; 46]; // INET6_ADDRSTRLEN
    let ret = unsafe {
        inet_ntop(
            AF_INET6,
            addr.as_ptr().cast(),
            buf.as_mut_ptr().cast(),
            buf.len() as u32,
        )
    };
    assert!(!ret.is_null());
    let s = unsafe { CStr::from_ptr(ret) };
    assert_eq!(s.to_bytes(), b"::1");
}

#[test]
fn inet_ntop_ipv6_all_zeros() {
    let addr = [0u8; 16];
    let mut buf = [0u8; 46];
    let ret = unsafe {
        inet_ntop(
            AF_INET6,
            addr.as_ptr().cast(),
            buf.as_mut_ptr().cast(),
            buf.len() as u32,
        )
    };
    assert!(!ret.is_null());
    let s = unsafe { CStr::from_ptr(ret) };
    assert_eq!(s.to_bytes(), b"::");
}

#[test]
fn inet_ntop_bad_family_returns_null() {
    let addr: [u8; 4] = [127, 0, 0, 1];
    let mut buf = [0u8; 16];
    let ret = unsafe {
        inet_ntop(
            99,
            addr.as_ptr().cast(),
            buf.as_mut_ptr().cast(),
            buf.len() as u32,
        )
    };
    assert!(ret.is_null());
}

// ---------------------------------------------------------------------------
// inet_pton + inet_ntop roundtrip
// ---------------------------------------------------------------------------

#[test]
fn inet_pton_ntop_ipv4_roundtrip() {
    let addrs = ["10.0.0.1", "172.16.0.1", "192.168.1.100", "8.8.8.8"];
    for &input in &addrs {
        let src = CString::new(input).unwrap();
        let mut binary = [0u8; 4];
        let rc = unsafe { inet_pton(AF_INET, src.as_ptr(), binary.as_mut_ptr().cast()) };
        assert_eq!(rc, 1, "inet_pton failed for {input}");

        let mut buf = [0u8; 16];
        let ret = unsafe {
            inet_ntop(
                AF_INET,
                binary.as_ptr().cast(),
                buf.as_mut_ptr().cast(),
                buf.len() as u32,
            )
        };
        assert!(!ret.is_null(), "inet_ntop failed for {input}");
        let s = unsafe { CStr::from_ptr(ret) };
        assert_eq!(s.to_bytes(), input.as_bytes());
    }
}

#[test]
fn inet_pton_ntop_ipv6_roundtrip() {
    // Canonical (compressed) forms
    let addrs = ["::1", "fe80::1", "::"];
    for &input in &addrs {
        let src = CString::new(input).unwrap();
        let mut binary = [0u8; 16];
        let rc = unsafe { inet_pton(AF_INET6, src.as_ptr(), binary.as_mut_ptr().cast()) };
        assert_eq!(rc, 1, "inet_pton failed for {input}");

        let mut buf = [0u8; 46];
        let ret = unsafe {
            inet_ntop(
                AF_INET6,
                binary.as_ptr().cast(),
                buf.as_mut_ptr().cast(),
                buf.len() as u32,
            )
        };
        assert!(!ret.is_null(), "inet_ntop failed for {input}");
        let s = unsafe { CStr::from_ptr(ret) };
        assert_eq!(s.to_bytes(), input.as_bytes());
    }
}

// ---------------------------------------------------------------------------
// inet_aton tests
// ---------------------------------------------------------------------------

#[test]
fn inet_aton_loopback() {
    let src = CString::new("127.0.0.1").unwrap();
    let mut addr: u32 = 0;
    let rc = unsafe { inet_aton(src.as_ptr(), &mut addr) };
    assert_eq!(rc, 1);
    let bytes = addr.to_ne_bytes();
    assert_eq!(bytes, [127, 0, 0, 1]);
}

#[test]
fn inet_aton_zeros() {
    let src = CString::new("0.0.0.0").unwrap();
    let mut addr: u32 = 0xDEADBEEF;
    let rc = unsafe { inet_aton(src.as_ptr(), &mut addr) };
    assert_eq!(rc, 1);
    assert_eq!(addr, 0);
}

#[test]
fn inet_aton_broadcast() {
    let src = CString::new("255.255.255.255").unwrap();
    let mut addr: u32 = 0;
    let rc = unsafe { inet_aton(src.as_ptr(), &mut addr) };
    assert_eq!(rc, 1);
    let bytes = addr.to_ne_bytes();
    assert_eq!(bytes, [255, 255, 255, 255]);
}

#[test]
fn inet_aton_invalid_returns_zero() {
    let src = CString::new("garbage").unwrap();
    let mut addr: u32 = 0;
    let rc = unsafe { inet_aton(src.as_ptr(), &mut addr) };
    assert_eq!(rc, 0);
}

#[test]
fn inet_aton_empty_returns_zero() {
    let src = CString::new("").unwrap();
    let mut addr: u32 = 0;
    let rc = unsafe { inet_aton(src.as_ptr(), &mut addr) };
    assert_eq!(rc, 0);
}

// ---------------------------------------------------------------------------
// inet_ntoa tests
// ---------------------------------------------------------------------------

#[test]
fn inet_ntoa_loopback() {
    // 127.0.0.1 in network byte order
    let addr = u32::from_ne_bytes([127, 0, 0, 1]);
    let ptr = unsafe { inet_ntoa(addr) };
    assert!(!ptr.is_null());
    let s = unsafe { CStr::from_ptr(ptr) };
    assert_eq!(s.to_bytes(), b"127.0.0.1");
}

#[test]
fn inet_ntoa_zeros() {
    let ptr = unsafe { inet_ntoa(0) };
    assert!(!ptr.is_null());
    let s = unsafe { CStr::from_ptr(ptr) };
    assert_eq!(s.to_bytes(), b"0.0.0.0");
}

#[test]
fn inet_ntoa_broadcast() {
    let addr = u32::from_ne_bytes([255, 255, 255, 255]);
    let ptr = unsafe { inet_ntoa(addr) };
    assert!(!ptr.is_null());
    let s = unsafe { CStr::from_ptr(ptr) };
    assert_eq!(s.to_bytes(), b"255.255.255.255");
}

#[test]
fn inet_ntoa_private_class_c() {
    let addr = u32::from_ne_bytes([192, 168, 1, 100]);
    let ptr = unsafe { inet_ntoa(addr) };
    assert!(!ptr.is_null());
    let s = unsafe { CStr::from_ptr(ptr) };
    assert_eq!(s.to_bytes(), b"192.168.1.100");
}

// ---------------------------------------------------------------------------
// inet_addr tests
// ---------------------------------------------------------------------------

#[test]
fn inet_addr_loopback() {
    let src = CString::new("127.0.0.1").unwrap();
    let result = unsafe { inet_addr(src.as_ptr()) };
    assert_ne!(result, INADDR_NONE);
    let bytes = result.to_ne_bytes();
    assert_eq!(bytes, [127, 0, 0, 1]);
}

#[test]
fn inet_addr_zeros() {
    let src = CString::new("0.0.0.0").unwrap();
    let result = unsafe { inet_addr(src.as_ptr()) };
    assert_eq!(result, 0);
}

#[test]
fn inet_addr_invalid_returns_none() {
    let src = CString::new("not_an_address").unwrap();
    let result = unsafe { inet_addr(src.as_ptr()) };
    assert_eq!(result, INADDR_NONE);
}

#[test]
fn inet_addr_empty_returns_none() {
    let src = CString::new("").unwrap();
    let result = unsafe { inet_addr(src.as_ptr()) };
    assert_eq!(result, INADDR_NONE);
}

#[test]
fn inet_addr_private_class_a() {
    let src = CString::new("10.1.2.3").unwrap();
    let result = unsafe { inet_addr(src.as_ptr()) };
    assert_ne!(result, INADDR_NONE);
    let bytes = result.to_ne_bytes();
    assert_eq!(bytes, [10, 1, 2, 3]);
}

// ---------------------------------------------------------------------------
// inet_aton + inet_addr consistency
// ---------------------------------------------------------------------------

#[test]
fn inet_aton_inet_addr_agree() {
    let addrs = ["10.0.0.1", "172.16.0.1", "192.168.1.1", "8.8.4.4"];
    for &input in &addrs {
        let src = CString::new(input).unwrap();
        let mut aton_result: u32 = 0;
        let rc = unsafe { inet_aton(src.as_ptr(), &mut aton_result) };
        assert_eq!(rc, 1, "inet_aton failed for {input}");

        let addr_result = unsafe { inet_addr(src.as_ptr()) };
        assert_eq!(
            aton_result, addr_result,
            "inet_aton and inet_addr disagree for {input}"
        );
    }
}

// ---------------------------------------------------------------------------
// if_nametoindex / if_indextoname tests
// ---------------------------------------------------------------------------

#[test]
fn if_nametoindex_lo_returns_one() {
    let name = CString::new("lo").unwrap();
    let idx = unsafe { if_nametoindex(name.as_ptr()) };
    assert_eq!(idx, 1, "loopback interface should have index 1");
}

#[test]
fn if_nametoindex_nonexistent_returns_zero() {
    let name = CString::new("nonexistent_iface_xyz").unwrap();
    let idx = unsafe { if_nametoindex(name.as_ptr()) };
    assert_eq!(idx, 0);
}

// Note: if_nametoindex(NULL) segfaults in glibc.
// Our native impl handles NULL safely, but in test mode we link against glibc.

#[test]
fn if_indextoname_one_returns_lo() {
    let mut buf = [0u8; 16]; // IFNAMSIZ = 16
    let ret = unsafe { if_indextoname(1, buf.as_mut_ptr().cast()) };
    assert!(!ret.is_null(), "if_indextoname(1) should return lo");
    let name = unsafe { CStr::from_ptr(ret) };
    assert_eq!(name.to_bytes(), b"lo");
}

#[test]
fn if_indextoname_zero_returns_null() {
    let mut buf = [0u8; 16];
    let ret = unsafe { if_indextoname(0, buf.as_mut_ptr().cast()) };
    assert!(ret.is_null(), "if_indextoname(0) should return null");
}

#[test]
fn if_indextoname_huge_returns_null() {
    let mut buf = [0u8; 16];
    let ret = unsafe { if_indextoname(0xFFFFFFFF, buf.as_mut_ptr().cast()) };
    assert!(ret.is_null());
}

#[test]
fn if_nametoindex_indextoname_roundtrip() {
    let name = CString::new("lo").unwrap();
    let idx = unsafe { if_nametoindex(name.as_ptr()) };
    assert!(idx > 0);

    let mut buf = [0u8; 16];
    let ret = unsafe { if_indextoname(idx, buf.as_mut_ptr().cast()) };
    assert!(!ret.is_null());
    let result_name = unsafe { CStr::from_ptr(ret) };
    assert_eq!(result_name.to_bytes(), b"lo");
}

// ---------------------------------------------------------------------------
// if_nameindex / if_freenameindex tests
// ---------------------------------------------------------------------------

/// struct if_nameindex layout on x86_64:
/// { if_index: u32, [pad 4], if_name: *mut c_char }
const IF_NAMEINDEX_ENTRY_SIZE: usize = 16;

#[test]
fn if_nameindex_returns_at_least_lo() {
    let array = unsafe { if_nameindex() };
    assert!(!array.is_null(), "if_nameindex should not return NULL");

    let base = array as *const u8;
    let mut count = 0;
    let mut found_lo = false;

    loop {
        let entry = unsafe { base.add(count * IF_NAMEINDEX_ENTRY_SIZE) };
        let idx = unsafe { *(entry as *const u32) };
        let name_ptr = unsafe { *(entry.add(8) as *const *const c_char) };

        if idx == 0 && name_ptr.is_null() {
            break; // Sentinel
        }

        assert!(
            !name_ptr.is_null(),
            "interface name pointer should not be null"
        );
        let name = unsafe { CStr::from_ptr(name_ptr) };
        let name_bytes = name.to_bytes();
        assert!(!name_bytes.is_empty(), "interface name should not be empty");

        if name_bytes == b"lo" {
            found_lo = true;
            assert_eq!(idx, 1, "loopback interface should have index 1");
        }

        count += 1;
        if count > 256 {
            break; // Safety limit
        }
    }

    assert!(count >= 1, "should find at least 1 interface, got {count}");
    assert!(found_lo, "should find loopback interface 'lo'");

    unsafe { if_freenameindex(array) };
}

// Note: if_freenameindex(NULL) segfaults in glibc.
// Our native impl handles NULL safely, but in test mode we link against glibc.
// Skipping NULL safety test for conformance.

// ---------------------------------------------------------------------------
// getservbyname_r tests
// ---------------------------------------------------------------------------

/// Helper: allocate a servent result buffer and string buffer for getservby*_r.
fn servent_buffers() -> (Vec<u8>, Vec<u8>) {
    // libc::servent is ~32 bytes on x86_64
    let result_buf = vec![0u8; 64];
    let buf = vec![0u8; 256];
    (result_buf, buf)
}

#[test]
fn getservbyname_r_finds_ssh() {
    let name = CString::new("ssh").unwrap();
    let proto = CString::new("tcp").unwrap();
    let (mut result_buf, mut buf) = servent_buffers();
    let mut result: *mut c_void = std::ptr::null_mut();

    let rc = unsafe {
        getservbyname_r(
            name.as_ptr(),
            proto.as_ptr(),
            result_buf.as_mut_ptr().cast(),
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut result,
        )
    };
    assert_eq!(rc, 0, "getservbyname_r should find ssh/tcp");
    assert!(!result.is_null());

    let servent = unsafe { &*(result as *const libc::servent) };
    let port_host = u16::from_be(servent.s_port as u16);
    assert_eq!(port_host, 22, "ssh should be port 22");

    let sname = unsafe { CStr::from_ptr(servent.s_name) };
    assert_eq!(sname.to_bytes(), b"ssh");
}

#[test]
fn getservbyname_r_finds_http() {
    let name = CString::new("http").unwrap();
    let proto = CString::new("tcp").unwrap();
    let (mut result_buf, mut buf) = servent_buffers();
    let mut result: *mut c_void = std::ptr::null_mut();

    let rc = unsafe {
        getservbyname_r(
            name.as_ptr(),
            proto.as_ptr(),
            result_buf.as_mut_ptr().cast(),
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut result,
        )
    };
    assert_eq!(rc, 0);
    assert!(!result.is_null());

    let servent = unsafe { &*(result as *const libc::servent) };
    let port_host = u16::from_be(servent.s_port as u16);
    assert_eq!(port_host, 80);
}

#[test]
fn getservbyname_r_no_proto_filter() {
    let name = CString::new("ssh").unwrap();
    let (mut result_buf, mut buf) = servent_buffers();
    let mut result: *mut c_void = std::ptr::null_mut();

    let rc = unsafe {
        getservbyname_r(
            name.as_ptr(),
            std::ptr::null(),
            result_buf.as_mut_ptr().cast(),
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut result,
        )
    };
    assert_eq!(rc, 0, "getservbyname_r with no proto should find ssh");
    assert!(!result.is_null());
}

#[test]
fn getservbyname_r_nonexistent_service() {
    let name = CString::new("zzz_no_such_service_ever").unwrap();
    let proto = CString::new("tcp").unwrap();
    let (mut result_buf, mut buf) = servent_buffers();
    let mut result: *mut c_void = std::ptr::null_mut();

    let rc = unsafe {
        getservbyname_r(
            name.as_ptr(),
            proto.as_ptr(),
            result_buf.as_mut_ptr().cast(),
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut result,
        )
    };
    // glibc may return nonzero error OR return 0 with null result
    assert!(
        rc != 0 || result.is_null(),
        "nonexistent service should not succeed"
    );
}

#[test]
fn getservbyname_r_tiny_buffer() {
    let name = CString::new("ssh").unwrap();
    let proto = CString::new("tcp").unwrap();
    let mut result_buf = vec![0u8; 64];
    let mut buf = vec![0u8; 2]; // Too small
    let mut result: *mut c_void = std::ptr::null_mut();

    let rc = unsafe {
        getservbyname_r(
            name.as_ptr(),
            proto.as_ptr(),
            result_buf.as_mut_ptr().cast(),
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut result,
        )
    };
    assert_eq!(rc, libc::ERANGE, "tiny buffer should return ERANGE");
}

// ---------------------------------------------------------------------------
// getservbyport_r tests
// ---------------------------------------------------------------------------

#[test]
fn getservbyport_r_finds_port_22() {
    let proto = CString::new("tcp").unwrap();
    let port_net = (22u16).to_be() as c_int; // network byte order (htons)
    let (mut result_buf, mut buf) = servent_buffers();
    let mut result: *mut c_void = std::ptr::null_mut();

    let rc = unsafe {
        getservbyport_r(
            port_net,
            proto.as_ptr(),
            result_buf.as_mut_ptr().cast(),
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut result,
        )
    };
    assert_eq!(rc, 0, "getservbyport_r should find port 22/tcp");
    assert!(!result.is_null());

    let servent = unsafe { &*(result as *const libc::servent) };
    let sname = unsafe { CStr::from_ptr(servent.s_name) };
    assert_eq!(sname.to_bytes(), b"ssh");
}

#[test]
fn getservbyport_r_finds_port_80() {
    let proto = CString::new("tcp").unwrap();
    let port_net = (80u16).to_be() as c_int;
    let (mut result_buf, mut buf) = servent_buffers();
    let mut result: *mut c_void = std::ptr::null_mut();

    let rc = unsafe {
        getservbyport_r(
            port_net as c_int,
            proto.as_ptr(),
            result_buf.as_mut_ptr().cast(),
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut result,
        )
    };
    assert_eq!(rc, 0);
    assert!(!result.is_null());

    let servent = unsafe { &*(result as *const libc::servent) };
    let sname = unsafe { CStr::from_ptr(servent.s_name) };
    assert_eq!(sname.to_bytes(), b"http");
}

#[test]
fn getservbyport_r_nonexistent_port() {
    let proto = CString::new("tcp").unwrap();
    let port_net = (59999u16).to_be() as c_int;
    let (mut result_buf, mut buf) = servent_buffers();
    let mut result: *mut c_void = std::ptr::null_mut();

    let rc = unsafe {
        getservbyport_r(
            port_net,
            proto.as_ptr(),
            result_buf.as_mut_ptr().cast(),
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut result,
        )
    };
    // glibc may return nonzero error OR return 0 with null result
    assert!(
        rc != 0 || result.is_null(),
        "nonexistent port should not succeed"
    );
}
