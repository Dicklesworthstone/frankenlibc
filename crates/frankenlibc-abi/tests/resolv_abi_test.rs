#![cfg(target_os = "linux")]

//! Integration tests for resolver ABI entrypoints (`<netdb.h>`).
//!
//! Covers: getaddrinfo, freeaddrinfo, getnameinfo, gai_strerror,
//! gethostbyname, gethostbyname_r, gethostbyaddr, getservbyname,
//! getservbyport, getprotobyname, getprotobynumber, __h_errno_location.

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::mem;
use std::ptr;

use frankenlibc_abi::inet_abi;
use frankenlibc_abi::resolv_abi;

const NO_RECOVERY_ERRNO: i32 = 3;
const HOST_NOT_FOUND_ERRNO: i32 = 1;

fn services_alias_fixture() -> Option<(CString, CString, u16)> {
    let content = std::fs::read("/etc/services").ok()?;
    let entry = content
        .split(|&b| b == b'\n')
        .filter_map(frankenlibc_core::resolv::parse_services_line)
        .find(|entry| {
            entry.protocol.eq_ignore_ascii_case(b"tcp")
                && entry
                    .aliases
                    .iter()
                    .any(|alias| alias.iter().all(u8::is_ascii_alphanumeric))
        })?;
    let alias = entry
        .aliases
        .iter()
        .find(|alias| alias.iter().all(u8::is_ascii_alphanumeric))?;
    Some((
        CString::new(alias.as_slice()).ok()?,
        CString::new(entry.protocol.clone()).ok()?,
        entry.port,
    ))
}

// ===========================================================================
// gethostbyname
// ===========================================================================

#[test]
fn gethostbyname_numeric_ipv4_returns_hostent() {
    let query = CString::new("127.0.0.1").expect("query should be valid C string");
    let ptr = unsafe { resolv_abi::gethostbyname(query.as_ptr()) };
    assert!(!ptr.is_null());

    let hostent = unsafe { &*(ptr as *const libc::hostent) };
    assert_eq!(hostent.h_addrtype, libc::AF_INET);
    assert_eq!(hostent.h_length, 4);
    assert!(!hostent.h_addr_list.is_null());

    let first_addr_ptr = unsafe { *hostent.h_addr_list };
    assert!(!first_addr_ptr.is_null());
    let octets = unsafe { std::slice::from_raw_parts(first_addr_ptr.cast::<u8>(), 4) };
    assert_eq!(octets, [127, 0, 0, 1]);
}

#[test]
fn gethostbyname_unknown_host_returns_null() {
    let query = CString::new("missing.example.invalid").expect("query should be valid C string");
    let ptr = unsafe { resolv_abi::gethostbyname(query.as_ptr()) };
    assert!(ptr.is_null());
}

#[test]
fn gethostbyname_unknown_host_sets_thread_local_h_errno() {
    let query = CString::new("missing.example.invalid").expect("query should be valid C string");
    unsafe {
        *resolv_abi::__h_errno_location() = 0;
    }

    let ptr = unsafe { resolv_abi::gethostbyname(query.as_ptr()) };
    assert!(ptr.is_null());
    assert_eq!(
        unsafe { *resolv_abi::__h_errno_location() },
        HOST_NOT_FOUND_ERRNO
    );
}

// ===========================================================================
// gethostbyname_r
// ===========================================================================

#[test]
fn gethostbyname_r_numeric_ipv4_populates_result() {
    let query = CString::new("10.20.30.40").expect("query should be valid C string");
    let mut hostent: libc::hostent = unsafe { mem::zeroed() };
    let mut scratch = [0i8; 256];
    let mut result_ptr: *mut c_void = ptr::null_mut();
    let mut h_errno = -1;

    let rc = unsafe {
        inet_abi::gethostbyname_r(
            query.as_ptr(),
            (&mut hostent as *mut libc::hostent).cast::<c_void>(),
            scratch.as_mut_ptr(),
            scratch.len(),
            &mut result_ptr,
            &mut h_errno,
        )
    };
    assert_eq!(rc, 0);
    assert_eq!(h_errno, 0);
    assert_eq!(
        result_ptr,
        (&mut hostent as *mut libc::hostent).cast::<c_void>()
    );
    assert_eq!(hostent.h_addrtype, libc::AF_INET);
    assert_eq!(hostent.h_length, 4);
    assert!(!hostent.h_addr_list.is_null());

    let first_addr_ptr = unsafe { *hostent.h_addr_list };
    assert!(!first_addr_ptr.is_null());
    let octets = unsafe { std::slice::from_raw_parts(first_addr_ptr.cast::<u8>(), 4) };
    assert_eq!(octets, [10, 20, 30, 40]);
}

#[test]
fn gethostbyname_r_small_buffer_returns_erange() {
    let query = CString::new("127.0.0.1").expect("query should be valid C string");
    let mut hostent: libc::hostent = unsafe { mem::zeroed() };
    let mut scratch = [0i8; 4];
    let mut result_ptr: *mut c_void = ptr::null_mut();
    let mut h_errno = -1;

    let rc = unsafe {
        inet_abi::gethostbyname_r(
            query.as_ptr(),
            (&mut hostent as *mut libc::hostent).cast::<c_void>(),
            scratch.as_mut_ptr(),
            scratch.len(),
            &mut result_ptr,
            &mut h_errno,
        )
    };
    assert_eq!(rc, libc::ERANGE);
    assert!(result_ptr.is_null());
    assert_eq!(h_errno, NO_RECOVERY_ERRNO);
}

#[test]
fn gethostbyname_r_unknown_host_returns_enoent() {
    let query = CString::new("missing.example.invalid").expect("query should be valid C string");
    let mut hostent: libc::hostent = unsafe { mem::zeroed() };
    let mut scratch = [0i8; 256];
    let mut result_ptr: *mut c_void = ptr::null_mut();
    let mut h_errno = -1;

    let rc = unsafe {
        inet_abi::gethostbyname_r(
            query.as_ptr(),
            (&mut hostent as *mut libc::hostent).cast::<c_void>(),
            scratch.as_mut_ptr(),
            scratch.len(),
            &mut result_ptr,
            &mut h_errno,
        )
    };
    assert_eq!(rc, libc::ENOENT);
    assert!(result_ptr.is_null());
    assert_eq!(h_errno, HOST_NOT_FOUND_ERRNO);
}

// ===========================================================================
// gai_strerror
// ===========================================================================

#[test]
fn gai_strerror_success_code_returns_success() {
    let msg = unsafe { resolv_abi::gai_strerror(0) };
    assert!(!msg.is_null());
    let s = unsafe { CStr::from_ptr(msg) }.to_string_lossy();
    assert!(
        s.contains("uccess"),
        "gai_strerror(0) should mention success, got: {s}"
    );
}

#[test]
fn gai_strerror_eai_noname_returns_message() {
    let msg = unsafe { resolv_abi::gai_strerror(libc::EAI_NONAME) };
    assert!(!msg.is_null());
    let s = unsafe { CStr::from_ptr(msg) }.to_string_lossy();
    assert!(
        !s.is_empty(),
        "gai_strerror(EAI_NONAME) should return non-empty string"
    );
}

#[test]
fn gai_strerror_eai_service_returns_message() {
    let msg = unsafe { resolv_abi::gai_strerror(libc::EAI_SERVICE) };
    assert!(!msg.is_null());
    let s = unsafe { CStr::from_ptr(msg) }.to_string_lossy();
    assert!(!s.is_empty());
}

#[test]
fn gai_strerror_eai_family_returns_message() {
    let msg = unsafe { resolv_abi::gai_strerror(libc::EAI_FAMILY) };
    assert!(!msg.is_null());
    let s = unsafe { CStr::from_ptr(msg) }.to_string_lossy();
    assert!(!s.is_empty());
}

#[test]
fn gai_strerror_unknown_code_returns_fallback() {
    let msg = unsafe { resolv_abi::gai_strerror(99999) };
    assert!(!msg.is_null());
    let s = unsafe { CStr::from_ptr(msg) }.to_string_lossy();
    assert!(!s.is_empty(), "unknown code should still return a string");
}

// ===========================================================================
// getaddrinfo / freeaddrinfo
// ===========================================================================

#[test]
fn getaddrinfo_numeric_ipv4_resolves() {
    let node = CString::new("127.0.0.1").unwrap();
    let service = CString::new("80").unwrap();
    let mut res: *mut libc::addrinfo = ptr::null_mut();

    let rc =
        unsafe { resolv_abi::getaddrinfo(node.as_ptr(), service.as_ptr(), ptr::null(), &mut res) };
    assert_eq!(rc, 0, "getaddrinfo should succeed for numeric IPv4");
    assert!(!res.is_null());

    let ai = unsafe { &*res };
    assert_eq!(ai.ai_family, libc::AF_INET);
    assert!(!ai.ai_addr.is_null());

    let sin = unsafe { &*(ai.ai_addr as *const libc::sockaddr_in) };
    assert_eq!(sin.sin_port, 80u16.to_be());

    unsafe { resolv_abi::freeaddrinfo(res) };
}

#[test]
fn getaddrinfo_numeric_ipv6_resolves() {
    let node = CString::new("::1").unwrap();
    let service = CString::new("443").unwrap();
    let mut hints: libc::addrinfo = unsafe { mem::zeroed() };
    hints.ai_family = libc::AF_INET6;
    let mut res: *mut libc::addrinfo = ptr::null_mut();

    let rc = unsafe { resolv_abi::getaddrinfo(node.as_ptr(), service.as_ptr(), &hints, &mut res) };
    assert_eq!(rc, 0, "getaddrinfo should succeed for numeric IPv6");
    assert!(!res.is_null());

    let ai = unsafe { &*res };
    assert_eq!(ai.ai_family, libc::AF_INET6);

    unsafe { resolv_abi::freeaddrinfo(res) };
}

#[test]
fn getaddrinfo_null_node_returns_unspecified() {
    let service = CString::new("8080").unwrap();
    let mut res: *mut libc::addrinfo = ptr::null_mut();

    let rc =
        unsafe { resolv_abi::getaddrinfo(ptr::null(), service.as_ptr(), ptr::null(), &mut res) };
    assert_eq!(
        rc, 0,
        "getaddrinfo(NULL node) should return unspecified address"
    );
    assert!(!res.is_null());

    unsafe { resolv_abi::freeaddrinfo(res) };
}

#[test]
fn getaddrinfo_null_service_uses_port_zero() {
    let node = CString::new("127.0.0.1").unwrap();
    let mut res: *mut libc::addrinfo = ptr::null_mut();

    let rc = unsafe { resolv_abi::getaddrinfo(node.as_ptr(), ptr::null(), ptr::null(), &mut res) };
    assert_eq!(rc, 0);
    assert!(!res.is_null());

    let ai = unsafe { &*res };
    let sin = unsafe { &*(ai.ai_addr as *const libc::sockaddr_in) };
    assert_eq!(sin.sin_port, 0);

    unsafe { resolv_abi::freeaddrinfo(res) };
}

#[test]
fn getaddrinfo_null_result_returns_error() {
    let node = CString::new("127.0.0.1").unwrap();
    let rc = unsafe {
        resolv_abi::getaddrinfo(node.as_ptr(), ptr::null(), ptr::null(), ptr::null_mut())
    };
    assert_ne!(rc, 0, "getaddrinfo with null result pointer should fail");
}

#[test]
fn getaddrinfo_nonexistent_host_returns_eai_noname() {
    let node = CString::new("nonexistent.invalid.test").unwrap();
    let mut res: *mut libc::addrinfo = ptr::null_mut();

    let rc = unsafe { resolv_abi::getaddrinfo(node.as_ptr(), ptr::null(), ptr::null(), &mut res) };
    assert_eq!(rc, libc::EAI_NONAME);
    assert!(res.is_null());
}

#[test]
fn freeaddrinfo_null_is_noop() {
    // Should not crash
    unsafe { resolv_abi::freeaddrinfo(ptr::null_mut()) };
}

// ===========================================================================
// getnameinfo
// ===========================================================================

#[test]
fn getnameinfo_ipv4_formats_numeric() {
    let sin = libc::sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: 80u16.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes([192, 168, 1, 1]),
        },
        sin_zero: [0; 8],
    };

    let mut host = [0u8; 64];
    let mut serv = [0u8; 16];

    let rc = unsafe {
        resolv_abi::getnameinfo(
            (&sin as *const libc::sockaddr_in).cast::<libc::sockaddr>(),
            mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            host.as_mut_ptr().cast::<c_char>(),
            host.len() as libc::socklen_t,
            serv.as_mut_ptr().cast::<c_char>(),
            serv.len() as libc::socklen_t,
            libc::NI_NUMERICHOST | libc::NI_NUMERICSERV,
        )
    };
    assert_eq!(rc, 0, "getnameinfo should succeed for IPv4");

    let host_str = unsafe { CStr::from_ptr(host.as_ptr().cast::<c_char>()) }.to_string_lossy();
    assert_eq!(host_str, "192.168.1.1");

    let serv_str = unsafe { CStr::from_ptr(serv.as_ptr().cast::<c_char>()) }.to_string_lossy();
    assert_eq!(serv_str, "80");
}

#[test]
fn getnameinfo_ipv6_formats_numeric() {
    let sin6 = libc::sockaddr_in6 {
        sin6_family: libc::AF_INET6 as u16,
        sin6_port: 443u16.to_be(),
        sin6_flowinfo: 0,
        sin6_addr: libc::in6_addr {
            s6_addr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        },
        sin6_scope_id: 0,
    };

    let mut host = [0u8; 64];
    let mut serv = [0u8; 16];

    let rc = unsafe {
        resolv_abi::getnameinfo(
            (&sin6 as *const libc::sockaddr_in6).cast::<libc::sockaddr>(),
            mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            host.as_mut_ptr().cast::<c_char>(),
            host.len() as libc::socklen_t,
            serv.as_mut_ptr().cast::<c_char>(),
            serv.len() as libc::socklen_t,
            libc::NI_NUMERICHOST | libc::NI_NUMERICSERV,
        )
    };
    assert_eq!(rc, 0, "getnameinfo should succeed for IPv6");

    let host_str = unsafe { CStr::from_ptr(host.as_ptr().cast::<c_char>()) }.to_string_lossy();
    assert_eq!(host_str, "::1");

    let serv_str = unsafe { CStr::from_ptr(serv.as_ptr().cast::<c_char>()) }.to_string_lossy();
    assert_eq!(serv_str, "443");
}

#[test]
fn getnameinfo_null_sockaddr_returns_error() {
    let mut host = [0u8; 64];
    let rc = unsafe {
        resolv_abi::getnameinfo(
            ptr::null(),
            0,
            host.as_mut_ptr().cast::<c_char>(),
            host.len() as libc::socklen_t,
            ptr::null_mut(),
            0,
            0,
        )
    };
    assert_ne!(rc, 0, "getnameinfo(NULL) should fail");
}

#[test]
fn getnameinfo_unsupported_family_returns_eai_family() {
    // Use AF_UNIX which is not supported by numeric getnameinfo
    let mut sa: libc::sockaddr = unsafe { mem::zeroed() };
    sa.sa_family = libc::AF_UNIX as u16;

    let mut host = [0u8; 64];
    let rc = unsafe {
        resolv_abi::getnameinfo(
            &sa,
            mem::size_of::<libc::sockaddr>() as libc::socklen_t,
            host.as_mut_ptr().cast::<c_char>(),
            host.len() as libc::socklen_t,
            ptr::null_mut(),
            0,
            0,
        )
    };
    assert_eq!(rc, libc::EAI_FAMILY);
}

// ===========================================================================
// gethostbyaddr
// ===========================================================================

#[test]
fn gethostbyaddr_localhost_may_resolve() {
    let addr: [u8; 4] = [127, 0, 0, 1];
    let ptr =
        unsafe { resolv_abi::gethostbyaddr(addr.as_ptr().cast::<c_void>(), 4, libc::AF_INET) };
    // /etc/hosts usually has 127.0.0.1 -> localhost
    // But we don't fail the test if it doesn't
    if !ptr.is_null() {
        let hostent = unsafe { &*(ptr as *const libc::hostent) };
        assert_eq!(hostent.h_addrtype, libc::AF_INET);
        assert_eq!(hostent.h_length, 4);
    }
}

#[test]
fn gethostbyaddr_null_returns_null() {
    let ptr = unsafe { resolv_abi::gethostbyaddr(ptr::null(), 4, libc::AF_INET) };
    assert!(ptr.is_null());
}

#[test]
fn gethostbyaddr_unsupported_af_returns_null() {
    let addr: [u8; 4] = [127, 0, 0, 1];
    let ptr = unsafe {
        resolv_abi::gethostbyaddr(
            addr.as_ptr().cast::<c_void>(),
            4,
            libc::AF_INET6, // IPv6 not supported for 4-byte addr
        )
    };
    assert!(ptr.is_null());
}

#[test]
fn gethostbyaddr_short_len_returns_null() {
    let addr: [u8; 4] = [127, 0, 0, 1];
    let ptr = unsafe {
        resolv_abi::gethostbyaddr(
            addr.as_ptr().cast::<c_void>(),
            2, // too short
            libc::AF_INET,
        )
    };
    assert!(ptr.is_null());
}

#[test]
fn gethostbyaddr_unsupported_af_sets_thread_local_h_errno() {
    let addr: [u8; 4] = [127, 0, 0, 1];
    unsafe {
        *resolv_abi::__h_errno_location() = 0;
    }

    let ptr =
        unsafe { resolv_abi::gethostbyaddr(addr.as_ptr().cast::<c_void>(), 4, libc::AF_INET6) };
    assert!(ptr.is_null());
    assert_eq!(
        unsafe { *resolv_abi::__h_errno_location() },
        HOST_NOT_FOUND_ERRNO
    );
}

// ===========================================================================
// getservbyname
// ===========================================================================

#[test]
fn getservbyname_ssh_resolves() {
    let name = CString::new("ssh").unwrap();
    let proto = CString::new("tcp").unwrap();
    let ptr = unsafe { resolv_abi::getservbyname(name.as_ptr(), proto.as_ptr()) };
    // /etc/services should have ssh/tcp = 22
    if !ptr.is_null() {
        let servent = unsafe { &*(ptr as *const libc::servent) };
        assert_eq!(u16::from_be(servent.s_port as u16), 22);
        assert!(!servent.s_name.is_null());
    }
}

#[test]
fn getservbyname_http_resolves() {
    let name = CString::new("http").unwrap();
    let proto = CString::new("tcp").unwrap();
    let ptr = unsafe { resolv_abi::getservbyname(name.as_ptr(), proto.as_ptr()) };
    if !ptr.is_null() {
        let servent = unsafe { &*(ptr as *const libc::servent) };
        assert_eq!(u16::from_be(servent.s_port as u16), 80);
    }
}

#[test]
fn getservbyname_null_name_returns_null() {
    let proto = CString::new("tcp").unwrap();
    let ptr = unsafe { resolv_abi::getservbyname(ptr::null(), proto.as_ptr()) };
    assert!(ptr.is_null());
}

#[test]
fn getservbyname_nonexistent_returns_null() {
    let name = CString::new("nonexistent_service_zzz").unwrap();
    let proto = CString::new("tcp").unwrap();
    let ptr = unsafe { resolv_abi::getservbyname(name.as_ptr(), proto.as_ptr()) };
    assert!(ptr.is_null());
}

#[test]
fn getservbyname_null_proto_resolves() {
    let name = CString::new("ssh").unwrap();
    let ptr = unsafe { resolv_abi::getservbyname(name.as_ptr(), ptr::null()) };
    // Should still find ssh without protocol filter
    if !ptr.is_null() {
        let servent = unsafe { &*(ptr as *const libc::servent) };
        assert_eq!(u16::from_be(servent.s_port as u16), 22);
    }
}

#[test]
fn getservbyname_alias_resolves_to_canonical_entry() {
    let Some((alias, proto, port)) = services_alias_fixture() else {
        return;
    };
    let ptr = unsafe { resolv_abi::getservbyname(alias.as_ptr(), proto.as_ptr()) };
    assert!(!ptr.is_null());

    let servent = unsafe { &*(ptr as *const libc::servent) };
    assert_eq!(u16::from_be(servent.s_port as u16), port);
    assert!(!servent.s_name.is_null());
}

// ===========================================================================
// getservbyport
// ===========================================================================

#[test]
fn getservbyport_22_resolves_ssh() {
    let port_net = (22u16).to_be() as c_int;
    let proto = CString::new("tcp").unwrap();
    let ptr = unsafe { resolv_abi::getservbyport(port_net, proto.as_ptr()) };
    if !ptr.is_null() {
        let servent = unsafe { &*(ptr as *const libc::servent) };
        let name = unsafe { CStr::from_ptr(servent.s_name) }.to_string_lossy();
        assert_eq!(name, "ssh");
    }
}

#[test]
fn getservbyport_80_resolves_http() {
    let port_net = (80u16).to_be() as c_int;
    let proto = CString::new("tcp").unwrap();
    let ptr = unsafe { resolv_abi::getservbyport(port_net, proto.as_ptr()) };
    if !ptr.is_null() {
        let servent = unsafe { &*(ptr as *const libc::servent) };
        let name = unsafe { CStr::from_ptr(servent.s_name) }.to_string_lossy();
        assert_eq!(name, "http");
    }
}

#[test]
fn getservbyport_nonexistent_returns_null() {
    let port_net = (59999u16).to_be() as c_int;
    let proto = CString::new("tcp").unwrap();
    let ptr = unsafe { resolv_abi::getservbyport(port_net, proto.as_ptr()) };
    assert!(ptr.is_null());
}

// ===========================================================================
// getprotobyname
// ===========================================================================

#[test]
fn getprotobyname_tcp_resolves() {
    let name = CString::new("tcp").unwrap();
    let ptr = unsafe { resolv_abi::getprotobyname(name.as_ptr()) };
    if !ptr.is_null() {
        let protoent = unsafe { &*(ptr as *const libc::protoent) };
        assert_eq!(protoent.p_proto, 6); // TCP = protocol 6
        assert!(!protoent.p_name.is_null());
    }
}

#[test]
fn getprotobyname_udp_resolves() {
    let name = CString::new("udp").unwrap();
    let ptr = unsafe { resolv_abi::getprotobyname(name.as_ptr()) };
    if !ptr.is_null() {
        let protoent = unsafe { &*(ptr as *const libc::protoent) };
        assert_eq!(protoent.p_proto, 17); // UDP = protocol 17
    }
}

#[test]
fn getprotobyname_icmp_resolves() {
    let name = CString::new("icmp").unwrap();
    let ptr = unsafe { resolv_abi::getprotobyname(name.as_ptr()) };
    if !ptr.is_null() {
        let protoent = unsafe { &*(ptr as *const libc::protoent) };
        assert_eq!(protoent.p_proto, 1); // ICMP = protocol 1
    }
}

#[test]
fn getprotobyname_null_returns_null() {
    let ptr = unsafe { resolv_abi::getprotobyname(ptr::null()) };
    assert!(ptr.is_null());
}

#[test]
fn getprotobyname_nonexistent_returns_null() {
    let name = CString::new("nonexistent_protocol_zzz").unwrap();
    let ptr = unsafe { resolv_abi::getprotobyname(name.as_ptr()) };
    assert!(ptr.is_null());
}

// ===========================================================================
// getprotobynumber
// ===========================================================================

#[test]
fn getprotobynumber_6_resolves_tcp() {
    let ptr = unsafe { resolv_abi::getprotobynumber(6) };
    if !ptr.is_null() {
        let protoent = unsafe { &*(ptr as *const libc::protoent) };
        let name = unsafe { CStr::from_ptr(protoent.p_name) }.to_string_lossy();
        assert_eq!(name, "tcp");
        assert_eq!(protoent.p_proto, 6);
    }
}

#[test]
fn getprotobynumber_17_resolves_udp() {
    let ptr = unsafe { resolv_abi::getprotobynumber(17) };
    if !ptr.is_null() {
        let protoent = unsafe { &*(ptr as *const libc::protoent) };
        let name = unsafe { CStr::from_ptr(protoent.p_name) }.to_string_lossy();
        assert_eq!(name, "udp");
    }
}

#[test]
fn getprotobynumber_nonexistent_returns_null() {
    let ptr = unsafe { resolv_abi::getprotobynumber(99999) };
    assert!(ptr.is_null());
}

// ===========================================================================
// __h_errno_location
// ===========================================================================

#[test]
fn h_errno_location_returns_valid_pointer() {
    let ptr = unsafe { resolv_abi::__h_errno_location() };
    assert!(!ptr.is_null());
    // Should be readable
    let _val = unsafe { *ptr };
}

#[test]
fn h_errno_location_is_writable() {
    let ptr = unsafe { resolv_abi::__h_errno_location() };
    assert!(!ptr.is_null());
    let old = unsafe { *ptr };
    unsafe { *ptr = 42 };
    assert_eq!(unsafe { *ptr }, 42);
    unsafe { *ptr = old };
}
