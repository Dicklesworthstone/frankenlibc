//! ABI layer for `<arpa/inet.h>` functions.
//!
//! Byte-order conversions are pure compute (no syscalls). Address parsing
//! delegates to `frankenlibc_core::inet` safe implementations.

use std::ffi::{c_char, c_int, c_void};

use frankenlibc_core::errno;
use frankenlibc_core::inet as inet_core;
use frankenlibc_core::socket::{AF_INET, AF_INET6};
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::runtime_policy;

#[inline]
unsafe fn set_abi_errno(val: c_int) {
    let p = unsafe { super::errno_abi::__errno_location() };
    unsafe { *p = val };
}

// ---------------------------------------------------------------------------
// htons
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn htons(hostshort: u16) -> u16 {
    hostshort.to_be()
}

// ---------------------------------------------------------------------------
// htonl
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn htonl(hostlong: u32) -> u32 {
    hostlong.to_be()
}

// ---------------------------------------------------------------------------
// ntohs
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ntohs(netshort: u16) -> u16 {
    u16::from_be(netshort)
}

// ---------------------------------------------------------------------------
// ntohl
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ntohl(netlong: u32) -> u32 {
    u32::from_be(netlong)
}

// ---------------------------------------------------------------------------
// inet_pton
// ---------------------------------------------------------------------------

/// Convert text IP address to binary form.
///
/// Returns 1 on success, 0 if `src` is not a valid address for the given
/// family, -1 if `af` is unsupported (sets errno to `EAFNOSUPPORT`).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn inet_pton(af: c_int, src: *const c_char, dst: *mut c_void) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::Inet, src as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Inet, decision.profile, 5, true);
        return -1;
    }

    if src.is_null() || dst.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::Inet, decision.profile, 5, true);
        return -1;
    }

    // Read the C string into a byte slice (scan for NUL).
    let src_bytes = unsafe { std::ffi::CStr::from_ptr(src) }.to_bytes();

    let dst_size = match af {
        AF_INET => 4,
        AF_INET6 => 16,
        _ => {
            unsafe { set_abi_errno(errno::EAFNOSUPPORT) };
            runtime_policy::observe(ApiFamily::Inet, decision.profile, 5, true);
            return -1;
        }
    };

    let dst_slice = unsafe { std::slice::from_raw_parts_mut(dst as *mut u8, dst_size) };
    let rc = inet_core::inet_pton(af, src_bytes, dst_slice);
    runtime_policy::observe(ApiFamily::Inet, decision.profile, 10, rc != 1);
    rc
}

// ---------------------------------------------------------------------------
// inet_ntop
// ---------------------------------------------------------------------------

/// Convert binary IP address to text form.
///
/// Returns `dst` on success, null on failure (sets errno).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn inet_ntop(
    af: c_int,
    src: *const c_void,
    dst: *mut c_char,
    size: u32,
) -> *const c_char {
    let (_, decision) = runtime_policy::decide(ApiFamily::Inet, src as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Inet, decision.profile, 5, true);
        return std::ptr::null();
    }

    if src.is_null() || dst.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::Inet, decision.profile, 5, true);
        return std::ptr::null();
    }

    let src_size = match af {
        AF_INET => 4,
        AF_INET6 => 16,
        _ => {
            unsafe { set_abi_errno(errno::EAFNOSUPPORT) };
            runtime_policy::observe(ApiFamily::Inet, decision.profile, 5, true);
            return std::ptr::null();
        }
    };

    let src_slice = unsafe { std::slice::from_raw_parts(src as *const u8, src_size) };
    match inet_core::inet_ntop(af, src_slice) {
        Some(text) => {
            if text.len() + 1 > size as usize {
                unsafe { set_abi_errno(errno::ENOSPC) };
                runtime_policy::observe(ApiFamily::Inet, decision.profile, 10, true);
                return std::ptr::null();
            }
            let dst_slice =
                unsafe { std::slice::from_raw_parts_mut(dst as *mut u8, size as usize) };
            dst_slice[..text.len()].copy_from_slice(&text);
            dst_slice[text.len()] = 0; // NUL terminator
            runtime_policy::observe(ApiFamily::Inet, decision.profile, 10, false);
            dst as *const c_char
        }
        None => {
            unsafe { set_abi_errno(errno::EAFNOSUPPORT) };
            runtime_policy::observe(ApiFamily::Inet, decision.profile, 10, true);
            std::ptr::null()
        }
    }
}

// ---------------------------------------------------------------------------
// inet_aton
// ---------------------------------------------------------------------------

/// Parse dotted-quad IPv4 string and write to `inp`.
///
/// Returns 1 on success, 0 on failure.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn inet_aton(cp: *const c_char, inp: *mut u32) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::Inet, cp as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Inet, decision.profile, 5, true);
        return 0;
    }

    if cp.is_null() || inp.is_null() {
        runtime_policy::observe(ApiFamily::Inet, decision.profile, 5, true);
        return 0;
    }

    let src_bytes = unsafe { std::ffi::CStr::from_ptr(cp) }.to_bytes();
    let mut octets = [0u8; 4];
    let rc = inet_core::inet_aton(src_bytes, &mut octets);
    if rc == 1 {
        // Write as network-byte-order u32 (same as in_addr.s_addr)
        unsafe { *inp = u32::from_ne_bytes(octets) };
    }
    runtime_policy::observe(ApiFamily::Inet, decision.profile, 8, rc != 1);
    rc
}

// ---------------------------------------------------------------------------
// inet_ntoa
// ---------------------------------------------------------------------------

/// Convert IPv4 address (network byte order u32) to dotted-quad string.
///
/// Returns a pointer to a thread-local static buffer. This function is NOT
/// reentrant — the buffer is overwritten on each call from the same thread.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn inet_ntoa(addr: u32) -> *const c_char {
    // Thread-local buffer for the returned string (max "255.255.255.255\0" = 16 bytes).
    thread_local! {
        static BUF: std::cell::RefCell<[u8; 16]> = const { std::cell::RefCell::new([0u8; 16]) };
    }

    let octets = addr.to_ne_bytes();
    let text = inet_core::format_ipv4(&[octets[0], octets[1], octets[2], octets[3]]);
    let len = inet_core::format_ipv4_len(&[octets[0], octets[1], octets[2], octets[3]]);

    BUF.with(|cell| {
        let mut buf = cell.borrow_mut();
        let copy_len = len.min(15);
        buf[..copy_len].copy_from_slice(&text[..copy_len]);
        buf[copy_len] = 0; // NUL terminator
        buf.as_ptr() as *const c_char
    })
}

// ---------------------------------------------------------------------------
// inet_addr
// ---------------------------------------------------------------------------

/// Parse dotted-quad IPv4 string to network-byte-order u32.
///
/// Returns `INADDR_NONE` (0xFFFFFFFF) on error.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn inet_addr(cp: *const c_char) -> u32 {
    let (_, decision) = runtime_policy::decide(ApiFamily::Inet, cp as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Inet, decision.profile, 5, true);
        return inet_core::INADDR_NONE;
    }

    if cp.is_null() {
        runtime_policy::observe(ApiFamily::Inet, decision.profile, 5, true);
        return inet_core::INADDR_NONE;
    }

    let src_bytes = unsafe { std::ffi::CStr::from_ptr(cp) }.to_bytes();
    let result = inet_core::inet_addr(src_bytes);
    runtime_policy::observe(
        ApiFamily::Inet,
        decision.profile,
        8,
        result == inet_core::INADDR_NONE,
    );
    result
}

// ---------------------------------------------------------------------------
// Network interface name/index — native via ioctl
// ---------------------------------------------------------------------------

use std::ffi::CStr;
use std::os::raw::c_long;

/// Compact ifreq-compatible struct for SIOCGIFINDEX / SIOCGIFNAME ioctls.
/// Layout: ifr_name[16] + ifr_ifindex(i32) + padding.
#[repr(C)]
struct IfreqCompat {
    ifr_name: [u8; 16],
    ifr_ifindex: i32,
    _pad: [u8; 20],
}

/// POSIX `if_nametoindex` — map interface name to index via ioctl.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn if_nametoindex(ifname: *const c_char) -> libc::c_uint {
    if ifname.is_null() {
        return 0;
    }
    let sock = unsafe {
        libc::syscall(
            libc::SYS_socket as c_long,
            libc::AF_INET,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            0,
        ) as c_int
    };
    if sock < 0 {
        return 0;
    }

    let mut ifr: IfreqCompat = unsafe { std::mem::zeroed() };
    let name = unsafe { CStr::from_ptr(ifname) };
    let name_bytes = name.to_bytes();
    let copy_len = name_bytes.len().min(15);
    ifr.ifr_name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

    let rc = unsafe {
        libc::syscall(
            libc::SYS_ioctl as c_long,
            sock,
            libc::SIOCGIFINDEX as c_long,
            &ifr,
        ) as c_int
    };
    unsafe { libc::syscall(libc::SYS_close as c_long, sock) };

    if rc < 0 {
        0
    } else {
        ifr.ifr_ifindex as libc::c_uint
    }
}

/// POSIX `if_indextoname` — map interface index to name via ioctl.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn if_indextoname(ifindex: libc::c_uint, ifname: *mut c_char) -> *mut c_char {
    if ifname.is_null() {
        return std::ptr::null_mut();
    }
    let sock = unsafe {
        libc::syscall(
            libc::SYS_socket as c_long,
            libc::AF_INET,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            0,
        ) as c_int
    };
    if sock < 0 {
        return std::ptr::null_mut();
    }

    let mut ifr: IfreqCompat = unsafe { std::mem::zeroed() };
    ifr.ifr_ifindex = ifindex as i32;

    let rc = unsafe {
        libc::syscall(
            libc::SYS_ioctl as c_long,
            sock,
            libc::SIOCGIFNAME as c_long,
            &ifr,
        ) as c_int
    };
    unsafe { libc::syscall(libc::SYS_close as c_long, sock) };

    if rc < 0 {
        return std::ptr::null_mut();
    }

    // Copy the name to the caller's buffer (must be >= IFNAMSIZ = 16)
    unsafe {
        std::ptr::copy_nonoverlapping(ifr.ifr_name.as_ptr() as *const c_char, ifname, 16);
    }
    ifname
}

// ---------------------------------------------------------------------------
// if_nameindex / if_freenameindex — GlibcCallThrough (complex enumeration)
// ---------------------------------------------------------------------------

unsafe extern "C" {
    #[link_name = "if_nameindex"]
    fn libc_if_nameindex() -> *mut c_void;
    #[link_name = "if_freenameindex"]
    fn libc_if_freenameindex(ptr: *mut c_void);
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn if_nameindex() -> *mut c_void {
    unsafe { libc_if_nameindex() }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn if_freenameindex(ptr: *mut c_void) {
    unsafe { libc_if_freenameindex(ptr) }
}

// ---------------------------------------------------------------------------
// getservbyname_r / getservbyport_r — native /etc/services parsing
// ---------------------------------------------------------------------------

/// Reentrant `getservbyname_r` — look up service by name in /etc/services.
///
/// Writes the result into the caller-provided buffer.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getservbyname_r(
    name: *const c_char,
    proto: *const c_char,
    result_buf: *mut c_void,
    buf: *mut c_char,
    buflen: usize,
    result: *mut *mut c_void,
) -> c_int {
    if name.is_null() || result_buf.is_null() || buf.is_null() || result.is_null() {
        if !result.is_null() {
            unsafe { *result = std::ptr::null_mut() };
        }
        return libc::EINVAL;
    }
    unsafe { *result = std::ptr::null_mut() };

    let name_cstr = unsafe { CStr::from_ptr(name) };
    let proto_filter = if proto.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(proto) }.to_bytes())
    };

    let content = match std::fs::read("/etc/services") {
        Ok(c) => c,
        Err(_) => return libc::ENOENT,
    };

    // Find the matching service entry
    let entry = content.split(|&b| b == b'\n').find_map(|line| {
        let (svc_name, port, svc_proto) = frankenlibc_core::resolv::parse_services_line(line)?;
        if !svc_name.eq_ignore_ascii_case(name_cstr.to_bytes()) {
            return None;
        }
        if let Some(pf) = proto_filter
            && !svc_proto.eq_ignore_ascii_case(pf)
        {
            return None;
        }
        Some((svc_name, port, svc_proto))
    });

    let (svc_name, port, svc_proto) = match entry {
        Some(e) => e,
        None => return libc::ENOENT,
    };

    // Write name + proto into caller's buffer
    let name_len = svc_name.len() + 1; // +NUL
    let proto_len = svc_proto.len() + 1;
    let aliases_size = std::mem::size_of::<*mut c_char>();
    let needed = name_len + proto_len + aliases_size;
    if needed > buflen {
        return libc::ERANGE;
    }

    let name_ptr = buf;
    unsafe {
        std::ptr::copy_nonoverlapping(svc_name.as_ptr() as *const c_char, name_ptr, svc_name.len());
        *name_ptr.add(svc_name.len()) = 0;
    }

    let proto_ptr = unsafe { buf.add(name_len) };
    unsafe {
        std::ptr::copy_nonoverlapping(
            svc_proto.as_ptr() as *const c_char,
            proto_ptr,
            svc_proto.len(),
        );
        *proto_ptr.add(svc_proto.len()) = 0;
    }

    let aliases_ptr = unsafe { buf.add(name_len + proto_len) as *mut *mut c_char };
    unsafe { *aliases_ptr = std::ptr::null_mut() };

    let servent = unsafe { &mut *result_buf.cast::<libc::servent>() };
    servent.s_name = name_ptr;
    servent.s_aliases = aliases_ptr;
    servent.s_port = (port as c_int).to_be();
    servent.s_proto = proto_ptr;

    unsafe { *result = result_buf };
    0
}

/// Reentrant `getservbyport_r` — look up service by port in /etc/services.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getservbyport_r(
    port: c_int,
    proto: *const c_char,
    result_buf: *mut c_void,
    buf: *mut c_char,
    buflen: usize,
    result: *mut *mut c_void,
) -> c_int {
    if result_buf.is_null() || buf.is_null() || result.is_null() {
        if !result.is_null() {
            unsafe { *result = std::ptr::null_mut() };
        }
        return libc::EINVAL;
    }
    unsafe { *result = std::ptr::null_mut() };

    let port_host = u16::from_be(port as u16);
    let proto_filter = if proto.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(proto) }.to_bytes())
    };

    let content = match std::fs::read("/etc/services") {
        Ok(c) => c,
        Err(_) => return libc::ENOENT,
    };

    let entry = content.split(|&b| b == b'\n').find_map(|line| {
        let (svc_name, p, svc_proto) = frankenlibc_core::resolv::parse_services_line(line)?;
        if p != port_host {
            return None;
        }
        if let Some(pf) = proto_filter
            && !svc_proto.eq_ignore_ascii_case(pf)
        {
            return None;
        }
        Some((svc_name, p, svc_proto))
    });

    let (svc_name, _, svc_proto) = match entry {
        Some(e) => e,
        None => return libc::ENOENT,
    };

    let name_len = svc_name.len() + 1;
    let proto_len = svc_proto.len() + 1;
    let aliases_size = std::mem::size_of::<*mut c_char>();
    let needed = name_len + proto_len + aliases_size;
    if needed > buflen {
        return libc::ERANGE;
    }

    let name_ptr = buf;
    unsafe {
        std::ptr::copy_nonoverlapping(svc_name.as_ptr() as *const c_char, name_ptr, svc_name.len());
        *name_ptr.add(svc_name.len()) = 0;
    }

    let proto_ptr = unsafe { buf.add(name_len) };
    unsafe {
        std::ptr::copy_nonoverlapping(
            svc_proto.as_ptr() as *const c_char,
            proto_ptr,
            svc_proto.len(),
        );
        *proto_ptr.add(svc_proto.len()) = 0;
    }

    let aliases_ptr = unsafe { buf.add(name_len + proto_len) as *mut *mut c_char };
    unsafe { *aliases_ptr = std::ptr::null_mut() };

    let servent = unsafe { &mut *result_buf.cast::<libc::servent>() };
    servent.s_name = name_ptr;
    servent.s_aliases = aliases_ptr;
    servent.s_port = port;
    servent.s_proto = proto_ptr;

    unsafe { *result = result_buf };
    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn gethostbyname_r(
    name: *const c_char,
    result_buf: *mut c_void,
    buf: *mut c_char,
    buflen: usize,
    result: *mut *mut c_void,
    h_errnop: *mut c_int,
) -> c_int {
    // SAFETY: forwards validated caller arguments to resolver ABI implementation.
    unsafe {
        crate::resolv_abi::gethostbyname_r_impl(name, result_buf, buf, buflen, result, h_errnop)
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn gethostbyaddr_r(
    addr: *const c_void,
    len: libc::socklen_t,
    type_: c_int,
    result_buf: *mut c_void,
    buf: *mut c_char,
    buflen: usize,
    result: *mut *mut c_void,
    h_errnop: *mut c_int,
) -> c_int {
    // SAFETY: forwards validated caller arguments to resolver ABI implementation.
    unsafe {
        crate::resolv_abi::gethostbyaddr_r_impl(
            addr, len, type_, result_buf, buf, buflen, result, h_errnop,
        )
    }
}
