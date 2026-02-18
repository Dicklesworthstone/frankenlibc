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
// Network interface name/index — GlibcCallThrough
// ---------------------------------------------------------------------------

unsafe extern "C" {
    #[link_name = "if_nametoindex"]
    fn libc_if_nametoindex(ifname: *const c_char) -> libc::c_uint;
    #[link_name = "if_indextoname"]
    fn libc_if_indextoname(ifindex: libc::c_uint, ifname: *mut c_char) -> *mut c_char;
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn if_nametoindex(ifname: *const c_char) -> libc::c_uint {
    unsafe { libc_if_nametoindex(ifname) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn if_indextoname(ifindex: libc::c_uint, ifname: *mut c_char) -> *mut c_char {
    unsafe { libc_if_indextoname(ifindex, ifname) }
}
