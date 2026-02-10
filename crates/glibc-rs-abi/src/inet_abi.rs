//! ABI layer for `<arpa/inet.h>` functions.
//!
//! Byte-order conversions are pure compute (no syscalls). Address parsing
//! delegates to `glibc_rs_core::inet` safe implementations.

use std::ffi::{c_char, c_int, c_void};

use glibc_rs_core::errno;
use glibc_rs_core::inet as inet_core;
use glibc_rs_core::socket::{AF_INET, AF_INET6};
use glibc_rs_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::runtime_policy;

#[inline]
unsafe fn set_abi_errno(val: c_int) {
    let p = unsafe { super::errno_abi::__errno_location() };
    unsafe { *p = val };
}

// ---------------------------------------------------------------------------
// htons
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn htons(hostshort: u16) -> u16 {
    hostshort.to_be()
}

// ---------------------------------------------------------------------------
// htonl
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn htonl(hostlong: u32) -> u32 {
    hostlong.to_be()
}

// ---------------------------------------------------------------------------
// ntohs
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ntohs(netshort: u16) -> u16 {
    u16::from_be(netshort)
}

// ---------------------------------------------------------------------------
// ntohl
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
// inet_addr
// ---------------------------------------------------------------------------

/// Parse dotted-quad IPv4 string to network-byte-order u32.
///
/// Returns `INADDR_NONE` (0xFFFFFFFF) on error.
#[unsafe(no_mangle)]
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
