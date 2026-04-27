//! ABI layer for `<arpa/inet.h>` functions.
//!
//! Byte-order conversions are pure compute (no syscalls). Address parsing
//! delegates to `frankenlibc_core::inet` safe implementations.

use std::ffi::{c_char, c_int, c_void};

use frankenlibc_core::errno;
use frankenlibc_core::inet as inet_core;
use frankenlibc_core::socket::{AF_INET, AF_INET6};
use frankenlibc_core::syscall as raw_syscall;
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::errno_abi::set_abi_errno;
use crate::malloc_abi::known_remaining;
use crate::runtime_policy;
use crate::util::scan_c_string;

// Socket constants for if_nametoindex/if_indextoname
const SOCK_DGRAM: i32 = 2;
const SOCK_CLOEXEC: i32 = 0x80000;
const SIOCGIFINDEX: usize = 0x8933;
const SIOCGIFNAME: usize = 0x8910;

#[inline]
fn is_aligned_for<T>(ptr: *const c_void) -> bool {
    (ptr as usize).is_multiple_of(std::mem::align_of::<T>())
}

fn aligned_buffer_offset(base: *const c_char, min_offset: usize, align: usize) -> Option<usize> {
    let addr = (base as usize).checked_add(min_offset)?;
    let rem = addr % align;
    let padding = if rem == 0 { 0 } else { align - rem };
    min_offset.checked_add(padding)
}

#[inline]
fn tracked_region_fits(ptr: *const c_void, len: usize) -> bool {
    known_remaining(ptr as usize).is_none_or(|remaining| len <= remaining)
}

/// Read a user-supplied C string pointer with a known-region bound so a
/// non-NUL-terminated argument cannot walk arbitrary process memory through
/// `CStr::from_ptr`. Returns `None` for null or unterminated input.
///
/// Mirrors the locale_abi / iconv_abi / dlfcn_abi defense (bd-z4k96 class).
/// inet_pton/inet_aton/inet_addr/if_nametoindex are commonly invoked from
/// network code; an attacker-controlled or corrupted address-text pointer
/// must not crash or leak memory across the libc.so boundary.
#[inline]
unsafe fn read_bounded_cstr(ptr: *const c_char) -> Option<Vec<u8>> {
    if ptr.is_null() {
        return None;
    }
    let (len, terminated) = unsafe { scan_c_string(ptr, known_remaining(ptr as usize)) };
    if !terminated {
        return None;
    }
    let bytes = unsafe { core::slice::from_raw_parts(ptr as *const u8, len) };
    Some(bytes.to_vec())
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
        unsafe { set_abi_errno(errno::EAFNOSUPPORT) };
        runtime_policy::observe(ApiFamily::Inet, decision.profile, 5, true);
        return -1;
    }

    if src.is_null() || dst.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::Inet, decision.profile, 5, true);
        return -1;
    }

    // Bounded read rejects non-NUL-terminated pointers at the boundary
    // instead of walking memory through CStr::from_ptr. Same defense
    // class as bd-z4k96 / iconv_open / dlopen / setlocale. (REVIEW round 5.)
    let Some(src_bytes) = (unsafe { read_bounded_cstr(src) }) else {
        runtime_policy::observe(ApiFamily::Inet, decision.profile, 5, true);
        return 0;
    };
    let src_bytes = src_bytes.as_slice();

    let dst_size = match af {
        AF_INET => 4,
        AF_INET6 => 16,
        _ => {
            unsafe { set_abi_errno(errno::EAFNOSUPPORT) };
            runtime_policy::observe(ApiFamily::Inet, decision.profile, 5, true);
            return -1;
        }
    };

    if !tracked_region_fits(dst as *const c_void, dst_size) {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::Inet, decision.profile, 5, true);
        return -1;
    }

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
        unsafe { set_abi_errno(errno::EAFNOSUPPORT) };
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

    if !tracked_region_fits(src, src_size) {
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::Inet, decision.profile, 5, true);
        return std::ptr::null();
    }

    let src_slice = unsafe { std::slice::from_raw_parts(src as *const u8, src_size) };
    match inet_core::inet_ntop(af, src_slice) {
        Some(text) => {
            let required = text.len() + 1;
            if required > size as usize {
                unsafe { set_abi_errno(errno::ENOSPC) };
                runtime_policy::observe(ApiFamily::Inet, decision.profile, 10, true);
                return std::ptr::null();
            }
            if !tracked_region_fits(dst.cast_const().cast(), required) {
                unsafe { set_abi_errno(errno::EFAULT) };
                runtime_policy::observe(ApiFamily::Inet, decision.profile, 10, true);
                return std::ptr::null();
            }
            let dst_slice = unsafe { std::slice::from_raw_parts_mut(dst as *mut u8, required) };
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
    if !tracked_region_fits(inp.cast_const().cast(), std::mem::size_of::<u32>()) {
        runtime_policy::observe(ApiFamily::Inet, decision.profile, 5, true);
        return 0;
    }

    // Bounded read — see bd-z4k96 class. (REVIEW round 5.)
    let Some(src_bytes) = (unsafe { read_bounded_cstr(cp) }) else {
        runtime_policy::observe(ApiFamily::Inet, decision.profile, 5, true);
        return 0;
    };
    let mut octets = [0u8; 4];
    let rc = inet_core::inet_aton(&src_bytes, &mut octets);
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

    // Bounded read — see bd-z4k96 class. (REVIEW round 5.)
    let Some(src_bytes) = (unsafe { read_bounded_cstr(cp) }) else {
        runtime_policy::observe(ApiFamily::Inet, decision.profile, 5, true);
        return inet_core::INADDR_NONE;
    };
    let result = inet_core::inet_addr(&src_bytes);
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
        unsafe { set_abi_errno(errno::EFAULT) };
        return 0;
    }
    let sock = match raw_syscall::sys_socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0) {
        Ok(fd) => fd,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            return 0;
        }
    };

    let mut ifr: IfreqCompat = unsafe { std::mem::zeroed() };
    // Bounded read — non-NUL-terminated `ifname` would otherwise walk
    // arbitrary memory through CStr::from_ptr. (REVIEW round 5.)
    let Some(name_bytes) = (unsafe { read_bounded_cstr(ifname) }) else {
        let _ = raw_syscall::sys_close(sock);
        unsafe { set_abi_errno(errno::ENODEV) };
        return 0;
    };
    let copy_len = name_bytes.len().min(15);
    ifr.ifr_name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

    let failure_errno =
        unsafe { raw_syscall::sys_ioctl(sock, SIOCGIFINDEX, &ifr as *const _ as usize) }.err();
    let _ = raw_syscall::sys_close(sock);

    if failure_errno.is_some() {
        unsafe { set_abi_errno(failure_errno.unwrap_or(errno::ENODEV)) };
        0
    } else {
        ifr.ifr_ifindex as libc::c_uint
    }
}

/// POSIX `if_indextoname` — map interface index to name via ioctl.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn if_indextoname(ifindex: libc::c_uint, ifname: *mut c_char) -> *mut c_char {
    if ifname.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        return std::ptr::null_mut();
    }
    if !tracked_region_fits(ifname.cast_const().cast(), libc::IF_NAMESIZE) {
        unsafe { set_abi_errno(errno::EFAULT) };
        return std::ptr::null_mut();
    }

    let sock = match raw_syscall::sys_socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0) {
        Ok(fd) => fd,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            return std::ptr::null_mut();
        }
    };

    let mut ifr: IfreqCompat = unsafe { std::mem::zeroed() };
    ifr.ifr_ifindex = ifindex as i32;

    let rc = unsafe { raw_syscall::sys_ioctl(sock, SIOCGIFNAME, &ifr as *const _ as usize) };
    let _ = raw_syscall::sys_close(sock);

    if rc.is_err() {
        unsafe { set_abi_errno(errno::ENXIO) };
        return std::ptr::null_mut();
    }

    // Copy the name to the caller's buffer (must be >= IFNAMSIZ = 16)
    unsafe {
        std::ptr::copy_nonoverlapping(ifr.ifr_name.as_ptr() as *const c_char, ifname, 16);
    }
    ifname
}

// ---------------------------------------------------------------------------
// if_nameindex / if_freenameindex — Implemented (native /sys/class/net enumeration)
// ---------------------------------------------------------------------------

/// `struct if_nameindex` layout: { if_index: c_uint, [pad], if_name: *mut c_char }
const IF_NAMEINDEX_ENTRY_SIZE: usize = std::mem::size_of::<libc::if_nameindex>();
/// Byte offset of the `if_name` pointer within `struct if_nameindex`.
const IF_NAMEINDEX_NAME_OFFSET: usize = std::mem::offset_of!(libc::if_nameindex, if_name);

/// POSIX `if_nameindex` — enumerate all network interfaces.
///
/// Returns a heap-allocated NULL-terminated array of `struct if_nameindex`.
/// Each entry contains an interface index and a heap-allocated name string.
/// Caller must free with `if_freenameindex`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn if_nameindex() -> *mut c_void {
    // Enumerate interfaces from /sys/class/net/
    let entries = match std::fs::read_dir("/sys/class/net") {
        Ok(iter) => iter,
        Err(_) => {
            unsafe { set_abi_errno(errno::ENOBUFS) };
            return std::ptr::null_mut();
        }
    };

    // Collect (index, name) pairs.
    let mut ifaces: Vec<(u32, Vec<u8>)> = Vec::new();
    for entry in entries {
        let Ok(entry) = entry else { continue };
        let name = entry.file_name();
        let name_bytes = name.as_encoded_bytes();
        if name_bytes.is_empty() || name_bytes[0] == b'.' {
            continue;
        }

        // Read the interface index from /sys/class/net/<name>/ifindex
        let idx_path = entry.path().join("ifindex");
        let idx = match std::fs::read_to_string(&idx_path) {
            Ok(s) => s.trim().parse::<u32>().unwrap_or(0),
            Err(_) => continue,
        };
        if idx == 0 {
            continue;
        }
        ifaces.push((idx, name_bytes.to_vec()));
    }

    // Allocate the result: (ifaces.len() + 1) entries, last is zero sentinel.
    let count = ifaces.len();
    let array_bytes = (count + 1) * IF_NAMEINDEX_ENTRY_SIZE;
    let array = unsafe { crate::malloc_abi::raw_alloc(array_bytes) } as *mut u8;
    if array.is_null() {
        unsafe { set_abi_errno(errno::ENOMEM) };
        return std::ptr::null_mut();
    }
    unsafe { std::ptr::write_bytes(array, 0, array_bytes) };

    for (i, (idx, name)) in ifaces.iter().enumerate() {
        let entry_ptr = unsafe { array.add(i * IF_NAMEINDEX_ENTRY_SIZE) };

        // Allocate and copy the name string (NUL-terminated).
        let name_buf = unsafe { crate::malloc_abi::raw_alloc(name.len() + 1) } as *mut u8;
        if name_buf.is_null() {
            // Free everything allocated so far.
            for j in 0..i {
                let prev = unsafe { array.add(j * IF_NAMEINDEX_ENTRY_SIZE) };
                let prev_name = unsafe { *(prev.add(IF_NAMEINDEX_NAME_OFFSET) as *const *mut u8) };
                if !prev_name.is_null() {
                    unsafe { crate::malloc_abi::raw_free(prev_name.cast()) };
                }
            }
            unsafe { crate::malloc_abi::raw_free(array.cast()) };
            unsafe { set_abi_errno(errno::ENOMEM) };
            return std::ptr::null_mut();
        }
        unsafe {
            std::ptr::copy_nonoverlapping(name.as_ptr(), name_buf, name.len());
            *name_buf.add(name.len()) = 0;
        }

        // Write if_index (u32 at offset 0).
        unsafe { *(entry_ptr as *mut u32) = *idx };
        // Write if_name (*mut c_char at offset 8 on x86_64).
        unsafe { *(entry_ptr.add(IF_NAMEINDEX_NAME_OFFSET) as *mut *mut u8) = name_buf };
    }

    // Sentinel entry is already zeroed from write_bytes above.
    array.cast()
}

/// POSIX `if_freenameindex` — free an array returned by `if_nameindex`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn if_freenameindex(ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }
    let array = ptr as *mut u8;
    let mut i = 0;
    loop {
        let entry_ptr = unsafe { array.add(i * IF_NAMEINDEX_ENTRY_SIZE) };
        let idx = unsafe { *(entry_ptr as *const u32) };
        let name = unsafe { *(entry_ptr.add(IF_NAMEINDEX_NAME_OFFSET) as *const *mut c_void) };
        if idx == 0 && name.is_null() {
            break; // Sentinel reached.
        }
        if !name.is_null() {
            unsafe { crate::malloc_abi::raw_free(name) };
        }
        i += 1;
    }
    unsafe { crate::malloc_abi::raw_free(ptr) };
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
    if !is_aligned_for::<libc::servent>(result_buf) {
        return libc::EINVAL;
    }

    let Some(name_bytes) = (unsafe { read_bounded_cstr(name) }) else {
        return libc::EINVAL;
    };
    let proto_filter = if proto.is_null() {
        None
    } else {
        let Some(proto_bytes) = (unsafe { read_bounded_cstr(proto) }) else {
            return libc::EINVAL;
        };
        Some(proto_bytes)
    };

    let content = match std::fs::read("/etc/services") {
        Ok(c) => c,
        Err(_) => return libc::ENOENT,
    };

    // Find the matching service entry
    let entry = content.split(|&b| b == b'\n').find_map(|line| {
        let entry = frankenlibc_core::resolv::parse_services_line(line)?;
        if !entry.name.eq_ignore_ascii_case(name_bytes.as_slice())
            && !entry
                .aliases
                .iter()
                .any(|alias| alias.eq_ignore_ascii_case(name_bytes.as_slice()))
        {
            return None;
        }
        if let Some(pf) = proto_filter.as_deref()
            && !entry.protocol.eq_ignore_ascii_case(pf)
        {
            return None;
        }
        Some((entry.name, entry.port, entry.protocol))
    });

    let (svc_name, port, svc_proto) = match entry {
        Some(e) => e,
        None => return libc::ENOENT,
    };

    // Write name + proto into caller's buffer
    let name_len = svc_name.len() + 1; // +NUL
    let proto_len = svc_proto.len() + 1;
    let aliases_offset = match aligned_buffer_offset(
        buf,
        name_len + proto_len,
        std::mem::align_of::<*mut c_char>(),
    ) {
        Some(offset) => offset,
        None => return libc::ERANGE,
    };
    let aliases_size = std::mem::size_of::<*mut c_char>();
    let needed = match aliases_offset.checked_add(aliases_size) {
        Some(needed) => needed,
        None => return libc::ERANGE,
    };
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

    let aliases_ptr = unsafe { buf.add(aliases_offset) as *mut *mut c_char };
    unsafe { *aliases_ptr = std::ptr::null_mut() };

    let servent = unsafe { &mut *result_buf.cast::<libc::servent>() };
    servent.s_name = name_ptr;
    servent.s_aliases = aliases_ptr;
    servent.s_port = port.to_be() as c_int;
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
    if !is_aligned_for::<libc::servent>(result_buf) {
        return libc::EINVAL;
    }

    let port_host = u16::from_be(port as u16);
    let proto_filter = if proto.is_null() {
        None
    } else {
        let Some(proto_bytes) = (unsafe { read_bounded_cstr(proto) }) else {
            return libc::EINVAL;
        };
        Some(proto_bytes)
    };

    let content = match std::fs::read("/etc/services") {
        Ok(c) => c,
        Err(_) => return libc::ENOENT,
    };

    let entry = content.split(|&b| b == b'\n').find_map(|line| {
        let entry = frankenlibc_core::resolv::parse_services_line(line)?;
        if entry.port != port_host {
            return None;
        }
        if let Some(pf) = proto_filter.as_deref()
            && !entry.protocol.eq_ignore_ascii_case(pf)
        {
            return None;
        }
        Some((entry.name, entry.port, entry.protocol))
    });

    let (svc_name, _, svc_proto) = match entry {
        Some(e) => e,
        None => return libc::ENOENT,
    };

    let name_len = svc_name.len() + 1;
    let proto_len = svc_proto.len() + 1;
    let aliases_offset = match aligned_buffer_offset(
        buf,
        name_len + proto_len,
        std::mem::align_of::<*mut c_char>(),
    ) {
        Some(offset) => offset,
        None => return libc::ERANGE,
    };
    let aliases_size = std::mem::size_of::<*mut c_char>();
    let needed = match aliases_offset.checked_add(aliases_size) {
        Some(needed) => needed,
        None => return libc::ERANGE,
    };
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

    let aliases_ptr = unsafe { buf.add(aliases_offset) as *mut *mut c_char };
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
