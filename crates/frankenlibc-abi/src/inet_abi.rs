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

/// Pack `aliases` into the caller buffer `buf` (capacity `buflen`) starting at
/// byte offset `str_off`: writes each alias string NUL-terminated, then an
/// aligned, NULL-terminated pointer table, and returns a pointer to that table
/// (suitable for s_aliases / n_aliases). Returns `None` (→ ERANGE) if the
/// buffer cannot hold both the strings and the table. Self-contained so both
/// the servent and network/protocol reentrant paths can share it.
///
/// # Safety
/// `buf` must be valid for `buflen` bytes.
pub(crate) unsafe fn pack_caller_aliases(
    buf: *mut c_char,
    buflen: usize,
    str_off: usize,
    aliases: &[Vec<u8>],
) -> Option<*mut *mut c_char> {
    let mut off = str_off;
    let mut offsets: Vec<usize> = Vec::with_capacity(aliases.len());
    for alias in aliases {
        let end = off.checked_add(alias.len())?.checked_add(1)?;
        if end > buflen {
            return None;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(
                alias.as_ptr() as *const c_char,
                buf.add(off),
                alias.len(),
            );
            *buf.add(off + alias.len()) = 0;
        }
        offsets.push(off);
        off = end;
    }
    let ptr_align = std::mem::align_of::<*mut c_char>();
    let arr_off = aligned_buffer_offset(buf, off, ptr_align)?;
    let ptr_size = std::mem::size_of::<*mut c_char>();
    let total = arr_off.checked_add(ptr_size.checked_mul(offsets.len().checked_add(1)?)?)?;
    if total > buflen {
        return None;
    }
    let arr = unsafe { buf.add(arr_off) as *mut *mut c_char };
    for (i, &so) in offsets.iter().enumerate() {
        unsafe { *arr.add(i) = buf.add(so) as *mut c_char };
    }
    unsafe { *arr.add(offsets.len()) = std::ptr::null_mut() };
    Some(arr)
}

#[inline]
fn tracked_region_fits(ptr: *const c_void, len: usize) -> bool {
    known_remaining(ptr as usize).is_none_or(|remaining| len <= remaining)
}

#[inline]
fn tracked_object_fits<T>(ptr: *const T) -> bool {
    is_aligned_for::<T>(ptr.cast())
        && known_remaining(ptr as usize)
            .is_none_or(|remaining| remaining >= std::mem::size_of::<T>())
}

#[inline]
fn effective_c_buffer_len(ptr: *const c_char, requested: usize) -> usize {
    known_remaining(ptr as usize).map_or(requested, |remaining| remaining.min(requested))
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
    let bytes = unsafe { read_bounded_cstr_ref(ptr)? };
    Some(bytes.to_vec())
}

/// Borrowed (allocation-free) variant of [`read_bounded_cstr`]: returns the
/// bounded, NUL-terminated input as a slice that aliases `ptr` directly. Use this
/// where the bytes are only READ within the call (e.g. the inet_pton/aton/addr
/// parsers, which consume the slice and never retain it) — the owning `to_vec`
/// copy was a per-call malloc+memcpy+free on these hot, pure conversions.
/// MEASURED: inet_pton 209ns -> 134ns (byte-identical; vs glibc 17ns). Same
/// bounded-read safety (rejects non-NUL-terminated pointers at the boundary).
#[inline]
unsafe fn read_bounded_cstr_ref<'a>(ptr: *const c_char) -> Option<&'a [u8]> {
    if ptr.is_null() {
        return None;
    }
    let (len, terminated) = unsafe { scan_c_string(ptr, known_remaining(ptr as usize)) };
    if !terminated {
        return None;
    }
    // SAFETY: scan_c_string confirmed `len` readable NUL-terminated bytes at `ptr`,
    // valid for the duration of the calling conversion (which does not retain it).
    Some(unsafe { core::slice::from_raw_parts(ptr as *const u8, len) })
}

#[cfg(feature = "owned-tls-cache")]
static INET_NTOA_BUF_OWNED_TLS: crate::owned_tls_cache::OwnedTlsCache<[u8; 16]> =
    crate::owned_tls_cache::OwnedTlsCache::new(|| [0; 16]);

#[cfg(not(feature = "owned-tls-cache"))]
thread_local! {
    static INET_NTOA_BUF: std::cell::RefCell<[u8; 16]> = const { std::cell::RefCell::new([0u8; 16]) };
}

#[inline]
fn with_inet_ntoa_buffer<R>(f: impl FnOnce(&mut [u8; 16]) -> R) -> R {
    #[cfg(feature = "owned-tls-cache")]
    {
        INET_NTOA_BUF_OWNED_TLS.with(f)
    }

    #[cfg(not(feature = "owned-tls-cache"))]
    {
        INET_NTOA_BUF.with(|cell| f(&mut cell.borrow_mut()))
    }
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

/// Single-pass dotted-quad parse over a NUL-terminated C string (glibc `inet_pton4`
/// structure): one branch per char, stopping at the terminator. Byte-for-byte the
/// same accept/reject set as the core `parse_ipv4` on the string's pre-NUL bytes,
/// but with NO separate `scan_c_string`/strlen pass — the strict `inet_pton` v4 path
/// was doing `scan_c_string` (pass 1) + `parse_ipv4` (pass 2); this collapses them.
///
/// # Safety
/// `src` must point to a readable NUL-terminated C string (the strict-mode caller
/// contract, identical to what glibc's `inet_pton` requires).
unsafe fn parse_ipv4_cstr(src: *const u8) -> Option<[u8; 4]> {
    let mut octets = [0u8; 4];
    let mut oct_idx = 0usize; // completed octets so far
    let mut val: u16 = 0;
    let mut saw_digit = false;
    let mut i = 0usize;
    loop {
        // SAFETY: caller guarantees a NUL terminator; the walk stops at it.
        let ch = unsafe { *src.add(i) };
        if ch == 0 {
            break;
        }
        if ch.is_ascii_digit() {
            // Leading-zero reject: a second digit while the octet value is still 0
            // means the first digit was '0' (matches `parse_ipv4`'s `len>1 && '0'`).
            if saw_digit && val == 0 {
                return None;
            }
            val = val * 10 + (ch - b'0') as u16; // max 255*10+9 < u16::MAX, no overflow
            if val > 255 {
                return None;
            }
            saw_digit = true;
        } else if ch == b'.' {
            if !saw_digit || oct_idx == 3 {
                return None; // empty octet (leading/double/trailing dot) or 5th part
            }
            octets[oct_idx] = val as u8;
            oct_idx += 1;
            val = 0;
            saw_digit = false;
        } else {
            return None; // non-digit, non-dot
        }
        i += 1;
    }
    if !saw_digit || oct_idx != 3 {
        return None; // trailing dot / empty final octet, or wrong number of parts
    }
    octets[3] = val as u8;
    Some(octets)
}

#[inline]
fn parse_bsd_part_bytes(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() {
        return None;
    }
    if bytes.len() >= 2 && bytes[0] == b'0' && (bytes[1] == b'x' || bytes[1] == b'X') {
        let rest = &bytes[2..];
        if rest.is_empty() {
            return None;
        }
        let mut v: u32 = 0;
        for &b in rest {
            let d = match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                _ => return None,
            };
            v = v.checked_mul(16)?.checked_add(d as u32)?;
        }
        Some(v)
    } else if bytes[0] == b'0' && bytes.len() > 1 {
        let mut v: u32 = 0;
        for &b in &bytes[1..] {
            if !(b'0'..=b'7').contains(&b) {
                return None;
            }
            v = v.checked_mul(8)?.checked_add((b - b'0') as u32)?;
        }
        Some(v)
    } else {
        let mut v: u32 = 0;
        for &b in bytes {
            if !b.is_ascii_digit() {
                return None;
            }
            v = v.checked_mul(10)?.checked_add((b - b'0') as u32)?;
        }
        Some(v)
    }
}

#[inline]
fn bsd_octets_from_parts(nums: &[u32; 4], nparts: usize) -> Option<[u8; 4]> {
    let mut octets = [0u8; 4];
    match nparts {
        1 => {
            let v = nums[0];
            octets[0] = (v >> 24) as u8;
            octets[1] = (v >> 16) as u8;
            octets[2] = (v >> 8) as u8;
            octets[3] = v as u8;
        }
        2 => {
            if nums[0] > 0xFF || nums[1] > 0x00FF_FFFF {
                return None;
            }
            octets[0] = nums[0] as u8;
            octets[1] = (nums[1] >> 16) as u8;
            octets[2] = (nums[1] >> 8) as u8;
            octets[3] = nums[1] as u8;
        }
        3 => {
            if nums[0] > 0xFF || nums[1] > 0xFF || nums[2] > 0xFFFF {
                return None;
            }
            octets[0] = nums[0] as u8;
            octets[1] = nums[1] as u8;
            octets[2] = (nums[2] >> 8) as u8;
            octets[3] = nums[2] as u8;
        }
        4 => {
            for n in nums {
                if *n > 0xFF {
                    return None;
                }
            }
            octets[0] = nums[0] as u8;
            octets[1] = nums[1] as u8;
            octets[2] = nums[2] as u8;
            octets[3] = nums[3] as u8;
        }
        _ => return None,
    }
    Some(octets)
}

/// Strict-mode BSD numbers-and-dots parser for `inet_addr`/`inet_aton`.
///
/// This is the C-string sibling of `frankenlibc_core::inet::parse_ipv4_bsd`:
/// it walks once until NUL or ASCII whitespace, parses each component in place,
/// and applies the same 1/2/3/4-part packing rules. The fast path avoids the
/// previous `scan_c_string` pre-pass and also avoids scanning ignored junk after
/// the first whitespace terminator.
///
/// # Safety
/// `src` must point to a readable NUL-terminated C string under the strict C
/// caller contract.
#[inline]
unsafe fn parse_ipv4_bsd_cstr(src: *const u8) -> Option<[u8; 4]> {
    let mut nums = [0u32; 4];
    let mut nparts = 0usize;
    let mut part_start = 0usize;
    let mut i = 0usize;

    loop {
        // SAFETY: strict mode trusts the caller's NUL-terminated C string.
        let ch = unsafe { *src.add(i) };
        let at_separator = ch == b'.';
        let at_end = ch == 0 || ch.is_ascii_whitespace();

        if at_separator || at_end {
            if nparts >= 4 || i == part_start {
                return None;
            }
            // SAFETY: bytes in [part_start, i) were just walked and are readable.
            let part = unsafe { core::slice::from_raw_parts(src.add(part_start), i - part_start) };
            nums[nparts] = parse_bsd_part_bytes(part)?;
            nparts += 1;

            if at_end {
                break;
            }
            i += 1;
            part_start = i;
        } else {
            i += 1;
        }
    }

    bsd_octets_from_parts(&nums, nparts)
}

/// Convert text IP address to binary form.
///
/// Returns 1 on success, 0 if `src` is not a valid address for the given
/// family, -1 if `af` is unsupported (sets errno to `EAFNOSUPPORT`).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn inet_pton(af: c_int, src: *const c_char, dst: *mut c_void) -> c_int {
    // Strict-mode fast path (the DEFAULT deployed mode): `Inet` `decide()` always-Allows in strict
    // (never denies), so the membrane's only output is the raw parse. Skip decide()/observe() +
    // `tracked_region_fits(dst)` + the `known_remaining` bound (scan src to NUL directly). Byte-
    // identical to the full path for valid inputs (same errno/return: EFAULT on null, 0 on
    // unterminated src, EAFNOSUPPORT on bad af); trust-the-caller region handling, glibc never
    // validates dst. Mirrors the string/sort/search strict fast paths.
    if runtime_policy::strict_passthrough_active() {
        if src.is_null() || dst.is_null() {
            unsafe { set_abi_errno(errno::EFAULT) };
            return -1;
        }
        match af {
            AF_INET => {
                // Single-pass parse straight over the NUL-terminated `src` (glibc
                // structure) — no separate `scan_c_string` strlen pass. Byte-identical
                // accept/reject to the two-pass `scan + parse_ipv4`. The raw-pointer
                // walk lives here in the ABI layer (the safe-Rust core forbids it).
                // SAFETY: strict trusts the caller's NUL-terminated `src` (C contract);
                // `dst` is valid for 4 bytes.
                return match unsafe { parse_ipv4_cstr(src as *const u8) } {
                    Some(octets) => {
                        unsafe {
                            core::ptr::copy_nonoverlapping(octets.as_ptr(), dst as *mut u8, 4)
                        };
                        1
                    }
                    None => 0,
                };
            }
            AF_INET6 => {
                // SAFETY: strict trusts the caller's NUL-terminated `src` (C contract).
                let (len, terminated) = unsafe { scan_c_string(src, None) };
                if !terminated {
                    return 0;
                }
                // SAFETY: `len` NUL-terminated bytes at `src`; caller guarantees `dst` for 16.
                let src_bytes = unsafe { core::slice::from_raw_parts(src as *const u8, len) };
                let dst_slice = unsafe { std::slice::from_raw_parts_mut(dst as *mut u8, 16) };
                return inet_core::inet_pton(AF_INET6, src_bytes, dst_slice);
            }
            _ => {
                unsafe { set_abi_errno(errno::EAFNOSUPPORT) };
                return -1;
            }
        }
    }

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
    // Borrowed (no-alloc): the core parser consumes src_bytes read-only and never
    // retains it, so the previous owning `to_vec` copy was pure per-call overhead.
    let Some(src_bytes) = (unsafe { read_bounded_cstr_ref(src) }) else {
        runtime_policy::observe(ApiFamily::Inet, decision.profile, 5, true);
        return 0;
    };

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
    if runtime_policy::inet_strict_membrane_fastpath() {
        match af {
            AF_INET => return unsafe { inet_ntop_ipv4_strict_fast(src, dst, size) },
            AF_INET6 => return unsafe { inet_ntop_ipv6_strict_fast(src, dst, size) },
            _ => {} // unsupported af → fall through to full path (sets EAFNOSUPPORT)
        }
    }

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
    // Format into a stack buffer (no per-call heap `Vec`); max text is IPv6
    // "x:x:x:x:x:x:255.255.255.255" = 45 bytes, 64 is ample.
    let mut text_buf = [0u8; 64];
    match inet_core::inet_ntop_into(af, src_slice, &mut text_buf) {
        Some(text_len) => {
            let required = text_len + 1;
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
            dst_slice[..text_len].copy_from_slice(&text_buf[..text_len]);
            dst_slice[text_len] = 0; // NUL terminator
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

#[inline]
unsafe fn inet_ntop_ipv4_strict_fast(
    src: *const c_void,
    dst: *mut c_char,
    size: u32,
) -> *const c_char {
    if src.is_null() || dst.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        return std::ptr::null();
    }

    let src = src.cast::<u8>();
    let addr = unsafe { [*src, *src.add(1), *src.add(2), *src.add(3)] };
    if size >= 16 {
        let dst_bytes = unsafe { &mut *dst.cast::<[u8; 16]>() };
        let text_len = inet_core::format_ipv4_into_fixed(&addr, dst_bytes);
        dst_bytes[text_len] = 0;
        return dst as *const c_char;
    }

    let text_len = inet_core::format_ipv4_len(&addr);
    let required = text_len + 1;
    if required > size as usize {
        unsafe { set_abi_errno(errno::ENOSPC) };
        return std::ptr::null();
    }

    let dst_bytes = unsafe { std::slice::from_raw_parts_mut(dst.cast::<u8>(), required) };
    let written = inet_core::format_ipv4_into(&addr, &mut dst_bytes[..text_len]);
    debug_assert_eq!(written, Some(text_len));
    dst_bytes[text_len] = 0;
    dst as *const c_char
}

/// Strict-mode `inet_ntop` for AF_INET6: format the 16-byte address to canonical
/// text with no membrane (`decide`/`observe`/`tracked_region_fits`). Byte-identical
/// to the full v6 path for valid inputs (EFAULT on null, ENOSPC when `size` too
/// small, else the canonical text); trust-the-caller regions, glibc never validates
/// `src`/`dst`. Mirrors `inet_ntop_ipv4_strict_fast`.
///
/// # Safety
/// `src` must be readable for 16 bytes and `dst` writable for `size` bytes (C contract).
unsafe fn inet_ntop_ipv6_strict_fast(
    src: *const c_void,
    dst: *mut c_char,
    size: u32,
) -> *const c_char {
    if src.is_null() || dst.is_null() {
        unsafe { set_abi_errno(errno::EFAULT) };
        return std::ptr::null();
    }
    // SAFETY: caller guarantees 16 readable bytes at `src` (C contract).
    let src_slice = unsafe { std::slice::from_raw_parts(src as *const u8, 16) };
    // Canonical IPv6 text is always < INET6_ADDRSTRLEN (46, incl. NUL). When `dst`
    // has room for the whole string, format DIRECTLY into it — no 64-byte stack temp
    // (zeroed) + copy. The temp path is only needed for a short `dst` to preserve
    // glibc's no-clobber-on-ENOSPC (it can't ENOSPC once size >= 46).
    if size >= 46 {
        // SAFETY: caller guarantees `dst` writable for `size` bytes.
        let dst_slice = unsafe { std::slice::from_raw_parts_mut(dst as *mut u8, size as usize) };
        return match inet_core::inet_ntop_into(AF_INET6, src_slice, dst_slice) {
            Some(text_len) => {
                dst_slice[text_len] = 0; // text_len < 46 <= size ⇒ in bounds
                dst as *const c_char
            }
            None => {
                unsafe { set_abi_errno(errno::EAFNOSUPPORT) };
                std::ptr::null()
            }
        };
    }
    // Short dst: format into a temp, then bounds-check before touching `dst`.
    let mut text_buf = [0u8; 64];
    match inet_core::inet_ntop_into(AF_INET6, src_slice, &mut text_buf) {
        Some(text_len) => {
            let required = text_len + 1;
            if required > size as usize {
                unsafe { set_abi_errno(errno::ENOSPC) };
                return std::ptr::null();
            }
            // SAFETY: caller guarantees `dst` writable for `required` (<= size) bytes.
            let dst_slice = unsafe { std::slice::from_raw_parts_mut(dst as *mut u8, required) };
            dst_slice[..text_len].copy_from_slice(&text_buf[..text_len]);
            dst_slice[text_len] = 0;
            dst as *const c_char
        }
        None => {
            unsafe { set_abi_errno(errno::EAFNOSUPPORT) };
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
    // Strict-mode fast path (DEFAULT deployed): `Inet` `decide()` always-Allows in strict, so skip
    // decide()/observe() + `tracked_region_fits(inp)` + `read_bounded_cstr_ref` (registry lookup) and
    // scan `cp` to NUL directly. Byte-identical under the C-string caller contract (0 on null/invalid,
    // rc from the BSD parser); trust-the-caller region handling, glibc never validates `inp`.
    // Mirrors inet_pton.
    if runtime_policy::strict_passthrough_active() {
        if cp.is_null() || inp.is_null() {
            return 0;
        }
        if let Some(octets) = unsafe { parse_ipv4_bsd_cstr(cp.cast()) } {
            // SAFETY: caller guarantees `inp` valid for a u32 (C contract).
            unsafe { *inp = u32::from_ne_bytes(octets) };
            return 1;
        }
        return 0;
    }

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

    // Bounded read — see bd-z4k96 class. (REVIEW round 5.) Borrowed (no-alloc):
    // the BSD parser consumes src_bytes read-only and never retains it.
    let Some(src_bytes) = (unsafe { read_bounded_cstr_ref(cp) }) else {
        runtime_policy::observe(ApiFamily::Inet, decision.profile, 5, true);
        return 0;
    };
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
    let octets = addr.to_ne_bytes();
    let text = inet_core::format_ipv4(&[octets[0], octets[1], octets[2], octets[3]]);
    let len = inet_core::format_ipv4_len(&[octets[0], octets[1], octets[2], octets[3]]);

    with_inet_ntoa_buffer(|buf| {
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
    // Strict-mode fast path (DEFAULT deployed): skip decide()/observe() + `read_bounded_cstr_ref`
    // (registry lookup); scan `cp` to NUL directly. Byte-identical under the C-string caller contract
    // (INADDR_NONE on null/invalid, else the BSD parse). Mirrors inet_pton/inet_aton.
    if runtime_policy::strict_passthrough_active() {
        if cp.is_null() {
            return inet_core::INADDR_NONE;
        }
        return unsafe { parse_ipv4_bsd_cstr(cp.cast()) }
            .map(u32::from_ne_bytes)
            .unwrap_or(inet_core::INADDR_NONE);
    }

    let (_, decision) = runtime_policy::decide(ApiFamily::Inet, cp as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Inet, decision.profile, 5, true);
        return inet_core::INADDR_NONE;
    }

    if cp.is_null() {
        runtime_policy::observe(ApiFamily::Inet, decision.profile, 5, true);
        return inet_core::INADDR_NONE;
    }

    // Bounded read — see bd-z4k96 class. (REVIEW round 5.) Borrowed (no-alloc):
    // the BSD parser consumes src_bytes read-only and never retains it.
    let Some(src_bytes) = (unsafe { read_bounded_cstr_ref(cp) }) else {
        runtime_policy::observe(ApiFamily::Inet, decision.profile, 5, true);
        return inet_core::INADDR_NONE;
    };
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

    // Bounded read first so invalid inputs do not pay socket/ioctl setup.
    // Linux interface names are capped at IF_NAMESIZE - 1 bytes; glibc
    // reports impossible names as ENODEV.
    let Some(name_bytes) = (unsafe { read_bounded_cstr(ifname) }) else {
        unsafe { set_abi_errno(errno::ENODEV) };
        return 0;
    };
    if name_bytes.is_empty() || name_bytes.len() >= libc::IF_NAMESIZE {
        unsafe { set_abi_errno(errno::ENODEV) };
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
    ifr.ifr_name[..name_bytes.len()].copy_from_slice(&name_bytes);

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
    if result.is_null() {
        return libc::EINVAL;
    }
    if !tracked_object_fits(result) {
        return libc::EINVAL;
    }
    if name.is_null() || result_buf.is_null() || buf.is_null() {
        unsafe { *result = std::ptr::null_mut() };
        return libc::EINVAL;
    }
    unsafe { *result = std::ptr::null_mut() };
    if !tracked_object_fits(result_buf.cast::<libc::servent>()) {
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

    // Shared generation-stamped parsed index (resolv_abi), the same one `getservbyname`
    // uses. Replaces a per-call `std::fs::read("/etc/services")` + line-by-line
    // `parse_services_line` scan: this entry point re-read and re-parsed the whole file on
    // EVERY call, so it did not even reach `BackendFileCache`. Lookup semantics are
    // unchanged (canonical name or alias, optional ASCII-case-insensitive protocol filter,
    // first match in file order); the caller-buffer packing below is untouched. The backend
    // now honors `FRANKENLIBC_SERVICES_PATH` exactly as the non-reentrant path does.
    // Pack straight out of the BORROWED cache entry. The `.cloned()` this replaces allocated a
    // name `Vec`, a protocol `Vec`, and a `Vec<Vec<u8>>` of aliases on every call; a frame
    // table of this row put ~91% of self time in the interposed allocator's bookkeeping
    // (bd-xmng5n / bd-qds9jk). Packing semantics below are byte-for-byte unchanged.
    let packed = crate::resolv_abi::with_service_entry_by_name(
        name_bytes.as_slice(),
        proto_filter.as_deref(),
        |entry| {
            let (svc_name, port, svc_proto) = (&entry.name, entry.port, &entry.protocol);

            // Layout in caller buffer: name\0 proto\0 alias strings\0 <align> ptr[].
            let name_len = svc_name.len() + 1; // +NUL
            let proto_len = svc_proto.len() + 1;
            let effective_buflen = effective_c_buffer_len(buf, buflen);
            if name_len + proto_len > effective_buflen {
                return libc::ERANGE;
            }

            let name_ptr = buf;
            unsafe {
                std::ptr::copy_nonoverlapping(
                    svc_name.as_ptr() as *const c_char,
                    name_ptr,
                    svc_name.len(),
                );
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

            let aliases_ptr = match unsafe {
                pack_caller_aliases(buf, effective_buflen, name_len + proto_len, &entry.aliases)
            } {
                Some(p) => p,
                None => return libc::ERANGE,
            };

            let servent = unsafe { &mut *result_buf.cast::<libc::servent>() };
            servent.s_name = name_ptr;
            servent.s_aliases = aliases_ptr;
            servent.s_port = port.to_be() as c_int;
            servent.s_proto = proto_ptr;

            unsafe { *result = result_buf };
            0
        },
    );

    match packed {
        Ok(Some(rc)) => rc,
        Ok(None) => 0,
        Err(_) => libc::ENOENT,
    }
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
    if result.is_null() {
        return libc::EINVAL;
    }
    if !tracked_object_fits(result) {
        return libc::EINVAL;
    }
    if result_buf.is_null() || buf.is_null() {
        unsafe { *result = std::ptr::null_mut() };
        return libc::EINVAL;
    }
    unsafe { *result = std::ptr::null_mut() };
    if !tracked_object_fits(result_buf.cast::<libc::servent>()) {
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

    // Shared generation-stamped parsed port index (resolv_abi), the same one
    // `getservbyport` uses; see `getservbyname_r` above. Replaces a per-call
    // `std::fs::read("/etc/services")` + line-by-line scan. Match semantics unchanged
    // (port plus optional case-insensitive protocol filter, first match in file order).
    // Pack from the BORROWED entry; see `getservbyname_r` above.
    let packed = crate::resolv_abi::with_service_entry_by_port(
        port_host,
        proto_filter.as_deref(),
        |entry| {
            let (svc_name, svc_proto) = (&entry.name, &entry.protocol);

            let name_len = svc_name.len() + 1;
            let proto_len = svc_proto.len() + 1;
            let effective_buflen = effective_c_buffer_len(buf, buflen);
            if name_len + proto_len > effective_buflen {
                return libc::ERANGE;
            }

            let name_ptr = buf;
            unsafe {
                std::ptr::copy_nonoverlapping(
                    svc_name.as_ptr() as *const c_char,
                    name_ptr,
                    svc_name.len(),
                );
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

            let aliases_ptr = match unsafe {
                pack_caller_aliases(buf, effective_buflen, name_len + proto_len, &entry.aliases)
            } {
                Some(p) => p,
                None => return libc::ERANGE,
            };

            let servent = unsafe { &mut *result_buf.cast::<libc::servent>() };
            servent.s_name = name_ptr;
            servent.s_aliases = aliases_ptr;
            servent.s_port = port;
            servent.s_proto = proto_ptr;

            unsafe { *result = result_buf };
            0
        },
    );

    match packed {
        Ok(Some(rc)) => rc,
        Ok(None) => 0,
        Err(_) => libc::ENOENT,
    }
}

/// Bench-only: the pre-index `getservbyname_r` (per-call `std::fs::read("/etc/services")` +
/// line-by-line `parse_services_line` scan), retained verbatim so `glibc_baseline_bench`
/// can measure ORIG vs patched in the SAME binary.
///
/// # Safety
/// Same contract as `getservbyname_r`.
#[doc(hidden)]
pub unsafe fn getservbyname_r_legacy_fs_per_call_for_bench(
    name: *const c_char,
    proto: *const c_char,
    result_buf: *mut c_void,
    buf: *mut c_char,
    buflen: usize,
    result: *mut *mut c_void,
) -> c_int {
    if result.is_null() {
        return libc::EINVAL;
    }
    if !tracked_object_fits(result) {
        return libc::EINVAL;
    }
    if name.is_null() || result_buf.is_null() || buf.is_null() {
        unsafe { *result = std::ptr::null_mut() };
        return libc::EINVAL;
    }
    unsafe { *result = std::ptr::null_mut() };
    if !tracked_object_fits(result_buf.cast::<libc::servent>()) {
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
        Some(entry)
    });

    let entry = match entry {
        Some(e) => e,
        None => return 0,
    };
    let (svc_name, port, svc_proto) = (&entry.name, entry.port, &entry.protocol);

    let name_len = svc_name.len() + 1;
    let proto_len = svc_proto.len() + 1;
    let effective_buflen = effective_c_buffer_len(buf, buflen);
    if name_len + proto_len > effective_buflen {
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

    let aliases_ptr = match unsafe {
        pack_caller_aliases(buf, effective_buflen, name_len + proto_len, &entry.aliases)
    } {
        Some(p) => p,
        None => return libc::ERANGE,
    };

    let servent = unsafe { &mut *result_buf.cast::<libc::servent>() };
    servent.s_name = name_ptr;
    servent.s_aliases = aliases_ptr;
    servent.s_port = port.to_be() as c_int;
    servent.s_proto = proto_ptr;

    unsafe { *result = result_buf };
    0
}

/// Bench-only: the pre-index `getservbyport_r`. See
/// `getservbyname_r_legacy_fs_per_call_for_bench`.
///
/// # Safety
/// Same contract as `getservbyport_r`.
#[doc(hidden)]
pub unsafe fn getservbyport_r_legacy_fs_per_call_for_bench(
    port: c_int,
    proto: *const c_char,
    result_buf: *mut c_void,
    buf: *mut c_char,
    buflen: usize,
    result: *mut *mut c_void,
) -> c_int {
    if result.is_null() {
        return libc::EINVAL;
    }
    if !tracked_object_fits(result) {
        return libc::EINVAL;
    }
    if result_buf.is_null() || buf.is_null() {
        unsafe { *result = std::ptr::null_mut() };
        return libc::EINVAL;
    }
    unsafe { *result = std::ptr::null_mut() };
    if !tracked_object_fits(result_buf.cast::<libc::servent>()) {
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
        Some(entry)
    });

    let entry = match entry {
        Some(e) => e,
        None => return 0,
    };
    let (svc_name, svc_proto) = (&entry.name, &entry.protocol);

    let name_len = svc_name.len() + 1;
    let proto_len = svc_proto.len() + 1;
    let effective_buflen = effective_c_buffer_len(buf, buflen);
    if name_len + proto_len > effective_buflen {
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

    let aliases_ptr = match unsafe {
        pack_caller_aliases(buf, effective_buflen, name_len + proto_len, &entry.aliases)
    } {
        Some(p) => p,
        None => return libc::ERANGE,
    };

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
