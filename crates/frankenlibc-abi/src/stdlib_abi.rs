//! ABI stubs for stdlib functions.
//!
//! Implements numeric conversion functions (`atoi`, `atol`, `strtol`, `strtoul`),
//! environment variables (`getenv`, `setenv`, `unsetenv`),
//! process control (`exit`, `atexit`), and sorting/searching (`qsort`, `bsearch`)
//! with membrane validation.

use std::cell::{Cell, RefCell};
use std::ffi::{
    c_char, c_double, c_int, c_long, c_longlong, c_uchar, c_uint, c_ulong, c_ulonglong, c_void,
};
use std::ptr;

use crate::errno_abi::set_abi_errno;
use crate::malloc_abi::known_remaining;
use crate::runtime_policy;
use crate::util::scan_c_string;
use frankenlibc_core::{errno, stdlib::conversion::ConversionStatus};

/// Length of a NUL-terminated numeric argument for the strto*/ato* family.
///
/// In deployed (non-test) builds this is a plain NUL scan — matching glibc's
/// "read until NUL/non-digit" model. `scan_c_string` unconditionally consults
/// `allocation_bound` → `malloc_abi::known_remaining` (deployed `fallback_remaining`
/// bookkeeping) on every call, which — together with the parse-time membrane —
/// dominates the deployed strtol cost (measured ~28 ns vs glibc ~6 ns for "42"
/// via the cdylib-equivalent `strtol_glibc_bench`, which builds the lib WITHOUT
/// cfg(test); a `--test` bench would instead route through validate_ptr and
/// overstate this). Unit-test builds keep the bounded scan so the allocation-bound
/// clamping stays exercised.
#[inline]
unsafe fn scan_numeric_c_string(ptr: *const c_char, bound: Option<usize>) -> (usize, bool) {
    if runtime_policy::stdlib_membrane_fastpath() {
        let mut i = 0usize;
        while unsafe { *ptr.add(i) } != 0 {
            i += 1;
        }
        (i, true)
    } else {
        unsafe { scan_c_string(ptr, bound) }
    }
}

#[inline]
const fn atoi_is_c_space(byte: u8) -> bool {
    byte == b' ' || (byte >= b'\t' && byte <= b'\r')
}

/// Deployed `ato*` specialization: POSIX defines `atoi`/`atol`/`atoll` as
/// base-10 `strtol`-family parses without an end pointer. Avoid the generic
/// scan-then-parse shape and parse directly from the C string until the first
/// non-digit.
#[inline]
unsafe fn parse_ato_decimal_i64(ptr: *const c_char) -> i64 {
    let mut cursor = ptr.cast::<u8>();

    loop {
        let byte = unsafe { *cursor };
        if !atoi_is_c_space(byte) {
            break;
        }
        cursor = unsafe { cursor.add(1) };
    }

    let mut byte = unsafe { *cursor };
    let negative = if byte == b'-' {
        cursor = unsafe { cursor.add(1) };
        byte = unsafe { *cursor };
        true
    } else if byte == b'+' {
        cursor = unsafe { cursor.add(1) };
        byte = unsafe { *cursor };
        false
    } else {
        false
    };

    if !byte.is_ascii_digit() {
        return 0;
    }

    let limit = if negative {
        (i64::MAX as u64) + 1
    } else {
        i64::MAX as u64
    };
    let cutoff = limit / 10;
    let cutlim = limit % 10;
    let mut acc = 0u64;

    loop {
        if !byte.is_ascii_digit() {
            break;
        }
        let digit = (byte - b'0') as u64;
        if acc > cutoff || (acc == cutoff && digit > cutlim) {
            return if negative { i64::MIN } else { i64::MAX };
        }
        acc = acc * 10 + digit;
        cursor = unsafe { cursor.add(1) };
        byte = unsafe { *cursor };
    }

    if negative {
        if acc == limit {
            i64::MIN
        } else {
            -(acc as i64)
        }
    } else {
        acc as i64
    }
}

#[inline]
const fn strtol_digit_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'z' => Some(byte - b'a' + 10),
        b'A'..=b'Z' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[inline]
const fn strtol_hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[inline]
const fn strtol_hex_digit_or_invalid(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => 0xff,
    }
}

#[inline]
unsafe fn parse_strtol_positive_decimal_fast(ptr: *const u8) -> (i64, usize, ConversionStatus) {
    // Caller has already proved the first byte is an unsigned decimal digit.
    let mut cursor = ptr;
    let mut acc = 0u64;
    let mut digits = 0usize;

    loop {
        let byte = unsafe { *cursor };
        let digit = byte.wrapping_sub(b'0');
        if digit > 9 {
            break;
        }

        let digit = digit as u64;
        if digits < 18 {
            acc = acc * 10 + digit;
        } else {
            let cutoff = (i64::MAX as u64) / 10;
            let cutlim = (i64::MAX as u64) % 10;
            if acc > cutoff || (acc == cutoff && digit > cutlim) {
                cursor = unsafe { cursor.add(1) };
                while unsafe { *cursor }.wrapping_sub(b'0') <= 9 {
                    cursor = unsafe { cursor.add(1) };
                }
                let consumed = unsafe { cursor.offset_from(ptr) as usize };
                return (i64::MAX, consumed, ConversionStatus::Overflow);
            }
            acc = acc * 10 + digit;
        }

        digits += 1;
        cursor = unsafe { cursor.add(1) };
    }

    let consumed = unsafe { cursor.offset_from(ptr) as usize };
    (acc as i64, consumed, ConversionStatus::Success)
}

#[inline]
unsafe fn parse_strtol_positive_hex_fast(ptr: *const u8) -> (i64, usize, ConversionStatus) {
    // Caller has already proved the first byte is a base-16 digit.
    let mut cursor = ptr;
    let mut byte = unsafe { *cursor };

    if byte == b'0' {
        let next = unsafe { *cursor.add(1) };
        if next == b'x' || next == b'X' {
            let after_prefix = unsafe { *cursor.add(2) };
            if strtol_hex_digit(after_prefix).is_some() {
                cursor = unsafe { cursor.add(2) };
                byte = after_prefix;
            }
        }
    }

    let mut acc = 0u64;
    let mut digits = 0usize;
    loop {
        let Some(digit) = strtol_hex_digit(byte) else {
            break;
        };
        let digit = digit as u64;
        if digits < 15 {
            acc = (acc << 4) | digit;
        } else {
            let cutoff = (i64::MAX as u64) >> 4;
            let cutlim = (i64::MAX as u64) & 0xf;
            if acc > cutoff || (acc == cutoff && digit > cutlim) {
                cursor = unsafe { cursor.add(1) };
                while strtol_hex_digit(unsafe { *cursor }).is_some() {
                    cursor = unsafe { cursor.add(1) };
                }
                let consumed = unsafe { cursor.offset_from(ptr) as usize };
                return (i64::MAX, consumed, ConversionStatus::Overflow);
            }
            acc = (acc << 4) | digit;
        }

        digits += 1;
        cursor = unsafe { cursor.add(1) };
        byte = unsafe { *cursor };
    }

    let consumed = unsafe { cursor.offset_from(ptr) as usize };
    (acc as i64, consumed, ConversionStatus::Success)
}

#[inline]
unsafe fn parse_strtol_positive_prefixed_hex_fast(
    ptr: *const u8,
) -> (i64, usize, ConversionStatus) {
    // Caller has already proved `ptr` starts with 0x/0X followed by a hex digit.
    let mut cursor = unsafe { ptr.add(2) };
    let mut acc = 0u64;
    let mut digits = 0usize;

    loop {
        let digit = strtol_hex_digit_or_invalid(unsafe { *cursor });
        if digit > 15 {
            break;
        }

        let digit = digit as u64;
        if digits < 15 {
            acc = (acc << 4) | digit;
        } else {
            let cutoff = (i64::MAX as u64) >> 4;
            let cutlim = (i64::MAX as u64) & 0xf;
            if acc > cutoff || (acc == cutoff && digit > cutlim) {
                cursor = unsafe { cursor.add(1) };
                while strtol_hex_digit_or_invalid(unsafe { *cursor }) <= 15 {
                    cursor = unsafe { cursor.add(1) };
                }
                let consumed = unsafe { cursor.offset_from(ptr) as usize };
                return (i64::MAX, consumed, ConversionStatus::Overflow);
            }
            acc = (acc << 4) | digit;
        }

        digits += 1;
        cursor = unsafe { cursor.add(1) };
    }

    let consumed = unsafe { cursor.offset_from(ptr) as usize };
    (acc as i64, consumed, ConversionStatus::Success)
}

/// Deployed `strtol` specialization for the hot bases measured in the
/// glibc head-to-head bench. It fuses the NUL scan and parse so `endptr` comes
/// from the same cursor that found the first non-digit.
#[inline]
unsafe fn parse_strtol_c_string_fast(
    ptr: *const c_char,
    base: c_int,
) -> Option<(i64, usize, ConversionStatus)> {
    if base != 10 && base != 16 {
        return None;
    }

    let start = ptr.cast::<u8>();
    let first = unsafe { *start };
    if base == 10 && first.wrapping_sub(b'0') <= 9 {
        return Some(unsafe { parse_strtol_positive_decimal_fast(start) });
    }
    if base == 16 && first == b'0' {
        let second = unsafe { *start.add(1) };
        if (second == b'x' || second == b'X')
            && strtol_hex_digit_or_invalid(unsafe { *start.add(2) }) <= 15
        {
            return Some(unsafe { parse_strtol_positive_prefixed_hex_fast(start) });
        }
    }
    if base == 16 && strtol_hex_digit(first).is_some() {
        return Some(unsafe { parse_strtol_positive_hex_fast(start) });
    }

    let mut cursor = start;
    loop {
        let byte = unsafe { *cursor };
        if !atoi_is_c_space(byte) {
            break;
        }
        cursor = unsafe { cursor.add(1) };
    }

    let mut byte = unsafe { *cursor };
    let negative = if byte == b'-' {
        cursor = unsafe { cursor.add(1) };
        byte = unsafe { *cursor };
        true
    } else if byte == b'+' {
        cursor = unsafe { cursor.add(1) };
        byte = unsafe { *cursor };
        false
    } else {
        false
    };

    let radix = base as u64;
    if base == 16 && byte == b'0' {
        let next = unsafe { *cursor.add(1) };
        if next == b'x' || next == b'X' {
            let after_prefix = unsafe { *cursor.add(2) };
            if matches!(strtol_digit_value(after_prefix), Some(digit) if digit < 16) {
                cursor = unsafe { cursor.add(2) };
                byte = after_prefix;
            }
        }
    }

    let limit = if negative {
        (i64::MAX as u64) + 1
    } else {
        i64::MAX as u64
    };
    let cutoff = limit / radix;
    let cutlim = limit % radix;
    let mut acc = 0u64;
    let mut any_digits = false;
    let mut overflow = false;

    while let Some(digit) = strtol_digit_value(byte) {
        let digit = digit as u64;
        if digit >= radix {
            break;
        }
        any_digits = true;
        if !overflow {
            if acc > cutoff || (acc == cutoff && digit > cutlim) {
                overflow = true;
            } else {
                acc = acc * radix + digit;
            }
        }
        cursor = unsafe { cursor.add(1) };
        byte = unsafe { *cursor };
    }

    if !any_digits {
        return Some((0, 0, ConversionStatus::Success));
    }

    let consumed = unsafe { cursor.offset_from(ptr.cast::<u8>()) as usize };
    if overflow {
        if negative {
            return Some((i64::MIN, consumed, ConversionStatus::Underflow));
        }
        return Some((i64::MAX, consumed, ConversionStatus::Overflow));
    }

    let value = if negative {
        if acc == limit {
            i64::MIN
        } else {
            -(acc as i64)
        }
    } else {
        acc as i64
    };
    Some((value, consumed, ConversionStatus::Success))
}

/// Deployed `strtod` specialization for short decimal tokens whose grammar is
/// regular enough to parse as a C-string transducer. Exact integer-valued
/// decimals (`12345`, `1.234567e10`) stay on the integer path; short fixed
/// decimals (`3.14159`) hand the already-scanned token to Rust's
/// correctly-rounded parser without the full core parser's extra NUL scan.
#[inline]
pub(crate) unsafe fn parse_strtod_short_decimal_c_string_fast(
    ptr: *const c_char,
) -> Option<(f64, usize)> {
    const MAX_EXACT_INTEGER: u64 = 1u64 << f64::MANTISSA_DIGITS;
    const MAX_FIXED_SIGNIFICANT_DIGITS: u32 = 15;

    let start = ptr.cast::<u8>();
    let mut cursor = start;

    loop {
        let byte = unsafe { *cursor };
        if !atoi_is_c_space(byte) {
            break;
        }
        cursor = unsafe { cursor.add(1) };
    }

    let token_start = cursor;
    let mut byte = unsafe { *cursor };
    let negative = if byte == b'-' {
        cursor = unsafe { cursor.add(1) };
        byte = unsafe { *cursor };
        true
    } else if byte == b'+' {
        cursor = unsafe { cursor.add(1) };
        byte = unsafe { *cursor };
        false
    } else {
        false
    };

    if byte == b'i' || byte == b'I' || byte == b'n' || byte == b'N' {
        return None;
    }
    if byte == b'0' {
        let next = unsafe { *cursor.add(1) };
        if next == b'x' || next == b'X' {
            return None;
        }
    }

    let mut acc = 0u64;
    let mut saw_digit = false;
    let mut saw_dot = false;
    let mut frac_digits = 0i32;
    let mut significant_digits = 0u32;

    loop {
        byte = unsafe { *cursor };
        if byte.is_ascii_digit() {
            saw_digit = true;
            if saw_dot {
                frac_digits = frac_digits.checked_add(1)?;
                if frac_digits > 400 {
                    return None;
                }
            }

            let digit = (byte - b'0') as u64;
            if acc != 0 || digit != 0 {
                acc = acc.checked_mul(10)?.checked_add(digit)?;
                significant_digits = significant_digits.checked_add(1)?;
                if acc > MAX_EXACT_INTEGER {
                    return None;
                }
            }
            cursor = unsafe { cursor.add(1) };
        } else if byte == b'.' && !saw_dot {
            saw_dot = true;
            cursor = unsafe { cursor.add(1) };
        } else {
            break;
        }
    }

    if !saw_digit {
        return None;
    }

    let mut exp10 = 0i32;
    let mut saw_exponent = false;
    byte = unsafe { *cursor };
    if byte == b'e' || byte == b'E' {
        let exponent_start = cursor;
        cursor = unsafe { cursor.add(1) };
        byte = unsafe { *cursor };

        let exponent_negative = if byte == b'-' {
            cursor = unsafe { cursor.add(1) };
            true
        } else if byte == b'+' {
            cursor = unsafe { cursor.add(1) };
            false
        } else {
            false
        };

        let mut saw_exponent_digit = false;
        let mut exponent = 0i32;
        loop {
            byte = unsafe { *cursor };
            if !byte.is_ascii_digit() {
                break;
            }
            saw_exponent_digit = true;
            exponent = exponent
                .checked_mul(10)?
                .checked_add((byte - b'0') as i32)?;
            if exponent > 400 {
                return None;
            }
            cursor = unsafe { cursor.add(1) };
        }

        if saw_exponent_digit {
            saw_exponent = true;
            exp10 = if exponent_negative {
                exponent.checked_neg()?
            } else {
                exponent
            };
        } else {
            cursor = exponent_start;
        }
    }

    let consumed = unsafe { cursor.offset_from(start) as usize };
    let mut shift = exp10.checked_sub(frac_digits)?;
    while shift < 0 {
        if !saw_exponent && frac_digits <= 15 && significant_digits <= MAX_FIXED_SIGNIFICANT_DIGITS
        {
            let token_len = unsafe { cursor.offset_from(token_start) as usize };
            let token = unsafe { std::slice::from_raw_parts(token_start, token_len) };
            let token = unsafe { core::str::from_utf8_unchecked(token) };
            return token.parse::<f64>().ok().map(|value| (value, consumed));
        }
        if acc % 10 != 0 {
            return None;
        }
        acc /= 10;
        shift += 1;
    }

    if acc == 0 {
        return Some((if negative { -0.0 } else { 0.0 }, consumed));
    }
    if shift > 22 {
        return None;
    }

    let mut value = acc;
    for _ in 0..shift {
        if value > MAX_EXACT_INTEGER / 10 {
            return None;
        }
        value *= 10;
    }

    let value = value as f64;
    Some((if negative { -value } else { value }, consumed))
}

use frankenlibc_core::syscall as raw_syscall;
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};
use libc::{intmax_t, uintmax_t};

const MAX_LEGACY_CVT_DIGITS: usize = 512;

#[derive(Clone, Copy)]
struct GetenvNameProbe {
    len: usize,
    terminated: bool,
    valid: bool,
    lo: u64,
    hi: u64,
}

#[derive(Clone, Copy)]
struct GetenvHotCache {
    epoch: u64,
    name_ptr: usize,
    name_len: usize,
    lo: u64,
    hi: u64,
    result: usize,
}

impl GetenvHotCache {
    const fn empty() -> Self {
        Self {
            epoch: 0,
            name_ptr: 0,
            name_len: 0,
            lo: 0,
            hi: 0,
            result: 0,
        }
    }
}

thread_local! {
    static GETENV_HOT_CACHE: Cell<GetenvHotCache> = const { Cell::new(GetenvHotCache::empty()) };
}

#[cfg(feature = "owned-tls-cache")]
struct StdlibTls {
    shell_idx: Cell<usize>,
    shell_cache: RefCell<Vec<String>>,
    qecvt_buf: RefCell<[u8; 128]>,
    qfcvt_buf: RefCell<[u8; 128]>,
}

#[cfg(feature = "owned-tls-cache")]
fn new_stdlib_tls() -> StdlibTls {
    StdlibTls {
        shell_idx: Cell::new(0),
        shell_cache: RefCell::new(Vec::new()),
        qecvt_buf: RefCell::new([0u8; 128]),
        qfcvt_buf: RefCell::new([0u8; 128]),
    }
}

#[cfg(feature = "owned-tls-cache")]
static STDLIB_OWNED_TLS: crate::owned_tls_cache::OwnedTlsCache<StdlibTls> =
    crate::owned_tls_cache::OwnedTlsCache::new(new_stdlib_tls);

#[inline]
fn repair_enabled(heals_enabled: bool, action: MembraneAction) -> bool {
    heals_enabled || matches!(action, MembraneAction::Repair(_))
}

#[inline]
unsafe fn set_abi_errno_if_clear(err: c_int) {
    let slot = unsafe { crate::errno_abi::__errno_location() };
    if unsafe { std::ptr::read_volatile(slot) } == 0 {
        unsafe { set_abi_errno(err) };
    }
}

const MAX_EXPLICIT_BZERO_LEN: usize = isize::MAX as usize;
const ENV_NAME_SCAN_LIMIT: usize = 131_072;
const NUMERIC_STRING_SCAN_LIMIT: usize = 131_072;

#[inline]
fn bounded_zero_len(ptr: *mut c_void, requested: usize) -> Option<usize> {
    let len = known_remaining(ptr as usize)
        .map(|remaining| remaining.min(requested))
        .unwrap_or(requested);
    (len <= MAX_EXPLICIT_BZERO_LEN).then_some(len)
}

#[inline]
fn tracked_char_output_capacity(ptr: *mut c_char, requested: usize) -> usize {
    known_remaining(ptr as usize).map_or(requested, |remaining| remaining.min(requested))
}

#[inline]
unsafe fn read_bounded_cstr_bytes(ptr: *const c_char) -> Option<Vec<u8>> {
    if ptr.is_null() {
        return None;
    }
    let (len, terminated) = unsafe { scan_c_string(ptr, known_remaining(ptr as usize)) };
    if !terminated {
        return None;
    }
    let bytes = unsafe { core::slice::from_raw_parts(ptr.cast::<u8>(), len) };
    Some(bytes.to_vec())
}

#[inline]
fn env_name_scan_bound(ptr: *const c_char) -> usize {
    known_remaining(ptr as usize)
        .map(|remaining| remaining.min(ENV_NAME_SCAN_LIMIT))
        .unwrap_or(ENV_NAME_SCAN_LIMIT)
}

#[inline]
fn numeric_string_scan_bound(ptr: *const c_char) -> usize {
    known_remaining(ptr as usize)
        .map(|remaining| remaining.min(NUMERIC_STRING_SCAN_LIMIT))
        .unwrap_or(NUMERIC_STRING_SCAN_LIMIT)
}

#[inline]
unsafe fn scan_terminated_numeric_string(ptr: *const c_char) -> Option<usize> {
    let (len, terminated) = unsafe { scan_c_string(ptr, Some(numeric_string_scan_bound(ptr))) };
    terminated.then_some(len)
}

#[inline]
unsafe fn scan_suboption_end(ptr: *mut c_char) -> Option<(*mut c_char, bool)> {
    let bound = known_remaining(ptr as usize);
    let mut len = 0usize;
    loop {
        if bound.is_some_and(|remaining| len >= remaining) {
            return None;
        }
        let current = unsafe { ptr.add(len) };
        let byte = unsafe { *current };
        if byte == 0 {
            return Some((current, false));
        }
        if byte == b',' as c_char {
            return Some((current, true));
        }
        len += 1;
    }
}

#[inline]
unsafe fn candidate_matches_name(
    candidate: *const c_char,
    name: *const c_char,
    name_len: usize,
) -> bool {
    if candidate.is_null() {
        return false;
    }
    let (candidate_len, terminated) =
        unsafe { scan_c_string(candidate, known_remaining(candidate as usize)) };
    if !terminated || candidate_len != name_len {
        return false;
    }
    let candidate_bytes =
        unsafe { core::slice::from_raw_parts(candidate.cast::<u8>(), candidate_len) };
    let name_bytes = unsafe { core::slice::from_raw_parts(name.cast::<u8>(), name_len) };
    candidate_bytes == name_bytes
}

unsafe extern "C" {
    #[link_name = "__environ"]
    static mut HOST_ENVIRON: *mut *mut c_char;
}

#[inline]
unsafe fn native_getenv(name_bytes: &[u8]) -> *mut c_char {
    unsafe { native_getenv_raw(name_bytes.as_ptr(), name_bytes.len()) }
}

#[inline]
unsafe fn native_getenv_raw(name_ptr: *const u8, name_len: usize) -> *mut c_char {
    // Hold ENVIRON_LOCK during the array walk so a concurrent setenv that
    // host_passthrough_realloc()s the HOST_ENVIRON array out from under us
    // cannot turn this read into a use-after-free. The lock is released
    // before we return the entry-value pointer; callers that retain the
    // pointer across a subsequent setenv must accept POSIX's documented
    // "value may be overwritten by setenv" semantics. (REVIEW round 3.)
    //
    // Single-threaded fast path: `ENVIRON_LOCK` is a reentrant mutex whose
    // `lock()` issues a `gettid()` SYSCALL every call (~hundreds of ns —
    // measured deployed getenv at ~560 ns vs glibc ~14 ns). While the process is
    // single-threaded there can be no concurrent setenv, so the lock (and its
    // syscall) is pure overhead — skip it, exactly as glibc skips its lock while
    // `__libc_single_threaded` is set. The flag flips to 0 at the first
    // pthread_create, restoring the lock for all subsequent concurrent access.
    let _lock = if crate::glibc_internal_abi::__libc_single_threaded
        .load(std::sync::atomic::Ordering::Acquire)
        == 0
    {
        Some(ENVIRON_LOCK.lock())
    } else {
        None
    };
    // SAFETY: HOST_ENVIRON is owned by libc; we only read pointers/bytes
    // and the array layout is stable while we hold the mutator lock.
    unsafe {
        let mut cursor = HOST_ENVIRON;
        if cursor.is_null() {
            return ptr::null_mut();
        }
        while !(*cursor).is_null() {
            let entry = *cursor as *const u8;
            let mut i = 0usize;
            while i < name_len && *entry.add(i) == *name_ptr.add(i) {
                i += 1;
            }
            if i == name_len && *entry.add(i) == b'=' {
                return entry.add(i + 1) as *mut c_char;
            }
            cursor = cursor.add(1);
        }
        ptr::null_mut()
    }
}

#[inline]
unsafe fn scan_env_name_fast(name: *const c_char, bound: usize) -> GetenvNameProbe {
    let mut i = 0usize;
    let mut valid = true;
    let mut lo = 0u64;
    let mut hi = 0u64;
    while i < bound {
        let byte = unsafe { *name.add(i) as u8 };
        if byte == 0 {
            return GetenvNameProbe {
                len: i,
                terminated: true,
                valid: valid && i != 0,
                lo,
                hi,
            };
        }
        if byte == b'=' {
            valid = false;
        }
        if i < 8 {
            lo |= u64::from(byte) << (i * 8);
        } else if i < 16 {
            hi |= u64::from(byte) << ((i - 8) * 8);
        }
        i += 1;
    }
    GetenvNameProbe {
        len: i,
        terminated: false,
        valid: false,
        lo,
        hi,
    }
}

// ---------------------------------------------------------------------------
// Native environ manipulation — no host delegation
// ---------------------------------------------------------------------------
//
// setenv/unsetenv/putenv directly manipulate the HOST_ENVIRON array.
// On first mutation that requires growing the array, we copy it to our
// own malloc'd buffer (the original is on the process stack from crt0).

/// Whether we've already copied environ to our own allocation.
static ENVIRON_OWNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Incremented after every successful environment mutation. The deployed
/// single-threaded `getenv` cache uses this as its coherence fence.
static ENVIRON_EPOCH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

#[inline]
fn bump_environ_epoch() {
    ENVIRON_EPOCH.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
}

#[inline]
fn getenv_hot_cache_enabled() -> bool {
    cfg!(not(test))
        && crate::glibc_internal_abi::__libc_single_threaded
            .load(std::sync::atomic::Ordering::Acquire)
            != 0
}

#[inline]
unsafe fn getenv_cached_name_matches(name: *const c_char, cache: GetenvHotCache) -> bool {
    let name = name.cast::<u8>();
    for i in 0..cache.name_len {
        let byte = unsafe { *name.add(i) };
        let expected = if i < 8 {
            (cache.lo >> (i * 8)) as u8
        } else {
            (cache.hi >> ((i - 8) * 8)) as u8
        };
        if byte != expected {
            return false;
        }
    }
    unsafe { *name.add(cache.name_len) == 0 }
}

#[inline]
unsafe fn getenv_hot_cache_lookup_same_ptr(name: *const c_char) -> Option<*mut c_char> {
    if !getenv_hot_cache_enabled() {
        return None;
    }
    let epoch = ENVIRON_EPOCH.load(std::sync::atomic::Ordering::Acquire);
    GETENV_HOT_CACHE.with(|slot| {
        let cache = slot.get();
        if cache.epoch == epoch
            && cache.name_ptr == name as usize
            && cache.name_len <= 16
            && unsafe { getenv_cached_name_matches(name, cache) }
        {
            Some(cache.result as *mut c_char)
        } else {
            None
        }
    })
}

#[inline]
fn getenv_hot_cache_lookup(probe: GetenvNameProbe) -> Option<*mut c_char> {
    if !getenv_hot_cache_enabled() || probe.len > 16 {
        return None;
    }
    let epoch = ENVIRON_EPOCH.load(std::sync::atomic::Ordering::Acquire);
    GETENV_HOT_CACHE.with(|slot| {
        let cache = slot.get();
        (cache.epoch == epoch
            && cache.name_len == probe.len
            && cache.lo == probe.lo
            && cache.hi == probe.hi)
            .then_some(cache.result as *mut c_char)
    })
}

#[inline]
fn getenv_hot_cache_store(name: *const c_char, probe: GetenvNameProbe, result: *mut c_char) {
    if !getenv_hot_cache_enabled() || probe.len > 16 {
        return;
    }
    let epoch = ENVIRON_EPOCH.load(std::sync::atomic::Ordering::Acquire);
    GETENV_HOT_CACHE.with(|slot| {
        slot.set(GetenvHotCache {
            epoch,
            name_ptr: name as usize,
            name_len: probe.len,
            lo: probe.lo,
            hi: probe.hi,
            result: result as usize,
        });
    });
}

/// Re-entrant mutex protecting all environ mutations and reads. Re-entrant
/// because host_passthrough_malloc / host_passthrough_realloc that we invoke
/// while holding the lock can transitively re-enter our getenv during early
/// glibc malloc initialization (MALLOC_PERTURB_/MALLOC_CHECK_ probes); a
/// non-reentrant Mutex would self-deadlock in that window.
pub(crate) static ENVIRON_LOCK: crate::util::AbiReentrantMutex<()> =
    crate::util::AbiReentrantMutex::new(());

/// Acquire `ENVIRON_LOCK` only when the process is multi-threaded.
///
/// `AbiReentrantMutex::lock()` issues a `gettid()` SYSCALL every call (via
/// `current_tid()`), and the lock exists solely to keep a concurrent `setenv`
/// from reallocating the environ table out from under another thread. While
/// `__libc_single_threaded` is set there is no concurrent access, so the lock —
/// and its syscall — is pure overhead (measured: setenv ~6x, getenv was ~40x).
/// The flag flips to 0 at the first `pthread_create`, restoring the lock for all
/// subsequent concurrent env access. Mirrors glibc's single-threaded lock elision.
#[inline]
fn environ_lock_guard() -> Option<crate::util::AbiReentrantMutexGuard<'static, ()>> {
    if crate::glibc_internal_abi::__libc_single_threaded.load(std::sync::atomic::Ordering::Acquire)
        == 0
    {
        Some(ENVIRON_LOCK.lock())
    } else {
        None
    }
}

/// Cross-module helper: run `f` with the environ array held stable. Other
/// ABI modules (process_abi for PATH lookup, etc.) need to walk environ
/// without UAFing on a concurrent setenv realloc; this acquires the same
/// lock the mutators use.
pub(crate) fn with_environ_locked<R>(f: impl FnOnce(*mut *mut c_char) -> R) -> R {
    let _lock = environ_lock_guard();
    // SAFETY: HOST_ENVIRON is the libc environ pointer; the lock guards the
    // array layout against concurrent realloc by setenv/unsetenv/clearenv.
    let envp = unsafe { HOST_ENVIRON };
    f(envp)
}

/// Count entries in the current environ array (excluding NULL terminator).
unsafe fn environ_len() -> usize {
    if unsafe { HOST_ENVIRON.is_null() } {
        return 0;
    }
    let mut n = 0usize;
    unsafe {
        while !(*HOST_ENVIRON.add(n)).is_null() {
            n += 1;
        }
    }
    n
}

/// Transfer ownership of the process environ array during startup (bd-zh1y.6.1).
///
/// Deep-copies the host environ into our own allocation so setenv/unsetenv can
/// safely realloc. Safe to call multiple times (idempotent). Must be called
/// after `init_environment_globals` has set the environ aliases.
pub fn take_environ_ownership() {
    let _lock = environ_lock_guard();
    // SAFETY: we hold the environ lock.
    let _ = unsafe { ensure_environ_owned() };
}

/// Ensure environ is in our own allocation so we can grow it.
/// Must be called with ENVIRON_LOCK held.
unsafe fn ensure_environ_owned() -> bool {
    use std::sync::atomic::Ordering;
    if ENVIRON_OWNED.load(Ordering::Acquire) {
        return true;
    }
    let count = unsafe { environ_len() };
    // Allocate count + 1 (for NULL) + 8 (growth room) pointers
    let Some(new_bytes) = count
        .checked_add(9)
        .and_then(|cap| cap.checked_mul(core::mem::size_of::<*mut c_char>()))
    else {
        return false;
    };
    let new_array =
        unsafe { crate::malloc_abi::host_passthrough_malloc(new_bytes) } as *mut *mut c_char;
    if new_array.is_null() {
        return false; // OOM — keep using original
    }
    if !unsafe { HOST_ENVIRON.is_null() } {
        unsafe {
            std::ptr::copy_nonoverlapping(HOST_ENVIRON, new_array, count);
        }
    }
    unsafe { *new_array.add(count) = std::ptr::null_mut() };
    unsafe { HOST_ENVIRON = new_array };
    ENVIRON_OWNED.store(true, Ordering::Release);
    true
}

/// Native setenv: scan environ for NAME=, replace or append.
#[inline]
unsafe fn native_setenv(
    name: *const c_char,
    name_len: usize,
    value: *const c_char,
    val_len: usize,
    overwrite: c_int,
) -> c_int {
    if name.is_null() || value.is_null() || name_len == 0 {
        return -1;
    }
    for i in 0..name_len {
        if unsafe { *name.add(i) } == b'=' as c_char {
            return -1;
        }
    }

    let _lock = environ_lock_guard();
    let environ_owned = unsafe { ensure_environ_owned() };

    // Build "NAME=value" string
    let Some(entry_len) = name_len
        .checked_add(1)
        .and_then(|len| len.checked_add(val_len))
        .and_then(|len| len.checked_add(1))
    else {
        unsafe { set_abi_errno(libc::ENOMEM) };
        return -1;
    };
    let new_entry = unsafe { crate::malloc_abi::host_passthrough_malloc(entry_len) } as *mut c_char;
    if new_entry.is_null() {
        unsafe { set_abi_errno(libc::ENOMEM) };
        return -1;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(name as *const u8, new_entry as *mut u8, name_len);
        *new_entry.add(name_len) = b'=' as c_char;
        if !value.is_null() {
            std::ptr::copy_nonoverlapping(
                value as *const u8,
                new_entry.add(name_len + 1) as *mut u8,
                val_len,
            );
        }
        *new_entry.add(name_len + 1 + val_len) = 0;
    }

    // Scan for existing entry
    if !unsafe { HOST_ENVIRON.is_null() } {
        let mut i = 0usize;
        unsafe {
            while !(*HOST_ENVIRON.add(i)).is_null() {
                let entry = *HOST_ENVIRON.add(i) as *const u8;
                let mut match_len = 0usize;
                while match_len < name_len
                    && *entry.add(match_len) == *(name as *const u8).add(match_len)
                {
                    match_len += 1;
                }
                if match_len == name_len && *entry.add(match_len) == b'=' {
                    if overwrite == 0 {
                        crate::malloc_abi::host_passthrough_free(new_entry as *mut c_void);
                        return 0; // already exists, don't overwrite
                    }
                    // Replace existing entry
                    *HOST_ENVIRON.add(i) = new_entry;
                    return 0;
                }
                i += 1;
            }
        }
    }

    // Not found — append to environ
    let count = unsafe { environ_len() };
    if !environ_owned && !unsafe { HOST_ENVIRON.is_null() } {
        unsafe {
            crate::malloc_abi::host_passthrough_free(new_entry as *mut c_void);
            set_abi_errno(libc::ENOMEM);
        }
        return -1;
    }
    // May need to grow the array
    let Some(new_array_bytes) = count
        .checked_add(2)
        .and_then(|cap| cap.checked_mul(core::mem::size_of::<*mut c_char>()))
    else {
        unsafe {
            crate::malloc_abi::host_passthrough_free(new_entry as *mut c_void);
            set_abi_errno(libc::ENOMEM);
        }
        return -1;
    };
    let new_array = unsafe {
        crate::malloc_abi::host_passthrough_realloc(HOST_ENVIRON as *mut c_void, new_array_bytes)
    } as *mut *mut c_char;
    if new_array.is_null() {
        unsafe {
            crate::malloc_abi::host_passthrough_free(new_entry as *mut c_void);
            set_abi_errno(libc::ENOMEM);
        }
        return -1;
    }
    unsafe {
        HOST_ENVIRON = new_array;
        *HOST_ENVIRON.add(count) = new_entry;
        *HOST_ENVIRON.add(count + 1) = std::ptr::null_mut();
    }
    0
}

/// Native unsetenv: scan and remove from environ.
#[inline]
unsafe fn native_unsetenv(name: *const c_char, name_len: usize) -> c_int {
    let _lock = environ_lock_guard();
    unsafe { remove_from_environ(name, name_len) }
}

/// Native putenv: store the string directly in environ (no copy).
/// Unlike setenv, the string must remain valid for the lifetime of the process.
unsafe fn native_putenv_impl(string: *mut c_char) -> c_int {
    if string.is_null() {
        return -1;
    }
    let (len, terminated) = unsafe { scan_c_string(string, known_remaining(string as usize)) };
    if !terminated {
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }
    let bytes = unsafe { std::slice::from_raw_parts(string.cast::<u8>(), len) };
    let eq_pos = match bytes.iter().position(|&b| b == b'=') {
        Some(p) => p,
        None => {
            // No '=': unset the variable (glibc behavior)
            let _lock = environ_lock_guard();
            return unsafe { remove_from_environ(string, len) };
        }
    };
    let name_len = eq_pos;

    let _lock = environ_lock_guard();
    let environ_owned = unsafe { ensure_environ_owned() };

    // Scan for existing entry with same name
    if !unsafe { HOST_ENVIRON.is_null() } {
        let mut i = 0usize;
        unsafe {
            while !(*HOST_ENVIRON.add(i)).is_null() {
                let entry = *HOST_ENVIRON.add(i) as *const u8;
                let mut match_len = 0usize;
                while match_len < name_len
                    && *entry.add(match_len) == *(string as *const u8).add(match_len)
                {
                    match_len += 1;
                }
                if match_len == name_len && *entry.add(match_len) == b'=' {
                    // Replace existing entry (putenv always overwrites)
                    *HOST_ENVIRON.add(i) = string;
                    return 0;
                }
                i += 1;
            }
        }
    }

    // Not found — append
    let count = unsafe { environ_len() };
    if !environ_owned && !unsafe { HOST_ENVIRON.is_null() } {
        unsafe { set_abi_errno(libc::ENOMEM) };
        return -1;
    }
    let Some(new_array_bytes) = count
        .checked_add(2)
        .and_then(|cap| cap.checked_mul(core::mem::size_of::<*mut c_char>()))
    else {
        unsafe { set_abi_errno(libc::ENOMEM) };
        return -1;
    };
    let new_array = unsafe {
        crate::malloc_abi::host_passthrough_realloc(HOST_ENVIRON as *mut c_void, new_array_bytes)
    } as *mut *mut c_char;
    if new_array.is_null() {
        unsafe { set_abi_errno(libc::ENOMEM) };
        return -1;
    }
    unsafe {
        HOST_ENVIRON = new_array;
        *HOST_ENVIRON.add(count) = string;
        *HOST_ENVIRON.add(count + 1) = std::ptr::null_mut();
    }
    0
}

/// Remove an env var by directly manipulating the environ array.
unsafe fn remove_from_environ(name: *const c_char, nlen: usize) -> c_int {
    unsafe {
        if HOST_ENVIRON.is_null() || name.is_null() {
            return 0;
        }
        let mut read = HOST_ENVIRON;
        let mut write = HOST_ENVIRON;
        while !(*read).is_null() {
            let entry = *read as *const u8;
            let mut match_len = 0usize;
            while match_len < nlen && *entry.add(match_len) == *(name as *const u8).add(match_len) {
                match_len += 1;
            }
            if match_len == nlen && *entry.add(match_len) == b'=' {
                // Skip this entry (remove it)
                read = read.add(1);
                continue;
            }
            *write = *read;
            write = write.add(1);
            read = read.add(1);
        }
        *write = std::ptr::null_mut();
        0
    }
}

#[inline]
fn getenv_bootstrap_sensitive() -> bool {
    runtime_policy::bootstrap_passthrough_active()
        || crate::membrane_state::pipeline_initialization_active()
        || crate::malloc_abi::in_allocator_reentry_context()
        || crate::pthread_abi::in_threading_policy_context()
        || frankenlibc_membrane::ptr_validator::in_validation_context()
}

// ---------------------------------------------------------------------------
// atoi
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atoi(nptr: *const c_char) -> c_int {
    if nptr.is_null() {
        return 0;
    }

    if runtime_policy::stdlib_membrane_fastpath() {
        return unsafe { parse_ato_decimal_i64(nptr) } as c_int;
    }

    let known = known_remaining(nptr as usize);
    let (mode, decision) = runtime_policy::decide(
        ApiFamily::Stdlib,
        nptr as usize,
        0,
        false,
        known.is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 6, true);
        return 0;
    }

    let bound = if repair_enabled(mode.heals_enabled(), decision.action) {
        known
    } else {
        None
    };

    let (len, _terminated) = unsafe { scan_numeric_c_string(nptr, bound) };
    let slice = unsafe { std::slice::from_raw_parts(nptr as *const u8, len) };
    let result = frankenlibc_core::stdlib::atoi(slice);

    runtime_policy::observe(
        ApiFamily::Stdlib,
        decision.profile,
        runtime_policy::scaled_cost(7, len),
        false,
    );
    result
}

// ---------------------------------------------------------------------------
// atol
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atol(nptr: *const c_char) -> c_long {
    if nptr.is_null() {
        return 0;
    }

    if runtime_policy::stdlib_membrane_fastpath() {
        return unsafe { parse_ato_decimal_i64(nptr) } as c_long;
    }

    let known = known_remaining(nptr as usize);
    let (mode, decision) = runtime_policy::decide(
        ApiFamily::Stdlib,
        nptr as usize,
        0,
        false,
        known.is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 6, true);
        return 0;
    }

    let bound = if repair_enabled(mode.heals_enabled(), decision.action) {
        known
    } else {
        None
    };

    let (len, _terminated) = unsafe { scan_numeric_c_string(nptr, bound) };
    let slice = unsafe { std::slice::from_raw_parts(nptr as *const u8, len) };
    let result = frankenlibc_core::stdlib::atol(slice);

    runtime_policy::observe(
        ApiFamily::Stdlib,
        decision.profile,
        runtime_policy::scaled_cost(7, len),
        false,
    );
    result as c_long
}

// ---------------------------------------------------------------------------
// atoll
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atoll(nptr: *const c_char) -> c_longlong {
    unsafe { atol(nptr) as c_longlong }
}

// ---------------------------------------------------------------------------
// strtol
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strtol(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
) -> c_long {
    if nptr.is_null() {
        return 0;
    }

    // Deployed fast-path (measured: strtol "42" ~28→~12 ns vs glibc ~6 ns).
    // Stdlib is always-Allow in non-test, so the per-call decide()+observe()
    // membrane is pure overhead (the parse reads the string regardless). strtol
    // pays it TWICE — `nptr` and the always-Allow `endptr` write-decide. `profile`
    // is `Some` only on the full (test) path, which still exercises deny/observe/
    // repair. Mirrors `strtod`.
    let (profile, bound) = if runtime_policy::stdlib_membrane_fastpath() {
        (None, None)
    } else {
        let (mode, decision) = runtime_policy::decide(
            ApiFamily::Stdlib,
            nptr as usize,
            0,
            false,
            known_remaining(nptr as usize).is_none(),
            0,
        );
        if matches!(decision.action, MembraneAction::Deny) {
            runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 6, true);
            return 0;
        }

        let bound = if repair_enabled(mode.heals_enabled(), decision.action) {
            known_remaining(nptr as usize)
        } else {
            None
        };

        if !endptr.is_null() {
            let (_, end_decision) = runtime_policy::decide(
                ApiFamily::Stdlib,
                endptr as usize,
                std::mem::size_of::<*mut c_char>(),
                true,
                true,
                0,
            );
            if matches!(end_decision.action, MembraneAction::Deny) {
                return 0;
            }
        }
        (Some(decision.profile), bound)
    };

    if profile.is_none()
        && let Some((val, consumed, status)) = unsafe { parse_strtol_c_string_fast(nptr, base) }
    {
        match status {
            ConversionStatus::Overflow | ConversionStatus::Underflow => unsafe {
                set_abi_errno(libc::ERANGE)
            },
            ConversionStatus::InvalidBase => unsafe {
                set_abi_errno(libc::EINVAL);
                return 0;
            },
            ConversionStatus::Success => {}
        }

        if !endptr.is_null() {
            unsafe {
                *endptr = (nptr as *mut c_char).add(consumed);
            }
        }
        return val as c_long;
    }

    let (len, _terminated) = unsafe { scan_numeric_c_string(nptr, bound) };
    let slice = unsafe { std::slice::from_raw_parts(nptr as *const u8, len) };

    let (val, consumed, status) = frankenlibc_core::stdlib::conversion::strtol_impl(slice, base);

    if status == frankenlibc_core::stdlib::conversion::ConversionStatus::Overflow
        || status == frankenlibc_core::stdlib::conversion::ConversionStatus::Underflow
    {
        unsafe { set_abi_errno(libc::ERANGE) };
    } else if status == frankenlibc_core::stdlib::conversion::ConversionStatus::InvalidBase {
        unsafe { set_abi_errno(libc::EINVAL) };
        // glibc validates the base first and leaves *endptr untouched (it never
        // writes it) when the base is invalid — it does NOT set it to NULL.
        return 0;
    }

    if !endptr.is_null() {
        unsafe {
            *endptr = (nptr as *mut c_char).add(consumed);
        }
    }

    if let Some(p) = profile {
        runtime_policy::observe(
            ApiFamily::Stdlib,
            p,
            runtime_policy::scaled_cost(15, consumed),
            false,
        );
    }

    val as c_long
}

// ---------------------------------------------------------------------------
// strtoimax
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strtoimax(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
) -> intmax_t {
    if nptr.is_null() {
        return 0;
    }

    // Deployed fast-path (measured: strtol "42" ~28→~12 ns vs glibc ~6 ns).
    // Stdlib is always-Allow in non-test, so the per-call decide()+observe()
    // membrane is pure overhead (the parse reads the string regardless). strtol
    // pays it TWICE — `nptr` and the always-Allow `endptr` write-decide. `profile`
    // is `Some` only on the full (test) path, which still exercises deny/observe/
    // repair. Mirrors `strtod`.
    let (profile, bound) = if runtime_policy::stdlib_membrane_fastpath() {
        (None, None)
    } else {
        let (mode, decision) = runtime_policy::decide(
            ApiFamily::Stdlib,
            nptr as usize,
            0,
            false,
            known_remaining(nptr as usize).is_none(),
            0,
        );
        if matches!(decision.action, MembraneAction::Deny) {
            runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 6, true);
            return 0;
        }

        let bound = if repair_enabled(mode.heals_enabled(), decision.action) {
            known_remaining(nptr as usize)
        } else {
            None
        };

        if !endptr.is_null() {
            let (_, end_decision) = runtime_policy::decide(
                ApiFamily::Stdlib,
                endptr as usize,
                std::mem::size_of::<*mut c_char>(),
                true,
                true,
                0,
            );
            if matches!(end_decision.action, MembraneAction::Deny) {
                return 0;
            }
        }
        (Some(decision.profile), bound)
    };

    let (len, _terminated) = unsafe { scan_numeric_c_string(nptr, bound) };
    let slice = unsafe { std::slice::from_raw_parts(nptr as *const u8, len) };

    let (val, consumed, status) = frankenlibc_core::stdlib::conversion::strtoimax_impl(slice, base);

    if status == frankenlibc_core::stdlib::conversion::ConversionStatus::Overflow
        || status == frankenlibc_core::stdlib::conversion::ConversionStatus::Underflow
    {
        unsafe { set_abi_errno(libc::ERANGE) };
    } else if status == frankenlibc_core::stdlib::conversion::ConversionStatus::InvalidBase {
        unsafe { set_abi_errno(libc::EINVAL) };
        // glibc validates the base first and leaves *endptr untouched on EINVAL.
        return 0;
    }

    if !endptr.is_null() {
        unsafe {
            *endptr = (nptr as *mut c_char).add(consumed);
        }
    }

    if let Some(p) = profile {
        runtime_policy::observe(
            ApiFamily::Stdlib,
            p,
            runtime_policy::scaled_cost(15, consumed),
            false,
        );
    }

    val as intmax_t
}

// ---------------------------------------------------------------------------
// strtoll
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strtoll(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
) -> c_longlong {
    unsafe { strtol(nptr, endptr, base) as c_longlong }
}

// ---------------------------------------------------------------------------
// strtoul
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strtoul(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
) -> c_ulong {
    if nptr.is_null() {
        return 0;
    }

    // Deployed fast-path (measured: strtol "42" ~28→~12 ns vs glibc ~6 ns).
    // Stdlib is always-Allow in non-test, so the per-call decide()+observe()
    // membrane is pure overhead (the parse reads the string regardless). strtol
    // pays it TWICE — `nptr` and the always-Allow `endptr` write-decide. `profile`
    // is `Some` only on the full (test) path, which still exercises deny/observe/
    // repair. Mirrors `strtod`.
    let (profile, bound) = if runtime_policy::stdlib_membrane_fastpath() {
        (None, None)
    } else {
        let (mode, decision) = runtime_policy::decide(
            ApiFamily::Stdlib,
            nptr as usize,
            0,
            false,
            known_remaining(nptr as usize).is_none(),
            0,
        );
        if matches!(decision.action, MembraneAction::Deny) {
            runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 6, true);
            return 0;
        }

        let bound = if repair_enabled(mode.heals_enabled(), decision.action) {
            known_remaining(nptr as usize)
        } else {
            None
        };

        if !endptr.is_null() {
            let (_, end_decision) = runtime_policy::decide(
                ApiFamily::Stdlib,
                endptr as usize,
                std::mem::size_of::<*mut c_char>(),
                true,
                true,
                0,
            );
            if matches!(end_decision.action, MembraneAction::Deny) {
                return 0;
            }
        }
        (Some(decision.profile), bound)
    };

    let (len, _terminated) = unsafe { scan_numeric_c_string(nptr, bound) };
    let slice = unsafe { std::slice::from_raw_parts(nptr as *const u8, len) };

    let (val, consumed, status) = frankenlibc_core::stdlib::conversion::strtoul_impl(slice, base);

    if status == frankenlibc_core::stdlib::conversion::ConversionStatus::Overflow
        || status == frankenlibc_core::stdlib::conversion::ConversionStatus::Underflow
    {
        unsafe { set_abi_errno(libc::ERANGE) };
    } else if status == frankenlibc_core::stdlib::conversion::ConversionStatus::InvalidBase {
        unsafe { set_abi_errno(libc::EINVAL) };
        // glibc validates the base first and leaves *endptr untouched on EINVAL.
        return 0;
    }

    if !endptr.is_null() {
        unsafe {
            *endptr = (nptr as *mut c_char).add(consumed);
        }
    }

    if let Some(p) = profile {
        runtime_policy::observe(
            ApiFamily::Stdlib,
            p,
            runtime_policy::scaled_cost(15, consumed),
            false,
        );
    }

    val as c_ulong
}

// ---------------------------------------------------------------------------
// strtoumax
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strtoumax(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
) -> uintmax_t {
    if nptr.is_null() {
        return 0;
    }

    // Deployed fast-path (measured: strtol "42" ~28→~12 ns vs glibc ~6 ns).
    // Stdlib is always-Allow in non-test, so the per-call decide()+observe()
    // membrane is pure overhead (the parse reads the string regardless). strtol
    // pays it TWICE — `nptr` and the always-Allow `endptr` write-decide. `profile`
    // is `Some` only on the full (test) path, which still exercises deny/observe/
    // repair. Mirrors `strtod`.
    let (profile, bound) = if runtime_policy::stdlib_membrane_fastpath() {
        (None, None)
    } else {
        let (mode, decision) = runtime_policy::decide(
            ApiFamily::Stdlib,
            nptr as usize,
            0,
            false,
            known_remaining(nptr as usize).is_none(),
            0,
        );
        if matches!(decision.action, MembraneAction::Deny) {
            runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 6, true);
            return 0;
        }

        let bound = if repair_enabled(mode.heals_enabled(), decision.action) {
            known_remaining(nptr as usize)
        } else {
            None
        };

        if !endptr.is_null() {
            let (_, end_decision) = runtime_policy::decide(
                ApiFamily::Stdlib,
                endptr as usize,
                std::mem::size_of::<*mut c_char>(),
                true,
                true,
                0,
            );
            if matches!(end_decision.action, MembraneAction::Deny) {
                return 0;
            }
        }
        (Some(decision.profile), bound)
    };

    let (len, _terminated) = unsafe { scan_numeric_c_string(nptr, bound) };
    let slice = unsafe { std::slice::from_raw_parts(nptr as *const u8, len) };

    let (val, consumed, status) = frankenlibc_core::stdlib::conversion::strtoumax_impl(slice, base);

    if status == frankenlibc_core::stdlib::conversion::ConversionStatus::Overflow
        || status == frankenlibc_core::stdlib::conversion::ConversionStatus::Underflow
    {
        unsafe { set_abi_errno(libc::ERANGE) };
    } else if status == frankenlibc_core::stdlib::conversion::ConversionStatus::InvalidBase {
        unsafe { set_abi_errno(libc::EINVAL) };
        // glibc validates the base first and leaves *endptr untouched on EINVAL.
        return 0;
    }

    if !endptr.is_null() {
        unsafe {
            *endptr = (nptr as *mut c_char).add(consumed);
        }
    }

    if let Some(p) = profile {
        runtime_policy::observe(
            ApiFamily::Stdlib,
            p,
            runtime_policy::scaled_cost(15, consumed),
            false,
        );
    }

    val as uintmax_t
}

// ---------------------------------------------------------------------------
// strtoull
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strtoull(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
) -> c_ulonglong {
    unsafe { strtoul(nptr, endptr, base) as c_ulonglong }
}

// ---------------------------------------------------------------------------
// strtoi / strtou (NetBSD bounded-integer parsers)
// ---------------------------------------------------------------------------

fn map_bounded_status(s: frankenlibc_core::stdlib::conversion::BoundedStatus) -> c_int {
    use frankenlibc_core::stdlib::conversion::BoundedStatus as B;
    match s {
        B::Success => 0,
        B::InvalidBase => libc::ENOTSUP,
        B::NoDigits => libc::EINVAL,
        B::OutOfRange => libc::ERANGE,
    }
}

/// NetBSD `strtoi(nptr, endptr, base, lo, hi, rstatus)` — like
/// [`strtoimax`] but additionally validates the parsed value against
/// the inclusive range `[lo, hi]`. On out-of-range or underlying
/// overflow the returned value is clamped to the violated bound.
/// `*rstatus` (when non-NULL) receives one of:
///
/// - `0` — success, value was in range.
/// - `EINVAL` — no digits could be parsed (`*endptr == nptr`).
/// - `ENOTSUP` — `base` was outside `0` or `2..=36`.
/// - `ERANGE` — value was out of `[lo, hi]` (clamped).
///
/// # Safety
///
/// `nptr` must be NUL-terminated. `endptr` and `rstatus`, when
/// non-NULL, must point to writable storage of the appropriate
/// type.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strtoi(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
    lo: intmax_t,
    hi: intmax_t,
    rstatus: *mut c_int,
) -> intmax_t {
    if nptr.is_null() {
        if !rstatus.is_null() {
            unsafe { *rstatus = libc::EINVAL };
        }
        return 0;
    }
    let (len, terminated) = unsafe { scan_c_string(nptr, known_remaining(nptr as usize)) };
    if !terminated {
        if !endptr.is_null() {
            unsafe { *endptr = nptr as *mut c_char };
        }
        if !rstatus.is_null() {
            unsafe { *rstatus = libc::EINVAL };
        }
        return 0;
    }
    let slice = unsafe { std::slice::from_raw_parts(nptr as *const u8, len) };
    let (val, consumed, status) =
        frankenlibc_core::stdlib::conversion::strtoi_impl(slice, base, lo, hi);
    if !endptr.is_null() {
        unsafe { *endptr = (nptr as *mut c_char).add(consumed) };
    }
    if !rstatus.is_null() {
        unsafe { *rstatus = map_bounded_status(status) };
    }
    val
}

/// NetBSD `strtou(nptr, endptr, base, lo, hi, rstatus)` — like
/// [`strtoumax`] but additionally validates the parsed value against
/// the inclusive range `[lo, hi]` (interpreted as `uintmax_t`). See
/// [`strtoi`] for the rstatus contract.
///
/// # Safety
///
/// Same as [`strtoi`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strtou(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
    lo: uintmax_t,
    hi: uintmax_t,
    rstatus: *mut c_int,
) -> uintmax_t {
    if nptr.is_null() {
        if !rstatus.is_null() {
            unsafe { *rstatus = libc::EINVAL };
        }
        return 0;
    }
    let (len, terminated) = unsafe { scan_c_string(nptr, known_remaining(nptr as usize)) };
    if !terminated {
        if !endptr.is_null() {
            unsafe { *endptr = nptr as *mut c_char };
        }
        if !rstatus.is_null() {
            unsafe { *rstatus = libc::EINVAL };
        }
        return 0;
    }
    let slice = unsafe { std::slice::from_raw_parts(nptr as *const u8, len) };
    let (val, consumed, status) =
        frankenlibc_core::stdlib::conversion::strtou_impl(slice, base, lo, hi);
    if !endptr.is_null() {
        unsafe { *endptr = (nptr as *mut c_char).add(consumed) };
    }
    if !rstatus.is_null() {
        unsafe { *rstatus = map_bounded_status(status) };
    }
    val
}

// ---------------------------------------------------------------------------
// exit
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn exit(status: c_int) -> ! {
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdlib, 0, 0, false, true, 0);
    runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 100, false);

    // First flush stdio streams since atexit handlers might not do it
    // Wait, POSIX says atexit handlers run, THEN streams are flushed.
    // So if atexit handler prints something, it needs to be flushed.
    // However, frankenlibc_core::stdlib::exit calls atexit handlers,
    // and we can't easily hook back into stdio here without splitting exit.
    // Let's implement the full POSIX exit here, calling `_exit`.

    // 1. Run atexit/on_exit handlers in one reverse-registration stack.
    //    Swap-extract under the lock, release, then iterate: invoking user
    //    callbacks while holding the mutex would self-deadlock on re-entrant
    //    registrations (bd-3jpoz).
    run_exit_handlers(status);

    // 3. Flush all open stdio streams.
    unsafe {
        crate::stdio_abi::fflush(ptr::null_mut());
    }

    // 4. Terminate process.
    frankenlibc_core::syscall::sys_exit_group(status)
}

// ---------------------------------------------------------------------------
// atexit
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atexit(func: Option<extern "C" fn()>) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdlib, 0, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(libc::EPERM) };
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 10, true);
        return -1;
    }

    let res = match func {
        Some(f) => register_exit_handler(ExitHandler::Atexit(f)),
        None => -1,
    };

    runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 50, res != 0);
    res
}

// ---------------------------------------------------------------------------
// qsort
// ---------------------------------------------------------------------------

fn tracked_region_fits(ptr: *const c_void, len: usize) -> bool {
    match known_remaining(ptr as usize) {
        Some(remaining) => len <= remaining,
        None => true,
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn qsort(
    base: *mut c_void,
    nmemb: usize,
    size: usize,
    compar: Option<unsafe extern "C" fn(*const c_void, *const c_void) -> c_int>,
) {
    if base.is_null() || nmemb == 0 || size == 0 {
        return;
    }
    let Some(total_bytes) = nmemb.checked_mul(size) else {
        return;
    };
    let Some(compar_fn) = compar else {
        return;
    };

    // Strict-mode fast path (the DEFAULT deployed mode): `Stdlib` `decide()` always-Allows in
    // strict (fast-path family; `decide_strict_observation` never denies) with no clamp/heal, so
    // the membrane's only output is the raw sort. Skip `tracked_region_fits` + `decide()` +
    // `observe()` — byte-identical to the full path for valid inputs (C requires them; glibc
    // never validates the region). This matters most for SMALL sorts, where the ~15ns membrane
    // dwarfs pdqsort's handful of comparisons. Mirrors the bsearch/string strict fast paths.
    if runtime_policy::strict_passthrough_active() {
        let wrapper = |a: &[u8], b: &[u8]| -> i32 {
            // SAFETY: slices are `size` bytes into the caller-provided (C-contract valid) array.
            unsafe { compar_fn(a.as_ptr() as *const c_void, b.as_ptr() as *const c_void) }
        };
        // SAFETY: caller guarantees `base` is `nmemb*size` writable bytes.
        let slice = unsafe { std::slice::from_raw_parts_mut(base as *mut u8, total_bytes) };
        frankenlibc_core::stdlib::sort::qsort(slice, size, wrapper);
        return;
    }

    if !tracked_region_fits(base.cast_const(), total_bytes) {
        return;
    }

    let (_, decision) = runtime_policy::decide(
        ApiFamily::Stdlib,
        base as usize,
        total_bytes,
        true, // read-write (sorting modifies)
        known_remaining(base as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 10, true);
        return;
    }

    // Wrap comparator
    let wrapper = |a: &[u8], b: &[u8]| -> i32 {
        unsafe { compar_fn(a.as_ptr() as *const c_void, b.as_ptr() as *const c_void) }
    };

    // SAFETY: We validated base for total_bytes.
    let slice = unsafe { std::slice::from_raw_parts_mut(base as *mut u8, total_bytes) };

    frankenlibc_core::stdlib::sort::qsort(slice, size, wrapper);

    runtime_policy::observe(
        ApiFamily::Stdlib,
        decision.profile,
        runtime_policy::scaled_cost(10, total_bytes), // N log N cost ideally
        false,
    );
}

// ---------------------------------------------------------------------------
// mergesort / heapsort (BSD libc sort variants)
// ---------------------------------------------------------------------------

/// BSD `mergesort(base, nmemb, size, compar)` — STABLE sort with
/// the same shape as qsort but returning int (0 on success, -1 with
/// errno on failure). NULL `compar` or zero-size element is rejected
/// with EINVAL; nmemb=0 / nmemb=1 is a no-op success.
///
/// # Safety
///
/// Caller must ensure `base` is valid for `nmemb * size` writable
/// bytes and `compar` (if non-NULL) is a valid C function pointer.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mergesort(
    base: *mut c_void,
    nmemb: usize,
    size: usize,
    compar: Option<unsafe extern "C" fn(*const c_void, *const c_void) -> c_int>,
) -> c_int {
    if size == 0 {
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }
    let Some(compar_fn) = compar else {
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    };
    if nmemb < 2 {
        return 0;
    }
    let total_bytes = match nmemb.checked_mul(size) {
        Some(t) => t,
        None => {
            unsafe { set_abi_errno(libc::ENOMEM) };
            return -1;
        }
    };
    if base.is_null() {
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }
    // Strict-mode fast path: skip the `tracked_region_fits` registry lookup (trust-the-caller,
    // byte-identical; glibc/BSD never validate the region). Completes the sort-family bypass.
    if !runtime_policy::strict_passthrough_active()
        && !tracked_region_fits(base.cast_const(), total_bytes)
    {
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }
    let wrapper = |a: &[u8], b: &[u8]| -> i32 {
        unsafe { compar_fn(a.as_ptr() as *const c_void, b.as_ptr() as *const c_void) }
    };
    // SAFETY: caller contract for mergesort.
    let slice = unsafe { std::slice::from_raw_parts_mut(base as *mut u8, total_bytes) };
    frankenlibc_core::stdlib::sort::mergesort(slice, size, wrapper);
    0
}

/// BSD `heapsort(base, nmemb, size, compar)` — IN-PLACE non-stable
/// heap sort with the same shape as mergesort. Returns 0 on
/// success, -1 with errno on failure (NULL compar / zero-size /
/// NULL base / overflow).
///
/// # Safety
///
/// Same as [`mergesort`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn heapsort(
    base: *mut c_void,
    nmemb: usize,
    size: usize,
    compar: Option<unsafe extern "C" fn(*const c_void, *const c_void) -> c_int>,
) -> c_int {
    if size == 0 {
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }
    let Some(compar_fn) = compar else {
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    };
    if nmemb < 2 {
        return 0;
    }
    let total_bytes = match nmemb.checked_mul(size) {
        Some(t) => t,
        None => {
            unsafe { set_abi_errno(libc::ENOMEM) };
            return -1;
        }
    };
    if base.is_null() {
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }
    // Strict-mode fast path: skip the `tracked_region_fits` registry lookup (trust-the-caller,
    // byte-identical; glibc/BSD never validate the region). Completes the sort-family bypass.
    if !runtime_policy::strict_passthrough_active()
        && !tracked_region_fits(base.cast_const(), total_bytes)
    {
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }
    let wrapper = |a: &[u8], b: &[u8]| -> i32 {
        unsafe { compar_fn(a.as_ptr() as *const c_void, b.as_ptr() as *const c_void) }
    };
    // SAFETY: caller contract for heapsort.
    let slice = unsafe { std::slice::from_raw_parts_mut(base as *mut u8, total_bytes) };
    frankenlibc_core::stdlib::sort::heapsort(slice, size, wrapper);
    0
}

// ---------------------------------------------------------------------------
// radixsort / sradixsort (NetBSD libutil radix sort family)
// ---------------------------------------------------------------------------

/// Per-string scan cap: caller must terminate each entry within this
/// many bytes (well above any realistic identifier or path length).
const RADIXSORT_MAX_SCAN: usize = 1 << 20;

/// Shared body for [`radixsort`] and [`sradixsort`]. Walks each
/// pointer in `base`, finds the first occurrence of the `endbyte`
/// terminator, sorts indices via the core comparator, then rewrites
/// the pointer array in place.
unsafe fn radixsort_impl(
    base: *mut *const c_uchar,
    nmemb: c_int,
    table: *const c_uchar,
    endbyte: c_uint,
    stable: bool,
) -> c_int {
    if base.is_null() || nmemb < 0 {
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }
    let n = nmemb as usize;
    if n < 2 {
        return 0;
    }
    let pointer_bytes = match n.checked_mul(core::mem::size_of::<*const c_uchar>()) {
        Some(bytes) => bytes,
        None => {
            unsafe { set_abi_errno(libc::EINVAL) };
            return -1;
        }
    };
    if !tracked_region_fits(base.cast_const().cast(), pointer_bytes) {
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }
    if !table.is_null() && !tracked_region_fits(table.cast(), 256) {
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }

    let endbyte_u8 = (endbyte & 0xff) as u8;
    let ptrs: &mut [*const c_uchar] = unsafe { std::slice::from_raw_parts_mut(base, n) };

    let mut slices: Vec<&[u8]> = Vec::with_capacity(n);
    for &p in ptrs.iter() {
        if p.is_null() {
            unsafe { set_abi_errno(libc::EINVAL) };
            return -1;
        }
        let scan_cap = known_remaining(p as usize)
            .map(|remaining| remaining.min(RADIXSORT_MAX_SCAN))
            .unwrap_or(RADIXSORT_MAX_SCAN);
        let mut len = 0usize;
        while len < scan_cap {
            if unsafe { *p.add(len) } == endbyte_u8 {
                break;
            }
            len += 1;
        }
        if len == scan_cap {
            unsafe { set_abi_errno(libc::EINVAL) };
            return -1;
        }
        slices.push(unsafe { std::slice::from_raw_parts(p, len) });
    }

    let table_arr: Option<&[u8; 256]> = if table.is_null() {
        None
    } else {
        Some(unsafe { &*(table as *const [u8; 256]) })
    };

    let order = frankenlibc_core::stdlib::sort::radix_sort(&slices, table_arr, stable);
    let saved: Vec<*const c_uchar> = ptrs.to_vec();
    for (dst, src) in order.iter().enumerate() {
        ptrs[dst] = saved[*src];
    }
    0
}

/// NetBSD `radixsort(base, nmemb, table, endbyte)` — sort an array
/// of byte-string pointers in place. Each entry is read up to (but
/// not including) the first occurrence of `endbyte` (typically NUL).
/// `table`, when non-NULL, must point to 256 bytes mapping each
/// input byte to a sort key. Returns 0 on success, -1 with errno
/// set on invalid input or when an entry exceeds the internal
/// `RADIXSORT_MAX_SCAN` length cap.
///
/// # Safety
///
/// `base` must point to `nmemb` writable pointer cells. Each
/// pointer in `base` must reference a NUL-terminated (or
/// `endbyte`-terminated) readable byte string.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn radixsort(
    base: *mut *const c_uchar,
    nmemb: c_int,
    table: *const c_uchar,
    endbyte: c_uint,
) -> c_int {
    unsafe { radixsort_impl(base, nmemb, table, endbyte, false) }
}

/// NetBSD `sradixsort(base, nmemb, table, endbyte)` — stable sibling
/// of [`radixsort`]: equal keys retain their input order. See
/// [`radixsort`] for argument and safety details.
///
/// # Safety
///
/// Same as [`radixsort`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sradixsort(
    base: *mut *const c_uchar,
    nmemb: c_int,
    table: *const c_uchar,
    endbyte: c_uint,
) -> c_int {
    unsafe { radixsort_impl(base, nmemb, table, endbyte, true) }
}

// ---------------------------------------------------------------------------
// bsearch
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn bsearch(
    key: *const c_void,
    base: *const c_void,
    nmemb: usize,
    size: usize,
    compar: Option<unsafe extern "C" fn(*const c_void, *const c_void) -> c_int>,
) -> *mut c_void {
    if key.is_null() || base.is_null() || nmemb == 0 || size == 0 {
        return ptr::null_mut();
    }
    let Some(total_bytes) = nmemb.checked_mul(size) else {
        return ptr::null_mut();
    };
    let Some(compar_fn) = compar else {
        return ptr::null_mut();
    };

    // Strict-mode fast path (the DEFAULT deployed mode): `Stdlib` `decide()` always-Allows in
    // strict (it is on the high-frequency fast-path family list; `decide_strict_observation`
    // never denies) with no clamp/heal, so the membrane's only output is the raw binary search.
    // Skip the `tracked_region_fits` region validation + the TWO `decide()` calls + `observe()`
    // — byte-identical to the full path for valid inputs (which C requires; glibc likewise does
    // not validate the region). Mirrors the string/inet_strict strict fast paths. Hardened mode
    // (`strict_passthrough_active() == false`) keeps the full validating path below.
    if runtime_policy::strict_passthrough_active() {
        let wrapper = |a: &[u8], b: &[u8]| -> i32 {
            // SAFETY: slices are `size` bytes into the caller-provided (C-contract valid) arrays.
            unsafe { compar_fn(a.as_ptr() as *const c_void, b.as_ptr() as *const c_void) }
        };
        // SAFETY: caller guarantees `base` is `nmemb*size` bytes and `key` is `size` bytes.
        let slice = unsafe { std::slice::from_raw_parts(base as *const u8, total_bytes) };
        let key_slice = unsafe { std::slice::from_raw_parts(key as *const u8, size) };
        return match frankenlibc_core::stdlib::sort::bsearch(key_slice, slice, size, wrapper) {
            Some(s) => s.as_ptr() as *mut c_void,
            None => ptr::null_mut(),
        };
    }

    if !tracked_region_fits(base, total_bytes) || !tracked_region_fits(key, size) {
        return ptr::null_mut();
    }

    // Validate base
    let (_, decision) = runtime_policy::decide(
        ApiFamily::Stdlib,
        base as usize,
        total_bytes,
        false, // read-only
        known_remaining(base as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 10, true);
        return ptr::null_mut();
    }

    // Validate key (assume at least size bytes?)
    // This is heuristic.
    let (_, key_decision) = runtime_policy::decide(
        ApiFamily::Stdlib,
        key as usize,
        size,
        false,
        known_remaining(key as usize).is_none(),
        0,
    );
    if matches!(key_decision.action, MembraneAction::Deny) {
        return ptr::null_mut();
    }

    let wrapper = |a: &[u8], b: &[u8]| -> i32 {
        unsafe { compar_fn(a.as_ptr() as *const c_void, b.as_ptr() as *const c_void) }
    };

    let slice = unsafe { std::slice::from_raw_parts(base as *const u8, total_bytes) };
    let key_slice = unsafe { std::slice::from_raw_parts(key as *const u8, size) };

    let result = frankenlibc_core::stdlib::sort::bsearch(key_slice, slice, size, wrapper);

    runtime_policy::observe(
        ApiFamily::Stdlib,
        decision.profile,
        runtime_policy::scaled_cost(5, nmemb), // log N cost
        false,
    );

    match result {
        Some(s) => s.as_ptr() as *mut c_void,
        None => ptr::null_mut(),
    }
}

// ---------------------------------------------------------------------------
// getenv
// ---------------------------------------------------------------------------

/// POSIX `getenv` — retrieve an environment variable value.
///
/// Returns a pointer to the value string, or null if the variable is not set.
/// The returned pointer belongs to the environment; callers must not free it.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getenv(name: *const c_char) -> *mut c_char {
    if name.is_null() {
        return ptr::null_mut();
    }

    // During early startup and membrane initialization, `std::env` inside the
    // runtime may route here. In that window we must not recurse back into
    // pointer validation or runtime-policy orchestration.
    if getenv_bootstrap_sensitive() {
        let (len, terminated) = unsafe { scan_c_string(name, Some(env_name_scan_bound(name))) };
        if !terminated {
            return ptr::null_mut();
        }
        let name_slice = unsafe { std::slice::from_raw_parts(name as *const u8, len) };
        if !frankenlibc_core::stdlib::valid_env_name(name_slice) {
            return ptr::null_mut();
        }
        // SAFETY: fast path performs a read-only walk of the active environ table.
        return unsafe { native_getenv(name_slice) };
    }

    // Deployed fast-path: Stdlib is always-Allow, so the decide()+observe()
    // membrane (and its `known_remaining` lookups) is pure overhead on top of the
    // environ walk — same lever as strtod (bd-n40in2 sibling). `profile` is `Some`
    // only on the full (test) path, which keeps deny/observe exercised.
    let (profile, len, terminated) = if runtime_policy::stdlib_membrane_fastpath() {
        if let Some(cached) = unsafe { getenv_hot_cache_lookup_same_ptr(name) } {
            return cached;
        }
        let bound = env_name_scan_bound(name);
        let probe = unsafe { scan_env_name_fast(name, bound) };
        if !probe.terminated || !probe.valid {
            return ptr::null_mut();
        }
        if let Some(cached) = getenv_hot_cache_lookup(probe) {
            return cached;
        }
        let result = unsafe { native_getenv_raw(name.cast::<u8>(), probe.len) };
        getenv_hot_cache_store(name, probe, result);
        return result;
    } else {
        let bound = env_name_scan_bound(name);
        let (_mode, decision) = runtime_policy::decide(
            ApiFamily::Stdlib,
            name as usize,
            0,
            false,
            known_remaining(name as usize).is_none(),
            0,
        );
        if matches!(decision.action, MembraneAction::Deny) {
            runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 5, true);
            return ptr::null_mut();
        }
        let (len, terminated) = unsafe { scan_c_string(name, Some(bound)) };
        (Some(decision.profile), len, terminated)
    };

    if !terminated {
        // Unterminated names are always rejected to avoid passing non-C strings to libc.
        if let Some(p) = profile {
            runtime_policy::observe(ApiFamily::Stdlib, p, 5, true);
        }
        return ptr::null_mut();
    }

    let name_slice = unsafe { std::slice::from_raw_parts(name as *const u8, len) };
    if !frankenlibc_core::stdlib::valid_env_name(name_slice) {
        if let Some(p) = profile {
            runtime_policy::observe(ApiFamily::Stdlib, p, 5, true);
        }
        return ptr::null_mut();
    }

    // SAFETY: we only read libc's environment table and return pointer to existing value storage.
    let result = unsafe { native_getenv(name_slice) };
    if let Some(p) = profile {
        let adverse = result.is_null();
        runtime_policy::observe(
            ApiFamily::Stdlib,
            p,
            runtime_policy::scaled_cost(8, len),
            adverse,
        );
    }
    result
}

// ---------------------------------------------------------------------------
// secure_getenv
// ---------------------------------------------------------------------------

/// GNU `secure_getenv` — getenv that returns null in secure execution mode.
///
/// We conservatively treat setuid/setgid transitions as secure execution and
/// return null in that context.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn secure_getenv(name: *const c_char) -> *mut c_char {
    let uid = unsafe { crate::unistd_abi::getuid() };
    let euid = unsafe { crate::unistd_abi::geteuid() };
    let gid = unsafe { crate::unistd_abi::getgid() };
    let egid = unsafe { crate::unistd_abi::getegid() };

    if uid != euid || gid != egid {
        return ptr::null_mut();
    }

    unsafe { getenv(name) }
}

// ---------------------------------------------------------------------------
// getenv_r (NetBSD re-entrant getenv)
// ---------------------------------------------------------------------------

/// NetBSD `getenv_r(name, buf, buflen)` — re-entrant `getenv`. Look
/// up the environment variable `name` and copy its value (with
/// trailing NUL) into `buf`. Returns:
///
/// - `0` on success.
/// - `-1` with `errno = ENOENT` if the variable is not set.
/// - `-1` with `errno = ERANGE` if `buf` is too small for the
///   value plus the trailing NUL.
/// - `-1` with `errno = EINVAL` if `name` or `buf` is NULL.
///
/// Useful for callers that want to avoid the global-pointer
/// aliasing risk of plain [`getenv`] (whose return pointer can be
/// invalidated by a concurrent `setenv`/`unsetenv`).
///
/// # Safety
///
/// `name`, when non-NULL, must be NUL-terminated. `buf`, when
/// non-NULL, must be valid for `buflen` writable bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getenv_r(name: *const c_char, buf: *mut c_char, buflen: usize) -> c_int {
    if name.is_null() || buf.is_null() {
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }
    let value = unsafe { getenv(name) };
    if value.is_null() {
        unsafe { set_abi_errno(libc::ENOENT) };
        return -1;
    }
    let Some(value_bytes) = (unsafe { read_bounded_cstr_bytes(value) }) else {
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    };
    if value_bytes.len() + 1 > buflen {
        unsafe { set_abi_errno(libc::ERANGE) };
        return -1;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(value_bytes.as_ptr(), buf as *mut u8, value_bytes.len());
        *buf.add(value_bytes.len()) = 0;
    }
    0
}

// ---------------------------------------------------------------------------
// setenv
// ---------------------------------------------------------------------------

/// POSIX `setenv` — set an environment variable.
///
/// If `overwrite` is zero, an existing variable is not changed.
/// Returns 0 on success, -1 on error (with errno set).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setenv(
    name: *const c_char,
    value: *const c_char,
    overwrite: c_int,
) -> c_int {
    if name.is_null() {
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }

    let (_mode, decision) = runtime_policy::decide(
        ApiFamily::Stdlib,
        name as usize,
        0,
        true, // write operation (modifying environment)
        known_remaining(name as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 5, true);
        unsafe { set_abi_errno(libc::EPERM) };
        return -1;
    }

    let bound = known_remaining(name as usize);
    let (name_len, name_terminated) = unsafe { scan_c_string(name, bound) };
    if !name_terminated {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 5, true);
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }

    let name_slice = unsafe { std::slice::from_raw_parts(name as *const u8, name_len) };
    if !frankenlibc_core::stdlib::valid_env_name(name_slice) {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 5, true);
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }

    // Validate value pointer.
    if value.is_null() {
        unsafe { set_abi_errno(libc::EINVAL) };
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 5, true);
        return -1;
    }

    let value_bound = known_remaining(value as usize);
    let (value_len, value_terminated) = unsafe { scan_c_string(value, value_bound) };
    if !value_terminated {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 5, true);
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }
    let value_slice = unsafe { std::slice::from_raw_parts(value as *const u8, value_len) };
    if !frankenlibc_core::stdlib::valid_env_value(value_slice) {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 5, true);
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }

    // SAFETY: validated NUL-terminated pointers and their lengths.
    let rc = unsafe { native_setenv(name, name_len, value, value_len, overwrite) };
    if rc != 0 {
        unsafe { set_abi_errno_if_clear(libc::EINVAL) };
    } else {
        bump_environ_epoch();
    }
    let adverse = rc != 0;
    runtime_policy::observe(
        ApiFamily::Stdlib,
        decision.profile,
        runtime_policy::scaled_cost(15, name_len),
        adverse,
    );
    rc
}

// ---------------------------------------------------------------------------
// unsetenv
// ---------------------------------------------------------------------------

/// POSIX `unsetenv` — remove an environment variable.
///
/// Returns 0 on success, -1 on error (with errno set).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn unsetenv(name: *const c_char) -> c_int {
    if name.is_null() {
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }

    let (_mode, decision) = runtime_policy::decide(
        ApiFamily::Stdlib,
        name as usize,
        0,
        true, // write operation (modifying environment)
        known_remaining(name as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 5, true);
        unsafe { set_abi_errno(libc::EPERM) };
        return -1;
    }

    let bound = known_remaining(name as usize);
    let (name_len, name_terminated) = unsafe { scan_c_string(name, bound) };
    if !name_terminated {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 5, true);
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }

    let name_slice = unsafe { std::slice::from_raw_parts(name as *const u8, name_len) };
    if !frankenlibc_core::stdlib::valid_env_name(name_slice) {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 5, true);
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }

    // SAFETY: validated NUL-terminated pointer.
    let rc = unsafe { native_unsetenv(name, name_len) };
    if rc != 0 {
        unsafe { set_abi_errno(libc::EINVAL) };
    } else {
        bump_environ_epoch();
    }
    let adverse = rc != 0;
    runtime_policy::observe(
        ApiFamily::Stdlib,
        decision.profile,
        runtime_policy::scaled_cost(10, name_len),
        adverse,
    );
    rc
}

// ---------------------------------------------------------------------------
// abs / labs / llabs
// ---------------------------------------------------------------------------

/// C `abs` -- absolute value of an integer.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn abs(n: c_int) -> c_int {
    frankenlibc_core::stdlib::abs(n)
}

/// C `labs` -- absolute value of a long.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn labs(n: c_long) -> c_long {
    frankenlibc_core::stdlib::labs(n)
}

/// C `llabs` -- absolute value of a long long.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn llabs(n: c_longlong) -> c_longlong {
    frankenlibc_core::stdlib::llabs(n)
}

// ---------------------------------------------------------------------------
// div / ldiv / lldiv
// ---------------------------------------------------------------------------

/// C `div_t` result type.
#[repr(C)]
pub struct CDiv {
    pub quot: c_int,
    pub rem: c_int,
}

/// C `ldiv_t` result type.
#[repr(C)]
pub struct CLdiv {
    pub quot: c_long,
    pub rem: c_long,
}

/// C `lldiv_t` result type.
#[repr(C)]
pub struct CLldiv {
    pub quot: c_longlong,
    pub rem: c_longlong,
}

/// C `div` -- integer division yielding quotient and remainder.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn div(numer: c_int, denom: c_int) -> CDiv {
    let r = frankenlibc_core::stdlib::div(numer, denom);
    CDiv {
        quot: r.quot,
        rem: r.rem,
    }
}

/// C `ldiv` -- long division yielding quotient and remainder.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn ldiv(numer: c_long, denom: c_long) -> CLdiv {
    let r = frankenlibc_core::stdlib::ldiv(numer, denom);
    CLdiv {
        quot: r.quot,
        rem: r.rem,
    }
}

/// C `lldiv` -- long long division yielding quotient and remainder.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn lldiv(numer: c_longlong, denom: c_longlong) -> CLldiv {
    let r = frankenlibc_core::stdlib::lldiv(numer, denom);
    CLldiv {
        quot: r.quot,
        rem: r.rem,
    }
}

// ---------------------------------------------------------------------------
// ffs / ffsl / ffsll
// ---------------------------------------------------------------------------

/// POSIX `ffs` -- find first set bit.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn ffs(i: c_int) -> c_int {
    frankenlibc_core::stdlib::ffs(i)
}

/// GNU `ffsl` -- find first set bit in long.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn ffsl(i: c_long) -> c_int {
    frankenlibc_core::stdlib::ffsl(i)
}

/// GNU `ffsll` -- find first set bit in long long.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn ffsll(i: c_longlong) -> c_int {
    frankenlibc_core::stdlib::ffsll(i)
}

// ---------------------------------------------------------------------------
// rand / srand / rand_r
// ---------------------------------------------------------------------------

/// C `rand` -- returns a pseudo-random integer in [0, RAND_MAX].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn rand() -> c_int {
    frankenlibc_core::stdlib::rand()
}

/// C `srand` -- seeds the pseudo-random number generator.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn srand(seed: c_uint) {
    frankenlibc_core::stdlib::srand(seed);
}

/// POSIX `rand_r` -- reentrant pseudo-random number generator.
///
/// # Safety
///
/// Caller must ensure `seedp` is a valid pointer to a `unsigned int`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rand_r(seedp: *mut c_uint) -> c_int {
    if seedp.is_null() {
        return 0;
    }
    // SAFETY: caller guarantees seedp is valid.
    let seed = unsafe { &mut *seedp };
    frankenlibc_core::stdlib::rand_r(seed)
}

// ---------------------------------------------------------------------------
// atof / strtod / strtof
// ---------------------------------------------------------------------------

/// C `atof` -- converts string to double.
///
/// # Safety
///
/// Caller must ensure `nptr` is a valid null-terminated string.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn atof(nptr: *const c_char) -> f64 {
    // C `atof(s)` is defined as `strtod(s, NULL)`, and glibc implements it exactly that way
    // (so it sets ERANGE like strtod). Delegating inherits strtod's single-pass decimal/
    // integer FAST PATHS — the old `scan_terminated_numeric_string` + `core::atof` took the
    // slow general path, so atof "0" ran ~2.7x glibc while strtod "0" WINS (strtod_survey).
    // Byte-identical value (strtod's fast paths == strtod_impl == core::atof) + glibc-matching
    // errno, and the same membrane fast-path handling strtod already has.
    unsafe { strtod(nptr, std::ptr::null_mut()) }
}

/// C `strtod` -- converts string to double with endptr.
///
/// # Safety
///
/// Caller must ensure `nptr` is a valid null-terminated string.
/// `endptr`, if non-null, will be set to point past the last parsed character.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strtod(nptr: *const c_char, endptr: *mut *mut c_char) -> f64 {
    if nptr.is_null() {
        if !endptr.is_null() {
            unsafe { *endptr = nptr as *mut c_char };
        }
        return 0.0;
    }

    // Deployed fast-path: Stdlib is always-Allow in non-test builds and the parse
    // reads the string regardless of the decision, so skip the per-call
    // decide()+observe() membrane (bd-n40in2 sibling). `profile` is `Some` only on
    // the full (test) path, which still exercises deny/observe.
    let profile = if runtime_policy::stdlib_membrane_fastpath() {
        None
    } else {
        let (_, decision) = runtime_policy::decide(
            ApiFamily::Stdlib,
            nptr as usize,
            0,
            false,
            known_remaining(nptr as usize).is_none(),
            0,
        );
        if matches!(decision.action, MembraneAction::Deny) {
            runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 5, true);
            if !endptr.is_null() {
                unsafe { *endptr = nptr as *mut c_char };
            }
            return 0.0;
        }
        Some(decision.profile)
    };

    if profile.is_none()
        && let Some((value, consumed)) = unsafe { parse_strtod_short_decimal_c_string_fast(nptr) }
    {
        if !endptr.is_null() {
            unsafe { *endptr = nptr.add(consumed) as *mut c_char };
        }
        return value;
    }

    let Some(len) = (unsafe { scan_terminated_numeric_string(nptr) }) else {
        if let Some(p) = profile {
            runtime_policy::observe(ApiFamily::Stdlib, p, 5, true);
        }
        if !endptr.is_null() {
            unsafe { *endptr = nptr as *mut c_char };
        }
        return 0.0;
    };
    let slice = unsafe { std::slice::from_raw_parts(nptr.cast::<u8>(), len + 1) };
    let (val, consumed, exact) = frankenlibc_core::stdlib::conversion::strtod_impl(slice);
    if !endptr.is_null() {
        unsafe { *endptr = nptr.add(consumed) as *mut c_char };
    }

    // POSIX strtod: on overflow set errno=ERANGE and return ±HUGE_VAL;
    // on underflow set errno=ERANGE and return a value at most as
    // large in magnitude as DBL_MIN. Detect both from the parsed
    // result + the consumed prefix and set errno accordingly.
    // An EXACTLY-representable subnormal is NOT underflow (glibc raises ERANGE
    // only for inexact underflow), so suppress the false positive when the
    // parser reports the result exact. (bd-2g7oyh.187, CONFORMANCE: numeric diff)
    if consumed > 0 {
        let consumed_bytes = unsafe { std::slice::from_raw_parts(nptr.cast::<u8>(), consumed) };
        if strtod_result_is_erange(val, consumed_bytes, exact) {
            unsafe { set_abi_errno(libc::ERANGE) };
        }
    }

    if let Some(p) = profile {
        runtime_policy::observe(
            ApiFamily::Stdlib,
            p,
            runtime_policy::scaled_cost(5, consumed),
            false,
        );
    }
    val
}

/// Case-insensitive check for "inf" or "infinity" anywhere in the consumed
/// prefix — used to distinguish a literal Infinity input from an overflow
/// result for strtod errno reporting.
fn contains_inf_literal(bytes: &[u8]) -> bool {
    if bytes.len() < 3 {
        return false;
    }
    bytes.windows(3).any(|w| {
        w[0].eq_ignore_ascii_case(&b'i')
            && w[1].eq_ignore_ascii_case(&b'n')
            && w[2].eq_ignore_ascii_case(&b'f')
    })
}

fn finite_float_underflowed_f64(value: f64, consumed: &[u8]) -> bool {
    value.is_finite()
        && value.abs() < f64::MIN_POSITIVE
        && contains_nonzero_significand_digit(consumed)
}

fn finite_float_underflowed_f32(value: f32, consumed: &[u8]) -> bool {
    value.is_finite()
        && value.abs() < f32::MIN_POSITIVE
        && contains_nonzero_significand_digit(consumed)
}

/// Whether a parsed `f64` strtod/wcstod result must raise `ERANGE`: overflow to
/// ±inf without a literal `inf` in the consumed text, or an inexact underflow
/// (an exactly-representable subnormal does NOT count — glibc only flags inexact
/// underflow). `exact` is `strtod_impl`'s exactness flag. Shared by strtod and
/// wcstod so the narrow and wide parsers agree (glibc 2.38+ raises ERANGE on the
/// wide path too — it previously suppressed it, a divergence fl used to mirror).
pub(crate) fn strtod_result_is_erange(value: f64, consumed: &[u8], exact: bool) -> bool {
    let overflowed = value.is_infinite() && !contains_inf_literal(consumed);
    let exact_subnormal = exact && value != 0.0 && value.abs() < f64::MIN_POSITIVE;
    let underflowed = !exact_subnormal && finite_float_underflowed_f64(value, consumed);
    overflowed || underflowed
}

/// `f32` counterpart of [`strtod_result_is_erange`] for strtof/wcstof.
/// `exact_subnormal` is `strtof_impl`'s flag (true when the result is an exactly
/// representable subnormal, which is not an underflow).
pub(crate) fn strtof_result_is_erange(value: f32, consumed: &[u8], exact_subnormal: bool) -> bool {
    let overflowed = value.is_infinite() && !contains_inf_literal(consumed);
    let underflowed = !exact_subnormal && finite_float_underflowed_f32(value, consumed);
    overflowed || underflowed
}

/// Whether the consumed prefix has a non-zero significand digit.
///
/// Exponent digits do not count: exact-zero inputs like `0e-400` must not set
/// `ERANGE`, while non-zero underflows like `1e-400` must.
fn contains_nonzero_significand_digit(bytes: &[u8]) -> bool {
    let mut i = 0usize;
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i < bytes.len() && matches!(bytes[i], b'+' | b'-') {
        i += 1;
    }

    let is_hex = i + 1 < bytes.len() && bytes[i] == b'0' && matches!(bytes[i + 1], b'x' | b'X');
    if is_hex {
        i += 2;
        while i < bytes.len() && !matches!(bytes[i], b'p' | b'P') {
            if matches!(bytes[i], b'1'..=b'9' | b'A'..=b'F' | b'a'..=b'f') {
                return true;
            }
            i += 1;
        }
        return false;
    }

    while i < bytes.len() && !matches!(bytes[i], b'e' | b'E') {
        if matches!(bytes[i], b'1'..=b'9') {
            return true;
        }
        i += 1;
    }
    false
}

/// C `strtof` -- converts string to float with endptr.
///
/// # Safety
///
/// Same safety requirements as `strtod`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strtof(nptr: *const c_char, endptr: *mut *mut c_char) -> f32 {
    if nptr.is_null() {
        if !endptr.is_null() {
            unsafe { *endptr = nptr as *mut c_char };
        }
        return 0.0;
    }

    // Deployed fast-path: see `strtod`. Stdlib is always-Allow in non-test, so the
    // per-call decide()+observe() membrane is skipped; `profile` is `Some` only on
    // the full (test) path.
    let profile = if runtime_policy::stdlib_membrane_fastpath() {
        None
    } else {
        let (_, decision) = runtime_policy::decide(
            ApiFamily::Stdlib,
            nptr as usize,
            0,
            false,
            known_remaining(nptr as usize).is_none(),
            0,
        );
        if matches!(decision.action, MembraneAction::Deny) {
            runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 5, true);
            if !endptr.is_null() {
                unsafe { *endptr = nptr as *mut c_char };
            }
            return 0.0;
        }
        Some(decision.profile)
    };

    let Some(len) = (unsafe { scan_terminated_numeric_string(nptr) }) else {
        if let Some(p) = profile {
            runtime_policy::observe(ApiFamily::Stdlib, p, 5, true);
        }
        if !endptr.is_null() {
            unsafe { *endptr = nptr as *mut c_char };
        }
        return 0.0;
    };
    let slice = unsafe { std::slice::from_raw_parts(nptr.cast::<u8>(), len + 1) };
    let (value, consumed, exact_subnormal) =
        frankenlibc_core::stdlib::conversion::strtof_impl(slice);
    if !endptr.is_null() {
        unsafe { *endptr = nptr.add(consumed) as *mut c_char };
    }

    // Exact f32 subnormals are not underflow (glibc raises ERANGE only for
    // inexact underflow), so the parser's flag suppresses the false positive.
    // (bd-2g7oyh.187)
    if consumed > 0 {
        let consumed_bytes = unsafe { std::slice::from_raw_parts(nptr.cast::<u8>(), consumed) };
        if strtof_result_is_erange(value, consumed_bytes, exact_subnormal) {
            unsafe { set_abi_errno(libc::ERANGE) };
        }
    }

    if let Some(p) = profile {
        runtime_policy::observe(
            ApiFamily::Stdlib,
            p,
            runtime_policy::scaled_cost(5, consumed),
            false,
        );
    }
    value
}

// ---------------------------------------------------------------------------
// system() POSIX signal handling
//
// POSIX requires system() to ignore SIGINT and SIGQUIT in the calling process
// and to block SIGCHLD while waiting for the command, restoring all three
// afterward (glibc implements this via posix_spawn with SETSIGDEF + SETSIGMASK).
// Without it, a SIGINT during system() wrongly fires the caller's handler and a
// caller's SIGCHLD handler can reap the command's child out from under us.
// ---------------------------------------------------------------------------

/// Kernel `struct sigaction` layout (the kernel order is handler, flags,
/// restorer, then an 8-byte mask — distinct from the libc userspace struct).
#[repr(C)]
#[derive(Clone, Copy)]
struct KernelSigaction {
    handler: usize,
    flags: usize,
    restorer: usize,
    mask: u64,
}

/// Kernel sigset size in bytes (a single 64-bit word covers signals 1..64).
const KSIG_SETSIZE: usize = core::mem::size_of::<u64>();

/// Install SIG_IGN for `sig`, returning the previous kernel disposition (so it
/// can be restored verbatim, preserving any restorer/flags the caller set).
unsafe fn system_ignore_signal(sig: c_int) -> Option<KernelSigaction> {
    let act = KernelSigaction {
        handler: libc::SIG_IGN,
        flags: 0,
        restorer: 0,
        mask: 0,
    };
    let mut old = KernelSigaction {
        handler: 0,
        flags: 0,
        restorer: 0,
        mask: 0,
    };
    match unsafe {
        raw_syscall::sys_rt_sigaction(
            sig,
            &act as *const _ as *const u8,
            &mut old as *mut _ as *mut u8,
            KSIG_SETSIZE,
        )
    } {
        Ok(()) => Some(old),
        Err(_) => None,
    }
}

/// Restore a previously-saved kernel disposition for `sig`.
unsafe fn system_restore_signal(sig: c_int, act: &KernelSigaction) {
    let _ = unsafe {
        raw_syscall::sys_rt_sigaction(
            sig,
            act as *const _ as *const u8,
            ptr::null_mut(),
            KSIG_SETSIZE,
        )
    };
}

/// Reset `sig` to SIG_DFL (used in the child before exec).
unsafe fn system_default_signal(sig: c_int) {
    let act = KernelSigaction {
        handler: libc::SIG_DFL,
        flags: 0,
        restorer: 0,
        mask: 0,
    };
    let _ = unsafe {
        raw_syscall::sys_rt_sigaction(
            sig,
            &act as *const _ as *const u8,
            ptr::null_mut(),
            KSIG_SETSIZE,
        )
    };
}

// ---------------------------------------------------------------------------
// system
// ---------------------------------------------------------------------------

/// POSIX `system` — execute a shell command.
///
/// If `command` is NULL, returns non-zero to indicate a shell is available.
/// Otherwise, forks and executes `/bin/sh -c command`, returning the exit status.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn system(command: *const c_char) -> c_int {
    let (mode, decision) = runtime_policy::decide(
        ApiFamily::Stdlib,
        command as usize,
        0,
        false,
        known_remaining(command as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(libc::EPERM) };
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 50, true);
        return -1;
    }

    if command.is_null() {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 5, false);
        return 1; // shell is available
    }

    let repair = repair_enabled(mode.heals_enabled(), decision.action);
    let bound = if repair {
        known_remaining(command as usize)
    } else {
        None
    };

    let (_len, terminated) = unsafe { scan_c_string(command, bound) };
    if !terminated {
        unsafe { set_abi_errno(libc::EINVAL) };
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 10, true);
        return -1;
    }

    // POSIX: ignore SIGINT/SIGQUIT and block SIGCHLD in the parent for the
    // duration of the command, restoring them afterward. Save the previous
    // dispositions and mask (copied into the child by fork) to restore.
    let saved_int = unsafe { system_ignore_signal(libc::SIGINT) };
    let saved_quit = unsafe { system_ignore_signal(libc::SIGQUIT) };
    let block_mask: u64 = 1u64 << ((libc::SIGCHLD - 1) as u64);
    let mut saved_mask: u64 = 0;
    let _ = unsafe {
        raw_syscall::sys_rt_sigprocmask(
            libc::SIG_BLOCK,
            &block_mask as *const u64 as *const u8,
            &mut saved_mask as *mut u64 as *mut u8,
            KSIG_SETSIZE,
        )
    };
    let restore_parent = || unsafe {
        if let Some(a) = saved_int {
            system_restore_signal(libc::SIGINT, &a);
        }
        if let Some(a) = saved_quit {
            system_restore_signal(libc::SIGQUIT, &a);
        }
        let _ = raw_syscall::sys_rt_sigprocmask(
            libc::SIG_SETMASK,
            &saved_mask as *const u64 as *const u8,
            ptr::null_mut(),
            KSIG_SETSIZE,
        );
    };

    // SAFETY: fork via clone(SIGCHLD).
    let pid = match raw_syscall::sys_clone_fork(libc::SIGCHLD as usize) {
        Ok(p) => p,
        Err(e) => {
            restore_parent();
            unsafe { set_abi_errno(e) };
            runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 50, true);
            return -1;
        }
    };

    if pid == 0 {
        // Child process: restore default signal handling and the caller's
        // original mask (matching glibc's posix_spawn SETSIGDEF/SETSIGMASK) so
        // the shell behaves normally, then exec /bin/sh -c command.
        unsafe {
            system_default_signal(libc::SIGINT);
            system_default_signal(libc::SIGQUIT);
            let _ = raw_syscall::sys_rt_sigprocmask(
                libc::SIG_SETMASK,
                &saved_mask as *const u64 as *const u8,
                ptr::null_mut(),
                KSIG_SETSIZE,
            );
        }
        let sh = c"/bin/sh".as_ptr();
        let dash_c = c"-c".as_ptr();
        let argv: [*const c_char; 4] = [sh, dash_c, command, ptr::null()];
        // SAFETY: argv is well-formed null-terminated array.
        unsafe {
            let _ = raw_syscall::sys_execve(
                sh as *const u8,
                argv.as_ptr() as *const *const u8,
                HOST_ENVIRON as *const *const u8,
            );
            // If execve returns, exit with 127.
            raw_syscall::sys_exit_group(127);
        }
    }

    // Parent: wait for child.
    let mut wstatus: c_int = 0;
    loop {
        let ret = unsafe {
            raw_syscall::sys_wait4(pid, &mut wstatus as *mut c_int, 0, core::ptr::null_mut())
        };
        match ret {
            Ok(waited_pid) if waited_pid == pid => break,
            Ok(_) => continue, // Spurious wakeup, keep waiting
            Err(e) if e != libc::EINTR => {
                restore_parent();
                unsafe { set_abi_errno(e) };
                runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 50, true);
                return -1;
            }
            Err(_) => continue, // EINTR, retry
        }
    }

    restore_parent();
    runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 50, false);
    wstatus
}

// ---------------------------------------------------------------------------
// putenv
// ---------------------------------------------------------------------------

/// POSIX `putenv` — change or add an environment variable.
///
/// The string must be of the form `NAME=value`. Unlike `setenv`, the string
/// itself is stored in the environment (not a copy), so it must remain valid.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn putenv(string: *mut c_char) -> c_int {
    if string.is_null() {
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }

    let (_mode, decision) = runtime_policy::decide(
        ApiFamily::Stdlib,
        string as usize,
        0,
        false,
        known_remaining(string as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(libc::EPERM) };
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 10, true);
        return -1;
    }

    let bound = known_remaining(string as usize);
    // Find '=' to split name and value.
    let (len, terminated) = unsafe { scan_c_string(string, bound) };
    if !terminated {
        unsafe { set_abi_errno(libc::EINVAL) };
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 10, true);
        return -1;
    }
    let bytes = unsafe { std::slice::from_raw_parts(string as *const u8, len) };
    if bytes.iter().position(|&b| b == b'=').is_none() {
        // No '=': unset the variable (glibc behavior).
        return unsafe { super::stdlib_abi::unsetenv(string) };
    }

    // Native putenv: store the string directly in environ (no copy).
    let ret = unsafe { native_putenv_impl(string) };
    if ret == 0 {
        bump_environ_epoch();
    }

    runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 10, ret != 0);
    ret
}

// ---------------------------------------------------------------------------
// Additional stdlib — temp file helpers
// ---------------------------------------------------------------------------

const MKTEMP_SUFFIX_LEN: usize = 6;
const MKTEMP_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const MKOSTEMP_ALLOWED_FLAGS: c_int =
    libc::O_APPEND | libc::O_CLOEXEC | libc::O_SYNC | libc::O_DSYNC | libc::O_RSYNC;

static MKTEMP_NONCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

#[inline]
fn mix64(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

unsafe fn mkostemps_inner(template: *mut c_char, suffixlen: c_int, flags: c_int) -> (c_int, bool) {
    if template.is_null() || suffixlen < 0 {
        unsafe { set_abi_errno(libc::EINVAL) };
        return (-1, true);
    }
    if flags & !MKOSTEMP_ALLOWED_FLAGS != 0 {
        unsafe { set_abi_errno(libc::EINVAL) };
        return (-1, true);
    }

    let (mode, decision) = runtime_policy::decide(
        ApiFamily::Stdlib,
        template as usize,
        0,
        true,
        known_remaining(template as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EACCES) };
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 5, true);
        return (-1, true);
    }

    let repair = repair_enabled(mode.heals_enabled(), decision.action);
    let bound = if repair {
        known_remaining(template as usize)
    } else {
        None
    };

    // SAFETY: `template` must be a writable, NUL-terminated byte string by ABI contract.
    let (total_len, terminated) = unsafe { scan_c_string(template, bound) };
    if !terminated {
        unsafe { set_abi_errno(errno::EINVAL) };
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 5, true);
        return (-1, true);
    }
    let suffix_len = suffixlen as usize;
    if total_len < MKTEMP_SUFFIX_LEN || suffix_len > total_len.saturating_sub(MKTEMP_SUFFIX_LEN) {
        unsafe { set_abi_errno(errno::EINVAL) };
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 5, true);
        return (-1, true);
    }

    let template_bytes = unsafe { std::slice::from_raw_parts(template as *const u8, total_len) };

    let x_start = total_len - suffix_len - MKTEMP_SUFFIX_LEN;
    if !template_bytes[x_start..x_start + MKTEMP_SUFFIX_LEN]
        .iter()
        .all(|&b| b == b'X')
    {
        unsafe { set_abi_errno(libc::EINVAL) };
        return (-1, true);
    }

    // SAFETY: `template` points to writable storage at least `total_len + 1` bytes long.
    let buf = unsafe { std::slice::from_raw_parts_mut(template as *mut u8, total_len) };
    let seed = mix64(
        (std::process::id() as u64).wrapping_shl(32)
            ^ (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0))
            ^ MKTEMP_NONCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
    );

    for attempt in 0_u64..256 {
        let mut state = mix64(seed ^ attempt.wrapping_mul(0x9e37_79b9_7f4a_7c15));
        for idx in 0..MKTEMP_SUFFIX_LEN {
            state = mix64(state.wrapping_add(idx as u64));
            buf[x_start + idx] = MKTEMP_CHARS[(state as usize) % MKTEMP_CHARS.len()];
        }

        // SAFETY: `template` now names a candidate pathname and points to NUL-terminated bytes.
        let fd = unsafe {
            raw_syscall::sys_openat(
                libc::AT_FDCWD,
                template as *const u8,
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | flags,
                0o600,
            )
        };
        match fd {
            Ok(f) => return (f as c_int, false),
            Err(e) if e != libc::EEXIST => {
                unsafe { set_abi_errno(e) };
                return (-1, true);
            }
            Err(_) => {} // EEXIST, try next
        }
    }

    unsafe { set_abi_errno(libc::EEXIST) };
    (-1, true)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn reallocarray(ptr: *mut c_void, nmemb: usize, size: usize) -> *mut c_void {
    let Some(total_size) = nmemb.checked_mul(size) else {
        // POSIX/glibc semantics: overflow is an allocation failure with ENOMEM.
        unsafe { set_abi_errno(libc::ENOMEM) };
        // Can't easily observe without a decision profile, but we can just return null.
        return ptr::null_mut();
    };

    // Deployed fast path (DEFAULT): `realloc` runs its OWN reentry/bootstrap/membrane
    // handling (decide+observe or the strict host path), so the stdlib decide+observe
    // here is a REDUNDANT per-call tax — measured 10.8ns (reallocarray 19.3ns vs
    // realloc 8.5ns), which made reallocarray 1.7x slower than glibc (11.2ns). Stdlib
    // is always-Allow in deployed mode, so the decision would be Allow regardless;
    // delegate straight to realloc. Mirrors the strtol/strtoul membrane fast path.
    if runtime_policy::stdlib_membrane_fastpath() {
        return unsafe { crate::malloc_abi::realloc(ptr, total_size) };
    }

    let adverse_pointer = !ptr.is_null() && known_remaining(ptr as usize).is_none();
    let (_, decision) = runtime_policy::decide(
        ApiFamily::Stdlib,
        ptr as usize,
        total_size,
        true,
        adverse_pointer,
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 6, true);
        return ptr::null_mut();
    }

    // SAFETY: ABI contract matches realloc; overflow has already been checked.
    let out = unsafe { crate::malloc_abi::realloc(ptr, total_size) };
    runtime_policy::observe(
        ApiFamily::Stdlib,
        decision.profile,
        runtime_policy::scaled_cost(8, total_size.max(1)),
        out.is_null(),
    );
    out
}

/// NetBSD `reallocarr(**ptr, num, size) -> int` — reallocarray-like
/// with overflow check. On success writes the new pointer through
/// `*ptr` and returns 0; on failure returns a positive errno value
/// (EINVAL/EOVERFLOW/ENOMEM) without setting the global errno or
/// modifying `*ptr`. `size == 0` is invalid; `num == 0` frees the
/// existing allocation and stores NULL. Distinct from POSIX
/// `reallocarray` which returns the new pointer or NULL via the global
/// errno.
///
/// # Safety
///
/// `ptr` must be a valid pointer to a writable `*mut c_void` slot.
/// The slot's current value, if non-NULL, must be a `realloc`-able
/// allocation.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn reallocarr(ptr: *mut *mut c_void, num: usize, size: usize) -> c_int {
    if ptr.is_null() {
        return libc::EINVAL;
    }
    if size == 0 {
        return libc::EINVAL;
    }
    let total = match num.checked_mul(size) {
        Some(t) => t,
        None => return libc::EOVERFLOW,
    };
    if total == 0 {
        // NetBSD reallocarr(ptr, 0, size) frees the existing allocation
        // and sets *ptr to NULL when size is non-zero.
        let cur = unsafe { *ptr };
        if !cur.is_null() {
            unsafe { crate::malloc_abi::free(cur) };
        }
        unsafe { *ptr = ptr::null_mut() };
        return 0;
    }
    let cur = unsafe { *ptr };
    let new_ptr = unsafe { crate::malloc_abi::realloc(cur, total) };
    if new_ptr.is_null() {
        return libc::ENOMEM;
    }
    unsafe { *ptr = new_ptr };
    0
}

/// OpenBSD `freezero` — zero `size` bytes at `ptr`, then free the allocation.
///
/// Used for buffers that contained secrets (private keys, passwords,
/// session tokens) so the freed slot can't leak data to a future
/// allocation that reuses it. Equivalent to:
///   `explicit_bzero(ptr, size); free(ptr);`
/// but exposed as a single primitive so callers can't forget to zero
/// before freeing.
///
/// `ptr == NULL` is a no-op (matches `free(NULL)`). `size` should
/// describe the original allocation size — passing a smaller value
/// leaves trailing bytes un-zeroed, which is a caller bug but not
/// undefined behavior here.
///
/// # Safety
///
/// Caller must ensure `ptr` was returned by an allocator from this
/// libc (malloc/calloc/realloc family) and that `size` does not
/// exceed the allocation's true size.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn freezero(ptr: *mut c_void, size: usize) {
    if ptr.is_null() {
        return;
    }
    let zero_len = bounded_zero_len(ptr, size);
    // SAFETY: caller contract requires `size` bytes valid at `ptr`.
    // `explicit_bzero` is guaranteed not to be optimized away even
    // though the memory is about to be freed. When the pointer is a
    // tracked FrankenLibC allocation, clamp to the true remaining size
    // so a bad caller-provided length cannot turn the helper into an
    // out-of-bounds write. If an untracked caller asks for a range Rust
    // cannot represent as a slice, we still free but skip the impossible
    // zeroing pass instead of violating explicit_bzero's preconditions.
    unsafe {
        if let Some(zero_len) = zero_len {
            crate::string_abi::explicit_bzero(ptr, zero_len);
        }
        crate::malloc_abi::free(ptr);
    }
}

/// OpenBSD `recallocarray` — reallocarray with secret-zeroing semantics.
///
/// Behaves like `reallocarray(ptr, nmemb, size)` (overflow-checked
/// `nmemb * size`) with two additional security guarantees:
///   * On grow: bytes beyond the previous logical size are zeroed
///     (so callers don't observe the prior contents of recycled
///     allocator slots).
///   * On shrink: bytes released back to the allocator are zeroed
///     before the allocation is reduced — the caller's secrets cannot
///     leak through the allocator's free-list.
///
/// `ptr == NULL` and `oldnmemb == 0` requests a fresh zero-initialized
/// allocation (matching `calloc(nmemb, size)` semantics). When `ptr`
/// is non-NULL, `oldnmemb * size` must describe the previously valid
/// region; if `oldnmemb` overflows, the call fails with `EINVAL`.
///
/// # Safety
///
/// Caller must ensure that, when `ptr` is non-NULL, it was returned
/// by a previous call to a libc allocator and that the previous
/// logical size was `oldnmemb * size`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn recallocarray(
    ptr: *mut c_void,
    oldnmemb: usize,
    nmemb: usize,
    size: usize,
) -> *mut c_void {
    let Some(new_size) = nmemb.checked_mul(size) else {
        unsafe { set_abi_errno(libc::ENOMEM) };
        return ptr::null_mut();
    };

    if ptr.is_null() {
        // OpenBSD requires oldnmemb == 0 in this case; otherwise the
        // request is malformed (we can't honour the contract of
        // zeroing previously-held bytes if there's no previous block).
        if oldnmemb != 0 {
            unsafe { set_abi_errno(libc::EINVAL) };
            return ptr::null_mut();
        }
        // Fresh zero-initialized allocation.
        return unsafe { crate::malloc_abi::calloc(nmemb, size) };
    }

    let Some(old_size) = oldnmemb.checked_mul(size) else {
        unsafe { set_abi_errno(libc::EINVAL) };
        return ptr::null_mut();
    };
    let Some(effective_old_size) = bounded_zero_len(ptr, old_size) else {
        unsafe { set_abi_errno(libc::EINVAL) };
        return ptr::null_mut();
    };
    if new_size > effective_old_size && new_size - effective_old_size > MAX_EXPLICIT_BZERO_LEN {
        unsafe { set_abi_errno(libc::ENOMEM) };
        return ptr::null_mut();
    }

    if new_size == 0 {
        // Equivalent to free(ptr) after zeroing — preserve the secret-
        // zeroing guarantee.
        unsafe {
            crate::string_abi::explicit_bzero(ptr, effective_old_size);
            crate::malloc_abi::free(ptr);
        }
        return ptr::null_mut();
    }

    // On shrink: zero the trailing region we're about to release back
    // to the allocator BEFORE the realloc — the allocator may reuse
    // those bytes for a future allocation, and secrets must not leak.
    if new_size < effective_old_size {
        // SAFETY: effective_old_size is clamped to the known allocation
        // size when the pointer is tracked, so the zeroed range is
        // bounded by real writable memory even if oldnmemb was wrong.
        unsafe {
            crate::string_abi::explicit_bzero(ptr.add(new_size), effective_old_size - new_size);
        }
    }

    let out = unsafe { crate::malloc_abi::realloc(ptr, new_size) };
    if out.is_null() {
        // realloc already set errno (typically ENOMEM); leave the
        // original block untouched per realloc semantics.
        return ptr::null_mut();
    }

    // On grow: zero the newly-acquired tail so the caller observes
    // a clean buffer instead of recycled allocator contents.
    if new_size > effective_old_size {
        // SAFETY: realloc returned a buffer of at least new_size bytes;
        // the [old_size, new_size) range is the freshly added tail.
        unsafe {
            crate::string_abi::explicit_bzero(
                out.add(effective_old_size),
                new_size - effective_old_size,
            );
        }
    }

    out
}

/// `strtold` — convert string to long double (on x86_64, same as f64).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strtold(nptr: *const c_char, endptr: *mut *mut c_char) -> f64 {
    // SAFETY: ABI contract mirrors strtod and current ABI model treats long double as f64.
    unsafe { strtod(nptr, endptr) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mkostemp(template: *mut c_char, flags: c_int) -> c_int {
    let (_, decision) = runtime_policy::decide(
        ApiFamily::Stdlib,
        template as usize,
        0,
        true,
        template.is_null() || known_remaining(template as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(libc::EPERM) };
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 8, true);
        return -1;
    }

    let (fd, failed) = unsafe { mkostemps_inner(template, 0, flags) };
    runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 18, failed);
    fd
}

// ---------------------------------------------------------------------------
// mkstemps / mkostemps / clearenv
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mkstemps(template: *mut c_char, suffixlen: c_int) -> c_int {
    let (_, decision) = runtime_policy::decide(
        ApiFamily::Stdlib,
        template as usize,
        0,
        true,
        template.is_null() || known_remaining(template as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(libc::EPERM) };
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 8, true);
        return -1;
    }

    let (fd, failed) = unsafe { mkostemps_inner(template, suffixlen, 0) };
    runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 18, failed);
    fd
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mkostemps(template: *mut c_char, suffixlen: c_int, flags: c_int) -> c_int {
    let (_, decision) = runtime_policy::decide(
        ApiFamily::Stdlib,
        template as usize,
        0,
        true,
        template.is_null() || known_remaining(template as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(libc::EPERM) };
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 8, true);
        return -1;
    }

    let (fd, failed) = unsafe { mkostemps_inner(template, suffixlen, flags) };
    runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 18, failed);
    fd
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clearenv() -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdlib, 0, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(libc::EPERM) };
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 6, true);
        return -1;
    }

    let mut cleared = false;
    {
        let _lock = environ_lock_guard();
        // SAFETY: HOST_ENVIRON is the process environment array. Holding
        // ENVIRON_LOCK makes the array stable while we replace its first slot
        // with the terminating NULL entry.
        unsafe {
            if !HOST_ENVIRON.is_null() {
                *HOST_ENVIRON = ptr::null_mut();
                cleared = true;
            }
        }
    }

    if cleared {
        bump_environ_epoch();
    }

    runtime_policy::observe(
        ApiFamily::Stdlib,
        decision.profile,
        runtime_policy::scaled_cost(4, usize::from(cleared)),
        false,
    );
    0
}

// ===========================================================================
// drand48 family (9 functions)
// ===========================================================================

const RAND48_STATE_BYTES: usize = core::mem::size_of::<[u16; 3]>();
const RAND48_PARAM_BYTES: usize = core::mem::size_of::<[u16; 7]>();
const RANDOM_STATE_MIN_BYTES: usize = 8;
// glibc's largest generator (TYPE_4, degree 63) uses a 256-byte state buffer.
// This bound must cover it so `setstate` recovers the same size — and thus the
// same generator type — that `initstate` selected; capping lower would make a
// 256-byte buffer initialize as TYPE_4 but restore as TYPE_3 (size 128).
const RANDOM_STATE_MAX_BYTES: usize = 256;
const RANDOM_STATE_REGISTRY_LIMIT: usize = 64;

static RANDOM_STATE_BUFFERS: std::sync::Mutex<Vec<(usize, usize)>> =
    std::sync::Mutex::new(Vec::new());

fn remember_random_state_buffer(ptr: *const c_char, len: usize) {
    let ptr = ptr as usize;
    let len = len.min(RANDOM_STATE_MAX_BYTES);
    let mut buffers = RANDOM_STATE_BUFFERS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some((_, stored_len)) = buffers
        .iter_mut()
        .find(|(stored_ptr, _)| *stored_ptr == ptr)
    {
        *stored_len = len;
        return;
    }
    if buffers.len() == RANDOM_STATE_REGISTRY_LIMIT {
        buffers.remove(0);
    }
    buffers.push((ptr, len));
}

fn remembered_random_state_len(ptr: *const c_char) -> Option<usize> {
    let ptr = ptr as usize;
    let buffers = RANDOM_STATE_BUFFERS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    buffers
        .iter()
        .rev()
        .find_map(|(stored_ptr, len)| (*stored_ptr == ptr).then_some(*len))
}

fn random_state_len_for_setstate(ptr: *const c_char) -> Option<usize> {
    match known_remaining(ptr as usize) {
        Some(remaining) if remaining >= RANDOM_STATE_MIN_BYTES => {
            Some(remaining.min(RANDOM_STATE_MAX_BYTES))
        }
        Some(_) => None,
        None => remembered_random_state_len(ptr).or(Some(RANDOM_STATE_MIN_BYTES)),
    }
}

/// `drand48` — return a double in [0.0, 1.0) using global 48-bit state.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn drand48() -> c_double {
    // Membrane fast-path (see strtol family / bd-n40in2): Stdlib RNG with no pointer arg
    // is provably always-Allow and `observe` is telemetry-only, so skip both in non-test —
    // byte-identical to the result the slow path returns. Tests take the full path.
    if runtime_policy::stdlib_membrane_fastpath() {
        return frankenlibc_core::stdlib::drand48();
    }
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdlib, 0, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, true);
        return 0.0;
    }
    let result = frankenlibc_core::stdlib::drand48();
    runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, false);
    result
}

/// `erand48` — return a double in [0.0, 1.0) using caller-supplied state.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn erand48(xsubi: *mut u16) -> c_double {
    // Deployed fast path: skip the redundant decide+observe membrane tax (~5ns,
    // ~2x on the ~5ns LCG). In deployed always-Allow mode `decide` never Denies, so
    // the full path's result is gated only by `null || !tracked_region_fits` — which
    // this keeps — making it byte-identical. Mirrors the drand48/lrand48/mrand48 fast
    // path (which have no pointer arg); the explicit-state RNGs keep the fit guard.
    if runtime_policy::stdlib_membrane_fastpath() {
        if xsubi.is_null() || !tracked_region_fits(xsubi.cast(), RAND48_STATE_BYTES) {
            return 0.0;
        }
        let state = unsafe { &mut *(xsubi as *mut [u16; 3]) };
        return frankenlibc_core::stdlib::erand48(state);
    }
    let (_, decision) = runtime_policy::decide(
        ApiFamily::Stdlib,
        xsubi as usize,
        0,
        true,
        xsubi.is_null(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny)
        || xsubi.is_null()
        || !tracked_region_fits(xsubi.cast(), RAND48_STATE_BYTES)
    {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, true);
        return 0.0;
    }
    let state = unsafe { &mut *(xsubi as *mut [u16; 3]) };
    let result = frankenlibc_core::stdlib::erand48(state);
    runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, false);
    result
}

/// `lrand48` — return non-negative long in [0, 2^31) using global state.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lrand48() -> c_long {
    // Membrane fast-path (see drand48): RNG, no pointer arg → always-Allow, telemetry-only.
    if runtime_policy::stdlib_membrane_fastpath() {
        return frankenlibc_core::stdlib::lrand48() as c_long;
    }
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdlib, 0, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, true);
        return 0;
    }
    let result = frankenlibc_core::stdlib::lrand48();
    runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, false);
    result as c_long
}

/// `nrand48` — return non-negative long using caller-supplied state.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nrand48(xsubi: *mut u16) -> c_long {
    // Deployed fast path: skip the redundant decide+observe tax (see erand48).
    if runtime_policy::stdlib_membrane_fastpath() {
        if xsubi.is_null() || !tracked_region_fits(xsubi.cast(), RAND48_STATE_BYTES) {
            return 0;
        }
        let state = unsafe { &mut *(xsubi as *mut [u16; 3]) };
        return frankenlibc_core::stdlib::nrand48(state) as c_long;
    }
    let (_, decision) = runtime_policy::decide(
        ApiFamily::Stdlib,
        xsubi as usize,
        0,
        true,
        xsubi.is_null(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny)
        || xsubi.is_null()
        || !tracked_region_fits(xsubi.cast(), RAND48_STATE_BYTES)
    {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, true);
        return 0;
    }
    let state = unsafe { &mut *(xsubi as *mut [u16; 3]) };
    let result = frankenlibc_core::stdlib::nrand48(state);
    runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, false);
    result as c_long
}

/// `mrand48` — return signed long in [-2^31, 2^31) using global state.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mrand48() -> c_long {
    // Membrane fast-path (see drand48): RNG, no pointer arg → always-Allow, telemetry-only.
    if runtime_policy::stdlib_membrane_fastpath() {
        return frankenlibc_core::stdlib::mrand48() as c_long;
    }
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdlib, 0, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, true);
        return 0;
    }
    let result = frankenlibc_core::stdlib::mrand48();
    runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, false);
    result as c_long
}

/// `jrand48` — return signed long using caller-supplied state.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn jrand48(xsubi: *mut u16) -> c_long {
    // Deployed fast path: skip the redundant decide+observe tax (see erand48).
    if runtime_policy::stdlib_membrane_fastpath() {
        if xsubi.is_null() || !tracked_region_fits(xsubi.cast(), RAND48_STATE_BYTES) {
            return 0;
        }
        let state = unsafe { &mut *(xsubi as *mut [u16; 3]) };
        return frankenlibc_core::stdlib::jrand48(state) as c_long;
    }
    let (_, decision) = runtime_policy::decide(
        ApiFamily::Stdlib,
        xsubi as usize,
        0,
        true,
        xsubi.is_null(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny)
        || xsubi.is_null()
        || !tracked_region_fits(xsubi.cast(), RAND48_STATE_BYTES)
    {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, true);
        return 0;
    }
    let state = unsafe { &mut *(xsubi as *mut [u16; 3]) };
    let result = frankenlibc_core::stdlib::jrand48(state);
    runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, false);
    result as c_long
}

/// `srand48` — seed the global 48-bit state from a single long.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn srand48(seedval: c_long) {
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdlib, 0, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, true);
        return;
    }
    frankenlibc_core::stdlib::srand48(seedval);
    runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, false);
}

/// `seed48` — seed global state with three u16 values; return old seed.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn seed48(seed16v: *mut u16) -> *mut u16 {
    // Static buffer for returning old seed (matching glibc's static buffer approach).
    static mut OLD_SEED: [u16; 3] = [0; 3];

    let (_, decision) = runtime_policy::decide(
        ApiFamily::Stdlib,
        seed16v as usize,
        0,
        true,
        seed16v.is_null(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny)
        || seed16v.is_null()
        || !tracked_region_fits(seed16v.cast(), RAND48_STATE_BYTES)
    {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, true);
        return std::ptr::addr_of_mut!(OLD_SEED) as *mut u16;
    }
    let input = unsafe { &*(seed16v as *const [u16; 3]) };
    let old = frankenlibc_core::stdlib::seed48(input);
    unsafe {
        let p = std::ptr::addr_of_mut!(OLD_SEED);
        (*p) = old;
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, false);
        p as *mut u16
    }
}

/// `lcong48` — set all 48-bit LCG parameters.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lcong48(param: *mut u16) {
    let (_, decision) = runtime_policy::decide(
        ApiFamily::Stdlib,
        param as usize,
        0,
        true,
        param.is_null(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny)
        || param.is_null()
        || !tracked_region_fits(param.cast(), RAND48_PARAM_BYTES)
    {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, true);
        return;
    }
    let p = unsafe { &*(param as *const [u16; 7]) };
    frankenlibc_core::stdlib::lcong48(p);
    runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, false);
}

// ===========================================================================
// System V random family (4 functions)
// ===========================================================================

/// `random` — return a pseudo-random number in [0, 2^31-1].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn random() -> c_long {
    // Membrane fast-path (see drand48): RNG, no pointer arg → always-Allow, telemetry-only.
    if runtime_policy::stdlib_membrane_fastpath() {
        return frankenlibc_core::stdlib::sv_random() as c_long;
    }
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdlib, 0, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, true);
        return 0;
    }
    let result = frankenlibc_core::stdlib::sv_random();
    runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, false);
    result as c_long
}

/// `srandom` — seed the random number generator.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn srandom(seed: c_uint) {
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdlib, 0, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, true);
        return;
    }
    frankenlibc_core::stdlib::srandom(seed);
    runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, false);
}

/// `initstate` — initialize and return state buffer for random().
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn initstate(seed: c_uint, state: *mut c_char, size: usize) -> *mut c_char {
    let (_, decision) = runtime_policy::decide(
        ApiFamily::Stdlib,
        state as usize,
        size,
        true,
        state.is_null(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny)
        || state.is_null()
        || size < RANDOM_STATE_MIN_BYTES
    {
        unsafe { set_abi_errno(libc::EINVAL) };
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 6, true);
        return ptr::null_mut();
    }
    if !tracked_region_fits(state.cast_const().cast(), size) {
        unsafe { set_abi_errno(libc::EINVAL) };
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 6, true);
        return ptr::null_mut();
    }
    let buf = unsafe { std::slice::from_raw_parts_mut(state as *mut u8, size) };
    let _ = frankenlibc_core::stdlib::initstate(seed, buf);
    remember_random_state_buffer(state.cast_const(), size);
    runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 6, false);
    state
}

/// `setstate` — restore random state from a previously saved buffer.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setstate(state: *mut c_char) -> *mut c_char {
    let (_, decision) = runtime_policy::decide(
        ApiFamily::Stdlib,
        state as usize,
        0,
        true,
        state.is_null(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) || state.is_null() {
        unsafe { set_abi_errno(libc::EINVAL) };
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 6, true);
        return ptr::null_mut();
    }
    let Some(state_len) = random_state_len_for_setstate(state.cast_const()) else {
        unsafe { set_abi_errno(libc::EINVAL) };
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 6, true);
        return ptr::null_mut();
    };
    let buf = unsafe { std::slice::from_raw_parts(state as *const u8, state_len) };
    let _ = frankenlibc_core::stdlib::setstate(buf);
    runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 6, false);
    state
}

// ===========================================================================
// qsort_r (1 function)
// ===========================================================================

/// `qsort_r` — sort array with reentrant comparator (GNU extension).
///
/// The comparator receives the context pointer as its third argument.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn qsort_r(
    base: *mut c_void,
    nmemb: usize,
    size: usize,
    compar: Option<unsafe extern "C" fn(*const c_void, *const c_void, *mut c_void) -> c_int>,
    arg: *mut c_void,
) {
    let Some(cmp_fn) = compar else {
        return;
    };
    if base.is_null() || nmemb == 0 || size == 0 {
        return;
    }
    let Some(total) = nmemb.checked_mul(size) else {
        return;
    };

    // Strict-mode fast path (the DEFAULT deployed mode): skip `tracked_region_fits` +
    // `decide()` + `observe()` — byte-identical to the full path (Stdlib always-Allows in
    // strict; region validation is the trust-the-caller bypass, glibc never validates).
    // Mirrors the sibling `qsort`/`bsearch` strict fast paths.
    if runtime_policy::strict_passthrough_active() {
        // SAFETY: caller guarantees `base` is `nmemb*size` writable bytes.
        let slice = unsafe { std::slice::from_raw_parts_mut(base as *mut u8, total) };
        frankenlibc_core::stdlib::qsort(slice, size, |a, b| unsafe {
            cmp_fn(
                a.as_ptr() as *const c_void,
                b.as_ptr() as *const c_void,
                arg,
            )
        });
        return;
    }

    if !tracked_region_fits(base.cast_const(), total) {
        return;
    }

    let (_, decision) =
        runtime_policy::decide(ApiFamily::Stdlib, base as usize, total, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 12, true);
        return;
    }

    let slice = unsafe { std::slice::from_raw_parts_mut(base as *mut u8, total) };

    frankenlibc_core::stdlib::qsort(slice, size, |a, b| unsafe {
        cmp_fn(
            a.as_ptr() as *const c_void,
            b.as_ptr() as *const c_void,
            arg,
        )
    });

    runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 12, false);
}

// ---------------------------------------------------------------------------
// bsearch_r (NetBSD reentrant bsearch with thunk)
// ---------------------------------------------------------------------------

/// NetBSD `bsearch_r(key, base, nmemb, size, compar, thunk)` — same
/// as POSIX [`bsearch`] but the comparator receives an extra
/// `void *thunk` parameter so callers can carry context (e.g. a
/// case-insensitive flag, sort-key index) without resorting to a
/// global. Returns a pointer to the matching element, or NULL on
/// no-match / NULL inputs / zero size or count.
///
/// # Safety
///
/// `base`, when non-NULL, must point to `nmemb * size` readable
/// bytes laid out as a sorted array of `size`-byte elements.
/// `key`, when non-NULL, must be readable for the bytes the
/// comparator reads. `compar`, when set, must be safe to invoke
/// with `(key, mid_elem, thunk)` triples.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn bsearch_r(
    key: *const c_void,
    base: *const c_void,
    nmemb: usize,
    size: usize,
    compar: Option<unsafe extern "C" fn(*const c_void, *const c_void, *mut c_void) -> c_int>,
    thunk: *mut c_void,
) -> *mut c_void {
    if key.is_null() || base.is_null() || nmemb == 0 || size == 0 {
        return ptr::null_mut();
    }
    let Some(cmp_fn) = compar else {
        return ptr::null_mut();
    };
    let Some(total) = nmemb.checked_mul(size) else {
        return ptr::null_mut();
    };
    // Strict-mode fast path: skip the two `tracked_region_fits` (each a `known_remaining`
    // registry lookup) — byte-identical to the full path for valid inputs (trust-the-caller,
    // glibc never validates the region). The search itself is identical.
    let validated = runtime_policy::strict_passthrough_active()
        || (tracked_region_fits(base, total) && tracked_region_fits(key, size));
    if !validated {
        return ptr::null_mut();
    }

    let mut low: usize = 0;
    let mut high: usize = nmemb;
    while low < high {
        let mid = low + (high - low) / 2;
        let mid_ptr = unsafe { (base as *const u8).add(mid * size) } as *const c_void;
        let cmp = unsafe { cmp_fn(key, mid_ptr, thunk) };
        match cmp.cmp(&0) {
            core::cmp::Ordering::Equal => return mid_ptr as *mut c_void,
            core::cmp::Ordering::Less => high = mid,
            core::cmp::Ordering::Greater => low = mid + 1,
        }
    }
    ptr::null_mut()
}

// ===========================================================================
// a64l / l64a (2 functions)
// ===========================================================================

/// `a64l` — convert base-64 encoded string to long.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn a64l(s: *const c_char) -> c_long {
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Stdlib, s as usize, 0, true, s.is_null(), 0);
    if matches!(decision.action, MembraneAction::Deny) || s.is_null() {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, true);
        return 0;
    }
    let (len, _) = unsafe { scan_c_string(s, Some(6)) };
    let slice = unsafe { std::slice::from_raw_parts(s as *const u8, len) };
    let result = frankenlibc_core::stdlib::a64l(slice);
    runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, false);
    result as c_long
}

/// `l64a` — convert long to base-64 encoded string.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn l64a(value: c_long) -> *mut c_char {
    // Static buffer for returned string (matching glibc's static buffer).
    static mut BUF: [u8; 8] = [0; 8];

    // SVID base-64 alphabet (index 0='.', 1='/', 2-11='0'-'9', 12-37='A'-'Z',
    // 38-63='a'-'z'), matching frankenlibc_core::stdlib::base64.
    const ALPHABET: &[u8; 64] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    let (_, decision) = runtime_policy::decide(ApiFamily::Stdlib, 0, 0, true, false, 0);
    unsafe {
        let p = std::ptr::addr_of_mut!(BUF);
        let buf = &mut *p;
        if matches!(decision.action, MembraneAction::Deny) {
            runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, true);
            buf[0] = 0;
            return p as *mut u8 as *mut c_char;
        }
        // Encode the low 32 bits as base-64 directly into the static buffer,
        // byte-identical to the old `core::l64a` -> Vec -> copy path but without
        // the per-call heap allocation (glibc uses a static buffer, no alloc).
        let mut v = (value as u32) as u64;
        let mut len = 0usize;
        while v != 0 && len < 6 {
            buf[len] = ALPHABET[(v & 0x3F) as usize];
            v >>= 6;
            len += 1;
        }
        buf[len] = 0;
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, false);
        p as *mut u8 as *mut c_char
    }
}

// ===========================================================================
// ecvt / fcvt / gcvt (3 functions)
// ===========================================================================

/// `ecvt` — convert double to string (scientific notation digits).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ecvt(
    value: c_double,
    ndigit: c_int,
    decpt: *mut c_int,
    sign: *mut c_int,
) -> *mut c_char {
    // Static buffer (matching glibc's thread-unsafe static buffer).
    static mut BUF: [u8; 384] = [0; 384];

    let (_, decision) = runtime_policy::decide(ApiFamily::Stdlib, 0, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 8, true);
        unsafe {
            let p = std::ptr::addr_of_mut!(BUF);
            (*p)[0] = 0;
            return p as *mut u8 as *mut c_char;
        }
    }

    let (digits, dp, neg) = frankenlibc_core::stdlib::ecvt(value, ndigit);
    unsafe {
        let p = std::ptr::addr_of_mut!(BUF);
        let buf = &mut *p;
        let len = digits.len().min(383);
        buf[..len].copy_from_slice(&digits[..len]);
        buf[len] = 0;
        if !decpt.is_null() {
            *decpt = dp;
        }
        if !sign.is_null() {
            *sign = if neg { 1 } else { 0 };
        }
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 8, false);
        p as *mut u8 as *mut c_char
    }
}

/// `fcvt` — convert double to string (fixed-point digits).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fcvt(
    value: c_double,
    ndigit: c_int,
    decpt: *mut c_int,
    sign: *mut c_int,
) -> *mut c_char {
    static mut BUF: [u8; 384] = [0; 384];

    let (_, decision) = runtime_policy::decide(ApiFamily::Stdlib, 0, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 8, true);
        unsafe {
            let p = std::ptr::addr_of_mut!(BUF);
            (*p)[0] = 0;
            return p as *mut u8 as *mut c_char;
        }
    }

    let (digits, dp, neg) = frankenlibc_core::stdlib::fcvt(value, ndigit);
    unsafe {
        let p = std::ptr::addr_of_mut!(BUF);
        let buf = &mut *p;
        let len = digits.len().min(383);
        buf[..len].copy_from_slice(&digits[..len]);
        buf[len] = 0;
        if !decpt.is_null() {
            *decpt = dp;
        }
        if !sign.is_null() {
            *sign = if neg { 1 } else { 0 };
        }
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 8, false);
        p as *mut u8 as *mut c_char
    }
}

/// `gcvt` — convert double to string using general format.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn gcvt(value: c_double, ndigit: c_int, buf: *mut c_char) -> *mut c_char {
    // Strict-mode fast path (DEFAULT deployed): strict passthrough always Allows, so
    // skip the decide + observe membrane bookkeeping and go straight to the same
    // clamped `known_remaining` slice + core render the full path builds — the
    // decide never denies and `observe` is telemetry, so this is byte-identical.
    // gcvt is a per-call float formatter; the ~decide/observe overhead was pure tax.
    if runtime_policy::strict_passthrough_active() {
        if buf.is_null() {
            return buf;
        }
        let assumed_size = (ndigit.max(0) as usize).saturating_add(32).min(512);
        let buf_size = known_remaining(buf as usize)
            .map(|remaining| remaining.min(assumed_size))
            .unwrap_or(assumed_size);
        let slice = unsafe { std::slice::from_raw_parts_mut(buf as *mut u8, buf_size) };
        frankenlibc_core::stdlib::gcvt(value, ndigit, slice);
        return buf;
    }

    let (_, decision) =
        runtime_policy::decide(ApiFamily::Stdlib, buf as usize, 0, true, buf.is_null(), 0);
    if matches!(decision.action, MembraneAction::Deny) || buf.is_null() {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 8, true);
        return buf;
    }

    // Preserve the historical assumption for untracked buffers, but never
    // manufacture a Rust slice past the end of a malloc-tracked allocation.
    let assumed_size = (ndigit.max(0) as usize).saturating_add(32).min(512);
    let tracked_remaining = known_remaining(buf as usize);
    let buf_size = tracked_remaining
        .map(|remaining| remaining.min(assumed_size))
        .unwrap_or(assumed_size);
    let adverse = tracked_remaining.is_some_and(|remaining| remaining < assumed_size);
    let slice = unsafe { std::slice::from_raw_parts_mut(buf as *mut u8, buf_size) };
    frankenlibc_core::stdlib::gcvt(value, ndigit, slice);
    runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 8, adverse);
    buf
}

// ===========================================================================
// Process control (3 functions)
// ===========================================================================

/// Re-entrancy depth for `abort`. A SIGABRT handler that calls `abort()`
/// (directly or transitively via fflush/raise/signal/sigprocmask) would
/// otherwise re-enter the full sequence on the same stack, recursing until
/// stack overflow. Glibc guards against this via an atomic depth counter
/// in `abort.c`; we mirror that behavior.
static ABORT_RECURSION_DEPTH: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// `abort` — abnormal process termination.
///
/// Raises SIGABRT. If caught, re-raises after resetting the handler.
///
/// POSIX: "If the SIGABRT signal is being held or ignored, abort() shall first
/// unblock or unignore the SIGABRT signal." Without unblocking, raise() leaves
/// the signal pending and the process never receives the default core-dump
/// action — production crashes lose their core file. Match glibc abort.c by
/// unblocking SIGABRT in the calling thread before each raise. (bd-r25ks)
///
/// On re-entrant invocation (e.g. a SIGABRT handler calls abort, or any of
/// the flush/raise/sigprocmask helpers transitively triggers another abort)
/// skip the bookkeeping and go straight to the kernel exit so we never
/// recurse on the same stack. (REVIEW round 2: abort recursion guard.)
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn abort() -> ! {
    let depth = ABORT_RECURSION_DEPTH.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    if depth > 0 {
        // Already inside abort on this process. Don't run flush/raise again
        // (they're what re-entered us); fall straight through to exit.
        frankenlibc_core::syscall::sys_exit_group(134)
    }

    // In a multi-threaded process, calling host_fflush(NULL) after fork()
    // (which assert_child_sigabrt does) will deadlock if the host's stdout
    // was locked during the fork. Instead of a full fflush(NULL), we only
    // attempt to flush our managed streams, and even then, we use try_lock.
    let _ = unsafe { crate::stdio_abi::fflush_managed_only_for_abort() };

    // Build a sigset containing only SIGABRT without entering signal_abi:
    // abort may run in a forked child while another vanished thread held
    // runtime-policy locks.
    let mut unblock_set: libc::sigset_t = unsafe { core::mem::zeroed() };
    let sig_idx = (libc::SIGABRT - 1) as usize;
    let bits_per_word = core::mem::size_of::<libc::c_ulong>() * 8;
    let sig_word = sig_idx / bits_per_word;
    let sig_bit = sig_idx % bits_per_word;
    let word_count = core::mem::size_of::<libc::sigset_t>() / core::mem::size_of::<libc::c_ulong>();
    if sig_word < word_count {
        unsafe {
            let words = (&mut unblock_set as *mut libc::sigset_t).cast::<libc::c_ulong>();
            *words.add(sig_word) = 1 << sig_bit;
        }
    }
    let _ = unsafe {
        raw_syscall::sys_rt_sigprocmask(
            libc::SIG_UNBLOCK,
            &unblock_set as *const libc::sigset_t as *const u8,
            ptr::null_mut(),
            core::mem::size_of::<libc::c_ulong>(),
        )
    };

    unsafe {
        // Use raw syscalls to bypass runtime_policy locks which may be held
        // if another thread called fork() while doing policy checks.
        let pid = frankenlibc_core::syscall::sys_getpid();
        let tid = frankenlibc_core::syscall::sys_gettid();
        let _ = raw_syscall::sys_tgkill(pid, tid, libc::SIGABRT);

        // Handler returned (or SIG_IGN was installed). Reset to SIG_DFL so the
        // next raise produces the default core-dump action, then unblock again
        // (a handler may have re-blocked the signal) and re-raise.
        let mut act = core::mem::zeroed::<libc::sigaction>();
        act.sa_sigaction = libc::SIG_DFL as libc::sighandler_t;
        let _ = raw_syscall::sys_rt_sigaction(
            libc::SIGABRT,
            &act as *const _ as *const u8,
            ptr::null_mut(),
            core::mem::size_of::<libc::c_ulong>(),
        );

        let _ = raw_syscall::sys_rt_sigprocmask(
            libc::SIG_UNBLOCK,
            &unblock_set as *const libc::sigset_t as *const u8,
            ptr::null_mut(),
            core::mem::size_of::<libc::c_ulong>(),
        );

        let _ = raw_syscall::sys_tgkill(pid, tid, libc::SIGABRT);
    }
    // Should never reach here, but the compiler needs a diverging path.
    frankenlibc_core::syscall::sys_exit_group(134)
}

/// Exit handler entry for `on_exit` — stores function pointer + arg.
struct OnExitEntry {
    func: unsafe extern "C" fn(c_int, *mut c_void),
    arg: *mut c_void,
}

// SAFETY: on_exit entries are only accessed from the exit handler chain,
// which runs in a single-threaded context (process exit).
unsafe impl Send for OnExitEntry {}
unsafe impl Sync for OnExitEntry {}

enum ExitHandler {
    Atexit(extern "C" fn()),
    OnExit(OnExitEntry),
}

static EXIT_HANDLERS: std::sync::Mutex<Vec<ExitHandler>> = std::sync::Mutex::new(Vec::new());

fn register_exit_handler(handler: ExitHandler) -> c_int {
    let mut handlers = EXIT_HANDLERS.lock().unwrap_or_else(|e| e.into_inner());
    handlers.push(handler);
    0
}

fn run_exit_handlers(status: c_int) {
    loop {
        let batch: Vec<ExitHandler> = {
            let mut guard = EXIT_HANDLERS.lock().unwrap_or_else(|e| e.into_inner());
            if guard.is_empty() {
                break;
            }
            std::mem::take(&mut *guard)
        };
        for handler in batch.into_iter().rev() {
            match handler {
                ExitHandler::Atexit(func) => func(),
                ExitHandler::OnExit(entry) => unsafe { (entry.func)(status, entry.arg) },
            }
        }
    }
}

/// `on_exit` — register a function to be called at exit (with status and arg).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn on_exit(
    func: Option<unsafe extern "C" fn(c_int, *mut c_void)>,
    arg: *mut c_void,
) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdlib, 0, 0, true, func.is_none(), 0);
    let Some(f) = func else {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, true);
        return -1;
    };
    register_exit_handler(ExitHandler::OnExit(OnExitEntry { func: f, arg }));
    runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, false);
    0
}

/// Exit handler entries for `at_quick_exit`.
static QUICK_EXIT_HANDLERS: std::sync::Mutex<Vec<unsafe extern "C" fn()>> =
    std::sync::Mutex::new(Vec::new());

/// `at_quick_exit` — register a function to be called at quick_exit.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn at_quick_exit(func: Option<unsafe extern "C" fn()>) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::Stdlib, 0, 0, true, func.is_none(), 0);
    let Some(f) = func else {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, true);
        return -1;
    };
    let mut handlers = QUICK_EXIT_HANDLERS
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    handlers.push(f);
    runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, false);
    0
}

/// `quick_exit` — rapid process termination, calling at_quick_exit handlers.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn quick_exit(status: c_int) -> ! {
    // Call registered quick_exit handlers in reverse order.
    // Swap-extract under the lock, release, then iterate. Invoking user
    // callbacks while holding QUICK_EXIT_HANDLERS would self-deadlock if a
    // handler transitively called at_quick_exit (bd-3jpoz).
    loop {
        let batch: Vec<unsafe extern "C" fn()> = {
            let mut guard = QUICK_EXIT_HANDLERS
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if guard.is_empty() {
                break;
            }
            std::mem::take(&mut *guard)
        };
        for func in batch.into_iter().rev() {
            unsafe { func() };
        }
    }
    frankenlibc_core::syscall::sys_exit_group(status)
}

// ===========================================================================
// getsubopt (1 function)
// ===========================================================================

/// `getsubopt` — parse suboption from comma-separated string.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getsubopt(
    optionp: *mut *mut c_char,
    tokens: *const *mut c_char,
    valuep: *mut *mut c_char,
) -> c_int {
    let (_, decision) = runtime_policy::decide(
        ApiFamily::Stdlib,
        optionp as usize,
        0,
        true,
        optionp.is_null() || tokens.is_null() || valuep.is_null(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny)
        || optionp.is_null()
        || tokens.is_null()
        || valuep.is_null()
    {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 8, true);
        return -1;
    }

    let opt_ptr = unsafe { *optionp };
    if opt_ptr.is_null() {
        unsafe { *valuep = ptr::null_mut() };
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, false);
        return -1;
    }

    // Find end of this suboption (comma or NUL).
    let Some((end, at_comma)) = (unsafe { scan_suboption_end(opt_ptr) }) else {
        unsafe {
            *valuep = ptr::null_mut();
            set_abi_errno(libc::EINVAL);
        }
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 8, true);
        return -1;
    };
    if end == opt_ptr && !at_comma {
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 4, false);
        return -1;
    }

    // Find '=' for value separation.
    let segment_len = unsafe { end.offset_from(opt_ptr) as usize };
    let segment = unsafe { core::slice::from_raw_parts(opt_ptr.cast::<u8>(), segment_len) };
    let eq_pos = segment.iter().position(|&byte| byte == b'=');
    let name_len = eq_pos.unwrap_or(segment_len);
    let value_ptr = if let Some(pos) = eq_pos {
        unsafe { opt_ptr.add(pos + 1) }
    } else {
        ptr::null_mut()
    };

    if at_comma {
        unsafe { *end = 0 };
    }

    // Advance optionp past this suboption.
    unsafe {
        if at_comma {
            *optionp = end.add(1);
        } else {
            *optionp = end;
        }
    }

    // Match against token list.
    let mut idx = 0i32;
    let token_slots =
        known_remaining(tokens as usize).map(|bytes| bytes / core::mem::size_of::<*mut c_char>());
    let mut token_offset = 0usize;
    loop {
        if token_slots.is_some_and(|slots| token_offset >= slots) {
            unsafe {
                *valuep = ptr::null_mut();
                set_abi_errno(libc::EINVAL);
            }
            runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 8, true);
            return -1;
        }
        let candidate = unsafe { *tokens.add(token_offset) };
        if candidate.is_null() {
            break;
        }
        if unsafe { candidate_matches_name(candidate.cast_const(), opt_ptr.cast_const(), name_len) }
        {
            unsafe { *valuep = value_ptr };
            runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 8, false);
            return idx;
        }
        if idx == i32::MAX {
            unsafe {
                *valuep = ptr::null_mut();
                set_abi_errno(libc::EINVAL);
            }
            runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 8, true);
            return -1;
        }
        token_offset += 1;
        idx += 1;
    }

    unsafe { *valuep = opt_ptr };
    runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 8, false);
    -1
}

// ---------------------------------------------------------------------------
// gnu_get_libc_version / gnu_get_libc_release
// ---------------------------------------------------------------------------

/// FrankenLibC version string reported via `gnu_get_libc_version()`.
///
/// We report glibc 2.38 compatibility to satisfy programs that check the
/// version string for minimum feature requirements.
static GNU_LIBC_VERSION: &[u8] = b"2.38\0";

/// GNU `gnu_get_libc_version` — return glibc-compatible version string.
///
/// Returns a static string like "2.38". Programs use this to detect glibc
/// features at runtime.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn gnu_get_libc_version() -> *const c_char {
    GNU_LIBC_VERSION.as_ptr() as *const c_char
}

/// POSIX `confstr` — get configuration-dependent string variable.
///
/// Returns the length of the string value for the given `name`, or 0 on error.
/// If `buf` is non-null and `len` > 0, copies the value into `buf`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn confstr(name: c_int, buf: *mut c_char, len: usize) -> usize {
    // _CS_GNU_LIBC_VERSION = 2 on Linux/glibc
    // _CS_GNU_LIBPTHREAD_VERSION = 3
    // _CS_PATH = 0
    // Values mirror host glibc on x86_64 (LP64). The POSIX programming-environment
    // and LFS flag strings are platform constants (verified byte-exact via a
    // confstr(0..1300) brute-probe of host glibc): the only non-empty entries are
    // the width-restricted-env names, the `-m64` CFLAGS/LDFLAGS for the LP64_OFF64
    // environments, the LFS64 `-D_LARGEFILE64_SOURCE`, and POSIXLY_CORRECT=1.
    // Keys 2/3 intentionally report "2.38" (frankenlibc's declared glibc-compat
    // level), not the host's running version.
    let value: &[u8] = match name {
        0 => b"/bin:/usr/bin\0",       // _CS_PATH
        1 => b"POSIX_V6_LP64_OFF64\0", // _CS_V6_WIDTH_RESTRICTED_ENVS
        2 => b"glibc 2.38\0",          // _CS_GNU_LIBC_VERSION
        3 => b"NPTL 2.38\0",           // _CS_GNU_LIBPTHREAD_VERSION
        4 => b"XBS5_LP64_OFF64\0",     // _CS_V5_WIDTH_RESTRICTED_ENVS
        5 => b"POSIX_V7_LP64_OFF64\0", // _CS_V7_WIDTH_RESTRICTED_ENVS
        // LFS / LFS64 compiler flags (_CS_LFS_* = 1000..=1003, _CS_LFS64_* = 1004..=1007).
        1004 | 1007 => b"-D_LARGEFILE64_SOURCE\0", // LFS64 CFLAGS / LINTFLAGS
        1000..=1007 => b"\0",
        // POSIX_V6 / V7 programming-environment flags (_CS_POSIX_V6_* / _CS_POSIX_V7_* = 1100..=1147)
        // and the V6/V7 ENV strings (1148/1149). On LP64 x86_64 only the LP64_OFF64
        // CFLAGS/LDFLAGS carry `-m64`; every other environment flag is empty.
        1148 | 1149 => b"POSIXLY_CORRECT=1\0", // _CS_V6_ENV / _CS_V7_ENV
        1108 | 1109 | 1124 | 1125 | 1140 | 1141 => b"-m64\0", // LP64_OFF64 CFLAGS/LDFLAGS
        1100..=1147 => b"\0",
        _ => {
            unsafe { crate::errno_abi::set_abi_errno_local(libc::EINVAL) };
            return 0;
        }
    };

    let value_len = value.len(); // includes NUL
    if !buf.is_null() && len > 0 {
        let effective_len = tracked_char_output_capacity(buf, len);
        if effective_len == 0 {
            return value_len;
        }
        let copy_len = std::cmp::min(effective_len, value_len);
        unsafe {
            std::ptr::copy_nonoverlapping(value.as_ptr(), buf as *mut u8, copy_len);
        }
        // Ensure NUL termination if we truncated.
        if copy_len < value_len {
            unsafe { *buf.add(effective_len - 1) = 0 };
        }
    }
    value_len
}

// ===========================================================================
// Batch: GNU hash table (hsearch) — Implemented
// ===========================================================================

use std::sync::atomic::Ordering as AtomicOrdering;

fn get_program_short_name() -> *const c_char {
    crate::startup_abi::program_invocation_short_name.load(AtomicOrdering::Acquire)
}

/// POSIX hash action for `hsearch`.
#[repr(C)]
#[allow(non_camel_case_types, dead_code)]
pub enum HashAction {
    FIND = 0,
    ENTER = 1,
}

/// POSIX hash table entry.
#[repr(C)]
#[allow(non_camel_case_types)]
pub struct HashEntry {
    pub key: *mut c_char,
    pub data: *mut c_void,
}

// Hash table functions (hcreate, hdestroy, hsearch, etc.) are defined
// in search_abi.rs (canonical module for POSIX search functions).

// ===========================================================================
// Batch: getloadavg — Implemented
// ===========================================================================

/// `getloadavg` — get system load averages from /proc/loadavg.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getloadavg(loadavg: *mut c_double, nelem: c_int) -> c_int {
    let content = match std::fs::read_to_string("/proc/loadavg") {
        Ok(s) => s,
        Err(_) => return -1,
    };
    // glibc opens /proc/loadavg first, then loops `for i in 0..min(nelem,3)` — so
    // nelem <= 0 fills nothing and returns 0 (NOT -1), and the buffer is only
    // dereferenced when nelem > 0.
    if nelem <= 0 {
        return 0;
    }
    if loadavg.is_null() {
        return -1;
    }
    let n = std::cmp::min(nelem, 3) as usize;
    let parts: Vec<&str> = content.split_whitespace().collect();
    if parts.len() < 3 {
        return -1;
    }
    let mut filled = 0usize;
    for (i, part) in parts.iter().enumerate().take(n) {
        match part.parse::<f64>() {
            Ok(val) => {
                unsafe { *loadavg.add(i) = val };
                filled += 1;
            }
            Err(_) => break,
        }
    }
    filled as c_int
}

// ===========================================================================
// Batch: error / error_at_line — Implemented
// ===========================================================================

/// Global error message count (GNU extension).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
#[allow(non_upper_case_globals)]
pub static mut error_message_count: c_uint = 0;

/// `error` — GNU error reporting function.
///
/// Prints "progname: format_message" to stderr. If errnum != 0,
/// appends ": strerror(errnum)". If status != 0, calls exit(status).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn error(status: c_int, errnum: c_int, fmt: *const c_char, mut args: ...) {
    use std::fmt::Write as _;

    unsafe { error_message_count += 1 };

    // glibc's error() calls flush_stdout() (an unconditional fflush(stdout) in
    // the _LIBC build) before writing to stderr, so buffered program output is
    // ordered ahead of the diagnostic. bd-7zdmvd.
    unsafe {
        crate::stdio_abi::fflush(crate::io_internal_abi::native_stdio_stream_ptr(
            libc::STDOUT_FILENO,
        ));
    }

    let progname = {
        let p = get_program_short_name();
        if p.is_null() {
            "unknown"
        } else {
            let (len, terminated) = unsafe { scan_c_string(p, known_remaining(p as usize)) };
            if !terminated {
                "unknown"
            } else {
                let bytes = unsafe { std::slice::from_raw_parts(p as *const u8, len) };
                std::str::from_utf8(bytes).unwrap_or("unknown")
            }
        }
    };

    // glibc: when error_print_progname is set it REPLACES the "progname: "
    // prefix (the hook writes its own text to stderr); otherwise print the
    // default prefix. bd-xqg5il.
    let progname_hook = unsafe { crate::glibc_internal_abi::error_print_progname };
    let mut out = String::new();
    if progname_hook.is_null() {
        let _ = write!(out, "{progname}: ");
    }

    // Format the message
    if !fmt.is_null() {
        let (fmt_len, terminated) = unsafe { scan_c_string(fmt, known_remaining(fmt as usize)) };
        if terminated {
            let fmt_bytes = unsafe { std::slice::from_raw_parts(fmt as *const u8, fmt_len) };
            if let Ok(f) = std::str::from_utf8(fmt_bytes) {
                // Simple format: just print as-is for common case.
                // For full printf compatibility, delegate to our printf engine.
                let msg = unsafe {
                    crate::stdio_abi::vprintf_extract_and_render(
                        f,
                        (&mut args) as *mut _ as *mut c_void,
                    )
                };
                let _ = write!(out, "{msg}");
            }
        }
    }

    if errnum != 0 {
        let err_ptr = unsafe { crate::string_abi::strerror(errnum) };
        let err_msg = if err_ptr.is_null() {
            "Unknown error"
        } else {
            let (len, terminated) =
                unsafe { scan_c_string(err_ptr, known_remaining(err_ptr as usize)) };
            if !terminated {
                "Unknown error"
            } else {
                let bytes = unsafe { std::slice::from_raw_parts(err_ptr as *const u8, len) };
                std::str::from_utf8(bytes).unwrap_or("Unknown error")
            }
        };
        let _ = write!(out, ": {err_msg}");
    }

    let _ = writeln!(out);
    // Invoke the progname hook (if any) before the message body so its output
    // precedes the rest on stderr, matching glibc's call ordering.
    if !progname_hook.is_null() {
        let hook: extern "C" fn() = unsafe { std::mem::transmute(progname_hook) };
        hook();
    }
    let _ = crate::stdio_abi::write_all_fd(libc::STDERR_FILENO, out.as_bytes());

    if status != 0 {
        // GNU error(status, ...) terminates via libc exit(status), preserving
        // this ABI layer's atexit/on_exit and stdio-flush behavior.
        unsafe { exit(status) };
    }
}

/// Tracks the (file, line) of the previous `error_at_line` call so that, when
/// `error_one_per_line` is set, a repeated message for the same location is
/// suppressed — mirroring glibc's `old_file_name`/`old_line_number` statics.
/// Initialised to (NULL file, line 0) exactly like glibc's zero-init statics.
static ERR_AT_LINE_STATE: std::sync::Mutex<(Option<Vec<u8>>, c_uint)> =
    std::sync::Mutex::new((None, 0));

/// `error_at_line` — GNU error reporting with file/line info.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn error_at_line(
    status: c_int,
    errnum: c_int,
    filename: *const c_char,
    linenum: c_uint,
    fmt: *const c_char,
    mut args: ...
) {
    use std::fmt::Write as _;

    // GNU error_at_line: when error_one_per_line is non-zero, suppress a
    // message whose file+line match the immediately preceding call — print
    // nothing AND do not bump error_message_count. glibc compares the file by
    // pointer-or-strcmp; we compare NULL-ness + content (same effect for the
    // documented behaviour). bd-enxo3y.
    if unsafe { crate::glibc_internal_abi::error_one_per_line } != 0 {
        let new_file: Option<Vec<u8>> = if filename.is_null() {
            None
        } else {
            unsafe { read_bounded_cstr_bytes(filename) }
        };
        let mut state = ERR_AT_LINE_STATE.lock().unwrap_or_else(|e| e.into_inner());
        let same_location = state.1 == linenum
            && match (&state.0, &new_file) {
                (None, None) => true,
                (Some(old), Some(new)) => old == new,
                _ => false,
            };
        if same_location {
            return;
        }
        state.0 = new_file;
        state.1 = linenum;
    }

    unsafe { error_message_count += 1 };

    // Match glibc: flush stdout before writing the diagnostic to stderr
    // (only reached when the message is not suppressed). bd-7zdmvd.
    unsafe {
        crate::stdio_abi::fflush(crate::io_internal_abi::native_stdio_stream_ptr(
            libc::STDOUT_FILENO,
        ));
    }

    let progname = {
        let p = get_program_short_name();
        if !p.is_null() {
            unsafe { read_bounded_cstr_bytes(p) }
                .and_then(|bytes| String::from_utf8(bytes).ok())
                .unwrap_or_else(|| "unknown".to_string())
        } else {
            "unknown".to_string()
        }
    };

    // glibc replaces the "progname:" prefix with the error_print_progname hook
    // when set; the file:line part is still printed afterwards. bd-xqg5il.
    let progname_hook = unsafe { crate::glibc_internal_abi::error_print_progname };
    let mut out = String::new();
    if progname_hook.is_null() {
        let _ = write!(out, "{progname}:");
    }

    if !filename.is_null()
        && let Some(filename_bytes) = unsafe { read_bounded_cstr_bytes(filename) }
        && let Ok(f) = std::str::from_utf8(&filename_bytes)
    {
        let _ = write!(out, "{f}:{linenum}: ");
    }

    if !fmt.is_null()
        && let Some(fmt_bytes) = unsafe { read_bounded_cstr_bytes(fmt) }
        && let Ok(f) = std::str::from_utf8(&fmt_bytes)
    {
        let msg = unsafe {
            crate::stdio_abi::vprintf_extract_and_render(f, (&mut args) as *mut _ as *mut c_void)
        };
        let _ = write!(out, "{msg}");
    }

    if errnum != 0 {
        let p = unsafe { crate::string_abi::strerror(errnum) };
        let err_msg = if !p.is_null() {
            unsafe { read_bounded_cstr_bytes(p) }
                .and_then(|bytes| String::from_utf8(bytes).ok())
                .unwrap_or_else(|| "Unknown error".to_string())
        } else {
            "Unknown error".to_string()
        };
        let _ = write!(out, ": {err_msg}");
    }

    let _ = writeln!(out);
    if !progname_hook.is_null() {
        let hook: extern "C" fn() = unsafe { std::mem::transmute(progname_hook) };
        hook();
    }
    let _ = crate::stdio_abi::write_all_fd(libc::STDERR_FILENO, out.as_bytes());

    if status != 0 {
        // GNU error_at_line(status, ...) has the same termination contract as
        // error(status, ...): go through libc exit rather than Rust process exit.
        unsafe { exit(status) };
    }
}

// ===========================================================================
// Batch: BSD err/warn family — Implemented
// ===========================================================================
// ===========================================================================
// Batch: GNU sysconf extensions — Implemented
// ===========================================================================

/// `get_nprocs` — return number of online processors.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn get_nprocs() -> c_int {
    // Read /sys/devices/system/cpu/online, parse range "0-N" → N+1
    if let Ok(content) = std::fs::read_to_string("/sys/devices/system/cpu/online") {
        let content = content.trim();
        // Format: "0-7" or "0" or "0-3,5-7"
        let mut count = 0i32;
        for range in content.split(',') {
            let parts: Vec<&str> = range.split('-').collect();
            if parts.len() == 2
                && let (Ok(lo), Ok(hi)) = (parts[0].parse::<i32>(), parts[1].parse::<i32>())
            {
                count += hi - lo + 1;
            } else if parts.len() == 1 && parts[0].parse::<i32>().is_ok() {
                count += 1;
            }
        }
        if count > 0 {
            return count;
        }
    }
    1 // fallback
}

/// `get_nprocs_conf` — return number of configured processors.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn get_nprocs_conf() -> c_int {
    if let Ok(content) = std::fs::read_to_string("/sys/devices/system/cpu/present") {
        let content = content.trim();
        let mut count = 0i32;
        for range in content.split(',') {
            let parts: Vec<&str> = range.split('-').collect();
            if parts.len() == 2
                && let (Ok(lo), Ok(hi)) = (parts[0].parse::<i32>(), parts[1].parse::<i32>())
            {
                count += hi - lo + 1;
            } else if parts.len() == 1 && parts[0].parse::<i32>().is_ok() {
                count += 1;
            }
        }
        if count > 0 {
            return count;
        }
    }
    1
}

/// `get_phys_pages` — return number of physical memory pages.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn get_phys_pages() -> c_long {
    if let Ok(content) = std::fs::read_to_string("/proc/meminfo") {
        for line in content.lines() {
            if line.starts_with("MemTotal:") {
                // MemTotal:       16384000 kB
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2
                    && let Ok(kb) = parts[1].parse::<c_long>()
                {
                    let page_size = unsafe { crate::unistd_abi::sysconf(libc::_SC_PAGESIZE) };
                    let page_size = if page_size > 0 { page_size } else { 4096 };
                    return (kb * 1024) / page_size;
                }
            }
        }
    }
    0
}

/// `get_avphys_pages` — return number of available physical memory pages.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn get_avphys_pages() -> c_long {
    // glibc's __get_avphys_pages returns sysinfo(2).freeram — the raw free RAM,
    // i.e. /proc/meminfo "MemFree" — NOT "MemAvailable" (a larger kernel
    // estimate that counts reclaimable cache). Using MemAvailable overcounted
    // available pages by a wide margin. bd-l18p7s.
    if let Ok(content) = std::fs::read_to_string("/proc/meminfo") {
        for line in content.lines() {
            if line.starts_with("MemFree:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2
                    && let Ok(kb) = parts[1].parse::<c_long>()
                {
                    let page_size = unsafe { crate::unistd_abi::sysconf(libc::_SC_PAGESIZE) };
                    let page_size = if page_size > 0 { page_size } else { 4096 };
                    return (kb * 1024) / page_size;
                }
            }
        }
    }
    0
}

// POSIX/GNU binary tree search exports live in search_abi.rs. Keep this
// non-exported delegate for internal callers that still route through
// stdlib_abi while avoiding a duplicate release symbol.
pub unsafe extern "C" fn tdestroy(root: *mut c_void, freefn: unsafe extern "C" fn(*mut c_void)) {
    // SAFETY: `search_abi::tdestroy` owns the current opaque tree layout and
    // performs the same GNU post-order callback contract.
    unsafe { crate::search_abi::tdestroy(root, Some(freefn)) };
}

// ===========================================================================
// Batch: lfind / lsearch — Implemented
// ===========================================================================
// ===========================================================================
// Batch: getauxval — Implemented
// ===========================================================================

/// `getauxval` — retrieve a value from the auxiliary vector.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getauxval(type_: c_ulong) -> c_ulong {
    // Read from /proc/self/auxv using raw syscalls to avoid recursion
    // (libc::getauxval goes through our interposed getauxval).
    let fd = unsafe {
        raw_syscall::sys_openat(
            libc::AT_FDCWD,
            c"/proc/self/auxv".as_ptr() as *const u8,
            libc::O_RDONLY,
            0,
        )
    };
    let fd = match fd {
        Ok(f) => f as c_int,
        Err(_) => {
            unsafe { set_abi_errno(libc::ENOENT) };
            return 0;
        }
    };
    // auxv is pairs of (type: ulong, value: ulong)
    let entry_size = 2 * std::mem::size_of::<c_ulong>();
    let mut buf = [0u8; 4096];
    let n = match unsafe { raw_syscall::sys_read(fd, buf.as_mut_ptr(), buf.len()) } {
        Ok(bytes) => bytes as isize,
        Err(_) => -1,
    };
    let _ = raw_syscall::sys_close(fd);
    if n <= 0 {
        unsafe { set_abi_errno(libc::ENOENT) };
        return 0;
    }
    let entries = n as usize / entry_size;
    for i in 0..entries {
        let offset = i * entry_size;
        let at = c_ulong::from_ne_bytes(buf[offset..offset + 8].try_into().unwrap_or([0; 8]));
        let av = c_ulong::from_ne_bytes(buf[offset + 8..offset + 16].try_into().unwrap_or([0; 8]));
        if at == 0 {
            break; // AT_NULL terminates
        }
        if at == type_ {
            return av;
        }
    }
    unsafe { set_abi_errno(libc::ENOENT) };
    0
}

// ===========================================================================
// Batch: getusershell family — Implemented
// ===========================================================================

static VALID_SHELLS: &[&str] = &[
    "/bin/sh",
    "/bin/bash",
    "/bin/zsh",
    "/bin/csh",
    "/bin/tcsh",
    "/bin/dash",
    "/bin/fish",
    "/usr/bin/bash",
    "/usr/bin/zsh",
    "/usr/bin/fish",
    "/usr/bin/tmux",
    "/bin/false",
    "/usr/sbin/nologin",
];

#[cfg(not(feature = "owned-tls-cache"))]
thread_local! {
    static SHELL_IDX: Cell<usize> = const { Cell::new(0) };
    static SHELL_CACHE: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

fn with_shell_state<R>(f: impl FnOnce(&Cell<usize>, &RefCell<Vec<String>>) -> R) -> R {
    #[cfg(feature = "owned-tls-cache")]
    {
        STDLIB_OWNED_TLS.with(|tls| f(&tls.shell_idx, &tls.shell_cache))
    }
    #[cfg(not(feature = "owned-tls-cache"))]
    {
        SHELL_CACHE.with(|cache| SHELL_IDX.with(|idx| f(idx, cache)))
    }
}

/// `getusershell` — get valid login shell from /etc/shells.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn getusershell() -> *mut c_char {
    with_shell_state(|idx, cache| {
        let mut cache = cache.borrow_mut();
        if cache.is_empty() {
            // Load from /etc/shells
            if let Ok(content) = std::fs::read_to_string("/etc/shells") {
                for line in content.lines() {
                    let line = line.trim();
                    if !line.is_empty() && !line.starts_with('#') {
                        cache.push(format!("{line}\0"));
                    }
                }
            }
            if cache.is_empty() {
                // Fallback
                for s in VALID_SHELLS {
                    cache.push(format!("{s}\0"));
                }
            }
        }

        let i = idx.get();
        if i < cache.len() {
            idx.set(i + 1);
            cache[i].as_ptr() as *mut c_char
        } else {
            ptr::null_mut()
        }
    })
}

/// `setusershell` — rewind the shell list iterator.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn setusershell() {
    with_shell_state(|idx, _cache| idx.set(0));
}

/// `endusershell` — close the shell list and free resources.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn endusershell() {
    with_shell_state(|idx, cache| {
        idx.set(0);
        cache.borrow_mut().clear();
    });
}

// ===========================================================================
// Batch: gets / tmpnam_r — Implemented
// ===========================================================================

/// `gets` — read a line from stdin (DEPRECATED, insecure).
///
/// POSIX removed this in 2008; kept for legacy compatibility.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn gets(s: *mut c_char) -> *mut c_char {
    if s.is_null() {
        return ptr::null_mut();
    }
    let mut i = 0usize;
    loop {
        let mut ch: u8 = 0;
        let n = unsafe { crate::unistd_abi::read(0, &mut ch as *mut u8 as *mut c_void, 1) };
        if n <= 0 {
            if i == 0 {
                return ptr::null_mut();
            }
            break;
        }
        if ch == b'\n' {
            break;
        }
        unsafe { *s.add(i) = ch as c_char };
        i += 1;
    }
    unsafe { *s.add(i) = 0 };
    s
}

/// `tmpnam_r` — generate unique temporary filename (reentrant).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tmpnam_r(s: *mut c_char) -> *mut c_char {
    if s.is_null() {
        return ptr::null_mut();
    }
    // Generate /tmp/tmpXXXXXX pattern and check uniqueness
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let pid = raw_syscall::sys_getpid() as libc::pid_t;
    let cnt = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let name = format!("/tmp/tmp{pid:06}{cnt:06}\0");
    let name_bytes = name.as_bytes();
    if name_bytes.len() > 20 {
        // Truncate to L_tmpnam
        unsafe {
            std::ptr::copy_nonoverlapping(name_bytes.as_ptr(), s as *mut u8, 20);
            *s.add(19) = 0;
        }
    } else {
        unsafe {
            std::ptr::copy_nonoverlapping(name_bytes.as_ptr(), s as *mut u8, name_bytes.len());
        }
    }
    s
}

// ===========================================================================
// Batch: cfmakeraw / cfsetspeed — Implemented
// ===========================================================================

/// `cfmakeraw` — set terminal attributes for raw mode.
/// Sets flags per glibc cfmakeraw: disable input/output processing,
/// disable signals, 8-bit chars, VMIN=1, VTIME=0.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cfmakeraw(termios: *mut libc::termios) {
    if termios.is_null() {
        return;
    }
    let t = unsafe { &mut *termios };
    // Clear input flags: no break handling, parity, strip, newline translation, XON/XOFF
    t.c_iflag &= !(libc::IGNBRK
        | libc::BRKINT
        | libc::PARMRK
        | libc::ISTRIP
        | libc::INLCR
        | libc::IGNCR
        | libc::ICRNL
        | libc::IXON) as libc::tcflag_t;
    // Clear output flag: no output processing
    t.c_oflag &= !(libc::OPOST) as libc::tcflag_t;
    // Clear local flags: no echo, no canonical mode, no signals, no extended processing
    t.c_lflag &=
        !(libc::ECHO | libc::ECHONL | libc::ICANON | libc::ISIG | libc::IEXTEN) as libc::tcflag_t;
    // Set char size to 8 bits, no parity
    t.c_cflag &= !(libc::CSIZE | libc::PARENB) as libc::tcflag_t;
    t.c_cflag |= libc::CS8 as libc::tcflag_t;
    // Set VMIN=1 (minimum chars), VTIME=0 (no timeout)
    t.c_cc[libc::VMIN] = 1;
    t.c_cc[libc::VTIME] = 0;
}

/// `cfsetspeed` — set both input and output baud rate.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cfsetspeed(termios: *mut libc::termios, speed: libc::speed_t) -> c_int {
    if termios.is_null() {
        return -1;
    }
    let r1 = unsafe { crate::termios_abi::cfsetispeed(termios, speed) };
    let r2 = unsafe { crate::termios_abi::cfsetospeed(termios, speed) };
    if r1 < 0 || r2 < 0 { -1 } else { 0 }
}

// ===========================================================================
// Locale-aware _l variants — C/POSIX locale passthrough
// ===========================================================================

/// `strtod_l` — locale-aware string to double. C locale: delegates to strtod.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strtod_l(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    _locale: *mut c_void,
) -> f64 {
    unsafe { strtod(nptr, endptr) }
}

/// `strtof_l` — locale-aware string to float.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strtof_l(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    _locale: *mut c_void,
) -> f32 {
    unsafe { strtof(nptr, endptr) }
}

/// `strtold_l` — locale-aware string to long double.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strtold_l(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    _locale: *mut c_void,
) -> f64 {
    unsafe { strtold(nptr, endptr) }
}

/// `strtol_l` — locale-aware string to long.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strtol_l(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
    _locale: *mut c_void,
) -> c_long {
    unsafe { strtol(nptr, endptr, base) }
}

/// `strtoul_l` — locale-aware string to unsigned long.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strtoul_l(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
    _locale: *mut c_void,
) -> c_ulong {
    unsafe { strtoul(nptr, endptr, base) }
}

/// `strtoll_l` — locale-aware string to long long.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strtoll_l(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
    _locale: *mut c_void,
) -> c_longlong {
    unsafe { strtoll(nptr, endptr, base) }
}

/// `strtoull_l` — locale-aware string to unsigned long long.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strtoull_l(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
    _locale: *mut c_void,
) -> c_ulonglong {
    unsafe { strtoull(nptr, endptr, base) }
}

// ===========================================================================
// C23 __isoc23_* aliases — GCC 14+ with -std=c23 emits these for scanf/strtol
// ===========================================================================
// ===========================================================================
// __assert* — assertion failure handlers (assert.h)
// ===========================================================================

/// `__assert_fail` — called by assert() macro on failure.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __assert_fail(
    assertion: *const c_char,
    file: *const c_char,
    line: c_uint,
    function: *const c_char,
) -> ! {
    let a = if assertion.is_null() {
        "??".to_string()
    } else {
        let (len, terminated) =
            unsafe { scan_c_string(assertion, known_remaining(assertion as usize)) };
        if !terminated {
            "??".to_string()
        } else {
            let bytes = unsafe { std::slice::from_raw_parts(assertion as *const u8, len) };
            String::from_utf8_lossy(bytes).into_owned()
        }
    };
    let f = if file.is_null() {
        "??".to_string()
    } else {
        let (len, terminated) = unsafe { scan_c_string(file, known_remaining(file as usize)) };
        if !terminated {
            "??".to_string()
        } else {
            let bytes = unsafe { std::slice::from_raw_parts(file as *const u8, len) };
            String::from_utf8_lossy(bytes).into_owned()
        }
    };
    let func = if function.is_null() {
        "??".to_string()
    } else {
        let (len, terminated) =
            unsafe { scan_c_string(function, known_remaining(function as usize)) };
        if !terminated {
            "??".to_string()
        } else {
            let bytes = unsafe { std::slice::from_raw_parts(function as *const u8, len) };
            String::from_utf8_lossy(bytes).into_owned()
        }
    };
    let msg = format!("{}: {}: {}: Assertion `{}' failed.\n", f, line, func, a);
    unsafe {
        crate::unistd_abi::sys_write_fd(libc::STDERR_FILENO, msg.as_ptr().cast(), msg.len());
    }
    std::process::abort();
}

/// `__assert_perror_fail` — called by assert_perror() macro on failure.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __assert_perror_fail(
    errnum: c_int,
    file: *const c_char,
    line: c_uint,
    function: *const c_char,
) -> ! {
    // Mirror __assert_fail's hardening: bound every string pointer through
    // scan_c_string + known_remaining so a caller that passes a non-NUL-
    // terminated pointer cannot walk arbitrary process memory here. Without
    // this guard, CStr::from_ptr walks unbounded — an info-leak / segfault
    // vector reachable from the libc.so boundary. (bd-9bijw)
    fn read_bounded(ptr: *const c_char) -> String {
        if ptr.is_null() {
            return "??".to_string();
        }
        let (len, terminated) = unsafe { scan_c_string(ptr, known_remaining(ptr as usize)) };
        if !terminated {
            return "??".to_string();
        }
        let bytes = unsafe { core::slice::from_raw_parts(ptr as *const u8, len) };
        String::from_utf8_lossy(bytes).into_owned()
    }
    let f = read_bounded(file);
    let func = read_bounded(function);
    let msg = std::io::Error::from_raw_os_error(errnum);
    let msg_str = format!("{f}: {line}: {func}: Unexpected error: {msg}.\n");
    unsafe {
        crate::unistd_abi::sys_write_fd(
            libc::STDERR_FILENO,
            msg_str.as_ptr().cast(),
            msg_str.len(),
        );
    }
    std::process::abort();
}

/// `__assert` — legacy assertion failure handler.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __assert(assertion: *const c_char, file: *const c_char, line: c_int) -> ! {
    unsafe { __assert_fail(assertion, file, line as c_uint, core::ptr::null()) }
}

/// `__cxa_at_quick_exit` — C++ runtime alias for at_quick_exit.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __cxa_at_quick_exit(func: Option<unsafe extern "C" fn()>) -> c_int {
    unsafe { at_quick_exit(func) }
}

// insque / remque — defined in search_abi.rs (canonical module)

// ===========================================================================
// __xpg_strerror_r — POSIX strerror_r variant
// ===========================================================================

/// `__xpg_strerror_r` — XSI-compliant strerror_r (returns int, not char*).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __xpg_strerror_r(errnum: c_int, buf: *mut c_char, buflen: usize) -> c_int {
    if buf.is_null() || buflen == 0 {
        return libc::ERANGE;
    }
    let (msg, unknown_errno) = crate::string_abi::rendered_strerror_message(errnum);
    let msg_bytes = msg.as_bytes();
    if msg_bytes.len() >= buflen {
        // Truncate and null-terminate
        unsafe {
            ptr::copy_nonoverlapping(msg_bytes.as_ptr(), buf as *mut u8, buflen - 1);
            *buf.add(buflen - 1) = 0;
        }
        return if unknown_errno {
            libc::EINVAL
        } else {
            libc::ERANGE
        };
    }
    unsafe {
        ptr::copy_nonoverlapping(msg_bytes.as_ptr(), buf as *mut u8, msg_bytes.len());
        *buf.add(msg_bytes.len()) = 0;
    }
    if unknown_errno { libc::EINVAL } else { 0 }
}

// ===========================================================================
// gnu_get_libc_release — GNU libc version info
// ===========================================================================

/// `gnu_get_libc_release` — return the release of the C library.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn gnu_get_libc_release() -> *const c_char {
    c"stable".as_ptr()
}

// ===========================================================================
// Reentrant random48 family (_r variants)
// ===========================================================================
//
// The `_r` variants use a caller-supplied `drand48_data` struct instead of
// global state. Layout (glibc x86_64):
//   __x[3]: u16 at offset 0  (current state, 6 bytes)
//   __old_x[3]: u16 at offset 6
//   __c: u16 at offset 12
//   __init: u16 at offset 14
//   __a: u64 at offset 16
// Total: 24 bytes.

const DRAND48_A: u64 = 0x5DEECE66D;
const DRAND48_C: u16 = 0xB;
const DRAND48_MASK: u64 = 0xFFFF_FFFF_FFFF;
const DRAND48_DATA_BYTES: usize = 24;
const DRAND48_C_OFFSET: usize = 12;
const DRAND48_INIT_OFFSET: usize = 14;
const DRAND48_A_OFFSET: usize = 16;
const DRAND48_INIT_MARKER: u16 = 1;

fn rand48_data_fits(data: *const c_void) -> bool {
    tracked_region_fits(data, DRAND48_DATA_BYTES)
}

fn rand48_result_fits<T>(result: *const T) -> bool {
    tracked_region_fits(result.cast(), core::mem::size_of::<T>())
}

unsafe fn rand48_read_u16(data: *const c_void, byte_offset: usize) -> u16 {
    let ptr = unsafe { (data as *const u8).add(byte_offset).cast::<u16>() };
    unsafe { ptr::read_unaligned(ptr) }
}

unsafe fn rand48_write_u16(data: *mut c_void, byte_offset: usize, value: u16) {
    let ptr = unsafe { (data as *mut u8).add(byte_offset).cast::<u16>() };
    unsafe { ptr::write_unaligned(ptr, value) };
}

unsafe fn rand48_read_u64(data: *const c_void, byte_offset: usize) -> u64 {
    let ptr = unsafe { (data as *const u8).add(byte_offset).cast::<u64>() };
    unsafe { ptr::read_unaligned(ptr) }
}

unsafe fn rand48_write_u64(data: *mut c_void, byte_offset: usize, value: u64) {
    let ptr = unsafe { (data as *mut u8).add(byte_offset).cast::<u64>() };
    unsafe { ptr::write_unaligned(ptr, value) };
}

unsafe fn rand48_read_word(ptr: *const u16, index: usize) -> u16 {
    unsafe { ptr::read_unaligned(ptr.add(index)) }
}

unsafe fn rand48_write_word(ptr: *mut u16, index: usize, value: u16) {
    unsafe { ptr::write_unaligned(ptr.add(index), value) };
}

unsafe fn rand48_state(data: *const c_void) -> u64 {
    let x0 = unsafe { rand48_read_u16(data, 0) } as u64;
    let x1 = unsafe { rand48_read_u16(data, 2) } as u64;
    let x2 = unsafe { rand48_read_u16(data, 4) } as u64;
    x0 | (x1 << 16) | (x2 << 32)
}

unsafe fn rand48_write_state(data: *mut c_void, state: u64) {
    unsafe {
        rand48_write_u16(data, 0, (state & 0xFFFF) as u16);
        rand48_write_u16(data, 2, ((state >> 16) & 0xFFFF) as u16);
        rand48_write_u16(data, 4, ((state >> 32) & 0xFFFF) as u16);
    }
}

unsafe fn rand48_params(data: *const c_void) -> (u64, u16) {
    let initialized = unsafe { rand48_read_u16(data, DRAND48_INIT_OFFSET) };
    if initialized == DRAND48_INIT_MARKER {
        let a = unsafe { rand48_read_u64(data, DRAND48_A_OFFSET) } & DRAND48_MASK;
        let c = unsafe { rand48_read_u16(data, DRAND48_C_OFFSET) };
        (a, c)
    } else {
        (DRAND48_A, DRAND48_C)
    }
}

unsafe fn rand48_write_params(data: *mut c_void, a: u64, c: u16) {
    unsafe {
        rand48_write_u16(data, DRAND48_C_OFFSET, c);
        rand48_write_u16(data, DRAND48_INIT_OFFSET, DRAND48_INIT_MARKER);
        rand48_write_u64(data, DRAND48_A_OFFSET, a & DRAND48_MASK);
    }
}

unsafe fn drand48_step(data: *mut c_void) {
    let xi = unsafe { rand48_state(data.cast_const()) };
    let (a, c) = unsafe { rand48_params(data.cast_const()) };
    let next = xi.wrapping_mul(a).wrapping_add(c as u64) & DRAND48_MASK;
    unsafe { rand48_write_state(data, next) };
}

unsafe fn drand48_result_double(data: *const c_void) -> f64 {
    let state = unsafe { rand48_state(data) };
    state as f64 / (1u64 << 48) as f64
}

unsafe fn drand48_result_lrand(data: *const c_void) -> c_long {
    let state = unsafe { rand48_state(data) };
    (state >> 17) as c_long
}

unsafe fn drand48_result_long(data: *const c_void) -> c_long {
    let state = unsafe { rand48_state(data) };
    ((state >> 16) as i32) as c_long
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn drand48_r(data: *mut c_void, result: *mut c_double) -> c_int {
    if data.is_null()
        || result.is_null()
        || !rand48_data_fits(data.cast_const())
        || !rand48_result_fits(result.cast_const())
    {
        return libc::EINVAL;
    }
    unsafe { drand48_step(data) };
    unsafe { ptr::write_unaligned(result, drand48_result_double(data)) };
    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn erand48_r(
    xsubi: *mut u16,
    data: *mut c_void,
    result: *mut c_double,
) -> c_int {
    if xsubi.is_null()
        || data.is_null()
        || result.is_null()
        || !tracked_region_fits(xsubi.cast(), RAND48_STATE_BYTES)
        || !rand48_data_fits(data.cast_const())
        || !rand48_result_fits(result.cast_const())
    {
        return libc::EINVAL;
    }
    // Copy xsubi into data state, step, copy back
    let dp = data as *mut u16;
    unsafe {
        rand48_write_word(dp, 0, rand48_read_word(xsubi.cast_const(), 0));
        rand48_write_word(dp, 1, rand48_read_word(xsubi.cast_const(), 1));
        rand48_write_word(dp, 2, rand48_read_word(xsubi.cast_const(), 2));
        drand48_step(data);
        rand48_write_word(xsubi, 0, rand48_read_word(dp.cast_const(), 0));
        rand48_write_word(xsubi, 1, rand48_read_word(dp.cast_const(), 1));
        rand48_write_word(xsubi, 2, rand48_read_word(dp.cast_const(), 2));
        ptr::write_unaligned(result, drand48_result_double(data));
    }
    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lrand48_r(data: *mut c_void, result: *mut c_long) -> c_int {
    if data.is_null()
        || result.is_null()
        || !rand48_data_fits(data.cast_const())
        || !rand48_result_fits(result.cast_const())
    {
        return libc::EINVAL;
    }
    unsafe { drand48_step(data) };
    unsafe { ptr::write_unaligned(result, drand48_result_lrand(data)) };
    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn nrand48_r(
    xsubi: *mut u16,
    data: *mut c_void,
    result: *mut c_long,
) -> c_int {
    if xsubi.is_null()
        || data.is_null()
        || result.is_null()
        || !tracked_region_fits(xsubi.cast(), RAND48_STATE_BYTES)
        || !rand48_data_fits(data.cast_const())
        || !rand48_result_fits(result.cast_const())
    {
        return libc::EINVAL;
    }
    let dp = data as *mut u16;
    unsafe {
        rand48_write_word(dp, 0, rand48_read_word(xsubi.cast_const(), 0));
        rand48_write_word(dp, 1, rand48_read_word(xsubi.cast_const(), 1));
        rand48_write_word(dp, 2, rand48_read_word(xsubi.cast_const(), 2));
        drand48_step(data);
        rand48_write_word(xsubi, 0, rand48_read_word(dp.cast_const(), 0));
        rand48_write_word(xsubi, 1, rand48_read_word(dp.cast_const(), 1));
        rand48_write_word(xsubi, 2, rand48_read_word(dp.cast_const(), 2));
        ptr::write_unaligned(result, drand48_result_lrand(data));
    }
    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mrand48_r(data: *mut c_void, result: *mut c_long) -> c_int {
    if data.is_null()
        || result.is_null()
        || !rand48_data_fits(data.cast_const())
        || !rand48_result_fits(result.cast_const())
    {
        return libc::EINVAL;
    }
    unsafe { drand48_step(data) };
    unsafe { ptr::write_unaligned(result, drand48_result_long(data)) };
    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn jrand48_r(
    xsubi: *mut u16,
    data: *mut c_void,
    result: *mut c_long,
) -> c_int {
    if xsubi.is_null()
        || data.is_null()
        || result.is_null()
        || !tracked_region_fits(xsubi.cast(), RAND48_STATE_BYTES)
        || !rand48_data_fits(data.cast_const())
        || !rand48_result_fits(result.cast_const())
    {
        return libc::EINVAL;
    }
    let dp = data as *mut u16;
    unsafe {
        rand48_write_word(dp, 0, rand48_read_word(xsubi.cast_const(), 0));
        rand48_write_word(dp, 1, rand48_read_word(xsubi.cast_const(), 1));
        rand48_write_word(dp, 2, rand48_read_word(xsubi.cast_const(), 2));
        drand48_step(data);
        rand48_write_word(xsubi, 0, rand48_read_word(dp.cast_const(), 0));
        rand48_write_word(xsubi, 1, rand48_read_word(dp.cast_const(), 1));
        rand48_write_word(xsubi, 2, rand48_read_word(dp.cast_const(), 2));
        ptr::write_unaligned(result, drand48_result_long(data));
    }
    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn srand48_r(seedval: c_long, data: *mut c_void) -> c_int {
    if data.is_null() || !rand48_data_fits(data.cast_const()) {
        return libc::EINVAL;
    }
    let dp = data as *mut u16;
    unsafe {
        rand48_write_word(dp, 0, 0x330E);
        rand48_write_word(dp, 1, (seedval & 0xFFFF) as u16);
        rand48_write_word(dp, 2, ((seedval >> 16) & 0xFFFF) as u16);
        rand48_write_params(data, DRAND48_A, DRAND48_C);
    }
    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn seed48_r(seed16v: *mut u16, data: *mut c_void) -> c_int {
    if seed16v.is_null()
        || data.is_null()
        || !tracked_region_fits(seed16v.cast(), RAND48_STATE_BYTES)
        || !rand48_data_fits(data.cast_const())
    {
        return libc::EINVAL;
    }
    let dp = data as *mut u16;
    unsafe {
        rand48_write_word(dp, 0, rand48_read_word(seed16v.cast_const(), 0));
        rand48_write_word(dp, 1, rand48_read_word(seed16v.cast_const(), 1));
        rand48_write_word(dp, 2, rand48_read_word(seed16v.cast_const(), 2));
        rand48_write_params(data, DRAND48_A, DRAND48_C);
    }
    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn lcong48_r(param: *mut u16, data: *mut c_void) -> c_int {
    if param.is_null()
        || data.is_null()
        || !tracked_region_fits(param.cast(), RAND48_PARAM_BYTES)
        || !rand48_data_fits(data.cast_const())
    {
        return libc::EINVAL;
    }
    let dp = data as *mut u16;
    unsafe {
        rand48_write_word(dp, 0, rand48_read_word(param.cast_const(), 0));
        rand48_write_word(dp, 1, rand48_read_word(param.cast_const(), 1));
        rand48_write_word(dp, 2, rand48_read_word(param.cast_const(), 2));
        let a = rand48_read_word(param.cast_const(), 3) as u64
            | ((rand48_read_word(param.cast_const(), 4) as u64) << 16)
            | ((rand48_read_word(param.cast_const(), 5) as u64) << 32);
        let c = rand48_read_word(param.cast_const(), 6);
        rand48_write_params(data, a, c);
    }
    0
}

// ===========================================================================
// Reentrant System V random (_r variants)
// ===========================================================================

// glibc's `struct random_data` is 48 bytes on LP64; the caller allocates it and
// we keep our own bookkeeping (a pointer to the bound statebuf plus the cursor /
// type record) inside that opaque blob.
const RANDOM_R_DATA_BYTES: usize = 48;
const RANDOM_R_RESULT_BYTES: usize = core::mem::size_of::<i32>();
/// Largest reentrant working set: TYPE_4 needs 1 encoding word + 63 state words.
const RANDOM_R_MAX_WORDS: usize = 64;
/// Marks a `random_data` blob as initialized by frankenlibc.
const FL_RANDOM_MAGIC: u32 = 0x6672_6c52; // "frlR"

/// frankenlibc's private view of the caller's opaque `random_data` (<= 48 bytes).
/// The live generator state lives in the caller's `statebuf` (glibc-compatible
/// word layout: `word[0]` = type/rear encoding, `word[1..=deg]` = state); this
/// record just locates it and carries the cursor.
#[repr(C)]
#[derive(Clone, Copy)]
struct FlRandomData {
    statebuf: *mut i32,
    rand_type: u32,
    deg: u32,
    sep: u32,
    fptr: u32,
    rptr: u32,
    magic: u32,
    _reserved: [u32; 3],
}

fn random_r_buf_fits(buf: *const c_void) -> bool {
    tracked_region_fits(buf, RANDOM_R_DATA_BYTES)
}

fn random_r_result_fits(result: *const i32) -> bool {
    tracked_region_fits(result.cast(), RANDOM_R_RESULT_BYTES)
}

fn random_statebuf_too_short_if_tracked(statebuf: *const c_char) -> bool {
    known_remaining(statebuf as usize).is_some_and(|remaining| remaining < RANDOM_STATE_MIN_BYTES)
}

#[inline]
unsafe fn read_state_words(statebuf: *const i32, n: usize, out: &mut [i32]) {
    for (i, slot) in out.iter_mut().enumerate().take(n) {
        *slot = unsafe { ptr::read_unaligned(statebuf.add(i)) };
    }
}

#[inline]
unsafe fn write_state_words(statebuf: *mut i32, words: &[i32]) {
    for (i, &w) in words.iter().enumerate() {
        unsafe { ptr::write_unaligned(statebuf.add(i), w) };
    }
}

fn rd_to_state(rd: &FlRandomData) -> frankenlibc_core::stdlib::RandomRState {
    frankenlibc_core::stdlib::RandomRState {
        rand_type: rd.rand_type as u8,
        deg: rd.deg,
        sep: rd.sep,
        fptr: rd.fptr,
        rptr: rd.rptr,
    }
}

fn state_into_rd(rd: &mut FlRandomData, st: &frankenlibc_core::stdlib::RandomRState) {
    rd.rand_type = st.rand_type as u32;
    rd.deg = st.deg;
    rd.sep = st.sep;
    rd.fptr = st.fptr;
    rd.rptr = st.rptr;
}

/// Flush a previously-initialized generator's live cursor back into the encoding
/// word of the statebuf it is bound to — glibc's "save old state" step performed
/// before `initstate_r`/`setstate_r` rebind the `random_data` to a new buffer.
unsafe fn flush_old_generator(rd: &FlRandomData) {
    if rd.magic == FL_RANDOM_MAGIC && !rd.statebuf.is_null() {
        let st = rd_to_state(rd);
        let mut w0 = [0i32; 1];
        frankenlibc_core::stdlib::random_r_flush(&mut w0, &st);
        unsafe { write_state_words(rd.statebuf, &w0) };
    }
}

/// `random_r` — reentrant `random()` over caller-supplied state.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn random_r(buf: *mut c_void, result: *mut i32) -> c_int {
    if buf.is_null()
        || result.is_null()
        || !random_r_buf_fits(buf.cast_const())
        || !random_r_result_fits(result.cast_const())
    {
        return libc::EINVAL;
    }
    let mut rd = unsafe { ptr::read_unaligned(buf as *const FlRandomData) };
    if rd.magic != FL_RANDOM_MAGIC || rd.statebuf.is_null() {
        return libc::EINVAL;
    }
    let n = (rd.deg as usize + 1).min(RANDOM_R_MAX_WORDS);
    let mut words = [0i32; RANDOM_R_MAX_WORDS];
    unsafe { read_state_words(rd.statebuf, n, &mut words) };
    let mut st = rd_to_state(&rd);
    let val = frankenlibc_core::stdlib::random_r_step(&mut words[..n], &mut st);
    unsafe { write_state_words(rd.statebuf, &words[..n]) };
    state_into_rd(&mut rd, &st);
    unsafe {
        ptr::write_unaligned(buf as *mut FlRandomData, rd);
        ptr::write_unaligned(result, val);
    }
    0
}

/// `srandom_r` — reseed a reentrant generator (type unchanged).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn srandom_r(seed: c_uint, buf: *mut c_void) -> c_int {
    if buf.is_null() || !random_r_buf_fits(buf.cast_const()) {
        return libc::EINVAL;
    }
    let mut rd = unsafe { ptr::read_unaligned(buf as *const FlRandomData) };
    if rd.magic != FL_RANDOM_MAGIC || rd.statebuf.is_null() {
        return libc::EINVAL;
    }
    let n = (rd.deg as usize + 1).min(RANDOM_R_MAX_WORDS);
    let mut words = [0i32; RANDOM_R_MAX_WORDS];
    unsafe { read_state_words(rd.statebuf, n, &mut words) };
    let mut st = rd_to_state(&rd);
    frankenlibc_core::stdlib::random_r_srandom(seed, &mut words[..n], &mut st);
    unsafe { write_state_words(rd.statebuf, &words[..n]) };
    state_into_rd(&mut rd, &st);
    unsafe { ptr::write_unaligned(buf as *mut FlRandomData, rd) };
    0
}

/// `initstate_r` — bind `statebuf` to `buf` and seed the type chosen by `statelen`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn initstate_r(
    seed: c_uint,
    statebuf: *mut c_char,
    statelen: usize,
    buf: *mut c_void,
) -> c_int {
    if statebuf.is_null()
        || buf.is_null()
        || statelen < RANDOM_STATE_MIN_BYTES
        || !tracked_region_fits(statebuf.cast_const().cast(), statelen)
        || !random_r_buf_fits(buf.cast_const())
    {
        return libc::EINVAL;
    }
    // Save the previously-bound generator's live cursor, like glibc.
    let existing = unsafe { ptr::read_unaligned(buf as *const FlRandomData) };
    unsafe { flush_old_generator(&existing) };

    let nwords = (statelen / 4).min(RANDOM_R_MAX_WORDS);
    let mut words = [0i32; RANDOM_R_MAX_WORDS];
    let Some(st) = frankenlibc_core::stdlib::random_r_initstate(seed, &mut words[..nwords]) else {
        return libc::EINVAL;
    };
    let used = (st.deg as usize + 1).min(nwords);
    let sb = statebuf as *mut i32;
    unsafe { write_state_words(sb, &words[..used]) };
    let mut rd = FlRandomData {
        statebuf: sb,
        rand_type: 0,
        deg: 0,
        sep: 0,
        fptr: 0,
        rptr: 0,
        magic: FL_RANDOM_MAGIC,
        _reserved: [0; 3],
    };
    state_into_rd(&mut rd, &st);
    unsafe { ptr::write_unaligned(buf as *mut FlRandomData, rd) };
    0
}

/// `setstate_r` — rebind `buf` to `statebuf`, recovering type/cursor from it.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setstate_r(statebuf: *mut c_char, buf: *mut c_void) -> c_int {
    if statebuf.is_null()
        || buf.is_null()
        || random_statebuf_too_short_if_tracked(statebuf.cast_const())
        || !random_r_buf_fits(buf.cast_const())
    {
        return libc::EINVAL;
    }
    let mut rd = unsafe { ptr::read_unaligned(buf as *const FlRandomData) };
    // Save the old generator's live cursor FIRST (glibc order); when rebinding
    // to the same statebuf this preserves the live position before we read it.
    unsafe { flush_old_generator(&rd) };

    let sb = statebuf as *mut i32;
    let encoding = unsafe { ptr::read_unaligned(sb) };
    let Some(st) = frankenlibc_core::stdlib::random_r_setstate(&[encoding]) else {
        return libc::EINVAL;
    };
    rd.statebuf = sb;
    rd.magic = FL_RANDOM_MAGIC;
    state_into_rd(&mut rd, &st);
    unsafe { ptr::write_unaligned(buf as *mut FlRandomData, rd) };
    0
}

// ===========================================================================
// ecvt_r / fcvt_r / qecvt / qfcvt / qgcvt / qecvt_r / qfcvt_r
// ===========================================================================

#[inline]
fn ecvt_r_required_capacity(value: c_double, requested: c_int, digits_len: usize) -> usize {
    if value.is_nan() || value.is_infinite() {
        return digits_len.saturating_add(1);
    }
    match requested.max(0) as usize {
        0 => 1,
        1 => 2,
        n => n.saturating_add(2),
    }
}

#[inline]
fn fcvt_r_required_capacity(value: c_double, requested: c_int, digits_len: usize) -> usize {
    if value.is_nan() || value.is_infinite() {
        return digits_len.saturating_add(1);
    }
    let requested = requested.max(0) as usize;
    if requested == 0 {
        return digits_len.saturating_add(1);
    }
    format!("{:.prec$}", value.abs(), prec = requested)
        .len()
        .saturating_add(1)
}

#[inline]
unsafe fn copy_legacy_cvt_digits(buf: *mut c_char, effective_buflen: usize, digits: &[u8]) {
    let copy_len = digits.len().min(effective_buflen.saturating_sub(1));
    if copy_len != 0 {
        unsafe { std::ptr::copy_nonoverlapping(digits.as_ptr(), buf as *mut u8, copy_len) };
    }
    if effective_buflen != 0 {
        unsafe { *buf.add(copy_len) = 0 };
    }
}

fn with_qecvt_buf<R>(f: impl FnOnce(&RefCell<[u8; 128]>) -> R) -> R {
    #[cfg(feature = "owned-tls-cache")]
    {
        STDLIB_OWNED_TLS.with(|tls| f(&tls.qecvt_buf))
    }
    #[cfg(not(feature = "owned-tls-cache"))]
    {
        thread_local! {
            static BUF: RefCell<[u8; 128]> = const { RefCell::new([0u8; 128]) };
        }
        BUF.with(f)
    }
}

fn with_qfcvt_buf<R>(f: impl FnOnce(&RefCell<[u8; 128]>) -> R) -> R {
    #[cfg(feature = "owned-tls-cache")]
    {
        STDLIB_OWNED_TLS.with(|tls| f(&tls.qfcvt_buf))
    }
    #[cfg(not(feature = "owned-tls-cache"))]
    {
        thread_local! {
            static BUF: RefCell<[u8; 128]> = const { RefCell::new([0u8; 128]) };
        }
        BUF.with(f)
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ecvt_r(
    value: c_double,
    ndigit: c_int,
    decpt: *mut c_int,
    sign: *mut c_int,
    buf: *mut c_char,
    buflen: usize,
) -> c_int {
    if buf.is_null() || decpt.is_null() || sign.is_null() || buflen == 0 {
        return libc::EINVAL;
    }
    let effective_buflen = known_remaining(buf as usize)
        .map(|remaining| remaining.min(buflen))
        .unwrap_or(buflen);
    if effective_buflen == 0 {
        return libc::EINVAL;
    }
    // Use signbit semantics: -0.0 returns sign=1 too, matching glibc.
    // Previous impl used `value < 0.0` which is false for -0.0.
    // Non-finite values (NaN/inf) carry their sign INSIDE the digit buffer
    // ("-inf"/"-nan") and report sign=0, so only finite negatives set sign=1.
    unsafe {
        *sign = if value.is_sign_negative() && value.is_finite() {
            1
        } else {
            0
        }
    };
    let requested = ndigit.max(0).min(MAX_LEGACY_CVT_DIGITS as i32);
    let (digits, dp, _neg) = frankenlibc_core::stdlib::ecvt(value, requested);
    let required = ecvt_r_required_capacity(value, requested, digits.len());
    unsafe { copy_legacy_cvt_digits(buf, effective_buflen, &digits) };
    if effective_buflen < required {
        return -1;
    }
    unsafe { *decpt = dp };
    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fcvt_r(
    value: c_double,
    ndigit: c_int,
    decpt: *mut c_int,
    sign: *mut c_int,
    buf: *mut c_char,
    buflen: usize,
) -> c_int {
    if buf.is_null() || decpt.is_null() || sign.is_null() || buflen == 0 {
        return libc::EINVAL;
    }
    let effective_buflen = known_remaining(buf as usize)
        .map(|remaining| remaining.min(buflen))
        .unwrap_or(buflen);
    if effective_buflen == 0 {
        return libc::EINVAL;
    }
    // signbit semantics again — -0.0 must report sign=1. Non-finite values
    // (NaN/inf) carry their sign in the buffer ("-inf"/"-nan") and report
    // sign=0, so only finite negatives set sign=1.
    unsafe {
        *sign = if value.is_sign_negative() && value.is_finite() {
            1
        } else {
            0
        }
    };
    // Clamp only the HIGH side. A NEGATIVE ndigit is meaningful — core fcvt
    // rounds the INTEGER part to the 10^|ndigit| place (fcvt_r(123456,-3)=
    // "123000") — so it must reach core, NOT be clamped to 0 (which would skip
    // the rounding and diverge from both fcvt and glibc; this also fixes qfcvt,
    // which delegates here). bd-2g7oyh.101.
    let requested = ndigit.min(MAX_LEGACY_CVT_DIGITS as i32);
    // Delegate to the corrected core fcvt: handles leading-zero
    // stripping for sub-1 magnitudes (digits="1" decpt=-3 for
    // 0.0001234 with ndigit=4), the rounded-to-zero case (digits=""
    // decpt=-ndigit when |value| < 0.5e-ndigit), and negative-ndigit
    // integer rounding.
    let (digits, dp, _neg) = frankenlibc_core::stdlib::fcvt(value, requested);
    let required = fcvt_r_required_capacity(value, requested, digits.len());
    unsafe { copy_legacy_cvt_digits(buf, effective_buflen, &digits) };
    if effective_buflen < required {
        return -1;
    }
    unsafe { *decpt = dp };
    0
}

// Quad-precision stubs (use f64 on platforms without __float128 support)
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn qecvt(
    value: c_double,
    ndigit: c_int,
    decpt: *mut c_int,
    sign: *mut c_int,
) -> *mut c_char {
    // Reuse ecvt for quad precision (f64 approximation)
    with_qecvt_buf(|b| {
        let mut buf = b.borrow_mut();
        unsafe {
            ecvt_r(
                value,
                ndigit,
                decpt,
                sign,
                buf.as_mut_ptr() as *mut c_char,
                128,
            );
        }
        buf.as_ptr() as *mut c_char
    })
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn qfcvt(
    value: c_double,
    ndigit: c_int,
    decpt: *mut c_int,
    sign: *mut c_int,
) -> *mut c_char {
    with_qfcvt_buf(|b| {
        let mut buf = b.borrow_mut();
        unsafe {
            fcvt_r(
                value,
                ndigit,
                decpt,
                sign,
                buf.as_mut_ptr() as *mut c_char,
                128,
            );
        }
        buf.as_ptr() as *mut c_char
    })
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn qgcvt(value: c_double, ndigit: c_int, buf: *mut c_char) -> *mut c_char {
    if buf.is_null() {
        return std::ptr::null_mut();
    }
    // Per glibc: qgcvt is the long-double variant of gcvt and shares
    // the same `%.<ndigit>g` semantics — total significant digits,
    // auto-switch between fixed and scientific based on exponent,
    // trailing-zero stripping, C-style `e+02` exponents. The previous
    // impl used `format!("{:.prec$}", value)` (i.e., %.Nf fixed-point
    // with N fractional digits), which diverged from glibc on every
    // case where %f and %g differ — same bug shape as the original
    // gcvt before its 58ac3c7f rewrite. Delegate to the now-correct
    // shared %g renderer in frankenlibc-core.
    let prec = (ndigit.max(0) as usize).min(MAX_LEGACY_CVT_DIGITS);
    let rendered = frankenlibc_core::stdlib::ecvt::render_pct_g(value, prec);
    let bytes = rendered.as_bytes();
    let tracked_remaining = known_remaining(buf as usize);
    let copy_len = tracked_remaining
        .map(|remaining| bytes.len().min(remaining.saturating_sub(1)))
        .unwrap_or(bytes.len());
    unsafe {
        // SAFETY: `buf` is non-null. For tracked allocations, `copy_len` is
        // capped to leave room for NUL when possible; untracked buffers keep
        // the historical libc caller-owned capacity contract.
        if copy_len != 0 {
            ptr::copy_nonoverlapping(bytes.as_ptr(), buf as *mut u8, copy_len);
        }
        if tracked_remaining.is_none_or(|remaining| remaining > copy_len) {
            *buf.add(copy_len) = 0;
        }
    }
    buf
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn qecvt_r(
    value: c_double,
    ndigit: c_int,
    decpt: *mut c_int,
    sign: *mut c_int,
    buf: *mut c_char,
    buflen: usize,
) -> c_int {
    unsafe { ecvt_r(value, ndigit, decpt, sign, buf, buflen) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn qfcvt_r(
    value: c_double,
    ndigit: c_int,
    decpt: *mut c_int,
    sign: *mut c_int,
    buf: *mut c_char,
    buflen: usize,
) -> c_int {
    unsafe { fcvt_r(value, ndigit, decpt, sign, buf, buflen) }
}

// ===========================================================================
// Integer math extras
// ===========================================================================

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn imaxabs(j: i64) -> i64 {
    j.wrapping_abs()
}

/// C `imaxdiv_t` result type (intmax_t == long long == i64 on x86-64).
#[repr(C)]
pub struct CImaxdiv {
    pub quot: i64,
    pub rem: i64,
}

/// `imaxdiv` — quotient and remainder of intmax_t division. Returned BY VALUE
/// (a 16-byte two-int struct -> RAX:RDX per SysV), matching the C signature
/// `imaxdiv_t imaxdiv(intmax_t, intmax_t)` and the div/ldiv/lldiv siblings. The
/// previous `(numer, denom, *mut i64)` sret form was an ABI mismatch: a C caller
/// passes no hidden pointer for a register-returned struct, so the function read
/// garbage as `result` and corrupted memory.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn imaxdiv(numer: i64, denom: i64) -> CImaxdiv {
    let r = frankenlibc_core::stdlib::lldiv(numer, denom);
    CImaxdiv {
        quot: r.quot,
        rem: r.rem,
    }
}

// ===========================================================================
// Misc string/conversion extras
// ===========================================================================

/// `strtoq` — BSD alias for strtoll.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strtoq(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
) -> c_long {
    unsafe { strtoll(nptr, endptr, base) as c_long }
}

/// `strtouq` — BSD alias for strtoull.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strtouq(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
) -> c_ulong {
    unsafe { strtoull(nptr, endptr, base) as c_ulong }
}

/// `glob_pattern_p` — check if string contains glob metacharacters.
///
/// Matches glibc's algorithm: '*' or '?' immediately return 1, but a
/// bracket expression only counts when both '[' and ']' are seen
/// (lone '[' or lone ']' return 0). When `quote != 0`, a backslash
/// causes the next character to be treated literally (skipped).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn glob_pattern_p(pattern: *const c_char, quote: c_int) -> c_int {
    if pattern.is_null() {
        return 0;
    }
    let mut p = pattern;
    let mut open = false;
    loop {
        let ch = unsafe { *p } as u8;
        if ch == 0 {
            return 0;
        }
        match ch {
            b'?' | b'*' => return 1,
            b'\\' if quote != 0 => {
                // Skip the next byte if not NUL.
                let next = unsafe { *p.add(1) };
                if next != 0 {
                    p = unsafe { p.add(1) };
                }
            }
            b'[' => open = true,
            b']' if open => return 1,
            _ => {}
        }
        p = unsafe { p.add(1) };
    }
}

// twalk_r is implemented in search_abi.rs

/// `ualarm` — schedule SIGALRM in microseconds.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ualarm(usecs: c_uint, interval: c_uint) -> c_uint {
    let new_val = libc::itimerval {
        it_value: libc::timeval {
            tv_sec: (usecs / 1_000_000) as i64,
            tv_usec: (usecs % 1_000_000) as i64,
        },
        it_interval: libc::timeval {
            tv_sec: (interval / 1_000_000) as i64,
            tv_usec: (interval % 1_000_000) as i64,
        },
    };
    let mut old_val: libc::itimerval = unsafe { std::mem::zeroed() };
    let ret = unsafe { crate::unistd_abi::setitimer(libc::ITIMER_REAL, &new_val, &mut old_val) };
    if ret < 0 {
        return 0;
    }
    (old_val.it_value.tv_sec as c_uint) * 1_000_000 + old_val.it_value.tv_usec as c_uint
}

// ---------------------------------------------------------------------------
// basename / dirname — POSIX libgen.h
// ---------------------------------------------------------------------------

use frankenlibc_core::unistd::dirname_range;

/// GNU `basename` — the bare `basename` SYMBOL in glibc is the GNU variant
/// (declared in `<string.h>` under `_GNU_SOURCE`), NOT the XPG/POSIX one; the
/// POSIX version is exported separately as `__xpg_basename`. GNU `basename`
/// returns the component after the LAST `/` — it does NOT strip trailing
/// slashes and does NOT modify the buffer, so `"a/b/"` and `"/usr/"` yield `""`
/// while `"abc"` yields `"abc"` and `""` yields `""`. (`__xpg_basename` is the
/// one that strips trailing slashes and maps `""`→`"."`, `"/"`→`"/"`.)
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn basename(path: *mut std::ffi::c_char) -> *mut std::ffi::c_char {
    // glibc's GNU basename dereferences immediately; return a stable empty
    // string rather than faulting if handed NULL or an unterminated buffer.
    static EMPTY: &[u8] = b"\0";
    let empty = || EMPTY.as_ptr() as *mut std::ffi::c_char;

    if path.is_null() {
        return empty();
    }
    let (len, terminated) = unsafe {
        scan_c_string(
            path as *const std::ffi::c_char,
            known_remaining(path as usize),
        )
    };
    if !terminated {
        return empty();
    }
    let slice = unsafe { std::slice::from_raw_parts(path as *const u8, len) };
    // Component after the last '/' — a pointer into the (unmodified) buffer.
    let start = match slice.iter().rposition(|&b| b == b'/') {
        Some(i) => i + 1,
        None => 0,
    };
    unsafe { path.add(start) }
}

/// Static "." fallback for dirname (must be mutable storage per POSIX).
static DIRNAME_DOT: std::sync::Mutex<[u8; 2]> = std::sync::Mutex::new([b'.', 0]);

/// POSIX `dirname` — extract directory component from a path.
///
/// Returns a pointer into the caller's buffer after truncating the directory
/// component in-place. Empty/null inputs return a mutable `"."` fallback.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn dirname(path: *mut std::ffi::c_char) -> *mut std::ffi::c_char {
    let return_dot = || {
        DIRNAME_DOT
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_mut_ptr() as *mut std::ffi::c_char
    };

    if path.is_null() {
        return return_dot();
    }
    let (len, terminated) = unsafe {
        scan_c_string(
            path as *const std::ffi::c_char,
            known_remaining(path as usize),
        )
    };
    if !terminated {
        return return_dot();
    }
    if len == 0 {
        return return_dot();
    }
    let slice = unsafe { std::slice::from_raw_parts(path as *const u8, len) };
    let (start, end) = dirname_range(slice);
    if end == start {
        return return_dot();
    }
    unsafe {
        *path.add(end) = 0;
        path.add(start)
    }
}

// ---------------------------------------------------------------------------
// realpath — via SYS_readlink iteration
// ---------------------------------------------------------------------------

/// POSIX `realpath` — resolve a pathname to an absolute path.
///
/// Small integer to ASCII in a fixed buffer. Returns number of bytes written.
fn itoa_small(mut n: u32, buf: &mut [u8]) -> usize {
    if n == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 10];
    let mut i = 0;
    while n > 0 {
        tmp[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    for j in 0..i {
        buf[j] = tmp[i - 1 - j];
    }
    i
}

/// Pure-userspace `realpath` resolution, used as a fallback when the primary
/// `open(O_PATH)` + `readlink(/proc/self/fd/N)` path cannot reach `/proc`
/// (chroot jails, minimal containers, sandboxes) where glibc still succeeds via
/// its own userspace readlink loop. (bd-2g7oyh.188)
///
/// Resolves `input` to an absolute, symlink-free, `.`/`..`-free path, requiring
/// every component to exist (glibc semantics). Uses `std::fs` readlink /
/// symlink_metadata / current_dir, all of which are thin syscall wrappers that
/// never call back into `realpath`, so there is no interposition recursion.
/// Returns the resolved bytes or a POSIX errno (`ENOENT`, `ELOOP`, `ENOTDIR`).
pub fn realpath_resolve_userspace(input: &[u8]) -> Result<Vec<u8>, c_int> {
    use std::collections::VecDeque;
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    use std::path::PathBuf;

    if input.is_empty() {
        return Err(errno::ENOENT);
    }
    const MAX_SYMLINKS: u32 = 40;
    // A trailing slash (other than the lone "/") requires the target to be a
    // directory — but `Path::components` drops it, so capture it from the bytes.
    let trailing_slash = input.last() == Some(&b'/') && input != b"/";

    // Split raw path bytes on '/', preserving `.` and `..` as real components.
    // `Path::components()` normalizes `.` away (except a leading one), which
    // would lose the directory requirement of a trailing/middle `.` — glibc
    // rejects `file/.` with ENOTDIR. Found by realpath_differential_fuzz.
    let collect = |bytes: &[u8], q: &mut VecDeque<Vec<u8>>, front: bool| {
        let comps: Vec<Vec<u8>> = bytes
            .split(|&b| b == b'/')
            .filter(|seg| !seg.is_empty())
            .map(|seg| seg.to_vec())
            .collect();
        if front {
            for c in comps.into_iter().rev() {
                q.push_front(c);
            }
        } else {
            for c in comps {
                q.push_back(c);
            }
        }
    };

    let mut queue: VecDeque<Vec<u8>> = VecDeque::new();
    if input.first() != Some(&b'/') {
        let cwd = std::env::current_dir().map_err(|e| e.raw_os_error().unwrap_or(errno::ENOENT))?;
        collect(cwd.as_os_str().as_bytes(), &mut queue, false);
    }
    collect(input, &mut queue, false);

    let mut result = PathBuf::from("/");
    let mut symlinks = 0u32;
    while let Some(comp) = queue.pop_front() {
        if comp == b".." {
            result.pop();
            continue;
        }
        if comp == b"." {
            // No-op for the path. `result` only ever holds directories here (a
            // file is pushed last, only when the queue is empty), and a `.`
            // following a file already triggered the ENOTDIR check below before
            // the file was pushed — so this is reached only with a directory.
            continue;
        }
        let candidate = result.join(OsStr::from_bytes(&comp));
        let md = std::fs::symlink_metadata(&candidate)
            .map_err(|e| e.raw_os_error().unwrap_or(errno::ENOENT))?;
        let ft = md.file_type();
        if ft.is_symlink() {
            symlinks += 1;
            if symlinks > MAX_SYMLINKS {
                return Err(errno::ELOOP);
            }
            let target = std::fs::read_link(&candidate)
                .map_err(|e| e.raw_os_error().unwrap_or(errno::ENOENT))?;
            let target_bytes = target.as_os_str().as_bytes();
            if target_bytes.first() == Some(&b'/') {
                result = PathBuf::from("/");
            }
            collect(target_bytes, &mut queue, true);
        } else if ft.is_dir() {
            result.push(OsStr::from_bytes(&comp));
        } else {
            // A non-directory is only valid as the final component.
            if !queue.is_empty() {
                return Err(errno::ENOTDIR);
            }
            result.push(OsStr::from_bytes(&comp));
        }
    }

    if trailing_slash {
        let md = std::fs::symlink_metadata(&result)
            .map_err(|e| e.raw_os_error().unwrap_or(errno::ENOENT))?;
        if !md.file_type().is_dir() {
            return Err(errno::ENOTDIR);
        }
    }

    Ok(result.as_os_str().as_bytes().to_vec())
}

/// If `resolved_path` is null, allocates a buffer via malloc.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn realpath(
    path: *const std::ffi::c_char,
    resolved_path: *mut std::ffi::c_char,
) -> *mut std::ffi::c_char {
    if path.is_null() {
        unsafe { set_abi_errno(errno::EINVAL) };
        return std::ptr::null_mut();
    }

    let (_, decision) = runtime_policy::decide(
        ApiFamily::IoFd,
        path as usize,
        0,
        false,
        known_remaining(path as usize).is_none(),
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(errno::EPERM) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, true);
        return std::ptr::null_mut();
    }

    let (_path_len, terminated) = unsafe { scan_c_string(path, known_remaining(path as usize)) };
    if !terminated {
        unsafe { set_abi_errno(errno::EINVAL) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, true);
        return std::ptr::null_mut();
    }

    // Resolve path using the raw readlink(/proc/self/fd/N) approach via open+readlink.
    // Cannot use std::fs::canonicalize because it calls libc realpath — which is
    // our own interposed symbol, causing infinite recursion.

    // Open the path with O_PATH (no actual I/O, just get an fd for the kernel path).
    let fd = unsafe {
        raw_syscall::sys_openat(
            libc::AT_FDCWD,
            path as *const u8,
            libc::O_PATH | libc::O_CLOEXEC,
            0,
        )
    };
    let fd = match fd {
        Ok(f) => f,
        Err(err) => {
            unsafe { set_abi_errno(err) };
            runtime_policy::observe(ApiFamily::IoFd, decision.profile, 16, true);
            return std::ptr::null_mut();
        }
    };

    // Read the kernel-resolved canonical path via /proc/self/fd/N.
    let mut proc_path = [0u8; 64];
    let prefix = b"/proc/self/fd/";
    proc_path[..prefix.len()].copy_from_slice(prefix);
    let fd_str = itoa_small(fd as u32, &mut proc_path[prefix.len()..]);
    let proc_len = prefix.len() + fd_str;
    proc_path[proc_len] = 0;

    let mut buf = [0u8; libc::PATH_MAX as usize];
    let n = unsafe {
        raw_syscall::sys_readlinkat(
            libc::AT_FDCWD,
            proc_path.as_ptr(),
            buf.as_mut_ptr(),
            buf.len() - 1,
        )
    };
    let _ = raw_syscall::sys_close(fd);

    // The O_PATH open above already succeeded, so the path EXISTS. If the
    // /proc/self/fd readlink could not resolve it (error, or empty result),
    // /proc is unavailable (chroot / minimal container / sandbox) — fall back to
    // pure-userspace resolution, which is what glibc does unconditionally.
    // (bd-2g7oyh.188)
    let resolved: Vec<u8> = match n {
        Ok(len) if len > 0 => buf[..len as usize].to_vec(),
        _ => {
            let path_bytes = unsafe { std::slice::from_raw_parts(path.cast::<u8>(), _path_len) };
            match realpath_resolve_userspace(path_bytes) {
                Ok(r) => r,
                Err(e) => {
                    unsafe { set_abi_errno(e) };
                    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 16, true);
                    return std::ptr::null_mut();
                }
            }
        }
    };

    let out: &[u8] = &resolved;
    if out.contains(&0) {
        unsafe { set_abi_errno(errno::EINVAL) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 16, true);
        return std::ptr::null_mut();
    }

    let dst = if resolved_path.is_null() {
        // SAFETY: POSIX realpath(3) with resolved_path=NULL returns a buffer
        // allocated by malloc, which the caller should free with free().
        let alloc = unsafe { crate::malloc_abi::malloc(out.len() + 1) as *mut std::ffi::c_char };
        if alloc.is_null() {
            unsafe { set_abi_errno(errno::ENOMEM) };
            runtime_policy::observe(ApiFamily::IoFd, decision.profile, 16, true);
            return std::ptr::null_mut();
        }
        alloc
    } else {
        resolved_path
    };

    // SAFETY: caller guarantees destination capacity when `resolved_path` is non-null.
    unsafe {
        std::ptr::copy_nonoverlapping(out.as_ptr() as *const std::ffi::c_char, dst, out.len());
        *dst.add(out.len()) = 0;
    }
    runtime_policy::observe(
        ApiFamily::IoFd,
        decision.profile,
        runtime_policy::scaled_cost(18, out.len().max(1)),
        false,
    );
    dst
}

// ---------------------------------------------------------------------------
// getbsize (BSD libutil block-size header)
// ---------------------------------------------------------------------------
//
// Pure-byte logic lives in `frankenlibc_core::stdlib::getbsize`. This shim
// owns: (a) reading the BLOCKSIZE environment variable, (b) writing the
// block size + header length out via the caller's pointers, and (c)
// publishing the header bytes through process-static storage.

fn publish_getbsize_header(
    preference: frankenlibc_core::stdlib::getbsize::BlocksizePreference,
) -> (*mut c_char, usize, u64) {
    use frankenlibc_core::stdlib::getbsize as core_gb;
    use std::sync::{Mutex, OnceLock};

    let (buf, header_len) = core_gb::format_preference_header(preference);

    // Process-static storage mirrors BSD's static header buffer while keeping
    // mutation synchronized on the Rust side. Later calls may update the
    // bytes when BLOCKSIZE changes; callers that need the string must copy it
    // before a subsequent getbsize call, as with BSD static-buffer APIs.
    static HEADER_CELL: OnceLock<Mutex<([u8; 33], usize, u64)>> = OnceLock::new();
    let cell = HEADER_CELL.get_or_init(|| Mutex::new(([0u8; 33], 0, core_gb::MIN_BLOCKSIZE)));
    let mut guard = match cell.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    guard.0 = [0u8; 33];
    guard.0[..header_len].copy_from_slice(&buf[..header_len]);
    guard.1 = header_len;
    guard.2 = preference.blocksize;
    (guard.0.as_mut_ptr() as *mut c_char, guard.1, guard.2)
}

fn emit_getbsize_diagnostic(
    diagnostic: frankenlibc_core::stdlib::getbsize::BlocksizeDiagnostic,
    env_ptr: *mut c_char,
) {
    use frankenlibc_core::stdlib::getbsize::BlocksizeDiagnostic;

    match diagnostic {
        BlocksizeDiagnostic::None => {}
        BlocksizeDiagnostic::Minimum => unsafe {
            crate::err_abi::warnx(c"%s: minimum blocksize is 512".as_ptr(), env_ptr);
        },
        BlocksizeDiagnostic::Maximum => unsafe {
            crate::err_abi::warnx(c"maximum blocksize is %ldG".as_ptr(), 1 as c_long);
        },
        BlocksizeDiagnostic::Malformed => unsafe {
            crate::err_abi::warnx(c"%s: unknown blocksize".as_ptr(), env_ptr);
            crate::err_abi::warnx(c"maximum blocksize is %ldG".as_ptr(), 1 as c_long);
            crate::err_abi::warnx(c"%s: minimum blocksize is 512".as_ptr(), env_ptr);
        },
    }
}

/// BSD libutil `getbsize(headerlenp, blocksizep)` — read `BLOCKSIZE`
/// env var, store the resolved block size into `*blocksizep`, the
/// header string length into `*headerlenp`, and return a pointer to
/// process-static storage holding the matching header (NUL-terminated).
///
/// `headerlenp` and `blocksizep` may be NULL; in that case the
/// corresponding output is silently skipped (matches NetBSD).
///
/// # Safety
///
/// Caller must ensure `headerlenp` and `blocksizep`, when non-NULL,
/// point to writable storage of `c_int` and `c_long` respectively.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getbsize(headerlenp: *mut c_int, blocksizep: *mut c_long) -> *mut c_char {
    use frankenlibc_core::stdlib::getbsize as core_gb;

    let requested_bytes = usize::from(!headerlenp.is_null()) * core::mem::size_of::<c_int>()
        + usize::from(!blocksizep.is_null()) * core::mem::size_of::<c_long>();
    let primary_addr = if !headerlenp.is_null() {
        headerlenp as usize
    } else {
        blocksizep as usize
    };
    let bloom_negative = (!headerlenp.is_null() && known_remaining(headerlenp as usize).is_none())
        || (!blocksizep.is_null() && known_remaining(blocksizep as usize).is_none());
    let (_, decision) = runtime_policy::decide(
        ApiFamily::Stdlib,
        primary_addr,
        requested_bytes,
        requested_bytes != 0,
        bloom_negative,
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(libc::EPERM) };
        let (ptr, _, _) = publish_getbsize_header(core_gb::BlocksizePreference::default_512());
        runtime_policy::observe(ApiFamily::Stdlib, decision.profile, 8, true);
        return ptr;
    }

    // Read BLOCKSIZE through the internal environment-table helper. Calling
    // the public ABI getenv wrapper here would re-enter runtime policy in
    // hardened mode and can recurse through stdlib policy decisions.
    let env_ptr = unsafe { native_getenv(b"BLOCKSIZE") };
    let preference = if env_ptr.is_null() {
        core_gb::BlocksizePreference::default_512()
    } else if let Some(bytes) = unsafe { read_bounded_cstr_bytes(env_ptr) } {
        let resolution = core_gb::resolve_preference_with_diagnostic(&bytes);
        emit_getbsize_diagnostic(resolution.diagnostic, env_ptr);
        resolution.preference
    } else {
        core_gb::BlocksizePreference::default_512()
    };

    let (ptr, header_len, blocksize) = publish_getbsize_header(preference);

    if !headerlenp.is_null() {
        // SAFETY: caller contract requires a writable c_int.
        unsafe { *headerlenp = header_len as c_int };
    }
    if !blocksizep.is_null() {
        // SAFETY: caller contract requires a writable c_long.
        unsafe { *blocksizep = blocksize as c_long };
    }
    runtime_policy::observe(
        ApiFamily::Stdlib,
        decision.profile,
        runtime_policy::scaled_cost(8, header_len),
        false,
    );
    ptr
}

// ---------------------------------------------------------------------------
// strtonum (OpenBSD bounded decimal parser)
// ---------------------------------------------------------------------------
//
// Pure-byte parsing logic lives in `frankenlibc_core::stdlib::strtonum`.
// This shim owns: NUL-terminated C-string handling, NULL `errstr` guard,
// and publishing OpenBSD's documented static error strings.

/// OpenBSD `strtonum(nptr, minval, maxval, errstr)` — parse `nptr` as
/// a decimal integer in `[minval, maxval]`. On success returns the
/// value and stores NULL through `*errstr` (when non-NULL). On
/// failure returns 0 and stores a pointer to one of OpenBSD's
/// canonical static C strings:
///
/// * `"invalid"`   — `nptr` was empty, contained no digits, had
///   trailing garbage, or `minval > maxval`.
/// * `"too small"` — value was below `minval` (or negative overflow).
/// * `"too large"` — value was above `maxval` (or positive overflow).
///
/// # Safety
///
/// Caller must ensure `nptr` is a valid NUL-terminated C string and
/// `errstr`, when non-NULL, points to a writable `*const c_char`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strtonum(
    nptr: *const c_char,
    minval: c_longlong,
    maxval: c_longlong,
    errstr: *mut *const c_char,
) -> c_longlong {
    use frankenlibc_core::stdlib::strtonum as core_st;

    // OpenBSD canonical error strings — process-static, NUL-terminated.
    static ERR_INVALID: &[u8] = b"invalid\0";
    static ERR_TOO_SMALL: &[u8] = b"too small\0";
    static ERR_TOO_LARGE: &[u8] = b"too large\0";

    if nptr.is_null() {
        unsafe { set_abi_errno(libc::EINVAL) };
        if !errstr.is_null() {
            // SAFETY: caller-supplied writable slot.
            unsafe { *errstr = ERR_INVALID.as_ptr() as *const c_char };
        }
        return 0;
    }

    let Some(bytes) = (unsafe { read_bounded_cstr_bytes(nptr) }) else {
        unsafe { set_abi_errno(libc::EINVAL) };
        if !errstr.is_null() {
            unsafe { *errstr = ERR_INVALID.as_ptr() as *const c_char };
        }
        return 0;
    };

    match core_st::parse(&bytes, minval, maxval) {
        Ok(v) => {
            if !errstr.is_null() {
                // SAFETY: caller-supplied writable slot.
                unsafe { *errstr = std::ptr::null() };
            }
            v
        }
        Err(e) => {
            let (msg, err): (&[u8], c_int) = match e {
                core_st::StrtonumError::Invalid => (ERR_INVALID, libc::EINVAL),
                core_st::StrtonumError::TooSmall => (ERR_TOO_SMALL, libc::ERANGE),
                core_st::StrtonumError::TooLarge => (ERR_TOO_LARGE, libc::ERANGE),
                core_st::StrtonumError::InvalidRange => (ERR_INVALID, libc::EINVAL),
            };
            unsafe { set_abi_errno(err) };
            if !errstr.is_null() {
                // SAFETY: caller-supplied writable slot.
                unsafe { *errstr = msg.as_ptr() as *const c_char };
            }
            0
        }
    }
}

// ---------------------------------------------------------------------------
// reallocf (BSD: realloc + free-on-failure)
// ---------------------------------------------------------------------------

/// BSD `reallocf(ptr, size)` — call `realloc(ptr, size)`. If realloc
/// fails (returns NULL with `size > 0`), free the original `ptr` to
/// defeat the classic "realloc loses your buffer on ENOMEM" leak that
/// requires every caller to either save the original pointer or
/// branch on NULL before reassigning.
///
/// Special cases match BSD libc + libbsd:
/// * `ptr == NULL` → equivalent to `realloc(NULL, size)` (i.e. `malloc(size)`).
///   No free is attempted because there is nothing to free.
/// * `size == 0`   → behaves like `realloc(ptr, 0)` from the host
///   allocator (which on glibc returns NULL after freeing). We must
///   NOT call `free(ptr)` again in that case — realloc already did.
///
/// # Safety
///
/// Caller must ensure `ptr` was returned by a previous call to a
/// libc allocator (malloc / calloc / realloc family) or is NULL.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn reallocf(ptr: *mut c_void, size: usize) -> *mut c_void {
    // SAFETY: ABI contract matches realloc.
    let out = unsafe { crate::malloc_abi::realloc(ptr, size) };
    if out.is_null() && size != 0 && !ptr.is_null() {
        // realloc failed and the original allocation is still live —
        // free it on the caller's behalf. (realloc(ptr, 0) frees ptr
        // and returns NULL on glibc; we must NOT double-free in that
        // path, hence the `size != 0` guard.)
        // SAFETY: same caller contract as for `ptr`.
        unsafe { crate::malloc_abi::free(ptr) };
    }
    out
}

// ---------------------------------------------------------------------------
// dehumanize_number (NetBSD libutil human-readable size parser)
// ---------------------------------------------------------------------------
//
// Pure-byte parsing logic lives in `frankenlibc_core::stdlib::dehumanize_number`.
// This shim owns NUL-terminated C-string handling, NULL `size` guard,
// and mapping the Invalid/Overflow categories to the EINVAL/ERANGE
// errno values that NetBSD documents.

/// NetBSD `dehumanize_number(str, size)` — parse `str` into an int64
/// with optional one-character size suffix (b/B=1, k/K=1024, m/M=1024^2,
/// g/G=1024^3, t/T=1024^4, p/P=1024^5, e/E=1024^6) and write the
/// result through `*size`. Returns 0 on success, -1 on failure with
/// errno set to:
///
/// * `EINVAL` — `str` was NULL, empty, contained non-digit non-suffix
///   bytes, had trailing garbage past the suffix, or the suffix was
///   not one of the recognized characters.
/// * `ERANGE` — arithmetic overflow during digit accumulation or the
///   suffix multiply (the resulting value won't fit in i64).
///
/// `size` may not be NULL; passing NULL yields -1 with errno=EINVAL.
///
/// # Safety
///
/// Caller must ensure `str`, when non-NULL, is a valid NUL-terminated
/// C string and `size` points to writable `int64_t` storage.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn dehumanize_number(str_ptr: *const c_char, size: *mut i64) -> c_int {
    use frankenlibc_core::stdlib::dehumanize_number as core_dh;

    if str_ptr.is_null() || size.is_null() {
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }

    let Some(bytes) = (unsafe { read_bounded_cstr_bytes(str_ptr) }) else {
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    };

    match core_dh::parse(&bytes) {
        Ok(v) => {
            // SAFETY: caller-supplied writable slot.
            unsafe { *size = v };
            0
        }
        Err(core_dh::DehumanizeError::Invalid) => {
            unsafe { set_abi_errno(libc::EINVAL) };
            -1
        }
        Err(core_dh::DehumanizeError::Overflow) => {
            unsafe { set_abi_errno(libc::ERANGE) };
            -1
        }
    }
}

// ---------------------------------------------------------------------------
// expand_number (FreeBSD libutil decimal-fraction size parser)
// ---------------------------------------------------------------------------

/// FreeBSD `expand_number(buf, num)` — parse `buf` as a non-negative
/// human-readable size with optional decimal fraction and one-character
/// suffix (k/K=1024, m/M=1024^2, g/G=1024^3, t/T=1024^4, p/P=1024^5,
/// e/E=1024^6 — note: no `b/B`, unlike NetBSD `dehumanize_number`).
/// Stores the result through `*num` and returns 0; on failure returns
/// -1 with errno set to:
///
/// * `EINVAL` — empty input, missing digits, negative sign,
///   fractional part without a suffix, unknown suffix, or trailing
///   garbage.
/// * `ERANGE` — arithmetic overflow during accumulation or the
///   suffix multiply.
///
/// `buf == NULL` or `num == NULL` yields -1 with errno=EINVAL.
///
/// # Safety
///
/// Caller must ensure `buf`, when non-NULL, is a valid NUL-terminated
/// C string and `num` points to writable `uint64_t` storage.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn expand_number(buf: *const c_char, num: *mut u64) -> c_int {
    use frankenlibc_core::stdlib::expand_number as core_ex;

    if buf.is_null() || num.is_null() {
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }

    let Some(bytes) = (unsafe { read_bounded_cstr_bytes(buf) }) else {
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    };

    match core_ex::parse(&bytes) {
        Ok(v) => {
            // SAFETY: caller-supplied writable slot.
            unsafe { *num = v };
            0
        }
        Err(core_ex::ExpandError::Invalid) => {
            unsafe { set_abi_errno(libc::EINVAL) };
            -1
        }
        Err(core_ex::ExpandError::Overflow) => {
            unsafe { set_abi_errno(libc::ERANGE) };
            -1
        }
    }
}

// ---------------------------------------------------------------------------
// humanize_number (NetBSD/FreeBSD libutil byte-count formatter)
// ---------------------------------------------------------------------------
//
// NetBSD/FreeBSD documented `<libutil.h>` constants — the abi shim
// translates the C-int `scale` parameter's special values (0x10 =
// HN_GETSCALE, 0x20 = HN_AUTOSCALE) to the internal sentinels in
// `frankenlibc_core::stdlib::humanize_number`.

/// Public NetBSD `HN_GETSCALE` value: when passed as the `scale`
/// argument, return the auto-scale level instead of writing.
const HN_C_GETSCALE: c_int = 0x10;
/// Public NetBSD `HN_AUTOSCALE` value: pick the largest scale that
/// keeps the integer part below the divisor.
const HN_C_AUTOSCALE: c_int = 0x20;

/// NetBSD/FreeBSD `humanize_number(buf, len, bytes, suffix, scale, flags)`
/// — render `bytes` into a human-readable string in `buf`.
///
/// On success returns the number of bytes written excluding the
/// trailing NUL (or, when `scale == HN_GETSCALE`, the auto-scale
/// level). Returns -1 on failure (NULL pointers, buffer too small,
/// invalid scale) with errno set to:
///
/// * `EINVAL` — NULL/zero-length buffer, unterminated suffix, or
///   invalid scale.
/// * `ERANGE` — output buffer cannot hold the rendered string plus NUL.
///
/// # Safety
///
/// Caller must ensure `buf` is valid for `len` writable bytes (with
/// `len > 0`), and `suffix`, when non-NULL, is a valid NUL-terminated
/// C string.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn humanize_number(
    buf: *mut c_char,
    len: usize,
    bytes: i64,
    suffix: *const c_char,
    scale: c_int,
    flags: c_int,
) -> c_int {
    use frankenlibc_core::stdlib::humanize_number as core_hn;

    if buf.is_null() || len == 0 {
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }

    // Translate the scale sentinels.
    let scale_internal: i32 = match scale {
        HN_C_AUTOSCALE => core_hn::HN_AUTOSCALE,
        HN_C_GETSCALE => core_hn::HN_GETSCALE,
        n => n,
    };

    // SAFETY: buf is valid for `len` writable bytes per the caller.
    let buf_slice = unsafe { std::slice::from_raw_parts_mut(buf as *mut u8, len) };

    let suffix_owned = if suffix.is_null() {
        None
    } else {
        let Some(bytes) = (unsafe { read_bounded_cstr_bytes(suffix) }) else {
            unsafe { set_abi_errno(libc::EINVAL) };
            return -1;
        };
        Some(bytes)
    };
    let suffix_bytes = suffix_owned.as_deref().unwrap_or(&[]);

    let core_flags = core_hn::HumanizeFlags(flags as u32 & 0x1f);

    match core_hn::format(buf_slice, bytes, suffix_bytes, scale_internal, core_flags) {
        Ok(n) => n as c_int,
        Err(core_hn::HumanizeError::InvalidScale) => {
            unsafe { set_abi_errno(libc::EINVAL) };
            -1
        }
        Err(core_hn::HumanizeError::BufferTooSmall) => {
            unsafe { set_abi_errno(libc::ERANGE) };
            -1
        }
    }
}

// ---------------------------------------------------------------------------
// fmtcheck (NetBSD/FreeBSD libutil printf-format compatibility check)
// ---------------------------------------------------------------------------

/// NetBSD/FreeBSD `fmtcheck(user, default_fmt)` — return `user` if
/// its printf-format conversion specifiers are compatible with
/// `default_fmt`'s; otherwise return `default_fmt`. "Compatible"
/// means same sequence of variadic-consuming conversions, with
/// matching type and length-modifier classes (per the rules in
/// `frankenlibc_core::stdlib::fmtcheck`).
///
/// `user == NULL` returns `default_fmt`. `default_fmt == NULL` is
/// only safe if `user` is also NULL or has an empty conversion
/// list — otherwise the caller would later printf with no fallback;
/// we still hand back `default_fmt` (NULL) and let the caller deal
/// with it.
///
/// # Safety
///
/// Caller must ensure `user` and `default_fmt`, when non-NULL, are
/// valid NUL-terminated C strings.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fmtcheck(
    user: *const c_char,
    default_fmt: *const c_char,
) -> *const c_char {
    use frankenlibc_core::stdlib::fmtcheck as core_fc;

    if user.is_null() {
        return default_fmt;
    }
    if default_fmt.is_null() {
        return default_fmt;
    }

    let Some(user_bytes) = (unsafe { read_bounded_cstr_bytes(user) }) else {
        return default_fmt;
    };
    let Some(default_bytes) = (unsafe { read_bounded_cstr_bytes(default_fmt) }) else {
        return default_fmt;
    };

    if core_fc::compatible(&user_bytes, &default_bytes) {
        user
    } else {
        default_fmt
    }
}

// ---------------------------------------------------------------------------
// strpct / strspct (NetBSD libutil percentage formatters)
// ---------------------------------------------------------------------------

/// Internal helper: copy `rendered` into `buf` (NUL-terminated)
/// per snprintf-style truncation rules. Returns `buf` on success
/// or NULL on `buf.is_null() || bufsize == 0`.
unsafe fn strpct_write(buf: *mut c_char, bufsize: usize, rendered: &[u8]) -> *mut c_char {
    if buf.is_null() || bufsize == 0 {
        return std::ptr::null_mut();
    }
    let cap = bufsize.saturating_sub(1);
    let n = rendered.len().min(cap);
    unsafe {
        std::ptr::copy_nonoverlapping(rendered.as_ptr(), buf as *mut u8, n);
        *buf.add(n) = 0;
    }
    buf
}

/// NetBSD `strpct(buf, bufsize, num, denom, precision)` — render
/// the unsigned percentage `100 * num / denom` rounded to
/// `precision` fractional digits into `buf`. Returns `buf` on
/// success, or NULL when `buf` is NULL / `bufsize` is zero.
/// `denom == 0` writes `"0"` (or `"0.000…0"` with `precision`
/// trailing zeros).
///
/// # Safety
///
/// `buf`, when non-NULL, must be valid for `bufsize` writable
/// bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strpct(
    buf: *mut c_char,
    bufsize: usize,
    num: uintmax_t,
    denom: uintmax_t,
    precision: usize,
) -> *mut c_char {
    let rendered = frankenlibc_core::stdlib::strpct::format_percent_unsigned(
        num as u128,
        denom as u128,
        precision,
    );
    unsafe { strpct_write(buf, bufsize, &rendered) }
}

/// NetBSD `strspct(buf, bufsize, num, denom, precision)` — signed
/// variant of [`strpct`]. Rendered value is negative iff `num` and
/// `denom` differ in sign; a true zero never carries a `-` sign.
///
/// # Safety
///
/// Same as [`strpct`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn strspct(
    buf: *mut c_char,
    bufsize: usize,
    num: intmax_t,
    denom: intmax_t,
    precision: usize,
) -> *mut c_char {
    let rendered = frankenlibc_core::stdlib::strpct::format_percent_signed(
        num as i128,
        denom as i128,
        precision,
    );
    unsafe { strpct_write(buf, bufsize, &rendered) }
}

// ---------------------------------------------------------------------------
// StringList (NetBSD libutil sl_init / sl_add / sl_find / sl_free)
// ---------------------------------------------------------------------------
//
// Tiny growable Vec<char*> with a public C-ABI struct layout. Used by ftpd,
// kvm tools, mtree, and other BSD utilities. The pointer is stored as-is —
// the StringList does NOT copy strings; the caller owns each string's
// lifetime unless `sl_free(sl, all=1)` is asked to free them.

/// Public StringList ABI layout. Field order, types, and sizes match
/// NetBSD's `<stringlist.h>`:
///
/// ```c
/// typedef struct _stringlist {
///     char    **sl_str;
///     size_t   sl_max;
///     size_t   sl_cur;
/// } StringList;
/// ```
#[repr(C)]
pub struct StringList {
    pub sl_str: *mut *mut c_char,
    pub sl_max: usize,
    pub sl_cur: usize,
}

const SL_INIT_CAPACITY: usize = 20;

/// NetBSD `sl_init()` — allocate a fresh empty `StringList`. Returns
/// NULL with errno=ENOMEM on allocation failure.
///
/// # Safety
///
/// No caller obligations. The returned pointer must eventually be
/// passed to [`sl_free`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sl_init() -> *mut StringList {
    // SAFETY: malloc returns NULL on failure; we propagate.
    let header_size = core::mem::size_of::<StringList>();
    let header = unsafe { crate::malloc_abi::malloc(header_size) } as *mut StringList;
    if header.is_null() {
        unsafe { set_abi_errno(libc::ENOMEM) };
        return ptr::null_mut();
    }
    let array_bytes = SL_INIT_CAPACITY
        .checked_mul(core::mem::size_of::<*mut c_char>())
        .unwrap_or(0);
    let array = unsafe { crate::malloc_abi::malloc(array_bytes) } as *mut *mut c_char;
    if array.is_null() {
        unsafe { crate::malloc_abi::free(header.cast()) };
        unsafe { set_abi_errno(libc::ENOMEM) };
        return ptr::null_mut();
    }
    // SAFETY: header is a freshly-allocated StringList-sized buffer.
    unsafe {
        (*header).sl_str = array;
        (*header).sl_max = SL_INIT_CAPACITY;
        (*header).sl_cur = 0;
    }
    header
}

/// NetBSD `sl_add(sl, name)` — append `name` to the StringList,
/// growing the backing array (via realloc with doubled capacity) if
/// needed. Returns 0 on success, -1 with errno=ENOMEM on alloc
/// failure.
///
/// The pointer `name` is stored as-is (no copy) — the caller owns
/// the string's lifetime unless `sl_free(sl, 1)` is asked to free it.
///
/// # Safety
///
/// `sl` must be a pointer previously returned by [`sl_init`] (or
/// equivalent), not yet freed. `name` may be any C-string pointer;
/// passing NULL is permitted but fairly useless.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sl_add(sl: *mut StringList, name: *mut c_char) -> c_int {
    if sl.is_null() {
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }
    // SAFETY: sl came from sl_init.
    let cur = unsafe { (*sl).sl_cur };
    let max = unsafe { (*sl).sl_max };
    if cur >= max {
        // Grow with doubled capacity (matches NetBSD libutil).
        let new_max = match max.checked_mul(2) {
            Some(0) | None => SL_INIT_CAPACITY,
            Some(n) => n,
        };
        let new_bytes = new_max
            .checked_mul(core::mem::size_of::<*mut c_char>())
            .unwrap_or(0);
        if new_bytes == 0 {
            unsafe { set_abi_errno(libc::ENOMEM) };
            return -1;
        }
        let old_arr = unsafe { (*sl).sl_str } as *mut c_void;
        let new_arr = unsafe { crate::malloc_abi::realloc(old_arr, new_bytes) } as *mut *mut c_char;
        if new_arr.is_null() {
            unsafe { set_abi_errno(libc::ENOMEM) };
            return -1;
        }
        unsafe {
            (*sl).sl_str = new_arr;
            (*sl).sl_max = new_max;
        }
    }
    // SAFETY: cur < sl_max (just enforced above) and sl_str is a
    // valid array of sl_max char* slots.
    unsafe {
        let arr = (*sl).sl_str;
        *arr.add(cur) = name;
        (*sl).sl_cur = cur + 1;
    }
    0
}

/// NetBSD `sl_find(sl, name)` — linear-search for an entry whose
/// stored C string compares equal to `name` (via byte equality up
/// to NUL). Returns the matching pointer or NULL if no match.
///
/// # Safety
///
/// `sl` must be a pointer returned by [`sl_init`]. `name` must be a
/// valid NUL-terminated C string.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sl_find(sl: *mut StringList, name: *const c_char) -> *mut c_char {
    if sl.is_null() || name.is_null() {
        return ptr::null_mut();
    }
    let Some(needle) = (unsafe { read_bounded_cstr_bytes(name) }) else {
        return ptr::null_mut();
    };
    // SAFETY: sl came from sl_init; sl_str has sl_cur valid char* slots.
    unsafe {
        let arr = (*sl).sl_str;
        let cur = (*sl).sl_cur;
        let mut i = 0usize;
        while i < cur {
            let entry = *arr.add(i);
            if !entry.is_null() {
                let Some(e_bytes) = read_bounded_cstr_bytes(entry) else {
                    i += 1;
                    continue;
                };
                if e_bytes == needle {
                    return entry;
                }
            }
            i += 1;
        }
    }
    ptr::null_mut()
}

/// NetBSD `sl_free(sl, all)` — release the StringList and its
/// backing array. When `all != 0`, also `free()` each stored char*
/// (typically used when the strings were `strdup`'d and the caller
/// wants the StringList to take ownership at free time).
///
/// `sl == NULL` is a no-op.
///
/// # Safety
///
/// `sl`, when non-NULL, must be a pointer returned by [`sl_init`]
/// and not yet freed.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn sl_free(sl: *mut StringList, all: c_int) {
    if sl.is_null() {
        return;
    }
    // SAFETY: sl came from sl_init.
    unsafe {
        let arr = (*sl).sl_str;
        let cur = (*sl).sl_cur;
        if all != 0 && !arr.is_null() {
            let mut i = 0usize;
            while i < cur {
                let entry = *arr.add(i);
                if !entry.is_null() {
                    crate::malloc_abi::free(entry.cast());
                }
                i += 1;
            }
        }
        if !arr.is_null() {
            crate::malloc_abi::free(arr.cast());
        }
        crate::malloc_abi::free(sl.cast());
    }
}

// ---------------------------------------------------------------------------
// setmode / getmode (BSD chmod symbolic-mode parser/applier)
// ---------------------------------------------------------------------------
//
// The "bitbox" returned by setmode is opaque to the caller. We
// allocate a little header { magic, n_ops } followed by the
// ChmodOp array on the C heap so getmode can recover the slice.

use frankenlibc_core::stdlib::setmode as core_sm;

const SETMODE_MAGIC: u32 = 0x53745468; // 'StTh' — "setmode header"

/// Bitbox header. Followed in memory by an `[ChmodOp; n_ops]` slice.
#[repr(C)]
struct SetmodeHeader {
    magic: u32,
    n_ops: u32,
}

/// BSD `setmode(mode_str)` — parse a chmod symbolic mode string
/// into a process-static "bitbox" that [`getmode`] can later apply.
/// Returns NULL on parse error or on malloc failure.
///
/// `mode_str == NULL` is malformed and yields NULL with errno=EINVAL.
///
/// # Safety
///
/// Caller must ensure `mode_str`, when non-NULL, is a valid
/// NUL-terminated C string. The returned pointer must be released
/// by the caller via `free()` (matching BSD's documented contract).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn setmode(mode_str: *const c_char) -> *mut c_void {
    if mode_str.is_null() {
        unsafe { set_abi_errno(libc::EINVAL) };
        return ptr::null_mut();
    }
    let Some(bytes) = (unsafe { read_bounded_cstr_bytes(mode_str) }) else {
        unsafe { set_abi_errno(libc::EINVAL) };
        return ptr::null_mut();
    };
    let ops = match core_sm::parse(&bytes) {
        Some(v) => v,
        None => {
            unsafe { set_abi_errno(libc::EINVAL) };
            return ptr::null_mut();
        }
    };

    let header_size = core::mem::size_of::<SetmodeHeader>();
    let op_size = core::mem::size_of::<core_sm::ChmodOp>();
    let total = match header_size.checked_add(ops.len().saturating_mul(op_size)) {
        Some(t) if t < usize::MAX => t,
        _ => {
            unsafe { set_abi_errno(libc::ENOMEM) };
            return ptr::null_mut();
        }
    };
    let raw = unsafe { crate::malloc_abi::malloc(total) };
    if raw.is_null() {
        unsafe { set_abi_errno(libc::ENOMEM) };
        return ptr::null_mut();
    }

    // SAFETY: raw is a freshly-allocated buffer of at least `total`
    // bytes; we initialize the header followed by the op slice.
    unsafe {
        let header_ptr = raw as *mut SetmodeHeader;
        (*header_ptr).magic = SETMODE_MAGIC;
        (*header_ptr).n_ops = ops.len() as u32;
        let ops_ptr = (raw as *mut u8).add(header_size) as *mut core_sm::ChmodOp;
        for (i, op) in ops.iter().enumerate() {
            *ops_ptr.add(i) = *op;
        }
    }
    raw
}

/// BSD `getmode(bbox, current_mode)` — apply the operations in
/// `bbox` (as previously returned by [`setmode`]) to `current_mode`,
/// returning the new mode.
///
/// `bbox == NULL` returns `current_mode` unchanged. A bbox with the
/// wrong magic header is treated as malformed and also returns
/// `current_mode` unchanged (rather than reading uninitialized
/// memory).
///
/// # Safety
///
/// `bbox`, when non-NULL, must point to a buffer previously
/// returned by [`setmode`] (or have the same in-memory layout).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getmode(bbox: *const c_void, current_mode: libc::mode_t) -> libc::mode_t {
    if bbox.is_null() {
        return current_mode;
    }
    // SAFETY: bbox came from setmode (or has the same layout).
    let header = unsafe { &*(bbox as *const SetmodeHeader) };
    if header.magic != SETMODE_MAGIC {
        return current_mode;
    }
    let n = header.n_ops as usize;
    let header_size = core::mem::size_of::<SetmodeHeader>();
    // SAFETY: setmode laid out [header][ops; n_ops] contiguously.
    let ops_slice = unsafe {
        let ops_ptr = (bbox as *const u8).add(header_size) as *const core_sm::ChmodOp;
        std::slice::from_raw_parts(ops_ptr, n)
    };
    core_sm::apply(ops_slice, current_mode)
}

// ---------------------------------------------------------------------------
// pidfile_open / pidfile_write / pidfile_close / pidfile_remove / pidfile_fileno
// ---------------------------------------------------------------------------
//
// FreeBSD/libbsd PID-file management for daemons. The lock acquisition
// path delegates to our just-shipped flopen (O_CREAT | O_RDWR | O_EXLOCK
// | O_NONBLOCK), which atomically opens + locks. On lock contention we
// open the file again (no flock) to read the existing locker's PID and
// surface it through *otherpid.
//
// `struct pidfh` is opaque to the caller; we malloc a header that
// stores the fd, the original path, and the path length so
// pidfile_remove can unlink without re-resolving.

#[repr(C)]
pub struct PidFh {
    fd: c_int,
    /// Pointer to a malloc'd NUL-terminated copy of the path; freed
    /// in pidfile_close / pidfile_remove.
    path: *mut c_char,
}

const PIDFILE_DEFAULT_MODE: libc::mode_t = 0o600;

unsafe fn copy_c_string(src: *const c_char) -> Option<*mut c_char> {
    let mut bytes = unsafe { read_bounded_cstr_bytes(src) }?;
    bytes.push(0);
    let buf = unsafe { crate::malloc_abi::malloc(bytes.len()) } as *mut c_char;
    if buf.is_null() {
        return None;
    }
    // SAFETY: buf was just allocated for `bytes.len()` bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf as *mut u8, bytes.len());
    }
    Some(buf)
}

/// FreeBSD `pidfile_open(path, mode, *otherpid)` — open or create a
/// PID-file at `path` with `mode` (defaults to 0o600 when 0) and
/// acquire an exclusive flock on it. On lock contention returns
/// NULL with errno=EEXIST and writes the existing locker's PID to
/// `*otherpid` (parsed from the file's contents; -1 on parse failure).
///
/// Other failure modes return NULL with the appropriate errno from
/// open/flock/malloc. The returned `*mut PidFh` must eventually be
/// passed to [`pidfile_close`] or [`pidfile_remove`].
///
/// # Safety
///
/// `path` must be a valid NUL-terminated C string. `otherpid`, when
/// non-NULL, must point to writable `pid_t` storage.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pidfile_open(
    path: *const c_char,
    mode: libc::mode_t,
    otherpid: *mut libc::pid_t,
) -> *mut PidFh {
    if path.is_null() {
        unsafe { set_abi_errno(libc::EFAULT) };
        return ptr::null_mut();
    }
    let Some(mut path_bytes) = (unsafe { read_bounded_cstr_bytes(path) }) else {
        unsafe { set_abi_errno(libc::EFAULT) };
        return ptr::null_mut();
    };
    path_bytes.push(0);
    let path_ptr = path_bytes.as_ptr().cast::<c_char>();

    let real_mode = if mode == 0 {
        PIDFILE_DEFAULT_MODE
    } else {
        mode
    };

    // Try to acquire an exclusive non-blocking lock atomically with
    // the open. flopen handles the O_EXLOCK | O_NONBLOCK strip + flock.
    const LIBBSD_O_EXLOCK: c_int = 0x20;
    let fd = unsafe {
        crate::unistd_abi::flopen(
            path_ptr,
            libc::O_CREAT | libc::O_RDWR | LIBBSD_O_EXLOCK | libc::O_NONBLOCK,
            real_mode,
        )
    };
    if fd < 0 {
        let err = unsafe { *crate::errno_abi::__errno_location() };
        if err == libc::EAGAIN || err == libc::EWOULDBLOCK {
            // Lock contention: read the locker's pid from the file
            // contents and surface it through *otherpid.
            if otherpid.is_null() {
                unsafe { set_abi_errno(libc::EEXIST) };
            } else {
                match unsafe { read_pid_from_path(path_ptr) } {
                    Ok(pid) => {
                        unsafe { *otherpid = pid };
                        unsafe { set_abi_errno(libc::EEXIST) };
                    }
                    Err(libc::EAGAIN) => {
                        unsafe { *otherpid = -1 };
                        unsafe { set_abi_errno(libc::EEXIST) };
                    }
                    Err(read_err) => unsafe { set_abi_errno(read_err) },
                }
            }
        }
        return ptr::null_mut();
    }

    // Allocate the opaque pidfh struct + dup the path.
    let path_copy = match unsafe { copy_c_string(path_ptr) } {
        Some(p) => p,
        None => {
            unsafe { crate::unistd_abi::close(fd) };
            unsafe { set_abi_errno(libc::ENOMEM) };
            return ptr::null_mut();
        }
    };
    let pfh = unsafe { crate::malloc_abi::malloc(core::mem::size_of::<PidFh>()) } as *mut PidFh;
    if pfh.is_null() {
        unsafe { crate::malloc_abi::free(path_copy.cast()) };
        unsafe { crate::unistd_abi::close(fd) };
        unsafe { set_abi_errno(libc::ENOMEM) };
        return ptr::null_mut();
    }
    // SAFETY: pfh is a freshly-allocated PidFh-sized buffer.
    unsafe {
        (*pfh).fd = fd;
        (*pfh).path = path_copy;
    }
    pfh
}

/// FreeBSD `pidfile_write(pfh)` — truncate the underlying file and
/// write the current process's PID as decimal ASCII. Returns 0 on
/// success, -1 with errno on failure.
///
/// # Safety
///
/// `pfh` must be a pointer returned by [`pidfile_open`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pidfile_write(pfh: *mut PidFh) -> c_int {
    if pfh.is_null() {
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }
    // SAFETY: pfh came from pidfile_open.
    let fd = unsafe { (*pfh).fd };
    if fd < 0 {
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }

    // FreeBSD pidfile_write renders only decimal PID bytes; pidfile_read
    // treats trailing junk (including a newline) as malformed.
    let pid = unsafe { crate::unistd_abi::getpid() };
    let mut buf = [0u8; 24];
    let n = render_pid_decimal(pid as i64, &mut buf);

    // Truncate first so a shorter pid doesn't leave stale bytes.
    if unsafe { crate::unistd_abi::ftruncate(fd, 0) } != 0 {
        return -1;
    }
    // Seek to start (lseek(fd, 0, SEEK_SET)) — truncate doesn't move
    // the file position.
    if unsafe { crate::unistd_abi::lseek(fd, 0, libc::SEEK_SET) } < 0 {
        unsafe { set_abi_errno(*crate::errno_abi::__errno_location()) };
        return -1;
    }
    let written = unsafe { crate::unistd_abi::write(fd, buf.as_ptr().cast(), n) };
    if written != n as libc::ssize_t {
        return -1;
    }
    0
}

/// FreeBSD `pidfile_close(pfh)` — release the lock and free the
/// pidfh struct WITHOUT unlinking the file (used in
/// double-fork patterns where the child inherits the file).
///
/// # Safety
///
/// `pfh` must be a pointer returned by [`pidfile_open`], not yet
/// closed/removed.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pidfile_close(pfh: *mut PidFh) -> c_int {
    if pfh.is_null() {
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }
    // SAFETY: pfh came from pidfile_open.
    unsafe {
        let fd = (*pfh).fd;
        if fd >= 0 {
            crate::unistd_abi::close(fd);
        }
        if !(*pfh).path.is_null() {
            crate::malloc_abi::free((*pfh).path.cast());
        }
        crate::malloc_abi::free(pfh.cast());
    }
    0
}

/// FreeBSD `pidfile_remove(pfh)` — unlink the file then close the
/// pidfh struct. Standard daemon cleanup path.
///
/// # Safety
///
/// `pfh` must be a pointer returned by [`pidfile_open`], not yet
/// closed/removed.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pidfile_remove(pfh: *mut PidFh) -> c_int {
    if pfh.is_null() {
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }
    // SAFETY: pfh came from pidfile_open.
    let path = unsafe { (*pfh).path };
    if !path.is_null() {
        // SAFETY: path is the malloc'd copy made by pidfile_open.
        unsafe { crate::unistd_abi::unlink(path) };
    }
    unsafe { pidfile_close(pfh) }
}

/// FreeBSD `pidfile_fileno(pfh)` — return the underlying fd or -1
/// if `pfh` is NULL.
///
/// # Safety
///
/// `pfh`, when non-NULL, must be a pointer returned by
/// [`pidfile_open`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pidfile_fileno(pfh: *const PidFh) -> c_int {
    if pfh.is_null() {
        return -1;
    }
    // SAFETY: pfh came from pidfile_open.
    unsafe { (*pfh).fd }
}

/// FreeBSD `pidfile_signal(*path, sig, **otherpid) -> int` — open
/// the pidfile at `path`, read the recorded pid, and send `sig` to
/// it. On success returns 0; if `otherpid` is non-NULL also writes
/// the pid through it. Returns an errno value on failure (missing or
/// unlocked pidfile, malformed contents, kill(2) failure).
///
/// # Safety
///
/// `path` must be a valid C string. `otherpid`, when non-NULL, must
/// point to writable `pid_t` storage.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pidfile_signal(
    path: *const c_char,
    sig: c_int,
    otherpid: *mut libc::pid_t,
) -> c_int {
    if path.is_null() {
        unsafe { set_abi_errno(libc::EFAULT) };
        return libc::EFAULT;
    }
    let Some(mut path_bytes) = (unsafe { read_bounded_cstr_bytes(path) }) else {
        unsafe { set_abi_errno(libc::EFAULT) };
        return libc::EFAULT;
    };
    path_bytes.push(0);
    let path_ptr = path_bytes.as_ptr().cast::<c_char>();

    let probe_fd = unsafe {
        crate::unistd_abi::flopen(
            path_ptr,
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0,
        )
    };
    if probe_fd >= 0 {
        unsafe { crate::unistd_abi::close(probe_fd) };
        unsafe { set_abi_errno(libc::ENOENT) };
        return libc::ENOENT;
    }

    let open_errno = unsafe { *crate::errno_abi::__errno_location() };
    if open_errno != libc::EAGAIN && open_errno != libc::EWOULDBLOCK {
        return open_errno;
    }

    let pid = match unsafe { read_pid_from_path(path_ptr) } {
        Ok(pid) => pid,
        Err(err) => {
            unsafe { set_abi_errno(err) };
            return err;
        }
    };
    if pid <= 0 {
        unsafe { set_abi_errno(libc::EDOM) };
        return libc::EDOM;
    }

    let rc = unsafe { crate::signal_abi::kill(pid, sig) };
    let err = if rc == 0 {
        0
    } else {
        unsafe { *crate::errno_abi::__errno_location() }
    };
    if !otherpid.is_null() {
        unsafe { *otherpid = pid };
    }
    err
}

unsafe fn read_pid_from_path(path: *const c_char) -> Result<libc::pid_t, c_int> {
    let Some(mut path_bytes) = (unsafe { read_bounded_cstr_bytes(path) }) else {
        return Err(libc::EFAULT);
    };
    path_bytes.push(0);
    let fd = unsafe {
        raw_syscall::sys_openat(
            libc::AT_FDCWD,
            path_bytes.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
            0,
        )
    }
    .map_err(|err| err as c_int)?;

    let mut buf = [0u8; 16];
    let n = match unsafe { raw_syscall::sys_read(fd, buf.as_mut_ptr(), buf.len() - 1) } {
        Ok(n) => n,
        Err(err) => {
            let _ = raw_syscall::sys_close(fd);
            return Err(err as c_int);
        }
    };
    let _ = raw_syscall::sys_close(fd);
    if n == 0 {
        return Err(libc::EAGAIN);
    }

    parse_decimal_pid(&buf[..n]).ok_or(libc::EINVAL)
}

fn parse_decimal_pid(input: &[u8]) -> Option<libc::pid_t> {
    // Lifted to frankenlibc_core::stdlib::pidfile (bd-jdq6k); the
    // libc::pid_t cast is preserved here so abi callers stay typed
    // against the platform pid type.
    frankenlibc_core::stdlib::pidfile::parse_decimal_pid(input).map(|v| v as libc::pid_t)
}

fn render_pid_decimal(pid: i64, out: &mut [u8]) -> usize {
    // Lifted to frankenlibc_core::stdlib::pidfile (bd-jdq6k).
    frankenlibc_core::stdlib::pidfile::render_pid_decimal(pid, out)
}
