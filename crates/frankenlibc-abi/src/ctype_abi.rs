//! ABI layer for `<ctype.h>` character classification and conversion.
//!
//! Pure compute — no pointers, no syscalls, no healing needed.
//! Each function masks the input to u8, delegates to `frankenlibc_core::ctype`,
//! and feeds the membrane kernel for online control telemetry.

use std::ffi::{c_int, c_void};

use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::runtime_policy;

// ---------------------------------------------------------------------------
// __ctype_*_loc — glibc-compatible ctype table accessors
// ---------------------------------------------------------------------------
//
// glibc's <ctype.h> macros expand to `(*__ctype_b_loc())[c]`, so every
// compiled C program that uses isalpha/isdigit/etc. needs these tables.
//
// The table is 384 entries (indices -128..255) and the returned pointer
// points to &table[128] so that `table[EOF]` (where EOF = -1) is valid.
//
// Bitmask layout matches glibc's <ctype.h> definitions.

// Bit positions must match glibc's <ctype.h> exactly (little-endian / x86_64).
// glibc uses a non-sequential layout where the low byte and high byte
// encode different property groups.
const _ISBLANK: u16 = 1 << 0; // 0x0001
const _ISCNTRL: u16 = 1 << 1; // 0x0002
const _ISPUNCT: u16 = 1 << 2; // 0x0004
const _ISALNUM: u16 = 1 << 3; // 0x0008
const _ISUPPER: u16 = 1 << 8; // 0x0100
const _ISLOWER: u16 = 1 << 9; // 0x0200
const _ISALPHA: u16 = 1 << 10; // 0x0400
const _ISDIGIT: u16 = 1 << 11; // 0x0800
const _ISXDIGIT: u16 = 1 << 12; // 0x1000
const _ISSPACE: u16 = 1 << 13; // 0x2000
const _ISPRINT: u16 = 1 << 14; // 0x4000
const _ISGRAPH: u16 = 1 << 15; // 0x8000

/// Build the 384-entry classification table for the C/POSIX locale.
/// Indices 0..128 are the "negative" range (-128..-1), index 128 is char 0,
/// index 128+c is char c.
const fn build_ctype_b_table() -> [u16; 384] {
    let mut t = [0u16; 384];
    // Only chars 0..=127 have defined POSIX behaviour; 128-255 are zero.
    let mut c: usize = 0;
    while c <= 255 {
        let idx = c + 128; // table[128 + c] = classification for char c
        let mut bits: u16 = 0;
        // control characters: 0-31 and 127
        if c <= 31 || c == 127 {
            bits |= _ISCNTRL;
        }
        // blank: space and tab
        if c == b' ' as usize || c == b'\t' as usize {
            bits |= _ISBLANK;
        }
        // space characters: space, tab, newline, vertical tab, form feed, carriage return
        if c == b' ' as usize
            || c == b'\t' as usize
            || c == b'\n' as usize
            || c == 0x0B // vertical tab
            || c == 0x0C // form feed
            || c == b'\r' as usize
        {
            bits |= _ISSPACE;
        }
        // uppercase
        if c >= b'A' as usize && c <= b'Z' as usize {
            bits |= _ISUPPER | _ISALPHA | _ISALNUM | _ISPRINT | _ISGRAPH;
        }
        // lowercase
        if c >= b'a' as usize && c <= b'z' as usize {
            bits |= _ISLOWER | _ISALPHA | _ISALNUM | _ISPRINT | _ISGRAPH;
        }
        // digit
        if c >= b'0' as usize && c <= b'9' as usize {
            bits |= _ISDIGIT | _ISALNUM | _ISXDIGIT | _ISPRINT | _ISGRAPH;
        }
        // xdigit (A-F, a-f) — digits already handled above
        if (c >= b'A' as usize && c <= b'F' as usize) || (c >= b'a' as usize && c <= b'f' as usize)
        {
            bits |= _ISXDIGIT;
        }
        // printable: 32-126
        if c >= 0x20 && c <= 0x7E {
            bits |= _ISPRINT;
        }
        // graph: printable minus space
        if c > 0x20 && c <= 0x7E {
            bits |= _ISGRAPH;
        }
        // punct: printable, not alnum, not space
        if c > 0x20 && c <= 0x7E && (bits & (_ISALPHA | _ISDIGIT)) == 0 {
            bits |= _ISPUNCT;
        }
        t[idx] = bits;
        c += 1;
    }
    t
}

const fn build_toupper_table() -> [i32; 384] {
    let mut t = [0i32; 384];
    let mut i: usize = 0;
    while i < 384 {
        let c = i as i32 - 128;
        t[i] = if c >= b'a' as i32 && c <= b'z' as i32 {
            c - 32 // a→A
        } else {
            c
        };
        i += 1;
    }
    t
}

const fn build_tolower_table() -> [i32; 384] {
    let mut t = [0i32; 384];
    let mut i: usize = 0;
    while i < 384 {
        let c = i as i32 - 128;
        t[i] = if c >= b'A' as i32 && c <= b'Z' as i32 {
            c + 32 // A→a
        } else {
            c
        };
        i += 1;
    }
    t
}

static CTYPE_B_TABLE: [u16; 384] = build_ctype_b_table();
static TOUPPER_TABLE: [i32; 384] = build_toupper_table();
static TOLOWER_TABLE: [i32; 384] = build_tolower_table();

/// Return a pointer to the ctype B table at offset 128 (for legacy `__ctype_b`).
/// SAFETY: caller must not write through the returned pointer.
#[allow(dead_code)] // called from glibc_internal_abi (cfg(not(test)))
pub(crate) unsafe fn ctype_b_table_ptr() -> *const u16 {
    unsafe { CTYPE_B_TABLE.as_ptr().add(128) }
}

/// Return a pointer to the tolower table at offset 128 (for legacy `__ctype_tolower`).
/// SAFETY: caller must not write through the returned pointer.
#[allow(dead_code)] // called from glibc_internal_abi (cfg(not(test)))
pub(crate) unsafe fn tolower_table_ptr() -> *const i32 {
    unsafe { TOLOWER_TABLE.as_ptr().add(128) }
}

/// Return a pointer to the toupper table at offset 128 (for legacy `__ctype_toupper`).
/// SAFETY: caller must not write through the returned pointer.
#[allow(dead_code)] // called from glibc_internal_abi (cfg(not(test)))
pub(crate) unsafe fn toupper_table_ptr() -> *const i32 {
    unsafe { TOUPPER_TABLE.as_ptr().add(128) }
}

// Thread-local pointers (glibc returns **const, pointing into the table at offset 128)
std::thread_local! {
    static CTYPE_B_PTR: std::cell::Cell<*const u16> = const {
        std::cell::Cell::new(std::ptr::null())
    };
    static TOUPPER_PTR: std::cell::Cell<*const i32> = const {
        std::cell::Cell::new(std::ptr::null())
    };
    static TOLOWER_PTR: std::cell::Cell<*const i32> = const {
        std::cell::Cell::new(std::ptr::null())
    };
}

/// Returns a pointer to a pointer to the ctype classification table.
/// The returned `*const u16` points to `table[128]`, so indexing with
/// values in -128..255 (including EOF = -1) is valid.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __ctype_b_loc() -> *const *const u16 {
    // SAFETY: CTYPE_B_TABLE is 'static and we return a pointer to TLS
    // that points into it at offset 128.
    CTYPE_B_PTR.with(|cell| {
        let ptr = cell.get();
        if ptr.is_null() {
            let p = unsafe { CTYPE_B_TABLE.as_ptr().add(128) };
            cell.set(p);
        }
        cell.as_ptr() as *const *const u16
    })
}

/// Returns a pointer to a pointer to the toupper conversion table.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __ctype_toupper_loc() -> *const *const i32 {
    TOUPPER_PTR.with(|cell| {
        let ptr = cell.get();
        if ptr.is_null() {
            let p = unsafe { TOUPPER_TABLE.as_ptr().add(128) };
            cell.set(p);
        }
        cell.as_ptr() as *const *const i32
    })
}

/// Returns a pointer to a pointer to the tolower conversion table.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __ctype_tolower_loc() -> *const *const i32 {
    TOLOWER_PTR.with(|cell| {
        let ptr = cell.get();
        if ptr.is_null() {
            let p = unsafe { TOLOWER_TABLE.as_ptr().add(128) };
            cell.set(p);
        }
        cell.as_ptr() as *const *const i32
    })
}

#[inline]
fn classify_with_mask(c: c_int, mask: u16) -> c_int {
    if !(0..=255).contains(&c) {
        return 0;
    }
    let byte = c as u8;
    let (_, decision) = runtime_policy::decide(ApiFamily::Ctype, byte as usize, 1, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Ctype, decision.profile, 3, true);
        return 0;
    }
    let flags = CTYPE_B_TABLE[usize::from(byte) + 128];
    let result = (flags & mask) != 0;
    runtime_policy::observe(ApiFamily::Ctype, decision.profile, 3, false);
    c_int::from(result)
}

#[inline]
fn convert_with_table(c: c_int, table: &[i32; 384]) -> c_int {
    if !(0..=255).contains(&c) {
        return c;
    }
    let byte = c as u8;
    let (_, decision) = runtime_policy::decide(ApiFamily::Ctype, byte as usize, 1, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Ctype, decision.profile, 3, true);
        return c;
    }
    let result = table[usize::from(byte) + 128];
    runtime_policy::observe(ApiFamily::Ctype, decision.profile, 3, false);
    result
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn isalpha(c: c_int) -> c_int {
    classify_with_mask(c, _ISALPHA)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn isdigit(c: c_int) -> c_int {
    classify_with_mask(c, _ISDIGIT)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn isalnum(c: c_int) -> c_int {
    classify_with_mask(c, _ISALNUM)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn isspace(c: c_int) -> c_int {
    classify_with_mask(c, _ISSPACE)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn isupper(c: c_int) -> c_int {
    classify_with_mask(c, _ISUPPER)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn islower(c: c_int) -> c_int {
    classify_with_mask(c, _ISLOWER)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn isprint(c: c_int) -> c_int {
    classify_with_mask(c, _ISPRINT)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ispunct(c: c_int) -> c_int {
    classify_with_mask(c, _ISPUNCT)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn isxdigit(c: c_int) -> c_int {
    classify_with_mask(c, _ISXDIGIT)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn toupper(c: c_int) -> c_int {
    convert_with_table(c, &TOUPPER_TABLE)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tolower(c: c_int) -> c_int {
    convert_with_table(c, &TOLOWER_TABLE)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn isblank(c: c_int) -> c_int {
    classify_with_mask(c, _ISBLANK)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn iscntrl(c: c_int) -> c_int {
    classify_with_mask(c, _ISCNTRL)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn isgraph(c: c_int) -> c_int {
    classify_with_mask(c, _ISGRAPH)
}

/// Returns non-zero if `c` is a 7-bit ASCII value (0–127).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn isascii(c: c_int) -> c_int {
    // isascii checks the full int range, not just 0-255
    if (0..=0x7F).contains(&c) { 1 } else { 0 }
}

/// Masks `c` to 7-bit ASCII.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn toascii(c: c_int) -> c_int {
    c & 0x7F
}

// ---------------------------------------------------------------------------
// Locale-aware _l variants — Implemented (C locale passthrough)
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn isalpha_l(c: c_int, _locale: *mut c_void) -> c_int {
    classify_with_mask(c, _ISALPHA)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn isdigit_l(c: c_int, _locale: *mut c_void) -> c_int {
    classify_with_mask(c, _ISDIGIT)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn isalnum_l(c: c_int, _locale: *mut c_void) -> c_int {
    classify_with_mask(c, _ISALNUM)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn isspace_l(c: c_int, _locale: *mut c_void) -> c_int {
    classify_with_mask(c, _ISSPACE)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn isupper_l(c: c_int, _locale: *mut c_void) -> c_int {
    classify_with_mask(c, _ISUPPER)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn islower_l(c: c_int, _locale: *mut c_void) -> c_int {
    classify_with_mask(c, _ISLOWER)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn isprint_l(c: c_int, _locale: *mut c_void) -> c_int {
    classify_with_mask(c, _ISPRINT)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ispunct_l(c: c_int, _locale: *mut c_void) -> c_int {
    classify_with_mask(c, _ISPUNCT)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn isxdigit_l(c: c_int, _locale: *mut c_void) -> c_int {
    classify_with_mask(c, _ISXDIGIT)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn isblank_l(c: c_int, _locale: *mut c_void) -> c_int {
    classify_with_mask(c, _ISBLANK)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn iscntrl_l(c: c_int, _locale: *mut c_void) -> c_int {
    classify_with_mask(c, _ISCNTRL)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn isgraph_l(c: c_int, _locale: *mut c_void) -> c_int {
    classify_with_mask(c, _ISGRAPH)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn toupper_l(c: c_int, _locale: *mut c_void) -> c_int {
    convert_with_table(c, &TOUPPER_TABLE)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tolower_l(c: c_int, _locale: *mut c_void) -> c_int {
    convert_with_table(c, &TOLOWER_TABLE)
}

// ===========================================================================
// __is*_l / __to*_l — glibc internal double-underscore locale aliases
// ===========================================================================

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isalnum_l(c: c_int, l: *mut c_void) -> c_int {
    unsafe { isalnum_l(c, l) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isalpha_l(c: c_int, l: *mut c_void) -> c_int {
    unsafe { isalpha_l(c, l) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isascii_l(c: c_int, _l: *mut c_void) -> c_int {
    if (c as u32) <= 127 { 1 } else { 0 }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isblank_l(c: c_int, l: *mut c_void) -> c_int {
    unsafe { isblank_l(c, l) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __iscntrl_l(c: c_int, l: *mut c_void) -> c_int {
    unsafe { iscntrl_l(c, l) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isdigit_l(c: c_int, l: *mut c_void) -> c_int {
    unsafe { isdigit_l(c, l) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isgraph_l(c: c_int, l: *mut c_void) -> c_int {
    unsafe { isgraph_l(c, l) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __islower_l(c: c_int, l: *mut c_void) -> c_int {
    unsafe { islower_l(c, l) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isprint_l(c: c_int, l: *mut c_void) -> c_int {
    unsafe { isprint_l(c, l) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __ispunct_l(c: c_int, l: *mut c_void) -> c_int {
    unsafe { ispunct_l(c, l) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isspace_l(c: c_int, l: *mut c_void) -> c_int {
    unsafe { isspace_l(c, l) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isupper_l(c: c_int, l: *mut c_void) -> c_int {
    unsafe { isupper_l(c, l) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __isxdigit_l(c: c_int, l: *mut c_void) -> c_int {
    unsafe { isxdigit_l(c, l) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __toascii_l(c: c_int, _l: *mut c_void) -> c_int {
    c & 0x7f
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __tolower_l(c: c_int, l: *mut c_void) -> c_int {
    unsafe { tolower_l(c, l) }
}
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __toupper_l(c: c_int, l: *mut c_void) -> c_int {
    unsafe { toupper_l(c, l) }
}
