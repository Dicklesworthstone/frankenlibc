//! ABI layer for `<ctype.h>` character classification and conversion.
//!
//! Pure compute — no pointers, no syscalls, no healing needed.
//! Each function masks the input to u8, delegates to `frankenlibc_core::ctype`,
//! and feeds the membrane kernel for online control telemetry.

use std::ffi::c_int;

use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::runtime_policy;

#[inline]
fn classify(c: c_int, f: fn(u8) -> bool) -> c_int {
    if !(0..=255).contains(&c) {
        return 0;
    }
    let byte = c as u8;
    let (_, decision) = runtime_policy::decide(ApiFamily::Ctype, byte as usize, 1, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Ctype, decision.profile, 3, true);
        return 0;
    }
    let result = f(byte);
    runtime_policy::observe(ApiFamily::Ctype, decision.profile, 3, false);
    c_int::from(result)
}

#[inline]
fn convert(c: c_int, f: fn(u8) -> u8) -> c_int {
    if !(0..=255).contains(&c) {
        return c;
    }
    let byte = c as u8;
    let (_, decision) = runtime_policy::decide(ApiFamily::Ctype, byte as usize, 1, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Ctype, decision.profile, 3, true);
        return c;
    }
    let result = f(byte);
    runtime_policy::observe(ApiFamily::Ctype, decision.profile, 3, false);
    result as c_int
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn isalpha(c: c_int) -> c_int {
    classify(c, frankenlibc_core::ctype::is_alpha)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn isdigit(c: c_int) -> c_int {
    classify(c, frankenlibc_core::ctype::is_digit)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn isalnum(c: c_int) -> c_int {
    classify(c, frankenlibc_core::ctype::is_alnum)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn isspace(c: c_int) -> c_int {
    classify(c, frankenlibc_core::ctype::is_space)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn isupper(c: c_int) -> c_int {
    classify(c, frankenlibc_core::ctype::is_upper)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn islower(c: c_int) -> c_int {
    classify(c, frankenlibc_core::ctype::is_lower)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn isprint(c: c_int) -> c_int {
    classify(c, frankenlibc_core::ctype::is_print)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ispunct(c: c_int) -> c_int {
    classify(c, frankenlibc_core::ctype::is_punct)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn isxdigit(c: c_int) -> c_int {
    classify(c, frankenlibc_core::ctype::is_xdigit)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn toupper(c: c_int) -> c_int {
    convert(c, frankenlibc_core::ctype::to_upper)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn tolower(c: c_int) -> c_int {
    convert(c, frankenlibc_core::ctype::to_lower)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn isblank(c: c_int) -> c_int {
    classify(c, frankenlibc_core::ctype::is_blank)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn iscntrl(c: c_int) -> c_int {
    classify(c, frankenlibc_core::ctype::is_cntrl)
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn isgraph(c: c_int) -> c_int {
    classify(c, frankenlibc_core::ctype::is_graph)
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
