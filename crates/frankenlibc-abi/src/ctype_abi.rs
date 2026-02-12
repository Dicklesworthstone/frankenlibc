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

#[unsafe(no_mangle)]
pub unsafe extern "C" fn isalpha(c: c_int) -> c_int {
    classify(c, frankenlibc_core::ctype::is_alpha)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn isdigit(c: c_int) -> c_int {
    classify(c, frankenlibc_core::ctype::is_digit)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn isalnum(c: c_int) -> c_int {
    classify(c, frankenlibc_core::ctype::is_alnum)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn isspace(c: c_int) -> c_int {
    classify(c, frankenlibc_core::ctype::is_space)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn isupper(c: c_int) -> c_int {
    classify(c, frankenlibc_core::ctype::is_upper)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn islower(c: c_int) -> c_int {
    classify(c, frankenlibc_core::ctype::is_lower)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn isprint(c: c_int) -> c_int {
    classify(c, frankenlibc_core::ctype::is_print)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ispunct(c: c_int) -> c_int {
    classify(c, frankenlibc_core::ctype::is_punct)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn isxdigit(c: c_int) -> c_int {
    classify(c, frankenlibc_core::ctype::is_xdigit)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn toupper(c: c_int) -> c_int {
    convert(c, frankenlibc_core::ctype::to_upper)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn tolower(c: c_int) -> c_int {
    convert(c, frankenlibc_core::ctype::to_lower)
}
