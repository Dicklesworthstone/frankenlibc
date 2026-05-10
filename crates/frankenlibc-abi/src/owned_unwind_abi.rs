//! Opt-in owned `_Unwind_*` substitutes for standalone artifact experiments.
//!
//! These symbols are intentionally gated behind `standalone,owned-unwind-stub`.
//! They are not a general unwinder. The experiment lane also builds with
//! `panic=abort`, so the cleanup/personality paths that would need real DWARF
//! unwinding are unreachable; the stubs only remove libgcc_s symbol edges so
//! the standalone blocker surface can be measured directly.

#![allow(non_snake_case)]

use std::ffi::{c_int, c_void};

type UnwindReasonCode = c_int;
type UnwindWord = usize;

const URC_END_OF_STACK: UnwindReasonCode = 5;

#[repr(C)]
pub struct UnwindContext {
    _private: [u8; 0],
}

#[repr(C)]
pub struct UnwindException {
    _private: [u8; 0],
}

pub type UnwindTraceFn =
    Option<unsafe extern "C" fn(ctx: *mut UnwindContext, arg: *mut c_void) -> UnwindReasonCode>;

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _Unwind_Backtrace(
    _trace: UnwindTraceFn,
    _trace_argument: *mut c_void,
) -> UnwindReasonCode {
    URC_END_OF_STACK
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _Unwind_DeleteException(_exception: *mut UnwindException) {}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _Unwind_GetDataRelBase(_ctx: *mut UnwindContext) -> UnwindWord {
    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _Unwind_GetIP(_ctx: *mut UnwindContext) -> UnwindWord {
    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _Unwind_GetIPInfo(
    _ctx: *mut UnwindContext,
    ip_before_insn: *mut c_int,
) -> UnwindWord {
    if !ip_before_insn.is_null() {
        // SAFETY: the caller provided the optional out-pointer defined by the
        // unwinder ABI; a non-null pointer is expected to reference writable
        // storage for one c_int.
        unsafe { ip_before_insn.write(1) };
    }
    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _Unwind_GetLanguageSpecificData(_ctx: *mut UnwindContext) -> *mut c_void {
    std::ptr::null_mut()
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _Unwind_GetRegionStart(_ctx: *mut UnwindContext) -> UnwindWord {
    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _Unwind_GetTextRelBase(_ctx: *mut UnwindContext) -> UnwindWord {
    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _Unwind_RaiseException(
    _exception: *mut UnwindException,
) -> UnwindReasonCode {
    std::process::abort()
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _Unwind_Resume(_exception: *mut UnwindException) {
    std::process::abort()
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _Unwind_SetGR(
    _ctx: *mut UnwindContext,
    _index: c_int,
    _new_value: UnwindWord,
) {
    std::process::abort()
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _Unwind_SetIP(_ctx: *mut UnwindContext, _new_value: UnwindWord) {
    std::process::abort()
}
