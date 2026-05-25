//! Opt-in owned `_Unwind_*` substitutes for standalone artifact experiments.
//!
//! These symbols are intentionally gated behind `standalone,owned-unwind-stub`.
//! They are not a general unwinder. The experiment lane can now perform a
//! bounded phase-1 search over registered `.eh_frame` data and invoke frame
//! personalities with LSDA/region context. Phase-2 cleanup personalities can
//! mutate an owned cursor, and x86_64 handler frames now have a guarded
//! landing-pad transfer path that validates the physical frame cursor before
//! installing the requested IP/register state.

#![allow(non_snake_case)]

use std::ffi::{c_int, c_void};
use std::sync::{Mutex, MutexGuard};

type UnwindReasonCode = c_int;
type UnwindAction = c_int;
type UnwindExceptionClass = u64;
type UnwindWord = usize;

const URC_NO_REASON: UnwindReasonCode = 0;
const URC_FATAL_PHASE2_ERROR: UnwindReasonCode = 2;
const URC_FATAL_PHASE1_ERROR: UnwindReasonCode = 3;
const URC_END_OF_STACK: UnwindReasonCode = 5;
const URC_HANDLER_FOUND: UnwindReasonCode = 6;
const URC_INSTALL_CONTEXT: UnwindReasonCode = 7;
const URC_CONTINUE_UNWIND: UnwindReasonCode = 8;
const UA_SEARCH_PHASE: UnwindAction = 1;
const UA_CLEANUP_PHASE: UnwindAction = 2;
const UA_HANDLER_FRAME: UnwindAction = 4;
const FRAME_REGISTRY_SLOTS: usize = 128;
const MAX_BACKTRACE_FRAMES: usize = 64;
const MAX_STACK_SCAN_BYTES: usize = 8 * 1024 * 1024;
const MAX_REGISTERED_EH_FRAME_BYTES: usize = 2 * 1024 * 1024;
const MAX_REGISTERED_EH_FRAME_RECORDS: usize = 16 * 1024;
const MAX_UNWIND_GR: usize = 32;
const DW_EH_PE_OMIT: u8 = 0xff;
const DW_EH_PE_ABSPTR: u8 = 0x00;
const DW_EH_PE_ULEB128: u8 = 0x01;
const DW_EH_PE_UDATA2: u8 = 0x02;
const DW_EH_PE_UDATA4: u8 = 0x03;
const DW_EH_PE_UDATA8: u8 = 0x04;
const DW_EH_PE_SLEB128: u8 = 0x09;
const DW_EH_PE_SDATA2: u8 = 0x0a;
const DW_EH_PE_SDATA4: u8 = 0x0b;
const DW_EH_PE_SDATA8: u8 = 0x0c;
const DW_EH_PE_PCREL: u8 = 0x10;
const DW_EH_PE_DATAREL: u8 = 0x30;
const DW_EH_PE_TEXTREL: u8 = 0x20;
const DW_EH_PE_INDIRECT: u8 = 0x80;
const DW_CFA_ADVANCE_LOC: u8 = 0x40;
const DW_CFA_OFFSET: u8 = 0x80;
const DW_CFA_RESTORE: u8 = 0xc0;
const DW_CFA_NOP: u8 = 0x00;
const DW_CFA_ADVANCE_LOC1: u8 = 0x02;
const DW_CFA_ADVANCE_LOC2: u8 = 0x03;
const DW_CFA_ADVANCE_LOC4: u8 = 0x04;
const DW_CFA_OFFSET_EXTENDED: u8 = 0x05;
const DW_CFA_RESTORE_EXTENDED: u8 = 0x06;
const DW_CFA_UNDEFINED: u8 = 0x07;
const DW_CFA_SAME_VALUE: u8 = 0x08;
const DW_CFA_REMEMBER_STATE: u8 = 0x0a;
const DW_CFA_RESTORE_STATE: u8 = 0x0b;
const DW_CFA_DEF_CFA: u8 = 0x0c;
const DW_CFA_DEF_CFA_REGISTER: u8 = 0x0d;
const DW_CFA_DEF_CFA_OFFSET: u8 = 0x0e;
const DW_CFA_DEF_CFA_EXPRESSION: u8 = 0x0f;
const DW_CFA_EXPRESSION: u8 = 0x10;
const DW_CFA_OFFSET_EXTENDED_SF: u8 = 0x11;
const DW_CFA_DEF_CFA_SF: u8 = 0x12;
const DW_CFA_DEF_CFA_OFFSET_SF: u8 = 0x13;
const DW_CFA_VAL_OFFSET: u8 = 0x14;
const DW_CFA_VAL_OFFSET_SF: u8 = 0x15;
const DW_CFA_VAL_EXPRESSION: u8 = 0x16;
const X86_64_DWARF_RBP: usize = 6;
const X86_64_DWARF_RSP: usize = 7;
const X86_64_DWARF_RIP: usize = 16;
const MAX_TRACKED_DWARF_REGISTERS: usize = 32;
const UNSET_DWARF_REGISTER: usize = usize::MAX;

type UnwindPersonalityFn = unsafe extern "C" fn(
    version: c_int,
    actions: UnwindAction,
    exception_class: UnwindExceptionClass,
    exception_object: *mut UnwindException,
    context: *mut UnwindContext,
) -> UnwindReasonCode;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnedUnwindDecodeError {
    Truncated,
    Overflow,
    UnterminatedAugmentation,
    UnsupportedRecordLength64,
    UnsupportedCieVersion(u8),
    UnsupportedAugmentation(u8),
    UnsupportedPointerEncoding(u8),
    UnsupportedCfiOpcode(u8),
    MissingCie,
    MalformedRecord,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnedFdeRecord {
    pub pc_begin: usize,
    pub pc_end: usize,
    pub cie_offset: usize,
    pub personality: Option<usize>,
    pub language_specific_data: Option<usize>,
    pub text_rel_base: usize,
    pub data_rel_base: usize,
    code_alignment_factor: usize,
    data_alignment_factor: isize,
    return_address_register: usize,
    cie_cfi_start: usize,
    cie_cfi_end: usize,
    fde_cfi_start: usize,
    fde_cfi_end: usize,
}

#[derive(Clone, Copy, Debug)]
struct OwnedCieRecord {
    offset: usize,
    code_alignment_factor: usize,
    data_alignment_factor: isize,
    return_address_register: usize,
    has_z_augmentation: bool,
    lsda_encoding: Option<u8>,
    personality: Option<usize>,
    fde_pointer_encoding: u8,
    text_rel_base: usize,
    data_rel_base: usize,
    cfi_start: usize,
    cfi_end: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnedCfiRow {
    pub pc: usize,
    pub cfa_register: usize,
    pub cfa_offset: isize,
    pub return_address_register: usize,
    pub saved_rip_offset: Option<isize>,
    pub saved_rbp_offset: Option<isize>,
    pub saved_rsp_offset: Option<isize>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CfiRegisterRule {
    Undefined,
    SameValue,
    Offset(isize),
    ValOffset(isize),
}

#[derive(Clone, Copy)]
struct CfiEvaluationState {
    pc: usize,
    cfa_register: usize,
    cfa_offset: isize,
    register_rules: [CfiRegisterRule; MAX_TRACKED_DWARF_REGISTERS],
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OwnedEhFrameSummary {
    pub fde_count: usize,
    pub personality_fde_count: usize,
    pub lsda_fde_count: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnedPhase1SearchOutcome {
    HandlerFound {
        frame_index: usize,
        ip: usize,
        region_start: usize,
        language_specific_data: usize,
    },
    NoHandler,
    Fatal {
        frame_index: usize,
        code: UnwindReasonCode,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnedPhase2CleanupOutcome {
    InstallRequested {
        frame_index: usize,
        ip: usize,
        general_register_0: usize,
        general_register_1: usize,
    },
    ContinueUnwind,
    Fatal {
        frame_index: usize,
        code: UnwindReasonCode,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnedContextInstallError {
    UnsupportedArchitecture,
    NullLandingPad,
    MissingPhysicalCursor,
    MisalignedFramePointer,
    MisalignedStackPointer,
    StackPointerEscapesHandlerFrame,
    UnsupportedCfaRegister(usize),
    MissingSavedInstructionPointer,
    CfaOverflow,
    Decode(OwnedUnwindDecodeError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnedLandingPadInstall {
    pub ip: usize,
    pub stack_pointer: usize,
    pub frame_pointer: usize,
    pub general_register_0: usize,
    pub general_register_1: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnedLandingPadInstallInput {
    pub call_site_ip: usize,
    pub landing_pad_ip: usize,
    pub frame_pointer: usize,
    pub stack_pointer: usize,
    pub general_register_0: usize,
    pub general_register_1: usize,
}

#[repr(C)]
pub struct UnwindContext {
    ip: UnwindWord,
    frame_index: usize,
    frame_pointer: UnwindWord,
    stack_pointer: UnwindWord,
    language_specific_data: UnwindWord,
    region_start: UnwindWord,
    text_rel_base: UnwindWord,
    data_rel_base: UnwindWord,
    general_registers: [UnwindWord; MAX_UNWIND_GR],
}

#[repr(C, align(16))]
pub struct UnwindException {
    pub exception_class: UnwindExceptionClass,
    pub exception_cleanup:
        Option<unsafe extern "C" fn(reason: UnwindReasonCode, exception: *mut UnwindException)>,
    pub private_1: UnwindWord,
    pub private_2: UnwindWord,
}

pub type UnwindTraceFn =
    Option<unsafe extern "C" fn(ctx: *mut UnwindContext, arg: *mut c_void) -> UnwindReasonCode>;

#[derive(Clone, Copy)]
struct FrameRegistration {
    fde: usize,
    object: usize,
}

static FRAME_REGISTRY: Mutex<[FrameRegistration; FRAME_REGISTRY_SLOTS]> =
    Mutex::new([FrameRegistration { fde: 0, object: 0 }; FRAME_REGISTRY_SLOTS]);

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _Unwind_Backtrace(
    trace: UnwindTraceFn,
    trace_argument: *mut c_void,
) -> UnwindReasonCode {
    let Some(trace_fn) = trace else {
        return URC_END_OF_STACK;
    };

    let mut frame_pointer = current_frame_pointer();
    let stack_pointer = current_stack_pointer();
    let Some(stack_limit) = stack_pointer.checked_add(MAX_STACK_SCAN_BYTES) else {
        return URC_END_OF_STACK;
    };

    let mut frame_index = 0usize;
    while frame_index < MAX_BACKTRACE_FRAMES
        && valid_frame_pointer(frame_pointer, stack_pointer, stack_limit)
    {
        let Some(next_frame) = read_word(frame_pointer) else {
            break;
        };
        let Some(return_address_slot) = frame_pointer.checked_add(core::mem::size_of::<usize>())
        else {
            break;
        };
        let Some(instruction_pointer) = read_word(return_address_slot) else {
            break;
        };

        if instruction_pointer != 0 {
            let mut context = UnwindContext {
                ip: instruction_pointer,
                frame_index,
                frame_pointer,
                stack_pointer,
                language_specific_data: 0,
                region_start: 0,
                text_rel_base: 0,
                data_rel_base: 0,
                general_registers: empty_general_registers(),
            };
            // SAFETY: the callback receives a pointer to a stack-local context
            // that remains alive for the duration of the call. The callback
            // contract is the platform unwinder ABI.
            let reason = unsafe { trace_fn(&mut context, trace_argument) };
            if reason != URC_NO_REASON {
                return reason;
            }
            frame_index += 1;
        }

        if next_frame <= frame_pointer
            || !valid_frame_pointer(next_frame, stack_pointer, stack_limit)
        {
            break;
        }
        frame_pointer = next_frame;
    }

    URC_END_OF_STACK
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _Unwind_DeleteException(exception: *mut UnwindException) {
    if exception.is_null() {
        return;
    }

    // SAFETY: the caller supplied an unwind exception header. If a cleanup
    // callback is present, the unwind ABI says it owns exception destruction.
    let Some(cleanup) = (unsafe { (*exception).exception_cleanup }) else {
        return;
    };
    // SAFETY: the cleanup function pointer comes from the exception header and
    // follows the platform unwinder ABI.
    unsafe { cleanup(1, exception) };
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _Unwind_GetDataRelBase(ctx: *mut UnwindContext) -> UnwindWord {
    if ctx.is_null() {
        return 0;
    }
    // SAFETY: non-null contexts are owned by this module during personality
    // calls or supplied by ABI peers following the opaque context contract.
    unsafe { (*ctx).data_rel_base }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _Unwind_GetGR(ctx: *mut UnwindContext, index: c_int) -> UnwindWord {
    let Ok(index) = usize::try_from(index) else {
        return 0;
    };
    if ctx.is_null() || index >= MAX_UNWIND_GR {
        return 0;
    }
    // SAFETY: non-null contexts are owned by this module during personality
    // calls or supplied by ABI peers following the opaque context contract.
    unsafe { (*ctx).general_registers[index] }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _Unwind_GetIP(ctx: *mut UnwindContext) -> UnwindWord {
    if ctx.is_null() {
        return 0;
    }
    // SAFETY: non-null contexts are created by this module while walking frames
    // or provided by an ABI peer following the opaque _Unwind_Context contract.
    unsafe { (*ctx).ip }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _Unwind_GetIPInfo(
    ctx: *mut UnwindContext,
    ip_before_insn: *mut c_int,
) -> UnwindWord {
    if !ip_before_insn.is_null() {
        // SAFETY: the caller provided the optional out-pointer defined by the
        // unwinder ABI; a non-null pointer is expected to reference writable
        // storage for one c_int.
        unsafe { ip_before_insn.write(0) };
    }
    // SAFETY: mirrors _Unwind_GetIP's opaque-context handling.
    unsafe { _Unwind_GetIP(ctx) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _Unwind_GetLanguageSpecificData(ctx: *mut UnwindContext) -> *mut c_void {
    if ctx.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: mirrors _Unwind_GetIP's opaque-context handling.
    unsafe { (*ctx).language_specific_data as *mut c_void }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _Unwind_GetRegionStart(ctx: *mut UnwindContext) -> UnwindWord {
    if ctx.is_null() {
        return 0;
    }
    // SAFETY: mirrors _Unwind_GetIP's opaque-context handling.
    unsafe { (*ctx).region_start }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _Unwind_GetTextRelBase(ctx: *mut UnwindContext) -> UnwindWord {
    if ctx.is_null() {
        return 0;
    }
    // SAFETY: mirrors _Unwind_GetIP's opaque-context handling.
    unsafe { (*ctx).text_rel_base }
}

#[cfg(all(not(debug_assertions), target_arch = "x86_64"))]
core::arch::global_asm!(
    ".global _Unwind_RaiseException",
    ".type _Unwind_RaiseException, @function",
    "_Unwind_RaiseException:",
    "  push rbp",
    "  mov rbp, rsp",
    "  mov rsi, rbp",
    "  mov rdx, rsp",
    "  call __frankenlibc_owned_raise_exception_from_frame",
    "  pop rbp",
    "  ret",
    ".size _Unwind_RaiseException, . - _Unwind_RaiseException",
);

#[cfg(any(debug_assertions, not(target_arch = "x86_64")))]
#[cfg_attr(
    all(not(debug_assertions), not(target_arch = "x86_64")),
    unsafe(no_mangle)
)]
pub unsafe extern "C" fn _Unwind_RaiseException(
    exception: *mut UnwindException,
) -> UnwindReasonCode {
    owned_raise_exception_from_frame(exception, current_frame_pointer(), current_stack_pointer())
}

#[cfg_attr(all(not(debug_assertions), target_arch = "x86_64"), unsafe(no_mangle))]
extern "C" fn __frankenlibc_owned_raise_exception_from_frame(
    exception: *mut UnwindException,
    frame_pointer: usize,
    stack_pointer: usize,
) -> UnwindReasonCode {
    owned_raise_exception_from_frame(exception, frame_pointer, stack_pointer)
}

fn owned_raise_exception_from_frame(
    exception: *mut UnwindException,
    frame_pointer: usize,
    stack_pointer: usize,
) -> UnwindReasonCode {
    trace_owned_unwind(format_args!(
        "raise exception={exception:p} fp={frame_pointer:#x} sp={stack_pointer:#x}"
    ));
    match owned_phase1_search_current_stack(exception, frame_pointer, stack_pointer) {
        OwnedPhase1SearchOutcome::HandlerFound {
            frame_index, ip, ..
        } => {
            trace_owned_unwind(format_args!(
                "phase1 handler frame_index={frame_index} ip={ip:#x}"
            ));
            if !exception.is_null() {
                // SAFETY: the exception header is supplied by the language
                // runtime. private_1/private_2 are reserved for the unwinder.
                unsafe {
                    (*exception).private_1 = 0;
                    (*exception).private_2 = ip;
                }
            }
            owned_phase2_cleanup_current_stack(
                exception,
                frame_index,
                ip,
                frame_pointer,
                stack_pointer,
            )
        }
        OwnedPhase1SearchOutcome::NoHandler => {
            trace_owned_unwind(format_args!("phase1 no handler"));
            URC_END_OF_STACK
        }
        OwnedPhase1SearchOutcome::Fatal { frame_index, code } => {
            trace_owned_unwind(format_args!(
                "phase1 fatal frame_index={frame_index} code={code}"
            ));
            code
        }
    }
}

#[cfg(all(not(debug_assertions), target_arch = "x86_64"))]
core::arch::global_asm!(
    ".global _Unwind_Resume",
    ".type _Unwind_Resume, @function",
    "_Unwind_Resume:",
    "  push rbp",
    "  mov rbp, rsp",
    "  mov rsi, rbp",
    "  mov rdx, rsp",
    "  call __frankenlibc_owned_resume_from_frame",
    "  pop rbp",
    "  ret",
    ".size _Unwind_Resume, . - _Unwind_Resume",
);

#[cfg(any(debug_assertions, not(target_arch = "x86_64")))]
#[cfg_attr(
    all(not(debug_assertions), not(target_arch = "x86_64")),
    unsafe(no_mangle)
)]
pub unsafe extern "C" fn _Unwind_Resume(exception: *mut UnwindException) {
    owned_resume_from_frame(exception, current_frame_pointer(), current_stack_pointer())
}

#[cfg_attr(all(not(debug_assertions), target_arch = "x86_64"), unsafe(no_mangle))]
extern "C" fn __frankenlibc_owned_resume_from_frame(
    exception: *mut UnwindException,
    frame_pointer: usize,
    stack_pointer: usize,
) {
    owned_resume_from_frame(exception, frame_pointer, stack_pointer)
}

fn owned_resume_from_frame(
    exception: *mut UnwindException,
    frame_pointer: usize,
    stack_pointer: usize,
) -> ! {
    trace_owned_unwind(format_args!(
        "resume exception={exception:p} fp={frame_pointer:#x} sp={stack_pointer:#x}"
    ));

    // _Unwind_Resume continues phase-2 cleanup from the current cleanup handler.
    // The handler was found during phase-1, and private_1 may store the handler
    // frame index. We re-raise from the current frame which will skip already-
    // cleaned frames and eventually reach the handler.
    let result = owned_raise_exception_from_frame(exception, frame_pointer, stack_pointer);

    // _Unwind_Resume should never return. If we get here, something went wrong.
    trace_owned_unwind(format_args!("resume unexpectedly returned code={result}"));
    std::process::abort()
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _Unwind_Resume_or_Rethrow(
    exception: *mut UnwindException,
) -> UnwindReasonCode {
    // SAFETY: this symbol is the Itanium ABI rethrow edge. The current owned
    // lane treats it as a fresh raise over the current stack so it either
    // installs a validated handler context or returns a fatal/no-handler code.
    owned_raise_exception_from_frame(exception, current_frame_pointer(), current_stack_pointer())
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _Unwind_SetGR(
    ctx: *mut UnwindContext,
    index: c_int,
    new_value: UnwindWord,
) {
    let Ok(index) = usize::try_from(index) else {
        return;
    };
    if ctx.is_null() || index >= MAX_UNWIND_GR {
        return;
    }
    // SAFETY: non-null contexts are stack-local owned cursors during this
    // phase-2 experiment. Mutating them records intent only; no CPU context is
    // installed by this symbol.
    unsafe { (*ctx).general_registers[index] = new_value };
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _Unwind_SetIP(ctx: *mut UnwindContext, new_value: UnwindWord) {
    if ctx.is_null() {
        return;
    }
    // SAFETY: mirrors _Unwind_SetGR's owned-cursor contract.
    unsafe { (*ctx).ip = new_value };
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __register_frame(fde: *mut c_void) {
    register_frame(fde as usize, 0);
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __register_frame_info(fde: *mut c_void, object: *mut c_void) {
    register_frame(fde as usize, object as usize);
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __deregister_frame(fde: *mut c_void) {
    deregister_frame(fde as usize);
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __deregister_frame_info(fde: *mut c_void) -> *mut c_void {
    deregister_frame(fde as usize)
        .map(|object| object as *mut c_void)
        .unwrap_or(core::ptr::null_mut())
}

#[doc(hidden)]
pub fn owned_frame_is_registered_for_tests(fde: *const c_void) -> bool {
    frame_slot_index(fde as usize).is_some()
}

#[doc(hidden)]
pub fn owned_frame_object_for_tests(fde: *const c_void) -> *mut c_void {
    let Some(index) = frame_slot_index(fde as usize) else {
        return core::ptr::null_mut();
    };
    frame_registry()[index].object as *mut c_void
}

fn register_frame(fde: usize, object: usize) {
    if fde == 0 {
        return;
    }

    let mut registry = frame_registry();
    if let Some(slot) = registry.iter_mut().find(|slot| slot.fde == fde) {
        if object != 0 {
            slot.object = object;
        }
        return;
    }

    if let Some(slot) = registry.iter_mut().find(|slot| slot.fde == 0) {
        *slot = FrameRegistration { fde, object };
    }
}

fn deregister_frame(fde: usize) -> Option<usize> {
    let mut registry = frame_registry();
    let slot = registry.iter_mut().find(|slot| slot.fde == fde)?;
    let object = slot.object;
    *slot = FrameRegistration { fde: 0, object: 0 };
    Some(object)
}

fn frame_slot_index(fde: usize) -> Option<usize> {
    if fde == 0 {
        return None;
    }
    frame_registry().iter().position(|slot| slot.fde == fde)
}

fn frame_registry() -> MutexGuard<'static, [FrameRegistration; FRAME_REGISTRY_SLOTS]> {
    FRAME_REGISTRY
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[doc(hidden)]
pub fn owned_decode_uleb128_for_tests(
    input: &[u8],
    offset: usize,
) -> Result<(usize, usize), OwnedUnwindDecodeError> {
    decode_uleb128(input, offset)
}

#[doc(hidden)]
pub fn owned_decode_sleb128_for_tests(
    input: &[u8],
    offset: usize,
) -> Result<(isize, usize), OwnedUnwindDecodeError> {
    decode_sleb128(input, offset)
}

#[doc(hidden)]
pub fn owned_validate_cfi_program_for_tests(input: &[u8]) -> Result<(), OwnedUnwindDecodeError> {
    validate_cfi_program(input, 0, input.len())
}

#[doc(hidden)]
pub fn owned_summarize_eh_frame_for_tests(
    eh_frame: &[u8],
    section_addr: usize,
) -> Result<OwnedEhFrameSummary, OwnedUnwindDecodeError> {
    summarize_eh_frame(eh_frame, section_addr, false)
}

#[doc(hidden)]
pub fn owned_phase1_search_for_tests(
    eh_frame: &[u8],
    section_addr: usize,
    ips: &[usize],
    exception_class: UnwindExceptionClass,
) -> Result<OwnedPhase1SearchOutcome, OwnedUnwindDecodeError> {
    let mut exception = UnwindException {
        exception_class,
        exception_cleanup: None,
        private_1: 0,
        private_2: 0,
    };
    phase1_search_ips(eh_frame, section_addr, ips, &mut exception, false)
}

#[doc(hidden)]
pub fn owned_phase2_cleanup_for_tests(
    eh_frame: &[u8],
    section_addr: usize,
    ip: usize,
    exception_class: UnwindExceptionClass,
) -> Result<OwnedPhase2CleanupOutcome, OwnedUnwindDecodeError> {
    let mut exception = UnwindException {
        exception_class,
        exception_cleanup: None,
        private_1: 0,
        private_2: 0,
    };
    phase2_cleanup_ip(eh_frame, section_addr, ip, &mut exception, false)
}

#[doc(hidden)]
pub fn owned_prepare_landing_pad_install_for_tests(
    eh_frame: &[u8],
    section_addr: usize,
    input: OwnedLandingPadInstallInput,
) -> Result<OwnedLandingPadInstall, OwnedContextInstallError> {
    let fde = find_fde_for_ip(eh_frame, section_addr, input.call_site_ip, false)
        .map_err(OwnedContextInstallError::Decode)?
        .ok_or(OwnedContextInstallError::Decode(
            OwnedUnwindDecodeError::MalformedRecord,
        ))?;
    let mut context = context_for_fde(input.call_site_ip, 0, fde);
    context.ip = input.landing_pad_ip;
    context.frame_pointer = input.frame_pointer;
    context.stack_pointer = input.stack_pointer;
    context.general_registers[0] = input.general_register_0;
    context.general_registers[1] = input.general_register_1;
    prepare_landing_pad_install(&context, eh_frame, fde, input.call_site_ip)
}

#[doc(hidden)]
pub fn owned_first_fde_for_tests(
    eh_frame: &[u8],
    section_addr: usize,
) -> Result<Option<OwnedFdeRecord>, OwnedUnwindDecodeError> {
    let mut cies = Vec::new();
    let mut cursor = 0usize;
    while let Some(record) = next_eh_frame_record(eh_frame, cursor)? {
        cursor = record.end;
        if record.is_cie {
            cies.push(parse_cie_record(eh_frame, section_addr, record, false)?);
        } else {
            let fde = parse_fde_record(eh_frame, section_addr, record, &cies, false)?;
            validate_fde_cfi_program(eh_frame, fde)?;
            return Ok(Some(fde));
        }
    }
    Ok(None)
}

#[doc(hidden)]
pub fn owned_find_fde_for_ip_for_tests(
    eh_frame: &[u8],
    section_addr: usize,
    ip: usize,
) -> Result<Option<OwnedFdeRecord>, OwnedUnwindDecodeError> {
    find_fde_for_ip(eh_frame, section_addr, ip, false)
}

#[doc(hidden)]
pub fn owned_evaluate_cfi_row_for_tests(
    eh_frame: &[u8],
    section_addr: usize,
    ip: usize,
) -> Result<Option<OwnedCfiRow>, OwnedUnwindDecodeError> {
    let Some(fde) = find_fde_for_ip(eh_frame, section_addr, ip, false)? else {
        return Ok(None);
    };
    evaluate_cfi_row(eh_frame, fde, ip).map(Some)
}

fn find_fde_for_ip(
    eh_frame: &[u8],
    section_addr: usize,
    ip: usize,
    resolve_indirect: bool,
) -> Result<Option<OwnedFdeRecord>, OwnedUnwindDecodeError> {
    let mut cies = Vec::new();
    let mut cursor = 0usize;
    while let Some(record) = next_eh_frame_record(eh_frame, cursor)? {
        cursor = record.end;
        if record.is_cie {
            cies.push(parse_cie_record(
                eh_frame,
                section_addr,
                record,
                resolve_indirect,
            )?);
            continue;
        }

        let fde = parse_fde_record(eh_frame, section_addr, record, &cies, resolve_indirect)?;
        if ip >= fde.pc_begin && ip < fde.pc_end {
            validate_fde_cfi_program(eh_frame, fde)?;
            return Ok(Some(fde));
        }
    }
    Ok(None)
}

fn summarize_eh_frame(
    eh_frame: &[u8],
    section_addr: usize,
    resolve_indirect: bool,
) -> Result<OwnedEhFrameSummary, OwnedUnwindDecodeError> {
    let mut summary = OwnedEhFrameSummary::default();
    let mut cies = Vec::new();
    let mut cursor = 0usize;
    while let Some(record) = next_eh_frame_record(eh_frame, cursor)? {
        cursor = record.end;
        if record.is_cie {
            cies.push(parse_cie_record(
                eh_frame,
                section_addr,
                record,
                resolve_indirect,
            )?);
            continue;
        }

        let fde = parse_fde_record(eh_frame, section_addr, record, &cies, resolve_indirect)?;
        summary.fde_count += 1;
        if fde.personality.is_some() {
            summary.personality_fde_count += 1;
        }
        if fde.language_specific_data.is_some() {
            summary.lsda_fde_count += 1;
        }
    }
    Ok(summary)
}

fn phase1_search_ips(
    eh_frame: &[u8],
    section_addr: usize,
    ips: &[usize],
    exception: *mut UnwindException,
    resolve_indirect: bool,
) -> Result<OwnedPhase1SearchOutcome, OwnedUnwindDecodeError> {
    let exception_class = if exception.is_null() {
        0
    } else {
        // SAFETY: non-null exception pointers are supplied by the language
        // runtime following the unwind ABI header layout.
        unsafe { (*exception).exception_class }
    };

    for (frame_index, ip) in ips.iter().copied().enumerate() {
        let Some(fde) = find_fde_for_ip(eh_frame, section_addr, ip, resolve_indirect)? else {
            continue;
        };
        let Some(personality) = fde.personality else {
            continue;
        };
        let mut context = context_for_fde(ip, frame_index, fde);
        let code = call_personality(
            personality,
            UA_SEARCH_PHASE,
            exception_class,
            exception,
            &mut context,
        );
        match code {
            URC_HANDLER_FOUND => {
                return Ok(OwnedPhase1SearchOutcome::HandlerFound {
                    frame_index,
                    ip,
                    region_start: context.region_start,
                    language_specific_data: context.language_specific_data,
                });
            }
            URC_CONTINUE_UNWIND | URC_NO_REASON => {}
            other => {
                return Ok(OwnedPhase1SearchOutcome::Fatal {
                    frame_index,
                    code: other,
                });
            }
        }
    }
    Ok(OwnedPhase1SearchOutcome::NoHandler)
}

fn phase2_cleanup_ip(
    eh_frame: &[u8],
    section_addr: usize,
    ip: usize,
    exception: *mut UnwindException,
    resolve_indirect: bool,
) -> Result<OwnedPhase2CleanupOutcome, OwnedUnwindDecodeError> {
    let exception_class = if exception.is_null() {
        0
    } else {
        // SAFETY: non-null exception pointers are supplied by the language
        // runtime following the unwind ABI header layout.
        unsafe { (*exception).exception_class }
    };
    let Some(fde) = find_fde_for_ip(eh_frame, section_addr, ip, resolve_indirect)? else {
        return Ok(OwnedPhase2CleanupOutcome::ContinueUnwind);
    };
    let Some(personality) = fde.personality else {
        return Ok(OwnedPhase2CleanupOutcome::ContinueUnwind);
    };
    let mut context = context_for_fde(ip, 0, fde);
    let code = call_personality(
        personality,
        UA_CLEANUP_PHASE | UA_HANDLER_FRAME,
        exception_class,
        exception,
        &mut context,
    );
    match code {
        URC_INSTALL_CONTEXT => Ok(OwnedPhase2CleanupOutcome::InstallRequested {
            frame_index: context.frame_index,
            ip: context.ip,
            general_register_0: context.general_registers[0],
            general_register_1: context.general_registers[1],
        }),
        URC_CONTINUE_UNWIND | URC_NO_REASON => Ok(OwnedPhase2CleanupOutcome::ContinueUnwind),
        other => Ok(OwnedPhase2CleanupOutcome::Fatal {
            frame_index: context.frame_index,
            code: other,
        }),
    }
}

fn owned_phase2_cleanup_current_stack(
    exception: *mut UnwindException,
    handler_frame_index: usize,
    handler_ip: usize,
    mut frame_pointer: usize,
    stack_pointer: usize,
) -> UnwindReasonCode {
    let Some(stack_limit) = stack_pointer.checked_add(MAX_STACK_SCAN_BYTES) else {
        return URC_FATAL_PHASE2_ERROR;
    };

    let exception_class = if exception.is_null() {
        0
    } else {
        // SAFETY: non-null exception pointers are supplied by the language
        // runtime following the unwind ABI header layout.
        unsafe { (*exception).exception_class }
    };

    let mut frame_index = 0usize;
    let mut previous_frame_pointer = None;
    while frame_index < MAX_BACKTRACE_FRAMES
        && valid_frame_pointer(frame_pointer, stack_pointer, stack_limit)
    {
        let Some(next_frame) = read_word(frame_pointer) else {
            break;
        };
        let Some(return_address_slot) = frame_pointer.checked_add(core::mem::size_of::<usize>())
        else {
            break;
        };
        let Some(instruction_pointer) = read_word(return_address_slot) else {
            break;
        };

        if instruction_pointer != 0 {
            let effective_ip = if frame_index == handler_frame_index {
                handler_ip
            } else {
                instruction_pointer
            };
            let lookup_ip = frame_lookup_ip(effective_ip);
            let record = match find_registered_fde_record_for_ip(lookup_ip) {
                Ok(Some(record)) => Some(record),
                Ok(None) => None,
                Err(_) => return URC_FATAL_PHASE2_ERROR,
            };
            if let Some(record) = record
                && let Some(personality) = record.fde.personality
            {
                let physical_stack_pointer = previous_frame_pointer
                    .and_then(|fp: usize| fp.checked_add(2 * core::mem::size_of::<usize>()))
                    .unwrap_or(stack_pointer);
                let mut context = context_for_physical_fde(
                    effective_ip,
                    frame_index,
                    record.fde,
                    frame_pointer,
                    physical_stack_pointer,
                );
                let mut actions = UA_CLEANUP_PHASE;
                if frame_index == handler_frame_index {
                    actions |= UA_HANDLER_FRAME;
                }
                let code = call_personality(
                    personality,
                    actions,
                    exception_class,
                    exception,
                    &mut context,
                );
                trace_owned_unwind(format_args!(
                    "phase2 frame_index={frame_index} target={handler_frame_index} ip={effective_ip:#x} raw_ip={instruction_pointer:#x} actions={actions:#x} code={code} ctx_ip={:#x} gr0={:#x} gr1={:#x}",
                    context.ip, context.general_registers[0], context.general_registers[1]
                ));
                match code {
                    URC_INSTALL_CONTEXT if frame_index == handler_frame_index => {
                        let install = match prepare_landing_pad_install(
                            &context,
                            &record.eh_frame,
                            record.fde,
                            lookup_ip,
                        ) {
                            Ok(install) => install,
                            Err(err) => {
                                trace_owned_unwind(format_args!("phase2 install error {err:?}"));
                                return URC_FATAL_PHASE2_ERROR;
                            }
                        };
                        trace_owned_unwind(format_args!(
                            "phase2 install ip={:#x} fp={:#x} sp={:#x} gr0={:#x} gr1={:#x}",
                            install.ip,
                            install.frame_pointer,
                            install.stack_pointer,
                            install.general_register_0,
                            install.general_register_1
                        ));
                        // SAFETY: prepare_landing_pad_install validated the
                        // physical stack/frame cursor and landing-pad IP for
                        // this architecture-specific non-returning transfer.
                        unsafe { install_landing_pad_context(install) };
                    }
                    URC_INSTALL_CONTEXT => return URC_FATAL_PHASE2_ERROR,
                    URC_CONTINUE_UNWIND | URC_NO_REASON => {}
                    other => return other,
                }
            }
            if frame_index == handler_frame_index {
                break;
            }
            frame_index += 1;
        }

        if next_frame <= frame_pointer
            || !valid_frame_pointer(next_frame, stack_pointer, stack_limit)
        {
            break;
        }
        previous_frame_pointer = Some(frame_pointer);
        frame_pointer = next_frame;
    }

    URC_FATAL_PHASE2_ERROR
}

fn trace_owned_unwind(args: std::fmt::Arguments<'_>) {
    if std::env::var_os("FRANKENLIBC_OWNED_UNWIND_TRACE").is_some() {
        eprintln!("[owned-unwind] {args}");
    }
}

#[inline]
fn frame_lookup_ip(return_address: usize) -> usize {
    return_address.saturating_sub(1)
}

fn owned_phase1_search_current_stack(
    exception: *mut UnwindException,
    mut frame_pointer: usize,
    stack_pointer: usize,
) -> OwnedPhase1SearchOutcome {
    let Some(stack_limit) = stack_pointer.checked_add(MAX_STACK_SCAN_BYTES) else {
        return OwnedPhase1SearchOutcome::NoHandler;
    };

    let mut frame_index = 0usize;
    while frame_index < MAX_BACKTRACE_FRAMES
        && valid_frame_pointer(frame_pointer, stack_pointer, stack_limit)
    {
        let Some(next_frame) = read_word(frame_pointer) else {
            break;
        };
        let Some(return_address_slot) = frame_pointer.checked_add(core::mem::size_of::<usize>())
        else {
            break;
        };
        let Some(instruction_pointer) = read_word(return_address_slot) else {
            break;
        };
        if instruction_pointer != 0 {
            let lookup_ip = frame_lookup_ip(instruction_pointer);
            match find_registered_fde_record_for_ip(lookup_ip) {
                Ok(Some(record)) => {
                    if let Some(personality) = record.fde.personality {
                        let mut context = context_for_physical_fde(
                            instruction_pointer,
                            frame_index,
                            record.fde,
                            frame_pointer,
                            stack_pointer,
                        );
                        let exception_class = if exception.is_null() {
                            0
                        } else {
                            // SAFETY: non-null exception pointers are supplied by
                            // the language runtime following the unwind ABI header.
                            unsafe { (*exception).exception_class }
                        };
                        let code = call_personality(
                            personality,
                            UA_SEARCH_PHASE,
                            exception_class,
                            exception,
                            &mut context,
                        );
                        match code {
                            URC_HANDLER_FOUND => {
                                return OwnedPhase1SearchOutcome::HandlerFound {
                                    frame_index,
                                    ip: instruction_pointer,
                                    region_start: context.region_start,
                                    language_specific_data: context.language_specific_data,
                                };
                            }
                            URC_CONTINUE_UNWIND | URC_NO_REASON => {}
                            other => {
                                return OwnedPhase1SearchOutcome::Fatal {
                                    frame_index,
                                    code: other,
                                };
                            }
                        }
                    }
                }
                Ok(None) => {}
                Err(_) => {
                    return OwnedPhase1SearchOutcome::Fatal {
                        frame_index,
                        code: URC_FATAL_PHASE1_ERROR,
                    };
                }
            }
            frame_index += 1;
        }

        if next_frame <= frame_pointer
            || !valid_frame_pointer(next_frame, stack_pointer, stack_limit)
        {
            break;
        }
        frame_pointer = next_frame;
    }

    OwnedPhase1SearchOutcome::NoHandler
}

struct RegisteredFdeRecord {
    fde: OwnedFdeRecord,
    eh_frame: Vec<u8>,
}

fn find_registered_fde_record_for_ip(
    ip: usize,
) -> Result<Option<RegisteredFdeRecord>, OwnedUnwindDecodeError> {
    let registry = *frame_registry();
    for slot in registry.iter().filter(|slot| slot.fde != 0) {
        let eh_frame = copy_registered_eh_frame(slot.fde)?;
        if let Some(fde) = find_fde_for_ip(&eh_frame, slot.fde, ip, true)? {
            return Ok(Some(RegisteredFdeRecord { fde, eh_frame }));
        }
    }
    Ok(None)
}

fn copy_registered_eh_frame(fde: usize) -> Result<Vec<u8>, OwnedUnwindDecodeError> {
    let len = registered_eh_frame_len(fde)?;
    if len == 0 || len > MAX_REGISTERED_EH_FRAME_BYTES {
        return Err(OwnedUnwindDecodeError::MalformedRecord);
    }
    // SAFETY: fde was registered through __register_frame* and points at an
    // in-process .eh_frame byte stream. The bounded length scan above stops at
    // the zero terminator before this copy.
    let bytes = unsafe { core::slice::from_raw_parts(fde as *const u8, len) };
    Ok(bytes.to_vec())
}

fn registered_eh_frame_len(fde: usize) -> Result<usize, OwnedUnwindDecodeError> {
    if fde == 0 {
        return Err(OwnedUnwindDecodeError::MalformedRecord);
    }

    let mut cursor = 0usize;
    for _ in 0..MAX_REGISTERED_EH_FRAME_RECORDS {
        let length_addr = fde
            .checked_add(cursor)
            .ok_or(OwnedUnwindDecodeError::Overflow)?;
        // SAFETY: fde is a registered in-process .eh_frame pointer. Reads are
        // bounded by MAX_REGISTERED_EH_FRAME_BYTES and use unaligned access
        // because .eh_frame records are byte streams.
        let length = unsafe { core::ptr::read_unaligned(length_addr as *const u32) };
        let next = cursor
            .checked_add(4)
            .and_then(|body| body.checked_add(length as usize))
            .ok_or(OwnedUnwindDecodeError::Overflow)?;
        if length == 0 {
            return Ok(cursor + 4);
        }
        if length == u32::MAX || next > MAX_REGISTERED_EH_FRAME_BYTES {
            return Err(OwnedUnwindDecodeError::UnsupportedRecordLength64);
        }
        cursor = next;
    }
    Err(OwnedUnwindDecodeError::MalformedRecord)
}

fn context_for_fde(ip: usize, frame_index: usize, fde: OwnedFdeRecord) -> UnwindContext {
    UnwindContext {
        ip,
        frame_index,
        frame_pointer: 0,
        stack_pointer: 0,
        language_specific_data: fde.language_specific_data.unwrap_or(0),
        region_start: fde.pc_begin,
        text_rel_base: fde.text_rel_base,
        data_rel_base: fde.data_rel_base,
        general_registers: empty_general_registers(),
    }
}

fn context_for_physical_fde(
    ip: usize,
    frame_index: usize,
    fde: OwnedFdeRecord,
    frame_pointer: usize,
    stack_pointer: usize,
) -> UnwindContext {
    let mut context = context_for_fde(ip, frame_index, fde);
    context.frame_pointer = frame_pointer;
    context.stack_pointer = stack_pointer;
    context
}

fn prepare_landing_pad_install(
    context: &UnwindContext,
    eh_frame: &[u8],
    fde: OwnedFdeRecord,
    call_site_ip: usize,
) -> Result<OwnedLandingPadInstall, OwnedContextInstallError> {
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (context, eh_frame, fde, call_site_ip);
        return Err(OwnedContextInstallError::UnsupportedArchitecture);
    }

    #[cfg(target_arch = "x86_64")]
    {
        let row = evaluate_cfi_row(eh_frame, fde, call_site_ip)
            .map_err(OwnedContextInstallError::Decode)?;
        prepare_x86_64_landing_pad_install(context, row)
    }
}

#[cfg(target_arch = "x86_64")]
fn prepare_x86_64_landing_pad_install(
    context: &UnwindContext,
    row: OwnedCfiRow,
) -> Result<OwnedLandingPadInstall, OwnedContextInstallError> {
    if context.ip == 0 {
        return Err(OwnedContextInstallError::NullLandingPad);
    }
    if context.frame_pointer == 0 || context.stack_pointer == 0 {
        return Err(OwnedContextInstallError::MissingPhysicalCursor);
    }
    if !context
        .frame_pointer
        .is_multiple_of(core::mem::align_of::<usize>())
    {
        return Err(OwnedContextInstallError::MisalignedFramePointer);
    }
    if !context
        .stack_pointer
        .is_multiple_of(core::mem::align_of::<usize>())
    {
        return Err(OwnedContextInstallError::MisalignedStackPointer);
    }
    if context.stack_pointer >= context.frame_pointer {
        return Err(OwnedContextInstallError::StackPointerEscapesHandlerFrame);
    }
    if row.saved_rip_offset.is_none() {
        return Err(OwnedContextInstallError::MissingSavedInstructionPointer);
    }
    let cfa_base = match row.cfa_register {
        X86_64_DWARF_RBP => context.frame_pointer,
        X86_64_DWARF_RSP => context.stack_pointer,
        other => return Err(OwnedContextInstallError::UnsupportedCfaRegister(other)),
    };
    let _cfa = checked_add_signed_usize(cfa_base, row.cfa_offset)
        .ok_or(OwnedContextInstallError::CfaOverflow)?;

    Ok(OwnedLandingPadInstall {
        ip: context.ip,
        stack_pointer: context.stack_pointer,
        frame_pointer: context.frame_pointer,
        general_register_0: context.general_registers[0],
        general_register_1: context.general_registers[1],
    })
}

#[cfg(target_arch = "x86_64")]
fn checked_add_signed_usize(base: usize, offset: isize) -> Option<usize> {
    if offset >= 0 {
        base.checked_add(offset as usize)
    } else {
        base.checked_sub(offset.unsigned_abs())
    }
}

unsafe fn install_landing_pad_context(install: OwnedLandingPadInstall) -> ! {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: the caller validated that the target IP, frame pointer, and
        // stack pointer describe an in-stack x86_64 handler frame. This path
        // never returns to Rust; it installs the Itanium ABI landing-pad
        // registers (GR0/GR1 map to RAX/RDX on x86_64 SysV) and jumps to the
        // personality-selected landing pad.
        unsafe {
            core::arch::asm!(
                "mov rbp, r8",
                "mov rsp, r9",
                "jmp r10",
                in("r8") install.frame_pointer,
                in("r9") install.stack_pointer,
                in("r10") install.ip,
                in("rax") install.general_register_0,
                in("rdx") install.general_register_1,
                options(noreturn)
            );
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = install;
        std::process::abort()
    }
}

fn empty_general_registers() -> [UnwindWord; MAX_UNWIND_GR] {
    [0; MAX_UNWIND_GR]
}

fn call_personality(
    personality: usize,
    actions: UnwindAction,
    exception_class: UnwindExceptionClass,
    exception: *mut UnwindException,
    context: *mut UnwindContext,
) -> UnwindReasonCode {
    if personality == 0 {
        return URC_CONTINUE_UNWIND;
    }
    // SAFETY: personality addresses are decoded from compiler-emitted CIE
    // augmentation data. The target function follows the platform unwinder ABI.
    let personality_fn = unsafe { core::mem::transmute::<usize, UnwindPersonalityFn>(personality) };
    // SAFETY: context is stack-local for this call and exception is the
    // language runtime's unwind header pointer.
    unsafe { personality_fn(1, actions, exception_class, exception, context) }
}

#[derive(Clone, Copy)]
struct EhFrameRecord {
    offset: usize,
    body: usize,
    end: usize,
    is_cie: bool,
    cie_pointer_or_id: u32,
}

fn next_eh_frame_record(
    eh_frame: &[u8],
    offset: usize,
) -> Result<Option<EhFrameRecord>, OwnedUnwindDecodeError> {
    if offset == eh_frame.len() {
        return Ok(None);
    }
    if offset > eh_frame.len() {
        return Err(OwnedUnwindDecodeError::Truncated);
    }

    let (length, body) = read_u32(eh_frame, offset)?;
    if length == 0 {
        return Ok(None);
    }
    if length == u32::MAX {
        return Err(OwnedUnwindDecodeError::UnsupportedRecordLength64);
    }

    let end = body
        .checked_add(length as usize)
        .ok_or(OwnedUnwindDecodeError::Overflow)?;
    if end > eh_frame.len() || body.checked_add(4).is_none_or(|id_end| id_end > end) {
        return Err(OwnedUnwindDecodeError::Truncated);
    }

    let (cie_pointer_or_id, payload) = read_u32(eh_frame, body)?;
    Ok(Some(EhFrameRecord {
        offset,
        body: payload,
        end,
        is_cie: cie_pointer_or_id == 0,
        cie_pointer_or_id,
    }))
}

fn parse_cie_record(
    eh_frame: &[u8],
    section_addr: usize,
    record: EhFrameRecord,
    resolve_indirect: bool,
) -> Result<OwnedCieRecord, OwnedUnwindDecodeError> {
    let (version, mut cursor) = read_u8(eh_frame, record.body)?;
    if !matches!(version, 1 | 3 | 4) {
        return Err(OwnedUnwindDecodeError::UnsupportedCieVersion(version));
    }

    let (augmentation, after_augmentation) = read_c_string(eh_frame, cursor, record.end)?;
    cursor = after_augmentation;
    let (code_alignment_factor, after_code_alignment) = decode_uleb128(eh_frame, cursor)?;
    let (data_alignment_factor, after_data_alignment) =
        decode_sleb128(eh_frame, after_code_alignment)?;
    cursor = after_data_alignment;
    let (return_address_register, after_return_address) = if version == 1 {
        let (register, after_register) = read_u8(eh_frame, cursor)?;
        (register as usize, after_register)
    } else {
        decode_uleb128(eh_frame, cursor)?
    };
    cursor = after_return_address;

    let mut fde_pointer_encoding = DW_EH_PE_ABSPTR;
    let mut lsda_encoding = None;
    let mut personality = None;
    let text_rel_base = 0usize;
    let data_rel_base = 0usize;
    if augmentation.first() == Some(&b'z') {
        let (augmentation_data_len, augmentation_data) = decode_uleb128(eh_frame, cursor)?;
        let augmentation_end = augmentation_data
            .checked_add(augmentation_data_len)
            .ok_or(OwnedUnwindDecodeError::Overflow)?;
        if augmentation_end > record.end {
            return Err(OwnedUnwindDecodeError::Truncated);
        }
        let mut augmentation_cursor = augmentation_data;
        for item in augmentation.iter().copied().skip(1) {
            match item {
                b'L' => {
                    let (encoding, after_encoding) = read_u8(eh_frame, augmentation_cursor)?;
                    lsda_encoding = Some(encoding);
                    augmentation_cursor = after_encoding;
                }
                b'P' => {
                    let (encoding, after_encoding) = read_u8(eh_frame, augmentation_cursor)?;
                    let field_addr = section_addr
                        .checked_add(after_encoding)
                        .ok_or(OwnedUnwindDecodeError::Overflow)?;
                    let (decoded, after_personality) = read_encoded_pointer(
                        eh_frame,
                        after_encoding,
                        field_addr,
                        encoding,
                        resolve_indirect,
                        text_rel_base,
                        data_rel_base,
                    )?;
                    personality = Some(decoded);
                    augmentation_cursor = after_personality;
                }
                b'R' => {
                    let (encoding, after_encoding) = read_u8(eh_frame, augmentation_cursor)?;
                    fde_pointer_encoding = encoding;
                    augmentation_cursor = after_encoding;
                }
                other => return Err(OwnedUnwindDecodeError::UnsupportedAugmentation(other)),
            }
        }
        if augmentation_cursor > augmentation_end {
            return Err(OwnedUnwindDecodeError::Truncated);
        }
        cursor = augmentation_end;
    } else if !augmentation.is_empty() {
        return Err(OwnedUnwindDecodeError::UnsupportedAugmentation(
            augmentation[0],
        ));
    }

    let cfi_start = cursor;
    validate_cfi_program(eh_frame, cfi_start, record.end)?;
    Ok(OwnedCieRecord {
        offset: record.offset,
        code_alignment_factor,
        data_alignment_factor,
        return_address_register,
        has_z_augmentation: augmentation.first() == Some(&b'z'),
        lsda_encoding,
        personality,
        fde_pointer_encoding,
        text_rel_base,
        data_rel_base,
        cfi_start,
        cfi_end: record.end,
    })
}

fn parse_fde_record(
    eh_frame: &[u8],
    section_addr: usize,
    record: EhFrameRecord,
    cies: &[OwnedCieRecord],
    resolve_indirect: bool,
) -> Result<OwnedFdeRecord, OwnedUnwindDecodeError> {
    let cie_pointer_offset = record.body - 4;
    let cie_offset = cie_pointer_offset
        .checked_sub(record.cie_pointer_or_id as usize)
        .ok_or(OwnedUnwindDecodeError::MalformedRecord)?;
    let cie = cies
        .iter()
        .rev()
        .find(|cie| cie.offset == cie_offset)
        .ok_or(OwnedUnwindDecodeError::MissingCie)?;

    let pc_field = record.body;
    let (pc_begin, cursor) = read_encoded_pointer(
        eh_frame,
        pc_field,
        section_addr
            .checked_add(pc_field)
            .ok_or(OwnedUnwindDecodeError::Overflow)?,
        cie.fde_pointer_encoding,
        resolve_indirect,
        cie.text_rel_base,
        cie.data_rel_base,
    )?;
    let (pc_range, mut cursor) = read_encoded_range(eh_frame, cursor, cie.fde_pointer_encoding)?;
    let mut language_specific_data = None;
    if cie.has_z_augmentation {
        let (augmentation_len, augmentation_data) = decode_uleb128(eh_frame, cursor)?;
        let augmentation_end = augmentation_data
            .checked_add(augmentation_len)
            .ok_or(OwnedUnwindDecodeError::Overflow)?;
        if augmentation_end > record.end {
            return Err(OwnedUnwindDecodeError::Truncated);
        }
        let mut augmentation_cursor = augmentation_data;
        if let Some(encoding) = cie.lsda_encoding
            && encoding != DW_EH_PE_OMIT
        {
            let field_addr = section_addr
                .checked_add(augmentation_cursor)
                .ok_or(OwnedUnwindDecodeError::Overflow)?;
            let (lsda, after_lsda) = read_encoded_pointer(
                eh_frame,
                augmentation_cursor,
                field_addr,
                encoding,
                resolve_indirect,
                cie.text_rel_base,
                cie.data_rel_base,
            )?;
            language_specific_data = Some(lsda);
            augmentation_cursor = after_lsda;
        }
        if augmentation_cursor > augmentation_end {
            return Err(OwnedUnwindDecodeError::Truncated);
        }
        cursor = augmentation_end;
    }
    let fde_cfi_start = cursor;
    let pc_end = pc_begin
        .checked_add(pc_range)
        .ok_or(OwnedUnwindDecodeError::Overflow)?;
    Ok(OwnedFdeRecord {
        pc_begin,
        pc_end,
        cie_offset,
        personality: cie.personality,
        language_specific_data,
        text_rel_base: cie.text_rel_base,
        data_rel_base: cie.data_rel_base,
        code_alignment_factor: cie.code_alignment_factor,
        data_alignment_factor: cie.data_alignment_factor,
        return_address_register: cie.return_address_register,
        cie_cfi_start: cie.cfi_start,
        cie_cfi_end: cie.cfi_end,
        fde_cfi_start,
        fde_cfi_end: record.end,
    })
}

fn validate_fde_cfi_program(
    eh_frame: &[u8],
    fde: OwnedFdeRecord,
) -> Result<(), OwnedUnwindDecodeError> {
    validate_cfi_program(eh_frame, fde.fde_cfi_start, fde.fde_cfi_end)
}

fn read_encoded_pointer(
    input: &[u8],
    offset: usize,
    field_addr: usize,
    encoding: u8,
    resolve_indirect: bool,
    text_rel_base: usize,
    data_rel_base: usize,
) -> Result<(usize, usize), OwnedUnwindDecodeError> {
    if encoding == DW_EH_PE_OMIT {
        return Err(OwnedUnwindDecodeError::UnsupportedPointerEncoding(encoding));
    }
    let application = encoding & 0x70;
    if !matches!(
        application,
        0 | DW_EH_PE_PCREL | DW_EH_PE_TEXTREL | DW_EH_PE_DATAREL
    ) {
        return Err(OwnedUnwindDecodeError::UnsupportedPointerEncoding(encoding));
    }

    let (value, cursor) = read_encoded_raw(input, offset, encoding)?;
    let base = match application {
        DW_EH_PE_PCREL => field_addr,
        DW_EH_PE_TEXTREL => text_rel_base,
        DW_EH_PE_DATAREL => data_rel_base,
        _ => 0,
    };
    let value = if base != 0 {
        (base as isize)
            .checked_add(value)
            .ok_or(OwnedUnwindDecodeError::Overflow)?
    } else if application == DW_EH_PE_PCREL {
        (field_addr as isize)
            .checked_add(value)
            .ok_or(OwnedUnwindDecodeError::Overflow)?
    } else {
        value
    };
    if value < 0 {
        return Err(OwnedUnwindDecodeError::Overflow);
    }
    let pointer = value as usize;
    if encoding & DW_EH_PE_INDIRECT == 0 {
        return Ok((pointer, cursor));
    }
    if !resolve_indirect {
        return Ok((pointer, cursor));
    }
    if pointer == 0 || !pointer.is_multiple_of(core::mem::align_of::<usize>()) {
        return Err(OwnedUnwindDecodeError::MalformedRecord);
    }
    // SAFETY: indirect unwind pointers are emitted by the compiler as machine
    // word slots in mapped image memory. Runtime decoding is used only for
    // frame data registered by the current process.
    let resolved = unsafe { core::ptr::read(pointer as *const usize) };
    Ok((resolved, cursor))
}

fn read_encoded_range(
    input: &[u8],
    offset: usize,
    encoding: u8,
) -> Result<(usize, usize), OwnedUnwindDecodeError> {
    if encoding == DW_EH_PE_OMIT || encoding & DW_EH_PE_INDIRECT != 0 {
        return Err(OwnedUnwindDecodeError::UnsupportedPointerEncoding(encoding));
    }
    let application = encoding & 0x70;
    if !matches!(
        application,
        0 | DW_EH_PE_PCREL | DW_EH_PE_TEXTREL | DW_EH_PE_DATAREL
    ) {
        return Err(OwnedUnwindDecodeError::UnsupportedPointerEncoding(encoding));
    }

    let (value, cursor) = read_encoded_raw(input, offset, encoding)?;
    if value < 0 {
        return Err(OwnedUnwindDecodeError::Overflow);
    }
    Ok((value as usize, cursor))
}

fn read_encoded_raw(
    input: &[u8],
    offset: usize,
    encoding: u8,
) -> Result<(isize, usize), OwnedUnwindDecodeError> {
    match encoding & 0x0f {
        DW_EH_PE_ABSPTR => {
            if core::mem::size_of::<usize>() == 8 {
                read_i64(input, offset).map(|(value, cursor)| (value as isize, cursor))
            } else {
                read_i32(input, offset).map(|(value, cursor)| (value as isize, cursor))
            }
        }
        DW_EH_PE_ULEB128 => {
            let (value, cursor) = decode_uleb128(input, offset)?;
            if value > isize::MAX as usize {
                return Err(OwnedUnwindDecodeError::Overflow);
            }
            Ok((value as isize, cursor))
        }
        DW_EH_PE_UDATA2 => read_u16(input, offset).map(|(value, cursor)| (value as isize, cursor)),
        DW_EH_PE_UDATA4 => read_u32(input, offset).map(|(value, cursor)| (value as isize, cursor)),
        DW_EH_PE_UDATA8 => read_u64(input, offset).and_then(|(value, cursor)| {
            if value > isize::MAX as u64 {
                Err(OwnedUnwindDecodeError::Overflow)
            } else {
                Ok((value as isize, cursor))
            }
        }),
        DW_EH_PE_SLEB128 => decode_sleb128(input, offset),
        DW_EH_PE_SDATA2 => read_i16(input, offset).map(|(value, cursor)| (value as isize, cursor)),
        DW_EH_PE_SDATA4 => read_i32(input, offset).map(|(value, cursor)| (value as isize, cursor)),
        DW_EH_PE_SDATA8 => read_i64(input, offset).and_then(|(value, cursor)| {
            if value < isize::MIN as i64 || value > isize::MAX as i64 {
                Err(OwnedUnwindDecodeError::Overflow)
            } else {
                Ok((value as isize, cursor))
            }
        }),
        _ => Err(OwnedUnwindDecodeError::UnsupportedPointerEncoding(encoding)),
    }
}

fn evaluate_cfi_row(
    eh_frame: &[u8],
    fde: OwnedFdeRecord,
    ip: usize,
) -> Result<OwnedCfiRow, OwnedUnwindDecodeError> {
    if ip < fde.pc_begin || ip >= fde.pc_end {
        return Err(OwnedUnwindDecodeError::MalformedRecord);
    }

    let mut initial_state = CfiEvaluationState::new(fde.pc_begin);
    let empty_state = initial_state;
    apply_cfi_program(
        eh_frame,
        fde.cie_cfi_start,
        fde.cie_cfi_end,
        &fde,
        None,
        &mut initial_state,
        &empty_state,
    )?;
    let mut state = initial_state;
    apply_cfi_program(
        eh_frame,
        fde.fde_cfi_start,
        fde.fde_cfi_end,
        &fde,
        Some(ip),
        &mut state,
        &initial_state,
    )?;
    if state.cfa_register == UNSET_DWARF_REGISTER {
        return Err(OwnedUnwindDecodeError::MalformedRecord);
    }

    Ok(OwnedCfiRow {
        pc: ip,
        cfa_register: state.cfa_register,
        cfa_offset: state.cfa_offset,
        return_address_register: fde.return_address_register,
        saved_rip_offset: cfi_rule_offset(state.register_rule(X86_64_DWARF_RIP)),
        saved_rbp_offset: cfi_rule_offset(state.register_rule(X86_64_DWARF_RBP)),
        saved_rsp_offset: cfi_rule_offset(state.register_rule(X86_64_DWARF_RSP)),
    })
}

fn apply_cfi_program(
    input: &[u8],
    mut cursor: usize,
    end: usize,
    fde: &OwnedFdeRecord,
    target_ip: Option<usize>,
    state: &mut CfiEvaluationState,
    initial_state: &CfiEvaluationState,
) -> Result<(), OwnedUnwindDecodeError> {
    let mut saved_states = Vec::new();
    while cursor < end {
        let (opcode, next) = read_u8(input, cursor)?;
        cursor = next;
        match opcode & 0xc0 {
            DW_CFA_ADVANCE_LOC => {
                let delta = (opcode & 0x3f) as usize;
                if advance_cfi_location(state, delta, fde.code_alignment_factor, target_ip)? {
                    return Ok(());
                }
                continue;
            }
            DW_CFA_OFFSET => {
                let register = (opcode & 0x3f) as usize;
                let (offset, after_offset) = decode_uleb128(input, cursor)?;
                cursor = after_offset;
                set_register_offset(state, register, offset, fde.data_alignment_factor)?;
                continue;
            }
            DW_CFA_RESTORE => {
                let register = (opcode & 0x3f) as usize;
                restore_register_rule(state, initial_state, register);
                continue;
            }
            _ => {}
        }

        match opcode {
            DW_CFA_NOP => {}
            DW_CFA_ADVANCE_LOC1 => {
                let (delta, next) = read_u8(input, cursor)?;
                cursor = next;
                if advance_cfi_location(
                    state,
                    delta as usize,
                    fde.code_alignment_factor,
                    target_ip,
                )? {
                    return Ok(());
                }
            }
            DW_CFA_ADVANCE_LOC2 => {
                let (delta, next) = read_u16(input, cursor)?;
                cursor = next;
                if advance_cfi_location(
                    state,
                    delta as usize,
                    fde.code_alignment_factor,
                    target_ip,
                )? {
                    return Ok(());
                }
            }
            DW_CFA_ADVANCE_LOC4 => {
                let (delta, next) = read_u32(input, cursor)?;
                cursor = next;
                if advance_cfi_location(
                    state,
                    delta as usize,
                    fde.code_alignment_factor,
                    target_ip,
                )? {
                    return Ok(());
                }
            }
            DW_CFA_OFFSET_EXTENDED => {
                let (register, after_register) = decode_uleb128(input, cursor)?;
                let (offset, after_offset) = decode_uleb128(input, after_register)?;
                cursor = after_offset;
                set_register_offset(state, register, offset, fde.data_alignment_factor)?;
            }
            DW_CFA_RESTORE_EXTENDED => {
                let (register, next) = decode_uleb128(input, cursor)?;
                cursor = next;
                restore_register_rule(state, initial_state, register);
            }
            DW_CFA_UNDEFINED => {
                let (register, next) = decode_uleb128(input, cursor)?;
                cursor = next;
                set_register_rule(state, register, CfiRegisterRule::Undefined);
            }
            DW_CFA_SAME_VALUE => {
                let (register, next) = decode_uleb128(input, cursor)?;
                cursor = next;
                set_register_rule(state, register, CfiRegisterRule::SameValue);
            }
            DW_CFA_REMEMBER_STATE => saved_states.push(*state),
            DW_CFA_RESTORE_STATE => {
                *state = saved_states
                    .pop()
                    .ok_or(OwnedUnwindDecodeError::MalformedRecord)?;
            }
            DW_CFA_DEF_CFA => {
                let (register, after_register) = decode_uleb128(input, cursor)?;
                let (offset, after_offset) = decode_uleb128(input, after_register)?;
                cursor = after_offset;
                state.cfa_register = register;
                state.cfa_offset = usize_to_isize(offset)?;
            }
            DW_CFA_DEF_CFA_REGISTER => {
                let (register, next) = decode_uleb128(input, cursor)?;
                cursor = next;
                state.cfa_register = register;
            }
            DW_CFA_DEF_CFA_OFFSET => {
                let (offset, next) = decode_uleb128(input, cursor)?;
                cursor = next;
                state.cfa_offset = usize_to_isize(offset)?;
            }
            DW_CFA_DEF_CFA_EXPRESSION | DW_CFA_EXPRESSION | DW_CFA_VAL_EXPRESSION => {
                return Err(OwnedUnwindDecodeError::UnsupportedCfiOpcode(opcode));
            }
            DW_CFA_OFFSET_EXTENDED_SF => {
                let (register, after_register) = decode_uleb128(input, cursor)?;
                let (offset, after_offset) = decode_sleb128(input, after_register)?;
                cursor = after_offset;
                set_register_signed_offset(state, register, offset, fde.data_alignment_factor)?;
            }
            DW_CFA_DEF_CFA_SF => {
                let (register, after_register) = decode_uleb128(input, cursor)?;
                let (offset, after_offset) = decode_sleb128(input, after_register)?;
                cursor = after_offset;
                state.cfa_register = register;
                state.cfa_offset = scale_signed_cfi_offset(offset, fde.data_alignment_factor)?;
            }
            DW_CFA_DEF_CFA_OFFSET_SF => {
                let (offset, next) = decode_sleb128(input, cursor)?;
                cursor = next;
                state.cfa_offset = scale_signed_cfi_offset(offset, fde.data_alignment_factor)?;
            }
            DW_CFA_VAL_OFFSET => {
                let (register, after_register) = decode_uleb128(input, cursor)?;
                let (offset, after_offset) = decode_uleb128(input, after_register)?;
                cursor = after_offset;
                let offset = scale_unsigned_cfi_offset(offset, fde.data_alignment_factor)?;
                set_register_rule(state, register, CfiRegisterRule::ValOffset(offset));
            }
            DW_CFA_VAL_OFFSET_SF => {
                let (register, after_register) = decode_uleb128(input, cursor)?;
                let (offset, after_offset) = decode_sleb128(input, after_register)?;
                cursor = after_offset;
                let offset = scale_signed_cfi_offset(offset, fde.data_alignment_factor)?;
                set_register_rule(state, register, CfiRegisterRule::ValOffset(offset));
            }
            0x2e => {
                cursor = decode_uleb128(input, cursor)?.1;
            }
            other => return Err(OwnedUnwindDecodeError::UnsupportedCfiOpcode(other)),
        }
    }
    if cursor == end {
        Ok(())
    } else {
        Err(OwnedUnwindDecodeError::Truncated)
    }
}

fn advance_cfi_location(
    state: &mut CfiEvaluationState,
    delta: usize,
    code_alignment_factor: usize,
    target_ip: Option<usize>,
) -> Result<bool, OwnedUnwindDecodeError> {
    let scaled = delta
        .checked_mul(code_alignment_factor)
        .ok_or(OwnedUnwindDecodeError::Overflow)?;
    let next_pc = state
        .pc
        .checked_add(scaled)
        .ok_or(OwnedUnwindDecodeError::Overflow)?;
    if target_ip.is_some_and(|target| target < next_pc) {
        return Ok(true);
    }
    state.pc = next_pc;
    Ok(false)
}

fn set_register_offset(
    state: &mut CfiEvaluationState,
    register: usize,
    offset: usize,
    data_alignment_factor: isize,
) -> Result<(), OwnedUnwindDecodeError> {
    let scaled = scale_unsigned_cfi_offset(offset, data_alignment_factor)?;
    set_register_rule(state, register, CfiRegisterRule::Offset(scaled));
    Ok(())
}

fn set_register_signed_offset(
    state: &mut CfiEvaluationState,
    register: usize,
    offset: isize,
    data_alignment_factor: isize,
) -> Result<(), OwnedUnwindDecodeError> {
    let scaled = scale_signed_cfi_offset(offset, data_alignment_factor)?;
    set_register_rule(state, register, CfiRegisterRule::Offset(scaled));
    Ok(())
}

fn set_register_rule(state: &mut CfiEvaluationState, register: usize, rule: CfiRegisterRule) {
    if register < MAX_TRACKED_DWARF_REGISTERS {
        state.register_rules[register] = rule;
    }
}

fn restore_register_rule(
    state: &mut CfiEvaluationState,
    initial_state: &CfiEvaluationState,
    register: usize,
) {
    if register < MAX_TRACKED_DWARF_REGISTERS {
        state.register_rules[register] = initial_state.register_rules[register];
    }
}

fn scale_unsigned_cfi_offset(
    offset: usize,
    data_alignment_factor: isize,
) -> Result<isize, OwnedUnwindDecodeError> {
    usize_to_isize(offset)?
        .checked_mul(data_alignment_factor)
        .ok_or(OwnedUnwindDecodeError::Overflow)
}

fn scale_signed_cfi_offset(
    offset: isize,
    data_alignment_factor: isize,
) -> Result<isize, OwnedUnwindDecodeError> {
    offset
        .checked_mul(data_alignment_factor)
        .ok_or(OwnedUnwindDecodeError::Overflow)
}

fn usize_to_isize(value: usize) -> Result<isize, OwnedUnwindDecodeError> {
    isize::try_from(value).map_err(|_| OwnedUnwindDecodeError::Overflow)
}

fn cfi_rule_offset(rule: CfiRegisterRule) -> Option<isize> {
    match rule {
        CfiRegisterRule::Offset(offset) => Some(offset),
        CfiRegisterRule::Undefined | CfiRegisterRule::SameValue | CfiRegisterRule::ValOffset(_) => {
            None
        }
    }
}

impl CfiEvaluationState {
    fn new(pc: usize) -> Self {
        Self {
            pc,
            cfa_register: UNSET_DWARF_REGISTER,
            cfa_offset: 0,
            register_rules: [CfiRegisterRule::Undefined; MAX_TRACKED_DWARF_REGISTERS],
        }
    }

    fn register_rule(&self, register: usize) -> CfiRegisterRule {
        self.register_rules
            .get(register)
            .copied()
            .unwrap_or(CfiRegisterRule::Undefined)
    }
}

fn validate_cfi_program(
    input: &[u8],
    mut cursor: usize,
    end: usize,
) -> Result<(), OwnedUnwindDecodeError> {
    while cursor < end {
        let (opcode, next) = read_u8(input, cursor)?;
        cursor = next;
        match opcode & 0xc0 {
            DW_CFA_ADVANCE_LOC | DW_CFA_RESTORE => continue,
            DW_CFA_OFFSET => {
                cursor = decode_uleb128(input, cursor)?.1;
                continue;
            }
            _ => {}
        }

        match opcode {
            0x00 => {}
            0x02 => cursor = skip_bytes(cursor, 1, end)?,
            0x03 => cursor = skip_bytes(cursor, 2, end)?,
            0x04 => cursor = skip_bytes(cursor, 4, end)?,
            0x05 | 0x09 => {
                cursor = decode_uleb128(input, cursor)?.1;
                cursor = decode_uleb128(input, cursor)?.1;
            }
            0x06 | 0x07 | 0x08 | 0x0d | 0x0e | 0x2e => {
                cursor = decode_uleb128(input, cursor)?.1;
            }
            0x0a | 0x0b => {}
            0x0c | 0x14 | 0x2f => {
                cursor = decode_uleb128(input, cursor)?.1;
                cursor = decode_uleb128(input, cursor)?.1;
            }
            0x0f => {
                let (len, after_len) = decode_uleb128(input, cursor)?;
                cursor = skip_bytes(after_len, len, end)?;
            }
            0x10 | 0x16 => {
                cursor = decode_uleb128(input, cursor)?.1;
                let (len, after_len) = decode_uleb128(input, cursor)?;
                cursor = skip_bytes(after_len, len, end)?;
            }
            0x11 | 0x12 | 0x15 => {
                cursor = decode_uleb128(input, cursor)?.1;
                cursor = decode_sleb128(input, cursor)?.1;
            }
            0x13 => cursor = decode_sleb128(input, cursor)?.1,
            other => return Err(OwnedUnwindDecodeError::UnsupportedCfiOpcode(other)),
        }
    }
    if cursor == end {
        Ok(())
    } else {
        Err(OwnedUnwindDecodeError::Truncated)
    }
}

fn decode_uleb128(
    input: &[u8],
    mut offset: usize,
) -> Result<(usize, usize), OwnedUnwindDecodeError> {
    let mut result = 0usize;
    let mut shift = 0u32;
    loop {
        let (byte, next) = read_u8(input, offset)?;
        offset = next;
        let payload = (byte & 0x7f) as usize;
        result = result
            .checked_add(
                payload
                    .checked_shl(shift)
                    .ok_or(OwnedUnwindDecodeError::Overflow)?,
            )
            .ok_or(OwnedUnwindDecodeError::Overflow)?;
        if byte & 0x80 == 0 {
            return Ok((result, offset));
        }
        shift += 7;
        if shift as usize >= usize::BITS as usize {
            return Err(OwnedUnwindDecodeError::Overflow);
        }
    }
}

fn decode_sleb128(
    input: &[u8],
    mut offset: usize,
) -> Result<(isize, usize), OwnedUnwindDecodeError> {
    let mut result = 0isize;
    let mut shift = 0u32;
    let mut byte;
    loop {
        let (read, next) = read_u8(input, offset)?;
        byte = read;
        offset = next;
        result |= ((byte & 0x7f) as isize)
            .checked_shl(shift)
            .ok_or(OwnedUnwindDecodeError::Overflow)?;
        shift += 7;
        if byte & 0x80 == 0 {
            break;
        }
        if shift as usize >= isize::BITS as usize {
            return Err(OwnedUnwindDecodeError::Overflow);
        }
    }

    if shift < isize::BITS && byte & 0x40 != 0 {
        result |= (!0isize)
            .checked_shl(shift)
            .ok_or(OwnedUnwindDecodeError::Overflow)?;
    }
    Ok((result, offset))
}

fn read_c_string(
    input: &[u8],
    offset: usize,
    end: usize,
) -> Result<(&[u8], usize), OwnedUnwindDecodeError> {
    let mut cursor = offset;
    while cursor < end {
        if input[cursor] == 0 {
            return Ok((&input[offset..cursor], cursor + 1));
        }
        cursor += 1;
    }
    Err(OwnedUnwindDecodeError::UnterminatedAugmentation)
}

fn skip_bytes(offset: usize, len: usize, end: usize) -> Result<usize, OwnedUnwindDecodeError> {
    let next = offset
        .checked_add(len)
        .ok_or(OwnedUnwindDecodeError::Overflow)?;
    if next > end {
        Err(OwnedUnwindDecodeError::Truncated)
    } else {
        Ok(next)
    }
}

fn read_u8(input: &[u8], offset: usize) -> Result<(u8, usize), OwnedUnwindDecodeError> {
    let byte = *input.get(offset).ok_or(OwnedUnwindDecodeError::Truncated)?;
    Ok((byte, offset + 1))
}

fn read_u16(input: &[u8], offset: usize) -> Result<(u16, usize), OwnedUnwindDecodeError> {
    let bytes = read_array::<2>(input, offset)?;
    Ok((u16::from_le_bytes(bytes), offset + 2))
}

fn read_i16(input: &[u8], offset: usize) -> Result<(i16, usize), OwnedUnwindDecodeError> {
    let bytes = read_array::<2>(input, offset)?;
    Ok((i16::from_le_bytes(bytes), offset + 2))
}

fn read_u32(input: &[u8], offset: usize) -> Result<(u32, usize), OwnedUnwindDecodeError> {
    let bytes = read_array::<4>(input, offset)?;
    Ok((u32::from_le_bytes(bytes), offset + 4))
}

fn read_i32(input: &[u8], offset: usize) -> Result<(i32, usize), OwnedUnwindDecodeError> {
    let bytes = read_array::<4>(input, offset)?;
    Ok((i32::from_le_bytes(bytes), offset + 4))
}

fn read_u64(input: &[u8], offset: usize) -> Result<(u64, usize), OwnedUnwindDecodeError> {
    let bytes = read_array::<8>(input, offset)?;
    Ok((u64::from_le_bytes(bytes), offset + 8))
}

fn read_i64(input: &[u8], offset: usize) -> Result<(i64, usize), OwnedUnwindDecodeError> {
    let bytes = read_array::<8>(input, offset)?;
    Ok((i64::from_le_bytes(bytes), offset + 8))
}

fn read_array<const N: usize>(
    input: &[u8],
    offset: usize,
) -> Result<[u8; N], OwnedUnwindDecodeError> {
    let end = offset
        .checked_add(N)
        .ok_or(OwnedUnwindDecodeError::Overflow)?;
    let bytes = input
        .get(offset..end)
        .ok_or(OwnedUnwindDecodeError::Truncated)?;
    bytes
        .try_into()
        .map_err(|_| OwnedUnwindDecodeError::Truncated)
}

#[inline]
fn valid_frame_pointer(frame_pointer: usize, stack_pointer: usize, stack_limit: usize) -> bool {
    frame_pointer >= stack_pointer
        && frame_pointer < stack_limit
        && frame_pointer.is_multiple_of(core::mem::align_of::<usize>())
}

#[inline]
fn read_word(addr: usize) -> Option<usize> {
    if addr == 0 || !addr.is_multiple_of(core::mem::align_of::<usize>()) {
        return None;
    }
    // SAFETY: callers restrict reads to the current thread stack window and to
    // aligned machine-word slots in the frame-pointer chain.
    Some(unsafe { core::ptr::read(addr as *const usize) })
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn current_frame_pointer() -> usize {
    let frame_pointer: usize;
    unsafe {
        // SAFETY: this is a register read only.
        core::arch::asm!("mov {}, rbp", out(reg) frame_pointer, options(nomem, nostack, preserves_flags));
    }
    frame_pointer
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn current_frame_pointer() -> usize {
    let frame_pointer: usize;
    unsafe {
        // SAFETY: this is a register read only.
        core::arch::asm!("mov {}, x29", out(reg) frame_pointer, options(nomem, nostack, preserves_flags));
    }
    frame_pointer
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn current_stack_pointer() -> usize {
    let stack_pointer: usize;
    unsafe {
        // SAFETY: this is a register read only.
        core::arch::asm!("mov {}, rsp", out(reg) stack_pointer, options(nomem, nostack, preserves_flags));
    }
    stack_pointer
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn current_stack_pointer() -> usize {
    let stack_pointer: usize;
    unsafe {
        // SAFETY: this is a register read only.
        core::arch::asm!("mov {}, sp", out(reg) stack_pointer, options(nomem, nostack, preserves_flags));
    }
    stack_pointer
}
