//! Opt-in owned `_Unwind_*` substitutes for standalone artifact experiments.
//!
//! These symbols are intentionally gated behind `standalone,owned-unwind-stub`.
//! They are not a general unwinder. The experiment lane can now perform a
//! bounded phase-1 search over registered `.eh_frame` data and invoke frame
//! personalities with LSDA/region context. Phase-2 cleanup personalities can
//! mutate an owned cursor, and x86_64 handler frames now have a guarded
//! landing-pad transfer path that validates the physical frame cursor before
//! installing the requested IP/register state.

#![allow(non_snake_case, dead_code)]

use std::ffi::{c_int, c_void};
use std::io::Write as _;
use std::sync::{Mutex, MutexGuard};

type UnwindReasonCode = c_int;
type UnwindAction = c_int;
type UnwindExceptionClass = u64;
type UnwindWord = usize;

const URC_NO_REASON: UnwindReasonCode = 0;
const URC_FATAL_PHASE2_ERROR: UnwindReasonCode = 2;
const URC_FATAL_PHASE1_ERROR: UnwindReasonCode = 3;
const URC_NORMAL_STOP: UnwindReasonCode = 4;
const URC_END_OF_STACK: UnwindReasonCode = 5;
const URC_HANDLER_FOUND: UnwindReasonCode = 6;
const URC_INSTALL_CONTEXT: UnwindReasonCode = 7;
const URC_CONTINUE_UNWIND: UnwindReasonCode = 8;
const UA_SEARCH_PHASE: UnwindAction = 1;
const UA_CLEANUP_PHASE: UnwindAction = 2;
const UA_HANDLER_FRAME: UnwindAction = 4;
const UA_FORCE_UNWIND: UnwindAction = 8;
const UA_END_OF_STACK: UnwindAction = 16;
const FRAME_REGISTRY_SLOTS: usize = 128;
const MAX_BACKTRACE_FRAMES: usize = 64;
const MAX_STACK_SCAN_BYTES: usize = 8 * 1024 * 1024;
const MAX_REGISTERED_EH_FRAME_BYTES: usize = 2 * 1024 * 1024;
const MAX_REGISTERED_EH_FRAME_RECORDS: usize = 16 * 1024;
const MAX_LOADED_OBJECT_PHDRS: usize = 256;
const PT_LOAD: u32 = 1;
const PT_GNU_EH_FRAME: u32 = 0x6474_e550;
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
const X86_64_DWARF_RBX: usize = 3;
const X86_64_DWARF_RBP: usize = 6;
const X86_64_DWARF_RSP: usize = 7;
const X86_64_DWARF_R12: usize = 12;
const X86_64_DWARF_R13: usize = 13;
const X86_64_DWARF_R14: usize = 14;
const X86_64_DWARF_R15: usize = 15;
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

pub type UnwindStopFn = Option<
    unsafe extern "C-unwind" fn(
        version: c_int,
        actions: UnwindAction,
        exception_class: UnwindExceptionClass,
        exception_object: *mut UnwindException,
        context: *mut UnwindContext,
        stop_parameter: *mut c_void,
    ) -> UnwindReasonCode,
>;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct X86PhysicalCursor {
    pub ip: usize,
    pub rsp: usize,
    pub rbp: usize,
    pub rbx: usize,
    pub r12: usize,
    pub r13: usize,
    pub r14: usize,
    pub r15: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct X86LandingPadRegisters {
    ip: usize,
    rsp: usize,
    rbp: usize,
    rbx: usize,
    r12: usize,
    r13: usize,
    r14: usize,
    r15: usize,
    rax: usize,
    rdx: usize,
}

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
    Register(usize),
}

#[derive(Clone, Copy)]
struct CfiEvaluationState {
    pc: usize,
    cfa_register: usize,
    cfa_offset: isize,
    gnu_args_size: usize,
    register_rules: [CfiRegisterRule; MAX_TRACKED_DWARF_REGISTERS],
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OwnedEhFrameSummary {
    pub fde_count: usize,
    pub personality_fde_count: usize,
    pub lsda_fde_count: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnedLoadedEhFrameRange {
    pub object_base: usize,
    pub load_start: usize,
    pub load_end: usize,
    pub eh_frame_hdr_start: usize,
    pub eh_frame_hdr_len: usize,
}

#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnedProgramHeaderForTests {
    pub p_type: u32,
    pub p_vaddr: usize,
    pub p_memsz: usize,
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
    cfa: UnwindWord,
    language_specific_data: UnwindWord,
    region_start: UnwindWord,
    text_rel_base: UnwindWord,
    data_rel_base: UnwindWord,
    general_registers: [UnwindWord; MAX_UNWIND_GR],
    physical_cursor: Option<X86PhysicalCursor>,
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

#[cfg(all(
    target_arch = "x86_64",
    any(debug_assertions, feature = "owned-unwind-stub")
))]
#[cfg_attr(
    all(debug_assertions, feature = "owned-unwind-stub"),
    unsafe(no_mangle)
)]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C" fn _Unwind_Backtrace(
    _trace: UnwindTraceFn,
    _trace_argument: *mut c_void,
) -> UnwindReasonCode {
    std::arch::naked_asm!(
        "sub rsp, 72",
        "mov rax, [rsp + 72]",
        "mov [rsp + 0], rax",
        "lea rax, [rsp + 80]",
        "mov [rsp + 8], rax",
        "mov [rsp + 16], rbp",
        "mov [rsp + 24], rbx",
        "mov [rsp + 32], r12",
        "mov [rsp + 40], r13",
        "mov [rsp + 48], r14",
        "mov [rsp + 56], r15",
        "mov rdx, rsp",
        "call {helper}",
        "add rsp, 72",
        "ret",
        helper = sym __frankenlibc_owned_backtrace_from_cursor,
    );
}

#[cfg(all(
    not(target_arch = "x86_64"),
    any(debug_assertions, feature = "owned-unwind-stub")
))]
#[cfg_attr(
    all(debug_assertions, feature = "owned-unwind-stub"),
    unsafe(no_mangle)
)]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _Unwind_Backtrace(
    trace: UnwindTraceFn,
    trace_argument: *mut c_void,
) -> UnwindReasonCode {
    owned_backtrace_from_frame_pointer(
        trace,
        trace_argument,
        current_frame_pointer(),
        current_stack_pointer(),
    )
}

extern "C" fn __frankenlibc_owned_backtrace_from_cursor(
    trace: UnwindTraceFn,
    trace_argument: *mut c_void,
    cursor_ptr: *const X86PhysicalCursor,
) -> UnwindReasonCode {
    let Some(trace_fn) = trace else {
        return URC_END_OF_STACK;
    };
    if cursor_ptr.is_null() {
        return URC_END_OF_STACK;
    }
    // SAFETY: cursor_ptr points to the 64-byte stack-allocated X86PhysicalCursor
    // initialized by the naked trampoline above.
    let mut cursor = unsafe { *cursor_ptr };
    for frame_index in 0..MAX_BACKTRACE_FRAMES {
        if cursor.ip == 0 {
            break;
        }
        let lookup_ip = frame_lookup_ip(cursor.ip);
        let mut context = match find_registered_fde_record_for_ip(lookup_ip) {
            Ok(Some(record)) => {
                context_for_cursor_record(cursor, frame_index, lookup_ip, Some(&record))
            }
            _ => context_for_cursor_record(cursor, frame_index, lookup_ip, None),
        };
        // SAFETY: context is a live stack-local UnwindContext for this callback.
        let reason = unsafe { trace_fn(&mut context, trace_argument) };
        if reason != URC_NO_REASON {
            return reason;
        }
        match step_x86_64_cursor(cursor) {
            Ok(Some(next)) => cursor = next,
            Ok(None) | Err(_) => break,
        }
    }
    URC_END_OF_STACK
}

fn owned_backtrace_from_frame_pointer(
    trace: UnwindTraceFn,
    trace_argument: *mut c_void,
    mut frame_pointer: usize,
    stack_pointer: usize,
) -> UnwindReasonCode {
    let Some(trace_fn) = trace else {
        return URC_END_OF_STACK;
    };
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
            let cfa = frame_pointer.saturating_add(2 * core::mem::size_of::<usize>());
            let mut context = UnwindContext {
                ip: instruction_pointer,
                frame_index,
                frame_pointer,
                stack_pointer,
                cfa,
                language_specific_data: 0,
                region_start: 0,
                text_rel_base: 0,
                data_rel_base: 0,
                general_registers: empty_general_registers(),
                physical_cursor: None,
            };
            // SAFETY: stack-local context remains valid for the trace callback.
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

#[cfg(any(debug_assertions, feature = "owned-unwind-stub"))]
#[cfg_attr(
    all(debug_assertions, feature = "owned-unwind-stub"),
    unsafe(no_mangle)
)]
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

#[inline]
pub(crate) unsafe fn owned_get_cfa_raw(ctx: *mut c_void) -> UnwindWord {
    if ctx.is_null() {
        return 0;
    }
    // SAFETY: non-null contexts are owned by this module during unwind stop or
    // personality callbacks. `cfa` holds the frame's DWARF Canonical Frame
    // Address matching libgcc's `_Unwind_GetCFA(context)` (`context->cfa`).
    unsafe { (*(ctx.cast::<UnwindContext>())).cfa }
}

#[cfg(any(debug_assertions, feature = "owned-unwind-stub"))]
#[cfg_attr(
    all(debug_assertions, feature = "owned-unwind-stub"),
    unsafe(no_mangle)
)]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _Unwind_GetCFA(ctx: *mut UnwindContext) -> UnwindWord {
    // SAFETY: delegates to null-checked owned_get_cfa_raw.
    unsafe { owned_get_cfa_raw(ctx.cast()) }
}

#[cfg(any(debug_assertions, feature = "owned-unwind-stub"))]
#[cfg_attr(
    all(debug_assertions, feature = "owned-unwind-stub"),
    unsafe(no_mangle)
)]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _Unwind_GetDataRelBase(ctx: *mut UnwindContext) -> UnwindWord {
    if ctx.is_null() {
        return 0;
    }
    // SAFETY: non-null contexts are owned by this module during personality
    // calls or supplied by ABI peers following the opaque context contract.
    unsafe { (*ctx).data_rel_base }
}

#[cfg(any(debug_assertions, feature = "owned-unwind-stub"))]
#[cfg_attr(
    all(debug_assertions, feature = "owned-unwind-stub"),
    unsafe(no_mangle)
)]
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

#[cfg(any(debug_assertions, feature = "owned-unwind-stub"))]
#[cfg_attr(
    all(debug_assertions, feature = "owned-unwind-stub"),
    unsafe(no_mangle)
)]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _Unwind_GetIP(ctx: *mut UnwindContext) -> UnwindWord {
    if ctx.is_null() {
        return 0;
    }
    // SAFETY: non-null contexts are created by this module while walking frames
    // or provided by an ABI peer following the opaque _Unwind_Context contract.
    unsafe { (*ctx).ip }
}

#[cfg(any(debug_assertions, feature = "owned-unwind-stub"))]
#[cfg_attr(
    all(debug_assertions, feature = "owned-unwind-stub"),
    unsafe(no_mangle)
)]
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

#[cfg(any(debug_assertions, feature = "owned-unwind-stub"))]
#[cfg_attr(
    all(debug_assertions, feature = "owned-unwind-stub"),
    unsafe(no_mangle)
)]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _Unwind_GetLanguageSpecificData(ctx: *mut UnwindContext) -> *mut c_void {
    if ctx.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: mirrors _Unwind_GetIP's opaque-context handling.
    unsafe { (*ctx).language_specific_data as *mut c_void }
}

#[cfg(any(debug_assertions, feature = "owned-unwind-stub"))]
#[cfg_attr(
    all(debug_assertions, feature = "owned-unwind-stub"),
    unsafe(no_mangle)
)]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _Unwind_GetRegionStart(ctx: *mut UnwindContext) -> UnwindWord {
    if ctx.is_null() {
        return 0;
    }
    // SAFETY: mirrors _Unwind_GetIP's opaque-context handling.
    unsafe { (*ctx).region_start }
}

#[cfg(any(debug_assertions, feature = "owned-unwind-stub"))]
#[cfg_attr(
    all(debug_assertions, feature = "owned-unwind-stub"),
    unsafe(no_mangle)
)]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _Unwind_GetTextRelBase(ctx: *mut UnwindContext) -> UnwindWord {
    if ctx.is_null() {
        return 0;
    }
    // SAFETY: mirrors _Unwind_GetIP's opaque-context handling.
    unsafe { (*ctx).text_rel_base }
}

#[cfg(all(
    target_arch = "x86_64",
    any(debug_assertions, feature = "owned-unwind-stub")
))]
#[cfg_attr(
    all(debug_assertions, feature = "owned-unwind-stub"),
    unsafe(no_mangle)
)]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C-unwind" fn _Unwind_RaiseException(
    _exception: *mut UnwindException,
) -> UnwindReasonCode {
    std::arch::naked_asm!(
        "sub rsp, 72",
        "mov rax, [rsp + 72]",
        "mov [rsp + 0], rax",
        "lea rax, [rsp + 80]",
        "mov [rsp + 8], rax",
        "mov [rsp + 16], rbp",
        "mov [rsp + 24], rbx",
        "mov [rsp + 32], r12",
        "mov [rsp + 40], r13",
        "mov [rsp + 48], r14",
        "mov [rsp + 56], r15",
        "mov rsi, rsp",
        "call {helper}",
        "add rsp, 72",
        "ret",
        helper = sym __frankenlibc_owned_raise_exception_from_cursor,
    );
}

#[cfg(all(
    not(target_arch = "x86_64"),
    any(debug_assertions, feature = "owned-unwind-stub")
))]
#[cfg_attr(
    all(debug_assertions, feature = "owned-unwind-stub"),
    unsafe(no_mangle)
)]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C-unwind" fn _Unwind_RaiseException(
    _exception: *mut UnwindException,
) -> UnwindReasonCode {
    URC_END_OF_STACK
}

extern "C-unwind" fn __frankenlibc_owned_raise_exception_from_cursor(
    exception: *mut UnwindException,
    cursor_ptr: *const X86PhysicalCursor,
) -> UnwindReasonCode {
    if cursor_ptr.is_null() {
        return URC_FATAL_PHASE1_ERROR;
    }
    // SAFETY: cursor_ptr points to the stack-allocated X86PhysicalCursor in the naked stub.
    let cursor = unsafe { *cursor_ptr };
    owned_raise_exception_from_cursor(exception, cursor)
}

fn owned_raise_exception_from_cursor(
    exception: *mut UnwindException,
    cursor: X86PhysicalCursor,
) -> UnwindReasonCode {
    trace_owned_unwind(format_args!(
        "raise exception={exception:p} ip={:#x} rsp={:#x} rbp={:#x}",
        cursor.ip, cursor.rsp, cursor.rbp
    ));
    emit_owned_unwind_jsonl("raise_enter", 0, cursor.ip, cursor.rsp, 0);
    match owned_phase1_search_from_cursor(exception, cursor) {
        OwnedPhase1CursorOutcome::HandlerFound {
            frame_index,
            ip,
            handler_cfa,
        } => {
            trace_owned_unwind(format_args!(
                "phase1 handler frame_index={frame_index} ip={ip:#x} cfa={handler_cfa:#x}"
            ));
            if !exception.is_null() {
                // SAFETY: private_1 == 0 marks normal exception unwinding;
                // private_2 records the target handler frame's canonical stack pointer.
                unsafe {
                    (*exception).private_1 = 0;
                    (*exception).private_2 = handler_cfa;
                }
            }
            owned_phase2_cleanup_from_cursor(exception, handler_cfa, cursor)
        }
        OwnedPhase1CursorOutcome::NoHandler => {
            trace_owned_unwind(format_args!("phase1 no handler"));
            emit_owned_unwind_jsonl(
                "raise_no_handler",
                0,
                cursor.ip,
                cursor.rsp,
                URC_END_OF_STACK,
            );
            URC_END_OF_STACK
        }
        OwnedPhase1CursorOutcome::Fatal { frame_index, code } => {
            trace_owned_unwind(format_args!(
                "phase1 fatal frame_index={frame_index} code={code}"
            ));
            emit_owned_unwind_jsonl("raise_fatal", frame_index, cursor.ip, cursor.rsp, code);
            code
        }
    }
}

#[cfg(all(
    target_arch = "x86_64",
    any(debug_assertions, feature = "owned-unwind-stub")
))]
#[cfg_attr(
    all(debug_assertions, feature = "owned-unwind-stub"),
    unsafe(no_mangle)
)]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C-unwind" fn _Unwind_ForcedUnwind(
    _exception: *mut UnwindException,
    _stop: UnwindStopFn,
    _stop_parameter: *mut c_void,
) -> UnwindReasonCode {
    std::arch::naked_asm!(
        "sub rsp, 72",
        "mov rax, [rsp + 72]",
        "mov [rsp + 0], rax",
        "lea rax, [rsp + 80]",
        "mov [rsp + 8], rax",
        "mov [rsp + 16], rbp",
        "mov [rsp + 24], rbx",
        "mov [rsp + 32], r12",
        "mov [rsp + 40], r13",
        "mov [rsp + 48], r14",
        "mov [rsp + 56], r15",
        "mov rcx, rsp",
        "call {helper}",
        "add rsp, 72",
        "ret",
        helper = sym __frankenlibc_owned_forced_unwind_from_cursor,
    );
}

#[cfg(all(
    not(target_arch = "x86_64"),
    any(debug_assertions, feature = "owned-unwind-stub")
))]
#[cfg_attr(
    all(debug_assertions, feature = "owned-unwind-stub"),
    unsafe(no_mangle)
)]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C-unwind" fn _Unwind_ForcedUnwind(
    _exception: *mut UnwindException,
    _stop: UnwindStopFn,
    _stop_parameter: *mut c_void,
) -> UnwindReasonCode {
    URC_FATAL_PHASE2_ERROR
}

#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
pub(crate) unsafe extern "C-unwind" fn owned_forced_unwind_entry(
    _exception: *mut UnwindException,
    _stop: UnwindStopFn,
    _stop_parameter: *mut c_void,
) -> UnwindReasonCode {
    std::arch::naked_asm!(
        "sub rsp, 72",
        "mov rax, [rsp + 72]",
        "mov [rsp + 0], rax",
        "lea rax, [rsp + 80]",
        "mov [rsp + 8], rax",
        "mov [rsp + 16], rbp",
        "mov [rsp + 24], rbx",
        "mov [rsp + 32], r12",
        "mov [rsp + 40], r13",
        "mov [rsp + 48], r14",
        "mov [rsp + 56], r15",
        "mov rcx, rsp",
        "call {helper}",
        "add rsp, 72",
        "ret",
        helper = sym __frankenlibc_owned_forced_unwind_from_cursor,
    );
}

#[cfg(not(target_arch = "x86_64"))]
pub(crate) unsafe extern "C-unwind" fn owned_forced_unwind_entry(
    _exception: *mut UnwindException,
    _stop: UnwindStopFn,
    _stop_parameter: *mut c_void,
) -> UnwindReasonCode {
    URC_FATAL_PHASE2_ERROR
}

extern "C-unwind" fn __frankenlibc_owned_forced_unwind_from_cursor(
    exception: *mut UnwindException,
    stop: UnwindStopFn,
    stop_parameter: *mut c_void,
    cursor_ptr: *const X86PhysicalCursor,
) -> UnwindReasonCode {
    if exception.is_null() || cursor_ptr.is_null() {
        return URC_FATAL_PHASE2_ERROR;
    }
    let Some(stop_fn) = stop else {
        return URC_FATAL_PHASE2_ERROR;
    };
    // SAFETY: cursor_ptr points to the stack-allocated X86PhysicalCursor in the naked stub,
    // and exception points to caller-owned 32-byte unwind header storage.
    let cursor = unsafe { *cursor_ptr };
    unsafe {
        (*exception).private_1 = stop_fn as usize;
        (*exception).private_2 = stop_parameter as usize;
    }
    emit_owned_unwind_jsonl("forced_unwind_enter", 0, cursor.ip, cursor.rsp, 0);
    owned_forced_unwind_from_cursor(exception, stop_fn, stop_parameter, cursor)
}

#[cfg(all(
    target_arch = "x86_64",
    any(debug_assertions, feature = "owned-unwind-stub")
))]
#[cfg_attr(
    all(debug_assertions, feature = "owned-unwind-stub"),
    unsafe(no_mangle)
)]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C-unwind" fn _Unwind_Resume(_exception: *mut UnwindException) -> ! {
    std::arch::naked_asm!(
        "sub rsp, 72",
        "mov rax, [rsp + 72]",
        "mov [rsp + 0], rax",
        "lea rax, [rsp + 80]",
        "mov [rsp + 8], rax",
        "mov [rsp + 16], rbp",
        "mov [rsp + 24], rbx",
        "mov [rsp + 32], r12",
        "mov [rsp + 40], r13",
        "mov [rsp + 48], r14",
        "mov [rsp + 56], r15",
        "mov rsi, rsp",
        "call {helper}",
        "ud2",
        helper = sym __frankenlibc_owned_resume_from_cursor,
    );
}

#[cfg(all(
    not(target_arch = "x86_64"),
    any(debug_assertions, feature = "owned-unwind-stub")
))]
#[cfg_attr(
    all(debug_assertions, feature = "owned-unwind-stub"),
    unsafe(no_mangle)
)]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C-unwind" fn _Unwind_Resume(_exception: *mut UnwindException) -> ! {
    std::process::abort()
}

extern "C-unwind" fn __frankenlibc_owned_resume_from_cursor(
    exception: *mut UnwindException,
    cursor_ptr: *const X86PhysicalCursor,
) -> ! {
    if exception.is_null() || cursor_ptr.is_null() {
        std::process::abort();
    }
    // SAFETY: cursor_ptr points to the naked trampoline's X86PhysicalCursor, which
    // describes the cleanup landing pad frame that just finished running and called
    // `_Unwind_Resume`. Step ONE frame outward into its caller before continuing.
    let resume_frame_cursor = unsafe { *cursor_ptr };
    trace_owned_unwind(format_args!(
        "resume exception={exception:p} from_ip={:#x} from_rsp={:#x}",
        resume_frame_cursor.ip, resume_frame_cursor.rsp
    ));
    emit_owned_unwind_jsonl(
        "resume_enter",
        0,
        resume_frame_cursor.ip,
        resume_frame_cursor.rsp,
        0,
    );

    let (private_1, private_2, exception_class) = unsafe {
        (
            (*exception).private_1,
            (*exception).private_2,
            (*exception).exception_class,
        )
    };

    match step_x86_64_cursor(resume_frame_cursor) {
        Ok(Some(caller_cursor)) => {
            let result = if private_1 != 0 {
                // SAFETY: `private_1` was populated with a validated `UnwindStopFn`
                // pointer in `__frankenlibc_owned_forced_unwind_from_cursor`.
                let stop_fn: unsafe extern "C-unwind" fn(
                    c_int,
                    UnwindAction,
                    UnwindExceptionClass,
                    *mut UnwindException,
                    *mut UnwindContext,
                    *mut c_void,
                ) -> UnwindReasonCode = unsafe { core::mem::transmute(private_1) };
                owned_forced_unwind_from_cursor(
                    exception,
                    stop_fn,
                    private_2 as *mut c_void,
                    caller_cursor,
                )
            } else {
                owned_phase2_cleanup_from_cursor(exception, private_2, caller_cursor)
            };
            trace_owned_unwind(format_args!("resume unexpectedly returned code={result}"));
            std::process::abort()
        }
        Ok(None) if private_1 != 0 => {
            // Cleanup ran on the outermost stack frame; notify the forced-unwind
            // stop function with UA_END_OF_STACK so thread teardown completes.
            let stop_fn: unsafe extern "C-unwind" fn(
                c_int,
                UnwindAction,
                UnwindExceptionClass,
                *mut UnwindException,
                *mut UnwindContext,
                *mut c_void,
            ) -> UnwindReasonCode = unsafe { core::mem::transmute(private_1) };
            let mut end_ctx = empty_context_at_end(resume_frame_cursor.rsp);
            let _ = unsafe {
                stop_fn(
                    1,
                    UA_FORCE_UNWIND | UA_CLEANUP_PHASE | UA_END_OF_STACK,
                    exception_class,
                    exception,
                    &mut end_ctx,
                    private_2 as *mut c_void,
                )
            };
            std::process::abort()
        }
        Ok(None) | Err(_) => {
            trace_owned_unwind(format_args!("resume failed to step caller cursor"));
            std::process::abort()
        }
    }
}

#[cfg(all(
    target_arch = "x86_64",
    any(debug_assertions, feature = "owned-unwind-stub")
))]
#[cfg_attr(
    all(debug_assertions, feature = "owned-unwind-stub"),
    unsafe(no_mangle)
)]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
#[unsafe(naked)]
pub unsafe extern "C-unwind" fn _Unwind_Resume_or_Rethrow(
    _exception: *mut UnwindException,
) -> UnwindReasonCode {
    std::arch::naked_asm!(
        "sub rsp, 72",
        "mov rax, [rsp + 72]",
        "mov [rsp + 0], rax",
        "lea rax, [rsp + 80]",
        "mov [rsp + 8], rax",
        "mov [rsp + 16], rbp",
        "mov [rsp + 24], rbx",
        "mov [rsp + 32], r12",
        "mov [rsp + 40], r13",
        "mov [rsp + 48], r14",
        "mov [rsp + 56], r15",
        "mov rsi, rsp",
        "call {helper}",
        "add rsp, 72",
        "ret",
        helper = sym __frankenlibc_owned_resume_or_rethrow_from_cursor,
    );
}

#[cfg(all(
    not(target_arch = "x86_64"),
    any(debug_assertions, feature = "owned-unwind-stub")
))]
#[cfg_attr(
    all(debug_assertions, feature = "owned-unwind-stub"),
    unsafe(no_mangle)
)]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C-unwind" fn _Unwind_Resume_or_Rethrow(
    _exception: *mut UnwindException,
) -> UnwindReasonCode {
    URC_END_OF_STACK
}

extern "C-unwind" fn __frankenlibc_owned_resume_or_rethrow_from_cursor(
    exception: *mut UnwindException,
    cursor_ptr: *const X86PhysicalCursor,
) -> UnwindReasonCode {
    if exception.is_null() || cursor_ptr.is_null() {
        return URC_FATAL_PHASE1_ERROR;
    }
    let private_1 = unsafe { (*exception).private_1 };
    if private_1 != 0 {
        // Itanium ABI §1.6.3: for forced unwinding, `_Unwind_Resume_or_Rethrow`
        // behaves identically to `_Unwind_Resume`.
        __frankenlibc_owned_resume_from_cursor(exception, cursor_ptr);
    }
    let cursor = unsafe { *cursor_ptr };
    owned_raise_exception_from_cursor(exception, cursor)
}

#[cfg(any(debug_assertions, feature = "owned-unwind-stub"))]
#[cfg_attr(
    all(debug_assertions, feature = "owned-unwind-stub"),
    unsafe(no_mangle)
)]
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
    // SAFETY: non-null contexts are stack-local owned cursors during phase-2.
    unsafe { (*ctx).general_registers[index] = new_value };
}

#[cfg(any(debug_assertions, feature = "owned-unwind-stub"))]
#[cfg_attr(
    all(debug_assertions, feature = "owned-unwind-stub"),
    unsafe(no_mangle)
)]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _Unwind_SetIP(ctx: *mut UnwindContext, new_value: UnwindWord) {
    if ctx.is_null() {
        return;
    }
    // SAFETY: mirrors _Unwind_SetGR's owned-cursor contract.
    unsafe { (*ctx).ip = new_value };
}

#[cfg(any(debug_assertions, feature = "owned-unwind-stub"))]
#[cfg_attr(
    all(debug_assertions, feature = "owned-unwind-stub"),
    unsafe(no_mangle)
)]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __register_frame(fde: *mut c_void) {
    register_frame(fde as usize, 0);
}

#[cfg(any(debug_assertions, feature = "owned-unwind-stub"))]
#[cfg_attr(
    all(debug_assertions, feature = "owned-unwind-stub"),
    unsafe(no_mangle)
)]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __register_frame_info(fde: *mut c_void, object: *mut c_void) {
    register_frame(fde as usize, object as usize);
}

#[cfg(any(debug_assertions, feature = "owned-unwind-stub"))]
#[cfg_attr(
    all(debug_assertions, feature = "owned-unwind-stub"),
    unsafe(no_mangle)
)]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __deregister_frame(fde: *mut c_void) {
    deregister_frame(fde as usize);
}

#[cfg(any(debug_assertions, feature = "owned-unwind-stub"))]
#[cfg_attr(
    all(debug_assertions, feature = "owned-unwind-stub"),
    unsafe(no_mangle)
)]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __deregister_frame_info(fde: *mut c_void) -> *mut c_void {
    deregister_frame(fde as usize)
        .map(|object| object as *mut c_void)
        .unwrap_or(core::ptr::null_mut())
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    not(debug_assertions),
    not(feature = "standalone"),
    feature = "owned-unwind-stub"
))]
core::arch::global_asm!(
    ".symver _Unwind_DeleteException, _Unwind_DeleteException@@GCC_3.0, remove",
    ".symver _Unwind_ForcedUnwind, _Unwind_ForcedUnwind@@GCC_3.0, remove",
    ".symver _Unwind_GetDataRelBase, _Unwind_GetDataRelBase@@GCC_3.0, remove",
    ".symver _Unwind_GetGR, _Unwind_GetGR@@GCC_3.0, remove",
    ".symver _Unwind_GetIP, _Unwind_GetIP@@GCC_3.0, remove",
    ".symver _Unwind_GetLanguageSpecificData, _Unwind_GetLanguageSpecificData@@GCC_3.0, remove",
    ".symver _Unwind_GetRegionStart, _Unwind_GetRegionStart@@GCC_3.0, remove",
    ".symver _Unwind_GetTextRelBase, _Unwind_GetTextRelBase@@GCC_3.0, remove",
    ".symver _Unwind_RaiseException, _Unwind_RaiseException@@GCC_3.0, remove",
    ".symver _Unwind_Resume, _Unwind_Resume@@GCC_3.0, remove",
    ".symver _Unwind_SetGR, _Unwind_SetGR@@GCC_3.0, remove",
    ".symver _Unwind_SetIP, _Unwind_SetIP@@GCC_3.0, remove",
    ".symver __register_frame, __register_frame@@GCC_3.0, remove",
    ".symver __register_frame_info, __register_frame_info@@GCC_3.0, remove",
    ".symver __deregister_frame, __deregister_frame@@GCC_3.0, remove",
    ".symver __deregister_frame_info, __deregister_frame_info@@GCC_3.0, remove",
    ".symver _Unwind_Backtrace, _Unwind_Backtrace@@GCC_3.3, remove",
    ".symver _Unwind_GetCFA, _Unwind_GetCFA@@GCC_3.3, remove",
    ".symver _Unwind_Resume_or_Rethrow, _Unwind_Resume_or_Rethrow@@GCC_3.3, remove",
    ".symver _Unwind_GetIPInfo, _Unwind_GetIPInfo@@GCC_4.2.0, remove",
);

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
pub fn owned_loaded_eh_frame_ranges_for_tests() -> Vec<OwnedLoadedEhFrameRange> {
    collect_loaded_eh_frame_ranges()
}

#[doc(hidden)]
pub fn owned_loaded_eh_frame_ranges_from_phdrs_for_tests(
    object_base: usize,
    phdrs: &[OwnedProgramHeaderForTests],
) -> Vec<OwnedLoadedEhFrameRange> {
    loaded_eh_frame_ranges_from_phdrs(object_base, phdrs)
}

fn collect_loaded_eh_frame_ranges() -> Vec<OwnedLoadedEhFrameRange> {
    let mut ranges = Vec::new();
    // SAFETY: the callback keeps `ranges` borrowed only for the duration of
    // dl_iterate_phdr. It copies bounded program-header metadata and never
    // retains dynamic-linker pointers after the callback returns.
    unsafe {
        crate::dlfcn_abi::dl_iterate_phdr(
            Some(collect_loaded_eh_frame_ranges_callback),
            (&mut ranges as *mut Vec<OwnedLoadedEhFrameRange>).cast(),
        );
    }
    ranges
}

unsafe extern "C-unwind" fn collect_loaded_eh_frame_ranges_callback(
    info: *mut libc::dl_phdr_info,
    _size: usize,
    data: *mut c_void,
) -> c_int {
    if info.is_null() || data.is_null() {
        return 0;
    }

    // SAFETY: dl_iterate_phdr calls this callback synchronously with the
    // `data` pointer supplied by collect_loaded_eh_frame_ranges.
    let ranges = unsafe { &mut *data.cast::<Vec<OwnedLoadedEhFrameRange>>() };
    // SAFETY: `info` is owned by the dynamic linker for this callback.
    let info = unsafe { &*info };
    let object_base = info.dlpi_addr as usize;
    let phnum = usize::from(info.dlpi_phnum).min(MAX_LOADED_OBJECT_PHDRS);

    if info.dlpi_phdr.is_null() || phnum == 0 {
        return 0;
    }

    let mut phdrs = Vec::with_capacity(phnum);
    for index in 0..phnum {
        // SAFETY: dl_iterate_phdr publishes `dlpi_phnum` entries at
        // `dlpi_phdr` for the callback lifetime. The loop is capped before
        // pointer arithmetic to keep malformed counts bounded.
        if let Some(phdr) = unsafe { copy_dl_phdr(info.dlpi_phdr, index) } {
            phdrs.push(phdr);
        }
    }
    ranges.extend(loaded_eh_frame_ranges_from_phdrs(object_base, &phdrs));
    0
}

#[cfg(target_pointer_width = "64")]
unsafe fn copy_dl_phdr(
    phdrs: *const libc::Elf64_Phdr,
    index: usize,
) -> Option<OwnedProgramHeaderForTests> {
    // SAFETY: caller checked the table length and callback lifetime.
    let phdr = unsafe { *phdrs.add(index) };
    Some(OwnedProgramHeaderForTests {
        p_type: phdr.p_type,
        p_vaddr: phdr.p_vaddr as usize,
        p_memsz: phdr.p_memsz as usize,
    })
}

#[cfg(target_pointer_width = "32")]
unsafe fn copy_dl_phdr(
    phdrs: *const libc::Elf32_Phdr,
    index: usize,
) -> Option<OwnedProgramHeaderForTests> {
    // SAFETY: caller checked the table length and callback lifetime.
    let phdr = unsafe { *phdrs.add(index) };
    Some(OwnedProgramHeaderForTests {
        p_type: phdr.p_type,
        p_vaddr: phdr.p_vaddr as usize,
        p_memsz: phdr.p_memsz as usize,
    })
}

fn loaded_eh_frame_ranges_from_phdrs(
    object_base: usize,
    phdrs: &[OwnedProgramHeaderForTests],
) -> Vec<OwnedLoadedEhFrameRange> {
    let load_ranges: Vec<_> = phdrs
        .iter()
        .filter(|phdr| phdr.p_type == PT_LOAD)
        .filter_map(|phdr| phdr_range(object_base, phdr))
        .collect();

    phdrs
        .iter()
        .filter(|phdr| phdr.p_type == PT_GNU_EH_FRAME)
        .filter_map(|phdr| {
            let (eh_frame_hdr_start, eh_frame_hdr_end) = phdr_range(object_base, phdr)?;
            let header_is_loaded = load_ranges
                .iter()
                .copied()
                .any(|(start, end)| start <= eh_frame_hdr_start && eh_frame_hdr_end <= end);
            if !header_is_loaded {
                return None;
            }
            let load_start = load_ranges.iter().map(|(start, _)| *start).min()?;
            let load_end = load_ranges.iter().map(|(_, end)| *end).max()?;
            Some(OwnedLoadedEhFrameRange {
                object_base,
                load_start,
                load_end,
                eh_frame_hdr_start,
                eh_frame_hdr_len: eh_frame_hdr_end - eh_frame_hdr_start,
            })
        })
        .collect()
}

fn phdr_range(object_base: usize, phdr: &OwnedProgramHeaderForTests) -> Option<(usize, usize)> {
    if phdr.p_memsz == 0 {
        return None;
    }
    let start = object_base.checked_add(phdr.p_vaddr)?;
    let end = start.checked_add(phdr.p_memsz)?;
    (end > start).then_some((start, end))
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

#[derive(Clone, Copy, Debug)]
enum OwnedPhase1CursorOutcome {
    HandlerFound {
        frame_index: usize,
        ip: usize,
        handler_cfa: usize,
    },
    NoHandler,
    Fatal {
        frame_index: usize,
        code: UnwindReasonCode,
    },
}

/// Under `-C panic=abort` (`CARGO_PROFILE_RELEASE_PANIC=abort`), `rustc` emits
/// zero `Drop` cleanup landing pads inside `libfrankenlibc_abi.so` and instead
/// attaches `rust_eh_personality` `panic_cannot_unwind` terminate pads around
/// `extern "C-unwind"` call boundaries (`continue_native_thread_exit`,
/// `pthread_exit`, cancellation sleep helpers, `thread_trampoline`, `qsort`).
/// Treating own-image personalities in `panic = "abort"` builds as unwind-transparent
/// preserves stop callbacks and outer C/C++/Rust application landing pads without
/// requiring `libgcc_s.so.1`.
#[inline]
fn own_panic_abort_frame(lookup_ip: usize) -> bool {
    cfg!(panic = "abort") && crate::pthread_abi::address_is_inside_this_object(lookup_ip)
}

fn owned_phase1_search_from_cursor(
    exception: *mut UnwindException,
    mut cursor: X86PhysicalCursor,
) -> OwnedPhase1CursorOutcome {
    let exception_class = if exception.is_null() {
        0
    } else {
        // SAFETY: non-null exception pointers are supplied by the language runtime.
        unsafe { (*exception).exception_class }
    };

    for frame_index in 0..MAX_BACKTRACE_FRAMES {
        if cursor.ip == 0 {
            break;
        }
        let lookup_ip = frame_lookup_ip(cursor.ip);
        match find_registered_fde_record_for_ip(lookup_ip) {
            Ok(Some(record)) => {
                if let Some(personality) = record.fde.personality
                    && !own_panic_abort_frame(lookup_ip)
                {
                    let mut context =
                        context_for_cursor_record(cursor, frame_index, lookup_ip, Some(&record));
                    let code = call_personality(
                        personality,
                        UA_SEARCH_PHASE,
                        exception_class,
                        exception,
                        &mut context,
                    );
                    emit_owned_unwind_jsonl(
                        "phase1_frame",
                        frame_index,
                        cursor.ip,
                        cursor.rsp,
                        code,
                    );
                    match code {
                        URC_HANDLER_FOUND => {
                            return OwnedPhase1CursorOutcome::HandlerFound {
                                frame_index,
                                ip: cursor.ip,
                                handler_cfa: cursor.rsp,
                            };
                        }
                        URC_CONTINUE_UNWIND | URC_NO_REASON => {}
                        other => {
                            return OwnedPhase1CursorOutcome::Fatal {
                                frame_index,
                                code: other,
                            };
                        }
                    }
                }
            }
            Ok(None) => {}
            Err(_) => {
                return OwnedPhase1CursorOutcome::Fatal {
                    frame_index,
                    code: URC_FATAL_PHASE1_ERROR,
                };
            }
        }
        match step_x86_64_cursor(cursor) {
            Ok(Some(next)) => cursor = next,
            Ok(None) => break,
            Err(_) => {
                return OwnedPhase1CursorOutcome::Fatal {
                    frame_index,
                    code: URC_FATAL_PHASE1_ERROR,
                };
            }
        }
    }

    OwnedPhase1CursorOutcome::NoHandler
}

fn owned_phase2_cleanup_from_cursor(
    exception: *mut UnwindException,
    handler_cfa: usize,
    mut cursor: X86PhysicalCursor,
) -> UnwindReasonCode {
    let exception_class = if exception.is_null() {
        0
    } else {
        // SAFETY: non-null exception pointers are supplied by the language runtime.
        unsafe { (*exception).exception_class }
    };

    for frame_index in 0..MAX_BACKTRACE_FRAMES {
        if cursor.ip == 0 {
            break;
        }
        let is_handler_frame = cursor.rsp == handler_cfa;
        let lookup_ip = frame_lookup_ip(cursor.ip);
        let record = match find_registered_fde_record_for_ip(lookup_ip) {
            Ok(Some(record)) => Some(record),
            Ok(None) => None,
            Err(_) => return URC_FATAL_PHASE2_ERROR,
        };
        if let Some(record) = record
            && let Some(personality) = record.fde.personality
            && !own_panic_abort_frame(lookup_ip)
        {
            let mut context =
                context_for_cursor_record(cursor, frame_index, lookup_ip, Some(&record));
            let mut actions = UA_CLEANUP_PHASE;
            if is_handler_frame {
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
                "phase2 frame_index={frame_index} cfa={:#x} target_cfa={handler_cfa:#x} ip={:#x} actions={actions:#x} code={code} ctx_ip={:#x} gr0={:#x} gr1={:#x}",
                cursor.rsp,
                cursor.ip,
                context.ip,
                context.general_registers[0],
                context.general_registers[1]
            ));
            emit_owned_unwind_jsonl("phase2_frame", frame_index, cursor.ip, cursor.rsp, code);
            match code {
                URC_INSTALL_CONTEXT => {
                    let regs = match prepare_cursor_landing_pad_registers(
                        &context,
                        &record.eh_frame,
                        record.fde,
                        lookup_ip,
                    ) {
                        Ok(regs) => regs,
                        Err(err) => {
                            trace_owned_unwind(format_args!("phase2 install error {err:?}"));
                            return URC_FATAL_PHASE2_ERROR;
                        }
                    };
                    emit_owned_unwind_jsonl(
                        if is_handler_frame {
                            "phase2_install_handler"
                        } else {
                            "phase2_install_cleanup"
                        },
                        frame_index,
                        regs.ip,
                        regs.rsp,
                        URC_INSTALL_CONTEXT,
                    );
                    // SAFETY: `prepare_cursor_landing_pad_registers` validated the
                    // landing pad IP, DWARF CFA row, stack alignment, and restored
                    // callee-saved register cursor for this frame.
                    unsafe { install_landing_pad_registers(regs) };
                }
                URC_CONTINUE_UNWIND | URC_NO_REASON => {
                    if is_handler_frame {
                        return URC_FATAL_PHASE2_ERROR;
                    }
                }
                other => return other,
            }
        } else if is_handler_frame {
            return URC_FATAL_PHASE2_ERROR;
        }

        match step_x86_64_cursor(cursor) {
            Ok(Some(next)) => cursor = next,
            Ok(None) | Err(_) => break,
        }
    }

    URC_FATAL_PHASE2_ERROR
}

fn owned_forced_unwind_from_cursor(
    exception: *mut UnwindException,
    stop_fn: unsafe extern "C-unwind" fn(
        c_int,
        UnwindAction,
        UnwindExceptionClass,
        *mut UnwindException,
        *mut UnwindContext,
        *mut c_void,
    ) -> UnwindReasonCode,
    stop_parameter: *mut c_void,
    mut cursor: X86PhysicalCursor,
) -> UnwindReasonCode {
    let exception_class = if exception.is_null() {
        0
    } else {
        // SAFETY: caller validated non-null exception pointer.
        unsafe { (*exception).exception_class }
    };

    for frame_index in 0..MAX_BACKTRACE_FRAMES {
        if cursor.ip == 0 {
            break;
        }
        let lookup_ip = frame_lookup_ip(cursor.ip);
        let record = match find_registered_fde_record_for_ip(lookup_ip) {
            Ok(Some(record)) => Some(record),
            Ok(None) => None,
            Err(_) => return URC_FATAL_PHASE2_ERROR,
        };
        let mut context =
            context_for_cursor_record(cursor, frame_index, lookup_ip, record.as_ref());
        let frame_cfa = context.cfa;

        // 1. Notify the forced-unwind stop callback BEFORE running this frame's
        // language personality so C cleanup buffers registered inside or deeper
        // than this frame run in exact LIFO stack-address order.
        let stop_actions = UA_FORCE_UNWIND | UA_CLEANUP_PHASE;
        // SAFETY: context is stack-local for this callback and stop_fn follows
        // the Itanium C++ ABI `_Unwind_Stop_Fn` contract.
        let stop_code = unsafe {
            stop_fn(
                1,
                stop_actions,
                exception_class,
                exception,
                &mut context,
                stop_parameter,
            )
        };
        trace_owned_unwind(format_args!(
            "forced stop frame_index={frame_index} ip={:#x} cfa={frame_cfa:#x} stop_code={stop_code}",
            cursor.ip
        ));
        emit_owned_unwind_jsonl(
            "forced_unwind_stop",
            frame_index,
            cursor.ip,
            frame_cfa,
            stop_code,
        );
        match stop_code {
            URC_NO_REASON => {}
            URC_NORMAL_STOP => return URC_NORMAL_STOP,
            other => return other,
        }

        // 2. Run this frame's language personality in forced-unwind cleanup mode.
        if let Some(record) = record
            && let Some(personality) = record.fde.personality
            && !own_panic_abort_frame(lookup_ip)
        {
            context = context_for_cursor_record(cursor, frame_index, lookup_ip, Some(&record));
            let pers_code = call_personality(
                personality,
                UA_FORCE_UNWIND | UA_CLEANUP_PHASE,
                exception_class,
                exception,
                &mut context,
            );
            trace_owned_unwind(format_args!(
                "forced personality frame_index={frame_index} ip={:#x} cfa={frame_cfa:#x} pers_code={pers_code} lpad={:#x}",
                cursor.ip, context.ip
            ));
            emit_owned_unwind_jsonl(
                "forced_unwind_personality",
                frame_index,
                cursor.ip,
                frame_cfa,
                pers_code,
            );
            match pers_code {
                URC_INSTALL_CONTEXT => {
                    let regs = match prepare_cursor_landing_pad_registers(
                        &context,
                        &record.eh_frame,
                        record.fde,
                        lookup_ip,
                    ) {
                        Ok(regs) => regs,
                        Err(err) => {
                            trace_owned_unwind(format_args!("forced install error {err:?}"));
                            return URC_FATAL_PHASE2_ERROR;
                        }
                    };
                    emit_owned_unwind_jsonl(
                        "forced_unwind_install_cleanup",
                        frame_index,
                        regs.ip,
                        regs.rsp,
                        URC_INSTALL_CONTEXT,
                    );
                    // SAFETY: landing pad and physical cursor validated above.
                    unsafe { install_landing_pad_registers(regs) };
                }
                URC_CONTINUE_UNWIND | URC_NO_REASON => {}
                _ => return URC_FATAL_PHASE2_ERROR,
            }
        }

        match step_x86_64_cursor(cursor) {
            Ok(Some(next)) => cursor = next,
            Ok(None) => {
                let mut end_ctx = empty_context_at_end(cursor.rsp);
                emit_owned_unwind_jsonl(
                    "forced_end_of_stack",
                    frame_index + 1,
                    0,
                    cursor.rsp,
                    UA_END_OF_STACK,
                );
                let end_code = unsafe {
                    stop_fn(
                        1,
                        UA_FORCE_UNWIND | UA_CLEANUP_PHASE | UA_END_OF_STACK,
                        exception_class,
                        exception,
                        &mut end_ctx,
                        stop_parameter,
                    )
                };
                return if end_code == URC_NO_REASON {
                    URC_FATAL_PHASE2_ERROR
                } else {
                    end_code
                };
            }
            Err(_) => return URC_FATAL_PHASE2_ERROR,
        }
    }

    let mut end_ctx = empty_context_at_end(cursor.rsp);
    let end_code = unsafe {
        stop_fn(
            1,
            UA_FORCE_UNWIND | UA_CLEANUP_PHASE | UA_END_OF_STACK,
            exception_class,
            exception,
            &mut end_ctx,
            stop_parameter,
        )
    };
    if end_code == URC_NO_REASON {
        URC_FATAL_PHASE2_ERROR
    } else {
        end_code
    }
}

fn trace_owned_unwind(args: std::fmt::Arguments<'_>) {
    if std::env::var_os("FRANKENLIBC_OWNED_UNWIND_TRACE").is_some() {
        let _ = writeln!(std::io::stderr(), "[owned-unwind] {args}");
    }
}

fn emit_owned_unwind_jsonl(
    event: &str,
    frame_index: usize,
    ip: usize,
    cfa: usize,
    code: UnwindReasonCode,
) {
    let Some(path) = std::env::var_os("FRANKENLIBC_OWNED_UNWIND_JSONL") else {
        return;
    };
    if path.is_empty() {
        return;
    }
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = writeln!(
            file,
            "{{\"schema_version\":\"frankenlibc.owned_unwind.v1\",\"event\":\"{event}\",\"frame_index\":{frame_index},\"ip\":\"{ip:#x}\",\"cfa\":\"{cfa:#x}\",\"code\":{code}}}"
        );
    }
}

#[inline]
fn frame_lookup_ip(return_address: usize) -> usize {
    return_address.saturating_sub(1)
}

fn step_x86_64_cursor(
    cursor: X86PhysicalCursor,
) -> Result<Option<X86PhysicalCursor>, OwnedUnwindDecodeError> {
    if cursor.ip == 0 || cursor.rsp == 0 {
        return Ok(None);
    }
    let lookup_ip = frame_lookup_ip(cursor.ip);
    if let Some(record) = find_registered_fde_record_for_ip(lookup_ip)? {
        let state = evaluate_cfi_state(&record.eh_frame, record.fde, lookup_ip)?;
        let Some(cfa_base) = cursor_read_dwarf_reg(&cursor, state.cfa_register) else {
            return Err(OwnedUnwindDecodeError::MalformedRecord);
        };
        let Some(cfa) = checked_add_signed_usize_any(cfa_base, state.cfa_offset) else {
            return Err(OwnedUnwindDecodeError::Overflow);
        };

        let ra_rule = state.register_rule(record.fde.return_address_register);
        let next_ip = match ra_rule {
            CfiRegisterRule::Undefined | CfiRegisterRule::SameValue => return Ok(None),
            CfiRegisterRule::Offset(off) => {
                let addr = checked_add_signed_usize_any(cfa, off)
                    .ok_or(OwnedUnwindDecodeError::Overflow)?;
                match read_word(addr) {
                    Some(0) | None => return Ok(None),
                    Some(ip) => ip,
                }
            }
            CfiRegisterRule::ValOffset(off) => {
                let ip = checked_add_signed_usize_any(cfa, off)
                    .ok_or(OwnedUnwindDecodeError::Overflow)?;
                if ip == 0 {
                    return Ok(None);
                }
                ip
            }
            CfiRegisterRule::Register(reg) => match cursor_read_dwarf_reg(&cursor, reg) {
                Some(0) | None => return Ok(None),
                Some(ip) => ip,
            },
        };

        let next_rsp = match state.register_rule(X86_64_DWARF_RSP) {
            CfiRegisterRule::Undefined => cfa,
            CfiRegisterRule::SameValue => cursor.rsp,
            CfiRegisterRule::Offset(off) => {
                let addr = checked_add_signed_usize_any(cfa, off)
                    .ok_or(OwnedUnwindDecodeError::Overflow)?;
                read_word(addr).ok_or(OwnedUnwindDecodeError::MalformedRecord)?
            }
            CfiRegisterRule::ValOffset(off) => {
                checked_add_signed_usize_any(cfa, off).ok_or(OwnedUnwindDecodeError::Overflow)?
            }
            CfiRegisterRule::Register(reg) => cursor_read_dwarf_reg(&cursor, reg)
                .ok_or(OwnedUnwindDecodeError::MalformedRecord)?,
        };

        let next_cursor_reg = |reg: usize,
                               current: usize|
         -> Result<usize, OwnedUnwindDecodeError> {
            match state.register_rule(reg) {
                CfiRegisterRule::Undefined | CfiRegisterRule::SameValue => Ok(current),
                CfiRegisterRule::Offset(off) => {
                    let addr = checked_add_signed_usize_any(cfa, off)
                        .ok_or(OwnedUnwindDecodeError::Overflow)?;
                    read_word(addr).ok_or(OwnedUnwindDecodeError::MalformedRecord)
                }
                CfiRegisterRule::ValOffset(off) => {
                    checked_add_signed_usize_any(cfa, off).ok_or(OwnedUnwindDecodeError::Overflow)
                }
                CfiRegisterRule::Register(other_reg) => cursor_read_dwarf_reg(&cursor, other_reg)
                    .ok_or(OwnedUnwindDecodeError::MalformedRecord),
            }
        };

        let next = X86PhysicalCursor {
            ip: next_ip,
            rsp: next_rsp,
            rbp: next_cursor_reg(X86_64_DWARF_RBP, cursor.rbp)?,
            rbx: next_cursor_reg(X86_64_DWARF_RBX, cursor.rbx)?,
            r12: next_cursor_reg(X86_64_DWARF_R12, cursor.r12)?,
            r13: next_cursor_reg(X86_64_DWARF_R13, cursor.r13)?,
            r14: next_cursor_reg(X86_64_DWARF_R14, cursor.r14)?,
            r15: next_cursor_reg(X86_64_DWARF_R15, cursor.r15)?,
        };
        if next.rsp == cursor.rsp && next.ip == cursor.ip {
            return Ok(None);
        }
        return Ok(Some(next));
    }

    // Fallback for hand-written stubs without `.eh_frame`: step `%rbp` chain if valid.
    let Some(stack_limit) = cursor.rsp.checked_add(MAX_STACK_SCAN_BYTES) else {
        return Ok(None);
    };
    if !valid_frame_pointer(cursor.rbp, cursor.rsp, stack_limit) {
        return Ok(None);
    }
    let Some(next_rbp) = read_word(cursor.rbp) else {
        return Ok(None);
    };
    let Some(ra_slot) = cursor.rbp.checked_add(core::mem::size_of::<usize>()) else {
        return Ok(None);
    };
    let Some(next_ip) = read_word(ra_slot) else {
        return Ok(None);
    };
    let Some(next_rsp) = cursor.rbp.checked_add(2 * core::mem::size_of::<usize>()) else {
        return Ok(None);
    };
    if next_ip == 0 || next_rsp <= cursor.rsp {
        return Ok(None);
    }
    Ok(Some(X86PhysicalCursor {
        ip: next_ip,
        rsp: next_rsp,
        rbp: next_rbp,
        rbx: cursor.rbx,
        r12: cursor.r12,
        r13: cursor.r13,
        r14: cursor.r14,
        r15: cursor.r15,
    }))
}

#[inline]
fn cursor_read_dwarf_reg(cursor: &X86PhysicalCursor, register: usize) -> Option<usize> {
    match register {
        X86_64_DWARF_RBX => Some(cursor.rbx),
        X86_64_DWARF_RBP => Some(cursor.rbp),
        X86_64_DWARF_RSP => Some(cursor.rsp),
        X86_64_DWARF_R12 => Some(cursor.r12),
        X86_64_DWARF_R13 => Some(cursor.r13),
        X86_64_DWARF_R14 => Some(cursor.r14),
        X86_64_DWARF_R15 => Some(cursor.r15),
        X86_64_DWARF_RIP => Some(cursor.ip),
        _ => None,
    }
}

#[inline]
fn checked_add_signed_usize_any(base: usize, offset: isize) -> Option<usize> {
    if offset >= 0 {
        base.checked_add(offset as usize)
    } else {
        base.checked_sub(offset.unsigned_abs())
    }
}

struct RegisteredFdeRecord {
    fde: OwnedFdeRecord,
    eh_frame: Vec<u8>,
}

fn find_registered_fde_record_for_ip(
    ip: usize,
) -> Result<Option<RegisteredFdeRecord>, OwnedUnwindDecodeError> {
    // First search explicitly registered frames (__register_frame)
    let registry = *frame_registry();
    for slot in registry.iter().filter(|slot| slot.fde != 0) {
        let eh_frame = copy_registered_eh_frame(slot.fde)?;
        if let Some(fde) = find_fde_for_ip(&eh_frame, slot.fde, ip, true)? {
            return Ok(Some(RegisteredFdeRecord { fde, eh_frame }));
        }
    }

    // Fall back to searching loaded objects via dl_iterate_phdr
    find_loaded_object_fde_record_for_ip(ip)
}

fn find_loaded_object_fde_record_for_ip(
    ip: usize,
) -> Result<Option<RegisteredFdeRecord>, OwnedUnwindDecodeError> {
    let ranges = collect_loaded_eh_frame_ranges();
    for range in ranges {
        if ip < range.load_start || ip >= range.load_end {
            continue;
        }
        if let Some(record) = search_eh_frame_hdr_for_ip(&range, ip)? {
            return Ok(Some(record));
        }
    }
    Ok(None)
}

fn search_eh_frame_hdr_for_ip(
    range: &OwnedLoadedEhFrameRange,
    ip: usize,
) -> Result<Option<RegisteredFdeRecord>, OwnedUnwindDecodeError> {
    if range.eh_frame_hdr_len < 4 {
        return Ok(None);
    }

    // SAFETY: the range comes from dl_iterate_phdr which validates the PT_GNU_EH_FRAME
    // segment is within the object's PT_LOAD bounds.
    let hdr = unsafe {
        core::slice::from_raw_parts(
            range.eh_frame_hdr_start as *const u8,
            range.eh_frame_hdr_len,
        )
    };

    let version = hdr[0];
    if version != 1 {
        return Ok(None);
    }

    let eh_frame_ptr_enc = hdr[1];
    let fde_count_enc = hdr[2];
    let table_enc = hdr[3];

    // Parse eh_frame pointer
    let mut cursor = 4usize;
    let (eh_frame_ptr, after_eh_frame) = read_encoded_pointer(
        hdr,
        cursor,
        range.eh_frame_hdr_start + cursor,
        eh_frame_ptr_enc,
        true,
        0,
        range.eh_frame_hdr_start,
    )?;
    cursor = after_eh_frame;

    // Parse FDE count
    if fde_count_enc == DW_EH_PE_OMIT {
        return Ok(None);
    }
    let (fde_count, after_fde_count) = read_encoded_pointer(
        hdr,
        cursor,
        range.eh_frame_hdr_start + cursor,
        fde_count_enc,
        false,
        0,
        range.eh_frame_hdr_start,
    )?;
    cursor = after_fde_count;

    if fde_count == 0 || table_enc == DW_EH_PE_OMIT {
        return Ok(None);
    }

    // Binary search the table for the IP
    let entry_size = encoded_pointer_size(table_enc & 0x0f)?;
    let table_start = cursor;

    // Binary search
    let mut lo = 0usize;
    let mut hi = fde_count;
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let entry_offset = table_start + mid * 2 * entry_size;
        if entry_offset + entry_size > hdr.len() {
            break;
        }
        let (initial_loc, _) = read_encoded_pointer(
            hdr,
            entry_offset,
            range.eh_frame_hdr_start + entry_offset,
            table_enc,
            true,
            0,
            range.eh_frame_hdr_start,
        )?;
        if ip < initial_loc {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }

    // lo-1 is the entry whose initial_loc <= ip (if lo > 0)
    if lo == 0 {
        return Ok(None);
    }
    let entry_index = lo - 1;
    let entry_offset = table_start + entry_index * 2 * entry_size;
    if entry_offset + 2 * entry_size > hdr.len() {
        return Ok(None);
    }

    let (_, after_initial) = read_encoded_pointer(
        hdr,
        entry_offset,
        range.eh_frame_hdr_start + entry_offset,
        table_enc,
        true,
        0,
        range.eh_frame_hdr_start,
    )?;
    let (fde_ptr, _) = read_encoded_pointer(
        hdr,
        after_initial,
        range.eh_frame_hdr_start + after_initial,
        table_enc,
        true,
        0,
        range.eh_frame_hdr_start,
    )?;

    let _ = eh_frame_ptr;

    // Decode the exact CIE + FDE pair in O(1) without copying the full .eh_frame section.
    if let Some(record) = decode_live_fde_at_address(range, fde_ptr, ip)? {
        return Ok(Some(record));
    }

    // If exact match failed (e.g. overlapping/adjacent FDE range), probe nearby table entries.
    for delta in [-1i32, 1, -2, 2] {
        let adj_index = entry_index as i32 + delta;
        if adj_index < 0 || adj_index as usize >= fde_count {
            continue;
        }
        let adj_offset = table_start + (adj_index as usize) * 2 * entry_size;
        if adj_offset + 2 * entry_size > hdr.len() {
            continue;
        }
        let (_, after_adj_initial) = read_encoded_pointer(
            hdr,
            adj_offset,
            range.eh_frame_hdr_start + adj_offset,
            table_enc,
            true,
            0,
            range.eh_frame_hdr_start,
        )?;
        let (adj_fde_ptr, _) = read_encoded_pointer(
            hdr,
            after_adj_initial,
            range.eh_frame_hdr_start + after_adj_initial,
            table_enc,
            true,
            0,
            range.eh_frame_hdr_start,
        )?;
        if let Some(record) = decode_live_fde_at_address(range, adj_fde_ptr, ip)? {
            return Ok(Some(record));
        }
    }

    Ok(None)
}

fn encoded_pointer_size(base_enc: u8) -> Result<usize, OwnedUnwindDecodeError> {
    match base_enc & 0x0f {
        DW_EH_PE_ABSPTR => Ok(core::mem::size_of::<usize>()),
        DW_EH_PE_UDATA2 | DW_EH_PE_SDATA2 => Ok(2),
        DW_EH_PE_UDATA4 | DW_EH_PE_SDATA4 => Ok(4),
        DW_EH_PE_UDATA8 | DW_EH_PE_SDATA8 => Ok(8),
        other => Err(OwnedUnwindDecodeError::UnsupportedPointerEncoding(other)),
    }
}

fn decode_live_fde_at_address(
    range: &OwnedLoadedEhFrameRange,
    fde_ptr: usize,
    ip: usize,
) -> Result<Option<RegisteredFdeRecord>, OwnedUnwindDecodeError> {
    if fde_ptr < range.load_start
        || fde_ptr
            .checked_add(8)
            .is_none_or(|end| end > range.load_end)
    {
        return Err(OwnedUnwindDecodeError::MalformedRecord);
    }

    // SAFETY: fde_ptr..fde_ptr+8 lies inside the loaded PT_LOAD span for this object.
    let fde_length = unsafe { core::ptr::read_unaligned(fde_ptr as *const u32) };
    if fde_length == 0 || fde_length == u32::MAX {
        return Err(OwnedUnwindDecodeError::MalformedRecord);
    }
    let fde_total = 4usize
        .checked_add(fde_length as usize)
        .ok_or(OwnedUnwindDecodeError::Overflow)?;
    if fde_total > MAX_REGISTERED_EH_FRAME_BYTES {
        return Err(OwnedUnwindDecodeError::MalformedRecord);
    }
    let fde_end = fde_ptr
        .checked_add(fde_total)
        .ok_or(OwnedUnwindDecodeError::Overflow)?;
    if fde_end > range.load_end {
        return Err(OwnedUnwindDecodeError::Truncated);
    }

    let cie_delta = unsafe { core::ptr::read_unaligned((fde_ptr + 4) as *const i32) };
    if cie_delta == 0 {
        return Err(OwnedUnwindDecodeError::MalformedRecord);
    }
    let cie_ptr_signed = ((fde_ptr + 4) as isize)
        .checked_sub(cie_delta as isize)
        .ok_or(OwnedUnwindDecodeError::Overflow)?;
    if cie_ptr_signed <= 0 {
        return Err(OwnedUnwindDecodeError::MalformedRecord);
    }
    let cie_ptr = cie_ptr_signed as usize;
    if cie_ptr < range.load_start
        || cie_ptr
            .checked_add(8)
            .is_none_or(|end| end > range.load_end)
    {
        return Err(OwnedUnwindDecodeError::MalformedRecord);
    }

    // SAFETY: cie_ptr..cie_ptr+8 lies inside the loaded PT_LOAD span for this object.
    let cie_length = unsafe { core::ptr::read_unaligned(cie_ptr as *const u32) };
    if cie_length == 0 || cie_length == u32::MAX {
        return Err(OwnedUnwindDecodeError::MalformedRecord);
    }
    let cie_total = 4usize
        .checked_add(cie_length as usize)
        .ok_or(OwnedUnwindDecodeError::Overflow)?;
    if cie_total > MAX_REGISTERED_EH_FRAME_BYTES {
        return Err(OwnedUnwindDecodeError::MalformedRecord);
    }
    let cie_end = cie_ptr
        .checked_add(cie_total)
        .ok_or(OwnedUnwindDecodeError::Overflow)?;
    if cie_end > range.load_end {
        return Err(OwnedUnwindDecodeError::Truncated);
    }

    // SAFETY: both CIE and FDE slices have been verified within range.load_start..range.load_end.
    let cie_slice = unsafe { core::slice::from_raw_parts(cie_ptr as *const u8, cie_total) };
    let fde_slice = unsafe { core::slice::from_raw_parts(fde_ptr as *const u8, fde_total) };

    let cie_rec =
        next_eh_frame_record(cie_slice, 0)?.ok_or(OwnedUnwindDecodeError::MalformedRecord)?;
    if !cie_rec.is_cie {
        return Err(OwnedUnwindDecodeError::MalformedRecord);
    }
    let cie = parse_cie_record(cie_slice, cie_ptr, cie_rec, true)?;

    let fde_rec =
        next_eh_frame_record(fde_slice, 0)?.ok_or(OwnedUnwindDecodeError::MalformedRecord)?;
    if fde_rec.is_cie {
        return Err(OwnedUnwindDecodeError::MalformedRecord);
    }
    let mut fde = parse_fde_record_with_cie(fde_slice, fde_ptr, fde_rec, &cie, 0, true)?;
    if ip < fde.pc_begin || ip >= fde.pc_end {
        return Ok(None);
    }

    let mut compact = Vec::with_capacity(cie_total + fde_total);
    compact.extend_from_slice(cie_slice);
    compact.extend_from_slice(fde_slice);
    fde.fde_cfi_start = fde
        .fde_cfi_start
        .checked_add(cie_total)
        .ok_or(OwnedUnwindDecodeError::Overflow)?;
    fde.fde_cfi_end = fde
        .fde_cfi_end
        .checked_add(cie_total)
        .ok_or(OwnedUnwindDecodeError::Overflow)?;
    validate_fde_cfi_program(&compact, fde)?;
    Ok(Some(RegisteredFdeRecord {
        fde,
        eh_frame: compact,
    }))
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
        cfa: 0,
        language_specific_data: fde.language_specific_data.unwrap_or(0),
        region_start: fde.pc_begin,
        text_rel_base: fde.text_rel_base,
        data_rel_base: fde.data_rel_base,
        general_registers: empty_general_registers(),
        physical_cursor: None,
    }
}

fn context_for_cursor_record(
    cursor: X86PhysicalCursor,
    frame_index: usize,
    lookup_ip: usize,
    record: Option<&RegisteredFdeRecord>,
) -> UnwindContext {
    let mut general_registers = empty_general_registers();
    general_registers[X86_64_DWARF_RBX] = cursor.rbx;
    general_registers[X86_64_DWARF_RBP] = cursor.rbp;
    general_registers[X86_64_DWARF_RSP] = cursor.rsp;
    general_registers[X86_64_DWARF_R12] = cursor.r12;
    general_registers[X86_64_DWARF_R13] = cursor.r13;
    general_registers[X86_64_DWARF_R14] = cursor.r14;
    general_registers[X86_64_DWARF_R15] = cursor.r15;
    general_registers[X86_64_DWARF_RIP] = cursor.ip;

    let fde = record.map(|r| r.fde);
    let cfa = record
        .and_then(|rec| {
            let state = evaluate_cfi_state(&rec.eh_frame, rec.fde, lookup_ip).ok()?;
            let base = cursor_read_dwarf_reg(&cursor, state.cfa_register)?;
            checked_add_signed_usize_any(base, state.cfa_offset)
        })
        .unwrap_or(cursor.rsp);

    UnwindContext {
        ip: cursor.ip,
        frame_index,
        frame_pointer: cursor.rbp,
        stack_pointer: cursor.rsp,
        cfa,
        language_specific_data: fde.and_then(|f| f.language_specific_data).unwrap_or(0),
        region_start: fde.map(|f| f.pc_begin).unwrap_or(0),
        text_rel_base: fde.map(|f| f.text_rel_base).unwrap_or(0),
        data_rel_base: fde.map(|f| f.data_rel_base).unwrap_or(0),
        general_registers,
        physical_cursor: Some(cursor),
    }
}

fn empty_context_at_end(last_stack_pointer: usize) -> UnwindContext {
    UnwindContext {
        ip: 0,
        frame_index: 0,
        frame_pointer: 0,
        stack_pointer: last_stack_pointer,
        cfa: last_stack_pointer,
        language_specific_data: 0,
        region_start: 0,
        text_rel_base: 0,
        data_rel_base: 0,
        general_registers: empty_general_registers(),
        physical_cursor: None,
    }
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
        let state = evaluate_cfi_state(eh_frame, fde, call_site_ip)
            .map_err(OwnedContextInstallError::Decode)?;
        let row = cfi_row_from_state(&state, fde, call_site_ip);
        prepare_x86_64_landing_pad_install(context, row, state.gnu_args_size)
    }
}

fn prepare_cursor_landing_pad_registers(
    context: &UnwindContext,
    eh_frame: &[u8],
    fde: OwnedFdeRecord,
    call_site_ip: usize,
) -> Result<X86LandingPadRegisters, OwnedContextInstallError> {
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (context, eh_frame, fde, call_site_ip);
        return Err(OwnedContextInstallError::UnsupportedArchitecture);
    }

    #[cfg(target_arch = "x86_64")]
    {
        let state = evaluate_cfi_state(eh_frame, fde, call_site_ip)
            .map_err(OwnedContextInstallError::Decode)?;
        let row = cfi_row_from_state(&state, fde, call_site_ip);
        let install = prepare_x86_64_landing_pad_install(context, row, state.gnu_args_size)?;
        let cursor = context
            .physical_cursor
            .ok_or(OwnedContextInstallError::MissingPhysicalCursor)?;
        Ok(X86LandingPadRegisters {
            ip: install.ip,
            rsp: install.stack_pointer,
            rbp: install.frame_pointer,
            rbx: cursor.rbx,
            r12: cursor.r12,
            r13: cursor.r13,
            r14: cursor.r14,
            r15: cursor.r15,
            rax: install.general_register_0,
            rdx: install.general_register_1,
        })
    }
}

#[cfg(target_arch = "x86_64")]
fn prepare_x86_64_landing_pad_install(
    context: &UnwindContext,
    row: OwnedCfiRow,
    gnu_args_size: usize,
) -> Result<OwnedLandingPadInstall, OwnedContextInstallError> {
    if context.ip == 0 {
        return Err(OwnedContextInstallError::NullLandingPad);
    }
    if context.stack_pointer == 0 {
        return Err(OwnedContextInstallError::MissingPhysicalCursor);
    }
    if !context
        .stack_pointer
        .is_multiple_of(core::mem::align_of::<usize>())
    {
        return Err(OwnedContextInstallError::MisalignedStackPointer);
    }
    if row.saved_rip_offset.is_none() {
        return Err(OwnedContextInstallError::MissingSavedInstructionPointer);
    }
    let cfa_base = match row.cfa_register {
        X86_64_DWARF_RBP => {
            if context.frame_pointer == 0 {
                return Err(OwnedContextInstallError::MissingPhysicalCursor);
            }
            if !context
                .frame_pointer
                .is_multiple_of(core::mem::align_of::<usize>())
            {
                return Err(OwnedContextInstallError::MisalignedFramePointer);
            }
            if context.stack_pointer >= context.frame_pointer {
                return Err(OwnedContextInstallError::StackPointerEscapesHandlerFrame);
            }
            context.frame_pointer
        }
        X86_64_DWARF_RSP => context.stack_pointer,
        X86_64_DWARF_RBX => context.physical_cursor.map(|c| c.rbx).ok_or(
            OwnedContextInstallError::UnsupportedCfaRegister(row.cfa_register),
        )?,
        other => return Err(OwnedContextInstallError::UnsupportedCfaRegister(other)),
    };
    let _cfa = checked_add_signed_usize(cfa_base, row.cfa_offset)
        .ok_or(OwnedContextInstallError::CfaOverflow)?;
    let adjusted_sp = context
        .stack_pointer
        .checked_add(gnu_args_size)
        .ok_or(OwnedContextInstallError::CfaOverflow)?;

    Ok(OwnedLandingPadInstall {
        ip: context.ip,
        stack_pointer: adjusted_sp,
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

#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
unsafe extern "C" fn install_x86_64_landing_pad(_regs: *const X86LandingPadRegisters) -> ! {
    std::arch::naked_asm!(
        "mov r11, [rdi + 0]",
        "mov rbp, [rdi + 16]",
        "mov rbx, [rdi + 24]",
        "mov r12, [rdi + 32]",
        "mov r13, [rdi + 40]",
        "mov r14, [rdi + 48]",
        "mov r15, [rdi + 56]",
        "mov rax, [rdi + 64]",
        "mov rdx, [rdi + 72]",
        "mov rsp, [rdi + 8]",
        "jmp r11",
    );
}

unsafe fn install_landing_pad_registers(regs: X86LandingPadRegisters) -> ! {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: `regs` was validated by `prepare_cursor_landing_pad_registers`.
        // `install_x86_64_landing_pad` reads all register slots from `&regs` before
        // switching `rsp` and jumping to `r11`.
        unsafe { install_x86_64_landing_pad(&regs) }
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = regs;
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
                b'S' => {}
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

    parse_fde_record_with_cie(
        eh_frame,
        section_addr,
        record,
        cie,
        cie_offset,
        resolve_indirect,
    )
}

fn parse_fde_record_with_cie(
    eh_frame: &[u8],
    section_addr: usize,
    record: EhFrameRecord,
    cie: &OwnedCieRecord,
    cie_offset: usize,
    resolve_indirect: bool,
) -> Result<OwnedFdeRecord, OwnedUnwindDecodeError> {
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

fn evaluate_cfi_state(
    eh_frame: &[u8],
    fde: OwnedFdeRecord,
    ip: usize,
) -> Result<CfiEvaluationState, OwnedUnwindDecodeError> {
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
    Ok(state)
}

fn cfi_row_from_state(state: &CfiEvaluationState, fde: OwnedFdeRecord, ip: usize) -> OwnedCfiRow {
    OwnedCfiRow {
        pc: ip,
        cfa_register: state.cfa_register,
        cfa_offset: state.cfa_offset,
        return_address_register: fde.return_address_register,
        saved_rip_offset: cfi_rule_offset(state.register_rule(X86_64_DWARF_RIP)),
        saved_rbp_offset: cfi_rule_offset(state.register_rule(X86_64_DWARF_RBP)),
        saved_rsp_offset: cfi_rule_offset(state.register_rule(X86_64_DWARF_RSP)),
    }
}

fn evaluate_cfi_row(
    eh_frame: &[u8],
    fde: OwnedFdeRecord,
    ip: usize,
) -> Result<OwnedCfiRow, OwnedUnwindDecodeError> {
    let state = evaluate_cfi_state(eh_frame, fde, ip)?;
    Ok(cfi_row_from_state(&state, fde, ip))
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
            0x09 => {
                let (register, after_reg) = decode_uleb128(input, cursor)?;
                let (target_reg, after_target) = decode_uleb128(input, after_reg)?;
                cursor = after_target;
                set_register_rule(state, register, CfiRegisterRule::Register(target_reg));
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
                let (args_size, next) = decode_uleb128(input, cursor)?;
                cursor = next;
                state.gnu_args_size = args_size;
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
        CfiRegisterRule::Undefined
        | CfiRegisterRule::SameValue
        | CfiRegisterRule::ValOffset(_)
        | CfiRegisterRule::Register(_) => None,
    }
}

impl CfiEvaluationState {
    fn new(pc: usize) -> Self {
        Self {
            pc,
            cfa_register: UNSET_DWARF_REGISTER,
            cfa_offset: 0,
            gnu_args_size: 0,
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
