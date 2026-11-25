//! Opt-in owned `_Unwind_*` substitutes for standalone artifact experiments.
//!
//! These symbols are intentionally gated behind `standalone,owned-unwind-stub`.
//! They are not a general unwinder. The experiment lane can now perform a
//! bounded DWARF walk over registered and loaded `.eh_frame` data. On x86_64,
//! the cursor captures and restores the SysV callee-saved registers, including
//! frames compiled without a frame pointer. Unsupported CFI fails closed.
//!
//! Itanium EH ABI sections 1.3 and 1.6 define the propagation contract: normal
//! exceptions search once, remember the handler's stack identity, and install
//! every intervening cleanup. Resume continues phase two after that cleanup.
//! Forced unwinding performs only phase two, calls the supplied stop function
//! before each personality, and preserves that callback across Resume. The
//! callback may leave nonlocally, so no owned allocation or lock spans it.

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
const MAX_UNWIND_FRAMES: usize = 4096;
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
const DW_CFA_REGISTER: u8 = 0x09;
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
const MAX_DWARF_EXPRESSION_BYTES: usize = 256;
const MAX_DWARF_EXPRESSION_STACK: usize = 32;
const MAX_DWARF_EXPRESSION_STEPS: usize = 128;

type UnwindPersonalityFn = unsafe extern "C" fn(
    version: c_int,
    actions: UnwindAction,
    exception_class: UnwindExceptionClass,
    exception_object: *mut UnwindException,
    context: *mut UnwindContext,
) -> UnwindReasonCode;

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
    UnsupportedSignalFrame,
    UnsupportedDwarfOpcode(u8),
    MalformedExpression,
    ExpressionLimit,
    InvalidStackAddress,
    MissingCie,
    MissingFde,
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
    pub signal_frame: bool,
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
    signal_frame: bool,
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
    Expression(CfiExpression),
    ValExpression(CfiExpression),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CfiExpression {
    start: usize,
    len: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct CfiEvaluationState {
    pc: usize,
    cfa_register: usize,
    cfa_offset: isize,
    gnu_args_size: usize,
    cfa_expression: Option<CfiExpression>,
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
    ip_before_instruction: bool,
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
    ip_before_insn: bool,
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

pub type UnwindStopFn = unsafe extern "C-unwind" fn(
    version: c_int,
    actions: UnwindAction,
    exception_class: UnwindExceptionClass,
    exception: *mut UnwindException,
    context: *mut UnwindContext,
    argument: *mut c_void,
) -> UnwindReasonCode;

/// Exact layout written by the entry stubs before Rust can use callee-saved
/// registers. `stack_pointer` is the caller's SP before its call to the stub.
#[repr(C)]
struct CapturedUnwindCursor {
    rbx: usize,
    rbp: usize,
    r12: usize,
    r13: usize,
    r14: usize,
    r15: usize,
    stack_pointer: usize,
    ip: usize,
}

#[derive(Clone, Copy)]
struct UnwindCursor {
    ip: usize,
    ip_before_instruction: bool,
    registers: [usize; MAX_UNWIND_GR],
}

impl UnwindCursor {
    fn captured(capture: &CapturedUnwindCursor) -> Self {
        let mut registers = empty_general_registers();
        registers[3] = capture.rbx;
        registers[X86_64_DWARF_RBP] = capture.rbp;
        registers[12] = capture.r12;
        registers[13] = capture.r13;
        registers[14] = capture.r14;
        registers[15] = capture.r15;
        registers[X86_64_DWARF_RSP] = capture.stack_pointer;
        registers[X86_64_DWARF_RIP] = capture.ip;
        Self {
            ip: capture.ip,
            ip_before_instruction: false,
            registers,
        }
    }

    fn stack_pointer(self) -> usize {
        self.registers[X86_64_DWARF_RSP]
    }

    fn lookup_ip(self) -> usize {
        frame_lookup_ip_for_mode(self.ip, self.ip_before_instruction)
    }

    fn physical(self) -> X86PhysicalCursor {
        X86PhysicalCursor {
            ip: self.ip,
            rsp: self.stack_pointer(),
            rbp: self.registers[X86_64_DWARF_RBP],
            rbx: self.registers[X86_64_DWARF_RBX],
            r12: self.registers[X86_64_DWARF_R12],
            r13: self.registers[X86_64_DWARF_R13],
            r14: self.registers[X86_64_DWARF_R14],
            r15: self.registers[X86_64_DWARF_R15],
        }
    }

    fn context(self, frame_index: usize, fde: Option<OwnedFdeRecord>) -> UnwindContext {
        UnwindContext {
            ip: self.ip,
            ip_before_instruction: self.ip_before_instruction,
            frame_index,
            frame_pointer: self.registers[X86_64_DWARF_RBP],
            stack_pointer: self.stack_pointer(),
            cfa: self.stack_pointer(),
            language_specific_data: fde.and_then(|fde| fde.language_specific_data).unwrap_or(0),
            region_start: fde.map_or(0, |fde| fde.pc_begin),
            text_rel_base: fde.map_or(0, |fde| fde.text_rel_base),
            data_rel_base: fde.map_or(0, |fde| fde.data_rel_base),
            general_registers: self.registers,
            physical_cursor: Some(self.physical()),
            ip_before_insn: self.ip_before_instruction,
        }
    }
}

#[derive(Clone, Copy)]
struct UnwindStackBounds {
    start: usize,
    end: usize,
}

impl UnwindStackBounds {
    fn new(cursor: UnwindCursor) -> Option<Self> {
        let start = cursor.stack_pointer();
        Some(Self {
            start,
            end: start.checked_add(MAX_STACK_SCAN_BYTES)?,
        })
    }

    fn contains_word(self, address: usize) -> bool {
        address >= self.start
            && address.is_multiple_of(core::mem::align_of::<usize>())
            && address
                .checked_add(core::mem::size_of::<usize>())
                .is_some_and(|end| end <= self.end)
    }
}

#[derive(Clone, Copy)]
struct FrameRegistration {
    fde: usize,
    object: usize,
}

static FRAME_REGISTRY: Mutex<[FrameRegistration; FRAME_REGISTRY_SLOTS]> =
    Mutex::new([FrameRegistration { fde: 0, object: 0 }; FRAME_REGISTRY_SLOTS]);

// Keep the public Itanium ABI behind its opt-in feature. In the default
// interpose build, resident libgcc owns opaque contexts and exception state;
// mixing its forced-unwind entry with an owned Resume skips cleanup or aborts.
// Private capture helpers remain available for native backtrace support.

#[cfg(not(target_arch = "x86_64"))]
#[cfg_attr(feature = "owned-unwind-stub", unsafe(no_mangle))]
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

#[unsafe(no_mangle)]
unsafe extern "C" fn __frankenlibc_owned_backtrace_from_cursor(
    trace: UnwindTraceFn,
    argument: *mut c_void,
    capture: &CapturedUnwindCursor,
) -> UnwindReasonCode {
    let Some(trace) = trace else {
        return URC_END_OF_STACK;
    };
    // The capture stub writes `CapturedUnwindCursor`. Walk with the same
    // bounded CFI caller step raise and resume use. Backtraces additionally
    // admit the checked physical step for a Linux restorer or hand-written
    // frame without metadata; exception propagation still rejects missing CFI.
    let mut cursor = UnwindCursor::captured(capture);
    let Some(mut bounds) = UnwindStackBounds::new(cursor) else {
        return URC_FATAL_PHASE1_ERROR;
    };
    for frame_index in 0..MAX_BACKTRACE_FRAMES {
        let frame = match owned_frame_state(cursor) {
            Ok(frame) => frame,
            Err(OwnedUnwindDecodeError::MissingFde) => {
                let mut context = cursor.context(frame_index, None);
                // SAFETY: this trace-only context is live for the callback;
                // no loader lock or owned frame-data buffer spans the call.
                let reason = unsafe { trace(&mut context, argument) };
                if reason != URC_NO_REASON {
                    return reason;
                }
                match backtrace_caller_without_metadata(cursor, &mut bounds) {
                    Ok(Some(next)) => {
                        cursor = next;
                        continue;
                    }
                    Ok(None) => return URC_END_OF_STACK,
                    Err(error) => {
                        trace_owned_unwind(format_args!(
                            "backtrace fallback {error:?} frame={frame_index} ip={:#x} sp={:#x}",
                            cursor.ip,
                            cursor.stack_pointer()
                        ));
                        return URC_FATAL_PHASE1_ERROR;
                    }
                }
            }
            Err(error) => {
                trace_owned_unwind(format_args!(
                    "backtrace decode {error:?} frame={frame_index} ip={:#x} sp={:#x}",
                    cursor.ip,
                    cursor.stack_pointer()
                ));
                return URC_FATAL_PHASE1_ERROR;
            }
        };
        let Some((fde, state)) = frame else {
            return URC_END_OF_STACK;
        };
        let mut context = cursor.context(frame_index, Some(fde));
        // SAFETY: the callback receives a live stack-local context, with no
        // loader/registry lock or owning frame-data buffer held across it.
        let reason = unsafe { trace(&mut context, argument) };
        if reason != URC_NO_REASON {
            return reason;
        }
        cursor = match unwind_caller(cursor, fde, state, &mut bounds) {
            Ok(cursor) => cursor,
            Err(error) => {
                trace_owned_unwind(format_args!(
                    "backtrace caller {error:?} frame={frame_index} ip={:#x} sp={:#x} cfa_reg={} cfa_offset={}",
                    cursor.ip,
                    cursor.stack_pointer(),
                    state.cfa_register,
                    state.cfa_offset
                ));
                return URC_FATAL_PHASE1_ERROR;
            }
        };
    }
    URC_FATAL_PHASE1_ERROR
}

fn backtrace_caller_without_metadata(
    cursor: UnwindCursor,
    bounds: &mut UnwindStackBounds,
) -> Result<Option<UnwindCursor>, OwnedUnwindDecodeError> {
    let Some((next, signal_frame)) =
        step_x86_64_cursor_with_mode(cursor.physical(), cursor.ip_before_instruction)?
    else {
        return Ok(None);
    };
    if next.rsp == 0
        || !next.rsp.is_multiple_of(core::mem::align_of::<usize>())
        || (!signal_frame && (next.rsp <= cursor.stack_pointer() || next.rsp > bounds.end))
    {
        return Err(OwnedUnwindDecodeError::InvalidStackAddress);
    }
    let mut caller = UnwindCursor::captured(&CapturedUnwindCursor {
        rbx: next.rbx,
        rbp: next.rbp,
        r12: next.r12,
        r13: next.r13,
        r14: next.r14,
        r15: next.r15,
        stack_pointer: next.rsp,
        ip: next.ip,
    });
    caller.ip_before_instruction = signal_frame;
    if signal_frame {
        // Only the recognized restorer may cross from an alternate signal
        // stack back to the interrupted stack. Ordinary frames stay bounded.
        *bounds = UnwindStackBounds::new(caller).ok_or(OwnedUnwindDecodeError::Overflow)?;
    }
    Ok(Some(caller))
}

#[repr(C)]
struct BacktraceCaptureState {
    buffer: *mut *mut c_void,
    capacity: usize,
    written: usize,
}

unsafe extern "C" fn backtrace_capture_trace(
    ctx: *mut UnwindContext,
    arg: *mut c_void,
) -> UnwindReasonCode {
    if ctx.is_null() || arg.is_null() {
        return URC_END_OF_STACK;
    }
    // SAFETY: `arg` points to the caller's live stack `BacktraceCaptureState`.
    let state = unsafe { &mut *arg.cast::<BacktraceCaptureState>() };
    if state.written >= state.capacity {
        return URC_NORMAL_STOP;
    }
    // SAFETY: `ctx` is a live `UnwindContext` supplied by the unwinder.
    let ip = unsafe { (*ctx).ip };
    if ip == 0 {
        return URC_END_OF_STACK;
    }
    // SAFETY: `state.buffer` has capacity for `state.capacity` pointers.
    unsafe {
        *state.buffer.add(state.written) = ip as *mut c_void;
    }
    state.written += 1;
    if state.written >= state.capacity {
        URC_NORMAL_STOP
    } else {
        URC_NO_REASON
    }
}

#[cfg(target_arch = "x86_64")]
extern "C" fn __frankenlibc_capture_backtrace_from_cursor(
    buffer: *mut *mut c_void,
    max_frames: usize,
    capture: &CapturedUnwindCursor,
) -> c_int {
    if buffer.is_null() || max_frames == 0 {
        return 0;
    }
    let capacity = max_frames
        .min(MAX_BACKTRACE_FRAMES)
        .min(c_int::MAX as usize);
    let mut state = BacktraceCaptureState {
        buffer,
        capacity,
        written: 0,
    };
    // SAFETY: the entry stub supplies the exact CapturedUnwindCursor layout,
    // and the stack-local callback state remains live for the bounded walk.
    let _ = unsafe {
        __frankenlibc_owned_backtrace_from_cursor(
            Some(backtrace_capture_trace),
            (&raw mut state).cast(),
            capture,
        )
    };
    if state.written == 0 {
        let fallback_ip = capture.ip;
        if fallback_ip != 0 {
            // SAFETY: `buffer` has room for at least 1 pointer (`max_frames > 0`).
            unsafe { *buffer = fallback_ip as *mut c_void };
            state.written = 1;
        }
    }
    state.written as c_int
}

/// Capture up to `max_frames` return addresses into `buffer` using FrankenLibC's
/// native DWARF `.eh_frame` + frame-pointer unwinder (zero host glibc delegation).
#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
pub(crate) unsafe extern "C" fn capture_owned_backtrace(
    _buffer: *mut *mut c_void,
    _max_frames: usize,
) -> c_int {
    std::arch::naked_asm!(
        "sub rsp, 72",
        "mov [rsp], rbx",
        "mov [rsp + 8], rbp",
        "mov [rsp + 16], r12",
        "mov [rsp + 24], r13",
        "mov [rsp + 32], r14",
        "mov [rsp + 40], r15",
        "lea rax, [rsp + 80]",
        "mov [rsp + 48], rax",
        "mov rax, [rsp + 72]",
        "mov [rsp + 56], rax",
        "mov rdx, rsp",
        "call {helper}",
        "add rsp, 72",
        "ret",
        helper = sym __frankenlibc_capture_backtrace_from_cursor,
    );
}

#[cfg(not(target_arch = "x86_64"))]
pub(crate) unsafe extern "C" fn capture_owned_backtrace(
    buffer: *mut *mut c_void,
    max_frames: usize,
) -> c_int {
    if buffer.is_null() || max_frames == 0 {
        return 0;
    }
    let capacity = max_frames
        .min(MAX_BACKTRACE_FRAMES)
        .min(c_int::MAX as usize);
    let mut state = BacktraceCaptureState {
        buffer,
        capacity,
        written: 0,
    };
    let _ = owned_backtrace_from_frame_pointer(
        Some(backtrace_capture_trace),
        (&raw mut state).cast(),
        current_frame_pointer(),
        current_stack_pointer(),
    );
    if state.written == 0 {
        unsafe { *buffer = capture_owned_backtrace as *const () as *mut c_void };
        state.written = 1;
    }
    state.written as c_int
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
                ip_before_instruction: false,
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
                ip_before_insn: false,
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
#[cfg_attr(feature = "owned-unwind-stub", unsafe(no_mangle))]
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
    // The native stop protocol and public personalities must observe the
    // same suspended-frame SP, including after a cleanup calls Resume.
    // SAFETY: non-null contexts are owned by this module during callbacks.
    unsafe { _Unwind_GetCFA(ctx.cast::<UnwindContext>()) }
}

#[cfg(any(debug_assertions, feature = "owned-unwind-stub"))]
#[cfg_attr(feature = "owned-unwind-stub", unsafe(no_mangle))]
pub unsafe extern "C" fn _Unwind_GetDataRelBase(ctx: *mut UnwindContext) -> UnwindWord {
    if ctx.is_null() {
        return 0;
    }
    // SAFETY: non-null contexts are owned by this module during personality
    // calls or supplied by ABI peers following the opaque context contract.
    unsafe { (*ctx).data_rel_base }
}

#[cfg(any(debug_assertions, feature = "owned-unwind-stub"))]
#[cfg_attr(feature = "owned-unwind-stub", unsafe(no_mangle))]
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

#[cfg_attr(feature = "owned-unwind-stub", unsafe(no_mangle))]
pub unsafe extern "C" fn _Unwind_GetCFA(ctx: *mut UnwindContext) -> UnwindWord {
    if ctx.is_null() {
        return 0;
    }
    // SAFETY: contexts belong to this unwinder. The GNU accessor exposes the
    // current frame's SP at its suspended call, i.e. the preceding frame's
    // evaluated CFA, not the CFA used to advance this frame to its caller.
    unsafe { (*ctx).stack_pointer }
}

#[cfg_attr(feature = "owned-unwind-stub", unsafe(no_mangle))]
pub unsafe extern "C" fn _Unwind_GetIP(ctx: *mut UnwindContext) -> UnwindWord {
    if ctx.is_null() {
        return 0;
    }
    // SAFETY: non-null contexts are created by this module while walking frames
    // or provided by an ABI peer following the opaque _Unwind_Context contract.
    unsafe { (*ctx).ip }
}

#[cfg(any(debug_assertions, feature = "owned-unwind-stub"))]
#[cfg_attr(feature = "owned-unwind-stub", unsafe(no_mangle))]
pub unsafe extern "C" fn _Unwind_GetIPInfo(
    ctx: *mut UnwindContext,
    ip_before_insn: *mut c_int,
) -> UnwindWord {
    if !ip_before_insn.is_null() {
        let before = if ctx.is_null() {
            0
        } else {
            // SAFETY: non-null ctx points to the active UnwindContext.
            c_int::from(unsafe { (*ctx).ip_before_insn })
        };
        // SAFETY: the caller provided the optional out-pointer defined by the
        // unwinder ABI; a non-null pointer is expected to reference writable
        // storage for one c_int.
        unsafe { ip_before_insn.write(before) };
    }
    // SAFETY: mirrors _Unwind_GetIP's opaque-context handling.
    unsafe { _Unwind_GetIP(ctx) }
}

#[cfg(any(debug_assertions, feature = "owned-unwind-stub"))]
#[cfg_attr(feature = "owned-unwind-stub", unsafe(no_mangle))]
pub unsafe extern "C" fn _Unwind_GetLanguageSpecificData(ctx: *mut UnwindContext) -> *mut c_void {
    if ctx.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: mirrors _Unwind_GetIP's opaque-context handling.
    unsafe { (*ctx).language_specific_data as *mut c_void }
}

#[cfg(any(debug_assertions, feature = "owned-unwind-stub"))]
#[cfg_attr(feature = "owned-unwind-stub", unsafe(no_mangle))]
pub unsafe extern "C" fn _Unwind_GetRegionStart(ctx: *mut UnwindContext) -> UnwindWord {
    if ctx.is_null() {
        return 0;
    }
    // SAFETY: mirrors _Unwind_GetIP's opaque-context handling.
    unsafe { (*ctx).region_start }
}

#[cfg(any(debug_assertions, feature = "owned-unwind-stub"))]
#[cfg_attr(feature = "owned-unwind-stub", unsafe(no_mangle))]
pub unsafe extern "C" fn _Unwind_GetTextRelBase(ctx: *mut UnwindContext) -> UnwindWord {
    if ctx.is_null() {
        return 0;
    }
    // SAFETY: mirrors _Unwind_GetIP's opaque-context handling.
    unsafe { (*ctx).text_rel_base }
}

#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    ".macro owned_unwind_entry name, target, cursor_reg",
    ".global \\name",
    ".hidden \\name",
    ".type \\name, @function",
    "\\name:",
    "  .cfi_startproc",
    "  sub rsp, 72",
    "  .cfi_def_cfa_offset 80",
    "  mov [rsp], rbx",
    "  mov [rsp + 8], rbp",
    "  mov [rsp + 16], r12",
    "  mov [rsp + 24], r13",
    "  mov [rsp + 32], r14",
    "  mov [rsp + 40], r15",
    "  lea rax, [rsp + 80]",
    "  mov [rsp + 48], rax",
    "  mov rax, [rsp + 72]",
    "  mov [rsp + 56], rax",
    "  mov \\cursor_reg, rsp",
    "  call \\target",
    "  add rsp, 72",
    "  .cfi_def_cfa_offset 8",
    "  ret",
    "  .cfi_endproc",
    ".size \\name, . - \\name",
    ".endm",
    "owned_unwind_entry __frankenlibc_owned_raise_capture, __frankenlibc_owned_raise_from_cursor, rsi",
    "owned_unwind_entry __frankenlibc_owned_resume_capture, __frankenlibc_owned_resume_from_cursor, rsi",
    "owned_unwind_entry __frankenlibc_owned_rethrow_capture, __frankenlibc_owned_rethrow_from_cursor, rsi",
    "owned_unwind_entry __frankenlibc_owned_forced_capture, __frankenlibc_owned_forced_from_cursor, rcx",
    "owned_unwind_entry __frankenlibc_owned_backtrace_capture, __frankenlibc_owned_backtrace_from_cursor, rdx",
);

// Rust declarations keep the public names in rustc's cdylib export list.
// Naked tail branches preserve the original caller's SP and register values;
// an ordinary Rust wrapper would insert a compiler-dependent capture frame.
#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
#[cfg_attr(feature = "owned-unwind-stub", unsafe(no_mangle))]
pub unsafe extern "C-unwind" fn _Unwind_RaiseException(
    exception: *mut UnwindException,
) -> UnwindReasonCode {
    core::arch::naked_asm!("jmp __frankenlibc_owned_raise_capture");
}

#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
#[cfg_attr(feature = "owned-unwind-stub", unsafe(no_mangle))]
pub unsafe extern "C-unwind" fn _Unwind_Resume(exception: *mut UnwindException) -> ! {
    core::arch::naked_asm!("jmp __frankenlibc_owned_resume_capture");
}

#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
#[cfg_attr(feature = "owned-unwind-stub", unsafe(no_mangle))]
pub unsafe extern "C-unwind" fn _Unwind_Resume_or_Rethrow(
    exception: *mut UnwindException,
) -> UnwindReasonCode {
    core::arch::naked_asm!("jmp __frankenlibc_owned_rethrow_capture");
}

#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
#[cfg_attr(feature = "owned-unwind-stub", unsafe(no_mangle))]
pub unsafe extern "C-unwind" fn _Unwind_ForcedUnwind(
    exception: *mut UnwindException,
    stop: Option<UnwindStopFn>,
    argument: *mut c_void,
) -> UnwindReasonCode {
    core::arch::naked_asm!("jmp __frankenlibc_owned_forced_capture");
}

#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
#[cfg_attr(feature = "owned-unwind-stub", unsafe(no_mangle))]
pub unsafe extern "C" fn _Unwind_Backtrace(
    trace: UnwindTraceFn,
    argument: *mut c_void,
) -> UnwindReasonCode {
    core::arch::naked_asm!("jmp __frankenlibc_owned_backtrace_capture");
}

#[cfg(not(target_arch = "x86_64"))]
#[cfg_attr(feature = "owned-unwind-stub", unsafe(no_mangle))]
pub unsafe extern "C-unwind" fn _Unwind_RaiseException(
    _exception: *mut UnwindException,
) -> UnwindReasonCode {
    URC_FATAL_PHASE1_ERROR
}

#[unsafe(no_mangle)]
unsafe extern "C" fn __frankenlibc_owned_raise_from_cursor(
    exception: *mut UnwindException,
    capture: &CapturedUnwindCursor,
) -> UnwindReasonCode {
    owned_raise_exception(exception, UnwindCursor::captured(capture))
}

fn owned_raise_exception(
    exception: *mut UnwindException,
    cursor: UnwindCursor,
) -> UnwindReasonCode {
    if exception.is_null() {
        return URC_FATAL_PHASE1_ERROR;
    }
    let handler_stack = match owned_phase1_search(exception, cursor) {
        Ok(Some(handler_stack)) => handler_stack,
        Ok(None) => return URC_END_OF_STACK,
        Err(()) => return URC_FATAL_PHASE1_ERROR,
    };
    // SAFETY: the language runtime owns this live exception. These two words
    // belong exclusively to the unwinder; an address distinguishes recursive
    // activations that share the same return IP.
    unsafe {
        (*exception).private_1 = 0;
        (*exception).private_2 = handler_stack;
    }
    owned_phase2_cleanup(exception, cursor)
}

#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
pub(crate) unsafe extern "C-unwind" fn owned_forced_unwind_entry(
    _exception: *mut UnwindException,
    _stop: Option<UnwindStopFn>,
    _stop_parameter: *mut c_void,
) -> UnwindReasonCode {
    // Native cancellation must use the same cursor and phase-two engine as
    // the public entry and Resume. Tail-branch before a Rust prologue can
    // change the caller's register state or suspended stack pointer.
    core::arch::naked_asm!("jmp __frankenlibc_owned_forced_capture");
}

#[cfg(not(target_arch = "x86_64"))]
pub(crate) unsafe extern "C-unwind" fn owned_forced_unwind_entry(
    _exception: *mut UnwindException,
    _stop: Option<UnwindStopFn>,
    _stop_parameter: *mut c_void,
) -> UnwindReasonCode {
    URC_FATAL_PHASE2_ERROR
}

extern "C-unwind" fn __frankenlibc_owned_forced_unwind_from_cursor(
    exception: *mut UnwindException,
    stop: Option<UnwindStopFn>,
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

#[cfg(not(target_arch = "x86_64"))]
#[cfg_attr(feature = "owned-unwind-stub", unsafe(no_mangle))]
pub unsafe extern "C-unwind" fn _Unwind_Resume(_exception: *mut UnwindException) -> ! {
    std::process::abort()
}

#[unsafe(no_mangle)]
unsafe extern "C" fn __frankenlibc_owned_resume_from_cursor(
    exception: *mut UnwindException,
    capture: &CapturedUnwindCursor,
) -> ! {
    owned_resume(exception, UnwindCursor::captured(capture))
}

fn owned_resume(exception: *mut UnwindException, cursor: UnwindCursor) -> ! {
    // Resume's caller is the completed cleanup, now suspended at its Resume
    // call site. Revisit that context in phase two (including the forced stop
    // callback) before advancing; its personality must not run cleanup twice.
    // The original handler/stop protocol remains in the exception header.
    if !exception.is_null() {
        let result = owned_phase2_cleanup(exception, cursor);
        trace_owned_unwind(format_args!("resume unexpectedly returned code={result}"));
    }
    std::process::abort()
}

#[cfg(not(target_arch = "x86_64"))]
#[cfg_attr(feature = "owned-unwind-stub", unsafe(no_mangle))]
pub unsafe extern "C-unwind" fn _Unwind_Resume_or_Rethrow(
    _exception: *mut UnwindException,
) -> UnwindReasonCode {
    URC_FATAL_PHASE1_ERROR
}

#[unsafe(no_mangle)]
unsafe extern "C" fn __frankenlibc_owned_rethrow_from_cursor(
    exception: *mut UnwindException,
    capture: &CapturedUnwindCursor,
) -> UnwindReasonCode {
    let cursor = UnwindCursor::captured(capture);
    // SAFETY: a non-null exception header is live under the caller's ABI contract.
    if !exception.is_null() && unsafe { (*exception).private_1 } != 0 {
        owned_resume(exception, cursor);
    }
    owned_raise_exception(exception, cursor)
}

#[cfg(not(target_arch = "x86_64"))]
#[cfg_attr(feature = "owned-unwind-stub", unsafe(no_mangle))]
pub unsafe extern "C-unwind" fn _Unwind_ForcedUnwind(
    _exception: *mut UnwindException,
    _stop: Option<UnwindStopFn>,
    _argument: *mut c_void,
) -> UnwindReasonCode {
    URC_FATAL_PHASE2_ERROR
}

#[unsafe(no_mangle)]
unsafe extern "C" fn __frankenlibc_owned_forced_from_cursor(
    exception: *mut UnwindException,
    stop: Option<UnwindStopFn>,
    argument: *mut c_void,
    capture: &CapturedUnwindCursor,
) -> UnwindReasonCode {
    let Some(stop) = stop else {
        return URC_FATAL_PHASE2_ERROR;
    };
    if exception.is_null() {
        return URC_FATAL_PHASE2_ERROR;
    }
    // SAFETY: these reserved words survive discarded cleanup frames. There is
    // no heap/TLS side table, so nested exceptions and native threads remain
    // independent and a C cleanup longjmp may abandon this propagation.
    unsafe {
        (*exception).private_1 = stop as usize;
        (*exception).private_2 = argument as usize;
    }
    let cursor = UnwindCursor::captured(capture);
    emit_owned_unwind_jsonl(
        "forced_unwind_enter",
        0,
        cursor.ip,
        cursor.stack_pointer(),
        0,
    );
    owned_phase2_cleanup(exception, cursor)
}

#[cfg(any(debug_assertions, feature = "owned-unwind-stub"))]
#[cfg_attr(feature = "owned-unwind-stub", unsafe(no_mangle))]
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
#[cfg_attr(feature = "owned-unwind-stub", unsafe(no_mangle))]
pub unsafe extern "C" fn _Unwind_SetIP(ctx: *mut UnwindContext, new_value: UnwindWord) {
    if ctx.is_null() {
        return;
    }
    // SAFETY: mirrors _Unwind_SetGR's owned-cursor contract.
    unsafe { (*ctx).ip = new_value };
}

/// Crate-internal owned `.eh_frame` registration entrypoints used by
/// `dlfcn_unwind` whenever `standalone` or `owned-unwind-stub` is enabled,
/// avoiding undefined external references or interposable PLT calls to
/// host `libgcc_s`.
#[cfg_attr(
    not(any(feature = "standalone", feature = "owned-unwind-stub")),
    allow(dead_code)
)]
pub(crate) unsafe fn register_owned_frame(fde: *mut c_void) {
    register_frame(fde as usize, 0);
}

#[cfg_attr(
    not(any(feature = "standalone", feature = "owned-unwind-stub")),
    allow(dead_code)
)]
pub(crate) unsafe fn deregister_owned_frame(fde: *mut c_void) {
    deregister_frame(fde as usize);
}

#[cfg(any(debug_assertions, feature = "owned-unwind-stub"))]
#[cfg_attr(feature = "owned-unwind-stub", unsafe(no_mangle))]
pub unsafe extern "C" fn __register_frame(fde: *mut c_void) {
    register_frame(fde as usize, 0);
}

#[cfg(any(debug_assertions, feature = "owned-unwind-stub"))]
#[cfg_attr(feature = "owned-unwind-stub", unsafe(no_mangle))]
pub unsafe extern "C" fn __register_frame_info(fde: *mut c_void, object: *mut c_void) {
    register_frame(fde as usize, object as usize);
}

#[cfg(any(debug_assertions, feature = "owned-unwind-stub"))]
#[cfg_attr(feature = "owned-unwind-stub", unsafe(no_mangle))]
pub unsafe extern "C" fn __deregister_frame(fde: *mut c_void) {
    deregister_frame(fde as usize);
}

#[cfg(any(debug_assertions, feature = "owned-unwind-stub"))]
#[cfg_attr(feature = "owned-unwind-stub", unsafe(no_mangle))]
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

pub(crate) struct UnwindForkGuard {
    _registry: MutexGuard<'static, [FrameRegistration; FRAME_REGISTRY_SLOTS]>,
}

/// Hold `FRAME_REGISTRY` across `fork()` so a concurrent `__register_frame`,
/// `__deregister_frame`, or unwind snapshot cannot strand the lock in the child.
pub(crate) fn unwind_fork_prepare() -> UnwindForkGuard {
    UnwindForkGuard {
        _registry: frame_registry(),
    }
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

/// Decode while allocations are locally owned, then return only copyable
/// frame data. Neither stop callbacks nor landing-pad transfers may strand
/// an EH-frame buffer, loader snapshot, or registry lock on a discarded stack.
fn owned_frame_state(
    cursor: UnwindCursor,
) -> Result<Option<(OwnedFdeRecord, CfiEvaluationState)>, OwnedUnwindDecodeError> {
    if cursor.ip == 0 {
        return Ok(None);
    }
    let ip = cursor.lookup_ip();
    let Some(record) = find_registered_fde_record_for_ip(ip)? else {
        // A live PC without unwind metadata is an unsupported frame, not
        // proof that every outer destructor has run. Only a recovered zero
        // return address is an observed stack end.
        return Err(OwnedUnwindDecodeError::MissingFde);
    };
    let state = evaluate_cfi_state(&record.eh_frame, record.fde, ip)?;
    Ok(Some((record.fde, state)))
}

fn unwind_caller(
    cursor: UnwindCursor,
    fde: OwnedFdeRecord,
    state: CfiEvaluationState,
    bounds: &mut UnwindStackBounds,
) -> Result<UnwindCursor, OwnedUnwindDecodeError> {
    // Expression operands refer to the copied EH-frame bytes. Reacquire them
    // only after the stop/personality callback has elected to continue. This
    // keeps owned buffers off discarded landing-pad stacks and lets a native
    // boundary stop before any attempt to read its unsupported caller state.
    let caller = if state.has_expressions() {
        let record = find_registered_fde_record_for_ip(cursor.lookup_ip())?
            .ok_or(OwnedUnwindDecodeError::MissingFde)?;
        if record.fde != fde
            || evaluate_cfi_state(&record.eh_frame, fde, cursor.lookup_ip())? != state
        {
            return Err(OwnedUnwindDecodeError::MalformedRecord);
        }
        unwind_caller_with_metadata(cursor, fde, state, *bounds, &record.eh_frame)?
    } else {
        unwind_caller_with_metadata(cursor, fde, state, *bounds, &[])?
    };
    if fde.signal_frame {
        // A kernel signal context can resume another stack (SA_ONSTACK).
        // Only this explicit CIE marker permits a discontinuity; subsequent
        // ordinary frames again obey a bounded, monotonically growing SP.
        *bounds = UnwindStackBounds::new(caller).ok_or(OwnedUnwindDecodeError::Overflow)?;
    }
    Ok(caller)
}

fn unwind_caller_with_metadata(
    cursor: UnwindCursor,
    fde: OwnedFdeRecord,
    state: CfiEvaluationState,
    bounds: UnwindStackBounds,
    eh_frame: &[u8],
) -> Result<UnwindCursor, OwnedUnwindDecodeError> {
    if fde.return_address_register != X86_64_DWARF_RIP {
        return Err(OwnedUnwindDecodeError::MalformedRecord);
    }
    let cfa = if let Some(expression) = state.cfa_expression {
        evaluate_dwarf_expression(eh_frame, expression, &cursor.registers, bounds, None)?
    } else {
        let base = cursor
            .registers
            .get(state.cfa_register)
            .copied()
            .ok_or(OwnedUnwindDecodeError::MalformedRecord)?;
        checked_add_signed_usize(base, state.cfa_offset).ok_or(OwnedUnwindDecodeError::Overflow)?
    };
    if cfa == 0
        || cfa == cursor.stack_pointer()
        || (!fde.signal_frame && (cfa < cursor.stack_pointer() || cfa > bounds.end))
        || !cfa.is_multiple_of(core::mem::align_of::<usize>())
    {
        return Err(OwnedUnwindDecodeError::MalformedRecord);
    }
    let mut caller = cursor;
    // Ordinary calls preserve the SysV nonvolatile registers. Signals save the
    // entire interrupted machine context, including volatile GPRs and SP.
    // Every rule reads the original cursor, not earlier loop assignments.
    for register in 0..=X86_64_DWARF_RIP {
        if !fde.signal_frame && !matches!(register, 3 | 6 | 12..=16) {
            continue;
        }
        caller.registers[register] = match state.register_rule(register) {
            CfiRegisterRule::Undefined => 0,
            CfiRegisterRule::SameValue => cursor.registers[register],
            CfiRegisterRule::Offset(offset) => {
                let address = checked_add_signed_usize(cfa, offset)
                    .ok_or(OwnedUnwindDecodeError::Overflow)?;
                read_stack_word(address, bounds)?
            }
            CfiRegisterRule::ValOffset(offset) => {
                checked_add_signed_usize(cfa, offset).ok_or(OwnedUnwindDecodeError::Overflow)?
            }
            CfiRegisterRule::Register(source) => *cursor
                .registers
                .get(source)
                .ok_or(OwnedUnwindDecodeError::MalformedRecord)?,
            CfiRegisterRule::Expression(expression) => {
                let address = evaluate_dwarf_expression(
                    eh_frame,
                    expression,
                    &cursor.registers,
                    bounds,
                    Some(cfa),
                )?;
                read_stack_word(address, bounds)?
            }
            CfiRegisterRule::ValExpression(expression) => evaluate_dwarf_expression(
                eh_frame,
                expression,
                &cursor.registers,
                bounds,
                Some(cfa),
            )?,
        };
    }
    if fde.signal_frame
        && !matches!(
            state.register_rule(X86_64_DWARF_RSP),
            CfiRegisterRule::SameValue | CfiRegisterRule::Undefined
        )
        && caller.registers[X86_64_DWARF_RSP] != cfa
    {
        return Err(OwnedUnwindDecodeError::MalformedRecord);
    }
    caller.registers[X86_64_DWARF_RSP] = cfa;
    caller.ip = caller.registers[X86_64_DWARF_RIP];
    caller.ip_before_instruction = fde.signal_frame;
    Ok(caller)
}

fn owned_phase2_cleanup(
    exception: *mut UnwindException,
    mut cursor: UnwindCursor,
) -> UnwindReasonCode {
    let Some(mut bounds) = UnwindStackBounds::new(cursor) else {
        return URC_FATAL_PHASE2_ERROR;
    };
    // SAFETY: all entries reject null exceptions; the header outlives every
    // cleanup. Callback state belongs to the exception, not an unwound frame.
    let (exception_class, stop_address, destination) = unsafe {
        (
            (*exception).exception_class,
            (*exception).private_1,
            (*exception).private_2,
        )
    };
    let stop = if stop_address == 0 {
        None
    } else {
        // SAFETY: ForcedUnwind wrote this function pointer into private_1.
        Some(unsafe { core::mem::transmute::<usize, UnwindStopFn>(stop_address) })
    };

    for frame_index in 0..MAX_UNWIND_FRAMES {
        let frame_result = owned_frame_state(cursor);
        let frame = frame_result.as_ref().ok().copied().flatten();
        let at_end = matches!(frame_result, Ok(None));
        let mut context = cursor.context(frame_index, frame.map(|(fde, _)| fde));
        let mut actions = UA_CLEANUP_PHASE;
        if let Some(stop) = stop {
            actions |= UA_FORCE_UNWIND;
            if at_end {
                actions |= UA_END_OF_STACK;
                context.ip = 0;
            }
            // SAFETY: context is live for this callback; no resource-owning
            // local remains. The callback may transfer control nonlocally,
            // including at a native clone boundary with no caller FDE. Its
            // recovered SP/IP are valid independently of that FDE. A callback
            // that continues still receives the decoding error below.
            let code = unsafe {
                stop(
                    1,
                    actions,
                    exception_class,
                    exception,
                    &mut context,
                    destination as *mut c_void,
                )
            };
            if code != URC_NO_REASON {
                return URC_FATAL_PHASE2_ERROR;
            }
            if at_end {
                return URC_END_OF_STACK;
            }
        } else if cursor.stack_pointer() == destination {
            actions |= UA_HANDLER_FRAME;
        }
        if let Err(error) = frame_result {
            trace_owned_unwind(format_args!("phase2 decode {error:?} ip={:#x}", cursor.ip));
            return URC_FATAL_PHASE2_ERROR;
        }
        let Some((fde, state)) = frame else {
            return URC_FATAL_PHASE2_ERROR;
        };
        // Preserve the native forced engine's abort-profile handling: those
        // own-image frames have no Drop cleanup, only terminate pads. Stop
        // callbacks and CFI stepping still run, and ordinary exceptions keep
        // their personalities in every profile.
        if let Some(personality) = fde.personality
            && !(stop.is_some() && own_panic_abort_frame(cursor.lookup_ip()))
        {
            let code = call_personality(
                personality,
                actions,
                exception_class,
                exception,
                &mut context,
            );
            trace_owned_unwind(format_args!(
                "phase2 frame={frame_index} ip={:#x} sp={:#x} actions={actions:#x} code={code}",
                cursor.ip,
                cursor.stack_pointer()
            ));
            match code {
                URC_INSTALL_CONTEXT => {
                    // The cursor is already the state of this frame at its
                    // suspended call. A cleanup may change only landing-pad
                    // scratch registers and IP; no fabricated RBP is required.
                    if context.ip == 0
                        || context.stack_pointer == 0
                        || context.stack_pointer != cursor.stack_pointer()
                    {
                        return URC_FATAL_PHASE2_ERROR;
                    }
                    // DW_CFA_GNU_args_size describes outgoing arguments at the
                    // throwing call site. CFA recovery already accounts for
                    // them when stepping frames; discard them only when
                    // transferring control to this frame's landing pad.
                    let Some(stack_pointer) =
                        context.stack_pointer.checked_add(state.gnu_args_size)
                    else {
                        return URC_FATAL_PHASE2_ERROR;
                    };
                    // The scan window alone cannot prove a page is mapped.
                    // Validate the adjusted landing stack through the same
                    // bounded, fault-safe read used for CFI register recovery.
                    if read_stack_word(stack_pointer, bounds).is_err() {
                        return URC_FATAL_PHASE2_ERROR;
                    }
                    let install = OwnedLandingPadInstall {
                        ip: context.ip,
                        stack_pointer,
                        frame_pointer: context.general_registers[X86_64_DWARF_RBP],
                        general_register_0: context.general_registers[0],
                        general_register_1: context.general_registers[1],
                    };
                    // SAFETY: the live cursor was captured at entry and each
                    // caller state was recovered through bounded CFI reads.
                    // All nonvolatile registers are restored before the jump.
                    unsafe { install_landing_pad_context(install, &context.general_registers) };
                }
                URC_CONTINUE_UNWIND => {}
                _ => return URC_FATAL_PHASE2_ERROR,
            }
        }
        if actions & UA_HANDLER_FRAME != 0 {
            // The selected handler must install its context in phase two.
            return URC_FATAL_PHASE2_ERROR;
        }
        cursor = match unwind_caller(cursor, fde, state, &mut bounds) {
            Ok(caller) => caller,
            Err(_) => return URC_FATAL_PHASE2_ERROR,
        };
    }
    // A bounded walk exhausting its budget is not an observed end of stack.
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
    cursor: X86PhysicalCursor,
) -> UnwindReasonCode {
    owned_forced_unwind_from_cursor_mode(exception, stop_fn, stop_parameter, cursor, false)
}

fn owned_forced_unwind_from_cursor_mode(
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
    mut ip_before_insn: bool,
) -> UnwindReasonCode {
    let exception_class = if exception.is_null() {
        0
    } else {
        // SAFETY: caller validated non-null exception pointer.
        unsafe { (*exception).exception_class }
    };

    for frame_index in 0..MAX_UNWIND_FRAMES {
        if cursor.ip == 0 {
            break;
        }
        let lookup_ip = frame_lookup_ip_for_mode(cursor.ip, ip_before_insn);
        let record = match find_registered_fde_record_for_ip(lookup_ip) {
            Ok(Some(record)) => Some(record),
            Ok(None) => None,
            Err(_) => return URC_FATAL_PHASE2_ERROR,
        };
        let mut context = context_for_cursor_record(
            cursor,
            ip_before_insn,
            frame_index,
            lookup_ip,
            record.as_ref(),
        );
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
            context = context_for_cursor_record(
                cursor,
                ip_before_insn,
                frame_index,
                lookup_ip,
                Some(&record),
            );
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

        match step_x86_64_cursor_with_mode(cursor, ip_before_insn) {
            Ok(Some((next, next_ip_before))) => {
                cursor = next;
                ip_before_insn = next_ip_before;
            }
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

    // Exhausting MAX_UNWIND_FRAMES without reaching end-of-stack is a runaway
    // or cyclic unwind frame chain, not a true stack bottom.
    URC_FATAL_PHASE2_ERROR
}

fn trace_owned_unwind(args: std::fmt::Arguments<'_>) {
    if crate::malloc_abi::in_allocator_reentry_context() {
        return;
    }
    static ENABLED: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);
    let state = match ENABLED.load(std::sync::atomic::Ordering::Acquire) {
        1 => false,
        2 => true,
        _ => {
            let active =
                unsafe { crate::stdlib_abi::native_getenv(b"FRANKENLIBC_OWNED_UNWIND_TRACE") };
            let enabled = !active.is_null();
            ENABLED.store(
                if enabled { 2 } else { 1 },
                std::sync::atomic::Ordering::Release,
            );
            enabled
        }
    };
    if state {
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
    if crate::malloc_abi::in_allocator_reentry_context() {
        return;
    }
    static DISABLED_FAST: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);
    if DISABLED_FAST.load(std::sync::atomic::Ordering::Acquire) == 1 {
        return;
    }
    if DISABLED_FAST.load(std::sync::atomic::Ordering::Acquire) == 0 {
        let raw = unsafe { crate::stdlib_abi::native_getenv(b"FRANKENLIBC_OWNED_UNWIND_JSONL") };
        if raw.is_null() || unsafe { *raw == 0 } {
            DISABLED_FAST.store(1, std::sync::atomic::Ordering::Release);
            return;
        }
        DISABLED_FAST.store(2, std::sync::atomic::Ordering::Release);
    }
    static JSONL_PATH: std::sync::OnceLock<Option<std::ffi::OsString>> = std::sync::OnceLock::new();
    let Some(path) = JSONL_PATH
        .get_or_init(|| {
            std::env::var_os("FRANKENLIBC_OWNED_UNWIND_JSONL").filter(|p| !p.is_empty())
        })
        .as_deref()
    else {
        return;
    };
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
fn frame_lookup_ip_for_mode(ip: usize, ip_before_insn: bool) -> usize {
    if ip_before_insn {
        ip
    } else {
        ip.saturating_sub(1)
    }
}

fn step_x86_64_cursor(
    cursor: X86PhysicalCursor,
) -> Result<Option<X86PhysicalCursor>, OwnedUnwindDecodeError> {
    Ok(step_x86_64_cursor_with_mode(cursor, false)?.map(|(next, _)| next))
}

fn step_x86_64_cursor_with_mode(
    cursor: X86PhysicalCursor,
    ip_before_insn: bool,
) -> Result<Option<(X86PhysicalCursor, bool)>, OwnedUnwindDecodeError> {
    if cursor.ip == 0 || cursor.rsp == 0 {
        return Ok(None);
    }
    let lookup_ip = frame_lookup_ip_for_mode(cursor.ip, ip_before_insn);
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
            CfiRegisterRule::Expression(_) | CfiRegisterRule::ValExpression(_) => {
                return Err(OwnedUnwindDecodeError::UnsupportedCfiOpcode(
                    DW_CFA_EXPRESSION,
                ));
            }
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
            CfiRegisterRule::Expression(_) | CfiRegisterRule::ValExpression(_) => {
                return Err(OwnedUnwindDecodeError::UnsupportedCfiOpcode(
                    DW_CFA_EXPRESSION,
                ));
            }
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
                CfiRegisterRule::Expression(_) | CfiRegisterRule::ValExpression(_) => Err(
                    OwnedUnwindDecodeError::UnsupportedCfiOpcode(DW_CFA_EXPRESSION),
                ),
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
        return Ok(Some((next, record.fde.signal_frame)));
    }
    // Linux x86_64 signal restorer (`mov $15, %rax; syscall` = 48 c7 c0 0f 00 00 00 0f 05)
    // has no `.eh_frame` FDE; step directly across `rt_sigframe`'s `ucontext_t` at `cursor.rsp`
    // (matching libgcc `x86_64_fallback_frame_state`, including `sigaltstack` frames) using
    // fault-safe kernel copies so page-boundary stubs, execute-only pages, or corrupt frames
    // never fault in Rust.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    if cursor.ip >= 4096
        && cursor.rsp >= 4096
        && cursor.rsp.is_multiple_of(core::mem::align_of::<usize>())
    {
        const RT_SIGRETURN_X86_64: [u8; 9] = [0x48, 0xc7, 0xc0, 0x0f, 0x00, 0x00, 0x00, 0x0f, 0x05];
        let is_sigreturn = cursor.ip == crate::signal_abi::signal_restorer_trampoline_addr() || {
            let mut code = [0u8; 9];
            unsafe {
                crate::io_abi::iov_snapshot::copy_user_bytes_raw(
                    cursor.ip as *const u8,
                    code.as_mut_ptr(),
                    code.len(),
                )
            }
            .is_ok()
                && code == RT_SIGRETURN_X86_64
        };
        if is_sigreturn
            && let Some(gregs_addr) = cursor
                .rsp
                .checked_add(core::mem::offset_of!(libc::ucontext_t, uc_mcontext.gregs))
        {
            let mut gregs: [libc::greg_t; 23] = [0; 23];
            if unsafe {
                crate::io_abi::iov_snapshot::copy_user_bytes_raw(
                    gregs_addr as *const u8,
                    gregs.as_mut_ptr().cast::<u8>(),
                    core::mem::size_of_val(&gregs),
                )
            }
            .is_ok()
            {
                let next = X86PhysicalCursor {
                    ip: gregs[libc::REG_RIP as usize] as usize,
                    rsp: gregs[libc::REG_RSP as usize] as usize,
                    rbp: gregs[libc::REG_RBP as usize] as usize,
                    rbx: gregs[libc::REG_RBX as usize] as usize,
                    r12: gregs[libc::REG_R12 as usize] as usize,
                    r13: gregs[libc::REG_R13 as usize] as usize,
                    r14: gregs[libc::REG_R14 as usize] as usize,
                    r15: gregs[libc::REG_R15 as usize] as usize,
                };
                if next.ip != 0 && (next.rsp != cursor.rsp || next.ip != cursor.ip) {
                    return Ok(Some((next, true)));
                }
            }
        }
    }

    // Fallback for hand-written stubs without `.eh_frame`: step `%rbp` chain via
    // a fault-safe 16-byte copy so an unmapped/PROT_NONE `%rbp` in `-O2` code
    // never SIGSEGVs `backtrace()`.
    let Some(stack_limit) = cursor.rsp.checked_add(MAX_STACK_SCAN_BYTES) else {
        return Ok(None);
    };
    if !valid_frame_pointer(cursor.rbp, cursor.rsp, stack_limit) {
        return Ok(None);
    }
    let mut frame_pair = [0usize; 2];
    if unsafe {
        crate::io_abi::iov_snapshot::copy_user_bytes_raw(
            cursor.rbp as *const u8,
            frame_pair.as_mut_ptr().cast::<u8>(),
            core::mem::size_of::<[usize; 2]>(),
        )
    }
    .is_err()
    {
        return Ok(None);
    }
    let next_rbp = frame_pair[0];
    let next_ip = frame_pair[1];
    let Some(next_rsp) = cursor.rbp.checked_add(2 * core::mem::size_of::<usize>()) else {
        return Ok(None);
    };
    if next_ip == 0 || next_rsp <= cursor.rsp {
        return Ok(None);
    }
    Ok(Some((
        X86PhysicalCursor {
            ip: next_ip,
            rsp: next_rsp,
            rbp: next_rbp,
            rbx: cursor.rbx,
            r12: cursor.r12,
            r13: cursor.r13,
            r14: cursor.r14,
            r15: cursor.r15,
        },
        false,
    )))
}

fn owned_phase1_search(
    exception: *mut UnwindException,
    mut cursor: UnwindCursor,
) -> Result<Option<usize>, ()> {
    let mut bounds = UnwindStackBounds::new(cursor).ok_or(())?;
    // SAFETY: the raise entry rejected a null exception pointer.
    let exception_class = unsafe { (*exception).exception_class };
    for frame_index in 0..MAX_UNWIND_FRAMES {
        let Some((fde, state)) = owned_frame_state(cursor).map_err(|_| ())? else {
            return Ok(None);
        };
        if let Some(personality) = fde.personality {
            let mut context = cursor.context(frame_index, Some(fde));
            match call_personality(
                personality,
                UA_SEARCH_PHASE,
                exception_class,
                exception,
                &mut context,
            ) {
                URC_HANDLER_FOUND => return Ok(Some(cursor.stack_pointer())),
                URC_CONTINUE_UNWIND => {}
                _ => return Err(()),
            }
        }
        cursor = unwind_caller(cursor, fde, state, &mut bounds).map_err(|_| ())?;
    }
    Err(())
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
    // First search explicitly registered frames (__register_frame).
    // Hold `FRAME_REGISTRY` while copying registered `.eh_frame` bytes so a
    // concurrent `dlclose` -> `__deregister_frame` -> `munmap` cannot unmap a
    // slot's `.eh_frame` while we copy it, then release before DWARF parsing or
    // `dl_iterate_phdr`.
    let snapshots = {
        let registry = frame_registry();
        let mut snapshots = Vec::new();
        for slot in registry.iter().filter(|slot| slot.fde != 0) {
            if let Ok(eh_frame) = copy_registered_eh_frame(slot.fde) {
                snapshots.push((slot.fde, eh_frame));
            }
        }
        snapshots
    };
    for (fde_base, eh_frame) in snapshots {
        if let Ok(Some(fde)) = find_fde_for_ip(&eh_frame, fde_base, ip, true) {
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
        let Ok((_, after_adj_initial)) = read_encoded_pointer(
            hdr,
            adj_offset,
            range.eh_frame_hdr_start + adj_offset,
            table_enc,
            true,
            0,
            range.eh_frame_hdr_start,
        ) else {
            continue;
        };
        let Ok((adj_fde_ptr, _)) = read_encoded_pointer(
            hdr,
            after_adj_initial,
            range.eh_frame_hdr_start + after_adj_initial,
            table_enc,
            true,
            0,
            range.eh_frame_hdr_start,
        ) else {
            continue;
        };
        if let Ok(Some(record)) = decode_live_fde_at_address(range, adj_fde_ptr, ip) {
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
    let mut cie = parse_cie_record_with_bases(
        cie_slice,
        cie_ptr,
        cie_rec,
        true,
        0,
        range.eh_frame_hdr_start,
    )?;
    let _ = &mut cie;

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
        ip_before_instruction: false,
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
        ip_before_insn: fde.signal_frame,
    }
}

fn context_for_cursor_record(
    cursor: X86PhysicalCursor,
    ip_before_insn: bool,
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
        ip_before_instruction: false,
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
        ip_before_insn: ip_before_insn || fde.is_some_and(|f| f.signal_frame),
    }
}

fn empty_context_at_end(last_stack_pointer: usize) -> UnwindContext {
    UnwindContext {
        ip: 0,
        ip_before_instruction: false,
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
        ip_before_insn: false,
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
            if context.stack_pointer > context.frame_pointer {
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

unsafe fn install_landing_pad_context(
    install: OwnedLandingPadInstall,
    registers: &[UnwindWord; MAX_UNWIND_GR],
) -> ! {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: the caller validated that the target IP, frame pointer, and
        // stack pointer describe an in-stack x86_64 handler frame. This path
        // never returns to Rust; it installs the Itanium ABI landing-pad
        // registers (GR0/GR1 map to RAX/RDX on x86_64 SysV) and jumps to the
        // personality-selected landing pad.
        unsafe {
            core::arch::asm!(
                "mov rbx, [rdi + 24]",
                "mov rbp, [rdi + 48]",
                "mov r12, [rdi + 96]",
                "mov r13, [rdi + 104]",
                "mov r14, [rdi + 112]",
                "mov r15, [rdi + 120]",
                "mov rsp, rcx",
                "jmp rsi",
                in("rdi") registers.as_ptr(),
                in("rcx") install.stack_pointer,
                in("rsi") install.ip,
                in("rax") install.general_register_0,
                in("rdx") install.general_register_1,
                options(noreturn)
            );
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (install, registers);
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
    parse_cie_record_with_bases(eh_frame, section_addr, record, resolve_indirect, 0, 0)
}

fn parse_cie_record_with_bases(
    eh_frame: &[u8],
    section_addr: usize,
    record: EhFrameRecord,
    resolve_indirect: bool,
    text_rel_base: usize,
    data_rel_base: usize,
) -> Result<OwnedCieRecord, OwnedUnwindDecodeError> {
    let (version, mut cursor) = read_u8(eh_frame, record.body)?;
    if !matches!(version, 1 | 3 | 4) {
        return Err(OwnedUnwindDecodeError::UnsupportedCieVersion(version));
    }

    let (augmentation, after_augmentation) = read_c_string(eh_frame, cursor, record.end)?;
    cursor = after_augmentation;
    if version == 4 {
        let (addr_size, after_addr_size) = read_u8(eh_frame, cursor)?;
        let (seg_size, after_seg_size) = read_u8(eh_frame, after_addr_size)?;
        if usize::from(addr_size) != core::mem::size_of::<usize>() || seg_size != 0 {
            return Err(OwnedUnwindDecodeError::MalformedRecord);
        }
        cursor = after_seg_size;
    }
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
    let mut signal_frame = false;
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
                // GNU as .cfi_signal_frame emits a marker with no payload.
                // Recognize it while scanning other FDEs in the same object.
                b'S' => signal_frame = true,
                other => return Err(OwnedUnwindDecodeError::UnsupportedAugmentation(other)),
            }
        }
        if augmentation_cursor > augmentation_end {
            return Err(OwnedUnwindDecodeError::Truncated);
        }
        cursor = augmentation_end;
    } else if augmentation == b"S" {
        signal_frame = true;
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
        signal_frame,
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
        signal_frame: cie.signal_frame,
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
    if state.cfa_register == UNSET_DWARF_REGISTER && state.cfa_expression.is_none() {
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
    if state.cfa_expression.is_some() {
        return Err(OwnedUnwindDecodeError::UnsupportedCfiOpcode(
            DW_CFA_DEF_CFA_EXPRESSION,
        ));
    }
    for rule in state.register_rules {
        match rule {
            CfiRegisterRule::Expression(_) => {
                return Err(OwnedUnwindDecodeError::UnsupportedCfiOpcode(
                    DW_CFA_EXPRESSION,
                ));
            }
            CfiRegisterRule::ValExpression(_) => {
                return Err(OwnedUnwindDecodeError::UnsupportedCfiOpcode(
                    DW_CFA_VAL_EXPRESSION,
                ));
            }
            _ => {}
        }
    }
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
            DW_CFA_REGISTER => {
                let (register, after_register) = decode_uleb128(input, cursor)?;
                let (source, next) = decode_uleb128(input, after_register)?;
                cursor = next;
                set_register_rule(state, register, CfiRegisterRule::Register(source));
            }
            DW_CFA_REMEMBER_STATE => saved_states.push(*state),
            DW_CFA_RESTORE_STATE => {
                let pc = state.pc;
                *state = saved_states
                    .pop()
                    .ok_or(OwnedUnwindDecodeError::MalformedRecord)?;
                // DWARF restores register rules, not the instruction location.
                state.pc = pc;
            }
            DW_CFA_DEF_CFA => {
                let (register, after_register) = decode_uleb128(input, cursor)?;
                let (offset, after_offset) = decode_uleb128(input, after_register)?;
                cursor = after_offset;
                state.cfa_register = register;
                state.cfa_offset = usize_to_isize(offset)?;
                state.cfa_expression = None;
            }
            DW_CFA_DEF_CFA_REGISTER => {
                if state.cfa_expression.is_some() {
                    return Err(OwnedUnwindDecodeError::MalformedRecord);
                }
                let (register, next) = decode_uleb128(input, cursor)?;
                cursor = next;
                state.cfa_register = register;
            }
            DW_CFA_DEF_CFA_OFFSET => {
                if state.cfa_expression.is_some() {
                    return Err(OwnedUnwindDecodeError::MalformedRecord);
                }
                let (offset, next) = decode_uleb128(input, cursor)?;
                cursor = next;
                state.cfa_offset = usize_to_isize(offset)?;
            }
            DW_CFA_DEF_CFA_EXPRESSION => {
                let (expression, next) = read_cfi_expression(input, cursor, end)?;
                cursor = next;
                state.cfa_expression = Some(expression);
            }
            DW_CFA_EXPRESSION | DW_CFA_VAL_EXPRESSION => {
                let (register, after_register) = decode_uleb128(input, cursor)?;
                let (expression, next) = read_cfi_expression(input, after_register, end)?;
                cursor = next;
                let rule = if opcode == DW_CFA_EXPRESSION {
                    CfiRegisterRule::Expression(expression)
                } else {
                    CfiRegisterRule::ValExpression(expression)
                };
                set_register_rule(state, register, rule);
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
                state.cfa_expression = None;
            }
            DW_CFA_DEF_CFA_OFFSET_SF => {
                if state.cfa_expression.is_some() {
                    return Err(OwnedUnwindDecodeError::MalformedRecord);
                }
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
            0x2f => {
                let (register, after_register) = decode_uleb128(input, cursor)?;
                let (offset, after_offset) = decode_uleb128(input, after_register)?;
                cursor = after_offset;
                let neg_offset = usize_to_isize(offset)?
                    .checked_neg()
                    .ok_or(OwnedUnwindDecodeError::Overflow)?;
                set_register_signed_offset(state, register, neg_offset, fde.data_alignment_factor)?;
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

fn read_cfi_expression(
    input: &[u8],
    cursor: usize,
    end: usize,
) -> Result<(CfiExpression, usize), OwnedUnwindDecodeError> {
    let (len, start) = decode_uleb128(input, cursor)?;
    if len > MAX_DWARF_EXPRESSION_BYTES {
        return Err(OwnedUnwindDecodeError::ExpressionLimit);
    }
    let next = skip_bytes(start, len, end)?;
    Ok((CfiExpression { start, len }, next))
}

fn read_stack_word(
    address: usize,
    bounds: UnwindStackBounds,
) -> Result<usize, OwnedUnwindDecodeError> {
    if !bounds.contains_word(address) {
        return Err(OwnedUnwindDecodeError::InvalidStackAddress);
    }
    // Bounds constrain expression arithmetic but do not prove a page is
    // mapped. Use the same fault-safe import as the physical cursor walker.
    read_word(address).ok_or(OwnedUnwindDecodeError::InvalidStackAddress)
}

struct DwarfExpressionStack {
    words: [usize; MAX_DWARF_EXPRESSION_STACK],
    len: usize,
}

impl DwarfExpressionStack {
    fn push(&mut self, word: usize) -> Result<(), OwnedUnwindDecodeError> {
        let slot = self
            .words
            .get_mut(self.len)
            .ok_or(OwnedUnwindDecodeError::ExpressionLimit)?;
        *slot = word;
        self.len += 1;
        Ok(())
    }

    fn pop(&mut self) -> Result<usize, OwnedUnwindDecodeError> {
        self.len = self
            .len
            .checked_sub(1)
            .ok_or(OwnedUnwindDecodeError::MalformedExpression)?;
        Ok(self.words[self.len])
    }

    fn peek(&self, depth: usize) -> Result<usize, OwnedUnwindDecodeError> {
        let index = self
            .len
            .checked_sub(depth + 1)
            .ok_or(OwnedUnwindDecodeError::MalformedExpression)?;
        Ok(self.words[index])
    }
}

/// Bounded DWARF 5 sections 2.5.1 / 6.4.2 expression evaluation. Address
/// dereferences stay inside the current stack segment. Calls, branches, TLS,
/// typed expressions and other debug-section dependencies fail closed.
fn evaluate_dwarf_expression(
    input: &[u8],
    expression: CfiExpression,
    registers: &[usize; MAX_UNWIND_GR],
    bounds: UnwindStackBounds,
    initial_cfa: Option<usize>,
) -> Result<usize, OwnedUnwindDecodeError> {
    if expression.len > MAX_DWARF_EXPRESSION_BYTES {
        return Err(OwnedUnwindDecodeError::ExpressionLimit);
    }
    let end = expression
        .start
        .checked_add(expression.len)
        .ok_or(OwnedUnwindDecodeError::Overflow)?;
    let program = input
        .get(expression.start..end)
        .ok_or(OwnedUnwindDecodeError::Truncated)?;
    let mut stack = DwarfExpressionStack {
        words: [0; MAX_DWARF_EXPRESSION_STACK],
        len: 0,
    };
    // Register expression/value-expression rules start with CFA on the stack;
    // a CFA expression has no pre-existing CFA and starts with an empty stack.
    if let Some(cfa) = initial_cfa {
        stack.push(cfa)?;
    }
    let mut cursor = 0;
    let mut steps = 0;
    while cursor < program.len() {
        steps += 1;
        if steps > MAX_DWARF_EXPRESSION_STEPS {
            return Err(OwnedUnwindDecodeError::ExpressionLimit);
        }
        let (opcode, next) = read_u8(program, cursor)?;
        cursor = next;
        match opcode {
            0x03 | 0x0e => {
                let (value, next) = read_u64(program, cursor)?;
                cursor = next;
                stack
                    .push(usize::try_from(value).map_err(|_| OwnedUnwindDecodeError::Overflow)?)?;
            }
            0x06 => {
                let address = stack.pop()?;
                stack.push(read_stack_word(address, bounds)?)?;
            }
            0x08 | 0x09 => {
                let (value, next) = read_u8(program, cursor)?;
                cursor = next;
                stack.push(if opcode == 0x09 {
                    (value as i8 as isize) as usize
                } else {
                    value as usize
                })?;
            }
            0x0a | 0x0b => {
                let (value, next) = read_u16(program, cursor)?;
                cursor = next;
                stack.push(if opcode == 0x0b {
                    (value as i16 as isize) as usize
                } else {
                    value as usize
                })?;
            }
            0x0c | 0x0d => {
                let (value, next) = read_u32(program, cursor)?;
                cursor = next;
                stack.push(if opcode == 0x0d {
                    (value as i32 as isize) as usize
                } else {
                    value as usize
                })?;
            }
            0x0f => {
                let (value, next) = read_i64(program, cursor)?;
                cursor = next;
                stack.push(
                    isize::try_from(value).map_err(|_| OwnedUnwindDecodeError::Overflow)? as usize,
                )?;
            }
            0x10 => {
                let (value, next) = decode_uleb128(program, cursor)?;
                cursor = next;
                stack.push(value)?;
            }
            0x11 => {
                let (value, next) = decode_sleb128(program, cursor)?;
                cursor = next;
                stack.push(value as usize)?;
            }
            0x12 => stack.push(stack.peek(0)?)?,
            0x13 => {
                stack.pop()?;
            }
            0x14 => stack.push(stack.peek(1)?)?,
            0x15 => {
                let (depth, next) = read_u8(program, cursor)?;
                cursor = next;
                stack.push(stack.peek(depth as usize)?)?;
            }
            0x16 => {
                let right = stack.pop()?;
                let left = stack.pop()?;
                stack.push(right)?;
                stack.push(left)?;
            }
            0x1f | 0x20 => {
                let word = stack.pop()?;
                stack.push(if opcode == 0x1f {
                    word.wrapping_neg()
                } else {
                    !word
                })?;
            }
            0x23 => {
                let (addend, next) = decode_uleb128(program, cursor)?;
                cursor = next;
                let left = stack.pop()?;
                stack.push(left.wrapping_add(addend))?;
            }
            0x1a | 0x1c | 0x1e | 0x21 | 0x22 | 0x24..=0x27 | 0x29..=0x2e => {
                let right = stack.pop()?;
                let left = stack.pop()?;
                let word = match opcode {
                    0x1a => left & right,
                    0x1c => left.wrapping_sub(right),
                    0x1e => left.wrapping_mul(right),
                    0x21 => left | right,
                    0x22 => left.wrapping_add(right),
                    0x24..=0x26 => {
                        let shift = u32::try_from(right)
                            .map_err(|_| OwnedUnwindDecodeError::MalformedExpression)?;
                        if shift >= usize::BITS {
                            return Err(OwnedUnwindDecodeError::MalformedExpression);
                        }
                        match opcode {
                            0x24 => left << shift,
                            0x25 => left >> shift,
                            _ => ((left as isize) >> shift) as usize,
                        }
                    }
                    0x27 => left ^ right,
                    0x29 => usize::from(left == right),
                    0x2a => usize::from((left as isize) >= (right as isize)),
                    0x2b => usize::from((left as isize) > (right as isize)),
                    0x2c => usize::from((left as isize) <= (right as isize)),
                    0x2d => usize::from((left as isize) < (right as isize)),
                    _ => usize::from(left != right),
                };
                stack.push(word)?;
            }
            0x30..=0x4f => stack.push((opcode - 0x30) as usize)?,
            0x70..=0x8f | 0x92 => {
                let register = if opcode == 0x92 {
                    let (register, next) = decode_uleb128(program, cursor)?;
                    cursor = next;
                    register
                } else {
                    (opcode - 0x70) as usize
                };
                let (offset, next) = decode_sleb128(program, cursor)?;
                cursor = next;
                let base = *registers
                    .get(register)
                    .ok_or(OwnedUnwindDecodeError::MalformedExpression)?;
                stack.push(
                    checked_add_signed_usize(base, offset)
                        .ok_or(OwnedUnwindDecodeError::Overflow)?,
                )?;
            }
            0x96 => {}
            other => return Err(OwnedUnwindDecodeError::UnsupportedDwarfOpcode(other)),
        }
    }
    stack.pop()
}

#[doc(hidden)]
pub fn owned_evaluate_dwarf_expression_for_tests(
    expression: &[u8],
    registers: [usize; MAX_UNWIND_GR],
    stack_words: &[usize],
    initial_cfa: Option<usize>,
) -> Result<usize, OwnedUnwindDecodeError> {
    let start = stack_words.as_ptr() as usize;
    let end = start
        .checked_add(core::mem::size_of_val(stack_words))
        .ok_or(OwnedUnwindDecodeError::Overflow)?;
    evaluate_dwarf_expression(
        expression,
        CfiExpression {
            start: 0,
            len: expression.len(),
        },
        &registers,
        UnwindStackBounds { start, end },
        initial_cfa,
    )
}

#[doc(hidden)]
pub fn owned_recover_cfi_registers_for_tests(
    eh_frame: &[u8],
    section_addr: usize,
    ip: usize,
    mut registers: [usize; MAX_UNWIND_GR],
    stack_words: &[usize],
) -> Result<([usize; MAX_UNWIND_GR], bool), OwnedUnwindDecodeError> {
    let fde = find_fde_for_ip(eh_frame, section_addr, ip, false)?
        .ok_or(OwnedUnwindDecodeError::MissingFde)?;
    let state = evaluate_cfi_state(eh_frame, fde, ip)?;
    let start = stack_words.as_ptr() as usize;
    let end = start
        .checked_add(core::mem::size_of_val(stack_words))
        .ok_or(OwnedUnwindDecodeError::Overflow)?;
    registers[X86_64_DWARF_RSP] = start;
    registers[X86_64_DWARF_RIP] = ip;
    let caller = unwind_caller_with_metadata(
        UnwindCursor {
            ip,
            ip_before_instruction: true,
            registers,
        },
        fde,
        state,
        UnwindStackBounds { start, end },
        eh_frame,
    )?;
    Ok((caller.registers, caller.ip_before_instruction))
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
        | CfiRegisterRule::Register(_)
        | CfiRegisterRule::Expression(_)
        | CfiRegisterRule::ValExpression(_) => None,
    }
}

impl CfiEvaluationState {
    fn has_expressions(&self) -> bool {
        self.cfa_expression.is_some()
            || self.register_rules.iter().any(|rule| {
                matches!(
                    rule,
                    CfiRegisterRule::Expression(_) | CfiRegisterRule::ValExpression(_)
                )
            })
    }

    fn new(pc: usize) -> Self {
        // SysV nonvolatile registers not mentioned by a CIE/FDE retain their
        // value. The return address must have an explicit recovery rule.
        let mut register_rules = [CfiRegisterRule::SameValue; MAX_TRACKED_DWARF_REGISTERS];
        register_rules[X86_64_DWARF_RIP] = CfiRegisterRule::Undefined;
        Self {
            pc,
            cfa_register: UNSET_DWARF_REGISTER,
            cfa_offset: 0,
            gnu_args_size: 0,
            cfa_expression: None,
            register_rules,
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
            0x11 | 0x12 | 0x15 => {
                cursor = decode_uleb128(input, cursor)?.1;
                cursor = decode_sleb128(input, cursor)?.1;
            }
            0x13 => cursor = decode_sleb128(input, cursor)?.1,
            DW_CFA_DEF_CFA_EXPRESSION => {
                cursor = read_cfi_expression(input, cursor, end)?.1;
            }
            DW_CFA_EXPRESSION | DW_CFA_VAL_EXPRESSION => {
                cursor = decode_uleb128(input, cursor)?.1;
                cursor = read_cfi_expression(input, cursor, end)?.1;
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
        // checked_shl checks only the shift count, not discarded high bits.
        // At the final group, reject a value outside the target word before
        // it can wrap into an apparently valid CFI register, length or offset.
        if payload > (usize::MAX >> shift) {
            return Err(OwnedUnwindDecodeError::Overflow);
        }
        result |= payload << shift;
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
        let remaining_bits = isize::BITS - shift;
        if remaining_bits < 7 {
            // Bits beyond the target word, including its sign bit, must
            // agree. On 64-bit targets the tenth payload is therefore either
            // 0x00 or 0x7f; 0x01 must not turn +2^63 into isize::MIN.
            let sign_mask = 0x7fu8 & (!0u8 << (remaining_bits - 1));
            let sign_bits = byte & sign_mask;
            if sign_bits != 0 && sign_bits != sign_mask {
                return Err(OwnedUnwindDecodeError::Overflow);
            }
        }
        result |= ((byte & 0x7f) as isize) << shift;
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
    let mut word = 0usize;
    // SAFETY: the destination is a live word. A bounded stack address or CFI
    // expression can still name an unmapped page; the kernel copy reports that
    // fault instead of dereferencing untrusted unwind data in Rust.
    unsafe {
        crate::io_abi::iov_snapshot::copy_user_bytes_raw(
            addr as *const u8,
            (&raw mut word).cast(),
            core::mem::size_of::<usize>(),
        )
    }
    .ok()
    .map(|()| word)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captured_context_preserves_registers_and_signal_instruction_position() {
        let capture = CapturedUnwindCursor {
            rbx: 0x303,
            rbp: 0x606,
            r12: 0xc0c,
            r13: 0xd0d,
            r14: 0xe0e,
            r15: 0xf0f,
            stack_pointer: 0x8000,
            ip: 0x1234,
        };
        let mut cursor = UnwindCursor::captured(&capture);
        assert_eq!(cursor.lookup_ip(), 0x1233);
        cursor.ip_before_instruction = true;
        assert_eq!(cursor.lookup_ip(), 0x1234);
        let mut context = cursor.context(7, None);
        let mut before = -1;
        // SAFETY: accessors receive a live context and output pointer owned by
        // this test, just as a personality or trace callback would.
        unsafe {
            assert_eq!(_Unwind_GetIPInfo(&mut context, &mut before), 0x1234);
            assert_eq!(before, 1);
            assert_eq!(_Unwind_GetCFA(&mut context), 0x8000);
            for (register, value) in [
                (3, 0x303),
                (6, 0x606),
                (7, 0x8000),
                (12, 0xc0c),
                (13, 0xd0d),
                (14, 0xe0e),
                (15, 0xf0f),
                (16, 0x1234),
            ] {
                assert_eq!(_Unwind_GetGR(&mut context, register), value);
            }
        }
        let physical = context.physical_cursor.expect("physical register snapshot");
        assert_eq!(physical.rbx, capture.rbx);
        assert_eq!(physical.rsp, capture.stack_pointer);
        assert_eq!(physical.ip, capture.ip);
    }

    #[test]
    fn read_word_rejects_inaccessible_and_unaligned_addresses() {
        let word = 0x1234_5678usize;
        let address = (&raw const word) as usize;
        assert_eq!(read_word(address), Some(word));
        assert_eq!(read_word(address + 1), None);
        assert_eq!(read_word(0), None);
        // SAFETY: this mapping belongs only to this test. No Rust reference is
        // formed to its inaccessible contents, and it is released afterward.
        unsafe {
            let mapping = frankenlibc_core::syscall::sys_mmap(
                core::ptr::null_mut(),
                4096,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
            .expect("raw mmap PROT_NONE in owned_unwind_abi test");
            assert_eq!(read_word(mapping as usize), None);
            assert_eq!(
                read_stack_word(
                    mapping as usize,
                    UnwindStackBounds {
                        start: mapping as usize,
                        end: mapping as usize + 4096,
                    },
                ),
                Err(OwnedUnwindDecodeError::InvalidStackAddress),
            );
            assert_eq!(frankenlibc_core::syscall::sys_munmap(mapping, 4096), Ok(()));
        }
    }

    #[test]
    fn valid_frame_pointer_accepts_leaf_frame_equal_to_stack_pointer() {
        let sp = 0x7fff_0000_1000usize;
        let limit = sp + 0x4000;
        assert!(valid_frame_pointer(sp, sp, limit));
        assert!(valid_frame_pointer(sp + 16, sp, limit));
        assert!(!valid_frame_pointer(sp - 8, sp, limit));
        assert!(!valid_frame_pointer(sp + 4, sp, limit));
    }

    #[test]
    fn frame_lookup_ip_for_mode_preserves_signal_frame_exact_pc() {
        assert_eq!(frame_lookup_ip_for_mode(0x401000, true), 0x401000);
        assert_eq!(frame_lookup_ip_for_mode(0x401000, false), 0x400fff);
        assert_eq!(frame_lookup_ip_for_mode(0, false), 0);
    }

    #[test]
    fn parse_cie_v4_signal_frame_and_gnu_negative_offset_extended_cfi() {
        // Build a synthetic .eh_frame containing a DWARF v4 CIE with "zRS" augmentation
        // and an FDE exercising opcode 0x2f (DW_CFA_GNU_negative_offset_extended).
        let mut eh = Vec::new();
        // CIE body:
        // version = 4, aug = "zRS\0", addr_size = 8, seg_size = 0,
        // code_align = 1, data_align = -8 (0x78), ret_reg = 16,
        // aug_len = 1, fde_enc = DW_EH_PE_UDATA8 (0x04),
        // initial instructions: DW_CFA_DEF_CFA(7, 8) -> [0x0c, 7, 8]
        let mut cie_payload = vec![
            0,
            0,
            0,
            0, // CIE ID = 0
            4, // CIE version 4
            b'z',
            b'R',
            b'S',
            0, // augmentation "zRS"
            core::mem::size_of::<usize>() as u8,
            0,    // segment_selector_size = 0
            1,    // code_alignment_factor = 1
            0x78, // data_alignment_factor = -8 (sleb128)
            16,   // return_address_register = 16
            1,    // augmentation length = 1
            DW_EH_PE_UDATA8,
            DW_CFA_DEF_CFA,
            7,
            8,
        ];
        while !cie_payload.len().is_multiple_of(8) {
            cie_payload.push(DW_CFA_NOP);
        }
        eh.extend_from_slice(&(cie_payload.len() as u32).to_le_bytes());
        eh.extend_from_slice(&cie_payload);

        let fde_offset = eh.len();
        let cie_backptr = ((fde_offset + 4) as u32).to_le_bytes();
        let mut fde_payload = Vec::new();
        fde_payload.extend_from_slice(&cie_backptr);
        fde_payload.extend_from_slice(&0x5000_0000u64.to_le_bytes()); // initial_location
        fde_payload.extend_from_slice(&0x40u64.to_le_bytes()); // address_range
        fde_payload.push(0); // augmentation data length = 0
        // Opcode 0x2f: DW_CFA_GNU_negative_offset_extended(reg=6, offset=2)
        // With data_alignment_factor = -8: neg_offset = -2, scaled = (-2) * (-8) = +16!
        fde_payload.extend_from_slice(&[0x2f, 6, 2]);
        while !fde_payload.len().is_multiple_of(8) {
            fde_payload.push(DW_CFA_NOP);
        }
        eh.extend_from_slice(&(fde_payload.len() as u32).to_le_bytes());
        eh.extend_from_slice(&fde_payload);
        eh.extend_from_slice(&0u32.to_le_bytes()); // terminator

        let records = decode_eh_frame_records(&eh, 0x1000_0000, false)
            .expect("CIE v4 + zRS + 0x2f FDE should decode");
        assert_eq!(records.len(), 1);
        let fde = records[0];
        assert!(fde.signal_frame, "zRS augmentation must mark signal_frame");
        assert_eq!(fde.initial_location, 0x5000_0000);
        assert_eq!(fde.address_range, 0x40);

        let mut init_state = CfiEvaluationState::new(fde.initial_location);
        execute_cfi_program(
            &eh,
            fde.cie_instructions_start,
            fde.cie_instructions_end,
            &fde,
            None,
            &mut init_state,
            &CfiEvaluationState::new(fde.initial_location),
        )
        .expect("CIE program executes");
        let mut row = init_state;
        execute_cfi_program(
            &eh,
            fde.fde_instructions_start,
            fde.fde_instructions_end,
            &fde,
            Some(0x5000_0010),
            &mut row,
            &init_state,
        )
        .expect("FDE program with 0x2f executes");
        assert_eq!(row.register_rule(6), CfiRegisterRule::Offset(16));
    }
}
