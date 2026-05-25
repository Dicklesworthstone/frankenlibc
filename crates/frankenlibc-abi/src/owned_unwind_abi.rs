//! Opt-in owned `_Unwind_*` substitutes for standalone artifact experiments.
//!
//! These symbols are intentionally gated behind `standalone,owned-unwind-stub`.
//! They are not a general unwinder. The experiment lane also builds with
//! `panic=abort`, so the cleanup/personality paths that would need real DWARF
//! unwinding are unreachable; the stubs only remove libgcc_s symbol edges so
//! the standalone blocker surface can be measured directly.

#![allow(non_snake_case)]

use std::ffi::{c_int, c_void};
use std::sync::{Mutex, MutexGuard};

type UnwindReasonCode = c_int;
type UnwindWord = usize;

const URC_NO_REASON: UnwindReasonCode = 0;
const URC_END_OF_STACK: UnwindReasonCode = 5;
const FRAME_REGISTRY_SLOTS: usize = 128;
const MAX_BACKTRACE_FRAMES: usize = 64;
const MAX_STACK_SCAN_BYTES: usize = 8 * 1024 * 1024;
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
const DW_EH_PE_INDIRECT: u8 = 0x80;
const DW_CFA_ADVANCE_LOC: u8 = 0x40;
const DW_CFA_OFFSET: u8 = 0x80;
const DW_CFA_RESTORE: u8 = 0xc0;

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
}

#[derive(Clone, Copy, Debug)]
struct OwnedCieRecord {
    offset: usize,
    fde_pointer_encoding: u8,
}

#[repr(C)]
pub struct UnwindContext {
    ip: UnwindWord,
    frame_index: usize,
}

#[repr(C)]
pub struct UnwindException {
    _private: [u8; 0],
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
pub unsafe extern "C" fn _Unwind_DeleteException(_exception: *mut UnwindException) {}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _Unwind_GetDataRelBase(_ctx: *mut UnwindContext) -> UnwindWord {
    0
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
        unsafe { ip_before_insn.write(1) };
    }
    // SAFETY: mirrors _Unwind_GetIP's opaque-context handling.
    unsafe { _Unwind_GetIP(ctx) }
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
pub fn owned_first_fde_for_tests(
    eh_frame: &[u8],
    section_addr: usize,
) -> Result<Option<OwnedFdeRecord>, OwnedUnwindDecodeError> {
    let mut cies = Vec::new();
    let mut cursor = 0usize;
    while let Some(record) = next_eh_frame_record(eh_frame, cursor)? {
        cursor = record.end;
        if record.is_cie {
            cies.push(parse_cie_record(eh_frame, record)?);
        } else {
            return Ok(Some(parse_fde_record(
                eh_frame,
                section_addr,
                record,
                &cies,
            )?));
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
    find_fde_for_ip(eh_frame, section_addr, ip)
}

fn find_fde_for_ip(
    eh_frame: &[u8],
    section_addr: usize,
    ip: usize,
) -> Result<Option<OwnedFdeRecord>, OwnedUnwindDecodeError> {
    let mut cies = Vec::new();
    let mut cursor = 0usize;
    while let Some(record) = next_eh_frame_record(eh_frame, cursor)? {
        cursor = record.end;
        if record.is_cie {
            cies.push(parse_cie_record(eh_frame, record)?);
            continue;
        }

        let fde = parse_fde_record(eh_frame, section_addr, record, &cies)?;
        if ip >= fde.pc_begin && ip < fde.pc_end {
            return Ok(Some(fde));
        }
    }
    Ok(None)
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
    record: EhFrameRecord,
) -> Result<OwnedCieRecord, OwnedUnwindDecodeError> {
    let (version, mut cursor) = read_u8(eh_frame, record.body)?;
    if !matches!(version, 1 | 3 | 4) {
        return Err(OwnedUnwindDecodeError::UnsupportedCieVersion(version));
    }

    let (augmentation, after_augmentation) = read_c_string(eh_frame, cursor, record.end)?;
    cursor = after_augmentation;
    let (_, after_code_alignment) = decode_uleb128(eh_frame, cursor)?;
    let (_, after_data_alignment) = decode_sleb128(eh_frame, after_code_alignment)?;
    cursor = after_data_alignment;
    cursor = if version == 1 {
        read_u8(eh_frame, cursor)?.1
    } else {
        decode_uleb128(eh_frame, cursor)?.1
    };

    let mut fde_pointer_encoding = DW_EH_PE_ABSPTR;
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
                    augmentation_cursor = read_u8(eh_frame, augmentation_cursor)?.1;
                }
                b'P' => {
                    let (encoding, after_encoding) = read_u8(eh_frame, augmentation_cursor)?;
                    augmentation_cursor = skip_encoded_value(
                        eh_frame,
                        after_encoding,
                        section_relative_addr(after_encoding),
                        encoding,
                    )?;
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

    validate_cfi_program(eh_frame, cursor, record.end)?;
    Ok(OwnedCieRecord {
        offset: record.offset,
        fde_pointer_encoding,
    })
}

fn parse_fde_record(
    eh_frame: &[u8],
    section_addr: usize,
    record: EhFrameRecord,
    cies: &[OwnedCieRecord],
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
    )?;
    let (pc_range, cursor) = read_encoded_range(eh_frame, cursor, cie.fde_pointer_encoding)?;
    validate_cfi_program(eh_frame, cursor, record.end)?;
    let pc_end = pc_begin
        .checked_add(pc_range)
        .ok_or(OwnedUnwindDecodeError::Overflow)?;
    Ok(OwnedFdeRecord {
        pc_begin,
        pc_end,
        cie_offset,
    })
}

fn read_encoded_pointer(
    input: &[u8],
    offset: usize,
    field_addr: usize,
    encoding: u8,
) -> Result<(usize, usize), OwnedUnwindDecodeError> {
    if encoding == DW_EH_PE_OMIT || encoding & DW_EH_PE_INDIRECT != 0 {
        return Err(OwnedUnwindDecodeError::UnsupportedPointerEncoding(encoding));
    }
    let application = encoding & 0x70;
    if !matches!(application, 0 | DW_EH_PE_PCREL) {
        return Err(OwnedUnwindDecodeError::UnsupportedPointerEncoding(encoding));
    }

    let (value, cursor) = read_encoded_raw(input, offset, encoding)?;
    let value = if application == DW_EH_PE_PCREL {
        (field_addr as isize)
            .checked_add(value)
            .ok_or(OwnedUnwindDecodeError::Overflow)?
    } else {
        value
    };
    if value < 0 {
        return Err(OwnedUnwindDecodeError::Overflow);
    }
    Ok((value as usize, cursor))
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
    if !matches!(application, 0 | DW_EH_PE_PCREL) {
        return Err(OwnedUnwindDecodeError::UnsupportedPointerEncoding(encoding));
    }

    let (value, cursor) = read_encoded_raw(input, offset, encoding)?;
    if value < 0 {
        return Err(OwnedUnwindDecodeError::Overflow);
    }
    Ok((value as usize, cursor))
}

fn skip_encoded_value(
    input: &[u8],
    offset: usize,
    _field_addr: usize,
    encoding: u8,
) -> Result<usize, OwnedUnwindDecodeError> {
    if encoding == DW_EH_PE_OMIT {
        return Err(OwnedUnwindDecodeError::UnsupportedPointerEncoding(encoding));
    }
    read_encoded_raw(input, offset, encoding).map(|(_, cursor)| cursor)
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

fn section_relative_addr(offset: usize) -> usize {
    offset
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
