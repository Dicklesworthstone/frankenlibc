//! Unwind metadata lifetime for manually mapped native ELF objects.
//!
//! The process unwinder cannot discover these objects through the host link
//! map. Register their relocated, readable `.eh_frame` streams with the same
//! unwind runtime already linked by Rust. PT_GNU_EH_FRAME is authoritative;
//! section headers need not be present. This does not load a host DSO or add
//! a native symbol-provider fallback.
//!
//! Format: LSB "Exception Frames" / "Exception Handling Frame Header":
//! https://refspecs.linuxfoundation.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/ehframechpt.html
//! Ordinary streams require a bounded zero terminator. A narrow fallback
//! normalizes simple streams bounded by a following GNU property note and a
//! verified header table; unsupported metadata is rejected before publication.
//! This is not a general C++ unwind loader.

use std::ffi::c_void;

use frankenlibc_core::elf::{LoadedObject, ProgramType};

use super::{Mapping, map_layout::IMAGE_PAGE_SIZE, raw_syscall};

#[cfg(all(feature = "standalone", feature = "owned-unwind-stub"))]
use crate::owned_unwind_abi::{__deregister_frame, __register_frame};

#[cfg(not(all(feature = "standalone", feature = "owned-unwind-stub")))]
unsafe extern "C" {
    fn __register_frame(frame: *mut c_void);
    fn __deregister_frame(frame: *mut c_void);
}

#[derive(Debug, Default)]
pub(super) struct Frames {
    start: usize,
    // Normalized records remain live until Drop has deregistered their address.
    _synthetic: Option<Mapping>,
}

impl Frames {
    /// Call after final relocation/protection and before public exposure.
    /// The owning DSO drops this guard before unmapping its image, including
    /// failed publication and dependency-group rollback.
    pub(super) fn register(object: &LoadedObject, mapping: &Mapping) -> Option<Self> {
        let mut headers = object
            .program_headers
            .iter()
            .filter(|header| header.p_type == ProgramType::GnuEhFrame);
        let Some(header) = headers.next() else {
            return Some(Self::default());
        };
        if headers.next().is_some() {
            return None;
        }
        let header_offset = usize::try_from(header.p_vaddr).ok()?;
        let header_len = usize::try_from(header.p_memsz).ok()?;
        let header_end = header_offset.checked_add(header_len)?;
        if header_len < 4 || header_end > readable_end(object, mapping, header_offset)? {
            return None;
        }
        let header_address = mapping.base.checked_add(header_offset)?;
        // SAFETY: this exact header range is inside readable owned pages.
        // Never construct a slice across inaccessible PT_LOAD holes.
        let header = unsafe { std::slice::from_raw_parts(header_address as *const u8, header_len) };
        if header[0] != 1 {
            return None;
        }
        let mut cursor = 4;
        let start = pointer(header, &mut cursor, header[1], header_address)?;
        let count = if header[2] == 0xff {
            None
        } else {
            // The FDE count is a scalar, never a relative/indirect pointer.
            if header[2] & 0xf0 != 0 {
                return None;
            }
            Some(pointer(header, &mut cursor, header[2], 0)?)
        };
        let offset = start.checked_sub(mapping.base)?;
        let limit = readable_end(object, mapping, offset)?;
        // SAFETY: the checked stream range is inside one readable page span.
        let stream = unsafe { std::slice::from_raw_parts(start as *const u8, limit - offset) };
        let Some(plan) = validate_stream(stream, count)? else {
            return Some(Self::default());
        };
        let (registered_start, synthetic) = if plan.terminated_in_place {
            (start, None)
        } else {
            // No-CRT (`-nostdlib`) ELF objects omit `crtendS.o`'s trailing
            // 0u32 sentinel and rely on `PT_GNU_EH_FRAME`'s `fde_count`. When
            // another read-only section (e.g. `.note.gnu.property` under CET)
            // immediately follows an 8-byte-aligned `.eh_frame`, `libgcc`'s
            // `__register_frame` cannot be pointed at `start` in-place because
            // it walks records until `*(u32 *)p == 0`. Synthesize a read-only
            // zero-terminated copy with PC-relative pointers rebased to `start`.
            let copy = synthesize_terminated_stream(stream, &plan, start, mapping)?;
            (copy.base, Some(copy))
        };
        // SAFETY: the registered stream has a verified zero terminator, valid
        // CIE targets, and bounded CIE/FDE address and augmentation fields.
        // Relocations have installed code/personality addresses. As with
        // executing the DSO itself, the compiler's CFI instructions are trusted
        // code. The guard owns its registration until the mapping is retired.
        // Normalized records remain live until Drop has deregistered their address.
        unsafe { __register_frame(registered_start as *mut c_void) };
        Some(Self {
            start: registered_start,
            _synthetic: synthetic,
        })
    }
}

impl Drop for Frames {
    fn drop(&mut self) {
        if self.start != 0 {
            // SAFETY: registered once above. `Drop::drop` runs before `_synthetic`
            // is dropped, and `NativeDso` field order keeps the DSO mapping alive
            // until deregistration completes.
            unsafe { __deregister_frame(self.start as *mut c_void) };
        }
    }
}

/// The loader maps zero-filled page padding, including the common no-crt
/// `.eh_frame` terminator immediately after the last file-backed byte. Do not
/// scan across a PT_LOAD hole or into a segment without read permission.
fn readable_end(object: &LoadedObject, mapping: &Mapping, offset: usize) -> Option<usize> {
    let mut end = None;
    let mut next_boundary = mapping.len;
    let mask = IMAGE_PAGE_SIZE - 1;
    for header in &object.program_headers {
        if !header.is_load() || header.p_memsz == 0 {
            continue;
        }
        let first = usize::try_from(header.p_vaddr).ok()? & !mask;
        let last = usize::try_from(header.p_vaddr.checked_add(header.p_memsz)?).ok()?;
        let last = last.checked_add(mask)? & !mask;
        for boundary in [first, last] {
            if boundary > offset {
                next_boundary = next_boundary.min(boundary);
            }
        }
        if first <= offset && offset < last {
            // Matching protect_object's segment order also handles an
            // overlapping page whose final segment removes read permission.
            end = header
                .p_flags
                .is_readable()
                .then_some(last.min(mapping.len));
        }
    }
    end.map(|end| end.min(next_boundary))
}

fn pointer(bytes: &[u8], cursor: &mut usize, encoding: u8, base: usize) -> Option<usize> {
    let at = *cursor;
    let raw = encoded(bytes, cursor, encoding)?;
    let relative_base = match encoding & 0xf0 {
        0x00 => 0,
        0x10 => base.checked_add(at)?,
        0x30 => base,
        // Indirect, text/function-relative and aligned encodings do not have
        // an unambiguous bounded target in this ELF header contract.
        _ => return None,
    };
    usize::try_from(relative_base as i128 + raw).ok()
}

fn encoded(bytes: &[u8], cursor: &mut usize, encoding: u8) -> Option<i128> {
    let at = *cursor;
    let (size, signed) = match encoding & 0x0f {
        0x00 => (std::mem::size_of::<usize>(), false),
        0x01 => return leb(bytes, cursor, false),
        0x02 => (2, false),
        0x03 => (4, false),
        0x04 => (8, false),
        0x09 => return leb(bytes, cursor, true),
        0x0a => (2, true),
        0x0b => (4, true),
        0x0c => (8, true),
        _ => return None,
    };
    let end = at.checked_add(size)?;
    let value = bytes.get(at..end)?;
    let negative = signed && value.last()? & 0x80 != 0;
    let mut padded = [if negative { 0xff } else { 0 }; 8];
    padded[..size].copy_from_slice(value);
    let raw = u64::from_le_bytes(padded);
    *cursor = end;
    Some(if negative {
        raw as i64 as i128
    } else {
        raw as i128
    })
}

fn leb(bytes: &[u8], cursor: &mut usize, signed: bool) -> Option<i128> {
    let mut value = 0i128;
    for shift in (0..70).step_by(7) {
        let byte = *bytes.get(*cursor)?;
        *cursor = cursor.checked_add(1)?;
        value |= i128::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            if signed && byte & 0x40 != 0 {
                value |= !0i128 << (shift + 7);
            }
            return if signed {
                i64::try_from(value).ok().map(i128::from)
            } else {
                u64::try_from(value).ok().map(i128::from)
            };
        }
    }
    None
}

struct Cie {
    offset: usize,
    fde_encoding: u8,
    lsda_encoding: u8,
    augmentation: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PcrelFixup {
    pos: usize,
    encoding: u8,
    raw: i128,
}

#[derive(Debug)]
struct StreamPlan {
    byte_len: usize,
    terminated_in_place: bool,
    pcrel_fixups: Vec<PcrelFixup>,
}

fn frame_encoding(encoding: u8) -> bool {
    // __register_frame supplies no external text/data bases. Absolute and
    // PC-relative pointers (including indirect personality/LSDA pointers)
    // are self-contained after the object's relocations have been applied.
    // PC-relative pointers must use fixed-width encodings so synthesized
    // streams can rebase them in place without shifting variable-width fields.
    match encoding & 0x70 {
        0x00 => matches!(encoding & 0x0f, 0x00..=0x04 | 0x09..=0x0c),
        0x10 => matches!(encoding & 0x0f, 0x00 | 0x02..=0x04 | 0x0a..=0x0c),
        _ => false,
    }
}

fn cie_record(
    record: &[u8],
    offset: usize,
    id_at: usize,
    fixups: &mut Vec<PcrelFixup>,
) -> Option<Cie> {
    let version = *record.get(4)?;
    if !matches!(version, 1 | 3 | 4) {
        return None;
    }
    let end = 5usize.checked_add(record.get(5..)?.iter().position(|byte| *byte == 0)?)?;
    let augmentation = record.get(5..end)?;
    let mut cursor = end.checked_add(1)?;
    if version == 4 {
        // ELF64 address size; segmented addressing is unsupported here.
        if *record.get(cursor)? != 8 || *record.get(cursor.checked_add(1)?)? != 0 {
            return None;
        }
        cursor = cursor.checked_add(2)?;
    }
    if leb(record, &mut cursor, false)? == 0 {
        return None;
    }
    leb(record, &mut cursor, true)?;
    if version == 1 {
        record.get(cursor)?;
        cursor = cursor.checked_add(1)?;
    } else {
        leb(record, &mut cursor, false)?;
    }
    let mut cie = Cie {
        offset,
        fde_encoding: 0,
        lsda_encoding: 0xff,
        augmentation: !augmentation.is_empty(),
    };
    if augmentation.is_empty() {
        return Some(cie);
    }
    if augmentation.first() != Some(&b'z') {
        return None;
    }
    let length = usize::try_from(leb(record, &mut cursor, false)?).ok()?;
    let aug_start = cursor;
    let data = record.get(aug_start..aug_start.checked_add(length)?)?;
    let mut data_cursor = 0usize;
    let mut seen = 0u8;
    for (index, byte) in augmentation[1..].iter().enumerate() {
        let bit = match byte {
            b'L' => 1,
            b'R' => 2,
            b'P' => 4,
            b'S' => 8,
            _ => return None,
        };
        if seen & bit != 0 || (*byte == b'S' && index + 2 != augmentation.len()) {
            // Registration runtimes may stop at the first R, or stop their
            // encoding scan at S. Reject ambiguous orders instead of parsing
            // a different pointer width from the active unwinder.
            return None;
        }
        seen |= bit;
        match byte {
            b'L' | b'R' | b'P' => {
                let encoding = *data.get(data_cursor)?;
                data_cursor = data_cursor.checked_add(1)?;
                if *byte == b'L' && encoding == 0xff {
                    cie.lsda_encoding = 0xff;
                    continue;
                }
                if !frame_encoding(encoding) {
                    return None;
                }
                match byte {
                    b'L' => cie.lsda_encoding = encoding,
                    // Indirect FDE code pointers would require a separate
                    // validated dereference before giving them to libgcc.
                    b'R' if encoding & 0x80 == 0 => cie.fde_encoding = encoding,
                    b'P' => {
                        let ptr_pos = id_at.checked_add(aug_start)?.checked_add(data_cursor)?;
                        let raw = encoded(data, &mut data_cursor, encoding)?;
                        if encoding & 0x70 == 0x10 && raw != 0 {
                            fixups.try_reserve(1).ok()?;
                            fixups.push(PcrelFixup {
                                pos: ptr_pos,
                                encoding,
                                raw,
                            });
                        }
                    }
                    _ => return None,
                }
            }
            b'S' => {}
            _ => return None,
        }
    }
    Some(cie)
}

fn fde_record(record: &[u8], id_at: usize, cie: &Cie, fixups: &mut Vec<PcrelFixup>) -> Option<()> {
    let mut cursor = 4;
    let init_pos = id_at.checked_add(cursor)?;
    let init_raw = encoded(record, &mut cursor, cie.fde_encoding)?;
    if cie.fde_encoding & 0x70 == 0x10 && init_raw != 0 {
        fixups.try_reserve(1).ok()?;
        fixups.push(PcrelFixup {
            pos: init_pos,
            encoding: cie.fde_encoding,
            raw: init_raw,
        });
    }
    if encoded(record, &mut cursor, cie.fde_encoding & 0x0f)? < 0 {
        return None;
    }
    if cie.augmentation {
        let length = usize::try_from(leb(record, &mut cursor, false)?).ok()?;
        let aug_start = cursor;
        let data = record.get(aug_start..aug_start.checked_add(length)?)?;
        if cie.lsda_encoding != 0xff {
            let mut data_cursor = 0;
            let lsda_pos = id_at.checked_add(aug_start)?;
            let lsda_raw = encoded(data, &mut data_cursor, cie.lsda_encoding)?;
            if cie.lsda_encoding & 0x70 == 0x10 && lsda_raw != 0 {
                fixups.try_reserve(1).ok()?;
                fixups.push(PcrelFixup {
                    pos: lsda_pos,
                    encoding: cie.lsda_encoding,
                    raw: lsda_raw,
                });
            }
        }
    }
    Some(())
}

fn validate_stream(bytes: &[u8], expected: Option<usize>) -> Option<Option<StreamPlan>> {
    if expected == Some(0) {
        return Some(None);
    }
    let mut at = 0usize;
    let mut fdes = 0usize;
    let mut cies = Vec::new();
    let mut pcrel_fixups = Vec::new();
    loop {
        let length = u32::from_le_bytes(bytes.get(at..at.checked_add(4)?)?.try_into().ok()?);
        if length == 0 {
            if !expected.is_none_or(|count| count == fdes) {
                return None;
            }
            return Some((fdes != 0).then_some(StreamPlan {
                byte_len: at,
                terminated_in_place: true,
                pcrel_fixups,
            }));
        }
        // The process registration ABI consumes ordinary 32-bit EH records.
        // Refuse extended/truncated records before handing it any pointers.
        if length < 4 || length == u32::MAX {
            return None;
        }
        let id_at = at.checked_add(4)?;
        let end = id_at.checked_add(length as usize)?;
        let record = bytes.get(id_at..end)?;
        let cie = u32::from_le_bytes(record.get(..4)?.try_into().ok()?) as usize;
        if cie == 0 {
            cies.try_reserve(1).ok()?;
            cies.push(cie_record(record, at, id_at, &mut pcrel_fixups)?);
        } else {
            let target = id_at.checked_sub(cie)?;
            let cie = &cies[cies.binary_search_by_key(&target, |cie| cie.offset).ok()?];
            fde_record(record, id_at, cie, &mut pcrel_fixups)?;
            fdes = fdes.checked_add(1)?;
            if expected == Some(fdes) {
                let terminated_in_place = bytes
                    .get(end..end.checked_add(4)?)
                    .is_some_and(|tail| tail == [0, 0, 0, 0]);
                return Some(Some(StreamPlan {
                    byte_len: end,
                    terminated_in_place,
                    pcrel_fixups,
                }));
            }
        }
        at = end;
    }
}

fn synthesize_terminated_stream(
    stream: &[u8],
    plan: &StreamPlan,
    original_start: usize,
    image_mapping: &Mapping,
) -> Option<Mapping> {
    let prefix = stream.get(..plan.byte_len)?;
    let needed = plan.byte_len.checked_add(4)?;
    let mask = IMAGE_PAGE_SIZE - 1;
    let map_len = needed.checked_add(mask)? & !mask;
    let image_end = image_mapping.base.saturating_add(image_mapping.len);
    let near_strides = [
        0usize,
        16 * 1024,
        64 * 1024,
        256 * 1024,
        1024 * 1024,
        4 * 1024 * 1024,
        16 * 1024 * 1024,
        64 * 1024 * 1024,
        256 * 1024 * 1024,
    ];
    let mut candidates = [(0usize, false); 19];
    let mut candidate_count = 0usize;
    for stride in near_strides {
        if let Some(below) = image_mapping
            .base
            .checked_sub(map_len.saturating_add(stride))
            && below >= IMAGE_PAGE_SIZE
        {
            candidates[candidate_count] = (below & !mask, true);
            candidate_count += 1;
        }
        if let Some(above) = image_end.checked_add(stride)
            && above >= IMAGE_PAGE_SIZE
        {
            candidates[candidate_count] = ((above + mask) & !mask, true);
            candidate_count += 1;
        }
    }
    candidates[candidate_count] = (0, false);
    candidate_count += 1;

    for &(hint, fixed_noreplace) in &candidates[..candidate_count] {
        let mut flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;
        if fixed_noreplace {
            flags |= libc::MAP_FIXED_NOREPLACE;
        }
        let Ok(ptr) = (unsafe {
            raw_syscall::sys_mmap(
                hint as *mut u8,
                map_len,
                libc::PROT_READ | libc::PROT_WRITE,
                flags,
                -1,
                0,
            )
        }) else {
            continue;
        };
        let copy = Mapping {
            base: ptr as usize,
            len: map_len,
        };
        // SAFETY: `copy` exclusively owns `map_len >= plan.byte_len + 4` RW
        // zero-filled anonymous bytes until `sys_mprotect` below.
        let dst = unsafe { std::slice::from_raw_parts_mut(copy.base as *mut u8, needed) };
        dst[..plan.byte_len].copy_from_slice(prefix);
        dst[plan.byte_len..needed].fill(0);
        if plan.pcrel_fixups.iter().all(|fixup| {
            rebase_pcrel_fixup(&mut dst[..plan.byte_len], fixup, original_start, copy.base)
                .is_some()
        }) && unsafe {
            raw_syscall::sys_mprotect(copy.base as *mut u8, copy.len, libc::PROT_READ)
        }
        .is_ok()
        {
            return Some(copy);
        }
    }
    None
}

fn rebase_pcrel_fixup(
    buf: &mut [u8],
    fixup: &PcrelFixup,
    original_start: usize,
    copy_base: usize,
) -> Option<()> {
    if fixup.encoding & 0x70 != 0x10 || fixup.raw == 0 {
        return Some(());
    }
    let orig_field = original_start.checked_add(fixup.pos)?;
    let copy_field = copy_base.checked_add(fixup.pos)?;
    let delta = (orig_field as i128).checked_sub(copy_field as i128)?;
    let rebased = fixup.raw.checked_add(delta)?;
    if rebased == 0 {
        return None;
    }
    match fixup.encoding & 0x0f {
        0x00 => {
            let width = std::mem::size_of::<usize>();
            let target = (orig_field as i128).checked_add(fixup.raw)?;
            let target_addr = usize::try_from(target).ok()?;
            let raw_word = target_addr.wrapping_sub(copy_field);
            if raw_word == 0 {
                return None;
            }
            buf.get_mut(fixup.pos..fixup.pos.checked_add(width)?)?
                .copy_from_slice(&raw_word.to_le_bytes());
        }
        0x02 => {
            let value = u16::try_from(rebased).ok()?;
            buf.get_mut(fixup.pos..fixup.pos.checked_add(2)?)?
                .copy_from_slice(&value.to_le_bytes());
        }
        0x03 => {
            let value = u32::try_from(rebased).ok()?;
            buf.get_mut(fixup.pos..fixup.pos.checked_add(4)?)?
                .copy_from_slice(&value.to_le_bytes());
        }
        0x04 => {
            let value = u64::try_from(rebased).ok()?;
            buf.get_mut(fixup.pos..fixup.pos.checked_add(8)?)?
                .copy_from_slice(&value.to_le_bytes());
        }
        0x0a => {
            let value = i16::try_from(rebased).ok()?;
            buf.get_mut(fixup.pos..fixup.pos.checked_add(2)?)?
                .copy_from_slice(&value.to_le_bytes());
        }
        0x0b => {
            let value = i32::try_from(rebased).ok()?;
            buf.get_mut(fixup.pos..fixup.pos.checked_add(4)?)?
                .copy_from_slice(&value.to_le_bytes());
        }
        0x0c => {
            let value = i64::try_from(rebased).ok()?;
            buf.get_mut(fixup.pos..fixup.pos.checked_add(8)?)?
                .copy_from_slice(&value.to_le_bytes());
        }
        _ => return None,
    }
    Some(())
}
