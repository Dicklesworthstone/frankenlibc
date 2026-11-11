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

use super::{Mapping, map_layout::IMAGE_PAGE_SIZE};

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
    _owned: Vec<u64>,
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
        let owned = match validate_stream(stream, count) {
            Some(false) => return Some(Self::default()),
            Some(true) => Vec::new(),
            None => {
                let boundary = property_boundary(object, mapping, offset, limit)?;
                let index = frame_index(header, cursor, count?, header_address)?;
                normalize_unterminated(
                    stream.get(..boundary.checked_sub(offset)?)?,
                    start,
                    index,
                    object,
                    mapping,
                )?
            }
        };
        let start = if owned.is_empty() {
            start
        } else {
            owned.as_ptr() as usize
        };
        // SAFETY: the original stream or owned normalization has a real zero
        // terminator and validated CIE/FDE fields. Normalized absolute PCs and
        // ranges name the original code; its copied CFI has no address operands.
        // As with executing the DSO, compiler CFI is otherwise trusted code.
        // The guard keeps both metadata and mapping live until deregistration.
        unsafe { __register_frame(start as *mut c_void) };
        Some(Self { start, _owned: owned })
    }
}

impl Drop for Frames {
    fn drop(&mut self) {
        if self.start != 0 {
            // SAFETY: registered once above, and NativeDso field order keeps
            // the mapping alive until deregistration completes.
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

// A search-table count cannot by itself establish the end of an unterminated
// stream. For this fallback the following GNU property note provides an
// independent, readable metadata boundary; its bytes are never overwritten.
fn property_boundary(
    object: &LoadedObject,
    mapping: &Mapping,
    offset: usize,
    limit: usize,
) -> Option<usize> {
    let header = object
        .program_headers
        .iter()
        .filter(|header| header.p_type == ProgramType::GnuProperty)
        .filter(|header| {
            usize::try_from(header.p_vaddr)
                .is_ok_and(|start| offset < start && start <= limit)
        })
        .min_by_key(|header| header.p_vaddr)?;
    let start = usize::try_from(header.p_vaddr).ok()?;
    let len = usize::try_from(header.p_memsz).ok()?;
    if header.p_filesz != header.p_memsz
        || len < 24
        || !start.is_multiple_of(8)
        || start.checked_add(len)? > readable_end(object, mapping, start)?
    {
        return None;
    }
    let address = mapping.base.checked_add(start)?;
    // SAFETY: the entire note lies in a checked readable owned mapping span.
    let note = unsafe { std::slice::from_raw_parts(address as *const u8, len) };
    let word = |at: usize| -> Option<u32> {
        Some(u32::from_le_bytes(note.get(at..at.checked_add(4)?)?.try_into().ok()?))
    };
    let desc_len = usize::try_from(word(4)?).ok()?;
    if word(0)? != 4
        || word(8)? != 5
        || note.get(12..16)? != b"GNU\0"
        || desc_len.checked_add(16)? != len
        || !desc_len.is_multiple_of(8)
    {
        return None;
    }
    let mut cursor = 16usize;
    while cursor < len {
        let data_len = usize::try_from(word(cursor.checked_add(4)?)?).ok()?;
        cursor = cursor.checked_add(8)?.checked_add(data_len)?;
        cursor = cursor.checked_add(7)? & !7;
        if cursor > len {
            return None;
        }
    }
    Some(start)
}

struct IndexedFrame {
    pc: usize,
    fde: usize,
    seen: bool,
}

fn frame_index(
    header: &[u8],
    mut cursor: usize,
    count: usize,
    address: usize,
) -> Option<Vec<IndexedFrame>> {
    // GNU's usual ELF64 header table is a sorted sequence of data-relative
    // signed 32-bit (initial PC, FDE) pairs. Other tables retain the original
    // terminated-stream contract.
    if count == 0
        || header[3] != 0x3b
        || cursor.checked_add(count.checked_mul(8)?)? != header.len()
    {
        return None;
    }
    let mut entries = Vec::new();
    entries.try_reserve_exact(count).ok()?;
    let mut previous = None;
    for _ in 0..count {
        let pc = pointer(header, &mut cursor, 0x3b, address)?;
        let fde = pointer(header, &mut cursor, 0x3b, address)?;
        if previous.is_some_and(|previous| previous >= pc) {
            return None;
        }
        previous = Some(pc);
        entries.push(IndexedFrame { pc, fde, seen: false });
    }
    Some(entries)
}

struct CopiedCie {
    source: usize,
    output: usize,
    encoding: u8,
}

// Only instructions whose operands remain valid after relocation are copied.
// In particular DW_CFA_set_loc uses the CIE's pointer encoding, and expression
// blocks can contain DW_OP_GNU_encoded_addr. Neither may be blindly copied.
fn position_independent_cfi(bytes: &[u8]) -> Option<()> {
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        let opcode = *bytes.get(cursor)?;
        cursor = cursor.checked_add(1)?;
        match opcode & 0xc0 {
            0x40 | 0xc0 => {}
            0x80 => {
                leb(bytes, &mut cursor, false)?;
            }
            _ => match opcode {
                0x00 | 0x0a | 0x0b => {}
                0x02..=0x04 => {
                    let size = 1usize << (opcode - 2);
                    let end = cursor.checked_add(size)?;
                    bytes.get(cursor..end)?;
                    cursor = end;
                }
                0x05 | 0x09 | 0x0c | 0x14 | 0x2f => {
                    leb(bytes, &mut cursor, false)?;
                    leb(bytes, &mut cursor, false)?;
                }
                0x06..=0x08 | 0x0d | 0x0e | 0x2e => {
                    leb(bytes, &mut cursor, false)?;
                }
                0x11 | 0x12 | 0x15 => {
                    leb(bytes, &mut cursor, false)?;
                    leb(bytes, &mut cursor, true)?;
                }
                0x13 => {
                    leb(bytes, &mut cursor, true)?;
                }
                _ => return None,
            },
        }
    }
    Some(())
}

fn append_record(output: &mut Vec<u8>, body: &[u8]) -> Option<()> {
    // Keep absolute ELF64 pointer operands aligned. Padding is DW_CFA_nop.
    let total = body.len().checked_add(4)?.checked_add(7)? & !7;
    let length = u32::try_from(total.checked_sub(4)?).ok()?;
    if length == u32::MAX {
        return None;
    }
    let end = output.len().checked_add(total)?;
    output.try_reserve(total).ok()?;
    output.extend_from_slice(&length.to_le_bytes());
    output.extend_from_slice(body);
    output.resize(end, 0);
    Some(())
}

fn copy_cie(record: &[u8], source: usize, output: &mut Vec<u8>) -> Option<CopiedCie> {
    let parsed = cie_record(record, source)?;
    let version = *record.get(4)?;
    let augmentation_end =
        5usize.checked_add(record.get(5..)?.iter().position(|byte| *byte == 0)?)?;
    if record.get(5..augmentation_end)? != b"zR" {
        return None;
    }
    let mut cursor = augmentation_end.checked_add(1)?;
    if version == 4 {
        cursor = cursor.checked_add(2)?;
    }
    leb(record, &mut cursor, false)?;
    leb(record, &mut cursor, true)?;
    if version == 1 {
        record.get(cursor)?;
        cursor = cursor.checked_add(1)?;
    } else {
        leb(record, &mut cursor, false)?;
    }
    if leb(record, &mut cursor, false)? != 1 {
        return None;
    }
    let encoding_offset = cursor;
    cursor = cursor.checked_add(1)?;
    position_independent_cfi(record.get(cursor..)?)?;
    let mut body = Vec::new();
    body.try_reserve_exact(record.len()).ok()?;
    body.extend_from_slice(record);
    // The normalized FDEs carry absolute ELF64 addresses and ranges.
    *body.get_mut(encoding_offset)? = 0;
    let copied = CopiedCie {
        source,
        output: output.len(),
        encoding: parsed.fde_encoding,
    };
    append_record(output, &body)?;
    Some(copied)
}

fn mapped_code_range(
    object: &LoadedObject,
    mapping: &Mapping,
    pc: usize,
    range: usize,
) -> Option<()> {
    let first = pc.checked_sub(mapping.base)?;
    let last = first.checked_add(range)?;
    if range == 0 || last > mapping.len {
        return None;
    }
    let first = u64::try_from(first).ok()?;
    let last = u64::try_from(last).ok()?;
    object
        .program_headers
        .iter()
        .any(|header| {
            header.is_load()
                && header.p_flags.is_executable()
                && header.p_vaddr <= first
                && header
                    .p_vaddr
                    .checked_add(header.p_memsz)
                    .is_some_and(|end| last <= end)
        })
        .then_some(())
}

fn normalize_unterminated(
    bytes: &[u8],
    address: usize,
    mut index: Vec<IndexedFrame>,
    object: &LoadedObject,
    mapping: &Mapping,
) -> Option<Vec<u64>> {
    let mut output = Vec::new();
    let mut cies: Vec<CopiedCie> = Vec::new();
    let mut at = 0usize;
    while at < bytes.len() {
        let id_at = at.checked_add(4)?;
        let length = u32::from_le_bytes(bytes.get(at..id_at)?.try_into().ok()?);
        // A zero before the independently established boundary is not an
        // unterminated stream, and must not bypass a count mismatch.
        if length < 4 || length == u32::MAX {
            return None;
        }
        let end = id_at.checked_add(usize::try_from(length).ok()?)?;
        let record = bytes.get(id_at..end)?;
        let delta = u32::from_le_bytes(record.get(..4)?.try_into().ok()?) as usize;
        if delta == 0 {
            let copied = copy_cie(record, at, &mut output)?;
            cies.try_reserve(1).ok()?;
            cies.push(copied);
        } else {
            let target = id_at.checked_sub(delta)?;
            let cie = &cies[cies.binary_search_by_key(&target, |cie| cie.source).ok()?];
            let mut cursor = 4usize;
            let raw = encoded(record, &mut cursor, cie.encoding)?;
            // libgcc treats a zero encoded initial PC as an absent FDE.
            if raw == 0 {
                return None;
            }
            let base = match cie.encoding & 0xf0 {
                0x00 => 0,
                0x10 => address.checked_add(id_at)?.checked_add(4)?,
                _ => return None,
            };
            let pc = usize::try_from(base as i128 + raw).ok()?;
            let range = usize::try_from(encoded(record, &mut cursor, cie.encoding & 0x0f)?).ok()?;
            mapped_code_range(object, mapping, pc, range)?;
            // zR has no per-FDE augmentation payload.
            if leb(record, &mut cursor, false)? != 0 {
                return None;
            }
            let instructions = record.get(cursor..)?;
            position_independent_cfi(instructions)?;
            let slot = index.binary_search_by_key(&pc, |entry| entry.pc).ok()?;
            let entry = &mut index[slot];
            if entry.seen || entry.fde != address.checked_add(at)? {
                return None;
            }
            entry.seen = true;
            let delta = output.len().checked_add(4)?.checked_sub(cie.output)?;
            let delta = u32::try_from(delta).ok()?;
            let mut body = Vec::new();
            body.try_reserve_exact(21usize.checked_add(instructions.len())?).ok()?;
            body.extend_from_slice(&delta.to_le_bytes());
            body.extend_from_slice(&u64::try_from(pc).ok()?.to_le_bytes());
            body.extend_from_slice(&u64::try_from(range).ok()?.to_le_bytes());
            body.push(0);
            body.extend_from_slice(instructions);
            append_record(&mut output, &body)?;
        }
        at = end;
    }
    if at != bytes.len() || index.iter().any(|entry| !entry.seen) {
        return None;
    }
    output.try_reserve(4).ok()?;
    output.extend_from_slice(&[0; 4]);
    if !validate_stream(&output, Some(index.len()))? {
        return None;
    }
    // Vec<u64> supplies ELF64 alignment and stable storage through deregister.
    let mut aligned = Vec::new();
    aligned.try_reserve_exact(output.len().checked_add(7)? / 8).ok()?;
    for chunk in output.chunks(8) {
        let mut word = [0; 8];
        word[..chunk.len()].copy_from_slice(chunk);
        aligned.push(u64::from_ne_bytes(word));
    }
    Some(aligned)
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

fn frame_encoding(encoding: u8) -> bool {
    // __register_frame supplies no external text/data bases. Absolute and
    // PC-relative pointers (including indirect personality/LSDA pointers)
    // are self-contained after the object's relocations have been applied.
    matches!(encoding & 0x70, 0x00 | 0x10) && matches!(encoding & 0x0f, 0x00..=0x04 | 0x09..=0x0c)
}

fn cie_record(record: &[u8], offset: usize) -> Option<Cie> {
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
    let data = record.get(cursor..cursor.checked_add(length)?)?;
    let mut cursor = 0usize;
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
                let encoding = *data.get(cursor)?;
                cursor = cursor.checked_add(1)?;
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
                        encoded(data, &mut cursor, encoding)?;
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

fn fde_record(record: &[u8], cie: &Cie) -> Option<()> {
    let mut cursor = 4;
    encoded(record, &mut cursor, cie.fde_encoding)?;
    if encoded(record, &mut cursor, cie.fde_encoding & 0x0f)? < 0 {
        return None;
    }
    if cie.augmentation {
        let length = usize::try_from(leb(record, &mut cursor, false)?).ok()?;
        let data = record.get(cursor..cursor.checked_add(length)?)?;
        if cie.lsda_encoding != 0xff {
            let mut cursor = 0;
            encoded(data, &mut cursor, cie.lsda_encoding)?;
        }
    }
    Some(())
}

fn validate_stream(bytes: &[u8], expected: Option<usize>) -> Option<bool> {
    let mut at = 0usize;
    let mut fdes = 0usize;
    let mut cies = Vec::new();
    loop {
        let length = u32::from_le_bytes(bytes.get(at..at.checked_add(4)?)?.try_into().ok()?);
        if length == 0 {
            return (expected.is_none_or(|count| count == fdes)).then_some(fdes != 0);
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
            cies.push(cie_record(record, at)?);
        } else {
            let target = id_at.checked_sub(cie)?;
            let cie = &cies[cies.binary_search_by_key(&target, |cie| cie.offset).ok()?];
            fde_record(record, cie)?;
            fdes = fdes.checked_add(1)?;
            if expected.is_some_and(|count| fdes > count) {
                return None;
            }
        }
        at = end;
    }
}
