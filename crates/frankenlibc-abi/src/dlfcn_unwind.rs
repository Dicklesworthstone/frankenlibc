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
//! Streams without a bounded zero terminator and unsupported encodings are
//! rejected before publication; this is not a general C++ unwind loader.

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
        if !validate_stream(stream, count)? {
            return Some(Self::default());
        }
        // SAFETY: the bounded stream has a zero terminator, valid CIE targets,
        // and bounded CIE/FDE address and augmentation fields. Relocations
        // have installed code/personality addresses. As with executing the
        // DSO itself, the compiler's CFI instructions are trusted code.
        // The guard owns its registration until the mapping is retired.
        unsafe { __register_frame(start as *mut c_void) };
        Some(Self { start })
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
