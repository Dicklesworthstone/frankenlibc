//! Checked address arithmetic for the native loader's ELF image mappings.
//!
//! The core materializer and native protection paths currently use 4 KiB image
//! pages. Segment p_align can be larger: the load bias must satisfy every
//! PT_LOAD alignment, not just mmap's ordinary page alignment. No address is
//! dereferenced here and no allocation, syscall, or loader state is involved.

use std::ops::Range;

pub(super) const IMAGE_PAGE_SIZE: usize = 4096;

#[derive(Debug)]
pub(super) struct Reservation {
    pub(super) image_len: usize,
    pub(super) reserve_len: usize,
    alignment: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Placement {
    pub(super) base: usize,
    pub(super) prefix: usize,
    pub(super) suffix: usize,
}

impl Reservation {
    /// Input tuples are (p_vaddr, p_offset, p_align) for PT_LOAD only.
    /// The native loader has already required low_vaddr == 0. Thus an aligned
    /// image base is also the load bias used by every relocation and symbol.
    pub(super) fn new(
        image_len: usize,
        segments: impl IntoIterator<Item = (u64, u64, u64)>,
    ) -> Option<Self> {
        if image_len == 0 || !image_len.is_multiple_of(IMAGE_PAGE_SIZE) {
            return None;
        }
        let mut alignment = IMAGE_PAGE_SIZE;
        let mut any = false;
        for (virtual_address, file_offset, segment_alignment) in segments {
            any = true;
            if virtual_address % IMAGE_PAGE_SIZE as u64 != file_offset % IMAGE_PAGE_SIZE as u64 {
                return None;
            }
            // ELF p_align 0/1 means no extra alignment. All other values must
            // be powers of two with congruent virtual and file addresses.
            if segment_alignment > 1 {
                if !segment_alignment.is_power_of_two()
                    || virtual_address % segment_alignment != file_offset % segment_alignment
                {
                    return None;
                }
                alignment = alignment.max(usize::try_from(segment_alignment).ok()?);
            }
        }
        // mmap is page-aligned, so at most alignment - one page is discarded
        // in front. Use checked arithmetic before issuing any mapping syscall.
        let reserve_len = image_len.checked_add(alignment.checked_sub(IMAGE_PAGE_SIZE)?)?;
        if !any || reserve_len > isize::MAX as usize {
            return None;
        }
        Some(Self {
            image_len,
            reserve_len,
            alignment,
        })
    }

    /// Partition one owned reservation into whole-page prefix/image/suffix.
    /// The caller may unmap the two unused ranges, but never replace arbitrary
    /// process mappings with MAP_FIXED to obtain the requested alignment.
    pub(super) fn place(&self, reserved_base: usize) -> Option<Placement> {
        if !reserved_base.is_multiple_of(IMAGE_PAGE_SIZE) {
            return None;
        }
        let reserved_end = reserved_base.checked_add(self.reserve_len)?;
        let base = reserved_base.checked_add(self.alignment - 1)? & !(self.alignment - 1);
        let image_end = base.checked_add(self.image_len)?;
        Some(Placement {
            base,
            prefix: base.checked_sub(reserved_base)?,
            suffix: reserved_end.checked_sub(image_end)?,
        })
    }
}

/// Match GNU RELRO page semantics: round BOTH endpoints down. The trailing
/// partial page can contain ordinary writable data. Rounding its end upward
/// can fault in a constructor even though its ELF relocation was successful.
/// A sub-page/empty interval protects no pages. Bounds precede rounding so an
/// invalid interval is not disguised by a smaller page-aligned endpoint.
pub(super) fn relro_pages(range: &Range<usize>, image_len: usize) -> Option<Range<usize>> {
    if range.start > range.end || range.end > image_len {
        return None;
    }
    let mask = !(IMAGE_PAGE_SIZE - 1);
    Some((range.start & mask)..(range.end & mask))
}
