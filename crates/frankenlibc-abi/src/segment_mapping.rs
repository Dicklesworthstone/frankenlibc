//! Monotone, allocation-free permission upgrades for the native segment heap.
//!
//! Reserving address space is not the same as making it writable: Linux charges
//! the latter to RLIMIT_DATA even with MAP_NORESERVE. Keep unused payload pages
//! PROT_NONE and upgrade only chunks that are about to enter a thread's cache.

use core::sync::atomic::{AtomicU64, Ordering};
use frankenlibc_core::syscall;

// Compatible with the 4K, 16K and 64K pages supported by the segment geometry.
// One word covers a 4 MiB segment. This metadata is only read on chunk refill,
// never on the warmed per-slot allocation/free paths.
pub(super) const GRANULE: usize = 64 * 1024;

pub(super) struct WritablePages {
    ready: AtomicU64,
}

impl WritablePages {
    pub(super) const fn new() -> Self {
        Self { ready: AtomicU64::new(0) }
    }

    /// Enable the granules intersecting [start, end) within one reservation.
    ///
    /// # Safety
    /// `base..base+len` must be an exclusively owned, GRANULE-aligned anonymous
    /// mapping, dedicated to this instance. It must remain mapped and must never
    /// lose write permission for the lifetime of this instance. Concurrent
    /// callers may only upgrade permissions, not replace mappings or clear data.
    pub(super) unsafe fn enable(
        &self, base: usize, len: usize, start: usize, end: usize,
    ) -> bool {
        self.enable_with(base, len, start, end, |addr, bytes| {
            // SAFETY: the caller owns the reservation; range() confines this
            // operation to its aligned granules. Raw syscalls cannot reenter
            // the interposed mmap/mprotect/malloc entrypoints.
            unsafe {
                syscall::sys_mprotect(
                    addr as *mut core::ffi::c_void,
                    bytes,
                    libc::PROT_READ | libc::PROT_WRITE,
                ).is_ok()
            }
        })
    }

    fn enable_with(
        &self, base: usize, len: usize, start: usize, end: usize,
        protect: impl FnOnce(usize, usize) -> bool,
    ) -> bool {
        let Some((addr, bytes, mask)) = range(base, len, start, end) else {
            return false;
        };
        if self.ready.load(Ordering::Acquire) & mask == mask {
            return true;
        }
        // No initializing bit, lock, or wait: a fork child cannot inherit an
        // unfinished permission transition. Racing upgrades are idempotent.
        // On failure mprotect may have upgraded a prefix; retain it but certify
        // nothing. A retry can safely upgrade that range again.
        if !protect(addr, bytes) {
            return false;
        }
        self.ready.fetch_or(mask, Ordering::Release);
        true
    }
}

fn range(base: usize, len: usize, start: usize, end: usize) -> Option<(usize, usize, u64)> {
    if base == 0 || base % GRANULE != 0 || len == 0 || len % GRANULE != 0
        || len > 64 * GRANULE || start >= end || end > len
    {
        return None;
    }
    base.checked_add(len)?;
    let first = start / GRANULE;
    let last = end.checked_add(GRANULE - 1)? / GRANULE;
    let count = last - first;
    let mask = (u64::MAX >> (64 - count)) << first;
    Some((base + first * GRANULE, count * GRANULE, mask))
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{
        SEGMENT_SIZE, SEGMENT_HEADER_BYTES, SEGMENT_COUNT, SEGMENT_OWNED_BITMAP,
        SEGMENT_DESCRIPTORS, SEGMENT_SLOT_FREE, initialize_segment,
        segment_base, segment_header, segment_slot_view_at, segment_remaining,
        claim_segment_bump_chunk,
    };
    use std::sync::{Arc, Barrier};

    fn permissions(addr: usize) -> String {
        let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
        for line in maps.lines() {
            let mut fields = line.split_whitespace();
            let (lo, hi) = fields.next().unwrap().split_once('-').unwrap();
            let lo = usize::from_str_radix(lo, 16).unwrap();
            let hi = usize::from_str_radix(hi, 16).unwrap();
            if lo <= addr && addr < hi { return fields.next().unwrap().to_owned(); }
        }
        panic!("mapping not found");
    }

    #[test]
    fn range_rounding_and_last_bit_are_exact() {
        let base = 64 * GRANULE;
        assert_eq!(range(base, 64 * GRANULE, 1, GRANULE + 1), Some((base, 2 * GRANULE, 3)));
        assert_eq!(range(base, 64 * GRANULE, 63 * GRANULE, 64 * GRANULE),
                   Some((base + 63 * GRANULE, GRANULE, 1 << 63)));
        assert_eq!(range(base, 64 * GRANULE, 0, 64 * GRANULE),
                   Some((base, 64 * GRANULE, u64::MAX)));
    }

    #[test]
    fn invalid_ranges_do_not_call_the_kernel() {
        let pages = WritablePages::new();
        for (base, len, start, end) in [
            (0, GRANULE, 0, 1), (1, GRANULE, 0, 1),
            (GRANULE, 0, 0, 1), (GRANULE, GRANULE + 1, 0, 1),
            (GRANULE, 65 * GRANULE, 0, 1), (GRANULE, GRANULE, 0, 0),
            (GRANULE, GRANULE, 2, 1), (GRANULE, GRANULE, 0, GRANULE + 1),
            (usize::MAX & !(GRANULE - 1), GRANULE, 0, 1),
        ] {
            assert!(!pages.enable_with(base, len, start, end, |_, _| panic!("invalid syscall")));
        }
        assert_eq!(pages.ready.load(Ordering::Acquire), 0);
    }

    #[test]
    fn repeated_refills_skip_already_writable_granules() {
        let pages = WritablePages::new();
        assert!(pages.enable_with(GRANULE, 4 * GRANULE, 1, 100, |a, n| {
            assert_eq!((a, n), (GRANULE, GRANULE)); true
        }));
        assert!(pages.enable_with(GRANULE, 4 * GRANULE, 100, 200, |_, _| panic!("duplicate upgrade")));
        assert_eq!(pages.ready.load(Ordering::Acquire), 1);
    }

    #[test]
    fn failed_upgrade_is_not_published_and_can_be_retried() {
        let pages = WritablePages::new();
        assert!(!pages.enable_with(GRANULE, 4 * GRANULE, 0, 2 * GRANULE, |_, _| false));
        assert_eq!(pages.ready.load(Ordering::Acquire), 0);
        assert!(pages.enable_with(GRANULE, 4 * GRANULE, 0, 2 * GRANULE, |_, _| true));
        assert_eq!(pages.ready.load(Ordering::Acquire), 3);
        assert!(!pages.enable_with(GRANULE, 4 * GRANULE, GRANULE, 3 * GRANULE, |_, _| false));
        assert_eq!(pages.ready.load(Ordering::Acquire), 3);
    }

    #[test]
    fn permission_is_published_only_after_upgrade_finishes() {
        let pages = Arc::new(WritablePages::new());
        let barrier = Arc::new(Barrier::new(2));
        let other = pages.clone(); let rendezvous = barrier.clone();
        let worker = std::thread::spawn(move || {
            assert!(other.enable_with(GRANULE, GRANULE, 0, 1, |_, _| {
                rendezvous.wait(); rendezvous.wait(); true
            }));
        });
        barrier.wait();
        assert_eq!(pages.ready.load(Ordering::Acquire), 0);
        barrier.wait(); worker.join().unwrap();
        assert_eq!(pages.ready.load(Ordering::Acquire), 1);
    }

    #[test]
    fn concurrent_refills_preserve_all_successful_upgrades() {
        let pages = WritablePages::new();
        std::thread::scope(|scope| {
            for i in 0..64 {
                let pages = &pages;
                scope.spawn(move || assert!(pages.enable_with(
                    GRANULE, 64 * GRANULE, i * GRANULE, (i + 1) * GRANULE, |_, _| true,
                )));
            }
        });
        assert_eq!(pages.ready.load(Ordering::Acquire), u64::MAX);
    }

    #[test]
    fn actual_segment_reservation_stays_inaccessible_until_refill() {
        let index = initialize_segment(0).expect("new segment");
        let base = segment_base(index).unwrap();
        let header = segment_header(index).unwrap();
        assert_eq!(&permissions(base + SEGMENT_HEADER_BYTES)[..3], "---",
                   "unused payload must remain PROT_NONE");
        assert_eq!(&permissions(base + SEGMENT_SIZE - 1)[..3], "---");
        // Ownership lookups must still be safe for every never-used slot.
        let last = segment_slot_view_at(index, header.slot_count - 1).unwrap();
        assert_eq!(last.meta.requested_size.load(Ordering::Acquire), 0);
        assert_eq!(segment_remaining(last.user_base), None);
        let (start, end) = claim_segment_bump_chunk(index, 0).unwrap();
        assert_eq!(start, 0); assert!(end > start);
        let first = segment_slot_view_at(index, start).unwrap();
        assert_eq!(&permissions(first.user_base)[..3], "rw-");
        assert_eq!(&permissions(base + SEGMENT_SIZE - 1)[..3], "---");
        assert_eq!(SEGMENT_DESCRIPTORS[index].writable.ready.load(Ordering::Acquire), 2);
        // SAFETY: the freshly claimed chunk is writable and has no other owner.
        unsafe { assert_eq!(*(first.user_base as *const u8), 0); *(first.user_base as *mut u8) = 0xa5; }
    }

    #[test]
    fn growing_an_entire_segment_preserves_earlier_payload() {
        let index = initialize_segment(0).unwrap();
        let header = segment_header(index).unwrap();
        let mut chunks = Vec::new();
        while let Some((start, end)) = claim_segment_bump_chunk(index, 0) {
            let first = segment_slot_view_at(index, start).unwrap();
            let last = segment_slot_view_at(index, end - 1).unwrap();
            for addr in [first.user_base, last.user_base + header.class_size as usize - 1] {
                // SAFETY: both bytes are in this test's newly claimed chunk.
                unsafe { assert_eq!(*(addr as *const u8), 0); *(addr as *mut u8) = 0x5a; }
                chunks.push(addr);
            }
        }
        for addr in chunks { unsafe { assert_eq!(*(addr as *const u8), 0x5a); } }
        assert_eq!(SEGMENT_DESCRIPTORS[index].writable.ready.load(Ordering::Acquire), u64::MAX - 1);
    }

    #[test]
    fn concurrent_real_chunk_claims_are_disjoint_and_writable() {
        let index = initialize_segment(0).unwrap();
        let mut ranges = std::thread::scope(|scope| {
            let workers: Vec<_> = (0..8).map(|_| scope.spawn(move || {
                let mut ranges = Vec::new();
                for _ in 0..16 {
                    let (start, end) = claim_segment_bump_chunk(index, 0).unwrap();
                    let first = segment_slot_view_at(index, start).unwrap();
                    // SAFETY: successful claims have disjoint payloads and
                    // cannot return until their permission upgrades complete.
                    unsafe { *(first.user_base as *mut u8) = 0x33; }
                    ranges.push((start, end));
                }
                ranges
            })).collect();
            workers.into_iter().flat_map(|w| w.join().unwrap()).collect::<Vec<_>>()
        });
        ranges.sort_unstable();
        for pair in ranges.windows(2) { assert!(pair[0].1 <= pair[1].0); }
        assert_eq!(ranges.len(), 128);
        assert_ne!(SEGMENT_OWNED_BITMAP.load(Ordering::Acquire) & (1 << index), 0);
        assert!(index < SEGMENT_COUNT);
        assert_eq!(SEGMENT_SLOT_FREE, u16::MAX);
    }
}
