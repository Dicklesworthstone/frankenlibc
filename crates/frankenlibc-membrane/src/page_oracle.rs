//! Two-level page bitmap for ownership queries.
//!
//! Level 1 (L1): Fixed-size array covering the address space in 16M-pointer
//! chunks. Each entry is a flag indicating whether any allocation exists
//! in that chunk.
//!
//! Level 2 (L2): On-demand 512-byte bitmaps tracking individual pages
//! within a chunk.
//!
//! This provides O(1) "is this page ours?" queries without scanning
//! the full arena.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};

use crate::bravo::BravoRwLock;

/// Page size assumed for the oracle (4KB).
const PAGE_SIZE: usize = 4096;

/// Number of pages per L2 bitmap (512 bytes * 8 bits = 4096 pages = 16MB).
const PAGES_PER_L2: usize = 4096;
/// Lock-free approximate filter over L1 chunks.
///
/// Each bit means "some chunk hashing here has had an L2 bitmap published."
/// The filter is monotone: removals never clear bits, so it can only produce
/// false positives. A zero bit is enough to skip the read-side map lock.
const L1_FILTER_WORDS: usize = 1024;
const L1_FILTER_BITS: usize = L1_FILTER_WORDS * u64::BITS as usize;

/// Two-level page ownership bitmap.
pub struct PageOracle {
    /// L2 bitmaps keyed by L1 index (chunk number).
    l2_maps: BravoRwLock<HashMap<usize, Arc<L2Bitmap>>>,
    /// Approximate lock-free L1 presence filter for fast negative queries.
    l1_presence_filter: Box<[AtomicU64; L1_FILTER_WORDS]>,
    /// Number of pages currently marked owned across all L2 bitmaps.
    owned_pages: AtomicUsize,
}

/// A bitmap covering PAGES_PER_L2 pages.
struct L2Bitmap {
    /// Atomic array for lock-free refcounting.
    counts: Box<[AtomicU32; PAGES_PER_L2]>,
}

impl L2Bitmap {
    fn new() -> Self {
        // SAFETY: AtomicU32 has the same layout as u32. We can initialize a zeroed
        // array of u32s and safely treat it as AtomicU32. For now, we'll use a safer
        // approach with a typed initializer to avoid any UB risks.
        let counts: Box<[AtomicU32; PAGES_PER_L2]> =
            std::array::from_fn(|_| AtomicU32::new(0)).into();
        Self { counts }
    }

    fn set(&self, page_within_chunk: usize) -> bool {
        // Saturating increment
        self.counts[page_within_chunk]
            .fetch_update(Ordering::Release, Ordering::Relaxed, |x| {
                Some(if x == u32::MAX { u32::MAX } else { x + 1 })
            })
            .is_ok_and(|previous| previous == 0)
    }

    fn get(&self, page_within_chunk: usize) -> bool {
        self.counts[page_within_chunk].load(Ordering::Acquire) > 0
    }

    fn clear(&self, page_within_chunk: usize) -> bool {
        // Saturating decrement
        self.counts[page_within_chunk]
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |x| {
                match x {
                    0 => Some(0),               // Should not happen if balanced
                    u32::MAX => Some(u32::MAX), // Saturated, sticky
                    _ => Some(x - 1),
                }
            })
            .is_ok_and(|previous| previous == 1)
    }
}

impl PageOracle {
    /// Create a new empty page oracle.
    #[must_use]
    pub fn new() -> Self {
        Self {
            l2_maps: BravoRwLock::new(HashMap::new()),
            l1_presence_filter: std::array::from_fn(|_| AtomicU64::new(0)).into(),
            owned_pages: AtomicUsize::new(0),
        }
    }

    /// Returns true if no pages are currently marked owned.
    #[must_use]
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.owned_pages.load(Ordering::Acquire) == 0
    }

    /// Mark all pages covered by an allocation as owned.
    pub fn insert(&self, base: usize, size: usize) {
        if size == 0 {
            return;
        }

        let start_page = base / PAGE_SIZE;
        let end_page = (base + size - 1) / PAGE_SIZE;

        let mut last_marked_l1 = None;
        for page in start_page..=end_page {
            let (l1_idx, l2_page) = Self::decompose(page);
            if last_marked_l1 != Some(l1_idx) {
                self.mark_l1_chunk_maybe_present(l1_idx);
                last_marked_l1 = Some(l1_idx);
            }

            // Fast path: check if L2 already exists
            {
                let maps = self.l2_maps.read();
                if let Some(bitmap) = maps.get(&l1_idx) {
                    if bitmap.set(l2_page) {
                        self.owned_pages.fetch_add(1, Ordering::Release);
                    }
                    continue;
                }
            }

            // Slow path: create L2 bitmap
            self.l2_maps.with_write(|maps| {
                let bitmap = maps
                    .entry(l1_idx)
                    .or_insert_with(|| Arc::new(L2Bitmap::new()));
                if bitmap.set(l2_page) {
                    self.owned_pages.fetch_add(1, Ordering::Release);
                }
            });
        }
    }

    /// Query whether a page is marked as owned.
    ///
    /// No false negatives: if we inserted it, we'll find it.
    #[must_use]
    pub fn query(&self, addr: usize) -> bool {
        if self.is_empty() {
            return false;
        }

        let page = addr / PAGE_SIZE;
        let (l1_idx, l2_page) = Self::decompose(page);
        if !self.l1_chunk_may_be_present(l1_idx) {
            return false;
        }

        let maps = self.l2_maps.read();
        maps.get(&l1_idx).is_some_and(|bitmap| bitmap.get(l2_page))
    }

    /// Remove ownership marks for pages covered by an allocation.
    pub fn remove(&self, base: usize, size: usize) {
        if size == 0 {
            return;
        }

        let start_page = base / PAGE_SIZE;
        let end_page = (base + size - 1) / PAGE_SIZE;

        let maps = self.l2_maps.read();
        for page in start_page..=end_page {
            let (l1_idx, l2_page) = Self::decompose(page);
            if let Some(bitmap) = maps.get(&l1_idx)
                && bitmap.clear(l2_page)
            {
                self.owned_pages.fetch_sub(1, Ordering::Release);
            }
        }
    }

    /// Decompose a global page number into (L1 index, L2 page offset).
    fn decompose(page: usize) -> (usize, usize) {
        let l1_idx = page / PAGES_PER_L2;
        let l2_page = page % PAGES_PER_L2;
        (l1_idx, l2_page)
    }

    fn mark_l1_chunk_maybe_present(&self, l1_idx: usize) {
        let (word, mask) = Self::l1_filter_word_and_mask(l1_idx);
        self.l1_presence_filter[word].fetch_or(mask, Ordering::Release);
    }

    fn l1_chunk_may_be_present(&self, l1_idx: usize) -> bool {
        let (word, mask) = Self::l1_filter_word_and_mask(l1_idx);
        self.l1_presence_filter[word].load(Ordering::Acquire) & mask != 0
    }

    fn l1_filter_word_and_mask(l1_idx: usize) -> (usize, u64) {
        let bit = Self::mix_l1_index(l1_idx) & (L1_FILTER_BITS - 1);
        (
            bit / u64::BITS as usize,
            1_u64 << (bit % u64::BITS as usize),
        )
    }

    fn mix_l1_index(value: usize) -> usize {
        let mut value = value as u64;
        value ^= value >> 33;
        value = value.wrapping_mul(0xff51_afd7_ed55_8ccd);
        value ^= value >> 33;
        value = value.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
        (value ^ (value >> 33)) as usize
    }
}

impl Default for PageOracle {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_query() {
        let oracle = PageOracle::new();
        let base = 0x1000; // page-aligned
        assert!(oracle.is_empty());
        oracle.insert(base, 4096);

        assert!(!oracle.is_empty());
        assert!(oracle.query(base));
        assert!(oracle.query(base + 2048));
        assert!(!oracle.query(base + 8192));
    }

    #[test]
    fn multi_page_allocation() {
        let oracle = PageOracle::new();
        let base = 0x10000;
        oracle.insert(base, 3 * PAGE_SIZE);

        assert!(oracle.query(base));
        assert!(oracle.query(base + PAGE_SIZE));
        assert!(oracle.query(base + 2 * PAGE_SIZE));
        assert!(!oracle.query(base + 3 * PAGE_SIZE));
    }

    #[test]
    fn no_false_negatives() {
        let oracle = PageOracle::new();
        let allocations: Vec<(usize, usize)> = (0..100)
            .map(|i| (0x100000 + i * 0x10000, (i + 1) * 256))
            .collect();

        for &(base, size) in &allocations {
            oracle.insert(base, size);
        }

        for &(base, _size) in &allocations {
            assert!(oracle.query(base), "false negative at {base:#x}");
        }
    }

    #[test]
    fn remove_works() {
        let oracle = PageOracle::new();
        let base = 0x2000;
        oracle.insert(base, 4096);
        assert!(oracle.query(base));

        oracle.remove(base, 4096);
        assert!(oracle.is_empty());
        assert!(!oracle.query(base));
    }

    #[test]
    fn empty_oracle_returns_false() {
        let oracle = PageOracle::new();
        assert!(!oracle.query(0x1000));
        assert!(!oracle.query(0xDEAD_BEEF));
    }

    #[test]
    fn l1_presence_filter_is_monotone() {
        let oracle = PageOracle::new();
        let base = 0x4000_0000;
        let (l1_idx, _) = PageOracle::decompose(base / PAGE_SIZE);

        assert!(!oracle.l1_chunk_may_be_present(l1_idx));
        oracle.insert(base, 4096);
        assert!(oracle.l1_chunk_may_be_present(l1_idx));
        oracle.remove(base, 4096);
        assert!(oracle.l1_chunk_may_be_present(l1_idx));
        assert!(!oracle.query(base));
    }
}
