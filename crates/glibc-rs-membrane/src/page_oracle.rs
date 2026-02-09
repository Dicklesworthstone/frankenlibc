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
use std::sync::atomic::{AtomicU8, Ordering};

use parking_lot::RwLock;

/// Page size assumed for the oracle (4KB).
const PAGE_SIZE: usize = 4096;

/// Number of pages per L2 bitmap (512 bytes * 8 bits = 4096 pages = 16MB).
const PAGES_PER_L2: usize = 4096;

/// Two-level page ownership bitmap.
pub struct PageOracle {
    /// L2 bitmaps keyed by L1 index (chunk number).
    l2_maps: RwLock<HashMap<usize, L2Bitmap>>,
}

/// A 512-byte bitmap covering PAGES_PER_L2 pages.
struct L2Bitmap {
    /// Atomic byte array for lock-free refcounting (one byte per page).
    counts: Box<[AtomicU8; PAGES_PER_L2]>,
}

impl L2Bitmap {
    fn new() -> Self {
        // Initialize all counts to 0
        let counts: Vec<AtomicU8> = (0..PAGES_PER_L2).map(|_| AtomicU8::new(0)).collect();
        let counts_array: Box<[AtomicU8; PAGES_PER_L2]> =
            counts.into_boxed_slice().try_into().expect("correct size");
        Self {
            counts: counts_array,
        }
    }

    fn set(&self, page_within_chunk: usize) {
        // Saturating increment
        let _ = self.counts[page_within_chunk].fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |x| Some(if x == 255 { 255 } else { x + 1 }),
        );
    }

    fn get(&self, page_within_chunk: usize) -> bool {
        self.counts[page_within_chunk].load(Ordering::Relaxed) > 0
    }

    fn clear(&self, page_within_chunk: usize) {
        // Saturating decrement
        let _ = self.counts[page_within_chunk].fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |x| {
                match x {
                    0 => Some(0),     // Should not happen if balanced
                    255 => Some(255), // Saturated, sticky
                    _ => Some(x - 1),
                }
            },
        );
    }
}

impl PageOracle {
    /// Create a new empty page oracle.
    #[must_use]
    pub fn new() -> Self {
        Self {
            l2_maps: RwLock::new(HashMap::new()),
        }
    }

    /// Mark all pages covered by an allocation as owned.
    pub fn insert(&self, base: usize, size: usize) {
        if size == 0 {
            return;
        }

        let start_page = base / PAGE_SIZE;
        let end_page = (base + size - 1) / PAGE_SIZE;

        for page in start_page..=end_page {
            let (l1_idx, l2_page) = Self::decompose(page);

            // Fast path: check if L2 already exists
            {
                let maps = self.l2_maps.read();
                if let Some(bitmap) = maps.get(&l1_idx) {
                    bitmap.set(l2_page);
                    continue;
                }
            }

            // Slow path: create L2 bitmap
            let mut maps = self.l2_maps.write();
            let bitmap = maps.entry(l1_idx).or_insert_with(L2Bitmap::new);
            bitmap.set(l2_page);
        }
    }

    /// Query whether a page is marked as owned.
    ///
    /// No false negatives: if we inserted it, we'll find it.
    #[must_use]
    pub fn query(&self, addr: usize) -> bool {
        let page = addr / PAGE_SIZE;
        let (l1_idx, l2_page) = Self::decompose(page);

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
            if let Some(bitmap) = maps.get(&l1_idx) {
                bitmap.clear(l2_page);
            }
        }
    }

    /// Decompose a global page number into (L1 index, L2 page offset).
    fn decompose(page: usize) -> (usize, usize) {
        let l1_idx = page / PAGES_PER_L2;
        let l2_page = page % PAGES_PER_L2;
        (l1_idx, l2_page)
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
        oracle.insert(base, 4096);

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
        assert!(!oracle.query(base));
    }

    #[test]
    fn empty_oracle_returns_false() {
        let oracle = PageOracle::new();
        assert!(!oracle.query(0x1000));
        assert!(!oracle.query(0xDEAD_BEEF));
    }
}
