//! Bloom filter for O(1) "is this pointer ours?" pre-check.
//!
//! Optimal sizing: m = -n*ln(p)/(ln2)^2, k = (m/n)*ln2
//!
//! Guarantees: zero false negatives within a generation (if we inserted it, we
//! will find it). False positive rate is configurable; storage exhaustion
//! conservatively disables negative answers until a quiesced rebuild.
//!
//! ## Saturation and rebuilds
//!
//! The filter is insert-only **within** a generation: bits are set, never
//! cleared, so the zero-false-negative invariant is structural. A long-running
//! process eventually inserts more pointers than the filter is sized for, at
//! which point the false-positive rate climbs toward 100% and the "O(1) reject
//! non-owned pointer" benefit decays toward nothing.
//!
//! Two countermeasures live here:
//!
//! - The default `expected_items` is sized for a typical long-running libc
//!   consumer (4M items at 0.1% FP), not the 1M of the original design.
//! - The data structure exposes diagnostic and rebuild primitives
//!   (`insert_count`, `saturation_ratio`, `is_saturated`, `clear`,
//!   `rebuild_from`) so callers holding the authoritative live set can
//!   rebuild the filter from truth while insertions and queries are quiesced.
//!   Callers enumerate the current live set, hand it to `rebuild_from`, and
//!   resume queries after the bloom replaces its bit pattern in place.

use crate::util::LazyBox;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Default expected number of insertions. Sized for long-running consumers
/// (4M items at 0.1% false-positive rate ≈ 7.2 MB of bit array). Callers
/// expecting much higher allocation churn should construct the filter via
/// `with_capacity` and arrange periodic `rebuild_from` rebuilds from the
/// arena's live set.
const DEFAULT_EXPECTED_ITEMS: usize = 4_000_000;

/// Bits per block of the blocked layout: one 64-byte cache line.
const BLOOM_BLOCK_BITS: usize = 512;

/// Commit bit storage in 4 KiB pages, keeping every block within one page.
const BLOOM_PAGE_WORDS: usize = 512;
const BLOOM_PAGE_BITS: usize = BLOOM_PAGE_WORDS * u64::BITS as usize;
const _: () = assert!(BLOOM_PAGE_BITS.is_multiple_of(BLOOM_BLOCK_BITS));

/// Default false positive rate target.
const DEFAULT_FP_RATE: f64 = 0.001; // 0.1%

/// Bloom filter for pointer ownership queries.
///
/// Thread-safe via atomic bit operations on the underlying array.
pub struct PointerBloomFilter {
    /// Logical bit pages, published on first insertion and retained until Drop.
    /// The default directory is 16 KiB; its 8 MiB of bit storage is not eager.
    pages: Box<[LazyBox<[AtomicU64; BLOOM_PAGE_WORDS]>]>,
    /// Failed storage allocation disables negative answers until a quiesced
    /// clear/rebuild. An unavailable directory remains conservative for life.
    conservative: AtomicBool,
    /// Number of bits in the filter.
    num_bits: usize,
    /// Number of hash functions.
    num_hashes: u32,
    /// Sizing target the filter was constructed with — used by saturation
    /// diagnostics so callers can decide when to drive a `rebuild_from`.
    expected_items: usize,
    /// Monotonic counter of `insert` calls. Reset by `clear` /
    /// `rebuild_from`.
    insert_count: AtomicU64,
}

impl PointerBloomFilter {
    /// Create a new bloom filter with default parameters.
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_EXPECTED_ITEMS, DEFAULT_FP_RATE)
    }

    /// Create a bloom filter with specific capacity and false positive rate.
    #[must_use]
    pub fn with_capacity(expected_items: usize, fp_rate: f64) -> Self {
        let fp_rate = fp_rate.clamp(1e-10, 0.5);
        let n = expected_items.max(1) as f64;

        // Optimal bit count: m = -n * ln(p) / (ln2)^2
        let ln2 = std::f64::consts::LN_2;
        let m = crate::util::ceil_f64(-n * crate::util::ln_f64(fp_rate) / (ln2 * ln2)) as usize;
        let m = m.max(64); // minimum 64 bits

        // Optimal hash count: k = (m/n) * ln2
        let k = crate::util::ceil_f64((m as f64 / n) * ln2) as u32;
        let k = k.clamp(1, 16); // clamp to reasonable range

        // Round up to whole u64 words, and ensure it's a power of 2 for double hashing
        let num_words = m.div_ceil(64).next_power_of_two();
        let num_bits = num_words * 64;

        let page_count = num_words.div_ceil(BLOOM_PAGE_WORDS);
        let mut pages = Vec::new();
        let conservative = pages.try_reserve_exact(page_count).is_err();
        if !conservative {
            pages.resize_with(page_count, LazyBox::new);
        }

        Self {
            pages: pages.into_boxed_slice(),
            conservative: AtomicBool::new(conservative),
            num_bits,
            num_hashes: k,
            expected_items: expected_items.max(1),
            insert_count: AtomicU64::new(0),
        }
    }

    /// Insert a pointer into the bloom filter.
    pub fn insert(&self, ptr: usize) {
        self.insert_bits(ptr);
        self.insert_count.fetch_add(1, Ordering::Relaxed);
    }

    fn insert_bits(&self, ptr: usize) {
        if self.conservative.load(Ordering::Acquire) {
            return;
        }
        let (h1, h2) = (self.hash1(ptr), self.hash2(ptr));
        // Blocked hashing keeps every bit of this key on the same storage
        // page, including filters smaller than a block. Resolve it only once.
        let page_index = self.bit_index(h1, h2, 0) / BLOOM_PAGE_BITS;
        let Some(page) = self.pages.get(page_index).and_then(|page| {
            page.get_or_try_init(|| Some(std::array::from_fn(|_| AtomicU64::new(0))))
        }) else {
            // Losing an optional precheck must never hide an owned pointer.
            // The full page-oracle/arena validation remains authoritative.
            self.conservative.store(true, Ordering::Release);
            return;
        };
        for i in 0..self.num_hashes {
            let bit_idx = self.bit_index(h1, h2, i);
            let word = &page[(bit_idx / 64) % BLOOM_PAGE_WORDS];
            let mask = 1u64 << (bit_idx % 64);
            // Plain load first: in a filled filter most bits are already set,
            // and a locked RMW costs ~20 cycles and takes the line exclusive
            // even when it changes nothing (every hardened malloc inserts).
            if word.load(Ordering::Relaxed) & mask == 0 {
                word.fetch_or(mask, Ordering::Relaxed);
            }
        }
    }

    /// Query whether a pointer might be in the filter.
    ///
    /// Returns `true` if the pointer might be ours (may be false positive).
    /// Returns `false` if the pointer is definitely not ours (no false negatives).
    /// Storage exhaustion conservatively returns `true` for every pointer.
    #[must_use]
    pub fn might_contain(&self, ptr: usize) -> bool {
        let (h1, h2) = (self.hash1(ptr), self.hash2(ptr));
        let page_index = self.bit_index(h1, h2, 0) / BLOOM_PAGE_BITS;
        let Some(page) = self.pages.get(page_index).and_then(LazyBox::get) else {
            return self.conservative.load(Ordering::Acquire);
        };
        for i in 0..self.num_hashes {
            let bit_idx = self.bit_index(h1, h2, i);
            let word_idx = (bit_idx / 64) % BLOOM_PAGE_WORDS;
            let bit_pos = bit_idx % 64;
            if page[word_idx].load(Ordering::Relaxed) & (1u64 << bit_pos) == 0 {
                // Check at the negative-return boundary so a failed insertion
                // cannot be treated as an ordinary unset bit.
                return self.conservative.load(Ordering::Acquire);
            }
        }
        true
    }

    /// Number of bits in the filter.
    #[must_use]
    pub fn num_bits(&self) -> usize {
        self.num_bits
    }

    /// Number of hash functions.
    #[must_use]
    pub fn num_hashes(&self) -> u32 {
        self.num_hashes
    }

    /// Sizing target the filter was constructed with.
    #[must_use]
    pub fn expected_items(&self) -> usize {
        self.expected_items
    }

    /// Number of `insert` calls since the last `clear` /
    /// `rebuild_from`.
    #[must_use]
    pub fn insert_count(&self) -> u64 {
        self.insert_count.load(Ordering::Relaxed)
    }

    /// Ratio of `insert_count` to `expected_items`. 1.0 means the filter is at
    /// its design target; values >> 1.0 mean the false-positive rate has
    /// climbed well above the configured `fp_rate` and the caller should
    /// consider driving a `rebuild_from` against its authoritative live set.
    #[must_use]
    pub fn saturation_ratio(&self) -> f64 {
        self.insert_count() as f64 / self.expected_items.max(1) as f64
    }

    /// Convenience predicate: filter has absorbed at least 2× its design
    /// capacity. The FP rate at 2× is empirically ~5-10× the configured rate
    /// (depending on `k`), enough that the precheck benefit decays
    /// noticeably. Callers may use this as the trigger for `rebuild_from`.
    #[must_use]
    pub fn is_saturated(&self) -> bool {
        self.insert_count() >= (self.expected_items as u64).saturating_mul(2)
    }

    /// Clear every bit and reset the insert counter.
    ///
    /// **WARNING:** this is destructive. Callers MUST quiesce insertions and
    /// queries until the authoritative live set has been reinserted, normally
    /// through `rebuild_from`. Otherwise a query could observe a partially
    /// cleared filter and incorrectly reject a still-live pointer.
    ///
    /// Published pages remain allocated for reuse. A page allocation failure
    /// can recover in the new generation; a missing directory remains
    /// conservative for the lifetime of the filter. Otherwise, every query
    /// returns `false` until insertions resume.
    pub fn clear(&self) {
        for page in self.pages.iter().filter_map(LazyBox::get) {
            for word in page {
                word.store(0, Ordering::Relaxed);
            }
        }
        self.insert_count.store(0, Ordering::Relaxed);
        // Existing pages stay published. A valid directory can retry failed
        // pages in the new generation; a missing directory stays fail-open.
        self.conservative
            .store(self.pages.is_empty(), Ordering::Release);
    }

    /// Replace the filter's contents with the hashes of `items`.
    ///
    /// This is the saturation-recovery primitive: the caller (typically the
    /// allocation arena) enumerates its current live pointer set, hands it
    /// in here, and the bloom is refilled from truth. Items that
    /// were inserted but have since been freed drop out of the filter; the
    /// false-positive rate is restored to the design `fp_rate` if storage
    /// is available. Allocation failure keeps every query conservative.
    ///
    /// `items` is iterated once. Each pointer's hash bits are set with the
    /// same procedure as `insert`. The insert counter is set to the count
    /// of inserted items.
    ///
    /// **Synchronization:** during a rebuild a concurrent `might_contain`
    /// query *may* transiently observe an intermediate state in which some
    /// of the truth-set's bits are not yet set. Callers MUST hold a
    /// suitable barrier (quiescing both insertions and queries during the
    /// rebuild) when false negatives would be unsafe. For the ownership-precheck use
    /// case this is normally arranged by the arena's existing EBR /
    /// quarantine machinery.
    pub fn rebuild_from<I>(&self, items: I)
    where
        I: IntoIterator<Item = usize>,
    {
        // Zero first, then refill. Inserts during this window may race; the
        // contract above documents the requirement that callers quiesce.
        self.clear();
        let mut count: u64 = 0;
        for ptr in items {
            self.insert_bits(ptr);
            count = count.saturating_add(1);
        }
        self.insert_count.store(count, Ordering::Relaxed);
    }

    /// Bit `i` of a key with base hashes `h1`, `h2`.
    ///
    /// BLOCKED: every bit of one key lies in the same 512-bit (64-byte) block,
    /// chosen by `h1`, so an insert or query touches ONE cache line instead of
    /// `num_hashes` random lines of a multi-megabyte array -- the hardened
    /// allocator inserts every fresh (quarantine-rotated) address, and those
    /// misses were its largest self cost (bd-rc0923-epic-eeuy4f.9). Filters
    /// smaller than a block use plain double hashing over the whole array.
    #[inline]
    fn bit_index(&self, h1: usize, h2: usize, i: u32) -> usize {
        if self.num_bits < BLOOM_BLOCK_BITS {
            // Double hashing; `num_bits` is a power of two.
            return h1.wrapping_add((i as usize).wrapping_mul(h2)) & (self.num_bits - 1);
        }
        let block = h1 & (self.num_bits - 1) & !(BLOOM_BLOCK_BITS - 1);
        let step = (h2 >> 32) | 1;
        block + ((h2 >> 1).wrapping_add((i as usize).wrapping_mul(step)) & (BLOOM_BLOCK_BITS - 1))
    }

    /// Primary hash function (based on multiplicative hashing).
    fn hash1(&self, ptr: usize) -> usize {
        let mut x = ptr as u64;
        x = x.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        x ^= x >> 30;
        x = x.wrapping_mul(0xBF58_476D_1CE4_E5B9);
        x ^= x >> 27;
        x as usize
    }

    /// Secondary hash function.
    fn hash2(&self, ptr: usize) -> usize {
        let mut x = ptr as u64;
        x ^= x >> 33;
        x = x.wrapping_mul(0xFF51_AFD7_ED55_8CCD);
        x ^= x >> 33;
        x = x.wrapping_mul(0xC4CE_B9FE_1A85_EC53);
        x ^= x >> 33;
        // Ensure odd to get full period with double hashing
        (x as usize) | 1
    }
}

impl Default for PointerBloomFilter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paged_words_match_the_dense_layout_across_block_and_page_boundaries() {
        for (capacity, fp_rate) in [
            (1, 0.5),
            (20, 0.01),
            (64, 0.01),
            (1000, 0.01),
            (10_000, 0.001),
        ] {
            let filter = PointerBloomFilter::with_capacity(capacity, fp_rate);
            let mut dense = vec![0u64; filter.num_bits() / 64];
            for i in 0..512usize {
                let ptr = (i + 1).wrapping_mul(0x9e37);
                let (h1, h2) = (filter.hash1(ptr), filter.hash2(ptr));
                let page_index = filter.bit_index(h1, h2, 0) / BLOOM_PAGE_BITS;
                for hash in 0..filter.num_hashes() {
                    let bit = filter.bit_index(h1, h2, hash);
                    assert_eq!(bit / BLOOM_PAGE_BITS, page_index, "one page per key");
                    dense[bit / 64] |= 1u64 << (bit % 64);
                }
                filter.insert(ptr);
            }

            for (index, expected) in dense.into_iter().enumerate() {
                let actual = filter.pages[index / BLOOM_PAGE_WORDS]
                    .get()
                    .map_or(0, |page| {
                        page[index % BLOOM_PAGE_WORDS].load(Ordering::Relaxed)
                    });
                assert_eq!(actual, expected, "capacity {capacity}, word {index}");
            }
            assert_eq!(filter.insert_count(), 512);
        }
    }

    #[test]
    fn no_false_negatives() {
        let filter = PointerBloomFilter::with_capacity(1000, 0.01);
        let ptrs: Vec<usize> = (0..1000).map(|i| (i + 1) * 0x1000).collect();

        for &p in &ptrs {
            filter.insert(p);
        }

        for &p in &ptrs {
            assert!(
                filter.might_contain(p),
                "false negative for inserted pointer {p:#x}"
            );
        }
    }

    #[test]
    fn uninserted_pointers_mostly_absent() {
        let filter = PointerBloomFilter::with_capacity(1000, 0.01);
        for i in 0..1000 {
            filter.insert((i + 1) * 0x1000);
        }

        let mut false_positives = 0;
        let test_count = 10_000;
        for i in 0..test_count {
            let p = 0xDEAD_0000 + i * 0x1000;
            if filter.might_contain(p) {
                false_positives += 1;
            }
        }

        // Allow up to 2x the theoretical FP rate
        let fp_rate = false_positives as f64 / test_count as f64;
        assert!(
            fp_rate < 0.02,
            "false positive rate {fp_rate} exceeds 2x theoretical (0.01)"
        );
    }

    #[test]
    fn empty_filter_returns_false() {
        let filter = PointerBloomFilter::new();
        assert!(!filter.might_contain(0x1000));
        assert!(!filter.might_contain(0xDEAD_BEEF));
    }

    #[test]
    fn sizing_is_reasonable() {
        let filter = PointerBloomFilter::with_capacity(100_000, 0.001);
        // Should have at least ~1.44M bits for 100K items at 0.1% FP rate
        assert!(filter.num_bits() >= 1_000_000);
        assert!(filter.num_hashes() >= 7);
    }

    #[test]
    fn insert_count_tracks_inserts_and_resets_on_clear() {
        let filter = PointerBloomFilter::with_capacity(1_000, 0.01);
        assert_eq!(filter.insert_count(), 0);
        for i in 0..50 {
            filter.insert((i + 1) * 0x100);
        }
        assert_eq!(filter.insert_count(), 50);
        filter.clear();
        assert_eq!(filter.insert_count(), 0);
        // Post-clear, no inserted pointer should still be found.
        for i in 0..50 {
            assert!(!filter.might_contain((i + 1) * 0x100));
        }
    }

    #[test]
    fn saturation_diagnostic_signals_when_overfilled() {
        let filter = PointerBloomFilter::with_capacity(1_000, 0.01);
        assert!(!filter.is_saturated());
        assert!(filter.saturation_ratio() < 0.01);

        // At 1× capacity not yet saturated by the 2× threshold.
        for i in 0..1_000 {
            filter.insert((i + 1) * 0x100);
        }
        assert!(!filter.is_saturated());
        assert!((filter.saturation_ratio() - 1.0).abs() < 0.001);

        // Cross 2× → saturated.
        for i in 1_000..2_001 {
            filter.insert((i + 1) * 0x100);
        }
        assert!(filter.is_saturated());
        assert!(filter.saturation_ratio() > 2.0);
    }

    #[test]
    fn rebuild_from_atomically_replaces_contents_from_truth_set() {
        // Saturate the filter, then rebuild from a small truth set and
        // confirm: (a) inserts pre-rebuild are gone unless they appear in
        // the truth set; (b) every truth-set member is found; (c) the
        // insert counter is reset to the truth set's length; (d) the
        // false-positive rate is restored to the design target.
        let filter = PointerBloomFilter::with_capacity(1_000, 0.01);
        for i in 0..3_000 {
            filter.insert((i + 1) * 0x100);
        }
        assert!(filter.is_saturated());

        let truth: Vec<usize> = (0..100).map(|i| 0xCAFE_0000 + i * 0x10).collect();
        filter.rebuild_from(truth.iter().copied());

        // Every truth-set member is found (zero false negatives within the
        // rebuilt generation).
        for &p in &truth {
            assert!(
                filter.might_contain(p),
                "false negative for truth-set pointer {p:#x} after rebuild"
            );
        }
        // The insert counter reflects the truth set, not the saturation.
        assert_eq!(filter.insert_count(), 100);
        assert!(!filter.is_saturated());
        assert!(filter.saturation_ratio() <= 1.0);

        // The false-positive rate over a disjoint test set is back near
        // the design target (was ~100% before the rebuild).
        let mut fp = 0;
        let probes = 10_000;
        for i in 0..probes {
            let p = 0xBEEF_0000 + i * 0x10; // disjoint from `truth`
            if filter.might_contain(p) {
                fp += 1;
            }
        }
        let fp_rate = fp as f64 / probes as f64;
        // The fill is far below capacity (100 items in a 1000-capacity
        // filter), so the FP rate must be well under the configured 0.01.
        assert!(
            fp_rate < 0.01,
            "post-rebuild FP rate {fp_rate} not below design target 0.01"
        );
    }

    #[test]
    fn no_false_negatives_under_high_saturation() {
        // The article-flagged scenario: a long-running process inserts well
        // beyond the design capacity. The structural zero-false-negative
        // invariant must hold per-generation: every inserted pointer is
        // found, even when the filter is heavily saturated (only the FP
        // rate degrades). This is what makes the precheck *safe* to keep
        // calling even while saturated.
        let filter = PointerBloomFilter::with_capacity(1_000, 0.01);
        let ptrs: Vec<usize> = (0..5_000).map(|i| (i + 1) * 0x40).collect();
        for &p in &ptrs {
            filter.insert(p);
        }
        assert!(filter.is_saturated());
        for &p in &ptrs {
            assert!(
                filter.might_contain(p),
                "false negative under saturation for {p:#x}"
            );
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // PROPERTY-BASED: Bloom filter invariants via proptest
    //
    // The key property: zero false negatives. Any inserted pointer
    // must always be found by might_contain(). False positives are
    // acceptable (bounded by the configured rate).
    // ═══════════════════════════════════════════════════════════════

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_zero_false_negatives(ptrs in proptest::collection::vec(1usize..usize::MAX, 1..200)) {
            let filter = PointerBloomFilter::with_capacity(1000, 0.01);
            for &p in &ptrs {
                filter.insert(p);
            }
            for &p in &ptrs {
                prop_assert!(
                    filter.might_contain(p),
                    "false negative for inserted pointer {:#x}",
                    p
                );
            }
        }

        #[test]
        fn prop_insert_is_monotonic(ptr in 1usize..usize::MAX) {
            // Once inserted, a pointer is always found (monotonic)
            let filter = PointerBloomFilter::new();
            // Before insert: might_contain may return true (false positive) or false — both ok.
            filter.insert(ptr);
            prop_assert!(filter.might_contain(ptr)); // must be found after
            // Insert again — still found (idempotent)
            filter.insert(ptr);
            prop_assert!(filter.might_contain(ptr));
        }

        #[test]
        fn prop_concurrent_insert_no_false_negative(
            ptrs in proptest::collection::vec(1usize..usize::MAX, 1..50)
        ) {
            use std::sync::Arc;
            use std::thread;

            let filter = Arc::new(PointerBloomFilter::with_capacity(1000, 0.01));

            // Insert from multiple threads
            let mut handles = Vec::new();
            for chunk in ptrs.chunks(10) {
                let filter = Arc::clone(&filter);
                let chunk = chunk.to_vec();
                handles.push(thread::spawn(move || {
                    for &p in &chunk {
                        filter.insert(p);
                    }
                }));
            }
            for h in handles {
                h.join().expect("thread panicked");
            }

            // All inserted pointers must be found
            for &p in &ptrs {
                prop_assert!(
                    filter.might_contain(p),
                    "false negative after concurrent insert for {:#x}",
                    p
                );
            }
        }
    }
}
