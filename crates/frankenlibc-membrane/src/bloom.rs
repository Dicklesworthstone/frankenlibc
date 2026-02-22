//! Bloom filter for O(1) "is this pointer ours?" pre-check.
//!
//! Optimal sizing: m = -n*ln(p)/(ln2)^2, k = (m/n)*ln2
//!
//! Guarantees: zero false negatives (if we inserted it, we'll find it).
//! False positive rate is bounded and configurable.

use std::sync::atomic::{AtomicU64, Ordering};

/// Default expected number of insertions.
const DEFAULT_EXPECTED_ITEMS: usize = 1_000_000;

/// Default false positive rate target.
const DEFAULT_FP_RATE: f64 = 0.001; // 0.1%

/// Bloom filter for pointer ownership queries.
///
/// Thread-safe via atomic bit operations on the underlying array.
pub struct PointerBloomFilter {
    /// Bit array stored as atomic u64 words.
    bits: Box<[AtomicU64]>,
    /// Number of bits in the filter.
    num_bits: usize,
    /// Number of hash functions.
    num_hashes: u32,
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
        let m = (-n * fp_rate.ln() / (ln2 * ln2)).ceil() as usize;
        let m = m.max(64); // minimum 64 bits

        // Optimal hash count: k = (m/n) * ln2
        let k = ((m as f64 / n) * ln2).ceil() as u32;
        let k = k.clamp(1, 16); // clamp to reasonable range

        // Round up to whole u64 words, and ensure it's a power of 2 for double hashing
        let num_words = m.div_ceil(64).next_power_of_two();
        let num_bits = num_words * 64;

        let bits: Vec<AtomicU64> = (0..num_words).map(|_| AtomicU64::new(0)).collect();

        Self {
            bits: bits.into_boxed_slice(),
            num_bits,
            num_hashes: k,
        }
    }

    /// Insert a pointer into the bloom filter.
    pub fn insert(&self, ptr: usize) {
        for i in 0..self.num_hashes {
            let bit_idx = self.hash(ptr, i);
            let word_idx = bit_idx / 64;
            let bit_pos = bit_idx % 64;
            self.bits[word_idx].fetch_or(1u64 << bit_pos, Ordering::Relaxed);
        }
    }

    /// Query whether a pointer might be in the filter.
    ///
    /// Returns `true` if the pointer might be ours (may be false positive).
    /// Returns `false` if the pointer is definitely not ours (no false negatives).
    #[must_use]
    pub fn might_contain(&self, ptr: usize) -> bool {
        for i in 0..self.num_hashes {
            let bit_idx = self.hash(ptr, i);
            let word_idx = bit_idx / 64;
            let bit_pos = bit_idx % 64;
            if self.bits[word_idx].load(Ordering::Relaxed) & (1u64 << bit_pos) == 0 {
                return false;
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

    /// Compute the i-th hash for a pointer value.
    ///
    /// Uses double hashing: h(i) = (h1 + i*h2) mod m
    fn hash(&self, ptr: usize, i: u32) -> usize {
        let h1 = self.hash1(ptr);
        let h2 = self.hash2(ptr);
        let combined = h1.wrapping_add((i as usize).wrapping_mul(h2));
        combined % self.num_bits
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
}
