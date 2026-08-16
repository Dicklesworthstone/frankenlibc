//! Size class bins for small allocations.
//!
//! Defines size classes from 16 bytes to 32KB. Each size class has a bin
//! of free blocks. The bin index is computed by rounding up the requested
//! size to the nearest size class boundary.

use std::convert::TryFrom;

/// Minimum allocation size (bytes).
pub const MIN_SIZE: usize = 16;

/// Maximum size for small allocations (bytes). Above this, use large/mmap path.
pub const MAX_SMALL_SIZE: usize = 32 * 1024; // 32KB

/// Number of size class bins.
pub const NUM_SIZE_CLASSES: usize = 32;

/// Refinement-style index proving a value is in `[0, MAX)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct BoundedIndex<const MAX: usize>(usize);

/// Error returned when a [`BoundedIndex`] conversion fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundedIndexError<const MAX: usize> {
    pub value: usize,
    pub caller: &'static str,
}

impl<const MAX: usize> BoundedIndex<MAX> {
    fn build(value: usize, caller: &'static str) -> Result<Self, BoundedIndexError<MAX>> {
        if value < MAX {
            Ok(Self(value))
        } else {
            #[cfg(feature = "runtime-tracing")]
            tracing::warn!(
                target: "liquid_types",
                value,
                max = MAX,
                caller,
                "bounded index conversion failed"
            );
            Err(BoundedIndexError { value, caller })
        }
    }

    /// Validates an index at the module boundary and returns a bounded wrapper.
    pub fn new(value: usize, caller: &'static str) -> Result<Self, BoundedIndexError<MAX>> {
        Self::build(value, caller)
    }

    /// Returns the validated raw index.
    pub const fn get(self) -> usize {
        self.0
    }
}

impl<const MAX: usize> TryFrom<usize> for BoundedIndex<MAX> {
    type Error = BoundedIndexError<MAX>;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        Self::build(value, "BoundedIndex::try_from")
    }
}

/// Bounded wrapper for the small-allocation size-class table.
pub type SizeClassIndex = BoundedIndex<NUM_SIZE_CLASSES>;

/// Describes a single size class bin.
#[derive(Debug, Clone)]
pub struct SizeClass {
    /// The allocation size for this class (bytes).
    pub size: usize,
    /// Number of objects that fit in a slab/page for this class.
    pub objects_per_slab: usize,
}

impl SizeClass {
    /// Creates a new size class descriptor.
    pub fn new(size: usize, objects_per_slab: usize) -> Self {
        Self {
            size,
            objects_per_slab,
        }
    }
}

/// Size class table following a geometric progression.
///
/// Bins 0-7:   16-byte steps (16..128)
/// Bins 8-15:  32-byte steps (160..384)
/// Bins 16-23: wider steps (448, 512, 640, 768, 896, 1024, 1280, 1536)
/// Bins 24-31: large small classes (2048..32768)
const SIZE_TABLE: [usize; NUM_SIZE_CLASSES] = [
    16, 32, 48, 64, 80, 96, 112, 128, // 16-byte steps
    160, 192, 224, 256, 288, 320, 352, 384, // 32-byte steps
    448, 512, 640, 768, 896, 1024, 1280, 1536, // wider steps
    2048, 2560, 3072, 4096, 8192, 16384, 24576, 32768, // large small classes
];

/// Largest segment-relative offset for which the reciprocals below are exact.
///
/// The ABI's segment allocator asserts its own `SEGMENT_SIZE` against this, so a
/// segment that grows past the range these reciprocals were derived for fails to
/// compile rather than silently returning a wrong slot index.
pub const MAX_SLOT_OFFSET: usize = 1 << 22;

/// Granule every size class is a multiple of, as a shift.
///
/// Dividing both operands by 16 before the reciprocal is what lets the magic
/// number fit in a `u32`: the offset drops to `< 2^18` and the divisor to
/// `<= 2048`, so a shift of 29 suffices and `m <= 2^29`. That matters because a
/// `u32` fits the segment header's existing reserved word, which keeps the
/// reciprocal on the SAME CACHE LINE as the `class_size` the free path already
/// loads. A separate lookup table was measured and REJECTED for exactly this
/// reason -- see `docs/NEGATIVE_EVIDENCE.md` 2026-08-16.
const GRANULE_SHIFT: u32 = 4;

/// Shift for the magic reciprocals returned by [`slot_index_reciprocal`].
pub const SLOT_RECIPROCAL_SHIFT: u32 = 29;

/// The round-up reciprocal for one size class, or `None` for a bad index.
///
/// `m = floor(2^S / d) + 1` computes `n / d` exactly for every `n < N` when
/// `N * d <= 2^S`. Here, after the granule shift, `N = 2^18` and `d <= 2^11`,
/// so `S = 29` is exactly sufficient. Exactness is not left to that argument:
/// `slot_index_matches_division_at_every_transition` proves it against real
/// division at every point where the quotient changes, for every class.
pub fn slot_index_reciprocal(class_index: usize) -> Option<u32> {
    let size = *SIZE_TABLE.get(class_index)? as u64;
    let granules = size >> GRANULE_SHIFT;
    Some((((1u64 << SLOT_RECIPROCAL_SHIFT) / granules) + 1) as u32)
}

/// Divide a segment-relative payload offset by a size class, without dividing.
///
/// `reciprocal` must come from [`slot_index_reciprocal`] for the class the
/// offset belongs to, and `payload_offset` must be below [`MAX_SLOT_OFFSET`];
/// both are guaranteed by the segment allocator's header validation and its
/// compile-time size assertion.
#[inline(always)]
pub fn slot_index_from_reciprocal(reciprocal: u32, payload_offset: usize) -> usize {
    debug_assert!(payload_offset < MAX_SLOT_OFFSET);
    let granules = (payload_offset >> GRANULE_SHIFT) as u64;
    ((granules * reciprocal as u64) >> SLOT_RECIPROCAL_SHIFT) as usize
}

/// Validates a raw size-class index for the specified caller.
pub fn size_class_index(
    index: usize,
    caller: &'static str,
) -> Result<SizeClassIndex, BoundedIndexError<NUM_SIZE_CLASSES>> {
    SizeClassIndex::new(index, caller)
}

/// Number of 16-byte granules spanning `1..=MAX_SMALL_SIZE`. Every size class is
/// a multiple of 16, so all sizes in a granule `((g*16)+1 ..= (g+1)*16]` share a
/// bin — letting a granule-indexed table resolve the bin in O(1).
const SMALL_BIN_LUT_LEN: usize = MAX_SMALL_SIZE >> 4;

/// Precomputed `granule -> bin index` table, built at compile time from
/// [`SIZE_TABLE`] so the hot path needs no per-call search.
static SMALL_BIN_LUT: [u8; SMALL_BIN_LUT_LEN] = build_small_bin_lut();

const fn build_small_bin_lut() -> [u8; SMALL_BIN_LUT_LEN] {
    let mut lut = [0u8; SMALL_BIN_LUT_LEN];
    let mut g = 0;
    while g < SMALL_BIN_LUT_LEN {
        // Largest size in granule g; the smallest class >= it covers the whole
        // granule because every class boundary is a multiple of 16.
        let size = (g + 1) * 16;
        let mut i = 0;
        while i < NUM_SIZE_CLASSES {
            if size <= SIZE_TABLE[i] {
                lut[g] = i as u8;
                break;
            }
            i += 1;
        }
        g += 1;
    }
    lut
}

/// Computes the bounded bin index for a small allocation.
///
/// O(1) granule-table lookup (see [`SMALL_BIN_LUT`]) — byte-for-byte identical
/// to the smallest-class-`>=`-size search it replaced, since each granule maps
/// to exactly one class.
pub fn small_bin_index(size: usize) -> Option<SizeClassIndex> {
    let size = size.max(MIN_SIZE);
    if size > MAX_SMALL_SIZE {
        return None;
    }
    // size in 16..=MAX_SMALL_SIZE => granule in 0..SMALL_BIN_LUT_LEN.
    let granule = (size - 1) >> 4;
    Some(BoundedIndex(SMALL_BIN_LUT[granule] as usize))
}

/// Computes the bin index for a given allocation size.
///
/// Rounds `size` up to the nearest size class boundary and returns
/// the corresponding bin index. Sizes above `MAX_SMALL_SIZE` return
/// `NUM_SIZE_CLASSES` to signal the large-allocation path.
pub fn bin_index(size: usize) -> usize {
    small_bin_index(size).map_or(NUM_SIZE_CLASSES, SizeClassIndex::get)
}

/// Returns the allocation size for a given bin index.
///
/// This is the actual number of bytes allocated for objects in this bin.
/// Returns 0 for out-of-range indices.
pub fn bin_size(index: usize) -> usize {
    size_class_index(index, "size_class::bin_size")
        .map(size_for_index)
        .unwrap_or(0)
}

/// Returns the allocation size for a validated size-class index.
pub fn size_for_index(index: SizeClassIndex) -> usize {
    SIZE_TABLE[index.get()]
}

/// Returns true when `size` lands exactly on its resolved size-class boundary.
pub fn is_exact_size_class(size: usize, index: SizeClassIndex) -> bool {
    size.max(MIN_SIZE) == SIZE_TABLE[index.get()]
}

/// Initializes and returns the full table of size classes.
///
/// Each size class includes the allocation size and the number of objects
/// that fit in a 64KB slab (with 64-byte per-object overhead for metadata).
pub fn init_size_classes() -> Vec<SizeClass> {
    const SLAB_SIZE: usize = 64 * 1024; // 64KB slabs
    const PER_OBJECT_OVERHEAD: usize = 64; // fingerprint + canary + alignment

    SIZE_TABLE
        .iter()
        .map(|&size| {
            let effective = size + PER_OBJECT_OVERHEAD;
            let objects = SLAB_SIZE.checked_div(effective).unwrap_or(1);
            SizeClass::new(size, objects.max(1))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    /// Prove the magic reciprocals equal real division at every point where the
    /// quotient changes.
    ///
    /// Checking transitions rather than sampling is what makes this a proof and
    /// not a spot check: `n / d` is monotone non-decreasing and steps by one
    /// exactly at each multiple of `d`, so agreement at every `k*d` and every
    /// `k*d - 1` forces agreement everywhere between them. A randomised sweep
    /// could pass while being wrong on precisely the boundary that turns one
    /// allocation's slot into its neighbour's.
    #[test]
    fn slot_index_matches_division_at_every_transition() {
        let mut checked = 0usize;
        for class_index in 0..NUM_SIZE_CLASSES {
            let d = SIZE_TABLE[class_index];
            let recip = slot_index_reciprocal(class_index).expect("class in range");
            let mut k = 0usize;
            while k * d < MAX_SLOT_OFFSET {
                for n in [k * d, (k * d).saturating_sub(1)] {
                    if n >= MAX_SLOT_OFFSET {
                        continue;
                    }
                    assert_eq!(
                        slot_index_from_reciprocal(recip, n),
                        n / d,
                        "class {class_index} (size {d}) offset {n}"
                    );
                    checked += 1;
                }
                k += 1;
            }
        }
        // A zero here would mean the loops never ran and the assertions proved
        // nothing.
        assert!(
            checked > 500_000,
            "transition sweep only checked {checked} points"
        );
    }

    /// A bad class index yields `None`, not a wrong reciprocal.
    #[test]
    fn slot_index_reciprocal_rejects_out_of_range_class() {
        assert_eq!(slot_index_reciprocal(NUM_SIZE_CLASSES), None);
        assert!(slot_index_reciprocal(NUM_SIZE_CLASSES - 1).is_some());
        let recip = slot_index_reciprocal(0).expect("class 0");
        assert_eq!(
            slot_index_from_reciprocal(recip, MAX_SLOT_OFFSET - 1),
            (MAX_SLOT_OFFSET - 1) / 16
        );
    }

    use super::*;

    const BOUNDS_AUDIT_JSON: &str = include_str!(env!("FRANKENLIBC_CORE_BOUNDS_AUDIT_PATH"));

    // Reference: the original O(32) linear smallest-class->=-size scan.
    fn small_bin_index_linear(size: usize) -> Option<usize> {
        let size = size.max(MIN_SIZE);
        if size > MAX_SMALL_SIZE {
            return None;
        }
        for (i, &class_size) in SIZE_TABLE.iter().enumerate() {
            if size <= class_size {
                return Some(i);
            }
        }
        None
    }

    #[test]
    fn small_bin_index_lut_isomorphic_to_linear_scan() {
        // Exhaustive over every input the small path can see, plus a few above.
        for size in 0..=(MAX_SMALL_SIZE + 64) {
            let lut = small_bin_index(size).map(SizeClassIndex::get);
            let lin = small_bin_index_linear(size);
            assert_eq!(lut, lin, "small_bin_index mismatch at size={size}");
        }
        // And the bin actually fits the request (class_size >= requested).
        for size in 1..=MAX_SMALL_SIZE {
            let idx = small_bin_index(size).expect("small");
            assert!(
                size_for_index(idx) >= size,
                "bin {} (size {}) too small for request {size}",
                idx.get(),
                size_for_index(idx)
            );
        }
    }

    #[test]
    fn test_bin_index_min() {
        assert_eq!(bin_index(1), 0);
        assert_eq!(bin_index(16), 0);
    }

    #[test]
    fn test_bin_index_exact() {
        assert_eq!(bin_index(32), 1);
        assert_eq!(bin_index(64), 3);
        assert_eq!(bin_index(128), 7);
        assert_eq!(bin_index(256), 11);
    }

    #[test]
    fn test_bin_index_round_up() {
        // 17 bytes should round up to 32-byte class (index 1)
        assert_eq!(bin_index(17), 1);
        // 65 bytes should round up to 80-byte class (index 4)
        assert_eq!(bin_index(65), 4);
    }

    #[test]
    fn test_bin_index_large() {
        assert_eq!(bin_index(MAX_SMALL_SIZE), NUM_SIZE_CLASSES - 1);
        assert_eq!(bin_index(MAX_SMALL_SIZE + 1), NUM_SIZE_CLASSES);
    }

    #[test]
    fn test_bin_size_roundtrip() {
        for i in 0..NUM_SIZE_CLASSES {
            let size = bin_size(i);
            assert!(size > 0);
            assert_eq!(bin_index(size), i);
        }
    }

    #[test]
    fn test_bin_size_out_of_range() {
        assert_eq!(bin_size(NUM_SIZE_CLASSES), 0);
        assert_eq!(bin_size(100), 0);
    }

    #[test]
    fn test_size_table_monotonic() {
        for i in 1..NUM_SIZE_CLASSES {
            assert!(
                SIZE_TABLE[i] > SIZE_TABLE[i - 1],
                "size class {} ({}) must be > class {} ({})",
                i,
                SIZE_TABLE[i],
                i - 1,
                SIZE_TABLE[i - 1]
            );
        }
    }

    #[test]
    fn test_init_size_classes() {
        let classes = init_size_classes();
        assert_eq!(classes.len(), NUM_SIZE_CLASSES);
        for class in &classes {
            assert!(class.size >= MIN_SIZE);
            assert!(class.objects_per_slab >= 1);
        }
    }

    #[test]
    fn test_size_class_index_validates_bounds() {
        let index = SizeClassIndex::try_from(7).expect("index 7 should be valid");
        assert_eq!(index.get(), 7);
        assert_eq!(size_for_index(index), 128);
    }

    #[test]
    fn test_size_class_index_rejects_out_of_range() {
        let err = SizeClassIndex::try_from(NUM_SIZE_CLASSES).expect_err("out-of-range index");
        assert_eq!(err.value, NUM_SIZE_CLASSES);
        assert_eq!(err.caller, "BoundedIndex::try_from");
    }

    #[test]
    fn test_small_bin_index_returns_none_for_large_allocations() {
        assert!(small_bin_index(MAX_SMALL_SIZE + 1).is_none());
    }

    #[test]
    fn test_bounds_audit_reports_converted_allocator_sites() {
        assert!(BOUNDS_AUDIT_JSON.contains("\"total_bounds_checks\": 7"));
        assert!(BOUNDS_AUDIT_JSON.contains("\"statically_proven\": 7"));
        assert!(BOUNDS_AUDIT_JSON.contains("\"function\": \"ThreadCache::alloc\""));
        assert!(BOUNDS_AUDIT_JSON.contains("\"function\": \"MallocState::free.central_bin_push\""));
    }
}
