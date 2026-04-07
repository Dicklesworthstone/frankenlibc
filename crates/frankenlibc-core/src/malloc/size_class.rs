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

/// Validates a raw size-class index for the specified caller.
pub fn size_class_index(
    index: usize,
    caller: &'static str,
) -> Result<SizeClassIndex, BoundedIndexError<NUM_SIZE_CLASSES>> {
    SizeClassIndex::new(index, caller)
}

/// Computes the bounded bin index for a small allocation.
pub fn small_bin_index(size: usize) -> Option<SizeClassIndex> {
    let size = size.max(MIN_SIZE);
    if size > MAX_SMALL_SIZE {
        return None;
    }
    // Linear scan is fine for 32 entries; a real allocator would use
    // a lookup table indexed by (size >> 4) or similar.
    for (i, &class_size) in SIZE_TABLE.iter().enumerate() {
        if size <= class_size {
            return Some(BoundedIndex(i));
        }
    }
    None
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
    use super::*;

    const BOUNDS_AUDIT_JSON: &str = include_str!(env!("FRANKENLIBC_CORE_BOUNDS_AUDIT_PATH"));

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
