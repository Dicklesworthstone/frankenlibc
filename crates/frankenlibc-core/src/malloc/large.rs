//! Large allocation handling (>32KB).
//!
//! Allocations larger than the maximum small-allocation size class
//! are handled separately. In this safe Rust core layer, large allocations
//! are tracked as metadata records. The actual system-level memory mapping
//! happens at the ABI layer.

use std::collections::HashMap;

/// Metadata for a large allocation.
#[derive(Debug, Clone)]
pub struct LargeAllocation {
    /// Base offset of the allocation.
    pub base: usize,
    /// Total size of the mapped region (including metadata overhead).
    pub mapped_size: usize,
    /// Usable size requested by the caller.
    pub user_size: usize,
}

/// Page size for alignment.
const PAGE_SIZE: usize = 4096;

/// Rounds a size up to the nearest page boundary.
fn page_align(size: usize) -> Option<usize> {
    size.checked_add(PAGE_SIZE - 1)
        .map(|rounded| rounded & !(PAGE_SIZE - 1))
}

/// Tracks active large allocations.
///
/// In the safe Rust core, this manages a registry of large allocations.
/// The ABI layer handles actual mmap/munmap.
pub struct LargeAllocator {
    /// Map from base offset to allocation metadata.
    allocations: HashMap<usize, LargeAllocation>,
    /// Next base offset for simulated allocations.
    next_base: usize,
    /// Total bytes currently mapped.
    total_mapped: usize,
}

impl LargeAllocator {
    /// Creates a new large allocator.
    pub fn new() -> Self {
        Self {
            allocations: HashMap::new(),
            next_base: 0x1_0000_0000, // Start at a high offset to avoid confusion
            total_mapped: 0,
        }
    }

    /// Registers a large allocation.
    ///
    /// Returns allocation metadata including the base offset.
    pub fn alloc(&mut self, size: usize) -> Option<LargeAllocation> {
        if size == 0 {
            return None;
        }

        let mapped_size = page_align(size)?;
        let base = self.next_base;
        self.next_base = self.next_base.checked_add(mapped_size)?;
        self.total_mapped = self.total_mapped.saturating_add(mapped_size);

        let alloc = LargeAllocation {
            base,
            mapped_size,
            user_size: size,
        };
        self.allocations.insert(base, alloc.clone());
        Some(alloc)
    }

    /// Frees a large allocation by base offset.
    ///
    /// Returns `true` if the allocation was found and freed.
    pub fn free(&mut self, base: usize) -> bool {
        if let Some(alloc) = self.allocations.remove(&base) {
            self.total_mapped -= alloc.mapped_size;
            true
        } else {
            false
        }
    }

    /// Looks up a large allocation by base offset.
    pub fn lookup(&self, base: usize) -> Option<&LargeAllocation> {
        self.allocations.get(&base)
    }

    /// Resizes a large allocation.
    ///
    /// Creates a new allocation with the new size and removes the old one.
    /// Returns the new allocation metadata, or `None` on failure.
    pub fn realloc(&mut self, base: usize, new_size: usize) -> Option<LargeAllocation> {
        if new_size == 0 {
            let old = self.allocations.remove(&base)?;
            self.total_mapped -= old.mapped_size;
            return None;
        }

        // Remove old allocation temporarily
        let old = self.allocations.remove(&base)?;
        self.total_mapped -= old.mapped_size;

        // Create new allocation
        if let Some(new_alloc) = self.alloc(new_size) {
            Some(new_alloc)
        } else {
            // Restore old allocation on failure
            self.allocations.insert(base, old.clone());
            self.total_mapped += old.mapped_size;
            None
        }
    }

    /// Returns the total number of active large allocations.
    pub fn active_count(&self) -> usize {
        self.allocations.len()
    }

    /// Returns the total bytes currently mapped.
    pub fn total_mapped(&self) -> usize {
        self.total_mapped
    }
}

impl Default for LargeAllocator {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience function: allocate a large block.
pub fn large_alloc(size: usize) -> Option<LargeAllocation> {
    // In standalone usage, create a temporary allocator.
    // The real path goes through MallocState which owns the LargeAllocator.
    let mut alloc = LargeAllocator::new();
    alloc.alloc(size)
}

/// Convenience function: free a large allocation.
pub fn large_free(_alloc: &LargeAllocation) -> i32 {
    // In the core layer, this is a no-op since we don't do actual munmap.
    // The ABI layer handles actual system calls.
    0
}

/// Convenience function: resize a large allocation.
pub fn large_realloc(_alloc: &LargeAllocation, new_size: usize) -> Option<LargeAllocation> {
    // Create a new allocation record.
    large_alloc(new_size)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_large_alloc_basic() {
        let mut allocator = LargeAllocator::new();
        let alloc = allocator.alloc(65536).unwrap();
        assert_eq!(alloc.user_size, 65536);
        assert!(alloc.mapped_size >= 65536);
        assert_eq!(alloc.mapped_size % PAGE_SIZE, 0);
        assert_eq!(allocator.active_count(), 1);
    }

    #[test]
    fn test_large_alloc_zero() {
        let mut allocator = LargeAllocator::new();
        assert!(allocator.alloc(0).is_none());
    }

    #[test]
    fn test_large_free() {
        let mut allocator = LargeAllocator::new();
        let alloc = allocator.alloc(100_000).unwrap();
        assert!(allocator.free(alloc.base));
        assert_eq!(allocator.active_count(), 0);
        assert_eq!(allocator.total_mapped(), 0);
    }

    #[test]
    fn test_large_free_invalid() {
        let mut allocator = LargeAllocator::new();
        assert!(!allocator.free(0xDEAD));
    }

    #[test]
    fn test_large_realloc() {
        let mut allocator = LargeAllocator::new();
        let alloc = allocator.alloc(50000).unwrap();
        let new_alloc = allocator.realloc(alloc.base, 100000).unwrap();
        assert_eq!(new_alloc.user_size, 100000);
        assert_eq!(allocator.active_count(), 1);
    }

    #[test]
    fn test_large_realloc_unknown_base_is_none() {
        let mut allocator = LargeAllocator::new();
        assert!(allocator.realloc(0xBAD, 4096).is_none());
        assert_eq!(allocator.active_count(), 0);
        assert_eq!(allocator.total_mapped(), 0);
    }

    #[test]
    fn test_large_realloc_zero_removes_original() {
        let mut allocator = LargeAllocator::new();
        let alloc = allocator.alloc(8192).unwrap();
        assert!(allocator.realloc(alloc.base, 0).is_none());
        assert_eq!(allocator.active_count(), 0);
        assert_eq!(allocator.total_mapped(), 0);
    }

    #[test]
    fn test_page_alignment() {
        assert_eq!(page_align(1), Some(4096));
        assert_eq!(page_align(4096), Some(4096));
        assert_eq!(page_align(4097), Some(8192));
        assert_eq!(page_align(0), Some(0));
        assert_eq!(page_align(usize::MAX), None);
    }

    #[test]
    fn test_large_alloc_rejects_page_align_overflow() {
        let mut allocator = LargeAllocator::new();
        assert!(allocator.alloc(usize::MAX).is_none());
        assert_eq!(allocator.active_count(), 0);
        assert_eq!(allocator.total_mapped(), 0);
    }

    #[test]
    fn test_multiple_allocations() {
        let mut allocator = LargeAllocator::new();
        let a1 = allocator.alloc(50000).unwrap();
        let a2 = allocator.alloc(60000).unwrap();
        let a3 = allocator.alloc(70000).unwrap();

        assert_ne!(a1.base, a2.base);
        assert_ne!(a2.base, a3.base);
        assert_eq!(allocator.active_count(), 3);

        allocator.free(a2.base);
        assert_eq!(allocator.active_count(), 2);
        assert!(allocator.lookup(a1.base).is_some());
        assert!(allocator.lookup(a2.base).is_none());
        assert!(allocator.lookup(a3.base).is_some());
    }

    #[test]
    fn test_convenience_functions() {
        let alloc = large_alloc(100000).unwrap();
        assert_eq!(alloc.user_size, 100000);
        assert_eq!(large_free(&alloc), 0);

        let new_alloc = large_realloc(&alloc, 200000).unwrap();
        assert_eq!(new_alloc.user_size, 200000);
    }

    #[test]
    fn test_large_allocator_accounting_invariant_under_trace() {
        fn lcg(state: &mut u64) -> u64 {
            *state = state
                .wrapping_mul(2862933555777941757)
                .wrapping_add(3037000493);
            *state
        }

        let mut allocator = LargeAllocator::new();
        let mut live: Vec<usize> = Vec::new();
        let mut rng = 0xD00D_F00D_1234_5678u64;

        for _ in 0..1200 {
            let r = lcg(&mut rng);
            match r % 3 {
                0 => {
                    let size = ((r >> 11) as usize % 200_000).max(1);
                    if let Some(alloc) = allocator.alloc(size) {
                        live.push(alloc.base);
                    }
                }
                1 if !live.is_empty() => {
                    let idx = (r as usize) % live.len();
                    let base = live.swap_remove(idx);
                    assert!(allocator.free(base));
                }
                2 if !live.is_empty() => {
                    let idx = (r as usize) % live.len();
                    let base = live[idx];
                    let new_size = (r >> 17) as usize % 200_000;
                    let next = allocator.realloc(base, new_size);
                    if new_size == 0 {
                        assert!(next.is_none());
                        live.swap_remove(idx);
                    } else if let Some(new_alloc) = next {
                        live[idx] = new_alloc.base;
                    }
                }
                _ => {}
            }

            let observed_total: usize = live
                .iter()
                .map(|&base| {
                    allocator
                        .lookup(base)
                        .expect("live base must exist")
                        .mapped_size
                })
                .sum();
            assert_eq!(allocator.active_count(), live.len());
            assert_eq!(allocator.total_mapped(), observed_total);

            let unique: HashSet<usize> = live.iter().copied().collect();
            assert_eq!(unique.len(), live.len());
        }
    }
}
