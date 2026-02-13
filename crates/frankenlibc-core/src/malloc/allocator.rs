//! Core allocator state.
//!
//! Central allocation state that coordinates between the thread cache,
//! size-class bins, and large-allocation paths. This is the safe Rust
//! layer managing allocation policy and metadata.

use super::large::LargeAllocator;
use super::size_class::{self, NUM_SIZE_CLASSES};
use super::thread_cache::ThreadCache;

use std::collections::HashMap;

/// Tracks an individual allocation made through the core allocator.
#[derive(Debug, Clone)]
struct AllocationRecord {
    /// Usable size requested by caller.
    user_size: usize,
    /// Size class index (NUM_SIZE_CLASSES for large).
    bin: usize,
}

/// Global allocator state.
///
/// Manages the central heap, bin freelists, and coordination with
/// per-thread caches and the large allocator.
pub struct MallocState {
    /// Per-bin central freelists (bin index -> stack of free offsets).
    central_bins: Vec<Vec<usize>>,
    /// Large allocation manager.
    large_allocator: LargeAllocator,
    /// Thread cache (single-threaded model for now).
    thread_cache: ThreadCache,
    /// Active allocation records (offset -> record).
    active: HashMap<usize, AllocationRecord>,
    /// Next offset for new slab allocations.
    next_offset: usize,
    /// Whether the allocator has been initialized.
    initialized: bool,
    /// Total bytes allocated (user-requested).
    total_allocated: usize,
    /// Total number of active allocations.
    active_count: usize,
}

impl MallocState {
    /// Creates a new initialized allocator state.
    pub fn new() -> Self {
        let central_bins = (0..NUM_SIZE_CLASSES).map(|_| Vec::new()).collect();
        Self {
            central_bins,
            large_allocator: LargeAllocator::new(),
            thread_cache: ThreadCache::new(),
            active: HashMap::new(),
            next_offset: 0x1000, // Start above zero page
            initialized: true,
            total_allocated: 0,
            active_count: 0,
        }
    }

    /// Allocates `size` bytes of memory.
    ///
    /// Returns a logical offset (simulating a pointer) or `None` if
    /// allocation fails.
    pub fn malloc(&mut self, size: usize) -> Option<usize> {
        let size = if size == 0 { 1 } else { size };

        let bin = size_class::bin_index(size);

        if bin >= NUM_SIZE_CLASSES {
            // Large allocation path
            let alloc = self.large_allocator.alloc(size)?;
            let offset = alloc.base;
            self.active.insert(
                offset,
                AllocationRecord {
                    user_size: size,
                    bin: NUM_SIZE_CLASSES,
                },
            );
            self.total_allocated += size;
            self.active_count += 1;
            return Some(offset);
        }

        // Try thread cache first
        if let Some(offset) = self.thread_cache.alloc(bin) {
            self.active.insert(
                offset,
                AllocationRecord {
                    user_size: size,
                    bin,
                },
            );
            self.total_allocated += size;
            self.active_count += 1;
            return Some(offset);
        }

        // Try central bin freelist
        if let Some(offset) = self.central_bins[bin].pop() {
            self.active.insert(
                offset,
                AllocationRecord {
                    user_size: size,
                    bin,
                },
            );
            self.total_allocated += size;
            self.active_count += 1;
            return Some(offset);
        }

        // Allocate fresh from slab region
        let class_size = size_class::bin_size(bin);
        let offset = self.next_offset;
        self.next_offset += class_size;
        self.active.insert(
            offset,
            AllocationRecord {
                user_size: size,
                bin,
            },
        );
        self.total_allocated += size;
        self.active_count += 1;
        Some(offset)
    }

    /// Frees a previously allocated block.
    ///
    /// No-op if `ptr` is 0 (null equivalent).
    pub fn free(&mut self, ptr: usize) {
        if ptr == 0 {
            return;
        }

        let record = match self.active.remove(&ptr) {
            Some(r) => r,
            None => return, // Unknown pointer - ignore
        };

        self.total_allocated -= record.user_size;
        self.active_count -= 1;

        if record.bin >= NUM_SIZE_CLASSES {
            // Large allocation
            self.large_allocator.free(ptr);
            return;
        }

        // Try to cache in thread cache
        if !self.thread_cache.dealloc(record.bin, ptr) {
            // Magazine full - put in central bin
            self.central_bins[record.bin].push(ptr);
        }
    }

    /// Allocates memory for `count` objects of `size` bytes each, zeroed.
    ///
    /// Returns a logical offset or `None` on failure. Checks for
    /// multiplication overflow.
    pub fn calloc(&mut self, count: usize, size: usize) -> Option<usize> {
        let total = count.checked_mul(size)?;
        self.malloc(total)
        // Note: in this logical model, memory is not actually backed by real
        // bytes, so zeroing is implicit. The ABI layer handles real zeroing.
    }

    /// Resizes a previously allocated block to `new_size` bytes.
    ///
    /// If `ptr` is 0, equivalent to `malloc(new_size)`.
    /// If `new_size` is 0, equivalent to `free(ptr)`.
    pub fn realloc(&mut self, ptr: usize, new_size: usize) -> Option<usize> {
        if ptr == 0 {
            return self.malloc(new_size);
        }
        if new_size == 0 {
            self.free(ptr);
            return None;
        }

        let old_record = self.active.get(&ptr).cloned();
        let old_size = old_record.as_ref().map_or(0, |r| r.user_size);
        let old_bin = old_record.as_ref().map_or(NUM_SIZE_CLASSES, |r| r.bin);

        // If new size fits in the same size class, keep the same block
        let new_bin = size_class::bin_index(new_size);
        if new_bin == old_bin && new_bin < NUM_SIZE_CLASSES {
            // Update record in place
            if let Some(record) = self.active.get_mut(&ptr) {
                self.total_allocated -= record.user_size;
                record.user_size = new_size;
                self.total_allocated += new_size;
            }
            return Some(ptr);
        }

        // Allocate new, copy metadata, free old
        let new_ptr = self.malloc(new_size)?;

        // In the logical model, we don't copy actual bytes.
        // The ABI layer handles the real memcpy.
        let _ = old_size; // Suppress unused warning

        self.free(ptr);
        Some(new_ptr)
    }

    /// Returns the total bytes currently allocated (user-requested).
    pub fn total_allocated(&self) -> usize {
        self.total_allocated
    }

    /// Returns the total number of active allocations.
    pub fn active_count(&self) -> usize {
        self.active_count
    }

    /// Returns whether the allocator has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Looks up an allocation by offset.
    pub fn lookup(&self, ptr: usize) -> Option<usize> {
        self.active.get(&ptr).map(|r| r.user_size)
    }
}

impl Default for MallocState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::malloc::size_class::MAX_SMALL_SIZE;

    #[test]
    fn test_new_state() {
        let state = MallocState::new();
        assert!(state.is_initialized());
        assert_eq!(state.active_count(), 0);
        assert_eq!(state.total_allocated(), 0);
    }

    #[test]
    fn test_malloc_basic() {
        let mut state = MallocState::new();
        let ptr = state.malloc(100).unwrap();
        assert_ne!(ptr, 0);
        assert_eq!(state.active_count(), 1);
        assert_eq!(state.total_allocated(), 100);
    }

    #[test]
    fn test_malloc_zero() {
        let mut state = MallocState::new();
        let ptr = state.malloc(0).unwrap();
        assert_ne!(ptr, 0);
        assert_eq!(state.active_count(), 1);
    }

    #[test]
    fn test_free_basic() {
        let mut state = MallocState::new();
        let ptr = state.malloc(64).unwrap();
        state.free(ptr);
        assert_eq!(state.active_count(), 0);
        assert_eq!(state.total_allocated(), 0);
    }

    #[test]
    fn test_free_null() {
        let mut state = MallocState::new();
        state.free(0); // Should not panic
    }

    #[test]
    fn test_free_unknown() {
        let mut state = MallocState::new();
        state.free(0xDEAD); // Should not panic
    }

    #[test]
    fn test_calloc_basic() {
        let mut state = MallocState::new();
        let ptr = state.calloc(10, 8).unwrap();
        assert_ne!(ptr, 0);
        assert_eq!(state.total_allocated(), 80);
    }

    #[test]
    fn test_calloc_overflow() {
        let mut state = MallocState::new();
        assert!(state.calloc(usize::MAX, 2).is_none());
    }

    #[test]
    fn test_realloc_null() {
        let mut state = MallocState::new();
        let ptr = state.realloc(0, 100).unwrap();
        assert_ne!(ptr, 0);
        assert_eq!(state.active_count(), 1);
    }

    #[test]
    fn test_realloc_zero_size() {
        let mut state = MallocState::new();
        let ptr = state.malloc(100).unwrap();
        assert!(state.realloc(ptr, 0).is_none());
        assert_eq!(state.active_count(), 0);
    }

    #[test]
    fn test_realloc_same_class() {
        let mut state = MallocState::new();
        let ptr = state.malloc(20).unwrap();
        // 20 and 25 both fit in the 32-byte class
        let new_ptr = state.realloc(ptr, 25).unwrap();
        assert_eq!(new_ptr, ptr); // Same block reused
        assert_eq!(state.total_allocated(), 25);
    }

    #[test]
    fn test_realloc_different_class() {
        let mut state = MallocState::new();
        let ptr = state.malloc(16).unwrap();
        let new_ptr = state.realloc(ptr, 256).unwrap();
        assert_ne!(new_ptr, ptr);
        assert_eq!(state.active_count(), 1);
        assert_eq!(state.total_allocated(), 256);
    }

    #[test]
    fn test_large_allocation() {
        let mut state = MallocState::new();
        let ptr = state.malloc(MAX_SMALL_SIZE + 1).unwrap();
        assert_ne!(ptr, 0);
        assert_eq!(state.active_count(), 1);
        state.free(ptr);
        assert_eq!(state.active_count(), 0);
    }

    #[test]
    fn test_realloc_unknown_pointer_allocates_new_block() {
        let mut state = MallocState::new();
        let new_ptr = state.realloc(0xDEAD, 64).unwrap();
        assert_ne!(new_ptr, 0xDEAD);
        assert_eq!(state.active_count(), 1);
        assert_eq!(state.total_allocated(), 64);
        assert_eq!(state.lookup(0xDEAD), None);
        assert_eq!(state.lookup(new_ptr), Some(64));
    }

    #[test]
    fn test_realloc_large_to_small_moves_to_small_path() {
        let mut state = MallocState::new();
        let large_ptr = state.malloc(MAX_SMALL_SIZE + 1).unwrap();
        let small_ptr = state.realloc(large_ptr, 64).unwrap();

        assert_ne!(small_ptr, large_ptr);
        assert_eq!(state.active_count(), 1);
        assert_eq!(state.total_allocated(), 64);
        assert_eq!(state.lookup(large_ptr), None);
        assert_eq!(state.lookup(small_ptr), Some(64));
    }

    #[test]
    fn test_thread_cache_reuse() {
        let mut state = MallocState::new();

        // Allocate and free several blocks of the same size class
        let ptrs: Vec<usize> = (0..5).map(|_| state.malloc(32).unwrap()).collect();
        for &ptr in &ptrs {
            state.free(ptr);
        }

        // Re-allocate - should reuse cached blocks
        let new_ptr = state.malloc(32).unwrap();
        assert!(ptrs.contains(&new_ptr));
    }

    #[test]
    fn test_thread_cache_overflow_spills_to_central_bin_and_reuses() {
        use crate::malloc::thread_cache::MAGAZINE_CAPACITY;

        let mut state = MallocState::new();
        let bin = size_class::bin_index(32);
        let total = MAGAZINE_CAPACITY + 2;

        let ptrs: Vec<usize> = (0..total).map(|_| state.malloc(32).unwrap()).collect();
        for &ptr in &ptrs {
            state.free(ptr);
        }

        assert_eq!(
            state.thread_cache.total_cached(),
            MAGAZINE_CAPACITY,
            "thread cache should saturate to magazine capacity"
        );
        assert_eq!(
            state.central_bins[bin].len(),
            2,
            "overflow frees should spill into central bin"
        );

        let overflow_candidates: std::collections::HashSet<usize> = ptrs.iter().copied().collect();

        let drained = state.thread_cache.drain_magazine(bin);
        assert_eq!(
            drained.len(),
            MAGAZINE_CAPACITY,
            "draining should remove all cached objects from the magazine"
        );
        assert_eq!(state.thread_cache.total_cached(), 0);

        let from_central = state.malloc(32).expect("central fallback allocation");
        assert!(
            overflow_candidates.contains(&from_central),
            "allocated pointer should come from previously freed pool"
        );
        assert_eq!(
            state.central_bins[bin].len(),
            1,
            "central bin should shrink after serving one allocation"
        );
    }

    #[test]
    fn test_lookup() {
        let mut state = MallocState::new();
        let ptr = state.malloc(42).unwrap();
        assert_eq!(state.lookup(ptr), Some(42));
        assert_eq!(state.lookup(0xBEEF), None);
    }

    #[test]
    fn test_accounting_invariant_under_deterministic_trace() {
        fn lcg(state: &mut u64) -> u64 {
            *state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            *state
        }

        let mut state = MallocState::new();
        let mut live: Vec<usize> = Vec::new();
        let mut rng = 0xA5A5_5A5A_DEAD_BEEFu64;

        for _ in 0..1500 {
            let r = lcg(&mut rng);
            match r % 3 {
                0 => {
                    let size = ((r >> 8) as usize % (MAX_SMALL_SIZE * 2)).max(1);
                    if let Some(ptr) = state.malloc(size) {
                        live.push(ptr);
                    }
                }
                1 if !live.is_empty() => {
                    let idx = (r as usize) % live.len();
                    let ptr = live.swap_remove(idx);
                    state.free(ptr);
                }
                2 if !live.is_empty() => {
                    let idx = (r as usize) % live.len();
                    let ptr = live[idx];
                    let new_size = ((r >> 16) as usize) % (MAX_SMALL_SIZE * 2);
                    let next = state.realloc(ptr, new_size);
                    if new_size == 0 {
                        // realloc(ptr, 0) behaves like free(ptr)
                        live.swap_remove(idx);
                        assert!(next.is_none());
                    } else if let Some(new_ptr) = next {
                        live[idx] = new_ptr;
                    }
                }
                _ => {}
            }

            let observed_total: usize = live
                .iter()
                .map(|&ptr| {
                    state
                        .lookup(ptr)
                        .expect("all tracked pointers must stay live")
                })
                .sum();
            assert_eq!(state.active_count(), live.len());
            assert_eq!(state.total_allocated(), observed_total);
        }
    }
}
