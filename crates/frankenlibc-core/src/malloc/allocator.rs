//! Core allocator state.
//!
//! Central allocation state that coordinates between the thread cache,
//! size-class bins, and large-allocation paths. This is the safe Rust
//! layer managing allocation policy and metadata.

use super::large::LargeAllocator;
use super::size_class::{self, NUM_SIZE_CLASSES};
use super::thread_cache::ThreadCache;

use std::collections::{HashMap, HashSet};

/// Tracks an individual allocation made through the core allocator.
#[derive(Debug, Clone)]
struct AllocationRecord {
    /// Usable size requested by caller.
    user_size: usize,
    /// Size class index (NUM_SIZE_CLASSES for large).
    bin: usize,
}

/// Allocator lifecycle log level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocatorLogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

/// Structured allocator lifecycle record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllocatorLogRecord {
    /// Monotonic decision/event id.
    pub decision_id: u64,
    /// Correlation id for this lifecycle record.
    pub trace_id: String,
    /// Severity level.
    pub level: AllocatorLogLevel,
    /// API symbol (`malloc`, `free`, `calloc`, `realloc`).
    pub symbol: &'static str,
    /// Event kind (`alloc`, `free`, `allocator_stats`, ...).
    pub event: &'static str,
    /// Pointer offset involved in the event.
    pub ptr: Option<usize>,
    /// Size value involved in the event.
    pub size: Option<usize>,
    /// Size-class bin (`NUM_SIZE_CLASSES` for large allocations).
    pub bin: Option<usize>,
    /// Machine-readable outcome label.
    pub outcome: &'static str,
    /// Free-form details for debugging.
    pub details: String,
    /// Snapshot: currently active allocation count.
    pub active_count: usize,
    /// Snapshot: currently allocated user bytes.
    pub total_allocated: usize,
    /// Snapshot: thread-cache hit counter.
    pub thread_cache_hits: u64,
    /// Snapshot: thread-cache miss counter.
    pub thread_cache_misses: u64,
    /// Snapshot: central-bin hit counter.
    pub central_bin_hits: u64,
    /// Snapshot: spill-to-central counter.
    pub spills_to_central: u64,
    /// Snapshot: thread-cache hit rate in permille.
    pub cache_hit_rate_permille: u16,
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
    /// Recently freed pointers used to distinguish double-free from unknown free.
    recently_freed: HashSet<usize>,
    /// Monotonic lifecycle decision id.
    next_decision_id: u64,
    /// Structured allocator lifecycle records.
    lifecycle_logs: Vec<AllocatorLogRecord>,
    /// Thread-cache hit counter.
    thread_cache_hits: u64,
    /// Thread-cache miss counter.
    thread_cache_misses: u64,
    /// Central-bin hit counter.
    central_bin_hits: u64,
    /// Spill-to-central counter when magazine is full.
    spills_to_central: u64,
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
            recently_freed: HashSet::new(),
            next_decision_id: 1,
            lifecycle_logs: Vec::new(),
            thread_cache_hits: 0,
            thread_cache_misses: 0,
            central_bin_hits: 0,
            spills_to_central: 0,
            initialized: true,
            total_allocated: 0,
            active_count: 0,
        }
    }

    fn next_log_decision_id(&mut self) -> u64 {
        let id = self.next_decision_id;
        self.next_decision_id = self.next_decision_id.wrapping_add(1);
        id
    }

    fn cache_hit_rate_permille(&self) -> u16 {
        let total = self.thread_cache_hits + self.thread_cache_misses;
        if total == 0 {
            return 0;
        }
        ((self.thread_cache_hits.saturating_mul(1000)) / total) as u16
    }

    #[allow(clippy::too_many_arguments)]
    fn record_lifecycle(
        &mut self,
        level: AllocatorLogLevel,
        symbol: &'static str,
        event: &'static str,
        ptr: Option<usize>,
        size: Option<usize>,
        bin: Option<usize>,
        outcome: &'static str,
        details: impl Into<String>,
    ) {
        let decision_id = self.next_log_decision_id();
        let trace_id = format!("core::malloc::{}::{:016x}", symbol, decision_id);
        self.lifecycle_logs.push(AllocatorLogRecord {
            decision_id,
            trace_id,
            level,
            symbol,
            event,
            ptr,
            size,
            bin,
            outcome,
            details: details.into(),
            active_count: self.active_count,
            total_allocated: self.total_allocated,
            thread_cache_hits: self.thread_cache_hits,
            thread_cache_misses: self.thread_cache_misses,
            central_bin_hits: self.central_bin_hits,
            spills_to_central: self.spills_to_central,
            cache_hit_rate_permille: self.cache_hit_rate_permille(),
        });
    }

    fn record_allocator_stats(&mut self, symbol: &'static str) {
        let central_free_total: usize = self.central_bins.iter().map(Vec::len).sum();
        self.record_lifecycle(
            AllocatorLogLevel::Debug,
            symbol,
            "allocator_stats",
            None,
            None,
            None,
            "snapshot",
            format!(
                "cache_total={};central_free_total={}",
                self.thread_cache.total_cached(),
                central_free_total
            ),
        );
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
            let Some(alloc) = self.large_allocator.alloc(size) else {
                self.record_lifecycle(
                    AllocatorLogLevel::Warn,
                    "malloc",
                    "alloc",
                    None,
                    Some(size),
                    Some(NUM_SIZE_CLASSES),
                    "oom",
                    "large_allocator_alloc_failed",
                );
                self.record_allocator_stats("malloc");
                return None;
            };
            let offset = alloc.base;
            self.active.insert(
                offset,
                AllocationRecord {
                    user_size: size,
                    bin: NUM_SIZE_CLASSES,
                },
            );
            self.recently_freed.remove(&offset);
            self.total_allocated += size;
            self.active_count += 1;
            self.record_lifecycle(
                AllocatorLogLevel::Trace,
                "malloc",
                "alloc",
                Some(offset),
                Some(size),
                Some(NUM_SIZE_CLASSES),
                "success",
                "path=large_allocator",
            );
            self.record_allocator_stats("malloc");
            return Some(offset);
        }

        // Try thread cache first
        if let Some(offset) = self.thread_cache.alloc(bin) {
            self.thread_cache_hits += 1;
            self.active.insert(
                offset,
                AllocationRecord {
                    user_size: size,
                    bin,
                },
            );
            self.recently_freed.remove(&offset);
            self.total_allocated += size;
            self.active_count += 1;
            self.record_lifecycle(
                AllocatorLogLevel::Trace,
                "malloc",
                "alloc",
                Some(offset),
                Some(size),
                Some(bin),
                "success",
                "path=thread_cache_hit",
            );
            self.record_allocator_stats("malloc");
            return Some(offset);
        }
        self.thread_cache_misses += 1;

        // Try central bin freelist
        if let Some(offset) = self.central_bins[bin].pop() {
            self.central_bin_hits += 1;
            self.active.insert(
                offset,
                AllocationRecord {
                    user_size: size,
                    bin,
                },
            );
            self.recently_freed.remove(&offset);
            self.total_allocated += size;
            self.active_count += 1;
            self.record_lifecycle(
                AllocatorLogLevel::Trace,
                "malloc",
                "alloc",
                Some(offset),
                Some(size),
                Some(bin),
                "success",
                "path=central_bin_hit",
            );
            self.record_allocator_stats("malloc");
            return Some(offset);
        }

        // Allocate fresh from slab region
        let class_size = size_class::bin_size(bin);
        let offset = self.next_offset;
        let Some(next_offset) = self.next_offset.checked_add(class_size) else {
            self.record_lifecycle(
                AllocatorLogLevel::Info,
                "malloc",
                "generation_overflow",
                None,
                Some(class_size),
                Some(bin),
                "denied",
                format!("next_offset={} class_size={}", self.next_offset, class_size),
            );
            self.record_allocator_stats("malloc");
            return None;
        };
        self.next_offset = next_offset;
        self.active.insert(
            offset,
            AllocationRecord {
                user_size: size,
                bin,
            },
        );
        self.total_allocated += size;
        self.active_count += 1;
        self.record_lifecycle(
            AllocatorLogLevel::Trace,
            "malloc",
            "alloc",
            Some(offset),
            Some(size),
            Some(bin),
            "success",
            format!("path=fresh_slab class_size={}", class_size),
        );
        self.record_allocator_stats("malloc");
        Some(offset)
    }

    /// Frees a previously allocated block.
    ///
    /// No-op if `ptr` is 0 (null equivalent).
    pub fn free(&mut self, ptr: usize) {
        if ptr == 0 {
            self.record_lifecycle(
                AllocatorLogLevel::Trace,
                "free",
                "free_null",
                Some(ptr),
                None,
                None,
                "noop",
                "null_pointer",
            );
            return;
        }

        let record = match self.active.remove(&ptr) {
            Some(r) => r,
            None => {
                if self.recently_freed.contains(&ptr) {
                    self.record_lifecycle(
                        AllocatorLogLevel::Warn,
                        "free",
                        "double_free_detected",
                        Some(ptr),
                        None,
                        None,
                        "ignored",
                        "pointer_observed_in_recently_freed_set",
                    );
                } else {
                    self.record_lifecycle(
                        AllocatorLogLevel::Warn,
                        "free",
                        "unknown_free_pointer",
                        Some(ptr),
                        None,
                        None,
                        "ignored",
                        "pointer_not_present_in_active_map",
                    );
                }
                self.record_allocator_stats("free");
                return; // Unknown pointer - ignore
            }
        };

        match self.total_allocated.checked_sub(record.user_size) {
            Some(next) => {
                self.total_allocated = next;
            }
            None => {
                self.total_allocated = 0;
                self.record_lifecycle(
                    AllocatorLogLevel::Error,
                    "free",
                    "invariant_total_allocated_underflow",
                    Some(ptr),
                    Some(record.user_size),
                    Some(record.bin),
                    "recovered",
                    "checked_sub_failed",
                );
            }
        }
        match self.active_count.checked_sub(1) {
            Some(next) => {
                self.active_count = next;
            }
            None => {
                self.active_count = 0;
                self.record_lifecycle(
                    AllocatorLogLevel::Error,
                    "free",
                    "invariant_active_count_underflow",
                    Some(ptr),
                    Some(record.user_size),
                    Some(record.bin),
                    "recovered",
                    "checked_sub_failed",
                );
            }
        }

        if record.bin >= NUM_SIZE_CLASSES {
            // Large allocation
            self.large_allocator.free(ptr);
            self.recently_freed.insert(ptr);
            self.record_lifecycle(
                AllocatorLogLevel::Trace,
                "free",
                "free",
                Some(ptr),
                Some(record.user_size),
                Some(NUM_SIZE_CLASSES),
                "success",
                "path=large_allocator",
            );
            self.record_allocator_stats("free");
            return;
        }

        // Try to cache in thread cache
        if !self.thread_cache.dealloc(record.bin, ptr) {
            // Magazine full - put in central bin
            self.central_bins[record.bin].push(ptr);
            self.spills_to_central += 1;
            self.record_lifecycle(
                AllocatorLogLevel::Info,
                "free",
                "cache_spill_to_central",
                Some(ptr),
                Some(record.user_size),
                Some(record.bin),
                "spilled",
                format!("central_bin_len={}", self.central_bins[record.bin].len()),
            );
        } else {
            self.record_lifecycle(
                AllocatorLogLevel::Trace,
                "free",
                "free",
                Some(ptr),
                Some(record.user_size),
                Some(record.bin),
                "success",
                "path=thread_cache_store",
            );
        }
        self.recently_freed.insert(ptr);
        self.record_allocator_stats("free");
    }

    /// Allocates memory for `count` objects of `size` bytes each, zeroed.
    ///
    /// Returns a logical offset or `None` on failure. Checks for
    /// multiplication overflow.
    pub fn calloc(&mut self, count: usize, size: usize) -> Option<usize> {
        let Some(total) = count.checked_mul(size) else {
            self.record_lifecycle(
                AllocatorLogLevel::Warn,
                "calloc",
                "calloc_overflow",
                None,
                None,
                None,
                "denied",
                format!("count={} size={}", count, size),
            );
            self.record_allocator_stats("calloc");
            return None;
        };

        let out = self.malloc(total);
        self.record_lifecycle(
            AllocatorLogLevel::Trace,
            "calloc",
            "calloc_result",
            out,
            Some(total),
            Some(size_class::bin_index(total)),
            if out.is_some() { "success" } else { "oom" },
            format!("count={} elem_size={}", count, size),
        );
        self.record_allocator_stats("calloc");
        out
        // Note: in this logical model, memory is not actually backed by real
        // bytes, so zeroing is implicit. The ABI layer handles real zeroing.
    }

    /// Resizes a previously allocated block to `new_size` bytes.
    ///
    /// If `ptr` is 0, equivalent to `malloc(new_size)`.
    /// If `new_size` is 0, equivalent to `free(ptr)`.
    pub fn realloc(&mut self, ptr: usize, new_size: usize) -> Option<usize> {
        if ptr == 0 {
            let out = self.malloc(new_size);
            self.record_lifecycle(
                AllocatorLogLevel::Trace,
                "realloc",
                "realloc_null_as_malloc",
                out,
                Some(new_size),
                Some(size_class::bin_index(new_size.max(1))),
                if out.is_some() { "success" } else { "oom" },
                "ptr_was_null",
            );
            self.record_allocator_stats("realloc");
            return out;
        }
        if new_size == 0 {
            self.free(ptr);
            self.record_lifecycle(
                AllocatorLogLevel::Trace,
                "realloc",
                "realloc_zero_as_free",
                Some(ptr),
                Some(new_size),
                None,
                "freed",
                "new_size_was_zero",
            );
            self.record_allocator_stats("realloc");
            return None;
        }

        let old_record = self.active.get(&ptr).cloned();
        let old_size = old_record.as_ref().map_or(0, |r| r.user_size);
        let old_bin = old_record.as_ref().map_or(NUM_SIZE_CLASSES, |r| r.bin);
        if old_record.is_none() {
            self.record_lifecycle(
                AllocatorLogLevel::Warn,
                "realloc",
                "realloc_unknown_pointer",
                Some(ptr),
                Some(new_size),
                Some(size_class::bin_index(new_size)),
                "fallback_alloc",
                "source_pointer_not_active",
            );
        }

        // If new size fits in the same size class, keep the same block
        let new_bin = size_class::bin_index(new_size);
        if new_bin == old_bin && new_bin < NUM_SIZE_CLASSES {
            // Update record in place
            if let Some(record) = self.active.get_mut(&ptr) {
                self.total_allocated = self.total_allocated.saturating_sub(record.user_size);
                record.user_size = new_size;
                self.total_allocated += new_size;
            }
            self.record_lifecycle(
                AllocatorLogLevel::Trace,
                "realloc",
                "realloc_in_place",
                Some(ptr),
                Some(new_size),
                Some(new_bin),
                "success",
                format!("old_size={} old_bin={}", old_size, old_bin),
            );
            self.record_allocator_stats("realloc");
            return Some(ptr);
        }

        // Allocate new, copy metadata, free old
        let Some(new_ptr) = self.malloc(new_size) else {
            self.record_lifecycle(
                AllocatorLogLevel::Warn,
                "realloc",
                "realloc_allocate_new_failed",
                Some(ptr),
                Some(new_size),
                Some(new_bin),
                "oom",
                format!("old_size={} old_bin={}", old_size, old_bin),
            );
            self.record_allocator_stats("realloc");
            return None;
        };

        // In the logical model, we don't copy actual bytes.
        // The ABI layer handles the real memcpy.
        let _ = old_size; // Suppress unused warning

        self.free(ptr);
        self.record_lifecycle(
            AllocatorLogLevel::Trace,
            "realloc",
            "realloc_move",
            Some(new_ptr),
            Some(new_size),
            Some(new_bin),
            "success",
            format!("old_ptr={} old_size={} old_bin={}", ptr, old_size, old_bin),
        );
        self.record_allocator_stats("realloc");
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

    /// Returns a view of allocator lifecycle log records.
    pub fn lifecycle_logs(&self) -> &[AllocatorLogRecord] {
        &self.lifecycle_logs
    }

    /// Drains allocator lifecycle log records.
    pub fn drain_lifecycle_logs(&mut self) -> Vec<AllocatorLogRecord> {
        std::mem::take(&mut self.lifecycle_logs)
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
    fn test_lifecycle_logs_include_trace_and_decision_ids() {
        let mut state = MallocState::new();
        let ptr = state.malloc(64).unwrap();
        state.free(ptr);

        let logs = state.drain_lifecycle_logs();
        assert!(!logs.is_empty());
        assert!(logs.iter().all(|entry| entry.decision_id > 0));
        assert!(
            logs.iter()
                .all(|entry| entry.trace_id.starts_with("core::malloc::"))
        );
        assert!(
            logs.iter()
                .any(|entry| entry.level == AllocatorLogLevel::Trace && entry.symbol == "malloc")
        );
        assert!(logs.iter().any(
            |entry| entry.level == AllocatorLogLevel::Debug && entry.event == "allocator_stats"
        ));
    }

    #[test]
    fn test_lifecycle_logs_warn_on_double_free_and_unknown_realloc() {
        let mut state = MallocState::new();
        let ptr = state.malloc(16).unwrap();
        state.free(ptr);
        state.free(ptr); // Double free
        let _ = state.realloc(0xDEAD, 32); // Unknown source pointer

        let logs = state.drain_lifecycle_logs();
        assert!(
            logs.iter().any(|entry| {
                entry.level == AllocatorLogLevel::Warn && entry.event == "double_free_detected"
            }),
            "expected WARN double_free_detected entry"
        );
        assert!(
            logs.iter().any(|entry| {
                entry.level == AllocatorLogLevel::Warn && entry.event == "realloc_unknown_pointer"
            }),
            "expected WARN realloc_unknown_pointer entry"
        );
    }

    #[test]
    fn test_lifecycle_logs_info_for_spill_and_generation_overflow() {
        use crate::malloc::thread_cache::MAGAZINE_CAPACITY;

        let mut state = MallocState::new();
        let ptrs: Vec<usize> = (0..(MAGAZINE_CAPACITY + 1))
            .map(|_| state.malloc(32).unwrap())
            .collect();
        for ptr in ptrs {
            state.free(ptr);
        }
        let logs = state.drain_lifecycle_logs();
        assert!(
            logs.iter().any(|entry| {
                entry.level == AllocatorLogLevel::Info && entry.event == "cache_spill_to_central"
            }),
            "expected INFO cache_spill_to_central entry"
        );

        // Force generation overflow on a fresh state to avoid cache/central reuse.
        let mut overflow_state = MallocState::new();
        overflow_state.next_offset = usize::MAX;
        assert!(overflow_state.malloc(32).is_none());
        let overflow_logs = overflow_state.drain_lifecycle_logs();
        assert!(
            overflow_logs.iter().any(|entry| {
                entry.level == AllocatorLogLevel::Info && entry.event == "generation_overflow"
            }),
            "expected INFO generation_overflow entry"
        );
    }

    #[test]
    fn test_lifecycle_logs_error_on_invariant_violation_recovery() {
        let mut state = MallocState::new();
        let ptr = state.malloc(128).unwrap();

        // Inject impossible accounting state and verify ERROR logging recovery.
        state.total_allocated = 0;
        state.active_count = 0;
        state.free(ptr);

        let logs = state.drain_lifecycle_logs();
        assert!(
            logs.iter().any(|entry| {
                entry.level == AllocatorLogLevel::Error
                    && entry.event == "invariant_total_allocated_underflow"
            }),
            "expected ERROR invariant_total_allocated_underflow entry"
        );
        assert!(
            logs.iter().any(|entry| {
                entry.level == AllocatorLogLevel::Error
                    && entry.event == "invariant_active_count_underflow"
            }),
            "expected ERROR invariant_active_count_underflow entry"
        );
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
