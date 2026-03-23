//! Core allocator state.
//!
//! Central allocation state that coordinates between the thread cache,
//! size-class bins, and large-allocation paths. This is the safe Rust
//! layer managing allocation policy and metadata.

use super::size_class::{self, NUM_SIZE_CLASSES};
use super::thread_cache::ThreadCache;
use frankenlibc_membrane::runtime_math::sos_barrier::evaluate_size_class_barrier;

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
    /// Pointer involved in the event.
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
///
/// # Safety
///
/// In a production libc, this would manage raw memory regions. Here it
/// provides the high-level policy and metadata tracking used by the membrane.
pub struct MallocState {
    /// Per-bin central freelists (bin index -> stack of free pointers).
    central_bins: Vec<Vec<usize>>,
    /// Thread cache.
    thread_cache: ThreadCache,
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
    #[must_use]
    pub fn new() -> Self {
        let central_bins = (0..NUM_SIZE_CLASSES).map(|_| Vec::new()).collect();
        Self {
            central_bins,
            thread_cache: ThreadCache::new(),
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

    /// Allocates `size` bytes of memory using the given backend.
    pub fn malloc<F>(&mut self, size: usize, mut alloc_fn: F) -> Option<usize>
    where
        F: FnMut(usize) -> Option<usize>,
    {
        let size = if size == 0 { 1 } else { size };
        let bin = size_class::bin_index(size);

        if bin >= NUM_SIZE_CLASSES {
            // Large allocation path
            let out = alloc_fn(size);
            if let Some(ptr) = out {
                self.total_allocated = self.total_allocated.saturating_add(size);
                self.active_count = self.active_count.saturating_add(1);
                self.record_lifecycle(
                    AllocatorLogLevel::Trace,
                    "malloc",
                    "alloc",
                    Some(ptr),
                    Some(size),
                    Some(NUM_SIZE_CLASSES),
                    "success",
                    "path=large_allocator",
                );
            }
            return out;
        }

        let class_size = size_class::bin_size(bin);
        let class_membership_valid = class_size >= size && class_size > 0;
        let size_class_cert_value =
            evaluate_size_class_barrier(size, class_size, class_membership_valid);

        self.record_lifecycle(
            if size_class_cert_value >= 0 {
                AllocatorLogLevel::Trace
            } else {
                AllocatorLogLevel::Warn
            },
            "malloc",
            "size_class_certificate",
            None,
            Some(size),
            Some(bin),
            if size_class_cert_value >= 0 {
                "certificate_pass"
            } else {
                "certificate_violation"
            },
            format!(
                "requested_size={size};mapped_class_size={class_size};cert_value={size_class_cert_value}"
            ),
        );

        // Try thread cache first
        if let Some(ptr) = self.thread_cache.alloc(bin) {
            self.thread_cache_hits += 1;
            self.total_allocated = self.total_allocated.saturating_add(size);
            self.active_count = self.active_count.saturating_add(1);
            self.record_lifecycle(
                AllocatorLogLevel::Trace,
                "malloc",
                "alloc",
                Some(ptr),
                Some(size),
                Some(bin),
                "success",
                "path=thread_cache",
            );
            return Some(ptr);
        }

        self.thread_cache_misses += 1;

        // Try central bin
        if let Some(ptr) = self.central_bins[bin].pop() {
            self.central_bin_hits += 1;
            self.total_allocated = self.total_allocated.saturating_add(size);
            self.active_count = self.active_count.saturating_add(1);
            self.record_lifecycle(
                AllocatorLogLevel::Trace,
                "malloc",
                "alloc",
                Some(ptr),
                Some(size),
                Some(bin),
                "success",
                "path=central_bin",
            );
            return Some(ptr);
        }

        // Refill from backend
        if let Some(ptr) = alloc_fn(class_size) {
            self.total_allocated = self.total_allocated.saturating_add(size);
            self.active_count = self.active_count.saturating_add(1);
            self.record_lifecycle(
                AllocatorLogLevel::Trace,
                "malloc",
                "alloc",
                Some(ptr),
                Some(size),
                Some(bin),
                "success",
                "path=backend_refill",
            );
            return Some(ptr);
        }

        self.record_lifecycle(
            AllocatorLogLevel::Warn,
            "malloc",
            "alloc",
            None,
            Some(size),
            Some(bin),
            "oom",
            "backend_refill_failed",
        );
        None
    }

    /// Frees an allocation.
    pub fn free<F>(&mut self, ptr: usize, size: usize, mut free_fn: F)
    where
        F: FnMut(usize),
    {
        if ptr == 0 {
            return;
        }

        let bin = size_class::bin_index(size);
        if bin >= NUM_SIZE_CLASSES {
            self.total_allocated = self.total_allocated.saturating_sub(size);
            self.active_count = self.active_count.saturating_sub(1);
            free_fn(ptr);
            self.record_lifecycle(
                AllocatorLogLevel::Trace,
                "free",
                "free",
                Some(ptr),
                Some(size),
                Some(NUM_SIZE_CLASSES),
                "success",
                "path=large_allocator",
            );
            return;
        }

        self.total_allocated = self.total_allocated.saturating_sub(size);
        self.active_count = self.active_count.saturating_sub(1);

        if self.thread_cache.dealloc(bin, ptr) {
            self.record_lifecycle(
                AllocatorLogLevel::Trace,
                "free",
                "free",
                Some(ptr),
                Some(size),
                Some(bin),
                "success",
                "path=thread_cache",
            );
        } else {
            // Thread cache full, spill to central bin or backend
            self.spills_to_central += 1;
            if self.central_bins[bin].len() < 1024 {
                self.central_bins[bin].push(ptr);
                self.record_lifecycle(
                    AllocatorLogLevel::Trace,
                    "free",
                    "free",
                    Some(ptr),
                    Some(size),
                    Some(bin),
                    "success",
                    "path=central_bin_spill",
                );
            } else {
                free_fn(ptr);
                self.record_lifecycle(
                    AllocatorLogLevel::Trace,
                    "free",
                    "free",
                    Some(ptr),
                    Some(size),
                    Some(bin),
                    "success",
                    "path=backend_release",
                );
            }
        }
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
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};

    fn test_alloc_registry() -> &'static Mutex<HashMap<usize, Box<[u8]>>> {
        static REGISTRY: OnceLock<Mutex<HashMap<usize, Box<[u8]>>>> = OnceLock::new();
        REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
    }

    fn test_alloc(size: usize) -> Option<usize> {
        let alloc_size = size.max(1);
        let mut backing = vec![0u8; alloc_size].into_boxed_slice();
        let ptr = backing.as_mut_ptr() as usize;
        test_alloc_registry()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(ptr, backing);
        Some(ptr)
    }

    fn test_free(ptr: usize, _size: usize) {
        let removed = test_alloc_registry()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&ptr);
        assert!(
            removed.is_some(),
            "test_free must release a known test allocation"
        );
    }

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
        let ptr = state.malloc(100, |s| test_alloc(s)).unwrap();
        assert_ne!(ptr, 0);
        assert_eq!(state.active_count(), 1);
        assert_eq!(state.total_allocated(), 100);
        state.free(ptr, 100, |p| test_free(p, 128)); // bin_size(bin_index(100)) = 128
    }

    #[test]
    fn test_free_basic() {
        let mut state = MallocState::new();
        let size = 64;
        let ptr = state.malloc(size, |s| test_alloc(s)).unwrap();
        state.free(ptr, size, |p| test_free(p, 64));
        assert_eq!(state.active_count(), 0);
        assert_eq!(state.total_allocated(), 0);
    }

    #[test]
    fn test_thread_cache_reuse() {
        let mut state = MallocState::new();
        let size = 32;

        // Allocate and free several blocks
        let mut ptrs = Vec::new();
        for _ in 0..5 {
            ptrs.push(state.malloc(size, |s| test_alloc(s)).unwrap());
        }
        for &ptr in &ptrs {
            state.free(ptr, size, |p| test_free(p, 32));
        }

        // Re-allocate - should reuse from thread cache (no new backend calls)
        let new_ptr = state
            .malloc(size, |_| panic!("should not call backend"))
            .unwrap();
        assert!(ptrs.contains(&new_ptr));
    }
}
