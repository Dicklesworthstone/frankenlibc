//! Core allocator state.
//!
//! Central allocation state that coordinates between the thread cache,
//! size-class bins, and large-allocation paths. This is the safe Rust
//! layer managing allocation policy and metadata.

use super::elimination::{DEFAULT_ELIMINATION_SLOTS, EliminationArray, OfferOutcome, TakeOutcome};
use super::large::{LargeAllocation, LargeAllocator};
use super::size_class::{self, NUM_SIZE_CLASSES, SizeClassIndex};
use super::thread_cache::ThreadCache;
use frankenlibc_membrane::runtime_math::sos_barrier::evaluate_size_class_barrier;
use std::borrow::Cow;
use std::fmt;
use std::sync::Arc;

const TRACE_ID_PREFIX: &str = "core::malloc::";
const TRACE_ID_SEPARATOR: &str = "::";
const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";
const HOT_CERT_64_REQUEST_SIZE: usize = 64;
const HOT_CERT_64_CLASS_SIZE: usize = 64;
const HOT_CERT_64_VALUE: i64 = 150_000;
const HOT_CERT_64_DETAILS: &str = "requested_size=64;mapped_class_size=64;cert_value=150000";
const SIZE_CLASS_CERT_MAX_REQUEST: usize = 64 * 1024;
const SIZE_CLASS_CERT_MAX_WASTE_RATIO_PPM: u64 = 900_000;

/// Allocator lifecycle log level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocatorLogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

/// Symbolic allocator trace id.
///
/// Lifecycle rows use the legacy `core::malloc::{symbol}::{decision_id:016x}`
/// text when observed, but the hot allocator path stores only the components.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct AllocatorTraceId {
    symbol: &'static str,
    decision_id: u64,
}

impl AllocatorTraceId {
    fn new(symbol: &'static str, decision_id: u64) -> Self {
        Self {
            symbol,
            decision_id,
        }
    }

    fn eq_legacy_str(self, other: &str) -> bool {
        let Some(rest) = other.strip_prefix(TRACE_ID_PREFIX) else {
            return false;
        };
        let Some(rest) = rest.strip_prefix(self.symbol) else {
            return false;
        };
        let Some(hex) = rest.strip_prefix(TRACE_ID_SEPARATOR) else {
            return false;
        };
        let bytes = hex.as_bytes();
        if bytes.len() != 16 {
            return false;
        }
        for (idx, shift) in (0..16).rev().map(|n| n * 4).enumerate() {
            let digit = ((self.decision_id >> shift) & 0x0f) as usize;
            if bytes[idx] != LOWER_HEX[digit] {
                return false;
            }
        }
        true
    }
}

impl fmt::Debug for AllocatorTraceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("\"")?;
        fmt::Display::fmt(self, f)?;
        f.write_str("\"")
    }
}

impl fmt::Display for AllocatorTraceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(TRACE_ID_PREFIX)?;
        f.write_str(self.symbol)?;
        f.write_str(TRACE_ID_SEPARATOR)?;
        write_fixed_lower_hex_u64(f, self.decision_id)
    }
}

impl PartialEq<String> for AllocatorTraceId {
    fn eq(&self, other: &String) -> bool {
        self.eq_legacy_str(other.as_str())
    }
}

impl PartialEq<&str> for AllocatorTraceId {
    fn eq(&self, other: &&str) -> bool {
        self.eq_legacy_str(other)
    }
}

/// Structured allocator lifecycle record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllocatorLogRecord {
    /// Monotonic decision/event id.
    pub decision_id: u64,
    /// Correlation id for this lifecycle record.
    pub trace_id: AllocatorTraceId,
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
    pub details: Cow<'static, str>,
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
    /// Direct handoff array for complementary `free`/`malloc` traffic.
    elimination: Arc<EliminationArray<usize, DEFAULT_ELIMINATION_SLOTS>>,
    /// One-object front slot per size class before the general thread-cache
    /// magazine. This preserves LIFO order while avoiding Vec traffic for
    /// one-live-object malloc/free cycles.
    thread_cache_hot_slots: [Option<usize>; NUM_SIZE_CLASSES],
    /// Thread cache.
    thread_cache: ThreadCache,
    /// Active large-allocation metadata keyed by backend pointer.
    large_allocations: LargeAllocator,
    /// Single active large allocation fast slot for the common one-live-large-object cycle.
    large_fast_active: Option<LargeAllocation>,
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
    /// Minimum severity recorded into `lifecycle_logs`. Events below this level
    /// are dropped before any record is built, keeping the alloc/free hot path
    /// free of per-operation log work. Defaults to `Warn` so errors/OOM are
    /// still captured while the high-frequency `Trace` events are skipped;
    /// raise verbosity with [`MallocState::set_min_log_level`].
    min_log_level: AllocatorLogLevel,
}

impl MallocState {
    /// Creates a new initialized allocator state.
    #[must_use]
    pub fn new() -> Self {
        let central_bins = (0..NUM_SIZE_CLASSES).map(|_| Vec::new()).collect();
        Self {
            central_bins,
            elimination: Arc::new(EliminationArray::new()),
            thread_cache_hot_slots: [None; NUM_SIZE_CLASSES],
            thread_cache: ThreadCache::new(),
            large_allocations: LargeAllocator::new(),
            large_fast_active: None,
            next_decision_id: 1,
            lifecycle_logs: Vec::new(),
            thread_cache_hits: 0,
            thread_cache_misses: 0,
            central_bin_hits: 0,
            spills_to_central: 0,
            initialized: true,
            total_allocated: 0,
            active_count: 0,
            min_log_level: AllocatorLogLevel::Warn,
        }
    }

    /// Sets the minimum lifecycle-log severity. Pass
    /// [`AllocatorLogLevel::Trace`] to capture the full per-operation trace
    /// (diagnostics / tests); the default of `Warn` keeps the hot path lean.
    pub fn set_min_log_level(&mut self, level: AllocatorLogLevel) {
        self.min_log_level = level;
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
        details: impl Into<Cow<'static, str>>,
    ) {
        // Drop sub-threshold events before building/pushing any record — this is
        // what keeps the malloc/free hot path (all `Trace`) free of per-op log
        // work at the default `Warn` level. Fieldless enum, declaration order
        // Trace(0)<Debug<Info<Warn<Error(4).
        if (level as u8) < (self.min_log_level as u8) {
            return;
        }
        let decision_id = self.next_log_decision_id();
        let trace_id = lifecycle_trace_id(symbol, decision_id);
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

    fn central_bin(&self, index: SizeClassIndex) -> &Vec<usize> {
        &self.central_bins[index.get()]
    }

    fn central_bin_mut(&mut self, index: SizeClassIndex) -> &mut Vec<usize> {
        &mut self.central_bins[index.get()]
    }

    fn can_track_allocation(&self, size: usize) -> bool {
        self.total_allocated.checked_add(size).is_some()
            && self.active_count.checked_add(1).is_some()
    }

    fn track_allocation(&mut self, size: usize) {
        self.total_allocated += size;
        self.active_count += 1;
    }

    /// Allocates `size` bytes of memory using the given backend.
    pub fn malloc<F>(&mut self, size: usize, mut alloc_fn: F) -> Option<usize>
    where
        F: FnMut(usize) -> Option<usize>,
    {
        let size = if size == 0 { 1 } else { size };
        if !self.can_track_allocation(size) {
            self.record_lifecycle(
                AllocatorLogLevel::Warn,
                "malloc",
                "alloc",
                None,
                Some(size),
                None,
                "accounting_overflow",
                "allocation_counters_would_overflow",
            );
            return None;
        }

        let Some(bin) = size_class::small_bin_index(size) else {
            // Large allocation path
            let Some(mapped_size) = LargeAllocator::mapped_size_for(size) else {
                self.record_lifecycle(
                    AllocatorLogLevel::Warn,
                    "malloc",
                    "alloc",
                    None,
                    Some(size),
                    Some(NUM_SIZE_CLASSES),
                    "oom",
                    "large_allocator_mapped_size_overflow",
                );
                return None;
            };

            if self.large_fast_active.is_none() {
                let out = alloc_fn(size);
                if let Some(ptr) = out {
                    if ptr == 0 {
                        self.record_lifecycle(
                            AllocatorLogLevel::Warn,
                            "malloc",
                            "alloc",
                            Some(ptr),
                            Some(size),
                            Some(NUM_SIZE_CLASSES),
                            "metadata_error",
                            "path=large_allocator;metadata_register_failed",
                        );
                        return None;
                    }

                    let large_alloc = LargeAllocation {
                        base: ptr,
                        mapped_size,
                        user_size: size,
                    };
                    self.large_fast_active = Some(large_alloc);
                    self.track_allocation(size);
                    if (AllocatorLogLevel::Trace as u8) >= (self.min_log_level as u8) {
                        self.record_lifecycle(
                            AllocatorLogLevel::Trace,
                            "malloc",
                            "alloc",
                            Some(ptr),
                            Some(size),
                            Some(NUM_SIZE_CLASSES),
                            "success",
                            format!("path=large_allocator;mapped_size={mapped_size}"),
                        );
                    }
                }
                return out;
            }

            let out = alloc_fn(size);
            if let Some(ptr) = out {
                let fast_slot_duplicate = self
                    .large_fast_active
                    .as_ref()
                    .is_some_and(|alloc| alloc.base == ptr);
                if !fast_slot_duplicate
                    && let Some(large_alloc) = self.large_allocations.register(ptr, size)
                {
                    self.track_allocation(size);
                    // Only build the per-alloc detail string when the Trace row
                    // would actually be kept (default Warn drops it) — avoids a
                    // heap `format!` inside every large allocation. Identical logs.
                    if (AllocatorLogLevel::Trace as u8) >= (self.min_log_level as u8) {
                        self.record_lifecycle(
                            AllocatorLogLevel::Trace,
                            "malloc",
                            "alloc",
                            Some(ptr),
                            Some(size),
                            Some(NUM_SIZE_CLASSES),
                            "success",
                            format!(
                                "path=large_allocator;mapped_size={}",
                                large_alloc.mapped_size
                            ),
                        );
                    }
                } else {
                    self.record_lifecycle(
                        AllocatorLogLevel::Warn,
                        "malloc",
                        "alloc",
                        Some(ptr),
                        Some(size),
                        Some(NUM_SIZE_CLASSES),
                        "metadata_error",
                        "path=large_allocator;metadata_register_failed",
                    );
                    return None;
                }
            }
            return out;
        };

        let bin_usize = bin.get();
        let class_size = size_class::size_for_index(bin);
        let class_membership_valid = class_size >= size && class_size > 0;
        // The size-class certificate is diagnostic only (the allocation proceeds
        // regardless of the value). Under the default Warn log level, successful
        // certificate rows are dropped; avoid evaluating the SOS polynomial on
        // that hot path. Trace mode still records the byte-identical certificate,
        // and cheap violation prechecks preserve Warn rows for bad mappings.
        let trace_certificate_enabled =
            (AllocatorLogLevel::Trace as u8) >= (self.min_log_level as u8);
        if trace_certificate_enabled
            || size_class_certificate_may_violate(size, class_size, class_membership_valid)
        {
            let size_class_cert_value =
                size_class_certificate_value(size, class_size, class_membership_valid);
            let cert_level = if size_class_cert_value >= 0 {
                AllocatorLogLevel::Trace
            } else {
                AllocatorLogLevel::Warn
            };
            if (cert_level as u8) >= (self.min_log_level as u8) {
                self.record_lifecycle(
                    cert_level,
                    "malloc",
                    "size_class_certificate",
                    None,
                    Some(size),
                    Some(bin_usize),
                    if size_class_cert_value >= 0 {
                        "certificate_pass"
                    } else {
                        "certificate_violation"
                    },
                    size_class_certificate_details(size, class_size, size_class_cert_value),
                );
            }
        }

        // Try thread cache first
        if let Some(ptr) = self.thread_cache_hot_slots[bin_usize].take() {
            self.thread_cache_hits += 1;
            self.track_allocation(size);
            self.record_lifecycle(
                AllocatorLogLevel::Trace,
                "malloc",
                "alloc",
                Some(ptr),
                Some(size),
                Some(bin_usize),
                "success",
                "path=thread_cache",
            );
            return Some(ptr);
        }
        if let Some(ptr) = self.thread_cache.alloc_index(bin) {
            self.thread_cache_hits += 1;
            self.track_allocation(size);
            self.record_lifecycle(
                AllocatorLogLevel::Trace,
                "malloc",
                "alloc",
                Some(ptr),
                Some(size),
                Some(bin_usize),
                "success",
                "path=thread_cache",
            );
            return Some(ptr);
        }

        self.thread_cache_misses += 1;

        match self.elimination.try_take(bin_usize) {
            TakeOutcome::Matched { value: ptr, meta } => {
                self.track_allocation(size);
                // Build the detail string only when the Trace row would be kept;
                // avoids a heap `format!` on every elimination-matched alloc
                // (the common path under multi-threaded malloc/free traffic).
                if (AllocatorLogLevel::Trace as u8) >= (self.min_log_level as u8) {
                    self.record_lifecycle(
                        AllocatorLogLevel::Trace,
                        "malloc",
                        "alloc",
                        Some(ptr),
                        Some(size),
                        Some(bin_usize),
                        "success",
                        format!(
                            "path=elimination;slot={};wait_cycles={};partner_thread={}",
                            meta.slot_index.unwrap_or(usize::MAX),
                            meta.wait_cycles,
                            meta.partner_thread.unwrap_or(0)
                        ),
                    );
                }
                return Some(ptr);
            }
            TakeOutcome::Fallback { .. } => {}
        }

        // Try central bin
        if let Some(ptr) = self.central_bin_mut(bin).pop() {
            self.central_bin_hits += 1;
            self.track_allocation(size);
            self.record_lifecycle(
                AllocatorLogLevel::Trace,
                "malloc",
                "alloc",
                Some(ptr),
                Some(size),
                Some(bin_usize),
                "success",
                "path=central_bin",
            );
            return Some(ptr);
        }

        // Refill from backend
        if let Some(ptr) = alloc_fn(class_size) {
            self.track_allocation(size);
            self.record_lifecycle(
                AllocatorLogLevel::Trace,
                "malloc",
                "alloc",
                Some(ptr),
                Some(size),
                Some(bin_usize),
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
            Some(bin_usize),
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
        let size = if size == 0 { 1 } else { size };
        let mut ptr = ptr;

        let Some(bin) = size_class::small_bin_index(size) else {
            let removed = if self
                .large_fast_active
                .as_ref()
                .is_some_and(|alloc| alloc.base == ptr)
            {
                let _ = self
                    .large_fast_active
                    .take()
                    .expect("fast active slot existed");
                true
            } else {
                self.large_allocations.free(ptr)
            };
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
                if removed {
                    "path=large_allocator;metadata_removed"
                } else {
                    "path=large_allocator;metadata_missing"
                },
            );
            return;
        };
        let bin_usize = bin.get();

        self.total_allocated = self.total_allocated.saturating_sub(size);
        self.active_count = self.active_count.saturating_sub(1);

        // A single-owned elimination array cannot have a waiting consumer; once
        // another handle exists, preserve the existing elimination-first order.
        if Arc::strong_count(&self.elimination) > 1 {
            match self.elimination.try_offer(bin_usize, ptr) {
                OfferOutcome::Matched(meta) => {
                    // Detail string only when the Trace row survives the gate —
                    // skips a heap `format!` on every elimination-matched free.
                    if (AllocatorLogLevel::Trace as u8) >= (self.min_log_level as u8) {
                        self.record_lifecycle(
                            AllocatorLogLevel::Trace,
                            "free",
                            "free",
                            Some(ptr),
                            Some(size),
                            Some(bin_usize),
                            "success",
                            format!(
                                "path=elimination;slot={};wait_cycles={};partner_thread={}",
                                meta.slot_index.unwrap_or(usize::MAX),
                                meta.wait_cycles,
                                meta.partner_thread.unwrap_or(0)
                            ),
                        );
                    }
                    return;
                }
                OfferOutcome::Fallback { value, .. } => {
                    ptr = value;
                }
            }
        }

        let cached = self.cache_small_object(bin, ptr);

        if cached {
            self.record_lifecycle(
                AllocatorLogLevel::Trace,
                "free",
                "free",
                Some(ptr),
                Some(size),
                Some(bin_usize),
                "success",
                "path=thread_cache",
            );
        } else {
            // Thread cache full, spill to central bin or backend
            self.spills_to_central += 1;
            if self.central_bin(bin).len() < 1024 {
                self.central_bin_mut(bin).push(ptr);
                self.record_lifecycle(
                    AllocatorLogLevel::Trace,
                    "free",
                    "free",
                    Some(ptr),
                    Some(size),
                    Some(bin_usize),
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
                    Some(bin_usize),
                    "success",
                    "path=backend_release",
                );
            }
        }
    }

    fn cache_small_object(&mut self, bin: SizeClassIndex, ptr: usize) -> bool {
        let bin_usize = bin.get();
        match self.thread_cache_hot_slots[bin_usize] {
            None => {
                self.thread_cache_hot_slots[bin_usize] = Some(ptr);
                true
            }
            Some(displaced) => {
                if self.thread_cache.can_accept_hot_slot_displacement(bin) {
                    let cached = self.thread_cache.dealloc_index(bin, displaced);
                    debug_assert!(cached);
                    self.thread_cache_hot_slots[bin_usize] = Some(ptr);
                    true
                } else {
                    false
                }
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

    /// Returns the total number of active large allocations.
    pub fn active_large_count(&self) -> usize {
        self.large_allocations.active_count() + usize::from(self.large_fast_active.is_some())
    }

    /// Returns total mapped bytes tracked for active large allocations.
    pub fn total_large_mapped(&self) -> usize {
        self.large_allocations.total_mapped()
            + self
                .large_fast_active
                .as_ref()
                .map_or(0, |alloc| alloc.mapped_size)
    }

    /// Looks up active large-allocation metadata by backend pointer.
    pub fn large_allocation(&self, ptr: usize) -> Option<&LargeAllocation> {
        if let Some(alloc) = &self.large_fast_active
            && alloc.base == ptr
        {
            return Some(alloc);
        }
        self.large_allocations.lookup(ptr)
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
        self.lifecycle_logs.drain(..).collect()
    }

    #[cfg(test)]
    pub(crate) fn elimination_handle(
        &self,
    ) -> Arc<EliminationArray<usize, DEFAULT_ELIMINATION_SLOTS>> {
        Arc::clone(&self.elimination)
    }
}

fn lifecycle_trace_id(symbol: &'static str, decision_id: u64) -> AllocatorTraceId {
    AllocatorTraceId::new(symbol, decision_id)
}

fn size_class_certificate_details(
    size: usize,
    class_size: usize,
    cert_value: i64,
) -> Cow<'static, str> {
    if size == HOT_CERT_64_REQUEST_SIZE
        && class_size == HOT_CERT_64_CLASS_SIZE
        && cert_value == HOT_CERT_64_VALUE
    {
        Cow::Borrowed(HOT_CERT_64_DETAILS)
    } else {
        Cow::Owned(format!(
            "requested_size={size};mapped_class_size={class_size};cert_value={cert_value}"
        ))
    }
}

#[inline]
fn size_class_certificate_value(
    size: usize,
    class_size: usize,
    class_membership_valid: bool,
) -> i64 {
    if size == HOT_CERT_64_REQUEST_SIZE
        && class_size == HOT_CERT_64_CLASS_SIZE
        && class_membership_valid
    {
        HOT_CERT_64_VALUE
    } else {
        evaluate_size_class_barrier(size, class_size, class_membership_valid)
    }
}

#[inline]
fn size_class_certificate_may_violate(
    size: usize,
    class_size: usize,
    class_membership_valid: bool,
) -> bool {
    if !class_membership_valid || class_size == 0 || class_size > SIZE_CLASS_CERT_MAX_REQUEST {
        return true;
    }
    let normalized_size = size.clamp(size_class::MIN_SIZE, SIZE_CLASS_CERT_MAX_REQUEST);
    if class_size < normalized_size {
        return true;
    }
    let waste = (class_size - normalized_size) as u64;
    if waste == 0 {
        return false;
    }
    waste.saturating_mul(1_000_000) / (normalized_size as u64) > SIZE_CLASS_CERT_MAX_WASTE_RATIO_PPM
}

fn write_fixed_lower_hex_u64(out: &mut impl fmt::Write, value: u64) -> fmt::Result {
    for shift in (0..16).rev().map(|n| n * 4) {
        let digit = ((value >> shift) & 0x0f) as usize;
        out.write_char(char::from(LOWER_HEX[digit]))?;
    }
    Ok(())
}

impl Default for MallocState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;
    use std::fmt::Write as _;
    use std::sync::{Barrier, Mutex, OnceLock};
    use std::thread;
    use std::time::Duration;

    fn hex_lower(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for &byte in bytes {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
        out
    }

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
        let ptr = state.malloc(100, test_alloc).unwrap();
        assert_ne!(ptr, 0);
        assert_eq!(state.active_count(), 1);
        assert_eq!(state.total_allocated(), 100);
        state.free(ptr, 100, |p| test_free(p, 128)); // bin_size(bin_index(100)) = 128
    }

    #[test]
    fn test_free_basic() {
        let mut state = MallocState::new();
        let size = 64;
        let ptr = state.malloc(size, test_alloc).unwrap();
        state.free(ptr, size, |p| test_free(p, 64));
        assert_eq!(state.active_count(), 0);
        assert_eq!(state.total_allocated(), 0);
    }

    #[test]
    fn lifecycle_trace_id_matches_legacy_format() {
        let cases = [
            ("malloc", 0),
            ("free", 1),
            ("size_class_certificate", 0x1234_abcd),
            ("realloc", u64::MAX),
        ];
        let mut canonical = String::new();

        for (symbol, decision_id) in cases {
            let trace_id = lifecycle_trace_id(symbol, decision_id);
            let rendered_trace_id = trace_id.to_string();
            assert_eq!(
                rendered_trace_id,
                format!("core::malloc::{symbol}::{decision_id:016x}")
            );
            canonical.push_str(&rendered_trace_id);
            canonical.push('\n');
        }

        let digest = Sha256::digest(canonical.as_bytes());
        assert_eq!(
            hex_lower(&digest),
            "02366cecb133cea5d2253b23cf59720027771ef3bf9e56219364c9df719d36d4"
        );
    }

    #[test]
    fn drain_lifecycle_logs_preserves_records_and_retains_buffer() {
        let mut state = MallocState::new();
        state.set_min_log_level(AllocatorLogLevel::Trace);
        let size = 64;
        let mut next_ptr = 0x2000_0000usize;

        for _ in 0..700 {
            let ptr = state
                .malloc(size, |class_size| {
                    next_ptr = next_ptr.wrapping_add(class_size.max(1));
                    Some(next_ptr)
                })
                .unwrap();
            state.free(ptr, size, |_| {});
        }

        let expected_records = state.lifecycle_logs().to_vec();
        assert!(expected_records.len() > 2048);
        let capacity_before = state.lifecycle_logs.capacity();
        let last_decision_id = expected_records
            .last()
            .expect("expected lifecycle records before drain")
            .decision_id;

        let drained = state.drain_lifecycle_logs();

        assert_eq!(drained, expected_records);
        assert!(state.lifecycle_logs().is_empty());
        assert_eq!(state.lifecycle_logs.capacity(), capacity_before);

        let ptr = state
            .malloc(size, |class_size| {
                next_ptr = next_ptr.wrapping_add(class_size.max(1));
                Some(next_ptr)
            })
            .unwrap();
        state.free(ptr, size, |_| {});

        let after_drain_records = state.lifecycle_logs();
        assert_eq!(after_drain_records.len(), 3);
        assert_eq!(
            after_drain_records[0].decision_id,
            last_decision_id.wrapping_add(1)
        );
        assert_eq!(after_drain_records[0].event, "size_class_certificate");
        assert_eq!(after_drain_records[1].details, "path=thread_cache");
        assert_eq!(after_drain_records[2].details, "path=thread_cache");
    }

    #[test]
    fn hot_cycle_static_lifecycle_details_are_borrowed() {
        let mut state = MallocState::new();
        state.set_min_log_level(AllocatorLogLevel::Trace);
        let size = 64;
        let mut next_ptr = 0x3000_0000usize;

        let ptr = state
            .malloc(size, |class_size| {
                next_ptr = next_ptr.wrapping_add(class_size.max(1));
                Some(next_ptr)
            })
            .unwrap();
        state.free(ptr, size, |_| {});
        let bin = size_class::small_bin_index(size).expect("64B allocation has a small bin");
        assert_eq!(state.thread_cache_hot_slots[bin.get()], Some(ptr));
        assert_eq!(state.thread_cache.total_cached(), 0);
        let _ = state.drain_lifecycle_logs();

        let reused_ptr = state
            .malloc(size, |class_size| {
                next_ptr = next_ptr.wrapping_add(class_size.max(1));
                Some(next_ptr)
            })
            .unwrap();
        state.free(reused_ptr, size, |_| {});

        let records = state.lifecycle_logs();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].event, "size_class_certificate");
        assert!(
            records[0]
                .details
                .starts_with("requested_size=64;mapped_class_size=64;cert_value=")
        );
        assert!(matches!(
            &records[0].details,
            Cow::Borrowed(HOT_CERT_64_DETAILS)
        ));

        assert_eq!(records[1].symbol, "malloc");
        assert_eq!(records[1].event, "alloc");
        assert_eq!(records[1].details, "path=thread_cache");
        assert!(matches!(
            &records[1].details,
            Cow::Borrowed("path=thread_cache")
        ));

        assert_eq!(records[2].symbol, "free");
        assert_eq!(records[2].event, "free");
        assert_eq!(records[2].details, "path=thread_cache");
        assert!(matches!(
            &records[2].details,
            Cow::Borrowed("path=thread_cache")
        ));
    }

    #[test]
    fn hot_size_class_certificate_value_matches_sos_barrier() {
        assert_eq!(
            evaluate_size_class_barrier(HOT_CERT_64_REQUEST_SIZE, HOT_CERT_64_CLASS_SIZE, true),
            HOT_CERT_64_VALUE
        );
        assert_eq!(
            size_class_certificate_value(HOT_CERT_64_REQUEST_SIZE, HOT_CERT_64_CLASS_SIZE, true),
            HOT_CERT_64_VALUE
        );
        assert_eq!(
            size_class_certificate_value(65, 128, true),
            evaluate_size_class_barrier(65, 128, true)
        );
        assert_eq!(
            size_class_certificate_value(HOT_CERT_64_REQUEST_SIZE, HOT_CERT_64_CLASS_SIZE, false),
            evaluate_size_class_barrier(HOT_CERT_64_REQUEST_SIZE, HOT_CERT_64_CLASS_SIZE, false)
        );
    }

    #[test]
    fn size_class_certificate_skip_gate_keeps_violation_paths() {
        assert!(!size_class_certificate_may_violate(64, 64, true));
        assert!(!size_class_certificate_may_violate(17, 32, true));
        assert!(size_class_certificate_may_violate(17, 256, true));
        assert!(size_class_certificate_may_violate(128, 130, false));
        assert!(size_class_certificate_may_violate(
            64,
            SIZE_CLASS_CERT_MAX_REQUEST + 1,
            true
        ));
    }

    #[test]
    fn size_class_certificate_skip_gate_matches_current_table() {
        let mut current_table_mappings_that_force_evaluation = 0usize;
        for size in 1..=size_class::MAX_SMALL_SIZE {
            let bin = size_class::small_bin_index(size).expect("small allocation size");
            let class_size = size_class::size_for_index(bin);
            let may_violate = size_class_certificate_may_violate(size, class_size, true);
            let certificate_value = size_class_certificate_value(size, class_size, true);

            if may_violate {
                current_table_mappings_that_force_evaluation += 1;
            } else {
                assert!(
                    certificate_value >= 0,
                    "skipped mapping must be certificate-safe: size={size}, class_size={class_size}"
                );
            }
        }
        assert!(current_table_mappings_that_force_evaluation > 0);
    }

    #[test]
    fn hot_cycle_lifecycle_record_sha256_is_stable() {
        let mut state = MallocState::new();
        state.set_min_log_level(AllocatorLogLevel::Trace);
        let size = 64;
        let mut next_ptr = 0x3000_0000usize;

        let ptr = state
            .malloc(size, |class_size| {
                next_ptr = next_ptr.wrapping_add(class_size.max(1));
                Some(next_ptr)
            })
            .unwrap();
        state.free(ptr, size, |_| {});
        let _ = state.drain_lifecycle_logs();

        let reused_ptr = state
            .malloc(size, |class_size| {
                next_ptr = next_ptr.wrapping_add(class_size.max(1));
                Some(next_ptr)
            })
            .unwrap();
        state.free(reused_ptr, size, |_| {});

        let mut golden = String::new();
        for record in state.lifecycle_logs() {
            writeln!(
                &mut golden,
                "{},{},{},{:?},{:?},{:?},{},{},{},{},{},{},{},{},{},{}",
                record.decision_id,
                record.trace_id,
                record.symbol,
                record.event,
                record.ptr,
                record.size,
                record.bin.map_or(NUM_SIZE_CLASSES, |bin| bin),
                record.outcome,
                record.details,
                record.active_count,
                record.total_allocated,
                record.thread_cache_hits,
                record.thread_cache_misses,
                record.central_bin_hits,
                record.spills_to_central,
                record.cache_hit_rate_permille
            )
            .expect("writing lifecycle golden row to String must succeed");
        }

        assert_eq!(
            hex_lower(&Sha256::digest(golden.as_bytes())),
            "01df8806e2bfd0fda041e153ec61ec4737ad2d3cb1ce22050a2e35bab1688455"
        );
    }

    #[test]
    fn hot_slot_lifecycle_record_sha256_is_stable() {
        let mut state = MallocState::new();
        state.set_min_log_level(AllocatorLogLevel::Trace);
        let size = 256;
        let mut next_ptr = 0x3100_0000usize;

        let ptr = state
            .malloc(size, |class_size| {
                next_ptr = next_ptr.wrapping_add(class_size.max(1));
                Some(next_ptr)
            })
            .unwrap();
        state.free(ptr, size, |_| {});
        let _ = state.drain_lifecycle_logs();

        let reused_ptr = state
            .malloc(size, |class_size| {
                next_ptr = next_ptr.wrapping_add(class_size.max(1));
                Some(next_ptr)
            })
            .unwrap();
        state.free(reused_ptr, size, |_| {});

        let mut golden = String::new();
        for record in state.lifecycle_logs() {
            writeln!(
                &mut golden,
                "{},{},{},{:?},{:?},{:?},{},{},{},{},{},{},{},{},{},{}",
                record.decision_id,
                record.trace_id,
                record.symbol,
                record.event,
                record.ptr,
                record.size,
                record.bin.map_or(NUM_SIZE_CLASSES, |bin| bin),
                record.outcome,
                record.details,
                record.active_count,
                record.total_allocated,
                record.thread_cache_hits,
                record.thread_cache_misses,
                record.central_bin_hits,
                record.spills_to_central,
                record.cache_hit_rate_permille
            )
            .expect("writing lifecycle golden row to String must succeed");
        }

        assert_eq!(
            hex_lower(&Sha256::digest(golden.as_bytes())),
            "eca20f7a00fb7f2dc41fcafde6f1d9f7184f585b492b87616dd9ef07e16e2729"
        );
    }

    #[test]
    fn test_large_malloc_registers_backend_pointer_metadata() {
        let mut state = MallocState::new();
        let size = size_class::MAX_SMALL_SIZE + 1;

        let ptr = state.malloc(size, test_alloc).unwrap();
        let metadata = state
            .large_allocation(ptr)
            .expect("large allocation metadata must be registered");

        assert_eq!(metadata.base, ptr);
        assert_eq!(metadata.user_size, size);
        assert!(metadata.mapped_size >= size);
        assert_eq!(metadata.mapped_size % 4096, 0);
        assert_eq!(state.active_large_count(), 1);
        assert_eq!(state.total_large_mapped(), metadata.mapped_size);
        assert_eq!(state.active_count(), 1);
        assert_eq!(state.total_allocated(), size);

        state.free(ptr, size, |p| test_free(p, size));
        assert!(state.large_allocation(ptr).is_none());
        assert_eq!(state.active_large_count(), 0);
        assert_eq!(state.total_large_mapped(), 0);
        assert_eq!(state.active_count(), 0);
        assert_eq!(state.total_allocated(), 0);
    }

    #[test]
    fn test_large_malloc_fast_slot_preserves_free_callback_and_metadata() {
        let mut state = MallocState::new();
        let size = 65_536;
        let mut backend_allocations = 0usize;
        let mut next_ptr = 0x7000_0000usize;

        let ptr = state
            .malloc(size, |request| {
                backend_allocations += 1;
                next_ptr = next_ptr.wrapping_add(request);
                Some(next_ptr)
            })
            .expect("initial large allocation must succeed");
        assert_eq!(backend_allocations, 1);
        assert!(state.large_allocation(ptr).is_some());
        assert_eq!(state.active_large_count(), 1);

        let mut released = 0usize;
        state.free(ptr, size, |freed| {
            released = freed;
        });
        assert_eq!(released, ptr);
        assert!(state.large_allocation(ptr).is_none());
        assert_eq!(state.active_large_count(), 0);
        assert_eq!(state.total_large_mapped(), 0);
        assert_eq!(backend_allocations, 1);
        assert_eq!(state.total_allocated(), 0);
    }

    #[test]
    fn test_large_malloc_backend_failure_does_not_register_metadata() {
        let mut state = MallocState::new();
        let size = size_class::MAX_SMALL_SIZE + 1;

        let ptr = state.malloc(size, |_| None);

        assert!(ptr.is_none());
        assert_eq!(state.active_large_count(), 0);
        assert_eq!(state.total_large_mapped(), 0);
        assert_eq!(state.active_count(), 0);
        assert_eq!(state.total_allocated(), 0);
    }

    #[test]
    fn test_large_malloc_rejects_mapping_size_overflow_before_backend() {
        let mut state = MallocState::new();
        let mut backend_called = false;

        let ptr = state.malloc(usize::MAX, |_| {
            backend_called = true;
            Some(0x7fff_0000)
        });

        assert!(ptr.is_none());
        assert!(!backend_called);
        assert_eq!(state.active_large_count(), 0);
        assert_eq!(state.total_large_mapped(), 0);
        assert_eq!(state.active_count(), 0);
        assert_eq!(state.total_allocated(), 0);
    }

    #[test]
    fn test_malloc_rejects_total_allocated_overflow_before_backend() {
        let mut state = MallocState::new();
        state.total_allocated = usize::MAX;
        let mut backend_called = false;

        let ptr = state.malloc(16, |_| {
            backend_called = true;
            Some(0x7000)
        });

        assert!(ptr.is_none());
        assert!(!backend_called);
        assert_eq!(state.active_count(), 0);
        assert_eq!(state.total_allocated(), usize::MAX);
        let last = state
            .lifecycle_logs()
            .last()
            .expect("expected accounting overflow lifecycle record");
        assert_eq!(last.outcome, "accounting_overflow");
        assert_eq!(last.details, "allocation_counters_would_overflow");
    }

    #[test]
    fn test_malloc_rejects_active_count_overflow_before_backend() {
        let mut state = MallocState::new();
        state.active_count = usize::MAX;
        let mut backend_called = false;

        let ptr = state.malloc(16, |_| {
            backend_called = true;
            Some(0x7000)
        });

        assert!(ptr.is_none());
        assert!(!backend_called);
        assert_eq!(state.active_count(), usize::MAX);
        assert_eq!(state.total_allocated(), 0);
        let last = state
            .lifecycle_logs()
            .last()
            .expect("expected accounting overflow lifecycle record");
        assert_eq!(last.outcome, "accounting_overflow");
        assert_eq!(last.details, "allocation_counters_would_overflow");
    }

    #[test]
    fn test_thread_cache_reuse() {
        let mut state = MallocState::new();
        let size = 32;

        // Allocate and free several blocks
        let mut ptrs = Vec::new();
        for _ in 0..5 {
            ptrs.push(state.malloc(size, test_alloc).unwrap());
        }
        for &ptr in &ptrs {
            state.free(ptr, size, |p| test_free(p, 32));
        }

        // Re-allocate - should reuse from thread cache (no new backend calls)
        let new_ptr = state
            .malloc(size, |_| {
                unreachable!(
                    // ubs:ignore — test asserts cache reuse path
                    "should not call backend"
                )
            })
            .unwrap();
        assert!(ptrs.contains(&new_ptr));
    }

    #[test]
    fn thread_cache_hot_slot_preserves_lifo_order_and_capacity() {
        let mut state = MallocState::new();
        let size = 256;
        let bin = size_class::small_bin_index(size).expect("256 byte size class");
        let mut next_ptr = 0x8000_0000usize;
        let mut backend_calls = 0usize;
        let mut ptrs = Vec::new();

        for _ in 0..=crate::malloc::thread_cache::MAGAZINE_CAPACITY {
            ptrs.push(
                state
                    .malloc(size, |class_size| {
                        backend_calls += 1;
                        next_ptr = next_ptr.wrapping_add(class_size.max(1));
                        Some(next_ptr)
                    })
                    .expect("backend allocation must succeed"),
            );
        }

        for &ptr in &ptrs {
            state.free(ptr, size, |_| {
                unreachable!(
                    // ubs:ignore — cache/central-bin path should retain small allocations
                    "small object should not be released to backend"
                )
            });
        }

        assert_eq!(
            state.thread_cache_hot_slots[bin.get()],
            Some(ptrs[crate::malloc::thread_cache::MAGAZINE_CAPACITY - 1])
        );
        assert_eq!(
            state.thread_cache.total_cached(),
            crate::malloc::thread_cache::MAGAZINE_CAPACITY - 1
        );
        assert_eq!(state.central_bin(bin).as_slice(), &ptrs[64..65]);

        for &expected in ptrs[..crate::malloc::thread_cache::MAGAZINE_CAPACITY]
            .iter()
            .rev()
        {
            let ptr = state
                .malloc(size, |_| {
                    unreachable!(
                        // ubs:ignore — test drains hot slot and existing magazine entries
                        "thread cache should satisfy the allocation"
                    )
                })
                .expect("thread-cache allocation must succeed");
            assert_eq!(ptr, expected);
        }

        let ptr = state
            .malloc(size, |_| {
                unreachable!(
                    // ubs:ignore — central bin spill should satisfy this allocation
                    "central bin should satisfy the allocation"
                )
            })
            .expect("central-bin allocation must succeed");
        assert_eq!(ptr, ptrs[crate::malloc::thread_cache::MAGAZINE_CAPACITY]);
        assert_eq!(
            backend_calls,
            crate::malloc::thread_cache::MAGAZINE_CAPACITY + 1
        );
    }

    #[test]
    fn free_matches_waiting_consumer_through_elimination() {
        let mut state = MallocState::new();
        state.set_min_log_level(AllocatorLogLevel::Trace);
        let size = 32;
        let ptr = state.malloc(size, test_alloc).unwrap();
        let elimination = state.elimination_handle();
        elimination.set_wait_budget(Duration::from_millis(100));
        let barrier = Barrier::new(2);

        let consumer = thread::scope(|scope| {
            let barrier_ref = &barrier;
            let elimination_ref = &elimination;
            let consumer = scope.spawn(move || {
                barrier_ref.wait();
                elimination_ref.try_take(size_class::bin_index(size))
            });

            barrier.wait();
            state.free(ptr, size, |p| test_free(p, 32));
            consumer.join().expect("consumer thread must join")
        });

        match consumer {
            TakeOutcome::Matched { value, .. } => assert_eq!(value, ptr),
            other => unreachable!(
                // ubs:ignore — test expects elimination handoff
                "expected elimination match, got {other:?}"
            ),
        }
        assert_eq!(state.active_count(), 0);
        assert_eq!(state.total_allocated(), 0);
        let last = state
            .lifecycle_logs()
            .last()
            .expect("expected at least one lifecycle record");
        assert_eq!(last.symbol, "free");
        assert!(last.details.contains("path=elimination"));
    }
}
