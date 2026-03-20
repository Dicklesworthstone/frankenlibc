//! ABI layer for memory allocation functions (`malloc`, `free`, `calloc`, `realloc`).
//!
//! These functions integrate with the membrane's generational arena for temporal safety.
//! All allocations are tracked with fingerprint headers and canaries for buffer overflow
//! detection. Double-free and use-after-free are caught via generation counters and
//! quarantine queues.
//!
//! In test mode, this module is suppressed to avoid shadowing the system allocator
//! (which would cause infinite recursion in the test binary itself).

use std::cell::Cell;
use std::ffi::{c_int, c_void};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use frankenlibc_core::errno::{EINVAL, ENOMEM};
use frankenlibc_membrane::arena::{AllocationArena, FreeResult};
use frankenlibc_membrane::check_oracle::CheckStage;
use frankenlibc_membrane::heal::{HealingAction, global_healing_policy};
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::errno_abi::set_abi_errno;
use crate::runtime_policy;

unsafe extern "C" {
    #[link_name = "__libc_malloc@GLIBC_2.2.5"]
    fn native_libc_malloc_sym(size: usize) -> *mut c_void;
    #[link_name = "__libc_calloc@GLIBC_2.2.5"]
    fn native_libc_calloc_sym(nmemb: usize, size: usize) -> *mut c_void;
    #[link_name = "__libc_realloc@GLIBC_2.2.5"]
    fn native_libc_realloc_sym(ptr: *mut c_void, size: usize) -> *mut c_void;
    #[link_name = "__libc_free@GLIBC_2.2.5"]
    fn native_libc_free_sym(ptr: *mut c_void);
    #[link_name = "__libc_memalign@GLIBC_2.2.5"]
    fn native_libc_memalign_sym(alignment: usize, size: usize) -> *mut c_void;
}

#[inline]
unsafe fn native_libc_malloc(size: usize) -> *mut c_void {
    // SAFETY: direct call to libc allocator symbol.
    unsafe { native_libc_malloc_sym(size) }
}

#[inline]
unsafe fn native_libc_calloc(nmemb: usize, size: usize) -> *mut c_void {
    // SAFETY: direct call to libc allocator symbol.
    unsafe { native_libc_calloc_sym(nmemb, size) }
}

#[inline]
unsafe fn native_libc_realloc(ptr: *mut c_void, size: usize) -> *mut c_void {
    // SAFETY: direct call to libc allocator symbol.
    unsafe { native_libc_realloc_sym(ptr, size) }
}

#[inline]
unsafe fn native_libc_free(ptr: *mut c_void) {
    // SAFETY: direct call to libc allocator symbol.
    unsafe { native_libc_free_sym(ptr) }
}

#[inline]
unsafe fn native_libc_posix_memalign(
    memptr: *mut *mut c_void,
    alignment: usize,
    size: usize,
) -> c_int {
    if memptr.is_null()
        || !alignment.is_power_of_two()
        || !alignment.is_multiple_of(std::mem::size_of::<usize>())
    {
        return EINVAL as c_int;
    }
    let req = size.max(1);
    // SAFETY: direct call to libc allocator symbol.
    let ptr = unsafe { native_libc_memalign(alignment, req) };
    if ptr.is_null() {
        return ENOMEM as c_int;
    }
    fallback_insert(ptr);
    // SAFETY: memptr non-null and caller-provided writable out pointer.
    unsafe { *memptr = ptr };
    0
}

#[inline]
unsafe fn native_libc_memalign(alignment: usize, size: usize) -> *mut c_void {
    // SAFETY: direct call to libc allocator symbol.
    unsafe { native_libc_memalign_sym(alignment, size) }
}

#[inline]
unsafe fn native_libc_aligned_alloc(alignment: usize, size: usize) -> *mut c_void {
    // SAFETY: direct call to libc allocator symbol.
    unsafe { native_libc_memalign(alignment, size) }
}

thread_local! {
    static ALLOCATOR_REENTRY_DEPTH: Cell<u32> = const { Cell::new(0) };
}

const MALLOC_STATS_BIN_COUNT: usize = frankenlibc_core::malloc::size_class::NUM_SIZE_CLASSES + 1;
const FLAT_COMBINER_SLOT_COUNT: usize = 128;
const FC_OP_NONE: usize = 0;
const FC_OP_ALLOC: usize = 1;
const FC_OP_FREE: usize = 2;
const FC_OP_SNAPSHOT: usize = 3;

#[derive(Debug, Clone, Copy, Default)]
struct MallocStatsSnapshot {
    total_allocated: usize,
    total_freed: usize,
    active_allocations: usize,
    live_bytes: usize,
    peak_usage: usize,
}

#[derive(Debug, Clone, Copy)]
struct MallocStatsState {
    total_allocated: usize,
    total_freed: usize,
    active_allocations: usize,
    live_bytes: usize,
    peak_usage: usize,
    per_size_class: [usize; MALLOC_STATS_BIN_COUNT],
}

impl MallocStatsState {
    const fn new() -> Self {
        Self {
            total_allocated: 0,
            total_freed: 0,
            active_allocations: 0,
            live_bytes: 0,
            peak_usage: 0,
            per_size_class: [0; MALLOC_STATS_BIN_COUNT],
        }
    }

    const fn snapshot(self) -> MallocStatsSnapshot {
        MallocStatsSnapshot {
            total_allocated: self.total_allocated,
            total_freed: self.total_freed,
            active_allocations: self.active_allocations,
            live_bytes: self.live_bytes,
            peak_usage: self.peak_usage,
        }
    }
}

#[repr(align(128))]
struct PublicationSlot {
    op: AtomicUsize,
    request_id: AtomicU64,
    completed_id: AtomicU64,
    size: AtomicUsize,
    bin: AtomicUsize,
    active: AtomicBool,
    age: AtomicU32,
    result_total_allocated: AtomicUsize,
    result_total_freed: AtomicUsize,
    result_active_allocations: AtomicUsize,
    result_live_bytes: AtomicUsize,
    result_peak_usage: AtomicUsize,
}

impl PublicationSlot {
    const fn new() -> Self {
        Self {
            op: AtomicUsize::new(FC_OP_NONE),
            request_id: AtomicU64::new(0),
            completed_id: AtomicU64::new(0),
            size: AtomicUsize::new(0),
            bin: AtomicUsize::new(0),
            active: AtomicBool::new(false),
            age: AtomicU32::new(0),
            result_total_allocated: AtomicUsize::new(0),
            result_total_freed: AtomicUsize::new(0),
            result_active_allocations: AtomicUsize::new(0),
            result_live_bytes: AtomicUsize::new(0),
            result_peak_usage: AtomicUsize::new(0),
        }
    }
}

struct FlatCombiningStats {
    combiner_lock: AtomicBool,
    next_slot: AtomicUsize,
    slots: [PublicationSlot; FLAT_COMBINER_SLOT_COUNT],
    state: std::sync::Mutex<MallocStatsState>,
}

impl FlatCombiningStats {
    fn new() -> Self {
        Self {
            combiner_lock: AtomicBool::new(false),
            next_slot: AtomicUsize::new(0),
            slots: [const { PublicationSlot::new() }; FLAT_COMBINER_SLOT_COUNT],
            state: std::sync::Mutex::new(MallocStatsState::new()),
        }
    }

    fn slot_index(&self) -> usize {
        ALLOC_STATS_SLOT_INDEX.with(|slot| match slot.get() {
            Some(idx) => idx,
            None => {
                let idx = self
                    .next_slot
                    .fetch_add(1, Ordering::Relaxed)
                    .wrapping_rem(FLAT_COMBINER_SLOT_COUNT);
                slot.set(Some(idx));
                idx
            }
        })
    }

    fn apply_op(&self, op: usize, size: usize, bin: usize) -> MallocStatsSnapshot {
        let idx = self.slot_index();
        let slot = &self.slots[idx];

        let request_id = slot.request_id.fetch_add(1, Ordering::AcqRel) + 1;
        slot.size.store(size, Ordering::Relaxed);
        slot.bin
            .store(bin.min(MALLOC_STATS_BIN_COUNT - 1), Ordering::Relaxed);
        slot.age.fetch_add(1, Ordering::Relaxed);
        slot.active.store(true, Ordering::Release);
        slot.op.store(op, Ordering::Release);

        self.try_combine_round();

        let mut spins = 0_u32;
        while slot.completed_id.load(Ordering::Acquire) < request_id {
            self.try_combine_round();
            if spins < 256 {
                spins += 1;
                std::hint::spin_loop();
            } else {
                spins = 0;
                std::thread::yield_now();
            }
        }

        MallocStatsSnapshot {
            total_allocated: slot.result_total_allocated.load(Ordering::Acquire),
            total_freed: slot.result_total_freed.load(Ordering::Acquire),
            active_allocations: slot.result_active_allocations.load(Ordering::Acquire),
            live_bytes: slot.result_live_bytes.load(Ordering::Acquire),
            peak_usage: slot.result_peak_usage.load(Ordering::Acquire),
        }
    }

    fn try_combine_round(&self) {
        if self
            .combiner_lock
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }

        let mut guard = match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        for slot in &self.slots {
            let op = slot.op.swap(FC_OP_NONE, Ordering::AcqRel);
            if op == FC_OP_NONE {
                continue;
            }

            let size = slot.size.load(Ordering::Relaxed);
            let bin = slot
                .bin
                .load(Ordering::Relaxed)
                .min(MALLOC_STATS_BIN_COUNT - 1);
            Self::apply_locked(&mut guard, op, size, bin);
            let snapshot = guard.snapshot();

            slot.result_total_allocated
                .store(snapshot.total_allocated, Ordering::Release);
            slot.result_total_freed
                .store(snapshot.total_freed, Ordering::Release);
            slot.result_active_allocations
                .store(snapshot.active_allocations, Ordering::Release);
            slot.result_live_bytes
                .store(snapshot.live_bytes, Ordering::Release);
            slot.result_peak_usage
                .store(snapshot.peak_usage, Ordering::Release);

            let current_req = slot.request_id.load(Ordering::Acquire);
            slot.completed_id.store(current_req, Ordering::Release);
        }

        self.combiner_lock.store(false, Ordering::Release);
    }

    fn apply_locked(state: &mut MallocStatsState, op: usize, size: usize, bin: usize) {
        match op {
            FC_OP_ALLOC => {
                state.total_allocated = state.total_allocated.saturating_add(size);
                state.active_allocations = state.active_allocations.saturating_add(1);
                state.live_bytes = state.live_bytes.saturating_add(size);
                state.peak_usage = state.peak_usage.max(state.live_bytes);
                state.per_size_class[bin] = state.per_size_class[bin].saturating_add(1);
            }
            FC_OP_FREE => {
                state.total_freed = state.total_freed.saturating_add(size);
                state.active_allocations = state.active_allocations.saturating_sub(1);
                state.live_bytes = state.live_bytes.saturating_sub(size);
                state.per_size_class[bin] = state.per_size_class[bin].saturating_sub(1);
            }
            FC_OP_SNAPSHOT => {}
            _ => {}
        }
    }

    fn record_alloc(&self, size: usize, bin: usize) {
        let _ = self.apply_op(FC_OP_ALLOC, size, bin);
    }

    fn record_free(&self, size: usize, bin: usize) {
        let _ = self.apply_op(FC_OP_FREE, size, bin);
    }

    fn snapshot(&self) -> MallocStatsSnapshot {
        self.apply_op(FC_OP_SNAPSHOT, 0, 0)
    }
}

static GLOBAL_ALLOC_STATS: OnceLock<FlatCombiningStats> = OnceLock::new();

thread_local! {
    static ALLOC_STATS_SLOT_INDEX: Cell<Option<usize>> = const { Cell::new(None) };
}

fn global_alloc_stats() -> &'static FlatCombiningStats {
    GLOBAL_ALLOC_STATS.get_or_init(FlatCombiningStats::new)
}

#[inline]
fn stats_bin_for_size(size: usize) -> usize {
    frankenlibc_core::malloc::size_class::bin_index(size.max(1)).min(MALLOC_STATS_BIN_COUNT - 1)
}

#[inline]
fn record_alloc_stats(size: usize) {
    if size == 0 {
        return;
    }
    global_alloc_stats().record_alloc(size, stats_bin_for_size(size));
}

#[inline]
fn record_free_stats(size: usize) {
    if size == 0 {
        return;
    }
    global_alloc_stats().record_free(size, stats_bin_for_size(size));
}

#[inline]
fn snapshot_alloc_stats() -> MallocStatsSnapshot {
    global_alloc_stats().snapshot()
}

// Native-fallback allocation tracking.
//
// Some bootstrap/reentrant paths intentionally allocate via native libc
// instead of the membrane arena. These pointers must later use native
// realloc/free semantics to preserve C behavior.
const FALLBACK_ALLOC_TABLE_SLOTS: usize = 262144;
const FALLBACK_SLOT_EMPTY: usize = 0;
const FALLBACK_SLOT_TOMBSTONE: usize = 1;
static FALLBACK_ALLOC_PTRS: [AtomicUsize; FALLBACK_ALLOC_TABLE_SLOTS] =
    [const { AtomicUsize::new(FALLBACK_SLOT_EMPTY) }; FALLBACK_ALLOC_TABLE_SLOTS];

#[inline]
fn fallback_key(ptr: *mut c_void) -> Option<usize> {
    let key = ptr as usize;
    if key <= FALLBACK_SLOT_TOMBSTONE {
        None
    } else {
        Some(key)
    }
}

#[inline]
fn fallback_start_index(key: usize) -> usize {
    key.wrapping_mul(0x9e37_79b9_7f4a_7c15) % FALLBACK_ALLOC_TABLE_SLOTS
}

fn fallback_contains(ptr: *mut c_void) -> bool {
    let Some(key) = fallback_key(ptr) else {
        return false;
    };
    let start = fallback_start_index(key);
    for i in 0..FALLBACK_ALLOC_TABLE_SLOTS {
        let idx = (start + i) % FALLBACK_ALLOC_TABLE_SLOTS;
        let slot = FALLBACK_ALLOC_PTRS[idx].load(Ordering::Acquire);
        if slot == key {
            return true;
        }
        if slot == FALLBACK_SLOT_EMPTY {
            return false;
        }
    }
    false
}

fn fallback_insert(ptr: *mut c_void) {
    let Some(key) = fallback_key(ptr) else {
        return;
    };
    let start = fallback_start_index(key);
    let mut first_tombstone: Option<usize> = None;
    for i in 0..FALLBACK_ALLOC_TABLE_SLOTS {
        let idx = (start + i) % FALLBACK_ALLOC_TABLE_SLOTS;
        let slot = FALLBACK_ALLOC_PTRS[idx].load(Ordering::Acquire);
        if slot == key {
            return;
        }
        if slot == FALLBACK_SLOT_TOMBSTONE {
            if first_tombstone.is_none() {
                first_tombstone = Some(idx);
            }
            continue;
        }
        if slot == FALLBACK_SLOT_EMPTY {
            if let Some(tomb_idx) = first_tombstone {
                if FALLBACK_ALLOC_PTRS[tomb_idx]
                    .compare_exchange(
                        FALLBACK_SLOT_TOMBSTONE,
                        key,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_ok()
                {
                    return;
                }
                first_tombstone = None;
                // Tombstone was taken by another thread. Fall through to try
                // claiming the empty slot we just found at `idx`.
            }
            if FALLBACK_ALLOC_PTRS[idx]
                .compare_exchange(
                    FALLBACK_SLOT_EMPTY,
                    key,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                return;
            }
        }
    }

    if let Some(tomb_idx) = first_tombstone {
        let _ = FALLBACK_ALLOC_PTRS[tomb_idx].compare_exchange(
            FALLBACK_SLOT_TOMBSTONE,
            key,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
}

fn fallback_remove(ptr: *mut c_void) -> bool {
    let Some(key) = fallback_key(ptr) else {
        return false;
    };
    let start = fallback_start_index(key);
    for i in 0..FALLBACK_ALLOC_TABLE_SLOTS {
        let idx = (start + i) % FALLBACK_ALLOC_TABLE_SLOTS;
        let slot = FALLBACK_ALLOC_PTRS[idx].load(Ordering::Acquire);
        if slot == key {
            if FALLBACK_ALLOC_PTRS[idx]
                .compare_exchange(
                    key,
                    FALLBACK_SLOT_TOMBSTONE,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                return true;
            }
            continue;
        }
        if slot == FALLBACK_SLOT_EMPTY {
            return false;
        }
    }
    false
}

#[must_use]
pub(crate) fn in_allocator_reentry_context() -> bool {
    ALLOCATOR_REENTRY_DEPTH
        .try_with(|depth| depth.get() > 0)
        .unwrap_or(true)
}

struct AllocatorReentryGuard;

impl Drop for AllocatorReentryGuard {
    fn drop(&mut self) {
        let _ = ALLOCATOR_REENTRY_DEPTH.try_with(|depth| {
            let current = depth.get();
            depth.set(current.saturating_sub(1));
        });
    }
}

#[inline]
fn enter_allocator_reentry_guard() -> Option<AllocatorReentryGuard> {
    if runtime_policy::in_policy_reentry_context() {
        return None;
    }
    if crate::pthread_abi::in_threading_policy_context() {
        return None;
    }
    ALLOCATOR_REENTRY_DEPTH
        .try_with(|depth| {
            let current = depth.get();
            if current > 0 {
                None
            } else {
                depth.set(current + 1);
                Some(AllocatorReentryGuard)
            }
        })
        .unwrap_or(None)
}

#[inline]
fn stage_index(ordering: &[CheckStage; 7], stage: CheckStage) -> usize {
    ordering.iter().position(|s| *s == stage).unwrap_or(0)
}

#[inline]
fn allocator_stage_context(addr_hint: usize) -> (bool, bool, [CheckStage; 7]) {
    let aligned = (addr_hint & 0x7) == 0;
    let recent_page = addr_hint != 0 && known_remaining(addr_hint).is_some();
    let ordering = runtime_policy::check_ordering(ApiFamily::Allocator, aligned, recent_page);
    (aligned, recent_page, ordering)
}

#[inline]
fn record_allocator_stage_outcome(
    ordering: &[CheckStage; 7],
    aligned: bool,
    recent_page: bool,
    exit_stage: Option<usize>,
) {
    runtime_policy::note_check_order_outcome(
        ApiFamily::Allocator,
        aligned,
        recent_page,
        ordering,
        exit_stage,
    );
}

/// Remaining bytes in a known live allocation at `addr`.
///
/// Returns `None` if the pipeline is not yet initialized (reentrant guard).
#[must_use]
pub(crate) fn known_remaining(addr: usize) -> Option<usize> {
    use frankenlibc_membrane::ptr_validator::ValidationOutcome;
    let pipeline = crate::membrane_state::try_global_pipeline()?;
    match pipeline.validate(addr) {
        ValidationOutcome::CachedValid(abs) | ValidationOutcome::Validated(abs) => abs.remaining,
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// malloc
// ---------------------------------------------------------------------------

/// POSIX `malloc` -- allocates `size` bytes of uninitialized memory.
///
/// Returns a pointer to the allocated memory, or null on failure.
/// The memory is not initialized.
///
/// # Safety
///
/// Caller must eventually `free` the returned pointer exactly once.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn malloc(size: usize) -> *mut c_void {
    let Some(_reentry_guard) = enter_allocator_reentry_guard() else {
        // SAFETY: reentrant path bypasses membrane/runtime-policy to avoid allocator recursion.
        let out = unsafe { native_libc_malloc(size.max(1)) };
        fallback_insert(out);
        return out;
    };

    let _trace_scope = runtime_policy::entrypoint_scope("malloc");
    let req = size.max(1);
    let (aligned, recent_page, ordering) = allocator_stage_context(0);
    let (_, decision) = runtime_policy::decide(ApiFamily::Allocator, req, req, true, false, 0);

    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(ENOMEM as c_int) };
        record_allocator_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Arena)),
        );
        runtime_policy::observe(
            ApiFamily::Allocator,
            decision.profile,
            runtime_policy::scaled_cost(8, req),
            true,
        );
        return std::ptr::null_mut();
    }

    let out: *mut c_void = match crate::membrane_state::try_global_pipeline() {
        Some(pipeline) => match pipeline.allocate(req) {
            Some(ptr) => ptr.cast(),
            None => std::ptr::null_mut(),
        },
        None => {
            // SAFETY: reentrant allocator bootstrap falls back to libc allocator.
            let out = unsafe { native_libc_malloc(req) };
            fallback_insert(out);
            out
        }
    };
    if !out.is_null() {
        record_alloc_stats(req);
    }
    runtime_policy::observe(
        ApiFamily::Allocator,
        decision.profile,
        runtime_policy::scaled_cost(8, req),
        out.is_null(),
    );
    record_allocator_stage_outcome(
        &ordering,
        aligned,
        recent_page,
        if out.is_null() {
            Some(stage_index(&ordering, CheckStage::Arena))
        } else {
            None
        },
    );
    out
}

// ---------------------------------------------------------------------------
// free
// ---------------------------------------------------------------------------

/// POSIX `free` -- deallocates memory previously allocated by `malloc`, `calloc`,
/// or `realloc`.
///
/// If `ptr` is null, no operation is performed (per POSIX).
///
/// # Safety
///
/// `ptr` must have been returned by a previous call to `malloc`, `calloc`, or
/// `realloc`, and must not have been freed already.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn free(ptr: *mut c_void) {
    let Some(_reentry_guard) = enter_allocator_reentry_guard() else {
        // SAFETY: reentrant path bypasses membrane/runtime-policy to avoid allocator recursion.
        let _ = fallback_remove(ptr);
        unsafe { native_libc_free(ptr) };
        return;
    };

    let _trace_scope = runtime_policy::entrypoint_scope("free");
    let (aligned, recent_page, ordering) = allocator_stage_context(ptr as usize);
    if ptr.is_null() {
        record_allocator_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Null)),
        );
        return;
    }

    let (_, decision) =
        runtime_policy::decide(ApiFamily::Allocator, ptr as usize, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        record_allocator_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Arena)),
        );
        runtime_policy::observe(ApiFamily::Allocator, decision.profile, 6, true);
        return;
    }

    let Some(pipeline) = crate::membrane_state::try_global_pipeline() else {
        // SAFETY: reentrant allocator bootstrap falls back to libc allocator.
        let _ = fallback_remove(ptr);
        unsafe { native_libc_free(ptr) };
        runtime_policy::observe(ApiFamily::Allocator, decision.profile, 6, false);
        record_allocator_stage_outcome(&ordering, aligned, recent_page, None);
        return;
    };

    let known_size = pipeline
        .arena
        .lookup(ptr as usize)
        .and_then(|slot| (slot.user_base == ptr as usize).then_some(slot.user_size));

    let mut adverse = false;
    let result = pipeline.free(ptr.cast());

    match result {
        FreeResult::Freed => {
            if let Some(size) = known_size {
                record_free_stats(size);
            }
        }
        FreeResult::FreedWithCanaryCorruption => {
            // Buffer overflow was detected -- the canary after the allocation was
            // corrupted. In strict mode we still free (damage is done). Metrics
            // are recorded by the arena.
            adverse = true;
            if let Some(size) = known_size {
                record_free_stats(size);
            }
        }
        FreeResult::DoubleFree => {
            adverse = true;
            if runtime_policy::mode().heals_enabled() {
                let policy = global_healing_policy();
                policy.record(&HealingAction::IgnoreDoubleFree);
            }
            // Strict mode: double free is silently ignored too (safer than UB).
            // A real glibc would abort, but our membrane prioritizes defined behavior.
        }
        FreeResult::ForeignPointer => {
            if fallback_remove(ptr) {
                // SAFETY: pointer is tracked as native-fallback allocation.
                unsafe { native_libc_free(ptr) };
            } else {
                adverse = true;
                if runtime_policy::mode().heals_enabled() {
                    let policy = global_healing_policy();
                    policy.record(&HealingAction::IgnoreForeignFree);
                }
                // Strict mode: foreign pointer free is ignored.
            }
        }
        FreeResult::InvalidPointer => {
            // Pointer is in an invalid state. Ignore to avoid undefined behavior.
            adverse = true;
        }
    }

    runtime_policy::observe(ApiFamily::Allocator, decision.profile, 20, adverse);
    record_allocator_stage_outcome(
        &ordering,
        aligned,
        recent_page,
        if adverse {
            Some(stage_index(&ordering, CheckStage::Arena))
        } else {
            None
        },
    );
}

// ---------------------------------------------------------------------------
// calloc
// ---------------------------------------------------------------------------

/// POSIX `calloc` -- allocates memory for an array of `nmemb` elements of `size`
/// bytes each, and initializes all bytes to zero.
///
/// Returns null if the multiplication overflows or allocation fails.
///
/// # Safety
///
/// Caller must eventually `free` the returned pointer exactly once.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn calloc(nmemb: usize, size: usize) -> *mut c_void {
    let Some(_reentry_guard) = enter_allocator_reentry_guard() else {
        // SAFETY: reentrant path bypasses membrane/runtime-policy to avoid allocator recursion.
        let out = unsafe { native_libc_calloc(nmemb, size) };
        fallback_insert(out);
        return out;
    };

    let _trace_scope = runtime_policy::entrypoint_scope("calloc");
    let (aligned, recent_page, ordering) = allocator_stage_context(0);
    let total = match nmemb.checked_mul(size) {
        Some(t) => t.max(1),
        None => {
            unsafe { set_abi_errno(ENOMEM as c_int) };
            let (_, decision) = runtime_policy::decide(ApiFamily::Allocator, 0, 0, true, false, 0);
            runtime_policy::observe(ApiFamily::Allocator, decision.profile, 4, true);
            record_allocator_stage_outcome(
                &ordering,
                aligned,
                recent_page,
                Some(stage_index(&ordering, CheckStage::Bounds)),
            );
            return std::ptr::null_mut();
        }
    };

    let (_, decision) = runtime_policy::decide(ApiFamily::Allocator, total, total, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(ENOMEM as c_int) };
        record_allocator_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Arena)),
        );
        runtime_policy::observe(
            ApiFamily::Allocator,
            decision.profile,
            runtime_policy::scaled_cost(8, total),
            true,
        );
        return std::ptr::null_mut();
    }

    let out: *mut c_void = match crate::membrane_state::try_global_pipeline() {
        Some(pipeline) => match pipeline.allocate(total) {
            Some(ptr) => {
                // SAFETY: ptr is valid for `total` bytes from the arena allocate contract.
                unsafe { std::ptr::write_bytes(ptr, 0, total) };
                ptr.cast()
            }
            None => std::ptr::null_mut(),
        },
        None => {
            // SAFETY: reentrant allocator bootstrap falls back to libc allocator.
            let out = unsafe { native_libc_calloc(nmemb, size) };
            fallback_insert(out);
            out
        }
    };
    if !out.is_null() {
        record_alloc_stats(total);
    }
    runtime_policy::observe(
        ApiFamily::Allocator,
        decision.profile,
        runtime_policy::scaled_cost(10, total),
        out.is_null(),
    );
    record_allocator_stage_outcome(
        &ordering,
        aligned,
        recent_page,
        if out.is_null() {
            Some(stage_index(&ordering, CheckStage::Arena))
        } else {
            None
        },
    );
    out
}

// ---------------------------------------------------------------------------
// realloc
// ---------------------------------------------------------------------------

/// POSIX `realloc` -- changes the size of a previously allocated memory block.
///
/// - If `ptr` is null, behaves like `malloc(size)`.
/// - If `size` is 0 and `ptr` is non-null, behaves like `free(ptr)` and returns null.
/// - Otherwise, allocates new memory of `size`, copies the old data, frees the old.
///
/// # Safety
///
/// `ptr` must be null or a pointer previously returned by `malloc`/`calloc`/`realloc`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn realloc(ptr: *mut c_void, size: usize) -> *mut c_void {
    let Some(_reentry_guard) = enter_allocator_reentry_guard() else {
        // SAFETY: reentrant path bypasses membrane/runtime-policy to avoid allocator recursion.
        let out = unsafe { native_libc_realloc(ptr, size) };
        if !out.is_null() {
            let _ = fallback_remove(ptr);
            fallback_insert(out);
        }
        return out;
    };

    let _trace_scope = runtime_policy::entrypoint_scope("realloc");
    // realloc(NULL, size) == malloc(size)
    if ptr.is_null() {
        return unsafe { malloc(size) };
    }

    // realloc(ptr, 0) == free(ptr), return NULL
    if size == 0 {
        unsafe { free(ptr) };
        return std::ptr::null_mut();
    }

    let (aligned, recent_page, ordering) = allocator_stage_context(ptr as usize);
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Allocator, ptr as usize, size, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(ENOMEM as c_int) };
        record_allocator_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Arena)),
        );
        runtime_policy::observe(
            ApiFamily::Allocator,
            decision.profile,
            runtime_policy::scaled_cost(8, size),
            true,
        );
        return std::ptr::null_mut();
    }

    let Some(pipeline) = crate::membrane_state::try_global_pipeline() else {
        // SAFETY: reentrant allocator bootstrap falls back to libc allocator.
        let out = unsafe { native_libc_realloc(ptr, size) };
        if !out.is_null() {
            let _ = fallback_remove(ptr);
            fallback_insert(out);
        }
        return out;
    };
    let arena: &AllocationArena = &pipeline.arena;

    // Look up old allocation to get its size
    let old_addr = ptr as usize;
    let old_size = match arena.lookup(old_addr) {
        Some(slot) if slot.user_base == old_addr => slot.user_size,
        Some(_) => {
            // Inner pointer or metadata pointer. Invalid to realloc.
            record_allocator_stage_outcome(
                &ordering,
                aligned,
                recent_page,
                Some(stage_index(&ordering, CheckStage::Arena)),
            );
            runtime_policy::observe(
                ApiFamily::Allocator,
                decision.profile,
                runtime_policy::scaled_cost(6, size),
                true,
            );
            return std::ptr::null_mut();
        }
        None => {
            if fallback_contains(ptr) {
                // Pointer originated from native fallback allocation path.
                // Preserve realloc copy semantics by delegating to native realloc.
                let out = unsafe { native_libc_realloc(ptr, size) };
                if !out.is_null() {
                    let _ = fallback_remove(ptr);
                    fallback_insert(out);
                }
                record_allocator_stage_outcome(
                    &ordering,
                    aligned,
                    recent_page,
                    if out.is_null() {
                        Some(stage_index(&ordering, CheckStage::Arena))
                    } else {
                        None
                    },
                );
                runtime_policy::observe(
                    ApiFamily::Allocator,
                    decision.profile,
                    runtime_policy::scaled_cost(12, size),
                    out.is_null(),
                );
                return out;
            }

            // Foreign pointer -- in hardened mode, treat as malloc
            if runtime_policy::mode().heals_enabled() {
                let policy = global_healing_policy();
                policy.record(&HealingAction::ReallocAsMalloc { size });
                record_allocator_stage_outcome(
                    &ordering,
                    aligned,
                    recent_page,
                    Some(stage_index(&ordering, CheckStage::Arena)),
                );
                runtime_policy::observe(
                    ApiFamily::Allocator,
                    decision.profile,
                    runtime_policy::scaled_cost(6, size),
                    true,
                );
                return unsafe { malloc(size) };
            }
            // Strict mode: cannot determine old size; treat as malloc
            record_allocator_stage_outcome(
                &ordering,
                aligned,
                recent_page,
                Some(stage_index(&ordering, CheckStage::Arena)),
            );
            runtime_policy::observe(
                ApiFamily::Allocator,
                decision.profile,
                runtime_policy::scaled_cost(6, size),
                true,
            );
            return unsafe { malloc(size) };
        }
    };

    // Allocate new block
    let new_ptr = match arena.allocate(size) {
        Some(p) => {
            pipeline.register_allocation(p as usize, size);
            p
        }
        None => {
            record_allocator_stage_outcome(
                &ordering,
                aligned,
                recent_page,
                Some(stage_index(&ordering, CheckStage::Arena)),
            );
            runtime_policy::observe(
                ApiFamily::Allocator,
                decision.profile,
                runtime_policy::scaled_cost(12, size),
                true,
            );
            return std::ptr::null_mut();
        }
    };

    // Copy old data (up to the smaller of old and new sizes)
    let copy_size = old_size.min(size);

    // SAFETY: old ptr is valid for old_size bytes, new ptr is valid for size bytes.
    // copy_size <= min(old_size, size), so both reads and writes are in bounds.
    unsafe {
        std::ptr::copy_nonoverlapping(ptr.cast::<u8>(), new_ptr, copy_size);
    }

    // Account new live allocation first so failed old-block release does not undercount.
    record_alloc_stats(size);

    // Free old block and account deallocation only if arena confirms it was released.
    let old_free = pipeline.free(ptr.cast());
    if matches!(
        old_free,
        FreeResult::Freed | FreeResult::FreedWithCanaryCorruption
    ) {
        record_free_stats(old_size);
    }
    runtime_policy::observe(
        ApiFamily::Allocator,
        decision.profile,
        runtime_policy::scaled_cost(18, size),
        false,
    );
    record_allocator_stage_outcome(&ordering, aligned, recent_page, None);
    new_ptr.cast()
}

// ---------------------------------------------------------------------------
// posix_memalign
// ---------------------------------------------------------------------------

/// POSIX `posix_memalign` -- allocates `size` bytes of memory with specified alignment.
///
/// Stores the address of the allocated memory in `*memptr`.
/// Returns 0 on success, or an error code (EINVAL, ENOMEM) on failure.
///
/// # Safety
///
/// `memptr` must be a valid pointer to a `*mut c_void`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn posix_memalign(
    memptr: *mut *mut c_void,
    alignment: usize,
    size: usize,
) -> c_int {
    if memptr.is_null()
        || !alignment.is_power_of_two()
        || !alignment.is_multiple_of(std::mem::size_of::<usize>())
    {
        return EINVAL as c_int;
    }

    let Some(_reentry_guard) = enter_allocator_reentry_guard() else {
        // SAFETY: forwards arguments to libc-compatible fallback implementation.
        return unsafe { native_libc_posix_memalign(memptr, alignment, size) };
    };

    let _trace_scope = runtime_policy::entrypoint_scope("posix_memalign");
    let req = size.max(1);
    let (aligned, recent_page, ordering) = allocator_stage_context(0);
    let (_, decision) = runtime_policy::decide(ApiFamily::Allocator, req, req, true, false, 0);

    if matches!(decision.action, MembraneAction::Deny) {
        record_allocator_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Arena)),
        );
        runtime_policy::observe(
            ApiFamily::Allocator,
            decision.profile,
            runtime_policy::scaled_cost(8, req),
            true,
        );
        return ENOMEM as c_int;
    }

    let out: *mut c_void = match crate::membrane_state::try_global_pipeline() {
        Some(pipeline) => match pipeline.allocate_aligned(req, alignment) {
            Some(ptr) => ptr.cast(),
            None => std::ptr::null_mut(),
        },
        None => {
            // SAFETY: reentrant allocator bootstrap falls back to libc allocator.
            let ptr = unsafe { native_libc_memalign(alignment, req) };
            if !ptr.is_null() {
                fallback_insert(ptr);
            }
            ptr
        }
    };
    if !out.is_null() {
        record_alloc_stats(req);
    }

    runtime_policy::observe(
        ApiFamily::Allocator,
        decision.profile,
        runtime_policy::scaled_cost(10, req),
        out.is_null(),
    );
    record_allocator_stage_outcome(
        &ordering,
        aligned,
        recent_page,
        if out.is_null() {
            Some(stage_index(&ordering, CheckStage::Arena))
        } else {
            None
        },
    );

    if out.is_null() {
        ENOMEM as c_int
    } else {
        unsafe { *memptr = out };
        0
    }
}

// ---------------------------------------------------------------------------
// memalign
// ---------------------------------------------------------------------------

/// Legacy `memalign` -- allocates `size` bytes of memory with specified alignment.
///
/// Returns a pointer to the allocated memory, or null on failure.
///
/// # Safety
///
/// Caller must eventually `free` the returned pointer exactly once.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn memalign(alignment: usize, size: usize) -> *mut c_void {
    // POSIX requires alignment to be a power of two.
    if alignment == 0 || !alignment.is_power_of_two() {
        unsafe { set_abi_errno(EINVAL as c_int) };
        return std::ptr::null_mut();
    }

    let Some(_reentry_guard) = enter_allocator_reentry_guard() else {
        // SAFETY: direct delegation avoids recursive aligned-allocation lock paths.
        let out = unsafe { native_libc_memalign(alignment, size) };
        fallback_insert(out);
        return out;
    };

    let _trace_scope = runtime_policy::entrypoint_scope("memalign");
    let req = size.max(1);
    let (aligned, recent_page, ordering) = allocator_stage_context(0);
    let (_, decision) = runtime_policy::decide(ApiFamily::Allocator, req, req, true, false, 0);

    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(ENOMEM as c_int) };
        record_allocator_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Arena)),
        );
        runtime_policy::observe(
            ApiFamily::Allocator,
            decision.profile,
            runtime_policy::scaled_cost(8, req),
            true,
        );
        return std::ptr::null_mut();
    }

    let out: *mut c_void = match crate::membrane_state::try_global_pipeline() {
        Some(pipeline) => match pipeline.allocate_aligned(req, alignment) {
            Some(ptr) => ptr.cast(),
            None => std::ptr::null_mut(),
        },
        None => {
            let out = unsafe { native_libc_memalign(alignment, req) };
            if !out.is_null() {
                fallback_insert(out);
            }
            out
        }
    };
    if !out.is_null() {
        record_alloc_stats(req);
    }

    runtime_policy::observe(
        ApiFamily::Allocator,
        decision.profile,
        runtime_policy::scaled_cost(10, req),
        out.is_null(),
    );
    record_allocator_stage_outcome(
        &ordering,
        aligned,
        recent_page,
        if out.is_null() {
            Some(stage_index(&ordering, CheckStage::Arena))
        } else {
            None
        },
    );
    out
}

// ---------------------------------------------------------------------------
// aligned_alloc
// ---------------------------------------------------------------------------

/// C11 `aligned_alloc` -- allocates `size` bytes of memory with specified alignment.
///
/// `alignment` must be a valid alignment supported by the implementation.
/// `size` must be a multiple of `alignment`.
/// Returns a pointer to the allocated memory, or null on failure.
///
/// # Safety
///
/// Caller must eventually `free` the returned pointer exactly once.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn aligned_alloc(alignment: usize, size: usize) -> *mut c_void {
    // C11 requires alignment to be a power of two and size to be a multiple of alignment.
    if alignment == 0 || !alignment.is_power_of_two() || !size.is_multiple_of(alignment) {
        unsafe { set_abi_errno(EINVAL as c_int) };
        return std::ptr::null_mut();
    }

    let Some(_reentry_guard) = enter_allocator_reentry_guard() else {
        // SAFETY: direct delegation avoids recursive aligned-allocation lock paths.
        let out = unsafe { native_libc_aligned_alloc(alignment, size) };
        fallback_insert(out);
        return out;
    };

    let _trace_scope = runtime_policy::entrypoint_scope("aligned_alloc");
    let req = size.max(1);
    let (aligned, recent_page, ordering) = allocator_stage_context(0);
    let (_, decision) = runtime_policy::decide(ApiFamily::Allocator, req, req, true, false, 0);

    if matches!(decision.action, MembraneAction::Deny) {
        unsafe { set_abi_errno(ENOMEM as c_int) };
        record_allocator_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Arena)),
        );
        runtime_policy::observe(
            ApiFamily::Allocator,
            decision.profile,
            runtime_policy::scaled_cost(8, req),
            true,
        );
        return std::ptr::null_mut();
    }

    let out: *mut c_void = match crate::membrane_state::try_global_pipeline() {
        Some(pipeline) => match pipeline.allocate_aligned(req, alignment) {
            Some(ptr) => ptr.cast(),
            None => std::ptr::null_mut(),
        },
        None => {
            let out = unsafe { native_libc_aligned_alloc(alignment, req) };
            if !out.is_null() {
                fallback_insert(out);
            }
            out
        }
    };
    if !out.is_null() {
        record_alloc_stats(req);
    }

    runtime_policy::observe(
        ApiFamily::Allocator,
        decision.profile,
        runtime_policy::scaled_cost(10, req),
        out.is_null(),
    );
    record_allocator_stage_outcome(
        &ordering,
        aligned,
        recent_page,
        if out.is_null() {
            Some(stage_index(&ordering, CheckStage::Arena))
        } else {
            None
        },
    );
    out
}

// ---------------------------------------------------------------------------
// valloc
// ---------------------------------------------------------------------------

/// Legacy `valloc` -- allocates `size` bytes of page-aligned memory.
///
/// Returns a pointer to the allocated memory, or null on failure.
/// Equivalent to `memalign(page_size, size)`.
///
/// # Safety
///
/// Caller must eventually `free` the returned pointer exactly once.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn valloc(size: usize) -> *mut c_void {
    let page_sz = page_size();
    unsafe { memalign(page_sz, size) }
}

// ---------------------------------------------------------------------------
// pvalloc
// ---------------------------------------------------------------------------

/// GNU extension `pvalloc` -- allocates memory with page alignment and size
/// rounded up to the next page boundary.
///
/// Returns a pointer to the allocated memory, or null on failure.
///
/// # Safety
///
/// Caller must eventually `free` the returned pointer exactly once.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pvalloc(size: usize) -> *mut c_void {
    let page_sz = page_size();
    // Round up to next page boundary
    let rounded = match size.checked_add(page_sz - 1) {
        Some(v) => v & !(page_sz - 1),
        None => {
            unsafe { set_abi_errno(ENOMEM as c_int) };
            return std::ptr::null_mut();
        }
    };
    unsafe { memalign(page_sz, rounded) }
}

// ---------------------------------------------------------------------------
// cfree
// ---------------------------------------------------------------------------

/// BSD legacy `cfree` -- identical to `free`. Provided for compatibility.
///
/// # Safety
///
/// Same as `free`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cfree(ptr: *mut c_void) {
    unsafe { free(ptr) }
}

// ---------------------------------------------------------------------------
// mallopt
// ---------------------------------------------------------------------------

/// GNU `mallopt` -- set allocator tuning parameters.
///
/// Since FrankenLibC uses its own allocator with fixed policy, this is a
/// compatibility stub that accepts any parameter and returns 1 (success).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mallopt(_param: c_int, _value: c_int) -> c_int {
    1
}

// ---------------------------------------------------------------------------
// malloc_usable_size
// ---------------------------------------------------------------------------

/// GNU `malloc_usable_size` -- returns the number of usable bytes in the
/// allocation pointed to by `ptr`.
///
/// If `ptr` is null, returns 0.
///
/// # Safety
///
/// `ptr` must be null or a valid pointer returned by `malloc`/`calloc`/`realloc`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn malloc_usable_size(ptr: *mut c_void) -> usize {
    if ptr.is_null() {
        return 0;
    }
    let addr = ptr as usize;

    // Look up in membrane arena first
    if let Some(pipeline) = crate::membrane_state::try_global_pipeline()
        && let Some(slot) = pipeline.arena.lookup(addr)
        && slot.user_base == addr
    {
        return slot.user_size;
    }

    // Check fallback allocation table - delegate to native
    if fallback_contains(ptr) {
        unsafe extern "C" {
            #[link_name = "malloc_usable_size@GLIBC_2.2.5"]
            fn native_malloc_usable_size(ptr: *mut c_void) -> usize;
        }
        // SAFETY: ptr is a valid native allocation tracked in fallback table.
        return unsafe { native_malloc_usable_size(ptr) };
    }

    0
}

// ---------------------------------------------------------------------------
// malloc_trim
// ---------------------------------------------------------------------------

/// GNU `malloc_trim` -- release free memory from the allocator back to the OS.
///
/// Returns 1 if memory was released, 0 otherwise.
/// Since FrankenLibC uses its own arena-based allocator, this is a
/// compatibility stub that returns 1.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn malloc_trim(_pad: usize) -> c_int {
    1
}

// ---------------------------------------------------------------------------
// mallinfo / mallinfo2
// ---------------------------------------------------------------------------

/// The `mallinfo` struct returned by `mallinfo()`.
///
/// Fields use `c_int` (which truncates on 64-bit systems where total
/// allocations exceed 2 GiB). Use `mallinfo2` for accurate results.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Mallinfo {
    pub arena: c_int,
    pub ordblks: c_int,
    pub smblks: c_int,
    pub hblks: c_int,
    pub hblkhd: c_int,
    pub usmblks: c_int,
    pub fsmblks: c_int,
    pub uordblks: c_int,
    pub fordblks: c_int,
    pub keepcost: c_int,
}

/// The `mallinfo2` struct returned by `mallinfo2()`.
///
/// Same as `mallinfo` but uses `usize` (size_t) fields.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Mallinfo2 {
    pub arena: usize,
    pub ordblks: usize,
    pub smblks: usize,
    pub hblks: usize,
    pub hblkhd: usize,
    pub usmblks: usize,
    pub fsmblks: usize,
    pub uordblks: usize,
    pub fordblks: usize,
    pub keepcost: usize,
}

/// Collect raw allocation statistics from the flat-combining allocator stats state.
fn collect_alloc_stats() -> (usize, usize, usize) {
    let snapshot = snapshot_alloc_stats();
    (
        snapshot.live_bytes,
        snapshot.active_allocations,
        snapshot.peak_usage.max(snapshot.live_bytes),
    )
}

/// GNU `mallinfo` -- returns allocation statistics.
///
/// Note: `c_int` fields truncate values exceeding `i32::MAX`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mallinfo() -> Mallinfo {
    let (allocated, count, capacity) = collect_alloc_stats();
    let free_space = capacity.saturating_sub(allocated);
    Mallinfo {
        arena: capacity.min(c_int::MAX as usize) as c_int,
        ordblks: count.min(c_int::MAX as usize) as c_int,
        smblks: 0,
        hblks: 0,
        hblkhd: 0,
        usmblks: 0,
        fsmblks: 0,
        uordblks: allocated.min(c_int::MAX as usize) as c_int,
        fordblks: free_space.min(c_int::MAX as usize) as c_int,
        keepcost: 0,
    }
}

/// GNU `mallinfo2` -- returns allocation statistics with `size_t` fields.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn mallinfo2() -> Mallinfo2 {
    let (allocated, count, capacity) = collect_alloc_stats();
    let free_space = capacity.saturating_sub(allocated);
    Mallinfo2 {
        arena: capacity,
        ordblks: count,
        smblks: 0,
        hblks: 0,
        hblkhd: 0,
        usmblks: 0,
        fsmblks: 0,
        uordblks: allocated,
        fordblks: free_space,
        keepcost: 0,
    }
}

// ---------------------------------------------------------------------------
// malloc_stats
// ---------------------------------------------------------------------------

/// GNU `malloc_stats` -- print allocation statistics to stderr.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn malloc_stats() {
    let info = unsafe { mallinfo2() };
    let msg = format!(
        "Arena 0:\nsystem bytes     = {}\nin use bytes     = {}\nTotal (incl. mmap):\nsystem bytes     = {}\nin use bytes     = {}\nmax mmap regions = {}\nmax mmap bytes   = {}\n",
        info.arena, info.uordblks, info.arena, info.uordblks, info.hblks, info.hblkhd,
    );
    // SAFETY: write(2, buf, len) - writing to stderr fd.
    unsafe {
        libc::write(2, msg.as_ptr().cast(), msg.len());
    }
}

// ---------------------------------------------------------------------------
// malloc_info
// ---------------------------------------------------------------------------

/// GNU `malloc_info` -- print allocation statistics as XML to `stream`.
///
/// `options` must be 0. Returns 0 on success, -1 on error.
///
/// # Safety
///
/// `stream` must be a valid `FILE*` pointer.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn malloc_info(options: c_int, stream: *mut c_void) -> c_int {
    if options != 0 || stream.is_null() {
        unsafe { set_abi_errno(EINVAL as c_int) };
        return -1;
    }

    let info = unsafe { mallinfo2() };
    let xml = format!(
        "<malloc version=\"1\">\n<heap nr=\"0\">\n<sizes>\n</sizes>\n<total type=\"fast\" count=\"0\" size=\"0\"/>\n<total type=\"rest\" count=\"{}\" size=\"{}\"/>\n<system type=\"current\" size=\"{}\"/>\n<system type=\"max\" size=\"{}\"/>\n<aspace type=\"total\" size=\"{}\"/>\n<aspace type=\"mprotect\" size=\"{}\"/>\n</heap>\n<total type=\"fast\" count=\"0\" size=\"0\"/>\n<total type=\"rest\" count=\"{}\" size=\"{}\"/>\n<system type=\"current\" size=\"{}\"/>\n<system type=\"max\" size=\"{}\"/>\n<aspace type=\"total\" size=\"{}\"/>\n<aspace type=\"mprotect\" size=\"{}\"/>\n</malloc>\n",
        info.ordblks,
        info.uordblks,
        info.arena,
        info.arena,
        info.arena,
        info.arena,
        info.ordblks,
        info.uordblks,
        info.arena,
        info.arena,
        info.arena,
        info.arena,
    );

    // SAFETY: caller guarantees stream is a valid FILE*.
    unsafe extern "C" {
        fn fputs(s: *const std::ffi::c_char, stream: *mut c_void) -> c_int;
    }
    let c_xml = std::ffi::CString::new(xml).unwrap_or_default();
    let rc = unsafe { fputs(c_xml.as_ptr(), stream) };
    if rc < 0 { -1 } else { 0 }
}

// ---------------------------------------------------------------------------
// Helper: page size
// ---------------------------------------------------------------------------

#[inline]
fn page_size() -> usize {
    // SAFETY: sysconf(_SC_PAGESIZE) is always safe and returns the page size.
    let ps = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if ps > 0 { ps as usize } else { 4096 }
}

// ===========================================================================
// __libc_* internal aliases — glibc exports these for internal use
// ===========================================================================

/// `__libc_freeres` — release all libc internal resources (no-op).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_freeres() {}
