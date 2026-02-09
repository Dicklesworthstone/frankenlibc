//! ABI layer for memory allocation functions (`malloc`, `free`, `calloc`, `realloc`).
//!
//! These functions integrate with the membrane's generational arena for temporal safety.
//! All allocations are tracked with fingerprint headers and canaries for buffer overflow
//! detection. Double-free and use-after-free are caught via generation counters and
//! quarantine queues.
//!
//! In test mode, this module is suppressed to avoid shadowing the system allocator
//! (which would cause infinite recursion in the test binary itself).

use std::ffi::{c_int, c_void};

use glibc_rs_core::errno::{EINVAL, ENOMEM};
use glibc_rs_membrane::arena::{AllocationArena, FreeResult};
use glibc_rs_membrane::config::safety_level;
use glibc_rs_membrane::heal::{HealingAction, global_healing_policy};
use glibc_rs_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::runtime_policy;

/// Access to the global allocation arena from the pipeline.
fn arena() -> &'static AllocationArena {
    &crate::membrane_state::global_pipeline().arena
}

/// Remaining bytes in a known live allocation at `addr`.
#[must_use]
pub(crate) fn known_remaining(addr: usize) -> Option<usize> {
    use glibc_rs_membrane::ptr_validator::ValidationOutcome;
    match crate::membrane_state::global_pipeline().validate(addr) {
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn malloc(size: usize) -> *mut c_void {
    let req = size.max(1);
    let (_, decision) = runtime_policy::decide(ApiFamily::Allocator, req, req, true, false, 0);

    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(
            ApiFamily::Allocator,
            decision.profile,
            runtime_policy::scaled_cost(8, req),
            true,
        );
        return std::ptr::null_mut();
    }

    let out: *mut c_void = match crate::membrane_state::global_pipeline().allocate(req) {
        Some(ptr) => ptr.cast(),
        None => std::ptr::null_mut(),
    };
    runtime_policy::observe(
        ApiFamily::Allocator,
        decision.profile,
        runtime_policy::scaled_cost(8, req),
        out.is_null(),
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn free(ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }

    let (_, decision) =
        runtime_policy::decide(ApiFamily::Allocator, ptr as usize, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Allocator, decision.profile, 6, true);
        return;
    }

    let mut adverse = false;
    let (result, _drained) = arena().free(ptr.cast());

    match result {
        FreeResult::Freed => {}
        FreeResult::FreedWithCanaryCorruption => {
            // Buffer overflow was detected -- the canary after the allocation was
            // corrupted. In strict mode we still free (damage is done). Metrics
            // are recorded by the arena.
            adverse = true;
        }
        FreeResult::DoubleFree => {
            adverse = true;
            if safety_level().heals_enabled() {
                let policy = global_healing_policy();
                policy.record(&HealingAction::IgnoreDoubleFree);
            }
            // Strict mode: double free is silently ignored too (safer than UB).
            // A real glibc would abort, but our membrane prioritizes defined behavior.
        }
        FreeResult::ForeignPointer => {
            adverse = true;
            if safety_level().heals_enabled() {
                let policy = global_healing_policy();
                policy.record(&HealingAction::IgnoreForeignFree);
            }
            // Strict mode: foreign pointer free is ignored.
        }
        FreeResult::InvalidPointer => {
            // Pointer is in an invalid state. Ignore to avoid undefined behavior.
            adverse = true;
        }
    }

    runtime_policy::observe(ApiFamily::Allocator, decision.profile, 20, adverse);
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn calloc(nmemb: usize, size: usize) -> *mut c_void {
    let total = match nmemb.checked_mul(size) {
        Some(t) => t.max(1),
        None => {
            let (_, decision) = runtime_policy::decide(ApiFamily::Allocator, 0, 0, true, false, 0);
            runtime_policy::observe(ApiFamily::Allocator, decision.profile, 4, true);
            return std::ptr::null_mut();
        }
    };

    let (_, decision) = runtime_policy::decide(ApiFamily::Allocator, total, total, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(
            ApiFamily::Allocator,
            decision.profile,
            runtime_policy::scaled_cost(8, total),
            true,
        );
        return std::ptr::null_mut();
    }

    let out: *mut c_void = match arena().allocate(total) {
        Some(ptr) => {
            crate::membrane_state::global_pipeline().register_allocation(ptr as usize, total);
            // SAFETY: ptr is valid for `total` bytes from the arena allocate contract.
            unsafe { std::ptr::write_bytes(ptr, 0, total) };
            ptr.cast()
        }
        None => std::ptr::null_mut(),
    };
    runtime_policy::observe(
        ApiFamily::Allocator,
        decision.profile,
        runtime_policy::scaled_cost(10, total),
        out.is_null(),
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn realloc(ptr: *mut c_void, size: usize) -> *mut c_void {
    // realloc(NULL, size) == malloc(size)
    if ptr.is_null() {
        return unsafe { malloc(size) };
    }

    // realloc(ptr, 0) == free(ptr), return NULL
    if size == 0 {
        unsafe { free(ptr) };
        return std::ptr::null_mut();
    }

    let (_, decision) =
        runtime_policy::decide(ApiFamily::Allocator, ptr as usize, size, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(
            ApiFamily::Allocator,
            decision.profile,
            runtime_policy::scaled_cost(8, size),
            true,
        );
        return std::ptr::null_mut();
    }

    let arena = arena();

    // Look up old allocation to get its size
    let old_addr = ptr as usize;
    let old_size = match arena.lookup(old_addr) {
        Some(slot) => slot.user_size,
        None => {
            // Foreign pointer -- in hardened mode, treat as malloc
            if safety_level().heals_enabled() {
                let policy = global_healing_policy();
                policy.record(&HealingAction::ReallocAsMalloc { size });
                runtime_policy::observe(
                    ApiFamily::Allocator,
                    decision.profile,
                    runtime_policy::scaled_cost(6, size),
                    true,
                );
                return unsafe { malloc(size) };
            }
            // Strict mode: cannot determine old size; treat as malloc
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
            crate::membrane_state::global_pipeline().register_allocation(p as usize, size);
            p
        }
        None => {
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

    // Free old block
    let _ = crate::membrane_state::global_pipeline().free(ptr.cast());
    runtime_policy::observe(
        ApiFamily::Allocator,
        decision.profile,
        runtime_policy::scaled_cost(18, size),
        false,
    );
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn posix_memalign(
    memptr: *mut *mut c_void,
    alignment: usize,
    size: usize,
) -> c_int {
    // Requirements: alignment power of 2, multiple of sizeof(void*)
    if !alignment.is_power_of_two() || !alignment.is_multiple_of(std::mem::size_of::<usize>()) {
        return EINVAL;
    }

    let req = size.max(1);
    let (_, decision) = runtime_policy::decide(ApiFamily::Allocator, req, req, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(
            ApiFamily::Allocator,
            decision.profile,
            runtime_policy::scaled_cost(8, req),
            true,
        );
        return ENOMEM;
    }

    match crate::membrane_state::global_pipeline().allocate_aligned(req, alignment) {
        Some(ptr) => {
            // SAFETY: caller guarantees `memptr` points to writable `*mut c_void`.
            unsafe { *memptr = ptr.cast() };
            runtime_policy::observe(
                ApiFamily::Allocator,
                decision.profile,
                runtime_policy::scaled_cost(12, req),
                false,
            );
            0
        }
        None => {
            runtime_policy::observe(
                ApiFamily::Allocator,
                decision.profile,
                runtime_policy::scaled_cost(12, req),
                true,
            );
            ENOMEM
        }
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memalign(alignment: usize, size: usize) -> *mut c_void {
    if !alignment.is_power_of_two() {
        glibc_rs_core::errno::set_errno(EINVAL);
        return std::ptr::null_mut();
    }

    let req = size.max(1);
    let (_, decision) = runtime_policy::decide(ApiFamily::Allocator, req, req, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(
            ApiFamily::Allocator,
            decision.profile,
            runtime_policy::scaled_cost(8, req),
            true,
        );
        return std::ptr::null_mut();
    }

    match arena().allocate_aligned(req, alignment) {
        Some(ptr) => {
            crate::membrane_state::global_pipeline().register_allocation(ptr as usize, req);
            runtime_policy::observe(
                ApiFamily::Allocator,
                decision.profile,
                runtime_policy::scaled_cost(12, req),
                false,
            );
            ptr.cast()
        }
        None => {
            glibc_rs_core::errno::set_errno(ENOMEM);
            runtime_policy::observe(
                ApiFamily::Allocator,
                decision.profile,
                runtime_policy::scaled_cost(12, req),
                true,
            );
            std::ptr::null_mut()
        }
    }
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aligned_alloc(alignment: usize, size: usize) -> *mut c_void {
    // Requirements: alignment power of 2, size multiple of alignment
    if !alignment.is_power_of_two() || !size.is_multiple_of(alignment) {
        glibc_rs_core::errno::set_errno(EINVAL);
        return std::ptr::null_mut();
    }

    let req = size.max(1);
    let (_, decision) = runtime_policy::decide(ApiFamily::Allocator, req, req, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(
            ApiFamily::Allocator,
            decision.profile,
            runtime_policy::scaled_cost(8, req),
            true,
        );
        return std::ptr::null_mut();
    }

    match arena().allocate_aligned(req, alignment) {
        Some(ptr) => {
            crate::membrane_state::global_pipeline().register_allocation(ptr as usize, req);
            runtime_policy::observe(
                ApiFamily::Allocator,
                decision.profile,
                runtime_policy::scaled_cost(12, req),
                false,
            );
            ptr.cast()
        }
        None => {
            glibc_rs_core::errno::set_errno(ENOMEM);
            runtime_policy::observe(
                ApiFamily::Allocator,
                decision.profile,
                runtime_policy::scaled_cost(12, req),
                true,
            );
            std::ptr::null_mut()
        }
    }
}
