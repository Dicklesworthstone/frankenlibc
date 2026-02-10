//! ABI layer for selected `<pthread.h>` functions.
//!
//! This bootstrap implementation provides runtime-math routed threading surfaces
//! while full POSIX pthread coverage is still in progress.

#![allow(clippy::missing_safety_doc)]

use std::cell::Cell;
use std::collections::HashMap;
use std::ffi::{c_int, c_void};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::thread;

use glibc_rs_membrane::check_oracle::CheckStage;
use glibc_rs_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::malloc_abi::known_remaining;
use crate::runtime_policy;

type JoinTable = HashMap<libc::pthread_t, thread::JoinHandle<usize>>;
type StartRoutine = unsafe extern "C" fn(*mut c_void) -> *mut c_void;

static NEXT_THREAD_ID: AtomicU64 = AtomicU64::new(1);

thread_local! {
    static SELF_ID: Cell<libc::pthread_t> = const { Cell::new(0) };
}

fn join_table() -> &'static Mutex<JoinTable> {
    static TABLE: OnceLock<Mutex<JoinTable>> = OnceLock::new();
    TABLE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn lock_join_table() -> std::sync::MutexGuard<'static, JoinTable> {
    match join_table().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn fresh_thread_id() -> libc::pthread_t {
    NEXT_THREAD_ID.fetch_add(1, Ordering::Relaxed) as libc::pthread_t
}

fn current_thread_id() -> libc::pthread_t {
    SELF_ID.with(|slot| {
        let existing = slot.get();
        if existing != 0 {
            return existing;
        }
        let new_id = fresh_thread_id();
        slot.set(new_id);
        new_id
    })
}

#[inline]
fn stage_index(ordering: &[CheckStage; 7], stage: CheckStage) -> usize {
    ordering.iter().position(|s| *s == stage).unwrap_or(0)
}

#[inline]
fn threading_stage_context(addr1: usize, addr2: usize) -> (bool, bool, [CheckStage; 7]) {
    let aligned = ((addr1 | addr2) & 0x7) == 0;
    let recent_page = (addr1 != 0 && known_remaining(addr1).is_some())
        || (addr2 != 0 && known_remaining(addr2).is_some());
    let ordering = runtime_policy::check_ordering(ApiFamily::Threading, aligned, recent_page);
    (aligned, recent_page, ordering)
}

#[inline]
fn record_threading_stage_outcome(
    ordering: &[CheckStage; 7],
    aligned: bool,
    recent_page: bool,
    exit_stage: Option<usize>,
) {
    runtime_policy::note_check_order_outcome(
        ApiFamily::Threading,
        aligned,
        recent_page,
        ordering,
        exit_stage,
    );
}

/// POSIX `pthread_self`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_self() -> libc::pthread_t {
    let (aligned, recent_page, ordering) = threading_stage_context(0, 0);
    let (_, decision) = runtime_policy::decide(ApiFamily::Threading, 0, 0, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        record_threading_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Arena)),
        );
        runtime_policy::observe(ApiFamily::Threading, decision.profile, 4, true);
        return 0;
    }
    let id = current_thread_id();
    record_threading_stage_outcome(&ordering, aligned, recent_page, None);
    runtime_policy::observe(ApiFamily::Threading, decision.profile, 4, false);
    id
}

/// POSIX `pthread_equal`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_equal(a: libc::pthread_t, b: libc::pthread_t) -> c_int {
    let (aligned, recent_page, ordering) = threading_stage_context(a as usize, b as usize);
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Threading, a as usize, 0, false, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        record_threading_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Arena)),
        );
        runtime_policy::observe(ApiFamily::Threading, decision.profile, 4, true);
        return 0;
    }
    let equal = if a == b { 1 } else { 0 };
    record_threading_stage_outcome(&ordering, aligned, recent_page, None);
    runtime_policy::observe(ApiFamily::Threading, decision.profile, 4, false);
    equal
}

/// POSIX `pthread_create`.
///
/// Returns `0` on success, otherwise an errno-style integer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_create(
    thread_out: *mut libc::pthread_t,
    _attr: *const libc::pthread_attr_t,
    start_routine: Option<StartRoutine>,
    arg: *mut c_void,
) -> c_int {
    let (aligned, recent_page, ordering) =
        threading_stage_context(thread_out as usize, arg as usize);
    if thread_out.is_null() || start_routine.is_none() {
        record_threading_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(
                &ordering,
                if thread_out.is_null() {
                    CheckStage::Null
                } else {
                    CheckStage::Bounds
                },
            )),
        );
        return libc::EINVAL;
    }
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Threading, arg as usize, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        record_threading_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Arena)),
        );
        runtime_policy::observe(ApiFamily::Threading, decision.profile, 16, true);
        return libc::EAGAIN;
    }

    let tid = fresh_thread_id();
    let start = match start_routine {
        Some(start) => start,
        None => return libc::EINVAL,
    };
    let arg_addr = arg as usize;
    let spawned = thread::Builder::new().spawn(move || {
        SELF_ID.with(|slot| slot.set(tid));
        let arg_ptr = arg_addr as *mut c_void;
        // SAFETY: pthread_create contract supplies valid start routine pointer.
        let retval = unsafe { start(arg_ptr) };
        retval as usize
    });

    match spawned {
        Ok(handle) => {
            // SAFETY: `thread_out` was validated non-null above.
            unsafe { *thread_out = tid };
            lock_join_table().insert(tid, handle);
            record_threading_stage_outcome(&ordering, aligned, recent_page, None);
            runtime_policy::observe(ApiFamily::Threading, decision.profile, 40, false);
            0
        }
        Err(_) => {
            record_threading_stage_outcome(
                &ordering,
                aligned,
                recent_page,
                Some(stage_index(&ordering, CheckStage::Arena)),
            );
            runtime_policy::observe(ApiFamily::Threading, decision.profile, 40, true);
            libc::EAGAIN
        }
    }
}

/// POSIX `pthread_join`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_join(thread: libc::pthread_t, retval: *mut *mut c_void) -> c_int {
    let (aligned, recent_page, ordering) =
        threading_stage_context(thread as usize, retval as usize);
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Threading, thread as usize, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        record_threading_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Arena)),
        );
        runtime_policy::observe(ApiFamily::Threading, decision.profile, 24, true);
        return libc::EINVAL;
    }

    let handle = lock_join_table().remove(&thread);
    let Some(handle) = handle else {
        record_threading_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Arena)),
        );
        runtime_policy::observe(ApiFamily::Threading, decision.profile, 24, true);
        return libc::ESRCH;
    };

    match handle.join() {
        Ok(rv) => {
            if !retval.is_null() {
                // SAFETY: caller-provided output pointer.
                unsafe { *retval = rv as *mut c_void };
            }
            record_threading_stage_outcome(&ordering, aligned, recent_page, None);
            runtime_policy::observe(ApiFamily::Threading, decision.profile, 24, false);
            0
        }
        Err(_) => {
            record_threading_stage_outcome(
                &ordering,
                aligned,
                recent_page,
                Some(stage_index(&ordering, CheckStage::Arena)),
            );
            runtime_policy::observe(ApiFamily::Threading, decision.profile, 24, true);
            libc::EDEADLK
        }
    }
}

/// POSIX `pthread_detach`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_detach(thread: libc::pthread_t) -> c_int {
    let (aligned, recent_page, ordering) = threading_stage_context(thread as usize, 0);
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Threading, thread as usize, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        record_threading_stage_outcome(
            &ordering,
            aligned,
            recent_page,
            Some(stage_index(&ordering, CheckStage::Arena)),
        );
        runtime_policy::observe(ApiFamily::Threading, decision.profile, 8, true);
        return libc::EINVAL;
    }

    let removed = lock_join_table().remove(&thread);
    let adverse = removed.is_none();
    record_threading_stage_outcome(
        &ordering,
        aligned,
        recent_page,
        if adverse {
            Some(stage_index(&ordering, CheckStage::Arena))
        } else {
            None
        },
    );
    runtime_policy::observe(ApiFamily::Threading, decision.profile, 8, adverse);
    if adverse { libc::ESRCH } else { 0 }
}

// ===========================================================================
// Mutex operations
// ===========================================================================

/// POSIX `pthread_mutex_init`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutex_init(
    mutex: *mut libc::pthread_mutex_t,
    attr: *const libc::pthread_mutexattr_t,
) -> c_int {
    if mutex.is_null() {
        return libc::EINVAL;
    }
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Threading, mutex as usize, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Threading, decision.profile, 10, true);
        return libc::EPERM;
    }

    let rc = unsafe { libc::pthread_mutex_init(mutex, attr) };
    let adverse = rc != 0;
    runtime_policy::observe(ApiFamily::Threading, decision.profile, 10, adverse);
    rc
}

/// POSIX `pthread_mutex_destroy`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutex_destroy(mutex: *mut libc::pthread_mutex_t) -> c_int {
    if mutex.is_null() {
        return libc::EINVAL;
    }
    let (mode, decision) =
        runtime_policy::decide(ApiFamily::Threading, mutex as usize, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Threading, decision.profile, 10, true);
        return libc::EPERM;
    }

    let rc = unsafe { libc::pthread_mutex_destroy(mutex) };

    // Hardened: if EBUSY, force-unlock then retry destroy.
    if rc == libc::EBUSY && mode.heals_enabled() {
        let _ = unsafe { libc::pthread_mutex_unlock(mutex) };
        let rc2 = unsafe { libc::pthread_mutex_destroy(mutex) };
        runtime_policy::observe(ApiFamily::Threading, decision.profile, 15, rc2 != 0);
        return rc2;
    }

    runtime_policy::observe(ApiFamily::Threading, decision.profile, 10, rc != 0);
    rc
}

/// POSIX `pthread_mutex_lock`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutex_lock(mutex: *mut libc::pthread_mutex_t) -> c_int {
    if mutex.is_null() {
        return libc::EINVAL;
    }
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Threading, mutex as usize, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Threading, decision.profile, 12, true);
        return libc::EPERM;
    }

    let rc = unsafe { libc::pthread_mutex_lock(mutex) };
    runtime_policy::observe(ApiFamily::Threading, decision.profile, 12, rc != 0);
    rc
}

/// POSIX `pthread_mutex_trylock`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutex_trylock(mutex: *mut libc::pthread_mutex_t) -> c_int {
    if mutex.is_null() {
        return libc::EINVAL;
    }
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Threading, mutex as usize, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Threading, decision.profile, 8, true);
        return libc::EPERM;
    }

    let rc = unsafe { libc::pthread_mutex_trylock(mutex) };
    // EBUSY is not adverse — it's normal for trylock.
    let adverse = rc != 0 && rc != libc::EBUSY;
    runtime_policy::observe(ApiFamily::Threading, decision.profile, 8, adverse);
    rc
}

/// POSIX `pthread_mutex_unlock`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutex_unlock(mutex: *mut libc::pthread_mutex_t) -> c_int {
    if mutex.is_null() {
        return libc::EINVAL;
    }
    let (mode, decision) =
        runtime_policy::decide(ApiFamily::Threading, mutex as usize, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Threading, decision.profile, 8, true);
        return libc::EPERM;
    }

    let rc = unsafe { libc::pthread_mutex_unlock(mutex) };

    // Hardened: EPERM (not owner) → silently ignore.
    if rc == libc::EPERM && mode.heals_enabled() {
        runtime_policy::observe(ApiFamily::Threading, decision.profile, 8, false);
        return 0;
    }

    runtime_policy::observe(ApiFamily::Threading, decision.profile, 8, rc != 0);
    rc
}

// ===========================================================================
// Condition variable operations
// ===========================================================================

/// POSIX `pthread_cond_init`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_cond_init(
    cond: *mut libc::pthread_cond_t,
    attr: *const libc::pthread_condattr_t,
) -> c_int {
    if cond.is_null() {
        return libc::EINVAL;
    }
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Threading, cond as usize, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Threading, decision.profile, 10, true);
        return libc::EPERM;
    }

    let rc = unsafe { libc::pthread_cond_init(cond, attr) };
    runtime_policy::observe(ApiFamily::Threading, decision.profile, 10, rc != 0);
    rc
}

/// POSIX `pthread_cond_destroy`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_cond_destroy(cond: *mut libc::pthread_cond_t) -> c_int {
    if cond.is_null() {
        return libc::EINVAL;
    }
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Threading, cond as usize, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Threading, decision.profile, 10, true);
        return libc::EPERM;
    }

    let rc = unsafe { libc::pthread_cond_destroy(cond) };
    runtime_policy::observe(ApiFamily::Threading, decision.profile, 10, rc != 0);
    rc
}

/// POSIX `pthread_cond_wait`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_cond_wait(
    cond: *mut libc::pthread_cond_t,
    mutex: *mut libc::pthread_mutex_t,
) -> c_int {
    if cond.is_null() || mutex.is_null() {
        return libc::EINVAL;
    }
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Threading, cond as usize, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Threading, decision.profile, 20, true);
        return libc::EPERM;
    }

    let rc = unsafe { libc::pthread_cond_wait(cond, mutex) };
    runtime_policy::observe(ApiFamily::Threading, decision.profile, 20, rc != 0);
    rc
}

/// POSIX `pthread_cond_signal`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_cond_signal(cond: *mut libc::pthread_cond_t) -> c_int {
    if cond.is_null() {
        return libc::EINVAL;
    }
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Threading, cond as usize, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Threading, decision.profile, 8, true);
        return libc::EPERM;
    }

    let rc = unsafe { libc::pthread_cond_signal(cond) };
    runtime_policy::observe(ApiFamily::Threading, decision.profile, 8, rc != 0);
    rc
}

/// POSIX `pthread_cond_broadcast`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_cond_broadcast(cond: *mut libc::pthread_cond_t) -> c_int {
    if cond.is_null() {
        return libc::EINVAL;
    }
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Threading, cond as usize, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Threading, decision.profile, 10, true);
        return libc::EPERM;
    }

    let rc = unsafe { libc::pthread_cond_broadcast(cond) };
    runtime_policy::observe(ApiFamily::Threading, decision.profile, 10, rc != 0);
    rc
}

// ===========================================================================
// Reader-writer lock operations
// ===========================================================================

/// POSIX `pthread_rwlock_init`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_rwlock_init(
    rwlock: *mut libc::pthread_rwlock_t,
    attr: *const libc::pthread_rwlockattr_t,
) -> c_int {
    if rwlock.is_null() {
        return libc::EINVAL;
    }
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Threading, rwlock as usize, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Threading, decision.profile, 10, true);
        return libc::EPERM;
    }

    let rc = unsafe { libc::pthread_rwlock_init(rwlock, attr) };
    runtime_policy::observe(ApiFamily::Threading, decision.profile, 10, rc != 0);
    rc
}

/// POSIX `pthread_rwlock_destroy`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_rwlock_destroy(rwlock: *mut libc::pthread_rwlock_t) -> c_int {
    if rwlock.is_null() {
        return libc::EINVAL;
    }
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Threading, rwlock as usize, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Threading, decision.profile, 10, true);
        return libc::EPERM;
    }

    let rc = unsafe { libc::pthread_rwlock_destroy(rwlock) };
    runtime_policy::observe(ApiFamily::Threading, decision.profile, 10, rc != 0);
    rc
}

/// POSIX `pthread_rwlock_rdlock`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_rwlock_rdlock(rwlock: *mut libc::pthread_rwlock_t) -> c_int {
    if rwlock.is_null() {
        return libc::EINVAL;
    }
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Threading, rwlock as usize, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Threading, decision.profile, 12, true);
        return libc::EPERM;
    }

    let rc = unsafe { libc::pthread_rwlock_rdlock(rwlock) };
    runtime_policy::observe(ApiFamily::Threading, decision.profile, 12, rc != 0);
    rc
}

/// POSIX `pthread_rwlock_wrlock`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_rwlock_wrlock(rwlock: *mut libc::pthread_rwlock_t) -> c_int {
    if rwlock.is_null() {
        return libc::EINVAL;
    }
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Threading, rwlock as usize, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Threading, decision.profile, 12, true);
        return libc::EPERM;
    }

    let rc = unsafe { libc::pthread_rwlock_wrlock(rwlock) };
    runtime_policy::observe(ApiFamily::Threading, decision.profile, 12, rc != 0);
    rc
}

/// POSIX `pthread_rwlock_unlock`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_rwlock_unlock(rwlock: *mut libc::pthread_rwlock_t) -> c_int {
    if rwlock.is_null() {
        return libc::EINVAL;
    }
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Threading, rwlock as usize, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Threading, decision.profile, 8, true);
        return libc::EPERM;
    }

    let rc = unsafe { libc::pthread_rwlock_unlock(rwlock) };
    runtime_policy::observe(ApiFamily::Threading, decision.profile, 8, rc != 0);
    rc
}
