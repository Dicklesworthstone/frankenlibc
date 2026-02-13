//! ABI layer for selected `<pthread.h>` functions.
//!
//! This bootstrap implementation provides runtime-math routed threading surfaces
//! while full POSIX pthread coverage is still in progress.

#![allow(clippy::missing_safety_doc)]

use std::cell::Cell;
use std::ffi::{c_int, c_void};
use std::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, Ordering};

use frankenlibc_core::pthread::{
    CondvarData, PTHREAD_COND_CLOCK_REALTIME, condvar_broadcast as core_condvar_broadcast,
    condvar_destroy as core_condvar_destroy, condvar_init as core_condvar_init,
    condvar_signal as core_condvar_signal, condvar_wait as core_condvar_wait,
};
use frankenlibc_membrane::check_oracle::CheckStage;
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::malloc_abi::known_remaining;
use crate::runtime_policy;

type StartRoutine = unsafe extern "C" fn(*mut c_void) -> *mut c_void;

// ---------------------------------------------------------------------------
// Futex-backed NORMAL mutex core (bd-z84)
// ---------------------------------------------------------------------------

static MUTEX_SPIN_BRANCHES: AtomicU64 = AtomicU64::new(0);
static MUTEX_WAIT_BRANCHES: AtomicU64 = AtomicU64::new(0);
static MUTEX_WAKE_BRANCHES: AtomicU64 = AtomicU64::new(0);
const MANAGED_MUTEX_MAGIC: u32 = 0x474d_5854; // "GMXT"

thread_local! {
    static THREADING_POLICY_DEPTH: Cell<u32> = const { Cell::new(0) };
}

struct ThreadingPolicyGuard;

impl Drop for ThreadingPolicyGuard {
    fn drop(&mut self) {
        THREADING_POLICY_DEPTH.with(|depth| {
            let current = depth.get();
            depth.set(current.saturating_sub(1));
        });
    }
}

fn enter_threading_policy_guard() -> Option<ThreadingPolicyGuard> {
    THREADING_POLICY_DEPTH.with(|depth| {
        let current = depth.get();
        if current > 0 {
            None
        } else {
            depth.set(current + 1);
            Some(ThreadingPolicyGuard)
        }
    })
}

fn with_threading_policy_guard<T, Fallback, Work>(fallback: Fallback, work: Work) -> T
where
    Fallback: FnOnce() -> T,
    Work: FnOnce() -> T,
{
    if let Some(_guard) = enter_threading_policy_guard() {
        work()
    } else {
        fallback()
    }
}

/// Treats the leading atomic word of `pthread_mutex_t` as our lock state.
/// This avoids recursive dependence on libc's own pthread mutex internals.
fn mutex_word_ptr(mutex: *mut libc::pthread_mutex_t) -> Option<*mut AtomicI32> {
    if mutex.is_null() {
        return None;
    }
    let align = std::mem::align_of::<AtomicI32>();
    if !(mutex as usize).is_multiple_of(align) {
        return None;
    }
    Some(mutex.cast::<AtomicI32>())
}

fn mutex_magic_ptr(mutex: *mut libc::pthread_mutex_t) -> Option<*mut AtomicU32> {
    if mutex.is_null() {
        return None;
    }
    let base = mutex.cast::<u8>();
    let offset = std::mem::size_of::<AtomicI32>();
    // SAFETY: `base` comes from non-null `mutex`; adding a small in-object offset.
    let ptr = unsafe { base.add(offset) };
    let align = std::mem::align_of::<AtomicU32>();
    if !(ptr as usize).is_multiple_of(align) {
        return None;
    }
    Some(ptr.cast::<AtomicU32>())
}

fn is_managed_mutex(mutex: *mut libc::pthread_mutex_t) -> bool {
    let Some(magic_ptr) = mutex_magic_ptr(mutex) else {
        return false;
    };
    // SAFETY: alignment and non-null checked in `mutex_magic_ptr`.
    let magic = unsafe { &*magic_ptr };
    magic.load(Ordering::Acquire) == MANAGED_MUTEX_MAGIC
}

fn mark_managed_mutex(mutex: *mut libc::pthread_mutex_t) -> bool {
    let Some(magic_ptr) = mutex_magic_ptr(mutex) else {
        return false;
    };
    // SAFETY: alignment and non-null checked in `mutex_magic_ptr`.
    let magic = unsafe { &*magic_ptr };
    magic.store(MANAGED_MUTEX_MAGIC, Ordering::Release);
    true
}

fn clear_managed_mutex(mutex: *mut libc::pthread_mutex_t) {
    if let Some(magic_ptr) = mutex_magic_ptr(mutex) {
        // SAFETY: alignment and non-null checked in `mutex_magic_ptr`.
        let magic = unsafe { &*magic_ptr };
        magic.store(0, Ordering::Release);
    }
}

fn condvar_data_ptr(cond: *mut libc::pthread_cond_t) -> Option<*mut CondvarData> {
    if cond.is_null() {
        return None;
    }
    let ptr = cond.cast::<CondvarData>();
    if !(ptr as usize).is_multiple_of(std::mem::align_of::<CondvarData>()) {
        return None;
    }
    Some(ptr)
}

unsafe extern "C" {
    #[link_name = "pthread_self@@GLIBC_2.2.5"]
    fn host_pthread_self_sym() -> libc::pthread_t;
    #[link_name = "pthread_equal@@GLIBC_2.2.5"]
    fn host_pthread_equal_sym(a: libc::pthread_t, b: libc::pthread_t) -> c_int;
    #[link_name = "pthread_create@GLIBC_2.2.5"]
    fn host_pthread_create_sym(
        thread_out: *mut libc::pthread_t,
        attr: *const libc::pthread_attr_t,
        start_routine: StartRoutine,
        arg: *mut c_void,
    ) -> c_int;
    #[link_name = "pthread_join@GLIBC_2.2.5"]
    fn host_pthread_join_sym(thread: libc::pthread_t, retval: *mut *mut c_void) -> c_int;
    #[link_name = "pthread_detach@GLIBC_2.2.5"]
    fn host_pthread_detach_sym(thread: libc::pthread_t) -> c_int;
}

unsafe fn host_pthread_self() -> libc::pthread_t {
    // SAFETY: direct call to glibc symbol with matching signature.
    unsafe { host_pthread_self_sym() }
}

unsafe fn host_pthread_equal(a: libc::pthread_t, b: libc::pthread_t) -> c_int {
    // SAFETY: direct call to glibc symbol with matching signature.
    unsafe { host_pthread_equal_sym(a, b) }
}

unsafe fn host_pthread_create(
    thread_out: *mut libc::pthread_t,
    attr: *const libc::pthread_attr_t,
    start_routine: StartRoutine,
    arg: *mut c_void,
) -> c_int {
    // SAFETY: direct call to glibc symbol with matching signature.
    unsafe { host_pthread_create_sym(thread_out, attr, start_routine, arg) }
}

unsafe fn host_pthread_join(thread: libc::pthread_t, retval: *mut *mut c_void) -> c_int {
    // SAFETY: direct call to glibc symbol with matching signature.
    unsafe { host_pthread_join_sym(thread, retval) }
}

unsafe fn host_pthread_detach(thread: libc::pthread_t) -> c_int {
    // SAFETY: direct call to glibc symbol with matching signature.
    unsafe { host_pthread_detach_sym(thread) }
}

#[cfg(target_os = "linux")]
fn futex_wait_private(word: &AtomicI32, expected: i32) -> c_int {
    // SAFETY: Linux futex syscall with valid userspace address and null timeout.
    unsafe {
        libc::syscall(
            libc::SYS_futex,
            word as *const AtomicI32 as *const i32,
            libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG,
            expected,
            std::ptr::null::<libc::timespec>(),
        ) as c_int
    }
}

#[cfg(target_os = "linux")]
fn futex_wake_private(word: &AtomicI32, count: i32) -> c_int {
    // SAFETY: Linux futex syscall with valid userspace address.
    unsafe {
        libc::syscall(
            libc::SYS_futex,
            word as *const AtomicI32 as *const i32,
            libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG,
            count,
        ) as c_int
    }
}

fn futex_lock_normal(word: &AtomicI32) -> c_int {
    if word
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_ok()
    {
        return 0;
    }

    // Deterministic path: one spin/classification pass before parking.
    MUTEX_SPIN_BRANCHES.fetch_add(1, Ordering::Relaxed);
    loop {
        let observed = word.load(Ordering::Relaxed);
        if observed == 0 {
            if word
                .compare_exchange(0, 2, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return 0;
            }
            continue;
        }

        if observed == 1 {
            let _ = word.compare_exchange(1, 2, Ordering::Acquire, Ordering::Relaxed);
        }

        MUTEX_WAIT_BRANCHES.fetch_add(1, Ordering::Relaxed);

        #[cfg(target_os = "linux")]
        {
            let rc = futex_wait_private(word, 2);
            if rc == 0 {
                continue;
            }
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if errno == libc::EINTR || errno == libc::EAGAIN {
                continue;
            }
            return if errno == 0 { libc::EAGAIN } else { errno };
        }

        #[cfg(not(target_os = "linux"))]
        {
            thread::yield_now();
        }
    }
}

fn futex_trylock_normal(word: &AtomicI32) -> c_int {
    if word
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_ok()
    {
        0
    } else {
        libc::EBUSY
    }
}

fn futex_unlock_normal(word: &AtomicI32) -> c_int {
    let prev = word.swap(0, Ordering::Release);
    match prev {
        0 => libc::EPERM,
        1 => 0,
        _ => {
            MUTEX_WAKE_BRANCHES.fetch_add(1, Ordering::Relaxed);
            #[cfg(target_os = "linux")]
            {
                let _ = futex_wake_private(word, 1);
            }
            0
        }
    }
}

fn reset_mutex_registry_for_tests() {
    MUTEX_SPIN_BRANCHES.store(0, Ordering::Relaxed);
    MUTEX_WAIT_BRANCHES.store(0, Ordering::Relaxed);
    MUTEX_WAKE_BRANCHES.store(0, Ordering::Relaxed);
}

fn mutex_branch_counters() -> (u64, u64, u64) {
    (
        MUTEX_SPIN_BRANCHES.load(Ordering::Relaxed),
        MUTEX_WAIT_BRANCHES.load(Ordering::Relaxed),
        MUTEX_WAKE_BRANCHES.load(Ordering::Relaxed),
    )
}

/// Test hook: reset in-memory futex mutex registry + branch counters.
#[doc(hidden)]
pub fn pthread_mutex_reset_state_for_tests() {
    reset_mutex_registry_for_tests();
}

/// Test hook: snapshot spin/wait/wake branch counters.
#[doc(hidden)]
#[must_use]
pub fn pthread_mutex_branch_counters_for_tests() -> (u64, u64, u64) {
    mutex_branch_counters()
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
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_self() -> libc::pthread_t {
    with_threading_policy_guard(
        || {
            // SAFETY: reentrant path bypasses runtime policy and delegates to host runtime.
            unsafe { host_pthread_self() }
        },
        || {
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
            // SAFETY: call-through to host glibc pthread runtime.
            let id = unsafe { host_pthread_self() };
            record_threading_stage_outcome(&ordering, aligned, recent_page, None);
            runtime_policy::observe(ApiFamily::Threading, decision.profile, 4, false);
            id
        },
    )
}

/// POSIX `pthread_equal`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_equal(a: libc::pthread_t, b: libc::pthread_t) -> c_int {
    with_threading_policy_guard(
        || {
            // SAFETY: reentrant path bypasses runtime policy and delegates to host runtime.
            unsafe { host_pthread_equal(a, b) }
        },
        || {
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
            // SAFETY: call-through to host glibc pthread runtime.
            let equal = unsafe { host_pthread_equal(a, b) };
            record_threading_stage_outcome(&ordering, aligned, recent_page, None);
            runtime_policy::observe(ApiFamily::Threading, decision.profile, 4, false);
            equal
        },
    )
}

/// POSIX `pthread_create`.
///
/// Returns `0` on success, otherwise an errno-style integer.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
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
    with_threading_policy_guard(
        || {
            let start =
                start_routine.unwrap_or_else(|| unreachable!("start routine checked above"));
            // SAFETY: reentrant path bypasses runtime policy and delegates to host runtime.
            unsafe { host_pthread_create(thread_out, _attr, start, arg) }
        },
        || {
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

            let start =
                start_routine.unwrap_or_else(|| unreachable!("start routine checked above"));
            // SAFETY: call-through to host glibc pthread runtime (no recursive Rust std thread spawn).
            let rc = unsafe { host_pthread_create(thread_out, _attr, start, arg) };
            record_threading_stage_outcome(
                &ordering,
                aligned,
                recent_page,
                if rc == 0 {
                    None
                } else {
                    Some(stage_index(&ordering, CheckStage::Arena))
                },
            );
            runtime_policy::observe(ApiFamily::Threading, decision.profile, 40, rc != 0);
            rc
        },
    )
}

/// POSIX `pthread_join`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_join(thread: libc::pthread_t, retval: *mut *mut c_void) -> c_int {
    with_threading_policy_guard(
        || {
            // SAFETY: reentrant path bypasses runtime policy and delegates to host runtime.
            unsafe { host_pthread_join(thread, retval) }
        },
        || {
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
            // SAFETY: call-through to host glibc pthread runtime.
            let rc = unsafe { host_pthread_join(thread, retval) };
            record_threading_stage_outcome(
                &ordering,
                aligned,
                recent_page,
                if rc == 0 {
                    None
                } else {
                    Some(stage_index(&ordering, CheckStage::Arena))
                },
            );
            runtime_policy::observe(ApiFamily::Threading, decision.profile, 24, rc != 0);
            rc
        },
    )
}

/// POSIX `pthread_detach`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_detach(thread: libc::pthread_t) -> c_int {
    with_threading_policy_guard(
        || {
            // SAFETY: reentrant path bypasses runtime policy and delegates to host runtime.
            unsafe { host_pthread_detach(thread) }
        },
        || {
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
            // SAFETY: call-through to host glibc pthread runtime.
            let rc = unsafe { host_pthread_detach(thread) };
            record_threading_stage_outcome(
                &ordering,
                aligned,
                recent_page,
                if rc == 0 {
                    None
                } else {
                    Some(stage_index(&ordering, CheckStage::Arena))
                },
            );
            runtime_policy::observe(ApiFamily::Threading, decision.profile, 8, rc != 0);
            rc
        },
    )
}

// ===========================================================================
// Mutex operations
// ===========================================================================

/// POSIX `pthread_mutex_init`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutex_init(
    mutex: *mut libc::pthread_mutex_t,
    attr: *const libc::pthread_mutexattr_t,
) -> c_int {
    if mutex.is_null() {
        return libc::EINVAL;
    }

    if !attr.is_null() {
        clear_managed_mutex(mutex);
        return libc::EINVAL;
    }

    if let Some(word_ptr) = mutex_word_ptr(mutex) {
        // SAFETY: `word_ptr` is alignment-checked and points to caller-owned mutex storage.
        let word = unsafe { &*word_ptr };
        word.store(0, Ordering::Release);
        if mark_managed_mutex(mutex) {
            return 0;
        }
    }
    clear_managed_mutex(mutex);
    libc::EINVAL
}

/// POSIX `pthread_mutex_destroy`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutex_destroy(mutex: *mut libc::pthread_mutex_t) -> c_int {
    if mutex.is_null() {
        return libc::EINVAL;
    }

    if !is_managed_mutex(mutex) {
        return libc::EINVAL;
    }

    let Some(word_ptr) = mutex_word_ptr(mutex) else {
        clear_managed_mutex(mutex);
        return libc::EINVAL;
    };
    // SAFETY: `word_ptr` is alignment-checked and points to caller-owned mutex storage.
    let word = unsafe { &*word_ptr };
    if word.load(Ordering::Acquire) != 0 {
        return libc::EBUSY;
    }

    clear_managed_mutex(mutex);
    0
}

/// POSIX `pthread_mutex_lock`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutex_lock(mutex: *mut libc::pthread_mutex_t) -> c_int {
    if mutex.is_null() {
        return libc::EINVAL;
    }

    if !is_managed_mutex(mutex) {
        return libc::EINVAL;
    }
    let Some(word_ptr) = mutex_word_ptr(mutex) else {
        return libc::EINVAL;
    };
    // SAFETY: managed mutexes use our futex word in the leading i32.
    let word = unsafe { &*word_ptr };
    futex_lock_normal(word)
}

/// POSIX `pthread_mutex_trylock`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutex_trylock(mutex: *mut libc::pthread_mutex_t) -> c_int {
    if mutex.is_null() {
        return libc::EINVAL;
    }

    if !is_managed_mutex(mutex) {
        return libc::EINVAL;
    }
    let Some(word_ptr) = mutex_word_ptr(mutex) else {
        return libc::EINVAL;
    };
    // SAFETY: managed mutexes use our futex word in the leading i32.
    let word = unsafe { &*word_ptr };
    futex_trylock_normal(word)
}

/// POSIX `pthread_mutex_unlock`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutex_unlock(mutex: *mut libc::pthread_mutex_t) -> c_int {
    if mutex.is_null() {
        return libc::EINVAL;
    }

    if !is_managed_mutex(mutex) {
        return libc::EINVAL;
    }
    let Some(word_ptr) = mutex_word_ptr(mutex) else {
        return libc::EINVAL;
    };
    // SAFETY: managed mutexes use our futex word in the leading i32.
    let word = unsafe { &*word_ptr };
    futex_unlock_normal(word)
}

// ===========================================================================
// Condition variable operations
// ===========================================================================

/// POSIX `pthread_cond_init`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_cond_init(
    cond: *mut libc::pthread_cond_t,
    attr: *const libc::pthread_condattr_t,
) -> c_int {
    let Some(cond_ptr) = condvar_data_ptr(cond) else {
        return libc::EINVAL;
    };
    if !attr.is_null() {
        return libc::EINVAL;
    }
    // SAFETY: pointer validated/aligned above and points into caller-owned pthread_cond_t.
    unsafe { core_condvar_init(cond_ptr, PTHREAD_COND_CLOCK_REALTIME) }
}

/// POSIX `pthread_cond_destroy`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_cond_destroy(cond: *mut libc::pthread_cond_t) -> c_int {
    let Some(cond_ptr) = condvar_data_ptr(cond) else {
        return libc::EINVAL;
    };
    // SAFETY: pointer validated/aligned above and points into caller-owned pthread_cond_t.
    unsafe { core_condvar_destroy(cond_ptr) }
}

/// POSIX `pthread_cond_wait`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_cond_wait(
    cond: *mut libc::pthread_cond_t,
    mutex: *mut libc::pthread_mutex_t,
) -> c_int {
    if cond.is_null() || mutex.is_null() {
        return libc::EINVAL;
    }
    if !is_managed_mutex(mutex) {
        return libc::EINVAL;
    }
    let Some(cond_ptr) = condvar_data_ptr(cond) else {
        return libc::EINVAL;
    };
    let Some(word_ptr) = mutex_word_ptr(mutex) else {
        return libc::EINVAL;
    };
    // SAFETY: condvar pointer and mutex futex word pointer are validated/aligned and caller-owned.
    unsafe { core_condvar_wait(cond_ptr, word_ptr.cast::<u32>() as *const u32) }
}

/// POSIX `pthread_cond_signal`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_cond_signal(cond: *mut libc::pthread_cond_t) -> c_int {
    let Some(cond_ptr) = condvar_data_ptr(cond) else {
        return libc::EINVAL;
    };
    // SAFETY: pointer validated/aligned above and points into caller-owned pthread_cond_t.
    unsafe { core_condvar_signal(cond_ptr) }
}

/// POSIX `pthread_cond_broadcast`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_cond_broadcast(cond: *mut libc::pthread_cond_t) -> c_int {
    let Some(cond_ptr) = condvar_data_ptr(cond) else {
        return libc::EINVAL;
    };
    // SAFETY: pointer validated/aligned above and points into caller-owned pthread_cond_t.
    unsafe { core_condvar_broadcast(cond_ptr) }
}

// ===========================================================================
// Reader-writer lock operations
// ===========================================================================

/// POSIX `pthread_rwlock_init`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlock_init(
    rwlock: *mut libc::pthread_rwlock_t,
    attr: *const libc::pthread_rwlockattr_t,
) -> c_int {
    if rwlock.is_null() {
        return libc::EINVAL;
    }
    // SAFETY: direct passthrough to host libc with validated pointer.
    unsafe { libc::pthread_rwlock_init(rwlock, attr) }
}

/// POSIX `pthread_rwlock_destroy`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlock_destroy(rwlock: *mut libc::pthread_rwlock_t) -> c_int {
    if rwlock.is_null() {
        return libc::EINVAL;
    }
    // SAFETY: direct passthrough to host libc with validated pointer.
    unsafe { libc::pthread_rwlock_destroy(rwlock) }
}

/// POSIX `pthread_rwlock_rdlock`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlock_rdlock(rwlock: *mut libc::pthread_rwlock_t) -> c_int {
    if rwlock.is_null() {
        return libc::EINVAL;
    }
    // SAFETY: direct passthrough to host libc with validated pointer.
    unsafe { libc::pthread_rwlock_rdlock(rwlock) }
}

/// POSIX `pthread_rwlock_wrlock`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlock_wrlock(rwlock: *mut libc::pthread_rwlock_t) -> c_int {
    if rwlock.is_null() {
        return libc::EINVAL;
    }
    // SAFETY: direct passthrough to host libc with validated pointer.
    unsafe { libc::pthread_rwlock_wrlock(rwlock) }
}

/// POSIX `pthread_rwlock_unlock`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlock_unlock(rwlock: *mut libc::pthread_rwlock_t) -> c_int {
    if rwlock.is_null() {
        return libc::EINVAL;
    }
    // SAFETY: direct passthrough to host libc with validated pointer.
    unsafe { libc::pthread_rwlock_unlock(rwlock) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::time::Duration;

    fn alloc_mutex_ptr() -> *mut libc::pthread_mutex_t {
        let boxed: Box<libc::pthread_mutex_t> = Box::new(unsafe { std::mem::zeroed() });
        Box::into_raw(boxed)
    }

    unsafe fn free_mutex_ptr(ptr: *mut libc::pthread_mutex_t) {
        // SAFETY: pointer was returned by `Box::into_raw` in `alloc_mutex_ptr`.
        unsafe { drop(Box::from_raw(ptr)) };
    }

    #[test]
    fn futex_mutex_roundtrip_and_trylock_busy() {
        reset_mutex_registry_for_tests();
        let mutex = alloc_mutex_ptr();

        // SAFETY: ABI functions operate on opaque pointer identity in this implementation.
        unsafe {
            assert_eq!(pthread_mutex_init(mutex, std::ptr::null()), 0);
            assert_eq!(pthread_mutex_lock(mutex), 0);
            assert_eq!(pthread_mutex_trylock(mutex), libc::EBUSY);
            assert_eq!(pthread_mutex_unlock(mutex), 0);
            assert_eq!(pthread_mutex_destroy(mutex), 0);
            free_mutex_ptr(mutex);
        }
    }

    #[test]
    fn futex_mutex_contention_increments_wait_and_wake_counters() {
        reset_mutex_registry_for_tests();
        let mutex = alloc_mutex_ptr();

        // SAFETY: ABI functions operate on opaque pointer identity in this implementation.
        unsafe {
            assert_eq!(pthread_mutex_init(mutex, std::ptr::null()), 0);
            assert_eq!(pthread_mutex_lock(mutex), 0);
        }

        let before = mutex_branch_counters();
        let barrier = Arc::new(Barrier::new(2));
        let barrier_worker = Arc::clone(&barrier);
        let mutex_addr = mutex as usize;
        let handle = std::thread::spawn(move || {
            barrier_worker.wait();
            // SAFETY: pointer identity is stable for test lifetime.
            unsafe {
                assert_eq!(
                    pthread_mutex_lock(mutex_addr as *mut libc::pthread_mutex_t),
                    0
                );
                assert_eq!(
                    pthread_mutex_unlock(mutex_addr as *mut libc::pthread_mutex_t),
                    0
                );
            }
        });

        barrier.wait();
        std::thread::sleep(Duration::from_millis(10));
        // SAFETY: pointer identity is stable for test lifetime.
        unsafe { assert_eq!(pthread_mutex_unlock(mutex), 0) };
        handle.join().unwrap();
        let after = mutex_branch_counters();

        assert!(
            after.0 >= before.0 + 1,
            "spin branch counter did not increase: before={before:?} after={after:?}"
        );
        assert!(
            after.1 >= before.1 + 1,
            "wait branch counter did not increase: before={before:?} after={after:?}"
        );
        assert!(
            after.2 >= before.2 + 1,
            "wake branch counter did not increase: before={before:?} after={after:?}"
        );

        // SAFETY: pointer identity is stable for test lifetime.
        unsafe {
            assert_eq!(pthread_mutex_destroy(mutex), 0);
            free_mutex_ptr(mutex);
        }
    }
}
