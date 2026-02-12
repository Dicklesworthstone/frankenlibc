//! ABI layer for selected `<pthread.h>` functions.
//!
//! This bootstrap implementation provides runtime-math routed threading surfaces
//! while full POSIX pthread coverage is still in progress.

#![allow(clippy::missing_safety_doc)]

use std::cell::Cell;
use std::collections::HashMap;
use std::ffi::{c_int, c_void};
use std::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::thread;

use frankenlibc_membrane::check_oracle::CheckStage;
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

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

// ---------------------------------------------------------------------------
// Futex-backed NORMAL mutex core (bd-z84)
// ---------------------------------------------------------------------------

static MUTEX_SPIN_BRANCHES: AtomicU64 = AtomicU64::new(0);
static MUTEX_WAIT_BRANCHES: AtomicU64 = AtomicU64::new(0);
static MUTEX_WAKE_BRANCHES: AtomicU64 = AtomicU64::new(0);
const MANAGED_MUTEX_MAGIC: u32 = 0x474d_5854; // "GMXT"

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

unsafe extern "C" {
    #[link_name = "__pthread_mutex_init"]
    fn host_pthread_mutex_init_sym(
        mutex: *mut libc::pthread_mutex_t,
        attr: *const libc::pthread_mutexattr_t,
    ) -> c_int;
    #[link_name = "__pthread_mutex_destroy"]
    fn host_pthread_mutex_destroy_sym(mutex: *mut libc::pthread_mutex_t) -> c_int;
    #[link_name = "__pthread_mutex_lock"]
    fn host_pthread_mutex_lock_sym(mutex: *mut libc::pthread_mutex_t) -> c_int;
    #[link_name = "__pthread_mutex_trylock"]
    fn host_pthread_mutex_trylock_sym(mutex: *mut libc::pthread_mutex_t) -> c_int;
    #[link_name = "__pthread_mutex_unlock"]
    fn host_pthread_mutex_unlock_sym(mutex: *mut libc::pthread_mutex_t) -> c_int;
}

unsafe fn host_pthread_mutex_init(
    mutex: *mut libc::pthread_mutex_t,
    attr: *const libc::pthread_mutexattr_t,
) -> c_int {
    // SAFETY: direct call to glibc internal symbol with matching signature.
    unsafe { host_pthread_mutex_init_sym(mutex, attr) }
}

unsafe fn host_pthread_mutex_destroy(mutex: *mut libc::pthread_mutex_t) -> c_int {
    // SAFETY: direct call to glibc internal symbol with matching signature.
    unsafe { host_pthread_mutex_destroy_sym(mutex) }
}

unsafe fn host_pthread_mutex_lock(mutex: *mut libc::pthread_mutex_t) -> c_int {
    // SAFETY: direct call to glibc internal symbol with matching signature.
    unsafe { host_pthread_mutex_lock_sym(mutex) }
}

unsafe fn host_pthread_mutex_trylock(mutex: *mut libc::pthread_mutex_t) -> c_int {
    // SAFETY: direct call to glibc internal symbol with matching signature.
    unsafe { host_pthread_mutex_trylock_sym(mutex) }
}

unsafe fn host_pthread_mutex_unlock(mutex: *mut libc::pthread_mutex_t) -> c_int {
    // SAFETY: direct call to glibc internal symbol with matching signature.
    unsafe { host_pthread_mutex_unlock_sym(mutex) }
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
    if attr.is_null()
        && let Some(word_ptr) = mutex_word_ptr(mutex)
    {
        // SAFETY: `word_ptr` is alignment-checked and points to caller-owned mutex storage.
        let word = unsafe { &*word_ptr };
        word.store(0, Ordering::Release);
        if mark_managed_mutex(mutex) {
            return 0;
        }
    }

    clear_managed_mutex(mutex);
    // SAFETY: explicit fallback to host pthread mutex initialization.
    unsafe { host_pthread_mutex_init(mutex, attr) }
}

/// POSIX `pthread_mutex_destroy`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutex_destroy(mutex: *mut libc::pthread_mutex_t) -> c_int {
    if mutex.is_null() {
        return libc::EINVAL;
    }

    if is_managed_mutex(mutex) {
        let Some(word_ptr) = mutex_word_ptr(mutex) else {
            clear_managed_mutex(mutex);
            // SAFETY: fallback for malformed managed marker state.
            return unsafe { host_pthread_mutex_destroy(mutex) };
        };
        // SAFETY: `word_ptr` is alignment-checked and points to caller-owned mutex storage.
        let word = unsafe { &*word_ptr };
        let locked = word.load(Ordering::Acquire) != 0;
        if locked {
            return libc::EBUSY;
        }
        clear_managed_mutex(mutex);
        return 0;
    }

    // SAFETY: forwarding foreign/static mutexes to host implementation.
    unsafe { host_pthread_mutex_destroy(mutex) }
}

/// POSIX `pthread_mutex_lock`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutex_lock(mutex: *mut libc::pthread_mutex_t) -> c_int {
    if mutex.is_null() {
        return libc::EINVAL;
    }

    let Some(word_ptr) = mutex_word_ptr(mutex) else {
        // SAFETY: fallback when we cannot safely interpret mutex storage.
        return unsafe { host_pthread_mutex_lock(mutex) };
    };
    if !is_managed_mutex(mutex) {
        let _ = mark_managed_mutex(mutex);
    }
    // SAFETY: `word_ptr` is alignment-checked and points to caller-owned mutex storage.
    let word = unsafe { &*word_ptr };
    futex_lock_normal(word)
}

/// POSIX `pthread_mutex_trylock`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutex_trylock(mutex: *mut libc::pthread_mutex_t) -> c_int {
    if mutex.is_null() {
        return libc::EINVAL;
    }

    let Some(word_ptr) = mutex_word_ptr(mutex) else {
        // SAFETY: fallback when we cannot safely interpret mutex storage.
        return unsafe { host_pthread_mutex_trylock(mutex) };
    };
    if !is_managed_mutex(mutex) {
        let _ = mark_managed_mutex(mutex);
    }
    // SAFETY: `word_ptr` is alignment-checked and points to caller-owned mutex storage.
    let word = unsafe { &*word_ptr };
    futex_trylock_normal(word)
}

/// POSIX `pthread_mutex_unlock`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutex_unlock(mutex: *mut libc::pthread_mutex_t) -> c_int {
    if mutex.is_null() {
        return libc::EINVAL;
    }

    let Some(word_ptr) = mutex_word_ptr(mutex) else {
        // SAFETY: fallback when we cannot safely interpret mutex storage.
        return unsafe { host_pthread_mutex_unlock(mutex) };
    };
    if !is_managed_mutex(mutex) {
        let _ = mark_managed_mutex(mutex);
    }
    // SAFETY: `word_ptr` is alignment-checked and points to caller-owned mutex storage.
    let word = unsafe { &*word_ptr };
    futex_unlock_normal(word)
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
