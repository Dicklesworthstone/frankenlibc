//! ABI layer for selected `<pthread.h>` functions.
//!
//! This bootstrap implementation provides runtime-math routed threading surfaces
//! while full POSIX pthread coverage is still in progress.

#![allow(clippy::missing_safety_doc)]

use std::cell::Cell;
use std::collections::HashMap;
use std::ffi::{c_int, c_void};
use std::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};

use frankenlibc_core::pthread::tls::{
    PthreadKey, pthread_key_create as core_pthread_key_create,
    pthread_key_delete as core_pthread_key_delete,
};
#[cfg(target_arch = "x86_64")]
use frankenlibc_core::pthread::tls::{
    pthread_getspecific as core_pthread_getspecific,
    pthread_setspecific as core_pthread_setspecific,
};
use frankenlibc_core::pthread::{
    CondvarData, PTHREAD_COND_CLOCK_REALTIME, THREAD_RUNNING, THREAD_STARTING, ThreadHandle,
    condvar_broadcast as core_condvar_broadcast, condvar_destroy as core_condvar_destroy,
    condvar_init as core_condvar_init, condvar_signal as core_condvar_signal,
    condvar_timedwait as core_condvar_timedwait, condvar_wait as core_condvar_wait,
    create_thread as core_create_thread, detach_thread as core_detach_thread,
    join_thread as core_join_thread, self_tid as core_self_tid,
};
use frankenlibc_membrane::check_oracle::CheckStage;
use frankenlibc_membrane::runtime_math::ApiFamily;

use crate::malloc_abi::known_remaining;
use crate::runtime_policy;

type StartRoutine = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type HostPthreadCreateFn = unsafe extern "C" fn(
    *mut libc::pthread_t,
    *const libc::pthread_attr_t,
    Option<StartRoutine>,
    *mut c_void,
) -> c_int;
type HostPthreadJoinFn = unsafe extern "C" fn(libc::pthread_t, *mut *mut c_void) -> c_int;
type HostPthreadDetachFn = unsafe extern "C" fn(libc::pthread_t) -> c_int;
type HostPthreadSelfFn = unsafe extern "C" fn() -> libc::pthread_t;
type HostPthreadEqualFn = unsafe extern "C" fn(libc::pthread_t, libc::pthread_t) -> c_int;
type HostPthreadMutexInitFn =
    unsafe extern "C" fn(*mut libc::pthread_mutex_t, *const libc::pthread_mutexattr_t) -> c_int;
type HostPthreadMutexDestroyFn = unsafe extern "C" fn(*mut libc::pthread_mutex_t) -> c_int;
type HostPthreadMutexLockFn = unsafe extern "C" fn(*mut libc::pthread_mutex_t) -> c_int;
type HostPthreadMutexTrylockFn = unsafe extern "C" fn(*mut libc::pthread_mutex_t) -> c_int;
type HostPthreadMutexUnlockFn = unsafe extern "C" fn(*mut libc::pthread_mutex_t) -> c_int;
type HostPthreadCondInitFn =
    unsafe extern "C" fn(*mut libc::pthread_cond_t, *const libc::pthread_condattr_t) -> c_int;
type HostPthreadCondDestroyFn = unsafe extern "C" fn(*mut libc::pthread_cond_t) -> c_int;
type HostPthreadCondWaitFn =
    unsafe extern "C" fn(*mut libc::pthread_cond_t, *mut libc::pthread_mutex_t) -> c_int;
type HostPthreadCondSignalFn = unsafe extern "C" fn(*mut libc::pthread_cond_t) -> c_int;
type HostPthreadCondBroadcastFn = unsafe extern "C" fn(*mut libc::pthread_cond_t) -> c_int;
type HostPthreadCondTimedwaitFn = unsafe extern "C" fn(
    *mut libc::pthread_cond_t,
    *mut libc::pthread_mutex_t,
    *const libc::timespec,
) -> c_int;
type HostPthreadGetattrNpFn =
    unsafe extern "C" fn(libc::pthread_t, *mut libc::pthread_attr_t) -> c_int;
type HostPthreadAttrInitFn = unsafe extern "C" fn(*mut libc::pthread_attr_t) -> c_int;
type HostPthreadAttrDestroyFn = unsafe extern "C" fn(*mut libc::pthread_attr_t) -> c_int;
type HostPthreadAttrSetdetachstateFn =
    unsafe extern "C" fn(*mut libc::pthread_attr_t, c_int) -> c_int;
type HostPthreadAttrGetdetachstateFn =
    unsafe extern "C" fn(*const libc::pthread_attr_t, *mut c_int) -> c_int;
type HostPthreadAttrSetstacksizeFn =
    unsafe extern "C" fn(*mut libc::pthread_attr_t, usize) -> c_int;
type HostPthreadAttrGetstacksizeFn =
    unsafe extern "C" fn(*const libc::pthread_attr_t, *mut usize) -> c_int;
type HostPthreadMutexattrInitFn = unsafe extern "C" fn(*mut libc::pthread_mutexattr_t) -> c_int;
type HostPthreadMutexattrDestroyFn = unsafe extern "C" fn(*mut libc::pthread_mutexattr_t) -> c_int;
type HostPthreadMutexattrSettypeFn =
    unsafe extern "C" fn(*mut libc::pthread_mutexattr_t, c_int) -> c_int;
type HostPthreadMutexattrGettypeFn =
    unsafe extern "C" fn(*const libc::pthread_mutexattr_t, *mut c_int) -> c_int;
type HostPthreadCondattrInitFn = unsafe extern "C" fn(*mut libc::pthread_condattr_t) -> c_int;
type HostPthreadCondattrDestroyFn = unsafe extern "C" fn(*mut libc::pthread_condattr_t) -> c_int;
type HostPthreadCondattrSetclockFn =
    unsafe extern "C" fn(*mut libc::pthread_condattr_t, libc::clockid_t) -> c_int;
type HostPthreadCondattrGetclockFn =
    unsafe extern "C" fn(*const libc::pthread_condattr_t, *mut libc::clockid_t) -> c_int;
type HostPthreadRwlockattrInitFn = unsafe extern "C" fn(*mut libc::pthread_rwlockattr_t) -> c_int;
type HostPthreadRwlockattrDestroyFn =
    unsafe extern "C" fn(*mut libc::pthread_rwlockattr_t) -> c_int;

// ---------------------------------------------------------------------------
// Futex-backed NORMAL mutex core (bd-z84)
// ---------------------------------------------------------------------------

static MUTEX_SPIN_BRANCHES: AtomicU64 = AtomicU64::new(0);
static MUTEX_WAIT_BRANCHES: AtomicU64 = AtomicU64::new(0);
static MUTEX_WAKE_BRANCHES: AtomicU64 = AtomicU64::new(0);

/// When true, mutex operations skip host delegation and use the native futex
/// implementation directly. Set by [`pthread_mutex_reset_state_for_tests`] so
/// that tests can exercise the futex state machine without glibc intercepting.
static FORCE_NATIVE_MUTEX: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// When true, thread lifecycle operations (create/join/detach/self/equal) skip
/// host delegation and use the native implementation. Set by
/// [`pthread_threading_force_native_for_tests`].
static FORCE_NATIVE_THREADING: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
const MANAGED_MUTEX_MAGIC: u32 = 0x474d_5854; // "GMXT"
const MANAGED_RWLOCK_MAGIC: u32 = 0x4752_5758; // "GRWX"
static THREAD_HANDLE_REGISTRY: LazyLock<Mutex<HashMap<usize, usize>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static HOST_SYMBOL_CACHE: LazyLock<Mutex<HashMap<&'static [u8], usize>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

thread_local! {
    static THREADING_POLICY_DEPTH: Cell<u32> = const { Cell::new(0) };
}

unsafe fn resolve_host_symbol(name: &'static [u8]) -> *mut c_void {
    if let Some(ptr) = HOST_SYMBOL_CACHE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(name)
        .copied()
    {
        return ptr as *mut c_void;
    }

    let glibc_v225 = b"GLIBC_2.2.5\0";
    let glibc_v232 = b"GLIBC_2.3.2\0";
    let glibc_v34 = b"GLIBC_2.34\0";
    // SAFETY: versioned lookup in next object after this interposed library.
    let mut ptr = unsafe {
        libc::dlvsym(
            libc::RTLD_NEXT,
            name.as_ptr().cast::<libc::c_char>(),
            glibc_v225.as_ptr().cast::<libc::c_char>(),
        )
    };
    if ptr.is_null() {
        // SAFETY: common modern pthread baseline.
        ptr = unsafe {
            libc::dlvsym(
                libc::RTLD_NEXT,
                name.as_ptr().cast::<libc::c_char>(),
                glibc_v232.as_ptr().cast::<libc::c_char>(),
            )
        };
    }
    if ptr.is_null() {
        // SAFETY: symbols that only exist in newer libc.
        ptr = unsafe {
            libc::dlvsym(
                libc::RTLD_NEXT,
                name.as_ptr().cast::<libc::c_char>(),
                glibc_v34.as_ptr().cast::<libc::c_char>(),
            )
        };
    }
    let resolved = if ptr.is_null() {
        // SAFETY: final unversioned fallback.
        unsafe { libc::dlsym(libc::RTLD_NEXT, name.as_ptr().cast::<libc::c_char>()) }
    } else {
        ptr
    };

    HOST_SYMBOL_CACHE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(name, resolved as usize);
    resolved
}

unsafe fn host_pthread_create_fn() -> Option<HostPthreadCreateFn> {
    let ptr = unsafe { resolve_host_symbol(b"pthread_create\0") };
    if ptr.is_null() {
        None
    } else {
        // SAFETY: resolved symbol has pthread_create ABI.
        Some(unsafe { std::mem::transmute::<*mut c_void, HostPthreadCreateFn>(ptr) })
    }
}

unsafe fn host_pthread_join_fn() -> Option<HostPthreadJoinFn> {
    let ptr = unsafe { resolve_host_symbol(b"pthread_join\0") };
    if ptr.is_null() {
        None
    } else {
        // SAFETY: resolved symbol has pthread_join ABI.
        Some(unsafe { std::mem::transmute::<*mut c_void, HostPthreadJoinFn>(ptr) })
    }
}

unsafe fn host_pthread_detach_fn() -> Option<HostPthreadDetachFn> {
    let ptr = unsafe { resolve_host_symbol(b"pthread_detach\0") };
    if ptr.is_null() {
        None
    } else {
        // SAFETY: resolved symbol has pthread_detach ABI.
        Some(unsafe { std::mem::transmute::<*mut c_void, HostPthreadDetachFn>(ptr) })
    }
}

unsafe fn host_pthread_self_fn() -> Option<HostPthreadSelfFn> {
    let ptr = unsafe { resolve_host_symbol(b"pthread_self\0") };
    if ptr.is_null() {
        None
    } else {
        // SAFETY: resolved symbol has pthread_self ABI.
        Some(unsafe { std::mem::transmute::<*mut c_void, HostPthreadSelfFn>(ptr) })
    }
}

unsafe fn host_pthread_equal_fn() -> Option<HostPthreadEqualFn> {
    let ptr = unsafe { resolve_host_symbol(b"pthread_equal\0") };
    if ptr.is_null() {
        None
    } else {
        // SAFETY: resolved symbol has pthread_equal ABI.
        Some(unsafe { std::mem::transmute::<*mut c_void, HostPthreadEqualFn>(ptr) })
    }
}

unsafe fn host_pthread_mutex_init_fn() -> Option<HostPthreadMutexInitFn> {
    let ptr = unsafe { resolve_host_symbol(b"pthread_mutex_init\0") };
    if ptr.is_null() {
        None
    } else {
        // SAFETY: resolved symbol has pthread_mutex_init ABI.
        Some(unsafe { std::mem::transmute::<*mut c_void, HostPthreadMutexInitFn>(ptr) })
    }
}

unsafe fn host_pthread_mutex_destroy_fn() -> Option<HostPthreadMutexDestroyFn> {
    let ptr = unsafe { resolve_host_symbol(b"pthread_mutex_destroy\0") };
    if ptr.is_null() {
        None
    } else {
        // SAFETY: resolved symbol has pthread_mutex_destroy ABI.
        Some(unsafe { std::mem::transmute::<*mut c_void, HostPthreadMutexDestroyFn>(ptr) })
    }
}

unsafe fn host_pthread_mutex_lock_fn() -> Option<HostPthreadMutexLockFn> {
    let ptr = unsafe { resolve_host_symbol(b"pthread_mutex_lock\0") };
    if ptr.is_null() {
        None
    } else {
        // SAFETY: resolved symbol has pthread_mutex_lock ABI.
        Some(unsafe { std::mem::transmute::<*mut c_void, HostPthreadMutexLockFn>(ptr) })
    }
}

unsafe fn host_pthread_mutex_trylock_fn() -> Option<HostPthreadMutexTrylockFn> {
    let ptr = unsafe { resolve_host_symbol(b"pthread_mutex_trylock\0") };
    if ptr.is_null() {
        None
    } else {
        // SAFETY: resolved symbol has pthread_mutex_trylock ABI.
        Some(unsafe { std::mem::transmute::<*mut c_void, HostPthreadMutexTrylockFn>(ptr) })
    }
}

unsafe fn host_pthread_mutex_unlock_fn() -> Option<HostPthreadMutexUnlockFn> {
    let ptr = unsafe { resolve_host_symbol(b"pthread_mutex_unlock\0") };
    if ptr.is_null() {
        None
    } else {
        // SAFETY: resolved symbol has pthread_mutex_unlock ABI.
        Some(unsafe { std::mem::transmute::<*mut c_void, HostPthreadMutexUnlockFn>(ptr) })
    }
}

unsafe fn host_pthread_cond_init_fn() -> Option<HostPthreadCondInitFn> {
    let ptr = unsafe { resolve_host_symbol(b"pthread_cond_init\0") };
    if ptr.is_null() {
        None
    } else {
        // SAFETY: resolved symbol has pthread_cond_init ABI.
        Some(unsafe { std::mem::transmute::<*mut c_void, HostPthreadCondInitFn>(ptr) })
    }
}

unsafe fn host_pthread_cond_destroy_fn() -> Option<HostPthreadCondDestroyFn> {
    let ptr = unsafe { resolve_host_symbol(b"pthread_cond_destroy\0") };
    if ptr.is_null() {
        None
    } else {
        // SAFETY: resolved symbol has pthread_cond_destroy ABI.
        Some(unsafe { std::mem::transmute::<*mut c_void, HostPthreadCondDestroyFn>(ptr) })
    }
}

unsafe fn host_pthread_cond_wait_fn() -> Option<HostPthreadCondWaitFn> {
    let ptr = unsafe { resolve_host_symbol(b"pthread_cond_wait\0") };
    if ptr.is_null() {
        None
    } else {
        // SAFETY: resolved symbol has pthread_cond_wait ABI.
        Some(unsafe { std::mem::transmute::<*mut c_void, HostPthreadCondWaitFn>(ptr) })
    }
}

unsafe fn host_pthread_cond_signal_fn() -> Option<HostPthreadCondSignalFn> {
    let ptr = unsafe { resolve_host_symbol(b"pthread_cond_signal\0") };
    if ptr.is_null() {
        None
    } else {
        // SAFETY: resolved symbol has pthread_cond_signal ABI.
        Some(unsafe { std::mem::transmute::<*mut c_void, HostPthreadCondSignalFn>(ptr) })
    }
}

unsafe fn host_pthread_cond_broadcast_fn() -> Option<HostPthreadCondBroadcastFn> {
    let ptr = unsafe { resolve_host_symbol(b"pthread_cond_broadcast\0") };
    if ptr.is_null() {
        None
    } else {
        // SAFETY: resolved symbol has pthread_cond_broadcast ABI.
        Some(unsafe { std::mem::transmute::<*mut c_void, HostPthreadCondBroadcastFn>(ptr) })
    }
}

unsafe fn host_pthread_cond_timedwait_fn() -> Option<HostPthreadCondTimedwaitFn> {
    let ptr = unsafe { resolve_host_symbol(b"pthread_cond_timedwait\0") };
    if ptr.is_null() {
        None
    } else {
        // SAFETY: resolved symbol has pthread_cond_timedwait ABI.
        Some(unsafe { std::mem::transmute::<*mut c_void, HostPthreadCondTimedwaitFn>(ptr) })
    }
}

unsafe fn host_pthread_getattr_np_fn() -> Option<HostPthreadGetattrNpFn> {
    let ptr = unsafe { resolve_host_symbol(b"pthread_getattr_np\0") };
    if ptr.is_null() {
        None
    } else {
        // SAFETY: symbol resolved from host pthread implementation with matching ABI.
        Some(unsafe { std::mem::transmute::<*mut c_void, HostPthreadGetattrNpFn>(ptr) })
    }
}

unsafe fn host_pthread_attr_init_fn() -> Option<HostPthreadAttrInitFn> {
    let ptr = unsafe { resolve_host_symbol(b"pthread_attr_init\0") };
    if ptr.is_null() {
        None
    } else {
        // SAFETY: symbol resolved from host pthread implementation with matching ABI.
        Some(unsafe { std::mem::transmute::<*mut c_void, HostPthreadAttrInitFn>(ptr) })
    }
}

unsafe fn host_pthread_attr_destroy_fn() -> Option<HostPthreadAttrDestroyFn> {
    let ptr = unsafe { resolve_host_symbol(b"pthread_attr_destroy\0") };
    if ptr.is_null() {
        None
    } else {
        // SAFETY: symbol resolved from host pthread implementation with matching ABI.
        Some(unsafe { std::mem::transmute::<*mut c_void, HostPthreadAttrDestroyFn>(ptr) })
    }
}

unsafe fn host_pthread_attr_setdetachstate_fn() -> Option<HostPthreadAttrSetdetachstateFn> {
    let ptr = unsafe { resolve_host_symbol(b"pthread_attr_setdetachstate\0") };
    if ptr.is_null() {
        None
    } else {
        // SAFETY: symbol resolved from host pthread implementation with matching ABI.
        Some(unsafe { std::mem::transmute::<*mut c_void, HostPthreadAttrSetdetachstateFn>(ptr) })
    }
}

unsafe fn host_pthread_attr_getdetachstate_fn() -> Option<HostPthreadAttrGetdetachstateFn> {
    let ptr = unsafe { resolve_host_symbol(b"pthread_attr_getdetachstate\0") };
    if ptr.is_null() {
        None
    } else {
        // SAFETY: symbol resolved from host pthread implementation with matching ABI.
        Some(unsafe { std::mem::transmute::<*mut c_void, HostPthreadAttrGetdetachstateFn>(ptr) })
    }
}

unsafe fn host_pthread_attr_setstacksize_fn() -> Option<HostPthreadAttrSetstacksizeFn> {
    let ptr = unsafe { resolve_host_symbol(b"pthread_attr_setstacksize\0") };
    if ptr.is_null() {
        None
    } else {
        // SAFETY: symbol resolved from host pthread implementation with matching ABI.
        Some(unsafe { std::mem::transmute::<*mut c_void, HostPthreadAttrSetstacksizeFn>(ptr) })
    }
}

unsafe fn host_pthread_attr_getstacksize_fn() -> Option<HostPthreadAttrGetstacksizeFn> {
    let ptr = unsafe { resolve_host_symbol(b"pthread_attr_getstacksize\0") };
    if ptr.is_null() {
        None
    } else {
        // SAFETY: symbol resolved from host pthread implementation with matching ABI.
        Some(unsafe { std::mem::transmute::<*mut c_void, HostPthreadAttrGetstacksizeFn>(ptr) })
    }
}

unsafe fn host_pthread_mutexattr_init_fn() -> Option<HostPthreadMutexattrInitFn> {
    let ptr = unsafe { resolve_host_symbol(b"pthread_mutexattr_init\0") };
    if ptr.is_null() {
        None
    } else {
        // SAFETY: symbol resolved from host pthread implementation with matching ABI.
        Some(unsafe { std::mem::transmute::<*mut c_void, HostPthreadMutexattrInitFn>(ptr) })
    }
}

unsafe fn host_pthread_mutexattr_destroy_fn() -> Option<HostPthreadMutexattrDestroyFn> {
    let ptr = unsafe { resolve_host_symbol(b"pthread_mutexattr_destroy\0") };
    if ptr.is_null() {
        None
    } else {
        // SAFETY: symbol resolved from host pthread implementation with matching ABI.
        Some(unsafe { std::mem::transmute::<*mut c_void, HostPthreadMutexattrDestroyFn>(ptr) })
    }
}

unsafe fn host_pthread_mutexattr_settype_fn() -> Option<HostPthreadMutexattrSettypeFn> {
    let ptr = unsafe { resolve_host_symbol(b"pthread_mutexattr_settype\0") };
    if ptr.is_null() {
        None
    } else {
        // SAFETY: symbol resolved from host pthread implementation with matching ABI.
        Some(unsafe { std::mem::transmute::<*mut c_void, HostPthreadMutexattrSettypeFn>(ptr) })
    }
}

unsafe fn host_pthread_mutexattr_gettype_fn() -> Option<HostPthreadMutexattrGettypeFn> {
    let ptr = unsafe { resolve_host_symbol(b"pthread_mutexattr_gettype\0") };
    if ptr.is_null() {
        None
    } else {
        // SAFETY: symbol resolved from host pthread implementation with matching ABI.
        Some(unsafe { std::mem::transmute::<*mut c_void, HostPthreadMutexattrGettypeFn>(ptr) })
    }
}

unsafe fn host_pthread_condattr_init_fn() -> Option<HostPthreadCondattrInitFn> {
    let ptr = unsafe { resolve_host_symbol(b"pthread_condattr_init\0") };
    if ptr.is_null() {
        None
    } else {
        // SAFETY: symbol resolved from host pthread implementation with matching ABI.
        Some(unsafe { std::mem::transmute::<*mut c_void, HostPthreadCondattrInitFn>(ptr) })
    }
}

unsafe fn host_pthread_condattr_destroy_fn() -> Option<HostPthreadCondattrDestroyFn> {
    let ptr = unsafe { resolve_host_symbol(b"pthread_condattr_destroy\0") };
    if ptr.is_null() {
        None
    } else {
        // SAFETY: symbol resolved from host pthread implementation with matching ABI.
        Some(unsafe { std::mem::transmute::<*mut c_void, HostPthreadCondattrDestroyFn>(ptr) })
    }
}

unsafe fn host_pthread_condattr_setclock_fn() -> Option<HostPthreadCondattrSetclockFn> {
    let ptr = unsafe { resolve_host_symbol(b"pthread_condattr_setclock\0") };
    if ptr.is_null() {
        None
    } else {
        // SAFETY: symbol resolved from host pthread implementation with matching ABI.
        Some(unsafe { std::mem::transmute::<*mut c_void, HostPthreadCondattrSetclockFn>(ptr) })
    }
}

unsafe fn host_pthread_condattr_getclock_fn() -> Option<HostPthreadCondattrGetclockFn> {
    let ptr = unsafe { resolve_host_symbol(b"pthread_condattr_getclock\0") };
    if ptr.is_null() {
        None
    } else {
        // SAFETY: symbol resolved from host pthread implementation with matching ABI.
        Some(unsafe { std::mem::transmute::<*mut c_void, HostPthreadCondattrGetclockFn>(ptr) })
    }
}

unsafe fn host_pthread_rwlockattr_init_fn() -> Option<HostPthreadRwlockattrInitFn> {
    let ptr = unsafe { resolve_host_symbol(b"pthread_rwlockattr_init\0") };
    if ptr.is_null() {
        None
    } else {
        // SAFETY: symbol resolved from host pthread implementation with matching ABI.
        Some(unsafe { std::mem::transmute::<*mut c_void, HostPthreadRwlockattrInitFn>(ptr) })
    }
}

unsafe fn host_pthread_rwlockattr_destroy_fn() -> Option<HostPthreadRwlockattrDestroyFn> {
    let ptr = unsafe { resolve_host_symbol(b"pthread_rwlockattr_destroy\0") };
    if ptr.is_null() {
        None
    } else {
        // SAFETY: symbol resolved from host pthread implementation with matching ABI.
        Some(unsafe { std::mem::transmute::<*mut c_void, HostPthreadRwlockattrDestroyFn>(ptr) })
    }
}

#[allow(dead_code)]
struct ThreadingPolicyGuard;

impl Drop for ThreadingPolicyGuard {
    fn drop(&mut self) {
        let _ = THREADING_POLICY_DEPTH.try_with(|depth| {
            let current = depth.get();
            depth.set(current.saturating_sub(1));
        });
    }
}

#[allow(dead_code)]
fn enter_threading_policy_guard() -> Option<ThreadingPolicyGuard> {
    THREADING_POLICY_DEPTH
        .try_with(|depth| {
            let current = depth.get();
            if current > 0 {
                None
            } else {
                depth.set(current + 1);
                Some(ThreadingPolicyGuard)
            }
        })
        .unwrap_or(None)
}

#[allow(dead_code)]
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

#[must_use]
pub(crate) fn in_threading_policy_context() -> bool {
    THREADING_POLICY_DEPTH
        .try_with(|depth| depth.get() > 0)
        .unwrap_or(true)
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

fn rwlock_word_ptr(rwlock: *mut libc::pthread_rwlock_t) -> Option<*mut AtomicI32> {
    if rwlock.is_null() {
        return None;
    }
    let align = std::mem::align_of::<AtomicI32>();
    if !(rwlock as usize).is_multiple_of(align) {
        return None;
    }
    Some(rwlock.cast::<AtomicI32>())
}

fn rwlock_magic_ptr(rwlock: *mut libc::pthread_rwlock_t) -> Option<*mut AtomicU32> {
    if rwlock.is_null() {
        return None;
    }
    let base = rwlock.cast::<u8>();
    let offset = std::mem::size_of::<AtomicI32>();
    // SAFETY: `base` comes from non-null `rwlock`; adding a small in-object offset.
    let ptr = unsafe { base.add(offset) };
    let align = std::mem::align_of::<AtomicU32>();
    if !(ptr as usize).is_multiple_of(align) {
        return None;
    }
    Some(ptr.cast::<AtomicU32>())
}

fn is_managed_rwlock(rwlock: *mut libc::pthread_rwlock_t) -> bool {
    let Some(magic_ptr) = rwlock_magic_ptr(rwlock) else {
        return false;
    };
    // SAFETY: alignment and non-null checked in `rwlock_magic_ptr`.
    let magic = unsafe { &*magic_ptr };
    magic.load(Ordering::Acquire) == MANAGED_RWLOCK_MAGIC
}

fn mark_managed_rwlock(rwlock: *mut libc::pthread_rwlock_t) -> bool {
    let Some(magic_ptr) = rwlock_magic_ptr(rwlock) else {
        return false;
    };
    // SAFETY: alignment and non-null checked in `rwlock_magic_ptr`.
    let magic = unsafe { &*magic_ptr };
    magic.store(MANAGED_RWLOCK_MAGIC, Ordering::Release);
    true
}

fn clear_managed_rwlock(rwlock: *mut libc::pthread_rwlock_t) {
    if let Some(magic_ptr) = rwlock_magic_ptr(rwlock) {
        // SAFETY: alignment and non-null checked in `rwlock_magic_ptr`.
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

#[inline]
fn native_pthread_self() -> libc::pthread_t {
    if !FORCE_NATIVE_THREADING.load(Ordering::Acquire) {
        // SAFETY: host symbol lookup/transmute guarantees ABI if present.
        if let Some(host_self) = unsafe { host_pthread_self_fn() } {
            // SAFETY: direct call through resolved host symbol.
            return unsafe { host_self() };
        }
    }
    let tid = core_self_tid();
    if tid > 0 {
        let registry = THREAD_HANDLE_REGISTRY
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        for &handle_raw in registry.values() {
            let handle_ptr = handle_raw as *mut ThreadHandle;
            // SAFETY: registry only stores live handles from `core_create_thread`.
            let handle_tid = unsafe { (*handle_ptr).tid.load(Ordering::Acquire) };
            if handle_tid == tid {
                return handle_raw as libc::pthread_t;
            }
        }
    }
    // Fallback for threads not created via our managed pthread_create path.
    tid as libc::pthread_t
}

#[inline]
fn native_pthread_equal(a: libc::pthread_t, b: libc::pthread_t) -> c_int {
    if !FORCE_NATIVE_THREADING.load(Ordering::Acquire) {
        // SAFETY: host symbol lookup/transmute guarantees ABI if present.
        if let Some(host_equal) = unsafe { host_pthread_equal_fn() } {
            // SAFETY: direct call through resolved host symbol.
            return unsafe { host_equal(a, b) };
        }
    }
    if a == b { 1 } else { 0 }
}

#[allow(unsafe_code)]
unsafe fn native_pthread_create(
    thread_out: *mut libc::pthread_t,
    attr: *const libc::pthread_attr_t,
    start_routine: StartRoutine,
    arg: *mut c_void,
) -> c_int {
    if !FORCE_NATIVE_THREADING.load(Ordering::Acquire) {
        // SAFETY: host symbol lookup/transmute guarantees ABI if present.
        if let Some(host_create) = unsafe { host_pthread_create_fn() } {
            // SAFETY: direct call through resolved host symbol.
            return unsafe { host_create(thread_out, attr, Some(start_routine), arg) };
        }
    }
    if thread_out.is_null() {
        return libc::EINVAL;
    }
    if !attr.is_null() {
        return libc::EINVAL;
    }

    let handle_ptr = match unsafe { core_create_thread(start_routine as usize, arg as usize) } {
        Ok(ptr) => ptr,
        Err(errno) => return errno,
    };

    let thread_key = handle_ptr as usize;

    let mut registry = THREAD_HANDLE_REGISTRY
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if registry.contains_key(&thread_key) {
        let _ = unsafe { core_detach_thread(handle_ptr) };
        return libc::EAGAIN;
    }
    registry.insert(thread_key, handle_ptr as usize);
    drop(registry);

    // SAFETY: thread_out validated non-null above.
    unsafe { *thread_out = thread_key as libc::pthread_t };
    0
}

#[allow(unsafe_code)]
unsafe fn native_pthread_join(thread: libc::pthread_t, retval: *mut *mut c_void) -> c_int {
    if !FORCE_NATIVE_THREADING.load(Ordering::Acquire) {
        // SAFETY: host symbol lookup/transmute guarantees ABI if present.
        if let Some(host_join) = unsafe { host_pthread_join_fn() } {
            // SAFETY: direct call through resolved host symbol.
            return unsafe { host_join(thread, retval) };
        }
    }
    let thread_key = thread as usize;
    let my_tid = core_self_tid();
    if my_tid > 0 && thread_key == my_tid as usize {
        return libc::EDEADLK;
    }

    // Reject self-join before removing the handle from the registry. This
    // avoids entering core join wait paths when a thread attempts to join its
    // own `pthread_t`.
    {
        let registry = THREAD_HANDLE_REGISTRY
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(&raw) = registry.get(&thread_key) {
            let handle_ptr = raw as *mut ThreadHandle;
            // SAFETY: registry only stores handles created by core_create_thread.
            let state = unsafe { (*handle_ptr).state.load(Ordering::Acquire) };
            if state == THREAD_STARTING || state == THREAD_RUNNING {
                // SAFETY: handle_ptr is valid while present in registry.
                let handle_tid = unsafe { (*handle_ptr).tid.load(Ordering::Acquire) };
                // SAFETY: handle_ptr is valid while present in registry.
                let handle_self_tid = unsafe { (*handle_ptr).self_tid.load(Ordering::Acquire) };
                if my_tid > 0 && (handle_tid == my_tid || handle_self_tid == my_tid) {
                    return libc::EDEADLK;
                }
            }
        }
    }

    let handle_ptr = {
        let mut registry = THREAD_HANDLE_REGISTRY
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        match registry.remove(&thread_key) {
            Some(raw) => raw as *mut ThreadHandle,
            None => return libc::ESRCH,
        }
    };

    match unsafe { core_join_thread(handle_ptr) } {
        Ok(value) => {
            if !retval.is_null() {
                // SAFETY: caller provided a writable retval pointer.
                unsafe { *retval = value as *mut c_void };
            }
            0
        }
        Err(errno) => {
            let mut registry = THREAD_HANDLE_REGISTRY
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            registry.insert(thread_key, handle_ptr as usize);
            errno
        }
    }
}

#[allow(unsafe_code)]
unsafe fn native_pthread_detach(thread: libc::pthread_t) -> c_int {
    if !FORCE_NATIVE_THREADING.load(Ordering::Acquire) {
        // SAFETY: host symbol lookup/transmute guarantees ABI if present.
        if let Some(host_detach) = unsafe { host_pthread_detach_fn() } {
            // SAFETY: direct call through resolved host symbol.
            return unsafe { host_detach(thread) };
        }
    }
    let thread_key = thread as usize;
    let handle_ptr = {
        let mut registry = THREAD_HANDLE_REGISTRY
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        match registry.remove(&thread_key) {
            Some(raw) => raw as *mut ThreadHandle,
            None => return libc::ESRCH,
        }
    };

    match unsafe { core_detach_thread(handle_ptr) } {
        Ok(()) => 0,
        Err(errno) => {
            let mut registry = THREAD_HANDLE_REGISTRY
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            registry.insert(thread_key, handle_ptr as usize);
            errno
        }
    }
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

fn futex_rwlock_rdlock(word: &AtomicI32) -> c_int {
    loop {
        let state = word.load(Ordering::Acquire);
        if state >= 0 {
            if state == i32::MAX {
                return libc::EAGAIN;
            }
            if word
                .compare_exchange(state, state + 1, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return 0;
            }
            continue;
        }

        #[cfg(target_os = "linux")]
        {
            let rc = futex_wait_private(word, state);
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
            core::hint::spin_loop();
        }
    }
}

fn futex_rwlock_wrlock(word: &AtomicI32) -> c_int {
    loop {
        if word
            .compare_exchange(0, -1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            return 0;
        }

        let state = word.load(Ordering::Relaxed);

        #[cfg(target_os = "linux")]
        {
            let rc = futex_wait_private(word, state);
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
            core::hint::spin_loop();
        }
    }
}

fn futex_rwlock_unlock(word: &AtomicI32) -> c_int {
    loop {
        let state = word.load(Ordering::Acquire);
        if state == 0 {
            return libc::EPERM;
        }
        if state == -1 {
            if word
                .compare_exchange(-1, 0, Ordering::Release, Ordering::Relaxed)
                .is_ok()
            {
                #[cfg(target_os = "linux")]
                {
                    let _ = futex_wake_private(word, i32::MAX);
                }
                return 0;
            }
            continue;
        }
        if state > 0 {
            if word
                .compare_exchange(state, state - 1, Ordering::Release, Ordering::Relaxed)
                .is_ok()
            {
                if state == 1 {
                    #[cfg(target_os = "linux")]
                    {
                        let _ = futex_wake_private(word, i32::MAX);
                    }
                }
                return 0;
            }
            continue;
        }
        return libc::EINVAL;
    }
}

fn futex_rwlock_tryrdlock(word: &AtomicI32) -> c_int {
    let state = word.load(Ordering::Acquire);
    if state < 0 || state == i32::MAX {
        return libc::EBUSY;
    }
    match word.compare_exchange(state, state + 1, Ordering::Acquire, Ordering::Relaxed) {
        Ok(_) => 0,
        Err(_) => libc::EBUSY,
    }
}

fn futex_rwlock_trywrlock(word: &AtomicI32) -> c_int {
    match word.compare_exchange(0, -1, Ordering::Acquire, Ordering::Relaxed) {
        Ok(_) => 0,
        Err(_) => libc::EBUSY,
    }
}

// ---------------------------------------------------------------------------
// pthread_once
// ---------------------------------------------------------------------------
//
// once_control layout (inside libc::pthread_once_t, which is at least 4 bytes):
//   0 = INIT (never started)
//   1 = IN_PROGRESS (init_routine is running)
//   2 = DONE (init_routine completed)
const ONCE_INIT: i32 = 0;
const ONCE_IN_PROGRESS: i32 = 1;
const ONCE_DONE: i32 = 2;

fn reset_mutex_registry_for_tests() {
    MUTEX_SPIN_BRANCHES.store(0, Ordering::Relaxed);
    MUTEX_WAIT_BRANCHES.store(0, Ordering::Relaxed);
    MUTEX_WAKE_BRANCHES.store(0, Ordering::Relaxed);
    FORCE_NATIVE_MUTEX.store(true, Ordering::Release);
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

/// Test hook: force thread lifecycle operations (create/join/detach/self/equal)
/// to use the native implementation, bypassing host glibc delegation.
#[doc(hidden)]
pub fn pthread_threading_force_native_for_tests() {
    FORCE_NATIVE_THREADING.store(true, Ordering::Release);
}

#[inline]
#[allow(dead_code)]
fn stage_index(ordering: &[CheckStage; 7], stage: CheckStage) -> usize {
    ordering.iter().position(|s| *s == stage).unwrap_or(0)
}

#[inline]
#[allow(dead_code)]
fn threading_stage_context(addr1: usize, addr2: usize) -> (bool, bool, [CheckStage; 7]) {
    let aligned = ((addr1 | addr2) & 0x7) == 0;
    let recent_page = (addr1 != 0 && known_remaining(addr1).is_some())
        || (addr2 != 0 && known_remaining(addr2).is_some());
    let ordering = runtime_policy::check_ordering(ApiFamily::Threading, aligned, recent_page);
    (aligned, recent_page, ordering)
}

#[inline]
#[allow(dead_code)]
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
    native_pthread_self()
}

/// POSIX `pthread_equal`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_equal(a: libc::pthread_t, b: libc::pthread_t) -> c_int {
    native_pthread_equal(a, b)
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
    if thread_out.is_null() || start_routine.is_none() {
        return libc::EINVAL;
    }
    let start = start_routine.unwrap_or_else(|| unreachable!("start routine checked above"));
    // SAFETY: pointers and start routine are validated by this wrapper.
    unsafe { native_pthread_create(thread_out, _attr, start, arg) }
}

/// POSIX `pthread_join`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_join(thread: libc::pthread_t, retval: *mut *mut c_void) -> c_int {
    // SAFETY: native helper enforces thread-handle validity and pointer checks.
    unsafe { native_pthread_join(thread, retval) }
}

/// POSIX `pthread_detach`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_detach(thread: libc::pthread_t) -> c_int {
    // SAFETY: native helper enforces thread-handle validity.
    unsafe { native_pthread_detach(thread) }
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
    if !FORCE_NATIVE_MUTEX.load(Ordering::Acquire) {
        // SAFETY: host symbol lookup/transmute guarantees ABI if present.
        if let Some(host_init) = unsafe { host_pthread_mutex_init_fn() } {
            // SAFETY: direct call through resolved host symbol.
            return unsafe { host_init(mutex, attr) };
        }
    }

    if mutex.is_null() {
        return libc::EINVAL;
    }

    // Attribute handling is currently best-effort for preload compatibility:
    // we always initialize the futex word and only tag managed state when the
    // in-object marker slot is available.
    let _ = attr;

    if let Some(word_ptr) = mutex_word_ptr(mutex) {
        // SAFETY: `word_ptr` is alignment-checked and points to caller-owned
        // mutex storage.
        let word = unsafe { &*word_ptr };
        word.store(0, Ordering::Release);
        let _ = mark_managed_mutex(mutex);
        return 0;
    }
    clear_managed_mutex(mutex);
    libc::EINVAL
}

/// POSIX `pthread_mutex_destroy`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutex_destroy(mutex: *mut libc::pthread_mutex_t) -> c_int {
    if !FORCE_NATIVE_MUTEX.load(Ordering::Acquire) {
        // SAFETY: host symbol lookup/transmute guarantees ABI if present.
        if let Some(host_destroy) = unsafe { host_pthread_mutex_destroy_fn() } {
            // SAFETY: direct call through resolved host symbol.
            return unsafe { host_destroy(mutex) };
        }
    }

    if mutex.is_null() {
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
    if !FORCE_NATIVE_MUTEX.load(Ordering::Acquire) {
        // SAFETY: host symbol lookup/transmute guarantees ABI if present.
        if let Some(host_lock) = unsafe { host_pthread_mutex_lock_fn() } {
            // SAFETY: direct call through resolved host symbol.
            return unsafe { host_lock(mutex) };
        }
    }

    if mutex.is_null() {
        return libc::EINVAL;
    }

    let Some(word_ptr) = mutex_word_ptr(mutex) else {
        return libc::EINVAL;
    };
    // SAFETY: alignment is validated by `mutex_word_ptr`; use futex semantics
    // for both managed and pre-initialized foreign/default mutex layouts.
    let word = unsafe { &*word_ptr };
    futex_lock_normal(word)
}

/// POSIX `pthread_mutex_trylock`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutex_trylock(mutex: *mut libc::pthread_mutex_t) -> c_int {
    if !FORCE_NATIVE_MUTEX.load(Ordering::Acquire) {
        // SAFETY: host symbol lookup/transmute guarantees ABI if present.
        if let Some(host_trylock) = unsafe { host_pthread_mutex_trylock_fn() } {
            // SAFETY: direct call through resolved host symbol.
            return unsafe { host_trylock(mutex) };
        }
    }

    if mutex.is_null() {
        return libc::EINVAL;
    }

    let Some(word_ptr) = mutex_word_ptr(mutex) else {
        return libc::EINVAL;
    };
    // SAFETY: alignment is validated by `mutex_word_ptr`; use futex semantics
    // for both managed and pre-initialized foreign/default mutex layouts.
    let word = unsafe { &*word_ptr };
    futex_trylock_normal(word)
}

/// POSIX `pthread_mutex_unlock`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutex_unlock(mutex: *mut libc::pthread_mutex_t) -> c_int {
    if !FORCE_NATIVE_MUTEX.load(Ordering::Acquire) {
        // SAFETY: host symbol lookup/transmute guarantees ABI if present.
        if let Some(host_unlock) = unsafe { host_pthread_mutex_unlock_fn() } {
            // SAFETY: direct call through resolved host symbol.
            return unsafe { host_unlock(mutex) };
        }
    }

    if mutex.is_null() {
        return libc::EINVAL;
    }

    let Some(word_ptr) = mutex_word_ptr(mutex) else {
        return libc::EINVAL;
    };
    // SAFETY: alignment is validated by `mutex_word_ptr`; use futex semantics
    // for both managed and pre-initialized foreign/default mutex layouts.
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
    if !FORCE_NATIVE_MUTEX.load(Ordering::Acquire) {
        // SAFETY: host symbol lookup/transmute guarantees ABI if present.
        if let Some(host_init) = unsafe { host_pthread_cond_init_fn() } {
            // SAFETY: direct call through resolved host symbol.
            return unsafe { host_init(cond, attr) };
        }
    }

    let Some(cond_ptr) = condvar_data_ptr(cond) else {
        return libc::EINVAL;
    };
    let clock_id = if attr.is_null() {
        PTHREAD_COND_CLOCK_REALTIME
    } else {
        let mut clock_id: c_int = PTHREAD_COND_CLOCK_REALTIME;
        // SAFETY: attr pointer is caller-provided; host libc validates structure content.
        let rc = unsafe { libc::pthread_condattr_getclock(attr, &mut clock_id as *mut c_int) };
        if rc == 0 {
            clock_id
        } else {
            PTHREAD_COND_CLOCK_REALTIME
        }
    };
    // SAFETY: pointer validated/aligned above and points into caller-owned pthread_cond_t.
    unsafe { core_condvar_init(cond_ptr, clock_id) }
}

/// POSIX `pthread_cond_destroy`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_cond_destroy(cond: *mut libc::pthread_cond_t) -> c_int {
    if !FORCE_NATIVE_MUTEX.load(Ordering::Acquire) {
        // SAFETY: host symbol lookup/transmute guarantees ABI if present.
        if let Some(host_destroy) = unsafe { host_pthread_cond_destroy_fn() } {
            // SAFETY: direct call through resolved host symbol.
            return unsafe { host_destroy(cond) };
        }
    }

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
    if !FORCE_NATIVE_MUTEX.load(Ordering::Acquire) {
        // SAFETY: host symbol lookup/transmute guarantees ABI if present.
        if let Some(host_wait) = unsafe { host_pthread_cond_wait_fn() } {
            // SAFETY: direct call through resolved host symbol.
            return unsafe { host_wait(cond, mutex) };
        }
    }

    if cond.is_null() || mutex.is_null() {
        return libc::EINVAL;
    }
    let Some(cond_ptr) = condvar_data_ptr(cond) else {
        return libc::EINVAL;
    };
    let Some(word_ptr) = mutex_word_ptr(mutex) else {
        return libc::EINVAL;
    };
    // Require caller-held mutex semantics while allowing foreign/default mutex layouts.
    // For both managed and host-default mutexes on Linux, a held lock is non-zero.
    // SAFETY: `word_ptr` is alignment-checked by `mutex_word_ptr`.
    let word = unsafe { &*word_ptr };
    if word.load(Ordering::Acquire) == 0 {
        return libc::EINVAL;
    }
    // SAFETY: condvar pointer and mutex futex word pointer are validated/aligned and caller-owned.
    unsafe { core_condvar_wait(cond_ptr, word_ptr.cast::<u32>() as *const u32) }
}

/// POSIX `pthread_cond_signal`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_cond_signal(cond: *mut libc::pthread_cond_t) -> c_int {
    if !FORCE_NATIVE_MUTEX.load(Ordering::Acquire) {
        // SAFETY: host symbol lookup/transmute guarantees ABI if present.
        if let Some(host_signal) = unsafe { host_pthread_cond_signal_fn() } {
            // SAFETY: direct call through resolved host symbol.
            return unsafe { host_signal(cond) };
        }
    }

    let Some(cond_ptr) = condvar_data_ptr(cond) else {
        return libc::EINVAL;
    };
    // SAFETY: pointer validated/aligned above and points into caller-owned pthread_cond_t.
    unsafe { core_condvar_signal(cond_ptr) }
}

/// POSIX `pthread_cond_broadcast`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_cond_broadcast(cond: *mut libc::pthread_cond_t) -> c_int {
    if !FORCE_NATIVE_MUTEX.load(Ordering::Acquire) {
        // SAFETY: host symbol lookup/transmute guarantees ABI if present.
        if let Some(host_broadcast) = unsafe { host_pthread_cond_broadcast_fn() } {
            // SAFETY: direct call through resolved host symbol.
            return unsafe { host_broadcast(cond) };
        }
    }

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
    if !attr.is_null() {
        clear_managed_rwlock(rwlock);
        return libc::EINVAL;
    }
    let Some(word_ptr) = rwlock_word_ptr(rwlock) else {
        clear_managed_rwlock(rwlock);
        return libc::EINVAL;
    };
    // SAFETY: `word_ptr` is alignment-checked and points to caller-owned rwlock storage.
    let word = unsafe { &*word_ptr };
    word.store(0, Ordering::Release);
    if mark_managed_rwlock(rwlock) {
        0
    } else {
        libc::EINVAL
    }
}

/// POSIX `pthread_rwlock_destroy`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlock_destroy(rwlock: *mut libc::pthread_rwlock_t) -> c_int {
    if rwlock.is_null() {
        return libc::EINVAL;
    }
    if !is_managed_rwlock(rwlock) {
        return libc::EINVAL;
    }
    let Some(word_ptr) = rwlock_word_ptr(rwlock) else {
        clear_managed_rwlock(rwlock);
        return libc::EINVAL;
    };
    // SAFETY: `word_ptr` is alignment-checked and points to caller-owned rwlock storage.
    let word = unsafe { &*word_ptr };
    if word.load(Ordering::Acquire) != 0 {
        return libc::EBUSY;
    }
    clear_managed_rwlock(rwlock);
    0
}

/// POSIX `pthread_rwlock_rdlock`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlock_rdlock(rwlock: *mut libc::pthread_rwlock_t) -> c_int {
    if rwlock.is_null() {
        return libc::EINVAL;
    }
    if !is_managed_rwlock(rwlock) {
        return libc::EINVAL;
    }
    let Some(word_ptr) = rwlock_word_ptr(rwlock) else {
        return libc::EINVAL;
    };
    // SAFETY: `word_ptr` is alignment-checked and points to caller-owned rwlock storage.
    let word = unsafe { &*word_ptr };
    futex_rwlock_rdlock(word)
}

/// POSIX `pthread_rwlock_wrlock`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlock_wrlock(rwlock: *mut libc::pthread_rwlock_t) -> c_int {
    if rwlock.is_null() {
        return libc::EINVAL;
    }
    if !is_managed_rwlock(rwlock) {
        return libc::EINVAL;
    }
    let Some(word_ptr) = rwlock_word_ptr(rwlock) else {
        return libc::EINVAL;
    };
    // SAFETY: `word_ptr` is alignment-checked and points to caller-owned rwlock storage.
    let word = unsafe { &*word_ptr };
    futex_rwlock_wrlock(word)
}

/// POSIX `pthread_rwlock_unlock`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlock_unlock(rwlock: *mut libc::pthread_rwlock_t) -> c_int {
    if rwlock.is_null() {
        return libc::EINVAL;
    }
    if !is_managed_rwlock(rwlock) {
        return libc::EINVAL;
    }
    let Some(word_ptr) = rwlock_word_ptr(rwlock) else {
        return libc::EINVAL;
    };
    // SAFETY: `word_ptr` is alignment-checked and points to caller-owned rwlock storage.
    let word = unsafe { &*word_ptr };
    futex_rwlock_unlock(word)
}

/// POSIX `pthread_rwlock_tryrdlock`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlock_tryrdlock(rwlock: *mut libc::pthread_rwlock_t) -> c_int {
    if rwlock.is_null() {
        return libc::EINVAL;
    }
    if !is_managed_rwlock(rwlock) {
        return libc::EINVAL;
    }
    let Some(word_ptr) = rwlock_word_ptr(rwlock) else {
        return libc::EINVAL;
    };
    // SAFETY: `word_ptr` is alignment-checked and points to caller-owned rwlock storage.
    let word = unsafe { &*word_ptr };
    futex_rwlock_tryrdlock(word)
}

/// POSIX `pthread_rwlock_trywrlock`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlock_trywrlock(rwlock: *mut libc::pthread_rwlock_t) -> c_int {
    if rwlock.is_null() {
        return libc::EINVAL;
    }
    if !is_managed_rwlock(rwlock) {
        return libc::EINVAL;
    }
    let Some(word_ptr) = rwlock_word_ptr(rwlock) else {
        return libc::EINVAL;
    };
    // SAFETY: `word_ptr` is alignment-checked and points to caller-owned rwlock storage.
    let word = unsafe { &*word_ptr };
    futex_rwlock_trywrlock(word)
}

// ===========================================================================
// Condition variable timed wait
// ===========================================================================

/// POSIX `pthread_cond_timedwait`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_cond_timedwait(
    cond: *mut libc::pthread_cond_t,
    mutex: *mut libc::pthread_mutex_t,
    abstime: *const libc::timespec,
) -> c_int {
    if !FORCE_NATIVE_MUTEX.load(Ordering::Acquire) {
        // SAFETY: host symbol lookup/transmute guarantees ABI if present.
        if let Some(host_timedwait) = unsafe { host_pthread_cond_timedwait_fn() } {
            // SAFETY: direct call through resolved host symbol.
            return unsafe { host_timedwait(cond, mutex, abstime) };
        }
    }

    if cond.is_null() || mutex.is_null() || abstime.is_null() {
        return libc::EINVAL;
    }
    let Some(cond_ptr) = condvar_data_ptr(cond) else {
        return libc::EINVAL;
    };
    let Some(word_ptr) = mutex_word_ptr(mutex) else {
        return libc::EINVAL;
    };
    // Require caller-held mutex semantics while allowing foreign/default mutex layouts.
    // SAFETY: `word_ptr` is alignment-checked by `mutex_word_ptr`.
    let word = unsafe { &*word_ptr };
    if word.load(Ordering::Acquire) == 0 {
        return libc::EINVAL;
    }
    // SAFETY: abstime is non-null, condvar and mutex pointers are validated/aligned.
    let ts = unsafe { &*abstime };
    unsafe {
        core_condvar_timedwait(
            cond_ptr,
            word_ptr.cast::<u32>() as *const u32,
            ts.tv_sec,
            ts.tv_nsec,
        )
    }
}

// ===========================================================================
// Thread-specific data (TSD / pthread_key)
// ===========================================================================

/// POSIX `pthread_key_create`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_key_create(
    key: *mut libc::pthread_key_t,
    destructor: Option<unsafe extern "C" fn(*mut c_void)>,
) -> c_int {
    if key.is_null() {
        return libc::EINVAL;
    }
    let mut internal_key = PthreadKey::default();
    // Convert the C destructor to the core-expected signature.
    // Core uses `fn(u64)` where value is the stored pointer-as-integer.
    let core_dtor: Option<fn(u64)> = destructor.map(|f| {
        // SAFETY: We transmute the extern "C" fn(*mut c_void) to fn(u64) since
        // on all 64-bit platforms, *mut c_void and u64 have the same representation.
        unsafe { std::mem::transmute::<unsafe extern "C" fn(*mut c_void), fn(u64)>(f) }
    });
    let rc = core_pthread_key_create(&mut internal_key, core_dtor);
    if rc == 0 {
        // SAFETY: key is non-null and we write the index.
        unsafe { *key = internal_key.id };
    }
    rc
}

/// POSIX `pthread_key_delete`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_key_delete(key: libc::pthread_key_t) -> c_int {
    let internal_key = PthreadKey { id: key };
    core_pthread_key_delete(internal_key)
}

/// POSIX `pthread_getspecific`.
#[cfg(target_arch = "x86_64")]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_getspecific(key: libc::pthread_key_t) -> *mut c_void {
    let internal_key = PthreadKey { id: key };
    core_pthread_getspecific(internal_key) as *mut c_void
}

/// POSIX `pthread_setspecific`.
#[cfg(target_arch = "x86_64")]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_setspecific(
    key: libc::pthread_key_t,
    value: *const c_void,
) -> c_int {
    let internal_key = PthreadKey { id: key };
    core_pthread_setspecific(internal_key, value as u64)
}

// ===========================================================================
// pthread_once
// ===========================================================================

/// POSIX `pthread_once`.
///
/// Guarantees that `init_routine` is called exactly once, even when multiple
/// threads call `pthread_once` concurrently with the same `once_control`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_once(
    once_control: *mut libc::pthread_once_t,
    init_routine: Option<unsafe extern "C" fn()>,
) -> c_int {
    if once_control.is_null() {
        return libc::EINVAL;
    }
    let Some(routine) = init_routine else {
        return libc::EINVAL;
    };

    // Reinterpret the first 4 bytes of pthread_once_t as an AtomicI32.
    // SAFETY: pthread_once_t is at least 4-byte aligned on all Linux platforms.
    let state = unsafe { &*(once_control as *const AtomicI32) };

    // Fast path: already done.
    if state.load(Ordering::Acquire) == ONCE_DONE {
        return 0;
    }

    // Try to become the initializer.
    match state.compare_exchange(
        ONCE_INIT,
        ONCE_IN_PROGRESS,
        Ordering::Acquire,
        Ordering::Acquire,
    ) {
        Ok(_) => {
            // We won; run the init routine.
            unsafe { routine() };
            state.store(ONCE_DONE, Ordering::Release);
            #[cfg(target_os = "linux")]
            {
                let _ = futex_wake_private(state, i32::MAX);
            }
            0
        }
        Err(current) if current == ONCE_DONE => 0,
        Err(_) => {
            // Another thread is running init_routine; wait until done.
            loop {
                let s = state.load(Ordering::Acquire);
                if s == ONCE_DONE {
                    return 0;
                }
                #[cfg(target_os = "linux")]
                {
                    let _ = futex_wait_private(state, s);
                }
                #[cfg(not(target_os = "linux"))]
                {
                    core::hint::spin_loop();
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// pthread attribute functions
//
// Attribute init/destroy/get/set delegate to the host pthread via RTLD_NEXT
// because they manipulate opaque structs with glibc-version-specific layout.
// ---------------------------------------------------------------------------

// --- Thread attributes ---

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_init(attr: *mut libc::pthread_attr_t) -> c_int {
    match unsafe { host_pthread_attr_init_fn() } {
        // SAFETY: resolved symbol ABI matches pthread_attr_init.
        Some(func) => unsafe { func(attr) },
        None => libc::ENOSYS,
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_destroy(attr: *mut libc::pthread_attr_t) -> c_int {
    match unsafe { host_pthread_attr_destroy_fn() } {
        // SAFETY: resolved symbol ABI matches pthread_attr_destroy.
        Some(func) => unsafe { func(attr) },
        None => libc::ENOSYS,
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_setdetachstate(
    attr: *mut libc::pthread_attr_t,
    state: c_int,
) -> c_int {
    match unsafe { host_pthread_attr_setdetachstate_fn() } {
        // SAFETY: resolved symbol ABI matches pthread_attr_setdetachstate.
        Some(func) => unsafe { func(attr, state) },
        None => libc::ENOSYS,
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_getdetachstate(
    attr: *const libc::pthread_attr_t,
    state: *mut c_int,
) -> c_int {
    match unsafe { host_pthread_attr_getdetachstate_fn() } {
        // SAFETY: resolved symbol ABI matches pthread_attr_getdetachstate.
        Some(func) => unsafe { func(attr, state) },
        None => libc::ENOSYS,
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_setstacksize(
    attr: *mut libc::pthread_attr_t,
    size: usize,
) -> c_int {
    match unsafe { host_pthread_attr_setstacksize_fn() } {
        // SAFETY: resolved symbol ABI matches pthread_attr_setstacksize.
        Some(func) => unsafe { func(attr, size) },
        None => libc::ENOSYS,
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_getstacksize(
    attr: *const libc::pthread_attr_t,
    size: *mut usize,
) -> c_int {
    match unsafe { host_pthread_attr_getstacksize_fn() } {
        // SAFETY: resolved symbol ABI matches pthread_attr_getstacksize.
        Some(func) => unsafe { func(attr, size) },
        None => libc::ENOSYS,
    }
}

// --- Mutex attributes ---

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_init(attr: *mut libc::pthread_mutexattr_t) -> c_int {
    match unsafe { host_pthread_mutexattr_init_fn() } {
        // SAFETY: resolved symbol ABI matches pthread_mutexattr_init.
        Some(func) => unsafe { func(attr) },
        None => libc::ENOSYS,
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_destroy(attr: *mut libc::pthread_mutexattr_t) -> c_int {
    match unsafe { host_pthread_mutexattr_destroy_fn() } {
        // SAFETY: resolved symbol ABI matches pthread_mutexattr_destroy.
        Some(func) => unsafe { func(attr) },
        None => libc::ENOSYS,
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_settype(
    attr: *mut libc::pthread_mutexattr_t,
    kind: c_int,
) -> c_int {
    match unsafe { host_pthread_mutexattr_settype_fn() } {
        // SAFETY: resolved symbol ABI matches pthread_mutexattr_settype.
        Some(func) => unsafe { func(attr, kind) },
        None => libc::ENOSYS,
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_gettype(
    attr: *const libc::pthread_mutexattr_t,
    kind: *mut c_int,
) -> c_int {
    match unsafe { host_pthread_mutexattr_gettype_fn() } {
        // SAFETY: resolved symbol ABI matches pthread_mutexattr_gettype.
        Some(func) => unsafe { func(attr, kind) },
        None => libc::ENOSYS,
    }
}

// --- Condvar attributes ---

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_condattr_init(attr: *mut libc::pthread_condattr_t) -> c_int {
    match unsafe { host_pthread_condattr_init_fn() } {
        // SAFETY: resolved symbol ABI matches pthread_condattr_init.
        Some(func) => unsafe { func(attr) },
        None => libc::ENOSYS,
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_condattr_destroy(attr: *mut libc::pthread_condattr_t) -> c_int {
    match unsafe { host_pthread_condattr_destroy_fn() } {
        // SAFETY: resolved symbol ABI matches pthread_condattr_destroy.
        Some(func) => unsafe { func(attr) },
        None => libc::ENOSYS,
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_condattr_setclock(
    attr: *mut libc::pthread_condattr_t,
    clock_id: libc::clockid_t,
) -> c_int {
    match unsafe { host_pthread_condattr_setclock_fn() } {
        // SAFETY: resolved symbol ABI matches pthread_condattr_setclock.
        Some(func) => unsafe { func(attr, clock_id) },
        None => libc::ENOSYS,
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_condattr_getclock(
    attr: *const libc::pthread_condattr_t,
    clock_id: *mut libc::clockid_t,
) -> c_int {
    match unsafe { host_pthread_condattr_getclock_fn() } {
        // SAFETY: resolved symbol ABI matches pthread_condattr_getclock.
        Some(func) => unsafe { func(attr, clock_id) },
        None => libc::ENOSYS,
    }
}

// --- Rwlock attributes ---

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlockattr_init(attr: *mut libc::pthread_rwlockattr_t) -> c_int {
    match unsafe { host_pthread_rwlockattr_init_fn() } {
        // SAFETY: resolved symbol ABI matches pthread_rwlockattr_init.
        Some(func) => unsafe { func(attr) },
        None => libc::ENOSYS,
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlockattr_destroy(
    attr: *mut libc::pthread_rwlockattr_t,
) -> c_int {
    match unsafe { host_pthread_rwlockattr_destroy_fn() } {
        // SAFETY: resolved symbol ABI matches pthread_rwlockattr_destroy.
        Some(func) => unsafe { func(attr) },
        None => libc::ENOSYS,
    }
}

// ---------------------------------------------------------------------------
// pthread cancellation — GlibcCallThrough
// ---------------------------------------------------------------------------

unsafe extern "C" {
    #[link_name = "pthread_cancel"]
    fn libc_pthread_cancel(thread: libc::pthread_t) -> c_int;
    #[link_name = "pthread_setcancelstate"]
    fn libc_pthread_setcancelstate(state: c_int, oldstate: *mut c_int) -> c_int;
    #[link_name = "pthread_setcanceltype"]
    fn libc_pthread_setcanceltype(typ: c_int, oldtype: *mut c_int) -> c_int;
    #[link_name = "pthread_testcancel"]
    fn libc_pthread_testcancel();
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_cancel(thread: libc::pthread_t) -> c_int {
    unsafe { libc_pthread_cancel(thread) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_setcancelstate(state: c_int, oldstate: *mut c_int) -> c_int {
    unsafe { libc_pthread_setcancelstate(state, oldstate) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_setcanceltype(typ: c_int, oldtype: *mut c_int) -> c_int {
    unsafe { libc_pthread_setcanceltype(typ, oldtype) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_testcancel() {
    unsafe { libc_pthread_testcancel() }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_getattr_np(
    thread: libc::pthread_t,
    attr: *mut libc::pthread_attr_t,
) -> c_int {
    match unsafe { host_pthread_getattr_np_fn() } {
        // SAFETY: resolved symbol ABI matches pthread_getattr_np.
        Some(func) => unsafe { func(thread, attr) },
        None => libc::ENOSYS,
    }
}

// ---------------------------------------------------------------------------
// pthread spin locks — GlibcCallThrough
// ---------------------------------------------------------------------------

unsafe extern "C" {
    #[link_name = "pthread_spin_init"]
    fn libc_pthread_spin_init(lock: *mut c_void, pshared: c_int) -> c_int;
    #[link_name = "pthread_spin_destroy"]
    fn libc_pthread_spin_destroy(lock: *mut c_void) -> c_int;
    #[link_name = "pthread_spin_lock"]
    fn libc_pthread_spin_lock(lock: *mut c_void) -> c_int;
    #[link_name = "pthread_spin_trylock"]
    fn libc_pthread_spin_trylock(lock: *mut c_void) -> c_int;
    #[link_name = "pthread_spin_unlock"]
    fn libc_pthread_spin_unlock(lock: *mut c_void) -> c_int;
    #[link_name = "pthread_barrier_init"]
    fn libc_pthread_barrier_init(
        barrier: *mut c_void,
        attr: *const c_void,
        count: libc::c_uint,
    ) -> c_int;
    #[link_name = "pthread_barrier_destroy"]
    fn libc_pthread_barrier_destroy(barrier: *mut c_void) -> c_int;
    #[link_name = "pthread_barrier_wait"]
    fn libc_pthread_barrier_wait(barrier: *mut c_void) -> c_int;
    #[link_name = "pthread_setname_np"]
    fn libc_pthread_setname_np(thread: libc::pthread_t, name: *const std::ffi::c_char) -> c_int;
    #[link_name = "pthread_getname_np"]
    fn libc_pthread_getname_np(
        thread: libc::pthread_t,
        name: *mut std::ffi::c_char,
        len: usize,
    ) -> c_int;
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_spin_init(lock: *mut c_void, pshared: c_int) -> c_int {
    unsafe { libc_pthread_spin_init(lock, pshared) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_spin_destroy(lock: *mut c_void) -> c_int {
    unsafe { libc_pthread_spin_destroy(lock) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_spin_lock(lock: *mut c_void) -> c_int {
    unsafe { libc_pthread_spin_lock(lock) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_spin_trylock(lock: *mut c_void) -> c_int {
    unsafe { libc_pthread_spin_trylock(lock) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_spin_unlock(lock: *mut c_void) -> c_int {
    unsafe { libc_pthread_spin_unlock(lock) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_barrier_init(
    barrier: *mut c_void,
    attr: *const c_void,
    count: libc::c_uint,
) -> c_int {
    unsafe { libc_pthread_barrier_init(barrier, attr, count) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_barrier_destroy(barrier: *mut c_void) -> c_int {
    unsafe { libc_pthread_barrier_destroy(barrier) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_barrier_wait(barrier: *mut c_void) -> c_int {
    unsafe { libc_pthread_barrier_wait(barrier) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_setname_np(
    thread: libc::pthread_t,
    name: *const std::ffi::c_char,
) -> c_int {
    unsafe { libc_pthread_setname_np(thread, name) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_getname_np(
    thread: libc::pthread_t,
    name: *mut std::ffi::c_char,
    len: usize,
) -> c_int {
    unsafe { libc_pthread_getname_np(thread, name, len) }
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
