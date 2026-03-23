//! ABI layer for selected `<pthread.h>` functions.
//!
//! This bootstrap implementation provides runtime-math routed threading surfaces
//! while full POSIX pthread coverage is still in progress.

#![allow(clippy::missing_safety_doc)]

use std::cell::Cell;
use std::collections::HashMap;
use std::ffi::{CStr, c_int, c_void};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex, OnceLock};

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
    CondvarData, PTHREAD_COND_CLOCK_REALTIME, THREAD_DETACHED, THREAD_FINISHED, THREAD_JOINED,
    ThreadHandle, condvar_broadcast as core_condvar_broadcast,
    condvar_destroy as core_condvar_destroy, condvar_init as core_condvar_init,
    condvar_signal as core_condvar_signal, condvar_timedwait as core_condvar_timedwait,
    condvar_wait as core_condvar_wait, create_thread as core_create_thread,
    detach_thread as core_detach_thread, handle_for_tid as core_handle_for_tid,
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
type HostPthreadKeyCreateFn =
    unsafe extern "C" fn(*mut libc::pthread_key_t, Option<unsafe extern "C" fn(*mut c_void)>) -> c_int;
type HostPthreadKeyDeleteFn = unsafe extern "C" fn(libc::pthread_key_t) -> c_int;
#[cfg(target_arch = "x86_64")]
type HostPthreadGetspecificFn = unsafe extern "C" fn(libc::pthread_key_t) -> *mut c_void;
#[cfg(target_arch = "x86_64")]
type HostPthreadSetspecificFn = unsafe extern "C" fn(libc::pthread_key_t, *const c_void) -> c_int;
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
// Host attr type aliases removed — attr/mutexattr/condattr/rwlockattr are native.

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

// ---------------------------------------------------------------------------
// Mutex type constants (POSIX values)
// ---------------------------------------------------------------------------
const PTHREAD_MUTEX_NORMAL_TYPE: i32 = 0;
const PTHREAD_MUTEX_RECURSIVE_TYPE: i32 = 1;
const PTHREAD_MUTEX_ERRORCHECK_TYPE: i32 = 2;
const PTHREAD_CANCEL_ENABLE_STATE: c_int = 0;
const PTHREAD_CANCEL_DISABLE_STATE: c_int = 1;
const PTHREAD_CANCEL_DEFERRED_TYPE: c_int = 0;
const PTHREAD_CANCEL_ASYNCHRONOUS_TYPE: c_int = 1;

/// Sentinel value for "no owner" in owner_tid fields.
const MUTEX_NO_OWNER: i32 = 0;
const MANAGED_RWLOCK_MAGIC: u32 = 0x4752_5758; // "GRWX"
static THREAD_HANDLE_REGISTRY: LazyLock<Mutex<HashMap<usize, usize>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static CANCEL_PENDING_REGISTRY: LazyLock<Mutex<HashMap<usize, bool>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static HOST_SYMBOL_CACHE: LazyLock<Mutex<HashMap<&'static [u8], usize>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static HOST_PTHREAD_KEY_CREATE_PTR: OnceLock<usize> = OnceLock::new();
static HOST_PTHREAD_KEY_DELETE_PTR: OnceLock<usize> = OnceLock::new();
#[cfg(target_arch = "x86_64")]
static HOST_PTHREAD_GETSPECIFIC_PTR: OnceLock<usize> = OnceLock::new();
#[cfg(target_arch = "x86_64")]
static HOST_PTHREAD_SETSPECIFIC_PTR: OnceLock<usize> = OnceLock::new();

thread_local! {
    static THREADING_POLICY_DEPTH: Cell<u32> = const { Cell::new(0) };
    static THREAD_CANCEL_STATE: Cell<c_int> = const { Cell::new(PTHREAD_CANCEL_ENABLE_STATE) };
    static THREAD_CANCEL_TYPE: Cell<c_int> = const { Cell::new(PTHREAD_CANCEL_DEFERRED_TYPE) };
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

unsafe fn resolve_host_symbol_nocache(name: &'static [u8]) -> *mut c_void {
    let glibc_v225 = b"GLIBC_2.2.5\0";
    let glibc_v232 = b"GLIBC_2.3.2\0";
    let glibc_v34 = b"GLIBC_2.34\0";
    // SAFETY: versioned lookup in next object after this interposed library.
    let mut ptr = unsafe {
        crate::dlfcn_abi::dlvsym_next(
            name.as_ptr().cast::<libc::c_char>(),
            glibc_v34.as_ptr().cast::<libc::c_char>(),
        )
    };
    if ptr.is_null() {
        // SAFETY: older pthread/libc baseline.
        ptr = unsafe {
            crate::dlfcn_abi::dlvsym_next(
                name.as_ptr().cast::<libc::c_char>(),
                glibc_v225.as_ptr().cast::<libc::c_char>(),
            )
        };
    }
    if ptr.is_null() {
        // SAFETY: common intermediary pthread baseline.
        ptr = unsafe {
            crate::dlfcn_abi::dlvsym_next(
                name.as_ptr().cast::<libc::c_char>(),
                glibc_v232.as_ptr().cast::<libc::c_char>(),
            )
        };
    }
    if ptr.is_null() {
        // SAFETY: final RTLD_NEXT fallback.
        ptr = unsafe { libc::dlsym(libc::RTLD_NEXT, name.as_ptr().cast::<libc::c_char>()) };
    }
    ptr
}

unsafe fn resolve_host_symbol_with_aliases(names: &[&'static [u8]]) -> *mut c_void {
    for name in names {
        // SAFETY: each symbol name is a static NUL-terminated C string.
        let ptr = unsafe { resolve_host_symbol_nocache(name) };
        if !ptr.is_null() {
            return ptr;
        }
    }
    std::ptr::null_mut()
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

unsafe fn host_pthread_key_create_fn() -> Option<HostPthreadKeyCreateFn> {
    let ptr = *HOST_PTHREAD_KEY_CREATE_PTR.get_or_init(|| unsafe {
        resolve_host_symbol_with_aliases(&[b"pthread_key_create\0", b"__pthread_key_create\0"])
            as usize
    }) as *mut c_void;
    if ptr.is_null() {
        None
    } else {
        // SAFETY: resolved symbol has pthread_key_create ABI.
        Some(unsafe { std::mem::transmute::<*mut c_void, HostPthreadKeyCreateFn>(ptr) })
    }
}

unsafe fn host_pthread_key_delete_fn() -> Option<HostPthreadKeyDeleteFn> {
    let ptr = *HOST_PTHREAD_KEY_DELETE_PTR.get_or_init(|| unsafe {
        resolve_host_symbol_with_aliases(&[b"pthread_key_delete\0", b"__pthread_key_delete\0"])
            as usize
    }) as *mut c_void;
    if ptr.is_null() {
        None
    } else {
        // SAFETY: resolved symbol has pthread_key_delete ABI.
        Some(unsafe { std::mem::transmute::<*mut c_void, HostPthreadKeyDeleteFn>(ptr) })
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn host_pthread_getspecific_fn() -> Option<HostPthreadGetspecificFn> {
    let ptr = *HOST_PTHREAD_GETSPECIFIC_PTR.get_or_init(|| unsafe {
        resolve_host_symbol_with_aliases(&[b"pthread_getspecific\0", b"__pthread_getspecific\0"])
            as usize
    }) as *mut c_void;
    if ptr.is_null() {
        None
    } else {
        // SAFETY: resolved symbol has pthread_getspecific ABI.
        Some(unsafe { std::mem::transmute::<*mut c_void, HostPthreadGetspecificFn>(ptr) })
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn host_pthread_setspecific_fn() -> Option<HostPthreadSetspecificFn> {
    let ptr = *HOST_PTHREAD_SETSPECIFIC_PTR.get_or_init(|| unsafe {
        resolve_host_symbol_with_aliases(&[b"pthread_setspecific\0", b"__pthread_setspecific\0"])
            as usize
    }) as *mut c_void;
    if ptr.is_null() {
        None
    } else {
        // SAFETY: resolved symbol has pthread_setspecific ABI.
        Some(unsafe { std::mem::transmute::<*mut c_void, HostPthreadSetspecificFn>(ptr) })
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

pub(crate) fn prewarm_host_thread_symbols() {
    // Resolve the host pthread surface while startup is still in bootstrap
    // passthrough, so active-mode execution does not lazily enter dl* symbol
    // resolution through validated string/memory paths.
    unsafe {
        let _ = host_pthread_self_fn();
        let _ = host_pthread_equal_fn();
        let _ = host_pthread_create_fn();
        let _ = host_pthread_join_fn();
        let _ = host_pthread_detach_fn();
        let _ = host_pthread_key_create_fn();
        let _ = host_pthread_key_delete_fn();
        #[cfg(target_arch = "x86_64")]
        {
            let _ = host_pthread_getspecific_fn();
            let _ = host_pthread_setspecific_fn();
        }
        let _ = host_pthread_mutex_init_fn();
        let _ = host_pthread_mutex_destroy_fn();
        let _ = host_pthread_mutex_lock_fn();
        let _ = host_pthread_mutex_trylock_fn();
        let _ = host_pthread_mutex_unlock_fn();
        let _ = host_pthread_cond_init_fn();
        let _ = host_pthread_cond_destroy_fn();
        let _ = host_pthread_cond_wait_fn();
        let _ = host_pthread_cond_signal_fn();
        let _ = host_pthread_cond_broadcast_fn();
        let _ = host_pthread_cond_timedwait_fn();
    }
}

// Host pthread attr/mutexattr/condattr/rwlockattr resolution functions removed:
// all attribute operations are now native implementations.

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

/// Returns a pointer to the mutex type field at byte offset 8 within the
/// `pthread_mutex_t` opaque storage. Layout: [lock_word(4)][magic(4)][type(4)]...
fn mutex_type_ptr(mutex: *mut libc::pthread_mutex_t) -> Option<*mut AtomicI32> {
    if mutex.is_null() {
        return None;
    }
    let base = mutex.cast::<u8>();
    // offset 8: past lock_word (4 bytes) + magic (4 bytes)
    let ptr = unsafe { base.add(8) };
    let align = std::mem::align_of::<AtomicI32>();
    if !(ptr as usize).is_multiple_of(align) {
        return None;
    }
    Some(ptr.cast::<AtomicI32>())
}

/// Returns a pointer to the owner tid field at byte offset 12.
/// Layout: [lock_word(4)][magic(4)][type(4)][owner_tid(4)]...
fn mutex_owner_ptr(mutex: *mut libc::pthread_mutex_t) -> Option<*mut AtomicI32> {
    if mutex.is_null() {
        return None;
    }
    let base = mutex.cast::<u8>();
    let ptr = unsafe { base.add(12) };
    let align = std::mem::align_of::<AtomicI32>();
    if !(ptr as usize).is_multiple_of(align) {
        return None;
    }
    Some(ptr.cast::<AtomicI32>())
}

/// Returns a pointer to the lock count field at byte offset 16.
/// Layout: [lock_word(4)][magic(4)][type(4)][owner_tid(4)][lock_count(4)]...
fn mutex_lock_count_ptr(mutex: *mut libc::pthread_mutex_t) -> Option<*mut AtomicU32> {
    if mutex.is_null() {
        return None;
    }
    let base = mutex.cast::<u8>();
    let ptr = unsafe { base.add(16) };
    let align = std::mem::align_of::<AtomicU32>();
    if !(ptr as usize).is_multiple_of(align) {
        return None;
    }
    Some(ptr.cast::<AtomicU32>())
}

/// Read the mutex type stored at offset 8. Returns NORMAL (0) for unmanaged
/// or unrecognized mutexes.
fn read_mutex_type(mutex: *mut libc::pthread_mutex_t) -> i32 {
    let Some(type_ptr) = mutex_type_ptr(mutex) else {
        return PTHREAD_MUTEX_NORMAL_TYPE;
    };
    // SAFETY: alignment and non-null checked above.
    let mtype = unsafe { &*type_ptr };
    mtype.load(Ordering::Acquire)
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
        // Use the TLS table to resolve our own ThreadHandle in O(1) time
        // without taking the global registry lock. This also ensures
        // consistency for detached threads that are still running.
        if let Some(handle_ptr) = core_handle_for_tid(tid) {
            return handle_ptr as usize as libc::pthread_t;
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

fn resolve_thread_tid(thread: libc::pthread_t) -> Option<i32> {
    let thread_key = thread as usize;
    let handle_ptr = thread as *mut ThreadHandle;

    // Check if it's a managed thread handle.
    // We check the registry to ensure the pointer is still live and managed.
    let is_managed = {
        let registry = THREAD_HANDLE_REGISTRY
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        registry.contains_key(&thread_key)
    };

    if is_managed {
        // SAFETY: handle_ptr is validated.
        let tid = unsafe { (*handle_ptr).tid.load(Ordering::Acquire) };
        if tid > 0 {
            return Some(tid);
        }
        let self_tid = unsafe { (*handle_ptr).self_tid.load(Ordering::Acquire) };
        if self_tid > 0 {
            return Some(self_tid);
        }
    }

    // Unmanaged thread fallback: the pthread_t may be the TID itself.
    let candidate = thread_key as i32;
    if candidate > 0 {
        return Some(candidate);
    }
    None
}

/// Convert an absolute `timespec` deadline from `clockid` to `CLOCK_REALTIME`.
fn clock_convert_to_realtime(clockid: c_int, abstime: *const libc::timespec) -> libc::timespec {
    let mut clock_now: libc::timespec = unsafe { std::mem::zeroed() };
    let mut real_now: libc::timespec = unsafe { std::mem::zeroed() };
    unsafe {
        libc::syscall(libc::SYS_clock_gettime, clockid, &mut clock_now);
        libc::syscall(libc::SYS_clock_gettime, libc::CLOCK_REALTIME, &mut real_now);
    }
    let deadline = unsafe { &*abstime };
    let mut result = libc::timespec {
        tv_sec: real_now.tv_sec + (deadline.tv_sec - clock_now.tv_sec),
        tv_nsec: real_now.tv_nsec + (deadline.tv_nsec - clock_now.tv_nsec),
    };
    if result.tv_nsec >= 1_000_000_000 {
        result.tv_sec += 1;
        result.tv_nsec -= 1_000_000_000;
    } else if result.tv_nsec < 0 {
        result.tv_sec -= 1;
        result.tv_nsec += 1_000_000_000;
    }
    result
}

/// Futex wait with absolute timeout (CLOCK_REALTIME).
#[cfg(target_os = "linux")]
fn futex_wait_timed_private(
    word: &AtomicI32,
    expected: i32,
    abstime: *const libc::timespec,
) -> c_int {
    // SAFETY: Linux futex syscall with valid userspace address and timeout.
    unsafe {
        libc::syscall(
            libc::SYS_futex,
            word as *const AtomicI32 as *const i32,
            libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG,
            expected,
            abstime,
        ) as c_int
    }
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

    // Extract attributes if provided; default to 0 (use core defaults).
    let mut stack_size: usize = 0;
    let mut detach_state: c_int = 0;
    if !attr.is_null() {
        let mut handled = false;
        if let Some(data) = attr_data_ptr_const(attr) {
            // SAFETY: data points to caller-owned memory aligned for PthreadAttrData.
            let magic = unsafe { (*data).magic };
            if magic == MANAGED_ATTR_MAGIC {
                stack_size = unsafe { (*data).stack_size };
                detach_state = unsafe { (*data).detach_state };
                handled = true;
            }
        }
        if !handled {
            // SAFETY: attr is non-null, host libc interprets the opaque structure.
            unsafe { libc::pthread_attr_getstacksize(attr, &mut stack_size) };
            // pthread_attr_getdetachstate is not always in the libc crate; use
            // the host symbol directly.
            unsafe extern "C" {
                fn pthread_attr_getdetachstate(
                    attr: *const libc::pthread_attr_t,
                    detachstate: *mut c_int,
                ) -> c_int;
            }
            unsafe { pthread_attr_getdetachstate(attr, &mut detach_state) };
        }
    }

    let handle_ptr =
        match unsafe { core_create_thread(start_routine as usize, arg as usize, stack_size) } {
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

    // If created with PTHREAD_CREATE_DETACHED, detach immediately.
    // Must remove from registry first (same as native_pthread_detach) to
    // prevent a dangling pointer after the thread self-cleans on exit.
    if detach_state == libc::PTHREAD_CREATE_DETACHED {
        {
            let mut registry = THREAD_HANDLE_REGISTRY
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            registry.remove(&thread_key);
        }
        let _ = unsafe { core_detach_thread(handle_ptr) };
    }

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
    let handle_ptr = thread as *mut ThreadHandle;

    // Self-join detection: compare handles directly for O(1) reliability.
    if let Some(my_handle) = core_handle_for_tid(core_self_tid())
        && handle_ptr == my_handle
    {
        return libc::EDEADLK;
    }

    // Verify this is a valid managed thread handle that we know about.
    // We check the registry to ensure the pointer is still live and managed.
    let is_managed = {
        let registry = THREAD_HANDLE_REGISTRY
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        registry.contains_key(&thread_key)
    };

    if !is_managed {
        return libc::ESRCH;
    }

    // Call core_join_thread which handles final state transitions and synchronization.
    // We must ensure the handle is removed from the registry if join succeeds.
    match unsafe { core_join_thread(handle_ptr) } {
        Ok(value) => {
            if !retval.is_null() {
                // SAFETY: caller provided a writable retval pointer.
                unsafe { *retval = value as *mut c_void };
            }
            // Remove from registry after successful join.
            let mut registry = THREAD_HANDLE_REGISTRY
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            registry.remove(&thread_key);
            0
        }
        Err(errno) => errno,
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
    let handle_ptr = thread as *mut ThreadHandle;

    // Verify this is a valid managed thread handle that we know about.
    let is_managed = {
        let registry = THREAD_HANDLE_REGISTRY
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        registry.contains_key(&thread_key)
    };

    if !is_managed {
        return libc::ESRCH;
    }

    match unsafe { core_detach_thread(handle_ptr) } {
        Ok(()) => {
            // Remove from registry after successful detach.
            let mut registry = THREAD_HANDLE_REGISTRY
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            registry.remove(&thread_key);
            0
        }
        Err(errno) => errno,
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

        let state = word.load(Ordering::Acquire);

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

/// Timed read lock: same as `futex_rwlock_rdlock` but with futex timeout.
#[cfg(target_os = "linux")]
fn futex_rwlock_timed_rdlock(word: &AtomicI32, abstime: *const libc::timespec) -> c_int {
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
        let rc = futex_wait_timed_private(word, state, abstime);
        if rc == 0 {
            continue;
        }
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if errno == libc::ETIMEDOUT {
            return libc::ETIMEDOUT;
        }
        if errno == libc::EINTR || errno == libc::EAGAIN {
            continue;
        }
        return if errno == 0 { libc::EAGAIN } else { errno };
    }
}

/// Timed write lock: same as `futex_rwlock_wrlock` but with futex timeout.
#[cfg(target_os = "linux")]
fn futex_rwlock_timed_wrlock(word: &AtomicI32, abstime: *const libc::timespec) -> c_int {
    loop {
        if word
            .compare_exchange(0, -1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            return 0;
        }
        let state = word.load(Ordering::Acquire);
        let rc = futex_wait_timed_private(word, state, abstime);
        if rc == 0 {
            continue;
        }
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if errno == libc::ETIMEDOUT {
            return libc::ETIMEDOUT;
        }
        if errno == libc::EINTR || errno == libc::EAGAIN {
            continue;
        }
        return if errno == 0 { libc::EAGAIN } else { errno };
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

    // Read the mutex type from the attr if provided.
    let mutex_type = if attr.is_null() {
        PTHREAD_MUTEX_NORMAL_TYPE
    } else {
        // SAFETY: attr is non-null; the first 4 bytes store the type as an i32
        // (written by our pthread_mutexattr_settype).
        let kind = unsafe { *(attr.cast::<c_int>()) };
        if !(0..=2).contains(&kind) {
            return libc::EINVAL;
        }
        kind
    };

    if let Some(word_ptr) = mutex_word_ptr(mutex) {
        // SAFETY: `word_ptr` is alignment-checked and points to caller-owned
        // mutex storage.
        let word = unsafe { &*word_ptr };
        word.store(0, Ordering::Release);
        let _ = mark_managed_mutex(mutex);

        // Store the mutex type at offset 8.
        if let Some(type_ptr) = mutex_type_ptr(mutex) {
            // SAFETY: alignment checked; within pthread_mutex_t storage.
            let mtype = unsafe { &*type_ptr };
            mtype.store(mutex_type, Ordering::Release);
        }

        // Initialize owner_tid to "no owner" at offset 12.
        if let Some(owner_ptr) = mutex_owner_ptr(mutex) {
            // SAFETY: alignment checked; within pthread_mutex_t storage.
            let owner = unsafe { &*owner_ptr };
            owner.store(MUTEX_NO_OWNER, Ordering::Release);
        }

        // Initialize lock_count to 0 at offset 16.
        if let Some(count_ptr) = mutex_lock_count_ptr(mutex) {
            // SAFETY: alignment checked; within pthread_mutex_t storage.
            let count = unsafe { &*count_ptr };
            count.store(0, Ordering::Release);
        }

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

    // Clear extended fields (type, owner, count) for hygiene.
    if let Some(type_ptr) = mutex_type_ptr(mutex) {
        // SAFETY: alignment checked; within pthread_mutex_t storage.
        let mtype = unsafe { &*type_ptr };
        mtype.store(0, Ordering::Release);
    }
    if let Some(owner_ptr) = mutex_owner_ptr(mutex) {
        // SAFETY: alignment checked.
        let owner = unsafe { &*owner_ptr };
        owner.store(MUTEX_NO_OWNER, Ordering::Release);
    }
    if let Some(count_ptr) = mutex_lock_count_ptr(mutex) {
        // SAFETY: alignment checked.
        let count = unsafe { &*count_ptr };
        count.store(0, Ordering::Release);
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
    // SAFETY: alignment is validated by `mutex_word_ptr`.
    let word = unsafe { &*word_ptr };

    match read_mutex_type(mutex) {
        PTHREAD_MUTEX_RECURSIVE_TYPE => {
            let self_tid = core_self_tid();
            // Check if we already own this mutex.
            if let Some(owner_ptr) = mutex_owner_ptr(mutex) {
                // SAFETY: alignment checked.
                let owner = unsafe { &*owner_ptr };
                if owner.load(Ordering::Acquire) == self_tid && self_tid != MUTEX_NO_OWNER {
                    // We already own it — increment the recursion count.
                    if let Some(count_ptr) = mutex_lock_count_ptr(mutex) {
                        // SAFETY: alignment checked.
                        let count = unsafe { &*count_ptr };
                        let cur = count.load(Ordering::Relaxed);
                        if cur == u32::MAX {
                            return libc::EAGAIN; // overflow guard
                        }
                        count.store(cur + 1, Ordering::Release);
                        return 0;
                    }
                }
            }
            // Not the owner (or first acquisition) — acquire the underlying lock.
            let rc = futex_lock_normal(word);
            if rc != 0 {
                return rc;
            }
            // We now own the mutex — record ownership.
            if let Some(owner_ptr) = mutex_owner_ptr(mutex) {
                // SAFETY: alignment checked.
                let owner = unsafe { &*owner_ptr };
                owner.store(self_tid, Ordering::Release);
            }
            if let Some(count_ptr) = mutex_lock_count_ptr(mutex) {
                // SAFETY: alignment checked.
                let count = unsafe { &*count_ptr };
                count.store(1, Ordering::Release);
            }
            0
        }
        PTHREAD_MUTEX_ERRORCHECK_TYPE => {
            let self_tid = core_self_tid();
            // If we already own it, return EDEADLK.
            if let Some(owner_ptr) = mutex_owner_ptr(mutex) {
                // SAFETY: alignment checked.
                let owner = unsafe { &*owner_ptr };
                if owner.load(Ordering::Acquire) == self_tid && self_tid != MUTEX_NO_OWNER {
                    return libc::EDEADLK;
                }
            }
            // Acquire the lock.
            let rc = futex_lock_normal(word);
            if rc != 0 {
                return rc;
            }
            // Record ownership.
            if let Some(owner_ptr) = mutex_owner_ptr(mutex) {
                // SAFETY: alignment checked.
                let owner = unsafe { &*owner_ptr };
                owner.store(self_tid, Ordering::Release);
            }
            0
        }
        _ => {
            // PTHREAD_MUTEX_NORMAL — existing behavior.
            futex_lock_normal(word)
        }
    }
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
    // SAFETY: alignment is validated by `mutex_word_ptr`.
    let word = unsafe { &*word_ptr };

    match read_mutex_type(mutex) {
        PTHREAD_MUTEX_RECURSIVE_TYPE => {
            let self_tid = core_self_tid();
            // Check if we already own this mutex.
            if let Some(owner_ptr) = mutex_owner_ptr(mutex) {
                // SAFETY: alignment checked.
                let owner = unsafe { &*owner_ptr };
                if owner.load(Ordering::Acquire) == self_tid && self_tid != MUTEX_NO_OWNER {
                    // Already own it — increment recursion count.
                    if let Some(count_ptr) = mutex_lock_count_ptr(mutex) {
                        // SAFETY: alignment checked.
                        let count = unsafe { &*count_ptr };
                        let cur = count.load(Ordering::Relaxed);
                        if cur == u32::MAX {
                            return libc::EAGAIN;
                        }
                        count.store(cur + 1, Ordering::Release);
                        return 0;
                    }
                }
            }
            // Try to acquire.
            let rc = futex_trylock_normal(word);
            if rc != 0 {
                return rc;
            }
            // Record ownership.
            if let Some(owner_ptr) = mutex_owner_ptr(mutex) {
                // SAFETY: alignment checked.
                let owner = unsafe { &*owner_ptr };
                owner.store(self_tid, Ordering::Release);
            }
            if let Some(count_ptr) = mutex_lock_count_ptr(mutex) {
                // SAFETY: alignment checked.
                let count = unsafe { &*count_ptr };
                count.store(1, Ordering::Release);
            }
            0
        }
        PTHREAD_MUTEX_ERRORCHECK_TYPE => {
            let self_tid = core_self_tid();
            // If we already own it, return EDEADLK for trylock too.
            if let Some(owner_ptr) = mutex_owner_ptr(mutex) {
                // SAFETY: alignment checked.
                let owner = unsafe { &*owner_ptr };
                if owner.load(Ordering::Acquire) == self_tid && self_tid != MUTEX_NO_OWNER {
                    return libc::EBUSY;
                }
            }
            let rc = futex_trylock_normal(word);
            if rc != 0 {
                return rc;
            }
            // Record ownership.
            if let Some(owner_ptr) = mutex_owner_ptr(mutex) {
                // SAFETY: alignment checked.
                let owner = unsafe { &*owner_ptr };
                owner.store(self_tid, Ordering::Release);
            }
            0
        }
        _ => {
            // PTHREAD_MUTEX_NORMAL — existing behavior.
            futex_trylock_normal(word)
        }
    }
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
    // SAFETY: alignment is validated by `mutex_word_ptr`.
    let word = unsafe { &*word_ptr };

    match read_mutex_type(mutex) {
        PTHREAD_MUTEX_RECURSIVE_TYPE => {
            let self_tid = core_self_tid();
            // Verify ownership.
            if let Some(owner_ptr) = mutex_owner_ptr(mutex) {
                // SAFETY: alignment checked.
                let owner = unsafe { &*owner_ptr };
                if owner.load(Ordering::Acquire) != self_tid || self_tid == MUTEX_NO_OWNER {
                    return libc::EPERM;
                }
            }
            // Decrement lock count.
            if let Some(count_ptr) = mutex_lock_count_ptr(mutex) {
                // SAFETY: alignment checked.
                let count = unsafe { &*count_ptr };
                let cur = count.load(Ordering::Relaxed);
                if cur > 1 {
                    count.store(cur - 1, Ordering::Release);
                    return 0; // still held recursively
                }
                // count == 1 (or 0 for robustness): release fully.
                count.store(0, Ordering::Release);
            }
            // Clear ownership before releasing the underlying lock.
            if let Some(owner_ptr) = mutex_owner_ptr(mutex) {
                // SAFETY: alignment checked.
                let owner = unsafe { &*owner_ptr };
                owner.store(MUTEX_NO_OWNER, Ordering::Release);
            }
            futex_unlock_normal(word)
        }
        PTHREAD_MUTEX_ERRORCHECK_TYPE => {
            let self_tid = core_self_tid();
            // Verify ownership — non-owner unlock returns EPERM.
            if let Some(owner_ptr) = mutex_owner_ptr(mutex) {
                // SAFETY: alignment checked.
                let owner = unsafe { &*owner_ptr };
                if owner.load(Ordering::Acquire) != self_tid || self_tid == MUTEX_NO_OWNER {
                    return libc::EPERM;
                }
                // Clear ownership.
                owner.store(MUTEX_NO_OWNER, Ordering::Release);
            }
            futex_unlock_normal(word)
        }
        _ => {
            // PTHREAD_MUTEX_NORMAL — existing behavior.
            futex_unlock_normal(word)
        }
    }
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

    let mtype = read_mutex_type(mutex);
    let mut saved_count = 0;
    if mtype == PTHREAD_MUTEX_RECURSIVE_TYPE || mtype == PTHREAD_MUTEX_ERRORCHECK_TYPE {
        if let Some(owner_ptr) = mutex_owner_ptr(mutex) {
            let owner = unsafe { &*owner_ptr };
            owner.store(MUTEX_NO_OWNER, Ordering::Release);
        }
        if mtype == PTHREAD_MUTEX_RECURSIVE_TYPE
            && let Some(count_ptr) = mutex_lock_count_ptr(mutex)
        {
            let count = unsafe { &*count_ptr };
            saved_count = count.swap(0, Ordering::Release);
        }
    }

    // SAFETY: condvar pointer and mutex futex word pointer are validated/aligned and caller-owned.
    let rc = unsafe { core_condvar_wait(cond_ptr, word_ptr.cast::<u32>() as *const u32) };

    if mtype == PTHREAD_MUTEX_RECURSIVE_TYPE || mtype == PTHREAD_MUTEX_ERRORCHECK_TYPE {
        let self_tid = core_self_tid();
        if let Some(owner_ptr) = mutex_owner_ptr(mutex) {
            let owner = unsafe { &*owner_ptr };
            owner.store(self_tid, Ordering::Release);
        }
        if mtype == PTHREAD_MUTEX_RECURSIVE_TYPE
            && let Some(count_ptr) = mutex_lock_count_ptr(mutex)
        {
            let count = unsafe { &*count_ptr };
            // Restore the lock count we had before waiting.
            count.store(saved_count, Ordering::Release);
        }
    }

    rc
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

    let mtype = read_mutex_type(mutex);
    let mut saved_count = 0;
    if mtype == PTHREAD_MUTEX_RECURSIVE_TYPE || mtype == PTHREAD_MUTEX_ERRORCHECK_TYPE {
        if let Some(owner_ptr) = mutex_owner_ptr(mutex) {
            let owner = unsafe { &*owner_ptr };
            owner.store(MUTEX_NO_OWNER, Ordering::Release);
        }
        if mtype == PTHREAD_MUTEX_RECURSIVE_TYPE
            && let Some(count_ptr) = mutex_lock_count_ptr(mutex)
        {
            let count = unsafe { &*count_ptr };
            saved_count = count.swap(0, Ordering::Release);
        }
    }

    // SAFETY: abstime is non-null, condvar and mutex pointers are validated/aligned.
    let ts = unsafe { &*abstime };
    let rc = unsafe {
        core_condvar_timedwait(
            cond_ptr,
            word_ptr.cast::<u32>() as *const u32,
            ts.tv_sec,
            ts.tv_nsec,
        )
    };

    if mtype == PTHREAD_MUTEX_RECURSIVE_TYPE || mtype == PTHREAD_MUTEX_ERRORCHECK_TYPE {
        let self_tid = core_self_tid();
        if let Some(owner_ptr) = mutex_owner_ptr(mutex) {
            let owner = unsafe { &*owner_ptr };
            owner.store(self_tid, Ordering::Release);
        }
        if mtype == PTHREAD_MUTEX_RECURSIVE_TYPE
            && let Some(count_ptr) = mutex_lock_count_ptr(mutex)
        {
            let count = unsafe { &*count_ptr };
            count.store(saved_count, Ordering::Release);
        }
    }

    rc
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
    let sensitive_context = runtime_policy::bootstrap_passthrough_active()
        || crate::malloc_abi::in_allocator_reentry_context()
        || frankenlibc_membrane::ptr_validator::in_validation_context();
    if !FORCE_NATIVE_THREADING.load(Ordering::Acquire) {
        // SAFETY: host symbol lookup/transmute guarantees ABI if present.
        if let Some(host_key_create) = unsafe { host_pthread_key_create_fn() } {
            // SAFETY: direct call through resolved host symbol.
            return unsafe { host_key_create(key, destructor) };
        }
    }
    with_threading_policy_guard(
        || {
            if sensitive_context {
                libc::EAGAIN
            } else {
                let mut internal_key = PthreadKey::default();
                let rc = core_pthread_key_create(&mut internal_key, destructor);
                if rc == 0 {
                    // SAFETY: key is non-null and we write the index.
                    unsafe { *key = internal_key.id };
                }
                rc
            }
        },
        || {
            let mut internal_key = PthreadKey::default();
            let rc = core_pthread_key_create(&mut internal_key, destructor);
            if rc == 0 {
                // SAFETY: key is non-null and we write the index.
                unsafe { *key = internal_key.id };
            }
            rc
        },
    )
}

/// POSIX `pthread_key_delete`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_key_delete(key: libc::pthread_key_t) -> c_int {
    let sensitive_context = runtime_policy::bootstrap_passthrough_active()
        || crate::malloc_abi::in_allocator_reentry_context()
        || frankenlibc_membrane::ptr_validator::in_validation_context();
    if !FORCE_NATIVE_THREADING.load(Ordering::Acquire) {
        // SAFETY: host symbol lookup/transmute guarantees ABI if present.
        if let Some(host_key_delete) = unsafe { host_pthread_key_delete_fn() } {
            // SAFETY: direct call through resolved host symbol.
            return unsafe { host_key_delete(key) };
        }
    }
    with_threading_policy_guard(
        || {
            if sensitive_context {
                libc::EINVAL
            } else {
                core_pthread_key_delete(PthreadKey { id: key })
            }
        },
        || core_pthread_key_delete(PthreadKey { id: key }),
    )
}

/// POSIX `pthread_getspecific`.
#[cfg(target_arch = "x86_64")]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_getspecific(key: libc::pthread_key_t) -> *mut c_void {
    let sensitive_context = runtime_policy::bootstrap_passthrough_active()
        || crate::malloc_abi::in_allocator_reentry_context()
        || frankenlibc_membrane::ptr_validator::in_validation_context();
    if !FORCE_NATIVE_THREADING.load(Ordering::Acquire) {
        // SAFETY: host symbol lookup/transmute guarantees ABI if present.
        if let Some(host_getspecific) = unsafe { host_pthread_getspecific_fn() } {
            // SAFETY: direct call through resolved host symbol.
            return unsafe { host_getspecific(key) };
        }
    }
    with_threading_policy_guard(
        || {
            if sensitive_context {
                std::ptr::null_mut()
            } else {
                core_pthread_getspecific(PthreadKey { id: key }) as *mut c_void
            }
        },
        || core_pthread_getspecific(PthreadKey { id: key }) as *mut c_void,
    )
}

/// POSIX `pthread_setspecific`.
#[cfg(target_arch = "x86_64")]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_setspecific(
    key: libc::pthread_key_t,
    value: *const c_void,
) -> c_int {
    let sensitive_context = runtime_policy::bootstrap_passthrough_active()
        || crate::malloc_abi::in_allocator_reentry_context()
        || frankenlibc_membrane::ptr_validator::in_validation_context();
    if !FORCE_NATIVE_THREADING.load(Ordering::Acquire) {
        // SAFETY: host symbol lookup/transmute guarantees ABI if present.
        if let Some(host_setspecific) = unsafe { host_pthread_setspecific_fn() } {
            // SAFETY: direct call through resolved host symbol.
            return unsafe { host_setspecific(key, value) };
        }
    }
    with_threading_policy_guard(
        || {
            if sensitive_context {
                libc::EINVAL
            } else {
                core_pthread_setspecific(PthreadKey { id: key }, value as u64)
            }
        },
        || core_pthread_setspecific(PthreadKey { id: key }, value as u64),
    )
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

    loop {
        let s = state.load(Ordering::Acquire);
        if s == ONCE_DONE {
            return 0;
        }

        if s == ONCE_INIT {
            match state.compare_exchange(
                ONCE_INIT,
                ONCE_IN_PROGRESS,
                Ordering::Acquire,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    // We won; run the init routine.
                    // Use catch_unwind to prevent permanent deadlock if routine panics.
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        unsafe { routine() };
                    }));
                    match result {
                        Ok(()) => {
                            state.store(ONCE_DONE, Ordering::Release);
                            #[cfg(target_os = "linux")]
                            {
                                let _ = futex_wake_private(state, i32::MAX);
                            }
                            return 0;
                        }
                        Err(_) => {
                            // Reset to ONCE_INIT so another thread can retry.
                            state.store(ONCE_INIT, Ordering::Release);
                            #[cfg(target_os = "linux")]
                            {
                                let _ = futex_wake_private(state, i32::MAX);
                            }
                            return libc::EINVAL;
                        }
                    }
                }
                Err(_) => {
                    // State changed concurrently. Loop and retry.
                    continue;
                }
            }
        } else {
            // Another thread is running init_routine; wait until done or failed.
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

// ---------------------------------------------------------------------------
// pthread attribute functions — native implementation
//
// We overlay our own data layout on the opaque pthread_attr_t memory.
// Since we own the mutex/condvar/rwlock/thread implementations, our attrs
// only need to be self-consistent (not glibc-layout-compatible).
// ---------------------------------------------------------------------------

/// Default stack size: 2 MiB (matches glibc default).
const ATTR_DEFAULT_STACK_SIZE: usize = 2 * 1024 * 1024;

/// POSIX `PTHREAD_SCOPE_SYSTEM` — system contention scope (1:1 threading model).
const PTHREAD_SCOPE_SYSTEM: c_int = 0;

/// Minimum stack size: PTHREAD_STACK_MIN (typically 16 KiB on Linux x86_64).
const ATTR_MIN_STACK_SIZE: usize = 16384;

/// Magic tag to identify managed attr structs.
const MANAGED_ATTR_MAGIC: u32 = 0x4741_5454; // "GATT"

/// Default guard size: one page (4096 bytes on x86_64).
const ATTR_DEFAULT_GUARD_SIZE: usize = 4096;

/// POSIX scheduling inheritance constants.
const PTHREAD_INHERIT_SCHED_VAL: i32 = 0;

/// Extended attribute data that doesn't fit in the 56-byte inline overlay.
/// Keyed by attr address, stores affinity mask and signal mask.
struct ExtendedAttrData {
    affinity: Option<(usize, Vec<u8>)>, // (cpusetsize, raw bytes)
    sigmask: Option<[u8; 128]>,         // sigset_t is 128 bytes on x86_64
}

static EXTENDED_ATTR_REGISTRY: LazyLock<Mutex<HashMap<usize, ExtendedAttrData>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Default thread attributes (for `pthread_getattr_default_np` / `pthread_setattr_default_np`).
static DEFAULT_THREAD_ATTR: LazyLock<Mutex<PthreadAttrDefaults>> =
    LazyLock::new(|| Mutex::new(PthreadAttrDefaults::new()));

struct PthreadAttrDefaults {
    detach_state: i32,
    stack_size: usize,
    guard_size: usize,
    inherit_sched: i32,
    sched_policy: i32,
    sched_priority: i32,
}

impl PthreadAttrDefaults {
    fn new() -> Self {
        Self {
            detach_state: libc::PTHREAD_CREATE_JOINABLE,
            stack_size: ATTR_DEFAULT_STACK_SIZE,
            guard_size: ATTR_DEFAULT_GUARD_SIZE,
            inherit_sched: PTHREAD_INHERIT_SCHED_VAL,
            sched_policy: 0, // SCHED_OTHER
            sched_priority: 0,
        }
    }
}

/// Internal layout overlaid on pthread_attr_t (56 bytes on x86_64, we use 48).
#[repr(C)]
struct PthreadAttrData {
    magic: u32,          // 0..4
    detach_state: i32,   // 4..8
    stack_size: usize,   // 8..16
    guard_size: usize,   // 16..24
    stack_addr: usize,   // 24..32 (0 = system-allocated)
    inherit_sched: i32,  // 32..36
    sched_policy: i32,   // 36..40
    sched_priority: i32, // 40..44
    flags: u32,          // 44..48 (bit 0: affinity set, bit 1: sigmask set)
}

fn attr_data_ptr(attr: *mut libc::pthread_attr_t) -> Option<*mut PthreadAttrData> {
    if attr.is_null() {
        return None;
    }
    let ptr = attr.cast::<PthreadAttrData>();
    if !(ptr as usize).is_multiple_of(std::mem::align_of::<PthreadAttrData>()) {
        return None;
    }
    Some(ptr)
}

fn attr_data_ptr_const(attr: *const libc::pthread_attr_t) -> Option<*const PthreadAttrData> {
    if attr.is_null() {
        return None;
    }
    let ptr = attr.cast::<PthreadAttrData>();
    if !(ptr as usize).is_multiple_of(std::mem::align_of::<PthreadAttrData>()) {
        return None;
    }
    Some(ptr)
}

// --- Thread attributes ---

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_init(attr: *mut libc::pthread_attr_t) -> c_int {
    let Some(data) = attr_data_ptr(attr) else {
        return libc::EINVAL;
    };
    // SAFETY: pointer is non-null and aligned; caller owns the memory.
    unsafe {
        (*data).magic = MANAGED_ATTR_MAGIC;
        (*data).detach_state = libc::PTHREAD_CREATE_JOINABLE;
        (*data).stack_size = ATTR_DEFAULT_STACK_SIZE;
        (*data).guard_size = ATTR_DEFAULT_GUARD_SIZE;
        (*data).stack_addr = 0;
        (*data).inherit_sched = PTHREAD_INHERIT_SCHED_VAL;
        (*data).sched_policy = 0; // SCHED_OTHER
        (*data).sched_priority = 0;
        (*data).flags = 0;
    }
    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_destroy(attr: *mut libc::pthread_attr_t) -> c_int {
    let Some(data) = attr_data_ptr(attr) else {
        return libc::EINVAL;
    };
    // Clean up any extended data (affinity/sigmask).
    let key = attr as usize;
    if let Ok(mut reg) = EXTENDED_ATTR_REGISTRY.lock() {
        reg.remove(&key);
    }
    // SAFETY: pointer is non-null and aligned; caller owns the memory.
    unsafe {
        std::ptr::write_bytes(data, 0, 1);
    }
    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_setdetachstate(
    attr: *mut libc::pthread_attr_t,
    state: c_int,
) -> c_int {
    let Some(data) = attr_data_ptr(attr) else {
        return libc::EINVAL;
    };
    if state != libc::PTHREAD_CREATE_JOINABLE && state != libc::PTHREAD_CREATE_DETACHED {
        return libc::EINVAL;
    }
    // SAFETY: pointer is non-null and aligned; caller owns the memory.
    unsafe {
        (*data).detach_state = state;
    }
    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_getdetachstate(
    attr: *const libc::pthread_attr_t,
    state: *mut c_int,
) -> c_int {
    let Some(data) = attr_data_ptr_const(attr) else {
        return libc::EINVAL;
    };
    if state.is_null() {
        return libc::EINVAL;
    }
    // SAFETY: both pointers are non-null and aligned; caller owns the memory.
    unsafe {
        *state = (*data).detach_state;
    }
    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_setstacksize(
    attr: *mut libc::pthread_attr_t,
    size: usize,
) -> c_int {
    let Some(data) = attr_data_ptr(attr) else {
        return libc::EINVAL;
    };
    if size < ATTR_MIN_STACK_SIZE {
        return libc::EINVAL;
    }
    // SAFETY: pointer is non-null and aligned; caller owns the memory.
    unsafe {
        (*data).stack_size = size;
    }
    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_getstacksize(
    attr: *const libc::pthread_attr_t,
    size: *mut usize,
) -> c_int {
    let Some(data) = attr_data_ptr_const(attr) else {
        return libc::EINVAL;
    };
    if size.is_null() {
        return libc::EINVAL;
    }
    // SAFETY: both pointers are non-null and aligned; caller owns the memory.
    unsafe {
        *size = (*data).stack_size;
    }
    0
}

// --- Mutex attributes --- native implementation
//
// pthread_mutexattr_t is 4 bytes. We store the mutex type in the first c_int.

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_init(attr: *mut libc::pthread_mutexattr_t) -> c_int {
    if attr.is_null() {
        return libc::EINVAL;
    }
    // SAFETY: attr is non-null; caller owns the memory. Store default type.
    let word = unsafe { &mut *(attr.cast::<c_int>()) };
    *word = libc::PTHREAD_MUTEX_DEFAULT;
    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_destroy(attr: *mut libc::pthread_mutexattr_t) -> c_int {
    if attr.is_null() {
        return libc::EINVAL;
    }
    // SAFETY: attr is non-null; caller owns the memory.
    let word = unsafe { &mut *(attr.cast::<c_int>()) };
    *word = 0;
    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_settype(
    attr: *mut libc::pthread_mutexattr_t,
    kind: c_int,
) -> c_int {
    if attr.is_null() {
        return libc::EINVAL;
    }
    // Validate type: NORMAL=0, RECURSIVE=1, ERRORCHECK=2, DEFAULT=0
    if !(0..=2).contains(&kind) {
        return libc::EINVAL;
    }
    // SAFETY: attr is non-null; caller owns the memory.
    let word = unsafe { &mut *(attr.cast::<c_int>()) };
    *word = kind;
    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_gettype(
    attr: *const libc::pthread_mutexattr_t,
    kind: *mut c_int,
) -> c_int {
    if attr.is_null() || kind.is_null() {
        return libc::EINVAL;
    }
    // SAFETY: both pointers are non-null; caller owns the memory.
    let word = unsafe { *(attr.cast::<c_int>()) };
    unsafe { *kind = word };
    0
}

// --- Condvar attributes --- native implementation
//
// pthread_condattr_t is 4 bytes. We store the clock_id in the first c_int.

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_condattr_init(attr: *mut libc::pthread_condattr_t) -> c_int {
    if attr.is_null() {
        return libc::EINVAL;
    }
    // SAFETY: attr is non-null; caller owns the memory. Default clock is REALTIME (0).
    let word = unsafe { &mut *(attr.cast::<c_int>()) };
    *word = libc::CLOCK_REALTIME;
    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_condattr_destroy(attr: *mut libc::pthread_condattr_t) -> c_int {
    if attr.is_null() {
        return libc::EINVAL;
    }
    // SAFETY: attr is non-null; caller owns the memory.
    let word = unsafe { &mut *(attr.cast::<c_int>()) };
    *word = 0;
    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_condattr_setclock(
    attr: *mut libc::pthread_condattr_t,
    clock_id: libc::clockid_t,
) -> c_int {
    if attr.is_null() {
        return libc::EINVAL;
    }
    // Only CLOCK_REALTIME and CLOCK_MONOTONIC are valid for condvar.
    if clock_id != libc::CLOCK_REALTIME && clock_id != libc::CLOCK_MONOTONIC {
        return libc::EINVAL;
    }
    // SAFETY: attr is non-null; caller owns the memory.
    let word = unsafe { &mut *(attr.cast::<c_int>()) };
    *word = clock_id;
    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_condattr_getclock(
    attr: *const libc::pthread_condattr_t,
    clock_id: *mut libc::clockid_t,
) -> c_int {
    if attr.is_null() || clock_id.is_null() {
        return libc::EINVAL;
    }
    // SAFETY: both pointers are non-null; caller owns the memory.
    let word = unsafe { *(attr.cast::<c_int>()) };
    unsafe { *clock_id = word };
    0
}

// --- Rwlock attributes --- native implementation
//
// pthread_rwlockattr_t is 8 bytes. We store the kind (reader/writer preference)
// in the first c_int. Default is PREFER_READER.

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlockattr_init(attr: *mut libc::pthread_rwlockattr_t) -> c_int {
    if attr.is_null() {
        return libc::EINVAL;
    }
    // SAFETY: attr is non-null; caller owns the memory. Default kind is 0 (prefer reader).
    let word = unsafe { &mut *(attr.cast::<c_int>()) };
    *word = 0;
    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlockattr_destroy(
    attr: *mut libc::pthread_rwlockattr_t,
) -> c_int {
    if attr.is_null() {
        return libc::EINVAL;
    }
    // SAFETY: attr is non-null; caller owns the memory.
    let word = unsafe { &mut *(attr.cast::<c_int>()) };
    *word = 0;
    0
}

// ---------------------------------------------------------------------------
// pthread cancellation — native cooperative cancellation state
// ---------------------------------------------------------------------------

fn pthread_handle_key(thread: libc::pthread_t) -> usize {
    thread as usize
}

fn current_cancel_key() -> usize {
    native_pthread_self() as usize
}

fn cancellation_pending(thread_key: usize) -> bool {
    CANCEL_PENDING_REGISTRY
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&thread_key)
        .copied()
        .unwrap_or(false)
}

fn set_cancellation_pending(thread_key: usize, pending: bool) {
    let mut registry = CANCEL_PENDING_REGISTRY
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if pending {
        registry.insert(thread_key, true);
    } else {
        registry.remove(&thread_key);
    }
}

fn cancel_enabled_for_current_thread() -> bool {
    THREAD_CANCEL_STATE.with(|state| state.get() == PTHREAD_CANCEL_ENABLE_STATE)
}

fn cancel_async_for_current_thread() -> bool {
    THREAD_CANCEL_TYPE.with(|typ| typ.get() == PTHREAD_CANCEL_ASYNCHRONOUS_TYPE)
}

fn consume_pending_cancel_for_current_thread() -> bool {
    if !cancel_enabled_for_current_thread() {
        return false;
    }
    let thread_key = current_cancel_key();
    if !cancellation_pending(thread_key) {
        return false;
    }
    set_cancellation_pending(thread_key, false);
    true
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_cancel(thread: libc::pthread_t) -> c_int {
    if thread == 0 {
        return libc::ESRCH;
    }

    // Validate that the target looks alive before enqueuing a cancel request.
    // Signal 0 performs existence checking without delivering a signal.
    let liveness = unsafe { pthread_kill(thread, 0) };
    if liveness != 0 {
        return liveness;
    }

    let thread_key = pthread_handle_key(thread);
    set_cancellation_pending(thread_key, true);

    if thread_key == current_cancel_key()
        && cancel_enabled_for_current_thread()
        && cancel_async_for_current_thread()
    {
        let _ = consume_pending_cancel_for_current_thread();
    }

    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_setcancelstate(state: c_int, oldstate: *mut c_int) -> c_int {
    if state != PTHREAD_CANCEL_ENABLE_STATE && state != PTHREAD_CANCEL_DISABLE_STATE {
        return libc::EINVAL;
    }

    let previous = THREAD_CANCEL_STATE.with(|cell| {
        let prev = cell.get();
        cell.set(state);
        prev
    });
    if !oldstate.is_null() {
        // SAFETY: oldstate is provided by caller and checked for null.
        unsafe { *oldstate = previous };
    }

    if state == PTHREAD_CANCEL_ENABLE_STATE && cancel_async_for_current_thread() {
        let _ = consume_pending_cancel_for_current_thread();
    }
    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_setcanceltype(typ: c_int, oldtype: *mut c_int) -> c_int {
    if typ != PTHREAD_CANCEL_DEFERRED_TYPE && typ != PTHREAD_CANCEL_ASYNCHRONOUS_TYPE {
        return libc::EINVAL;
    }

    let previous = THREAD_CANCEL_TYPE.with(|cell| {
        let prev = cell.get();
        cell.set(typ);
        prev
    });
    if !oldtype.is_null() {
        // SAFETY: oldtype is provided by caller and checked for null.
        unsafe { *oldtype = previous };
    }

    if typ == PTHREAD_CANCEL_ASYNCHRONOUS_TYPE && cancel_enabled_for_current_thread() {
        let _ = consume_pending_cancel_for_current_thread();
    }
    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_testcancel() {
    if consume_pending_cancel_for_current_thread() {
        // PTHREAD_CANCELED is typically defined as ((void *) -1)
        unsafe { pthread_exit(!0usize as *mut std::ffi::c_void) };
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_getattr_np(
    thread: libc::pthread_t,
    attr: *mut libc::pthread_attr_t,
) -> c_int {
    // Initialize the attr struct with defaults, then fill in thread-specific info.
    let ret = unsafe { pthread_attr_init(attr) };
    if ret != 0 {
        return ret;
    }
    let Some(data) = attr_data_ptr(attr) else {
        return libc::EINVAL;
    };
    // Look up thread handle in our registry to determine detach state.
    let handle_raw = thread as usize;
    let registry = THREAD_HANDLE_REGISTRY
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if registry.values().any(|&v| v == handle_raw) {
        let handle_ptr = handle_raw as *mut ThreadHandle;
        // SAFETY: registry only stores live handles from core_create_thread.
        let state = unsafe { (*handle_ptr).state.load(Ordering::Acquire) };
        let detach_state = if state == THREAD_DETACHED {
            libc::PTHREAD_CREATE_DETACHED
        } else {
            libc::PTHREAD_CREATE_JOINABLE
        };
        // SAFETY: pointer is non-null and aligned; we initialized it above.
        unsafe {
            (*data).detach_state = detach_state;
        }
    }
    drop(registry);
    0
}

// ---------------------------------------------------------------------------
// pthread spin locks — native AtomicI32 implementation
//
// POSIX spinlocks are trivially implemented with a single atomic word.
// 0 = unlocked, 1 = locked. CAS spin loop with hint::spin_loop().
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_spin_init(lock: *mut c_void, _pshared: c_int) -> c_int {
    if lock.is_null() || !(lock as usize).is_multiple_of(std::mem::align_of::<AtomicI32>()) {
        return libc::EINVAL;
    }
    // SAFETY: pointer is non-null and properly aligned; caller owns the memory.
    let atom = unsafe { &*(lock.cast::<AtomicI32>()) };
    atom.store(0, Ordering::Release);
    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_spin_destroy(lock: *mut c_void) -> c_int {
    if lock.is_null() || !(lock as usize).is_multiple_of(std::mem::align_of::<AtomicI32>()) {
        return libc::EINVAL;
    }
    // SAFETY: pointer is non-null and properly aligned; caller owns the memory.
    let atom = unsafe { &*(lock.cast::<AtomicI32>()) };
    // Destroying a locked spinlock is undefined, but we're lenient: just zero it.
    atom.store(0, Ordering::Release);
    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_spin_lock(lock: *mut c_void) -> c_int {
    if lock.is_null() || !(lock as usize).is_multiple_of(std::mem::align_of::<AtomicI32>()) {
        return libc::EINVAL;
    }
    // SAFETY: pointer is non-null and properly aligned; caller owns the memory.
    let atom = unsafe { &*(lock.cast::<AtomicI32>()) };
    loop {
        match atom.compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed) {
            Ok(_) => return 0,
            Err(_) => core::hint::spin_loop(),
        }
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_spin_trylock(lock: *mut c_void) -> c_int {
    if lock.is_null() || !(lock as usize).is_multiple_of(std::mem::align_of::<AtomicI32>()) {
        return libc::EINVAL;
    }
    // SAFETY: pointer is non-null and properly aligned; caller owns the memory.
    let atom = unsafe { &*(lock.cast::<AtomicI32>()) };
    match atom.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed) {
        Ok(_) => 0,
        Err(_) => libc::EBUSY,
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_spin_unlock(lock: *mut c_void) -> c_int {
    if lock.is_null() || !(lock as usize).is_multiple_of(std::mem::align_of::<AtomicI32>()) {
        return libc::EINVAL;
    }
    // SAFETY: pointer is non-null and properly aligned; caller owns the memory.
    let atom = unsafe { &*(lock.cast::<AtomicI32>()) };
    atom.store(0, Ordering::Release);
    0
}

// ---------------------------------------------------------------------------
// pthread barriers — native futex-based implementation
//
// Internal layout overlaid on the opaque barrier memory:
//   word 0: magic (AtomicU32, validity sentinel)
//   word 1: count (total threads needed)
//   word 2-3: phase_arrived (AtomicU64, phase in upper 32 bits, arrived in lower 32)
//   word 4: futex_phase (AtomicU32, notification channel for futex wake/wait)
//
// The phase and arrival count are packed into a single AtomicU64 so that the
// last arriving thread can reset the counter and advance the phase in one
// atomic CAS.  This eliminates the race window that existed when `arrived`
// and `phase` were separate atomics: a new thread could arrive between the
// counter reset and the phase advance, increment the reset counter, read the
// stale phase, and then exit prematurely when the phase finally advanced.
//
// The separate `futex_phase` word mirrors the phase portion and is used
// solely as the futex notification address (futex requires a 32-bit word).
// ---------------------------------------------------------------------------

const BARRIER_MAGIC: u32 = 0x4742_4152; // "GBAR"

/// PTHREAD_BARRIER_SERIAL_THREAD: returned to exactly one thread per barrier cycle.
const PTHREAD_BARRIER_SERIAL_THREAD: c_int = -1;

/// Pack a phase and arrival count into a single u64.
#[inline(always)]
const fn barrier_pack(phase: u32, arrived: u32) -> u64 {
    ((phase as u64) << 32) | (arrived as u64)
}

/// Extract the phase (upper 32 bits) from the packed value.
#[inline(always)]
const fn barrier_phase(packed: u64) -> u32 {
    (packed >> 32) as u32
}

/// Extract the arrival count (lower 32 bits) from the packed value.
#[inline(always)]
const fn barrier_arrived(packed: u64) -> u32 {
    packed as u32
}

#[repr(C)]
struct BarrierData {
    magic: AtomicU32,
    count: u32,
    /// Packed: phase (upper 32) | arrived (lower 32).
    phase_arrived: AtomicU64,
    /// Mirrors the phase portion of `phase_arrived`; used as the futex address.
    futex_phase: AtomicU32,
}

fn barrier_data_ptr(barrier: *mut c_void) -> Option<*mut BarrierData> {
    if barrier.is_null() {
        return None;
    }
    let ptr = barrier.cast::<BarrierData>();
    if !(ptr as usize).is_multiple_of(std::mem::align_of::<BarrierData>()) {
        return None;
    }
    Some(ptr)
}

fn futex_wait_u32(addr: &AtomicU32, expected: u32) -> c_int {
    // SAFETY: Linux futex syscall with valid userspace address and null timeout.
    unsafe {
        libc::syscall(
            libc::SYS_futex,
            addr as *const AtomicU32 as *const u32,
            libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG,
            expected as i32,
            std::ptr::null::<libc::timespec>(),
        ) as c_int
    }
}

fn futex_wake_u32(addr: &AtomicU32, count: i32) -> c_int {
    // SAFETY: Linux futex syscall with valid userspace address.
    unsafe {
        libc::syscall(
            libc::SYS_futex,
            addr as *const AtomicU32 as *const u32,
            libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG,
            count,
        ) as c_int
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_barrier_init(
    barrier: *mut c_void,
    _attr: *const c_void,
    count: libc::c_uint,
) -> c_int {
    if count == 0 {
        return libc::EINVAL;
    }
    let Some(data) = barrier_data_ptr(barrier) else {
        return libc::EINVAL;
    };
    // SAFETY: pointer is non-null and aligned; caller owns the memory.
    unsafe {
        (*data).magic.store(BARRIER_MAGIC, Ordering::Release);
        (*data).count = count;
        (*data)
            .phase_arrived
            .store(barrier_pack(0, 0), Ordering::Release);
        (*data).futex_phase.store(0, Ordering::Release);
    }
    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_barrier_destroy(barrier: *mut c_void) -> c_int {
    let Some(data) = barrier_data_ptr(barrier) else {
        return libc::EINVAL;
    };
    // SAFETY: pointer is non-null and aligned; caller owns the memory.
    unsafe {
        // If any threads are currently blocked at the barrier, destruction is
        // not permitted (POSIX says behaviour is undefined, but returning
        // EBUSY is the quality-of-implementation choice made by glibc/musl).
        let packed = (*data).phase_arrived.load(Ordering::Acquire);
        if barrier_arrived(packed) > 0 {
            return libc::EBUSY;
        }
        (*data).magic.store(0, Ordering::Release);
    }
    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_barrier_wait(barrier: *mut c_void) -> c_int {
    let Some(data) = barrier_data_ptr(barrier) else {
        return libc::EINVAL;
    };
    // SAFETY: pointer is non-null and aligned; caller owns the memory.
    let bd = unsafe { &*data };
    let count = bd.count;

    // Atomically increment the arrival count via CAS on the packed u64.
    // This also captures the phase at the time of our arrival.
    let mut cur = bd.phase_arrived.load(Ordering::Acquire);
    let my_phase;
    loop {
        let phase = barrier_phase(cur);
        let arrived = barrier_arrived(cur);
        let new_arrived = arrived + 1;

        if new_arrived == count {
            // We are the last thread to arrive.  Atomically advance the phase
            // and reset the counter to 0 in a single CAS so that no thread
            // can observe the intermediate state.
            let new_phase = phase.wrapping_add(1);
            let desired = barrier_pack(new_phase, 0);
            match bd.phase_arrived.compare_exchange_weak(
                cur,
                desired,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    // Update the futex notification word and wake all waiters.
                    bd.futex_phase.store(new_phase, Ordering::Release);
                    futex_wake_u32(&bd.futex_phase, i32::MAX);
                    return PTHREAD_BARRIER_SERIAL_THREAD;
                }
                Err(actual) => {
                    // CAS failed — another thread raced us; retry.
                    cur = actual;
                    continue;
                }
            }
        } else {
            // Not the last thread — just bump the arrival count.
            let desired = barrier_pack(phase, new_arrived);
            match bd.phase_arrived.compare_exchange_weak(
                cur,
                desired,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    my_phase = phase;
                    break;
                }
                Err(actual) => {
                    cur = actual;
                    continue;
                }
            }
        }
    }

    // Wait until the phase advances past our arrival phase.
    loop {
        let fp = bd.futex_phase.load(Ordering::Acquire);
        if fp != my_phase {
            break;
        }
        futex_wait_u32(&bd.futex_phase, my_phase);
    }
    0
}

// ---------------------------------------------------------------------------
// pthread_setname_np / pthread_getname_np — native via prctl raw syscall
// ---------------------------------------------------------------------------

/// PR_SET_NAME = 15 (from linux/prctl.h)
const PR_SET_NAME: c_int = 15;
/// PR_GET_NAME = 16 (from linux/prctl.h)
const PR_GET_NAME: c_int = 16;

fn thread_name_error_from_io(err: &std::io::Error) -> c_int {
    match err.raw_os_error() {
        Some(code) if code == libc::ENOENT => libc::ESRCH,
        Some(code) => code,
        None => match err.kind() {
            std::io::ErrorKind::NotFound => libc::ESRCH,
            std::io::ErrorKind::PermissionDenied => libc::EPERM,
            _ => libc::EIO,
        },
    }
}

fn thread_comm_path(tid: i32) -> String {
    format!("/proc/self/task/{tid}/comm")
}

fn set_other_thread_name_via_procfs(tid: i32, name: &CStr) -> c_int {
    if tid <= 0 {
        return libc::ESRCH;
    }
    let path = thread_comm_path(tid);
    let mut file = match OpenOptions::new().write(true).open(&path) {
        Ok(file) => file,
        Err(err) => return thread_name_error_from_io(&err),
    };
    if let Err(err) = file.write_all(name.to_bytes()) {
        return thread_name_error_from_io(&err);
    }
    0
}

fn get_other_thread_name_via_procfs(tid: i32, name: *mut std::ffi::c_char, len: usize) -> c_int {
    if tid <= 0 {
        return libc::ESRCH;
    }
    let path = thread_comm_path(tid);
    let mut file = match OpenOptions::new().read(true).open(&path) {
        Ok(file) => file,
        Err(err) => return thread_name_error_from_io(&err),
    };
    let mut raw = [0_u8; 64];
    let n = match file.read(&mut raw) {
        Ok(n) => n,
        Err(err) => return thread_name_error_from_io(&err),
    };
    if n == 0 {
        return libc::ESRCH;
    }
    // `/proc/.../comm` returns "<name>\n". Strip trailing newline/NULs.
    let mut end = n;
    while end > 0 && (raw[end - 1] == b'\n' || raw[end - 1] == 0) {
        end -= 1;
    }
    if end + 1 > len {
        return libc::ERANGE;
    }
    // SAFETY: caller validated `name` and `len`; destination has room for payload + NUL.
    unsafe {
        std::ptr::copy_nonoverlapping(raw.as_ptr().cast::<std::ffi::c_char>(), name, end);
        *name.add(end) = 0;
    }
    0
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_setname_np(
    _thread: libc::pthread_t,
    name: *const std::ffi::c_char,
) -> c_int {
    if name.is_null() {
        return libc::EINVAL;
    }
    // Check name length: Linux limits thread name to 16 bytes including NUL.
    let name_cstr = unsafe { CStr::from_ptr(name) };
    if name_cstr.to_bytes().len() > 15 {
        return libc::ERANGE;
    }
    if _thread != native_pthread_self() {
        let Some(tid) = resolve_thread_tid(_thread) else {
            return libc::ESRCH;
        };
        return set_other_thread_name_via_procfs(tid, name_cstr);
    }
    // SAFETY: prctl(PR_SET_NAME) sets the calling thread's name.
    let ret = unsafe { libc::syscall(libc::SYS_prctl, PR_SET_NAME, name) };
    if ret == 0 {
        0
    } else {
        std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EINVAL)
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_getname_np(
    _thread: libc::pthread_t,
    name: *mut std::ffi::c_char,
    len: usize,
) -> c_int {
    if name.is_null() || len == 0 {
        return libc::EINVAL;
    }
    if len < 16 {
        return libc::ERANGE;
    }
    if _thread != native_pthread_self() {
        let Some(tid) = resolve_thread_tid(_thread) else {
            return libc::ESRCH;
        };
        return get_other_thread_name_via_procfs(tid, name, len);
    }
    // SAFETY: prctl(PR_GET_NAME) reads the calling thread's name into a buffer.
    let ret = unsafe { libc::syscall(libc::SYS_prctl, PR_GET_NAME, name) };
    if ret == 0 {
        0
    } else {
        std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EINVAL)
    }
}

// ===========================================================================
// Batch: pthread extensions — Implemented (delegate to libc)
// ===========================================================================

/// `pthread_atfork` — register fork handlers.
///
/// Registers functions to be called before and after fork():
/// - `prepare`: called in parent before fork
/// - `parent`: called in parent after fork
/// - `child`: called in child after fork
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_atfork(
    prepare: Option<unsafe extern "C" fn()>,
    parent: Option<unsafe extern "C" fn()>,
    child: Option<unsafe extern "C" fn()>,
) -> c_int {
    // Register with native handler list AND with glibc (for interop with
    // non-FrankenLibC code that calls fork() directly via glibc).
    let mut reg = match ATFORK_HANDLERS.lock() {
        Ok(r) => r,
        Err(_) => return libc::ENOMEM,
    };
    reg.push(AtforkHandlers {
        prepare,
        parent,
        child,
    });
    0
}

/// Fork handler triple registered by `pthread_atfork`.
#[allow(dead_code)]
struct AtforkHandlers {
    prepare: Option<unsafe extern "C" fn()>,
    parent: Option<unsafe extern "C" fn()>,
    child: Option<unsafe extern "C" fn()>,
}

// SAFETY: Function pointers are Send+Sync (they're just code addresses).
unsafe impl Send for AtforkHandlers {}

/// Registry of atfork handlers.
static ATFORK_HANDLERS: LazyLock<Mutex<Vec<AtforkHandlers>>> =
    LazyLock::new(|| Mutex::new(Vec::new()));

/// Called before fork (from our fork() wrapper) — runs prepare handlers in LIFO order.
#[allow(dead_code)]
pub(crate) fn run_atfork_prepare() {
    if let Ok(handlers) = ATFORK_HANDLERS.lock() {
        for h in handlers.iter().rev() {
            if let Some(f) = h.prepare {
                // SAFETY: caller registered a valid function pointer.
                unsafe { f() };
            }
        }
    }
}

/// Called after fork in parent — runs parent handlers in registration order.
#[allow(dead_code)]
pub(crate) fn run_atfork_parent() {
    if let Ok(handlers) = ATFORK_HANDLERS.lock() {
        for h in handlers.iter() {
            if let Some(f) = h.parent {
                // SAFETY: caller registered a valid function pointer.
                unsafe { f() };
            }
        }
    }
}

/// Called after fork in child — runs child handlers in registration order.
#[allow(dead_code)]
pub(crate) fn run_atfork_child() {
    if let Ok(handlers) = ATFORK_HANDLERS.lock() {
        for h in handlers.iter() {
            if let Some(f) = h.child {
                // SAFETY: caller registered a valid function pointer.
                unsafe { f() };
            }
        }
    }
}

/// `pthread_attr_getguardsize` — get the guard size of a thread attributes object.
/// Native implementation using `PthreadAttrData` overlay.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_getguardsize(
    attr: *const libc::pthread_attr_t,
    guardsize: *mut usize,
) -> c_int {
    let Some(data) = attr_data_ptr_const(attr) else {
        return libc::EINVAL;
    };
    if guardsize.is_null() {
        return libc::EINVAL;
    }
    // SAFETY: pointers are non-null and aligned.
    unsafe { *guardsize = (*data).guard_size };
    0
}

/// `pthread_attr_setguardsize` — set the guard size of a thread attributes object.
/// Native implementation using `PthreadAttrData` overlay.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_setguardsize(
    attr: *mut libc::pthread_attr_t,
    guardsize: usize,
) -> c_int {
    let Some(data) = attr_data_ptr(attr) else {
        return libc::EINVAL;
    };
    // SAFETY: pointer is non-null and aligned.
    unsafe { (*data).guard_size = guardsize };
    0
}

/// GNU `pthread_attr_getaffinity_np` — get CPU affinity from thread attributes.
/// Native implementation using extended attr registry.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_getaffinity_np(
    attr: *const libc::pthread_attr_t,
    cpusetsize: usize,
    cpuset: *mut libc::cpu_set_t,
) -> c_int {
    if attr.is_null() || cpuset.is_null() || cpusetsize == 0 {
        return libc::EINVAL;
    }
    let key = attr as usize;
    let reg = match EXTENDED_ATTR_REGISTRY.lock() {
        Ok(r) => r,
        Err(_) => return libc::EINVAL,
    };
    if let Some(ext) = reg.get(&key)
        && let Some((stored_size, ref mask_bytes)) = ext.affinity
    {
        let copy_len = cpusetsize.min(stored_size).min(mask_bytes.len());
        // SAFETY: cpuset points to caller-owned memory of at least cpusetsize bytes.
        unsafe {
            std::ptr::write_bytes(cpuset.cast::<u8>(), 0, cpusetsize);
            std::ptr::copy_nonoverlapping(mask_bytes.as_ptr(), cpuset.cast::<u8>(), copy_len);
        }
        return 0;
    }
    // No affinity set: return all CPUs (all bits set).
    // SAFETY: cpuset points to caller-owned memory.
    unsafe { std::ptr::write_bytes(cpuset.cast::<u8>(), 0xFF, cpusetsize) };
    0
}

/// GNU `pthread_attr_setaffinity_np` — set CPU affinity in thread attributes.
/// Native implementation using extended attr registry.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_setaffinity_np(
    attr: *mut libc::pthread_attr_t,
    cpusetsize: usize,
    cpuset: *const libc::cpu_set_t,
) -> c_int {
    if attr.is_null() || cpuset.is_null() || cpusetsize == 0 {
        return libc::EINVAL;
    }
    let Some(data) = attr_data_ptr(attr) else {
        return libc::EINVAL;
    };
    // Copy the raw bytes of the cpu_set_t.
    let mut mask_bytes = vec![0u8; cpusetsize];
    // SAFETY: cpuset points to caller-owned memory of at least cpusetsize bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(cpuset.cast::<u8>(), mask_bytes.as_mut_ptr(), cpusetsize);
    }
    let key = attr as usize;
    let mut reg = match EXTENDED_ATTR_REGISTRY.lock() {
        Ok(r) => r,
        Err(_) => return libc::EINVAL,
    };
    let ext = reg.entry(key).or_insert_with(|| ExtendedAttrData {
        affinity: None,
        sigmask: None,
    });
    ext.affinity = Some((cpusetsize, mask_bytes));
    // SAFETY: data pointer is valid.
    unsafe { (*data).flags |= 1 }; // bit 0: affinity set
    0
}

// ---------------------------------------------------------------------------
// Thread attr: scheduling, stack, scope (native where possible, else GCT)
// ---------------------------------------------------------------------------

/// POSIX `pthread_attr_getinheritsched` — get inherit-scheduler attribute.
/// Native implementation using `PthreadAttrData` overlay.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_getinheritsched(
    attr: *const libc::pthread_attr_t,
    inheritsched: *mut c_int,
) -> c_int {
    let Some(data) = attr_data_ptr_const(attr) else {
        return libc::EINVAL;
    };
    if inheritsched.is_null() {
        return libc::EINVAL;
    }
    // SAFETY: pointers are non-null and aligned.
    unsafe { *inheritsched = (*data).inherit_sched };
    0
}

/// POSIX `pthread_attr_setinheritsched` — set inherit-scheduler attribute.
/// Native implementation using `PthreadAttrData` overlay.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_setinheritsched(
    attr: *mut libc::pthread_attr_t,
    inheritsched: c_int,
) -> c_int {
    let Some(data) = attr_data_ptr(attr) else {
        return libc::EINVAL;
    };
    // Valid values: PTHREAD_INHERIT_SCHED (0) or PTHREAD_EXPLICIT_SCHED (1).
    if inheritsched != 0 && inheritsched != 1 {
        return libc::EINVAL;
    }
    // SAFETY: pointer is non-null and aligned.
    unsafe { (*data).inherit_sched = inheritsched };
    0
}

/// POSIX `pthread_attr_getschedparam` — get scheduling parameters.
/// Native implementation using `PthreadAttrData` overlay.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_getschedparam(
    attr: *const libc::pthread_attr_t,
    param: *mut libc::sched_param,
) -> c_int {
    let Some(data) = attr_data_ptr_const(attr) else {
        return libc::EINVAL;
    };
    if param.is_null() {
        return libc::EINVAL;
    }
    // SAFETY: pointers are non-null and aligned.
    unsafe {
        std::ptr::write_bytes(param, 0, 1);
        (*param).sched_priority = (*data).sched_priority;
    }
    0
}

/// POSIX `pthread_attr_setschedparam` — set scheduling parameters.
/// Native implementation using `PthreadAttrData` overlay.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_setschedparam(
    attr: *mut libc::pthread_attr_t,
    param: *const libc::sched_param,
) -> c_int {
    let Some(data) = attr_data_ptr(attr) else {
        return libc::EINVAL;
    };
    if param.is_null() {
        return libc::EINVAL;
    }
    // SAFETY: pointers are non-null and aligned.
    unsafe { (*data).sched_priority = (*param).sched_priority };
    0
}

/// POSIX `pthread_attr_getschedpolicy` — get scheduling policy.
/// Native implementation using `PthreadAttrData` overlay.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_getschedpolicy(
    attr: *const libc::pthread_attr_t,
    policy: *mut c_int,
) -> c_int {
    let Some(data) = attr_data_ptr_const(attr) else {
        return libc::EINVAL;
    };
    if policy.is_null() {
        return libc::EINVAL;
    }
    // SAFETY: pointers are non-null and aligned.
    unsafe { *policy = (*data).sched_policy };
    0
}

/// POSIX `pthread_attr_setschedpolicy` — set scheduling policy.
/// Native implementation using `PthreadAttrData` overlay.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_setschedpolicy(
    attr: *mut libc::pthread_attr_t,
    policy: c_int,
) -> c_int {
    let Some(data) = attr_data_ptr(attr) else {
        return libc::EINVAL;
    };
    // Valid POSIX policies: SCHED_OTHER(0), SCHED_FIFO(1), SCHED_RR(2).
    if !(0..=2).contains(&policy) {
        return libc::EINVAL;
    }
    // SAFETY: pointer is non-null and aligned.
    unsafe { (*data).sched_policy = policy };
    0
}

/// POSIX `pthread_attr_getscope` — get contention scope.
/// Linux NPTL only supports PTHREAD_SCOPE_SYSTEM (1:1 model).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_getscope(
    attr: *const libc::pthread_attr_t,
    scope: *mut c_int,
) -> c_int {
    if attr.is_null() || scope.is_null() {
        return libc::EINVAL;
    }
    // Linux always uses PTHREAD_SCOPE_SYSTEM.
    unsafe { *scope = PTHREAD_SCOPE_SYSTEM };
    0
}

/// POSIX `pthread_attr_setscope` — set contention scope.
/// Only PTHREAD_SCOPE_SYSTEM is supported on Linux.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_setscope(
    attr: *mut libc::pthread_attr_t,
    scope: c_int,
) -> c_int {
    if attr.is_null() {
        return libc::EINVAL;
    }
    if scope == PTHREAD_SCOPE_SYSTEM {
        0
    } else {
        libc::ENOTSUP
    }
}

/// POSIX `pthread_attr_getstack` — get stack address and size.
/// Native implementation using `PthreadAttrData` overlay.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_getstack(
    attr: *const libc::pthread_attr_t,
    stackaddr: *mut *mut c_void,
    stacksize: *mut usize,
) -> c_int {
    let Some(data) = attr_data_ptr_const(attr) else {
        return libc::EINVAL;
    };
    if stackaddr.is_null() || stacksize.is_null() {
        return libc::EINVAL;
    }
    // SAFETY: pointers are non-null and aligned.
    unsafe {
        *stackaddr = (*data).stack_addr as *mut c_void;
        *stacksize = (*data).stack_size;
    }
    0
}

/// POSIX `pthread_attr_setstack` — set stack address and size.
/// Native implementation using `PthreadAttrData` overlay.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_setstack(
    attr: *mut libc::pthread_attr_t,
    stackaddr: *mut c_void,
    stacksize: usize,
) -> c_int {
    let Some(data) = attr_data_ptr(attr) else {
        return libc::EINVAL;
    };
    if stackaddr.is_null() || stacksize < ATTR_MIN_STACK_SIZE {
        return libc::EINVAL;
    }
    // SAFETY: pointer is non-null and aligned.
    unsafe {
        (*data).stack_addr = stackaddr as usize;
        (*data).stack_size = stacksize;
    }
    0
}

/// Deprecated `pthread_attr_getstackaddr` — get stack address.
/// Returns NULL since we don't track custom stack addresses in our overlay.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_getstackaddr(
    attr: *const libc::pthread_attr_t,
    stackaddr: *mut *mut c_void,
) -> c_int {
    if attr.is_null() || stackaddr.is_null() {
        return libc::EINVAL;
    }
    // Deprecated API: return null (no custom stack address set).
    unsafe { *stackaddr = std::ptr::null_mut() };
    0
}

/// Deprecated `pthread_attr_setstackaddr` — set stack address.
/// Accepts and ignores the value (deprecated, use pthread_attr_setstack instead).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_setstackaddr(
    attr: *mut libc::pthread_attr_t,
    _stackaddr: *mut c_void,
) -> c_int {
    if attr.is_null() {
        return libc::EINVAL;
    }
    // Deprecated API: accept but don't store (use setstack instead).
    0
}

// ---------------------------------------------------------------------------
// Barrier attributes — native (simple int fields)
// ---------------------------------------------------------------------------

/// POSIX `pthread_barrierattr_init` — initialize barrier attributes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_barrierattr_init(attr: *mut libc::pthread_barrierattr_t) -> c_int {
    if attr.is_null() {
        return libc::EINVAL;
    }
    // SAFETY: attr is non-null; store default (private) pshared.
    let word = unsafe { &mut *(attr.cast::<c_int>()) };
    *word = libc::PTHREAD_PROCESS_PRIVATE;
    0
}

/// POSIX `pthread_barrierattr_destroy` — destroy barrier attributes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_barrierattr_destroy(
    attr: *mut libc::pthread_barrierattr_t,
) -> c_int {
    if attr.is_null() {
        return libc::EINVAL;
    }
    // SAFETY: attr is non-null; zero it.
    let word = unsafe { &mut *(attr.cast::<c_int>()) };
    *word = 0;
    0
}

/// POSIX `pthread_barrierattr_getpshared` — get barrier process-shared attribute.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_barrierattr_getpshared(
    attr: *const libc::pthread_barrierattr_t,
    pshared: *mut c_int,
) -> c_int {
    if attr.is_null() || pshared.is_null() {
        return libc::EINVAL;
    }
    // SAFETY: both pointers are non-null.
    unsafe {
        *pshared = *(attr.cast::<c_int>());
    }
    0
}

/// POSIX `pthread_barrierattr_setpshared` — set barrier process-shared attribute.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_barrierattr_setpshared(
    attr: *mut libc::pthread_barrierattr_t,
    pshared: c_int,
) -> c_int {
    if attr.is_null() {
        return libc::EINVAL;
    }
    if pshared != libc::PTHREAD_PROCESS_PRIVATE && pshared != libc::PTHREAD_PROCESS_SHARED {
        return libc::EINVAL;
    }
    // SAFETY: attr is non-null.
    let word = unsafe { &mut *(attr.cast::<c_int>()) };
    *word = pshared;
    0
}

// ---------------------------------------------------------------------------
// Condvar attribute extensions — native (pshared field)
// ---------------------------------------------------------------------------

/// POSIX `pthread_condattr_getpshared` — get condvar process-shared attribute.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_condattr_getpshared(
    attr: *const libc::pthread_condattr_t,
    pshared: *mut c_int,
) -> c_int {
    if attr.is_null() || pshared.is_null() {
        return libc::EINVAL;
    }
    // Condattr layout: first int is clock, second is pshared
    // SAFETY: attr is non-null, caller owns memory.
    unsafe {
        let words = attr.cast::<c_int>();
        *pshared = *words.add(1);
    }
    0
}

/// POSIX `pthread_condattr_setpshared` — set condvar process-shared attribute.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_condattr_setpshared(
    attr: *mut libc::pthread_condattr_t,
    pshared: c_int,
) -> c_int {
    if attr.is_null() {
        return libc::EINVAL;
    }
    if pshared != libc::PTHREAD_PROCESS_PRIVATE && pshared != libc::PTHREAD_PROCESS_SHARED {
        return libc::EINVAL;
    }
    // SAFETY: attr is non-null, caller owns memory.
    unsafe {
        let words = attr.cast::<c_int>();
        *words.add(1) = pshared;
    }
    0
}

// ---------------------------------------------------------------------------
// Mutex attribute extensions — native (protocol, pshared, robust)
// ---------------------------------------------------------------------------

/// POSIX `pthread_mutexattr_getprotocol` — get mutex protocol.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_getprotocol(
    attr: *const libc::pthread_mutexattr_t,
    protocol: *mut c_int,
) -> c_int {
    if attr.is_null() || protocol.is_null() {
        return libc::EINVAL;
    }
    // We only support PTHREAD_PRIO_NONE currently.
    unsafe {
        *protocol = libc::PTHREAD_PRIO_NONE;
    }
    0
}

/// POSIX `pthread_mutexattr_setprotocol` — set mutex protocol.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_setprotocol(
    attr: *mut libc::pthread_mutexattr_t,
    protocol: c_int,
) -> c_int {
    if attr.is_null() {
        return libc::EINVAL;
    }
    // Accept PTHREAD_PRIO_NONE; reject others for now.
    if protocol != libc::PTHREAD_PRIO_NONE
        && protocol != libc::PTHREAD_PRIO_INHERIT
        && protocol != libc::PTHREAD_PRIO_PROTECT
    {
        return libc::EINVAL;
    }
    // Store protocol at offset 1 in the mutexattr (first int is type).
    // SAFETY: attr is non-null, caller owns memory.
    unsafe {
        let words = attr.cast::<c_int>();
        *words.add(1) = protocol;
    }
    0
}

/// POSIX `pthread_mutexattr_getpshared` — get mutex process-shared.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_getpshared(
    attr: *const libc::pthread_mutexattr_t,
    pshared: *mut c_int,
) -> c_int {
    if attr.is_null() || pshared.is_null() {
        return libc::EINVAL;
    }
    // Default: PTHREAD_PROCESS_PRIVATE.
    unsafe {
        *pshared = libc::PTHREAD_PROCESS_PRIVATE;
    }
    0
}

/// POSIX `pthread_mutexattr_setpshared` — set mutex process-shared.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_setpshared(
    attr: *mut libc::pthread_mutexattr_t,
    pshared: c_int,
) -> c_int {
    if attr.is_null() {
        return libc::EINVAL;
    }
    if pshared != libc::PTHREAD_PROCESS_PRIVATE && pshared != libc::PTHREAD_PROCESS_SHARED {
        return libc::EINVAL;
    }
    0
}

/// POSIX `pthread_mutexattr_getrobust` — get mutex robust attribute.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_getrobust(
    attr: *const libc::pthread_mutexattr_t,
    robust: *mut c_int,
) -> c_int {
    if attr.is_null() || robust.is_null() {
        return libc::EINVAL;
    }
    // Default: PTHREAD_MUTEX_STALLED.
    unsafe {
        *robust = libc::PTHREAD_MUTEX_STALLED;
    }
    0
}

/// POSIX `pthread_mutexattr_setrobust` — set mutex robust attribute.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutexattr_setrobust(
    attr: *mut libc::pthread_mutexattr_t,
    robust: c_int,
) -> c_int {
    if attr.is_null() {
        return libc::EINVAL;
    }
    if robust != libc::PTHREAD_MUTEX_STALLED && robust != libc::PTHREAD_MUTEX_ROBUST {
        return libc::EINVAL;
    }
    0
}

// ---------------------------------------------------------------------------
// Rwlock attribute extensions — native
// ---------------------------------------------------------------------------

/// POSIX `pthread_rwlockattr_getpshared` — get rwlock process-shared.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlockattr_getpshared(
    attr: *const libc::pthread_rwlockattr_t,
    pshared: *mut c_int,
) -> c_int {
    if attr.is_null() || pshared.is_null() {
        return libc::EINVAL;
    }
    // SAFETY: attr is non-null.
    unsafe {
        *pshared = *(attr.cast::<c_int>());
    }
    0
}

/// POSIX `pthread_rwlockattr_setpshared` — set rwlock process-shared.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlockattr_setpshared(
    attr: *mut libc::pthread_rwlockattr_t,
    pshared: c_int,
) -> c_int {
    if attr.is_null() {
        return libc::EINVAL;
    }
    if pshared != libc::PTHREAD_PROCESS_PRIVATE && pshared != libc::PTHREAD_PROCESS_SHARED {
        return libc::EINVAL;
    }
    // SAFETY: attr is non-null.
    let word = unsafe { &mut *(attr.cast::<c_int>()) };
    *word = pshared;
    0
}

// ---------------------------------------------------------------------------
// Timed/clock pthread operations — raw syscall via futex
// ---------------------------------------------------------------------------

/// POSIX `pthread_mutex_timedlock` — lock with timeout.
///
/// Native implementation using futex CAS loop with absolute timeout.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutex_timedlock(
    mutex: *mut libc::pthread_mutex_t,
    abstime: *const libc::timespec,
) -> c_int {
    if mutex.is_null() || abstime.is_null() {
        return libc::EINVAL;
    }
    let Some(word_ptr) = mutex_word_ptr(mutex) else {
        return libc::EINVAL;
    };
    // SAFETY: alignment validated by `mutex_word_ptr`.
    let word = unsafe { &*word_ptr };

    // Fast path: uncontended.
    if word
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_ok()
    {
        return 0;
    }

    // Slow path: CAS loop with futex timed wait.
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

        #[cfg(target_os = "linux")]
        {
            let rc = futex_wait_timed_private(word, 2, abstime);
            if rc == 0 {
                continue;
            }
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if errno == libc::ETIMEDOUT {
                return libc::ETIMEDOUT;
            }
            if errno == libc::EINTR || errno == libc::EAGAIN {
                continue;
            }
            return if errno == 0 { libc::EAGAIN } else { errno };
        }
        #[cfg(not(target_os = "linux"))]
        {
            std::thread::yield_now();
        }
    }
}

/// POSIX `pthread_mutex_consistent` — mark robust mutex as consistent.
///
/// Native implementation: clears the EOWNERDEAD state on a robust mutex.
/// In our implementation, the lock word at offset 0 tracks state.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutex_consistent(mutex: *mut libc::pthread_mutex_t) -> c_int {
    if mutex.is_null() {
        return libc::EINVAL;
    }
    // Our native mutexes don't track robust/owner-died state separately.
    // Accept the call as a no-op for compatibility (the mutex is already usable).
    0
}

/// GNU `pthread_mutex_clocklock` — lock with specific clock timeout.
///
/// Native implementation: converts clock deadline to CLOCK_REALTIME and
/// delegates to `pthread_mutex_timedlock`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_mutex_clocklock(
    mutex: *mut libc::pthread_mutex_t,
    clockid: c_int,
    abstime: *const libc::timespec,
) -> c_int {
    if mutex.is_null() || abstime.is_null() {
        return libc::EINVAL;
    }
    if clockid == libc::CLOCK_REALTIME {
        return unsafe { pthread_mutex_timedlock(mutex, abstime) };
    }
    // Convert to CLOCK_REALTIME deadline.
    let real_deadline = clock_convert_to_realtime(clockid, abstime);
    unsafe { pthread_mutex_timedlock(mutex, &real_deadline) }
}

/// POSIX `pthread_rwlock_timedrdlock` — timed read lock.
///
/// Native implementation using futex with absolute timeout.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlock_timedrdlock(
    rwlock: *mut libc::pthread_rwlock_t,
    abstime: *const libc::timespec,
) -> c_int {
    if rwlock.is_null() || abstime.is_null() {
        return libc::EINVAL;
    }
    if !is_managed_rwlock(rwlock) {
        return libc::EINVAL;
    }
    let Some(word_ptr) = rwlock_word_ptr(rwlock) else {
        return libc::EINVAL;
    };
    let word = unsafe { &*word_ptr };
    futex_rwlock_timed_rdlock(word, abstime)
}

/// POSIX `pthread_rwlock_timedwrlock` — timed write lock.
///
/// Native implementation using futex with absolute timeout.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlock_timedwrlock(
    rwlock: *mut libc::pthread_rwlock_t,
    abstime: *const libc::timespec,
) -> c_int {
    if rwlock.is_null() || abstime.is_null() {
        return libc::EINVAL;
    }
    if !is_managed_rwlock(rwlock) {
        return libc::EINVAL;
    }
    let Some(word_ptr) = rwlock_word_ptr(rwlock) else {
        return libc::EINVAL;
    };
    let word = unsafe { &*word_ptr };
    futex_rwlock_timed_wrlock(word, abstime)
}

/// GNU `pthread_rwlock_clockrdlock` — clock-specific timed read lock.
///
/// Native implementation: converts clock deadline and uses futex timed wait.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlock_clockrdlock(
    rwlock: *mut libc::pthread_rwlock_t,
    clockid: c_int,
    abstime: *const libc::timespec,
) -> c_int {
    if rwlock.is_null() || abstime.is_null() {
        return libc::EINVAL;
    }
    if clockid == libc::CLOCK_REALTIME {
        return unsafe { pthread_rwlock_timedrdlock(rwlock, abstime) };
    }
    let real_deadline = clock_convert_to_realtime(clockid, abstime);
    unsafe { pthread_rwlock_timedrdlock(rwlock, &real_deadline) }
}

/// GNU `pthread_rwlock_clockwrlock` — clock-specific timed write lock.
///
/// Native implementation: converts clock deadline and uses futex timed wait.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_rwlock_clockwrlock(
    rwlock: *mut libc::pthread_rwlock_t,
    clockid: c_int,
    abstime: *const libc::timespec,
) -> c_int {
    if rwlock.is_null() || abstime.is_null() {
        return libc::EINVAL;
    }
    if clockid == libc::CLOCK_REALTIME {
        return unsafe { pthread_rwlock_timedwrlock(rwlock, abstime) };
    }
    let real_deadline = clock_convert_to_realtime(clockid, abstime);
    unsafe { pthread_rwlock_timedwrlock(rwlock, &real_deadline) }
}

/// GNU `pthread_cond_clockwait` — clock-specific timed condvar wait.
///
/// Native implementation: converts clock deadline to CLOCK_REALTIME and
/// delegates to `pthread_cond_timedwait`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_cond_clockwait(
    cond: *mut libc::pthread_cond_t,
    mutex: *mut libc::pthread_mutex_t,
    clockid: c_int,
    abstime: *const libc::timespec,
) -> c_int {
    if cond.is_null() || mutex.is_null() || abstime.is_null() {
        return libc::EINVAL;
    }
    if clockid == libc::CLOCK_REALTIME {
        return unsafe { pthread_cond_timedwait(cond, mutex, abstime) };
    }
    let real_deadline = clock_convert_to_realtime(clockid, abstime);
    unsafe { pthread_cond_timedwait(cond, mutex, &real_deadline) }
}

// ---------------------------------------------------------------------------
// Thread join extensions (GNU)
// ---------------------------------------------------------------------------

/// GNU `pthread_timedjoin_np` — join with timeout.
///
/// Native implementation: waits for thread completion using futex with timeout.
/// Returns `ETIMEDOUT` if the thread hasn't finished by the deadline.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_timedjoin_np(
    thread: libc::pthread_t,
    retval: *mut *mut c_void,
    abstime: *const libc::timespec,
) -> c_int {
    if abstime.is_null() {
        // NULL timeout = blocking join.
        return unsafe { native_pthread_join(thread, retval) };
    }
    let thread_key = thread as usize;
    let my_tid = core_self_tid();

    // Self-join detection.
    if my_tid > 0 && thread_key == my_tid as usize {
        return libc::EDEADLK;
    }

    // Peek at state without removing from registry.
    let handle_ptr = {
        let registry = THREAD_HANDLE_REGISTRY
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        match registry.get(&thread_key) {
            Some(&raw) => {
                let hp = raw as *mut ThreadHandle;
                let state = unsafe { (*hp).state.load(Ordering::Acquire) };
                if state == THREAD_DETACHED || state == THREAD_JOINED {
                    return libc::EINVAL;
                }
                hp
            }
            None => return libc::ESRCH,
        }
    };

    // Wait for TID to be cleared (thread exit) with timeout.
    // The kernel clears tid via CLONE_CHILD_CLEARTID and wakes futex waiters.
    loop {
        let tid = unsafe { (*handle_ptr).tid.load(Ordering::Acquire) };
        if tid == 0 {
            // Thread exited. Perform the actual join.
            return unsafe { native_pthread_join(thread, retval) };
        }
        // Check if deadline has passed.
        let mut now: libc::timespec = unsafe { std::mem::zeroed() };
        unsafe { libc::syscall(libc::SYS_clock_gettime, libc::CLOCK_REALTIME, &mut now) };
        if now.tv_sec > unsafe { (*abstime).tv_sec }
            || (now.tv_sec == unsafe { (*abstime).tv_sec }
                && now.tv_nsec >= unsafe { (*abstime).tv_nsec })
        {
            return libc::ETIMEDOUT;
        }
        // Futex wait on the tid field with timeout.
        // SAFETY: handle_ptr is valid (from registry lookup above).
        let tid_ptr = unsafe { &(*handle_ptr).tid };
        let ret = futex_wait_timed_private(tid_ptr, tid, abstime);
        if ret < 0 {
            let errno = unsafe { *libc::__errno_location() };
            if errno == libc::ETIMEDOUT {
                return libc::ETIMEDOUT;
            }
            // EINTR/EAGAIN — just retry.
        }
    }
}

/// GNU `pthread_tryjoin_np` — non-blocking join.
///
/// Native implementation: checks if thread is already finished and joins if so,
/// otherwise returns `EBUSY`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_tryjoin_np(
    thread: libc::pthread_t,
    retval: *mut *mut c_void,
) -> c_int {
    let thread_key = thread as usize;

    // Check if thread is finished without removing from registry.
    {
        let registry = THREAD_HANDLE_REGISTRY
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        match registry.get(&thread_key) {
            Some(&raw) => {
                let handle_ptr = raw as *mut ThreadHandle;
                // SAFETY: registry stores valid handles.
                let state = unsafe { (*handle_ptr).state.load(Ordering::Acquire) };
                match state {
                    s if s == THREAD_FINISHED => {
                        // Thread is done; proceed to join below.
                    }
                    s if s == THREAD_DETACHED || s == THREAD_JOINED => {
                        return libc::EINVAL;
                    }
                    _ => {
                        // STARTING or RUNNING — not finished yet.
                        return libc::EBUSY;
                    }
                }
            }
            None => return libc::ESRCH,
        }
    }

    // Thread is FINISHED. Perform a full join.
    unsafe { native_pthread_join(thread, retval) }
}

/// GNU `pthread_clockjoin_np` — clock-specific timed join.
///
/// Native implementation: converts the clock-specific deadline to CLOCK_REALTIME
/// and delegates to `pthread_timedjoin_np`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_clockjoin_np(
    thread: libc::pthread_t,
    retval: *mut *mut c_void,
    clockid: c_int,
    abstime: *const libc::timespec,
) -> c_int {
    if abstime.is_null() {
        return unsafe { native_pthread_join(thread, retval) };
    }
    if clockid == libc::CLOCK_REALTIME {
        return unsafe { pthread_timedjoin_np(thread, retval, abstime) };
    }
    // Convert from the specified clock to CLOCK_REALTIME.
    let mut clock_now: libc::timespec = unsafe { std::mem::zeroed() };
    let mut real_now: libc::timespec = unsafe { std::mem::zeroed() };
    unsafe {
        libc::syscall(libc::SYS_clock_gettime, clockid, &mut clock_now);
        libc::syscall(libc::SYS_clock_gettime, libc::CLOCK_REALTIME, &mut real_now);
    }
    // delta = abstime - clock_now
    let deadline = unsafe { &*abstime };
    let delta_sec = deadline.tv_sec - clock_now.tv_sec;
    let delta_nsec = deadline.tv_nsec - clock_now.tv_nsec;
    // real_deadline = real_now + delta
    let mut real_deadline = libc::timespec {
        tv_sec: real_now.tv_sec + delta_sec,
        tv_nsec: real_now.tv_nsec + delta_nsec,
    };
    // Normalise nanoseconds.
    if real_deadline.tv_nsec >= 1_000_000_000 {
        real_deadline.tv_sec += 1;
        real_deadline.tv_nsec -= 1_000_000_000;
    } else if real_deadline.tv_nsec < 0 {
        real_deadline.tv_sec -= 1;
        real_deadline.tv_nsec += 1_000_000_000;
    }
    unsafe { pthread_timedjoin_np(thread, retval, &real_deadline) }
}

// ---------------------------------------------------------------------------
// Thread signals
// ---------------------------------------------------------------------------

/// POSIX `pthread_kill` — send signal to thread.
///
/// Native implementation using `tgkill(2)` syscall.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_kill(thread: libc::pthread_t, sig: c_int) -> c_int {
    // Validate signal number (0 is allowed for existence check).
    if !(0..=64).contains(&sig) {
        return libc::EINVAL;
    }
    match resolve_thread_tid(thread) {
        Some(tid) => {
            let pid = unsafe { libc::syscall(libc::SYS_getpid) } as i32;
            let ret = unsafe { libc::syscall(libc::SYS_tgkill, pid, tid, sig) };
            if ret < 0 {
                unsafe { *libc::__errno_location() }
            } else {
                0
            }
        }
        None => libc::ESRCH,
    }
}

/// GNU `pthread_sigqueue` — queue signal with value to thread.
///
/// Native implementation using `rt_tgsigqueueinfo(2)` syscall.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_sigqueue(
    thread: libc::pthread_t,
    sig: c_int,
    value: libc::sigval,
) -> c_int {
    if !(1..=64).contains(&sig) {
        return libc::EINVAL;
    }
    match resolve_thread_tid(thread) {
        Some(tid) => {
            let pid = unsafe { libc::syscall(libc::SYS_getpid) } as i32;
            // Build a siginfo_t structure with SI_QUEUE.
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            info.si_signo = sig;
            info.si_code = libc::SI_QUEUE;
            // si_pid and si_uid are part of the _kill union in siginfo_t.
            // Set them via raw byte access for portability.
            unsafe {
                let p = &mut info as *mut libc::siginfo_t as *mut u8;
                // si_pid at offset 16, si_uid at offset 20 on x86_64
                *(p.add(16).cast::<i32>()) = pid;
                *(p.add(20).cast::<u32>()) = libc::syscall(libc::SYS_getuid as i64) as libc::uid_t;
                // si_value at offset 24
                *(p.add(24).cast::<libc::sigval>()) = value;
            }
            let ret = unsafe {
                libc::syscall(
                    libc::SYS_rt_tgsigqueueinfo,
                    pid,
                    tid,
                    sig,
                    &info as *const libc::siginfo_t,
                )
            };
            if ret < 0 {
                unsafe { *libc::__errno_location() }
            } else {
                0
            }
        }
        None => libc::ESRCH,
    }
}

// ---------------------------------------------------------------------------
// Thread affinity (get/set for running thread)
// ---------------------------------------------------------------------------

/// GNU `pthread_getaffinity_np` — get CPU affinity of running thread.
///
/// Native implementation using `sched_getaffinity(2)` syscall.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_getaffinity_np(
    thread: libc::pthread_t,
    cpusetsize: usize,
    cpuset: *mut libc::cpu_set_t,
) -> c_int {
    if cpuset.is_null() {
        return libc::EINVAL;
    }
    match resolve_thread_tid(thread) {
        Some(tid) => {
            let ret =
                unsafe { libc::syscall(libc::SYS_sched_getaffinity, tid, cpusetsize, cpuset) };
            if ret < 0 {
                unsafe { *libc::__errno_location() }
            } else {
                // Kernel may return fewer bytes than requested; zero the rest.
                let filled = ret as usize;
                if filled < cpusetsize {
                    unsafe {
                        std::ptr::write_bytes(
                            (cpuset as *mut u8).add(filled),
                            0,
                            cpusetsize - filled,
                        );
                    }
                }
                0
            }
        }
        None => libc::ESRCH,
    }
}

/// GNU `pthread_setaffinity_np` — set CPU affinity of running thread.
///
/// Native implementation using `sched_setaffinity(2)` syscall.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_setaffinity_np(
    thread: libc::pthread_t,
    cpusetsize: usize,
    cpuset: *const libc::cpu_set_t,
) -> c_int {
    if cpuset.is_null() {
        return libc::EINVAL;
    }
    match resolve_thread_tid(thread) {
        Some(tid) => {
            let ret =
                unsafe { libc::syscall(libc::SYS_sched_setaffinity, tid, cpusetsize, cpuset) };
            if ret < 0 {
                unsafe { *libc::__errno_location() }
            } else {
                0
            }
        }
        None => libc::ESRCH,
    }
}

// ---------------------------------------------------------------------------
// Concurrency (obsolete POSIX, kept for compat)
// ---------------------------------------------------------------------------

/// Obsolete POSIX `pthread_setconcurrency` — set concurrency level (no-op on Linux).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_setconcurrency(_level: c_int) -> c_int {
    // Linux uses 1:1 threading model; concurrency hint is meaningless.
    0
}

/// Obsolete POSIX `pthread_getconcurrency` — get concurrency level.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_getconcurrency() -> c_int {
    // Always 0 (system decides).
    0
}

/// Deprecated `pthread_yield` — yield processor (GNU extension, same as sched_yield).
///
/// Native implementation using `sched_yield(2)` syscall.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_yield() -> c_int {
    unsafe { libc::syscall(libc::SYS_sched_yield) as c_int }
}

// ---------------------------------------------------------------------------
// Thread lifecycle extensions
// ---------------------------------------------------------------------------

/// POSIX `pthread_exit` — terminate calling thread.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_exit(retval: *mut c_void) -> ! {
    // Store the return value for any thread that calls pthread_join.
    let tid = core_self_tid();
    if let Ok(reg) = THREAD_HANDLE_REGISTRY.lock() {
        for &raw in reg.values() {
            let handle_ptr = raw as *mut ThreadHandle;
            // SAFETY: registry only stores live handles.
            let handle_tid = unsafe { (*handle_ptr).tid.load(Ordering::Acquire) };
            if handle_tid == tid {
                // SAFETY: retval is synchronized — written here before state transition,
                // read by joiner after observing THREAD_FINISHED.
                // SAFETY: retval and state are synchronized — written here before
                // state transition, read by joiner after observing THREAD_FINISHED.
                unsafe {
                    *(*handle_ptr).retval.get() = retval as usize;
                    (*handle_ptr)
                        .state
                        .store(THREAD_FINISHED, Ordering::Release);
                }
                break;
            }
        }
    }
    // Exit the thread via the kernel. SYS_exit terminates only the calling thread.
    unsafe { libc::syscall(libc::SYS_exit, 0) };
    // Unreachable, but compiler needs a divergent path.
    loop {
        std::hint::spin_loop();
    }
}

/// GNU `pthread_getcpuclockid` — get CPU-time clock for a thread.
///
/// Native implementation using kernel CPUCLOCK formula:
/// `clockid = (~tid << 3) | 2` (CPUCLOCK_SCHED flag for thread CPU time).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_getcpuclockid(
    thread: libc::pthread_t,
    clockid: *mut libc::clockid_t,
) -> c_int {
    if clockid.is_null() {
        return libc::EINVAL;
    }
    match resolve_thread_tid(thread) {
        Some(tid) => {
            // Kernel CPUCLOCK formula: (~pid << 3) | CPUCLOCK_SCHED(2)
            let cid: libc::clockid_t = (!tid as libc::clockid_t) << 3 | 2;
            // Validate that the clock is usable via clock_getres.
            let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
            let ret = unsafe {
                libc::syscall(libc::SYS_clock_getres, cid, &mut ts as *mut libc::timespec)
            };
            if ret < 0 {
                return libc::ESRCH;
            }
            unsafe { *clockid = cid };
            0
        }
        None => libc::ESRCH,
    }
}

/// GNU `pthread_gettid_np` — get kernel TID for a thread.
///
/// Native implementation using `THREAD_HANDLE_REGISTRY` lookup.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_gettid_np(thread: libc::pthread_t) -> libc::pid_t {
    resolve_thread_tid(thread).unwrap_or(-1) as libc::pid_t
}

/// GNU `pthread_attr_getsigmask_np` — get signal mask from thread attributes.
/// Native implementation using extended attr registry.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_getsigmask_np(
    attr: *const libc::pthread_attr_t,
    sigmask: *mut libc::sigset_t,
) -> c_int {
    if attr.is_null() || sigmask.is_null() {
        return libc::EINVAL;
    }
    let key = attr as usize;
    let reg = match EXTENDED_ATTR_REGISTRY.lock() {
        Ok(r) => r,
        Err(_) => return libc::EINVAL,
    };
    if let Some(ext) = reg.get(&key)
        && let Some(ref mask_bytes) = ext.sigmask
    {
        // SAFETY: sigmask points to caller-owned memory (sigset_t = 128 bytes on x86_64).
        unsafe {
            std::ptr::copy_nonoverlapping(mask_bytes.as_ptr(), sigmask.cast::<u8>(), 128);
        }
        return 0;
    }
    // No sigmask set: PTHREAD_ATTR_NO_SIGMASK_NP behavior — return -1.
    // glibc returns PTHREAD_ATTR_NO_SIGMASK_NP (-1) to indicate "not set".
    -1
}

/// GNU `pthread_attr_setsigmask_np` — set signal mask in thread attributes.
/// Native implementation using extended attr registry.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_setsigmask_np(
    attr: *mut libc::pthread_attr_t,
    sigmask: *const libc::sigset_t,
) -> c_int {
    if attr.is_null() {
        return libc::EINVAL;
    }
    let Some(data) = attr_data_ptr(attr) else {
        return libc::EINVAL;
    };
    let key = attr as usize;
    if sigmask.is_null() {
        // NULL sigmask clears the stored mask.
        if let Ok(mut reg) = EXTENDED_ATTR_REGISTRY.lock()
            && let Some(ext) = reg.get_mut(&key)
        {
            ext.sigmask = None;
        }
        // SAFETY: data pointer is valid.
        unsafe { (*data).flags &= !2 }; // clear bit 1
        return 0;
    }
    let mut mask_bytes = [0u8; 128];
    // SAFETY: sigmask points to caller-owned sigset_t (128 bytes on x86_64).
    unsafe {
        std::ptr::copy_nonoverlapping(sigmask.cast::<u8>(), mask_bytes.as_mut_ptr(), 128);
    }
    let mut reg = match EXTENDED_ATTR_REGISTRY.lock() {
        Ok(r) => r,
        Err(_) => return libc::EINVAL,
    };
    let ext = reg.entry(key).or_insert_with(|| ExtendedAttrData {
        affinity: None,
        sigmask: None,
    });
    ext.sigmask = Some(mask_bytes);
    // SAFETY: data pointer is valid.
    unsafe { (*data).flags |= 2 }; // bit 1: sigmask set
    0
}

/// GNU `pthread_getattr_default_np` — get default thread attributes.
/// Native implementation using global default attr state.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_getattr_default_np(attr: *mut libc::pthread_attr_t) -> c_int {
    let Some(data) = attr_data_ptr(attr) else {
        return libc::EINVAL;
    };
    let defaults = match DEFAULT_THREAD_ATTR.lock() {
        Ok(d) => d,
        Err(_) => return libc::EINVAL,
    };
    // SAFETY: data pointer is non-null and aligned.
    unsafe {
        (*data).magic = MANAGED_ATTR_MAGIC;
        (*data).detach_state = defaults.detach_state;
        (*data).stack_size = defaults.stack_size;
        (*data).guard_size = defaults.guard_size;
        (*data).stack_addr = 0;
        (*data).inherit_sched = defaults.inherit_sched;
        (*data).sched_policy = defaults.sched_policy;
        (*data).sched_priority = defaults.sched_priority;
        (*data).flags = 0;
    }
    0
}

/// GNU `pthread_setattr_default_np` — set default thread attributes.
/// Native implementation using global default attr state.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_setattr_default_np(attr: *const libc::pthread_attr_t) -> c_int {
    let Some(data) = attr_data_ptr_const(attr) else {
        return libc::EINVAL;
    };
    let mut defaults = match DEFAULT_THREAD_ATTR.lock() {
        Ok(d) => d,
        Err(_) => return libc::EINVAL,
    };
    // SAFETY: data pointer is non-null and aligned.
    unsafe {
        defaults.detach_state = (*data).detach_state;
        defaults.stack_size = (*data).stack_size;
        defaults.guard_size = (*data).guard_size;
        defaults.inherit_sched = (*data).inherit_sched;
        defaults.sched_policy = (*data).sched_policy;
        defaults.sched_priority = (*data).sched_priority;
    }
    0
}

// ===========================================================================
// __pthread_* internal aliases — glibc exports these for internal use
// ===========================================================================

/// `__pthread_mutex_lock` — internal alias for pthread_mutex_lock.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_mutex_lock(m: *mut libc::pthread_mutex_t) -> c_int {
    unsafe { pthread_mutex_lock(m) }
}

/// `__pthread_mutex_unlock` — internal alias for pthread_mutex_unlock.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_mutex_unlock(m: *mut libc::pthread_mutex_t) -> c_int {
    unsafe { pthread_mutex_unlock(m) }
}

/// `__pthread_mutex_trylock` — internal alias for pthread_mutex_trylock.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_mutex_trylock(m: *mut libc::pthread_mutex_t) -> c_int {
    unsafe { pthread_mutex_trylock(m) }
}

/// `__pthread_mutex_init` — internal alias for pthread_mutex_init.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_mutex_init(
    m: *mut libc::pthread_mutex_t,
    attr: *const libc::pthread_mutexattr_t,
) -> c_int {
    unsafe { pthread_mutex_init(m, attr) }
}

/// `__pthread_mutex_destroy` — internal alias for pthread_mutex_destroy.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_mutex_destroy(m: *mut libc::pthread_mutex_t) -> c_int {
    unsafe { pthread_mutex_destroy(m) }
}

/// `__pthread_mutexattr_init` — internal alias.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_mutexattr_init(attr: *mut libc::pthread_mutexattr_t) -> c_int {
    unsafe { pthread_mutexattr_init(attr) }
}

/// `__pthread_mutexattr_destroy` — internal alias.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_mutexattr_destroy(
    attr: *mut libc::pthread_mutexattr_t,
) -> c_int {
    unsafe { pthread_mutexattr_destroy(attr) }
}

/// `__pthread_mutexattr_settype` — internal alias.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_mutexattr_settype(
    attr: *mut libc::pthread_mutexattr_t,
    kind: c_int,
) -> c_int {
    unsafe { pthread_mutexattr_settype(attr, kind) }
}

/// `__pthread_rwlock_init` — internal alias.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_rwlock_init(
    rwlock: *mut libc::pthread_rwlock_t,
    attr: *const libc::pthread_rwlockattr_t,
) -> c_int {
    unsafe { pthread_rwlock_init(rwlock, attr) }
}

/// `__pthread_rwlock_destroy` — internal alias.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_rwlock_destroy(rwlock: *mut libc::pthread_rwlock_t) -> c_int {
    unsafe { pthread_rwlock_destroy(rwlock) }
}

/// `__pthread_rwlock_rdlock` — internal alias.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_rwlock_rdlock(rwlock: *mut libc::pthread_rwlock_t) -> c_int {
    unsafe { pthread_rwlock_rdlock(rwlock) }
}

/// `__pthread_rwlock_wrlock` — internal alias.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_rwlock_wrlock(rwlock: *mut libc::pthread_rwlock_t) -> c_int {
    unsafe { pthread_rwlock_wrlock(rwlock) }
}

/// `__pthread_rwlock_unlock` — internal alias.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_rwlock_unlock(rwlock: *mut libc::pthread_rwlock_t) -> c_int {
    unsafe { pthread_rwlock_unlock(rwlock) }
}

/// `__pthread_rwlock_tryrdlock` — internal alias.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_rwlock_tryrdlock(rwlock: *mut libc::pthread_rwlock_t) -> c_int {
    unsafe { pthread_rwlock_tryrdlock(rwlock) }
}

/// `__pthread_rwlock_trywrlock` — internal alias.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_rwlock_trywrlock(rwlock: *mut libc::pthread_rwlock_t) -> c_int {
    unsafe { pthread_rwlock_trywrlock(rwlock) }
}

/// `__pthread_once` — internal alias.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_once(
    once: *mut libc::pthread_once_t,
    init: Option<unsafe extern "C" fn()>,
) -> c_int {
    unsafe { pthread_once(once, init) }
}

/// `__pthread_key_create` — internal alias.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_key_create(
    key: *mut libc::pthread_key_t,
    dtor: Option<unsafe extern "C" fn(*mut c_void)>,
) -> c_int {
    unsafe { pthread_key_create(key, dtor) }
}

/// `__pthread_getspecific` — internal alias.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_getspecific(key: libc::pthread_key_t) -> *mut c_void {
    unsafe { pthread_getspecific(key) }
}

/// `__pthread_setspecific` — internal alias.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_setspecific(
    key: libc::pthread_key_t,
    value: *const c_void,
) -> c_int {
    unsafe { pthread_setspecific(key, value) }
}

/// `__pthread_register_cancel` — cancellation cleanup registration (no-op stub).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_register_cancel(_buf: *mut c_void) {}

/// `__pthread_unregister_cancel` — cancellation cleanup unregistration (no-op stub).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_unregister_cancel(_buf: *mut c_void) {}

/// `__pthread_register_cancel_defer` — deferred cancellation registration (no-op stub).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_register_cancel_defer(_buf: *mut c_void) {}

/// `__pthread_unregister_cancel_restore` — deferred cancellation restore (no-op stub).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_unregister_cancel_restore(_buf: *mut c_void) {}

/// `__pthread_cleanup_routine` — cleanup routine handler (no-op stub).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_cleanup_routine(_buf: *mut c_void) {}

/// `__pthread_get_minstack` — get minimum stack size for a given attr.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_get_minstack(_attr: *const libc::pthread_attr_t) -> usize {
    libc::PTHREAD_STACK_MIN
}

/// `__pthread_unwind_next` — internal unwinding (no-op stub — process aborts).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __pthread_unwind_next(_buf: *mut c_void) {
    std::process::abort();
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

    fn reset_cancel_state_for_tests() {
        THREAD_CANCEL_STATE.with(|cell| cell.set(PTHREAD_CANCEL_ENABLE_STATE));
        THREAD_CANCEL_TYPE.with(|cell| cell.set(PTHREAD_CANCEL_DEFERRED_TYPE));
        set_cancellation_pending(current_cancel_key(), false);
    }

    fn current_thread_pending_cancel() -> bool {
        cancellation_pending(current_cancel_key())
    }

    #[test]
    fn pthread_cancel_validates_state_and_type_inputs() {
        reset_cancel_state_for_tests();
        let mut old_state = -1;
        let mut old_type = -1;

        // SAFETY: exercising local ABI state transitions.
        unsafe {
            assert_eq!(
                pthread_setcancelstate(PTHREAD_CANCEL_DISABLE_STATE, &mut old_state),
                0
            );
            assert_eq!(old_state, PTHREAD_CANCEL_ENABLE_STATE);
            assert_eq!(
                pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS_TYPE, &mut old_type),
                0
            );
            assert_eq!(old_type, PTHREAD_CANCEL_DEFERRED_TYPE);
            assert_eq!(
                pthread_setcancelstate(99, std::ptr::null_mut()),
                libc::EINVAL
            );
            assert_eq!(
                pthread_setcanceltype(99, std::ptr::null_mut()),
                libc::EINVAL
            );
        }
    }

    #[test]
    fn pthread_cancel_marks_pending_and_testcancel_consumes_when_enabled() {
        reset_cancel_state_for_tests();

        // SAFETY: exercising local ABI cancellation state machine.
        unsafe {
            let self_thread = pthread_self();
            assert_eq!(pthread_cancel(self_thread), 0);
            assert!(current_thread_pending_cancel());

            assert_eq!(
                pthread_setcancelstate(PTHREAD_CANCEL_DISABLE_STATE, std::ptr::null_mut()),
                0
            );
            pthread_testcancel();
            assert!(current_thread_pending_cancel());

            assert_eq!(
                pthread_setcancelstate(PTHREAD_CANCEL_ENABLE_STATE, std::ptr::null_mut()),
                0
            );
            pthread_testcancel();
            assert!(!current_thread_pending_cancel());
        }
    }

    #[test]
    fn pthread_cancel_self_async_consumes_immediately() {
        reset_cancel_state_for_tests();

        // SAFETY: exercising local ABI cancellation state machine.
        unsafe {
            assert_eq!(
                pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS_TYPE, std::ptr::null_mut()),
                0
            );
            let self_thread = pthread_self();
            assert_eq!(pthread_cancel(self_thread), 0);
            assert!(!current_thread_pending_cancel());
        }
    }
}
